use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, info, warn};
use uuid::Uuid;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};

use waf_common::metrics::{self, BudgetEvent, RequestAction};
use waf_common::{HostConfig, RequestCtx, WafAction};
use waf_engine::WafEngine;
use waf_engine::checks::ResponseCheckSet;

use crate::authority::{RouteAuthority, route_authority};
use crate::cache::ResponseCache;
use crate::context::{
    CACHE_BODY_LIMIT, FoldedHeaders, GatewayCtx, MAX_HEADER_VALUES_PER_NAME, body_inspection_policy,
    fold_request_headers, rightmost_forwarded_for,
};
use crate::lb::LoadBalancerRegistry;
use crate::response::{
    ResponseInspectMode, ResponseInspector, fold_response_headers, gate as response_gate, response_inspection_policy,
};
use crate::router::HostRouter;
use crate::ssl::ChallengeStore;
use crate::upstream_timeout::{UpstreamTimeouts, is_streaming_request};

/// Pingora-based reverse proxy with WAF integration
pub struct WafProxy {
    pub router: Arc<HostRouter>,
    pub engine: Arc<WafEngine>,
    /// Whether to trust X-Forwarded-For headers for client IP extraction.
    /// Should only be `true` when running behind a trusted reverse proxy.
    pub trust_proxy_headers: bool,
    /// Parsed trusted proxy CIDR ranges (from config).
    /// When non-empty and `trust_proxy_headers` is true, only XFF headers
    /// from connections originating within these ranges are honoured.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Pending ACME HTTP-01 challenge tokens served at
    /// `/.well-known/acme-challenge/{token}`. Shared with the `SslManager`
    /// when ACME is enabled; an empty store otherwise.
    pub acme_challenges: Arc<ChallengeStore>,
    /// Per-host load balancers keyed by `HostConfig::code`. A host with a
    /// registered balancer distributes traffic across its backend pool; hosts
    /// absent from the registry fall back to their single
    /// `remote_host`/`remote_port` (backward compatible).
    pub lb_registry: Arc<LoadBalancerRegistry>,
    /// Shared response cache. `None` when caching is disabled — in which case
    /// the request/response paths behave exactly as before (no cache lookups or
    /// stores are performed).
    pub cache: Option<Arc<ResponseCache>>,
    /// Enable shadow / log-only HTTP request-smuggling structural detection in
    /// [`request_filter`]. When `true` (default) the request framing headers are
    /// inspected for desync indicators and any match is logged; the request's
    /// allow/block decision is **never** changed. `false` skips the check.
    pub smuggling_detection: bool,
    /// Response-phase detectors (`ModSecurity` `phase:3` / `phase:4`).
    ///
    /// **Empty by default, and empty as this ships.** The whole response path
    /// keys off [`ResponseCheckSet::is_empty`]: while the set is empty no
    /// response is gated, buffered, scanned or delayed, and
    /// [`upstream_response_body_filter`](ProxyHttp::upstream_response_body_filter)
    /// runs the same cache-only code it ran before the response phase existed.
    /// The CRS `RESPONSE-95x` rules attach here once `checks::owasp` learns to
    /// evaluate `RESPONSE_BODY` / `RESPONSE_STATUS`.
    pub response_checks: Arc<ResponseCheckSet>,
    /// Per-stage timeouts stamped onto every upstream peer.
    ///
    /// **Unlimited by default**, which is what Pingora's own `PeerOptions`
    /// carry: with nothing configured, [`UpstreamTimeouts::apply`] returns
    /// without writing to the peer and no timer is armed. See
    /// [`crate::upstream_timeout`] and `[proxy.upstream_timeouts]`.
    pub upstream_timeouts: UpstreamTimeouts,
}

impl WafProxy {
    pub fn new(router: Arc<HostRouter>, engine: Arc<WafEngine>) -> Self {
        Self {
            router,
            engine,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
            acme_challenges: Arc::new(ChallengeStore::new()),
            lb_registry: Arc::new(LoadBalancerRegistry::new()),
            cache: None,
            smuggling_detection: true,
            response_checks: Arc::new(ResponseCheckSet::new()),
            upstream_timeouts: UpstreamTimeouts::default(),
        }
    }

    /// Extract client IP from session.
    ///
    /// Only reads X-Forwarded-For when `trust_proxy_headers` is enabled
    /// **and** the TCP peer address falls within `trusted_proxies` (or the
    /// list is empty, which means "trust any peer" for backwards compat).
    /// Otherwise always uses the TCP peer address.
    ///
    /// # Normalization boundary
    ///
    /// This is **the** point where a client address enters the HTTP/1.1 +
    /// HTTP/2 data plane, so it is also the only place that folds IPv4-mapped
    /// IPv6 (`::ffff:a.b.c.d`) down to plain IPv4 — see
    /// [`waf_common::net`] for why that matters and what breaks without it.
    /// An address can arrive here from exactly two sources, the TCP peer and a
    /// trusted `X-Forwarded-For` entry, and both are folded below. Everything
    /// downstream (`RequestCtx::client_ip`, blocklists, `CrowdSec`, `GeoIP`, the CC
    /// limiter) receives a canonical address and must not fold again.
    ///
    /// The peer fold has to happen *before* the `trusted_proxies` containment
    /// test, not merely on the return value: a `10.0.0.0/8` entry does not
    /// contain `::ffff:10.0.0.1`, so an unfolded peer would silently stop
    /// trusting a correctly configured IPv4 front proxy.
    fn extract_client_ip(&self, session: &Session) -> std::net::IpAddr {
        // Always resolve peer address first
        let peer_ip = waf_common::net::canonicalize_client_ip(session.client_addr().and_then(|a| a.as_inet()).map_or(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            std::net::SocketAddr::ip,
        ));

        if self.trust_proxy_headers {
            // When a trusted_proxies list is configured, only honour XFF from
            // connections that originate within those CIDR ranges.
            let peer_trusted =
                self.trusted_proxies.is_empty() || self.trusted_proxies.iter().any(|net| net.contains(&peer_ip));

            // Take the *right-most* non-empty entry rather than the left-most
            // one. The left-most value is fully client-controlled and can be
            // spoofed to bypass IP blocklists / rate limits; the right-most
            // entry is the address appended by the closest (trusted) proxy.
            //
            // The scan spans **every** `X-Forwarded-For` line: `get_header`
            // returns only the first one, so a client that prepends its own
            // `X-Forwarded-For` line would otherwise have its spoofed value
            // read as the right-most entry.
            if peer_trusted
                && let Some(rightmost) = rightmost_forwarded_for(&session.req_header().headers)
                && let Ok(ip) = rightmost.parse()
            {
                // A dual-stack front proxy may write the mapped form into XFF
                // even when this listener is IPv4-only, so this fold is not
                // redundant with the peer one above.
                return waf_common::net::canonicalize_client_ip(ip);
            }
        }

        peer_ip
    }

    /// Build a `RequestCtx` from the Pingora session.
    ///
    /// `headers` is the already-folded header map (see [`fold_request_headers`])
    /// — it must carry **every** value of a repeated header name, because the
    /// detectors only ever see this flat map.
    fn build_request_ctx(
        &self,
        session: &Session,
        host_config: Arc<HostConfig>,
        headers: HashMap<String, String>,
    ) -> RequestCtx {
        let client_ip = self.extract_client_ip(session);
        let client_port = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map_or(0, std::net::SocketAddr::port);

        let method = session.req_header().method.to_string();
        let uri = session.req_header().uri.clone();
        let path = uri.path().to_string();
        let query = uri.query().unwrap_or("").to_string();

        let host = host_config.host.clone();
        let port = host_config.port;

        // Parse Content-Length for informational purposes
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        RequestCtx {
            req_id: Uuid::new_v4().to_string(),
            client_ip,
            client_port,
            method,
            host,
            port,
            path,
            query,
            headers,
            body_preview: Bytes::new(),
            content_length,
            is_tls: false,
            host_config,
            geo: None, // populated by WafEngine::inspect when GeoIP is enabled
        }
    }

    /// Compute the cache key for a request **iff** it is safe to cache.
    ///
    /// Only `GET`/`HEAD` requests that carry no credentials (`Authorization` /
    /// `Cookie`) are cacheable. Anything else returns `None` so it is never
    /// served from — nor stored in — the shared cache (prevents cross-user
    /// leakage / cache poisoning). Returns `None` unless a host is resolved.
    fn cacheable_request_key(session: &Session, ctx: &GatewayCtx) -> Option<String> {
        let head = session.req_header();
        let method = head.method.as_str();
        if method != "GET" && method != "HEAD" {
            return None;
        }
        // Requests that carry credentials are user-specific: never share them.
        if session.get_header("authorization").is_some() || session.get_header("cookie").is_some() {
            return None;
        }

        let host_config = ctx.host_config.as_ref()?;
        let scheme = if session.digest().and_then(|d| d.ssl_digest.as_ref()).is_some() {
            "https"
        } else {
            "http"
        };
        let accept_encoding = session
            .get_header("accept-encoding")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .unwrap_or("");
        let path = head.uri.path();
        let query = head.uri.query().unwrap_or("");

        Some(ResponseCache::make_key(
            scheme,
            method,
            &host_config.host,
            host_config.port,
            path,
            query,
            accept_encoding,
        ))
    }

    /// Feed one response-body chunk to the response-phase detectors.
    ///
    /// Called only when [`GatewayCtx::response_inspection`] is armed. Returns
    /// `Err` when the response must be abandoned, which is the strongest action
    /// available at this point: the status line left the process before the
    /// first body byte arrived, so a finding cannot be turned into a `403`. What
    /// it *can* do is make sure the offending bytes never leave — in
    /// [`ResponseInspectMode::Enforce`] the chunk is withheld until its window
    /// comes back clean, so a hit inside the inspected prefix leaks nothing —
    /// and hand the client a message it is obliged to reject: Pingora answers
    /// the error by closing the downstream connection without completing the
    /// body, which is a `Content-Length` shortfall or a chunked body with no
    /// terminating chunk (RFC 9112 §8, an incomplete message).
    ///
    /// In [`ResponseInspectMode::Observe`] — the default — and for a host in
    /// `log_only_mode`, a finding is recorded and the response is delivered
    /// untouched.
    fn inspect_response_chunk(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()> {
        // Disjoint field borrows: the inspector is mutated while the request
        // context and host config are read.
        let GatewayCtx {
            response_inspection,
            request_ctx,
            host_config,
            ..
        } = ctx;
        let Some(inspector) = response_inspection.as_mut() else {
            return Ok(());
        };

        let step = inspector.push(body, end_of_stream);

        if step.over_cap {
            let policy = response_inspection_policy();
            warn!(
                "Response body exceeds the {} byte inspection ceiling; the remainder is delivered UNINSPECTED: \
                 host={} path={}",
                policy.max_total_bytes,
                request_ctx.as_ref().map_or("", |c| c.host.as_str()),
                request_ctx.as_ref().map_or("", |c| c.path.as_str()),
            );
        }

        let Some(window) = step.inspect else {
            return Ok(());
        };
        let Some(request) = request_ctx.as_ref() else {
            return Ok(());
        };

        let response_ctx = inspector.context(request, window, step.truncated);
        let Some(result) = self.response_checks.evaluate(&response_ctx) else {
            return Ok(());
        };

        // A host in log_only_mode downgrades every veto, exactly as it does for
        // the request phase.
        let log_only =
            inspector.mode() == ResponseInspectMode::Observe || host_config.as_ref().is_some_and(|h| h.log_only_mode);

        if log_only {
            warn!(
                "WAF response detection (log only): rule={} phase={} status={} ip={} host={} path={} detail={}",
                result.rule_name,
                result.phase,
                response_ctx.status,
                request.client_ip,
                request.host,
                request.path,
                result.detail,
            );
            return Ok(());
        }

        warn!(
            "WAF abandoned response: rule={} phase={} status={} ip={} host={} path={} detail={}",
            result.rule_name,
            result.phase,
            response_ctx.status,
            request.client_ip,
            request.host,
            request.path,
            result.detail,
        );

        // Withhold whatever this window would have released; the abort below
        // must not race a partial write of the offending bytes.
        *body = None;

        // `HTTPStatus(403)` is not cosmetic, and it is not guaranteed either.
        //
        // Pingora drains upstream tasks in batches: it filters every task in the
        // batch into `filtered_tasks` and only then calls
        // `write_response_tasks` (`proxy_h1.rs`). Returning `Err` here aborts
        // that loop through `?`, so a header sitting in the *same* batch is
        // dropped unwritten — `fail_to_proxy` then finds `response_written() ==
        // None` and emits a genuine `403`. That is the likely path for the small
        // origin responses the CRS `RESPONSE-95x` rules exist to catch (an error
        // page, a stack trace, a JSON fault) arriving from a fast backend.
        //
        // When the header went out in an earlier batch — any streamed or large
        // response — `respond_error` sees a written response, declines to write
        // a second one, and closes the connection instead. Both outcomes are
        // acceptable; only the first is a status code, and which one occurs is a
        // property of upstream timing, so nothing may be built on top of it.
        Err(pingora_core::Error::explain(
            pingora_core::ErrorType::HTTPStatus(403),
            "WAF blocked upstream response",
        ))
    }
}

/// Hop-by-hop headers (RFC 7230 §6.1) that must not be forwarded from a cached
/// response, plus `set-cookie` which is already rejected at store time. These
/// are connection-specific and would corrupt a replayed response.
fn is_uncacheable_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "set-cookie"
    )
}

/// Body value that withholds the current chunk from the upstream.
///
/// Pingora treats `None` as "the downstream body is finished" and closes the
/// upstream stream, so a chunk that is merely being buffered for inspection has
/// to be replaced with an **empty** `Bytes`: Pingora skips writing it (an empty
/// write would be a terminating chunk on the wire) and keeps the stream open.
/// Once the downstream really is done, `None` is the correct value.
const fn withheld_body(end_of_stream: bool) -> Option<Bytes> {
    if end_of_stream { None } else { Some(Bytes::new()) }
}

/// Body value that releases `forward` (already inspected) to the upstream,
/// falling back to [`withheld_body`] when there is nothing to release yet.
fn release_body(forward: Option<Bytes>, end_of_stream: bool) -> Option<Bytes> {
    forward.or_else(|| withheld_body(end_of_stream))
}

/// Map a WAF decision onto the metric label, or `None` when the decision is a
/// plain allow.
///
/// `None` rather than `Some(Allow)` so a later phase's real decision cannot be
/// overwritten by an earlier phase's non-decision: the body phase runs after
/// the header phase and both call this.
///
/// Shared with the HTTP/3 handler rather than duplicated there: the mapping is
/// what makes `action="block"` mean the same thing on both protocols, and two
/// copies of it would be free to drift on one dashboard.
pub(crate) const fn request_action_of(action: &WafAction) -> Option<RequestAction> {
    match action {
        WafAction::Allow => None,
        WafAction::Block { .. } => Some(RequestAction::Block),
        WafAction::LogOnly => Some(RequestAction::LogOnly),
        WafAction::Redirect { .. } => Some(RequestAction::Redirect),
    }
}

/// How many lines the raw request carries for `name`.
///
/// Only called on the refusal path, to tell the two `431` causes apart for the
/// metric. `fold_request_headers` knows which bound it hit but returns only the
/// offending name; threading a reason back out would put a metrics concern into
/// the fold return type for the benefit of a path that is, by construction,
/// rare.
fn header_line_count(headers: &http::HeaderMap, name: &str) -> usize {
    name.parse::<http::HeaderName>()
        .map_or(0, |name| headers.get_all(&name).iter().count())
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx::default()
    }

    /// Select the upstream peer.
    ///
    /// Host routing, site-status checks and WAF header inspection all happen in
    /// [`request_filter`] (which runs *before* this stage in Pingora's fixed
    /// phase order).  By the time we get here `ctx.host_config` is guaranteed to
    /// be populated for any request that was allowed through, so we simply
    /// rebuild the peer from it.
    async fn upstream_peer(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<Box<HttpPeer>> {
        // Streaming intent has to be read off the request: the peer is built
        // before any response byte exists. Only consulted when a read/write
        // bound is actually configured *and* the exemption is on.
        let streaming = self.upstream_timeouts.stream_exempt && is_streaming_request(session.req_header());

        let host_config = ctx.host_config.as_ref().ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                "internal: upstream_peer reached without a resolved host",
            )
        })?;

        // `upstream_ssl` when the operator set it, `ssl` otherwise — see
        // `HostConfig::upstream_uses_tls`. Shared with the HTTP/3 forwarder so
        // one host cannot dial its origin two different ways.
        let use_tls = host_config.upstream_uses_tls();

        // Multi-backend path: if this host has a registered load balancer, pick a
        // backend from the pool. The client IP (already resolved in
        // `request_filter`) feeds the IpHash strategy for sticky sessions.
        if let Some(lb) = self.lb_registry.get(&host_config.code) {
            let client_ip = ctx
                .request_ctx
                .as_ref()
                .map_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |c| c.client_ip);

            if let Some(backend) = lb.select_backend(client_ip) {
                // Track the active connection for Least-Connections accounting;
                // released in `logging`. Guard against a retry re-entering this
                // callback by releasing any previously selected backend first.
                if let Some(prev) = ctx.selected_backend.take() {
                    prev.release_connection();
                }
                backend.acquire_connection();
                let upstream_addr = backend.addr();
                let sni = backend.host.clone();
                ctx.selected_backend = Some(backend);

                info!("Proxying {} → {} (load-balanced)", host_config.host, upstream_addr);
                let mut peer = HttpPeer::new(&upstream_addr, use_tls, sni);
                self.upstream_timeouts.apply(&mut peer, streaming);
                return Ok(Box::new(peer));
            }
            // Empty / fully-drained pool → fall through to the single backend.
            warn!(
                "Load balancer for host {} returned no backend; using single upstream",
                host_config.host
            );
        }

        // Single-backend path (unchanged, backward compatible).
        let upstream_addr = format!("{}:{}", host_config.remote_host, host_config.remote_port);
        info!("Proxying {} → {}", host_config.host, upstream_addr);
        let mut peer = HttpPeer::new(&upstream_addr, use_tls, host_config.remote_host.clone());
        self.upstream_timeouts.apply(&mut peer, streaming);
        Ok(Box::new(peer))
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<bool> {
        // Start the request clock before anything can return early, so the
        // duration histogram covers ACME probes, 404s and refusals rather than
        // only the requests that made it to an upstream. `enabled()` gates the
        // clock read itself: with metrics off this is one `OnceLock` load and no
        // `clock_gettime`.
        if metrics::enabled() {
            ctx.started_at = Some(std::time::Instant::now());
        }

        // ── ACME HTTP-01 challenge (M-4) ──────────────────────────────────────
        // Answer Let's Encrypt validation probes before any host routing or WAF
        // inspection. Reads only the raw request path from the session and is
        // fully decoupled from `ctx.request_ctx`.
        let key_authorization = {
            let path = session.req_header().uri.path();
            self.acme_challenges.response_for_path(path)
        };
        if let Some(key_auth) = key_authorization {
            let mut response = pingora_http::ResponseHeader::build(200, None)?;
            response.insert_header("content-type", "text/plain")?;
            session.write_response_header(Box::new(response), false).await?;
            session.write_response_body(Some(Bytes::from(key_auth)), true).await?;
            return Ok(true);
        }

        // ── Health check endpoint (host-independent) ──────────────────────────
        let is_health = {
            let head = session.req_header();
            head.method.as_str() == "GET" && head.uri.path() == "/health"
        };
        if is_health {
            let _ = session.respond_error(200).await;
            return Ok(true);
        }

        // ── Header folding (must precede routing and inspection) ──────────────
        // Every value of a repeated header name is folded into one RFC-shaped
        // value so the detectors see the complete request, and the two abuse
        // cases that folding cannot represent faithfully are refused outright.
        let folded = fold_request_headers(&session.req_header().headers);
        if folded.duplicate_host {
            // RFC 9112 §3.2: more than one Host line is unroutable — we would
            // pick one and the origin might pick the other.
            metrics::record_budget_event(BudgetEvent::DuplicateHost);
            ctx.metric_action = Some(RequestAction::Block);
            // `action` is the metric's own label value, not a second spelling of
            // it: this refusal lands in `prxwaf_requests_total{action="block"}`
            // and an operator pivoting off that series has to be able to grep
            // the same token. Same for every refusal below.
            warn!(
                action = RequestAction::Block.label(),
                "Rejecting request with duplicate Host headers: ip={}",
                self.extract_client_ip(session)
            );
            let response = pingora_http::ResponseHeader::build(400, None)?;
            session.write_response_header(Box::new(response), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"Bad Request")), true)
                .await?;
            return Ok(true);
        }
        if let Some(name) = &folded.overflow {
            // The folded value would be incomplete; inspecting a truncated
            // header is exactly the bypass the fold closes, so refuse instead.
            // `fold_request_headers` records only the first offending name, so
            // which of the two bounds was hit is re-derived here rather than
            // threaded back out of the fold: over the line count, or over the
            // byte count.
            metrics::record_budget_event(
                if header_line_count(&session.req_header().headers, name) > MAX_HEADER_VALUES_PER_NAME {
                    BudgetEvent::HeaderValueCountExceeded
                } else {
                    BudgetEvent::HeaderFoldBytesExceeded
                },
            );
            ctx.metric_action = Some(RequestAction::Block);
            warn!(
                action = RequestAction::Block.label(),
                "Rejecting request: header '{name}' exceeds the fold limits: ip={}",
                self.extract_client_ip(session)
            );
            let response = pingora_http::ResponseHeader::build(431, None)?;
            session.write_response_header(Box::new(response), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"Request Header Fields Too Large")), true)
                .await?;
            return Ok(true);
        }
        let FoldedHeaders { mut headers, .. } = folded;

        // ── Routing authority (moved here from upstream_peer, C-1) ────────────
        // `route_authority` rather than `get_header("host")`, because this call
        // site now serves h2 as well: an h2 request carries its authority in
        // `:authority`, which Pingora leaves in `RequestHeader::uri` with the
        // field map untouched, so reading the `Host` field alone routed every
        // compliant h2 request on the empty string. On HTTP/1.1 the resolver
        // reads the same `Host` field it always did — Pingora's request targets
        // never carry an authority (see `crate::authority`).
        let resolved = {
            let head = session.req_header();
            match route_authority(&head.uri, &head.headers) {
                RouteAuthority::Found(a) => Some(a.to_string()),
                // Unroutable. Routed with an empty authority so this lands on
                // exactly the same 404 as an unknown host — never a default
                // config, never a forward.
                RouteAuthority::Missing => Some(String::new()),
                RouteAuthority::Contradicted => None,
            }
        };
        let Some(host_header) = resolved else {
            // Which site this request addressed is unknowable, and picking a
            // side is the desync itself: this WAF would apply the policy of one
            // authority while the origin resolved its vhost from the other.
            // Deliberately not attributed to either candidate, so neither
            // site's block rate carries the other's traffic.
            metrics::record_budget_event(BudgetEvent::ContradictedAuthority);
            ctx.metric_action = Some(RequestAction::Block);
            warn!(
                action = RequestAction::Block.label(),
                "Rejecting request whose Host disagrees with the request authority: ip={}",
                self.extract_client_ip(session)
            );
            let response = pingora_http::ResponseHeader::build(400, None)?;
            session.write_response_header(Box::new(response), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"Bad Request")), true)
                .await?;
            return Ok(true);
        };

        // The detectors must not see a different request depending on the wire
        // protocol: CRS-920350 reads the `Host` header to flag a numeric-IP
        // vhost, and it has to see the same value on h2, where that value
        // arrived as `:authority` and no `Host` field exists at all. `entry`
        // rather than `insert` so a client-sent `Host`, already proven
        // byte-equal above, stays exactly as it was received. HTTP/1.1 always
        // takes the `or_insert` no-op branch.
        if !host_header.is_empty() {
            headers.entry("host".to_string()).or_insert_with(|| host_header.clone());
        }

        debug!("Routing request for host: {}", host_header);

        // Intern the host label once. Everything downstream indexes with the
        // integer, so this is the only hash+probe on the request path. An
        // unroutable host is deliberately resolved anyway: 404 volume per
        // requested hostname is exactly the signal that tells an operator a
        // site is misconfigured rather than merely quiet.
        ctx.metric_host = metrics::resolve_host(&host_header);

        let Some(host_config) = self.router.resolve(&host_header) else {
            // Unknown host: previously fell through to a pass-through; now we
            // respond 404 so unrouted traffic is never forwarded / inspected.
            warn!(
                action = RequestAction::Block.label(),
                "No route found for host: {host_header}"
            );
            // Counted as a Block: the WAF refused it and nothing reached an
            // upstream. `prxwaf_responses_total{status="4xx"}` carries the 404
            // itself, so the two together separate "refused by routing" from
            // "refused by detection", which `prxwaf_detections_total` answers.
            ctx.metric_action = Some(RequestAction::Block);
            let response = pingora_http::ResponseHeader::build(404, None)?;
            session.write_response_header(Box::new(response), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"Not Found")), true)
                .await?;
            return Ok(true);
        };

        // Site administratively closed → 503 (previously an opaque proxy error).
        if !host_config.start_status {
            warn!(
                action = RequestAction::Block.label(),
                "Site closed for host: {host_header}"
            );
            ctx.metric_action = Some(RequestAction::Block);
            let response = pingora_http::ResponseHeader::build(503, None)?;
            session.write_response_header(Box::new(response), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"Service Unavailable")), true)
                .await?;
            return Ok(true);
        }

        let upstream_addr = format!("{}:{}", host_config.remote_host, host_config.remote_port);
        ctx.upstream_addr = Some(upstream_addr);
        ctx.host_config = Some(Arc::clone(&host_config));

        // ── HTTP request-smuggling structural detection (shadow / log-only) ───
        // Inspect the *raw* request framing headers (the `RequestCtx` HashMap
        // collapses duplicates, so we must read `HeaderMap` directly). Cheap:
        // two `get_all` walks, zero allocation for a clean request, no body
        // access. Matches are logged only — the request continues unchanged and
        // the allow/block decision below is untouched.
        if self.smuggling_detection {
            let findings = crate::smuggling::detect(&session.req_header().headers);
            if !findings.is_empty() {
                let client_ip = self.extract_client_ip(session);
                let path = session.req_header().uri.path();
                crate::smuggling::log_findings(&findings, client_ip, &host_header, path);
            }
        }

        // ── WAF header-phase inspection ───────────────────────────────────────
        let mut request_ctx = self.build_request_ctx(session, host_config, headers);
        let client_ip = request_ctx.client_ip;
        let path = request_ctx.path.clone();
        let host = request_ctx.host.clone();

        // Initialise the Lane 2 budget from the engine's compiled config so the
        // header and body phases of this request share one budget (plan §12.3).
        ctx.content_inspection = self.engine.new_content_inspection_state();

        // ctx is &mut so the engine can enrich it with GeoIP
        let decision = self
            .engine
            .inspect_with_state(&mut request_ctx, &mut ctx.content_inspection)
            .await;

        // Persist the (GeoIP-enriched) request context for the body phase and logging.
        ctx.request_ctx = Some(request_ctx);

        // Record the decision even when it allows: `LogOnly` is an allow for
        // the request and a detection for the operator, and the two must not be
        // conflated. `record_detection` fires from the engine, which is the only
        // place that knows which phase produced the verdict.
        if let Some(action) = request_action_of(&decision.action) {
            ctx.metric_action = Some(action);
        }

        // The phase that produced the verdict, spelled as
        // `prxwaf_detections_total{phase=…}` spells it. `Phase::to_string()` —
        // which is what `attack_logs.phase` stores — renders "SQL Injection",
        // and a log carrying that form would be a third spelling of a thing
        // that already has two.
        let detected_phase = decision.result.as_ref().map(|r| r.phase.metric_label());

        if !decision.is_allowed() {
            match &decision.action {
                WafAction::Block { status, body } => {
                    warn!(
                        action = RequestAction::Block.label(),
                        phase = detected_phase,
                        "WAF blocked request: ip={client_ip} path={path} host={host}"
                    );
                    let status_code = *status;
                    let body_str = body.clone().unwrap_or_else(|| "Access Denied".to_string());

                    let response = pingora_http::ResponseHeader::build(status_code, None)?;
                    session.write_response_header(Box::new(response), false).await?;
                    let body_bytes = Bytes::from(body_str);
                    session.write_response_body(Some(body_bytes), true).await?;
                    return Ok(true);
                }
                WafAction::Redirect { url } => {
                    // Previously silent. A redirect verdict increments
                    // `prxwaf_requests_total{action="redirect"}` exactly as a
                    // block increments its own label, and a counter that moves
                    // with nothing in the log to explain it is the shape of
                    // divergence this pass exists to remove. Same frequency
                    // class as a block — it fires only when a configured rule
                    // resolves to `redirect` — so it costs what the block line
                    // costs. The destination is operator-configured, not
                    // request-controlled, so naming it is safe.
                    warn!(
                        action = RequestAction::Redirect.label(),
                        phase = detected_phase,
                        "WAF redirected request: ip={client_ip} path={path} host={host} to={url}"
                    );
                    let mut response = pingora_http::ResponseHeader::build(302, None)?;
                    response.insert_header("location", url.as_str())?;
                    session.write_response_header(Box::new(response), true).await?;
                    return Ok(true);
                }
                _ => {}
            }
        }

        // ── Response cache lookup ─────────────────────────────────────────────
        // Runs only after the WAF has cleared the request (a cache hit still
        // must pass every detection above; it only lets us skip the upstream).
        if let Some(cache) = &self.cache
            && let Some(key) = Self::cacheable_request_key(session, ctx)
        {
            if let Some(hit) = cache.get(&key).await {
                let mut response = pingora_http::ResponseHeader::build(hit.status, None)?;
                for (name, value) in &hit.headers {
                    // Individual malformed headers must not fail the whole
                    // response; skip them rather than aborting.
                    let _ = response.insert_header(name.clone(), value.clone());
                }
                let _ = response.insert_header("x-cache", "HIT");
                session.write_response_header(Box::new(response), false).await?;
                session.write_response_body(Some(hit.body.clone()), true).await?;
                return Ok(true);
            }
            // Miss: remember the key so the response phase can store the result.
            ctx.cache_key = Some(key);
        }

        Ok(false)
    }

    /// Inspect the request body window by window and release each window to the
    /// upstream only after it has been scanned.
    ///
    /// This callback is invoked for each body chunk *before* it is forwarded.
    /// Chunks are buffered (and withheld from the upstream) until a full
    /// inspection window — or the end of the stream — is available; the window
    /// is then handed to the WAF and, if clean, forwarded. Consecutive windows
    /// overlap, so a payload split across a boundary is still seen contiguously.
    ///
    /// Unlike the previous implementation this never stops inspecting after the
    /// first window: a request that pads 64 KiB of harmless bytes in front of
    /// its payload no longer bypasses body detection. Bodies larger than the
    /// policy's inspected-byte ceiling are refused with `413` by default (see
    /// [`crate::context::BodyInspectionPolicy`]).
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()> {
        let step = ctx.body_inspector.push(body.take(), end_of_stream);

        // Nothing may leave the WAF until its window has been scanned; the
        // release happens at the end of this function. Note that a `None` body
        // means *end of body* to Pingora (it flags `upstream_end_of_body` and
        // terminates the upstream stream), so a withheld chunk must be an
        // **empty** `Bytes` — Pingora skips writing it and keeps the stream
        // open. `None` is only correct once the downstream really is done.
        *body = withheld_body(end_of_stream);

        if step.reject {
            metrics::record_budget_event(BudgetEvent::RequestBodyRejected);
            ctx.metric_action = Some(RequestAction::Block);
            let policy = body_inspection_policy();
            let (ip, path, host) = ctx.request_ctx.as_ref().map_or_else(
                || (String::from("unknown"), String::new(), String::new()),
                |c| (c.client_ip.to_string(), c.path.clone(), c.host.clone()),
            );
            warn!(
                action = RequestAction::Block.label(),
                "WAF rejected request body over the {} byte inspection ceiling: ip={ip} path={path} host={host}",
                policy.max_total_bytes,
            );
            let response = pingora_http::ResponseHeader::build(413, None)?;
            session.write_response_header(Box::new(response), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"Payload Too Large")), true)
                .await?;
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::HTTPStatus(413),
                "request body exceeds the WAF inspection ceiling",
            ));
        }

        if step.over_cap {
            // Only reachable under the opt-in fail-open policy — never silent.
            // docs/dos-budget.md §1.1 recorded that this path had a WARN and no
            // counter, so an operator could not alert on how much traffic was
            // being forwarded past the inspection ceiling. This is that counter.
            metrics::record_budget_event(BudgetEvent::RequestBodyForwardedUninspected);
            let policy = body_inspection_policy();
            warn!(
                "Request body exceeds the {} byte inspection ceiling; remaining bytes are forwarded UNINSPECTED \
                 (PRXWAF_BODY_INSPECT_OVERFLOW=log): ip={} path={}",
                policy.max_total_bytes,
                ctx.request_ctx
                    .as_ref()
                    .map_or_else(String::new, |c| c.client_ip.to_string()),
                ctx.request_ctx.as_ref().map_or("", |c| c.path.as_str()),
            );
        }

        let Some(window) = step.inspect else {
            *body = release_body(step.forward, end_of_stream);
            return Ok(());
        };

        // Build a RequestCtx clone with body_preview populated
        let Some(mut request_ctx) = ctx.request_ctx.clone() else {
            *body = release_body(step.forward, end_of_stream);
            return Ok(());
        };

        request_ctx.body_preview = window;

        // Run body-phase WAF inspection (content detectors only — CC / IP / URL
        // / geo / bouncer / community already ran once in the header phase).
        // Shares the header phase's Lane 2 budget (plan §12.3).
        let decision = self
            .engine
            .inspect_body_with_state(&mut request_ctx, &mut ctx.content_inspection)
            .await;

        if let Some(action) = request_action_of(&decision.action) {
            ctx.metric_action = Some(action);
        }

        let detected_phase = decision.result.as_ref().map(|r| r.phase.metric_label());

        if !decision.is_allowed() {
            match &decision.action {
                WafAction::Block {
                    status,
                    body: block_body,
                } => {
                    warn!(
                        action = RequestAction::Block.label(),
                        phase = detected_phase,
                        "WAF blocked request (body): ip={} path={} host={}",
                        request_ctx.client_ip,
                        request_ctx.path,
                        request_ctx.host,
                    );
                    let status_code = *status;
                    let body_str = block_body.clone().unwrap_or_else(|| "Access Denied".to_string());

                    let response = pingora_http::ResponseHeader::build(status_code, None)?;
                    session.write_response_header(Box::new(response), false).await?;
                    let body_bytes = Bytes::from(body_str);
                    session.write_response_body(Some(body_bytes), true).await?;

                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::HTTPStatus(status_code),
                        "WAF blocked request body",
                    ));
                }
                WafAction::Redirect { url } => {
                    warn!(
                        action = RequestAction::Redirect.label(),
                        phase = detected_phase,
                        "WAF redirected request (body): ip={} path={} host={} to={url}",
                        request_ctx.client_ip,
                        request_ctx.path,
                        request_ctx.host,
                    );
                    let mut response = pingora_http::ResponseHeader::build(302, None)?;
                    response.insert_header("location", url.as_str())?;
                    session.write_response_header(Box::new(response), true).await?;

                    return Err(pingora_core::Error::explain(
                        pingora_core::ErrorType::HTTPStatus(302),
                        "WAF redirected request",
                    ));
                }
                _ => {}
            }
        }

        // Scanned and clean: release this window to the upstream.
        *body = release_body(step.forward, end_of_stream);

        Ok(())
    }

    /// Arm the response-phase WAF for this response, then capture the upstream
    /// response headers and decide whether the body is worth buffering for a
    /// cache store. The cache half runs only when the request was a cache-store
    /// candidate (`ctx.cache_key` set in `request_filter`).
    ///
    /// Note what is **not** happening here: the status is not being held back.
    /// By the time this returns, Pingora writes the header task straight to the
    /// downstream socket (`proxy_h1.rs`, `write_response_tasks`), so nothing the
    /// body phase later discovers can change it. See [`crate::response`] for why
    /// that constraint is structural and what the response phase does instead.
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // ── Response-phase WAF arming ─────────────────────────────────────────
        // The `is_empty` test comes first and short-circuits everything: with no
        // registered response detector not a single header is folded and no
        // inspector is allocated, so this whole block is one pointer test.
        if !self.response_checks.is_empty() {
            let status = upstream_response.status.as_u16();
            let guard_status = ctx.host_config.as_ref().is_some_and(|h| h.guard_status);
            let header_str = |name: &str| {
                upstream_response
                    .headers
                    .get(name)
                    .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            };
            // Gate on the raw header map first; the fold only happens for a
            // response that is actually going to be inspected.
            let decision = response_gate(
                true,
                guard_status,
                status,
                header_str("content-type"),
                header_str("content-encoding"),
            );
            if decision.is_inspect() {
                let headers = fold_response_headers(&upstream_response.headers);
                ctx.response_inspection = Some(ResponseInspector::new(*response_inspection_policy(), status, headers));
            } else {
                debug!("Response phase skipped: {}", decision.reason());
            }
        }

        if self.cache.is_none() || ctx.cache_key.is_none() {
            return Ok(());
        }

        let status = upstream_response.status.as_u16();
        let has_set_cookie = upstream_response.headers.contains_key("set-cookie");
        let cache_control = upstream_response
            .headers
            .get("cache-control")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .map(str::to_string);

        // Early rejection so a no-store / private / non-2xx / cookie-bearing
        // response is never buffered. `put()` re-checks these as a safety net.
        let cc_forbids = cache_control.as_deref().is_some_and(|cc| {
            let lower = cc.to_ascii_lowercase();
            lower.contains("no-store") || lower.contains("no-cache") || lower.contains("private")
        });
        let storable = (200..300).contains(&status) && !has_set_cookie && !cc_forbids;
        if !storable {
            // Abandon the store; leave nothing to buffer.
            ctx.cache_key = None;
            return Ok(());
        }

        let mut headers = Vec::new();
        for (name, value) in &upstream_response.headers {
            let name = name.as_str();
            if is_uncacheable_header(name) {
                continue;
            }
            if let Ok(v) = std::str::from_utf8(value.as_bytes()) {
                headers.push((name.to_string(), v.to_string()));
            }
        }

        ctx.cache_status = status;
        ctx.cache_headers = headers;
        ctx.cache_control = cache_control;
        ctx.cache_store = true;
        Ok(())
    }

    /// Accumulate the upstream response body (bounded by [`CACHE_BODY_LIMIT`])
    /// and, at end of stream, hand the complete response off to the cache.
    ///
    /// This callback is synchronous, so the (async) `moka` insert is performed
    /// on a detached Tokio task rather than blocking the proxy hot path.
    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<Option<std::time::Duration>> {
        // ── Response-phase WAF ────────────────────────────────────────────────
        // `response_inspection` is `None` unless `upstream_response_filter` armed
        // an inspector, which it only does when a response detector is
        // registered. With none registered this is the *only* difference from
        // the cache-only filter that shipped before: one `Option` test.
        //
        // It runs **before** the cache accumulator on purpose. In enforce mode
        // the inspector re-times chunks (withholding each one until its window
        // is scanned) without adding, dropping or reordering a byte, so the
        // accumulator below still sees the complete body in order — but only if
        // it reads `body` after the inspector has finished with it.
        if ctx.response_inspection.is_some()
            && let Err(e) = self.inspect_response_chunk(body, end_of_stream, ctx)
        {
            // The response was abandoned mid-stream; a partial body must never
            // reach the cache.
            ctx.cache_store = false;
            ctx.cache_key = None;
            ctx.cache_body.clear();
            return Err(e);
        }

        if !ctx.cache_store {
            return Ok(None);
        }

        // Buffer only up to what is actually cacheable: the global per-request
        // bound, or the cache's own per-entry admission cap when that is
        // smaller (a small `cache.max_size_mb` makes it smaller). Accumulating
        // past the cap only to have `ResponseCache::put` refuse the entry is
        // per-request memory spent for nothing.
        let body_limit = self.cache.as_ref().map_or(CACHE_BODY_LIMIT, |cache| {
            usize::try_from(cache.max_entry_bytes())
                .unwrap_or(CACHE_BODY_LIMIT)
                .min(CACHE_BODY_LIMIT)
        });

        if let Some(chunk) = body {
            if ctx.cache_body.len().saturating_add(chunk.len()) > body_limit {
                // Response too large to cache: abandon and release the buffer.
                // The body still streams to the client untouched — refused, not
                // truncated. Counted here because this short-circuit runs
                // before `ResponseCache::put`, which is where refusals are
                // otherwise tallied.
                debug!("Response exceeds {body_limit} byte cache limit; not caching");
                if let Some(cache) = &self.cache {
                    cache.note_oversize_reject();
                }
                ctx.cache_store = false;
                ctx.cache_key = None;
                ctx.cache_body.clear();
                return Ok(None);
            }
            ctx.cache_body.extend_from_slice(chunk);
        }

        if end_of_stream && let (Some(cache), Some(key)) = (self.cache.clone(), ctx.cache_key.take()) {
            let status = ctx.cache_status;
            let headers = std::mem::take(&mut ctx.cache_headers);
            let body_bytes = Bytes::copy_from_slice(&ctx.cache_body);
            let cache_control = ctx.cache_control.take();
            ctx.cache_store = false;
            ctx.cache_body.clear();

            tokio::spawn(async move {
                cache
                    .put(key, status, headers, body_bytes, cache_control.as_deref())
                    .await;
            });
        }

        Ok(None)
    }

    async fn logging(&self, session: &mut Session, error: Option<&pingora_core::Error>, ctx: &mut GatewayCtx) {
        // Pingora calls this exactly once per request on every path — the normal
        // finish (`pingora-proxy-0.8.1/src/lib.rs:411`), the `request_filter`
        // short-circuit where the WAF already wrote the response (`:786`) and
        // the error path (`:968`) — which makes it the only place a request
        // counter can be incremented exactly once. Recording at the decision
        // sites instead would double-count: a request is decided in the header
        // phase and again per body window.
        //
        // The default is `Allow`, because reaching here with no stashed decision
        // means nothing refused the request.
        if metrics::enabled() {
            let host = ctx.metric_host;
            metrics::record_request(host, ctx.metric_action.unwrap_or(RequestAction::Allow));
            // The status actually written downstream, not the one the WAF
            // intended: an upstream 502 and a WAF 403 are both interesting and
            // only this reads the real one.
            if let Some(written) = session.response_written() {
                metrics::record_response(host, written.status.as_u16());
            }
            if let Some(started) = ctx.started_at {
                metrics::record_request_duration(host, started.elapsed());
            }
        }

        // Release the load-balanced backend's active-connection slot (paired
        // with the acquire in `upstream_peer`) so Least-Connections accounting
        // stays balanced even on errors / early termination.
        if let Some(backend) = ctx.selected_backend.take() {
            backend.release_connection();
        }

        // An upstream timeout is a configured cut, not a mystery 502: say so at
        // WARN, naming the stage and the peer, so `[proxy.upstream_timeouts]`
        // can be tuned from the log instead of from guesswork. These error
        // types have no other source in this proxy — nothing else arms a timer
        // on the upstream connection.
        if let Some(err) = error {
            let stage = match err.etype() {
                pingora_core::ErrorType::ConnectTimedout => Some("connect"),
                pingora_core::ErrorType::ReadTimedout => Some("read"),
                pingora_core::ErrorType::WriteTimedout => Some("write"),
                _ => None,
            };
            if let Some(stage) = stage {
                metrics::record_budget_event(match err.etype() {
                    pingora_core::ErrorType::ConnectTimedout => BudgetEvent::UpstreamConnectTimeout,
                    pingora_core::ErrorType::WriteTimedout => BudgetEvent::UpstreamWriteTimeout,
                    _ => BudgetEvent::UpstreamReadTimeout,
                });
                warn!(
                    target: "waf.upstream_timeout",
                    "Upstream {stage} timeout ({}) → upstream={} host={} path={}",
                    self.upstream_timeouts.summary(),
                    ctx.upstream_addr.as_deref().unwrap_or("unknown"),
                    ctx.request_ctx.as_ref().map_or("unknown", |c| c.host.as_str()),
                    ctx.request_ctx.as_ref().map_or("unknown", |c| c.path.as_str()),
                );
            }
        }

        if let Some(req_ctx) = &ctx.request_ctx {
            debug!(
                "Request completed: {} {} {} → upstream={}",
                req_ctx.method,
                req_ctx.host,
                req_ctx.path,
                ctx.upstream_addr.as_deref().unwrap_or("unknown"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pingora reads `None` as "downstream body finished". A chunk that is only
    /// being held back for inspection must therefore be an empty `Bytes`,
    /// otherwise the upstream stream is closed mid-request and the body is
    /// truncated.
    #[test]
    fn withheld_chunk_is_empty_not_none() {
        assert_eq!(withheld_body(false), Some(Bytes::new()));
        assert_eq!(withheld_body(true), None);
    }

    /// The header phase and the body phase both stash a decision, and the body
    /// phase runs last. A plain allow must not be able to overwrite a `LogOnly`
    /// the header phase already recorded, which is why this returns `None`
    /// rather than `Some(Allow)`.
    #[test]
    fn a_plain_allow_does_not_overwrite_an_earlier_decision() {
        assert_eq!(request_action_of(&WafAction::Allow), None);
        assert_eq!(request_action_of(&WafAction::LogOnly), Some(RequestAction::LogOnly));
        assert_eq!(
            request_action_of(&WafAction::Block {
                status: 403,
                body: None
            }),
            Some(RequestAction::Block)
        );
        assert_eq!(
            request_action_of(&WafAction::Redirect {
                url: "https://example.test/".to_string()
            }),
            Some(RequestAction::Redirect)
        );
    }

    /// The two `431` causes are distinguished by re-counting the header lines,
    /// so the count has to be right — including for a name the request does not
    /// carry at all, which the fold cannot produce but a future caller could.
    #[test]
    fn header_lines_are_counted_per_name() {
        let mut headers = http::HeaderMap::new();
        for value in ["a=1", "b=2", "c=3"] {
            headers.append(
                http::HeaderName::from_static("cookie"),
                http::HeaderValue::from_static(value),
            );
        }
        assert_eq!(header_line_count(&headers, "cookie"), 3);
        assert_eq!(header_line_count(&headers, "user-agent"), 0);
        // An unparseable name cannot index a HeaderMap; report zero rather than
        // failing the refusal path that is trying to emit a metric.
        assert_eq!(header_line_count(&headers, "not a header name"), 0);
    }

    #[test]
    fn released_window_is_forwarded_verbatim() {
        let window = Bytes::from_static(b"user=alice");
        assert_eq!(release_body(Some(window.clone()), false), Some(window.clone()));
        assert_eq!(release_body(Some(window.clone()), true), Some(window));
        // Nothing to release yet: withhold rather than terminate the stream.
        assert_eq!(release_body(None, false), Some(Bytes::new()));
        assert_eq!(release_body(None, true), None);
    }
}
