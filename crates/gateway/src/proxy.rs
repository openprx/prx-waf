use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, info, warn};
use uuid::Uuid;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};

use waf_common::{HostConfig, RequestCtx, WafAction};
use waf_engine::WafEngine;

use crate::cache::ResponseCache;
use crate::context::{BODY_PREVIEW_LIMIT, CACHE_BODY_LIMIT, GatewayCtx};
use crate::lb::LoadBalancerRegistry;
use crate::router::HostRouter;
use crate::ssl::ChallengeStore;

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
        }
    }

    /// Extract client IP from session.
    ///
    /// Only reads X-Forwarded-For when `trust_proxy_headers` is enabled
    /// **and** the TCP peer address falls within `trusted_proxies` (or the
    /// list is empty, which means "trust any peer" for backwards compat).
    /// Otherwise always uses the TCP peer address.
    fn extract_client_ip(&self, session: &Session) -> std::net::IpAddr {
        // Always resolve peer address first
        let peer_ip = session.client_addr().and_then(|a| a.as_inet()).map_or(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            std::net::SocketAddr::ip,
        );

        if self.trust_proxy_headers {
            // When a trusted_proxies list is configured, only honour XFF from
            // connections that originate within those CIDR ranges.
            let peer_trusted =
                self.trusted_proxies.is_empty() || self.trusted_proxies.iter().any(|net| net.contains(&peer_ip));

            // Take the *right-most* non-empty entry rather than the left-most
            // one. The left-most value is fully client-controlled and can be
            // spoofed to bypass IP blocklists / rate limits; the right-most
            // entry is the address appended by the closest (trusted) proxy.
            if peer_trusted
                && let Some(xff) = session.get_header("x-forwarded-for")
                && let Ok(s) = std::str::from_utf8(xff.as_bytes())
                && let Some(rightmost) = s.rsplit(',').map(str::trim).find(|seg| !seg.is_empty())
                && let Ok(ip) = rightmost.parse()
            {
                return ip;
            }
        }

        peer_ip
    }

    /// Build a `RequestCtx` from the Pingora session
    fn build_request_ctx(&self, session: &Session, host_config: Arc<HostConfig>) -> RequestCtx {
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

        // Extract headers as HashMap
        let mut headers = HashMap::new();
        for (name, value) in &session.req_header().headers {
            if let Ok(v) = std::str::from_utf8(value.as_bytes()) {
                headers.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

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
    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<Box<HttpPeer>> {
        let host_config = ctx.host_config.as_ref().ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                "internal: upstream_peer reached without a resolved host",
            )
        })?;

        let use_tls = host_config.ssl;

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
                let peer = HttpPeer::new(&upstream_addr, use_tls, sni);
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
        let peer = HttpPeer::new(&upstream_addr, use_tls, host_config.remote_host.clone());
        Ok(Box::new(peer))
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<bool> {
        // ── ACME HTTP-01 challenge (M-4) ──────────────────────────────────────
        // Answer Let's Encrypt validation probes before any host routing or WAF
        // inspection. Reads only the raw request path from the session and is
        // fully decoupled from `ctx.request_ctx`.
        let challenge_token = {
            let path = session.req_header().uri.path();
            path.strip_prefix("/.well-known/acme-challenge/")
                .map(std::string::ToString::to_string)
        };
        if let Some(token) = challenge_token
            && let Some(key_auth) = self.acme_challenges.get(&token)
        {
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

        // ── Host routing (moved here from upstream_peer, C-1) ─────────────────
        let host_header = session
            .get_header("host")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        debug!("Routing request for host: {}", host_header);

        let Some(host_config) = self.router.resolve(&host_header) else {
            // Unknown host: previously fell through to a pass-through; now we
            // respond 404 so unrouted traffic is never forwarded / inspected.
            warn!("No route found for host: {host_header}");
            let response = pingora_http::ResponseHeader::build(404, None)?;
            session.write_response_header(Box::new(response), false).await?;
            session
                .write_response_body(Some(Bytes::from_static(b"Not Found")), true)
                .await?;
            return Ok(true);
        };

        // Site administratively closed → 503 (previously an opaque proxy error).
        if !host_config.start_status {
            warn!("Site closed for host: {host_header}");
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
        let mut request_ctx = self.build_request_ctx(session, host_config);
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

        if !decision.is_allowed() {
            match &decision.action {
                WafAction::Block { status, body } => {
                    warn!("WAF blocked request: ip={client_ip} path={path} host={host}");
                    let status_code = *status;
                    let body_str = body.clone().unwrap_or_else(|| "Access Denied".to_string());

                    let response = pingora_http::ResponseHeader::build(status_code, None)?;
                    session.write_response_header(Box::new(response), false).await?;
                    let body_bytes = Bytes::from(body_str);
                    session.write_response_body(Some(body_bytes), true).await?;
                    return Ok(true);
                }
                WafAction::Redirect { url } => {
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

    /// Buffer the first [`BODY_PREVIEW_LIMIT`] bytes of the request body and
    /// run WAF body-content inspection once enough data is available.
    ///
    /// This callback is invoked for each body chunk *before* it is forwarded
    /// to the upstream.  We buffer up to 64 KiB and then run a supplementary
    /// WAF check so that `SQLi` / XSS / RCE patterns in POST bodies are caught.
    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()> {
        // Only buffer when we have a request context and haven't inspected yet
        if ctx.body_inspected {
            return Ok(());
        }

        // Accumulate body bytes up to the preview limit
        if let Some(chunk) = body {
            let remaining = BODY_PREVIEW_LIMIT.saturating_sub(ctx.body_buf.len());
            if remaining > 0 {
                let take = chunk.len().min(remaining);
                if let Some(slice) = chunk.get(..take) {
                    ctx.body_buf.extend_from_slice(slice);
                }
                if take < chunk.len() {
                    debug!(
                        "Request body exceeds {BODY_PREVIEW_LIMIT} byte inspection limit; only the first {BODY_PREVIEW_LIMIT} bytes are scanned"
                    );
                }
            } else {
                debug!(
                    "Request body exceeds {BODY_PREVIEW_LIMIT} byte inspection limit; only the first {BODY_PREVIEW_LIMIT} bytes are scanned"
                );
            }
        }

        // Run body WAF check when we have enough data or at end of stream
        let should_inspect = ctx.body_buf.len() >= BODY_PREVIEW_LIMIT || (end_of_stream && !ctx.body_buf.is_empty());

        if !should_inspect {
            return Ok(());
        }

        ctx.body_inspected = true;

        // Build a RequestCtx clone with body_preview populated
        let mut request_ctx = match &ctx.request_ctx {
            Some(c) => c.clone(),
            None => return Ok(()),
        };

        request_ctx.body_preview = Bytes::copy_from_slice(&ctx.body_buf);

        // Run body-phase WAF inspection (content detectors only — CC / IP / URL
        // / geo / bouncer / community already ran once in the header phase).
        // Shares the header phase's Lane 2 budget (plan §12.3).
        let decision = self
            .engine
            .inspect_body_with_state(&mut request_ctx, &mut ctx.content_inspection)
            .await;

        if !decision.is_allowed() {
            match &decision.action {
                WafAction::Block {
                    status,
                    body: block_body,
                } => {
                    warn!(
                        "WAF blocked request (body): ip={} path={} host={}",
                        request_ctx.client_ip, request_ctx.path, request_ctx.host,
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

        Ok(())
    }

    /// Capture the upstream response headers and decide whether the body is
    /// worth buffering for a cache store. Runs only when the request was a
    /// cache-store candidate (`ctx.cache_key` set in `request_filter`).
    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
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
        if !ctx.cache_store {
            return Ok(None);
        }

        if let Some(chunk) = body {
            if ctx.cache_body.len().saturating_add(chunk.len()) > CACHE_BODY_LIMIT {
                // Response too large to cache: abandon and release the buffer.
                debug!("Response exceeds {CACHE_BODY_LIMIT} byte cache limit; not caching");
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

    async fn logging(&self, _session: &mut Session, _error: Option<&pingora_core::Error>, ctx: &mut GatewayCtx) {
        // Release the load-balanced backend's active-connection slot (paired
        // with the acquire in `upstream_peer`) so Least-Connections accounting
        // stays balanced even on errors / early termination.
        if let Some(backend) = ctx.selected_backend.take() {
            backend.release_connection();
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
