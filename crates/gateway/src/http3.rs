//! HTTP/3 (QUIC) listener using `quinn` and `h3`.
//!
//! Runs alongside the Pingora-based HTTP/1.1+TLS listener.  Sends an
//! `Alt-Svc: h3=":443"; ma=86400` header via the existing proxy so that
//! QUIC-capable clients can upgrade.
//!
//! The listener accepts QUIC connections, decodes HTTP/3 requests, runs
//! them through the WAF engine (header **and** body phases, identical to the
//! HTTP/1.1 path), and forwards allowed requests to the **per-host** upstream
//! selected by the same [`HostRouter`] that Pingora uses.  Requests whose
//! authority matches no configured route are rejected (404) and never
//! forwarded — closing the H3 detection-bypass / SSRF surface (audit H-7).
//!
//! "Authority" is deliberate: HTTP/3 has no `Host` *header*, it has an
//! `:authority` pseudo-header, and a compliant client sends only that.  See
//! [`route_authority`] for how the two are reconciled.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use bytes::{Buf, Bytes};
use tracing::{debug, info, warn};
use uuid::Uuid;

use waf_common::metrics::{self, HostSlot, RequestAction};
use waf_common::{HostConfig, RequestCtx, WafAction};
use waf_engine::WafEngine;

use crate::context::{BodyOverflowAction, BodyWindows, body_inspection_policy, fold_request_headers};
use crate::proxy::request_action_of;
use crate::router::HostRouter;
use crate::upstream_timeout::{UpstreamTimeouts, headers_are_streaming};

// ─── Limits ───────────────────────────────────────────────────────────────────

/// Absolute per-request body buffer ceiling for a single HTTP/3 request.
///
/// The H3 forwarder buffers the whole body before handing it to `reqwest`, so
/// an explicit hard cap is required to bound per-request memory regardless of
/// the configured inspection policy.  Requests exceeding this are rejected with
/// 413 rather than partially forwarded — a WAF must never relay unscanned
/// bytes.
///
/// The *inspection* ceiling is [`crate::context::BodyInspectionPolicy`], shared
/// with the HTTP/1.1 path, and defaults to the same 10 MiB so both protocols
/// behave identically out of the box.
const MAX_H3_REQUEST_BODY: usize = 10 * 1024 * 1024;

// ─── Alt-Svc header value ─────────────────────────────────────────────────────

/// Returns the `Alt-Svc` header value advertising HTTP/3 on the given port.
pub fn alt_svc_header(port: u16) -> String {
    format!("h3=\":{port}\"; ma=86400")
}

// ─── Upstream helpers ─────────────────────────────────────────────────────────

/// Scheme (`http`/`https`) to use when connecting to a host's upstream.
///
/// Delegates to [`HostConfig::upstream_uses_tls`], the same predicate
/// [`crate::proxy`] hands to `HttpPeer::new`, so the two protocols answer "is
/// the origin connection encrypted" from one place. Reading `host_config.ssl`
/// here directly is what let the site's own scheme decide the upstream's.
const fn upstream_scheme(host_config: &HostConfig) -> &'static str {
    if host_config.upstream_uses_tls() {
        "https"
    } else {
        "http"
    }
}

/// Build the absolute upstream URL for a request, using the per-host
/// `remote_host`/`remote_port` (same source as the Pingora `upstream_peer`).
///
/// This replaces the previously hard-coded `http://127.0.0.1:8080`, so H3 now
/// honours each host's configured backend just like HTTP/1.1.
fn upstream_target(host_config: &HostConfig, path_and_query: &str) -> String {
    format!(
        "{}://{}:{}{}",
        upstream_scheme(host_config),
        host_config.remote_host,
        host_config.remote_port,
        path_and_query
    )
}

/// Hop-by-hop headers (RFC 7230 §6.1) that must not cross a proxy boundary.
/// `content-length`/`host` are handled separately at each call site.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

// ─── Routing authority ────────────────────────────────────────────────────────

/// Outcome of deciding which authority a request must be routed on.
enum RouteAuthority<'a> {
    /// The authority to route on, borrowed verbatim from the request.
    Found(&'a str),
    /// An `:authority` and a `Host` were both present and disagreed.
    Contradicted,
    /// Neither carried a usable value; nothing can be routed.
    Missing,
}

/// Decide the authority an HTTP/3 request is routed on.
///
/// HTTP/3 does not carry a `Host` header. RFC 9114 §4.3.1 defines the
/// `:authority` pseudo-header and says a client that sends `:authority`
/// **SHOULD NOT** also send `Host`; `curl --http3`, Chrome and quiche-based
/// clients all send `:authority` alone. Reading `headers["host"]` therefore
/// found nothing on every compliant request, and the empty string routed to
/// `None` — a 404 for all HTTP/3 traffic.
///
/// `h3` hands the authority up in [`http::Uri`], not in the header map: its
/// `Header::into_request_parts` folds `:authority` (or, absent that, a `Host`
/// field) into `Uri::authority` and leaves the field map untouched. So the URI
/// is the authoritative source here, with the header map as the fallback for
/// callers that build a request the other way round.
///
/// The disagreement case is refused rather than resolved. `h3` 0.0.8 already
/// rejects it at decode time (`HeaderError::ContradictedAuthority`), so on
/// today's dependency this branch is belt-and-braces — but that check is an
/// internal detail of a 0.0.x crate, not a contract, and the consequence of
/// silently picking one side is a desync primitive: this WAF would apply the
/// policy of authority A while the origin resolves its vhost from the `Host`
/// line carrying B. One `!=` is a cheap price for making the choice a property
/// of this function instead of an assumption about a dependency.
fn route_authority<'a>(uri: &'a http::Uri, headers: &'a http::HeaderMap) -> RouteAuthority<'a> {
    let authority = uri
        .authority()
        .map(http::uri::Authority::as_str)
        .filter(|a| !a.is_empty());
    // First line only, which is all `h3` compares too. A request carrying more
    // than one `Host` is refused before this point (`FoldedHeaders::duplicate_host`).
    let host = headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty());

    match (authority, host) {
        // Byte-exact, matching the decoder's own comparison: `a.com` and
        // `a.com:443` are different authorities and may hold different policy.
        (Some(a), Some(h)) if a != h => RouteAuthority::Contradicted,
        (Some(a), _) => RouteAuthority::Found(a),
        (None, Some(h)) => RouteAuthority::Found(h),
        (None, None) => RouteAuthority::Missing,
    }
}

// ─── Upstream clients ─────────────────────────────────────────────────────────

/// The `reqwest` clients this connection dials upstreams with.
///
/// `[proxy.upstream_timeouts]` reaches the H3 forwarder through
/// [`UpstreamTimeouts::apply_to_reqwest`]; see that method for the
/// stage-by-stage mapping and for the two places reqwest's semantics differ
/// from Pingora's.
///
/// There are two clients rather than one because `stream_exempt` is a
/// *per-request* decision while reqwest's read timeout is a *per-client*
/// setting (`ClientBuilder::read_timeout`; `RequestBuilder` offers only a total
/// deadline). The second client is built only when the exemption can actually
/// bite, so the default install still constructs exactly one client, as before.
struct UpstreamClients {
    /// Carries every configured bound. Used for all ordinary requests.
    bounded: reqwest::Client,
    /// `bounded` minus the read timeout, for requests that
    /// [`headers_are_streaming`] flags while `stream_exempt` is on.
    exempt: Option<reqwest::Client>,
}

impl UpstreamClients {
    /// Build the client(s) for one QUIC connection.
    ///
    /// `danger_accept_invalid_certs` only relaxes verification for `https`
    /// upstreams; `http` backends are unaffected.
    fn build(upstream_tls_verify: bool, timeouts: UpstreamTimeouts) -> reqwest::Result<Self> {
        let base = || reqwest::Client::builder().danger_accept_invalid_certs(!upstream_tls_verify);

        let bounded = timeouts.apply_to_reqwest(base(), false).build()?;
        // Only worth a second client when an exemption would change something.
        let exempt = if timeouts.stream_exempt && timeouts.read.is_some() {
            Some(timeouts.apply_to_reqwest(base(), true).build()?)
        } else {
            None
        };

        Ok(Self { bounded, exempt })
    }

    /// The client to use for a request with these headers.
    fn select(&self, headers: &http::HeaderMap) -> &reqwest::Client {
        match &self.exempt {
            Some(exempt) if headers_are_streaming(headers) => exempt,
            _ => &self.bounded,
        }
    }
}

// ─── TLS config builder ───────────────────────────────────────────────────────

/// Build a `rustls::ServerConfig` suitable for QUIC (ALPN "h3").
pub fn build_tls_config(cert_pem: &str, key_pem: &str) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pki_types::pem::PemObject as _;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM")?;

    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("no private key found in PEM")?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("invalid TLS certificate / key")?;

    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(tls_config)
}

// ─── HTTP/3 server ────────────────────────────────────────────────────────────

/// Start the HTTP/3 listener.  Runs until the process exits.
///
/// Accepts `engine` and `router` so every HTTP/3 request goes through the same
/// WAF inspection pipeline and per-host routing as HTTP/1.1 traffic handled by
/// Pingora.  `upstream_tls_verify` controls whether upstream TLS certificates
/// are validated when a host's backend uses `https`.
///
/// `upstream_timeouts` is the resolved `[proxy.upstream_timeouts]`, shared with
/// the Pingora path. It defaults to unlimited, in which case the upstream
/// clients are built exactly as they always were.
pub async fn start_http3_server(
    listen_addr: SocketAddr,
    cert_pem: String,
    key_pem: String,
    upstream_tls_verify: bool,
    smuggling_detection: bool,
    engine: Arc<WafEngine>,
    router: Arc<HostRouter>,
    upstream_timeouts: UpstreamTimeouts,
) -> anyhow::Result<()> {
    if !upstream_timeouts.is_unlimited() {
        info!("HTTP/3 upstream timeouts: {}", upstream_timeouts.reqwest_summary());
        if let Some(stage) = upstream_timeouts.reqwest_unenforced() {
            warn!(
                "[proxy.upstream_timeouts] {stage} is NOT enforced on the HTTP/3 path: the H3 forwarder dials \
                 upstreams with reqwest, which has no write timeout. HTTP/1.1 and HTTP/2 are unaffected."
            );
        }
    }

    let tls_config = build_tls_config(&cert_pem, &key_pem)?;
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| anyhow::anyhow!("QUIC TLS config error: {e:?}"))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

    let endpoint = quinn::Endpoint::server(server_config, listen_addr).context("failed to bind QUIC endpoint")?;

    info!("HTTP/3 listener on {}", listen_addr);

    while let Some(incoming) = endpoint.accept().await {
        let verify_tls = upstream_tls_verify;
        let eng = Arc::clone(&engine);
        let rtr = Arc::clone(&router);
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) =
                        handle_quic_connection(conn, verify_tls, smuggling_detection, eng, rtr, upstream_timeouts).await
                    {
                        warn!("HTTP/3 connection error: {e}");
                    }
                }
                Err(e) => warn!("QUIC accept error: {e}"),
            }
        });
    }

    Ok(())
}

/// Handle a single QUIC connection — serve all HTTP/3 requests on it.
async fn handle_quic_connection(
    conn: quinn::Connection,
    upstream_tls_verify: bool,
    smuggling_detection: bool,
    engine: Arc<WafEngine>,
    router: Arc<HostRouter>,
    upstream_timeouts: UpstreamTimeouts,
) -> anyhow::Result<()> {
    let peer = conn.remote_address();
    debug!(%peer, "HTTP/3 connection accepted");

    let h3_conn = h3_quinn::Connection::new(conn);
    let mut server_conn: h3::server::Connection<_, bytes::Bytes> = h3::server::builder()
        .build(h3_conn)
        .await
        .context("h3 handshake failed")?;

    let clients = Arc::new(UpstreamClients::build(upstream_tls_verify, upstream_timeouts)?);

    loop {
        match server_conn.accept().await {
            Ok(Some(resolver)) => {
                let clients = Arc::clone(&clients);
                let eng = Arc::clone(&engine);
                let rtr = Arc::clone(&router);
                let remote = peer;
                tokio::spawn(async move {
                    // h3 0.0.8: use resolver.resolve_request() to get (req, stream)
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) =
                                handle_h3_request(req, stream, &clients, &eng, &rtr, remote, smuggling_detection).await
                            {
                                warn!("HTTP/3 request error: {e}");
                            }
                        }
                        Err(e) => warn!("H3 request resolve error: {e}"),
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                warn!("HTTP/3 accept error: {e}");
                break;
            }
        }
    }

    Ok(())
}

// ─── RED accounting ───────────────────────────────────────────────────────────

/// What one finished HTTP/3 request contributes to the RED metrics.
///
/// The HTTP/1.1 path stashes exactly these three values on `GatewayCtx` and
/// reads them back in Pingora's `logging()` callback, which runs once on every
/// completion path and is therefore the only place a per-request counter can be
/// bumped exactly once (`crate::proxy`). HTTP/3 has no such callback: the
/// forwarder does not run under Pingora at all, so there is no equivalent
/// position to record from. [`handle_h3_request`] is the stand-in — it wraps the
/// handler proper, which cannot return without passing back through it — and
/// this struct is the stand-in for the context the handler writes its verdict
/// into on the way out.
///
/// Recording at the refusal sites instead would over-count for the same reason
/// it does on HTTP/1.1: a request is decided in the header phase and again per
/// body window.
#[derive(Default)]
struct H3Outcome {
    /// Interned `host` label. Left at the `__other__` fold for a request
    /// refused before an authority was resolved, which is where the HTTP/1.1
    /// path leaves its own pre-routing refusals.
    host: HostSlot,
    /// The WAF's decision. `None` means nothing refused the request and reads
    /// as `action="allow"`, matching the HTTP/1.1 default.
    action: Option<RequestAction>,
    /// The status actually written downstream — not the one this handler
    /// intended — so an upstream 502 and a WAF 403 stay distinguishable. `None`
    /// when no response header ever went out, which is what
    /// `Session::response_written()` reports on the HTTP/1.1 path.
    status: Option<u16>,
}

/// Send a simple (self-generated) HTTP/3 response with a body and finish the
/// stream.  Used for WAF blocks, routing errors and oversized-body rejections.
///
/// Records the status into `outcome` only once the header has actually gone out,
/// so a stream that dies mid-response contributes a request and a duration but
/// no response — the same asymmetry the HTTP/1.1 path has.
async fn respond_simple<C>(
    stream: &mut h3::server::RequestStream<C, Bytes>,
    status: http::StatusCode,
    content_type: &str,
    body: Bytes,
    outcome: &mut H3Outcome,
) -> anyhow::Result<()>
where
    C: h3::quic::BidiStream<Bytes>,
{
    let response = http::Response::builder()
        .status(status)
        .header("content-length", body.len().to_string())
        .header("content-type", content_type)
        .header("server", "prx-waf/h3")
        .body(())
        .map_err(|e| anyhow::anyhow!("failed to build H3 response: {e}"))?;

    stream.send_response(response).await.context("h3 send_response")?;
    outcome.status = Some(status.as_u16());
    if !body.is_empty() {
        stream.send_data(body).await.context("h3 send_data")?;
    }
    stream.finish().await.context("h3 finish")?;
    Ok(())
}

/// Serve one HTTP/3 request and record it on the RED metrics exactly once.
///
/// This is the HTTP/3 counterpart of Pingora's `logging()` callback and exists
/// for the same reason: [`serve_h3_request`] has a dozen return paths — three
/// refusals before an authority is even settled on, two more from routing, two
/// 413s, a WAF block and a WAF redirect in each of the two inspection phases,
/// two upstream failures, the normal relay, and any `?` on the QUIC stream — and
/// every one of them has to contribute one `prxwaf_requests_total`, one duration
/// observation and at most one `prxwaf_responses_total`. Wrapping is the only
/// structure that gets that for free; a counter at each site would be a dozen
/// places to forget one.
///
/// The clock starts before routing, so the histogram covers refusals rather than
/// only the requests that reached an upstream — as it does on HTTP/1.1.
///
/// Neither protocol adds a `proto` label. See `docs/metrics.md`.
async fn handle_h3_request<C>(
    req: http::Request<()>,
    stream: h3::server::RequestStream<C, Bytes>,
    clients: &UpstreamClients,
    engine: &WafEngine,
    router: &HostRouter,
    peer: SocketAddr,
    smuggling_detection: bool,
) -> anyhow::Result<()>
where
    C: h3::quic::BidiStream<Bytes>,
{
    // `enabled()` gates the clock read itself: with metrics off this is one
    // `OnceLock` load and no `clock_gettime`, per request.
    let started = metrics::enabled().then(std::time::Instant::now);
    let mut outcome = H3Outcome::default();

    let result = serve_h3_request(
        req,
        stream,
        clients,
        engine,
        router,
        peer,
        smuggling_detection,
        &mut outcome,
    )
    .await;

    // Recorded on the error path too: a request whose QUIC stream broke still
    // happened, and dropping it would make the request count disagree with the
    // duration count under exactly the conditions worth alerting on.
    record_h3_outcome(&outcome, started);

    result
}

/// Translate one finished request's [`H3Outcome`] into the three RED series.
///
/// Split out from [`handle_h3_request`] because it is the half that can be
/// driven in a unit test: `h3::server::RequestStream` has no public constructor,
/// so the handler itself is only reachable over a real QUIC connection (see
/// `tests/e2e-http3-red-metrics.sh`), while this arithmetic — the `allow`
/// default, the response series existing only when a header went out, the shared
/// host table — is exactly where a divergence from HTTP/1.1 would hide.
fn record_h3_outcome(outcome: &H3Outcome, started: Option<std::time::Instant>) {
    if !metrics::enabled() {
        return;
    }
    metrics::record_request(outcome.host, outcome.action.unwrap_or(RequestAction::Allow));
    if let Some(status) = outcome.status {
        metrics::record_response(outcome.host, status);
    }
    if let Some(started) = started {
        metrics::record_request_duration(outcome.host, started.elapsed());
    }
}

/// Handle one HTTP/3 request: route → WAF (header + body) → forward → relay.
///
/// Mirrors the HTTP/1.1 pipeline in `proxy.rs`:
///   1. Resolve the request authority ([`route_authority`]) via the router;
///      unknown authority → 404 (no forward).  Administratively closed host →
///      503.
///   2. WAF header-phase inspection ([`WafEngine::inspect`]).
///   3. Read the request body (bounded) and run body-phase inspection
///      ([`WafEngine::inspect_body`]).
///   4. Forward the request (original headers + body) to the per-host upstream
///      and relay the upstream status / headers / body back to the client.
///
/// Writes its verdict into `outcome` as it goes; [`handle_h3_request`] turns
/// that into the metrics after this returns, however it returns.
#[allow(
    clippy::too_many_arguments,
    reason = "one accounting out-parameter past the lint's bound"
)]
async fn serve_h3_request<C>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<C, Bytes>,
    clients: &UpstreamClients,
    engine: &WafEngine,
    router: &HostRouter,
    peer: SocketAddr,
    smuggling_detection: bool,
    outcome: &mut H3Outcome,
) -> anyhow::Result<()>
where
    C: h3::quic::BidiStream<Bytes>,
{
    // ── Normalization boundary for the HTTP/3 data plane ─────────────────────
    // The QUIC listener has the same dual-stack behaviour as the TCP one: bound
    // to `[::]`, an IPv4 client's `remote_address()` comes back as
    // `::ffff:a.b.c.d`. Fold it once, here, and use `client_ip` from this point
    // on instead of `peer.ip()` — see `waf_common::net` for the invariant.
    // H3 has no X-Forwarded-For path, so unlike the HTTP/1.1 + HTTP/2 plane the
    // socket peer is the only source an address can arrive from.
    let client_ip = waf_common::net::canonicalize_client_ip(peer.ip());

    let (parts, ()) = req.into_parts();
    let path_and_query = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let method = parts.method.to_string();

    // ── Header folding (identical semantics to the HTTP/1.1 path) ────────────
    // Repeated header names are folded into one RFC-shaped value so the
    // detectors see every value, and the two abuse cases folding cannot
    // represent faithfully are refused outright.
    let folded = fold_request_headers(&parts.headers);
    if folded.duplicate_host {
        // Refused before `route_authority`, which compares `:authority` with
        // the first `Host` line only — as does the `h3` decoder.
        // No authority has been settled on, so this lands on `__other__`, which
        // is where the HTTP/1.1 path leaves the same refusal.
        outcome.action = Some(RequestAction::Block);
        warn!("Rejecting H3 request with duplicate Host headers: ip={}", client_ip);
        return respond_simple(
            &mut stream,
            http::StatusCode::BAD_REQUEST,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Bad Request"),
            outcome,
        )
        .await;
    }
    if let Some(name) = &folded.overflow {
        outcome.action = Some(RequestAction::Block);
        warn!(
            "Rejecting H3 request: header '{name}' exceeds the fold limits: ip={}",
            client_ip
        );
        return respond_simple(
            &mut stream,
            http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Request Header Fields Too Large"),
            outcome,
        )
        .await;
    }
    let mut headers = folded.headers;

    // ── Routing authority (`:authority`, not a `Host` header) ────────────────
    let authority = match route_authority(&parts.uri, &parts.headers) {
        RouteAuthority::Found(a) => a,
        RouteAuthority::Contradicted => {
            // Deliberately not attributed to either candidate: the request is
            // refused precisely because which host it addressed is unknowable,
            // and interning one of the two would put a name on the wrong site's
            // block rate.
            outcome.action = Some(RequestAction::Block);
            warn!(
                "Rejecting H3 request whose Host disagrees with :authority: ip={}",
                client_ip
            );
            return respond_simple(
                &mut stream,
                http::StatusCode::BAD_REQUEST,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"Bad Request"),
                outcome,
            )
            .await;
        }
        // Unroutable. Fall through to the router with an empty authority so
        // this lands on exactly the same 404 as an unknown host — never a
        // default config, never a forward.
        RouteAuthority::Missing => "",
    };

    // Intern the host label once, before routing, so a 404 is attributed to the
    // authority that asked for it: per-authority 404 volume is what tells an
    // operator a site is misconfigured rather than merely quiet. The empty
    // string an unroutable request carries is interned as-is, which is what the
    // HTTP/1.1 path does with a missing `Host` header, so the two protocols
    // agree on that label value too. Every host past `max_host_labels` folds
    // into `__other__` inside `resolve_host` — HTTP/3 shares that one bounded
    // table rather than keeping its own.
    outcome.host = metrics::resolve_host(authority);

    // The detectors must not see a different request depending on the wire
    // protocol: a rule that matches on the `Host` header has to fire on HTTP/3
    // too, where the same value arrives as `:authority`. `entry` rather than
    // `insert` so a client-sent `Host` — already proven byte-equal to
    // `:authority` above — is preserved exactly as it was received.
    if !authority.is_empty() {
        headers
            .entry("host".to_string())
            .or_insert_with(|| authority.to_string());
    }

    // ── Host routing (matches proxy.rs; no default-config fall-through) ──────
    let Some(host_config) = router.resolve(authority) else {
        // Unknown authority: previously this path built a default HostConfig
        // and forwarded anyway (audit H-7). Now unrouted traffic is refused and
        // never reaches an upstream.
        //
        // Counted as a block, as on HTTP/1.1: the WAF refused it and nothing
        // reached an upstream. `prxwaf_responses_total{status="4xx"}` carries
        // the 404 itself, which is what separates "refused by routing" from
        // "refused by detection".
        outcome.action = Some(RequestAction::Block);
        warn!("No H3 route found for authority: {authority}");
        return respond_simple(
            &mut stream,
            http::StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Not Found"),
            outcome,
        )
        .await;
    };

    // ── HTTP request-smuggling structural detection (shadow / log-only) ──────
    // The CL/TE desync primitives are HTTP/1.1-specific: HTTP/3 carries body
    // length via its own frame layer and forbids the `Transfer-Encoding` and
    // connection-specific headers at the protocol level (the `h3`/`http` stack
    // enforces this). The same structural detector is still applied here for
    // defence in depth — a duplicate/obfuscated framing header that somehow
    // survives into the parsed map is logged. In practice h3 requests rarely
    // trip it; the check is cheap and log-only, and never alters routing.
    if smuggling_detection {
        let findings = crate::smuggling::detect(&parts.headers);
        if !findings.is_empty() {
            crate::smuggling::log_findings(&findings, client_ip, authority, &path);
        }
    }

    // Administratively closed site → 503.
    if !host_config.start_status {
        outcome.action = Some(RequestAction::Block);
        warn!("H3 site closed for authority: {authority}");
        return respond_simple(
            &mut stream,
            http::StatusCode::SERVICE_UNAVAILABLE,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Service Unavailable"),
            outcome,
        )
        .await;
    }

    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    // Build RequestCtx for WAF inspection.
    let mut request_ctx = RequestCtx {
        req_id: Uuid::new_v4().to_string(),
        client_ip,
        client_port: peer.port(),
        method,
        host: host_config.host.clone(),
        port: host_config.port,
        path,
        query,
        headers,
        body_preview: Bytes::new(),
        content_length,
        is_tls: true, // QUIC is always encrypted
        host_config: Arc::clone(&host_config),
        geo: None,
    };

    // ── WAF header-phase inspection ─────────────────────────────────────────
    // HTTP/3 has no GatewayCtx, so the Lane 2 budget lives in a local instance
    // reused across the header and body phases (plan §12.3).
    let mut content_inspection = engine.new_content_inspection_state();
    let decision = engine
        .inspect_with_state(&mut request_ctx, &mut content_inspection)
        .await;
    // Recorded even when the decision allows: `log_only` is an allow for the
    // request and a detection for the operator, and conflating the two is what
    // makes a shadow rollout unreadable. `request_action_of` is the HTTP/1.1
    // mapping, imported rather than restated.
    if let Some(action) = request_action_of(&decision.action) {
        outcome.action = Some(action);
    }
    if !decision.is_allowed()
        && let Some(handled) = respond_waf_action(&mut stream, &decision.action, &request_ctx, outcome).await?
    {
        return handled;
    }

    // ── Read the request body (bounded) ─────────────────────────────────────
    let mut body_buf: Vec<u8> = Vec::new();
    let mut too_large = false;
    loop {
        let chunk = stream.recv_data().await.context("reading H3 request body")?;
        let Some(mut buf) = chunk else { break };
        while buf.has_remaining() {
            let slice = buf.chunk();
            let n = slice.len();
            if body_buf.len() + n > MAX_H3_REQUEST_BODY {
                too_large = true;
                break;
            }
            body_buf.extend_from_slice(slice);
            buf.advance(n);
        }
        if too_large {
            break;
        }
    }

    if too_large {
        metrics::record_budget_event(metrics::BudgetEvent::Http3BodyRejected);
        // A refusal, so a block — the same label the HTTP/1.1 path puts on its
        // own over-ceiling body rejection.
        outcome.action = Some(RequestAction::Block);
        warn!(
            "H3 request body exceeds {} byte limit: ip={} host={}",
            MAX_H3_REQUEST_BODY, request_ctx.client_ip, request_ctx.host,
        );
        return respond_simple(
            &mut stream,
            http::StatusCode::PAYLOAD_TOO_LARGE,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Payload Too Large"),
            outcome,
        )
        .await;
    }

    // ── WAF body-phase inspection ───────────────────────────────────────────
    // The whole buffered body is scanned in overlapping windows — the same
    // window size, overlap and inspected-byte ceiling the HTTP/1.1 path uses —
    // so padding the front of the body with harmless bytes cannot push the
    // payload past the scanner on either protocol.
    if !body_buf.is_empty() {
        let policy = body_inspection_policy();
        let ceiling = policy.max_total_bytes;
        if ceiling > 0 && body_buf.len() > ceiling {
            if policy.overflow == BodyOverflowAction::Reject {
                outcome.action = Some(RequestAction::Block);
                warn!(
                    "H3 request body ({} bytes) exceeds the {ceiling} byte inspection ceiling: ip={} host={}",
                    body_buf.len(),
                    request_ctx.client_ip,
                    request_ctx.host,
                );
                return respond_simple(
                    &mut stream,
                    http::StatusCode::PAYLOAD_TOO_LARGE,
                    "text/plain; charset=utf-8",
                    Bytes::from_static(b"Payload Too Large"),
                    outcome,
                )
                .await;
            }
            warn!(
                "H3 request body ({} bytes) exceeds the {ceiling} byte inspection ceiling; the remainder is forwarded \
                 UNINSPECTED (PRXWAF_BODY_INSPECT_OVERFLOW=log): ip={} host={}",
                body_buf.len(),
                request_ctx.client_ip,
                request_ctx.host,
            );
        }

        request_ctx.content_length = body_buf.len() as u64;
        let inspect_len = if ceiling > 0 {
            body_buf.len().min(ceiling)
        } else {
            body_buf.len()
        };
        let inspectable = body_buf.get(..inspect_len).unwrap_or(&body_buf);

        for window in BodyWindows::with_policy(inspectable, policy) {
            request_ctx.body_preview = Bytes::copy_from_slice(window);
            let decision = engine
                .inspect_body_with_state(&mut request_ctx, &mut content_inspection)
                .await;
            // A window that allows leaves an earlier phase's real decision
            // standing — `request_action_of` returns `None` for a plain allow
            // precisely so this loop cannot erase it.
            if let Some(action) = request_action_of(&decision.action) {
                outcome.action = Some(action);
            }
            if !decision.is_allowed()
                && let Some(handled) = respond_waf_action(&mut stream, &decision.action, &request_ctx, outcome).await?
            {
                return handled;
            }
        }
    }

    // ── Forward the request to the per-host upstream ────────────────────────
    let target = upstream_target(&host_config, &path_and_query);
    debug!(method = %request_ctx.method, %target, "HTTP/3 → upstream");

    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).context("invalid H3 method")?;
    let mut req_builder = clients.select(&parts.headers).request(method, &target);
    for (name, value) in &parts.headers {
        let key = name.as_str();
        // Skip hop-by-hop headers and content-length (reqwest sets it from the
        // body). `host` is re-derived below from the routed authority.
        if is_hop_by_hop(key) || key.eq_ignore_ascii_case("content-length") || key.eq_ignore_ascii_case("host") {
            continue;
        }
        req_builder = req_builder.header(key, value.as_bytes());
    }
    // Name the origin's vhost with the authority this request was routed on.
    // A compliant HTTP/3 client sends no Host line, so left alone reqwest
    // derives one from the *upstream* address and a name-based origin serves
    // the wrong site. Deriving it from the routed authority also makes the two
    // impossible to disagree: whatever vhost the origin picks is the one whose
    // policy the WAF just applied. The value is either a parsed
    // `http::uri::Authority` or a `HeaderValue` the client already sent, so it
    // cannot carry a control character into the upstream request.
    if !authority.is_empty() {
        match http::HeaderValue::from_str(authority) {
            Ok(value) => req_builder = req_builder.header(http::header::HOST, value),
            // Unreachable for anything h3 decoded — an authority holds no
            // character a header value forbids. Record it instead of letting
            // reqwest quietly substitute the backend address.
            Err(e) => warn!("H3 authority '{authority}' is not a representable Host value: {e}"),
        }
    }
    if !body_buf.is_empty() {
        req_builder = req_builder.body(body_buf);
    }

    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            // The decision stands as an allow: the WAF let this through and the
            // upstream failed. `prxwaf_responses_total{status="5xx"}` carries
            // the 502, and the pair of series is what tells the two apart.
            log_upstream_failure(&e, &request_ctx.host, &target, "request");
            return respond_simple(
                &mut stream,
                http::StatusCode::BAD_GATEWAY,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"Bad Gateway"),
                outcome,
            )
            .await;
        }
    };

    // ── Relay the upstream response (status + headers + body) ───────────────
    let status = http::StatusCode::from_u16(resp.status().as_u16()).context("invalid upstream status")?;
    let upstream_headers = resp.headers().clone();
    // A `read_ms` expiry mid-body lands here. Answer it the same way as a
    // failed send — one 502, one record — rather than dropping the stream with
    // no response at all.
    let body_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            log_upstream_failure(&e, &request_ctx.host, &target, "response body");
            return respond_simple(
                &mut stream,
                http::StatusCode::BAD_GATEWAY,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"Bad Gateway"),
                outcome,
            )
            .await;
        }
    };

    let mut builder = http::Response::builder().status(status);
    for (name, value) in &upstream_headers {
        let key = name.as_str();
        // Drop hop-by-hop and length/framing headers; we set content-length
        // from the buffered body ourselves.
        if is_hop_by_hop(key) || key.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(key, value.as_bytes());
    }
    let response = builder
        .header("content-length", body_bytes.len().to_string())
        .body(())
        .map_err(|e| anyhow::anyhow!("failed to build H3 response: {e}"))?;

    stream.send_response(response).await.context("h3 send_response")?;
    // The upstream's status, not this handler's — an origin 500 relayed intact
    // must show up as a 5xx even though the WAF's own decision was an allow.
    outcome.status = Some(status.as_u16());
    if !body_bytes.is_empty() {
        stream.send_data(body_bytes).await.context("h3 send_data")?;
    }
    stream.finish().await.context("h3 finish")?;

    Ok(())
}

/// Record an upstream failure on the H3 path.
///
/// A timeout is separated out and logged at target `waf.upstream_timeout` —
/// the same target the Pingora path uses (`crate::proxy`) — so one query finds
/// every expiry regardless of which protocol the client spoke. `phase` names
/// where it bit ("request" covers connect + send, "response body" the relay).
fn log_upstream_failure(err: &reqwest::Error, host: &str, target: &str, phase: &str) {
    if err.is_timeout() {
        warn!(
            target: "waf.upstream_timeout",
            "H3 upstream timed out during {phase}: host={host} target={target} err={err}; \
             bound by [proxy.upstream_timeouts]"
        );
    } else {
        warn!("H3 upstream {phase} failed: host={host} target={target} err={err}");
    }
}

/// Emit the client response for a non-allow WAF decision.
///
/// Returns `Ok(Some(Ok(())))` when the action produced a terminal response
/// (Block / Redirect) — the caller must then return.  Returns `Ok(None)` for
/// non-terminal actions (e.g. `LogOnly`) so the caller continues forwarding.
async fn respond_waf_action<C>(
    stream: &mut h3::server::RequestStream<C, Bytes>,
    action: &WafAction,
    ctx: &RequestCtx,
    outcome: &mut H3Outcome,
) -> anyhow::Result<Option<anyhow::Result<()>>>
where
    C: h3::quic::BidiStream<Bytes>,
{
    match action {
        WafAction::Block { status, body } => {
            warn!(
                "WAF blocked HTTP/3 request: ip={} path={} host={}",
                ctx.client_ip, ctx.path, ctx.host,
            );
            let status_code = http::StatusCode::from_u16(*status).unwrap_or(http::StatusCode::FORBIDDEN);
            let body_str = body.clone().unwrap_or_else(|| "Access Denied".to_string());
            let result = respond_simple(
                stream,
                status_code,
                "text/html; charset=utf-8",
                Bytes::from(body_str),
                outcome,
            )
            .await;
            Ok(Some(result))
        }
        WafAction::Redirect { url } => {
            let response = http::Response::builder()
                .status(http::StatusCode::FOUND)
                .header("location", url.as_str())
                .header("content-length", "0")
                .header("server", "prx-waf/h3")
                .body(())
                .map_err(|e| anyhow::anyhow!("failed to build H3 redirect response: {e}"))?;
            let result = async {
                stream.send_response(response).await.context("h3 send_response")?;
                outcome.status = Some(http::StatusCode::FOUND.as_u16());
                stream.finish().await.context("h3 finish")?;
                Ok(())
            }
            .await;
            Ok(Some(result))
        }
        // Allow / LogOnly are not terminal — keep forwarding.
        WafAction::Allow | WafAction::LogOnly => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::HostConfig;

    fn host_cfg(host: &str, remote_host: &str, remote_port: u16, ssl: bool) -> Arc<HostConfig> {
        Arc::new(HostConfig {
            host: host.to_string(),
            port: if ssl { 443 } else { 80 },
            ssl,
            remote_host: remote_host.to_string(),
            remote_port,
            start_status: true,
            ..HostConfig::default()
        })
    }

    #[test]
    fn alt_svc_header_formats_port() {
        assert_eq!(alt_svc_header(443), "h3=\":443\"; ma=86400");
    }

    #[test]
    fn upstream_target_uses_per_host_http_backend() {
        let cfg = host_cfg("a.com", "10.0.0.5", 9000, false);
        assert_eq!(upstream_target(&cfg, "/x?y=1"), "http://10.0.0.5:9000/x?y=1");
    }

    #[test]
    fn upstream_target_uses_https_when_ssl() {
        let cfg = host_cfg("a.com", "backend", 8443, true);
        assert_eq!(upstream_target(&cfg, "/"), "https://backend:8443/");
    }

    /// The commonest reverse proxy there is: TLS at the edge, plaintext origin.
    /// `ssl = true` alone sends `https://` at a backend that does not speak it
    /// and the request 502s, so `upstream_ssl = false` has to override it.
    #[test]
    fn upstream_ssl_false_overrides_a_tls_site() {
        let mut cfg = HostConfig {
            host: "a.com".to_string(),
            port: 443,
            ssl: true,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8080,
            start_status: true,
            ..HostConfig::default()
        };
        assert_eq!(upstream_target(&Arc::new(cfg.clone()), "/"), "https://127.0.0.1:8080/");
        cfg.upstream_ssl = Some(false);
        assert_eq!(upstream_target(&Arc::new(cfg), "/"), "http://127.0.0.1:8080/");
    }

    /// And the other direction: a plaintext listener in front of a TLS origin.
    #[test]
    fn upstream_ssl_true_overrides_a_plaintext_site() {
        let cfg = HostConfig {
            host: "a.com".to_string(),
            port: 80,
            ssl: false,
            upstream_ssl: Some(true),
            remote_host: "origin.internal".to_string(),
            remote_port: 8443,
            start_status: true,
            ..HostConfig::default()
        };
        assert_eq!(upstream_target(&Arc::new(cfg), "/"), "https://origin.internal:8443/");
    }

    #[test]
    fn upstream_target_is_not_hardcoded_loopback() {
        // Regression guard for audit H-7: H3 must not forward to 127.0.0.1:8080.
        let cfg = host_cfg("a.com", "192.168.1.10", 3000, false);
        let target = upstream_target(&cfg, "/api");
        assert!(!target.contains("127.0.0.1:8080"), "target still hard-coded: {target}");
        assert_eq!(target, "http://192.168.1.10:3000/api");
    }

    #[test]
    fn unknown_host_does_not_resolve() {
        let router = HostRouter::new();
        router.register(&host_cfg("known.com", "10.0.0.1", 8080, false));
        assert!(router.resolve("known.com").is_some());
        // Unknown host resolves to None → handler returns 404, no forward.
        assert!(router.resolve("evil.com").is_none());
    }

    #[test]
    fn resolved_backend_is_per_host() {
        let router = HostRouter::new();
        router.register(&host_cfg("a.com", "10.0.0.1", 1111, false));
        router.register(&host_cfg("b.com", "10.0.0.2", 2222, false));
        let a = router.resolve("a.com").expect("a route");
        let b = router.resolve("b.com").expect("b route");
        assert_eq!(upstream_target(&a, "/"), "http://10.0.0.1:1111/");
        assert_eq!(upstream_target(&b, "/"), "http://10.0.0.2:2222/");
    }

    // ── Routing authority ───────────────────────────────────────────────────

    /// Build the `(uri, headers)` pair a request with these two fields
    /// produces, so each case names only what the client actually sent.
    fn authority_of(pseudo_authority: Option<&str>, host_field: Option<&str>) -> Option<String> {
        // `h3` builds exactly this shape: scheme + authority + path, with the
        // authority coming from `:authority` (or, absent that, from `Host`).
        let uri: http::Uri = pseudo_authority.map_or_else(
            || http::Uri::from_static("/x"),
            |a| format!("https://{a}/x").parse().expect("valid uri"),
        );

        let mut map = http::HeaderMap::new();
        if let Some(h) = host_field {
            let value = http::HeaderValue::from_str(h).expect("valid header value");
            map.insert(http::header::HOST, value);
        }

        match route_authority(&uri, &map) {
            RouteAuthority::Found(a) => Some(a.to_string()),
            RouteAuthority::Contradicted => Some("<contradicted>".to_string()),
            RouteAuthority::Missing => None,
        }
    }

    /// The regression this whole path exists for: a compliant HTTP/3 client
    /// sends `:authority` and no `Host` at all. Reading the header map found
    /// nothing and every such request 404'd.
    #[test]
    fn authority_pseudo_header_alone_is_routable() {
        assert_eq!(authority_of(Some("a.com"), None).as_deref(), Some("a.com"));
    }

    /// A `Host` with no `:authority` still routes — `h3` folds it into the URI
    /// on the way in, and a caller that does not gets the header-map fallback.
    #[test]
    fn host_header_alone_is_routable() {
        assert_eq!(authority_of(None, Some("a.com")).as_deref(), Some("a.com"));
    }

    /// Both present and equal: route on it, once.
    #[test]
    fn agreeing_authority_and_host_route_on_that_value() {
        assert_eq!(authority_of(Some("a.com"), Some("a.com")).as_deref(), Some("a.com"));
    }

    /// Both present and different is a desync primitive, not a preference:
    /// refuse rather than pick a side. Byte-exact, so a port that appears on
    /// only one of the two counts as a disagreement.
    #[test]
    fn contradicting_authority_and_host_are_refused() {
        assert_eq!(
            authority_of(Some("a.com"), Some("evil.com")).as_deref(),
            Some("<contradicted>")
        );
        assert_eq!(
            authority_of(Some("a.com"), Some("a.com:443")).as_deref(),
            Some("<contradicted>")
        );
    }

    /// Neither present: nothing to route on. The handler turns this into the
    /// unknown-authority 404 rather than a default config.
    #[test]
    fn missing_authority_and_host_yields_nothing() {
        assert!(authority_of(None, None).is_none());
        // And the empty authority the handler then routes with resolves to no
        // host, so the request is never forwarded.
        let router = HostRouter::new();
        router.register(&host_cfg("known.com", "10.0.0.1", 8080, false));
        assert!(router.resolve("").is_none());
    }

    /// An empty `Host` line is "no host", not an empty authority to route on.
    #[test]
    fn empty_host_field_falls_back_to_the_pseudo_header() {
        assert_eq!(authority_of(Some("a.com"), Some("")).as_deref(), Some("a.com"));
        assert!(authority_of(None, Some("")).is_none());
    }

    /// The authority is routed verbatim, so the router's port rules (and its
    /// refusal to fall through on a non-default port) apply to HTTP/3 exactly
    /// as they do to HTTP/1.1.
    #[test]
    fn authority_with_a_port_routes_through_the_same_rules() {
        let router = HostRouter::new();
        router.register(&host_cfg("a.com", "10.0.0.1", 8080, false));

        let resolves = |pseudo: &str| {
            authority_of(Some(pseudo), None)
                .and_then(|a| router.resolve(&a))
                .is_some()
        };
        assert!(resolves("a.com"));
        assert!(resolves("a.com:443"));
        assert!(!resolves("a.com:31337"));
        assert!(!resolves("evil.com"));
    }

    // ── Upstream client selection ───────────────────────────────────────────

    /// `reqwest` builds panic without a process-level `CryptoProvider` under
    /// the workspace's `rustls-no-provider` feature; the daemon installs one at
    /// `crates/prx-waf/src/main.rs:344`.
    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn timeouts(cfg: waf_common::UpstreamTimeoutConfig) -> UpstreamTimeouts {
        UpstreamTimeouts::from_config(&cfg)
    }

    fn headers(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        for (k, v) in pairs {
            let name = http::HeaderName::from_bytes(k.as_bytes()).expect("valid header name");
            let value = http::HeaderValue::from_str(v).expect("valid header value");
            map.insert(name, value);
        }
        map
    }

    /// The shipped default must build exactly one client, as it always has —
    /// no second client, and therefore no possible change of behaviour.
    #[test]
    fn default_config_builds_a_single_unbounded_client() {
        install_crypto_provider();
        let clients =
            UpstreamClients::build(true, timeouts(waf_common::UpstreamTimeoutConfig::default())).expect("build");
        assert!(clients.exempt.is_none());
        assert!(std::ptr::eq(
            clients.select(&headers(&[("accept", "text/event-stream")])),
            &raw const clients.bounded
        ));
    }

    /// A read bound without the exemption also needs only one client: every
    /// request, streaming or not, is bounded.
    #[test]
    fn read_bound_without_exemption_builds_a_single_client() {
        install_crypto_provider();
        let clients = UpstreamClients::build(
            true,
            timeouts(waf_common::UpstreamTimeoutConfig {
                read_ms: 2000,
                ..waf_common::UpstreamTimeoutConfig::default()
            }),
        )
        .expect("build");
        assert!(clients.exempt.is_none());
    }

    /// `stream_exempt` on with a read bound: two clients, and the streaming
    /// request is routed to the exempt one while everything else is not.
    #[test]
    fn stream_exempt_routes_streaming_requests_to_the_exempt_client() {
        install_crypto_provider();
        let clients = UpstreamClients::build(
            true,
            timeouts(waf_common::UpstreamTimeoutConfig {
                read_ms: 2000,
                stream_exempt: true,
                ..waf_common::UpstreamTimeoutConfig::default()
            }),
        )
        .expect("build");
        let exempt = clients.exempt.as_ref().expect("exempt client must exist");

        for streaming in [
            headers(&[("upgrade", "websocket")]),
            headers(&[("accept", "text/html, text/event-stream;q=0.9")]),
        ] {
            assert!(std::ptr::eq(clients.select(&streaming), exempt));
        }
        for ordinary in [headers(&[]), headers(&[("accept", "application/json")])] {
            assert!(std::ptr::eq(clients.select(&ordinary), &raw const clients.bounded));
        }
    }

    /// The exemption is pointless without a read bound to exempt from, so no
    /// second client is built for it.
    #[test]
    fn stream_exempt_without_a_read_bound_builds_a_single_client() {
        install_crypto_provider();
        let clients = UpstreamClients::build(
            true,
            timeouts(waf_common::UpstreamTimeoutConfig {
                connect_ms: 1000,
                stream_exempt: true,
                ..waf_common::UpstreamTimeoutConfig::default()
            }),
        )
        .expect("build");
        assert!(clients.exempt.is_none());
    }

    // ── RED accounting ──────────────────────────────────────────────────────

    /// Count of one `name{labels} value` series in a scrape, or 0 when the
    /// series is absent — a counter that has never been touched is not exported.
    fn series(text: &str, name: &str, labels: &str) -> u64 {
        let prefix = format!("{name}{{{labels}}} ");
        text.lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }

    /// Every H3 return path, recorded once each, lands on the labels the
    /// HTTP/1.1 path would have used for the same outcome.
    ///
    /// One test rather than several: `waf_common::metrics` is a process-global
    /// registry, so two tests recording into it concurrently would each see the
    /// other's counts. The whole table is driven here and asserted once.
    ///
    /// This proves the translation, not the wiring — that each request passes
    /// through it exactly once is a property of the real handler and is asserted
    /// against a live QUIC client in `tests/e2e-http3-red-metrics.sh`.
    #[test]
    fn every_h3_return_path_records_the_labels_http1_would_have() {
        assert!(
            waf_common::metrics::init(&waf_common::metrics::MetricsConfig::default()),
            "no other gateway test may initialise the global registry"
        );

        let host = waf_common::metrics::resolve_host("h3.test");
        // The refusals that happen before an authority is settled on keep the
        // default slot, which is the `__other__` fold.
        let unrouted = HostSlot::default();

        // (host, action, status, times) — one row per return path of
        // `serve_h3_request`, in the order they appear in it.
        let paths: &[(HostSlot, Option<RequestAction>, Option<u16>, usize)] = &[
            // duplicate Host → 400
            (unrouted, Some(RequestAction::Block), Some(400), 1),
            // header fold overflow → 431
            (unrouted, Some(RequestAction::Block), Some(431), 1),
            // :authority contradicted by Host → 400
            (unrouted, Some(RequestAction::Block), Some(400), 1),
            // unknown authority → 404
            (host, Some(RequestAction::Block), Some(404), 2),
            // site administratively closed → 503
            (host, Some(RequestAction::Block), Some(503), 1),
            // WAF header- or body-phase block → the rule's status
            (host, Some(RequestAction::Block), Some(403), 1),
            // WAF redirect
            (host, Some(RequestAction::Redirect), Some(302), 1),
            // body over the hard cap / inspection ceiling → 413
            (host, Some(RequestAction::Block), Some(413), 1),
            // log-only detection: an allow for the request, a detection for the
            // operator, and the two must not be conflated
            (host, Some(RequestAction::LogOnly), Some(200), 1),
            // upstream unreachable → 502, still an allow decision
            (host, None, Some(502), 1),
            // normal relay
            (host, None, Some(200), 3),
            // the stream died before a response header went out: a request and
            // a duration, no response
            (host, None, None, 1),
        ];

        let mut sent = 0;
        for &(host, action, status, times) in paths {
            for _ in 0..times {
                record_h3_outcome(&H3Outcome { host, action, status }, Some(std::time::Instant::now()));
                sent += 1;
            }
        }

        let text = waf_common::metrics::encode()
            .expect("metrics are enabled")
            .expect("encode");

        // Requests, by action. 15 sent, 15 counted, none twice.
        let routed = r#"host="h3.test""#;
        let other = r#"host="__other__""#;
        assert_eq!(
            series(&text, "prxwaf_requests_total", &format!("{other},action=\"block\"")),
            3
        );
        assert_eq!(
            series(&text, "prxwaf_requests_total", &format!("{routed},action=\"block\"")),
            5
        );
        assert_eq!(
            series(&text, "prxwaf_requests_total", &format!("{routed},action=\"redirect\"")),
            1
        );
        assert_eq!(
            series(&text, "prxwaf_requests_total", &format!("{routed},action=\"log_only\"")),
            1
        );
        // 5 allow: the 502, the three relays and the aborted stream. The
        // log_only row is not one of them — that is the distinction the two
        // series exist to keep.
        assert_eq!(
            series(&text, "prxwaf_requests_total", &format!("{routed},action=\"allow\"")),
            5
        );

        let total: u64 = ["allow", "block", "log_only", "redirect"]
            .iter()
            .flat_map(|action| [other, routed].map(|host| format!("{host},action=\"{action}\"")))
            .map(|labels| series(&text, "prxwaf_requests_total", &labels))
            .sum();
        assert_eq!(total, sent, "one request in, one counted");

        // Responses, by class. One fewer than the requests: the row whose
        // stream died wrote no header.
        assert_eq!(
            series(&text, "prxwaf_responses_total", &format!("{other},status=\"4xx\"")),
            3
        );
        assert_eq!(
            series(&text, "prxwaf_responses_total", &format!("{routed},status=\"2xx\"")),
            4
        );
        assert_eq!(
            series(&text, "prxwaf_responses_total", &format!("{routed},status=\"3xx\"")),
            1
        );
        assert_eq!(
            series(&text, "prxwaf_responses_total", &format!("{routed},status=\"4xx\"")),
            4
        );
        assert_eq!(
            series(&text, "prxwaf_responses_total", &format!("{routed},status=\"5xx\"")),
            2
        );

        let responses: u64 = ["1xx", "2xx", "3xx", "4xx", "5xx"]
            .iter()
            .flat_map(|class| [other, routed].map(|host| format!("{host},status=\"{class}\"")))
            .map(|labels| series(&text, "prxwaf_responses_total", &labels))
            .sum();
        assert_eq!(responses, sent - 1, "every request but the aborted one wrote a status");

        // Durations: one observation per request, refusals included.
        assert_eq!(
            series(&text, "prxwaf_request_duration_seconds_count", routed)
                + series(&text, "prxwaf_request_duration_seconds_count", other),
            sent,
        );

        // The host label came from the shared bounded table, not a second one,
        // so `max_host_labels` governs HTTP/3 as well.
        assert_eq!(waf_common::metrics::resolve_host("h3.test"), host);
    }

    /// The default an unfinished outcome carries is the HTTP/1.1 default:
    /// nothing refused the request, so it is an allow, attributed to the fold.
    #[test]
    fn a_request_no_path_decided_is_an_allow_on_the_fold() {
        let outcome = H3Outcome::default();
        assert_eq!(outcome.action.unwrap_or(RequestAction::Allow), RequestAction::Allow);
        assert_eq!(outcome.host, HostSlot::default());
        assert!(outcome.status.is_none());
    }

    /// The WAF-decision → label mapping is the HTTP/1.1 one, imported rather
    /// than restated, so `action="block"` cannot come to mean two things.
    #[test]
    fn the_action_mapping_is_shared_with_http1() {
        assert_eq!(request_action_of(&WafAction::Allow), None);
        assert_eq!(
            request_action_of(&WafAction::Block {
                status: 403,
                body: None
            }),
            Some(RequestAction::Block)
        );
        assert_eq!(request_action_of(&WafAction::LogOnly), Some(RequestAction::LogOnly));
        assert_eq!(
            request_action_of(&WafAction::Redirect {
                url: "https://example.test/".to_string()
            }),
            Some(RequestAction::Redirect)
        );
    }

    #[test]
    fn hop_by_hop_filter() {
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("transfer-encoding"));
        assert!(is_hop_by_hop("upgrade"));
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("x-custom"));
        // content-length / host are handled explicitly, not via this filter.
        assert!(!is_hop_by_hop("content-length"));
        assert!(!is_hop_by_hop("host"));
    }
}
