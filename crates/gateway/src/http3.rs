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
//! `Host` header matches no configured route are rejected (404) and never
//! forwarded — closing the H3 detection-bypass / SSRF surface (audit H-7).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use bytes::{Buf, Bytes};
use tracing::{debug, info, warn};
use uuid::Uuid;

use waf_common::{HostConfig, RequestCtx, WafAction};
use waf_engine::WafEngine;

use crate::context::BODY_PREVIEW_LIMIT;
use crate::router::HostRouter;

// ─── Limits ───────────────────────────────────────────────────────────────────

/// Maximum request-body bytes buffered for a single HTTP/3 request.
///
/// Unlike the Pingora path (which streams the body to the upstream while
/// inspecting only the first [`BODY_PREVIEW_LIMIT`] bytes), the H3 forwarder
/// buffers the whole body before handing it to `reqwest`, so an explicit hard
/// cap is required to bound per-request memory.  Requests exceeding this are
/// rejected with 413 rather than partially forwarded — a WAF must never relay
/// unscanned bytes.  Inspection still only looks at the first
/// [`BODY_PREVIEW_LIMIT`] bytes, matching the HTTP/1.1 behaviour.
const MAX_H3_REQUEST_BODY: usize = 10 * 1024 * 1024;

// ─── Alt-Svc header value ─────────────────────────────────────────────────────

/// Returns the `Alt-Svc` header value advertising HTTP/3 on the given port.
pub fn alt_svc_header(port: u16) -> String {
    format!("h3=\":{port}\"; ma=86400")
}

// ─── Upstream helpers ─────────────────────────────────────────────────────────

/// Scheme (`http`/`https`) to use when connecting to a host's upstream.
const fn upstream_scheme(host_config: &HostConfig) -> &'static str {
    if host_config.ssl { "https" } else { "http" }
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
pub async fn start_http3_server(
    listen_addr: SocketAddr,
    cert_pem: String,
    key_pem: String,
    upstream_tls_verify: bool,
    engine: Arc<WafEngine>,
    router: Arc<HostRouter>,
) -> anyhow::Result<()> {
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
                    if let Err(e) = handle_quic_connection(conn, verify_tls, eng, rtr).await {
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
    engine: Arc<WafEngine>,
    router: Arc<HostRouter>,
) -> anyhow::Result<()> {
    let peer = conn.remote_address();
    debug!(%peer, "HTTP/3 connection accepted");

    let h3_conn = h3_quinn::Connection::new(conn);
    let mut server_conn: h3::server::Connection<_, bytes::Bytes> = h3::server::builder()
        .build(h3_conn)
        .await
        .context("h3 handshake failed")?;

    // `danger_accept_invalid_certs` only relaxes verification for `https`
    // upstreams; `http` backends are unaffected.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!upstream_tls_verify)
        .build()?;

    loop {
        match server_conn.accept().await {
            Ok(Some(resolver)) => {
                let client = client.clone();
                let eng = Arc::clone(&engine);
                let rtr = Arc::clone(&router);
                let remote = peer;
                tokio::spawn(async move {
                    // h3 0.0.8: use resolver.resolve_request() to get (req, stream)
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(req, stream, &client, &eng, &rtr, remote).await {
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

/// Send a simple (self-generated) HTTP/3 response with a body and finish the
/// stream.  Used for WAF blocks, routing errors and oversized-body rejections.
async fn respond_simple<C>(
    stream: &mut h3::server::RequestStream<C, Bytes>,
    status: http::StatusCode,
    content_type: &str,
    body: Bytes,
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
    if !body.is_empty() {
        stream.send_data(body).await.context("h3 send_data")?;
    }
    stream.finish().await.context("h3 finish")?;
    Ok(())
}

/// Handle one HTTP/3 request: route → WAF (header + body) → forward → relay.
///
/// Mirrors the HTTP/1.1 pipeline in `proxy.rs`:
///   1. Resolve the `Host` header via the router; unknown host → 404 (no
///      forward).  Administratively closed host → 503.
///   2. WAF header-phase inspection ([`WafEngine::inspect`]).
///   3. Read the request body (bounded) and run body-phase inspection
///      ([`WafEngine::inspect_body`]).
///   4. Forward the request (original headers + body) to the per-host upstream
///      and relay the upstream status / headers / body back to the client.
async fn handle_h3_request<C>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<C, Bytes>,
    client: &reqwest::Client,
    engine: &WafEngine,
    router: &HostRouter,
    peer: SocketAddr,
) -> anyhow::Result<()>
where
    C: h3::quic::BidiStream<Bytes>,
{
    let (parts, ()) = req.into_parts();
    let path_and_query = parts.uri.path_and_query().map_or("/", |p| p.as_str()).to_string();
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let method = parts.method.to_string();

    // Extract Host header for route resolution.
    let host_header = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // ── Host routing (matches proxy.rs; no default-config fall-through) ──────
    let Some(host_config) = router.resolve(host_header) else {
        // Unknown host: previously this path built a default HostConfig and
        // forwarded anyway (audit H-7). Now unrouted traffic is refused and
        // never reaches an upstream.
        warn!("No H3 route found for host: {host_header}");
        return respond_simple(
            &mut stream,
            http::StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Not Found"),
        )
        .await;
    };

    // Administratively closed site → 503.
    if !host_config.start_status {
        warn!("H3 site closed for host: {host_header}");
        return respond_simple(
            &mut stream,
            http::StatusCode::SERVICE_UNAVAILABLE,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Service Unavailable"),
        )
        .await;
    }

    // Build request headers map (lower-cased keys, like the Pingora path).
    let mut headers = std::collections::HashMap::new();
    for (name, value) in &parts.headers {
        if let Ok(v) = std::str::from_utf8(value.as_bytes()) {
            headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    // Build RequestCtx for WAF inspection.
    let mut request_ctx = RequestCtx {
        req_id: Uuid::new_v4().to_string(),
        client_ip: peer.ip(),
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
    let decision = engine.inspect(&mut request_ctx).await;
    if !decision.is_allowed()
        && let Some(handled) = respond_waf_action(&mut stream, &decision.action, &request_ctx).await?
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
        warn!(
            "H3 request body exceeds {} byte limit: ip={} host={}",
            MAX_H3_REQUEST_BODY, request_ctx.client_ip, request_ctx.host,
        );
        return respond_simple(
            &mut stream,
            http::StatusCode::PAYLOAD_TOO_LARGE,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Payload Too Large"),
        )
        .await;
    }

    // ── WAF body-phase inspection ───────────────────────────────────────────
    if !body_buf.is_empty() {
        let preview_len = body_buf.len().min(BODY_PREVIEW_LIMIT);
        let preview = body_buf.get(..preview_len).unwrap_or(&body_buf);
        request_ctx.body_preview = Bytes::copy_from_slice(preview);
        request_ctx.content_length = body_buf.len() as u64;

        let decision = engine.inspect_body(&mut request_ctx).await;
        if !decision.is_allowed()
            && let Some(handled) = respond_waf_action(&mut stream, &decision.action, &request_ctx).await?
        {
            return handled;
        }
    }

    // ── Forward the request to the per-host upstream ────────────────────────
    let target = upstream_target(&host_config, &path_and_query);
    debug!(method = %request_ctx.method, %target, "HTTP/3 → upstream");

    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).context("invalid H3 method")?;
    let mut req_builder = client.request(method, &target);
    for (name, value) in &parts.headers {
        let key = name.as_str();
        // Skip hop-by-hop headers and content-length (reqwest sets it from the
        // body). The original Host header IS forwarded so upstream vhosts work.
        if is_hop_by_hop(key) || key.eq_ignore_ascii_case("content-length") {
            continue;
        }
        req_builder = req_builder.header(key, value.as_bytes());
    }
    if !body_buf.is_empty() {
        req_builder = req_builder.body(body_buf);
    }

    let resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(
                "H3 upstream request failed: host={} target={target} err={e}",
                request_ctx.host
            );
            return respond_simple(
                &mut stream,
                http::StatusCode::BAD_GATEWAY,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"Bad Gateway"),
            )
            .await;
        }
    };

    // ── Relay the upstream response (status + headers + body) ───────────────
    let status = http::StatusCode::from_u16(resp.status().as_u16()).context("invalid upstream status")?;
    let upstream_headers = resp.headers().clone();
    let body_bytes = resp.bytes().await.context("reading upstream body")?;

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
    if !body_bytes.is_empty() {
        stream.send_data(body_bytes).await.context("h3 send_data")?;
    }
    stream.finish().await.context("h3 finish")?;

    Ok(())
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
            let result = respond_simple(stream, status_code, "text/html; charset=utf-8", Bytes::from(body_str)).await;
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
