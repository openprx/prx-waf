//! HTTP/3 (QUIC) listener using `quinn` and `h3`.
//!
//! Runs alongside the Pingora-based HTTP/1.1+TLS listener.  Sends an
//! `Alt-Svc: h3=":443"; ma=86400` header via the existing proxy so that
//! QUIC-capable clients can upgrade.
//!
//! The listener accepts QUIC connections, decodes HTTP/3 requests, runs
//! them through the WAF engine (identical to the HTTP/1.1 path), and
//! forwards allowed requests to the configured upstream.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use tracing::{debug, info, warn};
use uuid::Uuid;

use waf_common::{RequestCtx, WafAction};
use waf_engine::WafEngine;

use crate::router::HostRouter;

// ─── Alt-Svc header value ─────────────────────────────────────────────────────

/// Returns the `Alt-Svc` header value advertising HTTP/3 on the given port.
pub fn alt_svc_header(port: u16) -> String {
    format!("h3=\":{port}\"; ma=86400")
}

// ─── TLS config builder ───────────────────────────────────────────────────────

/// Build a `rustls::ServerConfig` suitable for QUIC (ALPN "h3").
pub fn build_tls_config(cert_pem: &str, key_pem: &str) -> anyhow::Result<rustls::ServerConfig> {
    use rustls::pki_types::CertificateDer;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate PEM")?;

    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("failed to read private key PEM")?
        .context("no private key found in PEM")?;

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
/// Accepts `engine` and `router` so every HTTP/3 request goes through the
/// same WAF inspection pipeline as HTTP/1.1 traffic handled by Pingora.
pub async fn start_http3_server(
    listen_addr: SocketAddr,
    cert_pem: String,
    key_pem: String,
    upstream_url: String,
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
        let upstream = upstream_url.clone();
        let verify_tls = upstream_tls_verify;
        let eng = Arc::clone(&engine);
        let rtr = Arc::clone(&router);
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_quic_connection(conn, upstream, verify_tls, eng, rtr).await {
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
    upstream_url: String,
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

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!upstream_tls_verify)
        .build()?;

    loop {
        match server_conn.accept().await {
            Ok(Some(resolver)) => {
                let upstream = upstream_url.clone();
                let client = client.clone();
                let eng = Arc::clone(&engine);
                let rtr = Arc::clone(&router);
                let remote = peer;
                tokio::spawn(async move {
                    // h3 0.0.8: use resolver.resolve_request() to get (req, stream)
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(req, stream, &client, &upstream, &eng, &rtr, remote).await
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

/// Forward a single HTTP/3 request to the upstream and return the response.
///
/// Before forwarding, the request is inspected by the WAF engine using the
/// same pipeline as HTTP/1.1 requests.  Blocked requests receive a 403
/// response without touching the upstream.
async fn handle_h3_request<C>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<C, bytes::Bytes>,
    client: &reqwest::Client,
    upstream_url: &str,
    engine: &WafEngine,
    router: &HostRouter,
    peer: SocketAddr,
) -> anyhow::Result<()>
where
    C: h3::quic::BidiStream<bytes::Bytes>,
{
    let (parts, ()) = req.into_parts();
    let path_and_query = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let path = parts.uri.path().to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let method = parts.method.to_string();

    // Extract Host header for route resolution
    let host_header = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    // Resolve host config from router; if no route, still run WAF with default config
    let host_config = router.resolve(host_header).unwrap_or_else(|| {
        Arc::new(waf_common::HostConfig {
            host: host_header.to_string(),
            ..waf_common::HostConfig::default()
        })
    });

    // Build request headers map
    let mut headers = HashMap::new();
    for (name, value) in &parts.headers {
        if let Ok(v) = std::str::from_utf8(value.as_bytes()) {
            headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    // Build RequestCtx for WAF inspection
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
        content_length: 0,
        is_tls: true, // QUIC is always encrypted
        host_config: Arc::clone(&host_config),
        geo: None,
    };

    // ── WAF inspection — same pipeline as HTTP/1.1 ──────────────────────────
    let decision = engine.inspect(&mut request_ctx).await;

    if !decision.is_allowed() {
        match &decision.action {
            WafAction::Block { status, body } => {
                warn!(
                    "WAF blocked HTTP/3 request: ip={} path={} host={}",
                    request_ctx.client_ip, request_ctx.path, request_ctx.host,
                );
                let status_code = http::StatusCode::from_u16(*status).unwrap_or(http::StatusCode::FORBIDDEN);
                let body_str = body.clone().unwrap_or_else(|| "Access Denied".to_string());
                let body_bytes = Bytes::from(body_str);

                let response = http::Response::builder()
                    .status(status_code)
                    .header("content-length", body_bytes.len().to_string())
                    .header("content-type", "text/html; charset=utf-8")
                    .header("server", "prx-waf/h3")
                    .body(())
                    .map_err(|e| anyhow::anyhow!("failed to build H3 block response: {e}"))?;

                stream.send_response(response).await?;
                stream.send_data(body_bytes).await?;
                stream.finish().await?;
                return Ok(());
            }
            WafAction::Redirect { url } => {
                let response = http::Response::builder()
                    .status(http::StatusCode::FOUND)
                    .header("location", url.as_str())
                    .header("content-length", "0")
                    .header("server", "prx-waf/h3")
                    .body(())
                    .map_err(|e| anyhow::anyhow!("failed to build H3 redirect response: {e}"))?;

                stream.send_response(response).await?;
                stream.finish().await?;
                return Ok(());
            }
            _ => {}
        }
    }

    // ── Forward allowed request to upstream ──────────────────────────────────
    let target = format!("{}{}", upstream_url.trim_end_matches('/'), path_and_query);

    debug!(method = %request_ctx.method, %target, "HTTP/3 → upstream");

    let resp = client
        .request(reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?, &target)
        .send()
        .await
        .context("upstream request failed")?;

    let status = http::StatusCode::from_u16(resp.status().as_u16())?;
    let body_bytes = resp.bytes().await.context("reading upstream body")?;

    let response = http::Response::builder()
        .status(status)
        .header("content-length", body_bytes.len().to_string())
        .header("server", "prx-waf/h3")
        .body(())
        .map_err(|e| anyhow::anyhow!("failed to build H3 response: {e}"))?;

    stream.send_response(response).await?;
    stream.send_data(body_bytes).await?;
    stream.finish().await?;

    Ok(())
}
