//! HTTP/3 (QUIC) listener using `quinn` and `h3`.
//!
//! Runs alongside the Pingora-based HTTP/1.1+TLS listener.  Sends an
//! `Alt-Svc: h3=":443"; ma=86400` header via the existing proxy so that
//! QUIC-capable clients can upgrade.
//!
//! The listener accepts QUIC connections, decodes HTTP/3 requests, forwards
//! them to the configured upstream, and returns the response over the same
//! QUIC stream.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use tracing::{debug, info, warn};

// ─── Alt-Svc header value ─────────────────────────────────────────────────────

/// Returns the `Alt-Svc` header value advertising HTTP/3 on the given port.
pub fn alt_svc_header(port: u16) -> String {
    format!("h3=\":{}\"; ma=86400", port)
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
pub async fn start_http3_server(
    listen_addr: SocketAddr,
    cert_pem: String,
    key_pem: String,
    upstream_url: String,
    upstream_tls_verify: bool,
) -> anyhow::Result<()> {
    let tls_config = build_tls_config(&cert_pem, &key_pem)?;
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| anyhow::anyhow!("QUIC TLS config error: {e:?}"))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

    let endpoint = quinn::Endpoint::server(server_config, listen_addr)
        .context("failed to bind QUIC endpoint")?;

    info!("HTTP/3 listener on {}", listen_addr);

    while let Some(incoming) = endpoint.accept().await {
        let upstream = upstream_url.clone();
        let verify_tls = upstream_tls_verify;
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_quic_connection(conn, upstream, verify_tls).await {
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
                tokio::spawn(async move {
                    // h3 0.0.8: use resolver.resolve_request() to get (req, stream)
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            if let Err(e) = handle_h3_request(req, stream, &client, &upstream).await
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
async fn handle_h3_request<C>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<C, bytes::Bytes>,
    client: &reqwest::Client,
    upstream_url: &str,
) -> anyhow::Result<()>
where
    C: h3::quic::BidiStream<bytes::Bytes>,
{
    let (parts, _) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target = format!("{}{}", upstream_url.trim_end_matches('/'), path);

    debug!(method = %parts.method, %target, "HTTP/3 → upstream");

    let resp = client
        .request(
            reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?,
            &target,
        )
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
