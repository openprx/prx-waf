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

use crate::context::{BODY_PREVIEW_LIMIT, GatewayCtx};
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
}

impl WafProxy {
    pub fn new(router: Arc<HostRouter>, engine: Arc<WafEngine>) -> Self {
        Self {
            router,
            engine,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
            acme_challenges: Arc::new(ChallengeStore::new()),
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

        let upstream_addr = format!("{}:{}", host_config.remote_host, host_config.remote_port);
        let use_tls = host_config.ssl;

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

        // ── WAF header-phase inspection ───────────────────────────────────────
        let mut request_ctx = self.build_request_ctx(session, host_config);
        let client_ip = request_ctx.client_ip;
        let path = request_ctx.path.clone();
        let host = request_ctx.host.clone();

        // ctx is &mut so the engine can enrich it with GeoIP
        let decision = self.engine.inspect(&mut request_ctx).await;

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
        let decision = self.engine.inspect_body(&mut request_ctx).await;

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

    async fn logging(&self, _session: &mut Session, _error: Option<&pingora_core::Error>, ctx: &mut GatewayCtx) {
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
