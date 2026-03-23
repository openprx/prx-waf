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
}

impl WafProxy {
    #[allow(clippy::missing_const_for_fn)] // Vec::new() is not const in all contexts
    pub fn new(router: Arc<HostRouter>, engine: Arc<WafEngine>) -> Self {
        Self {
            router,
            engine,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
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

            if peer_trusted
                && let Some(xff) = session.get_header("x-forwarded-for")
                && let Ok(s) = std::str::from_utf8(xff.as_bytes())
                && let Some(first) = s.split(',').next()
                && let Ok(ip) = first.trim().parse()
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

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<Box<HttpPeer>> {
        let host_header = session
            .get_header("host")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        debug!("Routing request for host: {}", host_header);

        let host_config = self.router.resolve(&host_header).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                format!("No route found for host: {host_header}"),
            )
        })?;

        // Check if the site is started
        if !host_config.start_status {
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                "Site is closed",
            ));
        }

        let upstream_addr = format!("{}:{}", host_config.remote_host, host_config.remote_port);
        let use_tls = host_config.ssl;

        ctx.upstream_addr = Some(upstream_addr.clone());
        ctx.host_config = Some(Arc::clone(&host_config));

        let request_ctx = self.build_request_ctx(session, Arc::clone(&host_config));
        ctx.request_ctx = Some(request_ctx);

        info!("Proxying {} → {}", host_header, upstream_addr);

        let peer = HttpPeer::new(&upstream_addr, use_tls, host_config.remote_host.clone());
        Ok(Box::new(peer))
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<bool> {
        let mut request_ctx = match &ctx.request_ctx {
            Some(c) => c.clone(),
            None => return Ok(false),
        };

        // Handle health check endpoint
        if request_ctx.path == "/health" && request_ctx.method == "GET" {
            let _ = session.respond_error(200).await;
            return Ok(true);
        }

        // Run WAF inspection (ctx is &mut so the engine can enrich it with GeoIP)
        let decision = self.engine.inspect(&mut request_ctx).await;

        if !decision.is_allowed() {
            match &decision.action {
                WafAction::Block { status, body } => {
                    warn!(
                        "WAF blocked request: ip={} path={} host={}",
                        request_ctx.client_ip, request_ctx.path, request_ctx.host,
                    );
                    let status_code = *status;
                    let body_str = body.clone().unwrap_or_else(|| "Access Denied".to_string());

                    // Build a simple HTTP 403 response
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

        // Run WAF inspection with body content
        let decision = self.engine.inspect(&mut request_ctx).await;

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
