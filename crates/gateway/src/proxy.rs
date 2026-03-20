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

use crate::context::GatewayCtx;
use crate::router::HostRouter;

/// Pingora-based reverse proxy with WAF integration
pub struct WafProxy {
    pub router: Arc<HostRouter>,
    pub engine: Arc<WafEngine>,
    /// Whether to trust X-Forwarded-For headers for client IP extraction.
    /// Should only be `true` when running behind a trusted reverse proxy.
    pub trust_proxy_headers: bool,
}

impl WafProxy {
    pub fn new(router: Arc<HostRouter>, engine: Arc<WafEngine>) -> Self {
        Self {
            router,
            engine,
            trust_proxy_headers: false,
        }
    }

    /// Extract client IP from session.
    ///
    /// Only reads X-Forwarded-For when `trust_proxy_headers` is enabled;
    /// otherwise always uses the TCP peer address.
    fn extract_client_ip(&self, session: &Session) -> std::net::IpAddr {
        if self.trust_proxy_headers
            && let Some(xff) = session.get_header("x-forwarded-for")
            && let Ok(s) = std::str::from_utf8(xff.as_bytes())
            && let Some(first) = s.split(',').next()
            && let Ok(ip) = first.trim().parse()
        {
            return ip;
        }

        // Fall back to remote addr
        session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    }

    /// Build a RequestCtx from the Pingora session
    fn build_request_ctx(&self, session: &Session, host_config: Arc<HostConfig>) -> RequestCtx {
        let client_ip = self.extract_client_ip(session);
        let client_port = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.port())
            .unwrap_or(0);

        let method = session.req_header().method.to_string();
        let uri = session.req_header().uri.clone();
        let path = uri.path().to_string();
        let query = uri.query().unwrap_or("").to_string();

        let host = host_config.host.clone();
        let port = host_config.port;

        // Extract headers as HashMap
        let mut headers = HashMap::new();
        for (name, value) in session.req_header().headers.iter() {
            if let Ok(v) = std::str::from_utf8(value.as_bytes()) {
                headers.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

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
            content_length: 0,
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

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<Box<HttpPeer>> {
        let host_header = session
            .get_header("host")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        debug!("Routing request for host: {}", host_header);

        let host_config = self.router.resolve(&host_header).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                format!("No route found for host: {}", host_header),
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

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<bool> {
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
                    session
                        .write_response_header(Box::new(response), false)
                        .await?;
                    let body_bytes = Bytes::from(body_str);
                    session.write_response_body(Some(body_bytes), true).await?;
                    return Ok(true);
                }
                WafAction::Redirect { url } => {
                    let mut response = pingora_http::ResponseHeader::build(302, None)?;
                    response.insert_header("location", url.as_str())?;
                    session
                        .write_response_header(Box::new(response), true)
                        .await?;
                    return Ok(true);
                }
                _ => {}
            }
        }

        Ok(false)
    }

    async fn logging(
        &self,
        _session: &mut Session,
        _error: Option<&pingora_core::Error>,
        ctx: &mut GatewayCtx,
    ) {
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
