use std::sync::Arc;
use waf_common::{HostConfig, RequestCtx};

/// Per-request state stored in the Pingora session context
#[derive(Default)]
pub struct GatewayCtx {
    /// Built RequestCtx for WAF pipeline
    pub request_ctx: Option<RequestCtx>,
    /// Resolved upstream address (host:port)
    pub upstream_addr: Option<String>,
    /// Matched host config
    pub host_config: Option<Arc<HostConfig>>,
}
