use std::sync::Arc;

use bytes::BytesMut;
use waf_common::{HostConfig, RequestCtx};

/// Maximum request body bytes buffered for WAF inspection (64 KiB).
pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;

/// Per-request state stored in the Pingora session context
#[derive(Default)]
pub struct GatewayCtx {
    /// Built `RequestCtx` for WAF pipeline
    pub request_ctx: Option<RequestCtx>,
    /// Resolved upstream address (host:port)
    pub upstream_addr: Option<String>,
    /// Matched host config
    pub host_config: Option<Arc<HostConfig>>,
    /// Accumulates the first [`BODY_PREVIEW_LIMIT`] bytes of the request body
    /// for WAF body inspection in `request_body_filter`.
    pub body_buf: BytesMut,
    /// Set to `true` once the body WAF check has been performed so we only
    /// inspect once (on the first chunk that completes the preview or at EOS).
    pub body_inspected: bool,
}
