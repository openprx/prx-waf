use std::sync::Arc;

use bytes::BytesMut;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::ContentInspectionState;

use crate::lb::Backend;

/// Maximum request body bytes buffered for WAF inspection (64 KiB).
pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;

/// Maximum response body size (bytes) that is eligible for caching. Larger
/// responses are streamed through un-cached so a single big object cannot
/// balloon per-request memory. 8 MiB.
pub const CACHE_BODY_LIMIT: usize = 8 * 1024 * 1024;

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
    /// Lane 2 semantic work-budget state, shared across the header and body
    /// phases of this request (plan §12.3 — HTTP/1.1 owns it in `GatewayCtx`;
    /// HTTP/3 uses a local instance). Initialised from the engine's compiled
    /// budget in `request_filter`.
    pub content_inspection: ContentInspectionState,
    // ── Load balancing ─────────────────────────────────────────────────────────
    /// Backend chosen by the load balancer for this request. Held so its active
    /// connection counter can be released in `logging` (Least-Connections
    /// accounting). `None` for single-backend hosts.
    pub selected_backend: Option<Backend>,
    // ── Response cache ─────────────────────────────────────────────────────────
    /// Cache key for a cacheable request that missed. `Some` iff the request is
    /// eligible for caching (cache enabled, safe method, no credentials) and was
    /// not served from cache — meaning the upstream response is a store
    /// candidate.
    pub cache_key: Option<String>,
    /// Upstream status captured for a potential cache store.
    pub cache_status: u16,
    /// Upstream response headers captured for a potential cache store.
    pub cache_headers: Vec<(String, String)>,
    /// Upstream `Cache-Control` value captured for a potential cache store.
    pub cache_control: Option<String>,
    /// Whether the captured upstream response is eligible to be stored (set in
    /// the response-header phase, before body accumulation).
    pub cache_store: bool,
    /// Accumulated upstream response body for the pending cache store.
    pub cache_body: BytesMut,
}
