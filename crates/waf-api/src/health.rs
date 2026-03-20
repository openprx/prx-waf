//! Health check endpoint — GET /health
//!
//! Returns 200 with component status when all critical services are healthy,
//! or 503 when any critical component is degraded.

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};

use crate::state::AppState;

/// GET /health
pub async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let db_ok = state.db.pool().acquire().await.is_ok();

    let plugins = state.plugin_manager.list().await;
    let tunnels = state.tunnel_registry.list_status().await;
    let connected_tunnels = tunnels.iter().filter(|t| t.connected).count();

    let cache_stats = state.cache.stats();

    let status: Value = json!({
        "status": if db_ok { "ok" } else { "degraded" },
        "components": {
            "database": if db_ok { "ok" } else { "error" },
            "waf_engine": "ok",
            "plugins": {
                "loaded": plugins.len(),
                "enabled": plugins.iter().filter(|p| p.enabled).count(),
            },
            "tunnels": {
                "configured": tunnels.len(),
                "connected": connected_tunnels,
            },
            "cache": {
                "entries": state.cache.entry_count(),
                "hits": cache_stats.hits,
                "misses": cache_stats.misses,
            },
        },
        "counters": {
            "total_requests": state.total_requests(),
            "total_blocked":  state.total_blocked(),
        },
        "version": env!("CARGO_PKG_VERSION"),
    });

    let code = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(status)).into_response()
}
