//! Cache management API handlers.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;

use crate::state::AppState;

/// GET /api/cache/stats — cache hit/miss/eviction counters and byte usage
///
/// `bytes_used` / `max_bytes` are the real memory bound: `max_bytes` is
/// `cache.max_size_mb` converted to bytes and `bytes_used` is what the cache
/// currently holds against it (settled, not approximate — see
/// `ResponseCache::usage`). `oversize_rejects` counts responses refused for
/// exceeding `max_entry_bytes`.
pub async fn cache_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.cache.stats();
    let (count, bytes_used) = state.cache.usage().await;
    (
        StatusCode::OK,
        Json(json!({
            "hits": snap.hits,
            "misses": snap.misses,
            "evictions": snap.evictions,
            "stores": snap.stores,
            "oversize_rejects": snap.oversize_rejects,
            "entry_count": count,
            "bytes_used": bytes_used,
            "max_bytes": state.cache.max_bytes(),
            "max_entry_bytes": state.cache.max_entry_bytes(),
        })),
    )
        .into_response()
}

/// DELETE /api/cache — flush the entire cache
pub async fn cache_flush(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.cache.flush().await;
    (StatusCode::OK, Json(json!({ "flushed": true }))).into_response()
}

/// DELETE /api/cache/host/:host — flush all entries for a given host
pub async fn cache_flush_host(State(state): State<Arc<AppState>>, Path(host): Path<String>) -> impl IntoResponse {
    state.cache.purge_host(&host).await;
    (StatusCode::OK, Json(json!({ "flushed_host": host }))).into_response()
}

/// DELETE /api/cache/key — flush a specific cache key
///
/// Query param: `?key=<encoded-key>`
#[allow(clippy::implicit_hasher)]
pub async fn cache_flush_key(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let key = match params.get("key") {
        Some(k) => k.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "key query parameter required" })),
            )
                .into_response();
        }
    };
    state.cache.purge_key(&key).await;
    (StatusCode::OK, Json(json!({ "flushed_key": key }))).into_response()
}
