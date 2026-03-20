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

/// GET /api/cache/stats — cache hit/miss/eviction counters
pub async fn cache_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.cache.stats();
    let count = state.cache.entry_count();
    (
        StatusCode::OK,
        Json(json!({
            "hits": snap.hits,
            "misses": snap.misses,
            "evictions": snap.evictions,
            "stores": snap.stores,
            "entry_count": count,
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
pub async fn cache_flush_host(
    State(state): State<Arc<AppState>>,
    Path(host): Path<String>,
) -> impl IntoResponse {
    state.cache.purge_host(&host).await;
    (StatusCode::OK, Json(json!({ "flushed_host": host }))).into_response()
}

/// DELETE /api/cache/key — flush a specific cache key
///
/// Query param: `?key=<encoded-key>`
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
