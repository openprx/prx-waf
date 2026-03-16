/// Statistics and analytics API handlers.
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;

use crate::error::ApiResult;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct TimeseriesQuery {
    pub host_code: Option<String>,
    /// Number of hours to look back (default 24)
    pub hours: Option<i64>,
}

/// GET /api/stats/overview
pub async fn stats_overview(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let overview = state.db.get_stats_overview().await?;
    let total_requests_live = state.total_requests();
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "total_requests_db": overview.total_requests,
            "total_requests_live": total_requests_live,
            "total_blocked": overview.total_blocked,
            "total_allowed": overview.total_allowed,
            "hosts_count": overview.hosts_count,
            "top_ips": overview.top_ips,
            "top_rules": overview.top_rules,
            "top_countries": overview.top_countries,
            "top_isps": overview.top_isps,
        }
    })))
}

/// GET /api/stats/timeseries
pub async fn stats_timeseries(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TimeseriesQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let hours = q.hours.unwrap_or(24).clamp(1, 720);
    let series = state
        .db
        .get_stats_timeseries(q.host_code.as_deref(), hours)
        .await?;
    Ok(Json(serde_json::json!({ "success": true, "data": series })))
}

/// GET /api/stats/geo — GeoIP distribution of blocked requests
pub async fn stats_geo(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let geo = state.db.get_geo_stats().await?;
    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "top_countries": geo.top_countries,
            "top_cities": geo.top_cities,
            "top_isps": geo.top_isps,
            "country_distribution": geo.country_distribution,
        }
    })))
}
