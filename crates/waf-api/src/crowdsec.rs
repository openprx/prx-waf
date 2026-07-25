//! Phase 6: `CrowdSec` API handlers
//!
//! Routes:
//!   GET  /api/crowdsec/status        — connection + cache stats
//!   GET  /api/crowdsec/decisions     — list cached decisions
//!   DELETE /api/crowdsec/decisions/:id — delete a decision via LAPI
//!   POST /api/crowdsec/test          — test LAPI connection
//!   GET  /api/crowdsec/config        — get stored config
//!   PUT  /api/crowdsec/config        — update stored config
//!   GET  /api/crowdsec/stats         — cache hit/miss statistics
//!   GET  /api/crowdsec/events        — recent `CrowdSec` trigger events

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};

use waf_common::crypto::{encrypt_field, master_key};
use waf_common::url_validator::validate_scheme_only;
use waf_engine::{CacheStats, Decision};
use waf_storage::models::{CrowdSecEventQuery, UpsertCrowdSecConfig};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CrowdSecStatus {
    pub enabled: bool,
    pub lapi_url: Option<String>,
    pub mode: Option<String>,
    pub cache_stats: Option<CacheStats>,
    pub connection_ok: Option<bool>,
    pub connection_msg: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DecisionListResponse {
    pub decisions: Vec<Decision>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct CrowdSecConfigResponse {
    pub id: Option<i32>,
    pub enabled: bool,
    pub mode: String,
    pub lapi_url: Option<String>,
    pub api_key_set: bool,
    pub appsec_endpoint: Option<String>,
    pub appsec_key_set: bool,
    pub update_frequency_secs: i32,
    pub fallback_action: String,
}

// ── Handlers ───────────────────────────────────────────────────────────────────

/// GET /api/crowdsec/status
#[allow(clippy::similar_names)]
pub async fn crowdsec_status(State(state): State<Arc<AppState>>) -> Json<CrowdSecStatus> {
    state.crowdsec_cache.as_ref().map_or_else(
        || {
            Json(CrowdSecStatus {
                enabled: false,
                lapi_url: None,
                mode: None,
                cache_stats: None,
                connection_ok: None,
                connection_msg: Some("CrowdSec integration not enabled".to_string()),
            })
        },
        |cache| {
            let cache_stats = cache.stats();
            Json(CrowdSecStatus {
                enabled: true,
                lapi_url: state.crowdsec_lapi_url.clone(),
                mode: Some("active".to_string()),
                cache_stats: Some(cache_stats),
                connection_ok: None,
                connection_msg: None,
            })
        },
    )
}

/// GET /api/crowdsec/decisions
pub async fn list_crowdsec_decisions(State(state): State<Arc<AppState>>) -> Json<DecisionListResponse> {
    state.crowdsec_cache.as_ref().map_or_else(
        || {
            Json(DecisionListResponse {
                decisions: Vec::new(),
                total: 0,
            })
        },
        |cache| {
            let decisions = cache.list_decisions();
            let total = decisions.len();
            Json(DecisionListResponse { decisions, total })
        },
    )
}

/// DELETE /api/crowdsec/decisions/:id
pub async fn delete_crowdsec_decision(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    let client = state
        .crowdsec_client
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("CrowdSec not enabled".to_owned()))?;
    // The LAPI error text embeds the (internal) LAPI URL and connection
    // diagnostics — log it, return a generic 502.
    client.delete_decision(id).await.map_err(ApiError::Upstream)?;
    Ok(Json(serde_json::json!({ "success": true })))
}

/// Generic outcome for a failed connection test.
///
/// The underlying error carries the LAPI endpoint plus DNS/TLS/socket detail;
/// it is logged server-side instead of being handed to the caller.
const TEST_FAILED_MSG: &str = "connection test failed — see server logs for details";

/// POST /api/crowdsec/test
pub async fn test_crowdsec_connection(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    fn failed(context: &str, e: &anyhow::Error) -> Json<serde_json::Value> {
        tracing::error!(error = %e, "crowdsec {context} failed");
        Json(serde_json::json!({ "success": false, "message": TEST_FAILED_MSG }))
    }

    // Allow ad-hoc test with custom url/key from body
    let lapi_url = body
        .get("lapi_url")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .or_else(|| state.crowdsec_lapi_url.clone());
    let api_key = body.get("api_key").and_then(|v| v.as_str()).map(ToString::to_string);

    match (lapi_url, api_key) {
        (Some(url), Some(key)) => {
            // Validate scheme only: CrowdSec LAPI legitimately runs on loopback
            // or private addresses in on-premise deployments, so we only reject
            // non-HTTP(S) schemes (file://, ftp://, etc.) to block protocol-level
            // SSRF vectors while preserving normal local/private deployments.
            // The message describes the caller's own input, so it is returned.
            if let Err(e) = validate_scheme_only(&url) {
                return Json(serde_json::json!({ "success": false, "message": e.to_string() }));
            }
            match waf_engine::CrowdSecClient::new(url, key) {
                Ok(client) => match client.test_connection().await {
                    Ok(msg) => Json(serde_json::json!({ "success": true, "message": msg })),
                    Err(e) => failed("connection test", &e),
                },
                Err(e) => failed("client construction", &e),
            }
        }
        _ => {
            // Use the running client if available
            if let Some(ref client) = state.crowdsec_client {
                match client.test_connection().await {
                    Ok(msg) => Json(serde_json::json!({ "success": true, "message": msg })),
                    Err(e) => failed("connection test", &e),
                }
            } else {
                Json(serde_json::json!({
                    "success": false,
                    "message": "CrowdSec not enabled and no lapi_url/api_key provided"
                }))
            }
        }
    }
}

/// GET /api/crowdsec/config
pub async fn get_crowdsec_config(State(state): State<Arc<AppState>>) -> Json<CrowdSecConfigResponse> {
    match state.db.get_crowdsec_config().await {
        Ok(Some(row)) => Json(CrowdSecConfigResponse {
            id: Some(row.id),
            enabled: row.enabled,
            mode: row.mode,
            lapi_url: row.lapi_url,
            api_key_set: row.api_key_encrypted.is_some(),
            appsec_endpoint: row.appsec_endpoint,
            appsec_key_set: row.appsec_key_encrypted.is_some(),
            update_frequency_secs: row.update_frequency_secs,
            fallback_action: row.fallback_action,
        }),
        _ => Json(CrowdSecConfigResponse {
            id: None,
            enabled: false,
            mode: "bouncer".to_string(),
            lapi_url: None,
            api_key_set: false,
            appsec_endpoint: None,
            appsec_key_set: false,
            update_frequency_secs: 10,
            fallback_action: "allow".to_string(),
        }),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateCrowdSecConfig {
    pub enabled: bool,
    pub mode: Option<String>,
    pub lapi_url: Option<String>,
    pub api_key: Option<String>,
    pub appsec_endpoint: Option<String>,
    pub appsec_key: Option<String>,
    pub update_frequency_secs: Option<i32>,
    pub fallback_action: Option<String>,
}

/// PUT /api/crowdsec/config
pub async fn update_crowdsec_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateCrowdSecConfig>,
) -> ApiResult<Json<CrowdSecConfigResponse>> {
    // Validate lapi_url scheme before persisting to prevent storing a URL with
    // a dangerous protocol (file://, ftp://, etc.).  Private/loopback addresses
    // are intentionally allowed because CrowdSec LAPI commonly runs locally.
    // The message describes the caller's own input, so it is returned as-is.
    if let Some(ref url) = body.lapi_url {
        validate_scheme_only(url).map_err(|e| ApiError::BadRequest(format!("invalid lapi_url: {e}")))?;
    }

    // A missing/short MASTER_KEY is an operator misconfiguration: logged
    // server-side, generic 500 to the client.
    let key = master_key().map_err(ApiError::Internal)?;

    let api_key_enc = match body.api_key.as_deref().filter(|k| !k.is_empty()) {
        Some(k) => Some(encrypt_field(&key, k).map_err(ApiError::Internal)?),
        None => None,
    };

    let appsec_key_enc = match body.appsec_key.as_deref().filter(|k| !k.is_empty()) {
        Some(k) => Some(encrypt_field(&key, k).map_err(ApiError::Internal)?),
        None => None,
    };

    let req = UpsertCrowdSecConfig {
        host_id: None,
        enabled: body.enabled,
        mode: body.mode.unwrap_or_else(|| "bouncer".to_string()),
        lapi_url: body.lapi_url,
        api_key: None, // handled via encrypted field
        appsec_endpoint: body.appsec_endpoint,
        appsec_key: None, // handled via encrypted field
        update_frequency_secs: body.update_frequency_secs,
        fallback_action: body.fallback_action,
    };

    let row = state
        .db
        .upsert_crowdsec_config(&req, api_key_enc, appsec_key_enc)
        .await?;
    Ok(Json(CrowdSecConfigResponse {
        id: Some(row.id),
        enabled: row.enabled,
        mode: row.mode,
        lapi_url: row.lapi_url,
        api_key_set: row.api_key_encrypted.is_some(),
        appsec_endpoint: row.appsec_endpoint,
        appsec_key_set: row.appsec_key_encrypted.is_some(),
        update_frequency_secs: row.update_frequency_secs,
        fallback_action: row.fallback_action,
    }))
}

/// GET /api/crowdsec/stats
#[allow(clippy::similar_names)]
pub async fn crowdsec_stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    state.crowdsec_cache.as_ref().map_or_else(
        || {
            Json(serde_json::json!({
                "enabled": false,
                "message": "CrowdSec integration not active"
            }))
        },
        |cache| {
            let cache_stats = cache.stats();
            let decisions = cache.list_decisions();

            // Scenario breakdown
            let mut by_scenario: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for d in &decisions {
                *by_scenario.entry(d.scenario.clone()).or_default() += 1;
            }

            // Decision type breakdown
            let mut by_type: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for d in &decisions {
                *by_type.entry(d.type_.clone()).or_default() += 1;
            }

            Json(serde_json::json!({
                "cache": cache_stats,
                "by_scenario": by_scenario,
                "by_type": by_type,
                "total_decisions": decisions.len(),
            }))
        },
    )
}

/// GET /api/crowdsec/events
pub async fn list_crowdsec_events(State(state): State<Arc<AppState>>) -> ApiResult<Json<serde_json::Value>> {
    let query = CrowdSecEventQuery::default();
    let (events, total) = state.db.list_crowdsec_events(&query).await?;
    Ok(Json(serde_json::json!({
        "events": events,
        "total": total,
    })))
}
