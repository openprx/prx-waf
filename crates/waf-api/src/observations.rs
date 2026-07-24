//! Lane 2 semantic observation admin panel API (P1a-2, read-only).
//!
//! Surfaces the shadow `semantic_observations` telemetry so operators can
//! calibrate the semantic pipeline *before* enforcement. These handlers are
//! strictly read-only: they never write, never mutate detection / scoring, and
//! never change the shadow posture — they only project persisted observations
//! for display, behind the same auth as the other read-only admin endpoints.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use waf_storage::models::{SemanticObservation, SemanticObservationFilter};

use crate::error::ApiResult;
use crate::state::AppState;

/// One de-identified signal flattened from the JSONB `observations` array.
///
/// Every field is optional so a row from an older/newer `schema_version` (or a
/// partial signal) still renders instead of failing the whole response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservationSignalDto {
    #[serde(default)]
    pub detector: Option<String>,
    #[serde(default)]
    pub attack: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub confidence: Option<i64>,
    #[serde(default)]
    pub rule_key: Option<String>,
    #[serde(default)]
    pub provenance: Option<String>,
}

/// A semantic observation projected for the panel: row metadata plus the
/// expanded per-signal breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct ObservationDto {
    pub id: String,
    pub host_code: String,
    pub client_ip: String,
    pub req_id: String,
    pub scope: String,
    pub request_score: i16,
    pub recommendation: String,
    pub degraded: bool,
    pub exhausted: bool,
    pub pipeline: String,
    pub schema_version: i32,
    pub created_at: String,
    pub signals: Vec<ObservationSignalDto>,
}

impl From<SemanticObservation> for ObservationDto {
    fn from(o: SemanticObservation) -> Self {
        // `observations` is a JSONB array; parse leniently so a malformed or
        // schema-drifted entry degrades to an empty breakdown rather than
        // failing the whole response.
        let signals = serde_json::from_value::<Vec<ObservationSignalDto>>(o.observations).unwrap_or_default();
        Self {
            id: o.id.to_string(),
            host_code: o.host_code,
            client_ip: o.client_ip,
            req_id: o.req_id,
            scope: o.scope,
            request_score: o.request_score,
            recommendation: o.recommendation,
            degraded: o.degraded,
            exhausted: o.exhausted,
            pipeline: o.pipeline,
            schema_version: o.schema_version,
            created_at: o.created_at.to_rfc3339(),
            signals,
        }
    }
}

/// GET `/api/observations` — paginated, filtered list of shadow observations.
///
/// Filters (`host_code` / `attack` / `rule_key` / `min_score` / `from` / `to` /
/// `page` / `page_size`) are parsed from the query string into a fully
/// parameterised storage query.
pub async fn list_observations(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<SemanticObservationFilter>,
) -> ApiResult<Json<Value>> {
    let page = filter.page.unwrap_or(1);
    let page_size = filter.page_size.unwrap_or(50);
    let (rows, total) = state.db.query_semantic_observations(&filter).await?;
    let data: Vec<ObservationDto> = rows.into_iter().map(ObservationDto::from).collect();
    Ok(Json(json!({
        "success": true,
        "data": data,
        "total": total,
        "page": page,
        "page_size": page_size,
    })))
}

/// Query parameters for [`observation_stats`].
#[derive(Debug, Deserialize)]
pub struct ObservationStatsQuery {
    /// Look-back window in hours (default 24).
    pub hours: Option<i64>,
}

/// GET `/api/observations/stats` — attack-family and recommendation
/// distribution over a recent window, for the panel's shadow summary.
pub async fn observation_stats(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ObservationStatsQuery>,
) -> ApiResult<Json<Value>> {
    let hours = q.hours.unwrap_or(24);
    let families = state.db.semantic_observation_family_counts(hours, 20).await?;
    let recommendations = state.db.semantic_observation_recommendation_counts(hours).await?;
    Ok(Json(json!({
        "success": true,
        "data": {
            "families": families,
            "recommendations": recommendations,
        }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use waf_storage::models::SemanticObservation;

    fn row(observations: Value) -> SemanticObservation {
        SemanticObservation {
            id: uuid::Uuid::nil(),
            host_code: "h1".to_string(),
            client_ip: "203.0.113.1".to_string(),
            req_id: "req-1".to_string(),
            scope: "body".to_string(),
            request_score: 60,
            recommendation: "log".to_string(),
            degraded: false,
            exhausted: false,
            pipeline: "semantic".to_string(),
            schema_version: 1,
            observations,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn dto_expands_signal_fields() {
        let dto = ObservationDto::from(row(json!([{
            "detector": "struct_rule",
            "attack": "sql_injection",
            "field": "body",
            "scope": "body",
            "confidence": 60,
            "rule_key": "sql.union_null",
            "provenance": "raw"
        }])));
        assert_eq!(dto.signals.len(), 1);
        let s = dto.signals.first().expect("one signal");
        assert_eq!(s.attack.as_deref(), Some("sql_injection"));
        assert_eq!(s.rule_key.as_deref(), Some("sql.union_null"));
        assert_eq!(s.confidence, Some(60));
        assert_eq!(dto.request_score, 60);
    }

    #[test]
    fn dto_tolerates_partial_and_malformed_signals() {
        // A partial signal (missing fields) still parses, defaulting to None.
        let dto = ObservationDto::from(row(json!([{ "detector": "struct_rule" }])));
        assert_eq!(dto.signals.len(), 1);
        assert!(dto.signals.first().expect("one signal").attack.is_none());

        // A non-array / malformed `observations` degrades to an empty breakdown
        // rather than panicking or failing the response.
        let dto = ObservationDto::from(row(json!({ "not": "an array" })));
        assert!(dto.signals.is_empty());
    }
}
