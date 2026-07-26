//! Admin API for the OWASP CRS rule registry and the per-rule override layer.
//!
//! # Why every route here is admin-only, reads included
//!
//! `GET /api/rules/registry` is a complete inventory of what this WAF inspects:
//! every rule id, the surface it reads, the paranoia level that switches it on,
//! and — critically — which rules an operator has switched **off**. That last
//! column is a map of the holes. Handing it to any authenticated account turns a
//! compromised low-privilege login into a targeted-evasion briefing, so the
//! whole module sits in `admin_routes` and every call, refused ones included, is
//! recorded by the audit middleware.
//!
//! # What an override can and cannot do
//!
//! Two states, both subtractive:
//!
//! * `enabled = false` — the rule is not evaluated. It cannot match, cannot
//!   score and cannot be logged. **This is a hole in the rule set**, and the
//!   API says so in the response rather than leaving the operator to work it
//!   out.
//! * `action_override = "log"` — the rule is still evaluated and every match is
//!   written to the audit log, but it contributes nothing to the anomaly score.
//!   This is the tuning tool: it answers "how often would this rule have fired"
//!   without a 403 in the middle of the experiment.
//!
//! There is no way to *add* a rule here and no way to escalate one to an
//! unconditional deny. Adding rules is the custom-rules engine's job
//! (`POST /api/custom-rules`); escalation is deliberately not implemented, see
//! [`waf_engine::RuleState::from_row`].
//!
//! # Write-time validation
//!
//! A rule id is resolved against the **running** rule set before the row is
//! written, so a typo is a `400` and never a row that quietly does nothing. The
//! same [`waf_engine::RuleState::from_row`] the request path uses decides
//! whether the row means anything at all, so "accepted" and "enforced" cannot
//! drift apart.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::{Json, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

use waf_engine::checks::owasp::{LoadSummary, RuleDescriptor, RuleState};
use waf_storage::models::{CreateRuleOverride, RuleOverride, UpdateRuleOverride};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Longest accepted operator note. `rule_overrides.note` is `TEXT`, so this is a
/// sanity bound rather than a schema one.
const MAX_NOTE_LEN: usize = 1000;

// ── Serialisation ─────────────────────────────────────────────────────────────

fn rule_json(rule: &RuleDescriptor) -> Value {
    json!({
        "id": rule.id,
        "crs_id": rule.crs_id,
        "name": rule.name,
        "category": rule.category,
        "source": rule.source,
        "severity": rule.severity,
        "score": rule.score,
        "paranoia": rule.paranoia,
        "phase": rule.phase,
        "declared_action": rule.declared_action,
        // What the request path will actually do with a match in this scope.
        "effective_action": match rule.state {
            RuleState::Active => rule.declared_action,
            RuleState::Disabled => "disabled",
            RuleState::LogOnly => "log",
        },
        "state": rule.state.as_str(),
        "enabled": rule.state != RuleState::Disabled,
        "overridden": rule.state != RuleState::Active,
    })
}

fn override_json(row: &RuleOverride, known_rule: bool) -> Value {
    json!({
        "id": row.id,
        "rule_id": row.rule_id,
        "host_code": row.host_code,
        "enabled": row.enabled,
        "action_override": row.action_override,
        "note": row.note,
        // `false` means the row is inert: it names a rule this build does not
        // load, so nothing on the request path reads it.
        "known_rule": known_rule,
        "state": RuleState::from_row(row.enabled, row.action_override.as_deref())
            .map_or("invalid", RuleState::as_str),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    })
}

/// The load diagnostics, plus what the override layer has done on top of them.
fn summary_json(summary: &LoadSummary, rules: &[RuleDescriptor]) -> Value {
    let disabled = rules.iter().filter(|r| r.state == RuleState::Disabled).count();
    let log_only = rules.iter().filter(|r| r.state == RuleState::LogOnly).count();
    json!({
        "declared": summary.attempted,
        "enforced": rules.len(),
        "request_rules": rules.iter().filter(|r| r.phase == "request").count(),
        "response_rules": rules.iter().filter(|r| r.phase == "response").count(),
        "rejected": summary.rejected.len(),
        "rejected_rules": summary.rejected.iter().map(|r| json!({
            "rule_id": r.rule_id,
            "source": r.source,
            "reason": r.reason.to_string(),
        })).collect::<Vec<_>>(),
        "source_errors": summary.source_errors.iter().map(|e| json!({
            "source": e.source,
            "error": e.error,
        })).collect::<Vec<_>>(),
        "severity_defaulted": summary.severity_defaulted,
        "action_defaulted": summary.action_defaulted,
        "used_embedded_fallback": summary.used_embedded_fallback,
        "degraded": summary.is_degraded(),
        // Overrides, in the queried scope. `disabled` is the number that matters
        // on a review: each one is a detection this WAF no longer performs.
        "disabled": disabled,
        "log_only": log_only,
    })
}

// ── Validation ────────────────────────────────────────────────────────────────

fn check_note(note: Option<&String>) -> ApiResult<()> {
    if let Some(n) = note
        && n.chars().count() > MAX_NOTE_LEN
    {
        return Err(ApiError::BadRequest(format!(
            "note is longer than {MAX_NOTE_LEN} characters"
        )));
    }
    Ok(())
}

/// Resolve the override into the state the request path would apply, refusing
/// anything the engine cannot carry out.
fn check_state(enabled: Option<bool>, action_override: Option<&str>) -> ApiResult<RuleState> {
    RuleState::from_row(enabled, action_override).map_err(|e| ApiError::BadRequest(e.to_string()))
}

/// Refuse an override for a rule this build does not load.
///
/// Without this the row is stored, reported as created, and never applied — the
/// exact shape of a control that looks like it works.
fn check_rule_id(state: &AppState, rule_id: &str) -> ApiResult<()> {
    if rule_id.trim().is_empty() {
        return Err(ApiError::BadRequest("rule_id must not be empty".to_owned()));
    }
    if state.engine.owasp_check().knows_rule(rule_id) {
        return Ok(());
    }
    Err(ApiError::BadRequest(format!(
        "unknown rule id {rule_id:?}: it is not in the rule set this WAF loaded. \
         GET /api/rules/registry lists every enforced rule; ids are accepted either as \
         \"CRS-942100\" or as the bare upstream number \"942100\""
    )))
}

/// What an operator must be told when a rule is switched off.
///
/// Returned in the response body of every write that produces a disabled rule.
/// It is not advice — it is the consequence, stated once, at the moment it takes
/// effect.
fn disable_warning(rule_id: &str, host_code: Option<&str>) -> String {
    let scope = host_code.map_or_else(
        || "every host served by this WAF".to_owned(),
        |code| format!("host {code}"),
    );
    format!(
        "Rule {rule_id} is now DISABLED for {scope}: it is no longer evaluated, so the attacks it \
         detects pass this WAF unrecorded. If the goal is to measure a rule's false positives \
         rather than to remove it, use action_override = \"log\" — the rule keeps running and \
         every match is written to the audit log, but it stops contributing to the anomaly score."
    )
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// Optional `?host=<code>` scope selector for the registry.
#[derive(Debug, Deserialize)]
pub struct RegistryQuery {
    /// Show the states in force for this host. Omitted = the global layer.
    pub host: Option<String>,
}

/// `GET /api/rules/registry` — the CRS rules this process is running.
///
/// Read from the live [`waf_engine::OWASPCheck`], not from a second copy of the
/// rule files: the list is by construction what the request path walks, so a
/// rule missing here is a rule that is genuinely not enforced.
pub async fn rules_registry(
    State(state): State<Arc<AppState>>,
    Query(q): Query<RegistryQuery>,
) -> ApiResult<Json<Value>> {
    let owasp = state.engine.owasp_check();
    let rules = owasp.registry(q.host.as_deref());
    let summary = summary_json(owasp.load_summary(), &rules);
    Ok(Json(json!({
        "success": true,
        "data": {
            "scope": { "host_code": q.host },
            "summary": summary,
            "rules": rules.iter().map(rule_json).collect::<Vec<_>>(),
        }
    })))
}

/// `GET /api/rules/overrides` — every stored override.
pub async fn list_rule_overrides(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let rows = state.db.list_rule_overrides().await?;
    let owasp = state.engine.owasp_check();
    let items: Vec<Value> = rows
        .iter()
        .map(|row| override_json(row, owasp.knows_rule(&row.rule_id)))
        .collect();
    Ok(Json(json!({
        "success": true,
        "data": { "overrides": items, "total": rows.len() }
    })))
}

/// `POST /api/rules/overrides` — create or replace one override, and apply it.
///
/// An upsert on `(rule_id, host)`: changing your mind about a rule edits one
/// decision instead of stacking rows that contradict each other.
pub async fn create_rule_override(
    State(state): State<Arc<AppState>>,
    Json(mut req): Json<CreateRuleOverride>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    req.rule_id = req.rule_id.trim().to_owned();
    check_rule_id(&state, &req.rule_id)?;
    check_note(req.note.as_ref())?;
    let resolved = check_state(req.enabled, req.action_override.as_deref())?;
    // Store the canonical spelling, so the table reads the same way whichever
    // form the operator typed.
    req.action_override = req.action_override.map(|a| a.trim().to_ascii_lowercase());

    let row = state.db.upsert_rule_override(&req).await?.ok_or_else(|| {
        ApiError::BadRequest(format!(
            "unknown host code {:?}: an override can only be scoped to a host in the database. \
             Hosts declared in the config file get a fresh code on every start and can only be \
             governed by a global override (host_code = null)",
            req.host_code.as_deref().unwrap_or_default()
        ))
    })?;

    let report = reload(&state).await;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "success": true,
            "data": override_json(&row, true),
            "applied": report.is_some(),
            "warning": (resolved == RuleState::Disabled)
                .then(|| disable_warning(&row.rule_id, row.host_code.as_deref())),
        })),
    ))
}

/// `PUT /api/rules/overrides/{id}` — replace one override's decision, and apply.
pub async fn update_rule_override(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
    Json(mut req): Json<UpdateRuleOverride>,
) -> ApiResult<Json<Value>> {
    check_note(req.note.as_ref())?;
    let resolved = check_state(req.enabled, req.action_override.as_deref())?;
    req.action_override = req.action_override.map(|a| a.trim().to_ascii_lowercase());

    let row = state
        .db
        .update_rule_override(id, &req)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Rule override {id} not found")))?;

    let report = reload(&state).await;
    Ok(Json(json!({
        "success": true,
        "data": override_json(&row, state.engine.owasp_check().knows_rule(&row.rule_id)),
        "applied": report.is_some(),
        "warning": (resolved == RuleState::Disabled)
            .then(|| disable_warning(&row.rule_id, row.host_code.as_deref())),
    })))
}

/// `DELETE /api/rules/overrides/{id}` — drop one override, restoring the rule.
pub async fn delete_rule_override(State(state): State<Arc<AppState>>, Path(id): Path<i32>) -> ApiResult<Json<Value>> {
    if !state.db.delete_rule_override(id).await? {
        return Err(ApiError::NotFound(format!("Rule override {id} not found")));
    }
    let report = reload(&state).await;
    Ok(Json(
        json!({ "success": true, "data": null, "applied": report.is_some() }),
    ))
}

/// `POST /api/rules/reload` — rebuild the override layer from the database.
///
/// The mutating routes above already republish, so this is for the case they do
/// not cover: rows changed out of band (a migration, a `psql` session, the CLI
/// against a shared database), or a republish that failed and was logged.
///
/// It reloads the *override* layer, not the CRS rule files: those are compiled
/// once at startup from `rules/owasp-crs/`, and re-reading them at runtime would
/// mean rebuilding several hundred automata under live traffic. Restart to pick
/// up an edited rule file.
pub async fn reload_rules_overrides(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let report = state.engine.reload_rule_overrides().await.map_err(ApiError::Internal)?;
    Ok(Json(json!({
        "success": true,
        "data": {
            "applied": report.applied,
            "disabled": report.disabled,
            "log_only": report.log_only,
            "hosts": report.hosts,
            "unknown_rule_ids": report.unknown_rule_ids,
            "enforced_rules": state.engine.owasp_check().rule_count(),
        }
    })))
}

/// Republish the override layer after a mutation.
///
/// `None` when the republish failed. As in `bot_patterns.rs`, that is a log line
/// and not a `500`: the row *was* stored, and the next reload or restart picks
/// it up. Reporting a failure would tell the operator their change was lost when
/// it was not — but the response carries `applied: false`, so they are not told
/// it is live either.
async fn reload(state: &Arc<AppState>) -> Option<waf_engine::OverrideLoadReport> {
    match state.engine.reload_rule_overrides().await {
        Ok(report) => Some(report),
        Err(e) => {
            tracing::error!(
                "rule override written but the running engine could not reload it: {e} — \
                 the change takes effect on the next successful reload or restart"
            );
            None
        }
    }
}
