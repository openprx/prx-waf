//! Admin API for operator-managed bot detection patterns.
//!
//! # Why every route here is admin-only, reads included
//!
//! A bot pattern is a detection signature. Handing the list to any
//! authenticated account tells the reader exactly which User-Agents are caught
//! and — more usefully to an attacker — which are *not*, plus every whitelist
//! entry that would let a request skip bot detection entirely. That is an
//! evasion recipe, and a low-privilege account is the first thing an intruder
//! obtains. The built-in catalogue is public in the source tree, but an
//! operator's own additions and whitelists are not, and splitting the response
//! across two privilege levels would mean two endpoints returning half a page.
//!
//! These routes sit in `admin_routes`, so the audit middleware records every
//! mutation — including refused ones — against the admin who attempted it.
//!
//! # Write-time validation
//!
//! Every accepted pattern is compiled here, under the engine's size limits,
//! before the row is written. A pattern that cannot be compiled is a `400` with
//! the regex crate's own message; it never reaches the database, so the request
//! path can never meet one.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::{Json, extract::Query};
use serde::Deserialize;
use serde_json::{Value, json};

use waf_engine::checks::bot::{
    BUILTIN_BAD_BOTS, BUILTIN_GOOD_BOTS, BotAction, BotMatch, BuiltinBotRule, MAX_USER_PATTERN_LEN, MAX_USER_PATTERNS,
    validate_user_pattern,
};
use waf_storage::models::{BotPattern, CreateBotPattern, UpdateBotPattern};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Longest accepted rule name. Matches `bot_patterns.name` (`VARCHAR(100)`), so
/// an over-long name is a `400` rather than a truncation or a database error.
const MAX_NAME_LEN: usize = 100;

/// Longest accepted description. `bot_patterns.description` is `TEXT`, so this
/// is a sanity bound rather than a schema one.
const MAX_DESCRIPTION_LEN: usize = 1000;

/// The only `pattern_type` the bot checker inspects.
const PATTERN_TYPE_UA: &str = "ua";

// ── Serialisation helpers ─────────────────────────────────────────────────────

fn builtin_json(rule: &BuiltinBotRule, category: &str) -> Value {
    json!({
        "id": rule.id,
        "name": rule.name,
        "pattern": rule.pattern,
        "action": rule.action.as_str(),
        "source": "builtin",
        "category": category,
        "enabled": true,
    })
}

fn user_json(row: &BotPattern) -> Value {
    json!({
        "id": row.id,
        "rule_id": waf_engine::checks::bot::user_rule_id(row.id),
        "name": row.name,
        "pattern": row.pattern,
        "pattern_type": row.pattern_type,
        "action": row.action,
        "description": row.description,
        "enabled": row.enabled,
        "source": "user",
        "category": "user",
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    })
}

fn match_json(m: &BotMatch) -> Value {
    json!({
        "id": m.id,
        "name": m.name,
        "action": m.action.as_str(),
        "source": if m.builtin { "builtin" } else { "user" },
    })
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Validate a name, returning the trimmed value.
fn check_name(name: &str) -> ApiResult<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".to_owned()));
    }
    if trimmed.chars().count() > MAX_NAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "name is longer than {MAX_NAME_LEN} characters"
        )));
    }
    Ok(trimmed.to_owned())
}

/// Compile the pattern under the engine's limits. This is the check that makes
/// "saved" mean "will actually run".
fn check_pattern(pattern: &str) -> ApiResult<()> {
    validate_user_pattern(pattern).map_err(|e| ApiError::BadRequest(e.to_string()))
}

/// Accept only the actions the request path can carry out.
///
/// `log` and `captcha` are in the 0007 schema but neither exists at the engine
/// level: whether a detection blocks or is merely recorded is the host's
/// `log_only_mode`, not a per-rule setting, and there is no challenge
/// subsystem. Storing either would be a rule that silently does something else.
fn check_action(action: &str) -> ApiResult<BotAction> {
    BotAction::parse(action).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "unsupported action {action:?}: only \"block\" and \"allow\" are implemented. \
             Detect-without-blocking is a per-host setting (log_only_mode), not a per-rule one, \
             and no challenge/captcha subsystem exists"
        ))
    })
}

fn check_pattern_type(pattern_type: &str) -> ApiResult<()> {
    if pattern_type == PATTERN_TYPE_UA {
        return Ok(());
    }
    Err(ApiError::BadRequest(format!(
        "unsupported pattern_type {pattern_type:?}: the bot checker inspects the User-Agent header \
         only (\"ua\"). Block by address with the IP rule lists; rate-limit behaviour with CC \
         protection"
    )))
}

fn check_description(description: Option<&String>) -> ApiResult<()> {
    if let Some(d) = description
        && d.chars().count() > MAX_DESCRIPTION_LEN
    {
        return Err(ApiError::BadRequest(format!(
            "description is longer than {MAX_DESCRIPTION_LEN} characters"
        )));
    }
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /api/bot-patterns` — the built-in catalogue and the operator rows.
///
/// Both halves come from the running engine's own definitions (the `&'static`
/// tables the `RegexSet`s are built from, and the table the reload reads), so
/// what is listed is what matches.
pub async fn list_bot_patterns(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let rows = state.db.list_bot_patterns(false).await?;
    let builtin: Vec<Value> = BUILTIN_GOOD_BOTS
        .iter()
        .map(|r| builtin_json(r, "good"))
        .chain(BUILTIN_BAD_BOTS.iter().map(|r| builtin_json(r, "bad")))
        .collect();
    let user: Vec<Value> = rows.iter().map(user_json).collect();

    Ok(Json(json!({
        "success": true,
        "data": {
            "builtin": builtin,
            "user": user,
            // What the request path is running right now, which is not the same
            // as `user.len()`: disabled rows are excluded and a row written
            // directly into the database can be unusable.
            "active_user_patterns": state.engine.bot_check().user_pattern_count(),
            "limits": {
                "max_user_patterns": MAX_USER_PATTERNS,
                "max_pattern_len": MAX_USER_PATTERN_LEN,
                "max_name_len": MAX_NAME_LEN,
            },
        }
    })))
}

/// `POST /api/bot-patterns` — add one operator pattern and publish it.
pub async fn create_bot_pattern(
    State(state): State<Arc<AppState>>,
    Json(mut req): Json<CreateBotPattern>,
) -> ApiResult<Json<Value>> {
    req.name = check_name(&req.name)?;
    check_pattern(&req.pattern)?;
    let action = check_action(req.action.as_deref().unwrap_or("block"))?;
    check_pattern_type(req.pattern_type.as_deref().unwrap_or(PATTERN_TYPE_UA))?;
    check_description(req.description.as_ref())?;
    req.action = Some(action.as_str().to_owned());
    req.pattern_type = Some(PATTERN_TYPE_UA.to_owned());

    // Refuse the row that would be silently dropped on the next reload rather
    // than accepting it and quietly not enforcing it.
    if req.enabled.unwrap_or(true) {
        let existing = state.db.count_enabled_bot_patterns().await?;
        if existing >= i64::try_from(MAX_USER_PATTERNS).unwrap_or(i64::MAX) {
            return Err(ApiError::BadRequest(format!(
                "the operator bot pattern set is full ({MAX_USER_PATTERNS} enabled patterns); \
                 disable or delete one first"
            )));
        }
    }

    let row = state.db.create_bot_pattern(req).await?;
    reload(&state).await;
    Ok(Json(json!({ "success": true, "data": user_json(&row) })))
}

/// `PUT /api/bot-patterns/{id}` — patch one operator pattern and republish.
pub async fn update_bot_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
    Json(mut req): Json<UpdateBotPattern>,
) -> ApiResult<Json<Value>> {
    if let Some(name) = &req.name {
        req.name = Some(check_name(name)?);
    }
    if let Some(pattern) = &req.pattern {
        check_pattern(pattern)?;
    }
    if let Some(action) = &req.action {
        req.action = Some(check_action(action)?.as_str().to_owned());
    }
    check_description(req.description.as_ref())?;

    let row = state
        .db
        .update_bot_pattern(id, req)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Bot pattern {id} not found")))?;
    reload(&state).await;
    Ok(Json(json!({ "success": true, "data": user_json(&row) })))
}

/// `DELETE /api/bot-patterns/{id}` — remove one operator pattern and republish.
pub async fn delete_bot_pattern(State(state): State<Arc<AppState>>, Path(id): Path<i32>) -> ApiResult<Json<Value>> {
    if !state.db.delete_bot_pattern(id).await? {
        return Err(ApiError::NotFound(format!("Bot pattern {id} not found")));
    }
    reload(&state).await;
    Ok(Json(json!({ "success": true, "data": null })))
}

/// Query for [`test_bot_pattern`].
#[derive(Debug, Deserialize)]
pub struct TestUaQuery {
    /// The User-Agent string to evaluate.
    pub user_agent: Option<String>,
}

/// `GET /api/bot-patterns/test?user_agent=…` — evaluate a UA against the live
/// rule set.
///
/// Runs the engine's own matcher rather than re-implementing it in the browser.
/// The admin UI used to test with JavaScript's `RegExp`, which does not support
/// the inline `(?i)` flag every shipped pattern starts with, so it reported "no
/// match" for User-Agents the WAF blocks.
pub async fn test_bot_pattern(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TestUaQuery>,
) -> ApiResult<Json<Value>> {
    let ua = q
        .user_agent
        .ok_or_else(|| ApiError::BadRequest("user_agent is required".to_owned()))?;
    let matches = state.engine.bot_check().explain(&ua);
    // Precedence, not just membership: the first `allow` wins outright, and
    // otherwise the first `block` decides. Mirrors `BotCheck::check`.
    let verdict = matches.first().map(|m| match m.action {
        BotAction::Allow => "allow",
        BotAction::Block => "block",
    });
    Ok(Json(json!({
        "success": true,
        "data": {
            "user_agent": ua,
            "verdict": verdict.unwrap_or("no-match"),
            "matches": matches.iter().map(match_json).collect::<Vec<_>>(),
        }
    })))
}

/// Republish the operator layer after a mutation.
///
/// A failure here means the write landed but the running engine is still on the
/// previous snapshot, which is worth a log line but not a `500`: the caller's
/// row *was* stored, and the next reload or restart picks it up. Returning an
/// error would tell the operator the change failed when it did not.
async fn reload(state: &Arc<AppState>) {
    if let Err(e) = state.engine.reload_bot_patterns().await {
        tracing::error!(
            "bot pattern written but the running engine could not reload it: {e} — \
             the change takes effect on the next successful reload or restart"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn err_text(r: ApiResult<impl Sized>) -> String {
        match r {
            Ok(_) => String::from("<accepted>"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn rejects_unimplemented_actions_by_name() {
        assert!(err_text(check_action("log")).contains("log_only_mode"));
        assert!(err_text(check_action("captcha")).contains("captcha"));
        assert_eq!(check_action("block").ok(), Some(BotAction::Block));
        assert_eq!(check_action("allow").ok(), Some(BotAction::Allow));
    }

    #[test]
    fn rejects_pattern_types_the_checker_does_not_inspect() {
        assert!(check_pattern_type("ua").is_ok());
        assert!(err_text(check_pattern_type("ip")).contains("IP rule lists"));
        assert!(err_text(check_pattern_type("behavior")).contains("CC"));
    }

    #[test]
    fn rejects_an_uncompilable_pattern_before_it_is_stored() {
        let msg = err_text(check_pattern(r"(?i)[unclosed"));
        assert!(msg.contains("invalid regular expression"), "{msg}");
        assert!(check_pattern(r"(?i)\bMyBot\b").is_ok());
    }

    #[test]
    fn names_are_trimmed_and_bounded() {
        assert_eq!(check_name("  My Bot  ").ok().as_deref(), Some("My Bot"));
        assert!(err_text(check_name("   ")).contains("must not be empty"));
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert!(err_text(check_name(&long)).contains("longer than"));
    }

    #[test]
    fn descriptions_are_bounded() {
        assert!(check_description(None).is_ok());
        let long = "x".repeat(MAX_DESCRIPTION_LEN + 1);
        assert!(err_text(check_description(Some(&long))).contains("longer than"));
    }

    #[test]
    fn builtin_catalogue_is_serialised_with_its_source_and_category() {
        let good = BUILTIN_GOOD_BOTS.first().expect("catalogue is not empty");
        let v = builtin_json(good, "good");
        assert_eq!(v.get("source").and_then(Value::as_str), Some("builtin"));
        assert_eq!(v.get("category").and_then(Value::as_str), Some("good"));
        assert_eq!(v.get("action").and_then(Value::as_str), Some("allow"));
        let bad = BUILTIN_BAD_BOTS.first().expect("catalogue is not empty");
        assert_eq!(
            builtin_json(bad, "bad").get("action").and_then(Value::as_str),
            Some("block")
        );
    }
}
