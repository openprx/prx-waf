use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

use waf_storage::models::{
    AttackLogQuery, CreateCertificate, CreateCustomRule, CreateHost, CreateIpRule, CreateLbBackend,
    CreateSensitivePattern, CreateUrlRule, Host, SecurityEventQuery, UpdateHost, UpsertHotlinkConfig,
};

use waf_common::{DefenseConfig, HostConfig};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Response wrapper ─────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub const fn ok(data: T) -> Json<Self> {
        Json(Self { success: true, data })
    }
}

// ─── Hosts ────────────────────────────────────────────────────────────────────

/// Build the runtime [`HostConfig`] the router serves from a persisted [`Host`].
///
/// Shared by `create_host` and `update_host` so the field mapping — most
/// importantly `log_only_mode`, whose omission previously left API-configured
/// log-only hosts silently blocking — cannot drift between the two paths.
///
/// This is a deliberately partial projection: fields the admin API does not yet
/// surface into the runtime (load-balancing, `exclude_url_log`, block page
/// template, backends) keep their `HostConfig::default()` values.
///
/// `defense_config` is projected from the persisted `defense_json` JSONB column:
/// a stored config drives the per-host Lane1 detector toggles, while `NULL` (or
/// a value that fails to deserialise) falls back to `DefenseConfig::default()`
/// — every detector on, the historical behaviour.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn host_runtime_config(host: &Host) -> HostConfig {
    let defense_config = host
        .defense_json
        .as_ref()
        .and_then(|v| serde_json::from_value::<DefenseConfig>(v.clone()).ok())
        .unwrap_or_default();
    HostConfig {
        code: host.code.clone(),
        host: host.host.clone(),
        port: host.port as u16,
        ssl: host.ssl,
        guard_status: host.guard_status,
        remote_host: host.remote_host.clone(),
        remote_port: host.remote_port as u16,
        remote_ip: host.remote_ip.clone(),
        cert_file: host.cert_file.clone(),
        key_file: host.key_file.clone(),
        start_status: host.start_status,
        log_only_mode: host.log_only_mode,
        defense_config,
        ..HostConfig::default()
    }
}

pub async fn list_hosts(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let hosts = state.db.list_hosts().await?;
    Ok(Json(json!({ "success": true, "data": hosts })))
}

pub async fn get_host(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;
    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn create_host(State(state): State<Arc<AppState>>, Json(req): Json<CreateHost>) -> ApiResult<Json<Value>> {
    // Validate port ranges before DB write to prevent i32→u16 truncation
    if !(1..=65535).contains(&req.port) {
        return Err(ApiError::BadRequest("port must be between 1 and 65535".into()));
    }
    if !(1..=65535).contains(&req.remote_port) {
        return Err(ApiError::BadRequest("remote_port must be between 1 and 65535".into()));
    }

    let host = state.db.create_host(req).await?;

    // Register with router
    let config = Arc::new(host_runtime_config(&host));
    state.router.register(&config);

    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn update_host(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateHost>,
) -> ApiResult<Json<Value>> {
    // Validate port ranges before DB write to prevent i32→u16 truncation
    if let Some(port) = req.port
        && !(1..=65535).contains(&port)
    {
        return Err(ApiError::BadRequest("port must be between 1 and 65535".into()));
    }
    if let Some(remote_port) = req.remote_port
        && !(1..=65535).contains(&remote_port)
    {
        return Err(ApiError::BadRequest("remote_port must be between 1 and 65535".into()));
    }

    // Fetch old host to unregister from router before update

    let old_host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;
    let host = state
        .db
        .update_host(id, req)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;
    // Unregister old route, register updated config
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let old_port = old_host.port as u16;
    state.router.unregister(&old_host.host, old_port);
    let config = Arc::new(host_runtime_config(&host));
    state.router.register(&config);
    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn delete_host(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    // Fetch host before deleting to get hostname/port for router unregister
    let host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;
    let deleted = state.db.delete_host(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Host {id} not found")));
    }
    // Unregister from in-memory router
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let port = host.port as u16;
    state.router.unregister(&host.host, port);
    // Clear any rules associated with this host
    state.engine.store.allow_ips.clear_host(&host.code);
    state.engine.store.block_ips.clear_host(&host.code);
    state.engine.store.allow_urls.clear_host(&host.code);
    state.engine.store.block_urls.clear_host(&host.code);
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Allow IPs ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct HostCodeFilter {
    pub host_code: Option<String>,
}

pub async fn list_allow_ips(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_allow_ips(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_allow_ip(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateIpRule>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_allow_ip(req.clone()).await?;
    // Hot-update engine rules
    state.engine.store.allow_ips.insert(&req.host_code, &req.ip_cidr);
    state
        .cluster_broadcast_upsert(waf_engine::cluster_sync::allow_ip_to_rule(&row))
        .await;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_allow_ip(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_allow_ip(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Allow IP {id} not found")));
    }
    // Sync in-memory rules with database
    if let Err(e) = state.engine.store.reload_all().await {
        tracing::warn!("Failed to reload allow IPs after delete: {}", e);
    }
    state
        .cluster_broadcast_delete(waf_engine::cluster_sync::SyncedKind::AllowIp, id)
        .await;
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Block IPs ───────────────────────────────────────────────────────────────

pub async fn list_block_ips(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_block_ips(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_block_ip(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateIpRule>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_block_ip(req.clone()).await?;
    // Hot-update engine rules
    state.engine.store.block_ips.insert(&req.host_code, &req.ip_cidr);
    state
        .cluster_broadcast_upsert(waf_engine::cluster_sync::block_ip_to_rule(&row))
        .await;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_block_ip(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_block_ip(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Block IP {id} not found")));
    }
    // Sync in-memory rules with database
    if let Err(e) = state.engine.store.reload_all().await {
        tracing::warn!("Failed to reload block IPs after delete: {}", e);
    }
    state
        .cluster_broadcast_delete(waf_engine::cluster_sync::SyncedKind::BlockIp, id)
        .await;
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Allow URLs ──────────────────────────────────────────────────────────────

pub async fn list_allow_urls(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_allow_urls(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_allow_url(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateUrlRule>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_allow_url(req.clone()).await?;
    state
        .cluster_broadcast_upsert(waf_engine::cluster_sync::allow_url_to_rule(&row))
        .await;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_allow_url(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_allow_url(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Allow URL {id} not found")));
    }
    // Sync in-memory rules with database
    if let Err(e) = state.engine.store.reload_all().await {
        tracing::warn!("Failed to reload allow URLs after delete: {}", e);
    }
    state
        .cluster_broadcast_delete(waf_engine::cluster_sync::SyncedKind::AllowUrl, id)
        .await;
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Block URLs ──────────────────────────────────────────────────────────────

pub async fn list_block_urls(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_block_urls(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_block_url(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateUrlRule>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_block_url(req.clone()).await?;
    state
        .cluster_broadcast_upsert(waf_engine::cluster_sync::block_url_to_rule(&row))
        .await;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_block_url(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_block_url(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Block URL {id} not found")));
    }
    // Sync in-memory rules with database
    if let Err(e) = state.engine.store.reload_all().await {
        tracing::warn!("Failed to reload block URLs after delete: {}", e);
    }
    state
        .cluster_broadcast_delete(waf_engine::cluster_sync::SyncedKind::BlockUrl, id)
        .await;
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Attack Logs ─────────────────────────────────────────────────────────────

pub async fn list_attack_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AttackLogQuery>,
) -> ApiResult<Json<Value>> {
    let (logs, total) = state.db.list_attack_logs(&query).await?;
    Ok(Json(json!({
        "success": true,
        "data": logs,
        "total": total,
        "page": query.page.unwrap_or(1),
        "page_size": query.page_size.unwrap_or(20),
    })))
}

// ─── Security Events ─────────────────────────────────────────────────────────

pub async fn list_security_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SecurityEventQuery>,
) -> ApiResult<Json<Value>> {
    let (events, total) = state.db.list_security_events(&query).await?;
    Ok(Json(json!({
        "success": true,
        "data": events,
        "total": total,
        "page": query.page.unwrap_or(1),
        "page_size": query.page_size.unwrap_or(20),
    })))
}

// ─── Status ──────────────────────────────────────────────────────────────────

pub async fn get_status(State(state): State<Arc<AppState>>) -> Json<Value> {
    let hosts = state.router.len();
    let allow_ips = state.engine.store.allow_ips.len();
    let block_ips = state.engine.store.block_ips.len();
    let allow_urls = state.engine.store.allow_urls.len();
    let block_urls = state.engine.store.block_urls.len();
    let total_requests = state.total_requests();

    Json(json!({
        "success": true,
        "data": {
            "version": env!("CARGO_PKG_VERSION"),
            "hosts": hosts,
            "rules": {
                "allow_ips": allow_ips,
                "block_ips": block_ips,
                "allow_urls": allow_urls,
                "block_urls": block_urls,
            },
            "total_requests": total_requests,
        }
    }))
}

// ─── Reload ──────────────────────────────────────────────────────────────────

pub async fn reload_rules(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    state.engine.reload_rules().await.map_err(ApiError::Internal)?;
    Ok(Json(json!({ "success": true, "data": "Rules reloaded" })))
}

// ─── Custom Rules ─────────────────────────────────────────────────────────────

pub async fn list_custom_rules(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_custom_rules(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_custom_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCustomRule>,
) -> ApiResult<Json<Value>> {
    use waf_engine::rules::engine::from_db_rule;

    let row = state.db.create_custom_rule(req.clone()).await?;
    // Hot-add to engine
    if let Ok(rule) = from_db_rule(&row) {
        state.engine.custom_rules.add_rule(rule);
    }
    // Cluster: broadcast so workers pick up the new rule on their request path.
    state
        .cluster_broadcast_upsert(waf_engine::cluster_sync::custom_rule_to_rule(&row))
        .await;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_custom_rule(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let rule = state
        .db
        .get_custom_rule(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Rule {id} not found")))?;
    let deleted = state.db.delete_custom_rule(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Rule {id} not found")));
    }
    state
        .engine
        .custom_rules
        .remove_rule(&rule.host_code, &rule.id.to_string());
    state
        .cluster_broadcast_delete(waf_engine::cluster_sync::SyncedKind::Custom, id)
        .await;
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Sensitive Patterns ───────────────────────────────────────────────────────

pub async fn list_sensitive_patterns(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_sensitive_patterns(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_sensitive_pattern(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSensitivePattern>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_sensitive_pattern(req).await?;
    // Trigger a full reload to rebuild the AhoCorasick automaton
    if let Err(e) = state.engine.reload_rules().await {
        tracing::warn!("Failed to reload after pattern add: {}", e);
    }
    state
        .cluster_broadcast_upsert(waf_engine::cluster_sync::sensitive_to_rule(&row))
        .await;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_sensitive_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_sensitive_pattern(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Pattern {id} not found")));
    }
    if let Err(e) = state.engine.reload_rules().await {
        tracing::warn!("Failed to reload after pattern delete: {}", e);
    }
    state
        .cluster_broadcast_delete(waf_engine::cluster_sync::SyncedKind::Sensitive, id)
        .await;
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Hotlink Config ───────────────────────────────────────────────────────────

pub async fn get_hotlink_config(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let host_code = filter
        .host_code
        .ok_or_else(|| ApiError::BadRequest("host_code required".into()))?;
    let config = state.db.get_hotlink_config(&host_code).await?;
    Ok(Json(json!({ "success": true, "data": config })))
}

pub async fn upsert_hotlink_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertHotlinkConfig>,
) -> ApiResult<Json<Value>> {
    let row = state.db.upsert_hotlink_config(req.clone()).await?;
    // Hot-update engine
    let domains = req.allowed_domains.unwrap_or_default();
    let config = waf_engine::checks::anti_hotlink::HotlinkConfig {
        enabled: row.enabled,
        allow_empty_referer: row.allow_empty_referer,
        allowed_domains: domains,
        redirect_url: row.redirect_url.clone(),
    };
    state.engine.hotlink.set_config(&row.host_code, config);
    Ok(Json(json!({ "success": true, "data": row })))
}

// ─── LB Backends ─────────────────────────────────────────────────────────────

pub async fn list_lb_backends(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_lb_backends(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_lb_backend(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateLbBackend>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_lb_backend(req).await?;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_lb_backend(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_lb_backend(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Backend {id} not found")));
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Certificates ─────────────────────────────────────────────────────────────

pub async fn list_certificates(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_certificates(filter.host_code.as_deref()).await?;
    // Don't expose private keys in list response
    let safe: Vec<Value> = rows
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "host_code": c.host_code,
                "domain": c.domain,
                "issuer": c.issuer,
                "subject": c.subject,
                "not_before": c.not_before,
                "not_after": c.not_after,
                "auto_renew": c.auto_renew,
                "status": c.status,
                "error_msg": c.error_msg,
                "created_at": c.created_at,
                "updated_at": c.updated_at,
            })
        })
        .collect();
    Ok(Json(json!({ "success": true, "data": safe })))
}

/// The PEM the TLS listener will actually try to serve for this row.
///
/// `tls_listener::resolve` appends `chain_pem` to `cert_pem` before validating,
/// so checking `cert_pem` on its own here would wave through an upload whose
/// intermediate bundle is the broken half and leave the listener to discover it
/// at the next start. Validation has to see the same bytes serving will.
fn served_chain(cert_pem: &str, chain_pem: Option<&str>) -> String {
    match chain_pem {
        Some(chain) if !chain.trim().is_empty() => format!("{}\n{}", cert_pem.trim_end(), chain.trim_start()),
        _ => cert_pem.to_string(),
    }
}

/// A required PEM field, present and not blank.
fn require_pem<'a>(value: Option<&'a String>, field: &str) -> ApiResult<&'a str> {
    value
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::BadRequest(format!("{field} is required and must hold PEM text")))
}

/// Store a certificate the proxy could actually serve.
///
/// Until this checked anything, the endpoint accepted any two strings, reported
/// `status: active`, and left the operator believing a certificate was installed.
/// The listener then skipped the row at startup with a WARN, because Pingora's
/// `build()` panics on material it cannot load and [`gateway::tls_listener`]
/// screens for that first — so the upload was not merely unvalidated, it was
/// *known* to be unusable by the only component that would ever read it, one
/// restart later and in a log nobody was watching.
///
/// Rejection is limited to what can never work for anyone: PEM that does not
/// parse, and a key that is not the certificate's. **Expiry is not a rejection.**
/// A not-yet-valid certificate is a legitimate upload — staging a renewal ahead
/// of its `notBefore` is the normal way to avoid a scramble — and an expired one
/// still has uses (a pinned client, a verification-off internal probe) and fails
/// loudly and visibly at the browser rather than silently at startup. Checking it
/// at the door would also buy less than it appears to: nothing re-checks the row
/// afterwards, so "it validated on upload" would mean only that it had not
/// expired at one past instant, while inviting the reading that a stored
/// certificate is a valid one. Both cases are reported as `warnings` instead, and
/// the validity window is now persisted so the expiry alert
/// (`list_certificates_expiring_within`, which filters `not_after IS NOT NULL`)
/// can see a manual upload at all — it never could before.
pub async fn upload_certificate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCertificate>,
) -> ApiResult<Json<Value>> {
    let cert_pem = require_pem(req.cert_pem.as_ref(), "cert_pem")?;
    let key_pem = require_pem(req.key_pem.as_ref(), "key_pem")?;
    let chain = served_chain(cert_pem, req.chain_pem.as_deref());

    gateway::tls_listener::validate(&chain, key_pem).map_err(|e| {
        ApiError::BadRequest(format!(
            "{e:#}. Nothing was stored. Confirm the two files belong together — `openssl x509 -noout -pubkey -in \
             cert.pem` and `openssl pkey -pubout -in key.pem` must print the same key — and that each holds the \
             whole BEGIN/END block."
        ))
    })?;
    let facts = gateway::tls_listener::inspect(&chain)
        .map_err(|e| ApiError::BadRequest(format!("{e:#}. Nothing was stored.")))?;

    let now = chrono::Utc::now();
    let mut warnings: Vec<String> = Vec::new();
    if facts.not_after <= now {
        warnings.push(format!(
            "this certificate expired on {} and every client will refuse it; it was stored and will be served anyway, \
             because refusing it here would not be a decision this endpoint can keep making",
            facts.not_after.format("%Y-%m-%d %H:%M:%SZ")
        ));
    } else if facts.not_before > now {
        warnings.push(format!(
            "this certificate is not valid until {}; clients will refuse it until then",
            facts.not_before.format("%Y-%m-%d %H:%M:%SZ")
        ));
    }

    let row = state.db.create_certificate(req.clone()).await?;
    // Second statement, and deliberately not folded into the INSERT: the insert
    // lands `status = 'pending'`, and only this fills the validity window and
    // promotes the row to `active`. If it fails, what survives is a pending row
    // with no metadata — which the listener skips — rather than an active row
    // whose columns say nothing about what it holds.
    state
        .db
        .update_certificate_pem(&waf_storage::models::UpdateCertificatePem {
            id: row.id,
            cert_pem,
            key_pem,
            chain_pem: req.chain_pem.as_deref(),
            not_before: facts.not_before,
            not_after: facts.not_after,
            issuer: &facts.issuer,
            subject: &facts.subject,
        })
        .await?;
    Ok(Json(json!({
        "success": true,
        "data": {
            "id": row.id,
            "domain": row.domain,
            "status": "active",
            "not_before": facts.not_before,
            "not_after": facts.not_after,
            "issuer": facts.issuer,
            "subject": facts.subject,
            "warnings": warnings,
            // Stored is not served. The TLS listener reads this table once,
            // while Pingora builds the endpoint, and Pingora offers no way to
            // replace an acceptor's certificate on a running one — so an upload
            // that reported success and changed nothing on the wire would be
            // indistinguishable, from here, from one that worked.
            "activation": "Stored. The proxy's TLS listener reads certificates at startup only; \
                           run `prx-waf run --upgrade` to serve this one without dropping connections.",
        }
    })))
}

pub async fn delete_certificate(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_certificate(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Certificate {id} not found")));
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    // ── Certificate upload validation ────────────────────────────────────────
    //
    // The pairing and parse checks themselves are `gateway::tls_listener`'s and
    // are tested there against real rcgen material. What is pinned here is the
    // part this module owns: that the upload path hands the listener the SAME
    // bytes it will serve (leaf + chain, not the leaf alone), and that a blank
    // field is refused before any of it runs.

    #[test]
    fn a_missing_pem_field_is_refused_by_name() {
        let err = super::require_pem(None, "cert_pem").expect_err("a missing field must not pass");
        assert!(format!("{err}").contains("cert_pem"), "{err}");
    }

    #[test]
    fn a_whitespace_only_pem_field_is_refused() {
        let blank = "   \n\t ".to_string();
        assert!(super::require_pem(Some(&blank), "key_pem").is_err());
    }

    #[test]
    fn a_present_pem_field_is_trimmed_not_rejected() {
        let padded = "  -----BEGIN CERTIFICATE-----\n".to_string();
        let got = super::require_pem(Some(&padded), "cert_pem").expect("a non-blank field must pass");
        assert!(got.starts_with("-----BEGIN"), "{got}");
    }

    #[test]
    fn the_chain_is_appended_the_way_the_listener_appends_it() {
        // Mirrors `tls_listener::resolve`: leaf first, one newline, intermediates
        // after. Validating the leaf alone would accept a broken bundle.
        let joined = super::served_chain("LEAF\n", Some("  INTERMEDIATE\n"));
        assert_eq!(joined, "LEAF\nINTERMEDIATE\n");
    }

    #[test]
    fn an_absent_or_blank_chain_leaves_the_leaf_alone() {
        assert_eq!(super::served_chain("LEAF", None), "LEAF");
        assert_eq!(super::served_chain("LEAF", Some("   ")), "LEAF");
    }

    /// Replicates the port validation logic used in `create_host` / `update_host`.
    fn is_valid_port(port: i32) -> bool {
        (1..=65535).contains(&port)
    }

    #[test]
    fn port_validation_valid_range() {
        assert!(is_valid_port(80));
        assert!(is_valid_port(443));
        assert!(is_valid_port(8080));
    }

    #[test]
    fn port_validation_zero_rejected() {
        assert!(!is_valid_port(0));
    }

    #[test]
    fn port_validation_over_65535_rejected() {
        assert!(!is_valid_port(65536));
        assert!(!is_valid_port(100_000));
    }

    #[test]
    fn port_validation_boundary_1() {
        assert!(is_valid_port(1));
    }

    #[test]
    fn port_validation_boundary_65535() {
        assert!(is_valid_port(65535));
    }

    #[test]
    fn port_validation_negative_rejected() {
        assert!(!is_valid_port(-1));
    }

    #[test]
    fn port_validation_i32_min_rejected() {
        assert!(!is_valid_port(i32::MIN));
    }

    #[test]
    fn port_validation_i32_max_rejected() {
        assert!(!is_valid_port(i32::MAX));
    }

    // ── host log_only_mode wiring (regression for the create/update_host bug) ──
    //
    // Proves the FULL runtime path, not just a field copy: a persisted `Host`
    // with `log_only_mode` set is projected by the SAME `host_runtime_config`
    // helper the handlers use, and the resulting `HostConfig` is fed to a real
    // `WafEngine`. A malicious SQLi request must Block when the host is NOT in
    // log-only mode and downgrade to LogOnly when it IS — so the previously
    // dropped `log_only_mode` field is observably honoured end-to-end.
    //
    // DB-gated exactly like the engine parity suite (`WafEngine::new` needs a
    // live Postgres for the security-event log path). Run with:
    //
    //   DATABASE_URL=postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf \
    //     cargo test -p waf-api -- --ignored --nocapture
    use super::host_runtime_config;
    use std::collections::HashMap;
    use std::sync::Arc;

    use bytes::Bytes;
    use chrono::Utc;
    use uuid::Uuid;
    use waf_common::{RequestCtx, WafAction};
    use waf_engine::{WafEngine, WafEngineConfig};
    use waf_storage::Database;
    use waf_storage::models::Host;

    fn database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://prx_waf:prx_waf@127.0.0.1:15432/prx_waf".to_string())
    }

    /// A persisted host row with the given `log_only_mode`; all other fields are
    /// benign defaults (guard on, no load-balancing).
    fn sample_host(log_only_mode: bool) -> Host {
        Host {
            id: Uuid::new_v4(),
            code: "h-logonly".to_string(),
            host: "example.com".to_string(),
            port: 80,
            ssl: false,
            guard_status: true,
            remote_host: "127.0.0.1".to_string(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            exclude_url_log: None,
            is_enable_load_balance: false,
            load_balance_stage: 0,
            defense_json: None,
            log_only_mode,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// A malicious `SQLi` request bound to the projected runtime config. Benign
    /// User-Agent keeps the header-phase scanner/bot detectors from firing ahead
    /// of the `SQLi` content detector.
    fn malicious_ctx(host: &Host) -> RequestCtx {
        let host_config = Arc::new(host_runtime_config(host));
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0 (logonly-wiring)".to_string());
        RequestCtx {
            req_id: "logonly-wiring".to_string(),
            client_ip: "198.51.100.9".parse().expect("ip"),
            client_port: 54321,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: "id=1 union select 1,2,3".to_string(),
            headers,
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
        }
    }

    async fn engine() -> WafEngine {
        let db = Arc::new(Database::connect(&database_url(), 5).await.expect("connect Postgres"));
        db.migrate().await.expect("migrate");
        WafEngine::new(db, WafEngineConfig::default())
    }

    #[tokio::test]
    #[ignore = "requires live Postgres; run with --ignored"]
    async fn host_runtime_config_carries_log_only_false_blocks() {
        let eng = engine().await;
        let host = sample_host(false);
        // Sanity: the projection actually carried the field the bug dropped.
        assert!(!host_runtime_config(&host).log_only_mode);
        let mut ctx = malicious_ctx(&host);
        let decision = eng.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::Block { status: 403, .. }),
            "log_only_mode=false host must Block the SQLi request, got {:?}",
            decision.action
        );
    }

    #[tokio::test]
    #[ignore = "requires live Postgres; run with --ignored"]
    async fn host_runtime_config_carries_log_only_true_downgrades_to_logonly() {
        let eng = engine().await;
        let host = sample_host(true);
        assert!(host_runtime_config(&host).log_only_mode);
        let mut ctx = malicious_ctx(&host);
        let decision = eng.inspect(&mut ctx).await;
        assert!(
            matches!(decision.action, WafAction::LogOnly),
            "log_only_mode=true host must downgrade the SQLi Block to LogOnly, got {:?}",
            decision.action
        );
        assert!(decision.is_allowed(), "LogOnly must forward (be allowed)");
        assert!(decision.result.is_some(), "the SQLi detection must still be recorded");
    }
}
