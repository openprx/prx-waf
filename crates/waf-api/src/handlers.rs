use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use waf_storage::models::{
    AttackLogQuery, CreateCertificate, CreateCustomRule, CreateHost, CreateIpRule,
    CreateLbBackend, CreateSensitivePattern, CreateUrlRule, SecurityEventQuery, UpdateHost,
    UpsertHotlinkConfig,
};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Response wrapper ─────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Json<Self> {
        Json(Self { success: true, data })
    }
}

// ─── Hosts ────────────────────────────────────────────────────────────────────

pub async fn list_hosts(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let hosts = state.db.list_hosts().await?;
    Ok(Json(json!({ "success": true, "data": hosts })))
}

pub async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {} not found", id)))?;
    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn create_host(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateHost>,
) -> ApiResult<Json<Value>> {
    let host = state.db.create_host(req).await?;

    // Register with router
    use waf_common::HostConfig;
    let config = Arc::new(HostConfig {
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
        ..HostConfig::default()
    });
    state.router.register(config);

    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn update_host(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateHost>,
) -> ApiResult<Json<Value>> {
    let host = state
        .db
        .update_host(id, req)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {} not found", id)))?;
    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn delete_host(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_host(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Host {} not found", id)));
    }
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
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_allow_ip(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_allow_ip(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Allow IP {} not found", id)));
    }
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
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_block_ip(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_block_ip(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Block IP {} not found", id)));
    }
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
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_allow_url(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_allow_url(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Allow URL {} not found", id)));
    }
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
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_block_url(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_block_url(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Block URL {} not found", id)));
    }
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
    state
        .engine
        .reload_rules()
        .await
        .map_err(|e| ApiError::Internal(e))?;
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
    let row = state.db.create_custom_rule(req.clone()).await?;
    // Hot-add to engine
    use waf_engine::rules::engine::{from_db_rule};
    if let Ok(rule) = from_db_rule(&row) {
        state.engine.custom_rules.add_rule(rule);
    }
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_custom_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let rule = state.db.get_custom_rule(id).await?.ok_or_else(|| ApiError::NotFound(format!("Rule {} not found", id)))?;
    let deleted = state.db.delete_custom_rule(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Rule {} not found", id)));
    }
    state.engine.custom_rules.remove_rule(&rule.host_code, &rule.id.to_string());
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
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_sensitive_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_sensitive_pattern(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Pattern {} not found", id)));
    }
    if let Err(e) = state.engine.reload_rules().await {
        tracing::warn!("Failed to reload after pattern delete: {}", e);
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Hotlink Config ───────────────────────────────────────────────────────────

pub async fn get_hotlink_config(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let host_code = filter.host_code.ok_or_else(|| ApiError::BadRequest("host_code required".into()))?;
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

pub async fn delete_lb_backend(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_lb_backend(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Backend {} not found", id)));
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
    let safe: Vec<Value> = rows.iter().map(|c| json!({
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
    })).collect();
    Ok(Json(json!({ "success": true, "data": safe })))
}

pub async fn upload_certificate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCertificate>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_certificate(req.clone()).await?;
    state.db.update_certificate_status(row.id, "active", None).await?;
    Ok(Json(json!({
        "success": true,
        "data": {
            "id": row.id,
            "domain": row.domain,
            "status": "active",
        }
    })))
}

pub async fn delete_certificate(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_certificate(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Certificate {} not found", id)));
    }
    Ok(Json(json!({ "success": true, "data": null })))
}
