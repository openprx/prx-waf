//! Phase 4: Cluster API handlers
//!
//! Routes (only active when `cluster_state` is Some in AppState):
//!   GET  /api/cluster/status        — topology + health
//!   GET  /api/cluster/nodes         — list all nodes with health
//!   GET  /api/cluster/nodes/:id     — single node detail
//!   POST /api/cluster/token         — generate join token (main node only)
//!   POST /api/cluster/nodes/remove  — remove a node from the peer list

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use tracing::warn;
use waf_cluster::NodeState;
use waf_common::config::NodeRole;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn node_health(last_seen_ms: u64) -> &'static str {
    let age_ms = now_ms().saturating_sub(last_seen_ms);
    if age_ms < 5_000 {
        "healthy"
    } else if age_ms < 15_000 {
        "suspect"
    } else {
        "dead"
    }
}

fn require_cluster(state: &AppState) -> ApiResult<Arc<NodeState>> {
    state
        .cluster_state
        .clone()
        .ok_or_else(|| ApiError::NotFound("cluster not enabled".into()))
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub role: NodeRole,
    pub addr: Option<String>,
    pub last_seen_ms: Option<u64>,
    pub health: &'static str,
    pub is_self: bool,
    pub rules_version: u64,
    pub config_version: u64,
}

#[derive(Debug, Serialize)]
pub struct ClusterStatusResponse {
    pub enabled: bool,
    pub node_id: String,
    pub role: NodeRole,
    pub term: u64,
    pub total_nodes: usize,
    pub rules_version: u64,
    pub config_version: u64,
    pub listen_addr: String,
    pub nodes: Vec<NodeInfo>,
}

#[derive(Debug, Serialize)]
pub struct NodeListResponse {
    pub nodes: Vec<NodeInfo>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct NodeDetailResponse {
    pub node_id: String,
    pub role: NodeRole,
    pub addr: Option<String>,
    pub last_seen_ms: Option<u64>,
    pub health: &'static str,
    pub is_self: bool,
    pub term: u64,
    pub rules_version: u64,
    pub config_version: u64,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token: String,
    pub ttl_ms: u64,
}

#[derive(Debug, Deserialize)]
pub struct GenerateTokenRequest {
    pub ttl_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct RemoveNodeRequest {
    pub node_id: String,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /api/cluster/status — cluster topology + health
pub async fn cluster_status(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<ClusterStatusResponse>> {
    let ns = require_cluster(&state)?;

    let role = *ns.role.read().await;
    let term = *ns.term.read().await;
    let rules_version = *ns.rules_version.read().await;
    let config_version = *ns.config_version.read().await;
    let peers = ns.peers.read().await.clone();

    let mut nodes: Vec<NodeInfo> = peers
        .iter()
        .map(|p| NodeInfo {
            node_id: p.node_id.clone(),
            role: p.role,
            addr: Some(p.addr.to_string()),
            last_seen_ms: Some(p.last_seen_ms),
            health: node_health(p.last_seen_ms),
            is_self: false,
            rules_version: 0,
            config_version: 0,
        })
        .collect();

    nodes.insert(
        0,
        NodeInfo {
            node_id: ns.node_id.clone(),
            role,
            addr: Some(ns.config.listen_addr.clone()),
            last_seen_ms: None,
            health: "healthy",
            is_self: true,
            rules_version,
            config_version,
        },
    );

    let total = nodes.len();
    Ok(Json(ClusterStatusResponse {
        enabled: true,
        node_id: ns.node_id.clone(),
        role,
        term,
        total_nodes: total,
        rules_version,
        config_version,
        listen_addr: ns.config.listen_addr.clone(),
        nodes,
    }))
}

/// GET /api/cluster/nodes — list all nodes with health
pub async fn list_cluster_nodes(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<NodeListResponse>> {
    let ns = require_cluster(&state)?;

    let role = *ns.role.read().await;
    let rules_version = *ns.rules_version.read().await;
    let config_version = *ns.config_version.read().await;
    let peers = ns.peers.read().await.clone();

    let mut nodes: Vec<NodeInfo> = peers
        .iter()
        .map(|p| NodeInfo {
            node_id: p.node_id.clone(),
            role: p.role,
            addr: Some(p.addr.to_string()),
            last_seen_ms: Some(p.last_seen_ms),
            health: node_health(p.last_seen_ms),
            is_self: false,
            rules_version: 0,
            config_version: 0,
        })
        .collect();

    nodes.insert(
        0,
        NodeInfo {
            node_id: ns.node_id.clone(),
            role,
            addr: Some(ns.config.listen_addr.clone()),
            last_seen_ms: None,
            health: "healthy",
            is_self: true,
            rules_version,
            config_version,
        },
    );

    let total = nodes.len();
    Ok(Json(NodeListResponse { nodes, total }))
}

/// GET /api/cluster/nodes/:id — single node detail
pub async fn get_cluster_node(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<NodeDetailResponse>> {
    let ns = require_cluster(&state)?;

    // Check if querying self
    if ns.node_id == id {
        let role = *ns.role.read().await;
        let term = *ns.term.read().await;
        let rules_version = *ns.rules_version.read().await;
        let config_version = *ns.config_version.read().await;
        return Ok(Json(NodeDetailResponse {
            node_id: ns.node_id.clone(),
            role,
            addr: Some(ns.config.listen_addr.clone()),
            last_seen_ms: None,
            health: "healthy",
            is_self: true,
            term,
            rules_version,
            config_version,
        }));
    }

    let peer = {
        let peers = ns.peers.read().await;
        peers.iter().find(|p| p.node_id == id).cloned()
    };

    let peer = peer.ok_or_else(|| ApiError::NotFound(format!("node '{id}' not found")))?;

    let term = *ns.term.read().await;
    Ok(Json(NodeDetailResponse {
        node_id: peer.node_id,
        role: peer.role,
        addr: Some(peer.addr.to_string()),
        last_seen_ms: Some(peer.last_seen_ms),
        health: node_health(peer.last_seen_ms),
        is_self: false,
        term,
        rules_version: 0,
        config_version: 0,
    }))
}

/// POST /api/cluster/token — generate a join token (main node only)
pub async fn generate_join_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GenerateTokenRequest>,
) -> ApiResult<Json<TokenResponse>> {
    let ns = require_cluster(&state)?;

    // Clone CA key out of parking_lot mutex without crossing an await point.
    let ca_key = ns.ca_key_pem.lock().clone().ok_or_else(|| {
        ApiError::NotFound("CA key not available — token generation requires the Main node".into())
    })?;

    let ttl_ms = req.ttl_ms.unwrap_or(3_600_000); // default 1 h

    let token = waf_cluster::crypto::token::generate_token(&ca_key, ttl_ms).map_err(|e| {
        warn!(err = %e, "Failed to generate cluster join token");
        ApiError::Internal(anyhow::anyhow!("token generation failed: {e}"))
    })?;

    Ok(Json(TokenResponse { token, ttl_ms }))
}

/// POST /api/cluster/nodes/remove — remove a node from the peer list
pub async fn remove_cluster_node(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RemoveNodeRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let ns = require_cluster(&state)?;

    if ns.node_id == req.node_id {
        return Err(ApiError::BadRequest(
            "cannot remove self from cluster".into(),
        ));
    }

    let mut peers = ns.peers.write().await;
    let before = peers.len();
    peers.retain(|p| p.node_id != req.node_id);

    if peers.len() == before {
        return Err(ApiError::NotFound(format!(
            "node '{}' not found",
            req.node_id
        )));
    }

    Ok(Json(serde_json::json!({ "removed": req.node_id })))
}
