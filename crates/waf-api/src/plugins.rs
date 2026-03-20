//! WASM Plugin API handlers

use std::sync::Arc;

use axum::extract::Multipart;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::json;
use tracing::info;
use uuid::Uuid;
use waf_storage::models::CreateWasmPlugin;

use crate::state::AppState;

/// GET /api/plugins — list all plugins
pub async fn list_plugins(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.list_wasm_plugins().await {
        Ok(rows) => {
            // Strip the binary from the listing response
            let list: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "name": r.name,
                        "version": r.version,
                        "description": r.description,
                        "author": r.author,
                        "enabled": r.enabled,
                        "config_json": r.config_json,
                        "created_at": r.created_at,
                        "updated_at": r.updated_at,
                        "wasm_size": r.wasm_binary.len(),
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "plugins": list }))).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/plugins — upload a WASM plugin via multipart form
///
/// Form fields:
///   - `name`        (text)  plugin identifier
///   - `version`     (text, optional)
///   - `description` (text, optional)
///   - `author`      (text, optional)
///   - `file`        (binary) the .wasm file
pub async fn upload_plugin(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut name = String::new();
    let mut version = None::<String>;
    let mut description = None::<String>;
    let mut author = None::<String>;
    let mut wasm_bytes = None::<Vec<u8>>;

    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("name") => {
                name = field.text().await.unwrap_or_default();
            }
            Some("version") => {
                version = Some(field.text().await.unwrap_or_default());
            }
            Some("description") => {
                description = Some(field.text().await.unwrap_or_default());
            }
            Some("author") => {
                author = Some(field.text().await.unwrap_or_default());
            }
            Some("file") => match field.bytes().await {
                Ok(b) => wasm_bytes = Some(b.to_vec()),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": format!("failed to read file: {e}") })),
                    )
                        .into_response();
                }
            },
            _ => {}
        }
    }

    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "plugin name is required" })),
        )
            .into_response();
    }

    let bytes = match wasm_bytes {
        Some(b) => b,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "WASM file is required" })),
            )
                .into_response();
        }
    };

    // Validate WASM magic bytes (\0asm)
    if bytes.len() < 4 || &bytes[..4] != b"\0asm" {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid WASM file (bad magic bytes)" })),
        )
            .into_response();
    }

    let req = CreateWasmPlugin {
        name: name.clone(),
        version: version.clone(),
        description: description.clone(),
        author: author.clone(),
        wasm_binary: bytes.clone(),
        enabled: Some(true),
        config_json: None,
    };

    // Persist to DB
    let row = match state.db.create_wasm_plugin(req).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    // Load into the plugin manager
    if let Err(e) = state
        .plugin_manager
        .load(waf_engine::plugins::manager::LoadPluginParams {
            id: row.id,
            name: row.name.clone(),
            version: row.version.clone(),
            description: row.description.clone().unwrap_or_default(),
            author: row.author.clone().unwrap_or_default(),
            enabled: row.enabled,
            wasm_bytes: &bytes,
        })
        .await
    {
        // Plugin stored but failed to compile — surface the error
        tracing::warn!(plugin=%name, "WASM compile error: {e}");
    }

    info!(plugin = %name, "Plugin uploaded");
    (
        StatusCode::CREATED,
        Json(json!({
            "id": row.id,
            "name": row.name,
            "version": row.version,
            "enabled": row.enabled,
        })),
    )
        .into_response()
}

/// DELETE /api/plugins/:id — remove a plugin
pub async fn delete_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    state.plugin_manager.unload(id).await;
    match state.db.delete_wasm_plugin(id).await {
        Ok(true) => (StatusCode::NO_CONTENT).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "plugin not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// POST /api/plugins/:id/enable
pub async fn enable_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    set_plugin_enabled(state, id, true).await
}

/// POST /api/plugins/:id/disable
pub async fn disable_plugin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    set_plugin_enabled(state, id, false).await
}

async fn set_plugin_enabled(state: Arc<AppState>, id: Uuid, enabled: bool) -> impl IntoResponse {
    state.plugin_manager.set_enabled(id, enabled).await;
    match state.db.set_wasm_plugin_enabled(id, enabled).await {
        Ok(true) => (StatusCode::OK, Json(json!({ "enabled": enabled }))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "plugin not found" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
