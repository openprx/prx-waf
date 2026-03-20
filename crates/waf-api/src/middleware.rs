/// JWT authentication middleware for protected API routes.
use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::auth::validate_access_token;
use crate::state::AppState;

/// Axum middleware that validates the `Authorization: Bearer <token>` header.
///
/// On success, the request passes through unchanged.
/// On failure, a 401 JSON response is returned immediately.
pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);

    match token {
        Some(t) => match validate_access_token(&t, &state.jwt_secret) {
            Ok(_claims) => next.run(req).await,
            Err(_) => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "success": false, "error": "Invalid or expired token" })),
            )
                .into_response(),
        },
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "error": "Authorization header required" })),
        )
            .into_response(),
    }
}
