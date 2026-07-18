/// JWT authentication and role-based authorization middleware.
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

use crate::auth::{Claims, validate_access_token};
use crate::state::AppState;

/// Axum middleware that validates the `Authorization: Bearer <token>` header.
///
/// On success, the decoded [`Claims`] are inserted into the request extensions
/// so downstream middleware (e.g. [`require_admin`]) and handlers can read the
/// authenticated identity, then the request passes through.
/// On failure, a 401 JSON response is returned immediately.
pub async fn require_auth(State(state): State<Arc<AppState>>, mut req: Request<Body>, next: Next) -> Response {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned);

    match token {
        Some(t) => match validate_access_token(&t, &state.jwt_secret) {
            Ok(claims) => {
                req.extensions_mut().insert(claims);
                next.run(req).await
            }
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

/// Axum middleware requiring the authenticated user to have the `admin` role.
///
/// Must run **after** [`require_auth`], which injects [`Claims`] into the
/// request extensions. Returns 403 when the caller is authenticated but not an
/// admin, and 401 when no authenticated identity is present.
pub async fn require_admin(req: Request<Body>, next: Next) -> Response {
    match req.extensions().get::<Claims>() {
        Some(claims) if claims.role == "admin" => next.run(req).await,
        Some(_) => (
            StatusCode::FORBIDDEN,
            Json(json!({ "success": false, "error": "Administrator privileges required" })),
        )
            .into_response(),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "success": false, "error": "Authentication required" })),
        )
            .into_response(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::{Router, middleware::from_fn};
    use tower::ServiceExt;

    /// Test middleware that injects [`Claims`] with the role from the
    /// `x-test-role` header, mimicking a successful `require_auth`.
    async fn inject_role(mut req: Request<Body>, next: Next) -> Response {
        let role = req
            .headers()
            .get("x-test-role")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if let Some(role) = role {
            req.extensions_mut().insert(Claims {
                sub: "00000000-0000-0000-0000-000000000000".to_owned(),
                username: "tester".to_owned(),
                role,
                exp: 0,
            });
        }
        next.run(req).await
    }

    /// Reproduces the server's route-split pattern: a read-only GET and an
    /// admin-only POST on the same path, merged, with `require_admin` gating
    /// only the admin group.
    fn app() -> Router {
        let readonly = Router::new().route("/r", get(|| async { "ok" }));
        let admin = Router::new()
            .route("/r", post(|| async { "ok" }))
            .route_layer(from_fn(require_admin));
        admin.merge(readonly).layer(from_fn(inject_role))
    }

    async fn call(method: &str, role: Option<&str>) -> StatusCode {
        let mut builder = Request::builder().method(method).uri("/r");
        if let Some(r) = role {
            builder = builder.header("x-test-role", r);
        }
        let req = builder.body(Body::empty()).unwrap();
        app().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn readonly_get_allowed_for_user_role() {
        assert_eq!(call("GET", Some("user")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn readonly_get_allowed_for_admin_role() {
        assert_eq!(call("GET", Some("admin")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_post_forbidden_for_user_role() {
        assert_eq!(call("POST", Some("user")).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_post_allowed_for_admin_role() {
        assert_eq!(call("POST", Some("admin")).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_post_unauthorized_without_claims() {
        // No injected Claims → require_admin returns 401.
        assert_eq!(call("POST", None).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn same_path_get_and_post_merge_without_panic() {
        // Merging a GET (read-only) and POST (admin) on the same path must not
        // panic and both methods must route.
        assert_eq!(call("GET", Some("user")).await, StatusCode::OK);
        assert_eq!(call("POST", Some("admin")).await, StatusCode::OK);
    }
}
