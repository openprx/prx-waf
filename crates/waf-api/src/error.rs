use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    /// A dependency the API talks to (`CrowdSec` LAPI, …) failed. The detail is
    /// logged server-side only: it typically embeds internal URLs, hostnames and
    /// connection diagnostics that must not reach the client.
    #[error("Upstream service error: {0}")]
    Upstream(anyhow::Error),

    /// A feature is not configured or not currently available. The message is
    /// authored here (never derived from an underlying error), so it is safe to
    /// return verbatim.
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Storage error: {0}")]
    Storage(#[from] waf_storage::StorageError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // 4xx client errors carry a specific, safe message. 5xx errors log the
        // detail server-side and return only a generic message to the client to
        // avoid leaking internal/database details.
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            // Invalid input rejected in the storage layer is a client error: the
            // message is caller-facing and carries no internal/DB detail.
            Self::BadRequest(msg) | Self::Storage(waf_storage::StorageError::InvalidInput(msg)) => {
                (StatusCode::BAD_REQUEST, msg.clone())
            }
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            Self::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            Self::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg.clone()),
            Self::Upstream(e) => {
                tracing::error!(error = %e, "upstream service error");
                (StatusCode::BAD_GATEWAY, "Upstream service error".to_owned())
            }
            Self::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_owned())
            }
            Self::Storage(e) => {
                tracing::error!(error = %e, "storage error");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_owned())
            }
        };

        let body = Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{ApiError, StatusCode};
    use axum::response::IntoResponse;

    /// Render an error the way axum would and return `(status, body)`.
    async fn render(err: ApiError) -> (StatusCode, String) {
        let resp = err.into_response();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// A database error whose text carries schema detail an attacker could map.
    fn db_error() -> waf_storage::StorageError {
        waf_storage::StorageError::Database(sqlx::Error::Protocol(
            "column notification_configs.config_json does not exist".to_owned(),
        ))
    }

    #[tokio::test]
    async fn database_error_body_reveals_nothing() {
        let (status, body) = render(ApiError::Storage(db_error())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"error":"Internal server error"}"#);
        assert!(!body.contains("notification_configs"), "schema leaked: {body}");
        assert!(!body.contains("column"), "schema leaked: {body}");
    }

    #[tokio::test]
    async fn internal_error_body_reveals_nothing() {
        let (status, body) = render(ApiError::Internal(anyhow::anyhow!(
            "MASTER_KEY missing while writing notification_configs"
        )))
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"error":"Internal server error"}"#);
        assert!(!body.contains("MASTER_KEY"), "config detail leaked: {body}");
    }

    #[tokio::test]
    async fn upstream_error_body_reveals_no_endpoint() {
        let (status, body) = render(ApiError::Upstream(anyhow::anyhow!(
            "error sending request for url (http://10.0.0.7:8080/v1/decisions): connection refused"
        )))
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body, r#"{"error":"Upstream service error"}"#);
        assert!(!body.contains("10.0.0.7"), "internal address leaked: {body}");
    }

    #[tokio::test]
    async fn client_errors_keep_their_message() {
        let (status, body) = render(ApiError::BadRequest("unknown channel_type: carrier".to_owned())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("unknown channel_type: carrier"));

        let (status, body) = render(ApiError::NotFound("Notification config 42 not found".to_owned())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("not found"));

        // Storage-layer input validation stays a 400 with its caller-facing text.
        let (status, body) = render(ApiError::Storage(waf_storage::StorageError::InvalidInput(
            "remote_ip must be an IP address".to_owned(),
        )))
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("remote_ip must be an IP address"));

        let (status, body) = render(ApiError::ServiceUnavailable("CrowdSec not enabled".to_owned())).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(body.contains("CrowdSec not enabled"));
    }
}
