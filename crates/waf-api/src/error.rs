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
