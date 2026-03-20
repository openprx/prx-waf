/// JWT-based authentication handlers.
///
/// Endpoints:
///   POST /api/auth/login   — returns access_token + refresh_token
///   POST /api/auth/logout  — revokes the refresh_token
///   POST /api/auth/refresh — exchanges refresh_token for a new access_token
use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::{Json, extract::State};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use waf_storage::models::CreateAdminUser;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── JWT claims ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject — admin user UUID as string
    pub sub: String,
    pub username: String,
    pub role: String,
    /// Expiration timestamp (Unix seconds)
    pub exp: i64,
}

// ─── Token helpers ────────────────────────────────────────────────────────────

pub fn generate_access_token(
    user_id: Uuid,
    username: &str,
    role: &str,
    secret: &str,
) -> anyhow::Result<String> {
    let exp = (Utc::now() + chrono::Duration::hours(24)).timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        exp,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

pub fn validate_access_token(token: &str, secret: &str) -> anyhow::Result<Claims> {
    let mut v = Validation::default();
    v.leeway = 0;
    let data = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &v)?;
    Ok(data.claims)
}

pub fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("password hash error: {e}"))?
        .to_string();
    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ─── Request / Response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let user = state
        .db
        .get_admin_user_by_username(&req.username)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Invalid credentials".into()))?;

    if !user.is_active {
        return Err(ApiError::Unauthorized("Account disabled".into()));
    }

    if !verify_password(&req.password, &user.password_hash) {
        return Err(ApiError::Unauthorized("Invalid credentials".into()));
    }

    let access_token =
        generate_access_token(user.id, &user.username, &user.role, &state.jwt_secret)
            .map_err(ApiError::Internal)?;

    // Generate a random refresh token
    let raw_refresh: String = {
        use rand::Rng;
        rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect()
    };
    let token_hash = hash_token(&raw_refresh);
    let expires_at = Utc::now() + chrono::Duration::days(7);

    state
        .db
        .create_refresh_token(user.id, &token_hash, expires_at)
        .await?;

    state.db.update_admin_user_last_login(user.id).await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "Bearer",
            "expires_in": 86400,
        }
    })))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let token_hash = hash_token(&req.refresh_token);
    state.db.revoke_refresh_token(&token_hash).await?;
    Ok(Json(
        serde_json::json!({ "success": true, "data": "logged out" }),
    ))
}

pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let token_hash = hash_token(&req.refresh_token);
    let stored = state
        .db
        .get_refresh_token_by_hash(&token_hash)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("Invalid or expired refresh token".into()))?;

    let user = state
        .db
        .get_admin_user_by_id(stored.user_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("User not found".into()))?;

    if !user.is_active {
        return Err(ApiError::Unauthorized("Account disabled".into()));
    }

    let access_token =
        generate_access_token(user.id, &user.username, &user.role, &state.jwt_secret)
            .map_err(ApiError::Internal)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "data": {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 86400,
        }
    })))
}

/// Bootstrap: create the default admin user if no users exist.
///
/// If `ADMIN_PASSWORD` is set, uses that value. Otherwise generates a random
/// 24-character password and prints it **once** to stdout so the operator can
/// capture it from the initial startup log.
pub async fn ensure_default_admin(state: &AppState) -> anyhow::Result<()> {
    let count = state.db.admin_users_count().await?;
    if count == 0 {
        let (password, generated) = match std::env::var("ADMIN_PASSWORD") {
            Ok(p) if !p.is_empty() => (p, false),
            _ => {
                use rand::Rng;
                let pw: String = rand::thread_rng()
                    .sample_iter(&rand::distributions::Alphanumeric)
                    .take(24)
                    .map(char::from)
                    .collect();
                (pw, true)
            }
        };
        let hash = hash_password(&password)?;
        state
            .db
            .create_admin_user(
                CreateAdminUser {
                    username: "admin".into(),
                    email: None,
                    password: password.clone(),
                    role: Some("admin".into()),
                },
                &hash,
            )
            .await?;
        if generated {
            // Print to stdout (not tracing) so operators can capture the initial password.
            // This is intentionally printed only once on first startup.
            println!("============================================================");
            println!("  ADMIN USER CREATED");
            println!("  Username: admin");
            println!("  Password: {password}");
            println!("  CHANGE THIS PASSWORD IMMEDIATELY!");
            println!("============================================================");
        }
        tracing::info!("Created default admin user (username=admin)");
    }
    Ok(())
}
