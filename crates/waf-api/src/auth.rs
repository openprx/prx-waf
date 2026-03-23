/// JWT-based authentication handlers.
///
/// Endpoints:
///   POST /api/auth/login   — returns `access_token` + `refresh_token`
///   POST /api/auth/logout  — revokes the `refresh_token`
///   POST /api/auth/refresh — exchanges `refresh_token` for a new `access_token`
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::extract::ConnectInfo;
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

pub fn generate_access_token(user_id: Uuid, username: &str, role: &str, secret: &str) -> anyhow::Result<String> {
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
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    // Enforce login-specific rate limit (stricter than general API)
    if let Some(ref limiter) = state.login_rate_limiter {
        let ip = connect_info
            .as_ref()
            .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ci| ci.0.ip());
        if !limiter.check(ip) {
            return Err(ApiError::TooManyRequests(
                "Too many login attempts, please try again later".into(),
            ));
        }
    }

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
        generate_access_token(user.id, &user.username, &user.role, &state.jwt_secret).map_err(ApiError::Internal)?;

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

    state.db.create_refresh_token(user.id, &token_hash, expires_at).await?;

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
    Ok(Json(serde_json::json!({ "success": true, "data": "logged out" })))
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
        generate_access_token(user.id, &user.username, &user.role, &state.jwt_secret).map_err(ApiError::Internal)?;

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
            #[allow(clippy::print_stdout)]
            {
                println!("============================================================");
                println!("  ADMIN USER CREATED");
                println!("  Username: admin");
                println!("  Password: {password}");
                println!("  CHANGE THIS PASSWORD IMMEDIATELY!");
                println!("============================================================");
            }
        }
        tracing::info!("Created default admin user (username=admin)");
    }
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};

    #[test]
    fn password_hash_roundtrip() {
        let hash = hash_password("test123").unwrap();
        assert!(verify_password("test123", &hash));
    }

    #[test]
    fn password_hash_wrong_password() {
        let hash = hash_password("test123").unwrap();
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn token_hash_deterministic() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
    }

    #[test]
    fn token_hash_different_tokens() {
        assert_ne!(hash_token("abc"), hash_token("def"));
    }

    #[test]
    fn jwt_create_and_validate() {
        let user_id = uuid::Uuid::new_v4();
        let secret = "test-secret-key";
        let token = generate_access_token(user_id, "alice", "admin", secret).unwrap();
        let claims = validate_access_token(&token, secret).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, "alice");
        assert_eq!(claims.role, "admin");
    }

    #[test]
    fn jwt_expired_rejected() {
        let claims = Claims {
            sub: "some-id".into(),
            username: "u".into(),
            role: "admin".into(),
            exp: 0,
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(b"secret")).unwrap();
        let result = validate_access_token(&token, "secret");
        assert!(result.is_err());
    }

    #[test]
    fn jwt_wrong_secret_rejected() {
        let user_id = uuid::Uuid::new_v4();
        let token = generate_access_token(user_id, "bob", "user", "secret1").unwrap();
        let result = validate_access_token(&token, "secret2");
        assert!(result.is_err());
    }

    #[test]
    fn jwt_claims_roundtrip() {
        let user_id = uuid::Uuid::new_v4();
        let secret = "roundtrip-secret";
        let token = generate_access_token(user_id, "carol", "viewer", secret).unwrap();
        let claims = validate_access_token(&token, secret).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.username, "carol");
        assert_eq!(claims.role, "viewer");
    }

    // JWT tampering: modifying the payload (role field) must be rejected by signature check.
    #[test]
    fn jwt_tampered_payload_rejected() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let user_id = uuid::Uuid::new_v4();
        let secret = "tamper-test-secret";
        let token = generate_access_token(user_id, "alice", "admin", secret).unwrap();

        // Split into header, payload, signature
        let mut iter = token.splitn(3, '.');
        let header_part = iter.next().expect("header");
        let payload_part = iter.next().expect("payload");
        let sig_part = iter.next().expect("signature");

        // Decode the payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_part).expect("valid base64url payload");
        let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).expect("valid JSON payload");

        // Tamper: change role to "superadmin"
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("role".to_owned(), serde_json::Value::String("superadmin".to_owned()));
        }

        // Re-encode the tampered payload
        let tampered_payload = URL_SAFE_NO_PAD.encode(serde_json::to_string(&payload).expect("serialize"));

        // Reassemble token with original header and signature but tampered payload
        let tampered_token = format!("{header_part}.{tampered_payload}.{sig_part}");

        // Validation must fail — signature no longer matches
        let result = validate_access_token(&tampered_token, secret);
        assert!(result.is_err(), "tampered JWT must be rejected");
    }

    // `hash_token("abc")` must produce the known SHA-256 hex digest for "abc".
    #[test]
    fn token_hash_known_answer() {
        use sha2::{Digest, Sha256};

        // Compute expected value independently
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        let expected = hex::encode(hasher.finalize());

        let got = hash_token("abc");
        assert_eq!(got.len(), 64, "SHA-256 hex digest must be 64 chars");
        assert_eq!(got, expected);
    }

    // `generate_access_token` should produce a token whose exp is ~now + 24h.
    #[test]
    fn jwt_exp_window() {
        use chrono::Utc;

        let user_id = uuid::Uuid::new_v4();
        let secret = "exp-window-secret";
        let before = Utc::now().timestamp();
        let token = generate_access_token(user_id, "dave", "admin", secret).unwrap();
        let after = Utc::now().timestamp();

        let claims = validate_access_token(&token, secret).unwrap();
        let expected_exp_low = before + 24 * 3600 - 60;
        let expected_exp_high = after + 24 * 3600 + 60;
        assert!(
            claims.exp >= expected_exp_low && claims.exp <= expected_exp_high,
            "exp={} not within 24h ±60s window [{}, {}]",
            claims.exp,
            expected_exp_low,
            expected_exp_high
        );
    }

    // `hash_password` and `verify_password` must work correctly with an empty string.
    #[test]
    fn password_hash_empty_string() {
        let hash = hash_password("").unwrap();
        assert!(
            verify_password("", &hash),
            "empty password must verify against its own hash"
        );
        assert!(
            !verify_password("nonempty", &hash),
            "non-empty password must not match empty hash"
        );
    }

    // `hash_password` must handle a very long password without error.
    #[test]
    fn password_hash_long_string() {
        let long_pw = "x".repeat(1000);
        let hash = hash_password(&long_pw).unwrap();
        assert!(
            verify_password(&long_pw, &hash),
            "long password must verify against its own hash"
        );
    }
}
