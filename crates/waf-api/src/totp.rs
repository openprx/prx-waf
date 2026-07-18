//! TOTP (RFC 6238) helpers for admin two-factor authentication.
//!
//! Secrets are stored as base32 (no padding) strings so they can be entered
//! directly into standard authenticator apps. Verification checks the current
//! 30-second window plus one window on each side (±30s clock skew) and enforces
//! replay protection: a step number may only be consumed once (strictly
//! increasing `last_step`), so a captured code cannot be reused.

use data_encoding::BASE32_NOPAD;
use totp_lite::{Sha1, totp_custom};

/// Time step in seconds (RFC 6238 default).
pub const TOTP_STEP: u64 = 30;
/// Number of digits in a generated code.
pub const TOTP_DIGITS: u32 = 6;
/// Secret length in bytes (160-bit, RFC 4226 recommended minimum).
const SECRET_LEN: usize = 20;

/// Generate a new random base32-encoded TOTP secret.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; SECRET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}

/// Build an `otpauth://` provisioning URI for authenticator apps.
pub fn provisioning_uri(issuer: &str, account: &str, secret_b32: &str) -> String {
    // Label and issuer are percent-encoded conservatively (only reserved chars
    // likely to appear in usernames are escaped).
    let account = account.replace(':', "%3A").replace(' ', "%20");
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}"
    )
}

/// Constant-time equality for two byte slices of equal length.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify a submitted `code` against `secret_b32` at `now_unix`.
///
/// Accepts the current window and ±1 window. Enforces replay protection: the
/// matched step must be strictly greater than `last_step`. On success returns
/// `Some(matched_step)` — the caller must persist it as the new `last_step`.
/// Returns `None` if the secret is malformed, the code is malformed, or no
/// window matches (including replayed / stale codes).
pub fn verify_code(secret_b32: &str, code: &str, now_unix: u64, last_step: u64) -> Option<u64> {
    let secret = BASE32_NOPAD.decode(secret_b32.as_bytes()).ok()?;
    let code = code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let step = now_unix / TOTP_STEP;
    // Check oldest → newest so we settle on the smallest still-valid step; any
    // candidate not strictly greater than the last consumed step is a replay.
    for candidate in [step.saturating_sub(1), step, step.saturating_add(1)] {
        if candidate <= last_step {
            continue;
        }
        let expected = totp_custom::<Sha1>(TOTP_STEP, TOTP_DIGITS, &secret, candidate.saturating_mul(TOTP_STEP));
        if ct_eq(expected.as_bytes(), code.as_bytes()) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn code_at(secret_b32: &str, step: u64) -> String {
        let secret = BASE32_NOPAD.decode(secret_b32.as_bytes()).unwrap();
        totp_custom::<Sha1>(TOTP_STEP, TOTP_DIGITS, &secret, step * TOTP_STEP)
    }

    #[test]
    fn secret_is_valid_base32() {
        let s = generate_secret();
        assert!(BASE32_NOPAD.decode(s.as_bytes()).is_ok());
        assert_eq!(BASE32_NOPAD.decode(s.as_bytes()).unwrap().len(), SECRET_LEN);
    }

    #[test]
    fn correct_code_accepted() {
        let secret = generate_secret();
        let now = 1_000_000_u64;
        let step = now / TOTP_STEP;
        let code = code_at(&secret, step);
        assert_eq!(verify_code(&secret, &code, now, 0), Some(step));
    }

    #[test]
    fn wrong_code_rejected() {
        let secret = generate_secret();
        let now = 1_000_000_u64;
        assert_eq!(verify_code(&secret, "000000", now, 0), None);
    }

    #[test]
    fn replay_same_step_rejected() {
        let secret = generate_secret();
        let now = 1_000_000_u64;
        let step = now / TOTP_STEP;
        let code = code_at(&secret, step);
        // First use succeeds and consumes `step`.
        assert_eq!(verify_code(&secret, &code, now, 0), Some(step));
        // Reusing the same code with last_step == step is a replay.
        assert_eq!(verify_code(&secret, &code, now, step), None);
    }

    #[test]
    fn prev_window_accepted_within_skew() {
        let secret = generate_secret();
        let now = 1_000_000_u64;
        let step = now / TOTP_STEP;
        let prev_code = code_at(&secret, step - 1);
        assert_eq!(verify_code(&secret, &prev_code, now, 0), Some(step - 1));
    }

    #[test]
    fn next_window_accepted_within_skew() {
        let secret = generate_secret();
        let now = 1_000_000_u64;
        let step = now / TOTP_STEP;
        let next_code = code_at(&secret, step + 1);
        assert_eq!(verify_code(&secret, &next_code, now, 0), Some(step + 1));
    }

    #[test]
    fn stale_code_two_windows_old_rejected() {
        let secret = generate_secret();
        let now = 1_000_000_u64;
        let step = now / TOTP_STEP;
        let old_code = code_at(&secret, step - 2);
        assert_eq!(verify_code(&secret, &old_code, now, 0), None);
    }

    #[test]
    fn malformed_code_rejected() {
        let secret = generate_secret();
        let now = 1_000_000_u64;
        assert_eq!(verify_code(&secret, "abc", now, 0), None);
        assert_eq!(verify_code(&secret, "12345", now, 0), None);
        assert_eq!(verify_code(&secret, "1234567", now, 0), None);
    }

    #[test]
    fn malformed_secret_rejected() {
        let now = 1_000_000_u64;
        assert_eq!(verify_code("not-base32-!!!", "123456", now, 0), None);
    }
}
