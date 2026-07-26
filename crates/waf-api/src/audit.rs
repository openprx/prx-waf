//! Admin action audit trail — the writer side of the `audit_log` table.
//!
//! # Why this exists
//!
//! `audit_log` answers a different question from every other history table this
//! product keeps. `security_events` / `attack_logs` record what *traffic* did;
//! `crowdsec_events` records what an *external decision source* did;
//! [`waf_engine::audit_log`] is a file-based, `ModSecurity`-shaped record of which
//! CRS rules a *request* touched. None of them record what an **operator** did to
//! the WAF's own configuration — who unblocked an IP, who deleted a host, who
//! uploaded a certificate, who was refused. That is the trail an incident review
//! needs when the question is "did someone change the WAF" rather than "did
//! someone attack it", and it is the only trail that survives the mutation it
//! describes: a deleted block-ip rule leaves no other evidence it ever existed.
//!
//! The table, its retention window (`storage.audit_log_retention_days`) and the
//! read endpoint (`GET /api/audit-log`) all shipped without a single writer, so
//! the endpoint could only ever return an empty list. This module is that writer.
//!
//! # What is recorded
//!
//! Every **mutating** request that reaches the admin route group: method,
//! normalised path, the authenticated username, the client IP, and the response
//! status. Reads (`GET`/`HEAD`/`OPTIONS`) are not recorded — they change nothing
//! and would bury the mutations under dashboard polling.
//!
//! Failures are recorded too. This middleware sits *outside* [`require_admin`],
//! so a non-admin's attempt to `DELETE /api/hosts/{id}` produces a row with
//! status 403. An audit trail that only kept successes would hide exactly the
//! events a review is looking for.
//!
//! # What is deliberately not recorded
//!
//! Request bodies. They carry TLS private keys (`POST /api/certificates`),
//! `CrowdSec` bouncer keys (`PUT /api/crowdsec/config`), SMTP passwords and
//! webhook URLs (`POST /api/notifications`). The row keeps *what* was touched,
//! never *with what secret*.

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request},
    middleware::Next,
    response::Response,
};
use serde_json::json;
use tracing::warn;

use crate::auth::Claims;
use crate::state::AppState;

/// Column widths from `migrations/0005_plugins_and_tunnels.sql`. A value longer
/// than its column makes Postgres reject the whole `INSERT`, which would drop
/// the audit row for the very request most worth recording, so every field is
/// truncated to fit before it is bound.
const MAX_ACTION_LEN: usize = 255;
const MAX_RESOURCE_TYPE_LEN: usize = 128;
const MAX_RESOURCE_ID_LEN: usize = 255;
const MAX_USERNAME_LEN: usize = 255;
const MAX_IP_LEN: usize = 64;

/// The identity of one mutating admin call, as the audit table needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTarget {
    /// `DELETE /api/hosts/{id}` — the *shape* of the call, with concrete ids
    /// replaced, so `action` stays low-cardinality and groupable.
    pub action: String,
    /// First path segment under `/api` (`hosts`, `notifications`, …).
    pub resource_type: Option<String>,
    /// The concrete id the call addressed, when the route takes one.
    pub resource_id: Option<String>,
}

/// Whether a method changes state and therefore belongs in the trail.
const fn is_mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Truncate on a character boundary — `String::truncate` panics mid-codepoint,
/// and a path segment is attacker-supplied text.
fn clamp(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// Does this segment look like a concrete resource id rather than a route word?
///
/// Every id this API routes on is either a UUID (`/api/hosts/{id}`), a decimal
/// id, or an opaque host/cache key (`/api/cache/host/{host}`). Route words are
/// lower-case ASCII letters plus `-` (`test`, `enable`, `nodes`, `rule-sources`),
/// so anything containing a digit, an upper-case letter, or a character outside
/// that alphabet is treated as an id and lifted out of `action`.
fn looks_like_id(segment: &str) -> bool {
    !segment.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c == '_')
}

/// Split a request path into the audit row's `action` / `resource_type` /
/// `resource_id`.
///
/// Pure and total: an unroutable path still yields an action, because the row
/// is written before the router's own 404 is known to be a 404.
#[must_use]
pub fn target_of(method: &Method, path: &str) -> AuditTarget {
    let mut resource_type = None;
    let mut resource_id = None;
    let mut shape = String::with_capacity(path.len());

    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        shape.push('/');
        if looks_like_id(segment) && resource_type.is_some() {
            shape.push_str("{id}");
            if resource_id.is_none() {
                resource_id = Some(clamp(segment, MAX_RESOURCE_ID_LEN));
            }
        } else {
            shape.push_str(segment);
            if resource_type.is_none() && segment != "api" {
                resource_type = Some(clamp(segment, MAX_RESOURCE_TYPE_LEN));
            }
        }
    }
    if shape.is_empty() {
        shape.push('/');
    }

    AuditTarget {
        action: clamp(&format!("{method} {shape}"), MAX_ACTION_LEN),
        resource_type,
        resource_id,
    }
}

/// Record every mutating admin API call in `audit_log`.
///
/// Placed on the admin route group **outside** [`crate::middleware::require_admin`]
/// and **inside** [`crate::middleware::require_auth`], so [`Claims`] are already
/// present but an authorization failure is still observed.
///
/// A failed insert never fails the request: the operator's change already
/// happened, and turning a storage hiccup into a 500 would be worse than a
/// missing row. It is logged at `warn` so the gap is visible.
pub async fn audit_log_middleware(State(state): State<Arc<AppState>>, req: Request<Body>, next: Next) -> Response {
    if !is_mutating(req.method()) {
        return next.run(req).await;
    }

    let target = target_of(req.method(), req.uri().path());
    let username = req
        .extensions()
        .get::<Claims>()
        .map(|c| clamp(&c.username, MAX_USERNAME_LEN));
    let ip = req
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| clamp(&ci.0.ip().to_string(), MAX_IP_LEN));

    let response = next.run(req).await;
    let status = response.status();

    if let Err(e) = state
        .db
        .create_audit_log(
            username.as_deref(),
            &target.action,
            target.resource_type.as_deref(),
            target.resource_id.as_deref(),
            Some(json!({ "status": status.as_u16(), "outcome": outcome_of(status) })),
            ip.as_deref(),
        )
        .await
    {
        warn!(action = %target.action, "audit_log write failed: {e}");
    }

    response
}

/// Coarse outcome label, so a reviewer can filter without knowing HTTP codes.
fn outcome_of(status: axum::http::StatusCode) -> &'static str {
    if status.is_success() {
        "success"
    } else if status.is_client_error() {
        "denied"
    } else {
        "error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_not_audited() {
        assert!(!is_mutating(&Method::GET));
        assert!(!is_mutating(&Method::HEAD));
        assert!(!is_mutating(&Method::OPTIONS));
        assert!(is_mutating(&Method::POST));
        assert!(is_mutating(&Method::PUT));
        assert!(is_mutating(&Method::DELETE));
        assert!(is_mutating(&Method::PATCH));
    }

    #[test]
    fn a_collection_call_names_only_its_resource() {
        let t = target_of(&Method::POST, "/api/hosts");
        assert_eq!(t.action, "POST /api/hosts");
        assert_eq!(t.resource_type.as_deref(), Some("hosts"));
        assert_eq!(t.resource_id, None);
    }

    #[test]
    fn a_uuid_is_lifted_out_of_the_action() {
        let t = target_of(&Method::DELETE, "/api/hosts/6f1b1d0e-0000-4000-8000-000000000001");
        assert_eq!(t.action, "DELETE /api/hosts/{id}");
        assert_eq!(t.resource_type.as_deref(), Some("hosts"));
        assert_eq!(t.resource_id.as_deref(), Some("6f1b1d0e-0000-4000-8000-000000000001"));
    }

    #[test]
    fn a_sub_action_after_an_id_survives_in_the_action() {
        let t = target_of(&Method::POST, "/api/notifications/42/test");
        assert_eq!(t.action, "POST /api/notifications/{id}/test");
        assert_eq!(t.resource_type.as_deref(), Some("notifications"));
        assert_eq!(t.resource_id.as_deref(), Some("42"));
    }

    #[test]
    fn route_words_are_never_mistaken_for_ids() {
        let t = target_of(&Method::POST, "/api/cluster/nodes/remove");
        assert_eq!(t.action, "POST /api/cluster/nodes/remove");
        assert_eq!(t.resource_type.as_deref(), Some("cluster"));
        assert_eq!(t.resource_id, None);
    }

    #[test]
    fn a_hostname_key_is_treated_as_an_id() {
        let t = target_of(&Method::DELETE, "/api/cache/host/Example.COM");
        assert_eq!(t.action, "DELETE /api/cache/host/{id}");
        assert_eq!(t.resource_id.as_deref(), Some("Example.COM"));
    }

    #[test]
    fn an_over_long_segment_cannot_overflow_its_column() {
        let long = "a1".repeat(400);
        let t = target_of(&Method::DELETE, &format!("/api/hosts/{long}"));
        assert!(t.action.len() <= MAX_ACTION_LEN);
        assert!(t.resource_id.is_some_and(|id| id.len() <= MAX_RESOURCE_ID_LEN));
    }

    #[test]
    fn a_multibyte_segment_is_truncated_on_a_char_boundary() {
        // 3 bytes per char: truncating to an odd byte count must not panic.
        let long = "€".repeat(200);
        assert!(clamp(&long, MAX_RESOURCE_ID_LEN).len() <= MAX_RESOURCE_ID_LEN);
    }

    #[test]
    fn the_root_path_still_yields_an_action() {
        assert_eq!(target_of(&Method::POST, "/").action, "POST /");
    }

    #[test]
    fn outcomes_are_labelled_for_every_status_class() {
        use axum::http::StatusCode;
        assert_eq!(outcome_of(StatusCode::OK), "success");
        assert_eq!(outcome_of(StatusCode::FORBIDDEN), "denied");
        assert_eq!(outcome_of(StatusCode::INTERNAL_SERVER_ERROR), "error");
    }
}
