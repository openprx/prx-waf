//! Durable mirror of the `CrowdSec` bouncer decision cache.
//!
//! # Why this exists
//!
//! The bouncer's authority at runtime is the in-memory [`DecisionCache`], fed
//! by [`super::sync::run_decision_sync`] from the LAPI decision stream. That
//! cache starts **empty** on every process start, and
//! [`super::init_crowdsec`] used to hand the sync task to `tokio::spawn` and
//! return immediately. When the first full pull succeeds that window is a few
//! milliseconds — but when LAPI is unreachable at boot (container start order,
//! a network blip, the `CrowdSec` container not up yet) the pull fails, the
//! cache stays empty until the next poll succeeds, and
//! [`super::CrowdSecChecker`] answers `None` for *every* IP. Every previously
//! banned address is allowed through: fail-open, for as long as LAPI stays
//! down.
//!
//! `crowdsec_decisions` — created by migration `0006` and, until now, written
//! by nothing — closes that window. Its schema comment already called it a
//! "cache of active decisions synced from LAPI", it carries the decision's own
//! `expires_at`, it is indexed on `value`, and the retention pruner keys on
//! `expires_at`: every one of those is the shape of a recovery mirror, not of
//! an audit trail (the audit trail is `crowdsec_events`, append-only with a
//! `BIGSERIAL` key and a `created_at DESC` index).
//!
//! # Invariants
//!
//! * **The mirror never holds what the cache would reject.** Both sides apply
//!   [`DecisionCache::should_cache`], so the scenario filters cannot make the
//!   two diverge.
//! * **The mirror can never resurrect a lifted ban.** Deletions from the LAPI
//!   stream are removed from the mirror by `(scope, value)` — the same key the
//!   cache removes on — and every successful *full* pull replaces the mirror's
//!   entire contents ([`DecisionStore::replace_all`]), so a decision revoked
//!   while this process was down is deleted at the first pull that succeeds.
//! * **A broken database never breaks the WAF.** Every mirror operation is
//!   fallible and every failure is logged and swallowed: the mirror is a
//!   fallback, and a fallback that fails must not take down the thing it backs
//!   up. It is never silent — see [`restore_cache`] and the sync task's
//!   `error!` on a mirror write failure.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use tracing::{debug, warn};

use waf_storage::models::CrowdSecDecisionRow;
use waf_storage::{Database, StorageError};

use super::cache::{DecisionCache, decision_lifetime_secs};
use super::config::CrowdSecConfig;
use super::models::Decision;

/// How long startup will wait for the mirror read before giving up and
/// continuing without it.
///
/// The read is a single indexed local query, so the normal cost is
/// milliseconds; the bound exists so a wedged database cannot hold the process
/// short of serving traffic. Exceeding it is reported exactly like a failure,
/// because the consequence is the same one.
pub const RESTORE_TIMEOUT: Duration = Duration::from_secs(10);

/// Persistence backend for the decision mirror.
///
/// A trait rather than a bare `Arc<Database>` so the sync/restore logic is
/// testable without a live Postgres (and so an operator can turn the mirror off
/// by supplying `None`).
#[async_trait]
pub trait DecisionStore: Send + Sync + 'static {
    /// Every mirrored decision that has not expired yet.
    async fn load_active(&self) -> Result<Vec<CrowdSecDecisionRow>, StorageError>;

    /// Make the mirror hold exactly `rows`, deleting everything else.
    async fn replace_all(&self, rows: &[CrowdSecDecisionRow]) -> Result<u64, StorageError>;

    /// Insert or refresh `rows`, keyed on the upstream decision id.
    async fn upsert(&self, rows: &[CrowdSecDecisionRow]) -> Result<u64, StorageError>;

    /// Remove the mirrored decisions identified by `(scope, value)`.
    async fn delete(&self, keys: &[(String, String)]) -> Result<u64, StorageError>;
}

#[async_trait]
impl DecisionStore for Database {
    async fn load_active(&self) -> Result<Vec<CrowdSecDecisionRow>, StorageError> {
        self.load_active_crowdsec_decisions().await
    }

    async fn replace_all(&self, rows: &[CrowdSecDecisionRow]) -> Result<u64, StorageError> {
        self.replace_crowdsec_decisions(rows).await
    }

    async fn upsert(&self, rows: &[CrowdSecDecisionRow]) -> Result<u64, StorageError> {
        self.upsert_crowdsec_decisions(rows).await
    }

    async fn delete(&self, keys: &[(String, String)]) -> Result<u64, StorageError> {
        self.delete_crowdsec_decisions(keys).await
    }
}

/// What the startup restore actually did, so the operator-facing startup
/// broadcast can state where the process's decisions came from instead of
/// leaving it to be inferred from debug logs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Whether a mirror was configured at all.
    pub enabled: bool,
    /// Decisions loaded into the cache.
    pub restored: usize,
    /// Mirrored rows dropped because the decision had already expired by the
    /// local clock (the query filters on the *database* clock, so this counts
    /// clock skew and rows that expired between query and apply).
    pub skipped_expired: usize,
    /// Mirrored rows dropped by the configured scenario filters, which may have
    /// changed since the row was written.
    pub skipped_filtered: usize,
    /// Populated when the mirror could not be read. The cache is then empty at
    /// startup and the process is fail-open until the first LAPI pull lands.
    pub error: Option<String>,
}

/// Restore the in-memory cache from the durable mirror.
///
/// Awaited by [`super::init_crowdsec`] **before** it returns, i.e. before the
/// proxy binds its listeners. Doing it inside the spawned sync task instead
/// would leave exactly the race this function exists to remove: requests would
/// be served while the restore was still in flight. The cost is one indexed
/// local query, bounded by [`RESTORE_TIMEOUT`].
pub async fn restore_cache(
    cache: &DecisionCache,
    store: &dyn DecisionStore,
    config: &CrowdSecConfig,
) -> RestoreOutcome {
    let mut outcome = RestoreOutcome {
        enabled: true,
        ..RestoreOutcome::default()
    };

    let rows = match tokio::time::timeout(RESTORE_TIMEOUT, store.load_active()).await {
        Ok(Ok(rows)) => rows,
        Ok(Err(e)) => {
            outcome.error = Some(e.to_string());
            return outcome;
        }
        Err(_) => {
            outcome.error = Some(format!(
                "timed out after {}s reading crowdsec_decisions",
                RESTORE_TIMEOUT.as_secs()
            ));
            return outcome;
        }
    };

    let now = Utc::now();
    let mut restored = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(remaining) = remaining_lifetime(row.expires_at, now) else {
            outcome.skipped_expired += 1;
            continue;
        };
        let decision = row_to_decision(row);
        if !DecisionCache::should_cache(&decision, config) {
            outcome.skipped_filtered += 1;
            continue;
        }
        restored.push((decision, cache.restore_ttl(remaining)));
    }

    outcome.restored = cache.insert_restored(restored);
    debug!(
        restored = outcome.restored,
        skipped_expired = outcome.skipped_expired,
        skipped_filtered = outcome.skipped_filtered,
        "Restored CrowdSec decisions from the local mirror"
    );
    outcome
}

/// Remaining lifetime of a decision, or `None` once it has expired.
fn remaining_lifetime(expires_at: DateTime<Utc>, now: DateTime<Utc>) -> Option<Duration> {
    let remaining = expires_at.signed_duration_since(now);
    if remaining <= TimeDelta::zero() {
        return None;
    }
    u64::try_from(remaining.num_seconds()).ok().map(Duration::from_secs)
}

/// Rebuild the LAPI decision from a mirrored row.
///
/// `duration` is re-rendered from the stored seconds only so the value round
/// trips through the API listing; the cache TTL of a restored decision comes
/// from its stored `expires_at`, never from this string.
fn row_to_decision(row: CrowdSecDecisionRow) -> Decision {
    Decision {
        id: row.id,
        origin: row.origin,
        scope: row.scope,
        value: row.value,
        type_: row.type_,
        scenario: row.scenario,
        duration: row.duration_secs.map(|secs| format!("{secs}s")),
        created_at: None,
    }
}

/// The mirror rows for a batch of decisions coming off the LAPI stream.
///
/// Applies the cache's own scenario filter, converts each surviving decision to
/// its row form, and de-duplicates by upstream id — Postgres rejects an
/// `ON CONFLICT DO UPDATE` that would touch the same row twice in one
/// statement, so a stream that repeats an id must be collapsed here rather than
/// failing the whole batch. Later occurrences win, matching the cache, which
/// also keeps the last write.
///
/// Returns the rows plus the number of decisions dropped because a field did
/// not fit its column — one malformed upstream value must not cost the whole
/// batch.
pub fn rows_for(
    decisions: &[Decision],
    config: &CrowdSecConfig,
    now: DateTime<Utc>,
) -> (Vec<CrowdSecDecisionRow>, usize) {
    let mut oversized = 0usize;
    let mut built = Vec::with_capacity(decisions.len());
    for decision in decisions {
        if !DecisionCache::should_cache(decision, config) {
            continue;
        }
        match decision_to_row(decision, now) {
            Some(row) => built.push(row),
            None => oversized += 1,
        }
    }

    let mut seen = std::collections::HashSet::with_capacity(built.len());
    let mut deduped: Vec<CrowdSecDecisionRow> = built.into_iter().rev().filter(|row| seen.insert(row.id)).collect();
    deduped.reverse();
    (deduped, oversized)
}

/// The `(scope, value)` keys to delete from the mirror for a batch of deleted
/// decisions.
///
/// Value-keyed, not id-keyed, so the mirror drops exactly what
/// [`DecisionCache`] drops. The scenario filter is deliberately **not** applied:
/// a removal must go through even if the filters changed since the decision was
/// written, otherwise a filtered-out row could linger and be restored later.
pub fn delete_keys_for(decisions: &[Decision]) -> Vec<(String, String)> {
    decisions
        .iter()
        .map(|decision| (decision.scope.clone(), decision.value.clone()))
        .collect()
}

/// Convert one decision to its mirror row, or `None` if a field overflows its
/// column (see [`CrowdSecDecisionRow::fits_schema`]).
fn decision_to_row(decision: &Decision, now: DateTime<Utc>) -> Option<CrowdSecDecisionRow> {
    let lifetime_secs = decision_lifetime_secs(decision);
    let lifetime = TimeDelta::try_seconds(i64::try_from(lifetime_secs).ok()?)?;
    let row = CrowdSecDecisionRow {
        id: decision.id,
        origin: decision.origin.clone(),
        scope: decision.scope.clone(),
        value: decision.value.clone(),
        type_: decision.type_.clone(),
        scenario: decision.scenario.clone(),
        duration_secs: i64::try_from(lifetime_secs).ok(),
        expires_at: now.checked_add_signed(lifetime)?,
    };
    row.fits_schema().then_some(row)
}

/// Log a mirror write failure loudly, without letting it reach the caller.
///
/// The mirror is best-effort at runtime — the in-memory cache is what enforces
/// — but a mirror that has silently stopped being written is a fail-open window
/// waiting for the next restart, so the failure is never swallowed quietly.
pub fn report_mirror_failure(operation: &str, error: &StorageError) {
    warn!(
        operation,
        error = %error,
        "CrowdSec decision mirror write failed — enforcement is unaffected right now (the in-memory cache is authoritative), \
         but the local mirror is drifting from LAPI, so a restart before this recovers will start with a stale or empty \
         decision cache (fail-open) until the first successful LAPI pull",
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    fn decision(id: i64, value: &str, scenario: &str, duration: Option<&str>) -> Decision {
        Decision {
            id,
            origin: "crowdsec".to_string(),
            scope: "Ip".to_string(),
            value: value.to_string(),
            type_: "ban".to_string(),
            scenario: scenario.to_string(),
            duration: duration.map(ToString::to_string),
            created_at: None,
        }
    }

    fn row(id: i64, value: &str, scenario: &str, expires_in_secs: i64) -> CrowdSecDecisionRow {
        CrowdSecDecisionRow {
            id,
            origin: "crowdsec".to_string(),
            scope: "Ip".to_string(),
            value: value.to_string(),
            type_: "ban".to_string(),
            scenario: scenario.to_string(),
            duration_secs: Some(expires_in_secs),
            expires_at: Utc::now() + TimeDelta::try_seconds(expires_in_secs).unwrap(),
        }
    }

    /// In-memory `DecisionStore` so the restore path is testable without a
    /// database, including the failure branch.
    #[derive(Default)]
    struct MockStore {
        rows: Mutex<Vec<CrowdSecDecisionRow>>,
        fail: bool,
        replaced: Mutex<Vec<Vec<CrowdSecDecisionRow>>>,
        deleted: Mutex<Vec<Vec<(String, String)>>>,
    }

    #[async_trait]
    impl DecisionStore for MockStore {
        async fn load_active(&self) -> Result<Vec<CrowdSecDecisionRow>, StorageError> {
            if self.fail {
                return Err(StorageError::NotFound("mirror unavailable".to_string()));
            }
            Ok(self.rows.lock().clone())
        }

        async fn replace_all(&self, rows: &[CrowdSecDecisionRow]) -> Result<u64, StorageError> {
            self.replaced.lock().push(rows.to_vec());
            Ok(0)
        }

        async fn upsert(&self, rows: &[CrowdSecDecisionRow]) -> Result<u64, StorageError> {
            self.rows.lock().extend_from_slice(rows);
            Ok(rows.len() as u64)
        }

        async fn delete(&self, keys: &[(String, String)]) -> Result<u64, StorageError> {
            self.deleted.lock().push(keys.to_vec());
            Ok(keys.len() as u64)
        }
    }

    #[tokio::test]
    async fn restore_populates_the_cache_before_any_lapi_contact() {
        let cache = DecisionCache::new(0);
        let store = MockStore {
            rows: Mutex::new(vec![row(1, "203.0.113.7", "crowdsecurity/ssh-bf", 3600)]),
            ..MockStore::default()
        };
        let outcome = restore_cache(&cache, &store, &CrowdSecConfig::default()).await;

        assert_eq!(outcome.restored, 1);
        assert!(outcome.error.is_none());
        let ip = "203.0.113.7".parse().unwrap();
        assert!(cache.check_ip(&ip).is_some(), "a restored ban must block immediately");
    }

    #[tokio::test]
    async fn an_expired_mirror_row_is_never_restored() {
        let cache = DecisionCache::new(0);
        let store = MockStore {
            rows: Mutex::new(vec![row(1, "203.0.113.8", "crowdsecurity/ssh-bf", -60)]),
            ..MockStore::default()
        };
        let outcome = restore_cache(&cache, &store, &CrowdSecConfig::default()).await;

        assert_eq!(outcome.restored, 0);
        assert_eq!(outcome.skipped_expired, 1);
        let ip = "203.0.113.8".parse().unwrap();
        assert!(cache.check_ip(&ip).is_none());
    }

    #[tokio::test]
    async fn the_scenario_filter_applies_to_restored_rows_too() {
        let cache = DecisionCache::new(0);
        let store = MockStore {
            rows: Mutex::new(vec![row(1, "203.0.113.9", "crowdsecurity/http-probing", 3600)]),
            ..MockStore::default()
        };
        let config = CrowdSecConfig {
            scenarios_not_containing: vec!["http-probing".to_string()],
            ..CrowdSecConfig::default()
        };
        let outcome = restore_cache(&cache, &store, &config).await;

        assert_eq!(outcome.restored, 0);
        assert_eq!(outcome.skipped_filtered, 1);
    }

    #[tokio::test]
    async fn a_mirror_read_failure_is_reported_and_never_panics() {
        let cache = DecisionCache::new(0);
        let store = MockStore {
            fail: true,
            ..MockStore::default()
        };
        let outcome = restore_cache(&cache, &store, &CrowdSecConfig::default()).await;

        assert_eq!(outcome.restored, 0);
        assert!(outcome.error.is_some(), "a failed restore must be reported, not silent");
        assert_eq!(cache.stats().total_cached, 0);
    }

    #[test]
    fn a_restored_cache_ttl_never_outlives_the_decision() {
        // cache_ttl_secs = 3600 must not extend a decision with 60s left.
        let cache = DecisionCache::new(3600);
        assert_eq!(cache.restore_ttl(Duration::from_mins(1)), Duration::from_mins(1));
        // …and must still cap a decision with more life than the TTL.
        assert_eq!(cache.restore_ttl(Duration::from_hours(2)), Duration::from_hours(1));
        // With no override the decision's own remaining lifetime is used.
        let plain = DecisionCache::new(0);
        assert_eq!(plain.restore_ttl(Duration::from_hours(2)), Duration::from_hours(2));
    }

    #[test]
    fn rows_are_deduplicated_by_upstream_id_with_the_last_write_winning() {
        let now = Utc::now();
        let decisions = vec![
            decision(1, "203.0.113.1", "crowdsecurity/ssh-bf", Some("1h")),
            decision(1, "203.0.113.2", "crowdsecurity/ssh-bf", Some("1h")),
        ];
        let (rows, oversized) = rows_for(&decisions, &CrowdSecConfig::default(), now);
        assert_eq!(oversized, 0);
        assert_eq!(rows.len(), 1, "a repeated id must collapse, not fail the batch");
        assert_eq!(rows.first().map(|row| row.value.as_str()), Some("203.0.113.2"));
    }

    #[test]
    fn an_oversized_value_is_dropped_instead_of_failing_the_batch() {
        let now = Utc::now();
        let long = "a".repeat(CrowdSecDecisionRow::MAX_VALUE_LEN + 1);
        let decisions = vec![
            decision(1, &long, "crowdsecurity/ssh-bf", Some("1h")),
            decision(2, "203.0.113.3", "crowdsecurity/ssh-bf", Some("1h")),
        ];
        let (rows, oversized) = rows_for(&decisions, &CrowdSecConfig::default(), now);
        assert_eq!(oversized, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows.first().map(|row| row.id), Some(2));
    }

    #[test]
    fn a_decision_without_a_duration_gets_the_same_fallback_lifetime_as_the_cache() {
        let now = Utc::now();
        let decisions = vec![decision(1, "203.0.113.4", "crowdsecurity/ssh-bf", None)];
        let (rows, _) = rows_for(&decisions, &CrowdSecConfig::default(), now);
        assert_eq!(rows.first().and_then(|row| row.duration_secs), Some(4 * 3600));
    }

    #[test]
    fn deletions_are_keyed_on_value_so_the_mirror_cannot_resurrect_a_lifted_ban() {
        let keys = delete_keys_for(&[decision(99, "203.0.113.5", "crowdsecurity/ssh-bf", Some("1h"))]);
        assert_eq!(keys, vec![("Ip".to_string(), "203.0.113.5".to_string())]);
    }
}
