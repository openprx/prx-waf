//! Background retention (TTL) enforcement for the observability / PII tables.
//!
//! Five tables accumulate rows on the request path or the admin path and every
//! one of them stores a client or operator IP address:
//!
//! | table | written by | personal data |
//! |---|---|---|
//! | `semantic_observations` | Lane 2 semantic detection (shadow-enabled by default) | `client_ip`, `req_id` |
//! | `security_events`       | every rule detection | `client_ip`, path, geo |
//! | `attack_logs`           | every blocked / logged request | `client_ip`, path, request headers |
//! | `audit_log`             | every mutating admin API call | `admin_username`, `ip_addr` |
//! | `crowdsec_events`       | the `CrowdSec` bouncer worker | `client_ip`, scenario |
//!
//! None of them had a cleanup path, so a default deployment grew without bound
//! and retained personal data indefinitely. This module is the scheduler that
//! deletes expired rows; [`Database::prune_retention_table`] is the statement.
//!
//! Design notes:
//!
//! * **One task for all tables.** A single loop sweeps every enabled table in
//!   turn, so retention costs one background task regardless of how many tables
//!   are covered. Logs carry a `table` field so "which table deleted how many"
//!   stays legible.
//! * **Per-table windows.** An admin audit trail and shadow telemetry have very
//!   different retention requirements, so each table gets its own configured
//!   window instead of one global number.
//! * **Batched deletes.** A single `DELETE` over millions of expired rows holds
//!   row locks for minutes and inflates the WAL. Each table is drained in
//!   bounded batches with a pause between them; see [`prune_in_batches`].
//! * The loop is generic over the prune operation so the scheduling / error
//!   behaviour is unit-testable without a database.
//! * A prune failure is logged and the loop continues — with the *other tables*
//!   in the same sweep and with the next sweep. A broken DB connection must
//!   never take the proxy down, and one bad table must never starve the rest.
//! * The first sweep is delayed by [`RetentionConfig::initial_delay`] so it does
//!   not pile onto the startup burst (migrations, rule compile, feed pulls).
//! * Shutdown is cooperative: the task exits as soon as the watch channel fires
//!   or its sender is dropped, including while sleeping between sweeps and
//!   between tables within one sweep.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::db::Database;
use crate::error::StorageError;

/// A table the retention scheduler is allowed to prune.
///
/// A closed enum rather than an operator-supplied string: a SQL table name
/// cannot be a bind parameter, so the only safe way to build the statement is
/// from a fixed set of literals. No configuration value ever reaches the
/// statement text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetentionTable {
    /// Lane 2 semantic shadow telemetry.
    SemanticObservations,
    /// Rule-detection events surfaced in the dashboard.
    SecurityEvents,
    /// Blocked / logged request records, including request headers.
    AttackLogs,
    /// Mutating admin API calls.
    AuditLog,
    /// `CrowdSec` decision echoes.
    CrowdsecEvents,
}

impl RetentionTable {
    /// Every prunable table, in sweep order (cheapest / most volatile first).
    pub const ALL: [Self; 5] = [
        Self::SemanticObservations,
        Self::SecurityEvents,
        Self::AttackLogs,
        Self::CrowdsecEvents,
        Self::AuditLog,
    ];

    /// The physical table name, used as the `table` log field.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SemanticObservations => "semantic_observations",
            Self::SecurityEvents => "security_events",
            Self::AttackLogs => "attack_logs",
            Self::AuditLog => "audit_log",
            Self::CrowdsecEvents => "crowdsec_events",
        }
    }

    /// The `[storage]` key that sets this table's window, for operator-facing
    /// messages ("set X to re-enable").
    #[must_use]
    pub const fn config_key(self) -> &'static str {
        match self {
            Self::SemanticObservations => "storage.semantic_observation_retention_days",
            Self::SecurityEvents => "storage.security_event_retention_days",
            Self::AttackLogs => "storage.attack_log_retention_days",
            Self::AuditLog => "storage.audit_log_retention_days",
            Self::CrowdsecEvents => "storage.crowdsec_event_retention_days",
        }
    }

    /// What the rows hold, so a startup warning about a disabled window can
    /// state the concrete consequence instead of "data is kept".
    #[must_use]
    pub const fn contents(self) -> &'static str {
        match self {
            Self::SemanticObservations => "Lane 2 shadow telemetry; client_ip + req_id per detection",
            Self::SecurityEvents => "rule detections; client_ip, method, path, geo",
            Self::AttackLogs => "blocked/logged requests; client_ip, path, query, request headers",
            Self::AuditLog => "admin API mutations; admin_username, admin source ip_addr",
            Self::CrowdsecEvents => "CrowdSec decisions; client_ip, scenario, request path",
        }
    }

    /// One batch of the retention delete for this table.
    ///
    /// `$1` is the cutoff timestamp, `$2` the batch size. The `ctid IN
    /// (SELECT … LIMIT $2)` form is the standard Postgres bounded delete: the
    /// subquery walks the `created_at` index, takes at most `$2` physical row
    /// identifiers, and the outer `DELETE` touches exactly those rows. Every
    /// table below has an index on `created_at` (`0001`, `0002`, `0005`, `0006`,
    /// `0011`), so the subquery is an index range scan that stops at the LIMIT
    /// rather than a full table scan.
    ///
    /// `audit_log` deliberately uses the same shape even though it has a
    /// `BIGSERIAL` key: keying on `created_at` keeps a single policy definition
    /// and stays correct if rows are ever backfilled out of id order.
    pub(crate) const fn delete_batch_sql(self) -> &'static str {
        match self {
            Self::SemanticObservations => {
                "DELETE FROM semantic_observations WHERE ctid IN \
                 (SELECT ctid FROM semantic_observations WHERE created_at < $1 LIMIT $2)"
            }
            Self::SecurityEvents => {
                "DELETE FROM security_events WHERE ctid IN \
                 (SELECT ctid FROM security_events WHERE created_at < $1 LIMIT $2)"
            }
            Self::AttackLogs => {
                "DELETE FROM attack_logs WHERE ctid IN \
                 (SELECT ctid FROM attack_logs WHERE created_at < $1 LIMIT $2)"
            }
            Self::AuditLog => {
                "DELETE FROM audit_log WHERE ctid IN \
                 (SELECT ctid FROM audit_log WHERE created_at < $1 LIMIT $2)"
            }
            Self::CrowdsecEvents => {
                "DELETE FROM crowdsec_events WHERE ctid IN \
                 (SELECT ctid FROM crowdsec_events WHERE created_at < $1 LIMIT $2)"
            }
        }
    }
}

/// One table's retention policy: how long its rows are kept.
///
/// A `retention_days` of `0` or below is the operator's explicit "keep rows
/// forever" opt-out; [`enabled_policies`] filters those out and the caller is
/// expected to warn about the consequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableRetention {
    /// Which table this policy applies to.
    pub table: RetentionTable,
    /// Rows older than this many days are deleted.
    pub retention_days: i64,
}

impl TableRetention {
    /// Build a policy for `table` with a window of `retention_days`.
    #[must_use]
    pub const fn new(table: RetentionTable, retention_days: i64) -> Self {
        Self { table, retention_days }
    }

    /// Whether this policy actually deletes anything.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.retention_days > 0
    }
}

/// Scheduling parameters shared by every table in the sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Interval between sweeps.
    pub interval: Duration,
    /// Delay before the first sweep, so retention work does not collide with
    /// process startup.
    pub initial_delay: Duration,
    /// Rows deleted per `DELETE` statement. Always positive.
    pub batch_size: i64,
}

/// Default delay before the first retention sweep.
pub const DEFAULT_INITIAL_DELAY: Duration = Duration::from_mins(5);

/// Default rows per `DELETE` statement.
///
/// Sized so one statement is a short transaction even on a busy node: at a few
/// hundred bytes per row this is single-digit megabytes of WAL and a lock held
/// for milliseconds, while still draining a million-row backlog in ~200
/// statements. Smaller batches would multiply round-trips for no benefit;
/// materially larger ones reintroduce the long-lock problem batching exists to
/// avoid.
pub const DEFAULT_DELETE_BATCH_SIZE: i64 = 5_000;

/// Upper clamp on the configured batch size, so a stray large value cannot
/// recreate an unbounded single-statement delete.
const MAX_DELETE_BATCH_SIZE: i64 = 100_000;

/// Upper clamp on the configured sweep interval (one year). Bounds the
/// `Duration` construction so no operator value can overflow it.
const MAX_INTERVAL_HOURS: u64 = 24 * 365;

/// Maximum batches one table may run in a single sweep.
///
/// At [`DEFAULT_DELETE_BATCH_SIZE`] this is a 10-million-row ceiling per table
/// per sweep. It bounds the worst case (a first sweep against a table that has
/// been accumulating for a year) so retention cannot monopolise the pool
/// indefinitely; whatever is left is deleted on the next sweep.
const MAX_BATCHES_PER_TABLE_SWEEP: u32 = 2_000;

/// Pause between delete batches, yielding the connection pool and giving
/// Postgres room to checkpoint / autovacuum between transactions.
const BATCH_PAUSE: Duration = Duration::from_millis(50);

impl RetentionConfig {
    /// Build a config from the operator-facing knobs in `[storage]`.
    ///
    /// The interval is clamped to `1..=8760` hours so a `0` in the config can
    /// never turn the loop into a busy spin and an absurd value cannot overflow
    /// the `Duration`. The batch size is clamped to
    /// <code>1..=[MAX_DELETE_BATCH_SIZE]</code> so a `0` cannot make the batch
    /// loop spin forever deleting nothing.
    #[must_use]
    pub const fn from_settings(interval_hours: u64, batch_size: i64) -> Self {
        // `Ord::clamp` is not const yet; the explicit branches keep this a const fn.
        let hours = if interval_hours < 1 {
            1
        } else if interval_hours > MAX_INTERVAL_HOURS {
            MAX_INTERVAL_HOURS
        } else {
            interval_hours
        };
        let batch_size = if batch_size < 1 {
            DEFAULT_DELETE_BATCH_SIZE
        } else if batch_size > MAX_DELETE_BATCH_SIZE {
            MAX_DELETE_BATCH_SIZE
        } else {
            batch_size
        };
        Self {
            interval: Duration::from_hours(hours),
            initial_delay: DEFAULT_INITIAL_DELAY,
            batch_size,
        }
    }
}

/// Keep only the policies that actually delete something.
///
/// A non-positive window is the operator's "retain forever" opt-out. Filtering
/// here (rather than inside the loop) keeps the decision visible to the caller,
/// which is what produces the startup warning.
#[must_use]
pub fn enabled_policies(policies: &[TableRetention]) -> Vec<TableRetention> {
    policies.iter().copied().filter(|p| p.is_enabled()).collect()
}

/// Delete expired rows in bounded batches until the table is drained.
///
/// `delete_batch` runs one `DELETE … LIMIT n` and returns the rows it removed.
/// A batch that comes back short of `batch_size` means no expired rows are
/// left, so the loop stops; otherwise it pauses for [`BATCH_PAUSE`] and goes
/// again, up to [`MAX_BATCHES_PER_TABLE_SWEEP`] times.
///
/// Errors propagate: rows already deleted by earlier batches stay deleted (each
/// batch is its own transaction) and the caller retries at the next sweep.
///
/// `table` is only used for log context.
pub async fn prune_in_batches<F, Fut>(table: &str, batch_size: i64, delete_batch: F) -> Result<u64, StorageError>
where
    F: Fn(i64) -> Fut,
    Fut: Future<Output = Result<u64, StorageError>>,
{
    if batch_size <= 0 {
        return Err(StorageError::InvalidInput(format!(
            "retention batch_size must be positive, got {batch_size}"
        )));
    }
    // A batch that removed fewer rows than requested proves the `created_at <
    // cutoff` set is exhausted. `try_from` cannot fail for a positive i64, but
    // the fallback keeps the code panic-free without an `as` cast.
    let full_batch = u64::try_from(batch_size).unwrap_or(u64::MAX);

    let mut total: u64 = 0;
    for batch in 1..=MAX_BATCHES_PER_TABLE_SWEEP {
        let deleted = delete_batch(batch_size).await?;
        total = total.saturating_add(deleted);
        if deleted < full_batch {
            return Ok(total);
        }
        debug!(
            table,
            batch, deleted, total, "Retention deleted a full batch; continuing"
        );
        tokio::time::sleep(BATCH_PAUSE).await;
    }

    warn!(
        table,
        total,
        max_batches = MAX_BATCHES_PER_TABLE_SWEEP,
        "Retention hit the per-sweep batch cap; the remaining backlog is deleted on the next sweep"
    );
    Ok(total)
}

/// Sleep for `duration`, returning `true` if shutdown was signalled instead.
///
/// Shutdown is either an explicit `true` on the channel or a dropped sender
/// (`changed()` resolving to `Err`), matching the other background workers.
async fn sleep_or_shutdown(duration: Duration, shutdown_rx: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => false,
        result = shutdown_rx.changed() => result.is_err() || *shutdown_rx.borrow(),
    }
}

/// Non-blocking shutdown check, used between tables inside one sweep so a long
/// multi-table sweep still stops promptly.
fn shutdown_requested(shutdown_rx: &watch::Receiver<bool>) -> bool {
    shutdown_rx.has_changed().is_err() || *shutdown_rx.borrow()
}

/// The retention loop: one task, every table.
///
/// Each sweep walks `policies` in order and calls `prune(table, retention_days)`
/// once per table, logging the deleted row count per table. An `Err` from one
/// table is logged at WARN and the sweep moves on to the next table — retention
/// is best-effort maintenance, and a single broken table must not stop the
/// others.
pub async fn run_retention_loop<F, Fut>(
    policies: &[TableRetention],
    config: RetentionConfig,
    mut shutdown_rx: watch::Receiver<bool>,
    prune: F,
) where
    F: Fn(RetentionTable, i64) -> Fut + Send,
    Fut: Future<Output = Result<u64, StorageError>> + Send,
{
    if policies.is_empty() {
        warn!("Retention pruner started with no enabled table; nothing will ever be deleted");
        return;
    }

    info!(
        tables = policies.len(),
        interval_secs = config.interval.as_secs(),
        first_sweep_in_secs = config.initial_delay.as_secs(),
        batch_size = config.batch_size,
        "Retention pruner started"
    );

    if sleep_or_shutdown(config.initial_delay, &mut shutdown_rx).await {
        info!("Retention pruner shutting down before first sweep");
        return;
    }

    loop {
        for policy in policies {
            let table = policy.table.name();
            match prune(policy.table, policy.retention_days).await {
                Ok(0) => debug!(
                    table,
                    retention_days = policy.retention_days,
                    "Retention sweep deleted 0 rows"
                ),
                Ok(deleted) => info!(
                    table,
                    deleted,
                    retention_days = policy.retention_days,
                    "Retention sweep deleted expired rows"
                ),
                Err(e) => warn!(
                    table,
                    retention_days = policy.retention_days,
                    error = %e,
                    "Retention sweep failed for this table; remaining tables still sweep and this one retries at the next interval"
                ),
            }

            if shutdown_requested(&shutdown_rx) {
                info!(table, "Retention pruner shutting down mid-sweep");
                return;
            }
        }

        if sleep_or_shutdown(config.interval, &mut shutdown_rx).await {
            info!("Retention pruner shutting down");
            return;
        }
    }
}

/// Spawn the single retention pruner task covering every enabled table.
///
/// Returns `None` — spawning nothing — when no table has a positive window,
/// which is the operator's explicit "keep everything forever" opt-out. The
/// caller is expected to warn about the unbounded growth in that case.
pub fn spawn_retention_pruner(
    db: Arc<Database>,
    config: RetentionConfig,
    policies: &[TableRetention],
    shutdown_rx: watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let enabled = enabled_policies(policies);
    if enabled.is_empty() {
        return None;
    }
    Some(tokio::spawn(async move {
        run_retention_loop(&enabled, config, shutdown_rx, move |table, days| {
            let db = Arc::clone(&db);
            async move { db.prune_retention_table(table, days, config.batch_size).await }
        })
        .await;
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use parking_lot::Mutex;

    use super::*;

    fn test_config() -> RetentionConfig {
        RetentionConfig {
            interval: Duration::from_hours(1),
            initial_delay: Duration::from_mins(5),
            batch_size: DEFAULT_DELETE_BATCH_SIZE,
        }
    }

    fn one_table() -> Vec<TableRetention> {
        vec![TableRetention::new(RetentionTable::SemanticObservations, 30)]
    }

    /// Every sweep argument the loop passed to `prune`, in call order.
    type SweepLog = Arc<Mutex<Vec<(RetentionTable, i64)>>>;

    /// Take up to `limit` rows off a shared count of expired rows, standing in
    /// for one `DELETE … LIMIT $2` statement against a table holding that many.
    fn take_batch(remaining: &Mutex<i64>, limit: i64) -> u64 {
        let took = {
            let mut left = remaining.lock();
            let took = (*left).min(limit);
            *left -= took;
            took
        };
        u64::try_from(took).unwrap_or(0)
    }

    /// A prune outcome that fails for exactly one table, to prove the sweep
    /// keeps going for the others.
    fn fail_only_security_events(table: RetentionTable) -> Result<u64, StorageError> {
        if table == RetentionTable::SecurityEvents {
            return Err(StorageError::InvalidInput("simulated database failure".to_string()));
        }
        Ok(1)
    }

    // ─── Table metadata ───────────────────────────────────────────────────────

    #[test]
    fn every_table_has_a_distinct_name_key_and_statement() {
        let mut names: Vec<&str> = RetentionTable::ALL.iter().map(|t| t.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), RetentionTable::ALL.len(), "duplicate table name");

        let mut keys: Vec<&str> = RetentionTable::ALL.iter().map(|t| t.config_key()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), RetentionTable::ALL.len(), "duplicate config key");

        for table in RetentionTable::ALL {
            let sql = table.delete_batch_sql();
            assert!(
                sql.contains(table.name()),
                "{} statement targets another table",
                table.name()
            );
            assert!(sql.contains("created_at < $1"), "{} is not time-bounded", table.name());
            assert!(sql.contains("LIMIT $2"), "{} delete is not batched", table.name());
            assert!(
                table.config_key().starts_with("storage."),
                "{} config key must be operator-pasteable",
                table.name()
            );
        }
    }

    #[test]
    fn the_four_pii_tables_are_all_covered() {
        for expected in [
            "semantic_observations",
            "security_events",
            "attack_logs",
            "audit_log",
            "crowdsec_events",
        ] {
            assert!(
                RetentionTable::ALL.iter().any(|t| t.name() == expected),
                "{expected} is not covered by the retention scheduler"
            );
        }
    }

    // ─── Config ───────────────────────────────────────────────────────────────

    #[test]
    fn from_settings_maps_hours_to_an_interval() {
        let cfg = RetentionConfig::from_settings(6, 1_000);
        assert_eq!(cfg.interval, Duration::from_hours(6));
        assert_eq!(cfg.initial_delay, DEFAULT_INITIAL_DELAY);
        assert_eq!(cfg.batch_size, 1_000);
    }

    #[test]
    fn from_settings_clamps_a_zero_interval_to_one_hour() {
        // A `0` in the config must never become a zero-length sleep (busy spin).
        assert_eq!(
            RetentionConfig::from_settings(0, DEFAULT_DELETE_BATCH_SIZE).interval,
            Duration::from_hours(1)
        );
    }

    #[test]
    fn from_settings_clamps_the_batch_size_into_a_usable_range() {
        // 0 / negative would make the batch loop delete nothing forever.
        assert_eq!(
            RetentionConfig::from_settings(6, 0).batch_size,
            DEFAULT_DELETE_BATCH_SIZE
        );
        assert_eq!(
            RetentionConfig::from_settings(6, -1).batch_size,
            DEFAULT_DELETE_BATCH_SIZE
        );
        // An absurd value must not recreate the unbounded single-shot delete.
        assert_eq!(
            RetentionConfig::from_settings(6, i64::MAX).batch_size,
            MAX_DELETE_BATCH_SIZE
        );
    }

    #[test]
    fn enabled_policies_drops_the_retain_forever_opt_out() {
        let policies = vec![
            TableRetention::new(RetentionTable::SemanticObservations, 30),
            TableRetention::new(RetentionTable::SecurityEvents, 0),
            TableRetention::new(RetentionTable::AttackLogs, -1),
            TableRetention::new(RetentionTable::AuditLog, 365),
        ];
        let enabled = enabled_policies(&policies);
        assert_eq!(
            enabled,
            vec![
                TableRetention::new(RetentionTable::SemanticObservations, 30),
                TableRetention::new(RetentionTable::AuditLog, 365),
            ],
            "only the positive windows survive"
        );
    }

    #[test]
    fn enabled_policies_is_empty_when_every_table_retains_forever() {
        let policies: Vec<TableRetention> = RetentionTable::ALL.iter().map(|t| TableRetention::new(*t, 0)).collect();
        assert!(
            enabled_policies(&policies).is_empty(),
            "all-zero config must spawn no pruner"
        );
    }

    // ─── Batched delete ───────────────────────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn a_single_short_batch_finishes_in_one_statement() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let deleted = prune_in_batches("t", 100, move |_limit| {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            }
        })
        .await
        .expect("prune must succeed");

        assert_eq!(deleted, 7);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a short batch means the table is drained"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn batching_drains_a_backlog_larger_than_one_batch() {
        // 2 500 expired rows, 1 000 per batch: 1000 + 1000 + 500 = 3 statements
        // and every row deleted.
        let remaining = Arc::new(Mutex::new(2_500_i64));
        let calls = Arc::new(AtomicUsize::new(0));
        let sink = Arc::clone(&remaining);
        let seen = Arc::clone(&calls);

        let deleted = prune_in_batches("t", 1_000, move |limit| {
            let sink = Arc::clone(&sink);
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(take_batch(&sink, limit))
            }
        })
        .await
        .expect("prune must succeed");

        assert_eq!(deleted, 2_500, "every expired row must be deleted");
        assert_eq!(*remaining.lock(), 0, "no expired row may be left behind");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "2500 rows at 1000/batch is three statements"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_exact_multiple_backlog_needs_one_confirming_batch() {
        // 2 000 rows at 1 000/batch: two full batches cannot prove the table is
        // drained, so a third (empty) statement confirms it.
        let remaining = Arc::new(Mutex::new(2_000_i64));
        let calls = Arc::new(AtomicUsize::new(0));
        let sink = Arc::clone(&remaining);
        let seen = Arc::clone(&calls);

        let deleted = prune_in_batches("t", 1_000, move |limit| {
            let sink = Arc::clone(&sink);
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(take_batch(&sink, limit))
            }
        })
        .await
        .expect("prune must succeed");

        assert_eq!(deleted, 2_000);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn batching_stops_at_the_per_sweep_cap() {
        // An always-full batch would loop forever without the cap.
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let deleted = prune_in_batches("t", 10, move |limit| {
            let seen = Arc::clone(&seen);
            async move {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(u64::try_from(limit).unwrap_or(0))
            }
        })
        .await
        .expect("hitting the cap is not an error");

        let cap = usize::try_from(MAX_BATCHES_PER_TABLE_SWEEP).unwrap_or(usize::MAX);
        assert_eq!(calls.load(Ordering::SeqCst), cap, "the batch loop must be bounded");
        assert_eq!(deleted, 10 * u64::from(MAX_BATCHES_PER_TABLE_SWEEP));
    }

    #[tokio::test(start_paused = true)]
    async fn batching_pauses_between_statements() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let handle = tokio::spawn(async move {
            prune_in_batches("t", 10, move |limit| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(u64::try_from(limit).unwrap_or(0))
                }
            })
            .await
        });

        // Within the first pause window only the first statement has run: the
        // loop yields between batches instead of hammering the pool.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "batches must be paced, not back-to-back"
        );

        handle.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_batch_propagates() {
        let result = prune_in_batches("t", 100, |_limit| async {
            Err(StorageError::InvalidInput("simulated database failure".to_string()))
        })
        .await;
        assert!(result.is_err(), "a DB error must surface to the sweep logger");
    }

    #[tokio::test]
    async fn a_non_positive_batch_size_is_rejected_instead_of_spinning() {
        for bad in [0_i64, -1] {
            let calls = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&calls);
            let result = prune_in_batches("t", bad, move |_limit| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(0)
                }
            })
            .await;
            assert!(result.is_err(), "batch_size {bad} must be rejected");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "no statement may run for batch_size {bad}"
            );
        }
    }

    // ─── Scheduling ───────────────────────────────────────────────────────────

    /// Spawn the loop over `policies`, recording every `(table, days)` pair.
    fn spawn_recording_loop(
        policies: Vec<TableRetention>,
        config: RetentionConfig,
        rx: watch::Receiver<bool>,
    ) -> (SweepLog, tokio::task::JoinHandle<()>) {
        let log: SweepLog = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let handle = tokio::spawn(async move {
            run_retention_loop(&policies, config, rx, move |table, days| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().push((table, days));
                    Ok(0)
                }
            })
            .await;
        });
        (log, handle)
    }

    #[tokio::test(start_paused = true)]
    async fn first_sweep_waits_for_the_initial_delay() {
        let (tx, rx) = watch::channel(false);
        let (log, handle) = spawn_recording_loop(one_table(), test_config(), rx);

        // Just short of the initial delay: nothing has run yet.
        tokio::time::sleep(Duration::from_secs(299)).await;
        assert_eq!(log.lock().len(), 0, "swept before the initial delay");

        // Past the initial delay: exactly one sweep.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(log.lock().len(), 1, "first sweep did not run");

        // One interval later: a second sweep.
        tokio::time::sleep(Duration::from_hours(1)).await;
        assert_eq!(log.lock().len(), 2, "periodic sweep did not run");

        drop(tx);
        handle.await.expect("retention task must exit cleanly");
    }

    #[tokio::test(start_paused = true)]
    async fn one_sweep_visits_every_table_with_its_own_window() {
        let policies = vec![
            TableRetention::new(RetentionTable::SemanticObservations, 30),
            TableRetention::new(RetentionTable::SecurityEvents, 90),
            TableRetention::new(RetentionTable::AttackLogs, 90),
            TableRetention::new(RetentionTable::CrowdsecEvents, 30),
            TableRetention::new(RetentionTable::AuditLog, 365),
        ];
        let (tx, rx) = watch::channel(false);
        let (log, handle) = spawn_recording_loop(policies.clone(), test_config(), rx);

        tokio::time::sleep(Duration::from_secs(301)).await;
        tx.send(true).expect("shutdown signal must be delivered");
        handle.await.expect("retention task must exit cleanly");

        let calls = log.lock().clone();
        let expected: Vec<(RetentionTable, i64)> = policies.iter().map(|p| (p.table, p.retention_days)).collect();
        assert_eq!(
            calls, expected,
            "each table must be pruned once per sweep, with its own configured window"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_policy_set_never_sweeps() {
        let (tx, rx) = watch::channel(false);
        let (log, handle) = spawn_recording_loop(Vec::new(), test_config(), rx);

        tokio::time::sleep(Duration::from_hours(4)).await;
        assert!(handle.is_finished(), "an empty policy set must return immediately");
        assert_eq!(log.lock().len(), 0, "nothing may be pruned without a policy");

        drop(tx);
        handle.await.expect("retention task must exit cleanly");
    }

    #[tokio::test(start_paused = true)]
    async fn one_failing_table_does_not_stop_the_other_tables() {
        // `security_events` always errors; the tables before and after it in the
        // sweep order must still be pruned, in this sweep and the next.
        let policies = vec![
            TableRetention::new(RetentionTable::SemanticObservations, 30),
            TableRetention::new(RetentionTable::SecurityEvents, 90),
            TableRetention::new(RetentionTable::AuditLog, 365),
        ];
        let log: SweepLog = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            run_retention_loop(&policies, test_config(), rx, move |table, days| {
                let sink = Arc::clone(&sink);
                async move {
                    sink.lock().push((table, days));
                    fail_only_security_events(table)
                }
            })
            .await;
        });

        // Two sweeps: initial delay + one interval.
        tokio::time::sleep(Duration::from_secs(300 + 3600 + 1)).await;
        let calls = log.lock().clone();
        assert_eq!(
            calls,
            vec![
                (RetentionTable::SemanticObservations, 30),
                (RetentionTable::SecurityEvents, 90),
                (RetentionTable::AuditLog, 365),
                (RetentionTable::SemanticObservations, 30),
                (RetentionTable::SecurityEvents, 90),
                (RetentionTable::AuditLog, 365),
            ],
            "a failing table must not skip the tables after it, nor stop later sweeps"
        );
        assert!(!handle.is_finished(), "loop exited on a prune error");

        drop(tx);
        handle.await.expect("retention task must exit cleanly, not panic");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_signal_stops_the_loop_between_sweeps() {
        let (tx, rx) = watch::channel(false);
        let (log, handle) = spawn_recording_loop(one_table(), test_config(), rx);

        tokio::time::sleep(Duration::from_secs(301)).await;
        assert_eq!(log.lock().len(), 1);

        tx.send(true).expect("shutdown signal must be delivered");
        handle.await.expect("retention task must exit on shutdown");
        assert_eq!(log.lock().len(), 1, "swept again after shutdown");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_stops_a_multi_table_sweep_at_the_next_table_boundary() {
        // Shutdown is signalled *while* the first table is being pruned. A
        // five-table sweep must abandon the remaining four instead of finishing
        // the round, so a slow sweep cannot delay process exit.
        let policies: Vec<TableRetention> = RetentionTable::ALL
            .iter()
            .map(|t| TableRetention::new(*t, 30))
            .collect();
        let log: SweepLog = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            run_retention_loop(&policies, test_config(), rx, move |table, days| {
                let sink = Arc::clone(&sink);
                // Signalling from inside the prune puts the request exactly
                // where a real SIGTERM would land: mid-sweep.
                let _ = tx.send(true);
                async move {
                    sink.lock().push((table, days));
                    Ok(0)
                }
            })
            .await;
        });

        tokio::time::sleep(Duration::from_secs(301)).await;
        handle.await.expect("retention task must exit on shutdown");
        assert_eq!(
            log.lock().len(),
            1,
            "the sweep must stop at the first table boundary after shutdown, not finish all five"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_during_the_initial_delay_skips_the_first_sweep() {
        let (tx, rx) = watch::channel(false);
        let (log, handle) = spawn_recording_loop(one_table(), test_config(), rx);

        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(tx);
        handle.await.expect("retention task must exit on shutdown");
        assert_eq!(log.lock().len(), 0, "swept despite an early shutdown");
    }
}
