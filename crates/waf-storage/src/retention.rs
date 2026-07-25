//! Background retention (TTL) enforcement for observability tables.
//!
//! The Lane 2 `semantic_observations` table is written on every semantic
//! detection and carries `client_ip` + `req_id`. The semantic lane ships
//! shadow-enabled, so a default deployment writes to it continuously; without a
//! TTL the table grows without bound and retains personal data indefinitely.
//! [`Database::prune_semantic_observations`] implements the delete, and this
//! module is the scheduler that actually calls it in production.
//!
//! Design notes:
//!
//! * The loop is generic over the prune operation so the scheduling / error
//!   behaviour is unit-testable without a database.
//! * A prune failure is logged and the loop continues — a broken DB connection
//!   must never take the proxy down.
//! * The first sweep is delayed by [`RetentionConfig::initial_delay`] so it does
//!   not pile onto the startup burst (migrations, rule compile, feed pulls).
//! * Shutdown is cooperative: the task exits as soon as the watch channel fires
//!   or its sender is dropped, including while sleeping between sweeps.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::db::Database;
use crate::error::StorageError;

/// Scheduling parameters for the retention task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Rows older than this many days are deleted. Must be positive; a
    /// non-positive value means "retention disabled" and is rejected by
    /// [`spawn_semantic_observation_pruner`] before any task is spawned.
    pub retention_days: i64,
    /// Interval between sweeps.
    pub interval: Duration,
    /// Delay before the first sweep, so retention work does not collide with
    /// process startup.
    pub initial_delay: Duration,
}

/// Default delay before the first retention sweep.
pub const DEFAULT_INITIAL_DELAY: Duration = Duration::from_mins(5);

/// Upper clamp on the configured sweep interval (one year). Bounds the
/// `Duration` construction so no operator value can overflow it.
const MAX_INTERVAL_HOURS: u64 = 24 * 365;

impl RetentionConfig {
    /// Build a config from the operator-facing knobs in
    /// `[storage]`: a retention window in days and a sweep interval in hours.
    /// The interval is clamped to `1..=8760` hours so a `0` in the config can
    /// never turn the loop into a busy spin and an absurd value cannot overflow
    /// the `Duration`.
    #[must_use]
    pub const fn from_settings(retention_days: i64, interval_hours: u64) -> Self {
        // `Ord::clamp` is not const yet; the explicit branches keep this a const fn.
        let hours = if interval_hours < 1 {
            1
        } else if interval_hours > MAX_INTERVAL_HOURS {
            MAX_INTERVAL_HOURS
        } else {
            interval_hours
        };
        Self {
            retention_days,
            interval: Duration::from_hours(hours),
            initial_delay: DEFAULT_INITIAL_DELAY,
        }
    }
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

/// The retention loop, generic over the prune operation.
///
/// `prune` is invoked with [`RetentionConfig::retention_days`] once per sweep
/// and returns the number of rows deleted. An `Err` is logged at WARN and the
/// loop continues to the next sweep — retention is best-effort maintenance, not
/// a reason to abort.
///
/// `table` is only used for log context.
pub async fn run_retention_loop<F, Fut>(
    table: &str,
    config: RetentionConfig,
    mut shutdown_rx: watch::Receiver<bool>,
    prune: F,
) where
    F: Fn(i64) -> Fut + Send,
    Fut: Future<Output = Result<u64, StorageError>> + Send,
{
    info!(
        table,
        retention_days = config.retention_days,
        interval_secs = config.interval.as_secs(),
        first_sweep_in_secs = config.initial_delay.as_secs(),
        "Retention pruner started"
    );

    if sleep_or_shutdown(config.initial_delay, &mut shutdown_rx).await {
        info!(table, "Retention pruner shutting down before first sweep");
        return;
    }

    loop {
        match prune(config.retention_days).await {
            Ok(0) => debug!(
                table,
                retention_days = config.retention_days,
                "Retention sweep deleted 0 rows"
            ),
            Ok(deleted) => info!(
                table,
                deleted,
                retention_days = config.retention_days,
                "Retention sweep deleted expired rows"
            ),
            Err(e) => warn!(
                table,
                retention_days = config.retention_days,
                error = %e,
                "Retention sweep failed; retrying at the next interval"
            ),
        }

        if sleep_or_shutdown(config.interval, &mut shutdown_rx).await {
            info!(table, "Retention pruner shutting down");
            return;
        }
    }
}

/// Spawn the `semantic_observations` retention pruner.
///
/// Returns `None` — spawning nothing — when `retention_days` is non-positive,
/// which is the operator's explicit "keep rows forever" opt-out. The caller is
/// expected to warn about the unbounded growth in that case.
pub fn spawn_semantic_observation_pruner(
    db: Arc<Database>,
    config: RetentionConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    if config.retention_days <= 0 {
        return None;
    }
    Some(tokio::spawn(async move {
        run_retention_loop("semantic_observations", config, shutdown_rx, move |days| {
            let db = Arc::clone(&db);
            async move { db.prune_semantic_observations(days).await }
        })
        .await;
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

    use super::*;

    fn test_config() -> RetentionConfig {
        RetentionConfig {
            retention_days: 30,
            interval: Duration::from_hours(1),
            initial_delay: Duration::from_mins(5),
        }
    }

    #[test]
    fn from_settings_maps_hours_to_an_interval() {
        let cfg = RetentionConfig::from_settings(45, 6);
        assert_eq!(cfg.retention_days, 45);
        assert_eq!(cfg.interval, Duration::from_hours(6));
        assert_eq!(cfg.initial_delay, DEFAULT_INITIAL_DELAY);
    }

    #[test]
    fn from_settings_clamps_a_zero_interval_to_one_hour() {
        // A `0` in the config must never become a zero-length sleep (busy spin).
        assert_eq!(RetentionConfig::from_settings(30, 0).interval, Duration::from_hours(1));
    }

    #[tokio::test(start_paused = true)]
    async fn first_sweep_waits_for_the_initial_delay() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            run_retention_loop("t", test_config(), rx, move |_days| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(0)
                }
            })
            .await;
        });

        // Just short of the initial delay: nothing has run yet.
        tokio::time::sleep(Duration::from_secs(299)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0, "swept before the initial delay");

        // Past the initial delay: exactly one sweep.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "first sweep did not run");

        // One interval later: a second sweep.
        tokio::time::sleep(Duration::from_hours(1)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "periodic sweep did not run");

        drop(tx);
        handle.await.expect("retention task must exit cleanly");
    }

    #[tokio::test(start_paused = true)]
    async fn sweep_uses_the_configured_retention_window() {
        let observed = Arc::new(AtomicI64::new(-1));
        let calls = Arc::new(AtomicUsize::new(0));
        let sink = Arc::clone(&observed);
        let seen = Arc::clone(&calls);
        let (tx, rx) = watch::channel(false);
        let mut config = test_config();
        config.retention_days = 7;
        let handle = tokio::spawn(async move {
            run_retention_loop("t", config, rx, move |days| {
                let sink = Arc::clone(&sink);
                let seen = Arc::clone(&seen);
                async move {
                    sink.store(days, Ordering::SeqCst);
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(3)
                }
            })
            .await;
        });

        tokio::time::sleep(Duration::from_secs(301)).await;
        drop(tx);
        handle.await.expect("retention task must exit cleanly");

        assert_eq!(calls.load(Ordering::SeqCst), 1, "expected exactly one sweep");
        assert_eq!(
            observed.load(Ordering::SeqCst),
            7,
            "the prune must be called with the configured retention_days"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_sweep_does_not_abort_the_loop() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            run_retention_loop("t", test_config(), rx, move |_days| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Err(StorageError::InvalidInput("simulated database failure".to_string()))
                }
            })
            .await;
        });

        // Three sweeps, all failing: the task must still be alive and sweeping.
        tokio::time::sleep(Duration::from_secs(300 + 2 * 3600 + 1)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 3, "loop stopped after a failed sweep");
        assert!(!handle.is_finished(), "loop exited on a prune error");

        drop(tx);
        handle.await.expect("retention task must exit cleanly, not panic");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_signal_stops_the_loop_between_sweeps() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            run_retention_loop("t", test_config(), rx, move |_days| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(1)
                }
            })
            .await;
        });

        tokio::time::sleep(Duration::from_secs(301)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tx.send(true).expect("shutdown signal must be delivered");
        handle.await.expect("retention task must exit on shutdown");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "swept again after shutdown");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_during_the_initial_delay_skips_the_first_sweep() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            run_retention_loop("t", test_config(), rx, move |_days| {
                let seen = Arc::clone(&seen);
                async move {
                    seen.fetch_add(1, Ordering::SeqCst);
                    Ok(0)
                }
            })
            .await;
        });

        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(tx);
        handle.await.expect("retention task must exit on shutdown");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "swept despite an early shutdown");
    }
}
