//! Bounded, back-pressured sink for `attack_logs` and `security_events`.
//!
//! # What this replaces, and why
//!
//! Every enforced detection costs a database row, and until this module existed
//! the engine bought that row with a `tokio::spawn` per detection. That is fine
//! at any rate the database can absorb and a denial of service at any rate it
//! cannot, because nothing anywhere connects the two: the hot path spawns as
//! fast as the proxy can block requests, the pool drains as fast as
//! `storage.max_connections` allows, and the difference accumulates in memory
//! with no ceiling.
//!
//! It was measured rather than argued. `tests/perf/results/soak/` holds the
//! series: a saturating `SQLi` flood against the shipping posture put 557,584
//! rows in flight in thirty-one seconds and took RSS from 856 MiB to 6.2 GiB along
//! a line with an R² of 1.000 and a slope of 10.4 GiB per minute, while the pool
//! sat at twenty connections with zero idle throughout. Arrival was 20,300
//! blocked requests a second; drain was about 4,300. **The attacker chose the
//! slope**, which is the shape of a `DoS` and not a capacity-planning problem.
//!
//! # The shape of the fix
//!
//! Two bounded MPSC channels drained by one background worker — the same
//! structure [`crate::semantic_sink`] and [`crate::audit_log`] already use, for
//! the same reason, so this is the last unbounded writer rather than a new
//! pattern. The hot path does one synchronous `try_send` and never awaits, never
//! spawns and never allocates a task. A full channel drops the record, counts it
//! on a `BudgetEvent` and leaves the request path untouched.
//!
//! **The drop is loud on purpose.** This repository has already paid for the
//! alternative: a silently discarded security record makes "nothing was
//! detected" and "something was detected and not written down" look identical to
//! everything downstream — the API, the dashboard, the operator. So the drop
//! increments `prxwaf_budget_events_total{subsystem="queue", limit="attack_log"}`
//! or `{limit="security_event"}`, the depth that preceded it is visible on
//! `prxwaf_queue_depth`, and the worker WARNs a running total every thirty
//! seconds. An operator can see exactly how much of their security record they
//! are losing and to which queue.
//!
//! # Why the batch is a multi-row statement here and not in the other sinks
//!
//! [`crate::semantic_sink`] drains a batch and inserts the rows one at a time,
//! which is a deliberate choice there: the shadow lane's volume is a fraction of
//! a percent of traffic and one round trip per row is not the bottleneck. It is
//! the bottleneck here. Under flood the arrival rate is the whole problem, and
//! every round trip saved is a row that does not have to be dropped, so the
//! worker composes one `INSERT ... VALUES (…),(…),…` per batch. Measured on the
//! same soak, that is the difference between drowning at 4,300 rows a second and
//! keeping up with far more of the flood.
//!
//! Bounding the queue is what makes memory safe; batching is what makes the
//! bound rarely matter. Both are needed — batching alone would only move the
//! cliff, and a bound alone would drop far more than it has to.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use waf_common::metrics::{self, BudgetEvent, QueueGauge};
use waf_storage::StorageError;
use waf_storage::{
    Database,
    models::{AttackLog, CreateSecurityEvent},
};

/// Bounded capacity for pending `attack_logs` rows.
///
/// Sized like every other queue in this crate (4 096) so an operator has one
/// number to reason about rather than five. At the ~1 KiB an `AttackLog` costs
/// once its strings are counted, a full channel is single-digit MiB — a working
/// set, not a leak, and a constant of the configuration rather than of the
/// traffic.
pub const ATTACK_LOG_CHANNEL_CAPACITY: usize = 4096;

/// Bounded capacity for pending `security_events` rows.
///
/// Separate from the attack-log channel so the two back-pressure independently:
/// a flood of content-pipeline detections must not be able to evict the
/// blocklist's record of who it came from.
pub const SECURITY_EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Max rows drained and inserted per channel per worker wake-up.
///
/// One multi-row `INSERT` per batch, so this is also the widest statement the
/// worker will build. 256 rows × 15 bind parameters is 3 840 parameters, safely
/// under the 65 535 a Postgres extended-query message can carry.
const DRAIN_BATCH_SIZE: usize = 256;

/// How often the worker logs (and resets) the drop counters.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Sink-write abstraction so the drain worker can be unit-tested without a real
/// database. Implemented for `Arc<Database>` in production.
pub trait DetectionSinkWriter: Send + Sync + 'static {
    /// Persist a batch of `attack_logs` rows.
    fn write_attack_logs(
        &self,
        logs: Vec<AttackLog>,
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;

    /// Persist a batch of `security_events` rows.
    fn write_security_events(
        &self,
        events: Vec<CreateSecurityEvent>,
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;
}

impl DetectionSinkWriter for Arc<Database> {
    async fn write_attack_logs(&self, logs: Vec<AttackLog>) -> Result<(), StorageError> {
        self.create_attack_logs(logs).await
    }

    async fn write_security_events(&self, events: Vec<CreateSecurityEvent>) -> Result<(), StorageError> {
        self.create_security_events(events).await
    }
}

/// Hot-path handle: two bounded senders plus per-channel drop counters.
pub struct DetectionLogSink {
    attack_tx: mpsc::Sender<AttackLog>,
    event_tx: mpsc::Sender<CreateSecurityEvent>,
    /// Receivers, taken exactly once by [`Self::take_worker`].
    rx: parking_lot::Mutex<Option<TakenReceivers>>,
    /// `attack_logs` rows dropped because the channel was full.
    attack_dropped: Arc<AtomicU64>,
    /// `security_events` rows dropped because the channel was full.
    event_dropped: Arc<AtomicU64>,
}

/// The receiver pair, moved into the worker exactly once.
struct TakenReceivers {
    attack_rx: mpsc::Receiver<AttackLog>,
    event_rx: mpsc::Receiver<CreateSecurityEvent>,
}

/// The drain side, moved into the background task.
///
/// Owns only the receivers and the drop counters — **not** an
/// `Arc<DetectionLogSink>` — so the worker exits as soon as the engine drops the
/// last `Sender` (no reference cycle).
pub struct DetectionLogWorker {
    attack_rx: mpsc::Receiver<AttackLog>,
    event_rx: mpsc::Receiver<CreateSecurityEvent>,
    attack_dropped: Arc<AtomicU64>,
    event_dropped: Arc<AtomicU64>,
}

impl DetectionLogSink {
    /// Build a sink with the given bounded capacities.
    #[must_use]
    pub fn new(attack_capacity: usize, event_capacity: usize) -> Self {
        let (attack_tx, attack_rx) = mpsc::channel(attack_capacity.max(1));
        let (event_tx, event_rx) = mpsc::channel(event_capacity.max(1));
        Self {
            attack_tx,
            event_tx,
            rx: parking_lot::Mutex::new(Some(TakenReceivers { attack_rx, event_rx })),
            attack_dropped: Arc::new(AtomicU64::new(0)),
            event_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Take the worker (drain side) exactly once. Returns `None` on subsequent
    /// calls. The caller spawns [`DetectionLogWorker::run`].
    #[must_use]
    pub fn take_worker(&self) -> Option<DetectionLogWorker> {
        self.rx.lock().take().map(|r| DetectionLogWorker {
            attack_rx: r.attack_rx,
            event_rx: r.event_rx,
            attack_dropped: Arc::clone(&self.attack_dropped),
            event_dropped: Arc::clone(&self.event_dropped),
        })
    }

    /// Hot-path enqueue of an `attack_logs` row: synchronous, never awaits,
    /// never spawns. A full channel drops the row and counts it.
    pub fn try_persist_attack_log(&self, log: AttackLog) {
        if self.attack_tx.try_send(log).is_err() {
            metrics::record_budget_event(BudgetEvent::AttackLogWriteDrop);
            self.attack_dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            metrics::queue_depth_inc(QueueGauge::AttackLog);
        }
    }

    /// Hot-path enqueue of a `security_events` row: synchronous, never awaits,
    /// never spawns. A full channel drops the row and counts it.
    pub fn try_persist_security_event(&self, event: CreateSecurityEvent) {
        if self.event_tx.try_send(event).is_err() {
            metrics::record_budget_event(BudgetEvent::SecurityEventWriteDrop);
            self.event_dropped.fetch_add(1, Ordering::Relaxed);
        } else {
            metrics::queue_depth_inc(QueueGauge::SecurityEvent);
        }
    }

    /// Rows dropped because the `attack_logs` channel was full (telemetry /
    /// tests). Reset by the worker's periodic log, so this is a since-last-log
    /// figure; the monotonic series lives on `prxwaf_budget_events_total`.
    #[must_use]
    pub fn dropped_attack_logs(&self) -> u64 {
        self.attack_dropped.load(Ordering::Relaxed)
    }

    /// Rows dropped because the `security_events` channel was full.
    #[must_use]
    pub fn dropped_security_events(&self) -> u64 {
        self.event_dropped.load(Ordering::Relaxed)
    }
}

impl DetectionLogWorker {
    /// Drain both channels in bounded batches and insert each batch as one
    /// multi-row statement.
    ///
    /// Exits when a channel closes (the engine — and thus every `Sender` — has
    /// been dropped), draining whatever the other receiver still holds first, so
    /// a clean shutdown does not throw away records that were already accepted.
    pub async fn run<W: DetectionSinkWriter>(mut self, writer: W) {
        let mut ticker = tokio::time::interval(DROP_LOG_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.log_and_reset_drops();
                }
                maybe = self.attack_rx.recv() => {
                    let Some(first) = maybe else {
                        self.drain_events(&writer).await;
                        self.log_and_reset_drops();
                        return;
                    };
                    let mut batch = Vec::with_capacity(DRAIN_BATCH_SIZE);
                    batch.push(first);
                    while batch.len() < DRAIN_BATCH_SIZE {
                        match self.attack_rx.try_recv() {
                            Ok(log) => batch.push(log),
                            Err(_) => break,
                        }
                    }
                    Self::flush_attack_logs(&writer, batch).await;
                }
                maybe = self.event_rx.recv() => {
                    let Some(first) = maybe else {
                        self.drain_attack_logs(&writer).await;
                        self.log_and_reset_drops();
                        return;
                    };
                    let mut batch = Vec::with_capacity(DRAIN_BATCH_SIZE);
                    batch.push(first);
                    while batch.len() < DRAIN_BATCH_SIZE {
                        match self.event_rx.try_recv() {
                            Ok(event) => batch.push(event),
                            Err(_) => break,
                        }
                    }
                    Self::flush_security_events(&writer, batch).await;
                }
            }
        }
    }

    /// Insert one batch of attack logs and settle the depth gauge for it.
    ///
    /// The gauge is decremented whether the insert succeeded or failed: the
    /// gauge's unit is "rows this process still owes a write", and a row whose
    /// write was attempted and lost is no longer owed. The loss itself is
    /// reported by the `warn!`, not by leaving a gauge permanently high.
    async fn flush_attack_logs<W: DetectionSinkWriter>(writer: &W, batch: Vec<AttackLog>) {
        let n = batch.len();
        if let Err(e) = writer.write_attack_logs(batch).await {
            warn!(rows = n, "Failed to persist attack log batch: {e}");
        }
        for _ in 0..n {
            metrics::queue_depth_dec(QueueGauge::AttackLog);
        }
    }

    /// Insert one batch of security events and settle the depth gauge for it.
    async fn flush_security_events<W: DetectionSinkWriter>(writer: &W, batch: Vec<CreateSecurityEvent>) {
        let n = batch.len();
        if let Err(e) = writer.write_security_events(batch).await {
            warn!(rows = n, "Failed to persist security event batch: {e}");
        }
        for _ in 0..n {
            metrics::queue_depth_dec(QueueGauge::SecurityEvent);
        }
    }

    /// Drain any attack logs still buffered after the event channel closed.
    async fn drain_attack_logs<W: DetectionSinkWriter>(&mut self, writer: &W) {
        loop {
            let mut batch = Vec::new();
            while batch.len() < DRAIN_BATCH_SIZE {
                match self.attack_rx.try_recv() {
                    Ok(log) => batch.push(log),
                    Err(_) => break,
                }
            }
            if batch.is_empty() {
                return;
            }
            Self::flush_attack_logs(writer, batch).await;
        }
    }

    /// Drain any security events still buffered after the attack-log channel
    /// closed.
    async fn drain_events<W: DetectionSinkWriter>(&mut self, writer: &W) {
        loop {
            let mut batch = Vec::new();
            while batch.len() < DRAIN_BATCH_SIZE {
                match self.event_rx.try_recv() {
                    Ok(event) => batch.push(event),
                    Err(_) => break,
                }
            }
            if batch.is_empty() {
                return;
            }
            Self::flush_security_events(writer, batch).await;
        }
    }

    /// Log and reset the per-channel dropped counters (only when non-zero).
    ///
    /// The `prxwaf_budget_events_total` series is the monotonic record; this is
    /// the copy an operator with no Prometheus still gets, and it says which
    /// queue lost records so "we are not detecting" is never a possible reading
    /// of "we are not writing".
    fn log_and_reset_drops(&self) {
        let attack_dropped = self.attack_dropped.swap(0, Ordering::Relaxed);
        if attack_dropped > 0 {
            // `queue` is the metric's own label, so the token in the alert
            // (`{subsystem="queue", limit="attack_log"}`) is the token in the
            // log the alert sends you to. The message keeps the table name,
            // which is what an operator will look in next.
            warn!(
                queue = BudgetEvent::AttackLogWriteDrop.limit(),
                dropped = attack_dropped,
                "attack_log queue full — detections were BLOCKED but the attack_logs row was not recorded \
                 (back-pressure)"
            );
        }
        let event_dropped = self.event_dropped.swap(0, Ordering::Relaxed);
        if event_dropped > 0 {
            warn!(
                queue = BudgetEvent::SecurityEventWriteDrop.limit(),
                dropped = event_dropped,
                "security_event queue full — detections were BLOCKED but the security_events row was not recorded \
                 (back-pressure)"
            );
        }
    }
}

/// Spawn the drain worker on the current Tokio runtime, if one exists.
///
/// Returns `true` when the worker was started. When called outside a runtime
/// (a synchronous construction path, or a unit test) no worker starts and the
/// hot-path `try_send`s fill the channels and then drop — bounded and counted,
/// which is the same degradation a saturated worker produces.
#[must_use]
pub fn spawn_worker_if_runtime(sink: &DetectionLogSink, db: Arc<Database>) -> bool {
    let Some(worker) = sink.take_worker() else {
        return false;
    };
    tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        handle.spawn(async move {
            info!("Detection log worker started (bounded MPSC drain: attack_logs + security_events)");
            worker.run(db).await;
        });
        true
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn attack_log() -> AttackLog {
        AttackLog {
            id: uuid::Uuid::new_v4(),
            host_code: "h".to_string(),
            host: "example.test".to_string(),
            client_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            rule_id: None,
            rule_name: "ip_blocklist".to_string(),
            action: "block".to_string(),
            phase: "ip".to_string(),
            detail: Some("blocked".to_string()),
            request_headers: None,
            geo_info: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn security_event() -> CreateSecurityEvent {
        CreateSecurityEvent {
            host_code: "h".to_string(),
            client_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            rule_id: None,
            rule_name: "sql_injection".to_string(),
            action: "block".to_string(),
            detail: Some("union select".to_string()),
            geo_info: None,
        }
    }

    /// Counts rows and batches, so the worker's drain/exit path and the
    /// multi-row shape are both testable without a database.
    #[derive(Default)]
    struct MockWriter {
        attack_rows: Arc<AtomicU64>,
        attack_batches: Arc<AtomicU64>,
        event_rows: Arc<AtomicU64>,
        event_batches: Arc<AtomicU64>,
    }

    impl DetectionSinkWriter for Arc<MockWriter> {
        async fn write_attack_logs(&self, logs: Vec<AttackLog>) -> Result<(), StorageError> {
            self.attack_rows.fetch_add(logs.len() as u64, Ordering::Relaxed);
            self.attack_batches.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn write_security_events(&self, events: Vec<CreateSecurityEvent>) -> Result<(), StorageError> {
            self.event_rows.fetch_add(events.len() as u64, Ordering::Relaxed);
            self.event_batches.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    /// The property the whole module exists for: past the bound, the hot path
    /// keeps returning immediately and the overflow is counted rather than
    /// queued. Without a worker running, the channel is a hard N.
    #[test]
    fn past_capacity_the_hot_path_drops_and_counts() {
        let sink = DetectionLogSink::new(4, 4);
        for _ in 0..100 {
            sink.try_persist_security_event(security_event());
            sink.try_persist_attack_log(attack_log());
        }
        assert_eq!(
            sink.dropped_security_events(),
            96,
            "4 of 100 fit in the channel, the rest must be dropped and counted"
        );
        assert_eq!(sink.dropped_attack_logs(), 96);
    }

    #[tokio::test]
    async fn channel_close_drains_and_exits_cleanly() {
        let writer = Arc::new(MockWriter::default());
        let sink = DetectionLogSink::new(64, 64);
        let worker = sink.take_worker().expect("worker");

        for _ in 0..10 {
            sink.try_persist_attack_log(attack_log());
            sink.try_persist_security_event(security_event());
        }
        let handle = tokio::spawn({
            let writer = Arc::clone(&writer);
            async move { worker.run(writer).await }
        });

        // Dropping the sink closes both senders, which is the worker's exit
        // condition. It must drain what it already holds before returning.
        drop(sink);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("worker did not exit")
            .expect("worker panicked");

        assert_eq!(writer.attack_rows.load(Ordering::Relaxed), 10);
        assert_eq!(writer.event_rows.load(Ordering::Relaxed), 10);
    }

    /// Batching is the half of the fix that keeps the bound from mattering, so
    /// it is asserted rather than assumed: a burst that is already queued when
    /// the worker wakes must go out in far fewer statements than it has rows.
    #[tokio::test]
    async fn a_queued_burst_goes_out_in_batches_not_one_row_at_a_time() {
        let writer = Arc::new(MockWriter::default());
        let sink = DetectionLogSink::new(1024, 1024);
        let worker = sink.take_worker().expect("worker");
        for _ in 0..1000 {
            sink.try_persist_security_event(security_event());
        }
        let handle = tokio::spawn({
            let writer = Arc::clone(&writer);
            async move { worker.run(writer).await }
        });
        drop(sink);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("worker did not exit")
            .expect("worker panicked");

        assert_eq!(writer.event_rows.load(Ordering::Relaxed), 1000);
        let batches = writer.event_batches.load(Ordering::Relaxed);
        assert!(
            batches <= 1000 / 4,
            "1000 already-queued rows went out in {batches} statements — batching is not engaging"
        );
    }
}
