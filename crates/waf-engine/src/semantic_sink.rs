//! Bounded, back-pressured sink for Lane 2 semantic **observations** and
//! **shadow security events** (codex A-1).
//!
//! The shadow semantic lane persists a de-identified observation on every hit
//! and, when the recommendation is non-`None`, also writes a forced `LogOnly`
//! `security_events` row. The naive implementation spawned one `tokio::task` per
//! observation **and** per security event, so an attack flood (or a noisy
//! detector) could create unbounded tasks and unbounded `INSERT` pressure — a
//! resource-exhaustion `DoS`.
//!
//! This sink mirrors the community reporter pattern
//! ([`crate::community::reporter::CommunityReporter`]): **two bounded MPSC
//! channels** (observations + shadow security events) drained by **one**
//! background worker. The hot path only does a synchronous `try_send`; when a
//! channel is full the item is dropped and a **per-channel** counter is
//! incremented, so a flood degrades to "some shadow rows are dropped" instead of
//! "the process runs out of memory or DB connections". The observation and
//! security-event drop metrics are kept **separate**. The worker drains each
//! channel in bounded batches and inserts the rows one at a time (it is a
//! drain-batch, **not** a single multi-row SQL statement). It is auto-started
//! from [`crate::WafEngine::new`] when a Tokio runtime is present and shuts down
//! cleanly when the engine (and therefore the last `Sender`) is dropped — the
//! `channel_close_drains_and_exits_cleanly` test drives that path with a mock
//! writer.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use waf_storage::StorageError;
use waf_storage::{
    Database,
    models::{CreateSecurityEvent, CreateSemanticObservation},
};

/// Bounded channel capacity for pending observations. A sustained flood beyond
/// this is dropped (and counted), never queued without limit.
pub const OBSERVATION_CHANNEL_CAPACITY: usize = 4096;

/// Bounded channel capacity for pending shadow security events. Separate from
/// the observation channel so the two back-pressure independently.
pub const EVENT_CHANNEL_CAPACITY: usize = 4096;

/// Max rows drained and inserted per channel per worker wake-up.
const DRAIN_BATCH_SIZE: usize = 256;

/// How often the worker logs (and resets) the drop counters.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(30);

/// Sink-write abstraction so the drain worker can be unit-tested without a real
/// database (the `channel_close_drains_and_exits_cleanly` test uses a mock).
/// Implemented for `Arc<Database>` in production.
pub trait SemanticSinkWriter: Send + Sync + 'static {
    /// Persist one de-identified semantic observation.
    fn write_observation(
        &self,
        obs: CreateSemanticObservation,
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;

    /// Persist one shadow `LogOnly` security event.
    fn write_event(
        &self,
        event: CreateSecurityEvent,
    ) -> impl std::future::Future<Output = Result<(), StorageError>> + Send;
}

impl SemanticSinkWriter for Arc<Database> {
    async fn write_observation(&self, obs: CreateSemanticObservation) -> Result<(), StorageError> {
        self.insert_semantic_observation(obs).await
    }

    async fn write_event(&self, event: CreateSecurityEvent) -> Result<(), StorageError> {
        self.create_security_event(event).await
    }
}

/// Hot-path handle: two bounded senders plus per-channel drop counters. Held by
/// the engine.
pub struct SemanticObservationSink {
    obs_tx: mpsc::Sender<CreateSemanticObservation>,
    event_tx: mpsc::Sender<CreateSecurityEvent>,
    /// Receivers, taken exactly once by [`Self::take_worker`].
    rx: parking_lot::Mutex<Option<TakenReceivers>>,
    /// Observations dropped because the observation channel was full.
    obs_dropped: Arc<AtomicU64>,
    /// Shadow security events dropped because the event channel was full.
    event_dropped: Arc<AtomicU64>,
}

/// The receiver pair, moved into the worker exactly once.
struct TakenReceivers {
    obs_rx: mpsc::Receiver<CreateSemanticObservation>,
    event_rx: mpsc::Receiver<CreateSecurityEvent>,
}

/// The drain side, moved into the background task.
///
/// Owns only the receivers and the drop counters — **not** an
/// `Arc<SemanticObservationSink>` — so the worker exits as soon as the engine
/// drops the last `Sender` (no reference cycle).
pub struct SemanticObservationWorker {
    obs_rx: mpsc::Receiver<CreateSemanticObservation>,
    event_rx: mpsc::Receiver<CreateSecurityEvent>,
    obs_dropped: Arc<AtomicU64>,
    event_dropped: Arc<AtomicU64>,
}

impl SemanticObservationSink {
    /// Build a sink with the given bounded capacities.
    #[must_use]
    pub fn new(obs_capacity: usize, event_capacity: usize) -> Self {
        let (obs_tx, obs_rx) = mpsc::channel(obs_capacity.max(1));
        let (event_tx, event_rx) = mpsc::channel(event_capacity.max(1));
        Self {
            obs_tx,
            event_tx,
            rx: parking_lot::Mutex::new(Some(TakenReceivers { obs_rx, event_rx })),
            obs_dropped: Arc::new(AtomicU64::new(0)),
            event_dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Take the worker (drain side) exactly once. Returns `None` on subsequent
    /// calls. The caller spawns [`SemanticObservationWorker::run`].
    #[must_use]
    pub fn take_worker(&self) -> Option<SemanticObservationWorker> {
        self.rx.lock().take().map(|r| SemanticObservationWorker {
            obs_rx: r.obs_rx,
            event_rx: r.event_rx,
            obs_dropped: Arc::clone(&self.obs_dropped),
            event_dropped: Arc::clone(&self.event_dropped),
        })
    }

    /// Hot-path enqueue of an observation: synchronous, never awaits, never
    /// spawns. When the bounded channel is full the observation is dropped and
    /// counted.
    pub fn try_persist(&self, obs: CreateSemanticObservation) {
        if self.obs_tx.try_send(obs).is_err() {
            self.obs_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Hot-path enqueue of a shadow security event: synchronous, never awaits,
    /// never spawns. When the bounded channel is full the event is dropped and
    /// counted (codex A-1: the shadow log path must not spawn a task per hit).
    pub fn try_persist_event(&self, event: CreateSecurityEvent) {
        if self.event_tx.try_send(event).is_err() {
            self.event_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Current dropped-observation count (telemetry / tests).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.obs_dropped.load(Ordering::Relaxed)
    }

    /// Current dropped shadow-security-event count (telemetry / tests). Kept
    /// **separate** from the observation drop metric (codex A-1).
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.event_dropped.load(Ordering::Relaxed)
    }
}

impl SemanticObservationWorker {
    /// Drain both channels in bounded batches and insert into
    /// `semantic_observations` / `security_events`, mirroring the community flush
    /// task. This is a **drain-batch** (collect up to [`DRAIN_BATCH_SIZE`] queued
    /// rows, then insert them one at a time) — **not** a single multi-row SQL
    /// statement. Exits when a channel closes (the engine — and thus every
    /// `Sender` — has been dropped), draining whatever each receiver still holds
    /// first. A periodic timer logs the accumulated per-channel drop counts.
    pub async fn run<W: SemanticSinkWriter>(mut self, writer: W) {
        let mut ticker = tokio::time::interval(DROP_LOG_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    self.log_and_reset_drops();
                }
                maybe = self.obs_rx.recv() => {
                    let Some(first) = maybe else {
                        // Observation channel closed — drain remaining events, log, exit.
                        self.drain_events(&writer).await;
                        self.log_and_reset_drops();
                        return;
                    };
                    let mut batch = Vec::with_capacity(DRAIN_BATCH_SIZE);
                    batch.push(first);
                    while batch.len() < DRAIN_BATCH_SIZE {
                        match self.obs_rx.try_recv() {
                            Ok(o) => batch.push(o),
                            Err(_) => break,
                        }
                    }
                    for obs in batch {
                        if let Err(e) = writer.write_observation(obs).await {
                            warn!("Failed to persist semantic observation: {e}");
                        }
                    }
                }
                maybe = self.event_rx.recv() => {
                    let Some(first) = maybe else {
                        // Event channel closed — drain remaining observations, log, exit.
                        self.drain_observations(&writer).await;
                        self.log_and_reset_drops();
                        return;
                    };
                    let mut batch = Vec::with_capacity(DRAIN_BATCH_SIZE);
                    batch.push(first);
                    while batch.len() < DRAIN_BATCH_SIZE {
                        match self.event_rx.try_recv() {
                            Ok(e) => batch.push(e),
                            Err(_) => break,
                        }
                    }
                    for event in batch {
                        if let Err(e) = writer.write_event(event).await {
                            warn!("Failed to persist shadow security event: {e}");
                        }
                    }
                }
            }
        }
    }

    /// Drain any observations still buffered after the event channel closed.
    async fn drain_observations<W: SemanticSinkWriter>(&mut self, writer: &W) {
        while let Ok(obs) = self.obs_rx.try_recv() {
            if let Err(e) = writer.write_observation(obs).await {
                warn!("Failed to persist semantic observation: {e}");
            }
        }
    }

    /// Drain any shadow security events still buffered after the observation
    /// channel closed.
    async fn drain_events<W: SemanticSinkWriter>(&mut self, writer: &W) {
        while let Ok(event) = self.event_rx.try_recv() {
            if let Err(e) = writer.write_event(event).await {
                warn!("Failed to persist shadow security event: {e}");
            }
        }
    }

    /// Log and reset the per-channel dropped counters (only when non-zero).
    fn log_and_reset_drops(&self) {
        let obs_dropped = self.obs_dropped.swap(0, Ordering::Relaxed);
        if obs_dropped > 0 {
            warn!(
                dropped = obs_dropped,
                "Semantic observation channel full — dropped observations (back-pressure)"
            );
        }
        let event_dropped = self.event_dropped.swap(0, Ordering::Relaxed);
        if event_dropped > 0 {
            warn!(
                dropped = event_dropped,
                "Semantic shadow security-event channel full — dropped events (back-pressure)"
            );
        }
    }
}

/// Spawn the drain worker on the current Tokio runtime, if one exists.
///
/// Returns `true` when the worker was started. When called outside a runtime
/// (e.g. a non-async construction path) no worker is started and the hot-path
/// `try_send`s simply drop (and count) — but that only matters when the lane is
/// enabled, which never happens outside the async server path.
#[must_use]
pub fn spawn_worker_if_runtime(sink: &SemanticObservationSink, db: Arc<Database>) -> bool {
    let Some(worker) = sink.take_worker() else {
        return false;
    };
    tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        handle.spawn(async move {
            info!("Semantic observation worker started (bounded MPSC drain: observations + shadow events)");
            worker.run(db).await;
        });
        true
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn obs() -> CreateSemanticObservation {
        CreateSemanticObservation {
            host_code: "h".to_string(),
            client_ip: "127.0.0.1".to_string(),
            req_id: "r".to_string(),
            scope: "body".to_string(),
            request_score: 0,
            recommendation: "log".to_string(),
            degraded: false,
            exhausted: false,
            pipeline: "semantic".to_string(),
            schema_version: 1,
            observations: serde_json::Value::Array(Vec::new()),
        }
    }

    fn event() -> CreateSecurityEvent {
        CreateSecurityEvent {
            host_code: "h".to_string(),
            client_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            rule_id: None,
            rule_name: "sql.union_null".to_string(),
            action: "log_only".to_string(),
            detail: Some("shadow".to_string()),
            geo_info: None,
        }
    }

    /// Mock writer counting inserts, so the worker drain/exit path is testable
    /// without a database.
    #[derive(Clone, Default)]
    struct MockWriter {
        obs: Arc<AtomicU64>,
        events: Arc<AtomicU64>,
    }

    impl SemanticSinkWriter for MockWriter {
        async fn write_observation(&self, _obs: CreateSemanticObservation) -> Result<(), StorageError> {
            self.obs.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn write_event(&self, _event: CreateSecurityEvent) -> Result<(), StorageError> {
            self.events.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn full_observation_channel_drops_and_counts() {
        // Capacity 2, no worker draining → the 3rd send is dropped and counted.
        let sink = SemanticObservationSink::new(2, 2);
        sink.try_persist(obs());
        sink.try_persist(obs());
        assert_eq!(sink.dropped(), 0, "first two fit the bounded channel");
        sink.try_persist(obs());
        assert_eq!(sink.dropped(), 1, "the third is dropped under back-pressure");
        sink.try_persist(obs());
        assert_eq!(sink.dropped(), 2, "drops accumulate");
    }

    #[test]
    fn full_event_channel_drops_and_counts_separately() {
        // codex A-1: the shadow security-event channel is bounded with its own
        // metric, independent of the observation channel.
        let sink = SemanticObservationSink::new(2, 2);
        sink.try_persist_event(event());
        sink.try_persist_event(event());
        assert_eq!(sink.dropped_events(), 0, "first two fit the bounded event channel");
        sink.try_persist_event(event());
        assert_eq!(
            sink.dropped_events(),
            1,
            "the third event is dropped under back-pressure"
        );
        // The observation metric is untouched — the two channels are separate.
        assert_eq!(sink.dropped(), 0, "event drops do not touch the observation metric");
    }

    #[test]
    fn worker_taken_once() {
        let sink = SemanticObservationSink::new(4, 4);
        assert!(sink.take_worker().is_some());
        assert!(sink.take_worker().is_none(), "the worker is taken exactly once");
    }

    #[tokio::test]
    async fn channel_close_drains_and_exits_cleanly() {
        // codex A-1: after the last Sender is dropped (engine shutdown) the worker
        // drains whatever is buffered on BOTH channels and then returns — no hang,
        // no leaked task. Driven with a mock writer so no database is needed.
        let sink = SemanticObservationSink::new(8, 8);
        sink.try_persist(obs());
        sink.try_persist(obs());
        sink.try_persist_event(event());
        let worker = sink.take_worker().expect("worker present");
        // Drop the sink → both senders drop → both channels close after their
        // buffered rows are drained.
        drop(sink);

        let writer = MockWriter::default();
        let w = writer.clone();
        let handle = tokio::spawn(async move { worker.run(w).await });

        // The worker must complete (clean exit), not hang.
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("worker must exit cleanly after the channels close")
            .expect("worker task must not panic");

        assert_eq!(
            writer.obs.load(Ordering::Relaxed),
            2,
            "both buffered observations drained"
        );
        assert_eq!(
            writer.events.load(Ordering::Relaxed),
            1,
            "the buffered shadow event drained"
        );
    }
}
