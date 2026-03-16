use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::debug;

use crate::protocol::{ClusterMessage, EventBatch, SecurityEvent, StatsBatch};

// ─── EventBatcher ─────────────────────────────────────────────────────────────

/// Batches security events on the worker before forwarding to main.
///
/// Events accumulate in a bounded ring buffer.  A full batch or a timer flush
/// (driven by [`run_event_batcher`]) triggers an [`EventBatch`] message.
pub struct EventBatcher {
    node_id: String,
    queue: VecDeque<SecurityEvent>,
    batch_size: usize,
    flush_interval_ms: u64,
}

impl EventBatcher {
    pub fn new(node_id: String, batch_size: usize, flush_interval_ms: u64) -> Self {
        Self {
            node_id,
            queue: VecDeque::new(),
            batch_size,
            flush_interval_ms,
        }
    }

    /// The configured flush interval in milliseconds.
    pub fn flush_interval_ms(&self) -> u64 {
        self.flush_interval_ms
    }

    /// Enqueue a security event.  Auto-flushes if the batch is full.
    pub fn push(&mut self, event: SecurityEvent) -> Option<EventBatch> {
        self.queue.push_back(event);
        if self.queue.len() >= self.batch_size {
            self.flush()
        } else {
            None
        }
    }

    /// Drain up to `batch_size` events and return an `EventBatch`, or `None`
    /// if the queue is empty.
    pub fn flush(&mut self) -> Option<EventBatch> {
        if self.queue.is_empty() {
            return None;
        }
        let count = self.queue.len().min(self.batch_size);
        let events: Vec<SecurityEvent> = self.queue.drain(..count).collect();
        debug!(
            node_id = %self.node_id,
            count = events.len(),
            "Flushing event batch"
        );
        Some(EventBatch {
            node_id: self.node_id.clone(),
            events,
        })
    }

    /// Number of events currently buffered.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }
}

/// Run an event-batcher loop that flushes to `sender` on a timer or when full.
///
/// Receives events from `event_rx`, buffers them in `batcher`, and sends
/// [`EventBatch`] messages whenever the batch is full or the timer fires.
///
/// The loop exits when `event_rx` is closed.
pub async fn run_event_batcher(
    mut batcher: EventBatcher,
    mut event_rx: mpsc::Receiver<SecurityEvent>,
    batch_tx: mpsc::Sender<EventBatch>,
) {
    let interval = batcher.flush_interval_ms().max(1);
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(interval));

    loop {
        tokio::select! {
            biased;

            event = event_rx.recv() => {
                match event {
                    Some(ev) => {
                        if let Some(batch) = batcher.push(ev)
                            && batch_tx.send(batch).await.is_err()
                        {
                            debug!("Event batch channel closed; stopping batcher");
                            return;
                        }
                    }
                    None => {
                        // Flush any remaining events before exit.
                        if let Some(batch) = batcher.flush() {
                            let _ = batch_tx.send(batch).await;
                        }
                        return;
                    }
                }
            }

            _ = ticker.tick() => {
                if let Some(batch) = batcher.flush()
                    && batch_tx.send(batch).await.is_err()
                {
                    debug!("Event batch channel closed; stopping batcher");
                    return;
                }
            }
        }
    }
}

// ─── StatsCollector ───────────────────────────────────────────────────────────

/// Accumulates per-node request statistics for periodic aggregation.
///
/// Stats are sent to the main node as unreliable QUIC datagrams via
/// [`StatsBatch`].  Loss of a single batch is acceptable; the main node keeps
/// a rolling window rather than an exact total.
pub struct StatsCollector {
    node_id: String,
    total_requests: u64,
    blocked_requests: u64,
    allowed_requests: u64,
    top_ips: HashMap<String, u64>,
    top_rules: HashMap<String, u64>,
    top_countries: HashMap<String, u64>,
}

impl StatsCollector {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            total_requests: 0,
            blocked_requests: 0,
            allowed_requests: 0,
            top_ips: HashMap::new(),
            top_rules: HashMap::new(),
            top_countries: HashMap::new(),
        }
    }

    /// Record a single processed request.
    ///
    /// `rule_id` is `None` for requests that passed all checks without a match.
    /// `country` may be an empty string if geo data is unavailable.
    pub fn record_request(
        &mut self,
        ip: &str,
        rule_id: Option<&str>,
        country: &str,
        blocked: bool,
    ) {
        self.total_requests += 1;
        if blocked {
            self.blocked_requests += 1;
        } else {
            self.allowed_requests += 1;
        }

        *self.top_ips.entry(ip.to_string()).or_default() += 1;

        if let Some(rule) = rule_id {
            *self.top_rules.entry(rule.to_string()).or_default() += 1;
        }

        if !country.is_empty() {
            *self.top_countries.entry(country.to_string()).or_default() += 1;
        }
    }

    /// Drain the accumulated stats into a [`StatsBatch`] and reset counters.
    ///
    /// The batch is timestamped at the moment of the flush call.
    pub fn flush(&mut self) -> StatsBatch {
        let batch = StatsBatch {
            node_id: self.node_id.clone(),
            timestamp_ms: unix_ms(),
            total_requests: self.total_requests,
            blocked_requests: self.blocked_requests,
            allowed_requests: self.allowed_requests,
            top_ips: std::mem::take(&mut self.top_ips),
            top_rules: std::mem::take(&mut self.top_rules),
            top_countries: std::mem::take(&mut self.top_countries),
        };
        self.total_requests = 0;
        self.blocked_requests = 0;
        self.allowed_requests = 0;
        batch
    }

    /// Current total request count (without flushing).
    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ─── Stats sender (QUIC datagrams) ────────────────────────────────────────────

/// Periodically flush `collector` and ship the resulting [`StatsBatch`] to the
/// main node as an unreliable QUIC datagram.
///
/// Datagram loss is acceptable — the main node uses a rolling window rather than
/// an exact total, so a missed batch merely reduces precision.
///
/// The loop exits cleanly when the QUIC connection is closed.
pub async fn run_stats_sender(
    mut collector: StatsCollector,
    interval_ms: u64,
    conn: quinn::Connection,
) {
    let interval = interval_ms.max(1);
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;

            _ = conn.closed() => {
                debug!("Stats sender: QUIC connection closed, stopping");
                return;
            }

            _ = ticker.tick() => {
                let batch = collector.flush();
                if batch.total_requests == 0 {
                    continue;
                }
                let msg = ClusterMessage::StatsBatch(batch);
                match serde_json::to_vec(&msg) {
                    Ok(data) => {
                        if let Err(e) = conn.send_datagram(Bytes::from(data)) {
                            match e {
                                quinn::SendDatagramError::ConnectionLost(_) => {
                                    debug!("Stats sender: connection lost, stopping");
                                    return;
                                }
                                other => {
                                    tracing::warn!("Stats datagram send failed: {other}");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to serialize StatsBatch: {e}");
                    }
                }
            }
        }
    }
}
