//! Notification runtime: the producers that raise events, and the single
//! consumer that turns them into notifications.
//!
//! # The gap this closes
//!
//! Everything below [`crate::notifications::dispatch_notification`] — channel
//! configs, encryption at rest, webhook/email/Telegram transports,
//! `notification_log`, the admin UI — already existed and worked, but nothing
//! ever *called* the dispatcher outside the "Test send" button. An operator
//! could configure alerting, watch the test succeed, and then never hear about a
//! real attack. This module supplies the missing triggers.
//!
//! # Shape
//!
//! ```text
//!  producers (any crate)            transport            consumer (here)
//!  ─────────────────────            ─────────            ───────────────
//!  waf-storage  create_security_event ─┐
//!  waf-storage  create_attack_log    ──┤
//!  cert expiry monitor (below)       ──┼─> NotificationBus ─> Coalescer ─> dispatch_notification
//!  backend health monitor (below)    ──┘   (bounded MPSC)     (per-scope    (per-channel
//!                                                              window)       rate_limit_secs)
//! ```
//!
//! Producers only ever do a synchronous, bounded `try_send`
//! ([`waf_common::notify::NotificationBus::publish`]) — no awaiting, no
//! spawning, no network or database work on any request path. If the queue
//! backs up, events are dropped and counted, and the count is logged; the proxy
//! is never slowed or stalled by notification delivery.
//!
//! # Two independent limiters
//!
//! 1. **Coalescing** (here). The first event for a given kind+scope alerts
//!    immediately; further events with the same scope inside the window are
//!    folded into one follow-up summary carrying the suppressed count. This is
//!    what makes a scanner generating hundreds of blocks per second produce two
//!    messages rather than hundreds.
//! 2. **Per-channel cooldown** (`dispatch_notification`), honouring each
//!    channel's stored `rate_limit_secs`, keyed per (config, host).
//!
//! Neither limiter discards silently: coalesced counts are reported in the
//! follow-up message and in the log, and cooldown suppressions are written to
//! `notification_log` with status `rate_limited`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use gateway::LoadBalancer;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{debug, info, warn};
use waf_common::config::NotificationsConfig;
use waf_common::notify::{NotificationBus, NotificationEvent, NotificationEventKind};
use waf_storage::Database;

use crate::notifications::dispatch_notification;
use crate::state::AppState;

/// Upper bound on live coalescing buckets.
///
/// Each bucket may emit one notification per window, so this also bounds how
/// many dispatch tasks a single window can start. Scopes are derived from
/// configured hosts / backends / certificates, so hitting this ceiling means
/// something is generating unexpected scope cardinality — the overflow is
/// treated as suppressed rather than allowed to grow.
const MAX_COALESCE_BUCKETS: usize = 256;

/// How often the dispatcher wakes to close expired windows and report drops.
const DISPATCHER_TICK: Duration = Duration::from_secs(5);

// ─── Coalescer ────────────────────────────────────────────────────────────────

/// One coalescing bucket: the window it belongs to, how many events it has
/// swallowed, and the most recent one (used as the sample in the summary).
#[derive(Debug)]
struct Bucket {
    window_ends: Instant,
    suppressed: u64,
    latest: NotificationEvent,
}

/// Leading-edge coalescer.
///
/// Pure state machine over an injected `now`, so the whole burst-suppression
/// policy is unit-testable without sleeping or touching the network.
#[derive(Debug)]
struct Coalescer {
    window: Duration,
    buckets: HashMap<(NotificationEventKind, String), Bucket>,
    /// Events rejected because [`MAX_COALESCE_BUCKETS`] was reached.
    overflow: u64,
}

impl Coalescer {
    fn new(window: Duration) -> Self {
        Self {
            window,
            buckets: HashMap::new(),
            overflow: 0,
        }
    }

    /// Offer an event.
    ///
    /// Returns `Some(event)` when it should be dispatched **now** (it opened a
    /// fresh window), `None` when it was folded into an open window.
    fn admit(&mut self, event: NotificationEvent, now: Instant) -> Option<NotificationEvent> {
        let key = (event.kind, event.dedup_key.clone());
        match self.buckets.get_mut(&key) {
            // An open window: fold the event in, keeping it as the sample so
            // the summary quotes the most recent occurrence.
            Some(bucket) if now < bucket.window_ends => {
                bucket.suppressed = bucket.suppressed.saturating_add(1);
                bucket.latest = event;
                None
            }
            // The window lapsed without `flush` running (possible only if the
            // ticker is starved): reopen it and alert immediately.
            Some(bucket) => {
                bucket.window_ends = now + self.window;
                bucket.suppressed = 0;
                bucket.latest = event.clone();
                Some(event)
            }
            None => {
                if self.buckets.len() >= MAX_COALESCE_BUCKETS {
                    self.overflow = self.overflow.saturating_add(1);
                    return None;
                }
                self.buckets.insert(
                    key,
                    Bucket {
                        window_ends: now + self.window,
                        suppressed: 0,
                        latest: event.clone(),
                    },
                );
                Some(event)
            }
        }
    }

    /// Close every window that has elapsed.
    ///
    /// Buckets that swallowed events emit one summary and reopen (a sustained
    /// attack keeps producing periodic updates); quiet buckets are dropped, so
    /// the next event for that scope alerts immediately again.
    fn flush(&mut self, now: Instant) -> Vec<NotificationEvent> {
        let mut out = Vec::new();
        self.buckets.retain(|_, bucket| {
            if now < bucket.window_ends {
                return true;
            }
            if bucket.suppressed == 0 {
                return false;
            }
            out.push(summary_event(bucket, self.window));
            bucket.window_ends = now + self.window;
            bucket.suppressed = 0;
            true
        });
        out
    }

    /// Read and reset the overflow counter, for periodic logging.
    fn take_overflow(&mut self) -> u64 {
        std::mem::take(&mut self.overflow)
    }
}

/// Build the follow-up notification for a window that swallowed events.
fn summary_event(bucket: &Bucket, window: Duration) -> NotificationEvent {
    let sample = &bucket.latest;
    let n = bucket.suppressed;
    let secs = window.as_secs();
    NotificationEvent::new(
        sample.kind,
        sample.host_code.clone(),
        sample.dedup_key.clone(),
        &format!("{} (+{n} more)", sample.title),
        &format!(
            "{n} further '{}' event(s) occurred in the last {secs}s and were coalesced into this summary.\n\n\
             Most recent:\n{}",
            sample.kind, sample.message
        ),
    )
}

// ─── Consumer ─────────────────────────────────────────────────────────────────

/// Spawn the single consumer that drains the bus and delivers notifications.
///
/// Exits cleanly when every [`NotificationBus`] sender is dropped, flushing the
/// windows it still holds.
pub fn spawn_dispatcher(
    state: Arc<AppState>,
    bus: Arc<NotificationBus>,
    mut rx: mpsc::Receiver<NotificationEvent>,
    window: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            coalesce_window_secs = window.as_secs(),
            "Notification dispatcher started"
        );
        let mut coalescer = Coalescer::new(window);
        let mut ticker = tokio::time::interval(DISPATCHER_TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    let Some(event) = maybe else {
                        // Every producer is gone — emit whatever is pending and stop.
                        for pending in coalescer.flush(Instant::now() + window) {
                            deliver(&state, pending);
                        }
                        info!("Notification dispatcher stopped (all producers dropped)");
                        return;
                    };
                    if let Some(immediate) = coalescer.admit(event, Instant::now()) {
                        deliver(&state, immediate);
                    }
                }
                _ = ticker.tick() => {
                    for pending in coalescer.flush(Instant::now()) {
                        deliver(&state, pending);
                    }
                    report_suppression(&bus, &mut coalescer);
                }
            }
        }
    })
}

/// Hand one event to the channel dispatcher.
///
/// Spawned rather than awaited inline so a wedged SMTP server (10s timeout)
/// cannot stall the drain loop and back the bounded queue up behind it.
/// Coalescing bounds the concurrency to at most one task per scope per window.
fn deliver(state: &Arc<AppState>, event: NotificationEvent) {
    debug!(kind = %event.kind, scope = %event.dedup_key, "dispatching notification");
    let state = Arc::clone(state);
    tokio::spawn(async move {
        dispatch_notification(
            state,
            event.kind.as_str().to_owned(),
            event.host_code,
            event.title,
            event.message,
        )
        .await;
    });
}

/// Surface both suppression paths in the process log so neither is silent.
fn report_suppression(bus: &Arc<NotificationBus>, coalescer: &mut Coalescer) {
    let dropped = bus.take_dropped();
    if dropped > 0 {
        warn!(
            queue = waf_common::metrics::BudgetEvent::NotificationDrop.limit(),
            dropped, "notifications queue full — events dropped (back-pressure); delivery is degraded"
        );
    }
    let overflow = coalescer.take_overflow();
    if overflow > 0 {
        warn!(
            overflow,
            max_buckets = MAX_COALESCE_BUCKETS,
            "Notification coalescing bucket limit reached — events suppressed"
        );
    }
}

// ─── Producer: certificate expiry ─────────────────────────────────────────────

/// Emit at most one alert per certificate per remaining-day value.
///
/// The monitor runs hourly, but "your certificate expires in 9 days" is worth
/// saying once a day, not 24 times. Remembering the last day count that was
/// reported gives exactly that: one escalating alert per certificate per day,
/// with no timer state to keep in sync.
type ReportedDays = HashMap<uuid::Uuid, i64>;

/// Spawn the certificate-expiry monitor.
///
/// Deliberately independent of the ACME renewal task: it alerts on *every*
/// active certificate, including hand-installed ones that no automation will
/// renew, and it keeps working when ACME is disabled entirely.
pub fn spawn_cert_expiry_monitor(
    db: Arc<Database>,
    bus: Arc<NotificationBus>,
    interval: Duration,
    warn_days: i64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            interval_secs = interval.as_secs(),
            warn_days, "Certificate expiry monitor started"
        );
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut reported: ReportedDays = HashMap::new();

        loop {
            // `interval` fires immediately on its first tick, so an already
            // expiring certificate is reported at startup rather than an hour in.
            ticker.tick().await;
            match db.list_certificates_expiring_within(warn_days).await {
                Ok(certs) => {
                    let live: std::collections::HashSet<uuid::Uuid> = certs.iter().map(|c| c.id).collect();
                    // Forget certificates that were renewed or removed, so a
                    // future expiry alerts again from scratch.
                    reported.retain(|id, _| live.contains(id));

                    for cert in certs {
                        let Some(not_after) = cert.not_after else {
                            continue;
                        };
                        let days_left = (not_after - chrono::Utc::now()).num_days();
                        if reported.get(&cert.id) == Some(&days_left) {
                            continue;
                        }
                        reported.insert(cert.id, days_left);
                        bus.publish(cert_expiry_event(&cert.host_code, &cert.domain, days_left, not_after));
                    }
                }
                Err(e) => warn!("Certificate expiry check failed: {e}"),
            }
        }
    })
}

/// Build the `cert_expiry` event, wording it for the expired case too.
fn cert_expiry_event(
    host_code: &str,
    domain: &str,
    days_left: i64,
    not_after: chrono::DateTime<chrono::Utc>,
) -> NotificationEvent {
    let expiry = not_after.format("%Y-%m-%d %H:%M:%S UTC");
    let (title, lead) = if days_left < 0 {
        (
            format!("[PRX-WAF] Certificate EXPIRED: {domain}"),
            format!("The TLS certificate for {domain} expired {} day(s) ago.", -days_left),
        )
    } else {
        (
            format!("[PRX-WAF] Certificate expires in {days_left}d: {domain}"),
            format!("The TLS certificate for {domain} expires in {days_left} day(s)."),
        )
    };
    NotificationEvent::new(
        NotificationEventKind::CertExpiry,
        Some(host_code.to_owned()),
        format!("cert:{host_code}:{domain}"),
        &title,
        &format!("{lead}\n\nHost:      {host_code}\nDomain:    {domain}\nNot after: {expiry}"),
    )
}

// ─── Producer: backend health ─────────────────────────────────────────────────

/// A load-balanced pool to watch, paired with the host it serves.
///
/// The binary already builds one `LoadBalancer` per multi-backend host; it hands
/// the same `Arc`s here so health is observed through the gateway's existing
/// checker rather than by opening a second set of probes against the operator's
/// upstreams.
pub struct MonitoredPool {
    pub host_code: String,
    pub lb: Arc<LoadBalancer>,
}

/// Spawn the upstream-health monitor.
///
/// Samples the health flags the gateway's own TCP checker maintains and emits an
/// event on each **transition**, so a backend that stays down produces one alert
/// rather than one per poll. Recoveries are announced too — an alert you are
/// never told is over is an alert you learn to ignore.
pub fn spawn_backend_health_monitor(
    pools: Vec<MonitoredPool>,
    bus: Arc<NotificationBus>,
    poll: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            pools = pools.len(),
            poll_secs = poll.as_secs(),
            "Backend health monitor started"
        );
        // Seed from the current flags so the first poll reports nothing: the
        // gateway starts every backend as healthy, and a fresh process must not
        // announce a state it never observed changing.
        let mut last: HashMap<(String, String), bool> = HashMap::new();
        for pool in &pools {
            for backend in pool.lb.all_backends() {
                last.insert((pool.host_code.clone(), backend.id.clone()), backend.is_healthy());
            }
        }

        let mut ticker = tokio::time::interval(poll);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for pool in &pools {
                for backend in pool.lb.all_backends() {
                    let key = (pool.host_code.clone(), backend.id.clone());
                    let healthy = backend.is_healthy();
                    let previous = last.insert(key, healthy);
                    // `None` = a backend added after startup; adopt its state
                    // without alerting, same as the initial seed.
                    if previous.is_none_or(|was| was == healthy) {
                        continue;
                    }
                    bus.publish(backend_health_event(&pool.host_code, &backend.addr(), healthy));
                }
            }
        }
    })
}

/// Build the `backend_down` event for an up/down transition.
///
/// Recovery reuses the same event type: a channel subscribed to `backend_down`
/// wants the "back up" message too, and there is no `backend_up` type to
/// subscribe to.
fn backend_health_event(host_code: &str, addr: &str, healthy: bool) -> NotificationEvent {
    let (title, body) = if healthy {
        (
            format!("[PRX-WAF] Backend recovered: {addr}"),
            format!("Upstream backend {addr} for host {host_code} is reachable again."),
        )
    } else {
        (
            format!("[PRX-WAF] Backend DOWN: {addr}"),
            format!(
                "Upstream backend {addr} for host {host_code} failed its health check and has been \
                 taken out of rotation."
            ),
        )
    };
    NotificationEvent::new(
        NotificationEventKind::BackendDown,
        Some(host_code.to_owned()),
        format!("backend:{host_code}:{addr}"),
        &title,
        &body,
    )
}

// ─── Startup ──────────────────────────────────────────────────────────────────

/// Handles for the notification runtime, kept alive for the process lifetime.
///
/// Dropping this stops every producer and, once the bus senders are gone, the
/// dispatcher too.
pub struct NotifyRuntime {
    pub bus: Arc<NotificationBus>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for NotifyRuntime {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Start the notification runtime and attach the bus to the database.
///
/// Returns `None` when notifications are disabled by config. The caller must
/// keep the returned [`NotifyRuntime`] alive.
#[must_use]
pub fn start(
    cfg: &NotificationsConfig,
    state: &Arc<AppState>,
    db: &Arc<Database>,
    pools: Vec<MonitoredPool>,
) -> Option<NotifyRuntime> {
    if !cfg.enabled {
        info!("Notification delivery disabled by config; no events will be raised");
        return None;
    }

    let (bus, rx) = NotificationBus::new(cfg.queue_capacity);
    if !db.set_notification_bus(Arc::clone(&bus)) {
        warn!("Notification bus already installed; skipping duplicate notification runtime");
        return None;
    }

    let mut tasks = vec![spawn_dispatcher(
        Arc::clone(state),
        Arc::clone(&bus),
        rx,
        Duration::from_secs(cfg.coalesce_window_secs.max(1)),
    )];

    tasks.push(spawn_cert_expiry_monitor(
        Arc::clone(db),
        Arc::clone(&bus),
        Duration::from_secs(cfg.cert_expiry_check_interval_secs.max(1)),
        cfg.cert_expiry_warn_days.max(0),
    ));

    if pools.is_empty() {
        info!("No load-balanced host pools configured; backend_down monitoring is inactive");
    } else {
        tasks.push(spawn_backend_health_monitor(
            pools,
            Arc::clone(&bus),
            Duration::from_secs(cfg.backend_health_poll_secs.max(1)),
        ));
    }

    info!("Notification runtime started (attack_detected, cert_expiry, backend_down)");
    Some(NotifyRuntime { bus, tasks })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn attack(host: &str) -> NotificationEvent {
        NotificationEvent::new(
            NotificationEventKind::AttackDetected,
            Some(host.to_owned()),
            host,
            &format!("attack on {host}"),
            "body",
        )
    }

    // ── ① Leading edge alerts immediately ────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn first_event_of_a_scope_dispatches_immediately() {
        let mut c = Coalescer::new(Duration::from_mins(1));
        assert!(
            c.admit(attack("h1"), Instant::now()).is_some(),
            "the first event must alert without waiting for the window"
        );
    }

    // ── ② A burst collapses into one summary ─────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn a_flood_of_one_scope_produces_one_alert_plus_one_summary() {
        let window = Duration::from_mins(1);
        let mut c = Coalescer::new(window);
        let t0 = Instant::now();

        // 1000 blocks against the same host inside the window.
        let mut immediate = 0;
        for _ in 0..1000 {
            if c.admit(attack("h1"), t0).is_some() {
                immediate += 1;
            }
        }
        assert_eq!(immediate, 1, "only the leading edge is dispatched immediately");
        assert!(c.flush(t0).is_empty(), "nothing is emitted before the window closes");

        let summaries = c.flush(t0 + window);
        assert_eq!(summaries.len(), 1, "the burst collapses into a single summary");
        let summary = summaries.first().expect("one summary");
        assert!(
            summary.title.contains("+999 more"),
            "the suppressed count must be visible to the operator: {}",
            summary.title
        );
        assert!(summary.message.contains("999 further"));

        // 1001 events in, 2 notifications out.
        assert_eq!(immediate + summaries.len(), 2);
    }

    // ── ③ Different scopes are limited independently ─────────────────────────

    #[tokio::test(start_paused = true)]
    async fn distinct_hosts_do_not_silence_each_other() {
        let mut c = Coalescer::new(Duration::from_mins(1));
        let t0 = Instant::now();
        assert!(c.admit(attack("h1"), t0).is_some());
        assert!(
            c.admit(attack("h2"), t0).is_some(),
            "a flood on h1 must not mute alerts for h2"
        );
        assert!(c.admit(attack("h1"), t0).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn distinct_event_kinds_do_not_silence_each_other() {
        let mut c = Coalescer::new(Duration::from_mins(1));
        let t0 = Instant::now();
        let same_scope = "h1";
        assert!(c.admit(attack(same_scope), t0).is_some());
        let cert = NotificationEvent::new(
            NotificationEventKind::CertExpiry,
            Some("h1".to_owned()),
            same_scope,
            "cert",
            "body",
        );
        assert!(
            c.admit(cert, t0).is_some(),
            "coalescing is per (kind, scope), not per scope alone"
        );
    }

    // ── ④ A quiet scope alerts immediately again ─────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn a_scope_that_goes_quiet_alerts_immediately_next_time() {
        let window = Duration::from_mins(1);
        let mut c = Coalescer::new(window);
        let t0 = Instant::now();
        assert!(c.admit(attack("h1"), t0).is_some());

        // No further events: the window closes with nothing to summarise and
        // the bucket is retired.
        assert!(c.flush(t0 + window).is_empty());
        assert!(c.buckets.is_empty(), "quiet buckets are released");

        assert!(
            c.admit(attack("h1"), t0 + window).is_some(),
            "the next attack after a quiet period alerts at once"
        );
    }

    // ── ⑤ A sustained attack keeps reporting ─────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn a_sustained_attack_keeps_producing_periodic_summaries() {
        let window = Duration::from_mins(1);
        let mut c = Coalescer::new(window);
        let t0 = Instant::now();
        c.admit(attack("h1"), t0);
        c.admit(attack("h1"), t0);

        let first = c.flush(t0 + window);
        assert_eq!(first.len(), 1);

        // Still under attack in the second window.
        c.admit(attack("h1"), t0 + window);
        let second = c.flush(t0 + window * 2);
        assert_eq!(second.len(), 1, "the window reopens rather than latching silent");
    }

    // ── ⑥ Bucket cardinality is bounded ──────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn bucket_count_is_bounded_and_overflow_is_counted() {
        let mut c = Coalescer::new(Duration::from_mins(1));
        let t0 = Instant::now();
        for i in 0..(MAX_COALESCE_BUCKETS + 50) {
            c.admit(attack(&format!("h{i}")), t0);
        }
        assert_eq!(
            c.buckets.len(),
            MAX_COALESCE_BUCKETS,
            "bucket map cannot grow without limit"
        );
        assert_eq!(c.take_overflow(), 50, "overflow is counted, not silently ignored");
        assert_eq!(c.take_overflow(), 0, "the counter resets after a read");
    }

    // ── ⑦ Event wording ──────────────────────────────────────────────────────

    #[test]
    fn cert_event_distinguishes_expiring_from_expired() {
        let when = chrono::Utc::now();
        let soon = cert_expiry_event("h1", "example.com", 9, when);
        assert!(soon.title.contains("expires in 9d"), "{}", soon.title);
        assert!(soon.message.contains("expires in 9 day(s)"));

        let gone = cert_expiry_event("h1", "example.com", -3, when);
        assert!(gone.title.contains("EXPIRED"), "{}", gone.title);
        assert!(gone.message.contains("expired 3 day(s) ago"), "{}", gone.message);
    }

    #[test]
    fn cert_event_scope_is_per_certificate() {
        let when = chrono::Utc::now();
        let a = cert_expiry_event("h1", "a.example.com", 5, when);
        let b = cert_expiry_event("h1", "b.example.com", 5, when);
        assert_ne!(a.dedup_key, b.dedup_key, "two certs on one host alert separately");
    }

    #[test]
    fn backend_event_covers_both_directions() {
        let down = backend_health_event("h1", "10.0.0.1:8080", false);
        assert!(down.title.contains("DOWN"), "{}", down.title);
        assert_eq!(down.kind, NotificationEventKind::BackendDown);

        let up = backend_health_event("h1", "10.0.0.1:8080", true);
        assert!(up.title.contains("recovered"), "{}", up.title);
        assert_eq!(
            up.dedup_key, down.dedup_key,
            "a flap coalesces into one scope rather than two"
        );
    }

    // ── ⑧ The summary is derived from the most recent event ──────────────────

    #[tokio::test(start_paused = true)]
    async fn the_summary_quotes_the_most_recent_event() {
        let window = Duration::from_mins(1);
        let mut c = Coalescer::new(window);
        let t0 = Instant::now();
        c.admit(attack("h1"), t0);
        c.admit(
            NotificationEvent::new(
                NotificationEventKind::AttackDetected,
                Some("h1".to_owned()),
                "h1",
                "attack on h1",
                "LATEST-PAYLOAD",
            ),
            t0,
        );
        let summaries = c.flush(t0 + window);
        let summary = summaries.first().expect("one summary");
        assert!(summary.message.contains("LATEST-PAYLOAD"));
    }
}
