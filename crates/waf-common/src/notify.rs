//! Cross-crate notification event bus.
//!
//! # Why the bus lives here
//!
//! The notification *dispatcher* (`waf_api::notifications::dispatch_notification`)
//! needs the database, the encrypted channel configs and the HTTP/SMTP clients,
//! so it necessarily lives in `waf-api`. But `waf-api` already depends on
//! `gateway`, `waf-engine` and `waf-storage` — the crates where the events that
//! *should* trigger a notification actually happen. Those crates therefore
//! cannot call the dispatcher directly without inverting (and cycling) the
//! dependency graph.
//!
//! `waf-common` is the one crate every layer can see, so the **event type** and
//! the **transport** live here: producers depend only on `waf-common`, and the
//! dispatcher subscribes from above. No crate gains a new dependency edge.
//!
//! # Transport shape
//!
//! One bounded MPSC channel drained by a single background task — the same
//! pattern as `waf_engine::audit_log` and `waf_engine::semantic_sink`.
//! Producers only ever call [`NotificationBus::publish`], which is a synchronous
//! `try_send`: it never awaits, never spawns, never allocates beyond the event
//! itself, and never touches the network or the database. When the queue is full
//! the event is **dropped and counted**, so a wedged webhook endpoint or a slow
//! SMTP server degrades to "some alerts are missed" instead of stalling request
//! handling. The drop counter is drained periodically by the consumer so the
//! suppression is visible in the process log rather than silent.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

/// Default bounded queue depth. Deep enough to absorb a burst that arrives
/// while the consumer is dispatching, shallow enough that a wedged consumer
/// cannot accumulate meaningful memory.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// Upper bound on a single notification title, in characters.
const MAX_TITLE_CHARS: usize = 200;

/// Upper bound on a single notification message, in characters.
const MAX_MESSAGE_CHARS: usize = 2000;

/// The event taxonomy the admin UI offers when configuring a channel.
///
/// The string forms are the values stored in `notification_configs.event_type`
/// and must stay in sync with `migrations/0004_auth_and_stats.sql` and
/// `web/admin-ui/src/views/Notifications.vue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationEventKind {
    /// The WAF blocked a request.
    AttackDetected,
    /// A TLS certificate is approaching (or past) its expiry date.
    CertExpiry,
    /// Request volume crossed the configured threshold.
    HighTraffic,
    /// An upstream backend transitioned to unhealthy.
    BackendDown,
}

impl NotificationEventKind {
    /// The `notification_configs.event_type` value for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AttackDetected => "attack_detected",
            Self::CertExpiry => "cert_expiry",
            Self::HighTraffic => "high_traffic",
            Self::BackendDown => "backend_down",
        }
    }
}

impl std::fmt::Display for NotificationEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing that happened and may be worth telling an operator about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationEvent {
    pub kind: NotificationEventKind,
    /// Host this event belongs to, when it is host-scoped. Matched against
    /// `notification_configs.host_code` by the dispatcher.
    pub host_code: Option<String>,
    /// Coalescing identity **within** `kind`. Events sharing a key inside one
    /// window collapse into a single notification plus a suppressed count.
    ///
    /// Choose the coarsest key that still tells the operator something new:
    /// per-host for attacks (not per-rule — a scanner trips dozens of rules),
    /// per-backend for health, per-certificate for expiry.
    pub dedup_key: String,
    pub title: String,
    pub message: String,
}

impl NotificationEvent {
    /// Build an event with `title`/`message` sanitised and length-capped.
    ///
    /// Both fields can carry attacker-influenced text (a request path, a rule
    /// detail). The title becomes an **email `Subject:` header**, so control
    /// characters must never survive — a bare CR/LF there is header injection.
    /// Sanitising both also keeps a hostile payload from wrecking the layout of
    /// a Telegram or webhook message, and the length cap keeps one oversized
    /// request body from turning into a 2 MB alert.
    #[must_use]
    pub fn new(
        kind: NotificationEventKind,
        host_code: Option<String>,
        dedup_key: impl Into<String>,
        title: &str,
        message: &str,
    ) -> Self {
        Self {
            kind,
            host_code,
            dedup_key: dedup_key.into(),
            title: sanitize(title, MAX_TITLE_CHARS, false),
            message: sanitize(message, MAX_MESSAGE_CHARS, true),
        }
    }
}

/// Strip control characters and cap the length of a notification field.
///
/// `allow_newlines` keeps `\n` (message bodies are multi-line) while still
/// removing `\r` and every other control character; titles allow neither.
fn sanitize(value: &str, max_chars: usize, allow_newlines: bool) -> String {
    let mut out = String::with_capacity(value.len().min(max_chars));
    for ch in value.chars() {
        if out.chars().count() >= max_chars {
            out.push('…');
            break;
        }
        if ch == '\n' && allow_newlines {
            out.push('\n');
        } else if ch.is_control() {
            // Collapse CR, LF-in-title, tabs and everything else non-printing.
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Producer handle: a bounded sender plus publish/drop counters.
///
/// Cheap to clone behind an `Arc` and safe to call from any thread or task.
#[derive(Debug)]
pub struct NotificationBus {
    tx: mpsc::Sender<NotificationEvent>,
    published: AtomicU64,
    dropped: AtomicU64,
}

impl NotificationBus {
    /// Create a bus and its receiver.
    ///
    /// The receiver is handed out at construction (rather than stashed behind a
    /// mutex and taken later) so there is exactly one consumer by construction
    /// and no interior mutability is needed.
    #[must_use]
    pub fn new(capacity: usize) -> (Arc<Self>, mpsc::Receiver<NotificationEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Arc::new(Self {
                tx,
                published: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
            }),
            rx,
        )
    }

    /// Enqueue an event. Synchronous, non-blocking, infallible from the
    /// caller's point of view: a full queue (or a consumer that has exited)
    /// increments the drop counter instead of propagating an error.
    pub fn publish(&self, event: NotificationEvent) {
        if self.tx.try_send(event).is_ok() {
            self.published.fetch_add(1, Ordering::Relaxed);
        } else {
            crate::metrics::record_budget_event(crate::metrics::BudgetEvent::NotificationDrop);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Total events accepted onto the queue.
    #[must_use]
    pub fn published(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }

    /// Events discarded because the queue was full or closed.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Read **and reset** the drop counter, for periodic logging by the
    /// consumer.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(key: &str) -> NotificationEvent {
        NotificationEvent::new(
            NotificationEventKind::AttackDetected,
            Some("h1".to_owned()),
            key,
            "t",
            "m",
        )
    }

    #[test]
    fn publish_counts_accepted_events() {
        let (bus, _rx) = NotificationBus::new(4);
        bus.publish(ev("a"));
        bus.publish(ev("b"));
        assert_eq!(bus.published(), 2);
        assert_eq!(bus.dropped(), 0);
    }

    #[test]
    fn full_queue_drops_and_counts_instead_of_blocking() {
        // Capacity 2 with nothing draining: the 3rd publish must not block.
        let (bus, _rx) = NotificationBus::new(2);
        bus.publish(ev("a"));
        bus.publish(ev("b"));
        bus.publish(ev("c"));
        bus.publish(ev("d"));
        assert_eq!(bus.published(), 2, "only the bounded capacity is accepted");
        assert_eq!(bus.dropped(), 2, "the overflow is dropped and counted");
    }

    #[test]
    fn closed_consumer_drops_instead_of_erroring() {
        let (bus, rx) = NotificationBus::new(4);
        drop(rx);
        bus.publish(ev("a"));
        assert_eq!(bus.dropped(), 1);
        assert_eq!(bus.published(), 0);
    }

    #[test]
    fn take_dropped_resets_the_counter() {
        let (bus, rx) = NotificationBus::new(1);
        drop(rx);
        bus.publish(ev("a"));
        bus.publish(ev("b"));
        assert_eq!(bus.take_dropped(), 2);
        assert_eq!(bus.take_dropped(), 0, "counter resets after a read");
    }

    #[test]
    fn title_cannot_carry_a_crlf_email_header_injection() {
        // The title becomes an SMTP `Subject:` header — CR/LF must not survive.
        let e = NotificationEvent::new(
            NotificationEventKind::AttackDetected,
            None,
            "k",
            "Blocked\r\nBcc: attacker@evil.example",
            "body",
        );
        assert!(!e.title.contains('\r'), "CR survived in title: {:?}", e.title);
        assert!(!e.title.contains('\n'), "LF survived in title: {:?}", e.title);
        assert!(e.title.contains("Bcc: attacker@evil.example"), "text is kept, folded");
    }

    #[test]
    fn message_keeps_newlines_but_drops_other_control_chars() {
        let e = NotificationEvent::new(NotificationEventKind::CertExpiry, None, "k", "t", "a\nb\r\tc\u{0}d");
        assert_eq!(e.message, "a\nb  c d");
    }

    #[test]
    fn oversized_fields_are_capped() {
        let long = "A".repeat(10_000);
        let e = NotificationEvent::new(NotificationEventKind::AttackDetected, None, "k", &long, &long);
        assert_eq!(e.title.chars().count(), MAX_TITLE_CHARS + 1, "cap plus the ellipsis");
        assert_eq!(e.message.chars().count(), MAX_MESSAGE_CHARS + 1);
        assert!(e.title.ends_with('…'));
    }

    #[test]
    fn event_kind_strings_match_the_stored_schema() {
        assert_eq!(NotificationEventKind::AttackDetected.as_str(), "attack_detected");
        assert_eq!(NotificationEventKind::CertExpiry.as_str(), "cert_expiry");
        assert_eq!(NotificationEventKind::HighTraffic.as_str(), "high_traffic");
        assert_eq!(NotificationEventKind::BackendDown.as_str(), "backend_down");
    }
}
