//! Per-stage timeouts for the connection the proxy opens to the upstream.
//!
//! Pingora arms no upstream timer of its own: `HttpPeer::new()` builds
//! `PeerOptions` with `connection_timeout`, `total_connection_timeout`,
//! `read_timeout`, `write_timeout` and `idle_timeout` all `None`
//! (`pingora-core-0.8.1/src/upstreams/peer.rs:471-478`), and `None` is
//! *forever*. Combined with the single-threaded proxy data path, one wedged
//! upstream is enough to stop serving.
//!
//! This module turns [`UpstreamTimeoutConfig`] into the peer options that close
//! that gap — and does nothing at all when the operator has configured nothing,
//! which is the shipped default.

use std::time::Duration;

use pingora_core::upstreams::peer::HttpPeer;
use pingora_http::RequestHeader;

use waf_common::UpstreamTimeoutConfig;

/// Resolved form of [`UpstreamTimeoutConfig`]: milliseconds turned into
/// `Option<Duration>` once at startup, so the request path only ever copies
/// `Copy` fields onto the peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamTimeouts {
    /// One TCP connect attempt (`PeerOptions::connection_timeout`).
    pub connect: Option<Duration>,
    /// Whole connection setup incl. TLS (`PeerOptions::total_connection_timeout`).
    pub total_connect: Option<Duration>,
    /// Inactivity bound on a single upstream read (`PeerOptions::read_timeout`).
    pub read: Option<Duration>,
    /// Inactivity bound on a single upstream write (`PeerOptions::write_timeout`).
    pub write: Option<Duration>,
    /// Idle residency in the upstream connection pool (`PeerOptions::idle_timeout`).
    pub idle: Option<Duration>,
    /// Skip `read` / `write` for requests [`is_streaming_request`] flags.
    pub stream_exempt: bool,
}

impl UpstreamTimeouts {
    /// Resolve the TOML view. A key of `0` means "no timeout" and becomes
    /// `None`, which is exactly the value the peer already carries — so a
    /// fully-zero config produces `Self::default()` and [`Self::is_unlimited`]
    /// is true.
    pub const fn from_config(cfg: &UpstreamTimeoutConfig) -> Self {
        Self {
            connect: millis(cfg.connect_ms),
            total_connect: millis(cfg.total_connect_ms),
            read: millis(cfg.read_ms),
            write: millis(cfg.write_ms),
            idle: millis(cfg.idle_ms),
            stream_exempt: cfg.stream_exempt,
        }
    }

    /// True when no stage is bounded — the historical behaviour, and the state
    /// in which [`Self::apply`] touches nothing.
    ///
    /// `stream_exempt` is deliberately not consulted: it exempts requests from
    /// timeouts that, here, do not exist.
    pub const fn is_unlimited(&self) -> bool {
        self.connect.is_none()
            && self.total_connect.is_none()
            && self.read.is_none()
            && self.write.is_none()
            && self.idle.is_none()
    }

    /// Write the configured stages onto a freshly built peer.
    ///
    /// Returns immediately when nothing is configured, so the default install
    /// pays one boolean test per request and `peer.options` is never written.
    ///
    /// `streaming` comes from [`is_streaming_request`]. When it is set *and*
    /// `stream_exempt` is on, `read` / `write` are left unarmed for this one
    /// request: those two are per-I/O inactivity timers and Pingora applies
    /// them to upgraded and streaming bodies alike
    /// (`pingora-proxy-0.8.1/src/proxy_h1.rs:39-40`), which would cut a
    /// long-idle WebSocket or SSE feed. Connection setup and pool residency
    /// are never exempted — neither is a streaming activity.
    pub const fn apply(&self, peer: &mut HttpPeer, streaming: bool) {
        if self.is_unlimited() {
            return;
        }

        peer.options.connection_timeout = self.connect;
        peer.options.total_connection_timeout = self.total_connect;
        peer.options.idle_timeout = self.idle;

        if streaming && self.stream_exempt {
            peer.options.read_timeout = None;
            peer.options.write_timeout = None;
        } else {
            peer.options.read_timeout = self.read;
            peer.options.write_timeout = self.write;
        }
    }

    /// One-line rendering of the armed stages for the startup log. Only
    /// non-`None` stages appear, so the line says what is actually in force
    /// rather than repeating the defaults.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(6);
        for (name, value) in [
            ("connect", self.connect),
            ("total_connect", self.total_connect),
            ("read", self.read),
            ("write", self.write),
            ("idle", self.idle),
        ] {
            if let Some(d) = value {
                parts.push(format!("{name}={}ms", d.as_millis()));
            }
        }
        if self.stream_exempt && (self.read.is_some() || self.write.is_some()) {
            parts.push("stream_exempt=on (Upgrade / Accept: text/event-stream skip read+write)".to_string());
        }
        parts.join(", ")
    }
}

/// `0` means unlimited, matching `[content_security.lane1] max_body_bytes` and
/// the other opt-in budgets in this codebase.
const fn millis(ms: u64) -> Option<Duration> {
    if ms == 0 { None } else { Some(Duration::from_millis(ms)) }
}

/// Whether a request is expected to produce a long-lived, mostly-idle upstream
/// stream, and so should skip the read/write inactivity timers when
/// `stream_exempt` is on.
///
/// Only the *request* can be consulted: the peer is built in `upstream_peer`,
/// before a single response byte exists, so the `101 Switching Protocols` or
/// `Content-Type: text/event-stream` that would actually prove a stream has not
/// been seen yet. The two request-side signals are:
///
/// * `Upgrade` — the WebSocket / h2c / generic upgrade handshake. Same header
///   Pingora keys its own `is_upgrade_req` on
///   (`pingora-core-0.8.1/src/protocols/http/v1/common.rs:178-180`).
/// * `Accept: text/event-stream` — the SSE content negotiation from
///   `EventSource`, matched as a substring because the header is a list and may
///   carry q-values.
///
/// Both are client-supplied, which is the reason `stream_exempt` ships off:
/// under this predicate an attacker can hand themselves the exemption with one
/// header.
pub fn is_streaming_request(req: &RequestHeader) -> bool {
    if req.headers.contains_key(http::header::UPGRADE) {
        return true;
    }
    req.headers
        .get_all(http::header::ACCEPT)
        .iter()
        .any(|v| contains_ignore_ascii_case(v.as_bytes(), b"text/event-stream"))
}

/// ASCII-case-insensitive substring test. Avoids the lowercase `String` copy of
/// every `Accept` header on the request path.
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> UpstreamTimeoutConfig {
        UpstreamTimeoutConfig::default()
    }

    /// The shipped config must resolve to "no timer anywhere".
    #[test]
    fn default_config_is_unlimited() {
        let t = UpstreamTimeouts::from_config(&cfg());
        assert_eq!(t, UpstreamTimeouts::default());
        assert!(t.is_unlimited());
        assert_eq!(t.summary(), "");
    }

    /// ...and must leave the peer exactly as Pingora built it.
    #[test]
    fn default_config_does_not_touch_peer_options() {
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
        UpstreamTimeouts::from_config(&cfg()).apply(&mut peer, false);
        assert_eq!(peer.options.connection_timeout, None);
        assert_eq!(peer.options.total_connection_timeout, None);
        assert_eq!(peer.options.read_timeout, None);
        assert_eq!(peer.options.write_timeout, None);
        assert_eq!(peer.options.idle_timeout, None);
    }

    #[test]
    fn zero_means_unlimited_per_stage() {
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 0,
            read_ms: 2000,
            ..cfg()
        });
        assert_eq!(t.connect, None);
        assert_eq!(t.read, Some(Duration::from_secs(2)));
        assert!(!t.is_unlimited());
    }

    #[test]
    fn configured_stages_reach_the_peer() {
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 1500,
            total_connect_ms: 3000,
            read_ms: 2000,
            write_ms: 2500,
            idle_ms: 60_000,
            stream_exempt: false,
        });
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
        t.apply(&mut peer, false);
        assert_eq!(peer.options.connection_timeout, Some(Duration::from_millis(1500)));
        assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(3)));
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(2)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_millis(2500)));
        assert_eq!(peer.options.idle_timeout, Some(Duration::from_mins(1)));
    }

    /// A streaming request gets no exemption unless it was asked for.
    #[test]
    fn streaming_request_is_not_exempt_by_default() {
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            read_ms: 2000,
            write_ms: 2000,
            ..cfg()
        });
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
        t.apply(&mut peer, true);
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(2)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(2)));
    }

    /// With the exemption on, only read/write are dropped — setup and pool
    /// bounds stay armed.
    #[test]
    fn exempt_streaming_request_keeps_connect_and_idle() {
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 1500,
            total_connect_ms: 3000,
            read_ms: 2000,
            write_ms: 2000,
            idle_ms: 60_000,
            stream_exempt: true,
        });
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
        t.apply(&mut peer, true);
        assert_eq!(peer.options.read_timeout, None);
        assert_eq!(peer.options.write_timeout, None);
        assert_eq!(peer.options.connection_timeout, Some(Duration::from_millis(1500)));
        assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(3)));
        assert_eq!(peer.options.idle_timeout, Some(Duration::from_mins(1)));

        // A non-streaming request on the same config is still bounded.
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, String::new());
        t.apply(&mut peer, false);
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(2)));
    }

    #[test]
    fn summary_lists_only_armed_stages() {
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 1500,
            read_ms: 30_000,
            ..cfg()
        });
        assert_eq!(t.summary(), "connect=1500ms, read=30000ms");
    }

    #[test]
    fn summary_mentions_the_stream_exemption_only_when_it_can_bite() {
        let with_read = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            read_ms: 30_000,
            stream_exempt: true,
            ..cfg()
        });
        assert!(with_read.summary().contains("stream_exempt=on"));

        // No read/write bound → the exemption exempts nothing; do not claim it.
        let without_read = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 1500,
            stream_exempt: true,
            ..cfg()
        });
        assert_eq!(without_read.summary(), "connect=1500ms");
    }

    fn req(headers: &[(&str, &str)]) -> RequestHeader {
        let mut h = RequestHeader::build("GET", b"/", None).expect("valid request line");
        for (k, v) in headers {
            h.insert_header(k.to_string(), *v).expect("valid header");
        }
        h
    }

    #[test]
    fn upgrade_request_is_streaming() {
        assert!(is_streaming_request(&req(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket")
        ])));
    }

    #[test]
    fn sse_accept_is_streaming_in_any_case_or_position() {
        assert!(is_streaming_request(&req(&[("accept", "text/event-stream")])));
        assert!(is_streaming_request(&req(&[("accept", "TEXT/Event-Stream")])));
        assert!(is_streaming_request(&req(&[(
            "accept",
            "text/html, text/event-stream;q=0.9, */*"
        )])));
    }

    #[test]
    fn ordinary_request_is_not_streaming() {
        assert!(!is_streaming_request(&req(&[])));
        assert!(!is_streaming_request(&req(&[("accept", "application/json")])));
        // `Connection: upgrade` without an `Upgrade` header is not a handshake.
        assert!(!is_streaming_request(&req(&[("connection", "upgrade")])));
    }

    #[test]
    fn substring_search_edges() {
        assert!(contains_ignore_ascii_case(b"abc", b"abc"));
        assert!(!contains_ignore_ascii_case(b"ab", b"abc"));
        assert!(!contains_ignore_ascii_case(b"abc", b""));
    }
}
