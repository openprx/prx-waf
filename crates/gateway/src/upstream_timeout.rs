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

    // ── HTTP/3 (reqwest) ────────────────────────────────────────────────────
    //
    // The H3 forwarder does not go through Pingora at all: it dials the
    // upstream with `reqwest` (`crate::http3`), which arms its own timers and
    // exposes a different, smaller set of stages. The mapping below is
    // deliberately conservative — a stage reqwest cannot express is reported by
    // [`Self::reqwest_unenforced`] rather than approximated with something that
    // would cut at a different moment than the operator asked for.
    //
    // | `[proxy.upstream_timeouts]` | reqwest                | fidelity |
    // |-----------------------------|------------------------|----------|
    // | `total_connect_ms`          | `connect_timeout`      | exact    |
    // | `connect_ms`                | `connect_timeout` only when `total_connect_ms` is unset — see [`Self::reqwest_connect_timeout`] |
    // | `read_ms`                   | `read_timeout`         | exact    |
    // | `write_ms`                  | —                      | **not enforced** |
    // | `idle_ms`                   | `pool_idle_timeout`    | exact, but the *default* differs — see [`Self::apply_to_reqwest`] |
    // | `stream_exempt`             | a second client        | read only (there is no write timer to exempt) |

    /// The single connection-setup deadline reqwest offers, chosen from the two
    /// setup stages Pingora distinguishes.
    ///
    /// `ClientBuilder::connect_timeout` installs one `tower` `TimeoutLayer`
    /// around the *whole* connector — DNS, TCP and, for an `https` upstream,
    /// the TLS handshake (`reqwest-0.13.4/src/connect.rs:141-155`; the TLS
    /// connector sits inside the wrapped service). That is precisely
    /// `total_connect_ms`, so when it is set it is used verbatim.
    ///
    /// `connect_ms` bounds *one TCP connect attempt* and has no reqwest
    /// equivalent, so it is only used as a fallback, when the operator bounded
    /// the TCP attempt but left the total unbounded. In that fallback it is
    /// **stricter** than on the Pingora path: it then also has to cover DNS and
    /// TLS. Erring strict is the right direction for a `DoS` budget, and it is
    /// the only way an operator who configured `connect_ms` alone gets any
    /// setup bound on H3 at all.
    ///
    /// When both are set, `total_connect_ms` wins. Taking the minimum of the
    /// two was rejected: `connect_ms = 1s, total_connect_ms = 5s` authorises
    /// five seconds of setup, and cutting that install at one second would
    /// break a slow-TLS upstream that the operator explicitly allowed for.
    pub const fn reqwest_connect_timeout(&self) -> Option<Duration> {
        match self.total_connect {
            Some(d) => Some(d),
            None => self.connect,
        }
    }

    /// The configured stage that the H3 path cannot enforce, if any.
    ///
    /// reqwest 0.13 has no write timeout — neither on `ClientBuilder` nor on
    /// `RequestBuilder` (`reqwest-0.13.4/src/async_impl/request.rs:294` offers
    /// only a total per-request deadline) — so `write_ms` is silently absent
    /// from the H3 data path. The caller logs this once at startup rather than
    /// letting an operator believe a bound is in force that is not.
    pub const fn reqwest_unenforced(&self) -> Option<&'static str> {
        if self.write.is_some() { Some("write_ms") } else { None }
    }

    /// Write the configured stages onto a `reqwest` client builder.
    ///
    /// Like [`Self::apply`], this returns the builder untouched when nothing is
    /// configured, so the shipped default is byte-for-byte the client the H3
    /// forwarder has always built.
    ///
    /// **`idle_ms = 0` deliberately does not disable the pool timer.** Every
    /// other reqwest stage defaults to `None` = no timeout
    /// (`reqwest-0.13.4/src/async_impl/client.rs:1444/1456/1469`), so leaving
    /// them unset reproduces the old behaviour exactly. `pool_idle_timeout` is
    /// the exception: its default is **90 seconds**
    /// (`.../client.rs:1492-1499`), not unlimited. Calling
    /// `.pool_idle_timeout(None)` to make `0` mean "unlimited" here would
    /// therefore *change* the shipped behaviour in the name of preserving it.
    /// `0` is left as "reqwest's own default", and only a non-zero `idle_ms`
    /// moves it.
    ///
    /// `exempt` is [`is_streaming_request`] for the request about to be sent;
    /// combined with `stream_exempt` it drops `read_timeout`, mirroring
    /// [`Self::apply`]. Only the read timer can be exempted because there is no
    /// write timer to drop. reqwest has no per-request read timeout, so the
    /// caller builds one client per exemption state
    /// ([`crate::http3::UpstreamClients`]).
    pub fn apply_to_reqwest(&self, mut builder: reqwest::ClientBuilder, exempt: bool) -> reqwest::ClientBuilder {
        if self.is_unlimited() {
            return builder;
        }

        if let Some(d) = self.reqwest_connect_timeout() {
            builder = builder.connect_timeout(d);
        }
        if let Some(d) = self.read
            && !(exempt && self.stream_exempt)
        {
            builder = builder.read_timeout(d);
        }
        if let Some(d) = self.idle {
            builder = builder.pool_idle_timeout(d);
        }

        builder
    }

    /// One-line rendering of what the H3 forwarder actually armed, for the
    /// startup log. Deliberately separate from [`Self::summary`]: the stages
    /// differ, and reporting the Pingora set on the H3 line would overstate it.
    pub fn reqwest_summary(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(4);
        if let Some(d) = self.reqwest_connect_timeout() {
            parts.push(format!("connect_timeout={}ms", d.as_millis()));
        }
        if let Some(d) = self.read {
            parts.push(format!("read_timeout={}ms", d.as_millis()));
            if self.stream_exempt {
                parts.push("stream_exempt=on (Upgrade / Accept: text/event-stream skip read_timeout)".to_string());
            }
        }
        if let Some(d) = self.idle {
            parts.push(format!("pool_idle_timeout={}ms", d.as_millis()));
        }
        parts.join(", ")
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
    headers_are_streaming(&req.headers)
}

/// [`is_streaming_request`] over a bare [`http::HeaderMap`].
///
/// The HTTP/3 plane never builds a Pingora `RequestHeader` — it holds
/// `http::request::Parts` straight from `h3` — so the predicate has to be
/// reachable without one. Both planes must answer identically, hence one
/// implementation rather than two.
pub fn headers_are_streaming(headers: &http::HeaderMap) -> bool {
    if headers.contains_key(http::header::UPGRADE) {
        return true;
    }
    headers
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

    /// The workspace builds `reqwest` with `rustls-no-provider`, so
    /// `ClientBuilder::build` panics unless a process-level `CryptoProvider`
    /// was installed first. The daemon does this at startup
    /// (`crates/prx-waf/src/main.rs:344`); tests must do the same.
    /// `install_default` errors only when one is already set — idempotent.
    fn install_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
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

    // ── HTTP/3 (reqwest) mapping ────────────────────────────────────────────

    /// The shipped config must hand reqwest a builder it never touched, so the
    /// H3 client stays exactly the one the forwarder has always built.
    #[test]
    fn default_config_does_not_touch_the_reqwest_builder() {
        install_crypto_provider();
        let t = UpstreamTimeouts::from_config(&cfg());
        let untouched = format!("{:?}", reqwest::Client::builder());
        let applied = format!("{:?}", t.apply_to_reqwest(reqwest::Client::builder(), false));
        assert_eq!(applied, untouched);
        assert_eq!(t.reqwest_summary(), "");
        assert_eq!(t.reqwest_unenforced(), None);
    }

    /// `total_connect_ms` is the exact reqwest analogue and wins outright;
    /// `connect_ms` is only the fallback when no total was configured.
    #[test]
    fn reqwest_connect_timeout_prefers_the_total() {
        let both = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 1000,
            total_connect_ms: 5000,
            ..cfg()
        });
        assert_eq!(both.reqwest_connect_timeout(), Some(Duration::from_secs(5)));

        let tcp_only = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 1000,
            ..cfg()
        });
        assert_eq!(tcp_only.reqwest_connect_timeout(), Some(Duration::from_secs(1)));

        let total_only = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            total_connect_ms: 5000,
            ..cfg()
        });
        assert_eq!(total_only.reqwest_connect_timeout(), Some(Duration::from_secs(5)));

        assert_eq!(UpstreamTimeouts::from_config(&cfg()).reqwest_connect_timeout(), None);
    }

    /// The connect deadline must actually land on the builder — `connect_timeout`
    /// is one of the few fields reqwest renders in its `Debug` output.
    #[test]
    fn reqwest_connect_timeout_reaches_the_builder() {
        install_crypto_provider();
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            total_connect_ms: 2500,
            ..cfg()
        });
        let rendered = format!("{:?}", t.apply_to_reqwest(reqwest::Client::builder(), false));
        assert!(rendered.contains("connect_timeout"), "{rendered}");
        assert!(rendered.contains("2.5s"), "{rendered}");
    }

    /// `write_ms` has no reqwest equivalent; it must be reported, never faked.
    #[test]
    fn write_ms_is_reported_as_unenforced_on_the_h3_path() {
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            write_ms: 2000,
            ..cfg()
        });
        assert_eq!(t.reqwest_unenforced(), Some("write_ms"));
        // …and it must not leak into the H3 summary as if it were armed.
        assert_eq!(t.reqwest_summary(), "");
    }

    #[test]
    fn reqwest_summary_lists_only_what_h3_arms() {
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 1000,
            total_connect_ms: 3000,
            read_ms: 2000,
            write_ms: 4000,
            idle_ms: 60_000,
            stream_exempt: false,
        });
        assert_eq!(
            t.reqwest_summary(),
            "connect_timeout=3000ms, read_timeout=2000ms, pool_idle_timeout=60000ms"
        );

        let exempt = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            read_ms: 2000,
            stream_exempt: true,
            ..cfg()
        });
        assert!(
            exempt.reqwest_summary().contains("stream_exempt=on"),
            "{}",
            exempt.reqwest_summary()
        );

        // The exemption exempts nothing when no read bound exists; do not claim it.
        let no_read = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            connect_ms: 1000,
            stream_exempt: true,
            ..cfg()
        });
        assert_eq!(no_read.reqwest_summary(), "connect_timeout=1000ms");
    }

    /// Accept a TCP connection and then never write a byte: the shape of a
    /// wedged upstream. Returns the bound address; the task lives as long as
    /// the returned guard.
    async fn stalling_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalling upstream");
        let addr = listener.local_addr().expect("local_addr");
        let handle = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                // Hold the socket open, read nothing, answer nothing. Parking
                // it in its own task keeps it alive without ever polling it.
                tokio::spawn(async move {
                    let _held = sock;
                    std::future::pending::<()>().await;
                });
            }
        });
        (addr, handle)
    }

    /// `read_ms` must sever a stalled upstream response…
    #[tokio::test]
    async fn read_ms_cuts_a_stalled_upstream() {
        install_crypto_provider();
        let (addr, guard) = stalling_upstream().await;
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig { read_ms: 250, ..cfg() });
        let client = t
            .apply_to_reqwest(reqwest::Client::builder(), false)
            .build()
            .expect("build client");

        let err = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect_err("a stalled upstream must not succeed");
        assert!(err.is_timeout(), "expected a timeout error, got: {err}");
        guard.abort();
    }

    /// …and with nothing configured the very same upstream must still be
    /// waited on, which is the whole point of the zero default.
    #[tokio::test]
    async fn default_config_waits_on_the_same_stalled_upstream() {
        install_crypto_provider();
        let (addr, guard) = stalling_upstream().await;
        let client = UpstreamTimeouts::from_config(&cfg())
            .apply_to_reqwest(reqwest::Client::builder(), false)
            .build()
            .expect("build client");

        let outcome = tokio::time::timeout(
            Duration::from_millis(1500),
            client.get(format!("http://{addr}/")).send(),
        )
        .await;
        assert!(
            outcome.is_err(),
            "unconfigured client must still be waiting, but it returned: {:?}",
            outcome.map(|r| r.map(|resp| resp.status()))
        );
        guard.abort();
    }

    /// With `stream_exempt` on, a streaming request keeps the unbounded
    /// behaviour while an ordinary one is still cut.
    #[tokio::test]
    async fn stream_exempt_drops_the_read_timeout_for_exempt_requests() {
        install_crypto_provider();
        let (addr, guard) = stalling_upstream().await;
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig {
            read_ms: 250,
            stream_exempt: true,
            ..cfg()
        });

        let bounded = t
            .apply_to_reqwest(reqwest::Client::builder(), false)
            .build()
            .expect("build bounded client");
        let err = bounded
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect_err("non-exempt request must be cut");
        assert!(err.is_timeout(), "expected a timeout error, got: {err}");

        let exempt = t
            .apply_to_reqwest(reqwest::Client::builder(), true)
            .build()
            .expect("build exempt client");
        let outcome = tokio::time::timeout(Duration::from_secs(1), exempt.get(format!("http://{addr}/")).send()).await;
        assert!(outcome.is_err(), "exempt request must not be cut by read_ms");
        guard.abort();
    }

    /// The exemption only exists when it was asked for.
    #[tokio::test]
    async fn streaming_request_is_still_bounded_without_the_exemption() {
        install_crypto_provider();
        let (addr, guard) = stalling_upstream().await;
        let t = UpstreamTimeouts::from_config(&UpstreamTimeoutConfig { read_ms: 250, ..cfg() });
        let client = t
            .apply_to_reqwest(reqwest::Client::builder(), true)
            .build()
            .expect("build client");
        let err = client
            .get(format!("http://{addr}/"))
            .send()
            .await
            .expect_err("stream_exempt is off, so the bound still applies");
        assert!(err.is_timeout(), "expected a timeout error, got: {err}");
        guard.abort();
    }

    #[test]
    fn substring_search_edges() {
        assert!(contains_ignore_ascii_case(b"abc", b"abc"));
        assert!(!contains_ignore_ascii_case(b"ab", b"abc"));
        assert!(!contains_ignore_ascii_case(b"abc", b""));
    }
}
