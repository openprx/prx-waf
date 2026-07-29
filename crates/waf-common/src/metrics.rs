//! Prometheus metrics: storage, cardinality control and exposition.
//!
//! # Why this is not just `Family<Labels, Counter>`
//!
//! A WAF is the worst possible place to be careless with metric labels. The
//! obvious labels — client IP, rule id, path, user agent — are all unbounded or
//! effectively unbounded, and a label whose value set is chosen by the attacker
//! is a way to make the *monitoring system* the outage. So the label rules are
//! enforced structurally here rather than by review:
//!
//! * every label except `host` is a **compile-time enumeration**. There is no
//!   API in this module that accepts a caller-supplied label string;
//! * `host` is the single dynamic label, and it is bounded by
//!   [`MetricsConfig::max_host_labels`]. The (bounded+1)-th distinct host and
//!   every one after it is folded into a single `__other__` series, so the
//!   series count is a constant of the configuration and not a function of
//!   traffic.
//!
//! # Why the storage is hand-rolled atomics
//!
//! Recording happens on the proxy data path, which is CPU-bound and now
//! multi-threaded (`[proxy] worker_threads`). `prometheus_client`'s `Family`
//! takes a `parking_lot::RwLock` read guard on every increment and needs an
//! owned label set to look up with — one shared cache line and one allocation
//! per increment, multiplied by every worker thread. Instead, every counter
//! here lives in a flat `[AtomicU64]` indexed by the label enumeration, so an
//! increment is one relaxed `fetch_add` on a slot no other label combination
//! shares. The `host` label is resolved to an integer slot once per request
//! through a lock-free open-addressed table ([`HostSlots`]).
//!
//! `prometheus_client` is still the exposition layer: [`MetricsState`]
//! implements its [`Collector`] trait, so the text format, escaping and
//! `Registry` behaviour come from the library rather than from hand-rolled
//! string formatting.
//!
//! # Cost when disabled
//!
//! [`init`] is the only thing that populates the global. Until it does — and
//! forever, if `[metrics] enabled = false` — every `record_*` entry point is one
//! acquire load of a `OnceLock` and a predictable branch, and no timing clock is
//! read.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, NoLabelSet};
use prometheus_client::metrics::MetricType;
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};

use crate::types::Phase;

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// `[metrics]` — the Prometheus scrape endpoint.
///
/// **On by default, bound to loopback.** Off-by-default would mean the
/// overwhelming majority of deployments run blind, which is the problem this
/// section exists to solve; binding to `0.0.0.0` by default would publish
/// per-host request volumes and block rates to anyone who can route to the box.
/// `127.0.0.1:9127` is the combination that is useful out of the box and
/// exposes nothing — an operator who wants a remote scraper has to say so, and
/// gets a startup warning when they do.
///
/// The port is deliberately not 9090: that is Prometheus's own listen port, and
/// a node-local Prometheus is the intended scraper, so 9090 would collide on
/// exactly the deployment the default is for. 9091 is pushgateway and is out
/// for the same reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Serve `/metrics` and record into it. When `false` nothing is recorded at
    /// all — the record sites become a `OnceLock` load and a branch — and no
    /// listener is bound.
    pub enabled: bool,
    /// Address the metrics listener binds. Loopback by default.
    pub listen_addr: String,
    /// Upper bound on distinct values of the `host` label. Hosts beyond this
    /// are folded into `__other__`.
    ///
    /// This is the only number in the file that decides how many time series
    /// this process can produce, so it is worth setting deliberately: total
    /// series is roughly `(max_host_labels + 1) x 26` plus a fixed ~200. The
    /// default of 128 fits every deployment that fits in one node's routing
    /// table with room to spare.
    pub max_host_labels: usize,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_addr: "127.0.0.1:9127".to_string(),
            max_host_labels: 128,
        }
    }
}

impl MetricsConfig {
    /// Effective host-slot bound, clamped into a range that can be allocated
    /// and that leaves the `__other__` fold reachable.
    ///
    /// `0` is read as "fold every host into `__other__`", which is a legitimate
    /// posture for an operator who wants aggregate RED and no per-site
    /// breakdown at all.
    #[must_use]
    pub const fn effective_max_hosts(&self) -> usize {
        if self.max_host_labels > MAX_HOST_LABELS_CEILING {
            MAX_HOST_LABELS_CEILING
        } else {
            self.max_host_labels
        }
    }
}

/// Hard ceiling on `max_host_labels`, whatever the config says.
///
/// At the ceiling this process can emit roughly 110 000 series, which is
/// already more than a single Prometheus instance wants from one target. The
/// clamp exists so a typo (`max_host_labels = 1000000`) fails as a capped
/// setting rather than as an allocation.
pub const MAX_HOST_LABELS_CEILING: usize = 4096;

// ─────────────────────────────────────────────────────────────────────────────
// Label enumerations — every one of these is closed at compile time
// ─────────────────────────────────────────────────────────────────────────────

/// What the WAF did with a request. Mirrors [`crate::types::WafAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAction {
    /// Forwarded to the upstream (or served from cache).
    Allow,
    /// Answered by the WAF with a block status.
    Block,
    /// Matched, recorded, and forwarded anyway.
    LogOnly,
    /// Answered with a redirect.
    Redirect,
}

impl RequestAction {
    const ALL: [Self; 4] = [Self::Allow, Self::Block, Self::LogOnly, Self::Redirect];

    const fn index(self) -> usize {
        self as usize
    }

    /// The exported `action` label value.
    ///
    /// **Public because the log uses it too.** The refusal paths in
    /// `gateway::proxy` tag their `warn!` with `action = …` so that the word an
    /// operator reads off a dashboard is the word they can grep for, and reading
    /// it from here rather than writing `"block"` a second time is what keeps
    /// the two from drifting: renaming a label renames the log field with it,
    /// and there is no spelling of this word that only one surface knows about.
    /// `docs/logs-and-metrics.md` §1 is the audit that made this necessary.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::LogOnly => "log_only",
            Self::Redirect => "redirect",
        }
    }

    /// The action a [`crate::types::WafAction`] is counted and written down as.
    ///
    /// The evidence tables — `attack_logs.action`, `security_events.action` —
    /// store this same word, and they used to derive it from their own `match`
    /// over `WafAction`, one copy per sink. Three copies of a four-arm match is
    /// three chances for one surface to be renamed and the others not; routing
    /// them all through here makes the metric label, the log field and the
    /// database column one string with one definition.
    #[must_use]
    pub const fn of(action: &crate::types::WafAction) -> Self {
        match action {
            crate::types::WafAction::Allow => Self::Allow,
            crate::types::WafAction::Block { .. } => Self::Block,
            crate::types::WafAction::LogOnly => Self::LogOnly,
            crate::types::WafAction::Redirect { .. } => Self::Redirect,
        }
    }
}

/// The subset of [`RequestAction`] a *detection* can produce. A detection that
/// allowed the request is not a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictAction {
    Block,
    LogOnly,
    Redirect,
}

impl VerdictAction {
    const ALL: [Self; 3] = [Self::Block, Self::LogOnly, Self::Redirect];

    const fn index(self) -> usize {
        self as usize
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::LogOnly => "log_only",
            Self::Redirect => "redirect",
        }
    }
}

/// Response status bucketed to its class.
///
/// The full status code is deliberately not a label: it is bounded, but 60-odd
/// codes x host multiplies the series count for a question ("is this host
/// erroring") that the class already answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusClass {
    Informational,
    Success,
    Redirection,
    ClientError,
    ServerError,
}

impl StatusClass {
    const ALL: [Self; 5] = [
        Self::Informational,
        Self::Success,
        Self::Redirection,
        Self::ClientError,
        Self::ServerError,
    ];

    /// Classify a status code. Anything outside 100–599 is reported as a server
    /// error, because a proxy that emitted it has a bug worth seeing.
    #[must_use]
    pub const fn of(status: u16) -> Self {
        match status {
            100..=199 => Self::Informational,
            200..=299 => Self::Success,
            300..=399 => Self::Redirection,
            400..=499 => Self::ClientError,
            _ => Self::ServerError,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Informational => "1xx",
            Self::Success => "2xx",
            Self::Redirection => "3xx",
            Self::ClientError => "4xx",
            Self::ServerError => "5xx",
        }
    }
}

/// The three detection chains whose cost is measured separately.
///
/// They are measured separately because they do not share work: the per-lane
/// deltas in `tests/perf/RESULTS.md` sum to the aggregate, and the ordering
/// between them inverts with body size. An operator deciding whether to turn a
/// lane off needs the individual number, not the total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// The four frozen native detectors: `SQLi` / XSS / RCE / traversal, plus
    /// the Lane 2 semantic scoring that runs in the same subsystem call.
    Lane1,
    /// OWASP CRS rule evaluation.
    Crs,
    /// Lane 2 semantic content security.
    Lane2,
}

impl Lane {
    const ALL: [Self; 3] = [Self::Lane1, Self::Crs, Self::Lane2];

    const fn index(self) -> usize {
        self as usize
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Lane1 => "lane1",
            Self::Crs => "crs",
            Self::Lane2 => "lane2",
        }
    }
}

/// Every bounded resource in the request path whose exceed behaviour costs
/// coverage, availability or observability.
///
/// One variant per row of `docs/dos-budget.md`. The point of the enum is that
/// the mapping is *total*: a limit that can be exceeded but has no variant here
/// is a limit an operator cannot see, and the doc's table is generated against
/// this list.
///
/// The label pair is `(subsystem, limit)`, which keeps the whole set in one
/// metric family instead of forty separate metric names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetEvent {
    // ── §1.1 the limits that reject ──────────────────────────────────────────
    /// More than 64 values of one header name — 431, request refused.
    HeaderValueCountExceeded,
    /// A folded header name over 32 KiB — 431, request refused.
    HeaderFoldBytesExceeded,
    /// More than one `Host` line — 400, request refused as unroutable.
    DuplicateHost,
    /// Request body over the inspection ceiling with the default
    /// `PRXWAF_BODY_INSPECT_OVERFLOW=reject` — 413.
    RequestBodyRejected,
    /// Request body over the inspection ceiling under
    /// `PRXWAF_BODY_INSPECT_OVERFLOW=log` — the remainder is forwarded
    /// **uninspected**. `docs/dos-budget.md` §1.1 called out that this had no
    /// counter and therefore could not be alerted on.
    RequestBodyForwardedUninspected,
    /// HTTP/3 request body over the 10 MiB buffer — 413.
    Http3BodyRejected,

    // ── §1.2 inspection windows ──────────────────────────────────────────────
    /// Response body past `MAX_INSPECTED_RESPONSE_BYTES`: the remainder is
    /// delivered uninspected and the rules see a truncated view.
    ResponseBodyTruncated,

    // ── §1.3 multipart envelope ──────────────────────────────────────────────
    /// Boundary longer than RFC 2046 allows — the envelope is not parsed at all.
    MultipartBoundaryTooLong,
    /// More than 256 parts — the remainder falls back to whole-body inspection.
    MultipartPartsExceeded,
    /// A part's header block over 8 KiB — that part is dropped whole, name,
    /// filename and body included.
    MultipartPartHeaderBytesExceeded,
    /// A part with more than 32 header lines — that part is dropped whole.
    MultipartPartHeaderLinesExceeded,

    // ── §1.3 CRS body processors ─────────────────────────────────────────────
    /// Body over 64 KiB: the JSON processor is skipped, so no `ARGS_POST`.
    CrsJsonBodyTooLarge,
    /// Body over 64 KiB: the XML processor is skipped, so no `XML:` targets.
    CrsXmlBodyTooLarge,
    /// JSON nested past 64 bracket levels — parse declined outright.
    CrsJsonInputTooDeep,
    /// A JSON subtree past 32 levels is not descended.
    CrsJsonDepthExceeded,
    /// The JSON walk stopped at 512 members or 16 384 node visits.
    CrsJsonArgsExceeded,
    /// The XML reader stopped at 20 000 events.
    CrsXmlEventsExceeded,
    /// XML text accumulation truncated at 64 KiB.
    CrsXmlTextTruncated,
    /// Attributes past the 512th on one element are dropped.
    CrsXmlAttrsExceeded,
    /// urlencoded parameters past the 256th are folded into one anonymous
    /// member: values still reach `ARGS`, names no longer reach `ARGS_NAMES`.
    FormArgsFolded,

    // ── §2.1 Lane 2 work budget ──────────────────────────────────────────────
    /// `max_fields_per_phase`.
    Lane2FieldsPerPhase,
    /// `max_field_input_bytes`.
    Lane2FieldInputBytes,
    /// `max_ast_attempts_per_request`.
    Lane2AstAttempts,
    /// `max_ast_input_bytes_total`.
    Lane2AstInputBytes,
    /// `max_html_parse_attempts_per_request`.
    Lane2HtmlParseAttempts,
    /// `max_html_parse_input_bytes_total`.
    Lane2HtmlParseInputBytes,
    /// `max_views_per_field` refused a unit of view-producing work: a decoded
    /// view already in hand, a decode round already known to differ from the one
    /// before it, or a pending transform text the cap will not let the
    /// preprocessor scan. **Unit: refusals**, not requests — one field can raise
    /// it several times.
    ///
    /// Not raised when the cap merely equals what the field wanted: a field that
    /// produces exactly `max_views_per_field` views and has nothing further to
    /// offer lost nothing.
    Lane2ViewsPerField,
    /// `max_tokens_per_view` cut a view's normalised text short while tokens
    /// remained. **Unit: views truncated** — a field with four views can raise
    /// it four times.
    ///
    /// Not raised when the whole-view byte ceiling (`NormaliseLimits`, §1.3)
    /// stopped the walk first: that is a different limit with its own exceed
    /// behaviour, and attributing it here would blame the token cap for a cut it
    /// did not make.
    Lane2TokensPerView,
    /// `max_preprocess_output_bytes_total`.
    Lane2PreprocessOutputBytes,
    /// A Lane 2 detector declined a view because it exceeded that detector's
    /// own input cap: the SQL AST's 256 bytes / 12 nesting levels, the shell
    /// AST's 2 KiB / 20 levels, or the XSS DOM parser's 16 KiB.
    ///
    /// Deliberately **not** a `degraded` signal. These caps are per-view and the
    /// lane still scores the view from its other detectors, so the request is
    /// not blind — but the view was not seen by *that* detector, which is a
    /// documented exceed behaviour (`docs/dos-budget.md` §1.3) that previously
    /// had no signal of any kind.
    Lane2DetectorDegrade,
    /// A third-party Lane 2 parser panicked on a request-controlled string and
    /// the unwind was contained at the detector boundary: that view produced no
    /// signal, the request carried on, the worker survived.
    ///
    /// Any non-zero value is an upstream parser bug reachable from the network
    /// and worth an alert — it is not a tuning knob and no configuration change
    /// makes it go away.
    Lane2ParserPanic,

    // ── §1.3 Lane 2 structured extractor ─────────────────────────────────────
    /// Input over `MAX_EXTRACT_INPUT_BYTES` — the whole extraction is skipped.
    Lane2ExtractInputTooLarge,
    /// GraphQL raw-brace count over the cap — parse declined, falls back to the
    /// whole-body view.
    Lane2GraphqlDeclined,

    // ── §2.2 Lane 1 body budget ──────────────────────────────────────────────
    /// A Lane 1 detector declined to read a body because
    /// `content_security.lane1.max_body_bytes` withheld it. **Unit: detector
    /// invocations, not requests** — one oversized request contributes up to
    /// four per body window.
    Lane1BodySkip,

    // ── §3 queues and background sinks ───────────────────────────────────────
    /// Audit-log record dropped: the 4 096-slot channel was full.
    AuditLogDrop,
    /// An `attack_logs` row for an enforced detection was dropped: the write
    /// queue was full. **The request was still blocked** — what was lost is the
    /// record of it, which is why this must never be read as "nothing was
    /// detected".
    AttackLogWriteDrop,
    /// A `security_events` row for an enforced detection was dropped: the write
    /// queue was full. Same distinction as [`Self::AttackLogWriteDrop`].
    SecurityEventWriteDrop,
    /// Lane 2 observation dropped.
    SemanticObservationDrop,
    /// Lane 2 security event dropped.
    SemanticEventDrop,
    /// Operator notification dropped.
    NotificationDrop,
    /// Community threat-intel signal dropped.
    CommunityReportDrop,
    /// Cluster peer message dropped — `docs/dos-budget.md` §3 records this as
    /// silent and uncounted, which is how a congested peer link contributes to
    /// spurious elections without leaving a trace.
    ClusterPeerDrop,

    // ── §4.1 response cache ──────────────────────────────────────────────────
    /// A response too large for the cache: streamed through un-cached.
    CacheOversizeReject,
    /// An entry evicted involuntarily under size pressure.
    CacheEviction,

    // ── §5 timeouts ──────────────────────────────────────────────────────────
    /// Upstream connect timeout fired — the client got a 502.
    UpstreamConnectTimeout,
    /// Upstream read (inactivity) timeout fired.
    UpstreamReadTimeout,
    /// Upstream write (inactivity) timeout fired.
    UpstreamWriteTimeout,
    /// The `CrowdSec` `AppSec` request-path check did not answer within
    /// `appsec_timeout_ms` and `appsec_failure_action` was applied.
    AppSecUnavailable,
    /// The `CrowdSec` bouncer had no decision cache and could not reach LAPI, so
    /// `crowdsec.fallback_action` was applied.
    CrowdSecFallback,
}

impl BudgetEvent {
    /// Every variant, in declaration order. The exposition walks this, so a new
    /// variant appears in `/metrics` (at zero) the moment it is added — a
    /// counter an operator has never seen fire still has to be graphable.
    const ALL: [Self; 49] = [
        Self::HeaderValueCountExceeded,
        Self::HeaderFoldBytesExceeded,
        Self::DuplicateHost,
        Self::RequestBodyRejected,
        Self::RequestBodyForwardedUninspected,
        Self::Http3BodyRejected,
        Self::ResponseBodyTruncated,
        Self::MultipartBoundaryTooLong,
        Self::MultipartPartsExceeded,
        Self::MultipartPartHeaderBytesExceeded,
        Self::MultipartPartHeaderLinesExceeded,
        Self::CrsJsonBodyTooLarge,
        Self::CrsXmlBodyTooLarge,
        Self::CrsJsonInputTooDeep,
        Self::CrsJsonDepthExceeded,
        Self::CrsJsonArgsExceeded,
        Self::CrsXmlEventsExceeded,
        Self::CrsXmlTextTruncated,
        Self::CrsXmlAttrsExceeded,
        Self::FormArgsFolded,
        Self::Lane2FieldsPerPhase,
        Self::Lane2FieldInputBytes,
        Self::Lane2AstAttempts,
        Self::Lane2AstInputBytes,
        Self::Lane2HtmlParseAttempts,
        Self::Lane2HtmlParseInputBytes,
        Self::Lane2ViewsPerField,
        Self::Lane2TokensPerView,
        Self::Lane2PreprocessOutputBytes,
        Self::Lane2DetectorDegrade,
        Self::Lane2ParserPanic,
        Self::Lane2ExtractInputTooLarge,
        Self::Lane2GraphqlDeclined,
        Self::Lane1BodySkip,
        Self::AuditLogDrop,
        Self::AttackLogWriteDrop,
        Self::SecurityEventWriteDrop,
        Self::SemanticObservationDrop,
        Self::SemanticEventDrop,
        Self::NotificationDrop,
        Self::CommunityReportDrop,
        Self::ClusterPeerDrop,
        Self::CacheOversizeReject,
        Self::CacheEviction,
        Self::UpstreamConnectTimeout,
        Self::UpstreamReadTimeout,
        Self::UpstreamWriteTimeout,
        Self::AppSecUnavailable,
        Self::CrowdSecFallback,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    /// The exported `limit` label value.
    ///
    /// **Public because the drop WARNs use it too.** `docs/metrics.md` sends an
    /// operator to alert on
    /// `prxwaf_budget_events_total{subsystem="queue", limit="attack_log"}`; when
    /// that alert fires they go to the log, and the seven queue-drop WARNs each
    /// used to invent their own word for the same thing — `attack_logs queue
    /// full`, `Semantic observation channel full`, `Community signal channel
    /// full`. None of those contain the token in the alert. Reading it from here
    /// means the string that fired is the string to grep, and a relabelling
    /// cannot leave the log behind. See `docs/logs-and-metrics.md` §4.2.
    #[must_use]
    pub const fn limit(self) -> &'static str {
        self.labels().1
    }

    /// `(subsystem, limit)` — the two labels this event is exported under.
    const fn labels(self) -> (&'static str, &'static str) {
        match self {
            Self::HeaderValueCountExceeded => ("request_headers", "values_per_name"),
            Self::HeaderFoldBytesExceeded => ("request_headers", "folded_bytes"),
            Self::DuplicateHost => ("request_headers", "duplicate_host"),
            Self::RequestBodyRejected => ("request_body", "inspect_ceiling_reject"),
            Self::RequestBodyForwardedUninspected => ("request_body", "inspect_ceiling_forward"),
            Self::Http3BodyRejected => ("http3_body", "buffer_ceiling"),
            Self::ResponseBodyTruncated => ("response_body", "inspect_ceiling"),
            Self::MultipartBoundaryTooLong => ("multipart", "boundary_len"),
            Self::MultipartPartsExceeded => ("multipart", "parts"),
            Self::MultipartPartHeaderBytesExceeded => ("multipart", "part_header_bytes"),
            Self::MultipartPartHeaderLinesExceeded => ("multipart", "part_header_lines"),
            Self::CrsJsonBodyTooLarge => ("crs_body_processor", "json_body_bytes"),
            Self::CrsXmlBodyTooLarge => ("crs_body_processor", "xml_body_bytes"),
            Self::CrsJsonInputTooDeep => ("crs_body_processor", "json_parse_input_depth"),
            Self::CrsJsonDepthExceeded => ("crs_body_processor", "json_depth"),
            Self::CrsJsonArgsExceeded => ("crs_body_processor", "json_args"),
            Self::CrsXmlEventsExceeded => ("crs_body_processor", "xml_events"),
            Self::CrsXmlTextTruncated => ("crs_body_processor", "xml_text_bytes"),
            Self::CrsXmlAttrsExceeded => ("crs_body_processor", "xml_attrs"),
            Self::FormArgsFolded => ("crs_body_processor", "form_args"),
            Self::Lane2FieldsPerPhase => ("lane2_budget", "fields_per_phase"),
            Self::Lane2FieldInputBytes => ("lane2_budget", "field_input_bytes"),
            Self::Lane2AstAttempts => ("lane2_budget", "ast_attempts"),
            Self::Lane2AstInputBytes => ("lane2_budget", "ast_input_bytes"),
            Self::Lane2HtmlParseAttempts => ("lane2_budget", "html_parse_attempts"),
            Self::Lane2HtmlParseInputBytes => ("lane2_budget", "html_parse_input_bytes"),
            Self::Lane2ViewsPerField => ("lane2_budget", "views_per_field"),
            Self::Lane2TokensPerView => ("lane2_budget", "tokens_per_view"),
            Self::Lane2PreprocessOutputBytes => ("lane2_budget", "preprocess_output_bytes"),
            Self::Lane2DetectorDegrade => ("lane2_detector", "input_cap"),
            Self::Lane2ParserPanic => ("lane2_detector", "parser_panic"),
            Self::Lane2ExtractInputTooLarge => ("lane2_extract", "input_bytes"),
            Self::Lane2GraphqlDeclined => ("lane2_extract", "graphql_raw_opens"),
            Self::Lane1BodySkip => ("lane1_body", "max_body_bytes"),
            Self::AuditLogDrop => ("queue", "audit_log"),
            Self::AttackLogWriteDrop => ("queue", "attack_log"),
            Self::SecurityEventWriteDrop => ("queue", "security_event"),
            Self::SemanticObservationDrop => ("queue", "semantic_observations"),
            Self::SemanticEventDrop => ("queue", "semantic_events"),
            Self::NotificationDrop => ("queue", "notifications"),
            Self::CommunityReportDrop => ("queue", "community_reporter"),
            Self::ClusterPeerDrop => ("queue", "cluster_peer"),
            Self::CacheOversizeReject => ("response_cache", "entry_bytes"),
            Self::CacheEviction => ("response_cache", "total_bytes"),
            Self::UpstreamConnectTimeout => ("upstream_timeout", "connect"),
            Self::UpstreamReadTimeout => ("upstream_timeout", "read"),
            Self::UpstreamWriteTimeout => ("upstream_timeout", "write"),
            Self::AppSecUnavailable => ("crowdsec", "appsec_timeout"),
            Self::CrowdSecFallback => ("crowdsec", "decision_cache_blind"),
        }
    }
}

/// A background write path whose **current occupancy** an operator needs to see,
/// not just its drop count.
///
/// [`BudgetEvent`]'s `queue` rows are counters: they fire the moment a queue is
/// already full, which is *after* the interesting part. A queue that is filling
/// but has not yet overflowed produces no signal from them at all, and that is
/// exactly the state a memory-growth investigation is looking for — the depth is
/// the leading indicator, the drop is the trailing one.
///
/// The unit is **items presently owed a write**: incremented when the hot path
/// hands work to a background writer and decremented when that writer is done
/// with it. For a bounded channel that is the queue length; for a path that
/// spawns a task per item it is the number of tasks in flight, which is the same
/// quantity measured on the only structure that path has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueGauge {
    /// `attack_logs` rows owed a write.
    AttackLog,
    /// `security_events` rows owed a write, on the Lane 1 / CRS path.
    SecurityEvent,
    /// Lane 2 observations queued in the semantic sink.
    SemanticObservation,
    /// Lane 2 shadow security events queued in the semantic sink.
    SemanticEvent,
    /// Per-request rule-hit blocks queued for the audit-log file writer.
    AuditLog,
}

impl QueueGauge {
    /// Every variant, in declaration order — the exposition walks this, so a
    /// queue appears in `/metrics` at zero before it has ever been used.
    const ALL: [Self; 5] = [
        Self::AttackLog,
        Self::SecurityEvent,
        Self::SemanticObservation,
        Self::SemanticEvent,
        Self::AuditLog,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    const fn label(self) -> &'static str {
        match self {
            Self::AttackLog => "attack_log",
            Self::SecurityEvent => "security_event",
            Self::SemanticObservation => "semantic_observations",
            Self::SemanticEvent => "semantic_events",
            Self::AuditLog => "audit_log",
        }
    }
}

/// The two numbers that say whether the database pool is the bottleneck.
///
/// Both are sampled from the live `sqlx` pool rather than counted at a record
/// site, because neither is an event: `Connections` is how many the pool has
/// opened (it grows to `storage.max_connections` under load and stops), and
/// `Idle` is how many of those nobody is holding. `Connections` at the
/// configured maximum with `Idle` at zero is pool saturation, and it is the
/// state that turns a background writer's queue into a growing one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolGauge {
    /// Connections the pool currently owns, open or connecting.
    Connections,
    /// Connections currently idle — owned by the pool and held by nobody.
    Idle,
}

impl PoolGauge {
    const ALL: [Self; 2] = [Self::Connections, Self::Idle];

    const fn index(self) -> usize {
        self as usize
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Connections => "connections",
            Self::Idle => "idle",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Histogram bucket layouts — explicit, not the library defaults
// ─────────────────────────────────────────────────────────────────────────────

/// Upper bounds, in **nanoseconds**, for the per-lane detection histogram.
///
/// The library's default buckets start at 5 ms, which would put every clean
/// small request in the first bucket and tell an operator nothing. Detection
/// work on this proxy runs from ~40 µs (Lane 2 on a small GET) to ~100 ms
/// (Lane 1 on a 1 MiB body) — see `tests/perf/RESULTS.md` — so the layout is
/// 1 µs to 1 s in roughly half-decade steps, which resolves both ends.
///
/// Bounds are integers in nanoseconds so bucketing is an integer comparison
/// against a [`Duration::as_nanos`], with no float conversion on the hot path.
const LANE_BUCKETS_NANOS: [u64; 18] = [
    1_000,
    2_500,
    5_000,
    10_000,
    25_000,
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_500_000,
    5_000_000,
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    500_000_000,
    1_000_000_000,
];

/// Upper bounds, in nanoseconds, for end-to-end request duration.
///
/// Wider and coarser than [`LANE_BUCKETS_NANOS`] because it includes the
/// upstream round trip: the interesting range is 0.5 ms to 30 s, and the top
/// bucket has to be able to hold a request sitting on an upstream that has no
/// timeout configured (which is the shipped default — `docs/dos-budget.md`
/// §5.1).
const REQUEST_BUCKETS_NANOS: [u64; 16] = [
    500_000,
    1_000_000,
    2_500_000,
    5_000_000,
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
    2_500_000_000,
    5_000_000_000,
    10_000_000_000,
    30_000_000_000,
    60_000_000_000,
];

/// Lock-free histogram over a fixed bound layout.
///
/// **Storage is one count per bucket, not a running total.** An observation
/// increments exactly one slot; the cumulative form Prometheus publishes is
/// produced by the encoder, at scrape time, from these. Saying "cumulative"
/// here is what made the exposition wrong once already — see
/// [`Self::snapshot`].
///
/// `counts` has one slot per bound plus one for the `+Inf` overflow. The sum is
/// kept in integer nanoseconds rather than as a float, because there is no
/// stable atomic `f64` add; it is divided into seconds only at scrape time. A
/// `u64` of nanoseconds saturates after ~584 years of accumulated observed
/// time, which is not a bound anyone will reach.
#[derive(Debug)]
struct AtomicHistogram {
    bounds: &'static [u64],
    counts: Box<[AtomicU64]>,
    sum_nanos: AtomicU64,
    count: AtomicU64,
}

impl AtomicHistogram {
    fn new(bounds: &'static [u64]) -> Self {
        let counts = (0..=bounds.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            bounds,
            counts,
            sum_nanos: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record one observation. Two relaxed `fetch_add`s plus one on the bucket;
    /// the bucket search is a linear scan over at most 18 `u64` comparisons,
    /// which is branch-predictable and beats a binary search at this size.
    fn observe(&self, nanos: u64) {
        let slot = self
            .bounds
            .iter()
            .position(|&b| nanos <= b)
            .unwrap_or(self.bounds.len());
        if let Some(bucket) = self.counts.get(slot) {
            bucket.fetch_add(1, Ordering::Relaxed);
        }
        self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// `(sum_seconds, count, per_bucket_counts)` in the shape
    /// [`prometheus_client::encoding::MetricEncoder::encode_histogram`] wants.
    ///
    /// # The values are per bucket, not cumulative
    ///
    /// Prometheus *publishes* cumulative buckets, but `encode_histogram` is the
    /// thing that makes them cumulative — it keeps a running total across the
    /// slice it is handed (`prometheus-client-0.25.0/src/encoding/text.rs:422`),
    /// exactly as the library's own `Histogram` expects, since that stores one
    /// count per bucket too. Accumulating here as well published every bucket
    /// summed twice, which is silently wrong rather than obviously wrong: the
    /// series still rises, so it still looks like a histogram, and every
    /// `histogram_quantile` computed from it is a fabrication.
    ///
    /// So this returns the slots verbatim. That is also the cheaper shape —
    /// [`Self::observe`] increments exactly one slot, so reading them back
    /// unchanged is the identity, with no arithmetic to get wrong.
    ///
    /// # The last bound is `f64::MAX`, not `f64::INFINITY`
    ///
    /// The text encoder emits the literal `+Inf` only for `f64::MAX`
    /// (`text.rs:429`), which is the sentinel its own `Histogram::new` appends
    /// (`metrics/histogram.rs:326`). `f64::INFINITY` fails that comparison and
    /// falls through to the numeric branch, where `dtoa` renders it `inf` — and
    /// `le="inf"` is not a legal bucket bound in either the Prometheus text
    /// format or `OpenMetrics`.
    ///
    /// # Concurrency
    ///
    /// The counts are read one at a time, so a scrape concurrent with traffic
    /// can observe a bucket total slightly ahead of `count`. Prometheus already
    /// treats a histogram scrape as approximate for exactly this reason, and the
    /// alternative — a lock around the whole observation — is the cost this
    /// module exists to avoid.
    fn snapshot(&self) -> (f64, u64, Vec<(f64, u64)>) {
        let mut buckets = Vec::with_capacity(self.bounds.len() + 1);
        for (i, bound) in self.bounds.iter().enumerate() {
            let count = self.counts.get(i).map_or(0, |c| c.load(Ordering::Relaxed));
            buckets.push((nanos_to_seconds(*bound), count));
        }
        // The catch-all slot for observations past the last bound.
        let overflow = self
            .counts
            .get(self.bounds.len())
            .map_or(0, |c| c.load(Ordering::Relaxed));
        buckets.push((f64::MAX, overflow));
        let sum = nanos_to_seconds(self.sum_nanos.load(Ordering::Relaxed));
        (sum, self.count.load(Ordering::Relaxed), buckets)
    }
}

/// Nanoseconds to seconds. Split into whole seconds and the remainder so a
/// large accumulated sum does not lose its sub-second part to `f64` rounding.
#[allow(clippy::cast_precision_loss)]
fn nanos_to_seconds(nanos: u64) -> f64 {
    if nanos == u64::MAX {
        return f64::INFINITY;
    }
    let secs = nanos / 1_000_000_000;
    let rest = nanos % 1_000_000_000;
    secs as f64 + (rest as f64) / 1e9
}

// ─────────────────────────────────────────────────────────────────────────────
// Host label slots — the only dynamic label, and it is bounded
// ─────────────────────────────────────────────────────────────────────────────

/// An interned `host` label. Cheap to copy, cheap to index with; the only way
/// to obtain one is [`resolve_host`], which enforces the bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostSlot(usize);

impl HostSlot {
    /// The fold-everything-else slot. Also what an unresolved host reports as,
    /// so a code path that never calls [`resolve_host`] still produces a valid
    /// (if uninformative) series rather than a wrong one.
    pub const OTHER: Self = Self(usize::MAX);

    const fn index(self, capacity: usize) -> usize {
        if self.0 == usize::MAX { capacity } else { self.0 }
    }
}

impl Default for HostSlot {
    fn default() -> Self {
        Self::OTHER
    }
}

/// The label value used for every host past `max_host_labels`.
const OTHER_HOST_LABEL: &str = "__other__";

/// Lock-free, bounded, append-only host interner.
///
/// Open addressing over `OnceLock` cells: a lookup is a hash plus a short probe
/// of acquire loads, and a first-time insert is a `OnceLock::set`, which is a
/// compare-and-swap. Nothing here takes a lock, in either direction, which
/// matters because this runs once per request on every worker thread.
///
/// Append-only is the right shape: hosts are added by config reload and removed
/// approximately never, and a slot that stops receiving traffic costs one stale
/// series until the process restarts — which is what Prometheus expects anyway.
#[derive(Debug)]
struct HostSlots {
    cells: Box<[OnceLock<Box<str>>]>,
    used: AtomicUsize,
    max: usize,
    /// Set the first time a host was actually turned away into `__other__`
    /// because the table was full.
    ///
    /// **Not** `used >= max`: a node with exactly `max_host_labels` hostnames
    /// fills the table and folds nothing, and reporting that as a fold would
    /// send an operator to change a setting that is already right. This says
    /// what happened, not what could have.
    ///
    /// Deliberately excludes the `max == 0` posture, which means "fold
    /// everything" and is a configuration, not a surprise.
    folded: std::sync::atomic::AtomicBool,
}

impl HostSlots {
    /// Capacity is the smallest power of two that is at least twice `max`, so
    /// the table never runs above 50% load and probes stay short.
    fn new(max: usize) -> Self {
        let mut capacity = 8usize;
        while capacity < max.saturating_mul(2).max(8) {
            match capacity.checked_mul(2) {
                Some(next) => capacity = next,
                None => break,
            }
        }
        let cells = (0..capacity).map(|_| OnceLock::new()).collect();
        Self {
            cells,
            used: AtomicUsize::new(0),
            max,
            folded: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Note that a host was turned away, for [`host_labels_folding`].
    ///
    /// Load before store so that after the first fold this is a relaxed read of
    /// a line every worker thread holds shared, rather than a write that bounces
    /// it between them on every folded request. The flag is one-way, so a lost
    /// race merely means the next folded request sets it.
    #[inline]
    fn note_fold(&self) {
        if !self.folded.load(Ordering::Relaxed) {
            self.folded.store(true, Ordering::Relaxed);
        }
    }

    const fn capacity(&self) -> usize {
        self.cells.len()
    }

    /// FNV-1a. Chosen over `DefaultHasher` because it is stable across releases
    /// (so a slot keeps its identity in a restarted process reading the same
    /// config) and needs no allocation or state.
    fn hash(host: &str) -> usize {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in host.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        usize::try_from(h).unwrap_or(usize::MAX)
    }

    /// Resolve `host` to its slot, claiming a free one if there is room.
    /// Returns [`HostSlot::OTHER`] once `max` distinct hosts have been seen.
    fn resolve(&self, host: &str) -> HostSlot {
        let capacity = self.capacity();
        if self.max == 0 || capacity == 0 {
            return HostSlot::OTHER;
        }
        let mask = capacity - 1;
        let start = Self::hash(host) & mask;
        for probe in 0..capacity {
            let idx = (start + probe) & mask;
            let Some(cell) = self.cells.get(idx) else {
                self.note_fold();
                return HostSlot::OTHER;
            };
            if let Some(existing) = cell.get() {
                if existing.as_ref() == host {
                    return HostSlot(idx);
                }
                continue;
            }
            // Free cell. Reserve before claiming, so two threads racing on the
            // last free slot cannot both win: the loser sees `used > max` and
            // folds into `__other__`.
            if self.used.fetch_add(1, Ordering::AcqRel) >= self.max {
                self.used.fetch_sub(1, Ordering::AcqRel);
                self.note_fold();
                return HostSlot::OTHER;
            }
            if cell.set(host.into()).is_ok() {
                return HostSlot(idx);
            }
            // Another thread claimed this cell between the load and the set.
            // Give the reservation back and re-examine it: it may hold our own
            // host, and if it does not the probe continues.
            self.used.fetch_sub(1, Ordering::AcqRel);
            if cell.get().is_some_and(|existing| existing.as_ref() == host) {
                return HostSlot(idx);
            }
        }
        // Every cell probed and none was free or ours. Capacity is twice `max`,
        // so this is only reachable once the table is full.
        self.note_fold();
        HostSlot::OTHER
    }

    /// The label value for a slot index, for exposition.
    fn label(&self, idx: usize) -> &str {
        self.cells
            .get(idx)
            .and_then(|cell| cell.get())
            .map_or(OTHER_HOST_LABEL, |name| name.as_ref())
    }

    /// Slot indices that have been claimed, plus the trailing `__other__` slot.
    fn occupied(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.capacity())
            .filter(|idx| self.cells.get(*idx).is_some_and(|c| c.get().is_some()))
            .chain(std::iter::once(self.capacity()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The metric storage
// ─────────────────────────────────────────────────────────────────────────────

/// Every counter and histogram, in flat tables indexed by the label
/// enumerations. Shared by `Arc` between the record sites and the exposition
/// collector.
#[derive(Debug)]
pub struct MetricsState {
    hosts: HostSlots,
    /// `host_slot * 4 + action`.
    requests: Box<[AtomicU64]>,
    /// `host_slot * 5 + status_class`.
    responses: Box<[AtomicU64]>,
    /// One histogram per host slot.
    request_duration: Box<[AtomicHistogram]>,
    /// `phase_index * 3 + verdict_action`.
    detections: Box<[AtomicU64]>,
    /// One histogram per [`Lane`].
    lane_duration: Box<[AtomicHistogram]>,
    /// One slot per [`BudgetEvent`].
    budget: Box<[AtomicU64]>,
    /// One slot per [`QueueGauge`]. Signed because the increment and the
    /// decrement happen on different threads: a scrape that lands between a
    /// writer's decrement and its producer's increment can legitimately observe
    /// a transient −1, and clamping that to zero inside an unsigned type would
    /// hide a *real* pairing bug behind a plausible number. It is published
    /// clamped and stored honestly.
    queue_depth: Box<[AtomicI64]>,
    /// One slot per [`PoolGauge`], written by the sampler rather than by a
    /// record site.
    pool: Box<[AtomicI64]>,
    /// Requests whose Lane 2 verdict came back `degraded` — part of the request
    /// was never inspected.
    degraded: AtomicU64,
}

impl MetricsState {
    fn new(max_hosts: usize) -> Self {
        let hosts = HostSlots::new(max_hosts);
        // `+ 1` for the `__other__` slot, which lives past the table.
        let host_slots = hosts.capacity() + 1;
        Self {
            requests: (0..host_slots * RequestAction::ALL.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            responses: (0..host_slots * StatusClass::ALL.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            request_duration: (0..host_slots)
                .map(|_| AtomicHistogram::new(&REQUEST_BUCKETS_NANOS))
                .collect(),
            detections: (0..(Phase::MAX_INDEX + 1) * VerdictAction::ALL.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            lane_duration: Lane::ALL
                .iter()
                .map(|_| AtomicHistogram::new(&LANE_BUCKETS_NANOS))
                .collect(),
            budget: BudgetEvent::ALL.iter().map(|_| AtomicU64::new(0)).collect(),
            queue_depth: QueueGauge::ALL.iter().map(|_| AtomicI64::new(0)).collect(),
            pool: PoolGauge::ALL.iter().map(|_| AtomicI64::new(0)).collect(),
            degraded: AtomicU64::new(0),
            hosts,
        }
    }

    fn bump(table: &[AtomicU64], idx: usize) {
        if let Some(slot) = table.get(idx) {
            slot.fetch_add(1, Ordering::Relaxed);
        }
    }

    const fn host_index(&self, host: HostSlot) -> usize {
        host.index(self.hosts.capacity())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exposition
// ─────────────────────────────────────────────────────────────────────────────

// Metric names carry the `prxwaf_` prefix literally rather than through
// `Registry::with_prefix`, so the name in this file is the name on the wire and
// `grep prxwaf_requests` finds both ends of it.

impl Collector for MetricsState {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        self.encode_red(&mut encoder)?;
        self.encode_detections(&mut encoder)?;
        self.encode_lanes(&mut encoder)?;
        self.encode_budget(&mut encoder)?;
        self.encode_queues(&mut encoder)?;
        Ok(())
    }
}

impl MetricsState {
    fn encode_red(&self, encoder: &mut DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let mut requests = encoder.encode_descriptor(
            "prxwaf_requests",
            "Requests the WAF reached a decision on, by host and decision",
            None,
            MetricType::Counter,
        )?;
        for slot in self.hosts.occupied() {
            let host = self.hosts.label(slot);
            for action in RequestAction::ALL {
                let idx = slot * RequestAction::ALL.len() + action.index();
                let value = self.requests.get(idx).map_or(0, |c| c.load(Ordering::Relaxed));
                let labels = [("host", host), ("action", action.label())];
                let mut family = requests.encode_family(&labels)?;
                family.encode_counter::<NoLabelSet, u64, u64>(&value, None)?;
            }
        }

        let mut responses = encoder.encode_descriptor(
            "prxwaf_responses",
            "Responses delivered downstream, by host and status class",
            None,
            MetricType::Counter,
        )?;
        for slot in self.hosts.occupied() {
            let host = self.hosts.label(slot);
            for class in StatusClass::ALL {
                let idx = slot * StatusClass::ALL.len() + class.index();
                let value = self.responses.get(idx).map_or(0, |c| c.load(Ordering::Relaxed));
                let labels = [("host", host), ("status", class.label())];
                let mut family = responses.encode_family(&labels)?;
                family.encode_counter::<NoLabelSet, u64, u64>(&value, None)?;
            }
        }

        let mut duration = encoder.encode_descriptor(
            "prxwaf_request_duration_seconds",
            "End-to-end time from the WAF accepting a request to it finishing, by host",
            None,
            MetricType::Histogram,
        )?;
        for slot in self.hosts.occupied() {
            let Some(hist) = self.request_duration.get(slot) else {
                continue;
            };
            let (sum, count, buckets) = hist.snapshot();
            let labels = [("host", self.hosts.label(slot))];
            let mut family = duration.encode_family(&labels)?;
            family.encode_histogram::<NoLabelSet>(sum, count, &buckets, None)?;
        }
        Ok(())
    }

    fn encode_detections(&self, encoder: &mut DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let mut detections = encoder.encode_descriptor(
            "prxwaf_detections",
            "Detections by the phase that produced them and the action taken",
            None,
            MetricType::Counter,
        )?;
        for phase in Phase::ALL {
            for action in VerdictAction::ALL {
                let idx = phase.index() * VerdictAction::ALL.len() + action.index();
                let value = self.detections.get(idx).map_or(0, |c| c.load(Ordering::Relaxed));
                let labels = [("phase", phase.metric_label()), ("action", action.label())];
                let mut family = detections.encode_family(&labels)?;
                family.encode_counter::<NoLabelSet, u64, u64>(&value, None)?;
            }
        }

        let mut degraded = encoder.encode_descriptor(
            "prxwaf_degraded_requests",
            "Requests whose semantic verdict was degraded: part of the request was never inspected",
            None,
            MetricType::Counter,
        )?;
        let value = self.degraded.load(Ordering::Relaxed);
        degraded.encode_counter::<NoLabelSet, u64, u64>(&value, None)?;
        Ok(())
    }

    fn encode_lanes(&self, encoder: &mut DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let mut lanes = encoder.encode_descriptor(
            "prxwaf_inspection_duration_seconds",
            "Time spent inside one detection chain, per request phase it ran in",
            None,
            MetricType::Histogram,
        )?;
        for lane in Lane::ALL {
            let Some(hist) = self.lane_duration.get(lane.index()) else {
                continue;
            };
            let (sum, count, buckets) = hist.snapshot();
            let labels = [("lane", lane.label())];
            let mut family = lanes.encode_family(&labels)?;
            family.encode_histogram::<NoLabelSet>(sum, count, &buckets, None)?;
        }
        Ok(())
    }

    fn encode_budget(&self, encoder: &mut DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let mut budget = encoder.encode_descriptor(
            "prxwaf_budget_events",
            "Times a bounded resource was reached and the documented exceed behaviour ran \
             (see docs/dos-budget.md)",
            None,
            MetricType::Counter,
        )?;
        for event in BudgetEvent::ALL {
            let (subsystem, limit) = event.labels();
            let value = self.budget.get(event.index()).map_or(0, |c| c.load(Ordering::Relaxed));
            let labels = [("subsystem", subsystem), ("limit", limit)];
            let mut family = budget.encode_family(&labels)?;
            family.encode_counter::<NoLabelSet, u64, u64>(&value, None)?;
        }
        Ok(())
    }

    fn encode_queues(&self, encoder: &mut DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let mut depth = encoder.encode_descriptor(
            "prxwaf_queue_depth",
            "Items handed to a background writer and not yet written — the queue in front of \
             the database, before anything is dropped",
            None,
            MetricType::Gauge,
        )?;
        for queue in QueueGauge::ALL {
            // Clamped at the boundary, not in storage: see `queue_depth`.
            let value = self
                .queue_depth
                .get(queue.index())
                .map_or(0, |g| g.load(Ordering::Relaxed))
                .max(0);
            let labels = [("queue", queue.label())];
            let mut family = depth.encode_family(&labels)?;
            family.encode_gauge(&value)?;
        }

        let mut pool = encoder.encode_descriptor(
            "prxwaf_db_pool",
            "Database connection pool occupancy, sampled: connections owned, and of those, idle",
            None,
            MetricType::Gauge,
        )?;
        for gauge in PoolGauge::ALL {
            let value = self.pool.get(gauge.index()).map_or(0, |g| g.load(Ordering::Relaxed));
            let labels = [("state", gauge.label())];
            let mut family = pool.encode_family(&labels)?;
            family.encode_gauge(&value)?;
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process-global handle
// ─────────────────────────────────────────────────────────────────────────────

/// The registry plus the storage it exposes.
#[derive(Debug)]
pub struct Metrics {
    state: std::sync::Arc<MetricsState>,
    registry: Registry,
}

impl Metrics {
    fn new(max_hosts: usize) -> Self {
        let state = std::sync::Arc::new(MetricsState::new(max_hosts));
        let mut registry = Registry::default();
        registry.register_collector(Box::new(StateCollector(std::sync::Arc::clone(&state))));
        Self { state, registry }
    }

    /// Render the current values in the Prometheus text exposition format.
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &self.registry)?;
        Ok(out)
    }
}

/// `Collector` is implemented on this wrapper rather than on `Arc<MetricsState>`
/// directly so the blanket `impl Collector for Arc<T>` is not what gets used —
/// the wrapper keeps the registry's ownership of the storage explicit.
#[derive(Debug)]
struct StateCollector(std::sync::Arc<MetricsState>);

impl Collector for StateCollector {
    fn encode(&self, encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        self.0.encode(encoder)
    }
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// Bring metrics up. Returns `false` when `config.enabled` is `false` (nothing
/// is allocated and every record site stays a no-op) or when metrics were
/// already initialised.
///
/// Idempotent by construction: a second call cannot replace the storage, which
/// keeps counters monotonic across a config reload.
pub fn init(config: &MetricsConfig) -> bool {
    if !config.enabled {
        return false;
    }
    METRICS.set(Metrics::new(config.effective_max_hosts())).is_ok()
}

/// The live metrics, or `None` when disabled. One acquire load.
#[inline]
#[must_use]
pub fn metrics() -> Option<&'static Metrics> {
    METRICS.get()
}

/// Whether recording is active. Cheap enough to gate a `Instant::now()` on.
#[inline]
#[must_use]
pub fn enabled() -> bool {
    METRICS.get().is_some()
}

/// Render the exposition, or `None` when metrics are disabled.
pub fn encode() -> Option<Result<String, std::fmt::Error>> {
    metrics().map(Metrics::encode)
}

/// Whether at least one hostname has been turned away into `host="__other__"`
/// because `max_host_labels` was already spent.
///
/// The fold is the mechanism that makes this process's series count a property
/// of its configuration rather than of its traffic, so it is not a fault — but
/// it is invisible from both surfaces once it happens. `__other__` cannot name
/// what is inside it without undoing the bound, and the log carries the real
/// host with no indication of which bucket it landed in. An operator whose node
/// fronts more sites than the bound therefore reads `__other__` as a small tail
/// forever, and every per-host panel they build silently omits the remainder.
///
/// Exposed so the scrape endpoint can say so once. Deliberately reports
/// `false` under `max_host_labels = 0`, which is the documented "fold
/// everything" posture: the operator asked for it and the startup broadcast
/// already stated it.
///
/// Two relaxed loads. Called from the scrape handler, never from the request
/// path.
#[must_use]
pub fn host_labels_folding() -> bool {
    metrics().is_some_and(|m| m.state.hosts.folded.load(Ordering::Relaxed))
}

/// The effective `max_host_labels` this process is running with, for the
/// message [`host_labels_folding`] justifies. Zero when metrics are off.
#[must_use]
pub fn host_label_bound() -> usize {
    metrics().map_or(0, |m| m.state.hosts.max)
}

// ─────────────────────────────────────────────────────────────────────────────
// Recording API — the only way to write a metric
// ─────────────────────────────────────────────────────────────────────────────

/// Intern a host name into its label slot, once per request.
///
/// Hosts past `max_host_labels` collapse to [`HostSlot::OTHER`], which is
/// exported as `host="__other__"`.
#[inline]
#[must_use]
pub fn resolve_host(host: &str) -> HostSlot {
    metrics().map_or(HostSlot::OTHER, |m| m.state.hosts.resolve(host))
}

/// One request reached a decision.
#[inline]
pub fn record_request(host: HostSlot, action: RequestAction) {
    if let Some(m) = metrics() {
        let idx = m.state.host_index(host) * RequestAction::ALL.len() + action.index();
        MetricsState::bump(&m.state.requests, idx);
    }
}

/// One response was delivered downstream.
#[inline]
pub fn record_response(host: HostSlot, status: u16) {
    if let Some(m) = metrics() {
        let idx = m.state.host_index(host) * StatusClass::ALL.len() + StatusClass::of(status).index();
        MetricsState::bump(&m.state.responses, idx);
    }
}

/// End-to-end duration of one request.
#[inline]
pub fn record_request_duration(host: HostSlot, elapsed: Duration) {
    if let Some(m) = metrics()
        && let Some(hist) = m.state.request_duration.get(m.state.host_index(host))
    {
        hist.observe(duration_nanos(elapsed));
    }
}

/// One detection, attributed to the phase that produced it.
#[inline]
pub fn record_detection(phase: Phase, action: VerdictAction) {
    if let Some(m) = metrics() {
        let idx = phase.index() * VerdictAction::ALL.len() + action.index();
        MetricsState::bump(&m.state.detections, idx);
    }
}

/// Time one detection chain spent on one request phase.
#[inline]
pub fn record_lane_duration(lane: Lane, elapsed: Duration) {
    if let Some(m) = metrics()
        && let Some(hist) = m.state.lane_duration.get(lane.index())
    {
        hist.observe(duration_nanos(elapsed));
    }
}

/// A bounded resource was reached and its exceed behaviour ran.
#[inline]
pub fn record_budget_event(event: BudgetEvent) {
    if let Some(m) = metrics() {
        MetricsState::bump(&m.state.budget, event.index());
    }
}

/// One more item is owed a write by a background writer.
///
/// Must be paired with exactly one [`queue_depth_dec`] on every path the item
/// can leave by, the error and drop paths included — an unpaired increment
/// makes the gauge climb forever and look like the leak it is meant to detect.
#[inline]
pub fn queue_depth_inc(queue: QueueGauge) {
    if let Some(m) = metrics()
        && let Some(slot) = m.state.queue_depth.get(queue.index())
    {
        slot.fetch_add(1, Ordering::Relaxed);
    }
}

/// One item a background writer owed has left the queue — written, dropped or
/// failed. See [`queue_depth_inc`] for the pairing rule.
#[inline]
pub fn queue_depth_dec(queue: QueueGauge) {
    if let Some(m) = metrics()
        && let Some(slot) = m.state.queue_depth.get(queue.index())
    {
        slot.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Publish a sampled connection-pool occupancy. Absolute, not a delta: the
/// caller reads the live pool and states what it saw.
#[inline]
pub fn set_pool_gauge(gauge: PoolGauge, value: i64) {
    if let Some(m) = metrics()
        && let Some(slot) = m.state.pool.get(gauge.index())
    {
        slot.store(value, Ordering::Relaxed);
    }
}

/// Current depth of one queue. For tests and for the shutdown log; the
/// exposition reads the same slot.
#[must_use]
pub fn queue_depth(queue: QueueGauge) -> i64 {
    metrics().map_or(0, |m| {
        m.state
            .queue_depth
            .get(queue.index())
            .map_or(0, |g| g.load(Ordering::Relaxed))
    })
}

/// A request finished with part of it never inspected.
#[inline]
pub fn record_degraded() {
    if let Some(m) = metrics() {
        m.state.degraded.fetch_add(1, Ordering::Relaxed);
    }
}

/// `Duration::as_nanos` is a `u128`; saturate rather than wrap. A duration past
/// 584 years can only come from a clock fault, and folding it into the `+Inf`
/// bucket is the honest rendering of one.
fn duration_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn state(max_hosts: usize) -> MetricsState {
        MetricsState::new(max_hosts)
    }

    #[test]
    fn host_slots_are_stable_and_distinct() {
        let slots = HostSlots::new(4);
        let a = slots.resolve("a.example");
        let b = slots.resolve("b.example");
        assert_ne!(a, b);
        assert_eq!(a, slots.resolve("a.example"));
        assert_eq!(b, slots.resolve("b.example"));
    }

    #[test]
    fn host_slots_fold_past_the_bound() {
        let slots = HostSlots::new(2);
        let a = slots.resolve("a");
        let b = slots.resolve("b");
        assert_ne!(a, HostSlot::OTHER);
        assert_ne!(b, HostSlot::OTHER);
        // Third distinct host: folded, and folding must not evict the first two.
        assert_eq!(slots.resolve("c"), HostSlot::OTHER);
        assert_eq!(slots.resolve("d"), HostSlot::OTHER);
        assert_eq!(slots.resolve("a"), a);
        assert_eq!(slots.resolve("b"), b);
    }

    #[test]
    fn zero_bound_folds_everything() {
        let slots = HostSlots::new(0);
        assert_eq!(slots.resolve("a"), HostSlot::OTHER);
        assert_eq!(slots.label(slots.capacity()), OTHER_HOST_LABEL);
        // "Fold everything" is a configuration, not an exhaustion. Reporting it
        // would send an operator to change a setting they chose on purpose.
        assert!(!slots.folded.load(Ordering::Relaxed));
    }

    /// The fold flag has to say what happened, not what could have. A node with
    /// exactly `max_host_labels` hostnames fills the table and turns nobody
    /// away; warning it about a bound it fits inside would be a false alarm on
    /// the one signal that is only ever emitted once.
    #[test]
    fn the_fold_flag_needs_a_host_actually_turned_away() {
        let slots = HostSlots::new(3);
        for host in ["a.example", "b.example", "c.example"] {
            assert_ne!(slots.resolve(host), HostSlot::OTHER);
        }
        assert!(
            !slots.folded.load(Ordering::Relaxed),
            "a full table that refused nobody is not a fold"
        );

        // Re-resolving a host already interned is a hit, not a fold.
        assert_ne!(slots.resolve("b.example"), HostSlot::OTHER);
        assert!(!slots.folded.load(Ordering::Relaxed));

        assert_eq!(slots.resolve("d.example"), HostSlot::OTHER);
        assert!(slots.folded.load(Ordering::Relaxed));
    }

    #[test]
    fn host_slot_bound_is_clamped() {
        let cfg = MetricsConfig {
            max_host_labels: usize::MAX,
            ..MetricsConfig::default()
        };
        assert_eq!(cfg.effective_max_hosts(), MAX_HOST_LABELS_CEILING);
    }

    /// `snapshot` returns **per-bucket** counts — the encoder accumulates them.
    /// The published, cumulative form is asserted against the exposition text
    /// in `histogram_buckets_are_cumulative_exactly_once`; this checks the raw
    /// shape that feeds it.
    #[test]
    fn histogram_snapshot_is_per_bucket_and_sums_in_seconds() {
        let h = AtomicHistogram::new(&LANE_BUCKETS_NANOS);
        h.observe(500); // <= 1 µs      -> first bucket
        h.observe(3_000); // <= 5 µs      -> third bucket
        h.observe(2_000_000_000); // over the top bound -> overflow slot
        let (sum, count, buckets) = h.snapshot();
        assert_eq!(count, 3);
        assert!((sum - 2.000_003_5).abs() < 1e-6, "sum was {sum}");

        // Exactly one observation in each of three distinct slots, and nothing
        // anywhere else — not a running total.
        assert_eq!(buckets.iter().map(|b| b.1).sum::<u64>(), count);
        assert_eq!(buckets.first().map(|b| b.1), Some(1));
        assert_eq!(buckets.get(2).map(|b| b.1), Some(1));
        assert_eq!(buckets.get(1).map(|b| b.1), Some(0));
        assert_eq!(buckets.last().map(|b| b.1), Some(1));

        // The overflow bound must be the sentinel the encoder tests for.
        assert_eq!(buckets.last().map(|b| b.0), Some(f64::MAX));
        assert!(buckets.iter().all(|b| b.0.is_finite()));
    }

    #[test]
    fn bucket_bounds_are_strictly_increasing() {
        for bounds in [LANE_BUCKETS_NANOS.as_slice(), REQUEST_BUCKETS_NANOS.as_slice()] {
            for window in bounds.windows(2) {
                let (lo, hi) = (window.first().copied(), window.get(1).copied());
                assert!(lo < hi, "{window:?} is not strictly increasing");
            }
        }
    }

    #[test]
    fn budget_event_list_is_complete_and_indexes_uniquely() {
        for (i, event) in BudgetEvent::ALL.iter().enumerate() {
            assert_eq!(event.index(), i, "BudgetEvent::ALL is out of declaration order at {i}");
        }
        let mut labels: Vec<_> = BudgetEvent::ALL.iter().map(|e| e.labels()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(before, labels.len(), "two BudgetEvents share a label pair");
    }

    #[test]
    fn enumerations_index_in_declaration_order() {
        for (i, a) in RequestAction::ALL.iter().enumerate() {
            assert_eq!(a.index(), i);
        }
        for (i, a) in VerdictAction::ALL.iter().enumerate() {
            assert_eq!(a.index(), i);
        }
        for (i, c) in StatusClass::ALL.iter().enumerate() {
            assert_eq!(c.index(), i);
        }
        for (i, l) in Lane::ALL.iter().enumerate() {
            assert_eq!(l.index(), i);
        }
    }

    /// The `action` word is written on three surfaces — the metric label, the
    /// `action = …` field on the gateway's refusal logs, and the `action`
    /// column of `attack_logs` / `security_events`. All three now read it from
    /// [`RequestAction::label`], and this pins both halves of that: the mapping
    /// off `WafAction` is total and correct, and the four words themselves are
    /// what `docs/metrics.md` and `docs/logs-and-metrics.md` promise. Renaming
    /// one has to be a deliberate edit here, not a silent divergence between a
    /// dashboard and a `grep`.
    #[test]
    fn the_action_word_has_exactly_one_definition() {
        use crate::types::WafAction;

        assert_eq!(RequestAction::of(&WafAction::Allow), RequestAction::Allow);
        assert_eq!(
            RequestAction::of(&WafAction::Block {
                status: 403,
                body: None
            }),
            RequestAction::Block
        );
        assert_eq!(RequestAction::of(&WafAction::LogOnly), RequestAction::LogOnly);
        assert_eq!(
            RequestAction::of(&WafAction::Redirect {
                url: "https://example.test/".to_string()
            }),
            RequestAction::Redirect
        );

        assert_eq!(RequestAction::Allow.label(), "allow");
        assert_eq!(RequestAction::Block.label(), "block");
        assert_eq!(RequestAction::LogOnly.label(), "log_only");
        assert_eq!(RequestAction::Redirect.label(), "redirect");

        // A detection's three actions must be spelled identically to the
        // request's, or `detections_total{action="block"}` and
        // `requests_total{action="block"}` would not join.
        assert_eq!(VerdictAction::Block.label(), RequestAction::Block.label());
        assert_eq!(VerdictAction::LogOnly.label(), RequestAction::LogOnly.label());
        assert_eq!(VerdictAction::Redirect.label(), RequestAction::Redirect.label());
    }

    #[test]
    fn status_classification_covers_the_edges() {
        assert_eq!(StatusClass::of(200), StatusClass::Success);
        assert_eq!(StatusClass::of(299), StatusClass::Success);
        assert_eq!(StatusClass::of(300), StatusClass::Redirection);
        assert_eq!(StatusClass::of(403), StatusClass::ClientError);
        assert_eq!(StatusClass::of(502), StatusClass::ServerError);
        // Out of range: reported as a server error rather than silently dropped.
        assert_eq!(StatusClass::of(0), StatusClass::ServerError);
        assert_eq!(StatusClass::of(999), StatusClass::ServerError);
    }

    /// The exposition has to name every series even at zero, otherwise a
    /// counter that has never fired is invisible to a dashboard until the
    /// incident that makes it fire.
    #[test]
    fn exposition_names_every_series_from_zero() {
        let m = Metrics::new(8);
        let text = m.encode().expect("encode");
        assert!(text.contains("prxwaf_budget_events_total"), "{text}");
        assert!(
            text.contains(r#"subsystem="lane2_budget",limit="ast_attempts""#),
            "{text}"
        );
        assert!(text.contains(r#"subsystem="queue",limit="cluster_peer""#), "{text}");
        assert!(text.contains("prxwaf_detections_total"), "{text}");
        assert!(text.contains(r#"phase="sql_injection",action="block""#), "{text}");
        assert!(text.contains("prxwaf_inspection_duration_seconds_bucket"), "{text}");
        assert!(text.contains(r#"lane="crs""#), "{text}");
        assert!(text.contains("prxwaf_degraded_requests_total"), "{text}");
        assert!(text.contains("prxwaf_queue_depth"), "{text}");
        assert!(text.contains(r#"queue="attack_log""#), "{text}");
        assert!(text.contains(r#"queue="security_event""#), "{text}");
        assert!(text.contains("prxwaf_db_pool"), "{text}");
        assert!(text.contains(r#"state="idle""#), "{text}");
        // No host has been resolved, so only the `__other__` series exists.
        assert!(text.contains(r#"host="__other__""#), "{text}");
    }

    #[test]
    fn queue_gauges_index_uniquely_and_label_uniquely() {
        for (i, queue) in QueueGauge::ALL.iter().enumerate() {
            assert_eq!(queue.index(), i, "QueueGauge::ALL is out of declaration order at {i}");
        }
        let mut labels: Vec<_> = QueueGauge::ALL.iter().map(|q| q.label()).collect();
        let before = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(before, labels.len(), "two QueueGauges share a label");

        for (i, gauge) in PoolGauge::ALL.iter().enumerate() {
            assert_eq!(gauge.index(), i, "PoolGauge::ALL is out of declaration order at {i}");
        }
    }

    /// The pair `docs/metrics.md` tells operators to graph together —
    /// `prxwaf_queue_depth{queue="attack_log"}` against
    /// `prxwaf_budget_events_total{subsystem="queue", limit="attack_log"}` —
    /// only joins if the two families spell the queue the same way. They are
    /// separate enumerations that happen to agree, so nothing but this stops
    /// one of them from being renamed alone. The drop WARNs read the same word
    /// off `QueueGauge::label`, so a divergence would take the log with it.
    #[test]
    fn every_queue_gauge_has_a_drop_counter_spelled_the_same() {
        let drop_limits: Vec<&str> = BudgetEvent::ALL
            .iter()
            .map(|e| e.labels())
            .filter(|(subsystem, _)| *subsystem == "queue")
            .map(|(_, limit)| limit)
            .collect();
        for queue in QueueGauge::ALL {
            assert!(
                drop_limits.contains(&queue.label()),
                "prxwaf_queue_depth{{queue={:?}}} has no matching \
                 prxwaf_budget_events_total{{subsystem=\"queue\", limit={:?}}}; the depth and the drop \
                 cannot be graphed together",
                queue.label(),
                queue.label(),
            );
        }
    }

    /// A gauge is a level, not a count: what reaches the exposition has to be
    /// the difference between the increments and the decrements, and a queue
    /// that drained back to empty has to read zero rather than "how busy it
    /// once was".
    #[test]
    fn queue_depth_is_a_level_and_returns_to_zero() {
        let m = Metrics::new(4);
        let slot = m
            .state
            .queue_depth
            .get(QueueGauge::AttackLog.index())
            .expect("attack_log slot");
        slot.fetch_add(3, Ordering::Relaxed);
        slot.fetch_sub(1, Ordering::Relaxed);
        let text = m.encode().expect("encode");
        assert!(text.contains("prxwaf_queue_depth{queue=\"attack_log\"} 2"), "{text}");

        slot.fetch_sub(2, Ordering::Relaxed);
        let text = m.encode().expect("encode");
        assert!(text.contains("prxwaf_queue_depth{queue=\"attack_log\"} 0"), "{text}");
    }

    /// The storage is signed so a pairing bug stays visible in `queue_depth()`,
    /// but a transient negative must never be published — `-1` on a gauge whose
    /// unit is "items" is not a reading any dashboard can use.
    #[test]
    fn a_transient_negative_depth_is_published_as_zero() {
        let m = Metrics::new(4);
        let slot = m
            .state
            .queue_depth
            .get(QueueGauge::SecurityEvent.index())
            .expect("security_event slot");
        slot.fetch_sub(1, Ordering::Relaxed);
        let text = m.encode().expect("encode");
        assert!(
            text.contains("prxwaf_queue_depth{queue=\"security_event\"} 0"),
            "{text}"
        );
        assert_eq!(slot.load(Ordering::Relaxed), -1, "storage keeps the honest value");
    }

    #[test]
    fn pool_gauge_publishes_what_the_sampler_stored() {
        let m = Metrics::new(4);
        m.state
            .pool
            .get(PoolGauge::Connections.index())
            .expect("connections slot")
            .store(20, Ordering::Relaxed);
        let text = m.encode().expect("encode");
        assert!(text.contains("prxwaf_db_pool{state=\"connections\"} 20"), "{text}");
        assert!(text.contains("prxwaf_db_pool{state=\"idle\"} 0"), "{text}");
    }

    #[test]
    fn recorded_values_reach_the_exposition() {
        let m = Metrics::new(8);
        let slot = m.state.hosts.resolve("site.example");
        let idx = m.state.host_index(slot) * RequestAction::ALL.len() + RequestAction::Block.index();
        MetricsState::bump(&m.state.requests, idx);
        MetricsState::bump(&m.state.budget, BudgetEvent::Lane1BodySkip.index());
        let phase_idx = Phase::Owasp.index() * VerdictAction::ALL.len() + VerdictAction::LogOnly.index();
        MetricsState::bump(&m.state.detections, phase_idx);
        if let Some(h) = m.state.lane_duration.get(Lane::Lane2.index()) {
            h.observe(42_000);
        }

        let text = m.encode().expect("encode");
        assert!(
            text.contains(r#"prxwaf_requests_total{host="site.example",action="block"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"prxwaf_budget_events_total{subsystem="lane1_body",limit="max_body_bytes"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"prxwaf_detections_total{phase="owasp",action="log_only"} 1"#),
            "{text}"
        );
        assert!(
            text.contains(r#"prxwaf_inspection_duration_seconds_count{lane="lane2"} 1"#),
            "{text}"
        );
    }

    // ── Histogram exposition ─────────────────────────────────────────────────
    //
    // These assert on the **text**, not on the store. The store was correct
    // when the exposition was wrong: `observe` increments exactly one slot, and
    // `snapshot` returned a series that satisfied every invariant a test of its
    // return value would have checked. What it did not satisfy was the contract
    // of the function it was passed to — `MetricEncoder::encode_histogram`
    // accumulates the slice itself, so handing it accumulated values
    // accumulated them twice and every `histogram_quantile` downstream was
    // wrong. A test on either side of that seam passes; only one that reads the
    // published bytes catches it.

    /// One histogram's `le` bounds and values, plus its `_sum` and `_count`,
    /// parsed back out of the exposition in emission order.
    struct ParsedHistogram {
        buckets: Vec<(String, u64)>,
        count: u64,
    }

    /// Pull the histogram named `metric` with label text `labels` back out of
    /// an exposition. Deliberately a dumb string parser: reconstructing the
    /// values through the same types that produced them would re-import the
    /// bug.
    fn parse_histogram(text: &str, metric: &str, labels: &str) -> ParsedHistogram {
        let mut buckets = Vec::new();
        let mut count = None;
        for line in text.lines() {
            let Some(rest) = line.strip_prefix(metric) else {
                continue;
            };
            let Some((head, value)) = rest.rsplit_once(' ') else {
                continue;
            };
            if let Some(inner) = head.strip_prefix("_bucket{").and_then(|h| h.strip_suffix('}')) {
                let Some(le) = inner.strip_prefix("le=\"").and_then(|i| i.split('"').next()) else {
                    continue;
                };
                if !inner.contains(labels) {
                    continue;
                }
                buckets.push((le.to_string(), value.parse().expect("bucket value is an integer")));
            } else if head == format!("_count{{{labels}}}") {
                count = Some(value.parse().expect("count is an integer"));
            }
        }
        ParsedHistogram {
            buckets,
            count: count.unwrap_or_else(|| panic!("no _count line for {metric}{{{labels}}} in:\n{text}")),
        }
    }

    /// Assert the three things a Prometheus histogram must satisfy, whatever
    /// its bucket layout.
    fn assert_histogram_is_well_formed(h: &ParsedHistogram, what: &str, text: &str) {
        assert!(!h.buckets.is_empty(), "{what}: no buckets at all in:\n{text}");

        // Cumulative: never decreasing as `le` grows.
        let mut prev = 0u64;
        for (le, value) in &h.buckets {
            assert!(
                *value >= prev,
                "{what}: bucket le={le} is {value}, below the previous {prev} — buckets must be cumulative and \
                 non-decreasing:\n{text}"
            );
            prev = *value;
        }

        // The catch-all bucket holds every observation, by definition.
        let (last_le, last_value) = h.buckets.last().expect("buckets are non-empty");
        assert_eq!(
            last_le, "+Inf",
            "{what}: the final bucket must be le=\"+Inf\", got {last_le:?}:\n{text}"
        );
        assert_eq!(
            *last_value, h.count,
            "{what}: the +Inf bucket is {last_value} but _count is {}. Every observation falls in some bucket, so \
             these are the same number — a mismatch means the bucket values are not what was recorded:\n{text}",
            h.count
        );
    }

    /// The regression. Before the fix the +Inf bucket read 6 against a count of
    /// 3, because the values were accumulated in `snapshot` and then again by
    /// the encoder.
    #[test]
    fn histogram_buckets_are_cumulative_exactly_once() {
        let m = Metrics::new(8);
        for nanos in [500u64, 3_000, 2_000_000_000] {
            if let Some(h) = m.state.lane_duration.get(Lane::Lane1.index()) {
                h.observe(nanos);
            }
        }
        let text = m.encode().expect("encode");
        let h = parse_histogram(&text, "prxwaf_inspection_duration_seconds", r#"lane="lane1""#);
        assert_eq!(h.count, 3);
        assert_histogram_is_well_formed(&h, "lane1 inspection duration", &text);

        // And the published values themselves, not just the invariants. Three
        // observations at 500 ns, 3 µs and 2 s, so the cumulative series is
        // 1 at le=1e-6, still 1 at le=2.5e-6, 2 from le=5e-6 onwards, and 3
        // only in the catch-all. `le` is rendered by `dtoa`, hence the decimal
        // spelling rather than the exponent form the bound is written in.
        assert_eq!(h.buckets.first().map(|b| b.1), Some(1), "{text}");
        assert_eq!(
            h.buckets.iter().find(|b| b.0 == "0.0000025").map(|b| b.1),
            Some(1),
            "second bucket must not have absorbed the first:\n{text}"
        );
        assert_eq!(
            h.buckets.iter().find(|b| b.0 == "0.000005").map(|b| b.1),
            Some(2),
            "{text}"
        );
        // The 2 s observation is past the 1 s top bound, so every finite bucket
        // stops at 2 and only +Inf reaches 3.
        assert_eq!(
            h.buckets.iter().rev().nth(1).map(|b| b.1),
            Some(2),
            "the last finite bucket must not contain the overflow observation:\n{text}"
        );
    }

    /// `le="inf"` is what `dtoa` prints for `f64::INFINITY`, and it is not a
    /// legal `le` value — Prometheus and `OpenMetrics` both require the literal
    /// `+Inf`. The encoder only emits that spelling for `f64::MAX`, which is
    /// the sentinel its own `Histogram` uses.
    #[test]
    fn the_catch_all_bucket_is_spelled_plus_inf() {
        let m = Metrics::new(8);
        if let Some(h) = m.state.lane_duration.get(Lane::Crs.index()) {
            h.observe(1);
        }
        let text = m.encode().expect("encode");
        assert!(text.contains(r#"le="+Inf""#), "no le=\"+Inf\" bucket in:\n{text}");
        assert!(
            !text.contains(r#"le="inf""#),
            "le=\"inf\" is not a legal bucket bound; f64::INFINITY reached dtoa:\n{text}"
        );
        assert!(!text.contains(r#"le="NaN""#), "{text}");
    }

    /// Both histogram families go through the same `snapshot`, so both are
    /// checked — a fix applied to one call site and not the other would leave
    /// half the histograms wrong.
    #[test]
    fn every_exported_histogram_is_well_formed() {
        let m = Metrics::new(8);
        let slot = m.state.hosts.resolve("site.example");
        for (i, nanos) in [1u64, 900_000, 3_000_000, 90_000_000_000].iter().enumerate() {
            if let Some(h) = m.state.request_duration.get(m.state.host_index(slot)) {
                h.observe(*nanos);
            }
            if let Some(h) = m.state.lane_duration.get(i % Lane::ALL.len()) {
                h.observe(*nanos);
            }
        }
        let text = m.encode().expect("encode");

        let request = parse_histogram(&text, "prxwaf_request_duration_seconds", r#"host="site.example""#);
        assert_eq!(request.count, 4);
        assert_histogram_is_well_formed(&request, "request duration", &text);

        for lane in Lane::ALL {
            let labels = format!(r#"lane="{}""#, lane.label());
            let h = parse_histogram(&text, "prxwaf_inspection_duration_seconds", &labels);
            assert_histogram_is_well_formed(&h, lane.label(), &text);
        }

        // A histogram nothing was recorded into must still be well formed:
        // every bucket zero, +Inf zero, count zero.
        let untouched = parse_histogram(&text, "prxwaf_request_duration_seconds", r#"host="__other__""#);
        assert_eq!(untouched.count, 0);
        assert_histogram_is_well_formed(&untouched, "untouched host", &text);
    }

    /// The cardinality claim in the docs is only true if the fold actually
    /// binds. 1 000 distinct hosts against a bound of 16 must produce 17 host
    /// label values, not 1 000.
    #[test]
    fn series_count_is_a_function_of_the_bound_not_the_traffic() {
        let s = state(16);
        for i in 0..1_000 {
            let slot = s.hosts.resolve(&format!("host-{i}.example"));
            let idx = s.host_index(slot) * RequestAction::ALL.len() + RequestAction::Allow.index();
            MetricsState::bump(&s.requests, idx);
        }
        let distinct = s.hosts.occupied().count();
        assert_eq!(distinct, 17, "16 bounded hosts plus __other__");
    }

    #[test]
    fn record_sites_are_inert_before_init() {
        // The global is process-wide and other tests may have set it; this only
        // asserts the no-op path does not panic and returns the fold slot.
        if !enabled() {
            assert_eq!(resolve_host("anything"), HostSlot::OTHER);
            assert!(encode().is_none());
        }
        record_request(HostSlot::OTHER, RequestAction::Allow);
        record_budget_event(BudgetEvent::AuditLogDrop);
        record_degraded();
        record_lane_duration(Lane::Lane1, Duration::from_micros(3));
        record_request_duration(HostSlot::OTHER, Duration::from_millis(1));
        record_detection(Phase::Xss, VerdictAction::Block);
        record_response(HostSlot::OTHER, 200);
        queue_depth_inc(QueueGauge::AttackLog);
        queue_depth_dec(QueueGauge::AttackLog);
        set_pool_gauge(PoolGauge::Idle, 4);
    }
}
