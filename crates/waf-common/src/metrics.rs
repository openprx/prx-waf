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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
/// `127.0.0.1:9090` is the combination that is useful out of the box and
/// exposes nothing — an operator who wants a remote scraper has to say so, and
/// gets a startup warning when they do.
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
            listen_addr: "127.0.0.1:9090".to_string(),
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

    const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::LogOnly => "log_only",
            Self::Redirect => "redirect",
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
    /// `max_preprocess_output_bytes_total`.
    Lane2PreprocessOutputBytes,
    /// A detector-layer soft deadline or input cap marked the request degraded
    /// without going through one of the counted work budgets above.
    Lane2DetectorDegrade,

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
    const ALL: [Self; 44] = [
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
        Self::Lane2PreprocessOutputBytes,
        Self::Lane2DetectorDegrade,
        Self::Lane2ExtractInputTooLarge,
        Self::Lane2GraphqlDeclined,
        Self::Lane1BodySkip,
        Self::AuditLogDrop,
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
            Self::Lane2PreprocessOutputBytes => ("lane2_budget", "preprocess_output_bytes"),
            Self::Lane2DetectorDegrade => ("lane2_budget", "detector_limit"),
            Self::Lane2ExtractInputTooLarge => ("lane2_extract", "input_bytes"),
            Self::Lane2GraphqlDeclined => ("lane2_extract", "graphql_raw_opens"),
            Self::Lane1BodySkip => ("lane1_body", "max_body_bytes"),
            Self::AuditLogDrop => ("queue", "audit_log"),
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

/// Lock-free cumulative histogram over a fixed bound layout.
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

    /// `(sum_seconds, count, cumulative_buckets)` in the shape
    /// [`MetricEncoder::encode_histogram`] wants.
    ///
    /// The counts are read one at a time, so a scrape concurrent with traffic
    /// can observe a bucket total slightly ahead of `count`. Prometheus already
    /// treats a histogram scrape as approximate for exactly this reason, and the
    /// alternative — a lock around the whole observation — is the cost this
    /// module exists to avoid.
    fn snapshot(&self) -> (f64, u64, Vec<(f64, u64)>) {
        let mut cumulative = 0u64;
        let mut buckets = Vec::with_capacity(self.bounds.len() + 1);
        for (i, bound) in self.bounds.iter().enumerate() {
            cumulative = cumulative.saturating_add(self.counts.get(i).map_or(0, |c| c.load(Ordering::Relaxed)));
            buckets.push((nanos_to_seconds(*bound), cumulative));
        }
        cumulative = cumulative.saturating_add(
            self.counts
                .get(self.bounds.len())
                .map_or(0, |c| c.load(Ordering::Relaxed)),
        );
        buckets.push((f64::INFINITY, cumulative));
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
    }

    #[test]
    fn host_slot_bound_is_clamped() {
        let cfg = MetricsConfig {
            max_host_labels: usize::MAX,
            ..MetricsConfig::default()
        };
        assert_eq!(cfg.effective_max_hosts(), MAX_HOST_LABELS_CEILING);
    }

    #[test]
    fn histogram_buckets_are_cumulative_and_sum_in_seconds() {
        let h = AtomicHistogram::new(&LANE_BUCKETS_NANOS);
        h.observe(500); // <= 1 µs
        h.observe(3_000); // <= 5 µs
        h.observe(2_000_000_000); // over the top bound -> +Inf
        let (sum, count, buckets) = h.snapshot();
        assert_eq!(count, 3);
        assert!((sum - 2.000_003_5).abs() < 1e-6, "sum was {sum}");
        assert_eq!(buckets.first().map(|b| b.1), Some(1));
        assert_eq!(buckets.last().map(|b| b.1), Some(3));
        // Cumulative: never decreasing.
        let mut prev = 0;
        for (_, c) in &buckets {
            assert!(*c >= prev);
            prev = *c;
        }
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
        // No host has been resolved, so only the `__other__` series exists.
        assert!(text.contains(r#"host="__other__""#), "{text}");
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
    }
}
