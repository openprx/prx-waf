//! Bot detection — a compiled-in catalogue plus a hot-reloadable operator layer.
//!
//! # Two layers, one request path
//!
//! * **Built-in** (this file, [`BUILTIN_GOOD_BOTS`] / [`BUILTIN_BAD_BOTS`]) —
//!   the signatures that ship with the product. They are `&'static` data
//!   compiled into two [`LazyLock<RegexSet>`]s at first use and never change.
//! * **Operator** — rows in the `bot_patterns` table, compiled at load time and
//!   published to the request path through an [`ArcSwapOption`]. The operator
//!   layer is **additive**: it can add signatures and it can whitelist a UA the
//!   built-ins would have blocked, but it cannot delete a built-in rule. Turning
//!   an individual built-in off is what the `rule_overrides` table is for and is
//!   not implemented here.
//!
//! # Why `ArcSwapOption` and not a lock
//!
//! [`Check::check`] runs on every request, in the header phase, ahead of the
//! content detectors. A `RwLock` read would put a shared atomic write (the
//! reader count) on that path and serialise readers against a reload. `ArcSwap`
//! reads are wait-free and, with no operator patterns configured, `load()`
//! yields `None` and the whole layer costs one atomic load — the same code path
//! a deployment that never opens the Bot Detection page has always had.
//!
//! # Why nothing is compiled on the request path
//!
//! Every pattern is compiled twice before it can ever be matched: once by
//! [`validate_user_pattern`] when the API or CLI accepts it (so a bad regex is a
//! `400`, not a runtime surprise), and once by [`BotCheck::load_user_patterns`]
//! when the set is rebuilt. `check()` only ever runs an already-built automaton.
//!
//! # `ReDoS`
//!
//! The `regex` crate does not backtrack, so a user-supplied pattern cannot
//! produce catastrophic behaviour on the matching side: a `RegexSet` match is
//! linear in the length of the User-Agent and independent of how many patterns
//! are in the set. What an operator-supplied pattern *can* do is ask for an
//! enormous automaton (`(a{100}){100}` and friends), so the limits below are
//! about **memory and compile time**, not match time:
//!
//! * [`MAX_USER_PATTERN_LEN`] — bounds the source text (the column is
//!   `VARCHAR(500)`; this keeps the Rust side from depending on that).
//! * [`MAX_USER_PATTERNS`] — bounds the total set size and the cost of a reload.
//! * [`PATTERN_SIZE_LIMIT`] / [`DFA_SIZE_LIMIT`] — bound one pattern's compiled
//!   program and its lazy-DFA cache. A UA signature compiles to a few hundred
//!   bytes, so 64 KiB is roughly a hundred times what a real rule needs and
//!   still refuses the pathological ones.
//! * [`SET_SIZE_LIMIT`] — the same bound for the combined set.

use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwapOption;
use regex::{RegexBuilder, RegexSet, RegexSetBuilder};
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

// ── Limits ────────────────────────────────────────────────────────────────────

/// Longest accepted operator pattern, in bytes. Mirrors `bot_patterns.pattern`
/// (`VARCHAR(500)`) so the check does not depend on the column definition.
pub const MAX_USER_PATTERN_LEN: usize = 500;

/// Most operator patterns evaluated at once. Extra rows are dropped with a
/// warning rather than silently, and the API refuses to create the 513th.
pub const MAX_USER_PATTERNS: usize = 512;

/// Compiled-program budget for a single operator pattern (bytes).
const PATTERN_SIZE_LIMIT: usize = 64 * 1024;

/// Compiled-program budget for the combined operator set (bytes).
const SET_SIZE_LIMIT: usize = 16 * 1024 * 1024;

/// Lazy-DFA cache budget (bytes), applied to both the single-pattern validator
/// and the combined set.
const DFA_SIZE_LIMIT: usize = 1024 * 1024;

// ── Actions ───────────────────────────────────────────────────────────────────

/// What a bot rule does when its pattern matches the User-Agent.
///
/// Only the two actions the request path can actually carry out. `log` and
/// `captcha` appear in the `bot_patterns` schema but neither is expressible
/// through [`Check`], which returns "detected" or "not detected" and lets the
/// engine decide (log-only vs block is a *per-host* posture,
/// `HostConfig::log_only_mode`). Accepting them would be a promise the request
/// path cannot keep, so the API and CLI reject them at write time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BotAction {
    /// Whitelist: stop bot detection and let the request through.
    Allow,
    /// Report a detection; the engine blocks (or logs, per host posture).
    Block,
}

impl BotAction {
    /// Canonical storage / API spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }

    /// Parse an action from its storage / API spelling. `None` for anything
    /// else, including the unimplemented `log` and `captcha`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

// ── Built-in catalogue ────────────────────────────────────────────────────────

/// One compiled-in bot signature.
///
/// This is the single source of truth for the built-in layer: the `RegexSet`s
/// below are built from it, and the admin API and `prx-waf bot list` enumerate
/// it, so the catalogue an operator is shown is by construction the catalogue
/// the request path runs.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinBotRule {
    /// Stable identifier reported in detections and listings.
    pub id: &'static str,
    /// Human-readable label.
    pub name: &'static str,
    /// The User-Agent regex.
    pub pattern: &'static str,
    /// What a match does.
    pub action: BotAction,
}

/// Known search-engine / legitimate crawlers — allowed through.
///
/// A compile failure here is already fail-closed as an empty set: this set only
/// grants a bypass, so `RegexSet::empty()` means "never match" → never grant the
/// bypass → the request still falls through to [`BUILTIN_BAD_BOTS`] and the rest
/// of the pipeline.
pub static BUILTIN_GOOD_BOTS: &[BuiltinBotRule] = &[
    rule("BOT-GOOD-001", "Googlebot", r"(?i)\bgooglebot\b", BotAction::Allow),
    rule("BOT-GOOD-002", "Bingbot", r"(?i)\bbingbot\b", BotAction::Allow),
    rule("BOT-GOOD-003", "Yahoo Slurp", r"(?i)\bslurp\b", BotAction::Allow),
    rule("BOT-GOOD-004", "DuckDuckBot", r"(?i)\bduckduckbot\b", BotAction::Allow),
    rule("BOT-GOOD-005", "Baiduspider", r"(?i)\bbaiduspider\b", BotAction::Allow),
    rule("BOT-GOOD-006", "YandexBot", r"(?i)\byandexbot\b", BotAction::Allow),
    rule("BOT-GOOD-007", "Sogou spider", r"(?i)\bsogou\b", BotAction::Allow),
    rule("BOT-GOOD-008", "Exabot", r"(?i)\bexabot\b", BotAction::Allow),
    rule("BOT-GOOD-009", "Facebook crawler", r"(?i)\bfacebot\b", BotAction::Allow),
    rule(
        "BOT-GOOD-010",
        "Wayback Machine (ia_archiver)",
        r"(?i)\bia_archiver\b",
        BotAction::Allow,
    ),
    rule("BOT-GOOD-011", "Twitterbot", r"(?i)\btwitterbot\b", BotAction::Allow),
    rule("BOT-GOOD-012", "LinkedInBot", r"(?i)\bLinkedInBot\b", BotAction::Allow),
    rule("BOT-GOOD-013", "AppleBot", r"(?i)\bAppleBot\b", BotAction::Allow),
    rule("BOT-GOOD-014", "DuckDuckGo", r"(?i)\bDuckDuckGo\b", BotAction::Allow),
    rule("BOT-GOOD-015", "SemrushBot", r"(?i)\bSemrushBot\b", BotAction::Allow),
    rule("BOT-GOOD-016", "AhrefsBot", r"(?i)\bAhrefsBot\b", BotAction::Allow),
    rule(
        "BOT-GOOD-017",
        "Googlebot-Image",
        r"(?i)Googlebot-Image",
        BotAction::Allow,
    ),
    rule(
        "BOT-GOOD-018",
        "Googlebot-News",
        r"(?i)Googlebot-News",
        BotAction::Allow,
    ),
    rule(
        "BOT-GOOD-019",
        "Googlebot-Video",
        r"(?i)Googlebot-Video",
        BotAction::Allow,
    ),
];

/// Malicious / scripted bot signatures.
///
/// The `BOT-{:03}` ids are positional and match the historic detection ids, so
/// existing dashboards and alert rules keyed on `BOT-001` keep working.
pub static BUILTIN_BAD_BOTS: &[BuiltinBotRule] = &[
    rule("BOT-001", "Scrapy web scraper", r"(?i)\bscrapy\b", BotAction::Block),
    rule("BOT-002", "zgrab banner grabber", r"(?i)\bzgrab\b", BotAction::Block),
    rule("BOT-003", "Masscan port scanner", r"(?i)\bmasscan\b", BotAction::Block),
    rule(
        "BOT-004",
        "headless browser (Headless Chrome / Puppeteer)",
        r"(?i)(headlesschrome|headless[\s_-]?chrome|puppeteer)",
        BotAction::Block,
    ),
    rule(
        "BOT-005",
        "PhantomJS headless browser",
        r"(?i)\bphantomjs\b",
        BotAction::Block,
    ),
    rule(
        "BOT-006",
        "Selenium WebDriver",
        r"(?i)(selenium|webdriver)",
        BotAction::Block,
    ),
    rule(
        "BOT-007",
        "generic crawler/spider/scraper UA",
        r"(?i)\b(crawler|spider|scraper)\b",
        BotAction::Block,
    ),
    rule(
        "BOT-008",
        "harvester / extractor tool",
        r"(?i)\b(harvest|extractor)\b",
        BotAction::Block,
    ),
    rule("BOT-009", "empty User-Agent (no UA string)", r"^$", BotAction::Block),
    rule(
        "BOT-010",
        "Python urllib (scripted access)",
        r"(?i)^python-urllib/",
        BotAction::Block,
    ),
    rule(
        "BOT-011",
        "Java HTTP client (scripted access)",
        r"(?i)^Java/",
        BotAction::Block,
    ),
    rule(
        "BOT-012",
        "Ruby Net::HTTP (scripted access)",
        r"(?i)^Ruby$|^Ruby/",
        BotAction::Block,
    ),
    rule(
        "BOT-013",
        "Go standard HTTP client",
        r"(?i)^Go-http-client/",
        BotAction::Block,
    ),
];

/// `const` constructor so the catalogue tables stay readable.
const fn rule(id: &'static str, name: &'static str, pattern: &'static str, action: BotAction) -> BuiltinBotRule {
    BuiltinBotRule {
        id,
        name,
        pattern,
        action,
    }
}

static GOOD_BOT_SET: LazyLock<RegexSet> =
    LazyLock::new(|| match RegexSet::new(BUILTIN_GOOD_BOTS.iter().map(|r| r.pattern)) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: good bot regex set failed to compile: {e}");
            RegexSet::empty()
        }
    });

/// Fail-closed compile result (Low-1): see the equivalent comment in
/// `sql_injection.rs` for the full rationale. `None` means the pattern set
/// failed to compile; `check()` then treats every request as a match
/// (fail-closed, i.e. blocked as a bad bot) instead of falling back to
/// `RegexSet::empty()`, which would match nothing and fail open.
static BAD_BOT_SET: LazyLock<Option<RegexSet>> =
    LazyLock::new(|| match RegexSet::new(BUILTIN_BAD_BOTS.iter().map(|r| r.pattern)) {
        Ok(set) => Some(set),
        Err(e) => {
            tracing::error!(
                "BUG: bad bot regex set failed to compile: {e} — failing closed \
                 (this checker will now flag every request as a bad bot until the code is fixed)"
            );
            None
        }
    });

// ── Operator patterns ─────────────────────────────────────────────────────────

/// Why an operator-supplied pattern was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotPatternError {
    /// The pattern was empty or whitespace-only.
    Empty,
    /// The pattern exceeded [`MAX_USER_PATTERN_LEN`]; carries its length.
    TooLong(usize),
    /// The pattern is not a valid regular expression, or asks for an automaton
    /// bigger than [`PATTERN_SIZE_LIMIT`] / [`DFA_SIZE_LIMIT`].
    Invalid(String),
}

impl std::fmt::Display for BotPatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "pattern must not be empty"),
            Self::TooLong(len) => write!(f, "pattern is {len} bytes; the maximum is {MAX_USER_PATTERN_LEN}"),
            Self::Invalid(msg) => write!(f, "invalid regular expression: {msg}"),
        }
    }
}

impl std::error::Error for BotPatternError {}

/// Compile one operator pattern under the size limits and throw the result away.
///
/// Called by the admin API and the CLI **before** the row is written, so a
/// pattern that cannot be compiled is refused with a message the operator can
/// act on rather than stored and skipped forever after.
pub fn validate_user_pattern(pattern: &str) -> Result<(), BotPatternError> {
    if pattern.trim().is_empty() {
        return Err(BotPatternError::Empty);
    }
    if pattern.len() > MAX_USER_PATTERN_LEN {
        return Err(BotPatternError::TooLong(pattern.len()));
    }
    RegexBuilder::new(pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
        .map(|_| ())
        .map_err(|e| BotPatternError::Invalid(e.to_string()))
}

/// One operator-managed bot pattern, as handed to [`BotCheck::load_user_patterns`].
#[derive(Debug, Clone)]
pub struct UserBotPattern {
    /// `bot_patterns.id`.
    pub id: i32,
    /// Human-readable label, reported in the detection detail.
    pub name: String,
    /// The User-Agent regex.
    pub pattern: String,
    /// What a match does.
    pub action: BotAction,
}

/// One compiled half (allow or block) of the operator layer.
struct CompiledSide {
    /// The combined automaton. `matches()` returns indices into `meta`.
    set: RegexSet,
    /// Parallel metadata, same order as the patterns handed to `set`.
    meta: Vec<UserBotPattern>,
}

impl CompiledSide {
    /// Compile `patterns` into one set, dropping the individual patterns that do
    /// not survive [`validate_user_pattern`].
    ///
    /// Returns `None` when nothing is left to match, which is what lets the
    /// request path skip the layer entirely.
    fn build(patterns: Vec<UserBotPattern>, rejected: &mut usize) -> Option<Self> {
        let meta: Vec<UserBotPattern> = patterns
            .into_iter()
            .filter(|p| match validate_user_pattern(&p.pattern) {
                Ok(()) => true,
                Err(e) => {
                    // Reachable when a row was written straight into the
                    // database, bypassing the API, or when the limits are
                    // tightened after the fact.
                    tracing::warn!(pattern_id = p.id, "skipping unusable bot pattern {:?}: {e}", p.name);
                    *rejected += 1;
                    false
                }
            })
            .collect();
        if meta.is_empty() {
            return None;
        }
        match RegexSetBuilder::new(meta.iter().map(|p| &p.pattern))
            .size_limit(SET_SIZE_LIMIT)
            .dfa_size_limit(DFA_SIZE_LIMIT)
            .build()
        {
            Ok(set) => Some(Self { set, meta }),
            Err(e) => {
                // Every member compiled on its own, so this is the combined
                // budget. Dropping the side leaves the built-in layer intact:
                // failing closed here would block every request in the name of
                // rules the operator only meant to add.
                tracing::error!(
                    "operator bot pattern set ({} patterns) exceeded the combined compile budget: \
                     {e} — the built-in signatures still apply, but these patterns are NOT active",
                    meta.len()
                );
                *rejected += meta.len();
                None
            }
        }
    }
}

/// The published snapshot the request path reads.
struct UserBotSet {
    allow: Option<CompiledSide>,
    block: Option<CompiledSide>,
}

/// Outcome of a [`BotCheck::load_user_patterns`] call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BotPatternLoadReport {
    /// Patterns now live on the request path.
    pub loaded: usize,
    /// Patterns that were handed in but could not be compiled.
    pub rejected: usize,
}

// ── BotCheck ──────────────────────────────────────────────────────────────────

/// Bot detection checker.
///
/// Precedence, first match wins:
///
/// 1. operator `allow` — an explicit whitelist beats everything, including the
///    built-in bad-bot signatures. Without this an operator could not clear a
///    false positive on a UA containing e.g. "spider".
/// 2. operator `block` — an explicit block beats the built-in good-bot bypass,
///    so an operator who decides Googlebot is unwelcome is obeyed.
/// 3. built-in good bots → allow.
/// 4. built-in bad bots → block.
///
/// Cloning is cheap and shares the pattern storage: the engine keeps one handle
/// to reload through and hands a second to the header-phase checker vector, and
/// both see the same snapshot.
#[derive(Clone, Default)]
pub struct BotCheck {
    /// `None` until an operator adds a pattern, which is the common case and
    /// costs one relaxed atomic load per request to establish.
    user: Arc<ArcSwapOption<UserBotSet>>,
}

impl BotCheck {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the operator layer with `patterns`, atomically.
    ///
    /// In-flight requests keep matching against the previous snapshot and the
    /// next one picks up the new set; no request ever observes a half-built set
    /// and no request ever waits for this call. Patterns are compiled *here*,
    /// never on the request path.
    pub fn load_user_patterns(&self, mut patterns: Vec<UserBotPattern>) -> BotPatternLoadReport {
        let mut rejected = 0usize;
        if patterns.len() > MAX_USER_PATTERNS {
            let dropped = patterns.len() - MAX_USER_PATTERNS;
            tracing::warn!(
                "{} operator bot patterns configured; only the first {MAX_USER_PATTERNS} are active",
                patterns.len()
            );
            patterns.truncate(MAX_USER_PATTERNS);
            rejected += dropped;
        }

        let (allow, block): (Vec<_>, Vec<_>) = patterns.into_iter().partition(|p| p.action == BotAction::Allow);

        let allow = CompiledSide::build(allow, &mut rejected);
        let block = CompiledSide::build(block, &mut rejected);
        let loaded = allow.as_ref().map_or(0, |s| s.meta.len()) + block.as_ref().map_or(0, |s| s.meta.len());

        if allow.is_none() && block.is_none() {
            self.user.store(None);
        } else {
            self.user.store(Some(Arc::new(UserBotSet { allow, block })));
        }

        BotPatternLoadReport { loaded, rejected }
    }

    /// Number of operator patterns currently on the request path.
    pub fn user_pattern_count(&self) -> usize {
        self.user.load().as_ref().map_or(0, |u| {
            u.allow.as_ref().map_or(0, |s| s.meta.len()) + u.block.as_ref().map_or(0, |s| s.meta.len())
        })
    }

    /// Evaluate `ua` exactly the way the request path would, for the admin
    /// "test a User-Agent" tool and `prx-waf bot test`.
    ///
    /// Returns every rule id/name/action that fires, in precedence order, rather
    /// than short-circuiting — an operator debugging a false positive needs to
    /// see the built-in rule that would have caught the request as well as the
    /// whitelist that spares it.
    pub fn explain(&self, ua: &str) -> Vec<BotMatch> {
        let mut out = Vec::new();
        let guard = self.user.load();
        if let Some(user) = guard.as_ref() {
            if let Some(side) = &user.allow {
                push_side_matches(&mut out, side, ua);
            }
            if let Some(side) = &user.block {
                push_side_matches(&mut out, side, ua);
            }
        }
        if !ua.is_empty() {
            for idx in GOOD_BOT_SET.matches(ua) {
                if let Some(r) = BUILTIN_GOOD_BOTS.get(idx) {
                    out.push(BotMatch {
                        id: r.id.to_owned(),
                        name: r.name.to_owned(),
                        action: r.action,
                        builtin: true,
                    });
                }
            }
        }
        if let Some(set) = BAD_BOT_SET.as_ref() {
            for idx in set.matches(ua) {
                if let Some(r) = BUILTIN_BAD_BOTS.get(idx) {
                    out.push(BotMatch {
                        id: r.id.to_owned(),
                        name: r.name.to_owned(),
                        action: r.action,
                        builtin: true,
                    });
                }
            }
        }
        out
    }
}

/// One rule that fired during [`BotCheck::explain`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BotMatch {
    /// Rule id as it appears in detections and listings.
    pub id: String,
    /// Human-readable label.
    pub name: String,
    /// What the rule does.
    pub action: BotAction,
    /// `true` for the compiled-in catalogue, `false` for operator patterns.
    pub builtin: bool,
}

fn push_side_matches(out: &mut Vec<BotMatch>, side: &CompiledSide, ua: &str) {
    for idx in side.set.matches(ua) {
        if let Some(p) = side.meta.get(idx) {
            out.push(BotMatch {
                id: user_rule_id(p.id),
                name: p.name.clone(),
                action: p.action,
                builtin: false,
            });
        }
    }
}

/// Detection id for an operator pattern. Distinct prefix from the built-ins so a
/// security event says at a glance whose rule fired.
pub fn user_rule_id(id: i32) -> String {
    format!("BOT-USER-{id}")
}

impl Check for BotCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.bot {
            return None;
        }

        let ua = ctx.headers.get("user-agent").map_or("", String::as_str);

        // ── Operator layer ────────────────────────────────────────────────────
        // One wait-free load. `None` (no patterns configured) is the common case
        // and skips straight to the built-ins.
        let guard = self.user.load();
        if let Some(user) = guard.as_ref() {
            // Whitelist first: an explicit allow outranks every block, built-in
            // or not. Deliberately *not* gated on a non-empty UA — a pattern of
            // `^$` is how an operator exempts clients with no UA from BOT-009.
            if let Some(side) = &user.allow
                && side.set.is_match(ua)
            {
                return None;
            }
            if let Some(side) = &user.block
                && let Some(idx) = side.set.matches(ua).iter().next()
                && let Some(p) = side.meta.get(idx)
            {
                return Some(DetectionResult {
                    rule_id: Some(user_rule_id(p.id)),
                    rule_name: "Bot".to_owned(),
                    phase: Phase::Bot,
                    detail: format!("{} (operator bot pattern)", p.name),
                });
            }
        }
        drop(guard);

        // ── Built-in layer ────────────────────────────────────────────────────
        // Allow known legitimate search engines first.
        if !ua.is_empty() && GOOD_BOT_SET.matches(ua).matched_any() {
            return None;
        }

        let Some(bad_bot_set) = BAD_BOT_SET.as_ref() else {
            // Fail-closed: the pattern set failed to compile at startup.
            return Some(DetectionResult {
                rule_id: Some("BOT-000".to_owned()),
                rule_name: "Bot".to_owned(),
                phase: Phase::Bot,
                detail: "fail-closed: bad bot pattern set failed to compile at startup".to_owned(),
            });
        };

        // Block known malicious / scripted UA patterns.
        let bad_matches = bad_bot_set.matches(ua);
        if let Some(idx) = bad_matches.iter().next() {
            let hit = BUILTIN_BAD_BOTS.get(idx);
            return Some(DetectionResult {
                rule_id: Some(hit.map_or_else(|| "BOT-000".to_owned(), |r| r.id.to_owned())),
                rule_name: "Bot".to_owned(),
                phase: Phase::Bot,
                detail: format!("{} detected", hit.map_or("malicious bot", |r| r.name)),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(ua: &str) -> RequestCtx {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), ua.to_string());
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers,
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    bot: true,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    fn user(id: i32, pattern: &str, action: BotAction) -> UserBotPattern {
        UserBotPattern {
            id,
            name: format!("rule {id}"),
            pattern: pattern.to_string(),
            action,
        }
    }

    // ── Built-in behaviour (unchanged by the operator layer) ──────────────────

    #[test]
    fn allows_googlebot() {
        let checker = BotCheck::new();
        let ctx = make_ctx("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        assert!(checker.check(&ctx).is_none(), "Should allow Googlebot");
    }

    #[test]
    fn blocks_scrapy() {
        let checker = BotCheck::new();
        let ctx = make_ctx("Scrapy/2.6.1 (+https://scrapy.org)");
        let hit = checker.check(&ctx).expect("Should block Scrapy");
        assert_eq!(hit.rule_id.as_deref(), Some("BOT-001"));
    }

    #[test]
    fn blocks_headless_chrome() {
        let checker = BotCheck::new();
        let ctx = make_ctx("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/91.0.4472.114");
        assert!(checker.check(&ctx).is_some(), "Should block HeadlessChrome");
    }

    #[test]
    fn allows_regular_browser() {
        let checker = BotCheck::new();
        let ctx = make_ctx(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        );
        assert!(checker.check(&ctx).is_none(), "Should allow regular browser");
    }

    #[test]
    fn blocks_go_http_client() {
        let checker = BotCheck::new();
        let ctx = make_ctx("Go-http-client/1.1");
        assert!(checker.check(&ctx).is_some(), "Should block bare Go HTTP client");
    }

    #[test]
    fn builtin_ids_are_unique_and_positional() {
        let mut ids: Vec<&str> = BUILTIN_GOOD_BOTS.iter().chain(BUILTIN_BAD_BOTS).map(|r| r.id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate built-in bot rule id");
        assert_eq!(BUILTIN_BAD_BOTS.first().map(|r| r.id), Some("BOT-001"));
    }

    #[test]
    fn builtin_catalogue_compiles() {
        assert_eq!(GOOD_BOT_SET.len(), BUILTIN_GOOD_BOTS.len());
        assert_eq!(BAD_BOT_SET.as_ref().map(RegexSet::len), Some(BUILTIN_BAD_BOTS.len()));
    }

    // ── Operator layer ────────────────────────────────────────────────────────

    #[test]
    fn no_operator_patterns_means_no_snapshot() {
        let checker = BotCheck::new();
        assert_eq!(checker.user_pattern_count(), 0);
        let report = checker.load_user_patterns(vec![]);
        assert_eq!(report, BotPatternLoadReport { loaded: 0, rejected: 0 });
        assert_eq!(checker.user_pattern_count(), 0);
    }

    #[test]
    fn operator_block_pattern_takes_effect_without_restart() {
        let checker = BotCheck::new();
        let ctx = make_ctx("MyCustomAgent/1.0");
        assert!(checker.check(&ctx).is_none(), "not a bot before the rule is added");

        let report = checker.load_user_patterns(vec![user(7, r"(?i)MyCustomAgent", BotAction::Block)]);
        assert_eq!(report.loaded, 1);
        let hit = checker.check(&ctx).expect("blocked after the rule is added");
        assert_eq!(hit.rule_id.as_deref(), Some("BOT-USER-7"));
        assert!(hit.detail.contains("rule 7"));
    }

    #[test]
    fn removing_the_last_operator_pattern_restores_the_previous_verdict() {
        let checker = BotCheck::new();
        let ctx = make_ctx("MyCustomAgent/1.0");
        checker.load_user_patterns(vec![user(7, r"(?i)MyCustomAgent", BotAction::Block)]);
        assert!(checker.check(&ctx).is_some());
        checker.load_user_patterns(vec![]);
        assert!(checker.check(&ctx).is_none(), "rule removal must take effect");
        assert_eq!(checker.user_pattern_count(), 0);
    }

    #[test]
    fn operator_allow_beats_builtin_block() {
        let checker = BotCheck::new();
        let ctx = make_ctx("Friendly Spider/2.0");
        assert!(checker.check(&ctx).is_some(), "BOT-007 catches 'spider'");
        checker.load_user_patterns(vec![user(1, r"(?i)Friendly Spider", BotAction::Allow)]);
        assert!(checker.check(&ctx).is_none(), "operator allow must win");
    }

    #[test]
    fn operator_block_beats_builtin_allow() {
        let checker = BotCheck::new();
        let ctx = make_ctx("Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert!(checker.check(&ctx).is_none());
        checker.load_user_patterns(vec![user(2, r"(?i)googlebot", BotAction::Block)]);
        let hit = checker
            .check(&ctx)
            .expect("operator block must win over the good-bot bypass");
        assert_eq!(hit.rule_id.as_deref(), Some("BOT-USER-2"));
    }

    #[test]
    fn operator_allow_can_exempt_an_empty_user_agent() {
        let checker = BotCheck::new();
        let ctx = make_ctx("");
        assert!(checker.check(&ctx).is_some(), "BOT-009 blocks an empty UA");
        checker.load_user_patterns(vec![user(3, r"^$", BotAction::Allow)]);
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn operator_allow_wins_when_both_sides_match() {
        let checker = BotCheck::new();
        let ctx = make_ctx("DualAgent/1.0");
        checker.load_user_patterns(vec![
            user(4, r"(?i)DualAgent", BotAction::Block),
            user(5, r"(?i)DualAgent", BotAction::Allow),
        ]);
        assert!(checker.check(&ctx).is_none(), "allow outranks block");
    }

    // ── Validation ────────────────────────────────────────────────────────────

    #[test]
    fn rejects_syntactically_invalid_patterns() {
        let err = validate_user_pattern(r"(?i)[unclosed").expect_err("must reject");
        assert!(matches!(err, BotPatternError::Invalid(_)), "{err}");
        assert!(err.to_string().contains("invalid regular expression"));
    }

    #[test]
    fn rejects_empty_and_oversized_patterns() {
        assert_eq!(validate_user_pattern("   "), Err(BotPatternError::Empty));
        let long = "a".repeat(MAX_USER_PATTERN_LEN + 1);
        assert_eq!(
            validate_user_pattern(&long),
            Err(BotPatternError::TooLong(MAX_USER_PATTERN_LEN + 1))
        );
    }

    #[test]
    fn rejects_patterns_that_blow_the_compile_budget() {
        // Linear-time to match, but the compiled program is enormous. This is
        // the shape a `regex`-based WAF actually has to defend against.
        let err = validate_user_pattern(r"((((a{100}){100}){100}){100})").expect_err("must reject");
        assert!(matches!(err, BotPatternError::Invalid(_)), "{err}");
    }

    #[test]
    fn an_unusable_stored_pattern_is_skipped_not_fatal() {
        let checker = BotCheck::new();
        let report = checker.load_user_patterns(vec![
            user(1, r"(?i)[unclosed", BotAction::Block),
            user(2, r"(?i)GoodPattern", BotAction::Block),
        ]);
        assert_eq!(report, BotPatternLoadReport { loaded: 1, rejected: 1 });
        assert!(checker.check(&make_ctx("GoodPattern/1")).is_some());
    }

    #[test]
    fn pattern_count_is_capped() {
        let checker = BotCheck::new();
        let patterns: Vec<UserBotPattern> = (0..i32::try_from(MAX_USER_PATTERNS).unwrap_or(i32::MAX) + 10)
            .map(|i| user(i, &format!(r"(?i)agent{i}\b"), BotAction::Block))
            .collect();
        let report = checker.load_user_patterns(patterns);
        assert_eq!(report.loaded, MAX_USER_PATTERNS);
        assert_eq!(report.rejected, 10);
    }

    #[test]
    fn action_round_trips_and_refuses_unimplemented_ones() {
        assert_eq!(BotAction::parse("block"), Some(BotAction::Block));
        assert_eq!(BotAction::parse("allow"), Some(BotAction::Allow));
        assert_eq!(BotAction::parse("log"), None);
        assert_eq!(BotAction::parse("captcha"), None);
        assert_eq!(BotAction::Block.as_str(), "block");
    }

    // ── explain() ─────────────────────────────────────────────────────────────

    #[test]
    fn explain_reports_builtin_and_operator_matches_in_precedence_order() {
        let checker = BotCheck::new();
        checker.load_user_patterns(vec![user(9, r"(?i)Friendly Spider", BotAction::Allow)]);
        let matches = checker.explain("Friendly Spider/2.0");
        assert_eq!(matches.len(), 2, "{matches:?}");
        assert_eq!(matches.first().map(|m| m.id.as_str()), Some("BOT-USER-9"));
        assert_eq!(matches.first().map(|m| m.builtin), Some(false));
        assert_eq!(matches.get(1).map(|m| m.id.as_str()), Some("BOT-007"));
        assert_eq!(matches.get(1).map(|m| m.builtin), Some(true));
    }

    #[test]
    fn explain_on_a_clean_user_agent_is_empty() {
        let checker = BotCheck::new();
        assert!(checker.explain("Mozilla/5.0 (Macintosh) Safari/605.1").is_empty());
    }

    #[test]
    fn disabled_defense_short_circuits() {
        let checker = BotCheck::new();
        checker.load_user_patterns(vec![user(1, r"(?i)Scrapy", BotAction::Block)]);
        let mut ctx = make_ctx("Scrapy/2.6.1");
        ctx.host_config = Arc::new(HostConfig {
            defense_config: DefenseConfig {
                bot: false,
                ..DefenseConfig::default()
            },
            ..HostConfig::default()
        });
        assert!(checker.check(&ctx).is_none());
    }
}
