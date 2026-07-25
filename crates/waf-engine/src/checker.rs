use std::borrow::Cow;
use std::sync::Arc;
use tracing::{debug, info};

use waf_common::{DetectionResult, Phase, RequestCtx, WafAction, WafDecision};
use waf_storage::Database;

use crate::checks::{MAX_DECODE_PASSES, url_decode};
use crate::rules::{IpRuleSet, UrlMatchType, UrlRule, UrlRuleSet};

/// In-memory rule store backed by `PostgreSQL`
pub struct RuleStore {
    pub allow_ips: Arc<IpRuleSet>,
    pub block_ips: Arc<IpRuleSet>,
    /// Threat-intelligence IP blocklist populated by the IP-feed adapter
    /// (ET Open / Tor / Spamhaus …). Kept separate from `block_ips` because it
    /// is fed by the background feed sync task rather than the database: the
    /// database reload path ([`Self::reload_all`]) must not prune it, and each
    /// bucket is keyed by feed name for per-source replacement and cleanup.
    /// Every entry is globally applicable (see [`IpRuleSet::match_source`]).
    pub feed_block_ips: Arc<IpRuleSet>,
    pub allow_urls: Arc<UrlRuleSet>,
    pub block_urls: Arc<UrlRuleSet>,
    db: Arc<Database>,
}

impl RuleStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            allow_ips: Arc::new(IpRuleSet::new()),
            block_ips: Arc::new(IpRuleSet::new()),
            feed_block_ips: Arc::new(IpRuleSet::new()),
            allow_urls: Arc::new(UrlRuleSet::new()),
            block_urls: Arc::new(UrlRuleSet::new()),
            db,
        }
    }

    /// Load all rules from database into memory using atomic swap.
    ///
    /// Instead of clearing rules first (which creates a window where all rules
    /// are empty), this method:
    /// 1. Loads all data from DB into temporary rule sets (no live mutation)
    /// 2. Swaps each live rule set from the temporary one (overwrite + prune)
    ///
    /// This eliminates the "rule gap" where blacklist/whitelist rules are empty
    /// during the reload window.
    pub async fn reload_all(&self) -> anyhow::Result<()> {
        info!("Reloading WAF rules from database");

        // Phase 1: Load all rules from DB (no memory modification yet)
        let allow_ip_rows = self.db.list_allow_ips(None).await?;
        let block_ip_rows = self.db.list_block_ips(None).await?;
        let allow_url_rows = self.db.list_allow_urls(None).await?;
        let block_url_rows = self.db.list_block_urls(None).await?;

        // Phase 2: Build temporary rule sets (in-memory only, very fast)
        let new_allow_ips = IpRuleSet::new();
        Self::populate_ip_rules(&new_allow_ips, &allow_ip_rows, |row| (&row.host_code, &row.ip_cidr));

        let new_block_ips = IpRuleSet::new();
        Self::populate_ip_rules(&new_block_ips, &block_ip_rows, |row| (&row.host_code, &row.ip_cidr));

        let new_allow_urls = UrlRuleSet::new();
        Self::populate_url_rules(&new_allow_urls, &allow_url_rows, |row| {
            (
                &row.host_code,
                UrlRule {
                    id: row.id.to_string(),
                    pattern: row.url_pattern.clone(),
                    match_type: UrlMatchType::parse_str(&row.match_type),
                },
            )
        });

        let new_block_urls = UrlRuleSet::new();
        Self::populate_url_rules(&new_block_urls, &block_url_rows, |row| {
            (
                &row.host_code,
                UrlRule {
                    id: row.id.to_string(),
                    pattern: row.url_pattern.clone(),
                    match_type: UrlMatchType::parse_str(&row.match_type),
                },
            )
        });

        // Phase 3: Atomic swap — overwrite live sets from temporaries, then prune
        // No IO involved; only fast in-memory DashMap operations
        self.allow_ips.swap_from(&new_allow_ips);
        self.block_ips.swap_from(&new_block_ips);
        self.allow_urls.swap_from(&new_allow_urls);
        self.block_urls.swap_from(&new_block_urls);

        info!(
            "Rules loaded: allow_ips={}, block_ips={}, allow_urls={}, block_urls={}",
            self.allow_ips.len(),
            self.block_ips.len(),
            self.allow_urls.len(),
            self.block_urls.len(),
        );

        Ok(())
    }

    /// Populate an `IpRuleSet` from database rows.
    ///
    /// The `extract` closure maps each row to `(host_code, ip_cidr)`.
    fn populate_ip_rules<T, F>(target: &IpRuleSet, rows: &[T], extract: F)
    where
        F: Fn(&T) -> (&str, &str),
    {
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<String>> = HashMap::new();
        for row in rows {
            let (host_code, ip_cidr) = extract(row);
            map.entry(host_code).or_default().push(ip_cidr.to_string());
        }
        for (code, cidrs) in map {
            target.load(code, &cidrs);
        }
    }

    /// Populate a `UrlRuleSet` from database rows.
    ///
    /// The `extract` closure maps each row to `(host_code, UrlRule)`.
    fn populate_url_rules<T, F>(target: &UrlRuleSet, rows: &[T], extract: F)
    where
        F: Fn(&T) -> (&str, UrlRule),
    {
        use std::collections::HashMap;
        let mut map: HashMap<&str, Vec<UrlRule>> = HashMap::new();
        for row in rows {
            let (host_code, rule) = extract(row);
            map.entry(host_code).or_default().push(rule);
        }
        for (code, rules) in map {
            target.load(code, rules);
        }
    }

    /// Reload rules for a specific host using load-then-swap pattern.
    ///
    /// All DB queries complete before any live mutation. Then each rule set
    /// is updated with a single `load()` call (which overwrites the host key
    /// in the underlying `DashMap`), so the window is minimal.
    pub async fn reload_host(&self, host_code: &str) -> anyhow::Result<()> {
        debug!("Reloading rules for host: {}", host_code);

        // Phase 1: Load all data from DB (no live mutation yet)
        let allow_ip_rows = self.db.list_allow_ips(Some(host_code)).await?;
        let block_ip_rows = self.db.list_block_ips(Some(host_code)).await?;
        let allow_url_rows = self.db.list_allow_urls(Some(host_code)).await?;
        let block_url_rows = self.db.list_block_urls(Some(host_code)).await?;

        // Phase 2: Build rule data in memory
        let allow_cidrs: Vec<String> = allow_ip_rows.iter().map(|r| r.ip_cidr.clone()).collect();
        let block_cidrs: Vec<String> = block_ip_rows.iter().map(|r| r.ip_cidr.clone()).collect();
        let allow_rules: Vec<UrlRule> = allow_url_rows
            .iter()
            .map(|r| UrlRule {
                id: r.id.to_string(),
                pattern: r.url_pattern.clone(),
                match_type: UrlMatchType::parse_str(&r.match_type),
            })
            .collect();
        let block_rules: Vec<UrlRule> = block_url_rows
            .iter()
            .map(|r| UrlRule {
                id: r.id.to_string(),
                pattern: r.url_pattern.clone(),
                match_type: UrlMatchType::parse_str(&r.match_type),
            })
            .collect();

        // Phase 3: Swap — load() overwrites the host key atomically in DashMap
        // For empty result sets, clear the host key instead
        if allow_cidrs.is_empty() {
            self.allow_ips.clear_host(host_code);
        } else {
            self.allow_ips.load(host_code, &allow_cidrs);
        }

        if block_cidrs.is_empty() {
            self.block_ips.clear_host(host_code);
        } else {
            self.block_ips.load(host_code, &block_cidrs);
        }

        if allow_rules.is_empty() {
            self.allow_urls.clear_host(host_code);
        } else {
            self.allow_urls.load(host_code, allow_rules);
        }

        if block_rules.is_empty() {
            self.block_urls.clear_host(host_code);
        } else {
            self.block_urls.load(host_code, block_rules);
        }

        Ok(())
    }
}

// ─── Path canonicalisation ────────────────────────────────────────────────────
//
// URL rules are matched against a *decoded* path, but nothing used to remove
// dot-segments, so `/static/..%2f..%2f..%2fetc/passwd` single-decoded to
// `/static/../../../etc/passwd`, still started with `/static`, and matched a
// `/static` whitelist prefix — while the origin resolved the very same request
// to `/etc/passwd`. Detection and origin must agree on what the path *is*,
// which is what the helpers below establish.

/// Apply RFC 3986 §5.2.4 `remove_dot_segments` to a path and collapse empty
/// segments (`//`), yielding the path an origin actually resolves.
///
/// Borrows when the input is already canonical, so the common case allocates
/// nothing.
pub(crate) fn remove_dot_segments(path: &str) -> Cow<'_, str> {
    // Fast path: no dot-segment and no empty segment can be present.
    if !path.contains("./") && !path.contains("//") && !path.ends_with('.') {
        return Cow::Borrowed(path);
    }

    let absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    // Whether the resolved path keeps a trailing slash (`/a/b/`, `/a/.`, `/a/..`).
    let mut trailing_slash = false;
    for segment in path.split('/') {
        match segment {
            // Empty segments come from a leading, trailing or doubled slash.
            "" | "." => trailing_slash = true,
            ".." => {
                // Excess `..` at the root is discarded, as RFC 3986 requires.
                let _ = out.pop();
                trailing_slash = true;
            }
            other => {
                out.push(other);
                trailing_slash = false;
            }
        }
    }

    let mut resolved = String::with_capacity(path.len());
    if absolute {
        resolved.push('/');
    }
    for (i, segment) in out.iter().enumerate() {
        if i > 0 {
            resolved.push('/');
        }
        resolved.push_str(segment);
    }
    if trailing_slash && !resolved.ends_with('/') {
        resolved.push('/');
    }

    if resolved == path {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(resolved)
    }
}

/// Percent-decode repeatedly until the value stops changing.
///
/// Bounded by [`MAX_DECODE_PASSES`] so a crafted deeply re-encoded path cannot
/// force unbounded per-request work.
fn decode_recursive(path: &str) -> Cow<'_, str> {
    let mut current = Cow::Borrowed(path);
    for _ in 0..MAX_DECODE_PASSES {
        let next = url_decode(&current);
        if next == *current {
            break;
        }
        current = Cow::Owned(next);
    }
    current
}

/// Like [`decode_recursive`] but reports non-termination: `None` when the value
/// was still changing after [`MAX_DECODE_PASSES`] passes, i.e. residual
/// encoding remains and the true path is unknown.
fn decode_until_stable(path: &str) -> Option<Cow<'_, str>> {
    let mut current = Cow::Borrowed(path);
    for _ in 0..MAX_DECODE_PASSES {
        let next = url_decode(&current);
        if next == *current {
            return Some(current);
        }
        current = Cow::Owned(next);
    }
    None
}

/// Fully decoded, dot-segment-free form of a request path.
///
/// Used as an **additional** matching form for deny rules: normalising can only
/// add matches, never remove them, so this is always safe to try.
pub(crate) fn normalized_path(path: &str) -> Cow<'_, str> {
    let decoded = decode_recursive(path);
    match remove_dot_segments(&decoded) {
        Cow::Borrowed(_) => decoded,
        Cow::Owned(resolved) => Cow::Owned(resolved),
    }
}

/// Canonical path used for **allow** (whitelist) matching, or `None` when the
/// request path is structurally ambiguous.
///
/// An allow rule disables detection, so it may only be applied to a path whose
/// meaning the WAF and the origin are guaranteed to agree on. A path is
/// therefore rejected as a whitelist candidate when:
///
/// * percent-decoding does not stabilise within [`MAX_DECODE_PASSES`] passes;
/// * decoding changes the number of `/` separators — i.e. the request smuggled
///   an encoded slash (`%2f`), so the origin may treat the path as one segment
///   while the WAF sees several;
/// * the decoded path contains a backslash or a control character (alternate
///   separators / terminators that origins interpret inconsistently);
/// * dot-segments or empty segments survive decoding, so the resolved path
///   differs from the requested one (`/static/../../etc/passwd`).
///
/// Encoded *characters* are still accepted (`/%61dmin` → `/admin`, the M-6
/// behaviour): they change the spelling, never the structure. Every rejected
/// path simply falls through to the full detection pipeline — the safe
/// direction.
pub(crate) fn whitelist_path(path: &str) -> Option<Cow<'_, str>> {
    let decoded = decode_until_stable(path)?;

    if decoded.matches('/').count() != path.matches('/').count() {
        return None;
    }
    if decoded.bytes().any(|b| b < 0x20 || b == b'\\' || b == 0x7f) {
        return None;
    }
    if remove_dot_segments(&decoded).as_ref() != decoded.as_ref() {
        return None;
    }

    Some(decoded)
}

/// Match a path against an allow rule set using the canonical path only.
pub(crate) fn match_url_whitelist(rules: &UrlRuleSet, host_code: &str, path: &str) -> Option<String> {
    let candidate = whitelist_path(path)?;
    rules.matches(host_code, &candidate)
}

/// Match a path against a deny rule set in every form an origin might resolve:
/// raw, single-decoded (M-6) and fully normalised.
pub(crate) fn match_url_blacklist(rules: &UrlRuleSet, host_code: &str, path: &str) -> Option<String> {
    if let Some(rule_id) = rules.matches(host_code, path) {
        return Some(rule_id);
    }

    let decoded = url_decode(path);
    if decoded != path
        && let Some(rule_id) = rules.matches(host_code, &decoded)
    {
        return Some(rule_id);
    }

    let normalized = normalized_path(path);
    if normalized.as_ref() != path && normalized.as_ref() != decoded.as_str() {
        return rules.matches(host_code, &normalized);
    }

    None
}

/// Run Phase 1 WAF check: IP whitelist
/// If the IP is whitelisted, allow immediately (skip further checks)
pub fn check_ip_whitelist(ctx: &RequestCtx, store: &RuleStore) -> WafDecision {
    let host_code = &ctx.host_config.code;

    if store.allow_ips.matches(host_code, ctx.client_ip) {
        debug!("IP {} whitelisted for host {}", ctx.client_ip, host_code);
        return WafDecision {
            action: WafAction::Allow,
            result: Some(DetectionResult {
                rule_id: None,
                rule_name: "IP Whitelist".to_string(),
                phase: Phase::IpWhitelist,
                detail: format!("IP {} matched whitelist", ctx.client_ip),
            }),
        };
    }

    WafDecision::allow()
}

/// Run Phase 2 WAF check: IP blacklist
pub fn check_ip_blacklist(ctx: &RequestCtx, store: &RuleStore) -> WafDecision {
    let host_code = &ctx.host_config.code;

    if store.block_ips.matches(host_code, ctx.client_ip) {
        debug!("IP {} blocked for host {}", ctx.client_ip, host_code);
        return WafDecision::block(
            403,
            Some("Access denied.".to_string()),
            DetectionResult {
                rule_id: None,
                rule_name: "IP Blacklist".to_string(),
                phase: Phase::IpBlacklist,
                detail: format!("IP {} matched blacklist", ctx.client_ip),
            },
        );
    }

    // Threat-intelligence IP feeds (global, source-tagged). Checked after the
    // admin blacklist so an explicit rule's detail wins; the matched feed name
    // is surfaced for traceability.
    if let Some(source) = store.feed_block_ips.match_source(ctx.client_ip) {
        debug!("IP {} blocked by threat feed '{}'", ctx.client_ip, source);
        return WafDecision::block(
            403,
            Some("Access denied.".to_string()),
            DetectionResult {
                rule_id: None,
                rule_name: "IP Blacklist (Threat Feed)".to_string(),
                phase: Phase::IpBlacklist,
                detail: format!("IP {} matched threat-intel feed '{source}'", ctx.client_ip),
            },
        );
    }

    WafDecision::allow()
}

/// Run Phase 3 WAF check: URL whitelist
///
/// Matching uses the **canonical** path (see [`whitelist_path`]): fully decoded
/// and dot-segment free, and only when decoding cannot have changed the path's
/// structure. An encoded request such as `/%61dmin` is still whitelisted
/// consistently with its canonical form `/admin` (M-6), while
/// `/static/..%2f..%2fetc/passwd` no longer matches a `/static` prefix rule.
///
/// A match does **not** allow the request outright — see
/// [`crate::WafEngine::inspect_with_state`], where the allow decision is held
/// back until the client-scoped phases (reputation, geo, rate limit) have run.
pub fn check_url_whitelist(ctx: &RequestCtx, store: &RuleStore) -> Option<WafDecision> {
    let host_code = &ctx.host_config.code;

    if let Some(rule_id) = match_url_whitelist(&store.allow_urls, host_code, &ctx.path) {
        debug!("URL {} whitelisted for host {}", ctx.path, host_code);
        return Some(WafDecision {
            action: WafAction::Allow,
            result: Some(DetectionResult {
                rule_id: Some(rule_id),
                rule_name: "URL Whitelist".to_string(),
                phase: Phase::UrlWhitelist,
                detail: format!("Path {} matched URL whitelist", ctx.path),
            }),
        });
    }

    None
}

/// Run Phase 4 WAF check: URL blacklist.
///
/// Matching is attempted against the **raw**, the **decoded** (M-6) and the
/// fully **normalised** path, so neither encoding tricks such as `/%61dmin` nor
/// dot-segment tricks such as `/x/..%2fadmin` can bypass an `/admin` rule.
pub fn check_url_blacklist(ctx: &RequestCtx, store: &RuleStore) -> WafDecision {
    let host_code = &ctx.host_config.code;

    if let Some(rule_id) = match_url_blacklist(&store.block_urls, host_code, &ctx.path) {
        debug!("URL {} blocked for host {}", ctx.path, host_code);
        return WafDecision::block(
            403,
            Some("Access denied.".to_string()),
            DetectionResult {
                rule_id: Some(rule_id),
                rule_name: "URL Blacklist".to_string(),
                phase: Phase::UrlBlacklist,
                detail: format!("Path {} matched URL blacklist", ctx.path),
            },
        );
    }

    WafDecision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "h1";

    fn rule_set(pattern: &str, match_type: UrlMatchType) -> UrlRuleSet {
        let set = UrlRuleSet::new();
        set.load(
            HOST,
            vec![UrlRule {
                id: "r1".to_string(),
                pattern: pattern.to_string(),
                match_type,
            }],
        );
        set
    }

    // ── remove_dot_segments (RFC 3986 §5.2.4) ────────────────────────────────

    #[test]
    fn dot_segments_are_resolved() {
        assert_eq!(remove_dot_segments("/static/../../../etc/passwd"), "/etc/passwd");
        assert_eq!(remove_dot_segments("/a/b/../c"), "/a/c");
        assert_eq!(remove_dot_segments("/a/./b"), "/a/b");
        assert_eq!(remove_dot_segments("/a//b"), "/a/b");
        assert_eq!(remove_dot_segments("/a/b/"), "/a/b/");
        assert_eq!(remove_dot_segments("/a/b/.."), "/a/");
        assert_eq!(remove_dot_segments("/"), "/");
        // Already canonical paths are borrowed, not rebuilt.
        assert!(matches!(remove_dot_segments("/static/app.js"), Cow::Borrowed(_)));
        assert_eq!(remove_dot_segments("/static/app.js"), "/static/app.js");
        // A dot inside a segment name is not a dot-segment.
        assert_eq!(
            remove_dot_segments("/.well-known/acme-challenge/x"),
            "/.well-known/acme-challenge/x"
        );
        assert_eq!(remove_dot_segments("/a/..b/c"), "/a/..b/c");
    }

    // ── Bypass 2: whitelist short-circuit + missing normalisation ────────────

    /// Attack scenario: with a `/static` prefix whitelist configured, the
    /// classic encoded-traversal probe must NOT be whitelisted — pre-fix it
    /// single-decoded to `/static/../../../etc/passwd`, still started with
    /// `/static`, and skipped every detection phase while the origin resolved
    /// the request to `/etc/passwd`.
    #[test]
    fn encoded_traversal_is_not_whitelisted_by_a_static_prefix() {
        let allow = rule_set("/static", UrlMatchType::Prefix);
        let attack = "/static/..%2f..%2f..%2fetc/passwd";

        assert_eq!(
            match_url_whitelist(&allow, HOST, attack),
            None,
            "encoded traversal was allowed through the /static whitelist"
        );
        // The path the origin actually resolves, for the record.
        assert_eq!(normalized_path(attack), "/etc/passwd");
        // The plain (unencoded) and double-encoded spellings are refused too.
        assert_eq!(match_url_whitelist(&allow, HOST, "/static/../../etc/passwd"), None);
        assert_eq!(
            match_url_whitelist(&allow, HOST, "/static/..%252f..%252fetc/passwd"),
            None
        );
        assert_eq!(
            match_url_whitelist(&allow, HOST, "/static/%2e%2e/%2e%2e/etc/passwd"),
            None
        );
    }

    /// Negative control: ordinary traffic under the whitelisted prefix — and
    /// the documented M-6 encoded-spelling case — still match.
    #[test]
    fn ordinary_paths_still_match_the_whitelist() {
        let allow = rule_set("/static", UrlMatchType::Prefix);
        assert_eq!(
            match_url_whitelist(&allow, HOST, "/static/app.js").as_deref(),
            Some("r1")
        );
        assert_eq!(
            match_url_whitelist(&allow, HOST, "/static/css/site.css").as_deref(),
            Some("r1")
        );
        // Percent-encoded *characters* change spelling, not structure (M-6).
        assert_eq!(
            match_url_whitelist(&allow, HOST, "/%73tatic/app.js").as_deref(),
            Some("r1")
        );
        // Unrelated paths still do not match.
        assert_eq!(match_url_whitelist(&allow, HOST, "/api/users"), None);
    }

    #[test]
    fn structurally_ambiguous_paths_are_never_whitelist_candidates() {
        // Encoded separator: the origin may treat this as one segment.
        assert_eq!(whitelist_path("/static%2fapp.js"), None);
        // Backslash and control characters.
        assert_eq!(whitelist_path("/static\\..\\etc"), None);
        assert_eq!(whitelist_path("/static/%00.js"), None);
        // Decoding that never stabilises within the pass budget.
        assert_eq!(whitelist_path("/%25%32%35%32%66"), None);
        // Canonical paths are accepted and returned decoded.
        assert_eq!(whitelist_path("/static/app.js").as_deref(), Some("/static/app.js"));
        assert_eq!(whitelist_path("/%61dmin").as_deref(), Some("/admin"));
    }

    // ── Deny-side normalisation ──────────────────────────────────────────────

    #[test]
    fn blacklist_matches_normalised_and_encoded_forms() {
        let block = rule_set("/admin", UrlMatchType::Prefix);
        assert_eq!(match_url_blacklist(&block, HOST, "/admin/index").as_deref(), Some("r1"));
        // Encoded spelling (M-6) and dot-segment detour both still match.
        assert_eq!(match_url_blacklist(&block, HOST, "/%61dmin").as_deref(), Some("r1"));
        assert_eq!(
            match_url_blacklist(&block, HOST, "/x/..%2fadmin/index").as_deref(),
            Some("r1")
        );
        assert_eq!(
            match_url_blacklist(&block, HOST, "/public/../admin").as_deref(),
            Some("r1")
        );
        // Negative control: unrelated traffic is untouched.
        assert_eq!(match_url_blacklist(&block, HOST, "/public/index.html"), None);
    }
}
