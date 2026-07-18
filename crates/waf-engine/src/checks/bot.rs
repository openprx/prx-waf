use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

/// Known search-engine / legitimate crawlers — these are allowed through.
///
/// Unlike `BAD_BOT_SET` below, a compile failure here is *already*
/// fail-closed as an empty set (Low-1): this set only grants a bypass
/// (`matched_any()` → allow), so falling back to `RegexSet::empty()` means
/// "never match" → never grant the allow-list bypass → the request still
/// falls through to `BAD_BOT_SET` / the rest of the pipeline. No behavior
/// change needed for this particular set.
static GOOD_BOT_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    match RegexSet::new([
        r"(?i)\bgooglebot\b",
        r"(?i)\bbingbot\b",
        r"(?i)\bslurp\b", // Yahoo
        r"(?i)\bduckduckbot\b",
        r"(?i)\bbaiduspider\b",
        r"(?i)\byandexbot\b",
        r"(?i)\bsogou\b",
        r"(?i)\bexabot\b",
        r"(?i)\bfacebot\b",     // Facebook
        r"(?i)\bia_archiver\b", // Wayback Machine
        r"(?i)\btwitterbot\b",
        r"(?i)\bLinkedInBot\b",
        r"(?i)\bAppleBot\b",
        r"(?i)\bDuckDuckGo\b",
        r"(?i)\bSemrushBot\b",
        r"(?i)\bAhrefsBot\b",
        r"(?i)Googlebot-Image",
        r"(?i)Googlebot-News",
        r"(?i)Googlebot-Video",
    ]) {
        Ok(set) => set,
        Err(e) => {
            tracing::error!("BUG: good bot regex set failed to compile: {e}");
            RegexSet::empty()
        }
    }
});

/// Malicious / suspicious bot signatures.
static BAD_BOT_DESCS: &[&str] = &[
    "Scrapy web scraper",
    "zgrab banner grabber",
    "Masscan port scanner",
    "headless browser (Headless Chrome / Puppeteer)",
    "PhantomJS headless browser",
    "Selenium WebDriver",
    "generic crawler/spider/scraper UA",
    "harvester / extractor tool",
    "empty User-Agent (no UA string)",
    "Python urllib (scripted access)",
    "Java HTTP client (scripted access)",
    "Ruby Net::HTTP (scripted access)",
    "Go standard HTTP client",
];

/// Fail-closed compile result (Low-1): see the equivalent comment in
/// `sql_injection.rs` for the full rationale. `None` means the pattern set
/// failed to compile; `check()` then treats every request as a match
/// (fail-closed, i.e. blocked as a bad bot) instead of falling back to
/// `RegexSet::empty()`, which would match nothing and fail open.
static BAD_BOT_SET: LazyLock<Option<RegexSet>> = LazyLock::new(|| {
    match RegexSet::new([
        r"(?i)\bscrapy\b",
        r"(?i)\bzgrab\b",
        r"(?i)\bmasscan\b",
        r"(?i)(headlesschrome|headless[\s_-]?chrome|puppeteer)",
        r"(?i)\bphantomjs\b",
        r"(?i)(selenium|webdriver)",
        r"(?i)\b(crawler|spider|scraper)\b",
        r"(?i)\b(harvest|extractor)\b",
        // empty UA handled separately below
        r"^$",
        r"(?i)^python-urllib/",
        r"(?i)^Java/",
        r"(?i)^Ruby$|^Ruby/",
        r"(?i)^Go-http-client/",
    ]) {
        Ok(set) => Some(set),
        Err(e) => {
            tracing::error!(
                "BUG: bad bot regex set failed to compile: {e} — failing closed \
                 (this checker will now flag every request as a bad bot until the code is fixed)"
            );
            None
        }
    }
});

/// Bot detection checker.
///
/// - Known good search-engine bots → allow (return `None`)
/// - Known malicious / scripted bots → block
/// - All others → pass through
pub struct BotCheck;

impl BotCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for BotCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for BotCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.bot {
            return None;
        }

        let ua = ctx.headers.get("user-agent").map_or("", String::as_str);

        // Allow known legitimate search engines first.
        if !ua.is_empty() && GOOD_BOT_SET.matches(ua).matched_any() {
            return None;
        }

        let Some(bad_bot_set) = BAD_BOT_SET.as_ref() else {
            // Fail-closed: the pattern set failed to compile at startup.
            return Some(DetectionResult {
                rule_id: Some("BOT-000".to_string()),
                rule_name: "Bot".to_string(),
                phase: Phase::Bot,
                detail: "fail-closed: bad bot pattern set failed to compile at startup".to_string(),
            });
        };

        // Block known malicious / scripted UA patterns.
        let bad_matches = bad_bot_set.matches(ua);
        if bad_matches.matched_any() {
            let idx = bad_matches.iter().next().unwrap_or(0);
            let desc = BAD_BOT_DESCS.get(idx).copied().unwrap_or("malicious bot");
            return Some(DetectionResult {
                rule_id: Some(format!("BOT-{:03}", idx + 1)),
                rule_name: "Bot".to_string(),
                phase: Phase::Bot,
                detail: format!("{desc} detected"),
            });
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
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
        assert!(checker.check(&ctx).is_some(), "Should block Scrapy");
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
}
