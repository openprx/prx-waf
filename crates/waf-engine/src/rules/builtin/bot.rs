//! Built-in bot detection rules.
//!
//! Covers:
//! - Known good bots (search engines) — tagged allow
//! - Known bad bots (scrapers, spam, headless browsers) — tagged block
//! - AI crawlers (`GPTBot`, `Claude-Web`, `CCBot`, etc.) — tagged block by default
//! - Behavior indicators (empty UA, scripted HTTP clients)

use super::super::registry::Rule;
use std::collections::HashMap;

fn rule(id: &str, name: &str, pattern: &str, action: &str, severity: &str, tags: &[&str]) -> Rule {
    let mut meta = HashMap::new();
    meta.insert("ua_pattern".to_string(), pattern.to_string());
    Rule {
        id: id.to_string(),
        name: name.to_string(),
        description: Some(name.to_string()),
        category: "bot".to_string(),
        source: "builtin-bot".to_string(),
        enabled: true,
        action: action.to_string(),
        severity: Some(severity.to_string()),
        pattern: Some(pattern.to_string()),
        tags: tags.iter().copied().map(ToString::to_string).collect(),
        metadata: meta,
    }
}

/// Return the built-in bot detection rules.
pub fn rules() -> Vec<Rule> {
    vec![
        // ── Known good bots (allow) ────────────────────────────────────────────
        rule(
            "BOT-GOOD-001",
            "Googlebot",
            r"(?i)\bgooglebot\b",
            "allow",
            "low",
            &["good-bot", "search-engine"],
        ),
        rule(
            "BOT-GOOD-002",
            "Bingbot",
            r"(?i)\bbingbot\b",
            "allow",
            "low",
            &["good-bot", "search-engine"],
        ),
        rule(
            "BOT-GOOD-003",
            "DuckDuckBot",
            r"(?i)\bduckduckbot\b",
            "allow",
            "low",
            &["good-bot", "search-engine"],
        ),
        rule(
            "BOT-GOOD-004",
            "Baiduspider",
            r"(?i)\bbaiduspider\b",
            "allow",
            "low",
            &["good-bot", "search-engine"],
        ),
        rule(
            "BOT-GOOD-005",
            "YandexBot",
            r"(?i)\byandexbot\b",
            "allow",
            "low",
            &["good-bot", "search-engine"],
        ),
        rule(
            "BOT-GOOD-006",
            "AppleBot",
            r"(?i)\bapplebot\b",
            "allow",
            "low",
            &["good-bot"],
        ),
        rule(
            "BOT-GOOD-007",
            "FacebookBot (facebot)",
            r"(?i)\bfacebot\b",
            "allow",
            "low",
            &["good-bot"],
        ),
        rule(
            "BOT-GOOD-008",
            "Wayback Machine (ia_archiver)",
            r"(?i)\bia_archiver\b",
            "allow",
            "low",
            &["good-bot"],
        ),
        // ── AI crawlers (block by default) ────────────────────────────────────
        rule(
            "BOT-AI-001",
            "OpenAI GPTBot",
            r"(?i)\bgptbot\b",
            "block",
            "medium",
            &["ai-crawler", "openai"],
        ),
        rule(
            "BOT-AI-002",
            "ChatGPT-User",
            r"(?i)\bchatgpt-user\b",
            "block",
            "medium",
            &["ai-crawler", "openai"],
        ),
        rule(
            "BOT-AI-003",
            "Claude-Web (Anthropic)",
            r"(?i)\bclaude-web\b",
            "block",
            "medium",
            &["ai-crawler", "anthropic"],
        ),
        rule(
            "BOT-AI-004",
            "CCBot (Common Crawl)",
            r"(?i)\bccbot\b",
            "block",
            "medium",
            &["ai-crawler"],
        ),
        rule(
            "BOT-AI-005",
            "Bytespider (ByteDance)",
            r"(?i)\bbytespider\b",
            "block",
            "medium",
            &["ai-crawler", "bytedance"],
        ),
        rule(
            "BOT-AI-006",
            "Applebot-Extended",
            r"(?i)\bapplebot-extended\b",
            "block",
            "medium",
            &["ai-crawler"],
        ),
        rule(
            "BOT-AI-007",
            "Google-Extended",
            r"(?i)\bgoogle-extended\b",
            "block",
            "medium",
            &["ai-crawler"],
        ),
        rule(
            "BOT-AI-008",
            "PerplexityBot",
            r"(?i)\bperplexitybot\b",
            "block",
            "medium",
            &["ai-crawler"],
        ),
        // ── Scrapers and harvesting tools (block) ─────────────────────────────
        rule(
            "BOT-BAD-001",
            "Scrapy web scraper",
            r"(?i)\bscrapy\b",
            "block",
            "high",
            &["scraper"],
        ),
        rule(
            "BOT-BAD-002",
            "zgrab banner grabber",
            r"(?i)\bzgrab\b",
            "block",
            "high",
            &["scanner"],
        ),
        rule(
            "BOT-BAD-003",
            "Masscan port scanner",
            r"(?i)\bmasscan\b",
            "block",
            "high",
            &["scanner"],
        ),
        rule(
            "BOT-BAD-004",
            "Headless Chrome / Puppeteer",
            r"(?i)(headlesschrome|headless[\s_-]?chrome|puppeteer)",
            "block",
            "high",
            &["headless-browser"],
        ),
        rule(
            "BOT-BAD-005",
            "PhantomJS headless browser",
            r"(?i)\bphantomjs\b",
            "block",
            "high",
            &["headless-browser"],
        ),
        rule(
            "BOT-BAD-006",
            "Selenium WebDriver",
            r"(?i)(selenium|webdriver)",
            "block",
            "high",
            &["headless-browser"],
        ),
        rule(
            "BOT-BAD-007",
            "Generic crawler/spider/scraper UA",
            r"(?i)\b(crawler|spider|scraper)\b",
            "block",
            "medium",
            &["scraper"],
        ),
        rule(
            "BOT-BAD-008",
            "Harvester / extractor tool",
            r"(?i)\b(harvest|extractor)\b",
            "block",
            "medium",
            &["scraper"],
        ),
        rule(
            "BOT-BAD-009",
            "Python urllib (scripted access)",
            r"(?i)^python-urllib/",
            "block",
            "medium",
            &["scripted-client"],
        ),
        rule(
            "BOT-BAD-010",
            "Java HTTP client",
            r"(?i)^Java/",
            "block",
            "medium",
            &["scripted-client"],
        ),
        rule(
            "BOT-BAD-011",
            "Ruby Net::HTTP",
            r"(?i)^Ruby$|^Ruby/",
            "block",
            "medium",
            &["scripted-client"],
        ),
        rule(
            "BOT-BAD-012",
            "Go standard HTTP client",
            r"(?i)^Go-http-client/",
            "block",
            "medium",
            &["scripted-client"],
        ),
        rule(
            "BOT-BAD-013",
            "curl (bare, no custom UA)",
            r"^curl/",
            "block",
            "low",
            &["scripted-client"],
        ),
        rule(
            "BOT-BAD-014",
            "wget (bare, no custom UA)",
            r"^Wget/",
            "block",
            "low",
            &["scripted-client"],
        ),
        // ── SEO tools ─────────────────────────────────────────────────────────
        rule(
            "BOT-SEO-001",
            "Semrush Bot",
            r"(?i)\bsemrushbot\b",
            "log",
            "low",
            &["seo-tool"],
        ),
        rule(
            "BOT-SEO-002",
            "Ahrefs Bot",
            r"(?i)\bahrefsbot\b",
            "log",
            "low",
            &["seo-tool"],
        ),
        rule(
            "BOT-SEO-003",
            "MJ12bot (Majestic)",
            r"(?i)\bmj12bot\b",
            "log",
            "low",
            &["seo-tool"],
        ),
    ]
}
