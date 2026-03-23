use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

static SCANNER_UA_DESCS: &[&str] = &[
    "sqlmap (SQL injection scanner)",
    "Nmap (port scanner)",
    "Nikto (web scanner)",
    "Burp Suite (proxy/scanner)",
    "Acunetix (web scanner)",
    "Nessus (vulnerability scanner)",
    "Metasploit (exploitation framework)",
    "w3af (web application attack framework)",
    "DirBuster / dirbuster (directory brute-forcer)",
    "AppScan (IBM web scanner)",
    "WebInspect (HP web scanner)",
    "Paros Proxy",
    "OWASP ZAP",
    "gobuster (directory/DNS brute-forcer)",
    "ffuf (fast web fuzzer)",
    "wfuzz (web fuzzer)",
    "Nuclei (vulnerability scanner)",
    "dirb (web content scanner)",
    "Havij (automated SQL injection)",
    "Masscan (port scanner)",
    "zgrab (banner grabber)",
    "Netsparker (web scanner)",
    "Arachni (web scanner)",
    "OpenVAS (vulnerability scanner)",
    "Vega (web security scanner)",
    "Skipfish",
    "Wapiti (web app vulnerability scanner)",
    "Hydra (login brute-forcer)",
    "Medusa (login brute-forcer)",
    "curl (non-browser HTTP client)",
    "Python Requests library",
    "Go HTTP client",
    "libwww-perl (Perl HTTP lib)",
    "headless Chrome / Puppeteer / Selenium",
    "PhantomJS",
    "Scrapy (web scraper)",
];

#[allow(clippy::expect_used)]
static SCANNER_UA_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\bsqlmap\b",
        r"(?i)\bnmap\b",
        r"(?i)\bnikto\b",
        r"(?i)\bburp\b|\bburpsuite\b",
        r"(?i)\bacunetix\b",
        r"(?i)\bnessus\b",
        r"(?i)\bmetasploit\b",
        r"(?i)\bw3af\b",
        r"(?i)\bdirbuster\b",
        r"(?i)\bappscan\b",
        r"(?i)\bwebinspect\b",
        r"(?i)\bparos\b",
        r"(?i)\b(OWASP[\s_-]?)?ZAP\b",
        r"(?i)\bgobuster\b",
        r"(?i)\bffuf\b",
        r"(?i)\bwfuzz\b",
        r"(?i)\bnuclei\b",
        r"(?i)\bdirb\b",
        r"(?i)\bhavij\b",
        r"(?i)\bmasscan\b",
        r"(?i)\bzgrab\b",
        r"(?i)\bnetsparker\b",
        r"(?i)\barachni\b",
        r"(?i)\bopenvas\b",
        r"(?i)\bvega\b",
        r"(?i)\bskipfish\b",
        r"(?i)\bwapiti\b",
        r"(?i)\bhydra\b",
        r"(?i)\bmedusa\b",
        // Generic HTTP tool UAs — low-level / scripted
        r"(?i)^curl/",
        r"(?i)^python-requests/",
        r"(?i)^go-http-client/",
        r"(?i)^libwww-perl/",
        r"(?i)(headlesschrome|headless chrome|puppeteer|selenium|webdriver)",
        r"(?i)\bphantomjs\b",
        r"(?i)\bscrapy\b",
    ])
    .expect("Scanner UA regex set compilation failed")
});

/// Security scanner / automated tool detection checker (User-Agent based).
pub struct ScannerCheck;

impl ScannerCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ScannerCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for ScannerCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.scan {
            return None;
        }

        let ua = ctx.headers.get("user-agent").map_or("", String::as_str);

        let matches = SCANNER_UA_SET.matches(ua);
        if matches.matched_any() {
            let idx = matches.iter().next().unwrap_or(0);
            let desc = SCANNER_UA_DESCS.get(idx).copied().unwrap_or("scanner");
            return Some(DetectionResult {
                rule_id: Some(format!("SCAN-{:03}", idx + 1)),
                rule_name: "Scanner".to_string(),
                phase: Phase::Scanner,
                detail: format!("{desc} User-Agent detected"),
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
        if !ua.is_empty() {
            headers.insert("user-agent".to_string(), ua.to_string());
        }
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
                    scan: true,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    #[test]
    fn detects_sqlmap() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("sqlmap/1.7.6#stable (https://sqlmap.org)");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_nikto() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("Nikto/2.1.5");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_python_requests() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("python-requests/2.28.0");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_regular_browser() {
        let checker = ScannerCheck::new();
        let ctx = make_ctx("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0");
        assert!(checker.check(&ctx).is_none());
    }
}
