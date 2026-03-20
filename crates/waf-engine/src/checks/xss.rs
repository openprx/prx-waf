use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, request_targets};

static XSS_DESCS: &[&str] = &[
    "<script> tag",
    "event handler attribute (on*=)",
    "javascript: URI",
    "vbscript: URI",
    "CSS expression()",
    "data:text/html URI",
    "document.cookie / document.write access",
    "eval() call",
    ".innerHTML assignment",
    "String.fromCharCode() obfuscation",
    "HTML numeric character reference (&#...)",
    "<svg> with event handler",
    "<img> with javascript: src",
    "<iframe> injection",
    "<object>/<embed> injection",
    "<svg>/<math> inline vector",
];

static XSS_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // <script...>
        r"(?i)<\s*/?\s*script[\s/>]",
        // Event handlers: on[event]=
        r"(?i)\bon(abort|blur|change|click|dblclick|drag|drop|error|focus|hashchange|input|keydown|keypress|keyup|load|message|mousedown|mousemove|mouseout|mouseover|mouseup|paste|popstate|reset|resize|scroll|select|submit|touchend|touchmove|touchstart|unload|wheel)\s*=",
        // javascript: (allow whitespace/encoding obfuscation)
        r"(?i)j[\s]*a[\s]*v[\s]*a[\s]*s[\s]*c[\s]*r[\s]*i[\s]*p[\s]*t[\s]*:",
        // vbscript:
        r"(?i)v[\s]*b[\s]*s[\s]*c[\s]*r[\s]*i[\s]*p[\s]*t[\s]*:",
        // CSS expression()
        r"(?i)expression\s*\(",
        // data: URIs with html content
        r"(?i)data:\s*text/html",
        // document.cookie / document.write / document.location
        r"(?i)document\s*\.\s*(cookie|write|writeln|body|location|domain|referrer)",
        // eval(
        r"(?i)\beval\s*\(",
        // .innerHTML =
        r"(?i)\.innerHTML\s*=",
        // fromCharCode
        r"(?i)\bfromCharCode\b",
        // HTML numeric entities &#x41; or &#65;
        r"&#\s*(x\s*[0-9a-fA-F]+|[0-9]+)\s*;",
        // <svg onload=...>
        r"(?i)<\s*svg[^>]*\bon\w+\s*=",
        // <img src=javascript:
        r"(?i)<\s*img[^>]*src\s*=\s*javascript:",
        // <iframe ...>
        r"(?i)<\s*iframe[\s/>]",
        // <object> / <embed>
        r"(?i)<\s*(object|embed)[\s/>]",
        // Inline SVG/MathML vectors
        r"(?i)<\s*(svg|math)[\s/>]",
    ])
    .expect("XSS regex set compilation failed")
});

/// XSS detection checker.
pub struct XssCheck;

impl XssCheck {
    pub fn new() -> Self {
        Self
    }
}

impl Default for XssCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for XssCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.xss {
            return None;
        }

        for (location, value) in request_targets(ctx) {
            let matches = XSS_SET.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = XSS_DESCS.get(idx).copied().unwrap_or("XSS pattern");
                return Some(DetectionResult {
                    rule_id: Some(format!("XSS-{:03}", idx + 1)),
                    rule_name: "XSS".to_string(),
                    phase: Phase::Xss,
                    detail: format!("{} detected in {}", desc, location),
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
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(query: &str, body: &str) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: query.to_string(),
            headers: HashMap::new(),
            body_preview: Bytes::from(body.to_string()),
            content_length: body.len() as u64,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    xss: true,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    #[test]
    fn detects_script_tag() {
        let checker = XssCheck::new();
        let ctx = make_ctx("q=<script>alert(1)</script>", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_event_handler() {
        let checker = XssCheck::new();
        let ctx = make_ctx("", "name=<img onerror=alert(1)>");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_javascript_uri() {
        let checker = XssCheck::new();
        let ctx = make_ctx("url=javascript:alert(1)", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_clean_request() {
        let checker = XssCheck::new();
        let ctx = make_ctx("q=hello+world&page=1", "");
        assert!(checker.check(&ctx).is_none());
    }
}
