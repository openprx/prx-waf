//! Lane 2 XSS DOM semantic detector (plan §5.2, P-XSS-1).
//!
//! The **fourth** semantic attack family. It upgrades XSS from the frozen Lane 1
//! regex ([`crate::checks::XssCheck`], kept unchanged and additive) to a WHATWG
//! HTML5 **fragment parse**: the input is parsed with Servo's `html5ever` core
//! (via `scraper`) in the `body` context — the plan's "most dangerous context"
//! (§3.1) — and a match fires **only** on structure that really parses into
//! executable content:
//!
//! * a `<script>` element (`xss.script_tag`);
//! * an `on*=` event-handler attribute — restricted to the real HTML/SVG event
//!   handler names ([`EVENT_HANDLERS`]), so `once` / `online` / `onward` never
//!   fire — on a **genuinely parsed** element (`<svg onload>` gets its own key;
//!   every other handler is `event_handler`) — the string `onclick=` sitting in
//!   a *text* node never fires, which is the core false-positive win over the
//!   Lane 1 regex (plan §3.1 / §6.1);
//! * a dangerous URL scheme (`javascript:` / `vbscript:` / `data:text/html`,
//!   compared after removing ASCII tab/CR/LF and trimming leading control/space —
//!   exactly what a browser's URL parser strips, so an internal space keeps
//!   `java script:` inert) on a real URL attribute (`href` / `src` / `action` /
//!   `formaction`);
//! * `<iframe srcdoc>` (and, default-off since P-XSS-2, `<object>`/`<embed>` /
//!   `<base href>` — see [`scan_element`]);
//! * a `<body>` / `<frameset>` / `<html>` start-tag event handler, recovered by a
//!   budgeted document reparse the body-context fragment parse would drop (FN-1).
//!
//! **P-XSS-2.** Alongside the strongest structural construct, the same single
//! parse also extracts the JS **execution contexts** (event-handler attribute
//! values + `javascript:`/`vbscript:` URL script bodies) and stashes them in
//! [`ContentInspectionState`] for the second `Xss`-family detector
//! ([`super::xss_js::XssJsTokenDetector`]) — so a Block recommendation needs both
//! the DOM structure AND a dangerous JS token (0.5/0.5 corroboration), while a
//! lone structural hit stays at Log. `<template>` content is skipped (FP-5,
//! inert) and the noisy `<object>`/`<embed>`/`<base href>` constructs are
//! default-off (FP-4). Rawtext elements (`<textarea>`/`<title>`/`<style>`/
//! `<script>` content) need no special handling — html5ever already parses their
//! body as text, so no dangerous element or attribute is ever produced there
//! (the fire-drill's `<textarea>` probe was clean by construction).
//!
//! Like the other detectors it returns a **context-free** [`DetectionFinding`];
//! the pipeline ([`View::to_signal`](super::preprocess::View::to_signal)) stamps
//! provenance / field / scope / detector-id, so a `BlindDecoded` (base64/hex) XSS
//! view can never be relabelled hard-veto-capable (codex A-1). It runs on every
//! decode view, so an encoded XSS payload surfaces through the shared decode
//! chain. **Shadow only**: the `Xss` family ships `enforcement_mode = log_only`,
//! so a match is at most logged, never a Block.
//!
//! **Honest ceiling (plan §7).** A pure reverse proxy parses the input in
//! isolation, not in the target page's real context. Parse-differential (an
//! unclosed trailing tag the browser would auto-complete) and mutation-XSS
//! (re-serialisation surprises) are physical false-negative sources that a WHATWG
//! reference parser only *minimises*, never eliminates. The default-off
//! `dangling_open_tag` weak signal (below) keeps a low-confidence trace of the
//! unclosed-tag case for later shadow calibration; it does not run in production.

use std::borrow::Cow;

use scraper::Html;
use scraper::node::Element;

use super::budget::ContentInspectionState;
use super::preprocess::{PreprocessCtx, SemanticDetector, View};
use super::types::{AttackKind, Confidence, DetectionFinding, DetectorId};

/// Per-parse byte backstop (plan §5.3). An input longer than this is declined
/// for the HTML parser (no signal — fail-open) regardless of the per-request
/// byte budget, so a pathological field cannot force a large parse. Coordinated
/// with `max_field_input_bytes` (default 16 KiB): a field is already capped at
/// that size, and `html5ever`'s tree building is arena-backed and non-recursive,
/// so a deeply-nested `<div>×N` within this cap builds and drops in O(n) without
/// touching the call stack — this cap simply bounds the total work.
const XSS_MAX_INPUT_BYTES: usize = 16 * 1024;

/// Cheap pre-filter: an HTML element cannot exist without a tag-open (`<`
/// immediately followed by a name char, `/`, or `!`). Fields without one — the
/// overwhelming majority of traffic, and every entity-encoded payload *before*
/// its decoded view — skip the parser and the HTML budget entirely (mirrors
/// [`super::detectors`] `ast_prefilter`). Liberal on the safe side: a value that
/// slips through simply parses to no dangerous element.
fn looks_like_markup(s: &str) -> bool {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'<'
            && let Some(&next) = bytes.get(i + 1)
            && (next.is_ascii_alphabetic() || next == b'/' || next == b'!')
        {
            return true;
        }
    }
    false
}

/// Byte offset of the **first** literal `<body`, `<frameset`, or `<html`
/// start-tag (case-insensitive, name terminated by a tag delimiter), or `None`.
/// html5ever's body-context *fragment* parse silently drops the event-handler
/// attributes of a second `<body>`/`<frameset>` (a browser reflecting the payload
/// merges them onto the live document element and executes them — a genuine XSS).
/// A full *document* parse recovers them, so this gates a second, budget-charged
/// reparse (FN-1).
///
/// The offset (not just a bool) matters for a second false-negative source
/// (FN-2): the WHATWG **frameset-ok** flag is set to "not ok" by any preceding
/// non-whitespace content, after which a `<frameset onload=…>` / `<frameset
/// onpageshow=…>` start-tag is *dropped* even by a full document parse — so
/// `x<frameset onload=…>` or `<p>hi</p><frameset onpageshow=…>` would silently
/// miss. Reparsing the **suffix from this offset** (dropping the prefix that
/// zeroed frameset-ok) restores a fresh frameset-ok, recovering the handler as a
/// genuinely-parsed attribute — no text-level attribute scan, so the anti-FP
/// property is preserved. The suffix is a superset of what a whole-document
/// reparse could recover (leading non-host content only ever *hurts*), so this is
/// strictly-higher recall with no regression. The `<body-panel>` custom element
/// must not match, hence the delimiter check.
fn first_document_level_host(s: &str) -> Option<usize> {
    const HOSTS: &[&[u8]] = &[b"body", b"frameset", b"html"];
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'<' {
            continue;
        }
        let Some(rest) = bytes.get(i + 1..) else {
            continue;
        };
        for host in HOSTS {
            if let Some(head) = rest.get(..host.len())
                && head.eq_ignore_ascii_case(host)
                && let Some(&after) = rest.get(host.len())
                && matches!(after, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | b'/' | b'>')
            {
                return Some(i);
            }
        }
    }
    None
}

/// Text-only elements (rawtext / RCDATA / script-data) whose textual content is
/// **not** parsed as markup by the HTML tokenizer. A `<body`/`<frameset`/`<html`
/// tag-open sitting inside one of these is inert text — a browser never turns it
/// into a live element — so the FN-2 frameset-ok suffix reparse (which strips the
/// wrapper) must not resurrect it. `noscript` is included because a browser
/// reflecting a payload runs with scripting enabled, where `<noscript>` content is
/// rawtext.
const RAWTEXT_ELEMENTS: &[&[u8]] = &[
    b"script",
    b"style",
    b"textarea",
    b"title",
    b"xmp",
    b"iframe",
    b"noembed",
    b"noframes",
    b"noscript",
];

/// First byte offset (`>= from`) at which `needle` occurs in `haystack`, or
/// `None`. `needle` must be non-empty (all call sites pass constants).
fn find_from(haystack: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    let start = from.min(haystack.len());
    haystack
        .get(start..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| start + p)
}

/// First byte offset (`>= from`) of a `</name` end-tag-open (case-insensitive,
/// name terminated by a tag delimiter) in `haystack`, or `None`.
fn find_closing_tag(haystack: &[u8], from: usize, name: &[u8]) -> Option<usize> {
    let mut i = from;
    while let Some(&b) = haystack.get(i) {
        if b == b'<'
            && haystack.get(i + 1) == Some(&b'/')
            && haystack
                .get(i + 2..i + 2 + name.len())
                .is_some_and(|h| h.eq_ignore_ascii_case(name))
            && haystack
                .get(i + 2 + name.len())
                .is_none_or(|&c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | b'>' | b'/'))
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Is the tag-open at byte offset `host_idx` genuinely at HTML **data** (document)
/// level in the full input — i.e. NOT inside a comment (`<!-- … -->`) nor inside
/// the text content of a [`RAWTEXT_ELEMENTS`] element? Only then is the FN-2
/// frameset-ok **suffix reparse** legitimate. Reparsing the suffix from `host_idx`
/// as a document strips whatever wrapped the host, so a host the browser would
/// only ever see as inert comment / rawtext text must be left alone — otherwise a
/// lazy, never-executed `<!-- <body onload> -->` or
/// `<textarea><body onload></textarea>` would be "revived" into a false
/// event-handler hit (the P1 regression this guards).
///
/// It scans only the discarded prefix `[0, host_idx)`, tracking the tokenizer's
/// coarse state (data / comment / rawtext). Conservative by construction: any
/// unterminated comment or rawtext element covering the offset returns `false`
/// (skip the reparse). A comment / rawtext element that *closes* before the host
/// leaves the host at data level → `true`, so the legitimate frameset-ok recovery
/// (`x<frameset onload=…>`, `<p>hi</p><frameset onpageshow=…>`) is preserved.
fn host_offset_at_data_level(s: &str, host_idx: usize) -> bool {
    let bytes = s.as_bytes();
    let limit = host_idx.min(bytes.len());
    let mut i = 0usize;
    while i < limit {
        if bytes.get(i) != Some(&b'<') {
            i += 1;
            continue;
        }
        let after_lt = i + 1;
        // Comment `<!-- … -->`: if it does not close before `host_idx`, the host is
        // commented out (inert) → not data level.
        if bytes.get(after_lt..).is_some_and(|r| r.starts_with(b"!--")) {
            let Some(end) = find_from(bytes, after_lt + 3, b"-->") else {
                return false;
            };
            let after = end + 3;
            if after > limit {
                return false;
            }
            i = after;
            continue;
        }
        // Start tag of a rawtext / RCDATA element: its content up to the matching
        // close tag is text, so a host inside it is inert.
        let mut rawtext: Option<&[u8]> = None;
        for &name in RAWTEXT_ELEMENTS {
            if bytes
                .get(after_lt..after_lt + name.len())
                .is_some_and(|h| h.eq_ignore_ascii_case(name))
                && bytes
                    .get(after_lt + name.len())
                    .is_none_or(|&c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | b'>' | b'/'))
            {
                rawtext = Some(name);
                break;
            }
        }
        if let Some(name) = rawtext {
            // The start tag must close with `>` before its text content begins.
            let Some(gt) = find_from(bytes, after_lt + name.len(), b">") else {
                return false;
            };
            match find_closing_tag(bytes, gt + 1, name) {
                // Rawtext closes before the host → keep scanning after it as data.
                Some(close) if close <= limit => {
                    i = close;
                    continue;
                }
                // Never closed, or closes only after the host → host is inside it.
                _ => return false,
            }
        }
        i += 1;
    }
    true
}

/// URL attributes whose value is resolved as a navigation / fetch target and can
/// therefore carry a dangerous scheme. `xlink:href` reduces to the local name
/// `href` after parsing, so it is covered.
const URL_ATTRS: &[&str] = &["href", "src", "action", "formaction"];

/// Real HTML / SVG event-handler content attribute names (the `on*` allowlist).
/// Drawn from the WHATWG HTML event-handler content attributes, the SVG/SMIL
/// timing handlers (`onbegin`/`onend`/`onrepeat`), the animation/transition/
/// pointer/touch families, and the `<body>`/`<frameset>` window-reflected set —
/// the same surface `DOMPurify` strips. A bare `on` prefix is **not** enough: this
/// is what keeps `once` / `online` / `onward` / `ongoing` and custom `on-*` data
/// attributes clean (FP-2), while every genuine handler still fires.
const EVENT_HANDLERS: &[&str] = &[
    "onabort",
    "onafterprint",
    "onanimationcancel",
    "onanimationend",
    "onanimationiteration",
    "onanimationstart",
    "onauxclick",
    "onbeforeinput",
    "onbeforematch",
    "onbeforeprint",
    "onbeforetoggle",
    "onbeforeunload",
    "onbegin",
    "onblur",
    "oncancel",
    "oncanplay",
    "oncanplaythrough",
    "onchange",
    "onclick",
    "onclose",
    "oncontextlost",
    "oncontextmenu",
    "oncontextrestored",
    "oncopy",
    "oncuechange",
    "oncut",
    "ondblclick",
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondragstart",
    "ondrop",
    "ondurationchange",
    "onemptied",
    "onend",
    "onended",
    "onenterpictureinpicture",
    "onerror",
    "onfocus",
    "onfocusin",
    "onfocusout",
    "onformdata",
    "onfullscreenchange",
    "onfullscreenerror",
    "ongotpointercapture",
    "onhashchange",
    "oninput",
    "oninvalid",
    "onkeydown",
    "onkeypress",
    "onkeyup",
    "onlanguagechange",
    "onleavepictureinpicture",
    "onload",
    "onloadeddata",
    "onloadedmetadata",
    "onloadstart",
    "onlostpointercapture",
    "onmessage",
    "onmessageerror",
    "onmousedown",
    "onmouseenter",
    "onmouseleave",
    "onmousemove",
    "onmouseout",
    "onmouseover",
    "onmouseup",
    "onoffline",
    "ononline",
    "onpagehide",
    "onpageshow",
    "onpaste",
    "onpause",
    "onplay",
    "onplaying",
    "onpointercancel",
    "onpointerdown",
    "onpointerenter",
    "onpointerleave",
    "onpointermove",
    "onpointerout",
    "onpointerover",
    "onpointerrawupdate",
    "onpointerup",
    "onpopstate",
    "onprogress",
    "onratechange",
    "onrejectionhandled",
    "onrepeat",
    "onreset",
    "onresize",
    "onscroll",
    "onscrollend",
    "onsecuritypolicyviolation",
    "onseeked",
    "onseeking",
    "onselect",
    "onselectionchange",
    "onselectstart",
    "onshow",
    "onslotchange",
    "onstalled",
    "onstorage",
    "onsubmit",
    "onsuspend",
    "ontimeupdate",
    "ontoggle",
    "ontouchcancel",
    "ontouchend",
    "ontouchmove",
    "ontouchstart",
    "ontransitioncancel",
    "ontransitionend",
    "ontransitionrun",
    "ontransitionstart",
    "onunhandledrejection",
    "onunload",
    "onvolumechange",
    "onwaiting",
    "onwebkitanimationend",
    "onwebkitanimationiteration",
    "onwebkitanimationstart",
    "onwebkittransitionend",
    "onwheel",
];

/// Is `attr` a genuine event-handler content attribute? Cheap `on` prefix reject
/// first, then an allowlist membership test — a bare `on` prefix never matches.
fn is_event_handler(attr: &str) -> bool {
    attr.starts_with("on") && EVENT_HANDLERS.contains(&attr)
}

/// Classify a URL attribute value's scheme the way a browser's URL parser reads
/// it: remove **only** ASCII tab/CR/LF from anywhere (defeats `java\tscript:` /
/// newline obfuscation the tokenizer leaves in the decoded value), trim leading
/// C0-control-or-space, and lowercase. Internal spaces are **kept** — a space
/// inside the scheme (`java script:`) makes it inert, and the browser does not
/// execute it, so neither do we (FP-3). Returns the strongest dangerous-scheme
/// construct, or `None`.
fn dangerous_scheme(value: &str) -> Option<(&'static str, u8)> {
    let mut norm = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\t' || c == '\n' || c == '\r' {
            continue;
        }
        norm.push(c.to_ascii_lowercase());
    }
    let scheme = norm.trim_start_matches(|c: char| c == ' ' || c.is_control());
    if scheme.starts_with("javascript:") || scheme.starts_with("vbscript:") {
        Some(("xss.js_url", 85))
    } else if scheme.starts_with("data:text/html") {
        Some(("xss.data_html_url", 82))
    } else {
        None
    }
}

/// Keep `cand` if it is strictly stronger (higher confidence) than the current
/// best. Ties keep the incumbent — the walk order is deterministic (arena order),
/// but confidence alone decides the reported construct.
fn keep_stronger(best: &mut Option<(&'static str, u8)>, cand: (&'static str, u8)) {
    if best.is_none_or(|b| cand.1 > b.1) {
        *best = Some(cand);
    }
}

/// Extract the JS script body of a `javascript:` / `vbscript:` URL value — the
/// text after the scheme, with tab/CR/LF stripped and leading control/space
/// trimmed exactly as [`dangerous_scheme`] normalises it, but with the original
/// **case preserved** (a JS token like `String.fromCharCode` / `atob` is
/// case-significant). Returns `None` for a non-JS scheme (e.g. `data:text/html`,
/// whose body is HTML, not JS). The token detector ([`super::xss_js`])
/// classifies dangerous tokens inside the returned body.
fn js_url_body(value: &str) -> Option<String> {
    let mut norm = String::with_capacity(value.len());
    for c in value.chars() {
        if c == '\t' || c == '\n' || c == '\r' {
            continue;
        }
        norm.push(c);
    }
    let trimmed = norm.trim_start_matches(|c: char| c == ' ' || c.is_control());
    let lower = trimmed.to_ascii_lowercase();
    for scheme in ["javascript:", "vbscript:"] {
        if lower.starts_with(scheme) {
            // `scheme` is ASCII, so its byte length is the same in `trimmed`.
            return trimmed.get(scheme.len()..).map(str::to_string);
        }
    }
    None
}

/// Scan one parsed element for the strongest dangerous construct it introduces,
/// and (P-XSS-2) collect the JS **execution contexts** it exposes — event-handler
/// attribute values and `javascript:` / `vbscript:` URL script bodies — into
/// `js_contexts` for the token detector to corroborate.
///
/// Every branch fires only on a **real parsed element / attribute** — the whole
/// point of the DOM upgrade. Event handlers are matched against the
/// [`EVENT_HANDLERS`] allowlist (not a bare `on` prefix); the URL-scheme branches
/// run only on the curated [`URL_ATTRS`] set.
///
/// `include_weak` gates the P-XSS-2 default-off constructs: `<object>`/`<embed>`
/// and `<base href>` fired unconditionally at confidence 80 in P-XSS-1, but the
/// fire-drill showed legitimate PDF/media embeds and SPA `<base href="/app/">`
/// hit them 3/3 (`report/prx-waf-pxss-fire-drill-2026-07-23.md` §4.3). Per the
/// "default-on 只留低误报" discipline they now ship **default-off** (only under the
/// test/future all-constructs set), leaving corroboration to demote any residual
/// hit — they carry no JS sink, so the token detector never corroborates them and
/// a lone structural hit stays at Log.
fn scan_element(el: &Element, include_weak: bool, js_contexts: &mut Vec<String>) -> Option<(&'static str, u8)> {
    let name = el.name(); // html5ever lowercases HTML local names
    let mut best: Option<(&'static str, u8)> = None;

    match name {
        "script" => keep_stronger(&mut best, ("xss.script_tag", 90)),
        // FP-4 (P-XSS-2): default-off — legitimate media/PDF embeds and SPA
        // `<base href>` hit these unconditionally.
        "object" | "embed" if include_weak => keep_stronger(&mut best, ("xss.object_embed", 80)),
        "base" if include_weak && el.attr("href").is_some() => keep_stronger(&mut best, ("xss.base_href", 80)),
        "iframe" if el.attr("srcdoc").is_some() => keep_stronger(&mut best, ("xss.iframe_srcdoc", 85)),
        _ => {}
    }

    for (attr, value) in el.attrs() {
        if is_event_handler(attr) {
            // P-XSS-2: the handler's VALUE is a JS execution context.
            js_contexts.push(value.to_string());
            if name == "svg" && attr == "onload" {
                keep_stronger(&mut best, ("xss.svg_onload", 88));
            } else {
                keep_stronger(&mut best, ("xss.event_handler", 85));
            }
        }
        if URL_ATTRS.contains(&attr)
            && let Some(cand) = dangerous_scheme(value)
        {
            // P-XSS-2: a `javascript:` / `vbscript:` URL's script body is a JS
            // execution context (a `data:text/html` URL is HTML, not JS → `None`).
            if let Some(body) = js_url_body(value) {
                js_contexts.push(body);
            }
            keep_stronger(&mut best, cand);
        }
    }

    best
}

/// Dangerous start-tag names for the default-off `dangling_open_tag` weak signal
/// (plan §4 坑1). An input that ends with one of these tag-opens and no closing
/// `>` is dropped by the WHATWG fragment parser but would be auto-completed by a
/// browser reflecting it into a larger page.
const DANGLING_TAGS: &[&str] = &[
    "script", "img", "svg", "iframe", "object", "embed", "base", "body", "video", "audio", "math",
];

/// Default-off weak signal (plan §4 坑1): the input ends with an **unclosed**
/// dangerous start tag (`…<img src=x onerror=alert(1)` with no trailing `>`),
/// which the fragment parser discards but a browser would complete. Low
/// confidence, non-hard-veto by construction; kept only under
/// [`XssDomDetector::with_all_constructs`] so it can be shadow-calibrated before
/// it ever runs in production.
fn dangling_open_tag(s: &str) -> Option<(&'static str, u8)> {
    // Find the last tag-open `<name`; if nothing closes it, it is dangling.
    let mut idx = s.len();
    for (i, c) in s.char_indices().rev() {
        if c == '<' {
            idx = i;
            break;
        }
        if c == '>' {
            // A closed tag terminates the scan — the trailing region is complete.
            return None;
        }
    }
    let after = s.get(idx + 1..)?;
    if after.contains('>') {
        return None;
    }
    let name: String = after
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect::<String>()
        .to_ascii_lowercase();
    if !name.is_empty() && DANGLING_TAGS.contains(&name.as_str()) {
        Some(("xss.dangling_open_tag", 50))
    } else {
        None
    }
}

/// HTML5 DOM semantic XSS detector (plan §5.2, P-XSS-1). Registered in the `Xss`
/// attack family; parses each normalised view's text as an HTML fragment and
/// fires on the strongest dangerous construct.
pub struct XssDomDetector {
    /// Include the default-off high-noise constructs (currently the
    /// `dangling_open_tag` weak signal). `false` in production — set only by the
    /// test-only [`Self::with_all_constructs`], mirroring the structural
    /// detectors' default-on / all split.
    include_weak: bool,
}

impl XssDomDetector {
    /// Compile with the **default-on** low-false-positive construct set only.
    #[must_use]
    pub const fn new() -> Self {
        Self { include_weak: false }
    }

    /// Test-only: also emit the default-off weak `dangling_open_tag` signal.
    #[cfg(test)]
    #[must_use]
    pub const fn with_all_constructs() -> Self {
        Self { include_weak: true }
    }

    /// Walk a parsed fragment and return the strongest default-on construct,
    /// collecting the JS execution contexts (P-XSS-2) into `js_contexts`.
    ///
    /// `check_template` (set only when the input actually contains a `<template`
    /// tag) turns on the FP-5 ancestor check: `<template>` **content** is inert —
    /// it is cloned into a document fragment and never parsed/executed in place —
    /// so a `<script>` / `on*=` inside a template must NOT fire (fire-drill §4.9).
    /// The ancestor walk is O(depth) per node, so it is gated behind the cheap
    /// `check_template` flag to keep the common (no-template) walk O(n).
    fn scan_fragment(
        html: &Html,
        include_weak: bool,
        check_template: bool,
        js_contexts: &mut Vec<String>,
    ) -> Option<(&'static str, u8)> {
        let mut best: Option<(&'static str, u8)> = None;
        // Arena-order node iteration — non-recursive, so a deeply-nested tree is
        // walked (and later dropped) in O(n) without stack growth.
        for node in html.tree.nodes() {
            let Some(el) = node.value().as_element() else {
                continue;
            };
            // FP-5: skip anything inside a `<template>` (inert template content).
            if check_template
                && node
                    .ancestors()
                    .any(|a| a.value().as_element().is_some_and(|e| e.name() == "template"))
            {
                continue;
            }
            if let Some(cand) = scan_element(el, include_weak, js_contexts) {
                keep_stronger(&mut best, cand);
            }
        }
        best
    }
}

/// Does the input contain a literal `<template` start-tag (case-insensitive)? A
/// cheap over-approximate gate that turns on the FP-5 template-content ancestor
/// check in [`XssDomDetector::scan_fragment`] only when a template is actually
/// present, keeping the hot no-template path O(n).
fn contains_template_tag(s: &str) -> bool {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'<'
            && let Some(head) = bytes.get(i + 1..i + 9)
            && head.eq_ignore_ascii_case(b"template")
        {
            return true;
        }
    }
    false
}

impl Default for XssDomDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticDetector for XssDomDetector {
    fn id(&self) -> DetectorId {
        DetectorId::XssDom
    }

    fn detect(
        &self,
        view: &View<'_>,
        _ctx: &PreprocessCtx<'_>,
        state: &mut ContentInspectionState,
    ) -> Option<DetectionFinding> {
        // Parse the REAL view text, not `lower_trunc` (which collapses whitespace
        // and truncates tokens — that would mangle the HTML).
        let text = view.text.as_ref();
        // P-XSS-2: reset the corroboration channel for THIS view up front, before
        // any early return, so a previous view's JS contexts can never leak to the
        // token detector (which drains this immediately after us).
        state.stash_xss_js_contexts(Vec::new());
        // Cheap gate: no tag-open → no element → clean. Skips the parser + budget.
        if !looks_like_markup(text) {
            return None;
        }
        // Stack/DoS byte backstop BEFORE spending budget: decline oversized input
        // (fail-open, no signal — same posture as the AST depth guard).
        if text.len() > XSS_MAX_INPUT_BYTES {
            return None;
        }
        // Per-request HTML-parse budget (attempt + cumulative bytes). Exhaustion
        // marks the request degraded → scoring fails open (Lane 2 never overrides
        // the legacy verdict).
        if !state.try_take_html_parse_attempt() {
            return None;
        }
        if !state.try_take_html_parse_input_bytes(text.len()) {
            return None;
        }

        let check_template = contains_template_tag(text);
        // P-XSS-2: JS execution contexts extracted during the parse walk, stashed
        // for the token detector to corroborate (event-handler values + js-url
        // script bodies). Collected even when no construct fires so the token
        // detector can still classify (a benign handler value simply carries no
        // dangerous token).
        let mut js_contexts: Vec<String> = Vec::new();
        let html = Html::parse_fragment(text);
        let mut best = Self::scan_fragment(&html, self.include_weak, check_template, &mut js_contexts);
        // FN-1/FN-2: the body-context fragment parse drops `<body>`/`<frameset>`
        // start-tag event handlers (asymmetric with `<html>`, which it keeps), and
        // a full document parse still drops a `<frameset on*=>` once the WHATWG
        // frameset-ok flag has been zeroed by preceding non-whitespace content. A
        // document parse of the **suffix from the first host tag-open** merges the
        // host start-tag attributes onto the document element AND starts with a
        // fresh frameset-ok, recovering both. It takes its own parse-budget
        // attempt/bytes so it never bypasses the cap; if the budget is spent the
        // recovery is simply skipped (fail-open).
        //
        // The suffix reparse strips whatever wrapped the host tag-open, so it must
        // only run when the host is genuinely at document/data level in the full
        // input. `host_offset_at_data_level` rejects a host that is commented out
        // or buried in rawtext / RCDATA (`<textarea>`/`<title>`/`<style>`/`<xmp>`/
        // `<noscript>`) content — inert markup a browser never executes — so a lazy
        // `<!-- <body onload> -->` is not "revived" into a false handler hit.
        if let Some(host_idx) = first_document_level_host(text)
            && host_offset_at_data_level(text, host_idx)
            && let Some(doc_input) = text.get(host_idx..)
            && state.try_take_html_parse_attempt()
            && state.try_take_html_parse_input_bytes(doc_input.len())
            && let Some(cand) = Self::scan_fragment(
                &Html::parse_document(doc_input),
                self.include_weak,
                check_template,
                &mut js_contexts,
            )
        {
            keep_stronger(&mut best, cand);
        }
        // Hand the extracted JS contexts to the token detector (P-XSS-2). Done
        // before the weak-signal fallback: `dangling_open_tag` is text-level and
        // exposes no parsed attribute, so it contributes no JS context.
        state.stash_xss_js_contexts(js_contexts);
        if best.is_none() && self.include_weak {
            best = dangling_open_tag(text);
        }
        let (rule_key, confidence) = best?;
        Some(DetectionFinding {
            attack: AttackKind::Xss,
            confidence: Confidence::saturating(confidence),
            rule_key,
            detail: Cow::Owned(format!(
                "xss dom construct '{rule_key}' matched (confidence {confidence})"
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
    use crate::checks::content_security::budget::{Budget, ContentInspectionState};
    use crate::checks::content_security::types::{InspectionScope, Provenance};

    fn view(text: &str) -> View<'static> {
        // The XSS detector reads `view.text`; `lower_trunc` is only used by the
        // preprocessor's other consumers, so a simple lowercase is enough here.
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

    fn fire(text: &str) -> Option<DetectionFinding> {
        run(&XssDomDetector::new(), text)
    }

    fn run(det: &dyn SemanticDetector, text: &str) -> Option<DetectionFinding> {
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::default();
        det.detect(&view(text), &pctx, &mut st)
    }

    // ── Positive: each dangerous construct fires with the right rule_key ───────

    #[test]
    fn script_tag_fires() {
        let f = fire("<script>alert(1)</script>").expect("script tag must fire");
        assert_eq!(f.rule_key, "xss.script_tag");
        assert_eq!(f.attack, AttackKind::Xss);
        assert_eq!(f.confidence, 90);
    }

    #[test]
    fn svg_onload_fires() {
        let f = fire("<svg onload=alert(1)>").expect("svg onload must fire");
        assert_eq!(f.rule_key, "xss.svg_onload");
        assert_eq!(f.confidence, 88);
    }

    #[test]
    fn img_onerror_event_handler_fires() {
        let f = fire("<img src=x onerror=alert(1)>").expect("img onerror must fire");
        assert_eq!(f.rule_key, "xss.event_handler");
        assert_eq!(f.confidence, 85);
    }

    #[test]
    fn svg_animate_onbegin_fires() {
        // SMIL vector: <svg><animate onbegin=…> — animate is a real parsed SVG
        // element (body-context foreign content), so its on* handler fires.
        let f = fire("<svg><animate onbegin=alert(1) attributeName=x dur=1s>").expect("animate onbegin must fire");
        assert_eq!(f.rule_key, "xss.event_handler");
        assert_eq!(f.attack, AttackKind::Xss);
    }

    #[test]
    fn javascript_url_with_tab_obfuscation_fires() {
        // A tab inside the scheme (`javas\tcript:`) must be stripped before the
        // scheme comparison — the classic evasion.
        let f = fire("<a href=\"javas\tcript:alert(1)\">x</a>").expect("js url must fire");
        assert_eq!(f.rule_key, "xss.js_url");
        assert_eq!(f.confidence, 85);
        // Numeric-entity tab (`&#9;`) the tokenizer decodes into the attribute.
        let f2 = fire("<a href=\"javascript&#9;:alert(1)\">x</a>");
        // `javascript` + tab + `:` → after stripping the tab it is `javascript:`.
        assert_eq!(f2.expect("entity-tab js url must fire").rule_key, "xss.js_url");
    }

    #[test]
    fn vbscript_url_fires() {
        assert_eq!(
            fire("<a href=vbscript:msgbox(1)>x</a>").expect("vbscript url").rule_key,
            "xss.js_url"
        );
    }

    #[test]
    fn data_text_html_url_fires() {
        let f = fire("<iframe src=\"data:text/html,<script>alert(1)</script>\"></iframe>")
            .expect("data:text/html must fire");
        // srcdoc is absent, but the data: URL scheme fires js/data url; iframe
        // srcdoc is not present so the scheme construct is the hit.
        assert_eq!(f.rule_key, "xss.data_html_url");
    }

    #[test]
    fn iframe_srcdoc_fires() {
        let f = fire("<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>").expect("iframe srcdoc must fire");
        assert_eq!(f.rule_key, "xss.iframe_srcdoc");
        assert_eq!(f.confidence, 85);
    }

    #[test]
    fn object_embed_and_base_href_are_default_off_but_fire_with_all_constructs() {
        // FP-4 (P-XSS-2): legitimate media/PDF embeds and SPA `<base href>` hit
        // these 3/3 in the fire-drill, so they ship DEFAULT-OFF and stay clean on
        // the production set…
        for benign in [
            "<object data=evil.swf></object>",
            "<embed src=evil.swf>",
            "<base href=\"http://evil.example/\">",
        ] {
            assert!(
                fire(benign).is_none(),
                "object/embed/base_href must be default-off (FP-4): {benign:?}"
            );
        }
        // …but still fire under the test/future all-constructs set.
        assert_eq!(
            run(
                &XssDomDetector::with_all_constructs(),
                "<object data=evil.swf></object>"
            )
            .expect("object fires with all constructs")
            .rule_key,
            "xss.object_embed"
        );
        assert_eq!(
            run(&XssDomDetector::with_all_constructs(), "<embed src=evil.swf>")
                .expect("embed fires with all constructs")
                .rule_key,
            "xss.object_embed"
        );
        assert_eq!(
            run(
                &XssDomDetector::with_all_constructs(),
                "<base href=\"http://evil.example/\">"
            )
            .expect("base href fires with all constructs")
            .rule_key,
            "xss.base_href"
        );
    }

    #[test]
    fn template_inert_content_is_clean() {
        // FP-5 (P-XSS-2): `<template>` content is cloned into a document fragment
        // and never parsed/executed in place, so a `<script>` / `on*=` inside a
        // template must NOT fire (fire-drill §4.9). The same construct OUTSIDE a
        // template still fires (control), proving it is the template gate, not the
        // pre-filter, doing the work.
        for inert in [
            "<template><script>alert(1)</script></template>",
            "<template><img src=x onerror=alert(1)></template>",
            "<template><svg onload=alert(1)></template>",
            "<div><template><a href=\"javascript:alert(1)\">x</a></template></div>",
        ] {
            assert!(fire(inert).is_none(), "template content is inert: {inert:?}");
        }
        // Control: the SAME script, not wrapped in a template, still fires.
        assert_eq!(
            fire("<script>alert(1)</script>").expect("bare script fires").rule_key,
            "xss.script_tag"
        );
    }

    #[test]
    fn strongest_construct_wins() {
        // A <script> (90) co-occurring with an event handler (85) reports script.
        let f = fire("<img onerror=alert(1)><script>alert(2)</script>").expect("must fire");
        assert_eq!(f.rule_key, "xss.script_tag", "highest-confidence construct wins");
    }

    // ── False-positive regression: the five Lane 1 regex FPs → clean (plan §6) ─

    #[test]
    fn lane1_false_positives_are_clean() {
        // The exact shapes the Lane 1 XSS regex FIRES on but that are NOT
        // executable content — the core ROI of the DOM upgrade (plan §4/§6). None
        // contains a tag-open, so the DOM parse yields no dangerous element.
        for benign in [
            "The onclick= handler fires twice per second",       // bug-tracker comment
            "set onload=true in the service configuration file", // config doc
            "element.onerror = function(e) { retry(); }",        // Markdown / JS snippet
            "id,event,handler\n42,onchange=recalc,cell",         // CSV cell
            "see https://docs.example.com/javascript:guide/intro", // URL path segment
        ] {
            assert!(
                fire(benign).is_none(),
                "Lane 1 FP must be clean under DOM semantics: {benign:?}"
            );
        }
    }

    #[test]
    fn event_handler_string_in_text_node_is_clean() {
        // Stronger proof it is not merely the pre-filter: these DO parse to real
        // elements, but the `onclick=` / `javascript:` strings sit in TEXT / code
        // content, not as parsed attributes — so no construct fires.
        for benign in [
            "<p>The onclick= handler is described in the docs.</p>",
            "<code>element.onerror = fn</code>",
            "<pre>href=\"javascript:void(0)\" is an anti-pattern</pre>",
            "<div>data:text/html is a URI scheme</div>",
        ] {
            assert!(
                fire(benign).is_none(),
                "handler/scheme text must stay clean: {benign:?}"
            );
        }
    }

    #[test]
    fn ordinary_benign_markup_is_clean() {
        for benign in [
            "<p>Hello <b>world</b></p>",
            "<a href=\"https://example.com/page\">link</a>",
            "<img src=\"/static/logo.png\" alt=\"logo\">",
            "<div class=\"card\"><span>content</span></div>",
            "a < b and c > d in a math expression",
            "<!-- a comment only -->",
        ] {
            assert!(fire(benign).is_none(), "benign markup must be clean: {benign:?}");
        }
    }

    // ── FN-1: body/frameset/html start-tag event handlers (document reparse) ───

    #[test]
    fn body_frameset_start_tag_handlers_fire() {
        // The body-context fragment parse drops these; the document reparse
        // recovers them. `<body onload>` is a canonical reflected-XSS vector.
        for payload in [
            "<body onload=alert(1)>",
            "<body onpageshow=alert(1)>",
            "<frameset onload=alert(1)>",
        ] {
            let f = fire(payload).unwrap_or_else(|| panic!("must fire: {payload:?}"));
            assert_eq!(f.rule_key, "xss.event_handler", "payload {payload:?}");
            assert_eq!(f.attack, AttackKind::Xss);
        }
        // `<html on*>` is retained even by the fragment parse (asymmetric), so it
        // fires regardless of the reparse.
        assert_eq!(
            fire("<html onmouseover=alert(1)>")
                .expect("html handler fires")
                .rule_key,
            "xss.event_handler"
        );
    }

    #[test]
    fn frameset_handler_after_frameset_ok_zeroing_prefix_fires() {
        // FN-2: preceding non-whitespace content zeroes the WHATWG frameset-ok
        // flag, so a full document parse of the whole input DROPS the following
        // `<frameset on*=>` start tag — a browser reflecting the payload into a
        // fresh context still executes it. Reparsing the suffix from the first host
        // tag-open restores a fresh frameset-ok and recovers the handler.
        for payload in [
            "x<frameset onload=alert(1)>",
            "x<frameset onpageshow=alert(1)>",
            "<p>hi</p><frameset onload=alert(1)>",
            "<p>text</p><frameset onpageshow=alert(1)>",
            "lorem ipsum<frameset onunload=alert(1)>",
            "x<body onload=alert(1)>",
            "<div>content</div><body onpageshow=alert(1)>",
        ] {
            let f = fire(payload).unwrap_or_else(|| panic!("must fire (frameset-ok reset): {payload:?}"));
            assert_eq!(f.rule_key, "xss.event_handler", "payload {payload:?}");
            assert_eq!(f.attack, AttackKind::Xss);
        }
    }

    #[test]
    fn frameset_window_reflected_event_handlers_fire() {
        // Audit follow-up (D-3): the bare `<frameset on*=>` FN. The document-reparse
        // recovery is event-agnostic — every window-reflected handler the WHATWG spec
        // hoists onto `<body>`/`<frameset>` (`onpageshow` / `onpagehide` /
        // `onbeforeunload` / `onhashchange` / `onresize` / `onstorage` / `onpopstate`
        // / `onmessage` …) recovers identically to `onload`, so a bare
        // `<frameset onpageshow=…>` must fire just like `<frameset onload=…>`.
        for payload in [
            "<frameset onpageshow=alert(1)>",
            "<frameset onpagehide=alert(1)>",
            "<frameset onbeforeunload=alert(1)>",
            "<frameset onhashchange=alert(1)>",
            "<frameset onresize=alert(1)>",
            "<frameset onstorage=alert(1)>",
            "<frameset onpopstate=alert(1)>",
            "<frameset onmessage=alert(1)>",
        ] {
            let f = fire(payload).unwrap_or_else(|| panic!("frameset window handler must fire: {payload:?}"));
            assert_eq!(f.rule_key, "xss.event_handler", "payload {payload:?}");
            assert_eq!(f.attack, AttackKind::Xss);
        }
    }

    #[test]
    fn frameset_word_in_prose_stays_clean() {
        // Anti-FP for FN-2: the word "frameset"/"body" in prose (no `<frameset`
        // start tag) and a real `<frameset>`/`<body>` with no handler must both
        // stay clean — the suffix reparse only fires on a genuinely-parsed handler
        // attribute, never a text-node lookalike.
        for benign in [
            "<p>the frameset onload attribute is documented here</p>",
            "see the <body> element and its onload=true option in the manual",
            "<p>intro</p><frameset cols=\"50%,50%\"><frame src=a></frameset>",
            "text before<frameset rows=\"*\">",
        ] {
            assert!(
                fire(benign).is_none(),
                "frameset/body prose or handler-free markup must be clean: {benign:?}"
            );
        }
    }

    #[test]
    fn frameset_suffix_reparse_ignores_wrapped_lazy_content() {
        // Regression (P1): the FN-2 frameset-ok **suffix reparse** parses the raw
        // suffix from the first `<body`/`<frameset`/`<html` tag-open as a document,
        // which strips whatever *wrapped* that tag-open. A host sitting inside an
        // HTML comment or the text content of a rawtext / RCDATA element
        // (`<textarea>`/`<title>`/`<style>`/`<xmp>`/`<noscript>`) is **inert** — a
        // browser never turns it into a live element — so the reparse must NOT
        // "revive" it into a false `xss.event_handler` hit. Each of these is clean
        // in a real browser; the WAF must agree.
        for benign in [
            "<!-- <body onload=alert(1)> -->",
            "<!-- <frameset onpageshow=alert(1)> -->",
            "<textarea><body onload=alert(1)></textarea>",
            "<title><frameset onload=alert(1)></title>",
            "<xmp><body onload=alert(1)></xmp>",
            "<noscript><body onload=alert(1)></noscript>",
            "<style><frameset onload=alert(1)></style>",
        ] {
            assert!(
                fire(benign).is_none(),
                "commented / rawtext-wrapped host is inert, must stay clean: {benign:?}"
            );
        }
        // Control: the SAME hosts UNWRAPPED (genuinely at document level) still
        // fire — proving the guard rejects only the wrapping, not the recovery.
        for payload in ["<body onload=alert(1)>", "x<frameset onpageshow=alert(1)>"] {
            assert_eq!(
                fire(payload)
                    .unwrap_or_else(|| panic!("unwrapped host must still fire: {payload:?}"))
                    .rule_key,
                "xss.event_handler",
                "payload {payload:?}"
            );
        }
        // A comment / rawtext element that CLOSES before the host leaves the host
        // genuinely at data level — it must still fire.
        for payload in [
            "<!-- note --><frameset onload=alert(1)>",
            "<style>.a{}</style><body onpageshow=alert(1)>",
        ] {
            assert_eq!(
                fire(payload)
                    .unwrap_or_else(|| panic!("host after a closed wrapper must fire: {payload:?}"))
                    .rule_key,
                "xss.event_handler",
                "payload {payload:?}"
            );
        }
    }

    #[test]
    fn body_without_handler_stays_clean() {
        // The document reparse only recovers real handlers — a benign body/html
        // shell must not fire.
        for benign in [
            "<body class=\"page\">hello</body>",
            "<html lang=\"en\"><body><p>hi</p></body></html>",
            "<body once=true online>",
        ] {
            assert!(
                fire(benign).is_none(),
                "benign document shell must be clean: {benign:?}"
            );
        }
    }

    // ── FP-2: `on` prefix is not enough — only real event handlers fire ────────

    #[test]
    fn non_event_on_prefixed_attributes_are_clean() {
        // These parse to real elements with real attributes, but the attribute
        // name is NOT an event handler (only the `on` prefix), so nothing fires.
        for benign in [
            "<button once=true>go</button>",
            "<span online>x</span>",
            "<a onward href=\"/next\">next</a>",
            "<div ongoing>y</div>",
            "<x on-foo=bar>z</x>",
        ] {
            assert!(
                fire(benign).is_none(),
                "non-handler `on*` attr must be clean: {benign:?}"
            );
        }
    }

    #[test]
    fn real_event_handlers_still_fire() {
        // A representative slice across the handler families still fires.
        for payload in [
            "<div ontoggle=alert(1)>x</div>",
            "<div onanimationstart=alert(1)>x</div>",
            "<div onpointerdown=alert(1)>x</div>",
            "<div onbeforeinput=alert(1)>x</div>",
        ] {
            assert_eq!(
                fire(payload)
                    .unwrap_or_else(|| panic!("handler must fire: {payload:?}"))
                    .rule_key,
                "xss.event_handler",
                "payload {payload:?}"
            );
        }
    }

    // ── FP-3: URL scheme strips only tab/CR/LF, keeps internal spaces ──────────

    #[test]
    fn internal_space_in_scheme_is_clean() {
        // A browser's URL parser does NOT remove internal spaces, so `java script:`
        // is not a `javascript:` scheme and never executes → we must not fire.
        for benign in [
            "<a href=\"java script:alert(1)\">x</a>",
            "<a href=\"java\u{0c}script:alert(1)\">x</a>", // form-feed is not stripped internally
        ] {
            assert!(
                fire(benign).is_none(),
                "internal-space scheme must be clean: {benign:?}"
            );
        }
    }

    #[test]
    fn tab_cr_lf_and_leading_space_scheme_still_fires() {
        // tab / CR / LF are stripped from anywhere; leading control/space is
        // trimmed — the classic evasions must still fire.
        for payload in [
            "<a href=\"javas\tcript:alert(1)\">x</a>",
            "<a href=\"javas\ncript:alert(1)\">x</a>",
            "<a href=\"javas\rcript:alert(1)\">x</a>",
            "<a href=\"  javascript:alert(1)\">x</a>",
        ] {
            assert_eq!(
                fire(payload)
                    .unwrap_or_else(|| panic!("evasion must fire: {payload:?}"))
                    .rule_key,
                "xss.js_url",
                "payload {payload:?}"
            );
        }
    }

    // ── Pre-filter / parser safety ─────────────────────────────────────────────

    #[test]
    fn prefilter_skips_non_markup() {
        assert!(!looks_like_markup("a < b < c"));
        assert!(!looks_like_markup("no tags here at all"));
        assert!(looks_like_markup("<a href=x>"));
        assert!(looks_like_markup("</div>"));
        assert!(looks_like_markup("<!doctype html>"));
    }

    #[test]
    fn deeply_nested_divs_do_not_overflow_the_stack() {
        // Arena-backed tree building + non-recursive value walk: a very deep
        // (within-cap) nesting must parse, walk and drop without a stack overflow
        // and report clean (no dangerous construct).
        let depth = 3000; // 3000 × "<div>" = 15000 bytes < XSS_MAX_INPUT_BYTES
        let deep = "<div>".repeat(depth);
        assert!(deep.len() < XSS_MAX_INPUT_BYTES);
        assert!(fire(&deep).is_none(), "deep benign nesting must be clean, not crash");
        // A dangerous element buried at the bottom of a deep tree still fires.
        let deep_attack = format!("{}<img src=x onerror=alert(1)>", "<div>".repeat(depth));
        assert_eq!(
            run(&XssDomDetector::new(), &deep_attack)
                .expect("buried handler must still fire")
                .rule_key,
            "xss.event_handler"
        );
    }

    #[test]
    fn oversized_input_is_declined_by_byte_backstop() {
        // Over the per-parse byte cap → declined (no signal), even though it
        // contains a real script tag. Fail-open: no parse is attempted.
        let big = format!("<script>{}</script>", "a".repeat(XSS_MAX_INPUT_BYTES));
        assert!(big.len() > XSS_MAX_INPUT_BYTES);
        assert!(fire(&big).is_none(), "over-length input must be declined");
    }

    #[test]
    fn html_parse_budget_exhaustion_stops_parsing() {
        let det = XssDomDetector::new();
        let req = throwaway_req();
        let pctx = PreprocessCtx {
            scope: InspectionScope::Body,
            req: &req,
        };
        let mut st = ContentInspectionState::new(Budget {
            max_html_parse_attempts_per_request: 1,
            ..Budget::default()
        });
        // First parse spends the single attempt and hits.
        assert!(det.detect(&view("<script>x</script>"), &pctx, &mut st).is_some());
        assert!(!st.is_degraded());
        // The next parse cannot take an attempt → no signal, request degraded.
        assert!(det.detect(&view("<svg onload=x>"), &pctx, &mut st).is_none());
        assert!(st.is_degraded());
    }

    #[test]
    fn malformed_input_is_fail_safe_not_a_panic() {
        // Broken / truncated markup must never panic and must not spuriously fire.
        for weird in [
            "<<<<<<",
            "<script",
            "<<img src",
            "<div<div<div",
            "<a href=",
            "<!--",
            "<svg><",
        ] {
            // Just must not panic; result may be None or a finding.
            let _ = fire(weird);
        }
        // A bare unclosed non-dangerous fragment stays clean on the default set.
        assert!(fire("<span class=x").is_none());
    }

    // ── Default-off weak signal (dangling_open_tag) ────────────────────────────

    #[test]
    fn dangling_open_tag_is_default_off_but_fires_with_all_constructs() {
        // plan §4 坑1: an input ending in an unclosed dangerous tag is dropped by
        // the WHATWG fragment parser (→ clean on the default set) but retained as a
        // low-confidence weak signal under the all-constructs (test/future) set.
        let dangling = "<img src=x onerror=alert(1)"; // no trailing '>'
        assert!(fire(dangling).is_none(), "dangling tag is default-off in production");
        let f = run(&XssDomDetector::with_all_constructs(), dangling).expect("weak signal fires with all constructs");
        assert_eq!(f.rule_key, "xss.dangling_open_tag");
        assert_eq!(f.confidence, 50);
        // A closed benign tag is not dangling even with all constructs.
        assert!(run(&XssDomDetector::with_all_constructs(), "<p>ok</p>").is_none());
    }
}
