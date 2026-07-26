//! The `ModSecurity` request body processors the CRS rule set is written
//! against, plus the two structural guards they share with Lane 2.
//!
//! # Why a body *processor* and not "the body"
//!
//! Every CRS rule names request *variables*, and which variables a body
//! populates is decided up front by the body processor `ModSecurity` selected
//! for that request's `Content-Type`:
//!
//! | processor    | selected by                                    | populates |
//! |--------------|------------------------------------------------|-----------|
//! | `URLENCODED` | `application/x-www-form-urlencoded`            | `ARGS_POST` |
//! | `MULTIPART`  | `multipart/form-data`                          | `ARGS_POST` (non-file parts), `FILES*` |
//! | `JSON`       | `modsecurity.conf` rule 200001 — `^application/json` | `ARGS_POST` (one per leaf) |
//! | `XML`        | `modsecurity.conf` rule 200000 — the `text/xml`, `application/xml` and `application/soap+xml` family | `XML:` selectors |
//! | none         | anything else, via CRS-901340 `ctl:forceRequestBodyVariable=On` | `REQUEST_BODY` |
//!
//! The reference configuration the CRS regression corpus is scored against
//! (`owasp/modsecurity-crs` — `tests/docker-compose.yml`) ships rules 200000 and
//! 200001, so "CRS detects a payload in a JSON body" means "the JSON processor
//! put that payload in `ARGS`", **not** "a rule read the raw body". A WAF that
//! hands the whole body to the `XML:/*` rules instead is not approximating
//! upstream, it is scanning a surface upstream never offered them — see
//! [`super::owasp`] for what that mis-mapping cost.
//!
//! # Bounds
//!
//! Every entry point here is total: it takes a `&[u8]` window the gateway has
//! already capped, applies its own byte / node / event ceiling on top, and
//! returns whatever it managed to read. A malformed document is not an error, it
//! is simply a shorter answer — the raw-body surface still sees the bytes for
//! the rules that ask for it.

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// Pre-parse structural nesting guard. A body whose bracket / paren nesting
/// exceeds this is declined **before** any recursive parser runs, so a
/// pathologically nested payload can never drive parser recursion into a
/// worker-stack overflow. Set at/under each parser's own limit (`serde_json`
/// 128, `async-graphql-parser` selection-set 64) so admitted input is always
/// within the parser's safe range.
pub const MAX_PARSE_INPUT_DEPTH: usize = 64;

/// Hard ceiling on the body length handed to a processor here. The gateway
/// already caps `body_preview`; this keeps the module self-bounded regardless of
/// the caller.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Descent cap for the JSON walk, mirroring Lane 2's `MAX_STRUCT_DEPTH`.
const MAX_JSON_DEPTH: usize = 32;

/// Most `ARGS_POST` members one JSON body may contribute.
///
/// A JSON document with more leaves than this is not rejected — the members
/// found up to the cap are kept and the rest are not walked, which is the same
/// "honest partial answer" the multipart parser gives on an over-long envelope.
const MAX_JSON_ARGS: usize = 512;

/// Node visits allowed while walking one JSON document, independent of
/// [`MAX_JSON_ARGS`] so that a wide tree of objects carrying no leaves at all
/// still terminates promptly.
const MAX_JSON_NODES: usize = MAX_JSON_ARGS * 32;

/// `quick-xml` events read from one body.
const MAX_XML_EVENTS: usize = 20_000;

/// Bytes of concatenated character data `XML:/*` may yield.
const MAX_XML_TEXT_BYTES: usize = MAX_BODY_BYTES;

/// Attribute values `XML://@*` may yield.
const MAX_XML_ATTRS: usize = 512;

/// `true` when `ModSecurity` would have selected the **XML** body processor.
///
/// The predicate is upstream's `modsecurity.conf` rule 200000 verbatim —
/// `(?:application(?:/soap\+|/)|text/)xml`, matched on the lowercased header,
/// unanchored. That spelling admits `text/xml`, `application/xml` and
/// `application/soap+xml` and, deliberately, nothing else: `application/xhtml+xml`
/// and `application/atom+xml` do **not** activate the XML processor upstream, so
/// a rule reading `XML:/*` sees nothing for them here either.
pub fn is_xml_content_type(content_type: Option<&str>) -> bool {
    let Some(raw) = content_type else {
        return false;
    };
    let lower = raw.to_ascii_lowercase();
    ["application/soap+xml", "application/xml", "text/xml"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// `true` when `ModSecurity` would have selected the **JSON** body processor.
///
/// Upstream's `modsecurity.conf` rule 200001 is `^application/json` on the
/// lowercased header, so the test is a prefix and not a substring: a
/// `Content-Type` that merely mentions JSON somewhere (`text/plain;
/// x=application/json`) does not activate the processor upstream and must not
/// activate it here. The wider content-type list lives in upstream's *optional*
/// rule 200006, which the reference configuration does not enable.
pub fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|raw| raw.trim_start().to_ascii_lowercase().starts_with("application/json"))
}

/// What `ModSecurity`'s XML body processor exposes to the two `XPath` selectors
/// CRS actually uses.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct XmlBody {
    /// `XML:/*` — the *string value* of the document element, i.e. every
    /// descendant text and CDATA node concatenated in document order.
    ///
    /// One value, because `/*` selects one node and `libxml2`'s
    /// `xmlNodeGetContent` — which is what `ModSecurity`'s `var_xml_generate`
    /// calls on it — flattens that node's whole subtree into a single string.
    /// Element *names* and attribute values are not part of a node's string
    /// value and are therefore absent, which is the difference between this
    /// surface and the raw body.
    pub text: String,
    /// `XML://@*` — every attribute value in the document, one collection
    /// member each.
    pub attrs: Vec<String>,
}

/// Parse `body` as XML and return the two surfaces CRS selects from it.
///
/// Malformed input is not an error: the reader stops at the first bad event and
/// the caller gets whatever preceded it. `quick-xml` is a pull parser, so no
/// recursion is involved and nesting cannot overflow the stack.
pub fn parse_xml(body: &[u8]) -> XmlBody {
    let mut out = XmlBody::default();
    if body.is_empty() || body.len() > MAX_BODY_BYTES {
        return out;
    }
    let mut reader = Reader::from_reader(body);
    let mut buf: Vec<u8> = Vec::new();
    for _ in 0..MAX_XML_EVENTS {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) | Err(_) => break,
            Ok(Event::Start(e) | Event::Empty(e)) => collect_attrs(&e, &mut out.attrs),
            Ok(Event::Text(t)) => {
                if let Ok(decoded) = t.decode() {
                    push_text(&mut out.text, &decoded);
                }
            }
            Ok(Event::CData(t)) => {
                if let Ok(decoded) = t.decode() {
                    push_text(&mut out.text, &decoded);
                }
            }
            // An entity reference arrives as its own event in quick-xml 0.41,
            // and its `resolve_char_ref` does not resolve numeric ones — so a
            // payload spelled `&#39;` would reach the rules as nothing at all
            // unless both spellings are resolved here.
            Ok(Event::GeneralRef(r)) => {
                if let Ok(name) = r.decode() {
                    if let Some(c) = decode_numeric_char_ref(&name) {
                        push_text(&mut out.text, c.encode_utf8(&mut [0u8; 4]));
                    } else if let Some(rep) = quick_xml::escape::resolve_predefined_entity(&name) {
                        push_text(&mut out.text, rep);
                    }
                }
            }
            Ok(_) => {}
        }
        buf.clear();
    }
    out
}

/// Append character data to the `XML:/*` accumulator, up to its byte ceiling.
fn push_text(acc: &mut String, piece: &str) {
    let room = MAX_XML_TEXT_BYTES.saturating_sub(acc.len());
    if room == 0 {
        return;
    }
    if piece.len() <= room {
        acc.push_str(piece);
        return;
    }
    // Truncate on a character boundary; a split code point would not be a
    // payload either way.
    let cut = piece
        .char_indices()
        .map(|(at, _)| at)
        .take_while(|at| *at <= room)
        .last()
        .unwrap_or(0);
    acc.push_str(&piece[..cut]);
}

/// Collect one element's attribute values into the `XML://@*` collection.
fn collect_attrs(e: &BytesStart<'_>, out: &mut Vec<String>) {
    for attr in e.attributes() {
        if out.len() >= MAX_XML_ATTRS {
            return;
        }
        if let Ok(a) = attr
            && let Ok(value) = a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
            && !value.is_empty()
        {
            out.push(value.into_owned());
        }
    }
}

/// Flatten a JSON body into `ARGS_POST` members, as `ModSecurity`'s JSON body
/// processor does.
///
/// # The naming is upstream's, and rules depend on it
///
/// `msc_json.c` builds each argument's name by joining the object keys on the
/// way down with `.` and gives array elements the key of the array they are in;
/// a top-level key carries no synthetic prefix. `{"a":{"b":"x"}}` therefore
/// yields `a.b = x`, exactly as it does upstream. The names matter as much as
/// the values: CRS-942290 catches `{"$not": …}` through `ARGS_NAMES`, never
/// through the value.
///
/// Numbers and booleans become members too (upstream adds them through the same
/// `json_add_argument`); `null` is skipped, because upstream's member for it is
/// empty and an empty value cannot match any CRS pattern.
///
/// Returns an empty vector — never an error — for a body that is not JSON, is
/// nested past [`MAX_PARSE_INPUT_DEPTH`], or exceeds [`MAX_BODY_BYTES`]. The
/// caller's raw-body surface is unaffected either way.
pub fn json_args(body: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if body.is_empty() || body.len() > MAX_BODY_BYTES || nesting_depth(body) > MAX_PARSE_INPUT_DEPTH {
        return out;
    }
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(body) else {
        return out;
    };
    let mut visited = 0usize;
    let mut stack: Vec<(&serde_json::Value, String, usize)> = vec![(&root, String::new(), 0)];
    while let Some((node, path, depth)) = stack.pop() {
        if out.len() >= MAX_JSON_ARGS || visited >= MAX_JSON_NODES {
            break;
        }
        visited = visited.saturating_add(1);
        match node {
            serde_json::Value::Object(map) => {
                if depth >= MAX_JSON_DEPTH {
                    continue;
                }
                for (key, value) in map {
                    let child = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    stack.push((value, child, depth.saturating_add(1)));
                }
            }
            // An array contributes no name of its own upstream: its elements are
            // members of the key the array is bound to.
            serde_json::Value::Array(items) => {
                if depth >= MAX_JSON_DEPTH {
                    continue;
                }
                for value in items {
                    stack.push((value, path.clone(), depth.saturating_add(1)));
                }
            }
            serde_json::Value::String(text) => out.push((path, text.clone())),
            serde_json::Value::Number(number) => out.push((path, number.to_string())),
            serde_json::Value::Bool(flag) => out.push((path, flag.to_string())),
            serde_json::Value::Null => {}
        }
    }
    out
}

/// String-aware maximum bracket / paren nesting depth. Counts `{ [ (` opens and
/// `} ] )` closes, skipping anything inside a `"…"` string (with `\` escaping) so
/// brackets in a benign string value never inflate the estimate. A cheap linear
/// pre-parse `DoS` guard — an over-approximation is safe (it only declines more
/// aggressively), never a panic.
pub fn nesting_depth(bytes: &[u8]) -> usize {
    let mut depth: usize = 0;
    let mut max: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' | b'(' => {
                depth += 1;
                max = max.max(depth);
            }
            b'}' | b']' | b')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// Resolve an XML numeric character reference from a `GeneralRef` name: decimal
/// `#NN` (`&#39;`) or hexadecimal `#xNN` / `#XNN` (`&#x27;`). Returns `None` for a
/// named entity (`apos`), an out-of-range code point, or malformed digits — the
/// caller then falls back to the predefined-entity table. Never panics.
pub fn decode_numeric_char_ref(name: &str) -> Option<char> {
    let rest = name.strip_prefix('#')?;
    // Empty digits make both `from_str_radix` and `parse` fail (→ None), so no
    // explicit emptiness check is needed.
    let code = match rest.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => rest.parse::<u32>().ok()?,
    };
    char::from_u32(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted(mut args: Vec<(String, String)>) -> Vec<(String, String)> {
        args.sort();
        args
    }

    #[test]
    fn the_xml_content_types_upstream_rule_200000_selects() {
        assert!(is_xml_content_type(Some("text/xml")));
        assert!(is_xml_content_type(Some("application/xml; charset=utf-8")));
        assert!(is_xml_content_type(Some("APPLICATION/XML")));
        assert!(is_xml_content_type(Some("application/soap+xml")));
        // Not selected upstream, so not selected here.
        assert!(!is_xml_content_type(Some("application/xhtml+xml")));
        assert!(!is_xml_content_type(Some("application/atom+xml")));
        assert!(!is_xml_content_type(Some("application/json")));
        assert!(!is_xml_content_type(None));
    }

    #[test]
    fn the_json_content_type_is_a_prefix_test_not_a_substring_one() {
        assert!(is_json_content_type(Some("application/json")));
        assert!(is_json_content_type(Some("application/json; charset=utf-8")));
        assert!(is_json_content_type(Some("Application/JSON")));
        assert!(!is_json_content_type(Some("text/plain; x=application/json")));
        assert!(!is_json_content_type(Some("application/ld+json")));
        assert!(!is_json_content_type(None));
    }

    #[test]
    fn xml_text_is_the_documents_character_data_only() {
        let body = br#"<?xml version="1.0"?><a x="attr-value">one<b>two</b></a>"#;
        let parsed = parse_xml(body);
        assert_eq!(parsed.text, "onetwo");
        assert_eq!(parsed.attrs, vec!["attr-value".to_owned()]);
        // Element names are part of neither surface — that is the whole reason
        // the raw body was the wrong approximation.
        assert!(!parsed.text.contains('a'));
    }

    #[test]
    fn xml_attributes_are_one_member_each() {
        let parsed = parse_xml(br#"<r><t a="1" b="2"/><t a="3"/></r>"#);
        assert_eq!(parsed.attrs, vec!["1".to_owned(), "2".to_owned(), "3".to_owned()]);
        assert!(parsed.text.is_empty());
    }

    #[test]
    fn xml_entity_references_are_resolved_into_the_text_run() {
        let parsed = parse_xml(b"<r>&lt;script&gt;&#39;&#x27;</r>");
        assert_eq!(parsed.text, "<script>''");
    }

    #[test]
    fn cdata_is_character_data() {
        let parsed = parse_xml(b"<r><![CDATA[' OR 1=1--]]></r>");
        assert_eq!(parsed.text, "' OR 1=1--");
    }

    #[test]
    fn malformed_xml_yields_what_was_read_and_never_panics() {
        let parsed = parse_xml(b"<r>payload<unclosed");
        assert!(parsed.text.contains("payload"));
    }

    #[test]
    fn an_oversized_body_is_declined_by_both_processors() {
        let big = vec![b'a'; MAX_BODY_BYTES + 1];
        assert_eq!(parse_xml(&big), XmlBody::default());
        assert!(json_args(&big).is_empty());
    }

    #[test]
    fn json_leaves_take_the_dotted_key_path_upstream_gives_them() {
        let args = sorted(json_args(br#"{"a":{"b":"x"},"c":"y"}"#));
        assert_eq!(
            args,
            vec![("a.b".to_owned(), "x".to_owned()), ("c".to_owned(), "y".to_owned()),]
        );
    }

    #[test]
    fn json_array_elements_are_members_of_the_key_that_holds_the_array() {
        let args = sorted(json_args(br#"{"tags":["one","two"]}"#));
        assert_eq!(
            args,
            vec![
                ("tags".to_owned(), "one".to_owned()),
                ("tags".to_owned(), "two".to_owned()),
            ]
        );
    }

    #[test]
    fn a_nosql_operator_key_survives_as_the_member_name() {
        // CRS-942290 reads this through ARGS_NAMES and nothing else.
        assert_eq!(
            json_args(br#"{"$not": "foo"}"#),
            vec![("$not".to_owned(), "foo".to_owned())]
        );
    }

    #[test]
    fn json_scalars_other_than_null_become_members() {
        let args = sorted(json_args(br#"{"n":42,"t":true,"z":null}"#));
        assert_eq!(
            args,
            vec![("n".to_owned(), "42".to_owned()), ("t".to_owned(), "true".to_owned())]
        );
    }

    #[test]
    fn malformed_json_yields_no_members() {
        assert!(json_args(b"{not json").is_empty());
        assert!(json_args(b"").is_empty());
    }

    #[test]
    fn pathological_json_nesting_is_declined_before_the_parser_runs() {
        let deep = format!(
            "{}1{}",
            "[".repeat(MAX_PARSE_INPUT_DEPTH + 5),
            "]".repeat(MAX_PARSE_INPUT_DEPTH + 5)
        );
        assert!(json_args(deep.as_bytes()).is_empty());
    }

    #[test]
    fn the_json_member_count_is_bounded() {
        let members: Vec<String> = (0..(MAX_JSON_ARGS * 2)).map(|i| format!("\"k{i}\":\"v\"")).collect();
        let body = format!("{{{}}}", members.join(","));
        assert!(json_args(body.as_bytes()).len() <= MAX_JSON_ARGS);
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        for seed in 0u8..=255 {
            let noise: Vec<u8> = (0..64).map(|i| seed.wrapping_mul(i).wrapping_add(i)).collect();
            let _ = parse_xml(&noise);
            let _ = json_args(&noise);
        }
    }
}
