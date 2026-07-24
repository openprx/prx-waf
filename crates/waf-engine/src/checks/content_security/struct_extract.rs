//! Lane B — structured request-body **field extraction** for the semantic lane.
//!
//! The Lane 2 preprocessor (`super::preprocess`) treats a request body as a single
//! opaque `"body"` field. A payload buried in a deep JSON leaf, a JSON/GraphQL
//! string escape (`'` → `'`), a GraphQL variable, an XML text node split
//! across sibling elements, or one `multipart/form-data` part is therefore never
//! isolated for a detector — the whole-body view mixes it with unrelated bytes and
//! the structural / AST detectors score it 0. This module pulls the **leaf string
//! values** out of a structured body so each becomes its own field for the
//! existing five-family detector set.
//!
//! It also surfaces every `$`-prefixed JSON **object key** as its own leaf (under
//! [`NOSQL_OP_LABEL`]) so a `MongoDB`-style `NoSQL` operator injection — whose signal
//! lives in the key (`{"user":{"$ne":null}}`), not a string value — reaches the
//! `NoSqlInjection` detector (T2-B). This is the one place a *key* (not a value)
//! becomes a field.
//!
//! It adds **no detector** and changes **no scoring**: it only widens the field
//! source set the existing pipeline already consumes. The whole-body view is still
//! produced unchanged (`super::preprocess::collect_field_sources` keeps it), so
//! this is strictly additive — a body that is not structured (or does not parse)
//! yields no extra fields and the pipeline behaves exactly as before.
//!
//! # `DoS` safety (Lane A P0 precedent)
//! Every parser and every walk is depth-bounded so no input can drive unbounded
//! native recursion into a worker-stack overflow (the Lane A brush-parser P0). A
//! Rust stack overflow aborts the process (SIGABRT) and is **not** catchable, so
//! every pathological input must be refused *before* the recursive parser runs:
//!   * JSON: [`nesting_depth`] is a cheap, string-aware linear pre-scan that
//!     **declines a pathologically nested body before `serde_json` (which recurses
//!     while building `Value`) is invoked** — refused past [`MAX_PARSE_INPUT_DEPTH`],
//!     set at/under `serde_json`'s own 128 recursion limit.
//!   * GraphQL: a *lexer-accurate* pre-scan ([`graphql_max_depth`]) is required —
//!     `async-graphql-parser` only bounds selection-set recursion (at 64); its
//!     value parser (`parse_value` / `parse_const_value`, over `[…]` / `{…}`
//!     literals) has **no** depth guard and overflows a 2 MiB worker stack at ~330
//!     nested levels. A naive scan is not enough: a `#…` line comment or a `"…"` /
//!     `"""…"""` string can contain a lone `"`/bracket that a JSON-style scan
//!     mis-tracks, hiding the real depth (a 6 KB request drove a live worker
//!     `RestartCount 0→1`). [`graphql_max_depth`] therefore skips comments and
//!     both string forms exactly, then counts `( [ {` nesting; anything past
//!     [`MAX_PARSE_INPUT_DEPTH`] is declined. As a belt-and-suspenders backstop
//!     that no comment/string trick can bypass, [`graphql_raw_open_total`] counts
//!     **every** raw `( [ {` with no skipping — since the total open count is an
//!     absolute upper bound on achievable nesting, a body exceeding
//!     [`MAX_GRAPHQL_RAW_OPENS`] (kept well under the ~330 crash depth) is declined
//!     even if the lexer scan were somehow defeated. Either guard tripping refuses
//!     the parse and falls back to the whole-body view.
//!   * Every leaf walk is **iterative** (an explicit stack, never native
//!     recursion) with a hard [`MAX_STRUCT_DEPTH`] descent cap and a visited-node
//!     budget, so even a legally-parsed structure cannot exhaust the stack.
//!   * `quick-xml` is a pull parser (no recursion by construction); its walk is
//!     bounded by an event budget and the same depth cap.
//!   * The whole body handed to any parser is itself capped at
//!     [`MAX_EXTRACT_INPUT_BYTES`] (the gateway already caps `body_preview` at
//!     64 KiB; this is defence in depth if that ever changes).
//!
//! `multipart` runs `multer` over an in-memory one-shot stream driven by
//! `pollster::block_on`; the future is pure-memory ready (the whole body is
//! yielded in a single already-complete chunk) and never awaits real I/O, so it
//! cannot park a tokio worker.

use std::borrow::Cow;
use std::convert::Infallible;

use async_graphql_value::{ConstValue, Value as GqlValue};
use bytes::Bytes;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

/// A structured leaf: a field label plus its (parser-unescaped) value.
type Leaf = (Cow<'static, str>, String);

/// Iterative walk / emit descent cap. A node deeper than this is not descended —
/// a documented honest boundary (never a panic), mirroring Lane A's post-parse
/// `SHELL_WALK_MAX_DEPTH`.
const MAX_STRUCT_DEPTH: usize = 32;

/// Pre-parse structural nesting guard. A body whose bracket / paren nesting
/// exceeds this is declined **before** any recursive parser runs, so a
/// pathologically nested payload can never drive parser recursion into a
/// worker-stack overflow. Set at/under each parser's own limit (`serde_json` 128,
/// `async-graphql-parser` selection-set 64) so admitted input is always within the
/// parser's safe range. GraphQL is additionally backstopped by
/// [`MAX_GRAPHQL_RAW_OPENS`] because its *value* parser is not depth-limited.
const MAX_PARSE_INPUT_DEPTH: usize = 64;

/// GraphQL belt-and-suspenders backstop: the maximum number of raw `( [ {` opening
/// delimiters a GraphQL body may contain (counted with **no** string/comment
/// skipping). The total open count is an absolute upper bound on achievable
/// nesting, so this cannot be bypassed by any comment / string lexing trick. Kept
/// well under the measured ~330-level `parse_value` overflow depth on a 2 MiB
/// worker stack, yet far above any realistic query's delimiter count, so a normal
/// wide-but-shallow query is never declined by it.
const MAX_GRAPHQL_RAW_OPENS: usize = MAX_PARSE_INPUT_DEPTH * 4;

/// Hard ceiling on the whole-body byte length handed to any structured parser.
/// The gateway already caps `body_preview` at 64 KiB; this keeps the module
/// self-bounded regardless of the caller.
const MAX_EXTRACT_INPUT_BYTES: usize = 64 * 1024;

/// Absolute ceiling on `multipart` parts inspected, independent of the field
/// budget, to blunt a multipart-bomb (thousands of tiny parts) up front.
const MAX_MULTIPART_PARTS: usize = 256;

/// Per-`Value` walk node ceiling (a single GraphQL argument literal / list /
/// object). Bounds a wide inline literal independent of the overall field budget.
const MAX_VALUE_NODES: usize = 256;

const JSON_LABEL: &str = "body.json";
const XML_LABEL: &str = "body.xml";
const GQL_LABEL: &str = "body.graphql";
const MULTIPART_LABEL: &str = "body.multipart";

/// Label for a `$`-prefixed JSON **object key** surfaced as its own leaf (T2-B).
///
/// A `MongoDB`-style `NoSQL` operator injection (`{"user":{"$ne":null}}`) carries its
/// signal in the object **key** (`$ne`), not a string value, so the value-only leaf
/// extraction above never surfaces it. This module therefore emits every
/// `$`-prefixed key as a leaf under this label; the `NoSqlInjection` detector
/// anchored-matches the known dangerous operators against it. `serde_json` has
/// already unicode-unescaped the key, so a `$`-encoded `$` is caught. A
/// non-operator `$`-key (`$schema`, `$ref`) is surfaced too but matches no rule, so
/// it produces no finding.
pub(super) const NOSQL_OP_LABEL: &str = "body.nosql.op";

/// Extract leaf string fields from a structured request body.
///
/// Dispatch is by `Content-Type` (with a cheap first-byte sniff when the header is
/// absent or non-decisive). Returns owned `(label, value)` pairs — values are
/// owned because parsing unescapes them into fresh strings. At most `max_fields`
/// leaves are returned; the caller still meters each one through the per-field
/// budget, so this cap is an early bound, not the authoritative one.
///
/// Never panics and never allocates for a non-structured body: an unrecognised
/// content-type whose first byte is not a structured opener returns empty.
pub(super) fn extract_body_fields(body: &[u8], content_type: Option<&str>, max_fields: usize) -> Vec<Leaf> {
    let mut out = Vec::new();
    if body.is_empty() || max_fields == 0 || body.len() > MAX_EXTRACT_INPUT_BYTES {
        return out;
    }

    let raw_ct = content_type.unwrap_or_default();
    let ct = raw_ct.to_ascii_lowercase();

    if ct.contains("multipart/form-data") {
        // Boundary parsing is case-sensitive — hand it the ORIGINAL header.
        extract_multipart(body, raw_ct, max_fields, &mut out);
    } else if ct.contains("json") {
        // Covers GraphQL-over-JSON too (`{"query":…,"variables":…}`): the query
        // string and every variable value are leaves.
        extract_json(body, max_fields, &mut out);
    } else if ct.contains("graphql") {
        extract_graphql(body, max_fields, &mut out);
    } else if ct.contains("xml") {
        extract_xml(body, max_fields, &mut out);
    } else {
        // No decisive content-type: a single cheap first-byte sniff. Only a
        // structured opener triggers a parse; form-urlencoded / plain text is left
        // entirely to the existing whole-body view (zero behaviour change).
        match first_non_ws(body) {
            Some(b'{' | b'[') => extract_json(body, max_fields, &mut out),
            Some(b'<') => extract_xml(body, max_fields, &mut out),
            _ => {}
        }
    }
    out
}

/// First non-whitespace byte of `body`, for the content-type-absent sniff.
fn first_non_ws(body: &[u8]) -> Option<u8> {
    body.iter().copied().find(|b| !b.is_ascii_whitespace())
}

/// String-aware maximum bracket / paren nesting depth. Counts `{ [ (` opens and
/// `} ] )` closes, skipping anything inside a `"…"` string (with `\` escaping) so
/// brackets in a benign string value never inflate the estimate. A cheap linear
/// pre-parse `DoS` guard — an over-approximation is safe (it only declines more
/// aggressively), never a panic.
fn nesting_depth(bytes: &[u8]) -> usize {
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

/// Push one non-empty, trimmed leaf. Empty / whitespace-only leaves never become
/// a field (they cannot carry an attack and only waste budget).
fn push_leaf(out: &mut Vec<Leaf>, label: &'static str, value: &str) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        out.push((Cow::Borrowed(label), trimmed.to_owned()));
    }
}

// ── JSON ──────────────────────────────────────────────────────────────────────

/// Extract every string leaf from a JSON body via an **iterative** walk. The
/// pre-parse [`nesting_depth`] guard declines pathological nesting before
/// `serde_json` (which recurses while building `Value`) is invoked.
fn extract_json(body: &[u8], max_fields: usize, out: &mut Vec<Leaf>) {
    if nesting_depth(body) > MAX_PARSE_INPUT_DEPTH {
        return;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return;
    };
    let node_budget = max_fields.saturating_mul(32).max(512);
    let mut visited = 0usize;
    let mut stack: Vec<(&serde_json::Value, usize)> = vec![(&value, 0)];
    while let Some((node, depth)) = stack.pop() {
        if out.len() >= max_fields || visited >= node_budget {
            break;
        }
        visited += 1;
        if depth > MAX_STRUCT_DEPTH {
            continue;
        }
        match node {
            serde_json::Value::String(s) => push_leaf(out, JSON_LABEL, s),
            serde_json::Value::Array(items) => {
                for item in items {
                    stack.push((item, depth + 1));
                }
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    // T2-B: a `$`-prefixed key is a MongoDB-style operator carrier —
                    // surface it as its own leaf so the NoSQL detector can inspect the
                    // KEY (the value-only leaves never see it). Bounded by the same
                    // field cap; the key text is already unicode-unescaped by serde.
                    if out.len() < max_fields && k.starts_with('$') {
                        push_leaf(out, NOSQL_OP_LABEL, k);
                    }
                    stack.push((v, depth + 1));
                }
            }
            // Numbers / bools / null carry no attack surface.
            _ => {}
        }
    }
}

// ── XML ───────────────────────────────────────────────────────────────────────

/// Extract text nodes, CDATA and attribute values from an XML body. `quick-xml`
/// is a pull parser (iterative, no recursion), so depth cannot overflow the stack;
/// the depth counter is a defence-in-depth emit bound and the event budget caps
/// total work.
///
/// quick-xml 0.41 emits an entity reference (`&lt;`, `&#39;`) inside character
/// data as a **separate** [`Event::GeneralRef`] event, which would otherwise split
/// `&lt;script&gt;` into three fragments. The per-element text accumulator
/// (`acc`) coalesces consecutive text / CDATA / entity-ref events into one leaf,
/// flushing at each element boundary — so an entity-encoded payload is
/// reconstructed whole (`<script>`) while genuine sibling elements
/// (`<a>1 UNION</a><b>SELECT</b>`) stay separate leaves. Numeric character
/// references (`&#39;`, `&#x27;`) are resolved by [`decode_numeric_char_ref`]:
/// quick-xml 0.41's `BytesRef::resolve_char_ref` does not resolve them, so a
/// payload encoded as `&#39;`/`&#60;` would otherwise reach Lane 2 as nothing.
fn extract_xml(body: &[u8], max_fields: usize, out: &mut Vec<Leaf>) {
    let mut reader = Reader::from_reader(body);
    let mut buf: Vec<u8> = Vec::new();
    let mut depth: usize = 0;
    let mut events = 0usize;
    let event_budget = max_fields.saturating_mul(16).max(1024);
    // Per-element coalesced character data (text + CDATA + resolved entity refs).
    let mut acc = String::new();
    loop {
        if out.len() >= max_fields || events >= event_budget {
            break;
        }
        events += 1;
        match reader.read_event_into(&mut buf) {
            // EOF, or malformed XML: flush and stop cleanly (the whole-body view
            // still inspects the raw bytes).
            Ok(Event::Eof) | Err(_) => {
                flush_xml_text(&mut acc, max_fields, out);
                break;
            }
            // An element boundary terminates the current text run.
            Ok(Event::Start(e)) => {
                flush_xml_text(&mut acc, max_fields, out);
                collect_xml_attrs(&e, max_fields, out);
                depth = depth.saturating_add(1);
            }
            Ok(Event::Empty(e)) => {
                flush_xml_text(&mut acc, max_fields, out);
                collect_xml_attrs(&e, max_fields, out);
            }
            Ok(Event::End(_)) => {
                flush_xml_text(&mut acc, max_fields, out);
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Text(t)) => {
                if depth <= MAX_STRUCT_DEPTH
                    && let Ok(decoded) = t.decode()
                {
                    acc.push_str(&decoded);
                }
            }
            Ok(Event::CData(t)) => {
                if depth <= MAX_STRUCT_DEPTH
                    && let Ok(decoded) = t.decode()
                {
                    acc.push_str(&decoded);
                }
            }
            // Entity reference: numeric char ref (`&#39;`, `&#x27;`) or a predefined
            // named entity (`&lt;`); resolved into the current text run. Numeric
            // refs are decoded by hand — quick-xml 0.41's `resolve_char_ref` does
            // not resolve them, so relying on it silently drops the payload.
            Ok(Event::GeneralRef(r)) => {
                if depth <= MAX_STRUCT_DEPTH
                    && let Ok(name) = r.decode()
                {
                    if let Some(c) = decode_numeric_char_ref(&name) {
                        acc.push(c);
                    } else if let Some(rep) = quick_xml::escape::resolve_predefined_entity(&name) {
                        acc.push_str(rep);
                    }
                }
            }
            Ok(_) => {}
        }
        buf.clear();
    }
}

/// Flush the coalesced per-element XML text run as one leaf (trimmed, non-empty),
/// resetting the accumulator.
fn flush_xml_text(acc: &mut String, max_fields: usize, out: &mut Vec<Leaf>) {
    if out.len() < max_fields {
        push_leaf(out, XML_LABEL, acc);
    }
    acc.clear();
}

/// Resolve an XML numeric character reference from a `GeneralRef` name: decimal
/// `#NN` (`&#39;`) or hexadecimal `#xNN` / `#XNN` (`&#x27;`). Returns `None` for a
/// named entity (`apos`), an out-of-range code point, or malformed digits — the
/// caller then falls back to the predefined-entity table. Never panics.
fn decode_numeric_char_ref(name: &str) -> Option<char> {
    let rest = name.strip_prefix('#')?;
    // Empty digits make both `from_str_radix` and `parse` fail (→ None), so no
    // explicit emptiness check is needed.
    let code = match rest.strip_prefix(['x', 'X']) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => rest.parse::<u32>().ok()?,
    };
    char::from_u32(code)
}

/// Collect the (entity-unescaped) attribute values of one start/empty element.
fn collect_xml_attrs(e: &BytesStart<'_>, max_fields: usize, out: &mut Vec<Leaf>) {
    for attr in e.attributes() {
        if out.len() >= max_fields {
            break;
        }
        if let Ok(a) = attr
            && let Ok(v) = a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
        {
            push_leaf(out, XML_LABEL, &v);
        }
    }
}

// ── GraphQL (raw `application/graphql` document) ──────────────────────────────

/// Lexer-accurate maximum `( [ {` nesting depth of a GraphQL document.
///
/// Unlike the JSON-oriented [`nesting_depth`], this understands GraphQL lexing so a
/// bracket hidden in a comment or string cannot inflate the count and — critically
/// for the `DoS` guard — a lone `"` inside a `#…` comment cannot make a naive scan
/// treat the rest of the document as an unterminated string and thereby *miss* a
/// deep value. It skips, exactly:
///   * `#…` line comments (to the next `\n` / `\r`),
///   * `"""…"""` block strings (only `\"""` escapes the delimiter),
///   * `"…"` normal strings (`\` escapes the next char; a raw line terminator ends
///     the scan of the string defensively),
///
/// then counts `( [ {` opens against `) ] }` closes. Over-counting is safe (it only
/// declines more); the scan never under-counts a real bracket outside a string.
fn graphql_max_depth(bytes: &[u8]) -> usize {
    let is_triple =
        |j: usize| bytes.get(j) == Some(&b'"') && bytes.get(j + 1) == Some(&b'"') && bytes.get(j + 2) == Some(&b'"');
    let mut depth: usize = 0;
    let mut max: usize = 0;
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'#' => {
                i += 1;
                while let Some(&c) = bytes.get(i) {
                    if c == b'\n' || c == b'\r' {
                        break;
                    }
                    i += 1;
                }
            }
            b'"' if is_triple(i) => {
                // Block string: advance past `"""`, then to the closing `"""`,
                // treating `\"""` as an escaped (non-terminating) delimiter.
                i += 3;
                loop {
                    match bytes.get(i) {
                        None => break,
                        Some(&b'\\')
                            if bytes.get(i + 1) == Some(&b'"')
                                && bytes.get(i + 2) == Some(&b'"')
                                && bytes.get(i + 3) == Some(&b'"') =>
                        {
                            i += 4;
                        }
                        _ if is_triple(i) => {
                            i += 3;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
            }
            b'"' => {
                // Normal string: `\` escapes the next byte; ends at an unescaped `"`.
                i += 1;
                while let Some(&c) = bytes.get(i) {
                    match c {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        b'\n' | b'\r' => break,
                        _ => i += 1,
                    }
                }
            }
            b'{' | b'[' | b'(' => {
                depth += 1;
                max = max.max(depth);
                i += 1;
            }
            b'}' | b']' | b')' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }
    max
}

/// Count of **every** raw `( [ {` opener with no string/comment skipping — an
/// absolute, un-bypassable upper bound on the document's achievable nesting depth.
/// The belt-and-suspenders backstop behind [`graphql_max_depth`].
fn graphql_raw_open_total(bytes: &[u8]) -> usize {
    bytes.iter().filter(|&&b| b == b'{' || b == b'[' || b == b'(').count()
}

/// Extract string literals from a raw GraphQL query document: inline field /
/// directive argument values (GraphQL-unescaped) and variable default values,
/// across every operation and fragment.
///
/// `async-graphql-parser` bounds only its selection-set recursion (at 64); its
/// value parser (`parse_value` / `parse_const_value`) is **un-guarded** and
/// overflows the worker stack on a deeply nested `[…]` / `{…}` literal. So before
/// `parse_query` runs, the document must pass **both** the lexer-accurate
/// [`graphql_max_depth`] guard (`≤ MAX_PARSE_INPUT_DEPTH`) and the un-bypassable
/// [`graphql_raw_open_total`] backstop (`≤ MAX_GRAPHQL_RAW_OPENS`); either tripping
/// declines the parse and falls back to the whole-body view. The post-parse
/// selection-set walk and every value walk are iterative with a depth cap.
fn extract_graphql(body: &[u8], max_fields: usize, out: &mut Vec<Leaf>) {
    use async_graphql_parser::types::{Selection, SelectionSet};

    if graphql_max_depth(body) > MAX_PARSE_INPUT_DEPTH || graphql_raw_open_total(body) > MAX_GRAPHQL_RAW_OPENS {
        return;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let Ok(doc) = async_graphql_parser::parse_query(text) else {
        return;
    };

    let mut sel_stack: Vec<(&SelectionSet, usize)> = Vec::new();
    for (_name, op) in doc.operations.iter() {
        sel_stack.push((&op.node.selection_set.node, 0));
        for var in &op.node.variable_definitions {
            if let Some(dv) = &var.node.default_value {
                walk_gql_const_value(&dv.node, max_fields, out);
            }
        }
    }
    for frag in doc.fragments.values() {
        sel_stack.push((&frag.node.selection_set.node, 0));
    }

    let node_budget = max_fields.saturating_mul(32).max(512);
    let mut visited = 0usize;
    while let Some((sel, depth)) = sel_stack.pop() {
        if out.len() >= max_fields || visited >= node_budget {
            break;
        }
        visited += 1;
        if depth > MAX_STRUCT_DEPTH {
            continue;
        }
        for item in &sel.items {
            match &item.node {
                Selection::Field(f) => {
                    for (_arg, val) in &f.node.arguments {
                        walk_gql_value(&val.node, max_fields, out);
                    }
                    for dir in &f.node.directives {
                        for (_arg, val) in &dir.node.arguments {
                            walk_gql_value(&val.node, max_fields, out);
                        }
                    }
                    sel_stack.push((&f.node.selection_set.node, depth + 1));
                }
                Selection::InlineFragment(inf) => {
                    sel_stack.push((&inf.node.selection_set.node, depth + 1));
                }
                Selection::FragmentSpread(_) => {}
            }
        }
    }
}

/// Iterative string-leaf walk over a GraphQL `Value` (field / directive argument).
fn walk_gql_value(root: &GqlValue, max_fields: usize, out: &mut Vec<Leaf>) {
    let mut stack: Vec<(&GqlValue, usize)> = vec![(root, 0)];
    let mut visited = 0usize;
    while let Some((v, depth)) = stack.pop() {
        if out.len() >= max_fields || visited >= MAX_VALUE_NODES {
            break;
        }
        visited += 1;
        if depth > MAX_STRUCT_DEPTH {
            continue;
        }
        match v {
            GqlValue::String(s) => push_leaf(out, GQL_LABEL, s),
            GqlValue::List(items) => {
                for item in items {
                    stack.push((item, depth + 1));
                }
            }
            GqlValue::Object(map) => {
                for val in map.values() {
                    stack.push((val, depth + 1));
                }
            }
            _ => {}
        }
    }
}

/// Iterative string-leaf walk over a GraphQL `ConstValue` (variable default).
fn walk_gql_const_value(root: &ConstValue, max_fields: usize, out: &mut Vec<Leaf>) {
    let mut stack: Vec<(&ConstValue, usize)> = vec![(root, 0)];
    let mut visited = 0usize;
    while let Some((v, depth)) = stack.pop() {
        if out.len() >= max_fields || visited >= MAX_VALUE_NODES {
            break;
        }
        visited += 1;
        if depth > MAX_STRUCT_DEPTH {
            continue;
        }
        match v {
            ConstValue::String(s) => push_leaf(out, GQL_LABEL, s),
            ConstValue::List(items) => {
                for item in items {
                    stack.push((item, depth + 1));
                }
            }
            ConstValue::Object(map) => {
                for val in map.values() {
                    stack.push((val, depth + 1));
                }
            }
            _ => {}
        }
    }
}

// ── multipart/form-data ───────────────────────────────────────────────────────

/// Extract each part's text value from a `multipart/form-data` body. `multer`
/// runs over a one-shot in-memory stream driven by `pollster::block_on`; the future
/// is pure-memory ready (the whole body is a single already-complete chunk) and
/// never awaits real I/O, so it cannot park a tokio worker. A hard part cap plus a
/// whole-stream byte limit blunt a multipart-bomb before the field budget sees it.
fn extract_multipart(body: &[u8], content_type: &str, max_fields: usize, out: &mut Vec<Leaf>) {
    let Ok(boundary) = multer::parse_boundary(content_type) else {
        return;
    };
    let part_limit = max_fields.min(MAX_MULTIPART_PARTS);
    if part_limit == 0 {
        return;
    }

    let bytes = Bytes::copy_from_slice(body);
    let stream = futures_util::stream::once(async move { Ok::<Bytes, Infallible>(bytes) });
    #[allow(clippy::cast_possible_truncation)]
    let constraints = multer::Constraints::new().size_limit(multer::SizeLimit::new().whole_stream(body.len() as u64));
    let mut multipart = multer::Multipart::with_constraints(stream, boundary, constraints);

    pollster::block_on(async {
        let mut parts = 0usize;
        while parts < part_limit && out.len() < max_fields {
            match multipart.next_field().await {
                Ok(Some(field)) => {
                    parts += 1;
                    // A part's declared filename can itself carry a payload.
                    if let Some(name) = field.file_name() {
                        push_leaf(out, MULTIPART_LABEL, name);
                    }
                    // `text()` consumes the field and decodes its body; a non-UTF-8
                    // or over-limit part yields an error and is skipped.
                    if let Ok(text) = field.text().await {
                        push_leaf(out, MULTIPART_LABEL, &text);
                    }
                }
                // End of parts or a parse error: stop cleanly.
                _ => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels_values(leaves: &[Leaf]) -> Vec<(&str, &str)> {
        leaves.iter().map(|(l, v)| (l.as_ref(), v.as_str())).collect()
    }

    fn any_value_contains(leaves: &[Leaf], needle: &str) -> bool {
        leaves.iter().any(|(_, v)| v.contains(needle))
    }

    // ── JSON ──────────────────────────────────────────────────────────────────

    #[test]
    fn json_unicode_escape_leaf_is_extracted_and_unescaped() {
        // k3 probe: a `'` (') hidden in a JSON string leaf bypasses the
        // whole-body field. Extraction must surface the unescaped value.
        let body = br#"{"user":{"name":"admin' OR '1'='1"}}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(
            any_value_contains(&leaves, "admin' OR '1'='1"),
            "unicode-escaped SQLi leaf must be extracted & unescaped: {:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn json_deeply_nested_leaf_is_extracted() {
        // 5-level nesting (k3 probe) — the deep leaf must be pulled out.
        let body = br#"{"a":{"b":{"c":{"d":{"e":"1 UNION SELECT password FROM users"}}}}}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(
            any_value_contains(&leaves, "UNION SELECT"),
            "deep JSON leaf must be extracted: {:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn json_array_leaves_are_extracted() {
        let body = br#"["benign", "<script>alert(1)</script>", 42, true, null]"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(any_value_contains(&leaves, "<script>"));
        // Numbers / bools / null are not leaves.
        assert!(!any_value_contains(&leaves, "42"));
    }

    #[test]
    fn json_graphql_variables_are_extracted() {
        // GraphQL-over-JSON: the query string AND each variable value are leaves.
        let body = br#"{"query":"query($n:String){u(name:$n){id}}","variables":{"n":"' OR 1=1--"}}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(
            any_value_contains(&leaves, "' OR 1=1--"),
            "graphql variable (json) must be extracted & unescaped: {:?}",
            labels_values(&leaves)
        );
    }

    // ── NoSQL operator keys (T2-B) ──────────────────────────────────────────────

    fn op_leaves(leaves: &[Leaf]) -> Vec<&str> {
        leaves
            .iter()
            .filter(|(l, _)| l == NOSQL_OP_LABEL)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    #[test]
    fn json_dollar_key_is_surfaced_as_op_leaf() {
        // The classic auth-bypass shape: the operator is the KEY, not a value. It
        // must surface under the dedicated op label.
        let body = br#"{"user":"admin","pw":{"$ne":null}}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(
            op_leaves(&leaves).contains(&"$ne"),
            "the $ne operator key must surface as a {NOSQL_OP_LABEL} leaf: {:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn json_unicode_escaped_dollar_key_is_decoded_and_surfaced() {
        // `$where` decodes to `$where` — serde unescapes the key before we see
        // it, so the raw-text `$`-encoding evasion cannot slip past.
        let body = br#"{"$where":"sleep(1000)"}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(
            op_leaves(&leaves).contains(&"$where"),
            "unicode-escaped operator key must decode & surface: {:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn json_deep_nested_operator_key_is_surfaced() {
        let body = br#"{"a":{"b":{"c":{"$gt":""}}}}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(op_leaves(&leaves).contains(&"$gt"), "{:?}", labels_values(&leaves));
    }

    #[test]
    fn json_non_operator_dollar_key_is_surfaced_but_harmless() {
        // A `$`-key that is not a Mongo operator (JSON-Schema `$schema`) is still
        // surfaced (the detector, not the extractor, owns the operator allowlist),
        // and a plain value that merely mentions `$ne` is NOT an op leaf.
        let body = br#"{"$schema":"https://x/schema.json","note":"use $ne carefully"}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(op_leaves(&leaves).contains(&"$schema"));
        // The value string is a normal JSON leaf, never an op leaf.
        assert!(!op_leaves(&leaves).contains(&"use $ne carefully"));
        assert!(any_value_contains(&leaves, "use $ne carefully"));
    }

    #[test]
    fn json_object_values_still_extracted_alongside_op_keys() {
        // Surfacing keys is additive: the sibling string value is still a leaf.
        let body = br#"{"$where":"this.a==1","name":"alice"}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(op_leaves(&leaves).contains(&"$where"));
        assert!(any_value_contains(&leaves, "this.a==1"));
        assert!(any_value_contains(&leaves, "alice"));
    }

    #[test]
    fn json_all_leaves_carry_json_label() {
        let body = br#"{"a":"x","b":"y"}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 64);
        assert!(leaves.iter().all(|(l, _)| l == JSON_LABEL));
        assert_eq!(leaves.len(), 2);
    }

    // ── XML ─────────────────────────────────────────────────────────────────────

    #[test]
    fn xml_sibling_text_nodes_are_split() {
        // k3 probe: an SQLi split across sibling tags. Each text node is its own
        // leaf so the payload is not diluted by the surrounding markup.
        let body = br"<q><a>1 UNION</a><b>SELECT pwd</b></q>";
        let leaves = extract_body_fields(body, Some("text/xml"), 64);
        assert!(any_value_contains(&leaves, "1 UNION"), "{:?}", labels_values(&leaves));
        assert!(
            any_value_contains(&leaves, "SELECT pwd"),
            "{:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn xml_entity_encoded_text_is_unescaped() {
        let body = br"<x>&lt;script&gt;alert(1)&lt;/script&gt;</x>";
        let leaves = extract_body_fields(body, Some("application/xml"), 64);
        assert!(
            any_value_contains(&leaves, "<script>"),
            "xml entities must be unescaped: {:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn xml_numeric_char_refs_are_decoded() {
        // BUG-1: decimal `&#39;` (') and `&#60;` (<) numeric char refs must be
        // reconstructed — quick-xml 0.41 does not resolve them itself, so a payload
        // encoded this way otherwise reaches Lane 2 as an empty text run.
        let body = br"<x>1&#39; OR &#39;1&#39;=&#39;1</x>";
        let leaves = extract_body_fields(body, Some("application/xml"), 64);
        assert!(
            any_value_contains(&leaves, "1' OR '1'='1"),
            "decimal numeric char refs must be decoded: {:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn xml_hex_char_refs_are_decoded() {
        // `&#x27;` (') and `&#x3C;` (<) hexadecimal char refs.
        let body = br"<x>&#x3C;script&#x3E;a(&#x27;xss&#x27;)&#x3C;/script&#x3E;</x>";
        let leaves = extract_body_fields(body, Some("application/xml"), 64);
        assert!(
            any_value_contains(&leaves, "<script>a('xss')</script>"),
            "hex numeric char refs must be decoded: {:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn xml_numeric_and_named_refs_mix_in_one_run() {
        // Named (`&lt;`) and numeric (`&#39;`) refs coalesce into one leaf.
        let body = br"<x>&lt;a&gt;&#39;&#x2D;&#x2D;</x>";
        let leaves = extract_body_fields(body, Some("application/xml"), 64);
        assert!(any_value_contains(&leaves, "<a>'--"), "{:?}", labels_values(&leaves));
    }

    #[test]
    fn decode_numeric_char_ref_edge_cases() {
        assert_eq!(decode_numeric_char_ref("#39"), Some('\''));
        assert_eq!(decode_numeric_char_ref("#x27"), Some('\''));
        assert_eq!(decode_numeric_char_ref("#X3C"), Some('<'));
        // Named entity / malformed / empty digits are not numeric refs.
        assert_eq!(decode_numeric_char_ref("apos"), None);
        assert_eq!(decode_numeric_char_ref("#"), None);
        assert_eq!(decode_numeric_char_ref("#x"), None);
        assert_eq!(decode_numeric_char_ref("#xZZ"), None);
        assert_eq!(decode_numeric_char_ref("#99z"), None);
        // Surrogate code point is not a valid char -> None (never panics).
        assert_eq!(decode_numeric_char_ref("#xD800"), None);
    }

    #[test]
    fn xml_attribute_values_are_extracted() {
        let body = br#"<img src="javascript:alert(1)" onerror="evil()"/>"#;
        let leaves = extract_body_fields(body, Some("application/xml"), 64);
        assert!(any_value_contains(&leaves, "javascript:alert(1)"));
        assert!(any_value_contains(&leaves, "evil()"));
    }

    #[test]
    fn xml_cdata_is_extracted() {
        let body = br"<x><![CDATA[1' OR '1'='1]]></x>";
        let leaves = extract_body_fields(body, Some("application/xml"), 64);
        assert!(
            any_value_contains(&leaves, "1' OR '1'='1"),
            "{:?}",
            labels_values(&leaves)
        );
    }

    // ── GraphQL (raw document) ──────────────────────────────────────────────────

    #[test]
    fn graphql_inline_argument_string_is_extracted() {
        // k3 probe: a GraphQL-escaped argument literal. The raw document parser
        // must unescape and isolate the argument value.
        let body = br#"query { user(name: "' OR 1=1--") { id } }"#;
        let leaves = extract_body_fields(body, Some("application/graphql"), 64);
        assert!(
            any_value_contains(&leaves, "' OR 1=1--"),
            "graphql inline arg must be extracted & unescaped: {:?}",
            labels_values(&leaves)
        );
    }

    #[test]
    fn graphql_nested_and_variable_default_values_are_extracted() {
        let body = br#"query($f: String = "<svg onload=alert(1)>") {
            a(filter: {name: "1 UNION SELECT"}) { b(x: "../../etc/passwd") { c } }
        }"#;
        let leaves = extract_body_fields(body, Some("application/graphql"), 64);
        assert!(
            any_value_contains(&leaves, "<svg onload="),
            "{:?}",
            labels_values(&leaves)
        );
        assert!(
            any_value_contains(&leaves, "1 UNION SELECT"),
            "{:?}",
            labels_values(&leaves)
        );
        assert!(
            any_value_contains(&leaves, "../../etc/passwd"),
            "{:?}",
            labels_values(&leaves)
        );
    }

    // ── multipart/form-data ─────────────────────────────────────────────────────

    #[test]
    fn multipart_part_values_are_extracted() {
        let ct = "multipart/form-data; boundary=X";
        let body = concat!(
            "--X\r\n",
            "Content-Disposition: form-data; name=\"a\"\r\n\r\n",
            "1' OR '1'='1\r\n",
            "--X\r\n",
            "Content-Disposition: form-data; name=\"b\"\r\n\r\n",
            "<script>alert(1)</script>\r\n",
            "--X--\r\n",
        );
        let leaves = extract_body_fields(body.as_bytes(), Some(ct), 64);
        assert!(
            any_value_contains(&leaves, "1' OR '1'='1"),
            "{:?}",
            labels_values(&leaves)
        );
        assert!(any_value_contains(&leaves, "<script>"), "{:?}", labels_values(&leaves));
    }

    #[test]
    fn multipart_filename_is_extracted() {
        let ct = "multipart/form-data; boundary=Y";
        let body = concat!(
            "--Y\r\n",
            "Content-Disposition: form-data; name=\"f\"; filename=\"../../etc/passwd\"\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "data\r\n",
            "--Y--\r\n",
        );
        let leaves = extract_body_fields(body.as_bytes(), Some(ct), 64);
        assert!(
            any_value_contains(&leaves, "../../etc/passwd"),
            "multipart filename must be extracted: {:?}",
            labels_values(&leaves)
        );
    }

    // ── Dispatch / sniff / negative ──────────────────────────────────────────────

    #[test]
    fn sniff_json_without_content_type() {
        let body = br#"{"x":"<script>alert(1)</script>"}"#;
        let leaves = extract_body_fields(body, None, 64);
        assert!(any_value_contains(&leaves, "<script>"));
    }

    #[test]
    fn sniff_xml_without_content_type() {
        let body = br"<x>1 UNION SELECT</x>";
        let leaves = extract_body_fields(body, None, 64);
        assert!(any_value_contains(&leaves, "1 UNION SELECT"));
    }

    #[test]
    fn form_urlencoded_body_is_not_extracted() {
        // The existing whole-body view already covers form data — no extraction,
        // no behaviour change.
        let body = b"name=alice&role=admin&page=2";
        assert!(extract_body_fields(body, Some("application/x-www-form-urlencoded"), 64).is_empty());
        assert!(extract_body_fields(body, None, 64).is_empty());
    }

    #[test]
    fn plain_sqli_body_is_not_extracted() {
        // A bare (non-structured) body must yield nothing extra (zero regression
        // for the existing Lane 2 body tests).
        assert!(extract_body_fields(b"1' OR '1'='1", None, 64).is_empty());
    }

    #[test]
    fn empty_body_and_zero_budget_yield_nothing() {
        assert!(extract_body_fields(b"", Some("application/json"), 64).is_empty());
        assert!(extract_body_fields(br#"{"a":"b"}"#, Some("application/json"), 0).is_empty());
    }

    #[test]
    fn field_cap_bounds_leaf_count() {
        let body = br#"{"a":"1","b":"2","c":"3","d":"4","e":"5"}"#;
        let leaves = extract_body_fields(body, Some("application/json"), 3);
        assert!(leaves.len() <= 3, "leaf count must be capped: {}", leaves.len());
    }

    #[test]
    fn oversized_body_is_declined() {
        // Over the self-bound input cap → no parse, no extraction.
        let mut body = Vec::from(&b"[\""[..]);
        body.extend(std::iter::repeat_n(b'a', MAX_EXTRACT_INPUT_BYTES + 10));
        body.extend_from_slice(b"\"]");
        assert!(extract_body_fields(&body, Some("application/json"), 64).is_empty());
    }

    // ── DoS: deep nesting must never overflow the stack ─────────────────────────

    #[test]
    fn json_deep_nesting_declines_without_stack_overflow() {
        // ~1000 levels of nested JSON: the pre-parse depth guard declines it before
        // serde_json's recursive Value build runs. Reaching this assertion (exit 0,
        // no abort) is the DoS proof (mirrors Lane A's
        // `*_declines_without_stack_overflow`).
        for n in [1000usize, 5000usize] {
            let body: Vec<u8> = [b"{\"a\":".repeat(n), b"1".to_vec(), b"}".repeat(n)].concat();
            assert!(
                nesting_depth(&body) > MAX_PARSE_INPUT_DEPTH,
                "n={n}: fixture must exceed the pre-parse guard"
            );
            let leaves = extract_body_fields(&body, Some("application/json"), 64);
            assert!(leaves.is_empty(), "n={n}: deep JSON must be declined, not walked");
        }
    }

    #[test]
    fn json_deep_array_declines_without_stack_overflow() {
        for n in [1000usize, 5000usize] {
            let body: Vec<u8> = [b"[".repeat(n), b"1".to_vec(), b"]".repeat(n)].concat();
            let leaves = extract_body_fields(&body, Some("application/json"), 64);
            assert!(leaves.is_empty(), "n={n}: deep JSON array must be declined");
        }
    }

    #[test]
    fn xml_deep_nesting_does_not_stack_overflow() {
        // quick-xml is a pull parser (iterative) — 1000 nested elements must not
        // overflow; extraction returns cleanly (exit 0).
        for n in [1000usize, 5000usize] {
            let body: Vec<u8> = [b"<a>".repeat(n), b"x".to_vec(), b"</a>".repeat(n)].concat();
            // Must not panic / abort. Deep text (depth > cap) is simply not emitted.
            let _ = extract_body_fields(&body, Some("application/xml"), 64);
        }
    }

    #[test]
    fn graphql_deep_nesting_declines_without_stack_overflow() {
        for n in [1000usize, 5000usize] {
            let body = format!("query {{ {}{} }}", "a {".repeat(n), "}".repeat(n));
            let leaves = extract_body_fields(body.as_bytes(), Some("application/graphql"), 64);
            assert!(leaves.is_empty(), "n={n}: deep graphql must be declined");
        }
    }

    /// P0: run each pathological GraphQL body through `extract_body_fields` on an
    /// **explicit 2 MiB thread** (the Pingora worker stack). `async-graphql-parser`
    /// does not depth-limit its value parser, so a deep `[…]`/`{…}` literal — the
    /// depth of which a naive scan can be made to miss with a `#`-comment or string
    /// trick — overflows the worker stack and aborts (SIGABRT, uncatchable). That
    /// every case *returns* (`join` succeeds, exit 0) is the `DoS` proof: the
    /// lexer-accurate guard + raw-open backstop declined the body before `parse_query`.
    #[test]
    fn graphql_deep_value_variants_decline_without_stack_overflow() {
        // Each fixture would, unguarded, drive parse_value recursion past the
        // ~330-level 2 MiB crash depth. n=3000 far exceeds it.
        let n = 3000usize;
        let cases: Vec<(&str, String)> = vec![
            // Root cause 1a: lone `"` inside a `#` line comment flips a naive
            // in-string tracker, hiding the deep list that follows.
            (
                "comment-trick deep list",
                format!(
                    "query {{ a(\n# \"\n x: {}1{} ) {{ b }} }}",
                    "[".repeat(n),
                    "]".repeat(n)
                ),
            ),
            // Root cause 1b: a `\"\"\"` block string containing a lone bracket/quote
            // desynchronises a naive scan the same way.
            (
                "block-string-trick deep list",
                format!(
                    "query {{ a(c: \"\"\" [ \"\"\" b: {}1{} ) {{ d }} }}",
                    "[".repeat(n),
                    "]".repeat(n)
                ),
            ),
            // Plain deep list value, no trick.
            (
                "plain deep list",
                format!("query {{ a(x: {}1{}) {{ b }} }}", "[".repeat(n), "]".repeat(n)),
            ),
            // Deep object literal value.
            (
                "deep object literal",
                format!("query {{ a(x: {}{}) {{ b }} }}", "{k:".repeat(n), "}".repeat(n)),
            ),
        ];
        for (label, body) in cases {
            let handle = std::thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || extract_body_fields(body.as_bytes(), Some("application/graphql"), 64))
                .expect("spawn worker-stack thread");
            let leaves = handle
                .join()
                .expect("worker thread aborted (stack overflow not prevented)");
            assert!(
                leaves.is_empty(),
                "{label}: pathological body must be declined, not parsed"
            );
        }
    }

    #[test]
    fn graphql_wide_shallow_query_still_extracts_leaves() {
        // A legitimate wide-but-shallow query (many fields, real args & variables,
        // depth well under 64 and delimiter count well under MAX_GRAPHQL_RAW_OPENS)
        // must NOT be declined by the DoS guards — leaves are still extracted.
        use std::fmt::Write as _;
        let mut q = String::from("query Search($t: String = \"default-term\") {\n");
        for i in 0..40 {
            let _ = writeln!(
                q,
                "  f{i}(name: \"term-{i}' OR 1=1--\", filter: {{k: \"v{i}\"}}) {{ id title }}"
            );
        }
        q.push('}');
        assert!(
            graphql_max_depth(q.as_bytes()) <= MAX_PARSE_INPUT_DEPTH,
            "fixture must be shallow: depth={}",
            graphql_max_depth(q.as_bytes())
        );
        assert!(
            graphql_raw_open_total(q.as_bytes()) <= MAX_GRAPHQL_RAW_OPENS,
            "fixture must be under the raw-open backstop: opens={}",
            graphql_raw_open_total(q.as_bytes())
        );
        let leaves = extract_body_fields(q.as_bytes(), Some("application/graphql"), 512);
        assert!(
            any_value_contains(&leaves, "' OR 1=1--"),
            "wide shallow query args must still be extracted: got {} leaves",
            leaves.len()
        );
        assert!(
            any_value_contains(&leaves, "default-term"),
            "variable default must still be extracted"
        );
    }

    #[test]
    fn graphql_max_depth_is_lexer_accurate() {
        // Real nesting is counted: { (1) ( (2) [ [ [ (3,4,5).
        assert_eq!(graphql_max_depth(b"query { a(x: [[[1]]]) { b } }"), 5);
        // A lone `"` in a `#` comment must NOT desync tracking: the deep list after
        // it is still counted (naive nesting_depth would report ~0 here).
        let tricked = b"a(\n# \"\n x: [[[[[1]]]]] )";
        assert_eq!(graphql_max_depth(tricked), 6, "comment-trick must not hide depth");
        assert!(nesting_depth(tricked) < 6, "naive scan under-counts (the bug)");
        // Brackets inside strings/comments do not count.
        assert_eq!(graphql_max_depth(b"a(x: \"[[[[\") "), 1);
        assert_eq!(graphql_max_depth(b"# [[[[[\nquery { x }"), 1);
        assert_eq!(graphql_max_depth(b"a(x: \"\"\" {{{{ \"\"\") "), 1);
    }

    #[test]
    fn graphql_raw_open_backstop_declines_when_lexer_bypassed() {
        // Belt-and-suspenders: even if the lexer scan reported a low depth, the raw
        // open-total backstop declines a body whose bracket count exceeds the cap.
        let body = format!("query {{ a(x: {}1{}) {{ b }} }}", "[".repeat(300), "]".repeat(300));
        assert!(graphql_raw_open_total(body.as_bytes()) > MAX_GRAPHQL_RAW_OPENS);
        let leaves = extract_body_fields(body.as_bytes(), Some("application/graphql"), 64);
        assert!(leaves.is_empty(), "over-cap raw-open body must be declined");
    }

    #[test]
    fn nesting_depth_is_string_aware() {
        // Brackets inside a JSON string must not count toward nesting depth.
        assert_eq!(nesting_depth(br#"{"a":"{{{{{{"}"#), 1);
        assert_eq!(nesting_depth(br"[[[]]]"), 3);
        assert_eq!(nesting_depth(br#"{"a":{"b":{"c":1}}}"#), 3);
        // Escaped quote inside a string keeps us in-string.
        assert_eq!(nesting_depth(br#"{"a":"\"[[["}"#), 1);
    }
}
