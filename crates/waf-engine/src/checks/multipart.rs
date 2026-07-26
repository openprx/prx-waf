//! `multipart/form-data` envelope parsing (RFC 2046 §5.1, RFC 7578).
//!
//! Two jobs, and the second one is what keeps ordinary uploads out of the block
//! log: telling the rule set which parts are *files*, so their contents can be
//! kept out of the parameter surface ([`Multipart::payload_surface`]), and
//! backing three `ModSecurity` variables that cannot be approximated by any
//! other surface:
//!
//! * `FILES` — the `filename="…"` of every part that declares one, i.e. the
//!   name the file had on the client. CRS-920120, CRS-920121, CRS-932180,
//!   CRS-933110, CRS-933111, CRS-933220 and CRS-944140 are all "is this upload
//!   called something dangerous" rules and read nothing else.
//! * `FILES_NAMES` — the form field name (`name="…"`) each of those file parts
//!   was submitted under.
//! * `MULTIPART_PART_HEADERS` — every part's header lines, verbatim, one value
//!   per line. CRS-922120 and CRS-922130 inspect the header text itself.
//!
//! # Why a parser and not a substring scan
//!
//! Handing those rules the raw envelope is not a conservative approximation, it
//! is a different rule. CRS-933110 is `.*\.ph(?:p\d*|tml|ar|ps|t|pt)\.*$` — run
//! against a whole request it blocks every POST to a `.php` URL; run against a
//! part's `filename` it means what upstream means. The converse is just as bad:
//! the boundary lines and the `Content-Type:` header *names* an envelope carries
//! must **not** reach an `ARGS` rule, because CRS-921120 hunts
//! `\r\n…content-type:` as a response-splitting payload and every ordinary file
//! upload contains that verbatim.
//!
//! # The two failure modes are not the same failure
//!
//! [`parse`] is only reached once the `Content-Type` really did announce
//! `multipart/*` **and** name a boundary; "this is not a multipart body" is
//! answered by the caller before it gets here and is a *non-event*. What this
//! module reports through [`Multipart::malformed`] is the other thing: this is a
//! multipart envelope and it does not hold together — no delimiter line, a part
//! with no header terminator, a limit exceeded, or no closing delimiter. Those
//! two must not be conflated, because the caller draws opposite conclusions from
//! them: a non-multipart body is parsed as a body, while an envelope that
//! yielded nothing must still be shown to the `body` rules rather than silently
//! disappearing (see [`Multipart::yielded_nothing`]).
//!
//! # Bounds
//!
//! Every input here is attacker-chosen, so nothing in this module allocates in
//! proportion to something the attacker controls without a ceiling, and nothing
//! can panic: all indexing goes through `get` / slicing that is proven in range
//! by the scan that produced the index.

use std::borrow::Cow;

/// Longest `boundary=` value accepted, from RFC 2046 §5.1.1 (`1*70 bchars`).
///
/// A longer boundary is not merely unusual, it cannot be produced by a
/// conforming client, and accepting one costs a substring scan per line for a
/// needle no legitimate body contains.
const MAX_BOUNDARY_LEN: usize = 70;

/// Maximum number of parts extracted from one envelope.
///
/// Deliberately the same budget as [`waf_common::MAX_FORM_ARGS`]: a multipart
/// form is a form, every part is evaluated by every loaded rule exactly as an
/// `ARGS` member is, and the per-part cost does not shrink with the part. The
/// limit is a *precision* budget and not a parse limit — exceeding it stops the
/// part walk and marks the envelope malformed, which makes the remainder fall
/// back to whole-body inspection rather than vanish.
const MAX_PARTS: usize = 256;

/// Maximum size of one part's header block.
///
/// 8 KiB is the request-header ceiling nginx (`large_client_header_buffers`) and
/// Apache (`LimitRequestFieldSize`) ship by default; a *part* header block has
/// less to carry than a request's, so anything past it is not a header block.
/// Bounding it is what keeps the line split below proportional to a constant.
const MAX_PART_HEADER_BYTES: usize = 8 * 1024;

/// Maximum number of header lines in one part.
///
/// RFC 7578 parts carry `Content-Disposition` and at most a couple of
/// `Content-*` companions. 32 is an order of magnitude above any legitimate
/// use and bounds the per-part work independently of the byte ceiling above.
const MAX_PART_HEADER_LINES: usize = 32;

// ── Parsed shape ──────────────────────────────────────────────────────────────

/// One `multipart/*` part, as slices of the body it was parsed from.
///
/// Nothing is copied: every field borrows the inspection window, and the
/// conversion to `str` happens at the use site so a part of a binary upload
/// costs an allocation only if a rule actually reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Part<'a> {
    /// The part's header block, verbatim, without the blank line that ends it.
    headers: &'a [u8],
    /// The part's payload, verbatim, without the line break that introduces the
    /// next delimiter.
    payload: &'a [u8],
    /// `name="…"` of the part's `Content-Disposition`, if it declared one.
    name: Option<&'a [u8]>,
    /// `filename="…"` of the part's `Content-Disposition`.
    ///
    /// `Some` is what makes a part a *file* part upstream, which is why `FILES`
    /// and `FILES_NAMES` are both keyed off this and not off `name`.
    filename: Option<&'a [u8]>,
}

impl<'a> Part<'a> {
    /// The part's header lines, verbatim, one per header.
    ///
    /// Verbatim matters: CRS-922130 (`[^\x21-\x7E][\x21-\x39\x3B-\x7E]*:`) is
    /// looking for exactly the bytes a normaliser would remove, so the leading
    /// `\x0e` of `\x0eContent-Disposition:` has to survive to the matcher. Only
    /// the line terminator itself is dropped, and empty lines are skipped
    /// because `ModSecurity` creates no collection member for them.
    fn header_lines(&self) -> impl Iterator<Item = &'a [u8]> {
        self.headers
            .split(|&b| b == b'\n')
            .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
            .filter(|line| !line.is_empty())
            .take(MAX_PART_HEADER_LINES)
    }

    /// The quoted parameter values in the part's header block.
    ///
    /// These are the part's `name` and `filename` (and any other quoted
    /// parameter), and they are the only piece of the MIME envelope that
    /// upstream shows an `ARGS`-family rule — as collection members, never as
    /// part of the raw body. See [`Multipart::payload_surface`].
    fn quoted_values(&self) -> impl Iterator<Item = &'a [u8]> {
        self.headers
            .split(|&b| b == b'"')
            .enumerate()
            .filter_map(|(index, chunk)| (index % 2 == 1).then_some(chunk))
    }
}

/// A parsed `multipart/*` envelope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Multipart<'a> {
    parts: Vec<Part<'a>>,
    malformed: bool,
}

impl<'a> Multipart<'a> {
    /// `true` when this *is* a multipart envelope but it does not hold together.
    ///
    /// Structural failures only — a missing delimiter line, a part with no
    /// header terminator, a limit exceeded, a missing closing delimiter. A part
    /// with two `Content-Disposition:` headers is odd but perfectly parseable,
    /// so it is *not* reported here; the rule that cares (CRS-922130) reads the
    /// header lines and decides for itself.
    pub const fn malformed(&self) -> bool {
        self.malformed
    }

    /// How many parts were recognised.
    pub const fn part_count(&self) -> usize {
        self.parts.len()
    }

    /// `true` when the envelope is malformed **and** produced no parts at all.
    ///
    /// This is the case the caller must not treat as "the body was empty": a
    /// `Content-Type: multipart/form-data; boundary=x` carrying a body with no
    /// such boundary in it would otherwise hide every byte of that body from
    /// every `REQUEST_BODY` rule, which is a bypass, not a parse result.
    pub const fn yielded_nothing(&self) -> bool {
        self.malformed && self.parts.is_empty()
    }

    /// `FILES`: the `filename="…"` of every file part, in envelope order.
    pub fn files(&self) -> impl Iterator<Item = Cow<'a, str>> {
        self.parts.iter().filter_map(|part| part.filename.map(text))
    }

    /// `FILES_NAMES`: the form field name of every **file** part.
    ///
    /// A part that declares no `filename` is an ordinary form field and
    /// contributes nothing here — upstream `FILES_NAMES` is the key set of the
    /// `FILES` collection, not the key set of all parts. A file part that
    /// declares no `name` cannot be a key and is skipped.
    pub fn files_names(&self) -> impl Iterator<Item = Cow<'a, str>> {
        self.parts
            .iter()
            .filter(|part| part.filename.is_some())
            .filter_map(|part| part.name.map(text))
    }

    /// `MULTIPART_PART_HEADERS`: every part's header lines, one value per line.
    pub fn part_headers(&self) -> impl Iterator<Item = Cow<'a, str>> {
        self.parts.iter().flat_map(Part::header_lines).map(|line| text(line))
    }

    /// What the `ARGS` / `REQUEST_BODY` rules see of this envelope: every
    /// part's quoted parameter values, plus the payload of every part that is
    /// **not a file part**, newline-separated.
    ///
    /// # The MIME envelope is absent
    ///
    /// Boundary lines and header *names* are deliberately left out. Handing
    /// them over is a false-positive generator: CRS-921120 hunts
    /// `\r\n…content-type:` as a response-splitting payload, which every
    /// ordinary file upload contains verbatim.
    ///
    /// # A file part's *content* is absent, and that is upstream's rule
    ///
    /// A part that declares `filename=` is a file, and no engine this rule set
    /// was written for lets a file's bytes reach an `ARGS`-family or
    /// `REQUEST_BODY` variable:
    ///
    /// * `ModSecurity` v2 sorts each part into `MULTIPART_FILE` or
    ///   `MULTIPART_FORMDATA` purely on whether `filename=` was present
    ///   (`apache2/msc_multipart.c`), and `multipart_get_arguments()` walks the
    ///   `MULTIPART_FORMDATA` parts only — there is no file branch. `REQUEST_BODY`
    ///   itself is never even generated for a multipart request.
    /// * `ModSecurity` v3 routes file parts to `FILES*` and only the remaining
    ///   parts to `ARGS_POST`. It *does* also expose the whole raw body as
    ///   `REQUEST_BODY`, which is the known false-positive defect
    ///   `owasp-modsecurity/ModSecurity#2146` — open since 2019 and reported
    ///   against exactly this symptom.
    /// * Coraza copies a file part to a temp file or to `io.Discard` and adds
    ///   only non-file parts to `ARGS_POST`; it sets no `REQUEST_BODY` at all.
    ///
    /// CRS states the same assumption in its own corpus rather than only in its
    /// engines: `tests/.../942540.yaml` test 6 uploads a `text/markdown` part
    /// whose content is `my name is 'foo'; and I work on CRS.` and asserts
    /// CRS-942540 must **not** fire. That pattern (`^(?:[^']*'…)[\s\x0b]*;`)
    /// matches those bytes exactly, so the test can only pass on an engine that
    /// keeps file content out of `ARGS`. It also rules out the tempting
    /// half-measure of scanning "text-like" uploads by `Content-Type`: the file
    /// CRS insists must go unscanned *is* text.
    ///
    /// The split is not a concession to false positives either. It mirrors how
    /// the origin parses the same envelope — PHP's `$_FILES` vs `$_POST`, and
    /// the equivalent split in Rails, Django, multer and Spring, all key off
    /// `filename=` too — so a payload moved into a file part is a payload the
    /// application will not evaluate as a parameter. What it *does* become is a
    /// stored file, which is the `FILES` rules' beat: CRS-933110, CRS-933111,
    /// CRS-932180, CRS-944140 and friends read the declared file name, and
    /// [`Self::files`] feeds them.
    ///
    /// A part whose `Content-Disposition` is malformed enough that no
    /// `filename=` can be read out of it is *not* a file part and keeps its
    /// payload here, which is the safe direction to be wrong in.
    pub fn payload_surface(&self) -> String {
        let mut out = String::new();
        let mut push = |bytes: &[u8]| {
            if bytes.is_empty() {
                return;
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&text(bytes));
        };
        for part in &self.parts {
            for quoted in part.quoted_values() {
                push(quoted);
            }
            // `filename.is_some()` and not "a non-empty file name": `filename=""`
            // is what a browser sends for an untouched file input, upstream v2
            // and v3 both classify it as a file part, and it is the same test
            // `files()` and `files_names()` above already apply.
            if part.filename.is_none() {
                push(part.payload);
            }
        }
        out
    }
}

/// Lossy UTF-8 view of a slice, borrowing whenever it already is UTF-8.
fn text(bytes: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(bytes)
}

// ── Parsing ───────────────────────────────────────────────────────────────────

/// What a line beginning with `--<boundary>` turned out to be.
enum BoundaryLine {
    /// A real delimiter; a part begins after this many further bytes
    /// (transport padding + the line break).
    Part(usize),
    /// The closing `--<boundary>--`.
    Close,
    /// `--<boundary>` is only a prefix of this line (`--boundaryX`), so the
    /// line is ordinary payload of whatever part is open.
    Payload,
    /// The line ends with the boundary and nothing follows — the inspection
    /// window cut the envelope here.
    Truncated,
}

/// Parse a `multipart/*` body into its parts.
///
/// `boundary` is the `boundary=` parameter of the `Content-Type`, already
/// unquoted; the caller has established that the body claims to be multipart, so
/// the result always describes an envelope and never "this was something else".
pub fn parse<'a>(body: &'a [u8], boundary: &str) -> Multipart<'a> {
    // A boundary no conforming client could have sent cannot delimit anything;
    // report the envelope as malformed rather than scanning for a needle that
    // is not a boundary.
    if boundary.is_empty() || boundary.len() > MAX_BOUNDARY_LEN {
        return Multipart {
            parts: Vec::new(),
            malformed: true,
        };
    }

    let mut delimiter = Vec::with_capacity(boundary.len().saturating_add(2));
    delimiter.extend_from_slice(b"--");
    delimiter.extend_from_slice(boundary.as_bytes());

    let mut parts: Vec<Part<'a>> = Vec::new();
    let mut malformed = false;
    let mut closed = false;
    // Offset at which the currently open part's content begins, if one is open.
    let mut open: Option<usize> = None;
    let mut saw_delimiter = false;
    let mut line = Some(0usize);

    while let Some(start) = line {
        let Some(rest) = body.get(start..) else {
            break;
        };
        if rest.starts_with(&delimiter) {
            let after = start.saturating_add(delimiter.len());
            match classify(body.get(after..).unwrap_or_default()) {
                BoundaryLine::Part(skip) => {
                    saw_delimiter = true;
                    if let Some(content) = open.take()
                        && !close_part(body, content, start, &mut parts, &mut malformed)
                    {
                        malformed = true;
                        break;
                    }
                    open = Some(after.saturating_add(skip));
                }
                BoundaryLine::Close => {
                    saw_delimiter = true;
                    if let Some(content) = open.take() {
                        close_part(body, content, start, &mut parts, &mut malformed);
                    }
                    closed = true;
                    break;
                }
                BoundaryLine::Truncated => {
                    saw_delimiter = true;
                    if let Some(content) = open.take() {
                        close_part(body, content, start, &mut parts, &mut malformed);
                    }
                    malformed = true;
                    break;
                }
                // Not a delimiter after all: this line is ordinary payload of
                // whatever part is currently open.
                BoundaryLine::Payload => {}
            }
        }
        line = next_line(body, start);
    }

    // A part still open at the end of the buffer ran off the edge of the
    // inspection window (or of a body whose final delimiter never arrived).
    // It is still shown to the rules — a complete header block followed by a
    // truncated payload is exactly what a large upload looks like in the first
    // window — but the envelope is recorded as malformed.
    if let Some(content) = open.take() {
        close_part(body, content, body.len(), &mut parts, &mut malformed);
        malformed = true;
    }
    if !saw_delimiter || !closed {
        malformed = true;
    }

    Multipart { parts, malformed }
}

/// Close the part whose content starts at `content` and ends at the delimiter
/// line starting at `delimiter_line`.
///
/// Returns `false` when the part budget is spent and the walk must stop.
fn close_part<'a>(
    body: &'a [u8],
    content: usize,
    delimiter_line: usize,
    parts: &mut Vec<Part<'a>>,
    malformed: &mut bool,
) -> bool {
    if parts.len() >= MAX_PARTS {
        return false;
    }
    let end = strip_trailing_eol(body, delimiter_line);
    let Some(raw) = body.get(content..end.max(content)) else {
        *malformed = true;
        return true;
    };
    match parse_part(raw) {
        Some(part) => parts.push(part),
        None => *malformed = true,
    }
    true
}

/// Decide what a `--<boundary>` occurrence at a line start actually is, given
/// the bytes that follow it.
fn classify(rest: &[u8]) -> BoundaryLine {
    if rest.starts_with(b"--") {
        return BoundaryLine::Close;
    }
    // RFC 2046 allows linear whitespace ("transport padding") between the
    // boundary and the line break.
    let padding = rest.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(rest.len());
    match rest.get(padding..) {
        Some([b'\r', b'\n', ..]) => BoundaryLine::Part(padding.saturating_add(2)),
        Some([b'\n', ..]) => BoundaryLine::Part(padding.saturating_add(1)),
        Some([]) => BoundaryLine::Truncated,
        _ => BoundaryLine::Payload,
    }
}

/// Start offset of the line after the one beginning at `start`, or `None` at the
/// end of the buffer.
fn next_line(body: &[u8], start: usize) -> Option<usize> {
    let rest = body.get(start..)?;
    let at = rest.iter().position(|&b| b == b'\n')?;
    let next = start.saturating_add(at).saturating_add(1);
    (next < body.len()).then_some(next)
}

/// `delimiter_line` minus the line break that introduces it, so a part's payload
/// does not absorb the CRLF that belongs to the boundary.
fn strip_trailing_eol(body: &[u8], delimiter_line: usize) -> usize {
    let without_lf = match delimiter_line.checked_sub(1) {
        Some(index) if body.get(index) == Some(&b'\n') => index,
        _ => return delimiter_line,
    };
    match without_lf.checked_sub(1) {
        Some(index) if body.get(index) == Some(&b'\r') => index,
        _ => without_lf,
    }
}

/// Split one part into its header block and payload.
///
/// `None` means the part is malformed: no blank line separating headers from
/// payload, or a header block past one of the ceilings above. Nothing partial is
/// emitted — a half-read `Content-Disposition` must not produce a half-read file
/// name, because a rule such as CRS-920120 asserts a *property* of that name and
/// would read the truncation as a violation.
fn parse_part(raw: &[u8]) -> Option<Part<'_>> {
    let (headers, payload) = split_header_block(raw)?;
    if headers.len() > MAX_PART_HEADER_BYTES {
        return None;
    }
    let mut lines = 0usize;
    let mut disposition: Option<&[u8]> = None;
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        lines = lines.saturating_add(1);
        if lines > MAX_PART_HEADER_LINES {
            return None;
        }
        if disposition.is_none() && header_name(line).is_some_and(|n| n.eq_ignore_ascii_case(b"content-disposition")) {
            disposition = Some(line);
        }
    }
    let (name, filename) = disposition.map_or((None, None), disposition_params);
    Some(Part {
        headers,
        payload,
        name,
        filename,
    })
}

/// Split a part at the blank line that ends its header block.
///
/// Both spellings are accepted because both occur in the wild and in the CRS
/// corpus: the official regression tests write their bodies as YAML block
/// scalars, which are LF-only.
fn split_header_block(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    // A part that opens on the blank line carries no headers at all. It has to
    // be recognised here rather than by the double-terminator search below,
    // which would not find one: there is no header line in front of the blank
    // line for the first terminator to end.
    if let Some(payload) = raw.strip_prefix(b"\r\n").or_else(|| raw.strip_prefix(b"\n")) {
        return Some((&[], payload));
    }
    let crlf = find(raw, b"\r\n\r\n").map(|at| (at, 4usize));
    let lf = find(raw, b"\n\n").map(|at| (at, 2usize));
    let (at, len) = match (crlf, lf) {
        (Some(a), Some(b)) => {
            if a.0 <= b.0 {
                a
            } else {
                b
            }
        }
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    Some((raw.get(..at)?, raw.get(at.saturating_add(len)..)?))
}

/// The header name of a header line, i.e. everything left of the first `:`.
fn header_name(line: &[u8]) -> Option<&[u8]> {
    let at = line.iter().position(|&b| b == b':')?;
    line.get(..at).map(<[u8]>::trim_ascii)
}

/// `(name, filename)` from a `Content-Disposition` header line.
///
/// Quote-aware on purpose: `name="fi;le"` is a single parameter whose value
/// contains a semicolon, and it is precisely what CRS-920120 test 3 sends. A
/// naive split on `;` would lose it, which turns a positive test into a silent
/// miss.
///
/// A backslash is **not** an escape here. `ModSecurity`'s parser scans to the
/// next quote, and CRS-920120 tests 40/41 (`filename="1.j\s\p"`) exist to catch
/// exactly that byte — treating `\"` as a literal quote would hide it.
///
/// An unquoted or unterminated parameter value yields nothing: RFC 7578 requires
/// the quoted form, and inventing a value for a header the origin will refuse is
/// how a negated rule such as CRS-920120 turns into a false positive.
fn disposition_params(line: &[u8]) -> (Option<&[u8]>, Option<&[u8]>) {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return (None, None);
    };
    let value = line.get(colon.saturating_add(1)..).unwrap_or_default();
    let mut name: Option<&[u8]> = None;
    let mut filename: Option<&[u8]> = None;
    let mut i = 0usize;

    while i < value.len() {
        while value.get(i).is_some_and(u8::is_ascii_whitespace) {
            i = i.saturating_add(1);
        }
        let key_start = i;
        while value.get(i).is_some_and(|&b| b != b'=' && b != b';') {
            i = i.saturating_add(1);
        }
        let key = value.get(key_start..i).unwrap_or_default().trim_ascii();
        if value.get(i) == Some(&b'=') {
            i = i.saturating_add(1);
            while value.get(i).is_some_and(u8::is_ascii_whitespace) {
                i = i.saturating_add(1);
            }
            if value.get(i) == Some(&b'"') {
                i = i.saturating_add(1);
                let value_start = i;
                while value.get(i).is_some_and(|&b| b != b'"') {
                    i = i.saturating_add(1);
                }
                let Some(&b'"') = value.get(i) else {
                    // Unterminated: everything after it is unparseable too.
                    break;
                };
                let found = value.get(value_start..i).unwrap_or_default();
                i = i.saturating_add(1);
                if key.eq_ignore_ascii_case(b"name") {
                    name = name.or(Some(found));
                } else if key.eq_ignore_ascii_case(b"filename") {
                    filename = filename.or(Some(found));
                }
            } else {
                // Unquoted value: skip the segment without recording anything.
                while value.get(i).is_some_and(|&b| b != b';') {
                    i = i.saturating_add(1);
                }
            }
        }
        while value.get(i).is_some_and(|&b| b != b';') {
            i = i.saturating_add(1);
        }
        i = i.saturating_add(1);
    }
    (name, filename)
}

/// First offset of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    /// Collect an iterator of `Cow<str>` into owned strings, for assertions.
    fn owned<'a>(values: impl Iterator<Item = Cow<'a, str>>) -> Vec<String> {
        values.map(std::borrow::Cow::into_owned).collect()
    }

    fn envelope(boundary: &str, body: &str) -> String {
        body.replace("--B", &format!("--{boundary}"))
    }

    #[test]
    fn a_well_formed_upload_yields_its_file_and_field_names() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"\r\n\
                    Content-Type: application/pdf\r\n\r\n%PDF-1.4 hello\r\n\
                    --b\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n--b--\r\n";
        let mp = parse(body.as_bytes(), "b");
        assert!(!mp.malformed(), "a complete envelope is not malformed");
        assert_eq!(owned(mp.files()), ["report.pdf"]);
        assert_eq!(owned(mp.files_names()), ["file"], "only file parts are keys");
        assert_eq!(
            owned(mp.part_headers()),
            [
                "Content-Disposition: form-data; name=\"file\"; filename=\"report.pdf\"",
                "Content-Type: application/pdf",
                "Content-Disposition: form-data; name=\"note\"",
            ]
        );
        assert_eq!(
            mp.payload_surface(),
            "file\nreport.pdf\nnote\nhi",
            "the file part's content is not a parameter; the ordinary field's is"
        );
    }

    /// A file part's bytes are not a parameter, and a form field's bytes are.
    ///
    /// The two halves are one test on purpose: excluding file content is only
    /// correct while the ordinary fields beside it stay covered, and a change
    /// that dropped both would look like a false-positive fix.
    #[test]
    fn only_a_file_parts_content_is_withheld_from_the_parameter_surface() {
        // Bytes that CRS-942440 (`[';]--`) and CRS-942120 (`||`) both read as
        // SQL, which is what a binary upload looks like to those rules.
        let sqlish = "a';-- b || c";
        let as_file = format!(
            "--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"q.pdf\"\r\n\r\n{sqlish}\r\n--b--\r\n"
        );
        assert_eq!(
            parse(as_file.as_bytes(), "b").payload_surface(),
            "doc\nq.pdf",
            "a file part contributes its declared names and nothing else"
        );

        // The same bytes in a part with no `filename=` are an ordinary form
        // field, exactly as `ARGS_POST` would carry them upstream.
        let as_field = format!("--b\r\nContent-Disposition: form-data; name=\"doc\"\r\n\r\n{sqlish}\r\n--b--\r\n");
        assert_eq!(
            parse(as_field.as_bytes(), "b").payload_surface(),
            format!("doc\n{sqlish}"),
            "a non-file part is a parameter and must stay visible"
        );

        // `filename=""` is what a browser sends for a file input the user never
        // touched. Upstream v2 and v3 both sort it as a file part on the
        // parameter's presence, and so do `files()` / `files_names()` here.
        let empty_name =
            format!("--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=\"\"\r\n\r\n{sqlish}\r\n--b--\r\n");
        assert_eq!(parse(empty_name.as_bytes(), "b").payload_surface(), "doc");

        // A `Content-Disposition` too broken to yield a file name is not a file
        // part, and its payload keeps its coverage — the safe way to be wrong.
        let broken =
            format!("--b\r\nContent-Disposition: form-data; name=\"doc\"; filename=q.pdf\r\n\r\n{sqlish}\r\n--b--\r\n");
        assert!(
            parse(broken.as_bytes(), "b").payload_surface().contains(sqlish),
            "an unreadable filename parameter must not withhold the payload"
        );
    }

    /// LF-only line endings are the corpus's own spelling and must parse.
    #[test]
    fn bare_lf_line_endings_parse() {
        let body = "--b\nContent-Disposition: form-data; name=\"f\"; filename=\"a.php\"\n\nx\n--b--\n";
        let mp = parse(body.as_bytes(), "b");
        assert!(!mp.malformed());
        assert_eq!(owned(mp.files()), ["a.php"]);
        assert_eq!(mp.payload_surface(), "f\na.php", "`x` is file content, not a parameter");
    }

    /// A semicolon inside a quoted parameter is part of the value, not a
    /// separator (CRS-920120 test 3).
    #[test]
    fn a_quoted_parameter_may_contain_a_semicolon() {
        let body = "--b\nContent-Disposition: form-data; name=\"fi;le\"; filename=\"test\"\n\nx\n--b--\n";
        let mp = parse(body.as_bytes(), "b");
        assert_eq!(owned(mp.files_names()), ["fi;le"]);
        assert_eq!(owned(mp.files()), ["test"]);
    }

    /// A backslash is a literal byte, not an escape (CRS-920120 tests 40/41).
    #[test]
    fn a_backslash_in_a_quoted_parameter_is_literal() {
        let body = "--b\nContent-Disposition: form-data; name=\"cv.p\\d\\f\"; filename=\"1.j\\s\\p\"\n\nx\n--b--\n";
        let mp = parse(body.as_bytes(), "b");
        assert_eq!(owned(mp.files()), ["1.j\\s\\p"]);
        assert_eq!(owned(mp.files_names()), ["cv.p\\d\\f"]);
    }

    /// Empty parameter values are values, not absences (CRS-920120 test 39).
    #[test]
    fn empty_parameter_values_are_preserved() {
        let body = "--b\nContent-Disposition: form-data; name=\"\"; filename=\"\"\n\nx\n--b--\n";
        let mp = parse(body.as_bytes(), "b");
        assert_eq!(owned(mp.files()), [""]);
        assert_eq!(owned(mp.files_names()), [""]);
    }

    /// A part with no `filename` is an ordinary form field, not a file.
    #[test]
    fn a_part_without_a_filename_is_not_a_file() {
        let body = "--b\nContent-Disposition: form-data; name=\"note\"\n\nhi\n--b--\n";
        let mp = parse(body.as_bytes(), "b");
        assert!(owned(mp.files()).is_empty());
        assert!(owned(mp.files_names()).is_empty());
    }

    /// Two parts may legitimately carry the same file name.
    #[test]
    fn a_repeated_file_name_is_reported_once_per_part() {
        let body = "--b\nContent-Disposition: form-data; name=\"a\"; filename=\"x.php\"\n\n1\n\
                    --b\nContent-Disposition: form-data; name=\"b\"; filename=\"x.php\"\n\n2\n--b--\n";
        let mp = parse(body.as_bytes(), "b");
        assert_eq!(owned(mp.files()), ["x.php", "x.php"]);
        assert_eq!(owned(mp.files_names()), ["a", "b"]);
    }

    /// A parameter repeated inside one `Content-Disposition` binds once.
    ///
    /// `ModSecurity` treats the duplicate as a parse error; taking the first
    /// occurrence is the narrower reading — the second cannot introduce a value
    /// the origin's parser would not have used, so a rule sees one member
    /// instead of two rather than a name that was never submitted.
    #[test]
    fn a_repeated_parameter_binds_its_first_occurrence() {
        let mp = parse(
            b"--b\r\nContent-Disposition: form-data; name=\"a\"; filename=\"one.txt\"; filename=\"two.php\"; name=\"z\"\r\n\r\nx\r\n--b--\r\n",
            "b",
        );
        assert_eq!(owned(mp.files()), ["one.txt"]);
        assert_eq!(owned(mp.files_names()), ["a"]);
    }

    /// Two `Content-Disposition` headers in one part: the first wins, and both
    /// lines still reach `MULTIPART_PART_HEADERS`.
    #[test]
    fn a_part_with_two_content_dispositions_binds_the_first() {
        let mp = parse(
            b"--b\r\nContent-Disposition: form-data; name=\"a\"; filename=\"one.txt\"\r\n\
              Content-Disposition: form-data; name=\"z\"; filename=\"two.php\"\r\n\r\nx\r\n--b--\r\n",
            "b",
        );
        assert_eq!(owned(mp.files()), ["one.txt"]);
        assert_eq!(owned(mp.files_names()), ["a"]);
        assert_eq!(owned(mp.part_headers()).len(), 2, "both lines are still header text");
    }

    /// Header lines reach the rules byte for byte, including the control
    /// character CRS-922130 exists to find.
    #[test]
    fn header_lines_are_verbatim() {
        let body = "--b\r\n\x0eContent-Disposition: form-data; name=\"file\"; filename=\"1.php\"\r\n\
                    Content-Disposition: form-data; name=\"post\"\r\n\r\nx\r\n--b--";
        let mp = parse(body.as_bytes(), "b");
        let headers = owned(mp.part_headers());
        assert_eq!(headers.len(), 2);
        assert!(
            headers.first().is_some_and(|line| line.starts_with('\u{0e}')),
            "the control byte survives: {headers:?}"
        );
        // The mangled line is not a `Content-Disposition`, so the second one is.
        assert!(owned(mp.files()).is_empty(), "no part declares a parseable filename");
        assert_eq!(owned(mp.files_names()), Vec::<String>::new());
    }

    /// A body that names a boundary it does not contain is malformed, and the
    /// caller must be able to tell that apart from an empty envelope.
    #[test]
    fn a_body_without_the_boundary_is_malformed_and_yields_nothing() {
        let mp = parse(b"<?php system($_GET['c']); ?>", "b");
        assert!(mp.malformed());
        assert!(mp.yielded_nothing());
        assert_eq!(mp.payload_surface(), "");
    }

    /// Parts with no blank line are malformed and contribute no members
    /// (CRS-922130 test 8).
    #[test]
    fn parts_without_a_header_terminator_are_malformed() {
        let mp = parse(b"--b\ntest\n--b\nyet another test\n--b--\n", "b");
        assert!(mp.malformed());
        assert!(mp.yielded_nothing());
        assert!(owned(mp.part_headers()).is_empty());
    }

    /// A missing closing delimiter is malformed but does not discard the parts
    /// that did arrive — that is what the first window of a large upload is.
    #[test]
    fn a_missing_closing_delimiter_keeps_the_parts_it_read() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nhello";
        let mp = parse(body.as_bytes(), "b");
        assert!(mp.malformed());
        assert!(!mp.yielded_nothing());
        assert_eq!(owned(mp.files()), ["a.txt"]);
    }

    /// A header block cut off mid-parameter must not produce a truncated file
    /// name: a negated rule would read the truncation as a violation.
    #[test]
    fn a_truncated_quoted_parameter_yields_no_file_name() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"repo";
        let mp = parse(body.as_bytes(), "b");
        assert!(mp.malformed());
        assert!(owned(mp.files()).is_empty(), "no closing quote, no file name");
    }

    /// A window that starts in the middle of an envelope still parses the
    /// complete parts it contains and invents nothing from the partial one.
    #[test]
    fn a_window_starting_mid_envelope_parses_only_complete_parts() {
        let body = "…tail of a payload\r\n--b\r\nContent-Disposition: form-data; name=\"f\"; \
                    filename=\"second.txt\"\r\n\r\npayload\r\n--b--\r\n";
        let mp = parse(body.as_bytes(), "b");
        assert_eq!(owned(mp.files()), ["second.txt"]);
        assert!(!mp.malformed(), "a closing delimiter was present");
    }

    /// `--boundaryX` is not a delimiter; it is payload.
    #[test]
    fn a_boundary_prefix_is_not_a_delimiter() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n--bXtra\r\n--b--\r\n";
        let mp = parse(body.as_bytes(), "b");
        assert_eq!(mp.parts.len(), 1);
        assert_eq!(mp.payload_surface(), "f\n--bXtra");
    }

    /// A delimiter that is not at the start of a line is not a delimiter.
    #[test]
    fn a_mid_line_boundary_is_not_a_delimiter() {
        let body = "--b\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx--b\r\ny\r\n--b--\r\n";
        let mp = parse(body.as_bytes(), "b");
        assert_eq!(mp.parts.len(), 1);
        assert_eq!(mp.payload_surface(), "f\nx--b\r\ny");
    }

    /// RFC 2046 transport padding between the boundary and the line break.
    #[test]
    fn transport_padding_after_a_delimiter_is_tolerated() {
        let body = "--b  \r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nx\r\n--b--\r\n";
        let mp = parse(body.as_bytes(), "b");
        assert!(!mp.malformed());
        assert_eq!(owned(mp.files()), ["a.txt"]);
    }

    /// A boundary longer than RFC 2046 allows is refused outright.
    #[test]
    fn an_over_long_boundary_is_refused() {
        let boundary = "x".repeat(MAX_BOUNDARY_LEN + 1);
        let body = envelope(
            &boundary,
            "--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r\n--B--\r\n",
        );
        let mp = parse(body.as_bytes(), &boundary);
        assert!(mp.malformed());
        assert!(mp.yielded_nothing());
    }

    /// A boundary of exactly the RFC maximum still works.
    #[test]
    fn a_maximum_length_boundary_is_accepted() {
        let boundary = "x".repeat(MAX_BOUNDARY_LEN);
        let body = envelope(
            &boundary,
            "--B\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nx\r\n--B--\r\n",
        );
        let mp = parse(body.as_bytes(), &boundary);
        assert!(!mp.malformed());
        assert_eq!(owned(mp.files()), ["a.txt"]);
    }

    /// An empty boundary is not a boundary.
    #[test]
    fn an_empty_boundary_is_refused() {
        let mp = parse(b"--\r\n\r\nx\r\n----\r\n", "");
        assert!(mp.malformed());
        assert!(mp.yielded_nothing());
    }

    /// The part budget bounds the work an attacker can buy with a fixed body.
    #[test]
    fn the_part_count_is_bounded() {
        let mut body = String::new();
        for i in 0..(MAX_PARTS * 2) {
            let _ = write!(
                body,
                "--b\r\nContent-Disposition: form-data; name=\"f{i}\"; filename=\"f{i}.txt\"\r\n\r\nx\r\n"
            );
        }
        body.push_str("--b--\r\n");
        let mp = parse(body.as_bytes(), "b");
        assert_eq!(mp.parts.len(), MAX_PARTS);
        assert!(mp.malformed(), "the budget was spent, so the envelope is incomplete");
        assert!(!mp.yielded_nothing());
    }

    /// A part header block past the byte ceiling is refused rather than split.
    #[test]
    fn an_over_long_part_header_block_is_refused() {
        let filler = "X".repeat(MAX_PART_HEADER_BYTES + 1);
        let body = format!(
            "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\nX-Pad: {filler}\r\n\r\nx\r\n--b--\r\n"
        );
        let mp = parse(body.as_bytes(), "b");
        assert!(mp.malformed());
        assert!(owned(mp.files()).is_empty());
    }

    /// So is a part with an unreasonable number of headers.
    #[test]
    fn an_over_long_part_header_list_is_refused() {
        let mut headers = String::new();
        for i in 0..=MAX_PART_HEADER_LINES {
            let _ = write!(headers, "X-{i}: v\r\n");
        }
        let body = format!(
            "--b\r\n{headers}Content-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nx\r\n--b--\r\n"
        );
        let mp = parse(body.as_bytes(), "b");
        assert!(mp.malformed());
        assert!(owned(mp.files()).is_empty());
    }

    /// A nested `multipart/mixed` part is one part of the outer envelope; its
    /// inner boundary is payload and is not walked.
    #[test]
    fn a_nested_multipart_part_is_one_outer_part() {
        let body = "--outer\r\nContent-Disposition: form-data; name=\"f\"\r\n\
                    Content-Type: multipart/mixed; boundary=inner\r\n\r\n\
                    --inner\r\nContent-Disposition: attachment; filename=\"deep.php\"\r\n\r\nz\r\n\
                    --inner--\r\n--outer--\r\n";
        let mp = parse(body.as_bytes(), "outer");
        assert_eq!(mp.parts.len(), 1);
        assert!(
            owned(mp.files()).is_empty(),
            "the inner part's file name is not an outer FILES member"
        );
        assert!(
            mp.payload_surface().contains("deep.php"),
            "but its bytes are still body"
        );
    }

    /// An empty body is an envelope that never started.
    #[test]
    fn an_empty_body_is_malformed() {
        let mp = parse(b"", "b");
        assert!(mp.malformed());
        assert!(mp.yielded_nothing());
    }

    /// A body that is only the closing delimiter is well formed and empty.
    #[test]
    fn a_closing_delimiter_alone_is_well_formed() {
        let mp = parse(b"--b--\r\n", "b");
        assert!(!mp.malformed());
        assert!(!mp.yielded_nothing());
        assert_eq!(mp.payload_surface(), "");
    }

    /// Invalid UTF-8 in a part must not panic and must not be dropped.
    #[test]
    fn invalid_utf8_is_replaced_not_rejected() {
        let mut body = b"--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a\xff.txt\"\r\n\r\n".to_vec();
        body.extend_from_slice(&[0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe]);
        body.extend_from_slice(b"\r\n--b--\r\n");
        let mp = parse(&body, "b");
        let files = owned(mp.files());
        // The invalid byte becomes U+FFFD; everything around it is preserved,
        // so the file name is still recognisable rather than dropped.
        assert_eq!(files, ["a\u{fffd}.txt"]);
        assert!(!mp.payload_surface().is_empty());
    }

    /// A `Content-Disposition` with no parameters at all is still a part.
    #[test]
    fn a_bare_content_disposition_yields_no_parameters() {
        let mp = parse(b"--b\r\nContent-Disposition: form-data\r\n\r\nx\r\n--b--\r\n", "b");
        assert_eq!(mp.parts.len(), 1);
        assert!(owned(mp.files()).is_empty());
        assert!(owned(mp.files_names()).is_empty());
    }

    /// An unquoted parameter value contributes nothing: RFC 7578 requires the
    /// quoted form and so does `ModSecurity`'s parser.
    #[test]
    fn an_unquoted_parameter_value_is_ignored() {
        let mp = parse(
            b"--b\r\nContent-Disposition: form-data; name=f; filename=a.php\r\n\r\nx\r\n--b--\r\n",
            "b",
        );
        assert!(owned(mp.files()).is_empty());
        assert!(owned(mp.files_names()).is_empty());
    }

    /// `filename` must not be confused with `name`.
    #[test]
    fn filename_is_not_a_suffix_match_on_name() {
        let mp = parse(
            b"--b\r\nContent-Disposition: form-data; filename=\"a.php\"; name=\"f\"\r\n\r\nx\r\n--b--\r\n",
            "b",
        );
        assert_eq!(owned(mp.files()), ["a.php"]);
        assert_eq!(owned(mp.files_names()), ["f"]);
    }

    /// A part header block with no headers at all.
    #[test]
    fn a_headerless_part_is_payload_only() {
        let mp = parse(b"--b\r\n\r\njust payload\r\n--b--\r\n", "b");
        assert_eq!(mp.parts.len(), 1);
        assert!(owned(mp.part_headers()).is_empty());
        assert_eq!(mp.payload_surface(), "just payload");
    }

    /// Every byte offset the walk produces must stay inside the buffer, for any
    /// input at all. The assertion is that nothing panics.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let seeds: [&[u8]; 12] = [
            b"--b",
            b"--b-",
            b"--b--",
            b"\n--b\n",
            b"--b\r",
            b"--b\r\n",
            b"--b\r\nContent-Disposition:",
            b"--b\r\nContent-Disposition: form-data; name=\"",
            b"--b\r\n\r\n",
            b"\r\n\r\n--b--",
            b"--b\r\nContent-Disposition: form-data; name=;;;=\"\"\r\n\r\nx\r\n--b--",
            b"--b\r\n:\r\n\r\n\r\n--b--",
        ];
        for seed in seeds {
            let mp = parse(seed, "b");
            let _ = mp.payload_surface();
            let _ = owned(mp.files());
            let _ = owned(mp.files_names());
            let _ = owned(mp.part_headers());
        }
        // Every prefix of a realistic envelope, which is what a window boundary
        // produces.
        let full = "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\
                    Content-Type: text/plain\r\n\r\npayload\r\n--b--\r\n";
        for end in 0..=full.len() {
            let mp = parse(full.get(..end).unwrap_or_default().as_bytes(), "b");
            let _ = mp.payload_surface();
            let _ = owned(mp.files());
            let _ = owned(mp.part_headers());
        }
    }
}
