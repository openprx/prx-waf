//! Which authority a request is routed on — one answer for HTTP/1.1, h2 and h3.
//!
//! Every protocol this proxy speaks has to answer the same question before it
//! can do anything else: *which configured site did this request address?* The
//! answer selects the upstream, the per-host policy and the metric label, so a
//! wrong answer is not a routing bug, it is a policy bypass. Getting three
//! independent answers to one question is how HTTP/3 spent its first release
//! returning 404 to every compliant client (audit H-7), and it is why enabling
//! h2 on the TLS listener used to 404 every browser.
//!
//! ## What each protocol actually delivers
//!
//! | | authority in `Uri` | `Host` field | duplicate `Host` possible | conflict rejected below us |
//! |---|---|---|---|---|
//! | HTTP/1.1 | **never** — `pingora_http::RequestHeader::set_raw_path` builds the URI with `Uri::builder().path_and_query(..)` only (`pingora-http-0.8.1/src/lib.rs:259-278`), and the h1 server feeds it the raw request target verbatim (`pingora-core-0.8.1/src/protocols/http/v1/server.rs:229-234`) | yes, the only source | yes — repeated header lines survive parsing | n/a |
//! | h2 | yes — `:authority` is folded into `Uri` and the field map is passed through untouched (`h2-0.4.15/src/server.rs:1669-1738`, `pingora-core-0.8.1/src/protocols/http/v2/server.rs:154-157`) | optional, and compliant clients omit it | yes — HPACK may carry two `host` fields | **no** |
//! | h3 | yes — `:authority`, same folding | absent on every compliant client (RFC 9114 §4.3.1) | yes, in principle | yes (`h3` 0.0.8 `HeaderError::ContradictedAuthority`) |
//!
//! The HTTP/1.1 row is the load-bearing one, because it is what makes sharing
//! this resolver with HTTP/1.1 free. Pingora builds the HTTP/1.1 URI out of
//! `path_and_query` alone, which means the two request-target forms that carry
//! an authority do not merely lose it — they fail to parse: `GET
//! http://a.example/x HTTP/1.1` and `CONNECT a.example:443 HTTP/1.1` both come
//! back `InvalidHTTPHeader` and never reach `request_filter`. So on HTTP/1.1
//! [`route_authority`] can only ever take the `Host` branch, which is exactly
//! what the routing code read before. Behaviour preserving by construction, not
//! by argument — and
//! `no_http1_request_target_carries_a_uri_authority_under_pingora` pins the
//! construction so a Pingora upgrade that starts accepting either form has to
//! fail a test before it can change HTTP/1.1 routing.
//!
//! ## What is deliberately *not* unified
//!
//! * **Refusing more than one `Host` line.** That is [`crate::context::FoldedHeaders::duplicate_host`],
//!   and it runs *before* this resolver on all three protocols, because a
//!   request carrying two `Host` values is unroutable no matter which field the
//!   authority came from. Keeping it upstream of here is what lets this
//!   function read the first `Host` line only, exactly as the h2/h3 decoders do.
//! * **Framing-header smuggling.** `Content-Length`/`Transfer-Encoding` desync
//!   is [`crate::smuggling`] and stays per-protocol: h2 and h3 reject
//!   connection-specific fields at decode time (`h2-0.4.15/src/frame/headers.rs:915-928`)
//!   and validate `content-length` against the DATA frames
//!   (`h2-0.4.15/src/proto/streams/recv.rs:175-192, 695-705`), so the indicators
//!   this proxy looks for are reachable on HTTP/1.1 and mostly unreachable
//!   above it. Same detector, different reachability — not the same question.
//! * **What an unroutable request costs.** Each protocol writes its own 400 /
//!   404 with its own body and its own metric bookkeeping; this module only
//!   decides, it never responds.

/// Outcome of deciding which authority a request must be routed on.
pub enum RouteAuthority<'a> {
    /// The authority to route on, borrowed verbatim from the request.
    Found(&'a str),
    /// An authority and a `Host` were both present and disagreed.
    Contradicted,
    /// Neither carried a usable value; nothing can be routed.
    Missing,
}

/// Decide the authority a request is routed on, from its URI and header map.
///
/// The URI is the authoritative source and the `Host` field is the fallback.
/// That order is what HTTP/2 (RFC 9113 §8.3.1) and HTTP/3 (RFC 9114 §4.3.1)
/// both require — a request carrying `:authority` is addressed by `:authority`
/// — and it costs HTTP/1.1 nothing because Pingora hands this function a URI
/// with no authority in it (see the module table).
///
/// The disagreement case is refused rather than resolved. Silently picking one
/// side is a desync primitive: this WAF would apply the policy of authority A
/// while the origin resolves its vhost from the field carrying B. `h3` 0.0.8
/// already rejects the contradiction at decode time, but `h2` 0.4.15 does
/// **not** — `server.rs:1669-1738` copies `:authority` into the URI and the
/// field map into the request without ever comparing the two — so on h2 this
/// branch is the only thing standing between a mismatched pair and a routed
/// request. One `!=` is a cheap price for making the choice a property of this
/// function instead of an assumption about a dependency.
#[must_use]
pub fn route_authority<'a>(uri: &'a http::Uri, headers: &'a http::HeaderMap) -> RouteAuthority<'a> {
    let authority = uri
        .authority()
        .map(http::uri::Authority::as_str)
        .filter(|a| !a.is_empty());
    // First line only, which is all the h2/h3 decoders compare too. A request
    // carrying more than one `Host` is refused before this point
    // (`FoldedHeaders::duplicate_host`).
    let host = headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty());

    match (authority, host) {
        // Byte-exact, matching the decoders' own comparison: `a.com` and
        // `a.com:443` are different authorities and may hold different policy.
        (Some(a), Some(h)) if a != h => RouteAuthority::Contradicted,
        (Some(a), _) => RouteAuthority::Found(a),
        (None, Some(h)) => RouteAuthority::Found(h),
        (None, None) => RouteAuthority::Missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The resolver's verdict, detached from the request it borrowed from, so
    /// each case reads as one line.
    #[derive(Debug, PartialEq, Eq)]
    enum Verdict {
        Found(String),
        Contradicted,
        Missing,
    }

    fn found(authority: &str) -> Verdict {
        Verdict::Found(authority.to_string())
    }

    /// Resolve a request built from a request target and zero or more `Host`
    /// lines — the only two inputs the resolver reads.
    fn resolve(target: &str, host_lines: &[&str]) -> Verdict {
        let uri: http::Uri = target.parse().unwrap_or_default();
        let mut headers = http::HeaderMap::new();
        for line in host_lines {
            let value = http::HeaderValue::from_str(line).expect("a test Host line is a valid header value");
            headers.append(http::header::HOST, value);
        }
        match route_authority(&uri, &headers) {
            RouteAuthority::Found(a) => Verdict::Found(a.to_string()),
            RouteAuthority::Contradicted => Verdict::Contradicted,
            RouteAuthority::Missing => Verdict::Missing,
        }
    }

    #[test]
    fn uri_authority_wins_when_no_host_is_sent() {
        assert_eq!(resolve("https://a.example/x", &[]), found("a.example"));
    }

    #[test]
    fn host_is_the_fallback_when_the_uri_carries_no_authority() {
        assert_eq!(resolve("/x", &["a.example"]), found("a.example"));
    }

    #[test]
    fn an_agreeing_pair_routes_on_the_agreed_value() {
        assert_eq!(resolve("https://a.example/x", &["a.example"]), found("a.example"));
    }

    #[test]
    fn a_disagreeing_pair_is_refused_rather_than_resolved() {
        assert_eq!(resolve("https://a.example/x", &["b.example"]), Verdict::Contradicted);
    }

    #[test]
    fn a_default_port_spelling_is_a_different_authority() {
        // `a.example` and `a.example:443` may hold different policy here, so the
        // pair is a contradiction even though a browser would dial the same
        // socket for both.
        assert_eq!(
            resolve("https://a.example:443/x", &["a.example"]),
            Verdict::Contradicted
        );
    }

    #[test]
    fn an_empty_host_is_no_host_at_all() {
        assert_eq!(resolve("/x", &[""]), Verdict::Missing);
        // ... and it does not contradict an authority that is present.
        assert_eq!(resolve("https://a.example/x", &[""]), found("a.example"));
    }

    #[test]
    fn a_non_utf8_host_is_no_host_at_all() {
        let mut headers = http::HeaderMap::new();
        let value = http::HeaderValue::from_bytes(b"a.\xff.example").expect("valid header value bytes");
        headers.append(http::header::HOST, value);
        let uri = http::Uri::from_static("/x");
        assert!(matches!(route_authority(&uri, &headers), RouteAuthority::Missing));
    }

    #[test]
    fn only_the_first_host_line_is_compared() {
        // `duplicate_host` refuses this request before routing; the assertion
        // records that this function does not silently pick the second line if
        // that guard is ever moved.
        assert_eq!(resolve("/x", &["a.example", "b.example"]), found("a.example"));
    }

    /// The HTTP/1.1 half of the module table, pinned.
    ///
    /// `RequestHeader::build` is exactly what `pingora-core`'s HTTP/1.1 server
    /// calls with the raw request target, so this asserts the property that
    /// makes sharing this resolver with HTTP/1.1 a no-op: no request target
    /// that survives parsing produces a URI authority, and the two forms that
    /// syntactically carry one — absolute-form and authority-form — do not
    /// survive parsing at all. Every HTTP/1.1 request therefore takes the
    /// `Host` branch, which is the only thing the routing code read before this
    /// resolver was shared with it. If a Pingora upgrade starts accepting
    /// either form, this test fails and the HTTP/1.1 routing change gets
    /// reviewed instead of shipped.
    #[test]
    fn no_http1_request_target_carries_a_uri_authority_under_pingora() {
        let target = |t: &[u8]| pingora_http::RequestHeader::build("GET", t, None);

        // `Uri::builder().path_and_query(..)` is all pingora-http builds
        // (`pingora-http-0.8.1/src/lib.rs:259-278`), and it refuses both forms.
        // The request fails to parse and never reaches `request_filter`, so it
        // cannot route on a target authority.
        assert!(target(b"http://evil.example/x").is_err(), "absolute-form was accepted");
        assert!(target(b"evil.example:443").is_err(), "authority-form was accepted");

        // The forms that are accepted keep the whole target in the path.
        for (raw, path) in [
            (&b"/x"[..], "/x"),
            (b"*", "*"),
            // A protocol-relative target looks like an authority and is not one.
            (b"//evil.example/x", "//evil.example/x"),
        ] {
            let head = target(raw).expect("BUG: this request target parses");
            assert!(
                head.uri.authority().is_none(),
                "pingora parsed an authority out of {:?}: {:?}",
                String::from_utf8_lossy(raw),
                head.uri
            );
            assert_eq!(head.uri.path(), path);
        }
    }
}
