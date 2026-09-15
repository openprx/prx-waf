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
//! | | authority in `Uri` | authority elsewhere | `Host` field | conflict rejected below us |
//! |---|---|---|---|---|
//! | HTTP/1.1 | **never** — `pingora_http::RequestHeader::set_raw_path` deliberately leaves scheme and authority off the `Uri` for every request-target form (`pingora-http-0.9.0/src/lib.rs:746-782`, `parse_request_target`) | **yes, since Pingora 0.9** — an absolute-form target (`GET http://a.example/x`) parses, its path lands in the `Uri` and the whole target is kept verbatim behind [`pingora_http::RequestHeader::raw_path`]; the same is true of authority-form and any opaque `scheme:rest` target, whose `Uri` is `/` | yes | partly — `validate_request_authority` (`pingora-core-0.9.0/src/protocols/http/authority.rs:53-95`) runs inside `read_request` and answers 400 to a duplicated `Host`, to userinfo, to an ambiguous absolute-form and to an absolute-form authority that differs **byte-for-byte** from `Host`. It accepts absolute-form with no `Host`, and it accepts a non-CONNECT authority-form target, which the h1 client then writes to the origin verbatim (`v1/client.rs:917-925`) |
//! | h2 | yes — `:authority` is folded into `Uri` and the field map is passed through untouched | no — `raw_path()` is the `:path`; an absolute-form `:path` is refused at accept (`v2/server.rs:354-364`) | optional, and compliant clients omit it | yes, since 0.9 — `invalid_request_authority` (`v2/server.rs:328`) answers a headers-only 400 to a duplicated `Host` and to a `Host` that differs from `:authority`, before the stream becomes a session |
//! | h3 | yes — `:authority`, same folding | no | absent on every compliant client (RFC 9114 §4.3.1) | yes (`h3` 0.0.8 `HeaderError::ContradictedAuthority`) |
//!
//! The HTTP/1.1 row is the load-bearing one, and it changed with Pingora 0.9.
//! Under 0.8 the two request-target forms that carry an authority failed to
//! parse, so HTTP/1.1 could only ever take the `Host` branch. Under 0.9 they
//! parse, the authority is *not* in the `Uri`, and so a resolver that only reads
//! `uri.authority()` would route an absolute-form request on `Host` while the
//! origin, receiving the absolute-form request line, resolves its vhost from
//! the target (RFC 9112 §3.2.2 tells it to). That is exactly the desync the h2
//! branch already refuses. [`route_request_authority`] therefore reads the raw
//! target through Pingora's own classifier and applies one rule set:
//!
//! 1. only `Host` → route on `Host` (unchanged);
//! 2. only a target authority (absolute-form, no `Host`) → route on it;
//! 3. both, and not byte-equal → refuse; same status, log and counter as the
//!    h2/h3 contradiction. Pingora 0.9 already refuses this pair one layer
//!    down, with the same byte-exact comparison, so this branch is the
//!    defence that stays if that check moves;
//! 4. any other target Pingora lets through — authority-form outside CONNECT,
//!    an absolute-form with a non-HTTP scheme, an opaque `scheme:rest` — is
//!    refused. Pingora would forward the bytes to the origin unchanged while
//!    this proxy had inspected a `Uri` of `/`; a request whose path the WAF
//!    and the origin disagree about is not one this WAF can vouch for.
//!    CONNECT itself never reaches this resolver: `pingora-proxy` answers it
//!    405 unless `allow_connect_method_proxying` is set, and it is not.
//!
//! The tests under `pingora_boundary` pin what Pingora hands this module —
//! which forms parse, where the authority ends up, what `read_request` refuses
//! — so a Pingora upgrade that moves the boundary again fails a test before it
//! can change routing.
//!
//! ## What is deliberately *not* unified
//!
//! * **Refusing more than one `Host` line.** That is [`crate::context::FoldedHeaders::duplicate_host`],
//!   and it runs *before* this resolver on all three protocols, because a
//!   request carrying two `Host` values is unroutable no matter which field the
//!   authority came from. Keeping it upstream of here is what lets this
//!   function read the first `Host` line only, exactly as the h2/h3 decoders do.
//!   Since Pingora 0.9 that refusal is normally made by `read_request` itself
//!   (HTTP/1.1) or at h2 stream accept, before `request_filter` runs; the fold
//!   check remains as the layer that does not depend on it.
//! * **Framing-header smuggling.** `Content-Length`/`Transfer-Encoding` desync
//!   is [`crate::smuggling`] and stays per-protocol: h2 and h3 reject
//!   connection-specific fields at decode time and validate `content-length`
//!   against the DATA frames, so the indicators this proxy looks for are
//!   reachable on HTTP/1.1 and mostly unreachable above it. Same detector,
//!   different reachability — not the same question.
//! * **What an unroutable request costs.** Each protocol writes its own 400 /
//!   404 with its own body and its own metric bookkeeping; this module only
//!   decides, it never responds.

use pingora_http::RequestHeader;
use pingora_http::authority::{RawTargetAuthority, is_http_family_scheme, raw_target_authority};

/// Outcome of deciding which authority a request must be routed on.
pub enum RouteAuthority<'a> {
    /// The authority to route on, borrowed verbatim from the request.
    Found(&'a str),
    /// An authority and a `Host` were both present and disagreed.
    Contradicted,
    /// Neither carried a usable value; nothing can be routed.
    Missing,
}

/// Outcome of routing a request Pingora handed to `request_filter`, which is
/// [`RouteAuthority`] plus the one verdict only a raw request target can earn.
pub enum RequestAuthority<'a> {
    /// The request target was a form this proxy serves; here is the verdict.
    Resolved(RouteAuthority<'a>),
    /// The request target was a form Pingora accepts and this proxy refuses:
    /// authority-form outside CONNECT, absolute-form with a non-HTTP scheme, or
    /// an opaque `scheme:rest`. See rule 4 in the module documentation.
    UnsupportedTarget,
}

/// The syntactic form of a request target as Pingora delivers it.
///
/// Classified from [`RequestHeader::raw_path`], because that is the only place
/// an HTTP/1.1 authority survives parsing, and because Pingora writes exactly
/// these bytes to an HTTP/1.1 origin: whatever this classifier says about the
/// target is what the origin will be asked to interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestTarget<'a> {
    /// origin-form (RFC 9112 §3.2.1): a path, including the protocol-relative
    /// spelling `//host/x`, which is a path and not an authority.
    Origin,
    /// asterisk-form (§3.2.4): `*`.
    Asterisk,
    /// absolute-form (§3.2.2) with an `http`/`https`/`ws`/`wss` scheme; carries
    /// the authority exactly as Pingora's own classifier delimits it.
    Absolute(&'a str),
    /// Anything else Pingora lets through — see [`RequestAuthority::UnsupportedTarget`].
    Unsupported,
}

/// Classify a raw request target. See [`RequestTarget`].
#[must_use]
pub fn classify_request_target(raw: &[u8]) -> RequestTarget<'_> {
    if raw.first() == Some(&b'/') {
        return RequestTarget::Origin;
    }
    if raw == b"*" {
        return RequestTarget::Asterisk;
    }
    // Pingora's classifier, not a second parser: the authority boundary this
    // proxy routes on has to be the one Pingora validated against `Host` and
    // the one it will write to the origin. `RawTargetAuthority::Absolute` is
    // also returned for `ftp://` and friends, whose authority means nothing to
    // an HTTP origin, hence the scheme check.
    match raw_target_authority(raw) {
        RawTargetAuthority::Absolute { scheme, authority, .. } if is_http_family_scheme(scheme) => {
            match std::str::from_utf8(authority) {
                Ok(authority) if !authority.is_empty() => RequestTarget::Absolute(authority),
                _ => RequestTarget::Unsupported,
            }
        }
        RawTargetAuthority::Absolute { .. } | RawTargetAuthority::None | RawTargetAuthority::AmbiguousAuthority => {
            RequestTarget::Unsupported
        }
    }
}

/// Decide the authority a request is routed on, from its URI and header map.
///
/// The URI is the authoritative source and the `Host` field is the fallback.
/// That order is what HTTP/2 (RFC 9113 §8.3.1) and HTTP/3 (RFC 9114 §4.3.1)
/// both require — a request carrying `:authority` is addressed by `:authority`.
/// This is the h2/h3 entry point; a request Pingora hands to `request_filter`
/// goes through [`route_request_authority`], which reads the raw target first
/// and then lands here.
///
/// The disagreement case is refused rather than resolved. Silently picking one
/// side is a desync primitive: this WAF would apply the policy of authority A
/// while the origin resolves its vhost from the field carrying B. `h3` 0.0.8
/// rejects the contradiction at decode time and Pingora 0.9 rejects it at h2
/// stream accept, but neither of those is a property of this function, and
/// this branch is what holds if either moves. One `!=` is a cheap price for
/// making the choice a property of this function instead of an assumption
/// about a dependency.
#[must_use]
pub fn route_authority<'a>(uri: &'a http::Uri, headers: &'a http::HeaderMap) -> RouteAuthority<'a> {
    let authority = uri
        .authority()
        .map(http::uri::Authority::as_str)
        .filter(|a| !a.is_empty());
    decide(authority, first_host(headers))
}

/// Decide the authority for a request Pingora handed to `request_filter`,
/// HTTP/1.1 or h2 — the form of the raw target is read first, because on
/// HTTP/1.1 it is the only place an authority can be.
#[must_use]
pub fn route_request_authority(head: &RequestHeader) -> RequestAuthority<'_> {
    match classify_request_target(head.raw_path()) {
        // No authority in the target. The URI still may carry one — that is
        // how h2 delivers `:authority` — and the shared resolver reads it.
        RequestTarget::Origin | RequestTarget::Asterisk => {
            RequestAuthority::Resolved(route_authority(&head.uri, &head.headers))
        }
        RequestTarget::Absolute(authority) => {
            RequestAuthority::Resolved(decide(Some(authority), first_host(&head.headers)))
        }
        RequestTarget::Unsupported => RequestAuthority::UnsupportedTarget,
    }
}

/// First `Host` line only, which is all the h2/h3 decoders compare too. A
/// request carrying more than one `Host` is refused before this point
/// (`FoldedHeaders::duplicate_host`).
fn first_host(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty())
}

/// The one rule set, applied to whichever pair of sources a protocol offers.
fn decide<'a>(authority: Option<&'a str>, host: Option<&'a str>) -> RouteAuthority<'a> {
    match (authority, host) {
        // Byte-exact, matching the decoders' own comparison and Pingora 0.9's
        // ingress check: `a.com` and `a.com:443` are different authorities and
        // may hold different policy.
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
        UnsupportedTarget,
    }

    fn found(authority: &str) -> Verdict {
        Verdict::Found(authority.to_string())
    }

    impl From<RouteAuthority<'_>> for Verdict {
        fn from(route: RouteAuthority<'_>) -> Self {
            match route {
                RouteAuthority::Found(a) => Self::Found(a.to_string()),
                RouteAuthority::Contradicted => Self::Contradicted,
                RouteAuthority::Missing => Self::Missing,
            }
        }
    }

    impl From<RequestAuthority<'_>> for Verdict {
        fn from(route: RequestAuthority<'_>) -> Self {
            match route {
                RequestAuthority::Resolved(r) => r.into(),
                RequestAuthority::UnsupportedTarget => Self::UnsupportedTarget,
            }
        }
    }

    /// Resolve a request built from a request target and zero or more `Host`
    /// lines — the only two inputs the shared resolver reads.
    fn resolve(target: &str, host_lines: &[&str]) -> Verdict {
        let uri: http::Uri = target.parse().unwrap_or_default();
        let mut headers = http::HeaderMap::new();
        for line in host_lines {
            let value = http::HeaderValue::from_str(line).expect("a test Host line is a valid header value");
            headers.append(http::header::HOST, value);
        }
        route_authority(&uri, &headers).into()
    }

    /// Build the request exactly the way `pingora-core`'s HTTP/1.1 server does:
    /// the raw request-target bytes through `RequestHeader::build`, then the
    /// header lines. What this returns is what `request_filter` sees.
    fn http1(method: &str, target: &[u8], host_lines: &[&str]) -> RequestHeader {
        let mut head = RequestHeader::build(method, target, None).expect("BUG: this request target parses");
        for line in host_lines {
            head.append_header(http::header::HOST, *line)
                .expect("a test Host line is a valid header value");
        }
        head
    }

    /// Resolve an HTTP/1.1 request as `request_filter` would.
    fn resolve_http1(target: &[u8], host_lines: &[&str]) -> Verdict {
        route_request_authority(&http1("GET", target, host_lines)).into()
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

    // ── The HTTP/1.1 rule set (module documentation, rules 1-4) ───────────────

    #[test]
    fn http1_rule_1_host_alone_routes_on_host() {
        assert_eq!(resolve_http1(b"/x", &["a.example"]), found("a.example"));
        assert_eq!(resolve_http1(b"/x", &["a.example:8080"]), found("a.example:8080"));
        // asterisk-form (`OPTIONS *`) carries no authority either.
        assert_eq!(resolve_http1(b"*", &["a.example"]), found("a.example"));
        // A protocol-relative target is a path, not an authority: the origin
        // would serve `//evil.example/x` from `a.example`'s document root.
        assert_eq!(resolve_http1(b"//evil.example/x", &["a.example"]), found("a.example"));
    }

    #[test]
    fn http1_rule_2_absolute_form_without_host_routes_on_the_target_authority() {
        assert_eq!(resolve_http1(b"http://a.example/x", &[]), found("a.example"));
        assert_eq!(
            resolve_http1(b"https://a.example:8443/x?q=1", &[]),
            found("a.example:8443")
        );
        // A target with no path component is still addressed to its authority.
        assert_eq!(resolve_http1(b"http://a.example", &[]), found("a.example"));
        // An empty `Host` line is no `Host` at all, here as on h2.
        assert_eq!(resolve_http1(b"http://a.example/x", &[""]), found("a.example"));
    }

    #[test]
    fn http1_rule_2_and_3_an_agreeing_pair_routes_on_the_agreed_value() {
        assert_eq!(resolve_http1(b"http://a.example/x", &["a.example"]), found("a.example"));
        assert_eq!(
            resolve_http1(b"http://a.example:8080/x", &["a.example:8080"]),
            found("a.example:8080")
        );
    }

    #[test]
    fn http1_rule_3_a_contradicting_pair_is_refused() {
        assert_eq!(
            resolve_http1(b"http://a.example/x", &["b.example"]),
            Verdict::Contradicted
        );
        // Byte-exact, as on h2/h3 and as in Pingora's own ingress check: the
        // default-port spelling and the case of the host are both differences.
        assert_eq!(
            resolve_http1(b"http://a.example:80/x", &["a.example"]),
            Verdict::Contradicted
        );
        assert_eq!(
            resolve_http1(b"http://A.example/x", &["a.example"]),
            Verdict::Contradicted
        );
    }

    #[test]
    fn http1_rule_4_authority_form_outside_connect_is_refused() {
        // Pingora accepts this, roots the URI at `/`, and would write
        // `GET evil.example:443 HTTP/1.1` to the origin. The WAF has inspected
        // a path of `/`; the origin is asked to interpret something else.
        assert_eq!(
            resolve_http1(b"evil.example:443", &["a.example"]),
            Verdict::UnsupportedTarget
        );
        assert_eq!(resolve_http1(b"evil.example:443", &[]), Verdict::UnsupportedTarget);
    }

    #[test]
    fn http1_rule_4_non_http_targets_are_refused() {
        for target in [
            // absolute-form with a scheme no HTTP origin resolves a vhost from
            &b"ftp://a.example/x"[..],
            b"file:///etc/passwd",
            // opaque `scheme:rest`, which Pingora roots at `/` and forwards verbatim
            b"mailto:root@a.example",
            b"foo:bar",
            // an authority that is not UTF-8 cannot be matched against any route
            b"http://a.\xff.example/x",
        ] {
            assert_eq!(
                resolve_http1(target, &["a.example"]),
                Verdict::UnsupportedTarget,
                "{}",
                String::from_utf8_lossy(target)
            );
        }
    }

    #[test]
    fn classification_matches_the_rules() {
        assert_eq!(classify_request_target(b"/x?q=1"), RequestTarget::Origin);
        assert_eq!(classify_request_target(b"//a.example/x"), RequestTarget::Origin);
        assert_eq!(classify_request_target(b"*"), RequestTarget::Asterisk);
        assert_eq!(
            classify_request_target(b"http://a.example:8080/x"),
            RequestTarget::Absolute("a.example:8080")
        );
        assert_eq!(
            classify_request_target(b"WSS://a.example/x"),
            RequestTarget::Absolute("a.example")
        );
        assert_eq!(classify_request_target(b"a.example:443"), RequestTarget::Unsupported);
        assert_eq!(
            classify_request_target(b"ftp://a.example/x"),
            RequestTarget::Unsupported
        );
        assert_eq!(classify_request_target(b"?q=1"), RequestTarget::Unsupported);
        assert_eq!(classify_request_target(b""), RequestTarget::Unsupported);
    }

    #[test]
    fn an_h2_style_uri_authority_still_routes_through_the_shared_resolver() {
        // Pingora's h2 server delivers `:authority` inside the URI and the
        // `:path` as the raw target, so the raw target is origin-form and the
        // URI branch decides. The three verdicts must be the h2 ones.
        let h2 = |uri: &str, host: Option<&str>| -> Verdict {
            let mut request = http::Request::builder().uri(uri).body(()).expect("test URI is valid");
            if let Some(host) = host {
                request
                    .headers_mut()
                    .insert(http::header::HOST, http::HeaderValue::from_str(host).expect("valid"));
            }
            let head = RequestHeader::from(request.into_parts().0);
            assert_eq!(head.raw_path(), b"/x", "h2 raw target is the :path");
            route_request_authority(&head).into()
        };
        assert_eq!(h2("https://a.example/x", None), found("a.example"));
        assert_eq!(h2("https://a.example/x", Some("a.example")), found("a.example"));
        assert_eq!(h2("https://a.example/x", Some("b.example")), Verdict::Contradicted);
    }

    /// What Pingora 0.9 hands this module, pinned.
    ///
    /// `RequestHeader::build` is exactly what `pingora-core`'s HTTP/1.1 server
    /// calls with the raw request target, and `validate_request_authority` is
    /// what `read_request` then runs before `request_filter` can see the
    /// request. Together they fix the boundary the rules above are written
    /// against: which forms arrive, where the authority is, and which pairs
    /// Pingora has already refused. If a Pingora upgrade moves any of it, one
    /// of these fails and the HTTP/1.1 routing change gets reviewed instead of
    /// shipped — the same job the 0.8 tripwire did when 0.9 arrived.
    mod pingora_boundary {
        use super::*;
        use pingora_core::protocols::http::authority::validate_request_authority;

        #[test]
        fn absolute_form_parses_with_the_authority_kept_out_of_the_uri() {
            let head = http1("GET", b"http://evil.example/x?q=1", &[]);
            assert!(
                head.uri.authority().is_none(),
                "authority leaked into the Uri: {:?}",
                head.uri
            );
            assert_eq!(head.uri.path(), "/x");
            assert_eq!(head.uri.query(), Some("q=1"));
            // ... and the whole target survives for the origin's request line.
            assert_eq!(head.raw_path(), b"http://evil.example/x?q=1");
            assert!(head.raw_path_is_utf8());
        }

        #[test]
        fn authority_form_parses_with_a_root_uri() {
            // Under 0.8 this failed to parse. Under 0.9 the request reaches
            // `request_filter` looking like `GET /`, while the origin would be
            // sent the authority-form line — rule 4 exists because of this row.
            let head = http1("GET", b"evil.example:443", &[]);
            assert_eq!(head.uri.path(), "/");
            assert!(head.uri.authority().is_none());
            assert_eq!(head.raw_path(), b"evil.example:443");
        }

        #[test]
        fn origin_and_asterisk_forms_round_trip_through_the_uri() {
            for (raw, path) in [
                (&b"/x"[..], "/x"),
                (b"*", "*"),
                (b"//evil.example/x", "//evil.example/x"),
            ] {
                let head = http1("GET", raw, &[]);
                assert!(
                    head.uri.authority().is_none(),
                    "authority parsed out of {raw:?}: {:?}",
                    head.uri
                );
                assert_eq!(head.uri.path(), path);
                assert_eq!(head.raw_path(), raw);
            }
        }

        #[test]
        fn ingress_refuses_a_host_that_differs_from_the_target_authority() {
            // Rule 3 is normally decided here, one layer below `request_filter`,
            // with the same byte-exact comparison this module uses.
            let refused =
                |target: &[u8], host: &str| validate_request_authority(&http1("GET", target, &[host])).is_err();
            assert!(refused(b"http://a.example/x", "b.example"));
            assert!(refused(b"http://a.example:80/x", "a.example"));
            assert!(refused(b"http://A.example/x", "a.example"));
            assert!(!refused(b"http://a.example/x", "a.example"));
        }

        #[test]
        fn ingress_lets_the_forms_this_module_decides_through() {
            let admitted =
                |target: &[u8], hosts: &[&str]| validate_request_authority(&http1("GET", target, hosts)).is_ok();
            // Rule 2: absolute-form with no Host is Pingora's to admit and ours
            // to route.
            assert!(admitted(b"http://a.example/x", &[]));
            // Rule 4: authority-form outside CONNECT passes Pingora's check —
            // `raw_target_authority` sees no `://` and classifies it as carrying
            // no authority — so the refusal has to be made here.
            assert!(admitted(b"evil.example:443", &["a.example"]));
            assert!(admitted(b"foo:bar", &["a.example"]));
            // Rule 1, unchanged.
            assert!(admitted(b"/x", &["a.example"]));
        }

        #[test]
        fn ingress_refuses_a_duplicated_host_before_the_fold_check() {
            // `FoldedHeaders::duplicate_host` stays as the layer that does not
            // depend on this; the assertion records that under 0.9 it is the
            // second line of defence, not the first, which is why the
            // `duplicate_host` counter no longer moves for an HTTP/1.1 request.
            assert!(validate_request_authority(&http1("GET", b"/x", &["a.example", "b.example"])).is_err());
            assert!(validate_request_authority(&http1("GET", b"/x", &["a.example", "a.example"])).is_err());
        }
    }
}
