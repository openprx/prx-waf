use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, Lane1BodyBudget, request_targets};

static TRAVERSAL_DESCS: &[&str] = &[
    "directory traversal (../)",
    "URL-encoded traversal (%2e%2e)",
    "double URL-encoded traversal (%252e%252e)",
    "Unicode-encoded traversal",
    "Windows backslash traversal (..\\)",
    "null byte injection (%00)",
    "absolute path to a sensitive file",
    "Windows system path (C:\\Windows\\…)",
];

/// Fail-closed compile result (Low-1): see the equivalent comment in
/// `sql_injection.rs` for the full rationale. `None` means the pattern set
/// failed to compile; `check()` then treats every request as a match
/// (fail-closed) instead of falling back to `RegexSet::empty()`, which would
/// match nothing and fail open.
static TRAVERSAL_SET: LazyLock<Option<RegexSet>> = LazyLock::new(|| {
    match RegexSet::new([
        // Classic ../
        r"(\.\./|\.\.\\)",
        // URL single-encoded: %2e%2e or %2E%2E (with / or %2f after)
        r"(?i)%2e%2e(%2f|%5c|/|\\)",
        // Double URL-encoded: %252e%252e
        r"(?i)%252e%252e",
        // Unicode / overlong encoding
        r"(?i)\.\.((%c0%af)|(%c1%9c)|(%e0%80%af)|(%c0%9v))",
        // Windows backslash traversal
        r"\.\.\\",
        // Null byte
        r"%00",
        // ── TRAV-007 — absolute path to a sensitive file ─────────────────────
        //
        // The original pattern was `/(etc|proc|var/log|usr/local|root|home|tmp|
        // dev|sys)(/|$)`, i.e. *any* absolute path under one of nine very
        // ordinary directories. Because `request_targets` also feeds it the
        // request path, a site whose own routes are `/home`, `/dev/api/v1` or
        // `/tmp/preview` returned 403 for its own pages, and any ops/config
        // payload mentioning `/etc/nginx/nginx.conf`, `/etc/resolv.conf`,
        // `/var/log/nginx` or `/home/deploy/app` was blocked as well. An
        // absolute path is not by itself a traversal attempt — the traversal
        // *sequence* is what TRAV-001..006 detect — so this rule is now the
        // narrow net for the handful of targets that have no benign reason to
        // appear in a request: credential stores, private keys, process
        // memory/env, and the bash `/dev/tcp` reverse-shell pseudo-device.
        // `/etc/hosts`, `/etc/resolv.conf`, `/etc/nginx/**`, `/var/log/**`,
        // `/usr/local/**`, `/tmp/**`, `/sys/**` and plain `/home/<user>/…`
        // deliberately no longer match: they are normal content in runbooks,
        // config-management payloads and log shippers.
        concat!(
            r"(?i)/(?:etc/(?:passwd|shadow|gshadow|master\.passwd|sudoers|ssh/|ssl/private|security/opasswd)",
            r"|proc/(?:self|version|cmdline|environ|net/|[0-9]{1,10}/)",
            r"|root/\.[a-z_]",
            r"|home/[^/\s]{1,32}/\.(?:ssh|bash_history|aws|config|npmrc|docker|git-credentials|mysql_history)",
            r"|var/log/(?:auth\.log|secure)",
            r"|dev/(?:tcp|udp)/",
            r"|windows/(?:win\.ini|system32/config)",
            r"|winnt/win\.ini",
            r"|boot\.ini)",
        ),
        // ── TRAV-008 — Windows system path ───────────────────────────────────
        // `[A-Za-z]:\` matched every Windows path a user ever pastes into a bug
        // report or a log shipper sends (`C:\Users\alice\Desktop\report.xlsx`).
        // Windows LFI targets the system tree, so that is all this matches now.
        r"(?i)[a-z]:[\\/]{1,2}(?:windows|winnt|inetpub|xampp|wamp|boot\.ini)\b",
    ]) {
        Ok(set) => Some(set),
        Err(e) => {
            tracing::error!(
                "BUG: directory traversal regex set failed to compile: {e} — failing closed \
                 (this checker will now flag every request until the code is fixed)"
            );
            None
        }
    }
});

/// Directory traversal / path injection detection checker.
pub struct DirTraversalCheck {
    /// How much request body this detector will read. See [`Lane1BodyBudget`].
    body_budget: Lane1BodyBudget,
}

impl DirTraversalCheck {
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

impl Default for DirTraversalCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for DirTraversalCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.dir_traversal {
            return None;
        }

        let Some(set) = TRAVERSAL_SET.as_ref() else {
            // Fail-closed: the pattern set failed to compile at startup.
            return Some(DetectionResult {
                rule_id: Some("TRAV-000".to_string()),
                rule_name: "Directory Traversal".to_string(),
                phase: Phase::DirTraversal,
                detail: "fail-closed: directory traversal pattern set failed to compile at startup".to_string(),
            });
        };

        // Scan path / query / cookie / body plus curated headers, in raw and
        // (recursively) decoded forms — shared with the other content checkers.
        for (location, value) in request_targets(ctx, self.body_budget) {
            if value.is_empty() {
                continue;
            }
            let matches = set.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = TRAVERSAL_DESCS.get(idx).copied().unwrap_or("path traversal");
                return Some(DetectionResult {
                    rule_id: Some(format!("TRAV-{:03}", idx + 1)),
                    rule_name: "Directory Traversal".to_string(),
                    phase: Phase::DirTraversal,
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

    fn make_ctx(path: &str, query: &str) -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: path.to_string(),
            query: query.to_string(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig {
                defense_config: DefenseConfig {
                    dir_traversal: true,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    #[test]
    fn detects_dot_dot_slash() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/images/../../../etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_encoded_traversal() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/", "file=%2e%2e%2fetc%2fpasswd");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_double_encoded() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/%252e%252e/etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_clean_path() {
        let checker = DirTraversalCheck::new();
        let ctx = make_ctx("/api/v1/users", "page=2");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn detects_traversal_in_body() {
        let checker = DirTraversalCheck::new();
        let mut ctx = make_ctx("/upload", "");
        ctx.body_preview = Bytes::from_static(b"file=../../../etc/passwd");
        // M-5: body is now scanned via request_targets.
        assert!(checker.check(&ctx).is_some());
    }

    /// The reported production false positives: ordinary absolute paths.
    /// A site route named `/home` must not 403 its own page.
    #[test]
    fn ordinary_absolute_paths_are_allowed() {
        let checker = DirTraversalCheck::new();
        for (path, query) in [
            ("/home", ""),
            ("/dev/api/v1/status", ""),
            ("/tmp/preview/abc", ""),
            ("/p", "path=%2Fetc%2F"),
            ("/p", "file=%2Fetc%2Fhosts"),
        ] {
            let ctx = make_ctx(path, query);
            assert!(
                checker.check(&ctx).is_none(),
                "ordinary absolute path must not fire: {path}?{query}"
            );
        }
        for body in [
            r#"{"path":"/etc/nginx/nginx.conf","action":"review"}"#,
            r#"{"path":"/etc/resolv.conf"}"#,
            r#"{"note":"ran cat /etc/{hosts,resolv.conf} to confirm dns"}"#,
            r#"{"logdir":"/var/log/nginx","rotate":true}"#,
            r#"{"deploy_dir":"/home/deploy/app/current"}"#,
            r#"{"path":"/usr/local/bin/app","user":"/home/app"}"#,
            r#"{"text":"check /proc/cpuinfo and /sys/class/net"}"#,
            r#"{"attachment":"C:\\Users\\alice\\Desktop\\report.xlsx"}"#,
        ] {
            let mut ctx = make_ctx("/upload", "");
            ctx.body_preview = Bytes::from(body.to_string());
            ctx.content_length = body.len() as u64;
            assert!(
                checker.check(&ctx).is_none(),
                "ops/config payload must not fire: {body}"
            );
        }
    }

    /// The disclosure targets the narrowed rule must keep blocking.
    #[test]
    fn sensitive_absolute_paths_still_detected() {
        let checker = DirTraversalCheck::new();
        for query in [
            "f=%2Fetc%2Fpasswd",
            "f=%2Fetc%2Fshadow",
            "f=%2Fetc%2Fsudoers",
            "f=%2Fetc%2Fssh%2Fssh_host_rsa_key",
            "f=%2Fproc%2Fself%2Fenviron",
            "f=%2Fproc%2Fversion",
            "f=%2Froot%2F.ssh%2Fid_rsa",
            "f=%2Froot%2F.bash_history",
            "f=%2Fhome%2Falice%2F.ssh%2Fid_rsa",
            "f=%2Fdev%2Ftcp%2F1.2.3.4%2F4444",
            "f=C%3A%5CWindows%5Cwin.ini",
            "f=%2Fvar%2Flog%2Fauth.log",
        ] {
            let ctx = make_ctx("/p", query);
            assert!(
                checker.check(&ctx).is_some(),
                "sensitive path disclosure must still fire: {query}"
            );
        }
    }

    #[test]
    fn detects_traversal_in_cookie() {
        let checker = DirTraversalCheck::new();
        let mut ctx = make_ctx("/", "");
        ctx.headers
            .insert("cookie".to_string(), "sid=..%2f..%2fetc%2fpasswd".to_string());
        assert!(checker.check(&ctx).is_some());
    }
}
