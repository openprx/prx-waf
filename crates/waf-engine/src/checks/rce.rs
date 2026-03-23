use std::sync::LazyLock;

use regex::RegexSet;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::{Check, request_targets};

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
];

#[allow(clippy::expect_used)]
static RCE_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        // Pipe/semicolon followed by known shell commands
        r"(?i)[|;`]\s*(cat|ls|dir|wget|curl|bash|sh|zsh|fish|nc|ncat|nmap|python[23]?|perl|ruby|php|exec|system|passthru|popen|id|whoami|uname)\b",
        // $() subshell
        r"\$\s*\([^)]{1,200}\)",
        // Backtick subshell
        r"`[^`]{1,200}`",
        // Sensitive file paths
        r"(?i)/etc/passwd",
        r"(?i)/proc/self",
        r"(?i)/etc/shadow",
        // Double ampersand chained commands
        r"&&\s*(cat|ls|wget|curl|bash|sh|nc|nmap|python|perl|ruby)\b",
        // PHP opening tag
        r"<\?php",
        // Windows cmd.exe
        r"(?i)cmd\.exe",
        // PowerShell
        r"(?i)\bpowershell\b",
        // PHP functions commonly used in webshells
        r"(?i)\bbase64_decode\s*\(",
        r"(?i)\bsystem\s*\(",
        r"(?i)\bexec\s*\(",
        r"(?i)\bpassthru\s*\(",
        r"(?i)\bshell_exec\s*\(",
        r"(?i)\bpopen\s*\(",
        // Windows %SYSTEMROOT%
        r"(?i)%SystemRoot%",
        // curl/wget to external URLs
        r"(?i)\bcurl\s+https?://",
        r"(?i)\bwget\s+https?://",
        // Netcat reverse shell patterns
        r"(?i)\bnc\b.*-[el]",
    ])
    .expect("RCE regex set compilation failed")
});

/// Remote Code Execution / Command Injection detection checker.
pub struct RceCheck;

impl RceCheck {
    pub const fn new() -> Self {
        Self
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

        for (location, value) in request_targets(ctx) {
            let matches = RCE_SET.matches(&value);
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
}
