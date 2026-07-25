use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// `GeoIP` information resolved from the client IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoIpInfo {
    pub country: String,
    pub province: String,
    pub city: String,
    pub isp: String,
    pub iso_code: String,
}

/// Request context passed through the WAF pipeline
#[derive(Debug, Clone)]
pub struct RequestCtx {
    pub req_id: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body_preview: Bytes,
    pub content_length: u64,
    pub is_tls: bool,
    pub host_config: Arc<HostConfig>,
    /// `GeoIP` info populated by the WAF engine before checks run.
    ///
    /// `None` if `GeoIP` is disabled or the xdb file is missing.
    pub geo: Option<GeoIpInfo>,
}

// ── `ARGS` splitting ──────────────────────────────────────────────────────────

/// Maximum number of `ARGS` members split out of one surface (query string or
/// urlencoded body).
///
/// # Why there is a limit at all
///
/// Per-parameter evaluation multiplies work by the member count: every loaded
/// CRS pattern runs once per member, and the per-invocation cost does not shrink
/// with the member — a 4-byte value costs nearly as much as a 4 KiB one. Against
/// the shipped 216-rule set an extra member costs ~14 us, so an attacker who
/// splits the same bytes across more parameters buys CPU time for free.
///
/// # Why 256 and not the 1000 everyone else uses
///
/// `ModSecurity`'s `SecArgumentsLimit`, PHP's `max_input_vars`, Django's
/// `DATA_UPLOAD_MAX_NUMBER_FIELDS` and Tomcat's `maxParameterCount` all default
/// to 1000 — but those are *parse* limits, where exceeding them means rejecting
/// the request. Here it is a *precision* budget: exceeding it costs sharper
/// matching, never coverage.
///
/// Reaching the limit is **not** a silent drop. [`split_form_args`] emits the
/// entire unsplit remainder as one final nameless member, so every byte of the
/// surface is still handed to the rules — the overflow tail simply degrades to
/// the whole-string behaviour that every request got before splitting existed.
/// The overflow path is therefore never worse than the status quo ante, which
/// makes a low bound cheap: 256 covers the widest realistic HTML form or
/// bulk-edit grid, and it is what keeps the pathological cases close to the
/// pre-splitting cost. Measured (release build, one process, shipped rule set,
/// whole-surface `ARGS` vs. per-parameter `ARGS`):
///
/// | request                        | whole-surface | per-parameter | ratio |
/// |--------------------------------|---------------|---------------|-------|
/// | no query string                | 32.3 us       | 30.5 us       | 0.95x |
/// | 3 query parameters             | 51.2 us       | 76.0 us       | 1.48x |
/// | form POST, 4 parameters        | 44.0 us       | 72.6 us       | 1.65x |
/// | 200 query parameters           | 0.64 ms       | 2.30 ms       | 3.59x |
/// | 8 KiB query, 1 parameter       | 0.67 ms       | 0.73 ms       | 1.10x |
/// | 8 KiB query, 1024 parameters   | 3.29 ms       | 5.71 ms       | 1.73x |
/// | 2000 query parameters          | 6.44 ms       | 8.81 ms       | 1.37x |
///
/// At a 1000-member budget the last two rows read 15.0 ms (4.6x) and 17.9 ms
/// (2.8x) instead — i.e. the budget, not the splitting, is what bounds the
/// amplification an attacker can buy with a fixed number of bytes.
pub const MAX_FORM_ARGS: usize = 256;

/// One `name=value` member of a urlencoded surface, **still percent-encoded**.
///
/// Splitting happens before decoding, which is the order `ModSecurity`'s parser
/// uses and the only order that is correct: an encoded `%26` inside a value is
/// a literal `&` in the value, not a member separator, and decoding first would
/// turn it into one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawArg<'a> {
    /// Text left of the first `=`, or the whole member when it carries no `=`.
    pub name: &'a str,
    /// Text right of the first `=`; empty when the member carries no `=`.
    pub value: &'a str,
}

/// Split a urlencoded surface (`a=1&b=2`) into its members.
///
/// * The separator is `&` only — `ModSecurity`'s `SecArgumentSeparator` default.
/// * A member with no `=` contributes its text as the **name** and an empty
///   value, so `?phpsessid` names a parameter (which is exactly what CRS-943110
///   tests) rather than being an anonymous value.
/// * Empty members (`a=1&&b=2`, a trailing `&`) are skipped: `ModSecurity`
///   creates no `ARGS` entry for them.
/// * Repeated names are preserved in order and never merged — HTTP parameter
///   pollution has to stay visible to the rules (see the `ARGS` note in
///   `checks::owasp`).
/// * At most [`MAX_FORM_ARGS`] members are produced; see that constant for what
///   happens to the remainder.
#[must_use]
pub fn split_form_args(input: &str) -> Vec<RawArg<'_>> {
    let mut out: Vec<RawArg<'_>> = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let (member, tail) = rest.split_once('&').unwrap_or((rest, ""));
        if out.len() + 1 == MAX_FORM_ARGS && !tail.is_empty() {
            // Budget spent and more to come: hand the unsplit remainder over as
            // one member rather than dropping it. `name` stays empty so an
            // `ARGS_NAMES` rule — whose patterns are anchored parameter names —
            // is not run against a string that is not a parameter name.
            out.push(RawArg { name: "", value: rest });
            return out;
        }
        rest = tail;
        if member.is_empty() {
            continue;
        }
        let (name, value) = member.split_once('=').unwrap_or((member, ""));
        out.push(RawArg { name, value });
    }
    out
}

/// `true` when `content_type` announces a body the `ARGS_POST` splitter can
/// read.
///
/// Only `application/x-www-form-urlencoded` qualifies. JSON / XML / GraphQL /
/// multipart bodies are structured formats whose members are extracted by Lane
/// 2's `struct_extract`; splitting them here on `&` and `=` would invent
/// parameters that do not exist.
#[must_use]
pub fn is_form_urlencoded(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|ct| {
        ct.split(';')
            .next()
            .unwrap_or(ct)
            .trim()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded")
    })
}

/// WAF action decision
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Block { status: u16, body: Option<String> },
    LogOnly,
    Redirect { url: String },
}

/// WAF decision with context
#[derive(Debug, Clone)]
pub struct WafDecision {
    pub action: WafAction,
    pub result: Option<DetectionResult>,
}

impl WafDecision {
    pub const fn allow() -> Self {
        Self {
            action: WafAction::Allow,
            result: None,
        }
    }

    pub const fn block(status: u16, body: Option<String>, result: DetectionResult) -> Self {
        Self {
            action: WafAction::Block { status, body },
            result: Some(result),
        }
    }

    pub const fn is_allowed(&self) -> bool {
        matches!(self.action, WafAction::Allow | WafAction::LogOnly)
    }
}

/// Detection phase
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Phase {
    IpWhitelist = 1,
    IpBlacklist = 2,
    UrlWhitelist = 3,
    UrlBlacklist = 4,
    SqlInjection = 5,
    Xss = 6,
    Rce = 7,
    Scanner = 8,
    DirTraversal = 9,
    Bot = 10,
    RateLimit = 11,
    /// Custom scripted rules engine
    CustomRule = 12,
    /// OWASP Core Rule Set checks
    Owasp = 13,
    /// Sensitive word / data-leak detection
    Sensitive = 14,
    /// Anti-hotlinking (Referer check)
    AntiHotlink = 15,
    /// `CrowdSec` bouncer / `AppSec` decision
    CrowdSec = 16,
    /// `GeoIP`-based access control
    GeoIp = 17,
    /// Community threat intelligence blocklist
    Community = 18,
    /// XML external entity injection (Lane 2 semantic `xxe` family, T2-A)
    Xxe = 19,
    /// `NoSQL` (`MongoDB`-style operator) injection (Lane 2 semantic
    /// `nosql_injection` family, T2-B)
    NoSqlInjection = 20,
    /// Server-side template injection (Lane 2 semantic `ssti` family, T2-C)
    Ssti = 21,
    /// LDAP search-filter injection (Lane 2 semantic `ldap_injection` family,
    /// T2-D)
    LdapInjection = 22,
    /// `XPath` / `XQuery` injection (Lane 2 semantic `xpath_injection` family,
    /// T2-E)
    XpathInjection = 23,
    /// Unsafe / insecure deserialization — object-injection & gadget-chain
    /// signatures (Lane 2 semantic `deserialization` family, T2-F)
    Deserialization = 24,
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpWhitelist => write!(f, "IP Whitelist"),
            Self::IpBlacklist => write!(f, "IP Blacklist"),
            Self::UrlWhitelist => write!(f, "URL Whitelist"),
            Self::UrlBlacklist => write!(f, "URL Blacklist"),
            Self::SqlInjection => write!(f, "SQL Injection"),
            Self::Xss => write!(f, "XSS"),
            Self::Rce => write!(f, "RCE"),
            Self::Scanner => write!(f, "Scanner"),
            Self::DirTraversal => write!(f, "Directory Traversal"),
            Self::Bot => write!(f, "Bot"),
            Self::RateLimit => write!(f, "Rate Limit"),
            Self::CustomRule => write!(f, "Custom Rule"),
            Self::Owasp => write!(f, "OWASP CRS"),
            Self::Sensitive => write!(f, "Sensitive Data"),
            Self::AntiHotlink => write!(f, "Anti-Hotlink"),
            Self::CrowdSec => write!(f, "CrowdSec"),
            Self::GeoIp => write!(f, "GeoIP"),
            Self::Community => write!(f, "Community"),
            Self::Xxe => write!(f, "XXE"),
            Self::NoSqlInjection => write!(f, "NoSQL Injection"),
            Self::Ssti => write!(f, "SSTI"),
            Self::LdapInjection => write!(f, "LDAP Injection"),
            Self::XpathInjection => write!(f, "XPath Injection"),
            Self::Deserialization => write!(f, "Unsafe Deserialization"),
        }
    }
}

/// Detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub rule_id: Option<String>,
    pub rule_name: String,
    pub phase: Phase,
    pub detail: String,
}

/// Host configuration matching `SamWaf` Hosts model
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub code: String,
    pub host: String,
    pub port: u16,
    pub ssl: bool,
    pub guard_status: bool,
    pub remote_host: String,
    pub remote_port: u16,
    pub remote_ip: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub remarks: Option<String>,
    pub start_status: bool,
    pub exclude_url_log: Vec<String>,
    pub is_enable_load_balance: bool,
    pub load_balance_strategy: LoadBalanceStrategy,
    pub defense_config: DefenseConfig,
    pub log_only_mode: bool,
    /// Custom HTML block page template; placeholders: `{{req_id}}`, `{{rule_name}}`, `{{client_ip}}`
    pub block_page_template: Option<String>,
    /// Optional multi-backend pool for load balancing.
    ///
    /// When empty (the default), the single `remote_host`/`remote_port` pair is
    /// used verbatim — this preserves the historical single-backend behaviour
    /// and keeps existing configs working unchanged. When non-empty, a
    /// `LoadBalancer` is built for this host and requests are distributed across
    /// the listed backends according to `load_balance_strategy`.
    #[serde(default)]
    pub backends: Vec<BackendConfig>,
}

/// A single upstream backend in a load-balanced pool.
///
/// This is the *serializable* configuration counterpart of the runtime
/// `gateway::lb::Backend` (which additionally carries health/connection state).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendConfig {
    /// Upstream host or IP.
    pub host: String,
    /// Upstream port.
    pub port: u16,
    /// Relative weight for `WeightedRoundRobin` (defaults to 1). Ignored by
    /// strategies that do not consider weight.
    #[serde(default = "default_backend_weight")]
    pub weight: u32,
}

const fn default_backend_weight() -> u32 {
    1
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            code: String::new(),
            host: String::new(),
            port: 80,
            ssl: false,
            guard_status: true,
            remote_host: String::new(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            exclude_url_log: Vec::new(),
            is_enable_load_balance: false,
            load_balance_strategy: LoadBalanceStrategy::RoundRobin,
            defense_config: DefenseConfig::default(),
            log_only_mode: false,
            block_page_template: None,
            backends: Vec::new(),
        }
    }
}

/// Load balancing strategy
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    #[default]
    RoundRobin,
    IpHash,
    WeightedRoundRobin,
    LeastConnections,
}

/// Defense configuration per host.
///
/// **A3 contract — these toggles gate Lane 1 (legacy) checkers ONLY.** The
/// per-host `sqli` / `xss` / `rce` / `dir_traversal` flags below switch the
/// frozen Lane 1 regex checkers for this host. They are **independent** of the
/// Lane 2 semantic content-security families (`[content_security.attacks.*]` in
/// `configs/default.toml`): turning off a host's `sqli` here does **not** turn
/// off that host's Lane 2 `sql_injection` family — the two switch sets must be
/// managed separately (chosen contract: *explicit separation*, not linkage).
/// The single per-host kill switch for **both** lanes' blocking is the host's
/// `log_only_mode`, which downgrades every Lane 1 veto AND every Lane 2 enforce
/// Block to a `LogOnly` event. Runtime per-host, per-detector Lane 1 gating of
/// Lane 2 remains a backlog item — but these toggles themselves **do** have a
/// runtime write path: the admin API persists them into `hosts.defense_json`
/// and `host_runtime_config` projects them straight onto the live
/// [`HostConfig`](crate::HostConfig) the router serves, so an API host
/// create/update takes effect without a restart. See the full A3 note in
/// `configs/default.toml`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct DefenseConfig {
    pub bot: bool,
    pub sqli: bool,
    pub xss: bool,
    pub scan: bool,
    pub rce: bool,
    pub sensitive: bool,
    pub dir_traversal: bool,
    /// Enable the OWASP Core Rule Set check. Default: `true` at paranoia 1.
    ///
    /// Low false-positive: paranoia 1 only, and it degrades gracefully — if the
    /// `rules/owasp-crs/` directory is absent, a minimal embedded rule set is
    /// used (`OWASPCheck::new` logs a `warn!`); if even that yields no rules the
    /// check simply iterates an empty set and no-ops. Never blocks legitimate
    /// traffic on a fresh install.
    pub owasp_set: bool,
    /// CC / rate-limit protection enabled
    #[serde(default = "bool_true")]
    pub cc: bool,
    /// Token bucket refill rate (requests per second)
    #[serde(default = "default_cc_rps")]
    pub cc_rps: f64,
    /// Token bucket burst capacity
    #[serde(default = "default_cc_burst")]
    pub cc_burst: u32,
    /// Violations before auto-ban
    #[serde(default = "default_cc_ban_threshold")]
    pub cc_ban_threshold: u32,
    /// Auto-ban duration in seconds
    #[serde(default = "default_cc_ban_duration_secs")]
    pub cc_ban_duration_secs: u64,
    /// OWASP CRS paranoia level (1-4, default 1 = most permissive)
    #[serde(default = "default_owasp_paranoia")]
    pub owasp_paranoia: u8,
}

const fn bool_true() -> bool {
    true
}
const fn default_cc_rps() -> f64 {
    100.0
}
const fn default_cc_burst() -> u32 {
    200
}
const fn default_cc_ban_threshold() -> u32 {
    10
}
const fn default_cc_ban_duration_secs() -> u64 {
    300
}
const fn default_owasp_paranoia() -> u8 {
    1
}

impl Default for DefenseConfig {
    fn default() -> Self {
        Self {
            bot: true,
            sqli: true,
            xss: true,
            scan: true,
            rce: true,
            sensitive: true,
            dir_traversal: true,
            // OWASP CRS on by default (paranoia 1). Safe: embedded fallback
            // rules + graceful no-op when no rules load (see field docs).
            owasp_set: true,
            cc: true,
            cc_rps: default_cc_rps(),
            cc_burst: default_cc_burst(),
            cc_ban_threshold: default_cc_ban_threshold(),
            cc_ban_duration_secs: default_cc_ban_duration_secs(),
            owasp_paranoia: default_owasp_paranoia(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(input: &str) -> Vec<(&str, &str)> {
        split_form_args(input).into_iter().map(|a| (a.name, a.value)).collect()
    }

    #[test]
    fn members_split_on_ampersand_and_first_equals() {
        assert_eq!(pairs("a=1&b=2"), [("a", "1"), ("b", "2")]);
        // Only the *first* `=` splits: `a=b=c` is one parameter whose value
        // contains an `=`, which is what every server-side parser does.
        assert_eq!(pairs("a=b=c"), [("a", "b=c")]);
        // A member with no `=` is a name with an empty value.
        assert_eq!(pairs("phpsessid"), [("phpsessid", "")]);
        assert_eq!(pairs("a=1&flag&b=2"), [("a", "1"), ("flag", ""), ("b", "2")]);
        // An empty value is still a member; an empty *member* is not.
        assert_eq!(pairs("a="), [("a", "")]);
        assert_eq!(pairs("&&a=1&&"), [("a", "1")]);
        assert!(pairs("").is_empty());
        assert!(pairs("&&&").is_empty());
    }

    #[test]
    fn nothing_is_decoded_by_the_splitter() {
        // Splitting before decoding is the whole point: an encoded separator
        // must not become one.
        assert_eq!(pairs("q=a%26b%3Dc"), [("q", "a%26b%3Dc")]);
        assert_eq!(pairs("q=a+b"), [("q", "a+b")]);
    }

    #[test]
    fn repeated_names_are_preserved_in_order() {
        assert_eq!(pairs("id=1&id=2&id=3"), [("id", "1"), ("id", "2"), ("id", "3")]);
        assert_eq!(pairs("a[]=1&a[]=2"), [("a[]", "1"), ("a[]", "2")]);
    }

    #[test]
    fn the_member_budget_keeps_the_tail() {
        let surface = (0..MAX_FORM_ARGS + 10)
            .map(|i| format!("k{i}=v{i}"))
            .collect::<Vec<_>>()
            .join("&");
        let args = split_form_args(&surface);
        assert_eq!(args.len(), MAX_FORM_ARGS);

        let last = args.last().expect("budget produces a final member");
        assert_eq!(last.name, "", "the tail is not a parameter name");
        // Everything from the budget boundary onwards is in the tail, so no
        // byte of the surface goes uninspected.
        let boundary = format!("k{}=v{}", MAX_FORM_ARGS - 1, MAX_FORM_ARGS - 1);
        assert!(last.value.starts_with(&boundary), "tail starts at the boundary");
        assert!(
            last.value
                .ends_with(&format!("k{}=v{}", MAX_FORM_ARGS + 9, MAX_FORM_ARGS + 9)),
            "tail runs to the end of the surface"
        );

        // Exactly at the budget nothing is folded.
        let exact = (0..MAX_FORM_ARGS)
            .map(|i| format!("k{i}=v{i}"))
            .collect::<Vec<_>>()
            .join("&");
        let args = split_form_args(&exact);
        assert_eq!(args.len(), MAX_FORM_ARGS);
        assert_eq!(
            args.last().map(|a| a.name),
            Some(format!("k{}", MAX_FORM_ARGS - 1).as_str())
        );
    }

    #[test]
    fn only_a_urlencoded_form_body_is_splittable() {
        assert!(is_form_urlencoded(Some("application/x-www-form-urlencoded")));
        assert!(is_form_urlencoded(Some(
            "application/x-www-form-urlencoded; charset=UTF-8"
        )));
        assert!(is_form_urlencoded(Some("  Application/X-WWW-Form-Urlencoded  ")));
        assert!(!is_form_urlencoded(Some("application/json")));
        assert!(!is_form_urlencoded(Some("multipart/form-data; boundary=x")));
        assert!(!is_form_urlencoded(Some("")));
        assert!(!is_form_urlencoded(None));
    }
}
