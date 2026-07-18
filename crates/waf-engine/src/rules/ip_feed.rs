//! IP-feed threat-intelligence adapter.
//!
//! Pulls **raw IP/CIDR blocklists** (as opposed to WAF rule documents) from
//! external, opt-in intelligence sources — ET Open, the Tor exit-node list,
//! Spamhaus DROP, and similar — and folds the parsed CIDRs into the WAF's
//! IP blacklist so matching addresses are blocked (403).
//!
//! Design:
//! * **Fetch** — same SSRF hardening as remote rule sources
//!   ([`fetch_ip_feed`]): the URL is validated with
//!   [`waf_common::url_validator::validate_public_url_with_ips`], the HTTP
//!   client is pinned to the validated IPs (DNS-rebinding TOCTOU is closed),
//!   redirects are disabled, and both a timeout and a 50 MiB body cap apply.
//! * **Parse** — [`parse_ip_feed`] is fault-tolerant: comments (`#` / `;`),
//!   blank lines and trailing whitespace are ignored, and any malformed entry
//!   is skipped and counted rather than failing the whole feed.
//! * **Write** — parsed CIDRs are loaded into a dedicated, source-tagged
//!   [`crate::rules::IpRuleSet`] bucket (keyed by feed name) inside the live
//!   [`RuleStore`]. Because each feed owns its own bucket, a refresh replaces
//!   only that source's entries (no global rewrite jitter), and per-source
//!   cleanup is a single-key operation. The feed set is never touched by the
//!   database reload path, so admin rule reloads and feed refreshes never race.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde_json::Value;
use tracing::{info, warn};

use crate::checker::RuleStore;

/// Maximum allowed IP-feed response body size (50 MiB).
///
/// Larger than the rule-source cap because blocklists such as VirusShare-style
/// dumps can be sizeable, while still bounding memory use per fetch.
const MAX_IP_FEED_SIZE: u64 = 50 * 1024 * 1024;

/// Lower bound on a feed refresh interval, to avoid hammering upstream sources
/// if a configuration sets an unreasonably small value.
const MIN_FEED_INTERVAL_SECS: u64 = 60;

/// Total request timeout for a feed fetch.
const FEED_REQUEST_TIMEOUT_SECS: u64 = 60;

/// Connection-establishment timeout for a feed fetch.
const FEED_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Parsing format of an IP feed body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFeedFormat {
    /// One IPv4/IPv6 address or CIDR per line. `#` and `;` start inline
    /// comments; blank lines and surrounding whitespace are tolerated. This
    /// covers ET Open, the Tor exit list and the Spamhaus DROP `.txt` variant.
    Plain,
    /// Spamhaus DROP JSON: one JSON object per line (JSONL), each carrying a
    /// `"cidr"` string field, plus a trailing metadata record. A single
    /// top-level JSON array of such objects is also accepted.
    SpamhausJson,
}

impl IpFeedFormat {
    /// Parse a configuration string into a format, defaulting to [`Self::Plain`].
    pub fn parse_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "spamhaus_json" | "spamhaus" | "json" => Self::SpamhausJson,
            _ => Self::Plain,
        }
    }
}

/// A configured IP-feed source.
#[derive(Debug, Clone)]
pub struct IpFeedSource {
    /// Unique, human-readable feed name. Doubles as the source tag / bucket key
    /// used for per-source replacement and cleanup.
    pub name: String,
    /// HTTP(S) URL of the raw blocklist.
    pub url: String,
    /// Body format used to parse the response.
    pub format: IpFeedFormat,
    /// How often to re-fetch the feed.
    pub update_interval: Duration,
}

/// Outcome of parsing a feed body.
#[derive(Debug, Default, Clone)]
pub struct ParsedFeed {
    /// Successfully parsed networks.
    pub nets: Vec<IpNet>,
    /// Count of non-empty, non-comment entries that failed to parse.
    pub skipped: usize,
}

/// Parse a single token as an [`IpNet`], accepting either CIDR notation
/// (`1.2.3.0/24`) or a bare address (`1.2.3.4`, treated as a /32 or /128).
fn parse_one(token: &str) -> Option<IpNet> {
    token
        .parse::<IpNet>()
        .or_else(|_| token.parse::<IpAddr>().map(IpNet::from))
        .ok()
}

/// Parse `content` into CIDRs according to `format`.
///
/// Never fails: malformed entries are skipped and reported via
/// [`ParsedFeed::skipped`] so a few bad lines cannot discard an entire feed.
pub fn parse_ip_feed(content: &str, format: IpFeedFormat) -> ParsedFeed {
    match format {
        IpFeedFormat::Plain => parse_plain(content),
        IpFeedFormat::SpamhausJson => parse_spamhaus_json(content),
    }
}

fn parse_plain(content: &str) -> ParsedFeed {
    let mut nets = Vec::new();
    let mut skipped = 0usize;

    for raw in content.lines() {
        // Strip inline comments beginning with '#' or ';'. `split` always
        // yields at least one element, so the first segment is the pre-comment
        // portion (empty for a whole-line comment).
        let pre_comment = raw.split(['#', ';']).next().unwrap_or("");
        let line = pre_comment.trim();
        if line.is_empty() {
            continue;
        }

        // Some feeds append metadata after the address (space/tab/comma
        // separated); take only the first token.
        let token = line.split([' ', '\t', ',']).next().unwrap_or("").trim();
        if token.is_empty() {
            continue;
        }

        if let Some(net) = parse_one(token) {
            nets.push(net);
        } else {
            skipped += 1;
            warn!(entry = %token, "ip-feed: skipping malformed entry");
        }
    }

    ParsedFeed { nets, skipped }
}

/// Extract and parse the `"cidr"` field from a JSON object, if present.
fn extract_cidr(value: &Value) -> Option<IpNet> {
    let cidr = value.get("cidr")?.as_str()?;
    parse_one(cidr)
}

fn parse_spamhaus_json(content: &str) -> ParsedFeed {
    let mut nets = Vec::new();
    let mut skipped = 0usize;

    // Accept a single top-level JSON array of objects.
    if content.trim_start().starts_with('[')
        && let Ok(arr) = serde_json::from_str::<Vec<Value>>(content)
    {
        for value in &arr {
            // Objects without a `cidr` (e.g. a metadata record) are not data
            // errors — silently ignore.
            if let Some(net) = extract_cidr(value) {
                nets.push(net);
            }
        }
        return ParsedFeed { nets, skipped };
    }

    // Otherwise treat the body as JSONL: one JSON object per line, with a
    // trailing metadata record. Parse line-by-line so a single bad line never
    // discards the whole feed.
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            // A well-formed object without a `cidr` (metadata) is not an error
            // and is not counted as skipped.
            if let Some(net) = extract_cidr(&value) {
                nets.push(net);
            }
        } else {
            skipped += 1;
            warn!("ip-feed: skipping malformed JSON line");
        }
    }

    ParsedFeed { nets, skipped }
}

/// Fetch an IP-feed body over HTTP(S) with SSRF protections.
///
/// Mirrors the remote-rule-source fetch: the URL is validated against
/// private/reserved ranges, the client is pinned to the resolved IPs to close
/// the DNS-rebinding TOCTOU window, redirects are refused, and a timeout plus a
/// [`MAX_IP_FEED_SIZE`] body cap bound the request.
pub async fn fetch_ip_feed(url: &str) -> Result<String> {
    let (validated_url, resolved_addrs) = waf_common::url_validator::validate_public_url_with_ips(url)
        .with_context(|| format!("IP-feed URL failed SSRF validation: {url}"))?;

    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(FEED_REQUEST_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(FEED_CONNECT_TIMEOUT_SECS));

    // Pin the client to the validated IPs (DNS hostnames only; IP-literal URLs
    // return an empty address set).
    if !resolved_addrs.is_empty()
        && let Some(host) = validated_url.host_str()
    {
        builder = builder.resolve_to_addrs(host, &resolved_addrs);
    }

    let client = builder
        .build()
        .with_context(|| "Failed to build SSRF-safe HTTP client for IP feed")?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch IP feed {url}"))?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("IP-feed source returned HTTP {status} for {url}");
    }

    // Reject bodies that advertise a size over the cap before downloading.
    if let Some(len) = response.content_length()
        && len > MAX_IP_FEED_SIZE
    {
        anyhow::bail!("IP-feed response too large: {len} bytes (max {MAX_IP_FEED_SIZE})");
    }

    let body = response
        .text()
        .await
        .with_context(|| format!("Failed to read IP-feed body from {url}"))?;

    // Content-Length may be absent; re-check after download.
    if body.len() as u64 > MAX_IP_FEED_SIZE {
        anyhow::bail!("IP-feed body too large: {} bytes (max {MAX_IP_FEED_SIZE})", body.len());
    }

    Ok(body)
}

/// Refresh a single feed: fetch, parse, and atomically replace that feed's
/// entries in the shared feed block set.
///
/// The block set is keyed by the feed name, so this touches only this source's
/// bucket — no global rewrite, and stale entries from the previous fetch are
/// replaced in one operation. Returns the number of loaded CIDRs.
pub async fn refresh_feed(store: &RuleStore, feed: &IpFeedSource) -> Result<usize> {
    let body = fetch_ip_feed(&feed.url).await?;
    let parsed = parse_ip_feed(&body, feed.format);
    let loaded = parsed.nets.len();

    // Atomic per-source replacement: overwrites this feed's bucket in place.
    store.feed_block_ips.load_nets(&feed.name, parsed.nets);

    info!(
        feed = %feed.name,
        loaded,
        skipped = parsed.skipped,
        "ip-feed refreshed"
    );
    Ok(loaded)
}

/// Spawn one background task per feed, each refreshing on its configured
/// interval (clamped to [`MIN_FEED_INTERVAL_SECS`]). The first tick fires
/// immediately, so feeds load on startup.
///
/// Returns the task handles; callers keep them alive for the process lifetime.
/// A failed refresh is logged and retried on the next tick — a transient
/// upstream outage never tears down the task or the process.
pub fn spawn_ip_feed_sync(store: &Arc<RuleStore>, feeds: Vec<IpFeedSource>) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::with_capacity(feeds.len());

    for feed in feeds {
        let store = Arc::clone(store);
        let interval = feed.update_interval.max(Duration::from_secs(MIN_FEED_INTERVAL_SECS));

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                // First tick is immediate → initial load on startup.
                ticker.tick().await;
                if let Err(e) = refresh_feed(&store, &feed).await {
                    warn!(feed = %feed.name, "ip-feed refresh failed: {e}");
                }
            }
        });
        handles.push(handle);
    }

    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parse_str() {
        assert_eq!(IpFeedFormat::parse_str("plain"), IpFeedFormat::Plain);
        assert_eq!(IpFeedFormat::parse_str(""), IpFeedFormat::Plain);
        assert_eq!(IpFeedFormat::parse_str("unknown"), IpFeedFormat::Plain);
        assert_eq!(IpFeedFormat::parse_str("spamhaus_json"), IpFeedFormat::SpamhausJson);
        assert_eq!(IpFeedFormat::parse_str(" JSON "), IpFeedFormat::SpamhausJson);
    }

    // ── Plain parser ─────────────────────────────────────────────────────────

    #[test]
    fn plain_parses_ips_and_cidrs() {
        let body = "1.2.3.4\n10.0.0.0/8\n2001:db8::/32\n::1\n";
        let parsed = parse_ip_feed(body, IpFeedFormat::Plain);
        assert_eq!(parsed.nets.len(), 4);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn plain_tolerates_comments_blanks_and_whitespace() {
        // ET Open / Tor style: hash comments, blank lines, trailing whitespace.
        let body = "\
# Emerging Threats compromised IPs\n\
\n\
   1.2.3.4   \n\
5.6.7.8\t\n\
# another comment\n\
9.9.9.0/24 # inline comment\n\
";
        let parsed = parse_ip_feed(body, IpFeedFormat::Plain);
        assert_eq!(parsed.nets.len(), 3, "3 valid entries expected");
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn plain_tolerates_semicolon_comments_spamhaus_txt() {
        // Spamhaus DROP .txt format: "cidr ; SBLxxxxx".
        let body = "\
; Spamhaus DROP List\n\
1.10.16.0/20 ; SBL256894\n\
1.19.0.0/16 ; SBL434604\n\
";
        let parsed = parse_ip_feed(body, IpFeedFormat::Plain);
        assert_eq!(parsed.nets.len(), 2);
        assert_eq!(parsed.skipped, 0);
        let net: IpNet = "1.10.16.0/20".parse().expect("valid cidr");
        assert!(parsed.nets.contains(&net));
    }

    #[test]
    fn plain_counts_malformed_and_keeps_valid() {
        let body = "1.2.3.4\nnot-an-ip\n999.999.999.999\n5.6.7.8\n";
        let parsed = parse_ip_feed(body, IpFeedFormat::Plain);
        assert_eq!(parsed.nets.len(), 2);
        assert_eq!(parsed.skipped, 2, "two malformed lines must be counted, not fatal");
    }

    #[test]
    fn plain_empty_body_is_empty() {
        let parsed = parse_ip_feed("", IpFeedFormat::Plain);
        assert!(parsed.nets.is_empty());
        assert_eq!(parsed.skipped, 0);
    }

    // ── Spamhaus JSON parser ─────────────────────────────────────────────────

    #[test]
    fn spamhaus_jsonl_parses_cidr_and_ignores_metadata() {
        // Real Spamhaus DROP JSONL shape: data objects + trailing metadata.
        let body = "\
{\"cidr\":\"1.10.16.0/20\",\"sblid\":\"SBL256894\",\"rir\":\"apnic\"}\n\
{\"cidr\":\"1.19.0.0/16\",\"sblid\":\"SBL434604\",\"rir\":\"apnic\"}\n\
{\"type\":\"metadata\",\"timestamp\":1690000000,\"size\":2}\n\
";
        let parsed = parse_ip_feed(body, IpFeedFormat::SpamhausJson);
        assert_eq!(parsed.nets.len(), 2, "two cidr records expected");
        assert_eq!(parsed.skipped, 0, "metadata line is ignored, not skipped-as-error");
        let net: IpNet = "1.19.0.0/16".parse().expect("valid cidr");
        assert!(parsed.nets.contains(&net));
    }

    #[test]
    fn spamhaus_json_array_form() {
        let body = "[{\"cidr\":\"203.0.113.0/24\"},{\"cidr\":\"198.51.100.0/24\"},{\"type\":\"metadata\"}]";
        let parsed = parse_ip_feed(body, IpFeedFormat::SpamhausJson);
        assert_eq!(parsed.nets.len(), 2);
        assert_eq!(parsed.skipped, 0);
    }

    #[test]
    fn spamhaus_jsonl_counts_malformed_line() {
        let body = "\
{\"cidr\":\"1.10.16.0/20\"}\n\
{this is not json}\n\
{\"cidr\":\"1.19.0.0/16\"}\n\
";
        let parsed = parse_ip_feed(body, IpFeedFormat::SpamhausJson);
        assert_eq!(parsed.nets.len(), 2);
        assert_eq!(parsed.skipped, 1);
    }

    #[test]
    fn spamhaus_json_bad_cidr_ignored_not_fatal() {
        // Well-formed JSON, cidr present but unparseable → ignored (not data).
        let body = "{\"cidr\":\"not-a-cidr\"}\n{\"cidr\":\"8.8.8.0/24\"}\n";
        let parsed = parse_ip_feed(body, IpFeedFormat::SpamhausJson);
        assert_eq!(parsed.nets.len(), 1);
    }

    // ── SSRF protection ──────────────────────────────────────────────────────
    //
    // `fetch_ip_feed` must refuse any feed URL that resolves to a private,
    // loopback, link-local or otherwise-reserved destination — even though the
    // feed list is admin-configured — to prevent SSRF / internal probing.

    #[tokio::test]
    async fn ssrf_rejects_loopback_feed() {
        let err = fetch_ip_feed("http://127.0.0.1/blocklist.txt")
            .await
            .expect_err("loopback feed URL must be rejected");
        assert!(err.to_string().contains("SSRF"), "error should cite SSRF validation");
    }

    #[tokio::test]
    async fn ssrf_rejects_private_feed() {
        assert!(fetch_ip_feed("http://10.0.0.5/list").await.is_err());
        assert!(fetch_ip_feed("http://192.168.1.1/list").await.is_err());
        assert!(fetch_ip_feed("http://172.16.0.1/list").await.is_err());
    }

    #[tokio::test]
    async fn ssrf_rejects_cloud_metadata_feed() {
        // AWS/Azure/GCP IMDS must never be reachable via a feed URL.
        assert!(fetch_ip_feed("http://169.254.169.254/latest/meta-data/").await.is_err());
        assert!(fetch_ip_feed("http://metadata.google.internal/").await.is_err());
    }

    #[tokio::test]
    async fn ssrf_rejects_non_http_scheme() {
        assert!(fetch_ip_feed("file:///etc/passwd").await.is_err());
        assert!(fetch_ip_feed("ftp://example.com/list").await.is_err());
    }

    // ── Per-source feed set semantics ────────────────────────────────────────
    //
    // These exercise the dedicated feed `IpRuleSet` used by `RuleStore`:
    // globally-scoped `match_source`, per-source replacement, and cleanup.

    #[test]
    fn feed_set_match_source_is_global_and_named() {
        let set = crate::rules::IpRuleSet::new();
        set.load_nets("tor-exit", vec!["203.0.113.0/24".parse().expect("cidr")]);
        set.load_nets("et-open", vec!["198.51.100.7/32".parse().expect("cidr")]);

        // Matches regardless of host scoping, and returns the source name.
        let tor_ip: IpAddr = "203.0.113.42".parse().expect("ip");
        assert_eq!(set.match_source(tor_ip).as_deref(), Some("tor-exit"));
        let et_ip: IpAddr = "198.51.100.7".parse().expect("ip");
        assert_eq!(set.match_source(et_ip).as_deref(), Some("et-open"));

        let clean: IpAddr = "8.8.8.8".parse().expect("ip");
        assert!(set.match_source(clean).is_none());
    }

    #[test]
    fn feed_set_refresh_replaces_only_that_source() {
        let set = crate::rules::IpRuleSet::new();
        set.load_nets("tor-exit", vec!["203.0.113.0/24".parse().expect("cidr")]);
        set.load_nets("et-open", vec!["198.51.100.0/24".parse().expect("cidr")]);

        // Refresh "tor-exit" with a new list — "et-open" must be untouched.
        set.load_nets("tor-exit", vec!["192.0.2.0/24".parse().expect("cidr")]);

        let old_tor: IpAddr = "203.0.113.42".parse().expect("ip");
        let new_tor: IpAddr = "192.0.2.10".parse().expect("ip");
        let et: IpAddr = "198.51.100.9".parse().expect("ip");

        assert!(set.match_source(old_tor).is_none(), "stale tor entry pruned");
        assert_eq!(set.match_source(new_tor).as_deref(), Some("tor-exit"));
        assert_eq!(
            set.match_source(et).as_deref(),
            Some("et-open"),
            "other source untouched"
        );
    }
}
