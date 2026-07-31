//! Cluster rule-sync bridge between the database entities and the generic
//! [`Rule`](crate::rules::registry::Rule) wire model used by the cluster
//! data-plane synchronisation.
//!
//! # Why this module exists
//!
//! The cluster layer replicates a single, generic [`Rule`] registry
//! (`NodeState.rule_registry`) between the Main and its workers. The request
//! path, however, evaluates **typed** rule stores: the custom-rules engine, the
//! IP/URL allow/block sets and the sensitive-pattern matcher. This module is the
//! one place that maps between the two representations, in both directions:
//!
//! * **Encode** (Main / trigger side, used by `waf-api`): a database row that an
//!   administrator just created / deleted is turned into a [`Rule`] so it can be
//!   handed to `NodeState::record_rule_change` for broadcast.
//! * **Decode** (worker / consume side, used by [`WafEngine`](crate::WafEngine)):
//!   the synced [`RuleRegistry`] is rebuilt into a [`SyncedRuleStore`] that the
//!   request path consults **in addition to** the database-backed stores. Because
//!   the synced store is a *separate* set of buckets, a database reload can never
//!   prune the synced rules and vice-versa (the same "bucket isolation" the
//!   IP-feed adapter uses for `feed_block_ips`).
//!
//! The [`Rule`] carries the typed payload as follows:
//!
//! | kind              | `category`            | `pattern` | `metadata`                                  |
//! |-------------------|-----------------------|-----------|---------------------------------------------|
//! | custom rule       | `cluster-custom`      | —         | `payload` = JSON of the DB `CustomRule` row |
//! | block / allow IP  | `cluster-block-ip` …  | CIDR      | `host_code`                                 |
//! | block / allow URL | `cluster-block-url` … | URL       | `host_code`, `match_type`                   |
//! | sensitive         | `cluster-sensitive`   | pattern   | `host_code`, `check_request`                |
//! | Lane 2 config     | `cluster-semantic`    | —         | `payload` = JSON of `ContentSecurityConfig` |
//!
//! # Why the Lane 2 config travels on the *rule* channel
//!
//! The cluster has a second, nominally config-shaped channel
//! (`ClusterMessage::ConfigSync`), but `ConfigSyncer::apply_sync` only records the
//! version number it was handed and drops `config_toml` on the floor — nothing
//! downstream of it reaches the data plane. The rule registry is the only synced
//! state that a worker actually *applies*: it lands in `NodeState.rule_registry`
//! and `RuleReloader::on_rules_updated` rebuilds the request-path store from it.
//!
//! Lane 2's configuration has no database representation at all (there is no
//! `content_security` table; `semantic_observations` stores detections, not
//! settings), so before this existed the only way a node could learn its Lane 2
//! posture was its own local TOML file. A worker whose TOML omits
//! `[content_security]` — which is every node in `docker-compose.cluster.yml` —
//! silently ran the compiled default, `enabled = false`: no semantic detection at
//! all, no matter what the Main was configured to do.

use std::collections::HashMap;

use tracing::warn;
use uuid::Uuid;
use waf_common::content_security_config::ContentSecurityConfig;
use waf_storage::models::{AllowIp, AllowUrl, BlockIp, BlockUrl, CustomRule as DbCustomRule, SensitivePattern};

use crate::checks::{RuntimeContentSecurityConfig, SensitiveCheck};
use crate::rules::engine::{CustomRulesEngine, from_db_rule};
use crate::rules::registry::{Rule, RuleRegistry};
use crate::rules::{IpRuleSet, UrlMatchType, UrlRule, UrlRuleSet};

/// `source` stamped on every cluster-synced [`Rule`].
pub const SOURCE_CLUSTER: &str = "cluster";

/// `category` discriminators for each typed rule kind carried over the wire.
pub const CAT_CUSTOM: &str = "cluster-custom";
pub const CAT_BLOCK_IP: &str = "cluster-block-ip";
pub const CAT_ALLOW_IP: &str = "cluster-allow-ip";
pub const CAT_BLOCK_URL: &str = "cluster-block-url";
pub const CAT_ALLOW_URL: &str = "cluster-allow-url";
pub const CAT_SENSITIVE: &str = "cluster-sensitive";
pub const CAT_SEMANTIC: &str = "cluster-semantic";

/// `action` stamped on the Lane 2 config carrier.
///
/// The other six kinds map onto a real per-request verdict (`allow` / `block` /
/// whatever the custom rule row says). This one decides nothing by itself — it
/// carries the settings that govern how the semantic lane decides — so it gets
/// its own word rather than borrowing one that would misdescribe it.
pub const ACTION_CONFIG: &str = "config";

/// The kind of detection-affecting entity carried by a synced [`Rule`].
///
/// Used by the trigger side (`waf-api`) to build the stable registry id so that
/// a later delete refers to exactly the same entry even though only the row id
/// is known at delete time.
///
/// # Wire compatibility
///
/// This enum is **not** serialised. It exists only to produce the `category`
/// string and the registry id; what crosses the QUIC link is a [`Rule`], whose
/// `category` is a plain `String`. Adding a variant therefore cannot break the
/// frame decode on a peer built before it — an older node deserialises the
/// `Rule` fine and drops it on the catch-all arm of
/// [`SyncedRuleStore::from_registry`], exactly as it already does for any
/// category it does not recognise. See `unknown_categories_are_ignored`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncedKind {
    Custom,
    BlockIp,
    AllowIp,
    BlockUrl,
    AllowUrl,
    Sensitive,
    /// The cluster-wide Lane 2 (semantic content-security) configuration.
    ///
    /// Unlike the other six this is a **singleton**, not a database row: Lane 2
    /// config is one process-wide value, so it is keyed by [`Uuid::nil`] and
    /// there is exactly one such entry in the registry at a time. An upsert
    /// replaces it; see [`semantic_registry_id`].
    Semantic,
}

impl SyncedKind {
    const fn category(self) -> &'static str {
        match self {
            Self::Custom => CAT_CUSTOM,
            Self::BlockIp => CAT_BLOCK_IP,
            Self::AllowIp => CAT_ALLOW_IP,
            Self::BlockUrl => CAT_BLOCK_URL,
            Self::AllowUrl => CAT_ALLOW_URL,
            Self::Sensitive => CAT_SENSITIVE,
            Self::Semantic => CAT_SEMANTIC,
        }
    }
}

/// Build the stable registry id for a synced entity (`<category>:<uuid>`).
///
/// The prefix keeps ids unique across the different database tables (whose
/// UUIDs are only unique per-table) and lets a delete rebuild the exact id from
/// just the row id.
#[must_use]
pub fn registry_id(kind: SyncedKind, id: Uuid) -> String {
    format!("{}:{}", kind.category(), id)
}

// ─── Encode: DB row → generic Rule (trigger side) ───────────────────────────────

/// Encode a custom-rule row into a synced [`Rule`], embedding the full row JSON
/// so the worker can reconstruct the typed `CustomRule` via [`from_db_rule`].
#[must_use]
pub fn custom_rule_to_rule(row: &DbCustomRule) -> Rule {
    let mut metadata = HashMap::new();
    match serde_json::to_string(row) {
        Ok(json) => {
            metadata.insert("payload".to_string(), json);
        }
        Err(e) => warn!("failed to serialize custom rule {} for cluster sync: {e}", row.id),
    }
    metadata.insert("host_code".to_string(), row.host_code.clone());
    Rule {
        id: registry_id(SyncedKind::Custom, row.id),
        name: row.name.clone(),
        description: row.description.clone(),
        category: CAT_CUSTOM.to_string(),
        source: SOURCE_CLUSTER.to_string(),
        enabled: row.enabled,
        action: row.action.clone(),
        severity: None,
        pattern: None,
        tags: Vec::new(),
        metadata,
    }
}

fn ip_rule(kind: SyncedKind, id: Uuid, host_code: &str, cidr: &str) -> Rule {
    let mut metadata = HashMap::new();
    metadata.insert("host_code".to_string(), host_code.to_string());
    Rule {
        id: registry_id(kind, id),
        name: format!("{} {cidr}", kind.category()),
        description: None,
        category: kind.category().to_string(),
        source: SOURCE_CLUSTER.to_string(),
        enabled: true,
        action: if kind == SyncedKind::AllowIp { "allow" } else { "block" }.to_string(),
        severity: None,
        pattern: Some(cidr.to_string()),
        tags: Vec::new(),
        metadata,
    }
}

fn url_rule(kind: SyncedKind, id: Uuid, host_code: &str, pattern: &str, match_type: &str) -> Rule {
    let mut metadata = HashMap::new();
    metadata.insert("host_code".to_string(), host_code.to_string());
    metadata.insert("match_type".to_string(), match_type.to_string());
    Rule {
        id: registry_id(kind, id),
        name: format!("{} {pattern}", kind.category()),
        description: None,
        category: kind.category().to_string(),
        source: SOURCE_CLUSTER.to_string(),
        enabled: true,
        action: if kind == SyncedKind::AllowUrl { "allow" } else { "block" }.to_string(),
        severity: None,
        pattern: Some(pattern.to_string()),
        tags: Vec::new(),
        metadata,
    }
}

/// Encode an IP blocklist row.
#[must_use]
pub fn block_ip_to_rule(row: &BlockIp) -> Rule {
    ip_rule(SyncedKind::BlockIp, row.id, &row.host_code, &row.ip_cidr)
}

/// Encode an IP allowlist row.
#[must_use]
pub fn allow_ip_to_rule(row: &AllowIp) -> Rule {
    ip_rule(SyncedKind::AllowIp, row.id, &row.host_code, &row.ip_cidr)
}

/// Encode a URL blocklist row.
#[must_use]
pub fn block_url_to_rule(row: &BlockUrl) -> Rule {
    url_rule(
        SyncedKind::BlockUrl,
        row.id,
        &row.host_code,
        &row.url_pattern,
        &row.match_type,
    )
}

/// Encode a URL allowlist row.
#[must_use]
pub fn allow_url_to_rule(row: &AllowUrl) -> Rule {
    url_rule(
        SyncedKind::AllowUrl,
        row.id,
        &row.host_code,
        &row.url_pattern,
        &row.match_type,
    )
}

/// Encode a sensitive-pattern row.
#[must_use]
pub fn sensitive_to_rule(row: &SensitivePattern) -> Rule {
    let mut metadata = HashMap::new();
    metadata.insert("host_code".to_string(), row.host_code.clone());
    metadata.insert("check_request".to_string(), row.check_request.to_string());
    Rule {
        id: registry_id(SyncedKind::Sensitive, row.id),
        name: format!("sensitive {}", row.pattern_type),
        description: None,
        category: CAT_SENSITIVE.to_string(),
        source: SOURCE_CLUSTER.to_string(),
        enabled: row.enabled,
        action: row.action.clone(),
        severity: None,
        pattern: Some(row.pattern.clone()),
        tags: Vec::new(),
        metadata,
    }
}

/// The registry id of the cluster-wide Lane 2 config entry.
///
/// A singleton keyed by the nil UUID, so re-publishing overwrites in place and a
/// worker never accumulates stale copies of a config it has already applied.
#[must_use]
pub fn semantic_registry_id() -> String {
    registry_id(SyncedKind::Semantic, Uuid::nil())
}

/// Encode the cluster-wide Lane 2 config into a synced [`Rule`].
///
/// The whole `ContentSecurityConfig` is embedded as JSON rather than being
/// spread over `pattern` / `metadata` fields, for the same reason
/// [`custom_rule_to_rule`] does it: the struct has a dozen fields including two
/// nested maps and two rule-key lists, and any hand-rolled projection of it
/// would be a second schema to keep in step with the first. `#[serde(default)]`
/// on every field of that struct means a node running an older or newer build
/// still decodes what it understands and defaults the rest.
///
/// # Errors
///
/// Returns the `serde_json` error if the config cannot be serialised. This is
/// deliberately not swallowed the way `custom_rule_to_rule` warns-and-continues:
/// a custom rule that loses its payload is one rule missing, but a Lane 2 config
/// carrier with no payload would be published to the whole cluster as an entry
/// every worker then declines to apply — a silent cluster-wide no-op, which is
/// the failure mode this task exists to remove.
pub fn semantic_config_to_rule(cfg: &ContentSecurityConfig) -> Result<Rule, serde_json::Error> {
    let mut metadata = HashMap::new();
    metadata.insert("payload".to_string(), serde_json::to_string(cfg)?);
    Ok(Rule {
        id: semantic_registry_id(),
        name: "cluster semantic config".to_string(),
        description: Some(format!(
            "Lane 2 content-security config (enabled={}, mode={}, rollout_bps={})",
            cfg.enabled, cfg.enforcement_mode, cfg.rollout_bps
        )),
        category: CAT_SEMANTIC.to_string(),
        source: SOURCE_CLUSTER.to_string(),
        // Always `true`: this flags the *carrier* as live, not the lane. Whether
        // Lane 2 runs is `payload.enabled`, and keeping one answer to that
        // question in one place is why it is not mirrored here.
        enabled: true,
        action: ACTION_CONFIG.to_string(),
        severity: None,
        pattern: None,
        tags: Vec::new(),
        metadata,
    })
}

// ─── Decode: synced RuleRegistry → typed request-path store (consume side) ───────

/// Request-path stores rebuilt from the cluster-synced [`RuleRegistry`].
///
/// These are kept **separate** from the database-backed stores in
/// [`WafEngine`](crate::WafEngine) so neither prunes the other. The engine
/// consults them in addition to its DB stores at the matching pipeline phase.
pub struct SyncedRuleStore {
    pub custom_rules: CustomRulesEngine,
    pub allow_ips: IpRuleSet,
    pub block_ips: IpRuleSet,
    pub allow_urls: UrlRuleSet,
    pub block_urls: UrlRuleSet,
    pub sensitive: SensitiveCheck,
    /// The cluster-wide Lane 2 config, already compiled and validated, or `None`
    /// when the registry carries no `cluster-semantic` entry.
    ///
    /// `None` is not "Lane 2 off" — it is "the Main has said nothing about Lane
    /// 2", and the consumer must leave the node's own configured posture alone.
    /// Treating the two as the same would let a Main built before this feature
    /// existed silently disable the semantic lane on every worker that joins it.
    pub semantic: Option<RuntimeContentSecurityConfig>,
}

impl SyncedRuleStore {
    /// Build a fresh, fully-populated store from the synced registry.
    ///
    /// Only rules whose `source` is [`SOURCE_CLUSTER`] are consumed; anything
    /// else is ignored so a mixed registry cannot leak non-cluster entries into
    /// the data plane.
    #[must_use]
    pub fn from_registry(registry: &RuleRegistry) -> Self {
        let custom_rules = CustomRulesEngine::new();
        let allow_ips = IpRuleSet::new();
        let block_ips = IpRuleSet::new();
        let allow_urls = UrlRuleSet::new();
        let block_urls = UrlRuleSet::new();
        let sensitive = SensitiveCheck::new();
        let mut semantic = None;

        // Group the typed payloads per host_code so each store bucket is loaded
        // exactly once (matching the DB reload path's grouping).
        let mut custom_by_host: HashMap<String, Vec<_>> = HashMap::new();
        let mut allow_ip_by_host: HashMap<String, Vec<String>> = HashMap::new();
        let mut block_ip_by_host: HashMap<String, Vec<String>> = HashMap::new();
        let mut allow_url_by_host: HashMap<String, Vec<UrlRule>> = HashMap::new();
        let mut block_url_by_host: HashMap<String, Vec<UrlRule>> = HashMap::new();
        let mut sensitive_by_host: HashMap<String, Vec<String>> = HashMap::new();

        for rule in registry.rules.values() {
            if rule.source != SOURCE_CLUSTER {
                continue;
            }
            let host = rule
                .metadata
                .get("host_code")
                .cloned()
                .unwrap_or_else(|| "*".to_string());
            match rule.category.as_str() {
                CAT_CUSTOM => {
                    let Some(payload) = rule.metadata.get("payload") else {
                        warn!("cluster custom rule {} missing payload metadata", rule.id);
                        continue;
                    };
                    match serde_json::from_str::<DbCustomRule>(payload) {
                        Ok(row) => match from_db_rule(&row) {
                            Ok(custom) => custom_by_host.entry(row.host_code.clone()).or_default().push(custom),
                            Err(e) => warn!("failed to rebuild synced custom rule {}: {e}", rule.id),
                        },
                        Err(e) => warn!("failed to decode synced custom rule {}: {e}", rule.id),
                    }
                }
                CAT_ALLOW_IP => {
                    if let Some(cidr) = &rule.pattern {
                        allow_ip_by_host.entry(host).or_default().push(cidr.clone());
                    }
                }
                CAT_BLOCK_IP => {
                    if let Some(cidr) = &rule.pattern {
                        block_ip_by_host.entry(host).or_default().push(cidr.clone());
                    }
                }
                CAT_ALLOW_URL => {
                    if let Some(url) = &rule.pattern {
                        allow_url_by_host.entry(host).or_default().push(UrlRule {
                            id: rule.id.clone(),
                            pattern: url.clone(),
                            match_type: UrlMatchType::parse_str(
                                rule.metadata.get("match_type").map_or("exact", String::as_str),
                            ),
                        });
                    }
                }
                CAT_BLOCK_URL => {
                    if let Some(url) = &rule.pattern {
                        block_url_by_host.entry(host).or_default().push(UrlRule {
                            id: rule.id.clone(),
                            pattern: url.clone(),
                            match_type: UrlMatchType::parse_str(
                                rule.metadata.get("match_type").map_or("exact", String::as_str),
                            ),
                        });
                    }
                }
                CAT_SENSITIVE => {
                    // Only request-side patterns are evaluated on the request path.
                    let check_request = rule.metadata.get("check_request").is_none_or(|v| v == "true");
                    if rule.enabled
                        && check_request
                        && let Some(pat) = &rule.pattern
                    {
                        sensitive_by_host.entry(host).or_default().push(pat.clone());
                    }
                }
                CAT_SEMANTIC => {
                    let Some(payload) = rule.metadata.get("payload") else {
                        warn!("cluster semantic config {} missing payload metadata", rule.id);
                        continue;
                    };
                    // Two failure modes, both non-fatal by design: a payload this
                    // build cannot parse, and one that parses but does not
                    // validate (an `enforcement_mode` this build has never heard
                    // of, a rule key it does not have, a weight set that does not
                    // sum). Either way `semantic` stays `None` and the node keeps
                    // running the posture it already had. Adopting a config we
                    // could not fully compile is how a mixed-version cluster
                    // would turn a Main-side typo into a silently degraded
                    // detector set on every worker.
                    match serde_json::from_str::<ContentSecurityConfig>(payload) {
                        Ok(cfg) => match RuntimeContentSecurityConfig::compile(&cfg) {
                            Ok(compiled) => semantic = Some(compiled),
                            Err(e) => warn!(
                                "rejecting synced Lane 2 config {}: {e}; keeping the locally configured posture",
                                rule.id
                            ),
                        },
                        Err(e) => warn!("failed to decode synced Lane 2 config {}: {e}", rule.id),
                    }
                }
                _ => {}
            }
        }

        for (host, rules) in custom_by_host {
            custom_rules.load_host(&host, rules);
        }
        for (host, cidrs) in allow_ip_by_host {
            allow_ips.load(&host, &cidrs);
        }
        for (host, cidrs) in block_ip_by_host {
            block_ips.load(&host, &cidrs);
        }
        for (host, rules) in allow_url_by_host {
            allow_urls.load(&host, rules);
        }
        for (host, rules) in block_url_by_host {
            block_urls.load(&host, rules);
        }
        for (host, pats) in sensitive_by_host {
            sensitive.load_host(&host, &pats);
        }

        Self {
            custom_rules,
            allow_ips,
            block_ips,
            allow_urls,
            block_urls,
            sensitive,
            semantic,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::EnforcementMode;
    use bytes::Bytes;
    use chrono::Utc;
    use std::collections::HashMap as StdHashMap;
    use std::sync::Arc;
    use waf_common::{HostConfig, RequestCtx};

    fn ctx(path: &str) -> RequestCtx {
        let host_config = Arc::new(HostConfig {
            code: "h1".into(),
            host: "example.com".into(),
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "t".into(),
            client_ip: "1.2.3.4".parse().expect("ip"),
            client_port: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: path.into(),
            query: String::new(),
            headers: StdHashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
        }
    }

    fn custom_row(id: Uuid, host: &str, path_prefix: &str) -> DbCustomRule {
        DbCustomRule {
            id,
            host_code: host.to_string(),
            name: "block prefix".to_string(),
            description: None,
            priority: 1,
            enabled: true,
            condition_op: "and".to_string(),
            conditions: serde_json::json!([
                {"field": "path", "operator": "starts_with", "value": path_prefix}
            ]),
            action: "block".to_string(),
            action_status: 403,
            action_msg: None,
            script: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn custom_rule_roundtrips_through_registry_and_matches_request_path() {
        let row = custom_row(Uuid::new_v4(), "h1", "/admin");
        let rule = custom_rule_to_rule(&row);
        assert_eq!(rule.category, CAT_CUSTOM);
        assert_eq!(rule.source, SOURCE_CLUSTER);

        let mut registry = RuleRegistry::new();
        registry.insert(rule);

        // The whole point of Hook #2: the synced registry must yield a store the
        // request path hits directly, with no database involved.
        let store = SyncedRuleStore::from_registry(&registry);
        assert_eq!(store.custom_rules.len(), 1, "synced custom rule must be loaded");
        assert!(
            store.custom_rules.check(&ctx("/admin/users")).is_some(),
            "request to the blocked prefix must match the synced custom rule"
        );
        assert!(
            store.custom_rules.check(&ctx("/public")).is_none(),
            "an unrelated request must not match"
        );
    }

    #[test]
    fn deleting_a_rule_from_the_registry_prunes_it_from_the_store() {
        let id = Uuid::new_v4();
        let row = custom_row(id, "h1", "/admin");
        let mut registry = RuleRegistry::new();
        registry.insert(custom_rule_to_rule(&row));

        // Rebuild after the Main removes the entry (delete → registry.remove).
        registry.remove(&registry_id(SyncedKind::Custom, id));
        let store = SyncedRuleStore::from_registry(&registry);
        assert_eq!(store.custom_rules.len(), 0, "a deleted rule must not survive a rebuild");
        assert!(store.custom_rules.check(&ctx("/admin/users")).is_none());
    }

    #[test]
    fn ip_and_url_rows_roundtrip_into_synced_store() {
        let block_ip = BlockIp {
            id: Uuid::new_v4(),
            host_code: "h1".to_string(),
            ip_cidr: "10.0.0.0/8".to_string(),
            remarks: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let url_id = Uuid::new_v4();
        let block_url = BlockUrl {
            id: url_id,
            host_code: "h1".to_string(),
            url_pattern: "/secret".to_string(),
            match_type: "prefix".to_string(),
            remarks: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mut registry = RuleRegistry::new();
        registry.insert(block_ip_to_rule(&block_ip));
        registry.insert(block_url_to_rule(&block_url));

        let store = SyncedRuleStore::from_registry(&registry);
        assert!(store.block_ips.matches("h1", "10.1.2.3".parse().expect("ip")));
        assert_eq!(
            store.block_urls.matches("h1", "/secret/data"),
            Some(registry_id(SyncedKind::BlockUrl, url_id))
        );
    }

    #[test]
    fn semantic_config_roundtrips_through_the_registry() {
        let mut cfg = ContentSecurityConfig::default();
        cfg.enabled = true;
        cfg.enforcement_mode = "enforce".to_string();
        cfg.rollout_bps = 7500;
        cfg.rollout_salt = "s".to_string();
        cfg.rules_disabled = vec!["xss.script_tag".to_string()];

        let mut registry = RuleRegistry::new();
        registry.insert(semantic_config_to_rule(&cfg).expect("encode"));

        let store = SyncedRuleStore::from_registry(&registry);
        let got = store.semantic.expect("synced Lane 2 config must be decoded");
        assert!(got.enabled);
        assert_eq!(got.enforcement_mode, EnforcementMode::Enforce);
        assert_eq!(got.rollout_bps, 7500);
        assert_eq!(got.rollout_salt, "s");
        assert!(
            got.rule_toggles.forced_off().contains(&"xss.script_tag"),
            "a per-rule switch set on the Main must survive the trip"
        );
    }

    #[test]
    fn a_registry_without_a_semantic_entry_yields_none_not_a_disabled_lane() {
        // The distinction that keeps a pre-feature Main from silently switching
        // Lane 2 off on every worker that joins it: saying nothing is not the
        // same as saying "off".
        let mut registry = RuleRegistry::new();
        registry.insert(block_ip_to_rule(&BlockIp {
            id: Uuid::new_v4(),
            host_code: "h1".to_string(),
            ip_cidr: "10.0.0.0/8".to_string(),
            remarks: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }));
        assert!(SyncedRuleStore::from_registry(&registry).semantic.is_none());
    }

    #[test]
    fn republishing_the_semantic_config_replaces_it_in_place() {
        let mut cfg = ContentSecurityConfig::default();
        cfg.enabled = true;
        cfg.rollout_bps = 100;
        let mut registry = RuleRegistry::new();
        registry.insert(semantic_config_to_rule(&cfg).expect("encode"));

        cfg.rollout_bps = 10_000;
        registry.insert(semantic_config_to_rule(&cfg).expect("encode"));

        // Singleton id → one entry, carrying the newer value.
        assert_eq!(
            registry.rules.keys().filter(|k| k.starts_with(CAT_SEMANTIC)).count(),
            1,
            "the Lane 2 config is a singleton; a second publish must overwrite, not accumulate"
        );
        let store = SyncedRuleStore::from_registry(&registry);
        assert_eq!(store.semantic.map(|c| c.rollout_bps), Some(10_000));
    }

    #[test]
    fn an_undecodable_or_invalid_semantic_payload_leaves_the_local_posture_alone() {
        // Garbage payload — what a peer speaking a future dialect might send.
        let mut broken = semantic_config_to_rule(&ContentSecurityConfig::default()).expect("encode");
        broken.metadata.insert("payload".to_string(), "{not json".to_string());
        let mut registry = RuleRegistry::new();
        registry.insert(broken);
        assert!(
            SyncedRuleStore::from_registry(&registry).semantic.is_none(),
            "a payload we cannot parse must not be adopted"
        );

        // Parses, but fails validation (`rollout_bps` is capped at 10000).
        let mut cfg = ContentSecurityConfig::default();
        cfg.rollout_bps = 99_999;
        let mut invalid = semantic_config_to_rule(&cfg).expect("encode");
        invalid.metadata.insert(
            "payload".to_string(),
            serde_json::to_string(&cfg).expect("serialize invalid config"),
        );
        let mut registry = RuleRegistry::new();
        registry.insert(invalid);
        assert!(
            SyncedRuleStore::from_registry(&registry).semantic.is_none(),
            "a payload that does not compile must not be adopted"
        );
    }

    #[test]
    fn unknown_categories_are_ignored() {
        // The backward-compatibility guarantee for adding a `SyncedKind` variant.
        // `SyncedKind` never crosses the wire — a `Rule` does, and its `category`
        // is a plain String — so this is what a node built *before* a new kind
        // existed does when the Main sends one. It must be "nothing", not a
        // decode failure that costs it the rest of the sync frame.
        let mut registry = RuleRegistry::new();
        registry.insert(Rule {
            id: "cluster-from-the-future:1".to_string(),
            name: "n".to_string(),
            description: None,
            category: "cluster-from-the-future".to_string(),
            source: SOURCE_CLUSTER.to_string(),
            enabled: true,
            action: "block".to_string(),
            severity: None,
            pattern: Some("x".to_string()),
            tags: Vec::new(),
            metadata: HashMap::new(),
        });
        // A known-good rule alongside it must still be consumed: an unrecognised
        // entry is skipped, it does not abort the rebuild.
        registry.insert(block_ip_to_rule(&BlockIp {
            id: Uuid::new_v4(),
            host_code: "h1".to_string(),
            ip_cidr: "10.0.0.0/8".to_string(),
            remarks: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }));

        let store = SyncedRuleStore::from_registry(&registry);
        assert!(store.semantic.is_none());
        assert!(
            store.block_ips.matches("h1", "10.1.2.3".parse().expect("ip")),
            "an unknown category must not cost us the rules we do understand"
        );
    }

    #[test]
    fn a_semantic_rule_survives_json_serialisation_the_way_the_wire_sends_it() {
        // The transport is length-prefixed JSON (`transport/frame.rs`) carrying a
        // `ClusterMessage` whose `RuleChange.rule_json` is `serde_json::to_value`
        // of this very `Rule`. If the carrier did not survive that round trip the
        // registry test above would still pass and the cluster would still not
        // work, so exercise the same encoding the wire uses.
        let mut cfg = ContentSecurityConfig::default();
        cfg.enabled = true;
        cfg.enforcement_mode = "enforce".to_string();
        cfg.rollout_bps = 10_000;

        let rule = semantic_config_to_rule(&cfg).expect("encode");
        let wire = serde_json::to_value(&rule).expect("to_value");
        let back: Rule = serde_json::from_value(wire).expect("from_value");

        let mut registry = RuleRegistry::new();
        registry.insert(back);
        let got = SyncedRuleStore::from_registry(&registry)
            .semantic
            .expect("config must survive the wire encoding");
        assert!(got.enabled);
        assert_eq!(got.enforcement_mode, EnforcementMode::Enforce);
        assert_eq!(got.rollout_bps, 10_000);
    }

    #[test]
    fn non_cluster_rules_are_ignored() {
        let mut registry = RuleRegistry::new();
        registry.insert(Rule {
            id: "owasp-1".to_string(),
            name: "n".to_string(),
            description: None,
            category: "sqli".to_string(),
            source: "owasp".to_string(),
            enabled: true,
            action: "block".to_string(),
            severity: None,
            pattern: Some("x".to_string()),
            tags: Vec::new(),
            metadata: HashMap::new(),
        });
        let store = SyncedRuleStore::from_registry(&registry);
        assert_eq!(store.block_ips.len(), 0);
        assert_eq!(store.custom_rules.len(), 0);
    }
}
