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

use std::collections::HashMap;

use tracing::warn;
use uuid::Uuid;
use waf_storage::models::{AllowIp, AllowUrl, BlockIp, BlockUrl, CustomRule as DbCustomRule, SensitivePattern};

use crate::checks::SensitiveCheck;
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

/// The kind of detection-affecting entity carried by a synced [`Rule`].
///
/// Used by the trigger side (`waf-api`) to build the stable registry id so that
/// a later delete refers to exactly the same entry even though only the row id
/// is known at delete time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncedKind {
    Custom,
    BlockIp,
    AllowIp,
    BlockUrl,
    AllowUrl,
    Sensitive,
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
