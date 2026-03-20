//! RuleManager — loads, reloads, validates, enables/disables rules.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

use waf_common::config::RulesConfig;

use super::builtin::all_builtin_rules;
use super::formats::{
    ExportFormat, RuleFormat, ValidationError, export_rules, parse_rules, validate_rules,
};
use super::registry::{Rule, RuleRegistry, RuleStats};
use super::sources::{RuleLoadReport, RuleReloadReport, RuleSource};

/// Central rule management component.
///
/// Owns the `RuleRegistry` and knows how to load/reload rules from files,
/// built-ins, and remote sources.
pub struct RuleManager {
    pub registry: Arc<RwLock<RuleRegistry>>,
    pub sources: Vec<RuleSource>,
    pub rules_dir: PathBuf,
    enable_builtin_owasp: bool,
    enable_builtin_bot: bool,
    enable_builtin_scanner: bool,
}

impl RuleManager {
    /// Create a new `RuleManager` from configuration.
    pub fn new(config: &RulesConfig) -> Self {
        let mut sources: Vec<RuleSource> = Vec::new();

        // Convert configured sources into RuleSource variants
        for entry in &config.sources {
            if let Some(url) = &entry.url {
                let format = match entry.format.as_str() {
                    "modsec" => RuleFormat::ModSec,
                    "json" => RuleFormat::Json,
                    _ => RuleFormat::Yaml,
                };
                sources.push(RuleSource::RemoteUrl {
                    name: entry.name.clone(),
                    url: url.clone(),
                    format,
                    update_interval_secs: entry.update_interval,
                });
            } else if let Some(path) = &entry.path {
                let pb = PathBuf::from(path);
                if pb.is_file() {
                    let format = match entry.format.as_str() {
                        "modsec" => RuleFormat::ModSec,
                        "json" => RuleFormat::Json,
                        _ => RuleFormat::Yaml,
                    };
                    sources.push(RuleSource::LocalFile {
                        name: entry.name.clone(),
                        path: pb,
                        format,
                    });
                } else {
                    sources.push(RuleSource::LocalDir {
                        name: entry.name.clone(),
                        path: pb,
                        glob: "*.yaml".to_string(),
                    });
                }
            }
        }

        // Add builtin sources
        if config.enable_builtin_owasp {
            sources.push(RuleSource::Builtin {
                name: "builtin-owasp".to_string(),
            });
        }
        if config.enable_builtin_bot {
            sources.push(RuleSource::Builtin {
                name: "builtin-bot".to_string(),
            });
        }
        if config.enable_builtin_scanner {
            sources.push(RuleSource::Builtin {
                name: "builtin-scanner".to_string(),
            });
        }

        Self {
            registry: Arc::new(RwLock::new(RuleRegistry::new())),
            sources,
            rules_dir: PathBuf::from(&config.dir),
            enable_builtin_owasp: config.enable_builtin_owasp,
            enable_builtin_bot: config.enable_builtin_bot,
            enable_builtin_scanner: config.enable_builtin_scanner,
        }
    }

    /// Load all rules from all configured sources.
    pub fn load_all(&mut self) -> Result<RuleLoadReport> {
        let mut report = RuleLoadReport::default();

        // Load built-in rules
        let builtin = all_builtin_rules(
            self.enable_builtin_owasp,
            self.enable_builtin_bot,
            self.enable_builtin_scanner,
        );
        let builtin_count = builtin.len();

        {
            let mut reg = self.registry.write();
            reg.clear();
            for rule in builtin {
                reg.insert(rule);
            }
            report.rules_loaded += builtin_count;
            report.sources_loaded += 1;
        }

        // Load from rules directory
        if self.rules_dir.is_dir() {
            match self.load_from_dir(&self.rules_dir.clone()) {
                Ok(sub) => report.merge(sub),
                Err(e) => report.errors.push(format!("rules dir: {e}")),
            }
        }

        // Load from configured sources
        let sources = self.sources.clone();
        for source in &sources {
            match source {
                RuleSource::LocalFile { path, format, name } => match load_file(path, *format) {
                    Ok(rules) => {
                        let count = rules.len();
                        let mut reg = self.registry.write();
                        for rule in rules {
                            reg.insert(rule);
                        }
                        info!(source = %name, rules = count, "Loaded rules from file");
                        report.rules_loaded += count;
                        report.sources_loaded += 1;
                    }
                    Err(e) => report.errors.push(format!("{name}: {e}")),
                },
                RuleSource::LocalDir { path, name, .. } => match self.load_from_dir(path) {
                    Ok(sub) => {
                        info!(source = %name, rules = sub.rules_loaded, "Loaded rules from dir");
                        report.merge(sub);
                    }
                    Err(e) => report.errors.push(format!("{name}: {e}")),
                },
                RuleSource::Builtin { .. } => {
                    // Already handled above
                }
                RuleSource::RemoteUrl { name, .. } => {
                    // Remote URLs need async fetch; skip here
                    warn!(source = %name, "Remote source skipped in sync load_all");
                }
            }
        }

        {
            let mut reg = self.registry.write();
            reg.mark_loaded();
        }

        info!(
            rules_loaded = report.rules_loaded,
            sources = report.sources_loaded,
            "Rule manager load complete"
        );

        Ok(report)
    }

    /// Reload all rules (clear + load_all). Returns a diff report.
    pub fn reload(&mut self) -> Result<RuleReloadReport> {
        let before = {
            let reg = self.registry.read();
            reg.rules
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>()
        };

        let load_report = self.load_all()?;

        let after = {
            let reg = self.registry.read();
            reg.rules
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>()
        };

        let added = after.difference(&before).count();
        let removed = before.difference(&after).count();
        let unchanged = after.intersection(&before).count();

        Ok(RuleReloadReport {
            added,
            removed,
            unchanged,
            errors: load_report.errors,
        })
    }

    /// Validate a rule file and return any errors (empty = valid).
    pub fn validate_file(&self, path: &Path) -> Result<Vec<ValidationError>> {
        let format = RuleFormat::from_path(path)
            .ok_or_else(|| anyhow::anyhow!("Unknown rule format for: {}", path.display()))?;
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        Ok(validate_rules(&content, format))
    }

    /// Import rules from a local file.
    pub fn import_from_file(&mut self, path: &Path) -> Result<usize> {
        let format = RuleFormat::from_path(path)
            .ok_or_else(|| anyhow::anyhow!("Unknown rule format for: {}", path.display()))?;
        let rules = load_file(path, format)?;
        let count = rules.len();
        let mut reg = self.registry.write();
        for rule in rules {
            reg.insert(rule);
        }
        Ok(count)
    }

    /// Import rules from a remote URL (async; requires a tokio runtime).
    pub async fn import_from_url(&mut self, url: &str) -> Result<usize> {
        let response = reqwest::get(url)
            .await
            .with_context(|| format!("Failed to fetch {url}"))?;
        let content = response.text().await?;

        // Try YAML first, then JSON
        let rules = super::formats::yaml::parse(&content)
            .or_else(|_| super::formats::json::parse(&content))
            .with_context(|| format!("Failed to parse rules from {url}"))?;

        let count = rules.len();
        let mut reg = self.registry.write();
        for rule in rules {
            reg.insert(rule);
        }
        info!(url, rules = count, "Imported rules from URL");
        Ok(count)
    }

    /// Export all enabled rules in the given format.
    pub fn export(&self, format: ExportFormat) -> Result<String> {
        let reg = self.registry.read();
        let rules: Vec<Rule> = reg.list().into_iter().cloned().collect();
        export_rules(&rules, format)
    }

    /// Search rules by name, id, or description.
    pub fn search(&self, query: &str) -> Vec<Rule> {
        let reg = self.registry.read();
        reg.search(query).into_iter().cloned().collect()
    }

    /// Enable a rule by id.
    pub fn enable_rule(&mut self, id: &str) -> Result<()> {
        let mut reg = self.registry.write();
        match reg.get_mut(id) {
            Some(rule) => {
                rule.enabled = true;
                Ok(())
            }
            None => bail!("Rule not found: {id}"),
        }
    }

    /// Disable a rule by id.
    pub fn disable_rule(&mut self, id: &str) -> Result<()> {
        let mut reg = self.registry.write();
        match reg.get_mut(id) {
            Some(rule) => {
                rule.enabled = false;
                Ok(())
            }
            None => bail!("Rule not found: {id}"),
        }
    }

    /// Return registry statistics.
    pub fn stats(&self) -> RuleStats {
        let reg = self.registry.read();
        reg.stats()
    }

    /// Get a shared handle to the registry (for the WAF engine pipeline).
    pub fn registry_handle(&self) -> Arc<RwLock<RuleRegistry>> {
        Arc::clone(&self.registry)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn load_from_dir(&self, dir: &Path) -> Result<RuleLoadReport> {
        let mut report = RuleLoadReport::default();
        if !dir.is_dir() {
            return Ok(report);
        }

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("Cannot read rules dir: {}", dir.display()))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(format) = RuleFormat::from_path(&path) else {
                continue; // skip unknown extensions
            };
            match load_file(&path, format) {
                Ok(rules) => {
                    let count = rules.len();
                    let mut reg = self.registry.write();
                    for rule in rules {
                        reg.insert(rule);
                    }
                    report.rules_loaded += count;
                    report.sources_loaded += 1;
                }
                Err(e) => {
                    warn!(path = %path.display(), "Failed to load rule file: {e}");
                    report.errors.push(format!("{}: {e}", path.display()));
                }
            }
        }

        Ok(report)
    }
}

/// Read and parse a single rule file.
fn load_file(path: &Path, format: RuleFormat) -> Result<Vec<Rule>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Cannot read {}", path.display()))?;
    parse_rules(&content, format).with_context(|| format!("Failed to parse {}", path.display()))
}
