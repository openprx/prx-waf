//! Rule source definitions — local files, remote URLs, built-in sets.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::formats::RuleFormat;

/// A configured source from which rules are loaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleSource {
    /// A single local file
    LocalFile {
        name: String,
        path: PathBuf,
        format: RuleFormat,
    },
    /// A local directory (all matching files are loaded)
    LocalDir {
        name: String,
        path: PathBuf,
        /// Glob pattern to match files, e.g. "*.yaml"
        glob: String,
    },
    /// A remote URL (fetched via HTTP and cached locally)
    RemoteUrl {
        name: String,
        url: String,
        format: RuleFormat,
        /// How often to refresh the remote source
        update_interval_secs: u64,
    },
    /// A built-in source compiled into the binary
    Builtin { name: String },
}

impl RuleSource {
    pub fn name(&self) -> &str {
        match self {
            Self::LocalFile { name, .. } => name,
            Self::LocalDir { name, .. } => name,
            Self::RemoteUrl { name, .. } => name,
            Self::Builtin { name } => name,
        }
    }

    pub fn source_type(&self) -> &'static str {
        match self {
            Self::LocalFile { .. } => "local_file",
            Self::LocalDir { .. } => "local_dir",
            Self::RemoteUrl { .. } => "remote_url",
            Self::Builtin { .. } => "builtin",
        }
    }

    pub fn update_interval(&self) -> Option<Duration> {
        match self {
            Self::RemoteUrl {
                update_interval_secs,
                ..
            } => Some(Duration::from_secs(*update_interval_secs)),
            _ => None,
        }
    }
}

/// Load report after `RuleManager::load_all()`.
#[derive(Debug, Default, Clone)]
pub struct RuleLoadReport {
    pub sources_loaded: usize,
    pub rules_loaded: usize,
    pub rules_skipped: usize,
    pub errors: Vec<String>,
}

impl RuleLoadReport {
    pub fn merge(&mut self, other: RuleLoadReport) {
        self.sources_loaded += other.sources_loaded;
        self.rules_loaded += other.rules_loaded;
        self.rules_skipped += other.rules_skipped;
        self.errors.extend(other.errors);
    }
}

impl std::fmt::Display for RuleLoadReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Loaded {} rules from {} sources ({} skipped, {} errors)",
            self.rules_loaded,
            self.sources_loaded,
            self.rules_skipped,
            self.errors.len()
        )
    }
}

/// Reload report after `RuleManager::reload()`.
#[derive(Debug, Clone)]
pub struct RuleReloadReport {
    pub added: usize,
    pub removed: usize,
    pub unchanged: usize,
    pub errors: Vec<String>,
}

impl std::fmt::Display for RuleReloadReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Reload complete: +{} -{} ={} ({} errors)",
            self.added,
            self.removed,
            self.unchanged,
            self.errors.len()
        )
    }
}
