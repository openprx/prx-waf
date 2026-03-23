use anyhow::Result;
use tracing::debug;

use crate::protocol::ConfigSync;

/// Tracks and applies configuration synchronisation for this node.
pub struct ConfigSyncer {
    node_id: String,
    current_version: u64,
}

impl ConfigSyncer {
    pub const fn new(node_id: String) -> Self {
        Self {
            node_id,
            current_version: 0,
        }
    }

    pub const fn current_version(&self) -> u64 {
        self.current_version
    }

    /// Apply an incoming `ConfigSync` from main, updating the stored version.
    pub fn apply_sync(&mut self, sync: &ConfigSync) -> Result<()> {
        debug!(
            node_id = %self.node_id,
            version = sync.version,
            "Applying config sync"
        );
        self.current_version = sync.version;
        Ok(())
    }

    /// Build a `ConfigSync` message for the given TOML string (called by main).
    pub const fn build_sync(&self, config_toml: String) -> ConfigSync {
        ConfigSync {
            version: self.current_version + 1,
            config_toml,
        }
    }
}
