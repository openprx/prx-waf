use std::net::SocketAddr;

use anyhow::Result;
use waf_common::config::ClusterConfig;

/// Static seed-based peer discovery.
///
/// Reads the `seeds` list from `ClusterConfig` and resolves each entry to a
/// `SocketAddr`. mDNS auto-discovery is deferred to a future release.
pub struct StaticSeeds {
    seeds: Vec<SocketAddr>,
}

impl StaticSeeds {
    /// Build the seed list from configuration, returning an error if any
    /// address cannot be parsed.
    pub fn from_config(config: &ClusterConfig) -> Result<Self> {
        let seeds = config
            .seeds
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .map_err(|e| anyhow::anyhow!("invalid seed address {s:?}: {e}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { seeds })
    }

    /// Return the resolved peer addresses.
    pub fn peers(&self) -> &[SocketAddr] {
        &self.seeds
    }
}
