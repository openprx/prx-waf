use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;
use waf_common::HostConfig;

/// Routes incoming requests to the correct upstream based on Host header
pub struct HostRouter {
    /// key: "host:port" or just "host" (for default port)
    routes: DashMap<String, Arc<HostConfig>>,
}

impl Default for HostRouter {
    fn default() -> Self {
        Self {
            routes: DashMap::new(),
        }
    }
}

impl HostRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a host configuration
    pub fn register(&self, config: Arc<HostConfig>) {
        // Register by "host:port"
        let key = format!("{}:{}", config.host, config.port);
        self.routes.insert(key, Arc::clone(&config));

        // Also register by bare hostname for default ports (80/443)
        if config.port == 80 || config.port == 443 {
            self.routes.insert(config.host.clone(), Arc::clone(&config));
        }
    }

    /// Remove a host configuration
    pub fn unregister(&self, host: &str, port: u16) {
        let key = format!("{}:{}", host, port);
        self.routes.remove(&key);
        if port == 80 || port == 443 {
            self.routes.remove(host);
        }
    }

    /// Resolve a request to a host config using the Host header value
    pub fn resolve(&self, host_header: &str) -> Option<Arc<HostConfig>> {
        // Try exact match first
        if let Some(entry) = self.routes.get(host_header) {
            let cfg: Arc<HostConfig> = Arc::clone(&*entry);
            return Some(cfg);
        }

        // Try stripping default port if present
        if let Some(bare_host) = host_header.split(':').next()
            && let Some(entry) = self.routes.get(bare_host)
        {
            let cfg: Arc<HostConfig> = Arc::clone(&*entry);
            return Some(cfg);
        }

        None
    }

    /// List all registered host configs (deduplicated by code)
    pub fn list(&self) -> Vec<Arc<HostConfig>> {
        let mut seen: HashSet<String> = HashSet::new();
        let mut result: Vec<Arc<HostConfig>> = Vec::new();

        for entry in self.routes.iter() {
            let config: &Arc<HostConfig> = entry.value();
            let code = config.code.clone();
            if seen.insert(code) {
                result.push(Arc::clone(config));
            }
        }

        result
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}
