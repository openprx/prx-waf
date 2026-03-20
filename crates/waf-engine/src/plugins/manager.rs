//! WASM Plugin Manager
//!
//! Loads and executes sandboxed WebAssembly plugins that can inspect and
//! modify WAF decisions.  Each plugin is compiled once into a `wasmtime::Module`
//! and then instantiated per-request inside a fuel-limited `Store`.
//!
//! Plugin contract (WAT/WASM exports):
//!   - `get_action() -> i32`   — 0 = Allow, 1 = Block, 2 = Log
//!   - `get_name_len() -> i32` — byte length of plugin name
//!   - `get_name_ptr() -> i32` — pointer to plugin name in WASM memory
//!   - `get_version_ptr() -> i32`, `get_version_len() -> i32`
//!
//! The host imports `set_request_info(method_ptr, method_len, path_ptr, path_len,
//!                                    ip_ptr, ip_len)` so that plugins can read
//! request context written into their linear memory.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use wasmtime::{Config, Engine, Linker, Module, Store};

/// Maximum WASM linear memory (64 MiB)
const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// Fuel granted per-invocation (≈ 10 million instructions)
const FUEL_PER_CALL: u64 = 10_000_000;

// ─── Plugin action ────────────────────────────────────────────────────────────

/// Decision returned by a WASM plugin
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginAction {
    Allow = 0,
    Block = 1,
    Log = 2,
}

impl TryFrom<i32> for PluginAction {
    type Error = ();
    fn try_from(v: i32) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(PluginAction::Allow),
            1 => Ok(PluginAction::Block),
            2 => Ok(PluginAction::Log),
            _ => Err(()),
        }
    }
}

// ─── Plugin info ──────────────────────────────────────────────────────────────

/// Metadata describing a loaded plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
}

// ─── Single loaded plugin ─────────────────────────────────────────────────────

/// A compiled and ready-to-execute WASM plugin
pub struct WasmPlugin {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
    engine: Engine,
    module: Module,
}

impl WasmPlugin {
    /// Compile a WASM binary into a loadable plugin.
    pub fn new(
        id: Uuid,
        name: String,
        version: String,
        description: String,
        author: String,
        enabled: bool,
        wasm_bytes: &[u8],
    ) -> anyhow::Result<Self> {
        let mut cfg = Config::new();
        cfg.consume_fuel(true);
        // Limit stack depth to 512 KiB
        cfg.max_wasm_stack(512 * 1024);
        let engine = Engine::new(&cfg)?;
        let module = Module::new(&engine, wasm_bytes)?;

        Ok(Self {
            id,
            name,
            version,
            description,
            author,
            enabled,
            engine,
            module,
        })
    }

    /// Execute `on_request` with method / path / client IP context.
    ///
    /// Returns `PluginAction::Allow` on any execution error so that a buggy
    /// plugin cannot accidentally deny legitimate traffic.
    pub fn on_request(&self, method: &str, path: &str, client_ip: &str) -> PluginAction {
        if !self.enabled {
            return PluginAction::Allow;
        }

        match self.run_request(method, path, client_ip) {
            Ok(action) => action,
            Err(e) => {
                warn!(plugin = %self.name, "on_request error: {e}");
                PluginAction::Allow
            }
        }
    }

    fn run_request(
        &self,
        method: &str,
        path: &str,
        client_ip: &str,
    ) -> anyhow::Result<PluginAction> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(FUEL_PER_CALL)?;

        let linker = Linker::new(&self.engine);
        let instance = linker.instantiate(&mut store, &self.module)?;

        // Try to write context into plugin memory (best-effort)
        if let Some(mem) = instance.get_memory(&mut store, "memory") {
            let combined = format!("{}\0{}\0{}\0", method, path, client_ip);
            let bytes = combined.as_bytes();
            if bytes.len() < MAX_MEMORY_BYTES as usize {
                let _ = mem.write(&mut store, 0, bytes);
            }
        }

        // Call on_request() -> i32
        let action_code =
            if let Ok(func) = instance.get_typed_func::<(), i32>(&mut store, "on_request") {
                func.call(&mut store, ())?
            } else if let Ok(func) = instance.get_typed_func::<(), i32>(&mut store, "get_action") {
                func.call(&mut store, ())?
            } else {
                0 // default Allow
            };

        Ok(PluginAction::try_from(action_code).unwrap_or(PluginAction::Allow))
    }

    /// Read a plugin name/version string from WASM memory exports.
    pub fn read_string_export(&self, ptr_export: &str, len_export: &str) -> Option<String> {
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(1_000_000).ok()?;
        let linker = Linker::new(&self.engine);
        let instance = linker.instantiate(&mut store, &self.module).ok()?;
        let mem = instance.get_memory(&mut store, "memory")?;

        let ptr = instance
            .get_typed_func::<(), i32>(&mut store, ptr_export)
            .ok()?
            .call(&mut store, ())
            .ok()? as usize;
        let len = instance
            .get_typed_func::<(), i32>(&mut store, len_export)
            .ok()?
            .call(&mut store, ())
            .ok()? as usize;

        let data = mem.data(&store);
        if ptr + len <= data.len() {
            std::str::from_utf8(&data[ptr..ptr + len])
                .ok()
                .map(|s| s.to_owned())
        } else {
            None
        }
    }

    pub fn info(&self) -> PluginInfo {
        PluginInfo {
            id: self.id,
            name: self.name.clone(),
            version: self.version.clone(),
            description: self.description.clone(),
            author: self.author.clone(),
            enabled: self.enabled,
        }
    }
}

// ─── Plugin manager ───────────────────────────────────────────────────────────

/// Parameters for loading a WASM plugin.
pub struct LoadPluginParams<'a> {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
    pub wasm_bytes: &'a [u8],
}

/// Thread-safe registry of loaded WASM plugins.
pub struct PluginManager {
    plugins: RwLock<HashMap<Uuid, Arc<WasmPlugin>>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
        }
    }

    /// Load (or reload) a plugin from its binary bytes.
    pub async fn load(&self, params: LoadPluginParams<'_>) -> anyhow::Result<()> {
        let plugin = WasmPlugin::new(
            params.id,
            params.name.clone(),
            params.version,
            params.description,
            params.author,
            params.enabled,
            params.wasm_bytes,
        )?;
        let mut map = self.plugins.write().await;
        map.insert(params.id, Arc::new(plugin));
        info!(plugin = %params.name, "WASM plugin loaded");
        Ok(())
    }

    /// Remove a plugin by ID.
    pub async fn unload(&self, id: Uuid) -> bool {
        let mut map = self.plugins.write().await;
        let removed = map.remove(&id).is_some();
        if removed {
            debug!(plugin_id = %id, "WASM plugin unloaded");
        }
        removed
    }

    /// Enable or disable a plugin without unloading it.
    pub async fn set_enabled(&self, id: Uuid, enabled: bool) -> bool {
        let map = self.plugins.read().await;
        if let Some(plugin) = map.get(&id) {
            // WasmPlugin.enabled is set on load; we rebuild the entry
            let p = plugin.clone();
            drop(map);
            let mut wmap = self.plugins.write().await;
            if let Some(existing) = wmap.remove(&id) {
                let updated = WasmPlugin {
                    enabled,
                    id: existing.id,
                    name: existing.name.clone(),
                    version: existing.version.clone(),
                    description: existing.description.clone(),
                    author: existing.author.clone(),
                    engine: existing.engine.clone(),
                    module: existing.module.clone(),
                };
                wmap.insert(id, Arc::new(updated));
                return true;
            }
            drop(p);
        }
        false
    }

    /// Run all enabled plugins' `on_request` and return the strictest decision.
    pub async fn run_request(&self, method: &str, path: &str, client_ip: &str) -> PluginAction {
        let map = self.plugins.read().await;
        let mut decision = PluginAction::Allow;
        for plugin in map.values() {
            let action = plugin.on_request(method, path, client_ip);
            if action == PluginAction::Block {
                error!(plugin = %plugin.name, %path, "Plugin blocked request");
                return PluginAction::Block;
            }
            if action == PluginAction::Log && decision == PluginAction::Allow {
                decision = PluginAction::Log;
            }
        }
        decision
    }

    pub async fn list(&self) -> Vec<PluginInfo> {
        self.plugins
            .read()
            .await
            .values()
            .map(|p| p.info())
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<Arc<WasmPlugin>> {
        self.plugins.read().await.get(&id).cloned()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}
