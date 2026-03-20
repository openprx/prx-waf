//! Hot-reload — watches the rules directory for file changes and triggers reloads.
//!
//! Uses the `notify` crate for file-system events and optionally handles SIGHUP.
//! Debounces rapid successive changes by waiting `debounce_ms` after the last event.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use anyhow::Result;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{info, warn};

use super::manager::RuleManager;

/// A running file-system watcher that triggers rule reloads.
///
/// Drop this value to stop watching.
pub struct HotReloader {
    /// The underlying notify watcher (kept alive for the watcher's lifetime)
    _watcher: RecommendedWatcher,
}

impl HotReloader {
    /// Start watching `rules_dir` and trigger reloads on any change.
    ///
    /// `manager` is shared (Arc<Mutex>) so the watcher thread can call `reload()`.
    /// `debounce_ms` controls how long to wait after the last event before reloading.
    pub fn start(
        manager: Arc<Mutex<RuleManager>>,
        rules_dir: PathBuf,
        debounce_ms: u64,
    ) -> Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

        let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

        // Create the directory if it doesn't exist yet
        if !rules_dir.exists()
            && let Err(e) = std::fs::create_dir_all(&rules_dir)
        {
            warn!(path = %rules_dir.display(), "Failed to create rules directory: {e}");
        }

        watcher.watch(&rules_dir, RecursiveMode::Recursive)?;
        info!(path = %rules_dir.display(), "Hot-reload watching rules directory");

        // Spawn a background thread to receive events and trigger reloads
        std::thread::spawn(move || {
            let debounce = Duration::from_millis(debounce_ms);
            let mut last_event = std::time::Instant::now();
            let mut pending = false;

            loop {
                match rx.recv_timeout(debounce) {
                    Ok(Ok(event)) => {
                        // Filter: only react to Create, Modify, Remove
                        use notify::EventKind::*;
                        let relevant = matches!(event.kind, Create(_) | Modify(_) | Remove(_));
                        if relevant {
                            last_event = std::time::Instant::now();
                            pending = true;
                        }
                    }
                    Ok(Err(e)) => warn!("hot-reload watch error: {e}"),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // Check if enough time has passed since the last event
                        if pending && last_event.elapsed() >= debounce {
                            pending = false;
                            trigger_reload(&manager);
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        info!("Hot-reload watcher channel closed, stopping");
                        break;
                    }
                }
            }
        });

        Ok(Self { _watcher: watcher })
    }
}

fn trigger_reload(manager: &Arc<Mutex<RuleManager>>) {
    let mut mgr = manager.lock();
    match mgr.reload() {
        Ok(report) => info!("Hot-reload: {report}"),
        Err(e) => warn!("Hot-reload failed: {e}"),
    }
}

/// Register a SIGHUP handler that triggers a rule reload (Unix only).
///
/// Returns immediately. The handler runs in a background tokio task.
#[cfg(unix)]
pub fn register_sighup_handler(manager: Arc<Mutex<RuleManager>>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut stream = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to register SIGHUP handler: {e}");
                return;
            }
        };
        loop {
            stream.recv().await;
            info!("SIGHUP received — reloading rules");
            let mgr = Arc::clone(&manager);
            if let Err(e) = tokio::task::spawn_blocking(move || {
                trigger_reload(&mgr);
            })
            .await
            {
                warn!("SIGHUP reload task panicked: {e}");
            }
        }
    });
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
pub fn register_sighup_handler(_manager: Arc<Mutex<RuleManager>>) {}
