pub mod appsec;
pub mod cache;
pub mod checker;
pub mod client;
pub mod config;
pub mod models;
pub mod pusher;
pub mod sync;

pub use appsec::{appsec_to_detection, AppSecClient, AppSecResult};
pub use cache::DecisionCache;
pub use checker::CrowdSecChecker;
pub use client::CrowdSecClient;
pub use config::{AppSecConfig, CrowdSecConfig, CrowdSecMode, FallbackAction, PusherConfig};
pub use models::{CacheStats, CachedDecision, Decision, DecisionStream};
pub use pusher::CrowdSecPusher;

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

/// All runtime components of the CrowdSec integration.
pub struct CrowdSecComponents {
    /// Shared decision cache (also exposed via API)
    pub cache: Arc<DecisionCache>,
    /// Bouncer checker — plugged into the WAF pipeline
    pub checker: Arc<CrowdSecChecker>,
    /// Optional AppSec client for async per-request checks
    pub appsec_client: Option<Arc<AppSecClient>>,
    /// Optional log pusher
    pub pusher: Option<Arc<CrowdSecPusher>>,
    /// LAPI client (shared with API handlers for delete/test)
    pub lapi_client: Arc<CrowdSecClient>,
    /// Background sync task handle
    pub _sync_handle: tokio::task::JoinHandle<()>,
}

/// Initialise the CrowdSec integration from config.
///
/// Returns `None` when `config.enabled == false`.
pub async fn init_crowdsec(
    config: CrowdSecConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<CrowdSecComponents> {
    if !config.enabled {
        return None;
    }

    info!(
        mode = ?config.mode,
        lapi_url = %config.lapi_url,
        "Initialising CrowdSec integration",
    );

    // Build LAPI client
    let lapi_client = match CrowdSecClient::new(config.lapi_url.clone(), config.api_key.clone()) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            warn!("Failed to create CrowdSec LAPI client: {}", e);
            return None;
        }
    };

    // Decision cache
    let cache = Arc::new(DecisionCache::new(config.cache_ttl_secs));

    // Bouncer checker
    let checker = Arc::new(CrowdSecChecker::new(Arc::clone(&cache), config.clone()));

    // AppSec client (only when mode includes appsec)
    let appsec_client = if matches!(config.mode, CrowdSecMode::Appsec | CrowdSecMode::Both) {
        config.appsec.as_ref().and_then(|appsec_cfg| {
            match AppSecClient::new(appsec_cfg.clone()) {
                Ok(c) => Some(Arc::new(c)),
                Err(e) => {
                    warn!("Failed to create AppSec client: {}", e);
                    None
                }
            }
        })
    } else {
        None
    };

    // Log pusher
    let pusher = config.pusher.as_ref().map(|pusher_cfg| {
        let p = Arc::new(CrowdSecPusher::new(
            Arc::clone(&lapi_client),
            pusher_cfg.clone(),
        ));
        // Start flush background task
        let p2 = Arc::clone(&p);
        let rx2 = shutdown_rx.clone();
        tokio::spawn(async move { p2.run_flush_task(rx2).await });
        p
    });

    // Start decision sync task
    let client_sync = Arc::clone(&lapi_client);
    let cache_sync = Arc::clone(&cache);
    let config_sync = config.clone();
    let sync_handle = tokio::spawn(async move {
        sync::run_decision_sync(client_sync, cache_sync, config_sync, shutdown_rx).await;
    });

    Some(CrowdSecComponents {
        cache,
        checker,
        appsec_client,
        pusher,
        lapi_client,
        _sync_handle: sync_handle,
    })
}
