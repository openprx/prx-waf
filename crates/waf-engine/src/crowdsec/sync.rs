use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use super::cache::DecisionCache;
use super::client::CrowdSecClient;
use super::config::CrowdSecConfig;

/// Background task that keeps the decision cache in sync with LAPI.
///
/// 1. On startup: full pull of all active decisions.
/// 2. Every `update_frequency_secs`: incremental pull of new/deleted decisions.
/// 3. Every 5 minutes: clean up expired cache entries.
/// 4. Shuts down cleanly when `shutdown_rx` receives `true`.
pub async fn run_decision_sync(
    client: Arc<CrowdSecClient>,
    cache: Arc<DecisionCache>,
    config: CrowdSecConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!(
        lapi_url = %config.lapi_url,
        update_secs = config.update_frequency_secs,
        "CrowdSec sync task started",
    );

    // Full startup pull
    match client.get_decisions_stream(true).await {
        Ok(stream) => {
            let n_new = stream.new.as_ref().map(|v| v.len()).unwrap_or(0);
            info!("CrowdSec startup pull: {} decisions loaded", n_new);
            cache.apply_stream(stream, &config);
        }
        Err(e) => warn!("CrowdSec startup pull failed: {}", e),
    }

    let update_interval = Duration::from_secs(config.update_frequency_secs.max(5));
    let cleanup_interval = Duration::from_secs(300); // 5 minutes

    let mut last_cleanup = tokio::time::Instant::now();

    loop {
        // Sleep until the next poll or shutdown signal
        tokio::select! {
            _ = tokio::time::sleep(update_interval) => {}
            result = shutdown_rx.changed() => {
                if result.is_err() || *shutdown_rx.borrow() {
                    info!("CrowdSec sync task shutting down");
                    return;
                }
            }
        }

        // Incremental pull
        match client.get_decisions_stream(false).await {
            Ok(stream) => {
                let n_new = stream.new.as_ref().map(|v| v.len()).unwrap_or(0);
                let n_del = stream.deleted.as_ref().map(|v| v.len()).unwrap_or(0);
                if n_new > 0 || n_del > 0 {
                    info!(
                        new = n_new,
                        deleted = n_del,
                        "CrowdSec incremental update"
                    );
                    cache.apply_stream(stream, &config);
                }
            }
            Err(e) => warn!("CrowdSec incremental pull failed: {}", e),
        }

        // Periodic cleanup of expired entries
        if last_cleanup.elapsed() >= cleanup_interval {
            cache.cleanup_expired();
            last_cleanup = tokio::time::Instant::now();
        }
    }
}
