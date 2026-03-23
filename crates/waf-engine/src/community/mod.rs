pub mod blocklist;
pub mod checker;
pub mod client;
pub mod config;
pub mod enroll;
pub mod reporter;

pub use blocklist::CommunityBlocklistSync;
pub use checker::CommunityChecker;
pub use client::CommunityClient;
pub use config::CommunityConfig;
pub use reporter::{CommunityReporter, RequestInfo};

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{info, warn};

/// All runtime components of the community threat intelligence integration.
pub struct CommunityComponents {
    /// HTTP client shared across all community operations
    pub client: Arc<CommunityClient>,
    /// Signal reporter (buffer + flush)
    pub reporter: Arc<CommunityReporter>,
    /// IP blocklist checker for the WAF pipeline
    pub checker: Arc<CommunityChecker>,
    /// Background sync task handle
    pub sync_handle: tokio::task::JoinHandle<()>,
    /// Background flush task handle
    pub flush_handle: tokio::task::JoinHandle<()>,
}

/// Initialise the community threat intelligence integration.
///
/// Performs machine enrollment if no `api_key` is configured, then starts
/// background tasks for signal reporting and blocklist syncing.
///
/// Returns `None` when `config.enabled == false` or when enrollment fails.
pub async fn init_community(
    config: CommunityConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<CommunityComponents> {
    if !config.enabled {
        return None;
    }

    info!(
        server_url = %config.server_url,
        "Initialising community threat intelligence",
    );

    let client = match CommunityClient::new(&config.server_url) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            warn!("Failed to create community HTTP client: {}", e);
            return None;
        }
    };

    // Enrollment: if no api_key is set, attempt auto-enrollment
    let (_machine_id, api_key) = match (&config.machine_id, &config.api_key) {
        (Some(mid), Some(key)) if !mid.is_empty() && !key.is_empty() => (mid.clone(), key.clone()),
        _ => {
            info!("No community API key found, attempting machine enrollment...");
            match enroll::enroll_machine(&client).await {
                Ok(resp) => {
                    info!(
                        machine_id = %resp.machine_id,
                        "Machine enrolled successfully. Save the API key to your config file."
                    );
                    if let Some(ref cred) = resp.enrollment_credential {
                        info!(
                            enrollment_credential = %cred,
                            "Enrollment credential (save this for re-enrollment)"
                        );
                    }
                    (resp.machine_id, resp.api_key)
                }
                Err(e) => {
                    warn!("Community machine enrollment failed: {}", e);
                    return None;
                }
            }
        }
    };

    // Create blocklist sync and checker
    let blocklist_sync = Arc::new(CommunityBlocklistSync::new(
        Arc::clone(&client),
        api_key.clone(),
        config.sync_interval_secs,
    ));
    let checker = Arc::new(CommunityChecker::new(Arc::clone(&blocklist_sync)));

    // Create reporter
    let reporter = Arc::new(CommunityReporter::new(
        Arc::clone(&client),
        api_key,
        config.batch_size,
        config.flush_interval_secs,
    ));

    // Start background flush task
    let reporter_bg = Arc::clone(&reporter);
    let flush_shutdown = shutdown_rx.clone();
    let flush_handle = tokio::spawn(async move {
        reporter_bg.run_flush_task(flush_shutdown).await;
    });

    // Start background blocklist sync task
    let sync_bg = Arc::clone(&blocklist_sync);
    let sync_handle = tokio::spawn(async move {
        sync_bg.run_sync_task(shutdown_rx).await;
    });

    Some(CommunityComponents {
        client,
        reporter,
        checker,
        sync_handle,
        flush_handle,
    })
}
