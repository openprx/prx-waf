use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Mutex;
use tokio::sync::watch;
use tracing::{info, warn};

use waf_common::DetectionResult;

use super::client::CrowdSecClient;
use super::config::PusherConfig;

const BATCH_SIZE: usize = 50;
const FLUSH_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize)]
struct AlertEvent {
    scenario: String,
    source_ip: String,
    rule_name: String,
    detail: String,
}

/// Pushes prx-waf WAF detections to `CrowdSec` as machine alerts.
///
/// Events are buffered and sent either when the buffer reaches `BATCH_SIZE`
/// or every `FLUSH_INTERVAL_SECS`, whichever comes first.
pub struct CrowdSecPusher {
    client: Arc<CrowdSecClient>,
    config: PusherConfig,
    buffer: Arc<Mutex<Vec<AlertEvent>>>,
}

impl CrowdSecPusher {
    pub fn new(client: Arc<CrowdSecClient>, config: PusherConfig) -> Self {
        Self {
            client,
            config,
            buffer: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Queue a WAF detection for the next batch push.
    pub async fn push_detection(&self, client_ip: &str, detection: &DetectionResult) {
        let event = AlertEvent {
            scenario: detection
                .rule_id
                .clone()
                .unwrap_or_else(|| "prx-waf/detection".to_string()),
            source_ip: client_ip.to_string(),
            rule_name: detection.rule_name.clone(),
            detail: detection.detail.clone(),
        };

        let mut buf = self.buffer.lock().await;
        buf.push(event);

        if buf.len() >= BATCH_SIZE {
            let batch = std::mem::take(&mut *buf);
            drop(buf);
            self.flush_batch(batch).await;
        }
    }

    async fn flush_batch(&self, batch: Vec<AlertEvent>) {
        if batch.is_empty() {
            return;
        }

        let token = match self
            .client
            .machine_auth(&self.config.login, &self.config.password)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                warn!("CrowdSec machine auth failed: {}", e);
                return;
            }
        };

        let alerts = serde_json::json!(batch);
        match self.client.push_alerts(&token, alerts).await {
            Ok(()) => info!("Pushed {} WAF events to CrowdSec", batch.len()),
            Err(e) => warn!("Failed to push alerts to CrowdSec: {}", e),
        }
    }

    /// Background task: flush the event buffer on a timer and on shutdown.
    pub async fn run_flush_task(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        let interval = Duration::from_secs(FLUSH_INTERVAL_SECS);
        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                result = shutdown_rx.changed() => {
                    if result.is_err() || *shutdown_rx.borrow() {
                        // Final flush before exit
                        let batch = {
                            let mut buf = self.buffer.lock().await;
                            std::mem::take(&mut *buf)
                        };
                        self.flush_batch(batch).await;
                        return;
                    }
                }
            }

            let batch = {
                let mut buf = self.buffer.lock().await;
                std::mem::take(&mut *buf)
            };
            self.flush_batch(batch).await;
        }
    }
}
