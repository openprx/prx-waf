use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::sync::watch;
use tracing::{info, warn};

use waf_common::DetectionResult;

use super::client::CommunityClient;

/// A single WAF signal matching the community backend `WafSignalInput` contract.
#[derive(Debug, Clone, Serialize)]
struct WafSignal {
    source_ip: String,
    scenario: String,
    rule_id: String,
    rule_name: String,
    detail: String,
    http_method: String,
    request_path: String,
    request_host: String,
    geo_country: String,
    confidence: f64,
    signal_ts: DateTime<Utc>,
}

/// Wrapper batch matching the backend `WafSignalBatch` contract.
#[derive(Debug, Serialize)]
struct WafSignalBatch {
    signals: Vec<WafSignal>,
}

/// Optional request context for enriching WAF signals.
///
/// When the gateway calls `push_detection`, it should provide as much
/// HTTP context as available.
pub struct RequestInfo {
    pub http_method: String,
    pub request_path: String,
    pub request_host: String,
    pub geo_country: Option<String>,
}

/// Batches WAF detection signals and flushes them to the community API.
///
/// Mirrors the `CrowdSecPusher` pattern: events are buffered and sent
/// either when the buffer reaches `batch_size` or every
/// `flush_interval_secs`, whichever comes first.
pub struct CommunityReporter {
    client: Arc<CommunityClient>,
    api_key: String,
    batch_size: usize,
    flush_interval_secs: u64,
    buffer: Mutex<Vec<WafSignal>>,
}

impl CommunityReporter {
    pub fn new(client: Arc<CommunityClient>, api_key: String, batch_size: usize, flush_interval_secs: u64) -> Self {
        Self {
            client,
            api_key,
            batch_size,
            flush_interval_secs,
            buffer: Mutex::new(Vec::new()),
        }
    }

    /// Queue a WAF detection for the next batch push.
    ///
    /// `req_info` enriches the signal with HTTP request context.
    /// The backend derives `machine_id` from the Bearer token, so it is
    /// not included in the signal payload.
    ///
    /// Invalid `client_ip` values (not parseable as `IpAddr`) are silently
    /// dropped with a warning log, because the backend deserialises the field
    /// as `std::net::IpAddr` and an invalid IP would reject the whole batch.
    pub async fn push_detection(&self, client_ip: &str, detection: &DetectionResult, req_info: Option<&RequestInfo>) {
        // Validate IP before queuing — backend expects std::net::IpAddr
        let Ok(ip) = client_ip.parse::<IpAddr>() else {
            warn!(client_ip, "Dropping signal: invalid source IP");
            return;
        };

        let signal = WafSignal {
            source_ip: ip.to_string(),
            scenario: detection.phase.to_string(),
            rule_id: detection.rule_id.clone().unwrap_or_else(|| "unknown".to_string()),
            rule_name: detection.rule_name.clone(),
            detail: detection.detail.clone(),
            http_method: req_info.map(|r| r.http_method.clone()).unwrap_or_default(),
            request_path: req_info.map(|r| r.request_path.clone()).unwrap_or_default(),
            request_host: req_info.map(|r| r.request_host.clone()).unwrap_or_default(),
            geo_country: req_info
                .and_then(|r| r.geo_country.clone())
                .unwrap_or_else(|| "unknown".to_string()),
            confidence: 1.0,
            signal_ts: Utc::now(),
        };

        let mut buf = self.buffer.lock().await;
        buf.push(signal);

        if buf.len() >= self.batch_size {
            let batch = std::mem::take(&mut *buf);
            drop(buf);
            self.flush_batch(batch).await;
        }
    }

    /// Background task: flush the event buffer on a timer and on shutdown.
    pub async fn run_flush_task(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.flush_interval_secs);
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

    async fn flush_batch(&self, batch: Vec<WafSignal>) {
        if batch.is_empty() {
            return;
        }

        let url = format!("{}/api/v1/waf/signals", self.client.base_url);
        let count = batch.len();
        let payload = WafSignalBatch { signals: batch };

        match self
            .client
            .http
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                info!(count, "Community signals flushed successfully");
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                warn!(
                    count,
                    status = %status,
                    "Failed to push community signals: {body}"
                );
            }
            Err(e) => {
                warn!(count, "Community signal push failed: {e}");
            }
        }
    }
}
