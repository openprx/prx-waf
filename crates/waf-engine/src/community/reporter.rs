use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{info, warn};

use waf_common::{DetectionResult, Phase};

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
/// When the gateway calls `try_push_detection`, it should provide as much
/// HTTP context as available.
pub struct RequestInfo {
    pub http_method: String,
    pub request_path: String,
    pub request_host: String,
    pub geo_country: Option<String>,
}

/// Channel capacity multiplier applied to `batch_size`.
const CHANNEL_CAP_MULTIPLIER: usize = 16;

/// Minimum channel capacity regardless of batch size.
const CHANNEL_CAP_MIN: usize = 1024;

/// Batches WAF detection signals and flushes them to the community API.
///
/// Uses a bounded MPSC channel instead of a mutex-protected buffer.
/// `try_push_detection` is **synchronous** and never blocks the hot path.
/// When the channel is full (flood scenario), signals are dropped and
/// a counter is incremented for observability.
pub struct CommunityReporter {
    client: Arc<CommunityClient>,
    api_key: String,
    batch_size: usize,
    flush_interval_secs: u64,
    tx: mpsc::Sender<WafSignal>,
    /// Receiver is taken exactly once by `run_flush_task`.
    rx: parking_lot::Mutex<Option<mpsc::Receiver<WafSignal>>>,
    /// Number of signals dropped due to back-pressure.
    dropped: AtomicU64,
}

/// Map detection phase to signal confidence for community reporting.
///
/// Higher confidence means the detection engine is more precise.
/// Lower confidence (e.g. `GeoIP`) means the signal alone is weak evidence.
const fn compute_confidence(phase: Phase) -> f64 {
    match phase {
        Phase::SqlInjection | Phase::Rce => 0.95,
        Phase::Xss | Phase::Xxe => 0.90,
        // DirTraversal / Owasp sit here; NoSQL, SSTI and LDAP injection join them
        // because a reverse proxy cannot confirm the backend actually interprets the
        // payload — it cannot know MongoDB is the store (NoSQL comparison operators
        // recur in legitimate JSON), it cannot know a template engine evaluated the
        // field (`{{7*7}}` is only known to be SSTI once rendered), and it cannot know
        // an LDAP search consumed the field (filter metacharacters recur in ordinary
        // text/URLs). Structural / input-side confidence, deliberately below the
        // AST-backed XSS/XXE families.
        Phase::DirTraversal | Phase::Owasp | Phase::NoSqlInjection | Phase::Ssti | Phase::LdapInjection => 0.85,
        Phase::CustomRule | Phase::IpBlacklist | Phase::UrlBlacklist => 0.80,
        Phase::Sensitive | Phase::Scanner | Phase::Bot => 0.70,
        Phase::RateLimit | Phase::CrowdSec => 0.60,
        Phase::Community => 0.50,
        Phase::GeoIp | Phase::AntiHotlink => 0.40,
        // Whitelist phases rarely trigger signal reporting,
        // but covered for exhaustive matching.
        Phase::IpWhitelist | Phase::UrlWhitelist => 0.30,
    }
}

impl CommunityReporter {
    pub fn new(client: Arc<CommunityClient>, api_key: String, batch_size: usize, flush_interval_secs: u64) -> Self {
        let cap = (batch_size * CHANNEL_CAP_MULTIPLIER).max(CHANNEL_CAP_MIN);
        let (tx, rx) = mpsc::channel(cap);
        Self {
            client,
            api_key,
            batch_size,
            flush_interval_secs,
            tx,
            rx: parking_lot::Mutex::new(Some(rx)),
            dropped: AtomicU64::new(0),
        }
    }

    /// Synchronously queue a WAF detection for the next batch push.
    ///
    /// This is designed for the hot path: it never awaits, never spawns,
    /// and never allocates beyond the `WafSignal` itself.
    ///
    /// When the internal channel is full (sustained flood), the signal is
    /// silently dropped and a counter is incremented.  The flush task
    /// periodically logs the drop count for observability.
    pub fn try_push_detection(&self, client_ip: IpAddr, detection: &DetectionResult, req_info: Option<&RequestInfo>) {
        let signal = WafSignal {
            source_ip: client_ip.to_string(),
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
            confidence: compute_confidence(detection.phase),
            signal_ts: Utc::now(),
        };

        if self.tx.try_send(signal).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Background task: drain the channel in batches and flush to the API.
    ///
    /// Signals are flushed either when `batch_size` is reached or every
    /// `flush_interval_secs`, whichever comes first. On shutdown the
    /// remaining signals are drained and flushed.
    pub async fn run_flush_task(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        let mut rx = {
            let Some(r) = self.rx.lock().take() else {
                warn!("CommunityReporter flush task already started or receiver missing");
                return;
            };
            r
        };

        let interval = Duration::from_secs(self.flush_interval_secs);
        let mut batch = Vec::with_capacity(self.batch_size);

        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {
                    // Timer fired — drain whatever is in the channel
                    while let Ok(sig) = rx.try_recv() {
                        batch.push(sig);
                    }
                    self.log_and_reset_drops();
                    if !batch.is_empty() {
                        let to_flush = std::mem::replace(&mut batch, Vec::with_capacity(self.batch_size));
                        self.flush_batch(to_flush).await;
                    }
                }
                maybe_sig = rx.recv() => {
                    if let Some(sig) = maybe_sig {
                        batch.push(sig);
                        // Eagerly drain up to batch_size
                        while batch.len() < self.batch_size {
                            match rx.try_recv() {
                                Ok(s) => batch.push(s),
                                Err(_) => break,
                            }
                        }
                        if batch.len() >= self.batch_size {
                            let to_flush = std::mem::replace(&mut batch, Vec::with_capacity(self.batch_size));
                            self.flush_batch(to_flush).await;
                        }
                    } else {
                        // Channel closed — final flush
                        self.log_and_reset_drops();
                        if !batch.is_empty() {
                            self.flush_batch(std::mem::take(&mut batch)).await;
                        }
                        return;
                    }
                }
                result = shutdown_rx.changed() => {
                    if result.is_err() || *shutdown_rx.borrow() {
                        // Shutdown — drain remaining and flush
                        while let Ok(sig) = rx.try_recv() {
                            batch.push(sig);
                        }
                        self.log_and_reset_drops();
                        if !batch.is_empty() {
                            self.flush_batch(std::mem::take(&mut batch)).await;
                        }
                        return;
                    }
                }
            }
        }
    }

    /// Log and reset the dropped-signal counter.
    fn log_and_reset_drops(&self) {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            warn!(
                dropped,
                "Community signal channel full — dropped signals (back-pressure)"
            );
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
