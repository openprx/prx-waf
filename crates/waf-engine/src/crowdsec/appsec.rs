use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use tracing::{debug, warn};

use waf_common::{DetectionResult, Phase, RequestCtx};

use super::config::AppSecConfig;
use super::models::AppSecResponse;

/// Result of an `AppSec` check
#[derive(Debug, Clone)]
pub enum AppSecResult {
    /// Request is clean — allow it
    Allow,
    /// Request is malicious — block it
    Block { message: String },
    /// `AppSec` engine unavailable — caller applies `fallback_action`
    Unavailable,
}

/// `CrowdSec` `AppSec` protocol client.
///
/// Implements the `CrowdSec` `AppSec` protocol: forward each request to the
/// `AppSec` HTTP endpoint using special headers, then act on the response.
pub struct AppSecClient {
    client: Client,
    config: AppSecConfig,
}

impl AppSecClient {
    pub fn new(config: AppSecConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .context("failed to build AppSec HTTP client")?;
        Ok(Self { client, config })
    }

    /// Check a request against the `CrowdSec` `AppSec` engine.
    ///
    /// Returns `AppSecResult::Unavailable` on network/timeout errors so that
    /// the caller can apply the configured `failure_action`.
    pub async fn check_request(&self, ctx: &RequestCtx) -> AppSecResult {
        match self.check_request_inner(ctx).await {
            Ok(r) => r,
            Err(e) => {
                warn!("AppSec check error: {}", e);
                AppSecResult::Unavailable
            }
        }
    }

    async fn check_request_inner(&self, ctx: &RequestCtx) -> Result<AppSecResult> {
        let http_version = "HTTP/1.1";

        let mut builder = self
            .client
            .post(&self.config.endpoint)
            .header("X-Crowdsec-Appsec-Ip", ctx.client_ip.to_string())
            .header("X-Crowdsec-Appsec-Uri", &ctx.path)
            .header("X-Crowdsec-Appsec-Host", &ctx.host)
            .header("X-Crowdsec-Appsec-Verb", &ctx.method)
            .header("X-Crowdsec-Appsec-Api-Key", &self.config.api_key)
            .header("X-Crowdsec-Appsec-Http-Version", http_version);

        if let Some(ua) = ctx.headers.get("user-agent") {
            builder = builder.header("X-Crowdsec-Appsec-User-Agent", ua);
        }

        // Forward body for methods that carry one
        let builder = if ctx.body_preview.is_empty() {
            builder
        } else {
            builder.body(ctx.body_preview.clone())
        };

        let resp = builder.send().await.context("AppSec HTTP request failed")?;
        let status = resp.status().as_u16();
        debug!("AppSec response status: {}", status);

        match status {
            200 => Ok(AppSecResult::Allow),
            403 => {
                let body: Option<AppSecResponse> = resp.json().await.ok();
                let message = body
                    .and_then(|b| b.message)
                    .unwrap_or_else(|| "blocked by CrowdSec AppSec".to_string());
                Ok(AppSecResult::Block { message })
            }
            401 => anyhow::bail!("AppSec authentication failed — check API key"),
            _ => {
                warn!("AppSec unexpected status {}", status);
                Ok(AppSecResult::Unavailable)
            }
        }
    }
}

/// Convert an `AppSec` block result into a WAF `DetectionResult`.
pub fn appsec_to_detection(message: String) -> DetectionResult {
    DetectionResult {
        rule_id: Some("crowdsec:appsec".to_string()),
        rule_name: "CrowdSec AppSec".to_string(),
        phase: Phase::CrowdSec,
        detail: message,
    }
}
