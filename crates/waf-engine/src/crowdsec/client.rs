use anyhow::{Context, Result};
use reqwest::Client;
use std::time::Duration;
use tracing::debug;

use super::models::{Decision, DecisionStream, MachineAuthResponse};

/// `CrowdSec` Local API (LAPI) HTTP client.
pub struct CrowdSecClient {
    client: Client,
    lapi_url: String,
    api_key: String,
}

impl CrowdSecClient {
    pub fn new(lapi_url: String, api_key: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("failed to build LAPI HTTP client")?;
        Ok(Self {
            client,
            lapi_url,
            api_key,
        })
    }

    /// Pull a decision stream.
    ///
    /// `startup = true`  → full pull of all active decisions.
    /// `startup = false` → incremental update (new/deleted since last pull).
    pub async fn get_decisions_stream(&self, startup: bool) -> Result<DecisionStream> {
        let url = format!("{}/v1/decisions/stream?startup={}", self.lapi_url, startup);
        debug!("CrowdSec LAPI pull: {}", url);

        let resp = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .context("LAPI request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("LAPI decisions/stream returned {status}: {body}");
        }

        let stream: DecisionStream = resp.json().await.context("failed to parse decisions stream")?;
        Ok(stream)
    }

    /// Real-time single-IP query (bypass cache).
    pub async fn check_ip(&self, ip: &str) -> Result<Vec<Decision>> {
        let url = format!("{}/v1/decisions?ip={}", self.lapi_url, ip);
        let resp = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .context("LAPI check_ip request failed")?;

        if resp.status().as_u16() == 404 {
            return Ok(Vec::new());
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("LAPI decisions returned {status}: {body}");
        }

        let decisions: Option<Vec<Decision>> = resp.json().await.context("failed to parse decisions")?;
        Ok(decisions.unwrap_or_default())
    }

    /// Delete a decision by its LAPI ID.
    pub async fn delete_decision(&self, id: i64) -> Result<()> {
        let url = format!("{}/v1/decisions/{}", self.lapi_url, id);
        let resp = self
            .client
            .delete(&url)
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .context("LAPI delete_decision request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("LAPI DELETE decisions/{id} returned {status}: {body}");
        }
        Ok(())
    }

    /// Test LAPI connectivity and authentication.
    pub async fn test_connection(&self) -> Result<String> {
        let url = format!("{}/v1/decisions/stream?startup=false", self.lapi_url);
        let resp = self
            .client
            .get(&url)
            .header("X-Api-Key", &self.api_key)
            .send()
            .await
            .context("LAPI connection test failed")?;

        let status = resp.status();
        if status.as_u16() == 401 {
            anyhow::bail!("LAPI authentication failed — check API key");
        }
        if !status.is_success() {
            anyhow::bail!("LAPI test returned {status}");
        }

        Ok(format!("Connected to CrowdSec LAPI at {}", self.lapi_url))
    }

    /// Push alerts to LAPI (used by the log pusher).
    pub async fn push_alerts(&self, token: &str, alerts: serde_json::Value) -> Result<()> {
        let url = format!("{}/v1/alerts", self.lapi_url);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(token)
            .json(&alerts)
            .send()
            .await
            .context("failed to push alerts to LAPI")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("push_alerts returned {status}: {body}");
        }
        Ok(())
    }

    /// Authenticate as a watcher machine and return a JWT token.
    pub async fn machine_auth(&self, login: &str, password: &str) -> Result<String> {
        let url = format!("{}/v1/watchers/login", self.lapi_url);
        let body = serde_json::json!({ "machine_id": login, "password": password });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("machine auth request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("machine_auth returned {status}: {body}");
        }

        let auth: MachineAuthResponse = resp.json().await.context("failed to parse machine auth response")?;
        Ok(auth.token)
    }
}
