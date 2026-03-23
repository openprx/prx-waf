use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::client::CommunityClient;

/// Request body for machine enrollment.
#[derive(Debug, Serialize)]
struct EnrollRequest {
    machine_name: String,
    os_info: String,
    version: String,
    product_type: String,
}

/// Response from `POST /api/v1/machines/enroll`.
#[derive(Debug, Deserialize)]
pub struct EnrollResponse {
    pub machine_id: String,
    pub api_key: String,
    pub enrollment_credential: Option<String>,
}

/// Enroll this machine with the community server.
///
/// Sends hostname and OS metadata to receive a `machine_id` and `api_key`
/// that authenticate all subsequent API calls.
pub async fn enroll_machine(client: &CommunityClient) -> Result<EnrollResponse> {
    let machine_name = hostname_safe();
    let os_info = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    let version = env!("CARGO_PKG_VERSION").to_string();

    let body = EnrollRequest {
        machine_name,
        os_info,
        version,
        product_type: "waf".to_string(),
    };

    let url = format!("{}/api/v1/machines/enroll", client.base_url);
    let resp = client
        .http
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("community enrollment request failed")?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!("enrollment returned {status}: {body_text}");
    }

    let enroll_resp: EnrollResponse = resp.json().await.context("failed to parse enrollment response")?;
    Ok(enroll_resp)
}

/// Return the system hostname, falling back to "unknown" on error.
fn hostname_safe() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}
