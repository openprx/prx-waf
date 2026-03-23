//! Automatic ip2region xdb file updater with hot-reload support.
//!
//! Downloads the latest `ip2region_v4.xdb` and `ip2region_v6.xdb` files from
//! the upstream GitHub repository (or a configurable URL), validates each
//! download, atomically replaces the on-disk files, and triggers a hot-reload
//! of the in-process [`GeoIpService`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::geoip::GeoIpService;
use waf_common::config::GeoIpAutoUpdateConfig;

/// Default URL base for ip2region raw xdb files on GitHub.
const DEFAULT_GITHUB_BASE_URL: &str = "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data";

// ── Public types ──────────────────────────────────────────────────────────────

/// Result of a single update cycle.
#[derive(Debug, Default)]
pub struct UpdateResult {
    /// Whether the IPv4 xdb file was newly downloaded/replaced.
    pub ipv4_updated: bool,
    /// Whether the IPv6 xdb file was newly downloaded/replaced.
    pub ipv6_updated: bool,
    /// Size of the IPv4 xdb file in bytes (0 if not updated).
    pub ipv4_size: u64,
    /// Size of the IPv6 xdb file in bytes (0 if not updated).
    pub ipv6_size: u64,
}

/// Downloads the latest ip2region xdb files from a configurable URL.
///
/// All download operations are atomic: files are first written to a `.tmp`
/// sibling, validated by opening them with `ip2region::Searcher`, and then
/// renamed into place.  A failed download never corrupts the existing files.
pub struct XdbUpdater {
    data_dir: PathBuf,
    /// Base URL from which xdb files are fetched (without trailing slash).
    github_base_url: String,
}

impl XdbUpdater {
    /// Create an updater that fetches from `github_base_url`.
    pub const fn new(data_dir: PathBuf, github_base_url: String) -> Self {
        Self {
            data_dir,
            github_base_url,
        }
    }

    /// Create an updater using the default upstream GitHub URL.
    pub fn with_default_url(data_dir: PathBuf) -> Self {
        Self::new(data_dir, DEFAULT_GITHUB_BASE_URL.to_string())
    }

    /// Check whether the remote xdb files appear to be newer than the local
    /// copies, using HTTP `HEAD` + `Content-Length` comparison.
    ///
    /// Returns `Ok(true)` when an update seems available (including when either
    /// file is missing locally).  Returns `Ok(false)` when both local files
    /// match the remote sizes.  Network errors are propagated.
    pub async fn check_update(&self) -> Result<bool> {
        let client = build_client(30)?;

        for filename in &["ip2region_v4.xdb", "ip2region_v6.xdb"] {
            let local_path = self.data_dir.join(filename);

            // Missing file → definitely need to download.
            if !local_path.exists() {
                debug!("GeoIP updater: {} not found locally — update needed", filename);
                return Ok(true);
            }

            let local_size = local_path.metadata().map(|m| m.len()).unwrap_or(0);
            let url = format!("{}/{}", self.github_base_url, filename);

            match client.head(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    // Compare Content-Length if the server provides it.
                    if let Some(remote_size) = resp
                        .headers()
                        .get(reqwest::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok())
                        && remote_size != local_size
                    {
                        debug!(
                            "GeoIP updater: {} size mismatch local={} remote={}",
                            filename, local_size, remote_size
                        );
                        return Ok(true);
                    }
                }
                Ok(resp) => {
                    warn!("GeoIP updater: HEAD {} returned {}", url, resp.status());
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("GeoIP HEAD check failed for {url}: {e}"));
                }
            }
        }

        Ok(false)
    }

    /// Download the latest xdb files atomically.
    ///
    /// For each file:
    /// 1. Download to `<filename>.tmp` in `data_dir`.
    /// 2. Validate the download by opening it with `ip2region::Searcher`.
    /// 3. Atomically `rename` the tmp file to the final path.
    ///
    /// If any step fails the original file is left untouched.
    pub async fn download(&self) -> Result<UpdateResult> {
        std::fs::create_dir_all(&self.data_dir)
            .with_context(|| format!("Failed to create data dir: {}", self.data_dir.display()))?;

        let client = build_client(120)?;

        let (ipv4_updated, ipv4_size) = self.download_one(&client, "ip2region_v4.xdb").await?;
        let (ipv6_updated, ipv6_size) = self.download_one(&client, "ip2region_v6.xdb").await?;

        Ok(UpdateResult {
            ipv4_updated,
            ipv6_updated,
            ipv4_size,
            ipv6_size,
        })
    }

    /// Full update cycle: `check_update` → `download` → hot-reload.
    ///
    /// If nothing changed (`check_update` returns `false`) this is a no-op and
    /// returns a zeroed `UpdateResult`.  Gracefully degrades: a failed download
    /// returns an error but the running engine keeps using the existing files.
    pub async fn update(&self, geoip: &GeoIpService) -> Result<UpdateResult> {
        let needs_update = self.check_update().await.unwrap_or_else(|e| {
            warn!(
                "GeoIP updater: check_update error (will attempt download anyway): {}",
                e
            );
            true
        });

        if !needs_update {
            return Ok(UpdateResult::default());
        }

        let result = self.download().await?;

        if (result.ipv4_updated || result.ipv6_updated)
            && let Err(e) = geoip.reload()
        {
            warn!("GeoIP updater: hot-reload failed after download: {}", e);
        }

        Ok(result)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Download a single xdb file atomically.  Returns `(updated, size_bytes)`.
    async fn download_one(&self, client: &reqwest::Client, filename: &str) -> Result<(bool, u64)> {
        let url = format!("{}/{}", self.github_base_url, filename);
        let final_path = self.data_dir.join(filename);
        let tmp_path = self.data_dir.join(format!("{filename}.tmp"));

        info!("GeoIP updater: downloading {} from {}", filename, url);

        let resp = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("GET request failed for {url}"))?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!("HTTP {} downloading {}", resp.status(), url));
        }

        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("Failed to read response body for {filename}"))?;

        let size = bytes.len() as u64;

        // Write to tmp file first.
        std::fs::write(&tmp_path, &bytes).with_context(|| format!("Failed to write {}", tmp_path.display()))?;

        // Validate: try to open the tmp file as a Searcher.
        // Use NoCache policy to avoid loading ~20 MB into memory just for validation.
        if let Err(e) =
            ip2region::Searcher::new(tmp_path.to_string_lossy().to_string(), ip2region::CachePolicy::NoCache)
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(anyhow::anyhow!("Downloaded {filename} failed validation: {e}"));
        }

        // Atomic rename to final path.
        std::fs::rename(&tmp_path, &final_path)
            .with_context(|| format!("Failed to rename {} → {}", tmp_path.display(), final_path.display()))?;

        info!("GeoIP updater: {} updated ({} bytes)", filename, size);

        Ok((true, size))
    }
}

// ── Background auto-updater task ──────────────────────────────────────────────

/// Spawn a background tokio task that periodically checks for and downloads
/// xdb updates, then hot-reloads the in-process [`GeoIpService`].
///
/// The returned `JoinHandle` should be kept alive for the process lifetime
/// (e.g. via `std::mem::forget`) or stored somewhere that outlives the task.
///
/// The first update check runs after one full `interval`; it does **not** run
/// immediately at startup (the engine already loaded the current files).
pub fn spawn_auto_updater(
    geoip: Arc<GeoIpService>,
    config: GeoIpAutoUpdateConfig,
    data_dir: PathBuf,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let updater = XdbUpdater::new(data_dir, config.source_url.clone());
        let interval = parse_duration(&config.interval);

        info!(
            "GeoIP auto-updater: started (interval={}, source={})",
            config.interval, config.source_url
        );

        loop {
            tokio::time::sleep(interval).await;

            match updater.update(&geoip).await {
                Ok(result) if result.ipv4_updated || result.ipv6_updated => {
                    info!(
                        "GeoIP xdb files updated — v4: {} bytes, v6: {} bytes",
                        result.ipv4_size, result.ipv6_size
                    );
                }
                Ok(_) => debug!("GeoIP xdb files already up to date"),
                Err(e) => warn!("GeoIP auto-update failed: {}", e),
            }
        }
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a human-friendly duration string into a [`Duration`].
///
/// Supported suffixes: `d` (days), `h` (hours), `m` (minutes), `s` (seconds).
/// Falls back to 7 days if the string is unrecognised.
pub fn parse_duration(s: &str) -> Duration {
    let s = s.trim();
    let (num_str, unit) = s
        .find(|c: char| c.is_alphabetic())
        .map_or((s, "s"), |pos| (&s[..pos], &s[pos..]));

    let n: u64 = num_str.parse().unwrap_or(7);

    let secs = match unit.to_lowercase().as_str() {
        "d" => n * 86_400,
        "h" => n * 3_600,
        "m" => n * 60,
        "s" => n,
        _ => {
            warn!("GeoIP updater: unrecognised duration '{}', defaulting to 7d", s);
            7 * 86_400
        }
    };

    Duration::from_secs(secs)
}

/// Build a [`reqwest::Client`] with a given timeout (seconds).
fn build_client(timeout_secs: u64) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .context("Failed to build HTTP client for GeoIP updater")
}

// ── Display helper ────────────────────────────────────────────────────────────

/// Return a human-readable summary of an xdb file at `path`.
pub fn xdb_file_info(path: &Path) -> String {
    if !path.exists() {
        return format!("{} (not found)", path.display());
    }

    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return format!("{} (stat error: {})", path.display(), e),
    };

    let size = meta.len();
    let modified = meta.modified().map_or_else(
        |_| "unknown".to_string(),
        |t| {
            let secs = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            // Format as YYYY-MM-DD HH:MM:SS UTC (no chrono dep needed here)
            // SAFETY: secs from UNIX_EPOCH will not exceed i64::MAX in practice
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            let ts = secs as i64;
            chrono::DateTime::from_timestamp(ts, 0).map_or_else(
                || "unknown".to_string(),
                |d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            )
        },
    );

    format!("{} ({} bytes, modified {})", path.display(), size, modified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration("7d"), Duration::from_secs(7 * 86_400));
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("12h"), Duration::from_secs(12 * 3_600));
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("30m"), Duration::from_secs(30 * 60));
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration("60s"), Duration::from_secs(60));
    }

    #[test]
    fn parse_duration_fallback() {
        // Unrecognised unit falls back to 7 days.
        assert_eq!(parse_duration("3x"), Duration::from_secs(7 * 86_400));
    }
}
