use std::collections::VecDeque;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use waf_engine::{Rule, RuleRegistry, RuleReloader};

use crate::protocol::{ChangeOp, RuleChange, RuleSyncRequest, RuleSyncResponse, SyncType};

/// Maximum decompressed snapshot size accepted from a peer (256 MiB, M-18).
///
/// lz4 can inflate a tiny payload into an enormous buffer; a malicious peer
/// could send a "decompression bomb" that exhausts memory. The declared
/// (uncompressed) size prefix is validated against this cap **before** the
/// allocation implied by decompression.
pub const MAX_SNAPSHOT_DECOMPRESSED_LEN: usize = 256 * 1024 * 1024;

/// Decompress an lz4 blob produced with a prepended size, rejecting any blob
/// whose declared uncompressed size exceeds [`MAX_SNAPSHOT_DECOMPRESSED_LEN`].
///
/// `lz4_flex::compress_prepend_size` stores the uncompressed length as a
/// little-endian `u32` in the first four bytes; we read and bound-check it
/// before delegating to the decompressor (M-18).
fn checked_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let prefix: [u8; 4] = data
        .get(..4)
        .context("lz4 snapshot too short: missing uncompressed-size prefix")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("lz4 snapshot has a malformed size prefix"))?;
    let declared = u32::from_le_bytes(prefix) as usize;
    if declared > MAX_SNAPSHOT_DECOMPRESSED_LEN {
        anyhow::bail!(
            "lz4 snapshot declares {declared} bytes uncompressed, exceeding the {MAX_SNAPSHOT_DECOMPRESSED_LEN}-byte limit; rejecting"
        );
    }
    lz4_flex::decompress_size_prepended(data).map_err(|e| anyhow::anyhow!("lz4 decompress failed: {e}"))
}

/// Ring-buffer of recent rule changes maintained by the main node.
///
/// Workers send `RuleSyncRequest { current_version }` and receive either an
/// incremental delta (if the worker is caught up enough) or a full snapshot.
pub struct RuleChangelog {
    /// (`version_after_change`, change) pairs in chronological order
    changes: VecDeque<(u64, RuleChange)>,
    max_retained: usize,
    /// Monotonic version counter — incremented by every `record_change` call.
    current_version: u64,
}

impl RuleChangelog {
    /// Create a new changelog with the given ring-buffer capacity.
    pub const fn new(max_retained: usize) -> Self {
        Self {
            changes: VecDeque::new(),
            max_retained,
            current_version: 0,
        }
    }

    /// The version after the last recorded change.
    pub const fn current_version(&self) -> u64 {
        self.current_version
    }

    /// Record a rule change, incrementing the internal version counter.
    ///
    /// `rule` is `None` for `Delete` operations.
    pub fn record_change(&mut self, op: ChangeOp, rule_id: String, rule: Option<&Rule>) {
        self.current_version += 1;
        let version = self.current_version;
        let rule_json = rule.and_then(|r| serde_json::to_value(r).ok());
        let change = RuleChange { op, rule_id, rule_json };
        self.push(version, change);
    }

    /// Append a pre-built change entry at the given version.
    pub fn push(&mut self, version: u64, change: RuleChange) {
        if self.changes.len() >= self.max_retained {
            self.changes.pop_front();
        }
        self.changes.push_back((version, change));
    }

    /// Return all changes with `version > from_version`, or `None` when the
    /// worker is too far behind (its version precedes the oldest buffered entry).
    pub fn delta_since(&self, from_version: u64) -> Option<Vec<RuleChange>> {
        if self.changes.is_empty() {
            // No changes ever recorded; worker is already up to date.
            return Some(Vec::new());
        }
        let first = self.changes.front().map_or(0, |(v, _)| *v);
        if from_version < first {
            // Worker is too far behind; needs a full snapshot.
            return None;
        }
        Some(
            self.changes
                .iter()
                .filter(|(v, _)| *v > from_version)
                .map(|(_, c)| c.clone())
                .collect(),
        )
    }

    /// Build a `RuleSyncResponse` for a worker's sync request.
    ///
    /// Returns an `Incremental` response when possible.  For `Full` responses
    /// the `snapshot_lz4` field is left empty — callers must call
    /// [`handle_sync_request`] or fill it manually.
    pub fn build_response(&self, from_version: u64) -> RuleSyncResponse {
        self.delta_since(from_version).map_or_else(
            || RuleSyncResponse {
                version: self.current_version,
                sync_type: SyncType::Full,
                changes: Vec::new(),
                snapshot_lz4: Vec::new(),
            },
            |changes| RuleSyncResponse {
                version: self.current_version,
                sync_type: SyncType::Incremental,
                changes,
                snapshot_lz4: Vec::new(),
            },
        )
    }
}

// ─── Snapshot helpers ──────────────────────────────────────────────────────────

/// Serialize and lz4-compress a rule slice for transmission as a full snapshot.
pub fn snapshot_rules(rules: &[Rule]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(rules).context("failed to serialize rules to JSON")?;
    Ok(lz4_flex::compress_prepend_size(&json))
}

/// Decompress and deserialize a full snapshot produced by [`snapshot_rules`].
pub fn restore_snapshot(data: &[u8]) -> Result<Vec<Rule>> {
    let json = checked_decompress(data)?;
    serde_json::from_slice(&json).context("failed to deserialize rules from snapshot")
}

// ─── Main-side handler ─────────────────────────────────────────────────────────

/// Respond to a worker's `RuleSyncRequest`.
///
/// Sends incremental changes when the worker is close enough; falls back to a
/// full lz4-compressed snapshot when the worker is too far behind or is new.
///
/// `rules` is the current authoritative rule list on the main node.
pub fn handle_sync_request(
    changelog: &RuleChangelog,
    request: &RuleSyncRequest,
    rules: &[Rule],
) -> Result<RuleSyncResponse> {
    let mut response = changelog.build_response(request.current_version);
    if matches!(response.sync_type, SyncType::Full) {
        response.snapshot_lz4 = snapshot_rules(rules)?;
    }
    Ok(response)
}

// ─── Worker-side appliers ──────────────────────────────────────────────────────

/// Apply an incremental list of rule changes to a local registry.
///
/// `Upsert` changes deserialize the embedded JSON and insert the rule.
/// `Delete` changes remove the rule by id.
pub fn apply_rule_changes(registry: &mut RuleRegistry, changes: Vec<RuleChange>) -> Result<()> {
    for change in changes {
        match change.op {
            ChangeOp::Delete => {
                registry.remove(&change.rule_id);
            }
            ChangeOp::Upsert => {
                if let Some(val) = change.rule_json {
                    let rule: Rule =
                        serde_json::from_value(val).context("failed to deserialize rule from incremental change")?;
                    registry.insert(rule);
                }
            }
        }
    }
    Ok(())
}

/// Replace the entire local registry with rules from a full snapshot.
///
/// Clears the existing registry before inserting the deserialized rules so
/// that any rules deleted on the main node are also removed locally.
pub fn apply_full_snapshot(registry: &mut RuleRegistry, data: &[u8]) -> Result<()> {
    let rules = restore_snapshot(data)?;
    registry.clear();
    for rule in rules {
        registry.insert(rule);
    }
    Ok(())
}

/// Apply a `RuleSyncResponse` received from the main node to a local registry.
///
/// * `Incremental` — applies the embedded change list to the existing registry.
/// * `Full` — decompresses the lz4 snapshot, clears the registry, and reloads
///   all rules from scratch.
///
/// In both cases the registry version is set to the authoritative value carried
/// by the response, and `reloader.on_rules_updated()` is called so the engine
/// can react (e.g., hot-reload pattern matchers).
pub async fn apply_sync_response(
    response: RuleSyncResponse,
    registry: &mut RuleRegistry,
    reloader: &dyn RuleReloader,
) -> Result<()> {
    match response.sync_type {
        SyncType::Incremental => {
            apply_rule_changes(registry, response.changes)?;
        }
        SyncType::Full => {
            apply_full_snapshot(registry, &response.snapshot_lz4)?;
        }
    }
    // Override the version accumulated by individual insert/remove calls with
    // the single authoritative version stamped by the main node.
    registry.version = response.version;
    reloader.on_rules_updated(response.version).await
}

/// Apply a `RuleSyncResponse` to a **shared** registry guarded by an `RwLock`,
/// then notify the reloader so the data plane picks up the new rules.
///
/// This is the worker-side entry point used by the transport dispatch. It keeps
/// the registry write lock short and **never holds it across an `.await`**:
///
/// * `Incremental` — mutates the live registry in place under the write lock.
/// * `Full` — decompresses and deserialises the snapshot **off-lock** (bounded
///   by [`MAX_SNAPSHOT_DECOMPRESSED_LEN`], M-18), builds a fresh registry, and
///   swaps it in atomically under a single write lock. Readers therefore never
///   observe a half-cleared registry during a full resync.
///
/// The authoritative `version` from the response is stamped onto the registry,
/// and `reloader.on_rules_updated(version)` is awaited **after** the lock is
/// released.
pub async fn apply_sync_response_shared(
    response: RuleSyncResponse,
    registry: &RwLock<RuleRegistry>,
    reloader: &dyn RuleReloader,
) -> Result<()> {
    let version = response.version;
    match response.sync_type {
        SyncType::Incremental => {
            let mut guard = registry.write();
            apply_rule_changes(&mut guard, response.changes)?;
            guard.version = version;
        }
        SyncType::Full => {
            // Build the replacement registry off-lock so decompression and
            // deserialisation (the expensive, allocation-heavy work) do not
            // block data-plane readers.
            let rules = restore_snapshot(&response.snapshot_lz4)?;
            let mut fresh = RuleRegistry::new();
            for rule in rules {
                fresh.insert(rule);
            }
            fresh.version = version;
            fresh.mark_loaded();
            // Atomic swap: readers see either the old or the new registry.
            *registry.write() = fresh;
        }
    }
    reloader.on_rules_updated(version).await
}

// ─── Low-level compression helpers (kept for compatibility) ───────────────────

/// Compress a raw byte slice using lz4 with prepended original size.
pub fn compress_snapshot(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress an lz4-compressed blob produced by [`compress_snapshot`].
///
/// Rejects blobs whose declared uncompressed size exceeds
/// [`MAX_SNAPSHOT_DECOMPRESSED_LEN`] (M-18).
pub fn decompress_snapshot(data: &[u8]) -> Result<Vec<u8>> {
    checked_decompress(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_within_limit() {
        let payload = b"the quick brown fox jumps over the lazy dog";
        let blob = compress_snapshot(payload);
        assert_eq!(decompress_snapshot(&blob).expect("decompress"), payload);
    }

    #[test]
    fn oversized_declared_size_is_rejected_before_decompression() {
        // Valid lz4 body, but forge the prepended size prefix to 300 MiB so the
        // bound check trips before any large allocation.
        let valid = compress_snapshot(b"small payload");
        let huge = u32::try_from(300usize * 1024 * 1024).expect("fits u32").to_le_bytes();
        let mut bomb = Vec::with_capacity(valid.len());
        bomb.extend_from_slice(&huge);
        if let Some(body) = valid.get(4..) {
            bomb.extend_from_slice(body);
        }
        let err = decompress_snapshot(&bomb).expect_err("bomb must be rejected");
        assert!(
            err.to_string().contains("exceeding"),
            "expected size-limit error: {err}"
        );
    }

    #[test]
    fn short_blob_is_rejected() {
        assert!(decompress_snapshot(&[0u8; 2]).is_err());
    }
}
