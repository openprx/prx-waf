use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::cache::DecisionCache;
use super::client::CrowdSecClient;
use super::config::{CrowdSecConfig, FallbackAction};
use super::health::CrowdSecHealth;
use super::models::Decision;
use super::store::{DecisionStore, delete_keys_for, report_mirror_failure, rows_for};

/// Background task that keeps the decision cache in sync with LAPI, and mirrors
/// what it caches into `crowdsec_decisions` so the next restart does not start
/// blind.
///
/// 1. On startup: full pull of all active decisions. On success the mirror is
///    *replaced* by that set (it is the complete truth) and any entry restored
///    from the mirror that the pull did not confirm is evicted from the cache,
///    so a ban lifted while this process was down cannot survive.
/// 2. Every `update_frequency_secs`: incremental pull of new/deleted decisions,
///    applied to both the cache and the mirror.
/// 3. Every 5 minutes: clean up expired cache entries.
/// 4. Shuts down cleanly when `shutdown_rx` receives `true`.
///
/// **Until a full pull succeeds, every pull is retried as a full pull.** An
/// incremental pull only carries deltas since the last successful stream, so
/// taking one as the first success would silently establish an incomplete
/// baseline — the cache would hold only whatever changed in the last few
/// seconds.
///
/// `restored` is how many decisions [`super::store::restore_cache`] loaded
/// before this task started; it is reported in the fail-open diagnostics so an
/// operator reading a failed pull can tell whether anything is still covering
/// them.
///
/// `health` is this task's second output. Every pull outcome is published to it
/// so the request path can tell a cache miss that means "clean" from one that
/// means "I never got the list" — the distinction `crowdsec.fallback_action`
/// acts on. It is written here and nowhere else; see [`CrowdSecHealth`].
pub async fn run_decision_sync(
    client: Arc<CrowdSecClient>,
    cache: Arc<DecisionCache>,
    store: Option<Arc<dyn DecisionStore>>,
    config: CrowdSecConfig,
    restored: usize,
    health: Arc<CrowdSecHealth>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    info!(
        lapi_url = %config.lapi_url,
        update_secs = config.update_frequency_secs,
        restored_from_mirror = restored,
        mirror_enabled = store.is_some(),
        "CrowdSec sync task started",
    );

    let update_interval = Duration::from_secs(config.update_frequency_secs.max(5));
    let cleanup_interval = Duration::from_mins(5);

    let mut last_cleanup = tokio::time::Instant::now();
    // Set until a *full* pull has succeeded; see the doc comment.
    let mut need_full_pull = true;
    // Restored entries still standing in for a confirmed LAPI answer.
    let mut unconfirmed = restored;
    let mut first_iteration = true;

    loop {
        if first_iteration {
            first_iteration = false;
        } else {
            // Sleep until the next poll or shutdown signal
            tokio::select! {
                () = tokio::time::sleep(update_interval) => {}
                result = shutdown_rx.changed() => {
                    if result.is_err() || *shutdown_rx.borrow() {
                        info!("CrowdSec sync task shutting down");
                        return;
                    }
                }
            }
        }

        match client.get_decisions_stream(need_full_pull).await {
            Ok(stream) => {
                let new_decisions = stream.new.clone().unwrap_or_default();
                let deleted_decisions = stream.deleted.clone().unwrap_or_default();
                let n_new = new_decisions.len();
                let n_del = deleted_decisions.len();

                cache.apply_stream(stream, &config);

                // LAPI answered. Even an empty decision set is a real answer
                // ("nobody is banned"), so the bouncer is no longer blind and
                // `fallback_action` stops applying.
                health.observe(true, cache.stats().total_cached);

                if need_full_pull {
                    // The full pull is the complete active set, so anything the
                    // mirror put in the cache and this pull did not confirm was
                    // revoked upstream while we were not listening.
                    let dropped = cache.drop_unconfirmed_restored();
                    unconfirmed = 0;
                    need_full_pull = false;
                    info!(
                        loaded = n_new,
                        dropped_stale_restored = dropped,
                        cached = cache.stats().total_cached,
                        "CrowdSec full pull applied; local decisions now confirmed against LAPI",
                    );
                    persist_full(store.as_deref(), &new_decisions, &config).await;
                } else if n_new > 0 || n_del > 0 {
                    info!(new = n_new, deleted = n_del, "CrowdSec incremental update");
                    persist_delta(store.as_deref(), &new_decisions, &deleted_decisions, &config).await;
                }
            }
            Err(e) => report_pull_failure(&e, need_full_pull, &cache, unconfirmed, &config, &health),
        }

        // Periodic cleanup of expired entries
        if last_cleanup.elapsed() >= cleanup_interval {
            cache.cleanup_expired();
            last_cleanup = tokio::time::Instant::now();
        }
    }
}

/// Mirror the complete active decision set, replacing whatever was there.
async fn persist_full(store: Option<&dyn DecisionStore>, new_decisions: &[Decision], config: &CrowdSecConfig) {
    let Some(store) = store else { return };
    let (rows, oversized) = rows_for(new_decisions, config, Utc::now());
    warn_oversized(oversized);
    match store.replace_all(&rows).await {
        Ok(removed) => info!(
            mirrored = rows.len(),
            removed_stale = removed,
            "CrowdSec decision mirror rebuilt from the full LAPI pull",
        ),
        Err(e) => report_mirror_failure("replace_all", &e),
    }
}

/// Mirror one incremental delta: upsert what was added, delete what was lifted.
///
/// Deletions run **first**: if the upsert fails, the worst case is a mirror
/// missing a ban (which the next full pull re-adds); if a deletion were skipped,
/// the mirror would keep a lifted ban and resurrect it on the next restart.
async fn persist_delta(
    store: Option<&dyn DecisionStore>,
    new_decisions: &[Decision],
    deleted_decisions: &[Decision],
    config: &CrowdSecConfig,
) {
    let Some(store) = store else { return };

    if !deleted_decisions.is_empty() {
        let keys = delete_keys_for(deleted_decisions);
        if let Err(e) = store.delete(&keys).await {
            report_mirror_failure("delete", &e);
        }
    }

    if !new_decisions.is_empty() {
        let (rows, oversized) = rows_for(new_decisions, config, Utc::now());
        warn_oversized(oversized);
        if !rows.is_empty()
            && let Err(e) = store.upsert(&rows).await
        {
            report_mirror_failure("upsert", &e);
        }
    }
}

/// Report decisions dropped because a field overflowed its mirror column.
fn warn_oversized(oversized: usize) {
    if oversized > 0 {
        warn!(
            dropped = oversized,
            "CrowdSec decisions skipped by the local mirror: a field exceeds its column width. They still enforce from the \
             in-memory cache, but they will not survive a restart",
        );
    }
}

/// Report a failed LAPI pull at the severity the *current enforcement posture*
/// deserves.
///
/// A failed pull with a populated cache is a nuisance: decisions keep being
/// enforced from memory. A failed pull with an **empty** cache is the fail-open
/// state itself — no IP can match, so every previously banned client is being
/// allowed through — and it is logged at `error!` with that consequence spelled
/// out, because it is the exact moment an operator needs to see.
///
/// That same split drives `health`: the `error!` branch is the definition of
/// degraded, the `warn!` branch is explicitly not. Publishing it here rather
/// than only logging it is what lets `crowdsec.fallback_action` do anything at
/// all.
fn report_pull_failure(
    error: &anyhow::Error,
    was_full_pull: bool,
    cache: &DecisionCache,
    unconfirmed: usize,
    config: &CrowdSecConfig,
    health: &CrowdSecHealth,
) {
    let cached = cache.stats().total_cached;
    health.observe(false, cached);
    let kind = if was_full_pull { "full" } else { "incremental" };
    if cached == 0 {
        // The bouncer matching nothing is a constant; what it *does* about that
        // is the operator's choice, so name the posture actually in force rather
        // than assuming the fail-open default.
        let posture = match config.fallback_action {
            FallbackAction::Allow => {
                "FAIL-OPEN: every previously banned client is being allowed through (crowdsec.fallback_action=allow)"
            }
            FallbackAction::Block => {
                "FAIL-CLOSED: crowdsec.fallback_action=block, so every request is being REFUSED until LAPI answers"
            }
            FallbackAction::Log => {
                "FAIL-OPEN: every previously banned client is being allowed through; crowdsec.fallback_action=log records \
                 one security event per request instead of blocking"
            }
        };
        error!(
            error = %error,
            lapi_url = %config.lapi_url,
            pull = kind,
            retry_secs = config.update_frequency_secs.max(5),
            fallback_action = ?config.fallback_action,
            "CrowdSec is {posture}. The {kind} LAPI pull failed and the decision cache is EMPTY, so the bouncer matches no \
             IP at all. Nothing was restored from the local crowdsec_decisions mirror either (it was empty, disabled, or \
             unreadable). Retrying until LAPI answers",
        );
    } else {
        warn!(
            error = %error,
            lapi_url = %config.lapi_url,
            pull = kind,
            cached,
            unconfirmed_from_mirror = unconfirmed,
            "CrowdSec {kind} LAPI pull failed; the bouncer keeps enforcing {cached} cached decisions ({unconfirmed} of them \
             restored from the local mirror and not yet confirmed against LAPI). Decisions added or lifted upstream since \
             the last successful pull are not reflected",
        );
    }
}
