-- Retention (TTL) contract for four more tables that had no cleanup path:
--
--   crowdsec_decisions  value (client IP when scope='Ip'), scenario, expiry   PII, unbounded growth
--   refresh_tokens      token_hash, per-admin auth material                  security-sensitive
--   notification_log    message/error_msg free text (may embed a client_ip)  possible PII
--   request_stats       host_code + aggregated counters only                 no PII, low priority
--
-- All four are covered by the same batched, fully parameterised pruner as
-- `0013` (`Database::prune_retention_table`, closed `RetentionTable` enum, no
-- dynamic SQL). Two of them are keyed on a column other than `created_at`:
--
--   crowdsec_decisions.expires_at  — the decision's own expiry, not the row's
--                                    insertion time; a decision has zero value
--                                    once CrowdSec itself has stopped enforcing
--                                    it, whether it was inserted an hour or a
--                                    year ago.
--   request_stats.period_start     — the aggregation bucket's timestamp.
--
-- `refresh_tokens` is keyed on `expires_at` OR `revoked`: a revoked token is
-- dead the instant it is revoked, regardless of how far in the future
-- `expires_at` still is, so the prune predicate does not wait for the
-- window when `revoked = TRUE`.
--
-- INDEX AUDIT:
--
--   crowdsec_decisions.expires_at  idx_cs_decisions_expires    (0006) — present
--   request_stats.period_start     idx_request_stats_period_start (0004) — present
--   refresh_tokens.expires_at      idx_refresh_tokens_expires_at (0004) — present
--   notification_log.created_at    idx_notification_log_created_at (0004) — present
--
-- `refresh_tokens` is the one gap: the prune predicate is
-- `WHERE expires_at < $1 OR revoked = TRUE`, and while the `expires_at` half
-- is covered by the existing index, there was no index at all on `revoked`,
-- so the `revoked = TRUE` half would fall back to a sequential scan. Almost
-- every row has `revoked = FALSE` (a token is revoked only on explicit
-- logout/rotation), so a *partial* index over just the revoked subset is the
-- right shape: it stays tiny regardless of how large the table grows, and lets
-- Postgres combine it with the `expires_at` index via a bitmap OR instead of
-- scanning the whole table.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked
    ON refresh_tokens (revoked)
    WHERE revoked = TRUE;

-- The `CREATE INDEX IF NOT EXISTS` statements below for the already-indexed
-- columns are defensive no-ops (same rationale as `0013`): a database restored
-- from a partial dump, or one where an index was dropped by hand, must not
-- silently leave the pruner doing full scans.
CREATE INDEX IF NOT EXISTS idx_cs_decisions_expires        ON crowdsec_decisions (expires_at);
CREATE INDEX IF NOT EXISTS idx_request_stats_period_start  ON request_stats (period_start DESC);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at   ON refresh_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_notification_log_created_at ON notification_log (created_at DESC);

-- Record the policy at the schema level. The concrete window is supplied by
-- the caller from `[storage]`, never hard-coded here. `COMMENT ON` is
-- idempotent, so re-running this migration is a no-op.
COMMENT ON TABLE crowdsec_decisions IS
    'Cached CrowdSec LAPI decisions (value holds the banned client IP when scope=''Ip''). Retention/TTL is enforced application-side by prune_retention_table (batched DELETE WHERE expires_at < now() - storage.crowdsec_decision_retention_days). A NULL expires_at (no known expiry) is never matched by "<" and is therefore never pruned by this policy.';
COMMENT ON COLUMN crowdsec_decisions.expires_at IS
    'The retention key: this is the decision''s own expiry, not row insertion time. Rows whose expires_at is older than the configured window are deleted; a decision that is still active (or has no known expiry) is left alone regardless of created_at.';

COMMENT ON TABLE refresh_tokens IS
    'JWT refresh token hashes. Retention/TTL is enforced application-side by prune_retention_table (batched DELETE WHERE expires_at < now() - storage.refresh_token_retention_days OR revoked = TRUE): a revoked token is deleted immediately regardless of the window, since it can never be redeemed again.';
COMMENT ON COLUMN refresh_tokens.expires_at IS
    'The retention key for tokens that were never revoked: rows older than the configured window past their own expiry are deleted.';
COMMENT ON COLUMN refresh_tokens.revoked IS
    'A revoked token is deleted by the retention pruner on the next sweep regardless of expires_at, since a revoked token hash has no further authentication value.';

COMMENT ON TABLE notification_log IS
    'Notification delivery records. message/error_msg are free text supplied by the triggering event and may embed a client_ip. Retention/TTL is enforced application-side by prune_retention_table (batched DELETE WHERE created_at < now() - storage.notification_log_retention_days).';
COMMENT ON COLUMN notification_log.created_at IS
    'Insertion time and the retention key: rows older than the configured window are deleted.';

COMMENT ON TABLE request_stats IS
    'Aggregated per-host request/block counters (no personal data). Retention/TTL is enforced application-side by prune_retention_table (batched DELETE WHERE period_start < now() - storage.request_stats_retention_days).';
COMMENT ON COLUMN request_stats.period_start IS
    'The retention key: the aggregation bucket''s own timestamp, not row insertion time. Rows older than the configured window are deleted.';
