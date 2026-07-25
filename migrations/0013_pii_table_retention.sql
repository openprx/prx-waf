-- Retention (TTL) contract for the remaining observability / PII tables.
--
-- `0012` recorded the contract for `semantic_observations`. The same problem
-- existed on four more tables that are written on the request or admin path and
-- all store an IP address, none of which had any cleanup call site:
--
--   security_events   client_ip, method, path, geo        (rule detections)
--   attack_logs       client_ip, path, query, headers     (blocked/logged reqs)
--   audit_log         admin_username, ip_addr             (admin mutations)
--   crowdsec_events   client_ip, scenario, request_path   (CrowdSec decisions)
--
-- Retention stays enforced application-side by
-- `Database::prune_retention_table`, which runs a batched, fully parameterised
--   DELETE FROM <t> WHERE ctid IN (SELECT ctid FROM <t> WHERE created_at < $1 LIMIT $2)
-- in a loop until the expired set is drained. The table name comes from a
-- closed Rust enum (a table name cannot be a bind parameter), and the cutoff and
-- batch size are bound parameters, so no configuration value reaches the
-- statement text.
--
-- INDEX AUDIT: the `created_at` predicate above must not degrade into a
-- sequential scan on a large table. Every table already ships a `created_at`
-- index, so this migration adds none:
--
--   security_events        idx_security_events_created_at   (0002)
--   attack_logs            idx_attack_logs_created_at       (0001)
--   audit_log              idx_audit_log_created_at         (0005)
--   crowdsec_events        idx_cs_events_created            (0006)
--   semantic_observations  idx_semantic_observations_created_at (0011)
--
-- All five are `(created_at DESC)`, which Postgres scans in either direction, so
-- the `created_at < $cutoff` subquery is an index range scan that stops at the
-- LIMIT rather than reading the whole table. The `CREATE INDEX IF NOT EXISTS`
-- statements below are therefore no-ops on any database that has run the
-- migrations above; they exist so a database restored from a partial dump, or
-- one where an index was dropped by hand, cannot silently leave the pruner
-- doing full scans.
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_logs_created_at     ON attack_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at       ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cs_events_created          ON crowdsec_events (created_at DESC);

-- Record the policy at the schema level, so a DBA inspecting the table sees it.
-- The concrete window is supplied by the caller from `[storage]`, never
-- hard-coded here, so operators tune it without a schema change. `COMMENT ON` is
-- idempotent, so re-running this migration is a no-op.
COMMENT ON TABLE security_events IS
    'Rule-detection events (client_ip, method, path, geo). Retention/TTL is enforced application-side by prune_retention_table (batched DELETE WHERE created_at < now() - storage.security_event_retention_days); rows are not retained indefinitely.';
COMMENT ON COLUMN security_events.created_at IS
    'Insertion time and the retention key: rows older than the configured window are deleted.';

COMMENT ON TABLE attack_logs IS
    'Blocked/logged requests (client_ip, path, query, captured request headers). Retention/TTL is enforced application-side by prune_retention_table (batched DELETE WHERE created_at < now() - storage.attack_log_retention_days); rows are not retained indefinitely.';
COMMENT ON COLUMN attack_logs.created_at IS
    'Insertion time and the retention key: rows older than the configured window are deleted.';

COMMENT ON TABLE audit_log IS
    'Mutating admin API calls (admin_username, admin source ip_addr). Retention/TTL is enforced application-side by prune_retention_table (batched DELETE WHERE created_at < now() - storage.audit_log_retention_days). The default window is deliberately longer than the telemetry tables: this is accountability data about a known internal population, and one year is the common compliance floor.';
COMMENT ON COLUMN audit_log.created_at IS
    'Insertion time and the retention key: rows older than the configured window are deleted.';

COMMENT ON TABLE crowdsec_events IS
    'Local echo of CrowdSec decisions (client_ip, scenario, request_path); the CrowdSec LAPI holds the authoritative history. Retention/TTL is enforced application-side by prune_retention_table (batched DELETE WHERE created_at < now() - storage.crowdsec_event_retention_days).';
COMMENT ON COLUMN crowdsec_events.created_at IS
    'Insertion time and the retention key: rows older than the configured window are deleted.';
