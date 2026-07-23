-- Lane 2 semantic observation retention / TTL contract (plan v2.2 §13.1).
--
-- `0011` created `semantic_observations` with no cleanup path, so with shadow
-- telemetry enabled by default the table grows without bound. Retention is
-- enforced application-side by `Repositories::prune_semantic_observations`,
-- which runs a single parameterised `DELETE ... WHERE created_at < $cutoff`
-- where `$cutoff = now() - retention_days`. That time-range delete is already
-- served by the `idx_semantic_observations_created_at` index shipped in `0011`,
-- so this migration introduces no new index.
--
-- This migration records the retention contract at the schema level (a DBA
-- inspecting the table sees the policy) without altering any column, constraint
-- or the shadow posture. The concrete `retention_days` is supplied by the
-- caller, never hard-coded here, so operators can tune the window without a
-- schema change. `COMMENT ON` is idempotent, so re-running the migration is a
-- no-op.
COMMENT ON TABLE semantic_observations IS
    'Lane 2 semantic shadow telemetry. Retention/TTL is enforced application-side by prune_semantic_observations (DELETE WHERE created_at < now() - retention_days); rows are not retained indefinitely.';

COMMENT ON COLUMN semantic_observations.created_at IS
    'Insertion time and the retention key: prune_semantic_observations deletes rows whose created_at is older than the configured retention window.';
