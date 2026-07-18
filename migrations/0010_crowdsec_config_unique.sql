-- Fix M-11: `upsert_crowdsec_config` conflicted on the SERIAL primary key
-- `id`, which the INSERT never supplies, so `ON CONFLICT (id)` never fired
-- and every "update" was silently a fresh INSERT. `get_crowdsec_config` then
-- always read back the oldest (first-ever) row, so config changes appeared
-- to have no effect and the table grew without bound.
--
-- Fix: enforce at most one config row per scope (global, or per host_id) via
-- a functional unique index on COALESCE(host_id, <nil-uuid>), after
-- de-duplicating any rows that already violate it (keep the most recently
-- updated row per scope; ties broken by the highest id).

BEGIN;

DELETE FROM crowdsec_config c
USING crowdsec_config newer
WHERE COALESCE(c.host_id, '00000000-0000-0000-0000-000000000000'::uuid)
    = COALESCE(newer.host_id, '00000000-0000-0000-0000-000000000000'::uuid)
  AND (c.updated_at, c.id) < (newer.updated_at, newer.id);

CREATE UNIQUE INDEX IF NOT EXISTS ux_crowdsec_config_scope
    ON crowdsec_config ((COALESCE(host_id, '00000000-0000-0000-0000-000000000000'::uuid)));

COMMIT;
