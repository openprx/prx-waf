-- Lane 2 semantic content-security observations (plan v2.2 §13.1).
--
-- A dedicated table (NOT extra columns on `security_events`) so semantic
-- telemetry — score / degraded / per-signal breakdown — never bloats the main
-- security-event row. Signals are stored de-identified in a versioned JSONB
-- column (detector / attack / field / scope / confidence / rule_key /
-- provenance) and never the raw payload.
--
-- P1a ships this schema + storage model + repo as the observation persistence
-- foundation. There are no production detectors in P1a, so no rows are written
-- on the hot path yet; the hot-path insert lands with the P1 detectors.
-- Domain CHECK constraints (codex A-5): the score / scope / recommendation /
-- schema_version domains and the JSONB array shape are enforced at the database
-- so a same-crate caller can never persist out-of-range or malformed telemetry
-- (score 32767, an unknown action, a non-array `observations`, etc.). Named so
-- a later migration can alter them if the vocabulary grows.
CREATE TABLE IF NOT EXISTS semantic_observations (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code      TEXT NOT NULL,
    client_ip      TEXT NOT NULL,
    req_id         TEXT NOT NULL,
    scope          TEXT NOT NULL,              -- 'header' | 'body'
    request_score  SMALLINT NOT NULL,          -- 0..=100
    recommendation TEXT NOT NULL,              -- 'block' | 'log' | 'none'
    degraded       BOOLEAN NOT NULL DEFAULT FALSE,
    exhausted      BOOLEAN NOT NULL DEFAULT FALSE,
    pipeline       TEXT NOT NULL DEFAULT 'semantic',
    schema_version INTEGER NOT NULL DEFAULT 1,
    observations   JSONB NOT NULL,             -- de-identified signals[]
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT semantic_observations_request_score_range
        CHECK (request_score BETWEEN 0 AND 100),
    CONSTRAINT semantic_observations_scope_domain
        CHECK (scope IN ('header', 'body')),
    CONSTRAINT semantic_observations_recommendation_domain
        CHECK (recommendation IN ('block', 'log', 'none')),
    CONSTRAINT semantic_observations_schema_version_positive
        CHECK (schema_version > 0),
    CONSTRAINT semantic_observations_observations_is_array
        CHECK (jsonb_typeof(observations) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_semantic_observations_host_code  ON semantic_observations (host_code);
CREATE INDEX IF NOT EXISTS idx_semantic_observations_created_at ON semantic_observations (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_semantic_observations_score      ON semantic_observations (request_score DESC);
