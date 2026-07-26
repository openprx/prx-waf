-- Phase 7 stage 2: make `rule_overrides` usable as the per-rule enable/disable
-- store the engine now reads.
--
-- The 0007 table has been carried since Phase 7 landed with zero Rust
-- references. Two things have to change before it can back a request-path
-- decision.
--
-- 1. UNIQUE (rule_id, host_id) does NOT constrain the global rows. Postgres
--    treats NULLs as distinct in a unique constraint, so `('CRS-942100', NULL)`
--    can be inserted any number of times. Every one of those rows would be read
--    at load time and the last one seen would win, which makes "disable this
--    rule" and "re-enable this rule" both true at once and the outcome depend on
--    row order. A partial unique index over the global rows is the fix; the
--    original constraint stays and keeps doing its job for the host-scoped ones.
--
-- 2. An override that names neither `enabled` nor `action_override` changes
--    nothing, and one that both disables a rule and gives it an action is
--    contradictory. Both are refused at the API boundary
--    (`RuleState::from_row`), and the check is restated here so a row written
--    straight into the database cannot create a state the engine has to guess
--    about.
--
-- `action_override` is constrained to the two spellings the request path can
-- carry out. `deny` is deliberately absent: escalating a scoring rule to an
-- unconditional block is a different and larger decision than softening one,
-- and storing it would be a promise the engine does not keep.
--
-- The CHECKs are added NOT VALID. Nothing has ever written this table (it had
-- no reader and no writer in any release), so in practice there is nothing to
-- validate; NOT VALID means that if a hand-written row does exist somewhere, an
-- upgrade refuses the *next* bad write instead of refusing to boot. The unique
-- index is deliberately NOT given that latitude: two contradictory global rows
-- for one rule is an ambiguity the request path cannot resolve, and failing the
-- migration is the correct answer to it.

CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_overrides_global
    ON rule_overrides (rule_id)
    WHERE host_id IS NULL;

ALTER TABLE rule_overrides
    DROP CONSTRAINT IF EXISTS rule_overrides_meaningful;
ALTER TABLE rule_overrides
    ADD CONSTRAINT rule_overrides_meaningful
    CHECK (enabled IS NOT NULL OR action_override IS NOT NULL) NOT VALID;

ALTER TABLE rule_overrides
    DROP CONSTRAINT IF EXISTS rule_overrides_not_contradictory;
ALTER TABLE rule_overrides
    ADD CONSTRAINT rule_overrides_not_contradictory
    CHECK (enabled IS NOT FALSE OR action_override IS NULL) NOT VALID;

ALTER TABLE rule_overrides
    DROP CONSTRAINT IF EXISTS rule_overrides_action;
ALTER TABLE rule_overrides
    ADD CONSTRAINT rule_overrides_action
    CHECK (action_override IS NULL OR action_override IN ('log', 'block')) NOT VALID;
