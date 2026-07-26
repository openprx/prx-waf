-- Give operator-managed bot patterns a label.
--
-- 0007 shipped `bot_patterns` with `pattern` and a free-form `description` and
-- no name. A 500-character regex is not a label: the admin list, the CLI
-- listing and the detection detail all need a short human-readable identity for
-- the rule, and overloading `description` would mean either a table of prose or
-- a table with no explanation. The built-in catalogue in
-- `waf-engine/src/checks/bot.rs` has carried `name` since it existed; this makes
-- the operator rows describable the same way.
--
-- Backfilled from `description`, then the pattern, so pre-existing rows (there
-- are none in any shipped deployment — the table had no Rust reader or writer
-- before this change) still list sensibly.
ALTER TABLE bot_patterns ADD COLUMN IF NOT EXISTS name VARCHAR(100) NOT NULL DEFAULT '';

UPDATE bot_patterns
   SET name = LEFT(COALESCE(NULLIF(description, ''), pattern), 100)
 WHERE name = '';
