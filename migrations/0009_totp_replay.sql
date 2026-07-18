-- TOTP replay protection: track the highest one-time-password step already
-- consumed per admin user so a captured code cannot be reused.
ALTER TABLE admin_users
    ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0;
