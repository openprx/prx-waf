-- Add geo_info JSONB column to attack_logs for GeoIP data from IP/URL blacklist hits
ALTER TABLE attack_logs ADD COLUMN IF NOT EXISTS geo_info JSONB;

-- Indexes for geo queries on attack_logs
CREATE INDEX IF NOT EXISTS idx_attack_logs_geo_country ON attack_logs ((geo_info->>'country'));

-- Indexes for geo queries on security_events (geo_info column already exists)
CREATE INDEX IF NOT EXISTS idx_security_events_geo_country ON security_events ((geo_info->>'country'));
CREATE INDEX IF NOT EXISTS idx_security_events_geo_iso ON security_events ((geo_info->>'iso_code'));
