-- Phase 6: CrowdSec integration tables

-- CrowdSec integration configuration (one row per global config, optionally scoped to a host)
CREATE TABLE IF NOT EXISTS crowdsec_config (
    id                      SERIAL PRIMARY KEY,
    host_id                 UUID REFERENCES hosts(id) ON DELETE SET NULL,
    enabled                 BOOLEAN NOT NULL DEFAULT false,
    mode                    VARCHAR(20) NOT NULL DEFAULT 'bouncer',
    lapi_url                VARCHAR(500),
    api_key_encrypted       VARCHAR(1000),
    appsec_endpoint         VARCHAR(500),
    appsec_key_encrypted    VARCHAR(1000),
    update_frequency_secs   INTEGER NOT NULL DEFAULT 10,
    fallback_action         VARCHAR(20) NOT NULL DEFAULT 'allow',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Cache of active CrowdSec decisions (synced from LAPI)
CREATE TABLE IF NOT EXISTS crowdsec_decisions (
    id          BIGINT PRIMARY KEY,
    origin      VARCHAR(50),
    scope       VARCHAR(50),
    value       VARCHAR(500),
    type        VARCHAR(50),
    scenario    VARCHAR(255),
    duration_secs BIGINT,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cs_decisions_value   ON crowdsec_decisions(value);
CREATE INDEX IF NOT EXISTS idx_cs_decisions_expires ON crowdsec_decisions(expires_at);

-- Log of CrowdSec-triggered WAF events
CREATE TABLE IF NOT EXISTS crowdsec_events (
    id              BIGSERIAL PRIMARY KEY,
    host_id         UUID REFERENCES hosts(id) ON DELETE SET NULL,
    client_ip       VARCHAR(45),
    decision_type   VARCHAR(50),
    scenario        VARCHAR(255),
    action_taken    VARCHAR(20),
    request_path    VARCHAR(2000),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cs_events_created ON crowdsec_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cs_events_ip      ON crowdsec_events(client_ip);
