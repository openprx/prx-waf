-- Phase 3: SSL Certificates, Custom Rules, Sensitive Patterns, Hotlink Configs, LB Backends

-- SSL/TLS Certificates managed by the WAF
CREATE TABLE IF NOT EXISTS certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code       VARCHAR(32)  NOT NULL,
    domain          VARCHAR(253) NOT NULL,
    cert_pem        TEXT,
    key_pem         TEXT,
    chain_pem       TEXT,
    issuer          VARCHAR(256),
    subject         VARCHAR(256),
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    auto_renew      BOOLEAN      NOT NULL DEFAULT TRUE,
    acme_account    JSONB,
    status          VARCHAR(20)  NOT NULL DEFAULT 'pending',
    error_msg       TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certificates_host_code ON certificates (host_code);
CREATE INDEX IF NOT EXISTS idx_certificates_domain    ON certificates (domain);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates (not_after);
CREATE INDEX IF NOT EXISTS idx_certificates_status    ON certificates (status);

-- Custom WAF rules with condition/action model
CREATE TABLE IF NOT EXISTS custom_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code       VARCHAR(32)  NOT NULL,
    name            VARCHAR(128) NOT NULL,
    description     TEXT,
    priority        INTEGER      NOT NULL DEFAULT 100,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    condition_op    VARCHAR(3)   NOT NULL DEFAULT 'and',
    conditions      JSONB        NOT NULL DEFAULT '[]',
    action          VARCHAR(20)  NOT NULL DEFAULT 'block',
    action_status   INTEGER      NOT NULL DEFAULT 403,
    action_msg      TEXT,
    script          TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_rules_host_code ON custom_rules (host_code);
CREATE INDEX IF NOT EXISTS idx_custom_rules_priority  ON custom_rules (host_code, priority);
CREATE INDEX IF NOT EXISTS idx_custom_rules_enabled   ON custom_rules (enabled);

-- Sensitive word / data-leak patterns
CREATE TABLE IF NOT EXISTS sensitive_patterns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code       VARCHAR(32)  NOT NULL,
    pattern         TEXT         NOT NULL,
    pattern_type    VARCHAR(20)  NOT NULL DEFAULT 'word',
    check_request   BOOLEAN      NOT NULL DEFAULT TRUE,
    check_response  BOOLEAN      NOT NULL DEFAULT FALSE,
    action          VARCHAR(20)  NOT NULL DEFAULT 'block',
    remarks         TEXT,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sensitive_patterns_host_code ON sensitive_patterns (host_code);
CREATE INDEX IF NOT EXISTS idx_sensitive_patterns_enabled   ON sensitive_patterns (enabled);

-- Anti-hotlinking configuration per host
CREATE TABLE IF NOT EXISTS hotlink_configs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code           VARCHAR(32)  NOT NULL UNIQUE,
    enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
    allow_empty_referer BOOLEAN      NOT NULL DEFAULT TRUE,
    allowed_domains     JSONB        NOT NULL DEFAULT '[]',
    redirect_url        TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hotlink_configs_host_code ON hotlink_configs (host_code);

-- Load balancer backends per host
CREATE TABLE IF NOT EXISTS lb_backends (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code                   VARCHAR(32)  NOT NULL,
    backend_host                VARCHAR(253) NOT NULL,
    backend_port                INTEGER      NOT NULL,
    weight                      INTEGER      NOT NULL DEFAULT 1,
    enabled                     BOOLEAN      NOT NULL DEFAULT TRUE,
    health_check_url            TEXT,
    health_check_interval_secs  INTEGER      NOT NULL DEFAULT 30,
    last_health_check           TIMESTAMPTZ,
    is_healthy                  BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lb_backends_host_code ON lb_backends (host_code);
CREATE INDEX IF NOT EXISTS idx_lb_backends_enabled   ON lb_backends (host_code, enabled);
