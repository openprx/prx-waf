-- Phase 5: WASM Plugins, Tunnels, Audit Log

-- WASM plugin store
CREATE TABLE IF NOT EXISTS wasm_plugins (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    version     VARCHAR(64)  NOT NULL DEFAULT '1.0.0',
    description TEXT,
    author      VARCHAR(255),
    wasm_binary BYTEA        NOT NULL,
    enabled     BOOLEAN      NOT NULL DEFAULT true,
    config_json JSONB        NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (name)
);

-- Tunnel registry (Cloudflare-tunnel-style reverse tunnels)
CREATE TABLE IF NOT EXISTS tunnels (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    token_hash  VARCHAR(255) NOT NULL,   -- SHA-256 hex of the pre-shared key
    target_host VARCHAR(255) NOT NULL,
    target_port INTEGER      NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    enabled     BOOLEAN      NOT NULL DEFAULT true,
    status      VARCHAR(32)  NOT NULL DEFAULT 'disconnected',
    last_seen   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (name)
);

-- Admin audit log (all mutating admin API calls)
CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL    PRIMARY KEY,
    admin_username VARCHAR(255),
    action         VARCHAR(255) NOT NULL,
    resource_type  VARCHAR(128),
    resource_id    VARCHAR(255),
    detail         JSONB,
    ip_addr        VARCHAR(64),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_admin      ON audit_log (admin_username, created_at DESC);
