# PRX-WAF

> High-performance WAF built on Pingora

<!-- Badges placeholder -->
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-2024--edition-orange)
![PostgreSQL](https://img.shields.io/badge/postgresql-16%2B-blue)

PRX-WAF is a production-ready Web Application Firewall proxy built on [Pingora](https://github.com/cloudflare/pingora) (Cloudflare's Rust HTTP proxy library). It combines multi-phase attack detection, a Rhai scripting engine, ModSecurity rule support, CrowdSec integration, WASM plugins, and a Vue 3 admin UI into a single deployable binary.

---

## Features

- **Pingora reverse proxy** — HTTP/1.1, HTTP/2, HTTP/3 via QUIC (Quinn); weighted round-robin load balancing
- **10+ attack detection checkers** — SQL injection, XSS, RFI/LFI, SSRF, path traversal, command injection, scanner detection, protocol violations
- **CC/DDoS protection** — sliding-window rate limiting per IP with configurable thresholds
- **Rhai scripting engine** — write custom detection rules in a sandboxed scripting language
- **OWASP CRS rule support** — load and manage OWASP Core Rule Set in YAML format
- **ModSecurity rule parser** — import SecRule directives (basic subset: ARGS, REQUEST_HEADERS, REQUEST_URI, REQUEST_BODY)
- **Rule hot-reload** — file watcher (notify) + SIGHUP handler; rules reload atomically without downtime
- **Sensitive word detection** — Aho-Corasick multi-pattern matching for PII / credential leakage
- **Anti-hotlinking protection** — Referer-based validation per host
- **CrowdSec integration** — Bouncer (decision cache from LAPI) + AppSec (remote HTTP inspection) + Log Pusher
- **WASM plugin system** — sandboxed wasmtime runtime for custom logic
- **SSL/TLS automation** — Let's Encrypt via instant-acme (ACME v2); auto-renewal
- **Tunnel / Zero-Trust access** — WebSocket-based reverse tunnel (Cloudflare Tunnel-style)
- **Response caching** — moka LRU in-memory cache with TTL and size limits
- **PostgreSQL 16+ storage** — all configuration, rules, logs, and stats persisted
- **Vue 3 Admin UI** — JWT + TOTP authentication; real-time WebSocket monitoring; embedded in the binary
- **Real-time WebSocket monitoring** — live traffic stats and security event stream
- **Notification system** — Email (SMTP), Webhook, Telegram alerts
- **AES-256-GCM encryption at rest** — sensitive config values (API keys, passwords) encrypted in PostgreSQL
- **Docker & systemd deployment** — Docker Compose files and systemd unit examples included

---

## Quick Start

### Docker Compose

```bash
git clone https://github.com/openprx/prx-waf
cd prx-waf

# Edit environment variables in docker-compose.yml (DB password, etc.)
docker compose up -d

# Admin UI: http://localhost:9527
# Default credentials: admin / admin  (change immediately)
```

### Manual Build

**Prerequisites:** Rust 1.82+, PostgreSQL 16+

```bash
# Clone
git clone https://github.com/openprx/prx-waf
cd prx-waf

# Build release binary
cargo build --release

# Create database
createdb prx_waf
createuser prx_waf

# Run migrations and seed admin user
./target/release/prx-waf -c configs/default.toml migrate
./target/release/prx-waf -c configs/default.toml seed-admin

# Start the proxy + API server
./target/release/prx-waf -c configs/default.toml run
```

---

## CLI Reference

```
prx-waf [OPTIONS] <COMMAND>

Options:
  -c, --config <FILE>   Config file path [default: configs/default.toml]

Commands:
  run          Start proxy + management API (blocks forever)
  migrate      Run database migrations only
  seed-admin   Create default admin user (admin/admin)
  crowdsec     CrowdSec integration management
  rules        Rule management (list, load, validate, hot-reload)
  sources      Rule source management (add, remove, sync)
  bot          Bot detection management (list, add, test)
```

### CrowdSec Commands

```bash
prx-waf crowdsec status             # Show integration status
prx-waf crowdsec decisions          # List active decisions from LAPI
prx-waf crowdsec test               # Test LAPI connectivity
prx-waf crowdsec setup              # Interactive setup wizard
```

### Rule Management Commands

```bash
# Rule operations
prx-waf rules list                        # List all loaded rules
prx-waf rules list --category sqli        # Filter by category
prx-waf rules list --source owasp         # Filter by source
prx-waf rules info <rule-id>              # Show rule details
prx-waf rules enable <rule-id>            # Enable a rule
prx-waf rules disable <rule-id>           # Disable a rule
prx-waf rules reload                      # Hot-reload all rules from disk
prx-waf rules validate <path>             # Validate a rule file
prx-waf rules import <path|url>           # Import rules from file or URL
prx-waf rules export [--format yaml]      # Export current rules
prx-waf rules update                      # Fetch latest from remote sources
prx-waf rules search <query>              # Search rules by name/description
prx-waf rules stats                       # Rule statistics

# Source management
prx-waf sources list                      # List configured rule sources
prx-waf sources add <name> <url>          # Add a remote rule source
prx-waf sources remove <name>             # Remove a rule source
prx-waf sources update [name]             # Fetch latest from source
prx-waf sources sync                      # Sync all sources

# Bot detection
prx-waf bot list                          # List known bot signatures
prx-waf bot add <pattern> [--action block|captcha|log]
prx-waf bot remove <pattern>
prx-waf bot test <user-agent>             # Test a user-agent against bot rules
```

---

## Configuration

Configuration is loaded from a TOML file (default: `configs/default.toml`).

```toml
[proxy]
listen_addr     = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"
worker_threads  = 4          # optional, defaults to CPU count

[api]
listen_addr = "127.0.0.1:9527"

[storage]
database_url    = "postgresql://prx_waf:prx_waf@127.0.0.1:5432/prx_waf"
max_connections = 20

[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
max_ttl_secs     = 3600

[http3]
enabled     = false
listen_addr = "0.0.0.0:443"
cert_pem    = "/etc/ssl/certs/server.pem"
key_pem     = "/etc/ssl/private/server.key"

[security]
admin_ip_allowlist      = []        # empty = allow all
max_request_body_bytes  = 10485760  # 10 MB
api_rate_limit_rps      = 100
cors_origins            = []

# --- Rule Management ---
[rules]
dir                    = "rules/"   # rules directory to watch
hot_reload             = true       # enable file watching
reload_debounce_ms     = 500
enable_builtin_owasp   = true       # built-in OWASP CRS subset
enable_builtin_bot     = true       # built-in bot detection
enable_builtin_scanner = true       # built-in scanner detection

# Remote rule sources
[[rules.sources]]
name   = "custom"
path   = "rules/custom/"
format = "yaml"

[[rules.sources]]
name            = "owasp-crs"
url             = "https://example.com/rules/owasp.yaml"
format          = "yaml"
update_interval = 86400  # 24h in seconds

# --- CrowdSec Integration ---
[crowdsec]
enabled               = false
mode                  = "bouncer"   # bouncer | appsec | both
lapi_url              = "http://127.0.0.1:8080"
api_key               = ""
update_frequency_secs = 10
fallback_action       = "allow"     # allow | block | log

# Optional: AppSec endpoint
# appsec_endpoint = "http://127.0.0.1:7422"
# appsec_key      = "<appsec-key>"

# --- Static hosts (also managed via Admin UI / DB) ---
# [[hosts]]
# host        = "example.com"
# port        = 80
# remote_host = "127.0.0.1"
# remote_port = 8080
# ssl         = false
# guard_status = true
```

---

## Rule Management

PRX-WAF supports multiple rule formats and sources. Rules are loaded at startup and can be hot-reloaded without downtime.

### Rule Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| YAML | `.yaml`, `.yml` | Native PRX-WAF format |
| ModSecurity | `.conf` | SecRule directives (basic subset) |
| JSON | `.json` | JSON array of rule objects |

### YAML Rule Format

```yaml
- id: "CUSTOM-001"
  name: "Block admin path"
  description: "Block access to /admin from untrusted IPs"
  category: "access-control"
  source: "custom"
  enabled: true
  action: "block"
  severity: "high"
  pattern: "^/admin"
  tags:
    - "admin"
    - "access-control"
```

### ModSecurity Rule Format (basic subset)

```apache
SecRule REQUEST_URI "@rx /admin" \
    "id:1001,phase:1,deny,status:403,msg:'Admin path blocked'"

SecRule ARGS "@contains <script>" \
    "id:1002,phase:2,deny,status:403,msg:'XSS attempt'"
```

### Hot-Reload

PRX-WAF watches the `rules/` directory for file changes and automatically reloads rules when a file is created, modified, or deleted. Changes take effect within the configured debounce window (default: 500ms).

You can also trigger a reload manually:

```bash
# Via CLI
prx-waf rules reload

# Via SIGHUP (Unix only)
kill -HUP <prx-waf-pid>
```

### Built-in Rules

Built-in rules are compiled into the binary and loaded automatically (configurable):

- **OWASP CRS** — Common attack signatures (SQLi, XSS, RCE, scanner detection)
- **Bot Detection** — Known malicious bots, AI crawlers, headless browsers
- **Scanner Detection** — Vulnerability scanner fingerprints (Nmap, Nikto, etc.)

---

## Architecture

PRX-WAF is organized as a 6-crate Cargo workspace:

```
prx-waf/
├── crates/
│   ├── prx-waf/        Binary: CLI entry point, server bootstrap
│   ├── gateway/        Pingora proxy, HTTP/3, SSL automation, caching, tunnels
│   ├── waf-engine/     Detection pipeline, rules engine, checks, plugins, CrowdSec
│   ├── waf-storage/    PostgreSQL layer (sqlx), migrations, models
│   ├── waf-api/        Axum REST API, JWT/TOTP auth, WebSocket, static UI
│   └── waf-common/     Shared types: RequestCtx, WafDecision, HostConfig, config
├── migrations/         SQL migration files (0001–0007)
├── configs/            Example TOML config files
├── rules/              Rule files directory (YAML, ModSec, JSON)
└── web/admin-ui/       Vue 3 admin SPA (served embedded in waf-api)
```

### Request Flow

```
Client Request
    │
    ▼
Pingora Listener (TCP/TLS/QUIC)
    │
    ▼
WafEngine Pipeline (16 phases)
    ├── Phase 1-4:  IP/URL whitelist + blacklist (CIDR)
    ├── Phase 5:    CC/DDoS rate limiting
    ├── Phase 6:    Scanner detection
    ├── Phase 7:    Bot detection
    ├── Phase 8:    SQL injection
    ├── Phase 9:    XSS
    ├── Phase 10:   RCE / command injection
    ├── Phase 11:   Directory traversal
    ├── Phase 12:   Custom rules (Rhai scripts + JSON DSL)
    ├── Phase 13:   OWASP CRS
    ├── Phase 14:   Sensitive data detection
    ├── Phase 15:   Anti-hotlinking
    └── Phase 16:   CrowdSec bouncer + AppSec
    │
    ▼
HostRouter → Upstream (with load balancing)
```

---

## API Reference

The management API listens on `127.0.0.1:9527` by default. All endpoints (except `/api/auth/login`) require a JWT Bearer token.

### Authentication

```http
POST /api/auth/login
Content-Type: application/json

{"username": "admin", "password": "admin", "totp_code": "123456"}

→ {"token": "eyJ...", "refresh_token": "..."}
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/hosts` | List all hosts |
| POST | `/api/hosts` | Add a host |
| PUT | `/api/hosts/:id` | Update a host |
| DELETE | `/api/hosts/:id` | Delete a host |
| GET | `/api/rules/ip` | List IP rules |
| POST | `/api/rules/ip` | Add IP rule (allow/block) |
| GET | `/api/rules/url` | List URL rules |
| POST | `/api/rules/url` | Add URL rule |
| GET | `/api/rules/custom` | List custom rules |
| POST | `/api/rules/custom` | Create custom rule |
| GET | `/api/security-events` | List attack logs |
| GET | `/api/stats` | Request statistics |
| GET | `/api/crowdsec/decisions` | Active CrowdSec decisions |
| GET | `/api/plugins` | List WASM plugins |
| POST | `/api/plugins` | Upload WASM plugin |
| GET | `/api/tunnels` | List reverse tunnels |
| POST | `/api/tunnels` | Create tunnel |
| WS | `/ws/events` | Real-time security event stream |
| GET | `/health` | Health check |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes with tests
4. Run `cargo test` and `cargo clippy`
5. Submit a pull request

### Development Setup

```bash
# Install Rust (https://rustup.rs)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Node.js 18+ for the admin UI
# Install PostgreSQL 16+

# Start a local DB
createdb prx_waf && createuser -s prx_waf

# Build everything
cargo build

# Build admin UI
cd web/admin-ui && npm install && npm run build
```

### Code Structure

- All detection logic lives in `crates/waf-engine/src/checks/`
- New checks implement the `Check` trait from `checks/mod.rs`
- Database schema changes require a new migration in `migrations/`
- Admin UI components live in `web/admin-ui/src/views/`

---

## Links

- [Documentation](https://docs.openprx.dev/en/prx-waf/) — Full PRX-WAF documentation (10 languages)
- [Community](https://community.openprx.dev) — OpenPRX community forum
- [OpenPRX](https://openprx.dev) — Project homepage

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.
