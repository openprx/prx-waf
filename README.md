# PRX-WAF

> High-performance WAF built on Pingora

<!-- Badges placeholder -->
[![CI](https://github.com/openprx/prx-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/openprx/prx-waf/actions/workflows/ci.yml)
[![Sec Audit](https://github.com/openprx/prx-waf/actions/workflows/sec-audit.yml/badge.svg?branch=main)](https://github.com/openprx/prx-waf/actions/workflows/sec-audit.yml)
![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)
![Rust](https://img.shields.io/badge/rust-2024--edition-orange)
![PostgreSQL](https://img.shields.io/badge/postgresql-16%2B-blue)

PRX-WAF is a production-ready Web Application Firewall proxy built on [Pingora](https://github.com/cloudflare/pingora) (Cloudflare's Rust HTTP proxy library). It combines multi-phase attack detection, a Rhai scripting engine, ModSecurity rule support, CrowdSec integration, WASM plugins, and a Vue 3 admin UI into a single deployable binary.

---

## Features

- **Pingora reverse proxy** — HTTP/1.1, HTTP/2, HTTP/3 via QUIC (Quinn); weighted round-robin load balancing
- **10+ attack detection checkers** — SQL injection, XSS, RFI/LFI, SSRF, path traversal, command injection, scanner detection, protocol violations
- **libinjection-based SQLi/XSS detection** — battle-tested libinjection fingerprint engine for accurate SQL injection and XSS detection with low false-positive rates
- **SSRF protection** — URL validation with public-IP enforcement and scheme-allowlist modes; blocks requests to RFC-1918 / loopback / link-local addresses
- **DNS rebinding guard** — IP pinning after initial DNS resolution prevents mid-request DNS rebinding attacks
- **Iterative URL decoding** — up to 5 rounds of percent-decoding before analysis, preventing double/triple-encoding bypass techniques
- **Remote rule source loading** — async fetch of rule sources with configurable size limits and timeouts; fails safe on unreachable sources
- **CC/DDoS protection** — sliding-window rate limiting per IP with configurable thresholds
- **Rhai scripting engine** — write custom detection rules in a sandboxed scripting language
- **OWASP CRS rule support** — load and manage OWASP Core Rule Set in YAML format
- **ModSecurity rule parser** — import SecRule directives (basic subset: ARGS, REQUEST_HEADERS, REQUEST_URI, REQUEST_BODY)
- **Override reload without downtime** — `POST /api/rules/reload` rebuilds the per-rule override layer in the running process; the CRS rule files themselves are compiled once at startup and need a restart
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
- **Docker & systemd deployment** — signed multi-arch images on `ghcr.io/openprx/prx-waf`, Docker Compose files and systemd unit examples included

---

## Quick Start

### Docker Compose

Every tagged release publishes a multi-arch (`linux/amd64` + `linux/arm64`)
image to `ghcr.io/openprx/prx-waf`, so nothing is compiled here.

```bash
git clone https://github.com/openprx/prx-waf
cd prx-waf

# Configure secrets in one place: copy the template and fill it in.
cp .env.example .env
# At minimum set JWT_SECRET and MASTER_KEY (each >= 32 chars). Generate with:
#   openssl rand -hex 32
# docker-compose refuses to start if these required secrets are missing.

docker compose up -d          # pulls ghcr.io/openprx/prx-waf:latest

# Admin UI: http://localhost:16827  (docker-compose.yml maps host 16827 -> container 9527)
# Default credentials: admin / <ADMIN_PASSWORD, or the random one printed to the
# logs on first start>  (change immediately)
```

The clone is for the compose file, `configs/` and `rules/`, which the compose
file bind-mounts; the WAF itself comes from the registry.

`latest` tracks the newest stable release and never a pre-release. Pin an exact
version in production:

```bash
PRX_WAF_VERSION=v0.2.60 docker compose up -d
```

The image is signed with [cosign](https://docs.sigstore.dev/) in keyless mode —
there is no long-lived signing key — and carries SLSA build provenance. Verify
before you run it:

```bash
cosign verify ghcr.io/openprx/prx-waf:v0.2.60 \
  --certificate-identity-regexp '^https://github\.com/openprx/prx-waf/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

gh attestation verify oci://ghcr.io/openprx/prx-waf:v0.2.60 --repo openprx/prx-waf
```

To run your own build instead of the published image:

```bash
cargo build --release
mkdir -p data      # Dockerfile.prebuilt copies data/; `prx-waf geoip download` fills it
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

All security-critical settings can be configured via `.env` / environment
variables — see [`.env.example`](.env.example) for the full, documented list
(required secrets, reverse-proxy trust, cluster, database). Environment values
override the matching TOML fields.

### Manual Build

**Prerequisites:** Rust 1.86+, PostgreSQL 16+

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
  seed-admin   Create default admin user (username: admin, password: $ADMIN_PASSWORD if set, else a random 24-char password printed once to stdout)
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

Reads report the rule set this build actually enforces (`rules/owasp-crs/`, with the operator
overrides from the database layered on), so they answer "what is this WAF doing" rather than
"what is in some file". Run them from the deployment root — the CRS path is relative to the
working directory.

```bash
# What is enforced, and in what state
prx-waf rules list                        # Every enforced rule + its effective state
prx-waf rules list --category sqli        # Filter by category
prx-waf rules list --source sqli          # Filter by source file
prx-waf rules list --state disabled       # active | disabled | log_only | overridden
prx-waf rules list --host <code>          # States in force for one host
prx-waf rules info <rule-id>              # One rule in detail (CRS-942100 or 942100)
prx-waf rules search <query>              # Same listing, filtered by id/name/category/source
prx-waf rules stats                       # Enforced/declared/rejected + override totals

# Changing a rule (writes an override row; see "Reloading" below)
prx-waf rules enable <rule-id>            # Cancel an override
prx-waf rules disable <rule-id>           # Stop evaluating the rule
prx-waf rules disable <rule-id> --log-only  # Keep evaluating + auditing, stop scoring

# Rule files
prx-waf rules validate <path>             # Parse-check a rule file (reads `[rules]`, not the enforced set)
prx-waf rules export [--format yaml] [--host CODE]
                                          # Dump the enforced set — same source as `list`/`stats`.
                                          # Inventory on stdout, everything else on stderr.
prx-waf rules import <path|url>           # Not implemented; exits non-zero
prx-waf rules update                      # Withheld pending supply-chain review; exits non-zero

# Source management
prx-waf sources list                      # Print the configured `[[rules.sources]]`
# add / remove / update / sync are not implemented: they exit non-zero and tell
# you to edit the config file instead of pretending to have a writable store.

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
worker_threads  = 4          # optional; unset or 0 = the CPUs this process may use

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

# --- Cluster ---
[cluster]
enabled     = false
node_id     = ""                  # auto-generated if empty
role        = "auto"              # auto | main | worker
listen_addr = "0.0.0.0:16851"    # QUIC inter-node communication
seeds       = []                  # seed node addresses

[cluster.crypto]
auto_generate = true

# --- CrowdSec Integration ---
[crowdsec]
enabled               = false
mode                  = "bouncer"   # bouncer | appsec | both
lapi_url              = "http://127.0.0.1:8080"
api_key               = ""
update_frequency_secs = 10
fallback_action       = "allow"     # allow | block | log — what the bouncer does
                                    # when LAPI is unreachable AND the decision
                                    # cache is empty (a stale-but-populated cache
                                    # keeps enforcing and does not trigger this).
                                    # "block" refuses every request during a LAPI
                                    # outage; keep "allow" unless you mean it.

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

### Reloading

Two different things can change, and they reload differently.

**Operator overrides** (`rules enable` / `rules disable`, the Admin UI, or a direct edit of the `rule_overrides` table) live in the database. A running process rebuilds that layer in place, with no dropped connections:

```bash
curl -X POST http://127.0.0.1:9527/api/rules/reload \
     -H "Authorization: Bearer <admin JWT>"
```

The Admin UI and `POST /api/rules/overrides` already trigger this on every write, so the endpoint is only needed for changes made out of band — the CLI against a shared database, a migration, a `psql` session.

**The CRS rule files** under `rules/owasp-crs/` are parsed and compiled into matchers once, at startup. They are not re-read while the process is serving: restart to pick up an edited rule file. There is no file watcher and no SIGHUP handler — `prx-waf rules reload` is not implemented and says so.

### Built-in Rules

Built-in rules are compiled into the binary and loaded automatically (configurable):

- **OWASP CRS** — Common attack signatures (SQLi, XSS, RCE, scanner detection)
- **Bot Detection** — Known malicious bots, AI crawlers, headless browsers
- **Scanner Detection** — Vulnerability scanner fingerprints (Nmap, Nikto, etc.)

---

## Architecture

PRX-WAF is organized as a 7-crate Cargo workspace:

```
prx-waf/
├── crates/
│   ├── prx-waf/        Binary: CLI entry point, server bootstrap
│   ├── gateway/        Pingora proxy, HTTP/3, SSL automation, caching, tunnels
│   ├── waf-engine/     Detection pipeline, rules engine, checks, plugins, CrowdSec
│   ├── waf-storage/    PostgreSQL layer (sqlx), migrations, models
│   ├── waf-api/        Axum REST API, JWT/TOTP auth, WebSocket, static UI
│   ├── waf-common/     Shared types: RequestCtx, WafDecision, HostConfig, config
│   └── waf-cluster/    Cluster consensus, QUIC transport, rule sync, certificates
├── migrations/         SQL migration files (0001–0014)
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
WafEngine Pipeline (18 phases)
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
    ├── Phase 16:   CrowdSec bouncer + AppSec
    ├── Phase 17:   GeoIP access control
    └── Phase 18:   Community threat-intelligence blocklist
    │
    ▼
HostRouter → Upstream (with load balancing)
```

---

## Performance

Measured with [`tests/perf/run.sh`](tests/perf/run.sh); full numbers, conditions
and caveats in [`tests/perf/RESULTS.md`](tests/perf/RESULTS.md).

On an AMD Ryzen 9 5900HX (8 physical cores, 16 logical), shipping default
configuration, plaintext HTTP/1.1, `oha` at 50 connections against a
near-zero-work origin, with the WAF pinned to four hardware threads on two
physical cores:

| workload | origin | prx-waf, no detection | prx-waf, shipping default | added latency (p50, unsaturated) |
|---|--:|--:|--:|--:|
| small GET | 169,700 rps | 58,078 rps | **9,517 rps** | **+0.42 ms** |
| 1 KiB JSON POST | 160,776 rps | 45,832 rps | **1,789 rps** | **+2.18 ms** |
| 64 KiB multipart upload | 89,098 rps | 21,764 rps | **4,237 rps** | **+0.90 ms** |
| 1 MiB body POST | 26,889 rps | 2,130 rps | **306 rps** | not measured |

Three things an operator should know before deploying:

* **These are four-worker-thread numbers on two physical cores.** `[proxy]
  worker_threads` sizes the data plane and, unset, follows the CPUs the process
  may actually use — the cgroup quota and affinity mask, not `nproc`. Releases
  before it ran the whole data plane on one thread whatever the machine, and
  every figure recorded then was roughly 2–3× lower.
* **Cost is driven by request-body size, not request rate — and the shipped
  defaults now bound it.** `[content_security.lane1] max_body_bytes` defaults to
  64 KiB, the same boundary CRS already draws, which is worth **20–75×** on
  large-body workloads: a 64 KiB upload costs 565 µs of CPU under Lane 1 against
  42.7 ms unbounded. The price is that `sqli` / `xss` / `rce` / `dir_traversal`
  see none of a body over 64 KiB — not a truncated prefix, none of it. Raise the
  key if your application legitimately posts larger bodies.
* **Sustained attack traffic grows memory to gigabytes** (106 MiB → 4.1 GiB in
  ten seconds), because every blocked request writes to the database through a
  20-connection pool. This got worse, not better, when the data plane went wide.
  Give the process a memory limit.

Resource limits, queue capacities, timeouts and what happens when each is
exceeded are documented separately in [`docs/dos-budget.md`](docs/dos-budget.md),
and every one of them now has a counter on `/metrics` — see
[`docs/metrics.md`](docs/metrics.md).

This is deliberately **not** a CI gate — see
[`tests/perf/README.md`](tests/perf/README.md#why-this-is-not-a-ci-gate).

---

## Metrics

Prometheus exposition on **`127.0.0.1:9090/metrics`**, on by default.

```
curl -s http://127.0.0.1:9090/metrics
```

```
[metrics]
enabled = true
listen_addr = "127.0.0.1:9090"
max_host_labels = 128
```

Seven metrics: RED by host and decision, the detection mix by phase, per-lane
detection cost (Lane 1 / CRS / Lane 2 are timed separately, because they share
no work and their cost ordering inverts with body size), and a counter for every
bounded resource in [`docs/dos-budget.md`](docs/dos-budget.md) — so "how much
inspection am I losing" is a query rather than a log grep.

**Cardinality is a property of the config, not of the traffic.** Every label
except `host` is a compile-time enumeration; `host` is bounded by
`max_host_labels` and folds into `__other__` past it. Client IP, rule id, path
and user agent are never labels. Total series is `28 × max_host_labels + 214` —
about 3 800 at the default, whatever the traffic does.

The endpoint is **unauthenticated by design** and its own listener, not a route
on the management API: Prometheus cannot carry a JWT well, and reusing the admin
token would put a credential that can rewrite rules and replace certificates
into the monitoring system's config file. The bind address is the access
control, which is why it defaults to loopback and warns at startup when it does
not. Full reference: [`docs/metrics.md`](docs/metrics.md).

---

## API Reference

The management API listens on `0.0.0.0:9527` by default (as shipped in `configs/default.toml`; the code-level struct default is `127.0.0.1:9527`, but every documented run path here loads `configs/default.toml`, which overrides it — see `[security] admin_ip_allowlist` to restrict access). All endpoints (except `/api/auth/login`) require a JWT Bearer token.

### Authentication

```http
POST /api/auth/login
Content-Type: application/json

{"username": "admin", "password": "<admin-password>", "totp_code": "123456"}

→ {"token": "eyJ...", "refresh_token": "..."}
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check (public) |
| POST | `/api/auth/login` | Obtain JWT token |
| POST | `/api/auth/logout` | Invalidate session |
| POST | `/api/auth/refresh` | Refresh JWT token |
| GET/POST | `/api/hosts` | List / add proxy hosts |
| GET/PUT/DELETE | `/api/hosts/:id` | Get / update / delete host |
| GET/POST | `/api/allow-ips` | List / add IP allowlist entries |
| DELETE | `/api/allow-ips/:id` | Remove IP allowlist entry |
| GET/POST | `/api/block-ips` | List / add IP blocklist entries |
| DELETE | `/api/block-ips/:id` | Remove IP blocklist entry |
| GET/POST | `/api/allow-urls` | List / add URL allowlist entries |
| DELETE | `/api/allow-urls/:id` | Remove URL allowlist entry |
| GET/POST | `/api/block-urls` | List / add URL blocklist entries |
| DELETE | `/api/block-urls/:id` | Remove URL blocklist entry |
| GET | `/api/attack-logs` | Attack log entries |
| GET | `/api/security-events` | Security event stream history |
| GET | `/api/status` | System status |
| POST | `/api/reload` | Hot-reload rules |
| GET/POST | `/api/custom-rules` | List / create custom rules |
| DELETE | `/api/custom-rules/:id` | Delete custom rule |
| GET/POST | `/api/sensitive-patterns` | List / add sensitive word patterns |
| DELETE | `/api/sensitive-patterns/:id` | Delete sensitive pattern |
| GET/POST | `/api/bot-patterns` | Built-in bot catalogue + operator patterns / add one (admin-only, reads included) |
| PUT/DELETE | `/api/bot-patterns/:id` | Update / delete an operator bot pattern |
| GET | `/api/bot-patterns/test` | Evaluate a `user_agent` against the live rule set |
| GET/POST | `/api/hotlink-config` | Get / set anti-hotlink config |
| GET/POST | `/api/lb-backends` | List / add load-balancer backends |
| DELETE | `/api/lb-backends/:id` | Delete LB backend |
| GET/POST | `/api/certificates` | List / upload TLS certificates |
| DELETE | `/api/certificates/:id` | Delete certificate |
| GET | `/api/stats/overview` | Aggregated traffic statistics |
| GET | `/api/stats/timeseries` | Time-series traffic data |
| GET | `/api/stats/geo` | Geo-distribution statistics |
| GET/POST | `/api/notifications` | List / create notification channels |
| DELETE | `/api/notifications/:id` | Delete notification channel |
| GET | `/api/notifications/log` | Notification delivery log |
| POST | `/api/notifications/:id/test` | Send test notification |
| GET/POST | `/api/plugins` | List / upload WASM plugins |
| DELETE | `/api/plugins/:id` | Delete plugin |
| POST | `/api/plugins/:id/enable` | Enable plugin |
| POST | `/api/plugins/:id/disable` | Disable plugin |
| GET/POST | `/api/tunnels` | List / create reverse tunnels |
| DELETE | `/api/tunnels/:id` | Delete tunnel |
| GET | `/api/cache/stats` | Cache statistics |
| DELETE | `/api/cache` | Flush entire cache |
| DELETE | `/api/cache/host/:host` | Flush cache for a host |
| DELETE | `/api/cache/key` | Flush a specific cache key |
| GET | `/api/audit-log` | Admin action audit log |
| GET | `/api/cluster/status` | Cluster health overview |
| GET | `/api/cluster/nodes` | List cluster nodes |
| GET | `/api/cluster/nodes/:id` | Get cluster node details |
| POST | `/api/cluster/token` | Generate node join token |
| POST | `/api/cluster/nodes/remove` | Remove a node from cluster |
| GET | `/api/crowdsec/status` | CrowdSec integration status |
| GET | `/api/crowdsec/decisions` | Active CrowdSec decisions |
| DELETE | `/api/crowdsec/decisions/:id` | Delete a CrowdSec decision |
| POST | `/api/crowdsec/test` | Test LAPI connectivity |
| GET/PUT | `/api/crowdsec/config` | Get / update CrowdSec config |
| GET | `/api/crowdsec/stats` | CrowdSec statistics |
| GET | `/api/crowdsec/events` | CrowdSec event log |
| WS | `/ws/events` | Real-time security event stream |
| WS | `/ws/logs` | Real-time access/attack log stream |
| WS | `/ws/tunnel` | Reverse tunnel WebSocket endpoint |

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

### Fuzzing

Every parser reachable from a request is fuzzed with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz); the harnesses, seed corpora and target rationale live in [`fuzz/`](fuzz/README.md), and `.github/workflows/fuzz.yml` runs a short regression on each PR plus a weekly soak. If you touch a parser or a detector, run `cd fuzz && cargo +nightly fuzz run <target> -- -max_total_time=60` before opening the PR.

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

Copyright (c) 2026 Span Brain LLC.

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
