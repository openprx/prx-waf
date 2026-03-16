# CLAUDE.md — prx-waf Rust Production Code Standards

## Build & Test
```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
```

## Docker
```bash
podman-compose down && podman-compose up -d --build
# Uses Dockerfile.prebuilt (local binary, fast)
# Ports: 16880 (HTTP), 16843 (HTTPS), 16827 (API/Admin UI)
# Admin UI: http://localhost:16827/ui/  (admin / admin123)
```

## Rust Safety Rules (Non-Negotiable)

### NO .unwrap() in Production Code
- BANNED: `.unwrap()` outside `#[cfg(test)]`
- Use: `?`, `.unwrap_or_default()`, `.unwrap_or(val)`, `if let`, `.expect("BUG: reason")`
- `.expect()` only for compile-time constants

### Error Handling
- `?` with `.context("msg")` for anyhow propagation
- Never silently swallow errors — log before `.ok()`
- `tracing::warn!()` when intentionally discarding errors

### Mutex
- Sync: `parking_lot::Mutex` (no poison, no unwrap)
- Async: `tokio::sync::Mutex` (.lock().await)
- BANNED: `std::sync::Mutex` in production

### SQL Safety
- Parameterized queries only: `sqlx::query("...WHERE id = $1").bind(id)`
- Validate dynamic identifiers: `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`

### No Secret Logging
- Never log tokens, keys, passwords
- Sanitize URLs before logging

### Unsafe
- Requires `// SAFETY:` comment
- Validate inputs before unsafe block

## Architecture
- Workspace: 6 crates (prx-waf, gateway, waf-engine, waf-storage, waf-api, waf-common)
- WAF engine: Pingora-based reverse proxy
- Rules: YAML files in rules/ directory
- Admin UI: Vue 3 + Tailwind in web/admin-ui/
- Config: TOML in configs/
- English in code/commits
