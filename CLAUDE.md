# CLAUDE.md — prx-waf Rust Production Code Standards

## Rust Edition: 2024

## Seven Iron Rules (Strictly Enforced)
1. NO panic-capable unwrapping — .unwrap(), .expect(), any panic shorthand BANNED in production code
2. NO dead code — zero unused variables, parameters, imports. Zero warnings.
3. NO incomplete implementations — todo!(), unimplemented!(), placeholder returns, empty arms BANNED
4. Business logic must be verifiable — must pass cargo check, no speculative interfaces
5. Validate with cargo check and cargo fix — not cargo run/build
6. Explicit error handling — validate external inputs, never panic instead of error branch
7. Minimize allocations — prefer &str over String, Cow over clone, Arc over deep copy

## Build & Test
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

## Docker
```bash
# Published image. docker-compose.yml alone has no build: section, so --build
# here builds nothing and the tag is whatever PRX_WAF_VERSION points at.
podman-compose down && podman-compose up -d

# Your own build. Dockerfile.prebuilt copies target/release/prx-waf out of the
# working tree, so compile first; both -f files are required, the second is what
# swaps the ghcr image for the local one.
cargo build --release
podman-compose -f docker-compose.yml -f docker-compose.build.yml up -d --build

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
- Workspace: 7 crates (prx-waf, gateway, waf-engine, waf-storage, waf-api, waf-common, waf-cluster)
- WAF engine: Pingora-based reverse proxy
- Rules: YAML files in rules/ directory
- Admin UI: Vue 3 + Tailwind in web/admin-ui/
- Config: TOML in configs/
- English in code/commits
