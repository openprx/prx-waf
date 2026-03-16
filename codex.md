# codex.md — prx-waf Production Standards

## Build
```bash
cargo test && cargo build --release
```

## Docker
```bash
podman-compose down && podman-compose up -d --build
```

## Rules
- NO .unwrap() outside #[cfg(test)] — use ?, .unwrap_or_default(), .expect("BUG: reason")
- Parameterized SQL only (sqlx bind)
- parking_lot::Mutex for sync, tokio::sync::Mutex for async — NEVER std::sync::Mutex
- Every unsafe needs // SAFETY: comment
- Never log secrets/tokens
- English in code and commits
