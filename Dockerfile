# ─── Stage 1: Builder ────────────────────────────────────────────────────────
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first to cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates/prx-waf/Cargo.toml    crates/prx-waf/Cargo.toml
COPY crates/gateway/Cargo.toml    crates/gateway/Cargo.toml
COPY crates/waf-engine/Cargo.toml crates/waf-engine/Cargo.toml
COPY crates/waf-storage/Cargo.toml crates/waf-storage/Cargo.toml
COPY crates/waf-api/Cargo.toml    crates/waf-api/Cargo.toml
COPY crates/waf-common/Cargo.toml crates/waf-common/Cargo.toml

# Create stub source files to pre-build dependencies
RUN mkdir -p crates/prx-waf/src && echo 'fn main(){}' > crates/prx-waf/src/main.rs && \
    mkdir -p crates/gateway/src   && echo 'pub fn dummy(){}' > crates/gateway/src/lib.rs && \
    mkdir -p crates/waf-engine/src && echo 'pub fn dummy(){}' > crates/waf-engine/src/lib.rs && \
    mkdir -p crates/waf-storage/src && echo 'pub fn dummy(){}' > crates/waf-storage/src/lib.rs && \
    mkdir -p crates/waf-api/src   && echo 'pub fn dummy(){}' > crates/waf-api/src/lib.rs && \
    mkdir -p crates/waf-common/src && echo 'pub fn dummy(){}' > crates/waf-common/src/lib.rs

# Pre-build all dependencies (layer-cache friendly)
RUN cargo build --release 2>/dev/null || true

# Now copy the real source tree
COPY . .

# Rebuild with real source (only changed crates will be recompiled)
RUN cargo build --release -p prx-waf

# ─── Stage 2: Runtime ────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /build/target/release/prx-waf /usr/local/bin/prx-waf

# Copy default config, OWASP rules, and frontend dist
COPY configs/   /app/configs/
COPY rules/     /app/rules/
COPY --from=builder /build/web/admin-ui/dist /app/web/admin-ui/dist

RUN chmod +x /usr/local/bin/prx-waf

EXPOSE 80 443 9527

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9527/health || exit 1

CMD ["/usr/local/bin/prx-waf", "--config", "/app/configs/default.toml", "run"]
