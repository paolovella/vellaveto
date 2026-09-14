# Copyright 2026 Paolo Vella
# SPDX-License-Identifier: BUSL-1.1

# Vellaveto Multi-Stage Dockerfile
# Builds optimized production binaries for the MCP firewall
#
# Authenticated usage (deny-by-default policy baked in):
#   docker run -p 3000:3000 -e VELLAVETO_API_KEY=your-secret-key ghcr.io/paolovella/vellaveto:latest
#
# With custom policy:
#   docker run -p 3000:3000 -e VELLAVETO_API_KEY=your-secret-key -v ./policy.toml:/etc/vellaveto/config.toml:ro ghcr.io/paolovella/vellaveto:latest

# Build stage: Compile Rust binaries with musl for static linking
FROM rust:1.98-alpine@sha256:1716b3aa042d735f4566d14dc54e8037de9d69556e2d5dd58131d93a613d173d AS builder

# Resolve target triple from Docker's TARGETARCH (amd64 or arm64)
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
      amd64) echo "x86_64-unknown-linux-musl" > /tmp/rust-target ;; \
      arm64) echo "aarch64-unknown-linux-musl" > /tmp/rust-target ;; \
      *)     echo "x86_64-unknown-linux-musl" > /tmp/rust-target ;; \
    esac \
    && rustup target add "$(cat /tmp/rust-target)"

# Upgrade base packages for security patches, then install build dependencies
RUN apk upgrade --no-cache && apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconfig

# Create a non-root user for the build
WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY vellaveto-types/Cargo.toml vellaveto-types/
COPY vellaveto-engine/Cargo.toml vellaveto-engine/
COPY vellaveto-audit/Cargo.toml vellaveto-audit/
COPY vellaveto-config/Cargo.toml vellaveto-config/
COPY vellaveto-canonical/Cargo.toml vellaveto-canonical/
COPY vellaveto-discovery/Cargo.toml vellaveto-discovery/
COPY vellaveto-mcp/Cargo.toml vellaveto-mcp/
COPY vellaveto-approval/Cargo.toml vellaveto-approval/
COPY vellaveto-cluster/Cargo.toml vellaveto-cluster/
COPY vellaveto-server/Cargo.toml vellaveto-server/
COPY vellaveto-http-proxy/Cargo.toml vellaveto-http-proxy/
COPY vellaveto-proxy/Cargo.toml vellaveto-proxy/
COPY vellaveto-operator/Cargo.toml vellaveto-operator/
COPY vellaveto-integration/Cargo.toml vellaveto-integration/
COPY mcpsec/Cargo.toml mcpsec/
COPY vellaveto-mcp-shield/Cargo.toml vellaveto-mcp-shield/
COPY vellaveto-http-proxy-shield/Cargo.toml vellaveto-http-proxy-shield/
COPY vellaveto-canary/Cargo.toml vellaveto-canary/
COPY vellaveto-shield/Cargo.toml vellaveto-shield/
COPY vellaveto-tls/Cargo.toml vellaveto-tls/
COPY vellaveto-engine/benches vellaveto-engine/benches/
COPY vellaveto-audit/benches vellaveto-audit/benches/
COPY vellaveto-mcp/benches vellaveto-mcp/benches/
COPY vellaveto-http-proxy/benches vellaveto-http-proxy/benches/

# Create dummy src files for dependency caching
RUN mkdir -p vellaveto-types/src vellaveto-engine/src vellaveto-audit/src \
    vellaveto-config/src vellaveto-canonical/src vellaveto-discovery/src \
    vellaveto-mcp/src vellaveto-approval/src vellaveto-cluster/src \
    vellaveto-server/src vellaveto-http-proxy/src vellaveto-proxy/src \
    vellaveto-operator/src vellaveto-integration/src mcpsec/src \
    vellaveto-mcp-shield/src vellaveto-http-proxy-shield/src \
    vellaveto-canary/src vellaveto-shield/src vellaveto-tls/src \
    && echo "pub fn dummy() {}" > vellaveto-types/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-engine/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-audit/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-config/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-canonical/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-discovery/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-mcp/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-approval/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-cluster/src/lib.rs \
    && echo "fn main() {}" > vellaveto-server/src/main.rs \
    && echo "fn main() {}" > vellaveto-http-proxy/src/main.rs \
    && echo "fn main() {}" > vellaveto-proxy/src/main.rs \
    && echo "fn main() {}" > vellaveto-operator/src/main.rs \
    && echo "" > vellaveto-integration/src/lib.rs \
    && echo "fn main() {}" > mcpsec/src/main.rs \
    && echo "pub fn dummy() {}" > vellaveto-mcp-shield/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-http-proxy-shield/src/lib.rs \
    && echo "pub fn dummy() {}" > vellaveto-canary/src/lib.rs \
    && echo "fn main() {}" > vellaveto-shield/src/main.rs \
    && echo "pub fn dummy() {}" > vellaveto-tls/src/lib.rs

# Build dependencies only (for layer caching)
RUN RUST_TARGET="$(cat /tmp/rust-target)" \
    && cargo build --release --target "$RUST_TARGET" \
       --bin vellaveto --bin vellaveto-http-proxy --bin vellaveto-proxy || true

# Copy actual source code
COPY vellaveto-types/src vellaveto-types/src/
COPY vellaveto-engine/src vellaveto-engine/src/
COPY vellaveto-engine/benches vellaveto-engine/benches/
COPY vellaveto-audit/src vellaveto-audit/src/
COPY vellaveto-audit/benches vellaveto-audit/benches/
COPY vellaveto-config/src vellaveto-config/src/
COPY vellaveto-canonical/src vellaveto-canonical/src/
COPY vellaveto-discovery/src vellaveto-discovery/src/
COPY vellaveto-mcp/src vellaveto-mcp/src/
COPY vellaveto-mcp/benches vellaveto-mcp/benches/
COPY vellaveto-approval/src vellaveto-approval/src/
COPY vellaveto-cluster/src vellaveto-cluster/src/
COPY vellaveto-server/src vellaveto-server/src/
COPY vellaveto-http-proxy/src vellaveto-http-proxy/src/
COPY vellaveto-http-proxy/benches vellaveto-http-proxy/benches/
COPY vellaveto-proxy/src vellaveto-proxy/src/
COPY vellaveto-operator/src vellaveto-operator/src/
COPY mcpsec/src mcpsec/src/
COPY vellaveto-mcp-shield/src vellaveto-mcp-shield/src/
COPY vellaveto-http-proxy-shield/src vellaveto-http-proxy-shield/src/
COPY vellaveto-canary/src vellaveto-canary/src/
COPY vellaveto-shield/src vellaveto-shield/src/
COPY vellaveto-tls/src vellaveto-tls/src/

# Copy preset config files (embedded at compile time via include_str! in vellaveto-proxy/src/presets.rs)
COPY vellaveto-proxy/presets vellaveto-proxy/presets/
COPY examples/presets examples/presets/

# Touch source files to invalidate cache
RUN find . -name "*.rs" -exec touch {} \;

# Build release binaries
RUN RUST_TARGET="$(cat /tmp/rust-target)" \
    && cargo build --release --target "$RUST_TARGET" \
       --bin vellaveto --bin vellaveto-http-proxy --bin vellaveto-proxy \
    && mkdir -p /build/out \
    && cp "/build/target/$RUST_TARGET/release/vellaveto" /build/out/ \
    && cp "/build/target/$RUST_TARGET/release/vellaveto-http-proxy" /build/out/ \
    && cp "/build/target/$RUST_TARGET/release/vellaveto-proxy" /build/out/

# Verify binaries exist and are executable
RUN test -x /build/out/vellaveto \
    && test -x /build/out/vellaveto-http-proxy \
    && test -x /build/out/vellaveto-proxy

# Runtime stage: Minimal Alpine image
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

LABEL org.opencontainers.image.title="Vellaveto" \
      org.opencontainers.image.description="Runtime security engine for AI agent tool calls" \
      org.opencontainers.image.source="https://github.com/paolovella/vellaveto" \
      org.opencontainers.image.licenses="MPL-2.0 AND Apache-2.0 AND BUSL-1.1" \
      org.opencontainers.image.vendor="Paolo Vella"

# Security: Run as non-root user
RUN addgroup -S vellaveto && adduser -S vellaveto -G vellaveto

# Upgrade base packages to pick up security patches (musl, openssl)
RUN apk upgrade --no-cache

# Install runtime dependencies (CA certs for HTTPS)
RUN apk add --no-cache ca-certificates tzdata

# Create config and data directories
RUN mkdir -p /etc/vellaveto /var/lib/vellaveto /var/log/vellaveto \
    && chown -R vellaveto:vellaveto /etc/vellaveto /var/lib/vellaveto /var/log/vellaveto

# Copy binaries from builder
COPY --from=builder /build/out/vellaveto /usr/local/bin/
COPY --from=builder /build/out/vellaveto-http-proxy /usr/local/bin/
COPY --from=builder /build/out/vellaveto-proxy /usr/local/bin/

# Copy example configs
COPY examples/*.toml /etc/vellaveto/examples/

# Bake the default deny-by-default policy for zero-config usage
COPY examples/default.toml /etc/vellaveto/config.toml

# Switch to non-root user
USER vellaveto

# Default port for HTTP API server
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Default: serve with baked-in policy and require VELLAVETO_API_KEY.
ENTRYPOINT ["vellaveto"]
CMD ["serve", "--config", "/etc/vellaveto/config.toml", "--bind", "0.0.0.0"]
