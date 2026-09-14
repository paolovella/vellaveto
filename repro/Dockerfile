# Vellaveto Benchmark Reproducibility Container
#
# Provides an isolated, controlled environment for running benchmarks.
# Results are deterministic modulo CPU architecture and frequency.
#
# Usage:
#   docker build -t vellaveto-bench -f repro/Dockerfile .
#   docker run --rm vellaveto-bench
#   docker run --rm -v $(pwd)/target:/app/target vellaveto-bench  # persist results

FROM rust:1.98-alpine@sha256:1716b3aa042d735f4566d14dc54e8037de9d69556e2d5dd58131d93a613d173d AS builder

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static perl make

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY vellaveto-types/Cargo.toml vellaveto-types/Cargo.toml
COPY vellaveto-engine/Cargo.toml vellaveto-engine/Cargo.toml
COPY vellaveto-audit/Cargo.toml vellaveto-audit/Cargo.toml
COPY vellaveto-mcp/Cargo.toml vellaveto-mcp/Cargo.toml
COPY vellaveto-canonical/Cargo.toml vellaveto-canonical/Cargo.toml
COPY vellaveto-config/Cargo.toml vellaveto-config/Cargo.toml
COPY vellaveto-cluster/Cargo.toml vellaveto-cluster/Cargo.toml
COPY vellaveto-integration/Cargo.toml vellaveto-integration/Cargo.toml
COPY vellaveto-server/Cargo.toml vellaveto-server/Cargo.toml
COPY vellaveto-approval/Cargo.toml vellaveto-approval/Cargo.toml
COPY vellaveto-proxy/Cargo.toml vellaveto-proxy/Cargo.toml
COPY vellaveto-http-proxy/Cargo.toml vellaveto-http-proxy/Cargo.toml
COPY mcpsec/Cargo.toml mcpsec/Cargo.toml

# Create stub lib.rs files for dependency caching
RUN for dir in vellaveto-types vellaveto-engine vellaveto-audit vellaveto-mcp \
    vellaveto-canonical vellaveto-config vellaveto-cluster vellaveto-integration \
    vellaveto-server vellaveto-approval vellaveto-proxy vellaveto-http-proxy mcpsec; do \
    mkdir -p "$dir/src" && echo "" > "$dir/src/lib.rs"; \
    done

# Pre-build dependencies (cached layer)
RUN cargo build --release --workspace 2>/dev/null || true

# Copy full source
COPY . .

# Touch source files to invalidate stubs
RUN find . -name "*.rs" -exec touch {} +

# Build release + benchmarks
RUN cargo build --release --workspace && \
    cargo bench --workspace --no-run

# Runtime stage — just run benchmarks
FROM rust:1.98-alpine@sha256:1716b3aa042d735f4566d14dc54e8037de9d69556e2d5dd58131d93a613d173d

RUN apk add --no-cache bash bc jq

WORKDIR /app
COPY --from=builder /app /app

# Run benchmarks and print summary
CMD ["bash", "-c", "\
  echo '=== Vellaveto Benchmark (Docker) ===' && \
  echo '' && \
  echo \"Rust: $(rustc --version)\" && \
  echo \"CPU: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || echo 'unknown')\" && \
  echo \"Cores: $(nproc)\" && \
  echo '' && \
  cargo bench -p vellaveto-engine 2>&1 | grep -E '(Benchmarking|time:)' && \
  echo '' && \
  cargo bench -p vellaveto-mcp 2>&1 | grep -E '(Benchmarking|time:)' && \
  echo '' && \
  cargo bench -p vellaveto-audit 2>&1 | grep -E '(Benchmarking|time:)' && \
  echo '' && \
  cargo bench -p vellaveto-http-proxy 2>&1 | grep -E '(Benchmarking|time:)' && \
  echo '' && \
  echo 'HTML reports: target/criterion/report/index.html' && \
  echo 'Done.' \
"]
