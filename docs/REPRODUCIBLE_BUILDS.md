# Reproducible Builds

Vellaveto is configured for reproducible release builds. Given the same source
checkout, toolchain version, and target triple, two independent builds produce
bit-identical binaries.

## How It Works

### Dependency Pinning

- `Cargo.lock` is committed and CI uses `--locked` for every build/test/check
  command. This guarantees exact crate versions across all environments.
- `cargo metadata --locked` gate in CI rejects any Cargo.lock drift.

### Deterministic Codegen

In `Cargo.toml` under `[profile.release]`:

```toml
[profile.release]
lto = "thin"
codegen-units = 1   # Single codegen unit = deterministic code ordering
opt-level = 3
strip = "symbols"
overflow-checks = true
```

For release builds, CI sets `RUSTFLAGS="-Ctrim-paths=all"` to strip absolute
build paths from binaries.

Key settings:
- **`codegen-units = 1`** — Forces the compiler to use a single codegen unit,
  eliminating non-determinism from parallel code generation and link ordering.
- **`-Ctrim-paths=all`** (via RUSTFLAGS) — Removes absolute filesystem paths
  from the binary. Without this, different build directories produce different
  binaries due to embedded path strings in panic messages and debug info.
- **`strip = "symbols"`** — Removes symbol tables that may contain path-dependent
  information.

### CI Enforcement

- All CI jobs use `--locked` to prevent dependency resolution differences.
- Release builds are produced in CI with a fixed Ubuntu runner image.
- SLSA provenance attestations record the exact build environment.

## Verification

To verify a release binary was built from a specific commit:

```bash
# 1. Check out the exact commit
git checkout v6.0.0
git submodule update --init

# 2. Build with the same toolchain and trim-paths
RUSTFLAGS="-Ctrim-paths=all" rustup run 1.89.0 cargo build --release --locked -p vellaveto-server

# 3. Compare SHA-256
sha256sum target/release/vellaveto
# Should match the published checksum
```

### Container Builds

The `Dockerfile` uses a pinned Rust base image and `--locked` builds.
Multi-stage builds ensure the final image contains only the stripped binary.

```bash
# Build and hash
docker build -t vellaveto:local .
docker run --rm vellaveto:local sha256sum /usr/local/bin/vellaveto
```

## Limitations

- Cross-compilation to different targets may produce different binaries due to
  target-specific codegen differences. Reproducibility is guaranteed within the
  same target triple.
- Different Rust compiler versions will produce different binaries. Pin the
  exact toolchain version for reproducibility.
