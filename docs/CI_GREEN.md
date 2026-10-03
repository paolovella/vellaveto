# Keeping CI Green

> **Audience:** Claude Code instances, swarm agents, and contributors.
> **Last validated:** 2026-03-31 (all CI jobs green across all workflows; 11,574 Rust tests + 556 SDK tests + 59 admin console tests passing).

This document describes every CI gate, what breaks it, and how to stay green.

---

## CI Pipeline Overview

The main CI workflow (`.github/workflows/ci.yml`) runs on every push to `main`
and every PR. Two additional workflows provide coverage and dynamic analysis.
Total: **20 jobs** across 3 workflows.

```
actionlint-checksum ─┐
                     ├─ Check & Lint ─┬─ Test Suite ──────┬─ Release Build
                     │                ├─ Feature Gates     ├─ Benchmark Regression
                     │                ├─ Feature Matrix    │
                     │                ├─ Fuzz Targets      │
                     │                └─ Types Contract    │
MSRV (1.89.0) ──────┘                                     │
Coq Formal Proofs ────────────────────────────────────────┘
Security Audit ────────────────────────────────────────────┘
Supply Chain Audit ────────────────────────────────────────┘
```

**Concurrency:** `cancel-in-progress: true` — a new push cancels any running CI
for the same branch. Avoid rapid-fire pushes; batch fixes into one commit.

**Global env:** `RUSTFLAGS=-Dwarnings` — every Rust warning is a hard error.

---

## Gate-by-Gate Checklist

### 1. Check & Lint

This is the most common failure point. It runs **7 sub-steps** in sequence:

| Step | What it checks | Local command |
|------|---------------|---------------|
| **Lint GitHub workflows** | `actionlint` on all `.yml` | `actionlint .github/workflows/*.yml` |
| **Format** | `rustfmt` | `cargo fmt --all -- --check` |
| **Lockfile immutability** | `Cargo.lock` unchanged | `cargo metadata --locked --format-version=1 > /dev/null` |
| **zk-audit opt-in** | Feature not default-enabled | `cargo tree --workspace --locked -e features \| rg 'zk-audit'` (should find nothing) |
| **Check** | Workspace compiles | `cargo check --workspace --all-targets --locked` |
| **Clippy** | Zero warnings | `RUSTFLAGS=-Dwarnings cargo clippy --workspace --all-targets --locked -- -D warnings` |
| **Reject unwrap/expect** | No `.unwrap()` or `.expect()` in library code | See scanner command below |
| **Reject panic!** | No `panic!()` in library code | See scanner command below |

#### The unwrap/expect scanner

The scanner runs `awk` over all `vellaveto-*/src/*.rs` files **excluding**
`main.rs`, `tests.rs`, `*_tests.rs`, lines inside `#[cfg(test)]` blocks, and
doc comments (`///` and `//!`).

**What it catches:**
- `.unwrap()` — use `.ok_or_else(|| ...)?` or `.unwrap_or_else(|| ...)`
- `.expect("...")` — use `.ok_or_else(|| Error::...)?`

**What it does NOT catch (safe to use):**
- `.unwrap_or()`, `.unwrap_or_else()`, `.unwrap_or_default()` — these don't match `.unwrap()`
- `unreachable!()` — not caught by the `panic!` scanner either (it looks for literal `panic!(`)
- Anything in `main.rs`, `tests.rs`, or `#[cfg(test)]` blocks

**Common trap:** Adding a new library file with `.expect()` for a "safe" static
parse. Use `.unwrap_or_else(|_| unreachable!())` instead.

#### Clippy with `-Dwarnings`

Because `RUSTFLAGS=-Dwarnings` is set globally, **any** Clippy lint is fatal.
Common offenders:

- `unnecessary_cast` — remove redundant `as i32` casts
- `unused_mut` — variable only mutated behind a `#[cfg(feature)]` gate; add `#[allow(unused_mut)]` with a comment
- `needless_borrow` — `&foo` where `foo` is already a reference
- `manual_contains` — use `.contains()` instead of `.iter().any(|x| x == &val)`

### 2. MSRV (1.89.0)

Compiles the workspace with Rust 1.89.0. If you use a language feature or
stdlib API from a newer Rust version, this breaks.

**Local check:** `rustup run 1.89.0 cargo check --workspace --locked`

### 3. Feature Gates

Tests two non-default feature paths:

| Feature | Command |
|---------|---------|
| `a2a` | `cargo test -p vellaveto-mcp --features a2a --locked` |
| `redis-backend` | `cargo test -p vellaveto-server --features redis-backend --locked` |

**Common trap:** The `redis-backend` feature brings in `deadpool_redis`. If you
add code using `redis::cmd()`, you need `use deadpool_redis::redis;` (the `redis`
crate is re-exported, not a direct dependency).

### 4. Feature Matrix

Tests **5 feature combinations** of `vellaveto-server` and `vellaveto-audit`:

| Name | Command |
|------|---------|
| default | `cargo test --workspace --locked` |
| discovery only | `cargo test -p vellaveto-server --no-default-features --features discovery --locked` |
| projector only | `cargo test -p vellaveto-server --no-default-features --features projector --locked` |
| zk-audit | `cargo test -p vellaveto-audit --features zk-audit --locked` |
| all features | `cargo test -p vellaveto-server --features discovery,projector -p vellaveto-audit --features zk-audit --locked` |

**Common trap:** Code that is `mut` only when a specific feature is enabled.
The `projector only` build has `--no-default-features`, so code guarded by
`#[cfg(feature = "discovery")]` is absent. If a `let mut x` is only mutated
inside such a block, Clippy emits `unused_mut`. Fix with:
```rust
#[allow(unused_mut)] // mut needed when `discovery` feature enables set_topology_guard
let mut engine = ...;
```

### 5. Test Suite

`cargo test --workspace --no-fail-fast --locked` — runs all 10,990+ Rust tests (11,900+ total across all languages).

**Common trap:** Tests that use `std::env::set_var()` / `remove_var()` race
when run in parallel. Serialize them behind a static `Mutex`:
```rust
static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_that_sets_env_var() {
    let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("MY_VAR", "value");
    // ... test ...
    std::env::remove_var("MY_VAR");
}
```

### 6. Security Audit

Runs `cargo audit` via `rustsec/audit-check`. Fails if any dependency has a
known RUSTSEC advisory. Fix by updating the dependency.

### 7. Supply Chain Audit

Runs `cargo vet --locked` against `supply-chain/{config,audits}.toml`. If those
files are missing, falls back to `cargo deny`. When adding a new dependency,
you must audit it with `cargo vet certify`.

### 8. Fuzz Targets Compile

Checks that `fuzz/` targets compile with nightly. If you change types or APIs
used by fuzz harnesses, verify with:
```bash
cd fuzz && cargo +nightly check --all-targets
```

### 9. Benchmark Regression Check

Runs Criterion benchmarks with `--quick`. Only runs on pushes to `main` (not PRs).
If a benchmark binary fails to compile, this breaks. After changing bench harness
code, verify with:
```bash
cargo bench -p vellaveto-engine --bench evaluation --locked -- --quick
```

### 10. Coq Formal Proofs

Installs Coq via `apt`, runs `make` in `formal/coq/`, and rejects any
`Admitted` or `admit` markers (incomplete proofs).

**Local check:**
```bash
cd formal/coq && make
grep -rn 'Admitted\|admit' Vellaveto/*.v  # should return nothing
```

**Common trap:** Adding a theorem with `Admitted.` as a placeholder and
forgetting to complete the proof. CI enforces zero `Admitted`.

### 11. Release Build

`cargo build --release --workspace --locked` — fails if any binary exceeds 50MB.

### 12. SPDX License Headers

Added to the Check & Lint job. Scans all `vellaveto-*/src/*.rs` files for
`SPDX-License-Identifier`. Any file missing the header fails the build.

**Local check:**
```bash
find vellaveto-*/src/ -name '*.rs' -exec grep -L 'SPDX-License-Identifier' {} \;
# Should return nothing
```

### 13. Coverage (coverage.yml)

Separate workflow (`.github/workflows/coverage.yml`). Runs on push to main and
PRs. Uses nightly Rust + `cargo-llvm-cov` to generate LCOV coverage, then
uploads to Codecov. Currently `continue-on-error: true` (advisory).

### 14. Fuzz CI (fuzz-ci.yml)

Separate workflow (`.github/workflows/fuzz-ci.yml`). Runs weekly (Monday 04:00
UTC) and on push to main. Runs 5 critical fuzz targets for 30 seconds each:
`fuzz_injection_detection`, `fuzz_normalize_path`, `fuzz_extract_domain`,
`fuzz_dlp_decoding`, `fuzz_policy_compilation`. Crash artifacts are uploaded.

---

## Pre-Push Verification Script

Run this **before every push** to catch all CI issues locally:

```bash
# 1. Format
cargo fmt --all -- --check

# 2. Compile (all targets, all features exercise #[cfg])
cargo check --workspace --all-targets --locked

# 3. Clippy (matches CI exactly)
RUSTFLAGS=-Dwarnings cargo clippy --workspace --all-targets --locked -- -D warnings

# 4. unwrap/expect scanner (matches CI awk script)
find vellaveto-*/src/ -name '*.rs' \
  -not -name 'main.rs' -not -name 'tests.rs' -not -name '*_tests.rs' -print0 \
  | xargs -0 awk 'FNR==1 { skip=0 }
    /^#\[cfg\(test\)\]/ { skip=1 }
    skip==0 && /^[[:space:]]*(\/\/!|\/\/\/)/ { next }
    skip==0 && /\.unwrap\(\)/ { printf "%s:%d: %s\n", FILENAME, FNR, $0; found=1 }
    skip==0 && /\.expect\(/ { printf "%s:%d: %s\n", FILENAME, FNR, $0; found=1 }
    END { exit found ? 1 : 0 }'

# 5. Tests
cargo test --workspace --no-fail-fast --locked

# 6. Feature gate spot-checks (catches the most common breaks)
RUSTFLAGS=-Dwarnings cargo check -p vellaveto-server --features redis-backend --locked
RUSTFLAGS=-Dwarnings cargo check -p vellaveto-server --no-default-features --features projector --locked

# 7. Coq proofs (if coqc is installed)
if command -v coqc &>/dev/null; then
  (cd formal/coq && make)
  ! grep -rn 'Admitted\|admit' formal/coq/Vellaveto/*.v
fi
```

---

## Top 10 CI Killers (Historical)

These are the actual failures we've hit. Memorize them.

| # | Failure | Root Cause | Fix |
|---|---------|-----------|-----|
| 1 | **Clippy `unnecessary_cast`** | `as i32` on a value already `i32` | Remove the cast |
| 2 | **unwrap/expect scanner** | `.expect()` in library code | Use `.ok_or_else()?` or `.unwrap_or_else(\|_\| unreachable!())` |
| 3 | **Feature gate compile error** | Missing import only needed with a feature | Add the import inside `#[cfg(feature = "...")]` or unconditionally if it's a re-export |
| 4 | **`unused_mut` in feature subset** | `let mut x` only mutated inside `#[cfg(feature)]` | `#[allow(unused_mut)]` with comment |
| 5 | **Env var test race** | `set_var`/`remove_var` not thread-safe | Static `Mutex` to serialize |
| 6 | **Error message text changed** | Test asserts on exact substring | Grep `tests.rs` for old string before changing |
| 7 | **Lockfile drift** | `cargo add` or manual edit without `--locked` | Run `cargo update -p <pkg>` then commit `Cargo.lock` |
| 8 | **rustfmt diff** | Local rustfmt version differs from CI | `cargo fmt --all` before committing |
| 9 | **`redis::cmd()` unresolved** | `redis` crate is re-exported through `deadpool_redis` | `use deadpool_redis::redis;` |
| 10 | **Type annotation needed** | Generic turbofish not enough for closure inference | Add explicit type to closure param: `\|r: Option<String>\|` |

---

## Quick Diagnosis

When CI fails, run:

```bash
# See which job failed
GH_PAGER=cat gh run view <run-id> --json jobs \
  --jq '.jobs[] | select(.conclusion == "failure") | {name: .name}'

# Get the failed step logs
GH_PAGER=cat gh run view <run-id> --log-failed | tail -50
```

Then reproduce locally with the exact command from the job (see table above).

---

## Rules for Agents

1. **Never push without running the pre-push script.** CI takes 15+ minutes.
   Catching failures locally saves time.

2. **Batch fixes into one commit.** Each push cancels the previous CI run
   (`cancel-in-progress: true`). Rapid-fire pushes waste CI minutes.

3. **Test all feature combinations you touch.** If you edit `vellaveto-server`,
   test with `--features redis-backend` and `--no-default-features --features projector`.

4. **Never add `.unwrap()` or `.expect()` to library code.** The scanner will
   catch it. Use `?`, `.ok_or_else()`, or `.unwrap_or_else(|| unreachable!())`.

5. **Check Clippy with `-Dwarnings`.** A bare `cargo clippy` won't catch
   warnings that CI treats as errors.

6. **If a test uses `std::env::set_var`, serialize it.** Parallel test execution
   causes races.

7. **If you add a dependency, run `cargo vet certify`.** Supply chain audit
   will fail otherwise.
