# Hardening Guide

This document describes the defense-in-depth hardening measures applied to
Vellaveto binaries, builds, and runtime, satisfying the OpenSSF Best Practices
`hardening` criterion.

## Language-Level Safety

### Rust Memory Safety

Vellaveto is written in Rust, which provides compile-time guarantees against:
- Buffer overflows and out-of-bounds access
- Use-after-free and double-free
- Data races (via the ownership and borrowing system)
- Null pointer dereferences (via `Option<T>`)

### Zero Unsafe

Library code contains zero `unsafe` blocks. CI enforces this with a static
scanner that rejects `unwrap()`, `expect()`, and `panic!()` in library code.

### Integer Overflow Protection

```toml
[profile.release]
overflow-checks = true
```

All arithmetic in release builds is checked for overflow. Security-critical
counters (rate limits, circuit breakers, sequence numbers) additionally use
`saturating_add` / `saturating_sub` to prevent wrap-around even if overflow
checks are somehow bypassed.

## Binary Hardening

### Compiler Flags

| Setting | Value | Effect |
|---------|-------|--------|
| `lto` | `"thin"` | Link-time optimization for smaller binaries |
| `codegen-units` | `1` | Deterministic codegen, enables whole-program optimization |
| `opt-level` | `3` | Maximum optimization |
| `strip` | `"symbols"` | Remove symbol tables from release binaries |
| `overflow-checks` | `true` | Runtime integer overflow detection |
| `-Ctrim-paths=all` | RUSTFLAGS | Strip build paths from binaries |

### Platform Protections

Rust binaries on Linux are compiled as Position Independent Executables (PIE)
by default, enabling full ASLR. Combined with the OS defaults:

- **PIE + ASLR**: Address space layout randomization
- **Stack canaries**: Enabled by default in Rust's LLVM backend
- **RELRO**: Full RELRO enabled by default
- **NX**: Non-executable stack

## Supply Chain Hardening

### Dependency Management

- All GitHub Actions pinned to full SHA digests (not tags)
- `cargo-vet` or `cargo-deny` audits on every CI run
- `Cargo.lock` committed and `--locked` enforced in CI
- Dependabot configured for Cargo and GitHub Actions
- New dependencies require justification in commit messages

### Build Provenance

- SLSA provenance attestations generated for release builds
- SBOM (Software Bill of Materials) published with releases
- Container images built in CI with pinned base images

### Binary Verification

Release binaries include SHA-256 checksums. See `docs/REPRODUCIBLE_BUILDS.md`
for full reproducibility documentation.

## Runtime Hardening

### Fail-Closed Design

The core security invariant: errors always produce `Deny`, never `Allow`.

- Missing policies → Deny
- Lock poisoning → Deny (with tracing::error)
- Capacity exhaustion → Deny
- Parse failures → Deny
- Unknown fields in deserialized input → rejection (`deny_unknown_fields`)

### Input Validation

All external input is validated at system boundaries:

- **String fields**: Control character rejection (U+0000–U+009F), Unicode
  format character stripping (zero-width, bidi overrides, BOM)
- **Collections**: Bounded by `MAX_*` constants enforced in `validate()`
- **Numeric fields**: Range validation, NaN/Infinity rejection
- **Paths**: Traversal protection (reject `..` components)
- **Domains**: IDNA normalization, DNS rebinding detection
- **URLs**: SSRF prevention (private IP blocking, scheme validation)

### Injection Defense

Multi-layer injection scanning:
- Aho-Corasick pattern matching with NFKC normalization
- Homoglyph normalization (Latin confusables, mathematical alphanumeric symbols)
- ROT13 decode pass (with natural-language false positive suppression)
- Base64 decode pass
- Leetspeak normalization (14-character map)
- Regional indicator emoji smuggling detection
- Unicode tag character stripping

### TLS Workload Identity Hardening (R244)

SPIFFE workload path percent-decoding validates UTF-8 after decode. Previously,
raw decoded bytes were cast to `char` via `(hi << 4 | lo) as char`, which
produced invalid Unicode for multi-byte sequences (e.g., `%80` → U+0080 is
valid Latin-1 but invalid stand-alone UTF-8). Now:

- Percent-encoded bytes are collected into a `Vec<u8>`
- `std::str::from_utf8()` validates the decoded buffer
- Invalid UTF-8 sequences cause fail-closed rejection (`None`)
- ASCII-safe paths bypass percent-decoding entirely

### ACIS Envelope Validation (R244)

All ACIS (Agent-Consumer Interaction Surface) decision envelopes are validated
before audit persistence:

- `agent_id`: length-bounded (512), dangerous character rejection
- `reason`: length-bounded (4096), dangerous character rejection
- `findings`: each finding validated for dangerous characters
- `tool` / `function`: length-bounded (256)
- `evaluation_us`: capped at 3,600,000,000 µs (1 hour)
- `call_chain_depth`: capped at 256
- Construction-time clamping in `build_result()` / `build_acis_envelope()`
- Post-construction `validate()` with sanitization fallback (clear reason/findings
  on validation failure rather than rejecting the entire envelope)

### Cedar Policy Parser Hardening (R244)

Escape handling in Cedar `parse_head()` and `parse_when_clause()` now performs
bounds checking before advancing past a backslash:

```rust
// Before: unconditional skip could read past buffer end
if bytes[i] == b'\\' { i = i.saturating_add(2); continue; }

// After: bounds-checked skip with trailing backslash as literal
if bytes[i] == b'\\' {
    if i + 1 < len { i = i.saturating_add(2); continue; }
    // Trailing backslash — treat as literal
}
```

### Redis Cluster TLS Enforcement (R244)

`RedisBackend::new()` enforces `rediss://` (TLS) for non-localhost connections.
Localhost exemptions: `127.0.0.1`, `localhost`, `[::1]`. Approval state, rate
limits, and dedup hashes transmitted over unencrypted Redis are exposed to
network observers — TLS enforcement closes this gap.

### Cryptographic Standards

- **Audit signing**: Ed25519 (ed25519-dalek) — rationale, and the trade-offs it
  carries (not FIPS 140-3 approved, not post-quantum, no domain separation
  between artifact types), in [Security Model](SECURITY_MODEL.md#why-ed25519)
- **Credential encryption**: XChaCha20-Poly1305 with Argon2id key derivation
- **Password hashing**: Argon2id
- **Token binding**: DPoP (RFC 9449) — the complete RFC 9449 implementation is
  in the HTTP proxy's OAuth path; see [IAM](IAM.md) for which surfaces enforce it
- **Post-quantum**: Hybrid Ed25519 + ML-DSA-65 (FIPS 204), feature-gated, and
  covering audit checkpoints and rotation manifests only — not evidence packs,
  canaries, agent cards, or capability tokens
- **Timestamps**: signing host wall clock. No RFC 3161 timestamp authority,
  Roughtime, or transparency-log anchor — signatures attest authorship, not time

### Container Deployment

Recommended container security settings:

```yaml
securityContext:
  runAsNonRoot: true
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: [ALL]
  seccompProfile:
    type: RuntimeDefault
```

See `docs/SECURITY.md` for full container and systemd hardening guidance.

---

## R259-R270 Hardening Campaign (March 2026)

12-round adversarial audit campaign with 35 security findings fixed and 11 architectural hardening changes. Key additions:

### Cryptographic Integrity
- **Ed25519 evidence pack signing** — compliance artifacts (EvidencePack) are now signed with Ed25519, providing tamper detection and authorship attribution under a pinned key. `signing_content()` covers all fields including sections, recommendations, and period bounds. Note that the `generated_at` and period bounds are read from the signing host's clock and are not externally attested, so the signature does not establish *when* a pack was produced — see [Signing and timestamps](SECURITY_MODEL.md#where-signing-time-comes-from).
- **SHA-256 plugin content-hash verification** — Wasm plugin binaries are verified against a declared hash before instantiation (TOCTOU defense).
- **HMAC key minimum 32 bytes** — attestation keys shorter than 32 bytes are rejected at startup (fail-closed).

### Authentication & Authorization
- **Per-tenant API key verification** — tenants with stored `api_key_hash` require a matching Bearer token (SHA-256 + constant-time comparison via `subtle::ConstantTimeEq`).
- **FallbackBehavior::Allow gated** — semantic guardrails fail-open mode requires explicit `dangerous_allow_fail_open_acknowledged=true` (mirrors OPA pattern).
- **Transparency Full verbosity gated** — `inject_decision_explanation()` downgrades Full to Summary for non-admin callers to prevent policy structure leakage.

### NHI & Delegation
- **Eager transitive NHI revocation** — BFS-based revocation deactivates all reachable delegations from a revoked agent (depth-bounded to 50).
- **Rotation terminal state check** — `rotate_credentials()` rejects revoked/expired identities.

### Relay Hot-Path
- **Approval lineage drift enforcement** — drift detection now produces `ProxyDecision::Block` (previously logged but fell through to consume the approval).
- **ACIS audit entries** — DoW, jailbreak, token leakage, and memory query poisoning detections now produce audit entries via `log_entry_with_acis()`.
- **Store error fail-closed** — approval store errors during drift check set `drift_detected=true`.

### Infrastructure
- **Atomic signup** — `tokio::sync::Mutex` serializes tenant capacity check + creation (TOCTOU fix).
- **Webhook idempotency** — `WebhookDedup` with DashMap + TTL tracks event IDs; duplicate webhooks acknowledged without reprocessing.
- **Session persistence** — `SessionBackend` trait with write-through on every state transition; `warm_restart()` restores only Locked/Suspicious sessions.
- **Cross-tenant integration tests** — 4 tests verifying policy, approval, audit, and concurrent evaluation isolation.

### SDK Hardening (Python, TypeScript, Go, Java)
- Attestation signature must be exactly 64 hex characters
- Field type validation before HMAC construction (prevents type coercion attacks)
- Python tenant header CRLF injection prevention

### Formal Verification
- 4 new Verus kernels: DRIFT-1–4, REVOKE-1–4, EVIDENCE-SIGN-1–3, WARM-1–3
- 8 new Kani harnesses: K133-K140
- Total: 910+ verification instances (682 Verus, 116 Kani, 14 TLA+, 45 Coq, 32 Lean, 10 Alloy)
