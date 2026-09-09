# Formal Verification — Vellaveto MCP Policy Engine

Formal specifications of Vellaveto's core security properties using TLA+, Alloy,
Lean 4, Coq, Verus, and Kani.

This is the first formal model of MCP policy enforcement in any framework,
addressing Gap #1 (severity: Critical) from `docs/MCP_SECURITY_GAPS.md`.

## What's Verified

| Model | Framework | Properties | What It Covers |
|-------|-----------|------------|----------------|
| `MCPPolicyEngine.tla` | TLA+ | S1–S7, L1–L2 | First-match-wins policy evaluation, fail-closed defaults |
| `AbacForbidOverrides.tla` | TLA+ | S7–S10, L3 | ABAC forbid-overrides combining algorithm |
| `MCPTaskLifecycle.tla` | TLA+ | T1–T5, TL1–TL2 | MCP Task primitive lifecycle state machine |
| `CascadingFailure.tla` | TLA+ | C1–C5, CL1–CL2 | Multi-agent cascading failure circuit breaker |
| `CapabilityDelegation.tla` | TLA+ | D1–D5, DL1 | Capability delegation depth/expiry/issuer invariants |
| `CredentialVault.tla` | TLA+ | CV1–CV8, CVL1 | Credential vault state machine (Available→Active→Consumed) |
| `AuditChain.tla` | TLA+ | AC1–AC9, ACL1 | Audit hash chain integrity (append-only, tamper-evident) |
| `TrustContainment.tla` | TLA+ | TC1–TC6, TCL1 | Trust-tier lattice and privileged-sink containment flow rules |
| `SourceTaintContainment.tla` | TLA+ | ST1–ST4 | Source-class auto-tainting: completeness, monotonicity, inversion |
| `IntentScopeContainment.tla` | TLA+ | IS1–IS4 | Intent scope: enforcement completeness, monotonic narrowing, atomic restriction |
| `SequenceContainment.tla` | TLA+ | SQ1–SQ4 | Behavioral sequence: anomaly persistence, restriction monotonicity, warmup safety |
| `NHICredentialRotation.tla` | TLA+ | NHI-ROT-1–5 | NHI ephemeral credential rotation lifecycle: no use-after-expiry, atomic rotation, fail-closed |
| `CapabilityDelegation.als` | Alloy | S11–S16 | Capability token delegation with monotonic attenuation |
| `AbacForbidOverride.als` | Alloy | S7–S10 | ABAC forbid-override combining algorithm |
| `Determinism.lean` | Lean 4 | — | Policy evaluation determinism (same input → same verdict) |
| `FailClosed.lean` | Lean 4 | S1, S5 | Fail-closed: no match → Deny; Allow requires matching Allow policy |
| `PathNormalization.lean` | Lean 4 | — | Path normalization idempotence: `normalize(normalize(x)) = normalize(x)` |
| `AbacForbidOverride.lean` | Lean 4 | S7–S10 | ABAC forbid-overrides (first forbid wins) |
| `CapabilityDelegation.lean` | Lean 4 | S11–S16 | Capability delegation attenuation proofs |
| `verus/verified_core.rs` | Verus | V1–V8, V11–V12 | Core verdict computation + rule override proofs (ALL inputs, actual Rust) |
| `verus/verified_constraint_eval.rs` | Verus | ENG-CON-1–ENG-CON-4 | Constraint evaluation fail-closed control flow (ALL inputs, actual Rust) |
| `verus/verified_audit_append.rs` | Verus | AUD-APP-1–AUD-APP-5 | Audit append/recovery counter transitions on actual Rust |
| `verus/verified_audit_chain.rs` | Verus | AUD-CHAIN-1–AUD-CHAIN-5 | Audit-chain verification guard on actual Rust |
| `verus/verified_merkle.rs` | Verus | MERKLE-1–MERKLE-6 | Merkle append/init/proof-shape fail-closed guards on actual Rust |
| `verus/verified_merkle_fold.rs` | Verus | MERKLE-FOLD-1–MERKLE-FOLD-7 | Merkle next-level/proof-fold/peak-fold structure on actual Rust |
| `verus/verified_merkle_path.rs` | Verus | MERKLE-PATH-1–MERKLE-PATH-5 | Merkle proof sibling/orientation/parent-step structure on actual Rust |
| `verus/verified_rotation_manifest.rs` | Verus | ROT-MAN-1–ROT-MAN-3 | Cross-rotation manifest linkage and path-safety guards on actual Rust |
| `verus/verified_capability_attenuation.rs` | Verus | CAP-ATT-1–CAP-ATT-4 | Capability delegation depth/expiry attenuation on actual Rust |
| `verus/verified_capability_context.rs` | Verus | CAP-CTX-1–CAP-CTX-3 | Engine capability-token holder/issuer/depth authorization guards on actual Rust |
| `verus/verified_context_delegation.rs` | Verus | CTX-DEP-1–CTX-DEP-4 | Engine principal-presence, call-chain depth, and deputy delegation-depth guards on actual Rust |
| `verus/verified_capability_delegation_context.rs` | Verus | CAP-DEP-CTX-1–CAP-DEP-CTX-3 | Engine combined deputy-validation + capability-token fail-closed context guard on actual Rust |
| `verus/verified_bridge_principal.rs` | Verus | BRIDGE-PRINC-1–BRIDGE-PRINC-4 | Stdio bridge configured/claimed principal alignment for deputy and engine context on actual Rust |
| `verus/verified_delegation_projection.rs` | Verus | DEP-PROJ-1–DEP-PROJ-3 | Relay projection of deputy-validated delegation depth into fail-closed engine call-chain length on actual Rust |
| `verus/verified_deputy_handoff.rs` | Verus | DEP-HANDOFF-1–DEP-HANDOFF-3 | Relay promotion of deputy-validated claimed principals into engine evaluation on actual Rust |
| `verus/verified_evaluation_context_projection.rs` | Verus | EVAL-CTX-1–EVAL-CTX-4 | Combined relay projection of deputy-validated principal and delegation depth into engine evaluation context on actual Rust |
| `verus/verified_approval_scope.rs` | Verus | APPR-SCOPE-1–APPR-SCOPE-4 | Shared fail-closed approval binding for `session_id` and `action_fingerprint` on actual Rust |
| `verus/verified_approval_consumption.rs` | Verus | — | Shared single-use approval consumption gate for approved, fingerprint-bound replays on actual Rust |
| `verus/verified_presented_approval_id.rs` | Verus | — | Shared `_meta.approval_id` validation for MCP and HTTP proxy transports on actual Rust |
| `verus/verified_server_approval_id.rs` | Verus | — | HTTP server approval-id validation for path parameters and `x-vellaveto-approval-id` on actual Rust |
| `verus/verified_transport_context.rs` | Verus | TCTX-1–TCTX-4 | Shared fail-closed transport projection for `agent_identity` and `capability_token` on actual Rust |
| `verus/verified_capability_glob.rs` | Verus | CAP-GLOB-1–CAP-GLOB-5 | Capability case-insensitive glob matching and parent-glob literal-child containment on actual Rust |
| `verus/verified_capability_glob_subset.rs` | Verus | CAP-GSUB-1–CAP-GSUB-3 | Capability exact parent-glob/child-glob subset boundary on actual Rust |
| `verus/verified_capability_grant.rs` | Verus | CAP-GRANT-1–CAP-GRANT-4 | Capability grant restriction-shape and invocation attenuation on actual Rust |
| `verus/verified_capability_coverage.rs` | Verus | CAP-COV-1–CAP-COV-5 | Capability grant-coverage fail-closed path/domain restriction gate on actual Rust |
| `verus/verified_capability_domain.rs` | Verus | CAP-DOM-1–CAP-DOM-6 | Capability domain normalization, matching, and subset fail-closed gate on actual Rust |
| `verus/verified_capability_path.rs` | Verus | CAP-PATH-1–CAP-PATH-5 | Capability grant path-normalization fail-closed transition gate on actual Rust |
| `verus/verified_capability_selection.rs` | Verus | CAP-SEL-1–CAP-SEL-4 | Capability grant first-match selection rule on actual Rust |
| `verus/verified_capability_literal.rs` | Verus | CAP-LIT-1–CAP-LIT-4 | Capability literal fast paths for matching and subset fallthrough on actual Rust |
| `verus/verified_capability_pattern.rs` | Verus | CAP-PAT-1–CAP-PAT-4 | Capability subset fast-path guard on actual Rust |
| `verus/verified_capability_identity.rs` | Verus | CAP-ID-1–CAP-ID-3 | Capability holder/issuer identity-chain guards on actual Rust |
| `verus/verified_capability_verification.rs` | Verus | CAP-VER-1–CAP-VER-5 | Capability verification temporal, expected-key, and decoded-length fail-closed guards on actual Rust |
| `verus/verified_deputy.rs` | Verus | DEPUTY-1–DEPUTY-6 | Deputy chain continuity, depth, and tool-scope guards on actual Rust |
| `verus/verified_nhi_delegation.rs` | Verus | NHI-DEL-1–NHI-DEL-8 | NHI delegation terminal-state, participant, link-effective, depth, and revocation chain propagation guards on actual Rust |
| `verus/verified_nhi_graph.rs` | Verus | NHI-GRAPH-1–NHI-GRAPH-4 | NHI live-successor traversal and cycle-free delegation insertion guards on actual Rust |
| `verus/verified_refinement_safety.rs` | Verus | R-MCP-START-EMPTY, R-MCP-APPLY-DENY, R-MCP-EXHAUSTED-NOMATCH | Safety-critical policy engine refinement obligations (fail-closed) |
| `verus/verified_refinement_completeness.rs` | Verus | R-MCP-START-NONEMPTY, R-MCP-MATCH-MISS/HIT, R-MCP-APPLY-ALLOW/REQUIRE-APPROVAL, R-MCP-CONTINUE | Correctness refinement obligations — completes 9/9 simulation |
| `verus/verified_acis_action_summary.rs` | Verus | ACIS-FP-1–3, ACIS-SUM-1–5, ACIS-ENV-1–3 | ACIS fingerprint, action summary, envelope bounds on actual Rust |
| `verus/verified_source_taint.rs` | Verus | TAINT-1–5 | Phase 6.1D source-class trust floor containment on actual Rust |
| `verus/verified_intent_scope.rs` | Verus | SCOPE-1–5 | Phase 6.2E intent scope monotonic narrowing on actual Rust |
| `verus/verified_sequence_analysis.rs` | Verus | SEQ-1–6 | Phase 6.3E behavioral sequence anomaly monotonicity on actual Rust |
| `verus/verified_entropy_pipeline.rs` | Verus | EPIPE-1–6 | Entropy alert pipeline composition (millibit → gate → severity) on actual Rust |
| `verus/verified_entropy_gate.rs` | Verus | ENT-GATE-1–ENT-GATE-5 | Fixed-point entropy alert gate on actual Rust |
| `verus/verified_cross_call_dlp.rs` | Verus | CC-DLP-1–CC-DLP-5 | Cross-call DLP tracker field-capacity/update gate on actual Rust |
| `verus/verified_dlp_core.rs` | Verus | D1–D6 | Cross-call DLP buffer arithmetic (ALL inputs, actual Rust) |
| `verus/verified_path.rs` | Verus | V9-V10 | Engine path normalization kernel idempotence + no-traversal on actual Rust |
| `kani/src/proofs.rs` | Kani | K1–K132 | Bounded model checking of actual Rust |
| `FailClosed.v` | Coq | S1, S5 | Fail-closed: no match → Deny; Allow requires matching Allow policy |
| `Determinism.v` | Coq | — | Policy evaluation determinism (same input → same verdict) |
| `PathNormalization.v` | Coq | — | Path normalization idempotence: `normalize(normalize(x)) = normalize(x)` |
| `AbacForbidOverride.v` | Coq | S7–S10 | ABAC forbid-overrides combining algorithm (first forbid wins) |
| `CapabilityDelegation.v` | Coq | S11–S16 | Capability token delegation with monotonic attenuation |
| `CircuitBreaker.v` | Coq | C1–C5 | Circuit breaker state machine properties |
| `TaskLifecycle.v` | Coq | T1–T3 | MCP Task lifecycle terminal absorbing, valid transitions |

Current formal suite across 6 tools:
- all standalone Verus kernels now bind to a checker-enforced kernel-scoped
  assumption contract through `formal/verus/assumptions.rs`
- the Merkle and audit-filesystem trust boundaries now also exist as explicit
  Verus axiom modules under `formal/verus/`
- `formal/verus/Cargo.toml` now provides the canonical version-pinned
  `cargo-verus` entrypoint, while `formal/tools/verify-verus.sh` keeps the
  direct per-file `verus` fallback for offline/local runs

The current counts below are generated by `make evidence` and validated by
`make evidence-check`.

<!-- VELLAVETO:EVIDENCE:START -->
| Evidence item | Count |
|---|---:|
| Rust tests | 12922 |
| SDK tests | 977 |
| Total tests tracked by manifest | 13899 |
| Verus verified items | 1046 |
| Kani proof harnesses | 124 |
| TLA+ specs | 13 |
| Lean theorems | 32 |
| Coq theorems | 45 |
| Alloy assertions | 10 |
| Formal evidence items tracked by manifest | 1270 |
<!-- VELLAVETO:EVIDENCE:END -->

## Coverage Matrix

| Property | TLA+ | Alloy | Lean 4 | Coq | Verus | Kani |
|----------|------|-------|--------|-----|-------|------|
| **S1: Fail-closed** | S1 | — | S1 | S1 | V1, V2 | K1, K5, K14 |
| **S2: Priority ordering** | S2 | — | — | — | V6* | K18 |
| **S3: Blocked paths override** | S3 | — | — | — | V4 | K16 |
| **S4: Blocked domains override** | S4 | — | — | — | V4 | K16 |
| **S5: Allow requires match** | S5 | — | S5 | S5 | V3 | K15 |
| **S6: Missing context → Deny** | S6 | — | — | — | — | K24 |
| **S7: Forbid dominance** | S7 | S7 | S7 | S7 | — | K6 |
| **S8: Forbid ignores priority** | S8 | S8 | S8 | S8 | — | K19 |
| **S9: Permit requires no forbid** | S9 | S9 | S9 | S9 | — | K20 |
| **S10: No match → NoMatch** | S10 | S10 | S10 | S10 | — | K7 |
| **S11: Monotonic attenuation** | D1 | S11 | S11 | S11 | — | — |
| **S12: Transitive attenuation** | — | S12 | S12 | S12 | — | — |
| **S13: Depth bounded** | D2 | S13 | S13 | S13 | — | — |
| **S14: Temporal monotonicity** | D3 | S14 | S14 | S14 | — | — |
| **S15: Terminal no delegate** | D5 | S15 | S15 | S15 | — | — |
| **S16: Issuer chain integrity** | D4 | S16 | S16 | S16 | — | — |
| **C1: Chain depth bounded** | C1 | — | — | C1 | — | — |
| **C2: Error threshold → open** | C2 | — | — | C2 | — | — |
| **C3: Open denies all** | C3 | — | — | C3 | — | — |
| **C4: Half-open resolves** | C4 | — | — | C4 | — | — |
| **C5: Probe success closes** | C5 | — | — | C5 | — | — |
| **T1: Terminal absorbing** | T1 | — | — | T1 | — | — |
| **T2: Initial state** | T2 | — | — | T2 | — | — |
| **T3: Valid transitions** | T3 | — | — | T3 | — | — |
| **V8: Conditional pass-through** | — | — | — | — | V8 | K17, K25 |
| **D1: UTF-8 boundary safety** | — | — | — | — | D1 | K10, K11, K23 |
| **D2: Buffer size bounded** | — | — | — | — | D2 | K10 |
| **D3: Byte accounting correct** | — | — | — | — | D3 | K13 |
| **D4: Capacity fail-closed** | — | — | — | — | D4 | K12 |
| **D5: No arithmetic underflow** | — | — | — | — | D5 | K13 |
| **D6: Overlap completeness** | — | — | — | — | D6 | K21, K22 |
| **Path idempotence** | — | — | idem | idem | — | K2 |
| **No traversal** | — | — | no_dot | no_dot | V10 | K3 |
| **Determinism** | — | — | det | det | — | K8 |
| **Counter monotonicity** | — | — | — | — | — | K4 |
| **Domain norm idempotent** (simplified) | — | — | — | — | — | K9 |
| **IDNA fail-closed** | — | — | — | — | — | K61, K62, K63 |
| **Homoglyph idempotent** | — | — | — | — | — | K64 |
| **Confusable → ASCII** | — | — | — | — | — | K65 |
| **Lock poison safe** | — | — | — | — | — | K66, K67, K68 |
| **CV1: No double-consumption** | CV1 | — | — | — | — | K108 |
| **CV2: Active-only consume** | CV2 | — | — | — | — | K112 |
| **CV3: Epoch monotonicity** | CV3 | — | — | — | — | K109 |
| **CV4: Capacity bounded** | CV4 | — | — | — | — | K110 |
| **CV5: Fail-closed exhaustion** | CV5 | — | — | — | — | K111, K131 |
| **CV6: Binding uniqueness** | CV6 | — | — | — | — | — |
| **CV7: Active implies bound** | CV7 | — | — | — | — | — |
| **AC2: Chain linkage** | AC2 | — | — | — | AUD-CHAIN-4 | — |
| **AC3: Sequence monotonicity** | AC3 | — | — | — | AUD-CHAIN-2 | — |
| **AC4: Hash uniqueness** | AC4 | — | — | — | — | — |
| **AC6: Last hash consistency** | AC6 | — | — | — | — | — |
| **PII inversion correct** | — | — | — | — | — | K69, K70 |
| **Temporal window expiry** | — | — | — | — | — | K71, K72 |
| **Cascading FSM transitions** | C1–C5 | — | — | C1–C5 | — | K49–K52, K73–K75 |
| **Injection decode complete** | — | — | — | — | — | K76, K77 |

## Directory Structure

```
formal/
  README.md                          ← This file
  Dockerfile                         ← Reproducible Docker image (all tools pinned)
  tla/
    MCPCommon.tla                    ← Shared operators (pattern matching, sorting)
    MCPPolicyEngine.tla              ← Policy evaluation state machine
    MC_MCPPolicyEngine.tla           ← Model companion (concrete constants for TLC)
    MCPPolicyEngine.cfg              ← TLC model checker configuration
    AbacForbidOverrides.tla          ← ABAC forbid-overrides evaluation
    MC_AbacForbidOverrides.tla       ← Model companion (concrete constants for TLC)
    AbacForbidOverrides.cfg          ← TLC configuration for ABAC
    MCPTaskLifecycle.tla             ← MCP Task primitive lifecycle
    MC_MCPTaskLifecycle.tla          ← Model companion (task IDs)
    MCPTaskLifecycle.cfg             ← TLC configuration for tasks
    CascadingFailure.tla             ← Multi-agent cascading failure
    MC_CascadingFailure.tla          ← Model companion (agents, tools)
    CascadingFailure.cfg             ← TLC configuration for cascading failure
    CapabilityDelegation.tla         ← Capability delegation state machine
    MC_CapabilityDelegation.tla      ← Model companion (principals, depth)
    CapabilityDelegation.cfg         ← TLC configuration for delegation
    CredentialVault.tla              ← Credential vault state machine (CV1-CV8)
    MC_CredentialVault.tla           ← Model companion (credentials, sessions)
    CredentialVault.cfg              ← TLC configuration for credential vault
    AuditChain.tla                   ← Audit hash chain integrity (AC1-AC9)
    MC_AuditChain.tla                ← Model companion (entries, hashes)
    AuditChain.cfg                   ← TLC configuration for audit chain
    TrustContainment.tla             ← Trust-tier lattice and privileged-sink containment
    MC_TrustContainment.tla          ← Model companion (edge-case trust/sink requests)
    TrustContainment.cfg             ← TLC configuration for trust containment
  alloy/
    CapabilityDelegation.als         ← Capability token delegation model (S11-S16)
    AbacForbidOverride.als           ← ABAC forbid-override model (S7-S10)
  lean/
    lakefile.lean                    ← Lake build configuration
    lean-toolchain                   ← Lean 4 version pin
    Vellaveto/
      Determinism.lean              ← Evaluation determinism proof
      FailClosed.lean               ← Fail-closed and S1/S5 proofs
      PathNormalization.lean        ← Path normalization idempotence
      AbacForbidOverride.lean       ← ABAC forbid-override S7-S10 proofs
      CapabilityDelegation.lean     ← Capability delegation S11-S16 proofs
  coq/
    _CoqProject                      ← Build configuration (lists .v files)
    Makefile                         ← coq_makefile wrapper
    Vellaveto/
      Types.v                        ← Shared types (Verdict, Policy, Action, ABAC, CapToken)
      FailClosed.v                   ← Fail-closed and S1/S5 proofs (4 theorems)
      Determinism.v                  ← Evaluation determinism proof (4 theorems)
      PathNormalization.v            ← Path normalization idempotence (6 theorems)
      AbacForbidOverride.v           ← ABAC forbid-override S7-S10 (5 theorems)
      CapabilityDelegation.v         ← Capability delegation S11-S16 (8 theorems)
      CircuitBreaker.v               ← Circuit breaker C1-C5 (6 theorems)
      TaskLifecycle.v                ← Task lifecycle T1-T3 (10 theorems)
  verus/
    README.md                        ← Verus setup and verification guide
    Cargo.toml                       ← Canonical cargo-verus manifest
    src/lib.rs                       ← Cargo-verus shim that wires the full proof suite
    assumptions.rs                   ← Shared Verus-facing kernel-assumption registry mirror
    merkle_boundary_axioms.rs        ← Trusted Merkle hash/codec axiom surface
    audit_fs_boundary_axioms.rs      ← Trusted audit-filesystem axiom surface
    verified_core.rs                 ← Core verdict logic (V1-V8, V11-V12)
    verified_constraint_eval.rs      ← Constraint evaluation fail-closed kernel (ENG-CON-1–ENG-CON-4)
    verified_audit_append.rs         ← Audit append/recovery counter transitions (19 verified)
    verified_audit_chain.rs          ← Audit-chain verification guard (19 verified)
    verified_merkle.rs               ← Merkle append/init/proof-shape fail-closed guards (23 verified)
    verified_merkle_fold.rs          ← Merkle next-level/proof-fold/peak-fold structure (17 verified)
    verified_merkle_path.rs          ← Merkle proof sibling/orientation/parent structure (15 verified)
    verified_rotation_manifest.rs    ← Cross-rotation manifest linkage/path-safety guards (16 verified)
    verified_capability_attenuation.rs ← Capability delegation depth/expiry attenuation (13 verified)
    verified_capability_context.rs   ← Engine capability-token holder/issuer/depth guards (12 verified)
    verified_context_delegation.rs   ← Engine call-chain/principal delegation guards (11 verified)
    verified_capability_delegation_context.rs ← Engine combined deputy/capability context guard (11 verified)
    verified_bridge_principal.rs     ← Stdio bridge principal-binding alignment (12 verified)
    verified_delegation_projection.rs ← Deputy depth projection into engine call-chain length (7 verified)
    verified_deputy_handoff.rs       ← Deputy-validated claim promotion into engine evaluation (9 verified)
    verified_evaluation_context_projection.rs ← Combined relay projection into engine evaluation context (9 verified)
    verified_approval_scope.rs      ← Shared fail-closed approval binding for session and action scope (9 verified)
    verified_approval_consumption.rs ← Shared single-use approval consumption gate (7 verified)
    verified_presented_approval_id.rs ← Shared `_meta.approval_id` validation gate (6 verified)
    verified_server_approval_id.rs  ← HTTP server approval-id validation gate (6 verified)
    verified_transport_context.rs    ← Shared fail-closed transport projection for sensitive context fields (10 verified)
    verified_capability_glob.rs      ← Capability case-insensitive glob matching + parent-glob literal-child containment (19 verified)
    verified_capability_glob_subset.rs ← Capability exact parent-glob/child-glob subset boundary (11 verified)
    verified_capability_grant.rs     ← Capability grant restriction/invocation attenuation (10 verified)
    verified_capability_coverage.rs  ← Capability grant-coverage path/domain restriction gate (10 verified)
    verified_capability_domain.rs    ← Capability domain normalization/matching/subset gate (16 verified)
    verified_capability_path.rs      ← Capability grant path fail-closed normalization transition gate (9 verified)
    verified_capability_literal.rs   ← Capability literal matching/subset fast paths (11 verified)
    verified_capability_pattern.rs   ← Capability subset fast-path guard (12 verified)
    verified_capability_identity.rs  ← Capability holder/issuer identity-chain guards (11 verified)
    verified_capability_verification.rs ← Capability verification temporal/expected-key/length guards (15 verified)
    verified_deputy.rs               ← Deputy chain continuity/depth/tool guards (15 verified)
    verified_nhi_delegation.rs       ← NHI delegation terminal/participant/link/depth/revocation guards (19 verified)
    verified_nhi_graph.rs            ← NHI delegation live-successor/cycle-free insertion guards (9 verified)
    verified_refinement_safety.rs    ← Safety-critical policy engine refinement obligations (16 verified)
    verified_entropy_gate.rs         ← Fixed-point entropy alert gate (13 verified)
    verified_cross_call_dlp.rs       ← Cross-call tracker field-capacity/update gate (11 verified)
    verified_dlp_core.rs             ← DLP buffer arithmetic (D1-D6, 16 verified)
    verified_path.rs                 ← Engine path normalization idempotence + no-traversal (33 verified)
  kani/
    Cargo.toml                       ← Standalone crate (excluded from workspace)
    README.md                        ← Kani setup and usage guide
    src/
      lib.rs                         ← Crate root (K1-K85 property catalog)
      proofs.rs                      ← Proof harnesses (90 harnesses)
      path.rs                        ← Path normalization (from vellaveto-engine)
      verified_core.rs               ← Verdict computation (Verus bridge)
      dlp_core.rs                    ← DLP buffer arithmetic (Verus bridge)
      ip.rs                          ← IP address verification (Phase 5)
      cache.rs                       ← Cache safety (Phase 6)
      capability.rs                  ← Capability delegation (Phase 7)
      rule_check.rs                  ← Rule checking fail-closed (Phase 8)
      resolve.rs                     ← ResolvedMatch equivalence (Phase 9)
      cascading.rs                   ← Cascading failure (Phase 10)
      constraint.rs                  ← Constraint evaluation (Phase 11)
      task.rs                        ← Task lifecycle (Phase 12)
      entropy.rs                     ← Shannon entropy (collusion detection)
      domain.rs                      ← IDNA domain normalization wrapper
      unicode.rs                     ← Homoglyph normalization (from vellaveto-types)
      lock_safety.rs                 ← RwLock poisoning fail-closed predicates
      sanitizer.rs                   ← PII sanitizer bidirectional inversion
      temporal_window.rs             ← Collusion temporal window correctness
      cascading_fsm.rs               ← Cascading failure FSM transitions
      injection_pipeline.rs          ← Injection scanner decode pipeline
      trust_containment.rs           ← Trust-tier gating for privileged sinks
      output_contracts.rs            ← Semantic output-contract violation matrix
      counterfactual_containment.rs  ← Lightweight counterfactual approval threshold
```

## Tooling Setup

### TLA+ (TLC Model Checker)

Download `tla2tools.jar` from the [TLA+ releases](https://github.com/tlaplus/tlaplus/releases).

Requirements:
- Java 11+
- `tla2tools.jar` (or install the TLA+ Toolbox IDE)

### Alloy Analyzer 6

Download from [alloytools.org](https://alloytools.org/download.html).

Requirements:
- Java 11+
- `org.alloytools.alloy.dist.jar`

### Coq

Install via opam or nix:

```bash
# Via opam (recommended):
opam install coq

# Via nix:
nix-shell -p coq
```

Requirements:
- Coq 8.16+ (tested with 8.19)
- `coq_makefile` (included with Coq)

## Running Verification

### Docker (Reproducible, All Tools)

The easiest way to run the full formal mesh with pinned, SHA256-verified tools:

```bash
# Build the image (first run downloads ~2GB of tools)
make formal-docker

# Or run a single toolchain
docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-verus
docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-kani
docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-tla
docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-lean
docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-coq
docker run --rm -v "$(pwd):/workspace" vellaveto-formal make formal-trusted-assumptions
```

The Dockerfile pins every version to match CI: Verus `0.2026.03.01.25809cb`,
Kani `0.67.0`, TLA+ `v1.8.0`, Lean 4 `v4.16.0` (via elan `v4.2.0`),
Rust `1.94.0` + `1.93.1`, Coq via Ubuntu 24.04 apt. All binary downloads are
SHA256-verified.

### TLA+ Policy Engine (S1–S6, L1–L2)

```bash
cd formal/tla
# Note: TLC runs against the MC (model companion) module, which extends the spec.
java -jar tla2tools.jar -config MCPPolicyEngine.cfg MC_MCPPolicyEngine.tla
```

Expected output: all 7 invariants and 2 temporal properties pass with zero violations.

### TLA+ ABAC Forbid-Overrides (S7–S10, L3)

```bash
cd formal/tla
java -jar tla2tools.jar -config AbacForbidOverrides.cfg MC_AbacForbidOverrides.tla
```

Expected output: all 4 invariants and 1 liveness property pass with zero violations.

### TLA+ Capability Delegation (D1–D5, DL1)

```bash
cd formal/tla
java -jar tla2tools.jar -config CapabilityDelegation.cfg MC_CapabilityDelegation.tla
```

Expected output: all 5 invariants and 1 liveness property pass with zero violations.

### Alloy Capability Delegation (S11–S16)

```bash
cd formal/alloy
# GUI mode (recommended for first run — shows counterexample visualizations):
java -jar org.alloytools.alloy.dist.jar

# Open CapabilityDelegation.als in the Alloy Analyzer and execute all check commands.
```

Expected output: all 6 assertions pass with 0 counterexamples found.

### Alloy ABAC Forbid-Override (S7–S10)

```bash
cd formal/alloy
java -jar org.alloytools.alloy.dist.jar

# Open AbacForbidOverride.als and execute all check commands.
```

Expected output: all 4 assertions pass with 0 counterexamples found.

### TLA+ Task Lifecycle (T1–T5, TL1–TL2)

```bash
cd formal/tla
java -jar tla2tools.jar -config MCPTaskLifecycle.cfg MC_MCPTaskLifecycle.tla
```

Expected output: all 5 invariants and 2 temporal properties pass with zero violations.

### TLA+ Cascading Failure (C1–C5, CL1–CL2)

```bash
cd formal/tla
java -jar tla2tools.jar -config CascadingFailure.cfg MC_CascadingFailure.tla
```

Expected output: all 5 invariants and 2 temporal properties pass with zero violations.

### TLA+ Credential Vault (CV1–CV8, CVL1)

```bash
cd formal/tla
java -jar tla2tools.jar -config CredentialVault.cfg MC_CredentialVault.tla
```

Expected output: all 6 invariants and 2 temporal properties pass with zero violations.

### TLA+ Audit Chain (AC1–AC9, ACL1)

```bash
cd formal/tla
java -jar tla2tools.jar -config AuditChain.cfg MC_AuditChain.tla
```

Expected output: all 7 invariants and 2 temporal properties pass with zero violations.

### TLA+ Trust Containment (TC1–TC6, TCL1)

```bash
cd formal/tla
java -jar tla2tools.jar -config TrustContainment.cfg MC_TrustContainment.tla
```

Expected output: all 6 invariants and 1 temporal property pass with zero violations.

### Kani Extracted Code Parity Check

```bash
bash formal/tools/check-kani-parity.sh
```

Expected output: all parity checks pass. Run this after modifying any
function that is extracted into `formal/kani/src/` to detect drift.

### Lean 4 Proofs

```bash
cd formal/lean
# Install Lean 4 if not already present:
#   curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
lake build
```

Expected output: all five files type-check with no `sorry` markers and no warnings.

### Coq Proofs

```bash
cd formal/coq
make
```

Expected output: all 8 `.v` files compile cleanly with no `Admitted` markers.
Verify: `grep -r "Admitted\|admit" Vellaveto/*.v` returns no matches.

### Verus Proofs (audit, capability, engine, DLP, and path kernels)

```bash
# Option 1: Binary release (recommended)
VERUS_VERSION="0.2026.03.01.25809cb"
curl -sSL -o verus.zip \
  "https://github.com/verus-lang/verus/releases/download/release/${VERUS_VERSION}/verus-${VERUS_VERSION}-x86-linux.zip"
unzip verus.zip -d verus-bin
rustup install 1.93.1-x86_64-unknown-linux-gnu

# Audit append/recovery counter transitions (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_audit_append.rs

# Audit-chain verification guard (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_audit_chain.rs

# Merkle append/init/proof-shape fail-closed guards (23 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_merkle.rs

# Merkle next-level/proof-fold/peak-fold structure (17 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_merkle_fold.rs

# Merkle proof sibling/orientation/parent structure (15 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_merkle_path.rs

# Cross-rotation manifest linkage/path-safety guards (16 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_rotation_manifest.rs

# Capability attenuation depth/expiry kernel (13 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_attenuation.rs

# Stdio bridge principal-binding alignment (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_bridge_principal.rs

# Engine call-chain/principal delegation guards (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_context_delegation.rs

# Engine combined deputy/capability context guard (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_delegation_context.rs

# Deputy delegation-depth projection into engine call-chain length (7 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_delegation_projection.rs

# Deputy-validated claim promotion into engine evaluation (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_deputy_handoff.rs

# Combined relay projection into engine evaluation context (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_evaluation_context_projection.rs

# Shared approval scope binding gate (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_approval_scope.rs

# Shared fail-closed transport projection for sensitive context fields (10 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_transport_context.rs

# Engine capability-token holder/issuer/depth guards (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_context.rs

# Capability parent-glob literal-child matcher (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_glob.rs

# Capability exact parent-glob/child-glob subset boundary (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_glob_subset.rs

# Capability grant restriction/invocation kernel (10 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_grant.rs

# Capability grant-coverage path/domain restriction gate (10 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_coverage.rs

# Capability domain normalization/matching/subset gate (16 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_domain.rs

# Capability literal fast paths (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_literal.rs

# Capability subset fast-path guard (12 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_pattern.rs

# Capability holder/issuer identity-chain guards (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_identity.rs

# Capability verification temporal/expected-key/length guards (15 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_capability_verification.rs

# Deputy chain continuity/depth/tool guards (15 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_deputy.rs

# NHI delegation terminal/participant/link/depth/revocation guards (19 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_nhi_delegation.rs

# NHI delegation live-successor/cycle-free insertion guards (9 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_nhi_graph.rs

# Safety-critical refinement obligations (16 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_refinement_safety.rs

# Constraint evaluation fail-closed control flow (ENG-CON-1–ENG-CON-4, 14 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_constraint_eval.rs

# Core verdict + rule override (14 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_core.rs

# Fixed-point entropy alert gate (13 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_entropy_gate.rs

# Cross-call DLP tracker gate (11 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_cross_call_dlp.rs

# DLP buffer arithmetic (D1-D6, 16 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_dlp_core.rs

# Path normalization no-traversal (33 verified)
verus-bin/verus-x86-linux/verus --triggers-mode silent formal/verus/verified_path.rs
```

Expected output:
- `verified_audit_append.rs`: `verification results:: 19 verified, 0 errors`
- `verified_audit_chain.rs`: `verification results:: 19 verified, 0 errors`
- `verified_merkle.rs`: `verification results:: 23 verified, 0 errors`
- `verified_merkle_fold.rs`: `verification results:: 17 verified, 0 errors`
- `verified_merkle_path.rs`: `verification results:: 15 verified, 0 errors`
- `verified_rotation_manifest.rs`: `verification results:: 16 verified, 0 errors`
- `verified_capability_attenuation.rs`: `verification results:: 13 verified, 0 errors`
- `verified_capability_context.rs`: `verification results:: 12 verified, 0 errors`
- `verified_context_delegation.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_delegation_context.rs`: `verification results:: 11 verified, 0 errors`
- `verified_bridge_principal.rs`: `verification results:: 12 verified, 0 errors`
- `verified_delegation_projection.rs`: `verification results:: 7 verified, 0 errors`
- `verified_deputy_handoff.rs`: `verification results:: 9 verified, 0 errors`
- `verified_evaluation_context_projection.rs`: `verification results:: 9 verified, 0 errors`
- `verified_approval_scope.rs`: `verification results:: 9 verified, 0 errors`
- `verified_transport_context.rs`: `verification results:: 10 verified, 0 errors`
- `verified_capability_glob.rs`: `verification results:: 19 verified, 0 errors`
- `verified_capability_glob_subset.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_grant.rs`: `verification results:: 10 verified, 0 errors`
- `verified_capability_coverage.rs`: `verification results:: 10 verified, 0 errors`
- `verified_capability_domain.rs`: `verification results:: 16 verified, 0 errors`
- `verified_capability_literal.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_pattern.rs`: `verification results:: 12 verified, 0 errors`
- `verified_capability_identity.rs`: `verification results:: 11 verified, 0 errors`
- `verified_capability_verification.rs`: `verification results:: 15 verified, 0 errors`
- `verified_deputy.rs`: `verification results:: 15 verified, 0 errors`
- `verified_nhi_delegation.rs`: `verification results:: 19 verified, 0 errors`
- `verified_nhi_graph.rs`: `verification results:: 9 verified, 0 errors`
- `verified_refinement_safety.rs`: `verification results:: 16 verified, 0 errors`
- `verified_constraint_eval.rs`: `verification results:: 14 verified, 0 errors`
- `verified_cross_call_dlp.rs`: `verification results:: 11 verified, 0 errors`
- `verified_core.rs`: `verification results:: 14 verified, 0 errors`
- `verified_entropy_gate.rs`: `verification results:: 13 verified, 0 errors`
- `verified_dlp_core.rs`: `verification results:: 16 verified, 0 errors`
- `verified_path.rs`: `verification results:: 33 verified, 0 errors`

### Kani Proof Harnesses (K1–K85)

```bash
cd formal/kani
# Install Kani: cargo install --locked kani-verifier --version 0.67.0 && cargo kani setup

# Run parity tests first (fast, no Kani needed)
cargo test --lib

# Run individual harnesses (examples)
cargo kani --harness proof_fail_closed_no_match_produces_deny
cargo kani --harness proof_is_embedded_ipv4_reserved_parity   # K29: full 2^32 IPv4 space
cargo kani --harness proof_is_cacheable_context_no_session_state  # K33
cargo kani --harness proof_grant_is_subset_reflexive           # K36
cargo kani --harness proof_path_rules_blocked_before_allowed   # K42
cargo kani --harness proof_apply_policy_equivalence            # K48
cargo kani --harness proof_terminal_state_immutable            # K56
cargo kani --harness proof_idna_failure_non_ascii_fail_closed  # K61
cargo kani --harness proof_normalize_homoglyphs_idempotent     # K64
cargo kani --harness proof_all_lock_poison_handlers_safe       # K68
cargo kani --harness proof_injection_known_patterns_detected   # K77
cargo kani --harness proof_trust_containment_insufficient_trust_requires_gate  # K78
cargo kani --harness proof_output_contract_data_blocks_privilege_escalating_drift  # K80
cargo kani --harness proof_counterfactual_gate_triggers_for_quarantined_command_like_privileged_flow  # K84
```

Expected output: all 90 harnesses report VERIFICATION:- SUCCESSFUL.

## Property Catalog

### Policy Engine Safety (S1–S6)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S1 | **Fail-closed:** no matching policy → Deny, never Allow | `vellaveto-engine/src/lib.rs:417-419` | TLA+, Lean, Coq, **Verus V1/V2**, Kani K1/K5/K14 |
| S2 | **Priority ordering:** policies evaluated in priority-descending order | `vellaveto-engine/src/lib.rs:209-224` | TLA+, **Verus V6**, Kani K18 |
| S3 | **Blocked paths override allowed:** first-match blocked path → Deny | `vellaveto-engine/src/rule_check.rs:50-59` | TLA+, **Verus V4**, Kani K16 |
| S4 | **Blocked domains override allowed:** first-match blocked domain → Deny | `vellaveto-engine/src/rule_check.rs:124-133` | TLA+, **Verus V4**, Kani K16 |
| S5 | **Allow requires matching Allow policy:** Allow verdict only from Allow policy | `vellaveto-engine/src/lib.rs:545-547` | TLA+, Lean, Coq, **Verus V3**, Kani K15 |
| S6 | **Missing context → Deny:** context-conditions without context → Deny | `vellaveto-engine/src/lib.rs:519-535` | TLA+, Kani K24 |

### ABAC Safety (S7–S10)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S7 | **Forbid dominance:** any matching forbid → Deny (regardless of permits) | `vellaveto-engine/src/abac.rs:226-230` | TLA+, Alloy, Lean, Coq, Kani K6 |
| S8 | **Forbid ignores priority:** low-priority forbid beats high-priority permit | `vellaveto-engine/src/abac.rs` | TLA+, Alloy, Lean, Coq, Kani K19 |
| S9 | **Permit requires no forbid:** Allow only when zero forbids match | `vellaveto-engine/src/abac.rs:232-236` | TLA+, Alloy, Lean, Coq, Kani K20 |
| S10 | **No match → NoMatch:** nothing matches → NoMatch (caller decides) | `vellaveto-engine/src/abac.rs:239` | TLA+, Alloy, Lean, Coq, Kani K7 |

### Capability Delegation Safety (S11–S16 / D1–D5)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| S11/D1 | **Monotonic attenuation / depth:** child grants ⊆ parent, depth decreases | `capability_token.rs:470-508` | TLA+ D1, Alloy S11, Lean S11, Coq S11, Kani K36-K40 |
| S12 | **Transitive attenuation:** holds across entire delegation chains | Derived from S11 | Alloy S12, Lean S12, Coq S12 |
| S13/D2 | **Depth budget:** chain length ≤ MAX_DELEGATION_DEPTH | `capability.rs:21` | TLA+ D2, Alloy S13, Lean S13, Coq S13 |
| S14/D3 | **Temporal monotonicity:** child.expiry ≤ parent.expiry | `capability_token.rs:172-176` | TLA+ D3, Alloy S14, Lean S14, Coq S14 |
| S15/D5 | **Terminal cannot delegate:** depth=0 → no children | `capability_token.rs:128-131` | TLA+ D5, Alloy S15, Lean S15, Coq S15 |
| S16/D4 | **Issuer chain integrity:** child.issuer = parent.holder | `capability_token.rs:195` | TLA+ D4, Alloy S16, Lean S16, Coq S16 |

### Task Lifecycle Safety (T1–T5)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| T1 | **Terminal absorbing:** completed/failed/cancelled are permanent | `task_state.rs` | TLA+ T1, Coq T1 |
| T2 | **Initial state:** tasks begin in Working or Failed | MCP 2025-11-25 Tasks spec | TLA+ T2, Coq T2 |
| T3 | **Policy evaluated / valid transitions:** every task has verdict, only valid transitions | `task_state.rs` | TLA+ T3, Coq T3 |
| T4 | **Terminal audited:** terminal tasks always have audit events | `events.rs` | TLA+ T4 |
| T5 | **Bounded concurrency:** non-terminal tasks ≤ MaxTasks | `task_state.rs` | TLA+ T5 |

### Cascading Failure Safety (C1–C5)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| C1 | **Chain depth bounded:** call chain ≤ MaxChainDepth | `cascading.rs` | TLA+ C1, Coq C1 |
| C2 | **Error threshold:** consecutive errors trigger circuit open | OWASP ASI08 | TLA+ C2, Coq C2 |
| C3 | **Open denies all:** open circuit rejects requests (fail-closed) | `cascading.rs` | TLA+ C3, Coq C3 |
| C4 | **Half-open transient:** half-open is a transient probe state | Circuit breaker pattern | TLA+ C4, Coq C4 |
| C5 | **Probe success closes:** successful probe returns to closed | Circuit breaker pattern | TLA+ C5, Coq C5 |

### Credential Vault Safety (CV1–CV8)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| CV1 | **No double-consumption:** Consumed credential never consumed again | `credential_vault.rs:167-200` | TLA+ CV1 |
| CV2 | **Active-only consume:** only Active → Consumed (R238-SHLD-6) | `credential_vault.rs:182-187` | TLA+ CV2 |
| CV3 | **Epoch monotonicity:** current_epoch never decreases | `credential_vault.rs:99-101` | TLA+ CV3, CV3_Temporal |
| CV4 | **Capacity bounded:** entries ≤ MAX_VAULT_ENTRIES | `credential_vault.rs:87-91` | TLA+ CV4 |
| CV5 | **Fail-closed exhaustion:** no Available credential → no session | `credential_vault.rs:139-144` | TLA+ CV5 |
| CV6 | **Binding uniqueness:** no two sessions share a credential | `session_unlinker.rs` | TLA+ CV6 |
| CV7 | **Active implies bound:** Active credential always has a session | Structural | TLA+ CV7 |
| CV8 | **Error preserves state:** errors don't change credentials | `credential_vault.rs:153-155` | TLA+ CV8 |

### Audit Chain Integrity (AC1–AC9)

| ID | Property | Source | Spec Location |
|----|----------|--------|---------------|
| AC1 | **Append-only:** log only grows within rotation cycle | `logger.rs:526-529` (append mode) | TLA+ AC1 |
| AC2 | **Chain linkage:** entry[n].prev_hash = entry[n-1].hash | `logger.rs:513,519-520` | TLA+ AC2 |
| AC3 | **Sequence monotonicity:** sequence numbers strictly increase | `logger.rs:490-495` (SeqCst counter) | TLA+ AC3, AC3_Temporal |
| AC4 | **Hash uniqueness:** distinct entries have distinct hashes | `logger.rs:288-301` (SHA-256) | TLA+ AC4 |
| AC5 | **First entry linkage:** respects rotation boundary | `logger.rs:513` | TLA+ AC5 |
| AC6 | **Last hash consistency:** lastHash = log[last].hash | `logger.rs:519-520` | TLA+ AC6 |
| AC7 | **ID uniqueness:** UUID uniqueness across entries | `logger.rs:506` (Uuid::new_v4) | TLA+ AC7 |
| AC8 | **Sequence uniqueness:** no duplicate sequence numbers | `logger.rs:490-495` (fetch_add SeqCst) | TLA+ AC8 |
| AC9 | **Error preserves log:** I/O errors don't corrupt chain | `logger.rs:526-545` | TLA+ AC9 |

### Verus Core Verdict (V1–V8, proven for ALL inputs on actual Rust)

| ID | Property | Postcondition |
|----|----------|--------------|
| V1 | **Fail-closed empty** | `len() == 0 ==> Deny` |
| V2 | **Fail-closed no match** | All `!matched` → Deny |
| V3 | **Allow requires match** | `Allow` → ∃ matching Allow with no override |
| V4 | **Rule override forces Deny** | Path/network/IP override → Deny |
| V5 | **Totality** | Function always terminates |
| V6 | **Priority ordering** | Higher-priority wins (requires `is_sorted`). Compositional*: Kani K18 proves sort, Verus proves first-match-wins given sorted input. |
| V7 | **Deny-dominance at equal priority** | Deny beats Allow (requires `is_sorted`). Compositional*: same as V6. |
| V8 | **Conditional pass-through** | Unfired condition → evaluation continues |

Source: `formal/verus/verified_core.rs` (14 verified, 0 errors)

### Verus Cross-Call DLP (D1–D6, proven for ALL inputs on actual Rust)

| ID | Property | Meaning |
|----|----------|---------|
| D1 | **UTF-8 boundary safety** | `extract_tail` never returns start in mid-character |
| D2 | **Buffer size bounded** | Extracted tail ≤ `max_size` bytes |
| D3 | **Byte accounting correct** | `update_total_bytes` maintains consistency |
| D4 | **Capacity fail-closed** | At `max_fields`, `can_track_field` returns false |
| D5 | **No arithmetic underflow** | Saturating subtraction prevents wrapping |
| D6 | **Overlap completeness** | Secret ≤ 2 × overlap split at `split_point ≤ overlap_size` fully covered (first fragment must fit in tail buffer) |

Source: `formal/verus/verified_dlp_core.rs` (16 verified, 0 errors)

### Kani Proof Harnesses (K1–K85, bounded model checking on actual Rust)

| ID | Property | Bridge |
|----|----------|--------|
| K1 | **Fail-closed:** empty policies → Deny | — |
| K2 | **Path idempotence:** `normalize(normalize(x)) == normalize(x)` | — |
| K3 | **No traversal:** normalized path has no `..` | — |
| K4 | **Counter monotonicity:** `saturating_add` never decreases | — |
| K5 | **Error → Deny:** evaluation errors produce Deny | — |
| K6 | **ABAC forbid dominance:** matching forbid → Deny | — |
| K7 | **ABAC no-match → NoMatch:** no matches → NoMatch | — |
| K8 | **Evaluation determinism:** same input → same output | — |
| K9 | **Simplified domain normalization idempotent** (lowercase + trim) | — |
| K10 | **extract_tail no panic** for arbitrary bytes | D1, D2 |
| K11 | **UTF-8 boundary exhaustive** (all 256 bytes) | D1 |
| K12 | **can_track_field fail-closed** at capacity | D4 |
| K13 | **update_total_bytes saturating** correctness | D3, D5 |
| K14 | **compute_verdict fail-closed** empty | V1 |
| K15 | **compute_verdict allow requires match** | V3 |
| K16 | **compute_verdict rule_override forces deny** | V4 |
| K17 | **compute_verdict conditional pass-through** | V8 |
| K18 | **Sort produces sorted output** (Verus precondition) | V6, V7 |
| K19 | **ABAC forbid ignores priority order** | S8 |
| K20 | **ABAC permit requires no forbid** | S9 |
| K21 | **Overlap covers small secrets** | D6 |
| K22 | **Overlap region size saturating** | D6 |
| K23 | **extract_tail multibyte boundary** (4-byte emoji) | D1 |
| K24 | **context_deny overrides allow** | V3 |
| K25 | **all_constraints_skipped fail-closed** | V8 |
| K26 | **127.x.x.x always private** (loopback) | IP |
| K27 | **RFC 1918 ranges always private** | IP |
| K28 | **CGNAT 100.64.0.0/10 always private** | IP |
| K29 | **is_embedded_ipv4_reserved parity** with is_private_ipv4 | IP |
| K30 | **IPv4-mapped extraction correct** | IP |
| K31 | **Teredo XOR inversion round-trip** | IP |
| K32 | **Known public IPs NOT private** | IP |
| K33 | **is_cacheable → no session state** | Cache |
| K34 | **Cache key case-insensitive** | Cache |
| K35 | **Staleness monotonic** (TTL + generation) | Cache |
| K36 | **grant_is_subset reflexive** | S11 |
| K37 | **No capability escalation** | S11 |
| K38 | **pattern_is_subset correctness** | S11 |
| K39 | **glob_match("*", any) == true** | — |
| K40 | **normalize_path_for_grant no traversal** | S11 |
| K41 | **Empty paths + allowlist → Deny** | Rules |
| K42 | **Blocked before allowed** | Rules |
| K43 | **IDNA failure → Deny** | Rules |
| K44 | **IP rules + no resolved IPs → Deny** | Rules |
| K45 | **block_private + private IP → Deny** | Rules |
| K46 | **Path deny → rule_override_deny** | V11 |
| K47 | **Context deny → Deny** | V12 |
| K48 | **Inline verdict == verified verdict** | Equivalence |
| K49 | **NaN/Infinity config → rejected** | Cascading |
| K50 | **Chain depth never wraps** | Cascading |
| K51 | **MAX capacity → Deny** | Cascading |
| K52 | **Error rate ∈ [0.0, 1.0]** | Cascading |
| K53 | **All constraints skipped → detected** | Constraint |
| K54 | **Forbidden param → Deny** | Constraint |
| K55 | **require_approval → RequireApproval** | Constraint |
| K56 | **Terminal state immutable** | Task, T1 |
| K57 | **Max tasks → reject** | Task, T5 |
| K58 | **Self-cancel authorization** | Task |
| K59 | **Entropy finite, non-negative, ≤ 8.0** | Collusion |
| K60 | **Grant coverage fail-closed** | Capability |
| K61 | **IDNA failure non-ASCII → None** | Domain |
| K62 | **IDNA failure ASCII → lowercase fallback** | Domain |
| K63 | **Wildcard prefix preserved** | Domain |
| K64 | **Homoglyph normalization idempotent** | Unicode |
| K65 | **Confusables collapse to ASCII** | Unicode |
| K66 | **Cache lock poison → miss** | Lock safety |
| K67 | **Deputy lock poison → error** | Lock safety |
| K68 | **All lock handlers fail-closed** | Lock safety |
| K69 | **PII sanitizer round-trip inversion** | Sanitizer |
| K70 | **PII token uniqueness** | Sanitizer |
| K71 | **Temporal window expiry** | Temporal window |
| K72 | **Temporal window cutoff precision** | Temporal window |
| K73 | **Circuit break guard requires threshold + min_events** | Cascading FSM |
| K74 | **Half-open probe timing correct** | Cascading FSM |
| K75 | **Recovery requires error_rate below threshold** | Cascading FSM |
| K76 | **Injection pipeline completeness** | Injection |
| K77 | **Known injection patterns detected** | Injection |
| K78 | **Insufficient trust requires explicit gate** | Trust containment |
| K79 | **Sufficient trust skips explicit gate** | Trust containment |
| K80 | **Data contracts block privilege-escalating drift** | Semantic output contracts |
| K81 | **Free-text/tool-output contracts block URL/command/approval drift** | Semantic output contracts |
| K82 | **Resource/URL contracts only escalate on command/approval drift** | Semantic output contracts |
| K83 | **Counterfactual gate requires security-relevant taint** | Counterfactual containment |
| K84 | **Quarantined command-like privileged flows force counterfactual gate** | Counterfactual containment |
| K85 | **Verified untrusted tool output stays below counterfactual gate** | Counterfactual containment |

### Harness Assurance Levels

Not all Kani harnesses provide the same assurance. The table below classifies
each by input space coverage:

| Level | Harnesses | Description |
|-------|-----------|-------------|
| **Full symbolic** | K2, K3, K4, K6, K7, K9, K10, K11, K12, K13, K16, K18, K20, K22, K26, K27, K28, K29, K30, K31, K33, K34, K35, K39, K40, K41, K42, K43, K44, K45, K46, K47, K48, K50, K52, K53, K54, K55, K56, K57, K58, K66, K67, K68, K70, K71, K72, K73, K74, K75, K78, K79, K80, K81, K82, K83, K84, K85 | All fields symbolic within CBMC bounds. Explores full input space. |
| **Partial symbolic** | K15, K21 | Some fields symbolic, others fixed. Explores a subspace. |
| **Single-case** | K1, K5, K8, K14, K17, K19, K23, K24, K25, K32, K36, K37, K38, K49, K51, K59, K60, K61, K62, K63, K64, K65, K69, K76, K77 | Specific scenario test. Confirms property for specific cases. |

Single-case harnesses (K1, K5, K8) verify the trivial `evaluate_empty_policies()`
stub, not the full production `evaluate_action()`. The production fail-closed
property is proven by Verus V1/V2 on `compute_verdict` and exercised by the
Rust test inventory tracked in the generated evidence manifest.

### Liveness (L1–L3, TL1–TL2, CL1–CL2, DL1, TCL1)

| ID | Property | Spec Location |
|----|----------|---------------|
| L1 | **Eventual verdict:** every pending action eventually receives a verdict | `MCPPolicyEngine.tla` |
| L2 | **No stuck states:** engine never permanently stuck | `MCPPolicyEngine.tla` |
| L3 | **ABAC eventual decision:** every pending ABAC eval eventually gets a decision | `AbacForbidOverrides.tla` |
| TL1 | **Task termination:** every task eventually reaches a terminal state | `MCPTaskLifecycle.tla` |
| TL2 | **Input resolved:** input-required tasks eventually resume or terminate | `MCPTaskLifecycle.tla` |
| CL1 | **Circuit recovery:** open circuits eventually transition to half-open | `CascadingFailure.tla` |
| CL2 | **Half-open resolves:** half-open circuits eventually close or reopen | `CascadingFailure.tla` |
| DL1 | **Delegation terminates:** delegation chains exhaust depth budget | `CapabilityDelegation.tla` |
| CVL1 | **Vault error recovery:** vault eventually recovers from errors | `CredentialVault.tla` |
| ACL1 | **Audit error recovery:** audit chain eventually recovers from errors | `AuditChain.tla` |
| TCL1 | **Containment drain:** every pending trust-containment request is eventually decided | `TrustContainment.tla` |

## Design Decisions

### Abstract Pattern Matching

Pattern matching is reduced to two cases: wildcard (`*`) and exact match.
Full glob/regex correctness is already covered by 24 fuzz targets in the Rust
codebase. The security properties verified here are about evaluation ordering,
fail-closed semantics, and combining algorithms — not pattern compilation.

This abstraction is sound: if a safety property holds with abstract matching
(which is strictly more permissive), it holds with any concrete refinement.

### Small Model Bounds

The TLC configurations use small bounds (3 policies, 2 actions). This is
sufficient because the verified properties are structural:

- **Fail-closed** is independent of the number of policies
- **Priority ordering** is a pairwise relation on adjacent elements
- **Forbid-overrides** is independent of the number of matching policies
- **Monotonic attenuation** is a pairwise relation on parent-child pairs

A counterexample found with 3 policies also applies at 300. Alloy scopes use
7 tokens with MAX_DEPTH=3 to ensure the depth budget assertion (S13) is
non-vacuous (7 > MAX_DEPTH+1 = 4).

### TLC Model Companions (MC_*.tla)

TLC's `.cfg` file parser cannot handle set-of-record literals as CONSTANT
values. Record definitions (PolicySet, ActionSet, etc.) are placed in separate
`MC_*.tla` model companion modules that are loaded by TLC. The `.cfg` files
use `CONSTANT PolicySet <- const_PolicySet` operator overrides to reference them.

### Abstract Time

The Alloy and TLA+ capability delegation models use ordered values instead
of real timestamps. This captures temporal monotonicity (child.expiry ≤
parent.expiry) without requiring date arithmetic or timezone handling.

### Context Conditions as Booleans

Context conditions (time windows, call limits, agent identity, etc.) are
modeled as a single boolean predicate. The specification verifies the
fail-closed property: `requires_context ∧ ¬has_context → Deny`. It does not
model each of the 17 condition types individually — those are covered by the
Rust test inventory tracked in the generated evidence manifest.

### Conditional on_no_match="continue"

The `Conditional` policy type with `on_no_match="continue"` is explicitly
modeled because this is a subtle corner where bypass bugs could hide: if a
conditional policy doesn't fire, evaluation must continue to the next policy
rather than producing a verdict.

### Fact/Assertion Separation (Alloy)

The Alloy models separate structural well-formedness (encoded as facts) from
protocol constraints (also facts) and verified properties (assertions).
This ensures that the key assertions — especially S12 (transitive attenuation)
and S13 (depth budget) — are genuine theorems, not tautological restatements
of axioms.

### Error Modeling (TLA+)

HandleError is modeled as a non-deterministic transition that can occur during
matching or applying, always producing Deny. It is intentionally NOT given weak
fairness — errors are possible but not required. This ensures liveness properties
hold for the normal evaluation path while still allowing error traces.

## Scope and Limitations

These specifications verify **structural security properties** of the policy
evaluation algorithms, credential lifecycle, and audit chain integrity.
They do **not** cover:

- Pattern compilation correctness (covered by 24 fuzz targets)
- Cryptographic correctness of Ed25519 signatures (assumes correct primitives)
- Timing side channels or performance properties
- Concurrency (the engine is synchronous by design)
- Network-level properties (DNS rebinding, IP resolution)
- IP rule evaluation (modeled code paths stop at path/domain rules)
- Full glob/regex semantics (abstracted to wildcard + exact)
- Conditional constraint evaluation internals (modeled as fire/no-fire)
- ABAC entity store / group membership (principal matching is abstracted)
- `max_invocations` grant field (not checked during attenuation in Rust code)
- Token size / grant count bounds (serialization-level constraints)

For TLA+, Lean, Coq, Alloy, and Kani: the model bounds are finite (bounded
model checking), not unbounded proofs. However, the properties are structural
and do not depend on the specific bound values.

For Verus: properties V1-V12, V9-V10, ENG-CON-1–ENG-CON-4, and D1-D6 are
proven for ALL possible inputs on the actual Rust code. No bounds, no sampling.
The Verus core is the strongest verification layer.

### Known Abstraction Gaps

| Gap | Impact | Mitigation |
|-----|--------|------------|
| Glob patterns → Wildcard + Exact | Cannot detect glob-specific matching bugs | 24 fuzz targets cover pattern compilation |
| Path/domain subset uses set identity, not glob matching | Alloy model is more restrictive than Rust | Sound over-approximation for security |
| ABAC CHOOSE vs priority-ordered selection | Reported policy_id may differ | Does not affect Deny/Allow decision |
| Conditional policies simplified to fire/no-fire | Constraint-level deny paths not modeled | Covered by the generated Rust test inventory |
| Lean/Coq grant subset uses exact-pattern + depth preorder | Simpler than Rust glob/path/domain coverage, so it does not prove full runtime containment | Alloy + Kani + Rust tests cover the broader delegation surface |
| K9 simplified IDNA (lowercase + trim only) | Cannot detect full IDNA normalization bugs | Full IDNA tested by 200+ unit tests and fuzz targets |
| Kani sort omits production's 3rd ID tiebreaker | Sort order may differ when priority and type are equal | Does not affect V6/V7 safety; determinism tested by unit tests |
| V6/V7 compositional (not individually postconditioned) | Relies on K18 + Verus composition, not a single end-to-end proof | Both halves independently verified |
| D6 requires `split_point <= overlap_size` | Secrets with first fragment larger than overlap buffer are not covered | By design: overlap buffer bounds what can be reconstructed |

### Refinement Artifact

The protocol-to-implementation correspondence is documented explicitly in
[`refinement/MCPPolicyEngine.md`](/home/paolo/.vella-workspace/sentinel/formal/refinement/MCPPolicyEngine.md).
This artifact defines:

- the concrete-to-abstract projection from traced Rust evaluation to TLA state
- named simulation obligations (`R-MCP-*`) instead of an implicit correspondence story
- executable witness coverage in [`vellaveto-engine/tests/refinement_trace.rs`](/home/paolo/.vella-workspace/sentinel/vellaveto-engine/tests/refinement_trace.rs)

It is a refinement map with executable witnesses, not a machine-checked
forward simulation proof.

## Relation to Existing Test Suite

The generated evidence manifest is the authoritative count source for Rust
tests, SDK tests, and formal proof inventory. See the generated evidence block
above and `target/evidence/evidence.json`.

The three-layer verification architecture:
- **Layer 3 (TLA+):** Proves protocol design is correct (no deadlocks, no safety violations)
- **Layer 2 (Verus):** Proves core Rust code correct for ALL inputs where the verified kernels apply
- **Layer 1 (Kani):** Proves wrapper Rust code correct within bounds (bridges Verus trust boundary)
- **Lean/Coq/Alloy:** Defense-in-depth mathematical proofs on abstract models
- **Tests:** Concrete execution verification tracked in the generated evidence manifest plus fuzz targets
