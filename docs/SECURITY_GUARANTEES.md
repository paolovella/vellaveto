# Security Guarantees

This document defines Vellaveto's security properties as normative contracts.
Each guarantee is phrased as a falsifiable property with pointers to evidence.
For the full Claim → Evidence map, see [ASSURANCE_CASE.md](ASSURANCE_CASE.md).

---

## Normative Guarantees

### G1. Complete Mediation

Every tool call is evaluated on both the request path (before the tool executes)
and the response path (before the result reaches the agent). No tool call bypasses
policy evaluation in any supported transport (HTTP, stdio, WebSocket, gRPC, MCP
gateway).

- **Evidence:** Integration tests in `vellaveto-integration/tests/`; all 6 transport
  modes route through `PolicyEngine::evaluate`.
- **Limitation:** Vellaveto must be deployed inline. Out-of-band tool calls
  (direct agent-to-tool connections that bypass the proxy) are not mediated.

### G2. Fail-Closed

Errors, missing policies, unresolved evaluation context, and unrecognized inputs
produce `Deny`. An `Allow` verdict requires an explicit matching `Allow` policy.

- **Evidence:** TLA+ invariants S1, S5, S6 (`formal/tla/MCPPolicyEngine.tla`);
  Lean 4 proof (`formal/lean/Vellaveto/FailClosed.lean`);
  unit tests `test_no_matching_policy_denies`, `test_error_produces_deny`.
- **Limitation:** None. This property holds unconditionally in the policy engine.

### G3. Audit Integrity (Tamper Detection)

The audit trail provides tamper *detection*, not tamper *prevention*. Each entry
is linked to the previous via SHA-256 hash chain. Ed25519 checkpoint signatures
are applied every N entries (configurable). Merkle inclusion proofs allow
independent verification of individual entries. Every security decision carries an
ACIS (Agent-Consumer Interaction Surface) decision envelope — a structured
record of the decision ID, action fingerprint, verdict kind, origin
(PolicyEngine, Dlp, InjectionScanner, MemoryPoisoning, ApprovalGate,
CapabilityEnforcement, RateLimiter, CircuitBreaker, TopologyGuard, or
SessionGuard), transport label, and optional session/tenant binding —
persisted alongside the audit entry for cross-transport traceability.
See [ACIS Contract](ACIS_CONTRACT.md) for the full envelope specification.

- **Evidence:** `vellaveto-audit/src/lib.rs` (hash chain, `log_entry_with_acis`),
  `checkpoint.rs` (Ed25519 signatures), `merkle.rs` (inclusion proofs);
  `vellaveto-types/src/acis.rs` (ACIS types); verification tests;
  corruption detection tests.
- **Limitation:** An attacker with filesystem write access can truncate the log.
  Truncation is detected on the next verification pass but cannot be prevented
  at the application layer. Forward audit logs to an external SIEM for
  tamper-resistant archival.
- **Limitation:** Entry timestamps are **not attested**. They come from the
  signing host's wall clock, with no RFC 3161 timestamp authority or external
  anchor. Verification establishes that entries are hash-linked in a consistent
  order; it does not establish that they occurred at the times they state, and
  an operator holding the signing key can assign any non-decreasing sequence.
  Monotonicity is checked at verification time only, never at append time.
  See [Signing and timestamps](SECURITY_MODEL.md#where-signing-time-comes-from).
- **Limitation:** Checkpoints are disabled by default and, without a persistent
  `VELLAVETO_SIGNING_KEY`, are signed with a per-process ephemeral key that
  makes them unverifiable after a restart. Verifiers must pin the expected
  public key (`VELLAVETO_TRUSTED_KEY`); an unpinned signature proves nothing
  about who produced it.

### G4. Priority-Ordered Evaluation

Policies are evaluated in descending priority order. The first matching policy
determines the verdict. This is deterministic: the same input always produces
the same verdict.

- **Evidence:** TLA+ invariant S2 (`MCPCommon.tla:SortedByPriority`);
  Lean 4 determinism proof (`formal/lean/Vellaveto/Determinism.lean`);
  unit tests for priority ordering.
- **Limitation:** Determinism proof assumes the policy set is fixed for the
  duration of a single evaluation. Hot-reload between evaluations may change
  the policy set.

### G5. Blocked Paths/Domains Override Allowed

A matching blocked path or blocked domain in any policy produces `Deny`,
regardless of whether an `Allow` policy also matches.

- **Evidence:** TLA+ invariants S3, S4 (`MCPPolicyEngine.tla`);
  unit tests for path/domain override semantics.
- **Limitation:** Glob pattern correctness is not formally verified; it is
  covered by 24 fuzz targets.

### G6. ABAC Forbid Dominance

In ABAC evaluation, any matching `Forbid` rule produces `Deny` regardless
of the number or priority of matching `Permit` rules.

- **Evidence:** TLA+ invariants S7–S10 (`AbacForbidOverrides.tla`);
  unit tests in `vellaveto-engine/src/abac.rs`.
- **Limitation:** ABAC entity store and group membership resolution are
  abstracted in the formal model.

### G7. Capability Monotonic Attenuation

Delegated capability tokens can only narrow permissions, never widen them.
Child grants are a subset of parent grants. Child expiry does not exceed
parent expiry.

- **Evidence:** Alloy assertions S11–S16 (`CapabilityDelegation.als`);
  unit tests in `vellaveto-mcp/src/capability_token.rs`.
- **Limitation:** `max_invocations` field is not checked during attenuation
  in the current implementation (tracked as known gap).

### G8. No Panics in Library Code

Zero `unwrap()` or `expect()` calls in any library crate. All error paths
use `?` or `ok_or_else()` and propagate structured errors.

- **Evidence:** `grep -r 'unwrap()' vellaveto-*/src/ --include='*.rs'` returns
  zero matches (excluding `#[cfg(test)]` blocks and binary crates).
- **Limitation:** Binary crates (`main.rs`) may use `unwrap()` for startup
  configuration that cannot meaningfully recover.

---

## Non-Goals (Explicitly Out of Scope)

These are threats Vellaveto does **not** claim to address:

1. **LLM-internal threats.** Model weight manipulation, training data poisoning,
   and in-model jailbreaks operate below the interception layer.

2. **Credential provisioning.** How agents obtain credentials is outside scope.
   Vellaveto blocks suspicious *use* of credentials, not credential lifecycle.

3. **Physical/side-channel attacks.** Memory dumps, timing attacks, and
   electromagnetic emanations require OS/hardware mitigations.

4. **Tamper prevention.** The audit trail detects tampering; it cannot prevent
   an attacker with filesystem write access from deleting logs.

5. **Out-of-band tool calls.** If an agent connects directly to a tool server
   without routing through Vellaveto, no mediation occurs.

---

## Assumptions

These conditions must hold for the guarantees above to apply:

1. **Inline deployment.** Vellaveto is deployed as an intercepting proxy on all
   agent-to-tool communication paths.

2. **TLS termination.** Transport encryption is handled by the built-in
   `vellaveto-tls` module (rustls-based TLS/mTLS with SPIFFE and PQ KEX support)
   or by an upstream load balancer / reverse proxy.

3. **Filesystem integrity.** The host filesystem is not actively compromised
   during audit log writes. (Compromise is detected after the fact via hash
   chain verification.)

4. **Cryptographic primitive correctness.** Ed25519 (dalek), SHA-256 (ring),
   and HMAC-SHA256 are assumed correct. These are well-audited, widely-deployed
   implementations. Ed25519 was chosen primarily for its deterministic nonce
   derivation — see [Why Ed25519](SECURITY_MODEL.md#why-ed25519) for the
   rationale and the trade-offs it carries.

5. **Key management.** Ed25519 signing keys and HMAC secrets are provisioned
   securely by the operator. Key compromise invalidates audit checkpoint
   signatures. Because the Ed25519 payloads carry no per-artifact domain
   separation, the operator is also assumed **not** to reuse one key seed across
   artifact types (checkpoints, manifests, evidence packs, canaries, capability
   tokens, ETDI tool signatures) — see DOC-CRED-2 in [the audit log](AUDIT_LOG.md).

6. **Clock trust.** Timestamps in signed artifacts are read from the signing
   host's wall clock. Vellaveto uses no external time source, so signatures
   attest authorship and integrity but not time. An operator with the signing
   key can backdate or forward-date any artifact.

7. **Rust memory safety.** The `unsafe` keyword is not used in Vellaveto
   library code. Memory safety relies on the Rust compiler and its standard
   library.

8. **Policy correctness.** Vellaveto faithfully evaluates the policies the
   operator provides. A misconfigured policy (e.g., `Allow *:*`) will produce
   `Allow` verdicts. The engine does not validate policy *intent*.
