# Security Audit Log

> **Living document** tracking all adversarial security audit rounds, findings, and fixes.
> Updated after every audit-fix-commit cycle.
>
> **Last updated:** 2026-03-30 (Round 267)
> **Total audit rounds:** 267
> **Total security fix commits:** 375+
> **Total findings resolved:** 1,750+

---

## How to Read This Document

Each audit round follows this lifecycle:
1. **Audit** — 4 parallel agents scan: types+engine, MCP+audit, server+proxy, config+SDKs
2. **Triage** — Findings prioritized: P0 (critical exploit) > P1 (bypass) > P2 (security gap) > P3 (defense-in-depth) > P4 (code quality)
3. **Fix** — P1+P2 fixed first, then P3, then P4
4. **Verify** — `cargo test --workspace`, `cargo clippy --workspace`, SDK tests
5. **Commit** — All fixes committed with finding IDs in message

Finding IDs follow the pattern `FIND-R{round}-{number}` (e.g., `FIND-R116-001`).

---

## Unwired-Feature Sweep (Sep 2026)

A follow-up scan asked a sharper question than the documentation review below:
**which advertised features have no production caller at all?** Seven findings.
Unlike the round below, most were closed by wiring the feature rather than by
softening the claim.

| ID | Sev | Finding | Outcome |
|----|-----|---------|---------|
| **F1** | P1 | **Shield's encrypted local audit never wrote anything.** `vellaveto-shield/src/main.rs` built a `LocalAuditManager`, configured Merkle and ZK on it, bound it to `_audit_manager` (the "intentionally unused" convention) and never passed it to the bridge — while logging `"Encrypted audit store: ENABLED"` and `"ZK commitments: ENABLED"`. The real interaction history went to plaintext `shield-audit.log`. | **Fixed** — `with_shield_audit()` on the bridge, called at the outbound and inbound hook points beside the context isolator. Honours `audit.strict_mode`. |
| **F2** | P2 | **`vellaveto-http-proxy-shield` was an unconsumed workspace crate.** Traffic padding and privacy header stripping were both advertised and inert; the stdio shield only printed `"Traffic padding: ENABLED (HTTP transport only)"`, impossible for a stdio proxy. | **Split.** Header stripping wired into the HTTP proxy behind `shield.strip_privacy_headers`. Padding deliberately **not** wired — see F2a. |
| **F2a** | P2 | **Traffic padding cannot be enabled without breaking clients.** `pad_content` emits `[4-byte LE length][content][zero padding]`; a padded body is not valid JSON, so any standard MCP client fails to parse it. | **Fixed** — negotiated per request: requires `shield.traffic_padding` *and* the client sending `X-Vellaveto-Padding: v1`. Everyone else gets the unpadded body unchanged. No shipped client negotiates it yet, so the round-trip test is the only in-tree consumer; `vellaveto-http-proxy-shield/README.md` says so. |
| **F3** | P2 | **`DiscoveryEngine` was unfed on every transport except stdio.** Constructed in `vellaveto-http-proxy/src/main.rs`, stored in `ProxyState`, never read. Topology discovery silently indexed nothing over HTTP, SSE, WebSocket, or gRPC. | **Fixed** — `ingest_tools_for_discovery()` called at all four sites that already register output schemas from `tools/list`. |
| **F4** | P3 | **`SessionIsolator` was dead code** while the bridge sanitized through one process-global `QuerySanitizer`. Harmless in the stdio shield (one session per process) but README invariant #4 calls no-cross-session-leakage a product invariant, and a guarantee that holds only by deployment accident is not one. | **Fixed** — wired behind `shield.session_isolation`. Required adding custom-pattern support (it hardcoded `PiiScanner::default()`, which would have silently dropped operator patterns) and a JSON API. |
| **F5** | P3 | **`ContextIsolator`'s continuity claim was unimplementable safely.** Its doc said local history was "injected into the new session's prompt"; `get_recent_context()` had no caller. The only prompt-carrying message crossing a stdio proxy is a server-initiated `sampling/createMessage`, and the agent returns that completion **to the requesting server** — so injecting history there would let a malicious MCP server harvest it. | **Claim withdrawn, deliberately.** Wiring it as documented would have added an exfiltration channel. Per-session isolation (the real property) is kept and tested. |
| **F6** | P4 | **`CLAUDE.md` was a major version stale** — 6.1.1 / 2026-03-30 against a 7.0.0 release, with test counts (11,571 vs 13,235), preset counts (12 vs 18) and formal counts all drifted. | **Fixed** — refreshed, and hand-maintained counts replaced with a pointer to the generated evidence block so they cannot drift again. |
| **F7** | P4 | **Four dead `_requested_by` lookups** in `grpc/service.rs`, each carrying a `SECURITY` comment warning that without them self-approval prevention is bypassed. `create_pending_approval_with_context` derives the requester itself (`helpers.rs`), so they were redundant — but they read like an active control. | **Fixed** — removed, with a note pointing at where the derivation actually happens. |

Verified healthy during the same sweep and deliberately left alone: zero
`unwrap()`/`expect()` in library code; formal counts exact (Coq 45, Lean 32,
Alloy 10, TLA+ 14 specs, Kani 129 ≥ 124 claimed) with no `Admitted`, `sorry`, or
`verifier::external_body`; the 87 `assume(` calls are all `kani::assume` input
constraints governed by `formal/tools/check-formal-trusted-assumptions.sh`; and
fail-closed defaults correct at every site checked. The topology crawler and
recrawl scheduler **are** wired (`vellaveto-server/src/main.rs`), and
self-approval prevention **is** intact on gRPC — both looked broken on a first
pass and are not.

---

## Documentation Credibility Review (Mar 2026) — PARTIALLY CLOSED

A review of published claims against the source found several places where the
documentation asserted more than the code delivers. The claims were corrected in
the docs; the underlying code gaps are tracked here and are **not yet fixed**.

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| **DOC-CRED-1** | P3 | `PiiScanner::default_patterns()` has no file-path or personal-name pattern, so the Consumer Shield cannot sanitize either. Adding cross-platform path detection (POSIX `/home`/`/Users`, Windows `C:\Users\`, UNC `\\host\share`) needs ReDoS review under `validate_regex_safety()` and false-positive testing — a bare path regex matches ordinary prose, and these patterns run on the request hot path against a <5ms P99 budget. Personal names are out of reach for regex and should not be claimed until a real approach exists. | Open — docs corrected to stop claiming the coverage |
| **DOC-CRED-2** | P2 | No domain separation on any Ed25519 signature. Every payload is a bare 32-byte SHA-256 digest with no context prefix, so checkpoints, rotation manifests, evidence packs, and warrant canaries are indistinguishable to a verifier; separation rests on field layouts happening not to collide. An operator who reuses one seed across `VELLAVETO_SIGNING_KEY`, `create_canary`, `issue_capability_token`, `EtdiSigner`, and `sign_evidence_pack` makes digests cross-verifiable between artifact types. The `CHECKPOINT_CONTEXT`/`MANIFEST_CONTEXT` separators in `vellaveto-audit/src/pqc.rs` cover the ML-DSA half of the hybrid only. Fix: per-artifact context prefix in each Ed25519 signing payload (a signature-format change — needs a version bump and a verification-compatibility path). | **Fixed (Sep 2026)** — `vellaveto_types::signing_domain` seeds each digest with a length-prefixed per-type constant; migrated checkpoints, evidence packs, rotation manifests, capability tokens, accountability attestations, and the canary (which inlines its constant, being standalone Apache-2.0). Each type keeps its pre-separation content as a verification-only fallback, so no existing signed artifact stops verifying. Scope correction from the original entry: the verify paths all **recompute** the digest from the object being checked rather than accepting a caller-supplied one, so cross-type transfer would have needed a SHA-256 collision. This was hardening of an unstated assumption, not a live exploit. |
| **DOC-CRED-3** | P3 | Audit chain timestamp monotonicity is enforced only in `verify_chain()` (`vellaveto-audit/src/verification.rs`), as a lexicographic comparison of timestamp *strings*. Nothing is checked at append time — `log_entry_inner` stamps `Utc::now()` and writes unconditionally — so a backwards host clock jump produces a log that fails its own verification. `sequence == 0` is accepted unconditionally as "legacy", bypassing the sequence check. Checkpoint verification does not check timestamps at all. | Open — guarantee restated accurately |
| **DOC-CRED-4** | P2 | Warrant canary is unusable as published. `create_canary()` has no caller outside its own tests — there is no CLI, route, or publication workflow — and `verify_canary()` checks the signature against the verifying key carried inside the canary, so `signature_valid: true` proves internal consistency, not authenticity. Fix: an issuance workflow with a stated cadence, plus `verify_canary_with_key(canary, expected_key)` that fails closed on key mismatch. | Open — "prove" claims withdrawn |
| **DOC-CRED-5** | P3 | `SignedAgentMessage::verify` / `AgentKeyRegistry::verify_message` have no production callers; inter-agent Ed25519 signing and nonce replay protection are available library primitives, not enforced runtime controls, and were listed as ASI07 mitigations. Fix: wire them into the relay path. | Open — threat model corrected |
| **DOC-CRED-6** | P2 | `SecureTask` replay protection evicts seen nonces **FIFO at a count cap** (`vellaveto-types/src/task.rs`). An attacker who emits `max_nonces` fresh nonces flushes the cache and can then replay an evicted one. Fix: evict by time window rather than by count, so eviction is tied to the freshness bound instead of to volume. | Open — limitation documented |

All replay caches in the workspace are per-process (`RwLock<HashMap>` /
`DashMap`): none survive a restart or coordinate across replicas.

---

## ACIS Decision Envelopes (E1/E2, Mar 2026)

Every security decision now carries a structured `AcisDecisionEnvelope` in the audit trail, providing:

- **Decision identity** — unique decision ID and SHA-256 action fingerprint
- **Decision kind** — `Allow`, `Deny`, or `RequireApproval` with structured metadata
- **Decision origin** — `PolicyEngine` or `ApprovalGate`
- **Transport label** — `"http"`, `"stdio"`, `"websocket"`, `"grpc"` identifying the interception point
- **Session and tenant binding** — optional session/tenant context for multi-tenant traceability
- **Timestamp** — ISO 8601 decision timestamp

ACIS envelopes are wired into:
- **Server evaluate API** — 7 audit sites (`/api/evaluate`)
- **Stdio relay** — 4 primary sites (tool call allow/block, resource read allow/block)
- **HTTP proxy** — 6 primary sites (tool call, resource read, task request verdicts)
- **ProxyBridge** — via canonical `mediate()` pipeline

The `AuditEntry.acis_envelope` field is `Option<AcisDecisionEnvelope>` for backward compatibility — existing entries without envelopes remain valid.

---

## Round 116 (2026-02-21)

**Commit:** `df5a96e`
**Findings:** 2 P1 + 9 P2 + 20 P3 = 31 total (P1+P2 fixed, P3 noted)
**Auditors:** 4 parallel agents (types+engine, MCP+audit, server+proxy, config+SDKs)

### P1 Findings (Fixed)

| ID | Crate | Description |
|----|-------|-------------|
| FIND-R116-MCP-001 | vellaveto-mcp | Capability token `expires_at` NOT included in Ed25519 signature — attacker can extend token lifetime indefinitely |
| FIND-R116-MCP-002 | vellaveto-mcp | DPoP verification deadlocks on nonce validation failure (read lock held while acquiring write lock) |

### P2 Findings (Fixed)

| ID | Crate | Description |
|----|-------|-------------|
| FIND-R116-TE-001 | vellaveto-types | `validate_url_no_ssrf()` missing IPv6 transition mechanism checks (6to4, Teredo, NAT64) |
| FIND-R116-TE-002 | vellaveto-types | `Action::validate()` missing control char validation on `resolved_ips` |
| FIND-R116-TE-003 | vellaveto-engine | `BehavioralTracker::record_session()` missing tool key validation (asymmetry with `from_snapshot()`) |
| FIND-R116-MCP-003 | vellaveto-mcp | Delegation chain includes expired-but-uncleaned links (TOCTOU) |
| FIND-R116-MCP-004 | vellaveto-mcp | A2A response scanning misses `status.message` and `history` fields |
| FIND-R116-MCP-005 | vellaveto-mcp | Self-delegation check bypassed via Unicode confusables (Cyrillic lookalikes) |
| FIND-R116-CA-001 | vellaveto-approval | Local ApprovalStore::create() missing reason control/format char validation (parity gap vs Redis) |
| FIND-R116-CA-002 | vellaveto-approval | `with_max_pending()` uses `assert!` (panic in library code) |
| FIND-R116-CA-003 | sdk/python | Missing timeout range validation (parity gap vs Go/TS) |

### P3 Findings (Defense-in-Depth)

| ID | Crate | Description | Status |
|----|-------|-------------|--------|
| FIND-R116-TE-004 | vellaveto-engine | `LeastAgencyTracker` missing control char validation on agent_id/session_id | Noted |
| FIND-R116-TE-005 | vellaveto-types | `EvaluationContext.timestamp` not validated for length/control chars | Noted |
| FIND-R116-TE-006 | vellaveto-types | EvaluationTrace/ActionSummary/PolicyMatch missing `deny_unknown_fields` | Noted |
| FIND-R116-TE-007 | vellaveto-engine | Mixed `to_lowercase()` vs `to_ascii_lowercase()` across context conditions | Noted |
| FIND-R116-MCP-008 | vellaveto-mcp | `AuthScheme` missing `deny_unknown_fields` (by design with `#[serde(flatten)]`) | Noted |
| FIND-R116-MCP-009 | vellaveto-mcp | Delegation chain resolution O(n*d) quadratic performance | Noted |
| FIND-R116-CA-004 | vellaveto-cluster | Redis approval keys stored without TTL; never-resolved approvals accumulate | Noted |
| FIND-R116-CA-005 | vellaveto-cluster | Rate limit with rps=0/burst=0 silently blocks all requests | Noted |
| FIND-R116-CA-006 | vellaveto-config | ClusterConfig key_prefix missing Redis hash tag character validation | Noted |
| FIND-R116-CA-007 | sdk/python | discovery_tools() server_id missing Unicode format char validation | Noted |
| FIND-R116-CA-008 | sdk/go | DiscoveryTools() serverID missing Unicode format char validation | Noted |
| FIND-R116-CA-009 | sdk/typescript | discoveryTools() serverId missing Unicode format char validation | Noted |
| FIND-R116-SP-001–008 | vellaveto-server | 8 P3s: WS counter ordering, registry tool echo, auth level length, trim mismatch, access review filter, federation unbounded, deployment info exposure, handler error echo | Noted |

---

## Round 115 (2026-02-21)

**Commit:** `d0a954d`
**Findings:** 0 P1 + 17 P2 + 0 P3 = 17 total (all fixed)

### P2 Findings (All Fixed)

| ID | Crate | Description |
|----|-------|-------------|
| FIND-R115-001 | vellaveto-types | `CapabilityToken::validate_structure()` missing control/format char validation on identity fields |
| FIND-R115-002 | vellaveto-types | `AccessReviewEntry::validate()` missing control/format char validation |
| FIND-R115-003 | vellaveto-types | `ZkBatchProof::validate()` missing control/format char validation on `batch_id`/`created_at` |
| FIND-R115-004 | vellaveto-types | `CanonicalToolSchema/CanonicalToolCall::validate()` missing control/format char validation |
| FIND-R115-005 | vellaveto-types | `DeploymentInfo::validate()` missing control/format char validation |
| FIND-R115-006 | vellaveto-types | `AbacPolicy/AbacEntity/LeastAgencyReport::validate()` missing control/format char validation |
| FIND-R115-007 | vellaveto-types | 9 types missing `deny_unknown_fields` (ToolSignature, ToolAttestation, etc.) |
| FIND-R115-020 | vellaveto-mcp | Capability token canonical content length-prefix collision |
| FIND-R115-021 | vellaveto-mcp | NHI self-delegation rejection missing |
| FIND-R115-022 | vellaveto-mcp | NHI delegation from/to terminal-state agents allowed |
| FIND-R115-023 | vellaveto-mcp | WorkflowTracker `record_step` bypasses max_sessions/max_workflows limits |
| FIND-R115-024 | vellaveto-mcp | NHI `check_behavior` NaN bypass in request interval anomaly detection |
| FIND-R115-025 | vellaveto-mcp | NHI `register_identity` missing input validation |
| FIND-R115-040 | vellaveto-http-proxy | gRPC tools/list missing rug-pull annotation + output schema extraction |
| FIND-R115-041 | vellaveto-http-proxy | gRPC+WS resource_read missing rug-pull URI check |
| FIND-R115-042 | vellaveto-http-proxy | gRPC+WS resource_read missing circuit breaker check |
| FIND-R115-043 | vellaveto-http-proxy | gRPC handle_tool_call missing `tool_registry.record_call()` |

---

## Round 114 (2026-02-20)

**Commit:** `7277c2a`
**Findings:** NHI delegation bypass, IPv4-mapped IPv6 SSRF, SDK parity

### Key Fixes
- NHI delegation chain bypass via expired links
- `validate_url_no_ssrf()` added IPv4-mapped IPv6 check
- Go/TS SDK parity fixes for discovery and projector methods
- MCP DLP scan `result` field in PassThrough for sampling/elicitation responses

---

## Round 113 (2026-02-20)

**Commit:** `96f75d0`
**Findings:** gRPC injection scanning, deny reason redaction, extension parity

### Key Fixes
- gRPC forward_and_scan injection scanning parity with HTTP
- Deny reason redacted from client responses (internal details leaked)
- Extension method ABAC+DNS+tracking parity across all transports

---

## Round 112 (2026-02-19)

**Commits:** `71cc152`, `ee1f843`, `9cbd609`
**Findings:** Unicode format char validation, config hardening, WebSocket parity

### Key Fixes
- Unicode format character validation across 20+ types
- WebSocket ResourceRead parity with HTTP handler
- Projector compression bounds
- StatelessContextBlob char validation
- SDK+approval hardening

---

## Round 111 (2026-02-19)

**Commit:** `536850a`
**Findings:** 1 P1 + multiple P2

### P1 Fix
- **Capability token holder bypass** — attacker could issue token to holder with trailing whitespace, bypassing holder verification

### P2 Fixes
- DLP pattern leakage in error messages
- Audit sequence number continuity across rotation
- Route handler Content-Type validation
- Path parameter bounds

---

## Round 110 (2026-02-19)

**Commit:** `4d41640`
**Findings:** Enterprise/ETDI validation, schema depth limits, A2A bounds

### Key Fixes
- `EnterpriseConfig` and `EtdiConfig` validate() methods added
- JSON schema depth limits to prevent stack overflow
- A2A response body bounds
- Relay message sanitization

---

## Rounds 100–109 (2026-02-18–19)

**Key commits:** Multiple
**Focus:** Deep structural hardening

### Highlights
- Round 108: `#[must_use]` on Verdict types, `call_counts` saturating_add
- Round 104: Simulator validate() bypass, manifest bounds, budget tracker OOM, Debug redaction
- Round 103: Python SDK context validation, discovery deny_unknown_fields
- Round 101: Setup wizard TOCTOU race, Unicode format chars, Go SDK validation

---

## Rounds 80–99 (2026-02-17–18)

**Focus:** Transport parity, ABAC hardening, NHI management

### Major Findings
- Round 96–99: DLP result scanning in PassThrough across all transports
- Round 84–85: Levenshtein distance validation, Redis parity
- Round 82–83: UTF-8 truncation panics, audit deny_unknown_fields, config validation
- Round 81: WebSocket+NHI hardening, config validation gaps
- Round 80: Go+TS SDK P2s, MCP ABAC+DNS findings

---

## Rounds 58–79 (2026-02-15–17)

**Focus:** SDK parity, compliance, deep adversarial testing

### Major Findings (Round 58 — 78 findings)
- **3 P1:** Redis self-approval homoglyph bypass, Redis self-denial missing, TS SDK missing `resolved_ips`
- **24 P2:** Engine snapshot OOM, regex safety bypass, session baselines unbounded, config deny_unknown_fields (28 structs)
- Round 67: Server unbounded responses, SDK config validation
- Rounds 60–66: Incremental hardening across all crates

---

## Rounds 40–57 (2026-02-13–15)

**Focus:** Code quality, deduplication, formal verification alignment

### Round 57 (100 P4 findings, 84 fixed)
- Code deduplication: `glob_match`, `html_escape`, `FORWARDED_HEADERS`, `validate_path_param_core`, `parse_iso8601_secs`
- `thiserror` migration for error types
- `deny_unknown_fields` on 25 config structs
- New `validate()` methods on 9 types
- Named constants extracted from magic numbers

### Round 56 (91 P3 findings, ~72 fixed)
- Custom Debug impls redacting secrets on 6 types
- `MAX_DLP_FINDINGS=1000` cap
- `MultimodalConfig` validate+deny_unknown_fields
- Safe u128→u64 conversions
- `#[must_use]` on evaluate_action methods

### Round 55 (72 P2 findings)
- Setup wizard CSRF+session+TOML generation
- gRPC transport parity for injection/DLP/behavioral
- RAG defense config bounds
- Route handler hardening

---

## Rounds 1–39 (2026-02-01–13)

**Focus:** Foundation hardening, critical bypass fixes

### Landmark Findings
- **Round 53 (2 P0):** Constant-time HMAC verification compiler optimization bypass via `black_box`, tier_override silent license bypass
- **Round 52 (8 P1):** EvaluationContext previous_actions control char bypass, call_chain Unicode format chars, WebSocket DLP parity, SessionState pub→pub(crate), A2A response body limit, audit sequence counters SeqCst
- **Round 51:** Float scores [0.0,1.0] range validation across 6 types, ToolSignature.is_expired() ISO 8601 validation
- **Round 50 (6 P1):** Policy::validate() fail-closed, NhiDelegationChain.max_depth hard cap, TS SDK evaluate() target fields, federation JWT validation
- **Round 49 (6 P1):** EvaluationContext/StatelessContextBlob collection bounds OOM, AccessReviewEntry NaN bypass, ZK audit mutex poison redaction
- **Round 48 (2 P1):** WebSocket canonicalization TOCTOU across 6 message types, ABAC NaN risk.score bypass
- **Round 47 (3 P0 + 12 P1):** Unbounded intent_chains OOM, SDK payload format mismatch (Python/Go/TS), async response body limit, ZK witness restore-on-failure
- **Round 46:** Fail-closed defaults for ToolSensitivity/NhiIdentityStatus/ABAC, deny_unknown_fields on security structs, SDK input validation
- **Round 45:** GET /mcp full security parity with POST (session binding, identity validation, call chain, audit logging)
- **Round 44:** Various hardening fixes
- **Round 43 (35 findings):** Stdio pipe deadlock, subprocess environment clearing, stale circuit breaker, Merkle leaf pruning, NHI terminal-state enforcement, trust graph caps
- **Round 42:** Transport preference dedup, URL userinfo SSRF, circuit breaker capacity, exec graph metadata ordering
- **Round 41:** Header allowlist, shell injection prevention, circuit breaker OOM bound, response body limit, stdio zombie kill

---

## Vulnerability Categories Tracked

| Category | Description | Rounds with Findings |
|----------|-------------|---------------------|
| **SSRF** | Server-side request forgery via URL parsing | 41, 42, 50, 114, 116 |
| **Injection** | Command/log/template injection | 41, 43, 52, 55, 112 |
| **Auth Bypass** | Token/capability/delegation bypasses | 50, 51, 53, 58, 111, 116 |
| **DoS/OOM** | Unbounded collections, memory exhaustion | 43, 46, 47, 49, 52, 58 |
| **Transport Parity** | Missing checks in WS/gRPC/stdio/SSE | 45, 48, 52, 55, 80, 96, 113, 115 |
| **SDK Parity** | Missing validation/features across Python/Go/TS | 47, 50, 51, 58, 82, 104, 116 |
| **Unicode/Encoding** | Homoglyph, bidi, format char bypasses | 52, 58, 101, 112, 115, 116 |
| **Numeric** | NaN/Infinity/overflow bypasses | 48, 49, 51, 56, 115 |
| **Concurrency** | RwLock poisoning, TOCTOU, deadlocks | 43, 48, 52, 116 |
| **Cryptographic** | Signature, HMAC, timing attacks | 50, 53, 111, 116 |
| **Config** | Missing validation, fail-open defaults | 46, 55, 56, 57, 58, 110, 112 |

---

## Security Metrics

| Metric | Value |
|--------|-------|
| Total audit rounds | 116+ |
| Total findings found | ~1,400+ |
| P0 findings (all-time) | 5 |
| P1 findings (all-time) | ~82 |
| P2 findings (all-time) | ~509 |
| P3 findings (all-time) | ~500 |
| P4 findings (all-time) | ~300 |
| Rust tests | 6,593+ |
| Python SDK tests | 343 |
| Go SDK tests | 106 |
| TypeScript SDK tests | 103 |
| Fuzz targets | 24 |
| `unwrap()` in library code | 0 |

---

## Update Protocol

After every audit-fix-commit cycle:
1. Add a new round section at the top (below the header)
2. List all P1/P2 findings with status (Fixing/Fixed/Noted)
3. Update the "Last updated" date and round number
4. Update security metrics if counts changed significantly
5. Move findings from "Fixing" to "Fixed" once committed
