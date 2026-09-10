# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **MCPSEC: availability axis added, and the reference result republished from a
  recorded config.** The benchmark now scores two axes. `overall_score` is
  security across P1–P10, unchanged in definition and weighting; the new
  `availability_score` is the share of the 11 A17 legitimate-traffic cases the
  gateway allows through. The two are separate rather than blended because a
  gateway that denies every request scores highly on security by construction —
  57 of the security tests pass on a denial alone, and a measured
  deny-everything gateway reaches 96/105 (91.3%, Tier 4 "Comprehensive") while
  allowing nothing.

  The reference result is now
  [`mcpsec/results/vellaveto-v7.0.json`](mcpsec/results/vellaveto-v7.0.json),
  measured against the shipped `vault` preset: **94.9% security (Tier 4:
  Comprehensive) and 63.6% availability**, 103/116 tests. The file records the
  config path, its SHA-256, the commit and both commands, so the number can be
  reproduced.

  This supersedes the previously published **100/100 (Tier 5: Hardened)**.
  That figure recorded no config, no command and no commit, and no CI job
  regenerated it. Re-running the benchmark against a live server across all 18
  shipped presets did not reproduce it on any of them; the best security score
  available from a shipped preset was `vault` at 94.9%. The old file is retained
  as a historical record and marked superseded.

  Tier bands are deliberately **unchanged** (Tier 4 = 80–94%, Tier 5 = 95–100%),
  so security scores stay comparable across the change and the lower headline
  reflects measurement rather than rescaling.

  The nine security failures under `vault` are configuration and surface rather
  than absent capability: A10.4 needs rate limits, which `vault` does not
  configure; A14.1–A14.4 need `schema_poisoning.enabled`, which defaults to
  `false`; A13.1–A13.4 are cross-call secret splitting, a session-scoped defence
  that lives in the MCP relay and cannot apply to the stateless `/api/evaluate`
  endpoint the benchmark targets.

  Also fixed in the harness: the "perfect gateway" mock the suite validates
  itself against scored 100% Tier 5 while failing all eleven availability
  tests — its documented strategy was "Default: 403 Deny" plus 14 special
  cases, so the benchmark's own model of a correct gateway was
  indistinguishable from a brick wall. `ATTACKS.md` now documents A17, which it
  had omitted.
### Security

- **Task resume replay protection no longer forgets nonces under load**
  (DOC-CRED-6). `SecureTask::record_nonce` evicted the oldest nonce FIFO once
  `max_nonces` was reached, and an evicted nonce becomes replayable —
  `is_nonce_seen` reports a captured resume request carrying it as fresh again.
  New `SecureTask::try_record_nonce` refuses instead of evicting, and
  `resume_task` denies the resume when it returns false. `record_nonce` is
  deprecated rather than removed, so no caller breaks.

  Deliberately **not** fixed by evicting on a time window, which is the usual
  answer: `TaskResumeRequest` carries no timestamp, so nothing bounds a
  request's own freshness and the nonce cache is the only barrier to replay.
  Expiring nonces would make every captured request replayable by waiting out
  the window — a worse failure than the one being fixed. A time window becomes
  correct only once the request carries a signed timestamp checked against it.

## [7.0.0] - 2026-08-04

First release since 6.1.1 (2026-03-27). 273 commits.

Major version because public API surface changed in ways semver classifies as
breaking. Every break below is additive in intent — new fields and variants
carrying security hardening — but each one breaks external code that
constructs these types with struct literals or matches these enums
exhaustively.

### BREAKING CHANGES

Enumerated with `cargo semver-checks`; `vellaveto-audit` has no breaking
changes.

**vellaveto-types**

- `EvidencePack` gains `signature` and `verifying_key` (Ed25519 evidence pack
  signing). Both are `Option<String>` and `#[serde(default)]`, so
  deserialization of older packs is unaffected.

**vellaveto-config**

- `StreamableHttpConfig` gains `protocol_version_floor`,
  `require_protocol_version_header` and `allowed_mcp_param_headers`
  (2026 MCP protocol guardrails).
- `AcisConfig` gains `containment_mode`.

**vellaveto-engine**

- `PluginConfig` gains `content_hash` (SHA-256 plugin verification, TOCTOU
  defence).
- `PluginError` gains the `ContentHashMismatch` variant. The enum is
  exhaustive, so external `match` expressions must add an arm.

**vellaveto-mcp**

- `MediationConfig` gains `containment_mode`.
- `RugPullResult` gains `invalid_schema_tools`.
- `ServiceConfig` gains `dangerous_allow_fail_open_acknowledged` — the
  acknowledgement gate that stops `FallbackBehavior::Allow` being selected
  silently.
- `transparency::inject_decision_explanation` now takes 4 parameters instead
  of 3.
- `SemanticGuardrailsService::mock` was removed.
- `SessionGuard` no longer implements `UnwindSafe` or `RefUnwindSafe`.

### Migration

Construct the affected config structs with `..Default::default()` rather than
exhaustive struct literals, and add a wildcard arm when matching
`PluginError`. No serialized format changed: the new fields all carry
`#[serde(default)]`, so existing configuration files and persisted evidence
packs load unchanged.

### Added

- **Content-bound response attestation (Mar 2026):**
  HMAC-SHA256 signed attestation on every proxied response, binding security
  scan results to the exact response content. When `VELLAVETO_ATTESTATION_SECRET`
  is set, responses include `_meta.vellaveto_attestation` with content hash,
  injection/DLP/schema scan results, trust tier, and HMAC signature. Downstream
  consumers verify with SDK `verify_attestation()` methods (Python, TypeScript,
  Go, Java). Even if injection detection misses a payload, the attestation
  creates an auditable cryptographic record of what the proxy assessed.

- **R259-R267 adversarial audit campaign (Mar 2026):**
  9-round swarm adversarial audit. 30 security findings fixed (9 HIGH, 14 MEDIUM,
  7 LOW). Key fixes: HMAC key minimum 32 bytes, passphrase minimum 12 chars,
  Bearer token whitespace trim, attestation signature hex length validation,
  canary date chronological ordering, SDK signature/type validation (all 4 SDKs),
  approval consumption expiration check, call chain future timestamp rejection,
  GitHub fine-grained PAT DLP pattern, NHI rotation terminal state check, config
  validate() call gaps, fail-open default correction, email injection char
  rejection, A2A message dangerous char validation, Terraform Sensitive field,
  VS Code HTTP downgrade block, evidence pack signing content completeness,
  semantic guardrails constructor validation, tenant key bypass fix, webhook
  dedup off-by-one, approval lineage drift enforcement, ACIS audit entries for
  DoW/jailbreak/token-leakage/memory-query, store error fail-closed.

- **11 architectural hardening changes (Mar 2026):**
  Ed25519 evidence pack signing, SHA-256 plugin content-hash verification,
  FallbackBehavior::Allow acknowledgment gate, eager transitive NHI revocation
  (BFS depth-bounded), transparency Full verbosity admin gate, atomic signup
  capacity check, webhook idempotency tracking, SessionBackend trait +
  write-through persistence, warm restart (Locked/Suspicious sessions),
  per-tenant API key verification (constant-time), cross-tenant integration
  test suite. 36 new Rust tests, 36 new SDK tests, 4 new integration tests.

- **Formal verification expansion (Mar 2026):**
  4 new Verus kernels (DRIFT-1–4 approval drift, REVOKE-1–4 transitive
  revocation, EVIDENCE-SIGN-1–3 evidence signing, WARM-1–3 session restart).
  8 new Kani harnesses (K133-K140). 24 new Kani unit tests. Total: 682 Verus
  items, 116 Kani harnesses, 264 Kani unit tests, 910+ verification instances.

- **2026 MCP protocol guardrails (May 2026, #179, #180):**
  Protocol version floor enforcement, required protocol version header, and an
  allowlist for MCP parameter headers on the streamable HTTP transport.

- **One-command installer:** install script plus `--version` on every binary.

- **First-class evidence verification:** evidence packs are verifiable as a
  supported operation rather than an internal detail, and validation no longer
  depends on ripgrep being present.

- **Canonicalized tool schema pins**, so a pinned schema compares stably.

### Fixed

- **Sanitizer strips Unicode combining marks**, closing a normalization bypass
  in injection detection.
- **Supply-chain release gates hardened**, and release workflow conditionals
  normalized.
- **Python SDK adapter verdicts enforced**; SDK type checks and TypeScript lint
  are now blocking in CI.
- **Surface validation workflow added**, aligning checks with clean installs.

### Security

Advisories resolved during this cycle (25 open Dependabot alerts to zero):

- RUSTSEC-2026-0190 and RUSTSEC-2026-0204 (#283)
- gRPC, `x/net`, `x/text` in the Terraform provider (#284)
- npm advisories via lockfile-only updates (#285)
- `esbuild` pinned to a patched release (#208)
- `brace-expansion` ReDoS, 3 high (#297)
- `sharp`/libvips — CVE-2026-33327, CVE-2026-33328, CVE-2026-35590,
  CVE-2026-35591 (#299)
- react-router — 2 high, 3 moderate, via the 7 → 8 migration (#298)
- astro, js-yaml, postcss, langsmith, jackson-databind, `@babel/core`
- `cmov` and `serde_with` (RustSec), via a semver-compatible batch of 153
  packages (#294)

### Dependencies

146 dependency commits. Notable: `jsonwebtoken` 10.4 → 11.0 (#314), which
requires `use_pem` to be requested explicitly now that implicit
optional-crate features are gone. Dependabot no longer proposes TypeScript
majors in the two directories where `typescript-eslint`'s peer range blocks
them (#308).

## [6.1.1] - 2026-03-27

## [6.1.0] - 2026-03-27

### Added

- **Release infrastructure redesign (Mar 2026):**
  Complete rewrite of the release pipeline to prevent tag churn, duplicate
  publishes, and the workflow storm that caused the v6.0.9 GitHub account
  suspension.
  - `release.yml`: Rewritten as `workflow_dispatch` orchestrator — tags are
    output (created last), not input. Flow: preflight → build → publish → tag.
  - `scripts/release.sh`: Bumps all 33 version files, validates, commits.
    Supports `--trigger` (push + start workflow) and `--dry-run`.
  - `scripts/check-versions.sh`: Pre-flight validator scanning all 33
    version-bearing files (Cargo.toml ×19, package.json ×6, pyproject.toml,
    pom.xml, Chart.yaml, openapi.yaml, tauri.conf.json).
  - Idempotent publishing: npm/PyPI/Maven check if version exists before
    publishing — duplicate attempts succeed instead of crashing with 403.
  - Tag triggers removed from all 6 publish workflows (npm, PyPI, Maven,
    Docker, Go, provenance). Only the orchestrator creates tags.
  - Concurrency control: `cancel-in-progress: false` prevents mid-flight
    cancellation.
  - `CONTRIBUTING.md`: Release checklist updated to reference new process.

- **Formal verification: 7 new Verus proof kernels, 668 total verified items (Mar 2026):**
  - `verified_refinement_completeness.rs` (21 verified): Completes 9/9
    simulation obligations bridging TLA+ MCPPolicyEngine to Rust. Proves
    R-MCP-START-NONEMPTY, MATCH-MISS, MATCH-HIT, APPLY-ALLOW,
    APPLY-REQUIRE-APPROVAL, CONTINUE + first-match-wins composition.
  - `verified_acis_action_summary.rs` (27 verified): ACIS fingerprint
    determinism, action summary field bounds (tool/function ≤256, targets
    ≤100K), dangerous char rejection, DecisionKind default is Deny.
  - `verified_source_taint.rs` (21 verified): Phase 6.1D source-class
    trust floor monotonic degradation, sink gate fail-closed, privileged
    sinks blocked at untrusted floor, quarantined blocks all.
  - `verified_intent_scope.rs` (15 verified): Phase 6.2E intent scope
    restriction-is-subset (bit-vector proof), monotonic narrowing, taint
    locks scope, tool budget bounded, lock irreversible.
  - `verified_sequence_analysis.rs` (22 verified): Phase 6.3E anomaly
    detection monotonicity, confidence max-tracking, restriction requires
    anomaly, warmup independent of taint, high-confidence triggers
    restriction, composite state transition with all invariants.
  - `verified_entropy_pipeline.rs` (22 verified): End-to-end entropy
    alert pipeline composition — millibit bounds, below-threshold no alert,
    at-threshold detected, severity monotonic, zero-observations rejected.
  - `verified_acis_envelope.rs` added to CI verify script (was missing).

- **Formal verification: 8 new Kani modules, 108 CBMC proof harnesses, 240 unit tests (Mar 2026):**
  - `entropy_wrapper.rs` (K86-K90): Float-to-fixed wrapper — output bounded
    [0,8000], NaN/Infinity→0, negative→0, monotonicity, ceil≥floor.
  - `injection_pipeline.rs` expanded to 13-stage decode pipeline (K91-K97):
    Added DoubleUrlDecode, LeetspakeDecode, HtmlCommentStrip, PhoneticDecode,
    EmojiDecode, RegionalIndicatorDecode. Compound decode composition tests
    for leetspeak, HTML comments, double URL, ROT13+URL, multi-layer.
  - `collusion_detection.rs` (K98-K102): Config NaN/Infinity rejection,
    out-of-range validation, capacity exhaustion fail-closed, error rate
    [0,1], denial rate half-open interval.
  - `sort_bridge.rs` (K103-K107): Critical Kani→Verus bridge — proves
    `sort_resolved_matches` output satisfies `is_sorted` precondition for
    all 3-policy combinations. Sort idempotent, empty/single trivially sorted.
  - `credential_vault.rs` (K108-K112): Consumed credential single-use,
    epoch monotonicity, capacity bounded, fail-closed on exhaustion, valid
    state transitions (Available→Active→Consumed, Available→Expired).
  - `tls_spiffe.rs` (K113-K120): hex_digit exhaustive (all 256 bytes),
    SPIFFE parse rejection (non-URI, empty domain, invalid chars, path
    traversal), percent-decode UTF-8 integrity, PQ KEX identification.
  - `merkle_sanity.rs` (K121-K125 unit tests): SHA-256 output 32 bytes,
    deterministic, RFC 6962 domain separation, hex encoding 64 chars,
    collision sanity. (Unit tests only — sha2 crate uses inline asm
    incompatible with CBMC.)
  - Additional CBMC proofs in `proofs.rs` (K126-K132): Capacity exhaustion
    fail-closed, error rate bounded symbolic, error rate zero total, ROT13
    self-inverse, expired credential not consumable, empty vault fail-closed,
    denial rate boundary excluded. Plus K118 path traversal byte-level
    (2^48 symbolic paths through CBMC).

- **Formal verification: 4 new TLA+ specs model-checked, 14 total in CI (Mar 2026):**
  - `NHICredentialRotation.tla`: NHI ephemeral credential rotation lifecycle
    — no use-after-expiry, at-most-two-active during rotation, normal has
    one active, rotation failure cleanup, consistent active during rotation.
    11,677 states, 5 safety invariants verified.
  - `SourceTaintContainment.tla`: Wired into CI with MC_ module and .cfg.
    ST1 (untrusted sources taint), ST3 (privileged sinks unreachable),
    ST4 (auto-taint without detection). 36M states, 0 errors.
  - `IntentScopeContainment.tla`: Wired into CI. IS1 (enforcement
    completeness — fixed invariant to check recording-time scope), IS2
    (monotonic narrowing), IS3 (restriction subset), IS4 (atomic
    restriction). 19M states, 0 errors.
  - `SequenceContainment.tla`: Wired into CI. SQ2 (restriction monotonicity
    — fixed primed variable evaluation), SQ3 (anomaly implies restriction),
    SQ4 (warmup does not suppress taint). 2.4M states, 0 errors.
  - Alloy Analyzer job added to formal-verification.yml CI (2 models,
    10 assertions — previously local-only).

- **Incident statement (`docs/INCIDENT_STATEMENT_20260318.md`):**
  Detailed timeline, root cause analysis, and remediation evidence for the
  v6.0.9 GitHub account suspension incident.

### Changed

- All 6 publish workflows (`publish-npm/pypi/maven/go.yml`,
  `docker-publish.yml`, `provenance-sbom.yml`) no longer trigger on
  `push: tags: ["v*"]`. Tag-triggered release storms eliminated.
- `formal-verification.yml` CI: Added Alloy job, 5 new TLA+ specs in
  matrix (14 total), updated Verus/Kani/Lean/Coq job labels to current counts.
- `formal/tools/verify-verus.sh`: Added 7 new Verus kernels to verification
  list (47 files total).
- Documentation counts updated across CLAUDE.md, formal/README.md,
  docs/FORMAL_SCOPE.md, docs/ASSURANCE_CASE.md, docs/TRUSTED_COMPUTING_BASE.md,
  docs/SHOW_HN.md, docs/SECURITY_REVIEW.md, docs/FORMAL_VERIFICATION_PLAN.md.

### Fixed

- 3 TLA+ invariants corrected after TLC found genuine counterexamples:
  - `SourceTaintContainment.tla` ST3: Fixed to check sink at action time,
    not current state (scope can narrow after historical entries).
  - `IntentScopeContainment.tla` IS1: Fixed to verify recording-time scope
    (non-blocked action must have sink in initial allowed set).
  - `SequenceContainment.tla` SQ2: Fixed primed variable evaluation in
    LET blocks (extracted nextTaintActive/nextNewTools as local values).
- 2 Verus proof errors fixed:
  - `verified_refinement_completeness.rs`: Changed `nat` to `u64` for
    exec-compatible struct fields, added overflow preconditions.
  - `verified_intent_scope.rs`: Added `by(bit_vector)` proof hint for
    bitmask subset property.
- `NHICredentialRotation.tla`: Fixed TypeOK (expiry can exceed MaxTime
  by TTL), fixed IssueInitialCredential to clean up stale rotation targets.

## [6.0.9] - 2026-03-18

### Added

- **15 more security modules wired into relay (Mar 2026):**
  Stateless outbound scans: jailbreak patterns (AML.T0054), token/credential
  leakage, memory query poisoning (MINJA). Stateless inbound scans: system
  prompt leak (LLM07), browser agent attacks, output anomalies.
  Stateful per-session: denial-of-wallet tracker (rate spikes, recursive loops,
  token exhaustion), cascade failure graph (cross-tool failure propagation),
  exfiltration path tracker (read-to-egress correlation), server fingerprint
  drift detection (tools/list behavioral changes), goal drift (tool usage
  divergence), A2A message integrity (replay/spoofing/sequence), NHI
  overpermission (ambient authority, unused tools, trust inflation), agent
  behavioral baseline (cross-session deviation detection), prompt template
  injection (prompts/list interception — the last unwired module).
  All advisory mode. Previously implemented+tested but had zero relay callers.
  **All 30 standalone security modules now wired into the relay pipeline.**

- **6 stateless security scanners wired into relay (Mar 2026):**
  Outbound: jailbreak patterns (MITRE AML.T0054), token/credential leakage,
  memory query poisoning (MINJA). Inbound: system prompt leak (OWASP LLM07),
  browser agent attack patterns, output anomaly detection. All advisory mode
  (log warnings). Previously implemented+tested but had zero relay callers.

- **Dead code activation sweep (Mar 2026):**
  Systematic audit found 15+ config-to-bridge wiring gaps where features were
  fully implemented but never activated in the stdio proxy. Now wired:
  - Injection blocking mode (`block_on_injection`)
  - DLP response scanning and blocking (`dlp.enabled/block_on_finding`)
  - Elicitation controls (`elicitation` config)
  - Sampling controls (`sampling` config)
  - Sampling detector rate-limit/content/model enforcement (`sampling_detection`)
  - Manifest verification / rug-pull detection (`manifest.enabled`)
  - Custom known tool names for squatting detection (`known_tool_names`)
  - Tool quotas / per-tool rate limiting (`tool_quotas`)
  - Secret substitution engine (`secret_substitutions`)
  - EU AI Act Art 50 transparency marking (`compliance.eu_ai_act`)
  - Human oversight tool patterns (`compliance.eu_ai_act.human_oversight_tools`)
  - Tool drift blocking (`governance.block_tool_drift`)
  - MINJA memory security response recording (`memory_security`)
  - ETDI signature verification + version pin checking in tools/list
  - Channel separation: source trust, sink classification, intent scope
  - Desktop notification pipeline (`--notification-file` CLI flag)

- **Channel separation preset activation (Mar 2026):**
  Phase 6 three-layer defense was implemented but completely inert. Now active
  in 5 presets: shield (source trust + 9 sink rules), fortress (+ RequireApproval
  intent scope), vault (+ Deny, ReadOnly only), dev-laptop, sandworm-hardened
  (untrusted default, Deny, max 5 tools). 5 new preset tests.

## [6.0.8] - 2026-03-17

### Added

- **Phase 1 Sprint 1 — Sampling tool allowlist (Mar 2026):**
  `allowed_tools_in_sampling` field on `SamplingConfig` — glob patterns that
  restrict which tools can be referenced in `sampling/createMessage` requests.
  Prevents servers from using sampling to trick the LLM into invoking tools
  the server is not allowed to call directly. 9 new tests.

- **Phase 1 Sprint 2 — Elicitation URL domain policy (Mar 2026):**
  `blocked_url_domains` and `allowed_url_domains` fields on `ElicitationConfig`.
  Scans elicitation title, message, and schema defaults/descriptions/examples
  for HTTP(S) URLs and validates their domains. Wildcard patterns supported.
  8 new tests.

- **Phase 1 Sprint 3 — Task creator access enforcement (Mar 2026):**
  `verify_task_access()` on `TaskStateManager` — denies `tasks/get` and
  `tasks/send` when the requester's agent_id or session doesn't match the
  task creator. Prevents lower-trust agents from retrieving results authorized
  under a higher-trust context. `require_task_creator_match` config option
  (default: true). 7 new tests.

- **Phase 1 Sprint 4 — Security context propagation (Mar 2026):**
  Content hashing (SHA-256) on lineage refs so tool response data can be
  tracked across the session lineage graph. `min_lineage_trust_tier()` for
  querying the minimum trust level in the session's lineage chain.
  Taint propagation from injection/DLP/schema findings into session context
  was already implemented — verified and documented.

- **Phase 1 Sprint 5 — Response metadata stripping (Mar 2026):**
  Strip 10 security-sensitive `_meta` fields (`security_context`,
  `client_provenance`, `agent_identity`, `trust_tier`, `lineage_refs`, etc.)
  from server responses before forwarding to the agent. Prevents servers from
  injecting fake security context into responses. Covers `result._meta`,
  `content[]._meta`, and `contents[]._meta`. 4 new tests.

- **Phase 1 Sprint 6 — Extension registry enforcement (Mar 2026):**
  `check_method_permitted()` on `ExtensionRegistry` — checks allow/block
  patterns before policy evaluation. Wired into relay's `handle_extension_method`
  via new `extension_registry` field on `ProxyBridge`.

- **Phase 1 Sprint 7 — Cross-tool lineage graph queries (Mar 2026):**
  `has_source_in_lineage()`, `has_tainted_source()`, `distinct_lineage_sources()`
  on `SessionSemanticState` for detecting parasitic toolchain patterns
  (Living-Off-AI). Exposed through `RelayState` for mediation use. 4 new tests.

- **Phase 1 Sprint 8 — Cross-transport security context token (Mar 2026):**
  `SecurityContextToken` type in `vellaveto-types` — a compact HMAC-signed
  token carrying session scope, trust tier, taint labels, and lineage source
  count across transport boundaries (e.g., stdio → HTTP). Validated with
  bounded field checks and dangerous char rejection. 4 new tests.

- **Phase 2 Sprint 1 — Tool quotas config (Mar 2026):**
  `ToolQuota` type with `[[tool_quotas]]` TOML section — per-tool rate limits
  without writing full Conditional policies. Glob patterns, configurable
  window (1-86400s), deny or require_approval on exceed. 7 new tests.

- **Phase 2 Sprint 2 — Secret substitution config (Mar 2026):**
  `SecretSubstitution` type with `[[secret_substitutions]]` TOML section —
  replace named secrets with placeholders before model visibility, restore
  at execution boundaries. 4 new tests.

- **Phase 2 Sprint 3 — Tool quota runtime enforcement (Mar 2026):**
  `ToolQuotaTracker` runtime module — enforces configured quotas with
  per-tool sliding window counters, glob pattern matching, and
  deny/require_approval outcomes. 6 new tests.

- **Phase 2 Sprint 4 — Secret substitution runtime (Mar 2026):**
  `SecretSubstitutionEngine` — replaces secrets with placeholders before
  model visibility (`substitute_outbound`), restores at execution
  (`restore_inbound`). Env var resolution, tool pattern filtering,
  param path targeting, recursive scan of nested objects. 7 new tests.

- **Phase 2 Sprint 5 — OpenTelemetry span generation (Mar 2026):**
  `AuditSpan` and `build_evaluation_span()` in `vellaveto-audit/src/otel_spans.rs`.
  Converts audit entries to OTel-compatible span records with trace/span IDs,
  timing, vellaveto-specific attributes, and status mapping. 3 new tests.

- **Phase 2 Sprint 6 — Server reputation scoring (Mar 2026):**
  `ReputationTracker` — per-server behavioral signal tracking with exponential
  decay scoring (injection, DLP, rug-pull, squatting, memory/schema poisoning).
  Deny rate computation, threshold checking. Bounded 1024 servers. 6 new tests.

- **Phase 2 Sprint 7 — AI asset inventory types (Mar 2026):**
  `AiAsset`, `AiAssetInventory`, `AssetSecurityMetadata` types in
  `vellaveto-types`. Operator-facing AI BOM with trust levels, security
  metadata, type/trust filtering. 4 new tests.

- **Phase 2 Sprint 8 — Approval fact summaries (Mar 2026):**
  `ApprovalFactSummary` on `PendingApproval` — human-readable review briefs
  with headline, risk indicators (trust, sink, taint, risk score),
  requester, and time-to-expiry. 2 new tests.

- **Phase 2 Sprint 9 — Declarative policy templates (Mar 2026):**
  `PolicyTemplate` with 5 types (block_paths, block_domains, block_commands,
  require_approval_paths, allow_paths). `expand()` generates full policy
  rule JSON from 3-line TOML declarations. 6 new tests.

- **Phase 3 Sprint 1 — Trust lattice enforcement (Mar 2026):**
  `FlowPoint` product lattice (`TrustTier × SinkClass`) with `compose()`,
  `is_admissible()`, `trust_deficit()`. `check_flow_admissibility()` returns
  Admissible/Gated/Denied verdicts for inter-server flow control. 8 new tests.

- **Phase 3 Sprint 2 — Delegation control (Mar 2026):**
  `DelegationTracker` with chain depth limits, cycle detection, trust
  monotonicity enforcement, and target allow/block lists. 8 new tests.

- **Phase 3 Sprint 3 — Approval drift invalidation (Mar 2026):**
  `check_approval_lineage_drift()` detects trust downgrade and taint
  accumulation since approval creation. 3 new tests.

- **Phase 3 Sprint 4 — Semantic output contracts (Mar 2026):**
  `OutputContract` type with `check_output_contract()` — tools declare
  expected `ContextChannel` output types, violations trigger
  Log/Quarantine/Block actions. 5 new tests.

- **Phase 3 Sprint 5 — Contagion controls (Mar 2026):**
  `ContagionTracker` with 3 modes (SessionPersistent, DecayAfterClean,
  ExplicitClearOnly). Tracks injection/DLP/schema/memory taint with
  per-type trust floors. `should_block_privileged_sink()`. 7 new tests.

- **Phase 3 Sprint 6 — Cryptographic delegation tokens (Mar 2026):**
  `DelegationToken` with monotonic constraints: trust can only decrease,
  depth decrements, expiry can only be earlier. `derive_child()` for
  chain delegation. 7 new tests.

- **Phase 4 Sprint 1 — Annex IV technical documentation (Mar 2026):**
  `AnnexIvPackage` with 5 sections, `build_annex_iv_package()` from
  runtime state. Completeness scoring and gap detection. 4 new tests.

- **Phase 4 Sprint 2 — Article 73 incident reports (Mar 2026):**
  `IncidentReport` with cross-regulation notification deadlines (EU AI Act
  72h, NIS2 24h/72h/30d, DORA 4h). 5 new tests.

- **Phase 4 Sprint 3 — FRIA data export (Mar 2026):**
  `FriaExport` for Art 27 deployer FRIA workflows with scope, controls,
  monitoring, data protection, and oversight sections. 3 new tests.

- **Phase 5 Sprint 1 — Supply-chain trust types (Mar 2026):**
  `SupplyChainAttestation`, `SbomEntry`, `SupplyChainTrustDecision`.
  `compute_trust_decision()` scores from attestation verification, SBOM
  vulnerabilities, and behavioral reputation. 6 new tests.

- **AI Security Vulnerability Coverage (Mar 2026):**
  22 new detector modules addressing vulnerability classes across all 6 major
  frameworks (OWASP LLM/Agentic/ML, MITRE ATLAS, NIST AI RMF, COLING 2025):
  slopsquatting (LLM09), RAG poisoning (LLM08), STAC cumulative harm (COLING),
  divergence attacks (LLM02), tool description privilege audit (COLING),
  multi-modal indicators (CHAI), cross-session leak (promptfoo), NHI
  overpermission (ASI03), agent baseline (ASI10), A2A integrity (ASI07),
  MINJA query poisoning (NeurIPS 2025), denial of wallet (LLM10), jailbreak
  patterns (AML.T0054), browser agent defense, system prompt leak (LLM07),
  token leakage, cascading failure graph (ASI08), output anomaly (ML08),
  exfiltration path analysis, server fingerprint drift, goal drift (ASI01),
  prompt template injection. 121 new tests, ~11,100 new lines.

- **Phase 6 — Control/Data Channel Separation (Mar 2026):**
  Three-layer structural defense against MCP channel conflation:
  - **6.1A**: `SourceTrustConfig` — classify tools as untrusted/verified/unknown
  - **6.1B**: Source-class auto-tainting (`SourceClassUntrusted`, `SourceClassUnknown`)
    fires on EVERY response regardless of detection findings
  - **6.1C**: `SinkClassificationConfig` — policy-driven tool→sink mapping replaces
    hardcoded heuristics
  - **6.2**: `IntentScopeConfig` — session-level tool/sink constraints with
    `restrict_to_trust_floor()` for automatic scope narrowing after taint
  - **6.3**: `SequenceTracker` — 5 behavioral detectors (ReadThenExfil,
    PrivilegeEscalationAfterTaint, ToolDiversitySpike, NovelToolAfterUntrusted,
    PrivilegedActionCluster)
  - **6.4A**: 8-scenario integration test matrix validating three-layer composition
  - `docs/CHANNEL_SEPARATION.md` with configuration examples and preset guidance
  - 30+ new tests across config, engine, and integration

- **Runtime wiring — 15 modules activated (Mar 2026):**
  All standalone modules from Phase 1-5 wired into runtime enforcement
  or API surface. Key integrations:
  - `ToolQuotaTracker` + `SecretSubstitutionEngine` in `handle_tool_call`
  - `ContagionTracker` fed from response findings, blocks privileged sinks
  - `check_flow_admissibility()` enforces trust lattice in tool call path
  - `check_approval_lineage_drift()` at approval consumption
  - `ReputationTracker` fed injection/DLP/schema signals from responses
  - Policy template `expand()` called during `to_policies()` config loading
  - `fact_summary()` exposed in `GET /api/approvals/{id}`
  - `SecurityContextToken` minted on every response via `security_context_mint.rs`
  - API routes: `/api/compliance/annex-iv`, `/api/compliance/incident-report`,
    `/api/compliance/fria`, `/api/audit/otel-spans`, `/api/inventory/assets`

### Fixed

- **R255-ENG-1: Regex constraint bypass via path normalization (Mar 2026):**
  Path normalization mangled non-path parameter values before regex matching.
  Shell command patterns like `rm -rf /` were not blocked because the trailing
  `/` was consumed as a path separator. Fix: match raw value first, then
  normalized. Both constraint_eval.rs and traced.rs updated.

- **Gap Analysis — ACIS coverage hardening (Mar 2026):**
  Expert gap analysis identified 6 gaps across ACIS system; 3 closed:
  - **Gap 1 (P0 — ACIS test coverage):** 6 server-level tests verifying ACIS
    envelopes on Allow/Deny/RequireApproval verdicts (fingerprint determinism,
    decision ID uniqueness, fail-closed empty-policy deny, approval gate origin).
    5 integration-level tests (serialization roundtrip, audit persistence
    roundtrip, all 5 transport labels valid, deny reason populated, allow reason
    empty). Total: 21 ACIS tests across server + integration.
  - **Gap 3 (P1 — AcisConfig enforcement):** `require_session_id` and
    `require_agent_identity` wired into `MediationConfig` as Step 0 in the
    `mediate()` pipeline. Unauthenticated traffic denied with `SessionGuard`
    origin before DLP/injection scanning runs. 6 enforcement tests.
  - **Gap 5 (P2 — stale proof inventory counts):** Updated Verus 321→534,
    total 545→767+ across contributor guidance and formal inventory docs.
  - **Gap 2+4 (P1 — secondary ACIS decision envelopes) — DONE:**
    `build_secondary_acis_envelope()` convenience helper in `mediation.rs`.
    194 secondary security-decision sites across all 4 transports wired
    with ACIS envelopes: stdio relay (77), HTTP handlers (42), WebSocket
    (40), gRPC (35). Every DLP, injection, memory poisoning, circuit
    breaker, shadow agent, deputy, shield, rug-pull, and ABAC denial now
    has a structured ACIS envelope with `DecisionOrigin` and session
    binding for cross-session audit coherence.
  - **Gap 6 (P3 — Kani K26-K77 documentation) — DONE:**
    `formal/kani/README.md` expanded from K1-K25 to full K1-K77 catalog
    with 13 new sections (IP, Cache, Capability, Rule Check, ResolvedMatch,
    Cascading, Constraint, Task, IDNA, Lock Safety, Sanitizer, Temporal
    Window, Injection Pipeline) and complete source correspondence table
    mapping all 21 modules to production files.
  - **All 6 gaps closed.**

### Changed

- **Planning reset — roadmap sync (Mar 2026):**
  `ROADMAP.md` no longer frames the next cycle as abstract Phase 73-81 market
  positioning. It now reflects the actual repo state and 2026 execution order:
  Phase 0 worktree cleanup and Sprint 2 closeout, then protocol-complete
  runtime enforcement, policy/approval/operator productization, multi-agent
  containment, compliance evidence generation, and supply-chain trust.
- **Contributor guidance sync (Mar 2026):**
  `AGENTS.md` and `ROADMAP.md` now treat the shared substrate as shipped
  foundation, remove the retired "all phases implemented" framing, and point
  contributors at the active transport, product, research, compliance, and
  trust tracks.
- **HTTP proxy containment-audit parity (Mar 2026):**
  The HTTP proxy now carries structured `RuntimeSecurityContext` across nearly
  all request, response, discovery, guard, and protocol control secondary ACIS
  audit paths in HTTP, WebSocket, and gRPC. This includes approval gates,
  DLP/injection/schema events, memory-poisoning and rug-pull denials, sampling
  and elicitation interception, invalid call-chain denials, WebSocket binary
  rejection/drop, upstream rate limiting, and forwarded protocol control
  messages.
- **HTTP proxy smart-fallback audit parity (Mar 2026):**
  Gateway unavailability, cross-transport fallback success/failure, smart-fallback
  response DLP/injection blocking, and smart-fallback non-JSON rejection now
  also preserve structured containment-aware secondary ACIS context.
- **HTTP proxy containment-audit parity complete (Mar 2026):**
  OAuth DPoP validation failures and the remaining SSE inspection helper events
  now preserve structured containment-aware secondary ACIS context as well. As
  a result, `vellaveto-http-proxy` no longer has any plain
  `build_secondary_acis_envelope(...)` audit paths left in the crate.
- **HTTP proxy transport provenance evidence (Mar 2026):**
  The HTTP proxy runtime-security-context path now consumes explicit
  OAuth/DPoP validation evidence instead of reconstructing signature and replay
  state from raw headers. Verified `X-Agent-Identity` session context is now
  promoted into `client_provenance.workload_identity` and
  `workload_binding_status`, and no-session mediation fallbacks still preserve
  the current request's authenticated identity instead of collapsing to an
  empty evaluation context.
- **HTTP proxy verified workload claims (Mar 2026):**
  Verified custom claims from `X-Agent-Identity` JWTs are now preserved instead
  of being discarded. That allows the HTTP proxy to derive richer
  `workload_identity` fields (`namespace`, `service_account`,
  `process_identity`, `attestation_level`) plus `session_key_scope` and
  `execution_is_ephemeral` from validated transport identity claims.
- **HTTP proxy explicit workload-claims transport path (Mar 2026):**
  Authenticated HTTP and WebSocket requests can now carry a dedicated
  `x-workload-claims` header with base64url-encoded workload metadata.
  When present, the HTTP proxy prefers those allowlisted transport claims over
  bearer-token custom claims for `workload_id`, `namespace`,
  `service_account`, `process_identity`, `attestation_level`,
  `session_key_scope`, and `execution_is_ephemeral`, while still failing closed
  on malformed header values.
- **HTTP proxy detached request-signature ingestion (Mar 2026):**
  HTTP and WebSocket runtime provenance now also accepts a detached
  `x-request-signature` header with base64url-encoded `RequestSignature`
  metadata. Verified DPoP evidence still takes precedence, but detached
  signature fields now survive into `client_provenance` for audit and policy
  inputs, and malformed detached signature headers are surfaced as
  `signature_status = invalid` instead of being silently ignored.
- **HTTP proxy detached request-signature verification (Mar 2026):**
  `acis.trusted_request_signers` now lets operators configure trusted detached
  Ed25519 request-signature signers by `key_id`. When present, HTTP, WebSocket,
  and gRPC transport provenance verifies detached signatures against the
  canonical request preimage and upgrades them to verified provenance only on a
  successful cryptographic check. Verified detached signatures now also get
  session-local replay treatment through the HTTP proxy session store, so
  repeated nonces surface as `replay_detected` to the shared mediation path.
  Unknown signers, malformed signatures, and canonical-binding failures fail
  closed as `invalid` or `error` instead of being treated as unaudited metadata.
  Trusted signer config can now also project signer-scoped provenance
  metadata, including `session_key_scope`, `execution_is_ephemeral`, and an
  expected `workload_identity`. When a verified detached signature conflicts
  with a configured signer workload expectation, the HTTP proxy now marks the
  request as `workload_binding_status = mismatch` instead of silently dropping
  the conflict.
  When a verified detached signature matches a configured signer
  `workload_identity`, that signer projection now upgrades the request to
  `workload_binding_status = bound` instead of leaving it as advisory-only
  metadata, so the shared `require_workload_binding` mediation guard can admit
  detached-signer flows on verified signer provenance instead of treating that
  detached-signer requests on verified signer expectations alone.
  A verified detached signature with signer/transport workload mismatch now
  also downgrades the effective trust tier to `untrusted`, so privileged sink
  trust-floor enforcement can still gate the request even when
  `require_workload_binding` is not enabled globally.
- **Approval provenance summaries are now review-safe (Mar 2026):**
  Approval review payloads and approval-resolution audit rehydration now store
  opaque fingerprints for `client_key_id`, `session_scope_binding`, and
  `canonical_request_hash` instead of persisting raw transport identifiers.
  Legacy approvals with raw values remain compatible during approval
  consumption, but new approval contexts exposed through the server, MCP relay,
  and HTTP proxy now use review fingerprints by default.
- **ACIS client provenance is now audit-safe (Mar 2026):**
  Shared ACIS envelope construction now fingerprints persisted
  `client_key_id`, `session_scope_binding`, and `canonical_request_hash`, and
  omits raw `request_signature` and `workload_identity` details from audit
  records. The runtime still uses full provenance in memory for admission and
  replay checks, but audit JSONL and downstream approval views now retain only
  review-safe provenance summaries. Approval creation paths in the HTTP proxy,
  MCP relay, and server now all consume a shared review-safe provenance summary
  helper instead of touching raw `client_provenance` fields at persistence
  sites, aligning the code with the CodeQL cleartext-logging model too.
  Cluster-backed approval fixtures now also default the expanded provenance
  summary shape so workspace `cargo check --workspace --all-targets --locked`
  stays aligned with the new approval context contract.
- **gRPC approval replay audits now preserve replay metadata (Mar 2026):**
  gRPC tool approval replay denials now emit the same
  `presented_approval_replay_denied` event metadata as the other transports,
  including `approval_id`, registry context, and transport-clamped provenance
  in the persisted ACIS envelope. The gRPC test helpers now also retry long
  enough for async audit writes before failing.
- **HTTP proxy detached request-signature freshness (Mar 2026):**
  Verified detached request signatures now also enforce bounded `created_at`
  freshness in transport provenance. Signatures with malformed timestamps,
  stale timestamps, or excessive future skew are downgraded to
  `signature_status = expired`, while signatures missing `created_at` or
  `nonce` now fail closed as `invalid` before replay handling. Detached
  signatures are no longer treated as timeless once the cryptographic check
  passes.
  `acis.detached_request_signature_max_age_secs` and
  `acis.detached_request_signature_max_future_skew_secs` now let operators tune
  those fail-closed windows per deployment instead of relying on a fixed proxy
  constant.
- **HTTP proxy replay trust downgrade (Mar 2026):**
  Verified detached signatures that trip the session-local replay cache now
  also downgrade the effective trust tier to `quarantined` instead of keeping
  a `verified` trust floor whenever `deny_replay` is not enabled. That lets
  privileged sink trust-floor enforcement and approval summaries still treat
  replayed provenance as contained rather than high-trust.
- **HTTP proxy invalid-signature trust downgrade (Mar 2026):**
  Detached request signatures that are `expired`, malformed, or otherwise
  verification-invalid now also downgrade the effective trust tier during
  transport provenance construction. `expired` signatures project
  `quarantined`, while `invalid` and `error` signatures project `untrusted`,
  so semantic-containment policy never sees stale or broken detached
  provenance as implicitly high-trust.
  Transport-derived trust downgrades now also clamp any explicit
  `_meta.vellavetoSecurityContext.effective_trust_tier` instead of only filling
  it when absent, so caller-supplied trust metadata cannot mask replayed,
  expired, mismatched, or invalid detached provenance.
  Transport-negative provenance now also clamps `_meta.client_provenance`
  directly: invalid detached signature evidence overrides a caller-supplied
  `signature_status = verified`, and replay detection overrides a caller-
  supplied `replay_status = fresh`, so runtime metadata can no longer mask
  detached-signature failures before trust-tier inference.
  Conflicting transport workload identity now also fails closed against
  `_meta.client_provenance.workload_identity`: when authenticated transport
  workload claims disagree with caller-supplied provenance, VellaVeto keeps the
  transport identity, marks `workload_binding_status = mismatch`, and downgrades
  the request to `untrusted`.
  Explicit `_meta.client_provenance.session_key_scope` and
  `execution_is_ephemeral` now also clamp to authenticated transport scope, so
  caller-supplied ephemeral metadata cannot mask a persisted transport client.
  Runtime-owned provenance fields now also seal over `_meta` values:
  `session_scope_binding` is always taken from the transport runtime when
  available, and `canonical_request_hash` is always recomputed from the live
  request context instead of trusting caller-supplied hashes.
  Transport-provided `client_key_id` and detached `request_signature` fields
  now also override `_meta.client_provenance`, so caller metadata cannot mask
  the real key id, nonce, timestamp, or signature bytes that were presented on
  the transport. WebSocket now preserves handshake transport headers into the
  runtime-security-context path too, and regression coverage locks the same
  rule on HTTP, WebSocket, and gRPC request paths.
  WebSocket parity now also covers runtime-owned provenance fields:
  `_meta.client_provenance.session_scope_binding` and
  `_meta.client_provenance.canonical_request_hash` are replaced by the live WS
  session binding and recomputed canonical hash. gRPC regression coverage now
  locks the same runtime-owned provenance rule across HTTP, WebSocket, and
  gRPC entrypoints.
  Session-scope trust clamping now has explicit WebSocket and gRPC regression
  coverage too, so `_meta.client_provenance.session_key_scope` and
  `execution_is_ephemeral` cannot override persisted transport scope on those
  entrypoints either.
  Approval-containment derivation is now covered on WebSocket and gRPC too, so
  the reviewer-facing provenance summary reflects the clamped transport scope
  rather than the original `_meta` scope claims.
- **HTTP proxy trusted signer scope binding (Mar 2026):**
  Trusted detached signer metadata now fails closed when it conflicts with
  explicit transport key-scope evidence. A signer that projects an ephemeral
  scope can no longer validate a request already bound to a persisted transport
  scope, and a signer that projects persisted scope can no longer validate a
  transport request explicitly marked ephemeral. Those provenance conflicts now
  surface as `signature_status = invalid` instead of being silently merged.
  ACIS now also rejects duplicate `trusted_request_signers.key_id` entries so
  operator config cannot silently shadow one trusted signer definition with
  another at startup, and it rejects duplicate trusted signer public keys so
  the same detached signer cannot be aliased under multiple local identities.
- **Approval provenance retention and drift hardening (Mar 2026):**
  Pending approvals, approval-resolution ACIS events, and operator review
  surfaces now preserve the full transport-clamped provenance summary that
  survives admission, including `client_key_id`, `replay_status`,
  `session_scope_binding`, and `canonical_request_hash` alongside signature,
  workload-binding, and key-scope state. Presented-approval consumption in the
  HTTP proxy now also fails closed when the current stable transport provenance
  no longer matches the provenance summary captured when the approval was
  issued.
- **HTTP proxy detached signer provenance-guard coverage (Mar 2026):**
  Unit-level mediation coverage now proves the two fail-closed deny paths for
  detached signer provenance: verified detached signatures with signer/transport
  workload mismatch are rejected when `require_workload_binding` is enabled,
  and signer/transport key-scope conflicts are rejected when
  `require_verified_signature` is enabled. gRPC runtime-security-context tests
  now also lock in trusted-signer metadata projection, signer workload-mismatch
  propagation, and signer/transport scope-conflict invalidation on the non-HTTP
  transport path.
- **Ephemeral client provenance guard (Mar 2026):**
  Shared mediation can now require client provenance to represent an ephemeral
  execution context before a request is admitted. The new global ACIS toggle
  `require_ephemeral_client_provenance` denies non-ephemeral provenance in the
  provenance-guard phase, and HTTP detached signer metadata can satisfy that
  requirement when it projects ephemeral execution or ephemeral key scope.
- **Approval provenance summaries (Mar 2026):**
  Pending approvals and approval-resolution audit events now persist the
  provenance summary that actually drove the gate, not just semantic taint.
  `containment_context` can now carry `signature_status`,
  `workload_binding_status`, `session_key_scope`, and
  `execution_is_ephemeral`, and approval audit reconstruction restores that
  summary into `client_provenance` so reviewer-visible context matches the
  final ACIS envelope.
- **Stdio mediation provenance parity (Mar 2026):**
  `vellaveto-proxy` now forwards `acis.require_ephemeral_client_provenance`
  into the shared `MediationConfig`, keeping stdio admission behavior aligned
  with the other runtime transports and fixing the workspace/coverage build
  path that was still initializing the older config shape.
- **HTTP proxy presented-approval replay audits (Mar 2026):**
  Replayed presented approvals on resource, task, and extension flows now emit
  the same transport-provenance-aware deny audits as tool calls across HTTP,
  WebSocket, and gRPC. Targeted coverage now locks those replay-denial paths
  with seeded approval-consumption tests on gRPC and WebSocket plus HTTP
  consumed-approval matching coverage at the shared approval gate. Replay
  tests now also assert the emitted `event`, `approval_id`, and action-specific
  audit metadata for task and extension denial paths, and gRPC now has a live
  extension replay case in addition to the existing task replay coverage.
  WebSocket now mirrors that live non-tool replay coverage for both task and
  extension approval replays. HTTP now has live replay coverage for tool,
  task, and extension approval consumption too, completing the transport parity
  matrix for presented-approval replay handling.
- **gRPC transport identity parity (Mar 2026):**
  The gRPC transport now uses the same validated transport-identity helpers as
  HTTP/WS. Validated `x-agent-identity` JWTs preserve custom claims instead of
  dropping them, explicit `x-workload-claims` metadata can enrich or override
  workload fields, and verified bearer-token custom claims can now synthesize
  session `agent_identity` context when no separate identity token is present.
- **gRPC transport provenance parity (Mar 2026):**
  gRPC now also accepts detached `x-request-signature` metadata, preserves it
  in runtime provenance, and refreshes final tool/resource/task/extension ACIS
  envelopes with transport-derived `RuntimeSecurityContext` instead of relying
  on session identity alone. Approval-gate verdicts now merge that transport
  provenance into the stored containment context as well.
- **Opaque session-scope provenance binding (Mar 2026):**
  Canonical request hashing, relay approval scope, and HTTP proxy approval
  scope now use transport-generated opaque `session_scope_binding` values
  instead of hashing or persisting transport-facing session IDs directly.
  Relay state and HTTP proxy session state now mint internal `sidbind:v1:*`
  bindings, preserve them in `client_provenance`, and use them for approval
  creation/consumption and canonical request binding.
- **Allowlisted transport claim projection (Mar 2026):**
  The HTTP proxy no longer derives runtime provenance by reading generic OAuth
  claim maps inside the helper path. Workload claims are now decoded into a
  typed allowlisted structure, explicit workload metadata takes precedence over
  projected bearer-token identity when building `workload_identity`, and
  bearer-token custom claims are projected into session `agent_identity`
  earlier in the request lifecycle instead of being read directly in the audit
  path.
- **HTTP proxy transport canonical binding parity (Mar 2026):**
  The HTTP proxy now seals `client_provenance.canonical_request_hash` during
  runtime-security-context construction instead of waiting for shared
  mediation. Pre-mediation deny, approval-gate, and transport-control audits
  therefore carry the same opaque session-bound canonical request hash as the
  final mediated verdict path.
- **HTTP proxy transport provenance audit parity (Mar 2026):**
  WebSocket and gRPC regression coverage now also proves that secondary ACIS
  envelopes preserve clamped transport provenance rather than spoofed
  `_meta.client_provenance` fields. Approval-gate audit paths now have
  explicit parity coverage for transport-owned signature fields, runtime-owned
  scope/hash bindings, and persisted session-scope clamping.
- **HTTP proxy approval-envelope provenance parity (Mar 2026):**
  WebSocket and gRPC regression coverage now also proves that
  `approval_containment_context_from_envelope(...)` preserves those same
  clamped transport provenance fields. Reviewer-visible approval summaries
  therefore stay aligned with transport truth after the ACIS envelope hop, not
  just before it.
- **HTTP proxy pending-approval provenance parity (Mar 2026):**
  WebSocket and gRPC regression coverage now also proves that
  `create_pending_approval_with_context(...)` persists the clamped transport
  provenance summary into stored pending approvals. The approval store now has
  transport-parity coverage for opaque session binding plus persisted
  `session_key_scope`, `execution_is_ephemeral`, and signature-status fields.
- **HTTP proxy live approval-gate provenance merge (Mar 2026):**
  Unknown-tool and untrusted-tool approval gates now merge transport-derived
  runtime provenance into the approval security context before emitting ACIS or
  persisting pending approvals. HTTP, WebSocket, and gRPC approval-gate paths
  no longer drop detached-signature, scope, or canonical-binding provenance at
  the point where a live approval is created. gRPC unary service coverage now
  locks that end-to-end path, direct HTTP handler coverage proves the same
  persisted approval state on the real POST `/mcp` approval gate, and live
  WebSocket integration coverage now locks the same stored approval context on
  the real `/mcp/ws` unknown-tool and untrusted-tool branches.
  Live HTTP, WebSocket, and gRPC coverage now also locks the emitted approval-
  gate audit entry, so the persisted pending approval and the ACIS JSONL record
  both preserve the same clamped `client_provenance` summary.
- **HTTP proxy live presented-approval replay prevention (Mar 2026):**
  Live HTTP POST, WebSocket `/mcp/ws`, and gRPC unary coverage now proves that
  an approved presented `approval_id` is consumed exactly once on the real
  handler path: the first call forwards upstream and marks the approval
  `Consumed`, and a replayed second call with the same `approval_id` fails
  closed as `Denied by policy`. The replayed invalid-approval audit entry keeps
  the same clamped transport provenance in ACIS instead of dropping back to a
  context-free denial record.

### Fixed

- **R249 adversarial audit — transport parity + ACIS wiring (Mar 2026):**
  3 findings (1 CRITICAL, 1 HIGH, 1 MEDIUM).
  - R249-PROXY-PARITY-1 (CRITICAL) — `extract_text_from_result()` in
    http-proxy inspection only scanned `result.content[]` (tool call
    responses) but not `result.contents[]` (MCP resources/read responses).
    Resource read responses bypassed injection scanning on HTTP/WS/gRPC
    transports. Added all `contents[]` fields: text, blob, uri, name,
    description, mimeType, annotations. 1 new test.
  - R249-PROXY-1 (MEDIUM) — Content iteration bounded to 1000 items in
    `extract_text_from_result()` to prevent CPU exhaustion from
    pathologically structured JSON responses.
  - Gap 2/4 completion — Wired ACIS envelopes into remaining 10 secondary
    sites in http-proxy (upstream, SSE inspection, auth, helpers) and 11
    server route handlers (approval, auth_level, billing, circuit_breaker,
    deputy, policy, policy_lifecycle, registry, schema_lineage, shadow_agent).
    28 new integration tests for ACIS envelope coverage.

- **R246 adversarial audit — DLP/injection resource read gap (Mar 2026):**
  6 findings (2 CRITICAL, 2 HIGH, 2 MEDIUM). Genuine fixes:
  - R246-RELAY-5 (HIGH) — `scan_response_for_secrets()` (DLP) and
    `extract_response_text()` (injection) only scanned `result.content[]`
    but not `result.contents[]` (MCP resources/read response format).
    Resource read responses bypassed both DLP and injection scanning in
    the stdio relay response path. Added all `contents[]` fields:
    text, blob (base64-decoded), uri, name, description, mimeType,
    annotations. 4 new tests.
  - R246-RELAY-1/2 — Session binding added to approval matching and
    consumption methods (20 call sites updated for new `session_id`
    parameter). Prevents cross-session approval replay.
  - R246-SRV-3 — `retry_after_seconds` removed from rate limit JSON
    response bodies (kept in Retry-After header per RFC 7231).
  - R246-ENG-1 — Priority i32→u32 cast uses `u32::try_from().unwrap_or(0)`
    instead of `.max(0) as u32`.
  - R246-ACIS-1 — `AcisActionSummary::validate()` standalone method with
    `MAX_TARGET_COUNT` (100K) bounds on path/domain counts.
  - False positives closed: R246-RELAY-3 (DLP exists in handler),
    R246-RELAY-6 (dlp_findings checked), R246-RELAY-7 (tainted data
    skip is intentional per FIND-R79-001), R246-SRV-1 (Duration overflow
    requires 585K+ years).

- **R244 adversarial audit — ACIS + formal verification hardening (Mar 2026):**
  19 findings (2 CRITICAL, 5 HIGH, 7 MEDIUM, 5 LOW) across ACIS envelope
  validation, approval TOCTOU, formal proof completeness, and field bounds.
  - **Sprint 1 (2 CRITICAL):**
    R244-ACIS-1 — ACIS envelopes validated via `validate()` before audit
    persistence in `log_entry_with_acis()` (rejects malformed fields, oversized
    strings, dangerous characters). R244-TOCTOU-1 — approval consumption moved
    atomically adjacent to match validation at all 6 relay sites (tool call ×2,
    resource read, task request, sampling/elicitation, registry unknown/untrusted),
    closing ~230-line TOCTOU window between match and consume. 2 new tests.
  - **Sprint 2 (5 HIGH):**
    R244-ACIS-3 — `MAX_TOOL_LEN` (256) and `MAX_FUNCTION_LEN` (256) constants
    enforced in `AcisDecisionEnvelope::validate()`. R244-ACIS-4 — `agent_id`
    validated for emptiness, length (512), and dangerous characters. R244-ACIS-5 —
    `agent_identity` nested `validate()` delegated. R244-ACIS-8 —
    `action_summary.function` empty-string check added. R244-ACIS-2 —
    `EvaluationContext` now passed to all 4 relay `build_acis_envelope()` call
    sites, populating `agent_identity` and `agent_id` in audit envelopes.
    R244-FORMAL-1 — Verus `lemma_consumed_status_blocks_re_consumption()` proves
    that non-Approved status (Consumed, Pending, Denied, Expired) universally
    blocks consumption regardless of fingerprint or scope match. 6 new tests.
  - **Sprint 3 (4 MEDIUM):**
    R244-SESSION-1 — all 6 `create_pending_approval()` call sites in relay.rs
    now pass `state.agent_id` as the session binding parameter, closing
    cross-session approval isolation gap (task request, sampling/elicitation,
    tool call, resource read, registry unknown/untrusted handlers).
    R244-ACIS-7 — `evaluation_us` capped at 3,600,000,000 µs (1 hour) and
    `call_chain_depth` capped at 256 in `AcisDecisionEnvelope::validate()`;
    `build_result()` / `build_acis_envelope()` clamp depth to 256 at
    construction time. R244-FORMAL-2 — confirmed `has_dangerous_chars` and
    `is_unsafe_char` are semantically identical (both delegate to
    `is_control() || is_unicode_format_char()`); no oracle mismatch.
    R244-FINDINGS-1 — findings dedup confirmed non-issue: DLP findings use
    `"DLP: "` prefix, injection findings use `"injection: "` prefix, making
    collision impossible. 4 new tests.
  - **Sprint 4 (1 HIGH — transport parity):**
    R244-PROXY-1 — `EvaluationContext` now passed to all `build_acis_envelope()`
    calls across HTTP proxy (6 sites in handlers.rs — tool call, resource read,
    sampling/task request), gRPC proxy (12 sites in service.rs — tool call,
    resource read, task request, extension method × 3 verdicts each), and
    WebSocket proxy (12 sites in websocket/mod.rs — same handler matrix).
    HTTP handler closures refactored to return `(result, eval_ctx)` tuples so
    context survives past DashMap shard lock scope. Server routes already wired
    correctly via `build_evaluate_acis_envelope()`. Full transport parity for
    agent identity in ACIS envelopes across all 5 transports.
  - **Sprint 5 (2 HIGH — config/cluster):**
    R244-CEDAR-1 — Cedar policy parser `parse_head()` and `parse_when_clause()`
    escape handling now bounds-checks before advancing past backslash; trailing
    backslash at string end treated as literal instead of skipping past buffer.
    R244-CLUSTER-1 — `RedisBackend::new()` enforces `rediss://` (TLS) for
    non-localhost Redis connections; approval state, rate limits, and dedup
    hashes no longer exposed to network observers. Localhost exemptions:
    `127.0.0.1`, `localhost`, `[::1]`. 6 new tests.
  - **Sprint 6 (1 CRITICAL — TLS):**
    R244-TLS-1 — SPIFFE workload path percent-decoding changed from
    `(hi << 4 | lo) as char` to `Vec<u8>` + `std::str::from_utf8()`; invalid
    UTF-8 sequences (e.g., `%80`) now produce fail-closed rejection instead of
    invalid Unicode characters. Return type changed from `Option<String>` to
    `Result<Option<String>, ()>`. 1 new test.
- **R245 adversarial audit — strict UTF-8 percent-decode (Mar 2026):**
  - **R245-SRV-4 (MEDIUM):** All 5 `percent_decode_str().decode_utf8_lossy()`
    sites in `scan_params_for_targets_inner()` and `looks_like_relative_path()`
    replaced with strict `decode_utf8()`. Malformed UTF-8 in percent-encoded
    paths/domains/authority is now fail-closed (skipped) instead of silently
    substituted with U+FFFD, preventing replacement-character policy bypass
    where lossy decode could produce different strings than downstream consumers.
    Transport parity: same fix applied to 4 sites in `vellaveto-mcp/src/extractor.rs`.
- **R246 adversarial audit — ACIS validation + type safety hardening (Mar 2026):**
  - **Sprint 1 (1 HIGH, 2 MEDIUM):**
    R246-ENG-1 — policy priority `i32→u32` cast in 3 debug-assert sites changed
    from fragile `.max(0) as u32` to safe `u32::try_from(...).unwrap_or(0)`;
    prevents accidental priority inversion if `.max(0)` is ever removed.
    R246-ACIS-1 — `MAX_TARGET_COUNT` (100,000) constant added;
    `target_path_count` and `target_domain_count` now bounds-checked in
    `AcisActionSummary::validate()`, preventing metrics overflow from
    crafted envelopes. R246-TYPES-1 — `AcisActionSummary` gets standalone
    `validate()` method (tool/function length+content + target count bounds);
    `AcisDecisionEnvelope::validate()` refactored to delegate to it.
    7 new tests.
  - **Sprint 2 (1 MEDIUM):**
    R246-SRV-3 — `retry_after_seconds` removed from JSON response bodies at
    all 4 rate limit sites (tenant evaluation, per-IP, per-principal, global
    category). The `Retry-After` HTTP header (RFC 7231) is kept. Body leakage
    allowed attackers to infer tenant quota capacity and bucket sizes.
  - **Integration tests (R244-INTEGRATION-1):**
    10 end-to-end ACIS integration tests: mediation pipeline envelope
    construction (Allow/Deny), agent identity capture from EvaluationContext,
    fingerprint determinism across transports, evaluation_us/call_chain_depth
    validation bounds, depth clamping to 256, audit persistence with
    `log_entry_with_acis()`, invalid envelope rejection, DLP integration.

### Added

- **E1 — ACIS Contract and Boundary Inventory (Sprint 1, Mar 2026):**
  Defines the Agent-Consumer Interaction Surface (ACIS) as a runtime contract
  shared by every enforcement path. Every security decision now carries a
  structured `AcisDecisionEnvelope` in the audit trail.
  - E1-1: `AcisDecisionEnvelope`, `DecisionKind`, `DecisionOrigin`,
    `AcisActionSummary` types in `vellaveto-types/src/acis.rs` (16 tests).
  - E1-2: `AcisConfig` in `vellaveto-config/src/acis.rs` — envelope emission,
    session/identity binding, transport defaults (11 tests).
  - E1-3: Full transport interception inventory (stdio relay, HTTP handler,
    WebSocket, gRPC, server API).
  - E1-4: `compute_action_fingerprint()` SHA-256 + `fingerprint_action()` in
    `vellaveto-engine/src/acis.rs` (6 tests).
  - E1-5: `acis_envelope: Option<AcisDecisionEnvelope>` added to `AuditEntry`
    (backward-compatible). `log_entry_with_acis()` entrypoint in audit logger.
    Wired into server evaluate path (7 sites), stdio relay (4 sites: tool call
    allow/block, resource read allow/block), HTTP proxy handler (6 sites:
    tool call deny/require-approval, resource read deny/require-approval, task
    request allow/deny/require-approval), WebSocket proxy (12 sites: tool call,
    resource read, task request, extension method × Allow/Deny/RequireApproval),
    and gRPC proxy (12 sites: same handler × verdict matrix). **41 total
    ACIS-wired verdict decision sites across all 5 transports.** 33 new tests.

- **E2 — Canonical Mediation Pipeline (Sprint 1, Mar 2026):**
  Consolidates the ACIS envelope construction into a shared mediation pipeline
  for the ProxyBridge relay path.
  - E2-1: `mediate()` function in `vellaveto-mcp/src/mediation.rs` — canonical
    pipeline that evaluates action, builds ACIS envelope, and returns
    `MediationResult` with verdict + envelope.
  - E2-2/3/4: `build_acis_envelope()` shared builder + ProxyBridge integration.
  - E2-5/E2-6: Cross-transport determinism tests verifying identical actions
    produce identical ACIS fingerprints regardless of transport.

- **Gap closure — IDNA, Unicode, Lock Safety (K61-K68):**
  Closes the three remaining formal verification gaps (IDNA normalization, Unicode
  homoglyph preprocessing, and async/concurrent wrappers).
  - K61-K63 — IDNA domain normalization fail-closed: `normalize_domain_for_match`
    extracted with abstracted `idna::domain_to_ascii` as `Result<String, ()>` parameter.
    Non-ASCII IDNA failure → None (K61), ASCII IDNA failure → lowercase fallback (K62),
    wildcard prefix preserved (K63).
  - K64-K65 — Unicode homoglyph normalization: `normalize_homoglyphs` verbatim
    extraction (188-line char mapping: Cyrillic, Greek, Armenian, Cherokee, Fullwidth
    Latin, Palochka, dashes, curly quotes). Idempotency proven (K64), all mapped
    confusables collapse to ASCII (K65).
  - K66-K68 — RwLock poisoning fail-closed: all 6 lock sites modeled as pure predicates.
    Cache lock poison → miss (K66), Deputy lock poison → InternalError (K67), all handlers
    produce safe outcome (K68). No lock site ever produces stale Allow.
  - 109 parity tests (up from 83). 220 total verification instances.

- **Formalization completion (K59-K60, doc fixes, CI sync):**
  K59 — Shannon entropy verification (`compute_entropy` from collusion detector: finite,
  non-negative, ≤ 8.0, empty → 0.0). K60 — capability grant coverage fail-closed
  (`grant_covers_action` from capability_token.rs: path/domain restriction enforcement).
  Fixed task state extraction naming to match production (`Pending`/`Running`/`Cancelled`
  vs phantom `Submitted`/`Working`/`InputNeeded`). Fixed all documentation count
  inconsistencies (Verus 23→29, Kani 58→60, total 210→212). CI extraction sync checks.
  Updated GitHub README with Verus row and 212-property badge. 83 parity tests pass.

- **Phases 5–14 — Full Formalization Roadmap (K26-K58, V9-V12):**
  37 new verification instances bringing total from 173 to 210. All security-critical
  pure functions now formally verified on actual Rust code.
  - **Phase 5 — IP Address Verification (K26-K32, Kani):** 7 harnesses proving
    `is_private_ip` correctness for loopback, RFC 1918, CGNAT, IPv4-mapped IPv6,
    Teredo XOR inversion, and known-public-not-blocked. Full symbolic 2^32 IPv4 parity
    between `is_private_ipv4` and `is_embedded_ipv4_reserved`. Closes DNS rebinding/SSRF gap.
  - **Phase 6 — Cache Safety Verification (K33-K35, Kani):** 3 harnesses proving
    `is_cacheable_context` rejects session-dependent state, cache keys are case-insensitive,
    and entries are invalid after TTL expiry or generation bump. Closes cache poisoning gap.
  - **Phase 7 — Capability Delegation (K36-K40, Kani):** 5 harnesses proving
    `grant_is_subset` reflexivity, no-escalation (child ⊆ parent), `pattern_is_subset`
    correctness, `glob_match("*", any) == true`, and `normalize_path_for_grant` has no
    traversal. Closes capability escalation gap (was Alloy/Coq abstract only).
  - **Phase 8 — Rule Checking Fail-Closed (K41-K45, Kani):** 5 harnesses proving
    empty paths + allowlist → Deny, blocked pattern overrides allowed, IDNA failure → Deny,
    no resolved IPs → Deny, block_private + private IP → Deny.
  - **Phase 9 — ResolvedMatch Equivalence (K46-K48, Kani):** 3 harnesses proving
    path deny → `rule_override_deny`, context deny → `context_deny`, and inline verdict
    equals `compute_single_verdict(ResolvedMatch)` for all 13 symbolic boolean combinations.
    Connects verified core to production evaluation path.
  - **Phase 10 — Cascading Failure (K49-K52, Kani):** 4 harnesses proving NaN/Infinity
    config rejection, chain depth saturating increment, capacity fail-closed at MAX, and
    error rate bounded ∈ [0.0, 1.0].
  - **Phase 11 — Constraint Evaluation (K53-K55, Kani):** 3 harnesses proving
    all-constraints-skipped detection, forbidden parameter → Deny, and
    require_approval → RequireApproval verdict propagation.
  - **Phase 12 — Task Lifecycle (K56-K58, Kani):** 3 harnesses proving terminal
    state immutability, capacity fail-closed at MAX, and cancel authorization
    (self-cancel + different requester → reject).
  - **Phase 13 — Verus Path Normalization (V9-V10):** Byte-level `normalize_path_bytes`
    proven idempotent (V9) and traversal-free (V10) for ALL possible inputs via Z3 SMT.
  - **Phase 14 — Verus Rule Override Correctness (V11-V12):** Path block → Deny (V11)
    and network/IP block → Deny (V12) proven via `lemma_first_match_override_is_deny`.
  - 74 Kani parity tests, 8 new extraction modules, 3 new Verus lemmas.
  - Updated `docs/TRUSTED_COMPUTING_BASE.md` (v3.0.0), `formal/README.md`,
    `formal/verus/README.md`.

- **Phase 2 — Verus Cross-Call DLP Buffer Verification (14 verified, 0 errors):**
  `vellaveto-mcp/src/inspection/verified_dlp_core.rs` — pure buffer arithmetic functions
  (`extract_tail`, `can_track_field`, `update_total_bytes`) factored from `cross_call_dlp.rs`.
  `formal/verus/verified_dlp_core.rs` — Verus-annotated version proving D1-D6 (UTF-8 boundary
  safety, buffer size bounds, byte accounting, capacity fail-closed, no underflow, overlap
  completeness) for ALL possible inputs via Z3 SMT. 5 proof lemmas including bit_vector proofs
  for UTF-8 continuation byte classification. 32 unit tests. `CrossCallDlpTracker` wired to
  use verified core functions. Total: 155 verification instances across 6 tools.

- **Phase 1 — Verus Core Verdict Verification (9 verified, 0 errors):**
  `vellaveto-engine/src/verified_core.rs` — `ResolvedMatch` abstraction factors pure verdict
  computation from String/HashMap/serde. `formal/verus/verified_core.rs` — Verus-annotated
  version proving V1-V5, V8 for ALL possible inputs via Z3 SMT (Verus 0.2026.03.01). Engine
  wired with `debug_assert` validations. 41 unit tests. CI runs Verus binary release. 3 proof
  lemmas (first-match-override, all-unmatched, skip-continues). Total: 141 verification
  instances across 6 tools.

- **Phase 0 — Formal Verification Plan + TCB Document:**
  `docs/FORMAL_VERIFICATION_PLAN.md` — comprehensive 4-phase roadmap: Verus core verdict
  verification (V1-V8, ALL inputs), Verus cross-call DLP buffer arithmetic (D1-D6),
  Kani expansion to 34 harnesses, and arXiv paper. `docs/TRUSTED_COMPUTING_BASE.md` —
  complete TCB declaring every verified property, every trusted component, every abstraction
  boundary, and every unverified property with rationale. Updated CI workflow to gate PRs on
  formal verification when security-critical paths (engine, inspection, TLS) change.

- **Phase 71: Cross-call DLP state tracking** (`vellaveto-mcp/src/inspection/cross_call_dlp.rs`):
  `CrossCallDlpTracker` with overlap buffers detects secrets split across multiple tool calls
  within a session. ~150 bytes per field, 256 max tracked fields, UTF-8 boundary safe. 12 tests.

- **Phase 71.1: TLS termination** (new `vellaveto-tls` crate):
  Shared rustls-based TLS/mTLS module for `vellaveto-server` and `vellaveto-http-proxy`.
  SPIFFE identity extraction from X.509 SAN URIs. Post-quantum key exchange policy enforcement
  (ClassicalOnly, HybridPreferred, HybridRequiredWhenSupported). 11 tests.

- **Phase 72: Schema pattern validation tests** (MCPSEC A13 + A14):
  A13 — cross-call secret splitting attacks (4 test vectors). A14 — JSON Schema output
  validation bypass (4 test vectors). Registry expanded from 64→72 attack tests, 12→14 classes.

- **Independent verification infrastructure:**
  `SECURITY_BOUNTY.md` — HackerOne + Huntr bug bounty program with severity tiers ($100–$5,000).
  `docs/OSTIF_AUDIT_SCOPE.md` — audit scope document for OSTIF/Alpha-Omega applications.
  `codecov.yml` — Codecov configuration with 80% patch coverage target and binary exclusions.

- **Test coverage expansion — Phase 1** (3,764 lines across 16 files in 4 crates):
  Comprehensive tests for audit (archive, PQC, streaming, PostgreSQL query/sink, ZK proofs),
  cluster (Redis backend), HTTP proxy (gRPC convert/interceptors), MCP (A2A agent card/error,
  RAG defense embedding/error/grounding, semantic guardrails cache/intent).

- **Test coverage expansion — Phase 2** (+948 inline tests across 39 files in 7 crates):
  Tier 1 foundational coverage: vellaveto-types (+124: minja, threat, zk_audit, policy_lifecycle,
  compliance), vellaveto-config (+228: threat_detection, memory_nhi, mcp_protocol,
  semantic_guardrails, enterprise), vellaveto-audit (+88: redaction, events, etdi_audit,
  verification, merkle), vellaveto-discovery (+85: schedule, inference, serialize, crawler, diff).
  Tier 2 engine/proxy/server: vellaveto-engine (+206: compiled, constraint_eval, rule_check,
  legacy, normalize, traced, policy_compile, context_check), vellaveto-http-proxy (+104: auth,
  origin, call_chain, inspection, fallback), vellaveto-server (+123: routes/mod, dpop,
  idempotency, tenant, threat_intel, tls). All #[cfg(test)] modules only — zero production
  code modified.

- **Test coverage expansion — Phase 3** (+209 inline tests across 12 files in 5 crates):
  Server routes: vellaveto-server (+154: compliance, policy_lifecycle, inventory, approval,
  audit, etdi, exec_graph, tenant). Cluster: vellaveto-cluster (+14: local backend approval
  delegation, error mapping). Benchmark: mcpsec (+8: config construction, serde roundtrips,
  invariant checks). MCP proxy bridge: vellaveto-mcp (+17: helpers extraction, evaluation
  forwarding, annotation hints). Approval: vellaveto-approval (+16: dedup key determinism,
  homoglyph normalization, capacity, reason/identity validation).

- **Enhanced policy presets for non-expert users:**
  Every preset is now a complete, well-documented security posture with plain-language threat
  explanations. A user running `--protect shield` gets comprehensive protection without understanding
  policy syntax. Every policy has a `# THREAT:` comment block explaining the attack in plain language.
  - `shield` — 3→8 policies: added SANDWORM defense (AI config injection prevention), exfiltration domain
    blocking (pastebin, ngrok, webhook.site, etc.), git hook manipulation blocking, system file protection
    (/etc/shadow, sudoers, crontab, systemd), approval gates for destructive git operations, memory tracking.
  - `fortress` — 8→11 policies: added system file protection, package config tampering defense (.npmrc,
    pip.conf, cargo config, pypirc), privilege escalation approval (sudo/su/doas), enhanced dangerous
    commands (eval, python -c), memory poisoning detection (blocking), shadow agent detection.
  - `vault` — 7→11 policies: added usable Allow rules so basic coding works out of the box — source code
    reading allowed (credential files still blocked at higher priority), read-only git commands allowed,
    file writes require human approval. Elicitation controls enabled.
  - `dev-laptop` — 3→9 policies: comprehensive workstation protection with full credential coverage (17
    patterns), SANDWORM defense, exfil blocking, git hooks, system files, package configs, injection +
    DLP blocking.
  - `ci-agent` — 4→7 policies: SANDWORM defense, git hook protection, exfil domain blocking, expanded
    registry allowlist (npm, PyPI, crates.io, Maven, RubyGems, Docker Hub, GHCR).
  - `database-agent` — 4→6 policies: expanded credential coverage (17 patterns), SQL injection blocking
    (UNION SELECT, INTO OUTFILE, xp_cmdshell), schema change approval gates.
  - `browser-agent` — 5→7 policies: expanded credentials, sensitive JS execution blocking (document.cookie,
    localStorage, keylogger patterns), URL shortener phishing defense (bit.ly, tinyurl, t.co, goo.gl).
  - `devops-agent` — 9→11 policies: added credential file blocking (was missing), secret write approval
    (vault write, kubectl create secret, aws ssm put-parameter), namespace/cluster deletion blocking.
  - Updated `presets.rs` descriptions and test assertions to match new policy counts.
  - Updated README, website ProtectionLevels component, examples/presets/README, SHOW_HN, and
    create-vellaveto README with enhanced descriptions.

- **Easy Mode Protection Presets (`--protect shield/fortress/vault`):**
  Three beginner-friendly protection levels for users who don't want to write policy configs.
  - New `--protect <LEVEL>` CLI flag on `vellaveto-proxy`, mutually exclusive with `--config` and `--preset`.
  - Grouped `--list-presets` output showing protection levels first, then professional presets.
  - Claude Desktop, Cursor, and Windsurf integration examples in README and QUICKSTART.
  - 11 new tests, 6 new preset TOML files.

- **MCPSEC Benchmark promotion:** Added MCPSEC benchmark section to README and landing site.
  Open, vendor-neutral security benchmark for MCP gateways (Apache-2.0). 10 formal properties,
  64 attack tests, 12 attack classes. Updated reference results to v6.0.0 (100/100, Tier 5 — all 64 tests passed).

- **Content inspection endpoint for MCPSEC benchmarking:**
  New `_test_response` field on the evaluate endpoint triggers injection and DLP scanning on
  provided content, returning results in an `inspection` field. Enables the MCPSEC benchmark
  runner to test detection capabilities without a live proxy connection. Also adds rapid-fire
  test support for rate limiting tests.

- **Code-review-agent preset (`examples/presets/code-review-agent.toml`):**
  New professional preset for AI agents performing code review. Read-only access to source
  files and git history, blocks writes/deletes/destructive commands, credential file protection,
  network allowlist limited to git remotes, default deny. Registered in preset table and README.

- **Compliance-starter preset (`examples/presets/compliance-starter.toml`):**
  New preset enabling all 6 configurable compliance frameworks (EU AI Act, NIS2, DORA, SOC 2,
  OWASP ASI, Data Governance) with strict audit mode, injection/DLP blocking, and default deny.
  Designed as a comprehensive compliance baseline for regulated environments.

- **Comprehensive compliance documentation (`docs/COMPLIANCE.md`):**
  New guide covering all 12 regulatory and industry frameworks with detailed per-article
  requirement mappings, evidence pack generation instructions (API and Rust), cross-regulation
  incident reporting timelines, 10-framework gap analysis, full API endpoint reference (11 endpoints),
  and compliance preset catalog. Compliance messaging strengthened across README, SHOW_HN, and site.

- **Coq formal verification (15 theorems, S1–S16):**
  New `formal/coq/` directory with 6 proof files: `Types.v`, `FailClosed.v`, `Determinism.v`,
  `PathNormalization.v`, `AbacForbidOverride.v` (S7–S10), `CapabilityDelegation.v` (S11–S16).
  Zero `Admitted` proofs — all theorems fully machine-checked. Covers fail-closed semantics,
  determinism, path normalization idempotence, ABAC forbid-override, and capability delegation
  attenuation. Build infrastructure via `_CoqProject` and Makefile.

- **Crates.io publish readiness (`vellaveto-proxy` v3.1.0):**
  Presets embedded inside the binary via `include_str!()` for zero-file-dependency packaging.
  New `vellaveto-proxy init` command generates a starter config from any preset. Version fields
  added to all workspace path dependencies.

- **OpenSSF Best Practices Gold badge infrastructure:**
  SPDX license headers on all 211 `.rs` files (CI-enforced), coverage CI with cargo-llvm-cov +
  Codecov, dynamic analysis CI (5 fuzz targets), reproducible builds docs, security review docs,
  hardening docs, Gold self-assessment (`docs/OPENSSF_GOLD.md`).

- **Interactive demo tooling:**
  VHS tape script (`shield-demo.tape`) for automated terminal recording of consumer shield
  protection demo. Enhanced `run-demo.sh` shell script for guided demonstrations.

- **Policy cookbook (`docs/POLICY_COOKBOOK.md`):** Ready-to-use policy recipes for common
  deployment scenarios.

- **SDK examples:** LangChain agent integration example, Go SDK examples, examples index page.

- **Consumer Shield — Wire Unused Features (6 items, 15 new tests):**
  Closes gaps where shield modules were implemented but never wired into the production pipeline.
  - **Session cleanup on relay exit (HIGH):** `cleanup_shield_sessions()` calls `ContextIsolator::end_session()` and `SessionUnlinker::end_session()` after the relay loop breaks, preventing memory leaks and stale Active credentials.
  - **Credential vault replenishment (HIGH):** `generate_local_credential()` fills 32-byte cred + 64-byte sig from CSPRNG; `replenish()` fills vault to threshold; background tokio task checks `needs_replenishment` on a timer.
  - **Wire `desanitize_responses` flag (MEDIUM):** `shield_desanitize_responses` field on ProxyBridge guards the desanitize block; when `false`, PII placeholders are preserved in responses.
  - **Wire `audit_mode` field (MEDIUM):** Encrypted local audit store only initializes when `audit_mode == "local"`; `"remote"` mode logs skip message.
  - **`traffic_padding` config field (MEDIUM):** Bool field on `ShieldConfig` (default `false`) with startup logging when enabled.
  - **ZK commitments wiring (MEDIUM):** `zk-audit` feature on `vellaveto-mcp-shield` and `vellaveto-shield`; optional `PedersenCommitter` in `LocalAuditManager` with advisory commitment generation in log path.
  - **Test count:** 8,917 → 8,932 Rust tests, 0 failures, clippy clean.

- **Project governance:** Added `CODE_OF_CONDUCT.md` (Contributor Covenant) and `GOVERNANCE.md`
  (project governance structure and decision-making process).

- **Developer CI guide (`docs/CI_GREEN.md`):** Comprehensive guide documenting all CI gates,
  pre-push verification commands, and top 10 historical CI killers.

- **SDK and component READMEs:** Added missing READMEs for Python SDK, TypeScript SDK, Go SDK,
  Java SDK, Helm chart, Terraform provider, VS Code extension, and admin console.

### Security

- **Adversarial Audit Round 235 (59 findings across 6 parallel agents, 40 fixed in 3 sprints):**
  Full-codebase adversarial security audit. 59 raw findings (13 HIGH, 29 MEDIUM, 17 LOW), 40 fixed
  across 3 sprints covering engine, server, MCP relay, discovery, audit, config, and types crates.
  - **Sprint 1 — HIGHs (13 fixes, commit `7eb4beb`):**
    - **R235-SRV-1/2:** OIDC discovery + IAM HTTP client redirect disable (SSRF via open redirect).
    - **R235-SHIELD-1:** Traffic padding `as u32` → `u32::try_from` (silent truncation).
    - **R235-SHIELD-2:** Credential vault `expire_old_epochs()` persistence after mutation.
    - **R235-SHIELD-3:** Canary `canonical_payload()` error propagation (was `unwrap_or_default`).
    - **R235-DISC-1/2/3:** TopologyGuard RwLock poisoning — fail-closed check, `into_inner()` recovery on load/clear.
    - **R235-AUD-1/2:** IncidentReport per-entry Vec validation + RegulatoryReference `validate()`.
    - **R235-RLY-1:** Circuit breaker, shadow agent, deputy validation on `handle_resource_read`, `handle_task_request`, `handle_extension_method` (transport parity).
    - **R235-RLY-2:** Cross-call DLP + sharded exfil tracking on all non-tool-call handlers.
  - **Sprint 2 — MEDIUMs (17 fixes, commit `53ed9f8`):**
    - **R235-ENG-1/2:** Genericize deny reasons in `rule_check.rs` (5 sites) and `constraint_eval.rs` (5 sites) — remove user-controlled path/domain/pattern values from deny strings (info disclosure).
    - **R235-SRV-3:** DPoP `check_timestamp` fail-closed (`unwrap_or(0)` → `map_err`).
    - **R235-SRV-4/5:** Threat intel `check_indicator` input validation + post-deserialization `validate()`.
    - **R235-DISC-4/5:** `StaticProbe::upsert_server`/`remove_server` RwLock poisoning recovery.
    - **R235-DISC-6:** `schedule.rs` `fetch_add` wrapping → `fetch_update` + saturating + `SeqCst`.
    - **R235-AUD-3:** Merkle `leaf_count as usize` → `usize::try_from`.
    - **R235-AUD-4:** ETDI audit helpers dangerous char validation on all parameters.
    - **R235-TYP-1:** `McpCapability.version` `has_dangerous_chars`.
    - **R235-TYP-2/3/4:** `ProvenanceNode`, `QuarantineEntry`, `MemoryNamespace` `has_dangerous_chars` on all string fields.
    - **R235-CFG-1/2/3:** New `validate()` for `ShadowAgentConfig`, `SamplingDetectionConfig`, `AdvancedThreatConfig`.
  - **Sprint 3 — LOWs (10 fixes, commit `53ed9f8`):**
    - **R235-AUD-5/6:** `saturating_add` on all `verification.rs` counters (9 sites).
    - **R235-DISC-7:** `server_count()` RwLock poisoning recovery via `into_inner()`.
    - **R235-DISC-8:** `as u64` → `u64::try_from` on `timeout_ms`; `Ordering::Relaxed` → `SeqCst` on schedule counters.
    - **R235-CFG-4:** `extra_templates` per-entry length + dangerous chars validation.
    - **R235-TYP-5:** New `Cc6Evidence::validate()` wired into `AccessReviewReport`.
    - **R235-TYP-6:** `ZkBatchProof` `as usize` → `usize::try_from`.

- **Adversarial Audit Round 237 (31 findings, 22 fixed in 3 sprints):**
  Full-codebase 6-agent adversarial security audit. 31 findings (7 HIGH, 16 MEDIUM, 8 LOW),
  22 fixed across 3 sprints. 10,350 tests, 0 failures.
  - **Sprint 1 — HIGHs + critical MEDIUM (7 fixes):**
    - **R237-ENG-1:** Wasm `reload_plugins` case-insensitive duplicate check (MyPlugin vs myplugin).
    - **R237-MCP-1:** HTML named entity decode gap (`&lt;` `&gt;` `&amp;` `&quot;` `&apos;` `&nbsp;`).
    - **R237-SRV-1/3:** OIDC callback and session creation error genericization (info leak).
    - **R237-SRV-2:** `store_flow` capacity fail-closed with `CapacityExhausted` error variant.
    - **R237-SHLD-1:** Shield passphrase via `VELLAVETO_SHIELD_PASSPHRASE` env var (avoid cmdline exposure).
    - **R237-DIFF-1:** Audit log errors surfaced via `tracing::warn` at 6 relay sites (was `let _ =`).
  - **Sprint 2 — MEDIUMs (7 fixes + 1 LOW):**
    - **R237-MCP-2:** Circuit breaker checks on `handle_sampling_request` and `handle_elicitation_request`.
    - **R237-MCP-4:** Cross-call DLP capacity exhaustion produces synthetic `DlpFinding`.
    - **R237-MCP-5:** Elicitation DLP audit action includes tool name for traceability.
    - **R237-TLS-1:** SPIFFE `trust_domain` format validation (lowercase alphanumeric + `.` + `-`).
    - **R237-SHLD-3:** Context isolation method name sanitization (alphanumeric + `/._-`, max 128).
    - **R237-ENG-7:** Collusion window upper bounds (coordination 24h, recon 1h, drift 7d).
    - **R237-PROXY-1:** `call_chain_max_age_secs` u64→i64 safe cast via `try_from`.
  - **Sprint 3 — HIGH + MEDIUMs (10 fixes):**
    - **R237-ENG-2 (HIGH):** Regex constraint path normalization — percent-decode before regex match, parity with Glob/NotGlob (constraint_eval.rs + traced.rs).
    - **R237-ENG-3/5:** ABAC conditions use `normalize_full()` for all string comparison operators (Eq, Ne, In, NotIn, Contains, StartsWith) — prevents Unicode homoglyph/case bypass.
    - **R237-ENG-6:** Cache bypassed when `risk_score` is present (ABAC verdict dependency).
    - **R237-SHLD-2:** Temp file cleanup guard on `rewrite_all_entries` error path.
    - **R237-TLS-2:** `verify_client_cert` must be true when `require_client_cert` is true.
    - **R237-SRV-4:** M2M per-client rate limiting (10 requests/60s window, DashMap, 50K capacity).
    - **R237-SRV-5:** SAML `InResponseTo` replay protection (consumed via `remove()`, 600s TTL).
    - **R237-MCP-3:** Punycode decode pass in injection scanner (RFC 3492 bootstring, `xn--` labels).
    - **R237-MCP-6:** Semantic guardrails timeout audit logging on all 3 fallback paths.
    - **R237-CFG-1:** TLS cert/key path traversal + length validation.

- **Adversarial Audit Round 236 (20 findings fixed):**
  See commit `ad4e4ee` for details.

- **Coq formal verification CI gate (17th CI job):**
  Builds and verifies all Coq proofs on every push. Rejects incomplete proofs containing
  `Admitted` or `admit` markers. 10-minute timeout, independent of Rust pipeline.

- **CodeQL advanced configuration:** Enhanced static analysis with test file exclusions
  to reduce noise while maintaining security scanning of production code.

- **Rust clippy CI workflow:** Dedicated clippy lint gate.

- **Secret scanning hardening:** MongoDB test URI split to avoid GitHub secret scanning
  false positives.

### Changed

- **Repository organization migration:** All GitHub URLs updated from `paolovella` to `vellaveto`
  organization namespace. Old URLs redirect.

- **Go SDK file naming:** Source files renamed from `sentinel.go` to `client.go` for Go
  package naming conventions.

- **Docker base images pinned:** SHA256-pinned base images for reproducible container builds.
  Scorecard workflow permissions added.

### Fixed

- **Python SDK URL detection:** Fixed `urlparse()` usage instead of `startswith()` for HTTP/HTTPS
  detection, preventing URL parsing edge cases.

- **Policy ID format:** Corrected policy ID format in all preset TOML files to match validation rules.

- **Docker image license label:** Corrected from `AGPL-3.0` to tri-license (MPL-2.0 / Apache-2.0 / BUSL-1.1).

- **Stale references:** Corrected outdated references across Helm chart, ROADMAP, CI docs, and site.

- **Compliance documentation accuracy:** Fixed API endpoint examples (path params not query params),
  evidence pack availability (SOC 2 separate endpoint), gap analysis framework count (7 → 10),
  Art 14 escalation claim removed (approval has timeout only).

- **Coq proof compilation:** Fixed 5 proof issues for Coq 8.18 compatibility (PathNormalization
  destruct semantics, induction hypothesis rewriting, parent variable substitution).

- **CI compliance:** Removed `.expect()` from library code, resolved clippy blockers, fixed
  env-var test race conditions via test serialization.

### Dependencies

- Bumped GitHub Actions group (9 action updates).
- Bumped admin-console npm dependencies.
- Bumped TypeScript SDK npm dependencies.
- Bumped VS Code extension `@types/node`.
- Fixed LangGraph typing for mypy compliance.

## [6.0.1] - 2026-02-28

### Fixed

- **Consumer shield stylometric normalization:** Fixed fail-closed behavior in relay outbound path —
  normalization errors now produce deny instead of passing through unnormalized content.

### Changed

- **Repository organization migration:** All GitHub URLs migrated from `paolovella` to `vellaveto`
  organization namespace.

## [6.0.0] - 2026-02-28

### Security

- **Adversarial Audit Round 231 (52 findings across 6 parallel agents, 31 fixed):**
  Full-codebase adversarial security audit across engine, MCP, server, audit+proxy, types+config, and discovery+A2A+cluster. 52 raw findings (8 HIGH, 22 MEDIUM, 22 LOW), 31 fixed across 4 sprints, remainder triaged as design decisions/theoretical/feature requests.
  - **Sprint 1 — HIGHs (8 fixes):**
    - **R231-SRV-1 (HIGH):** SCIM provisioning endpoint SSRF — added `validate_url_no_ssrf()` before `spawn_scim_sync`.
    - **R231-SRV-2 (HIGH):** SAML metadata URL SSRF — added `validate_url_no_ssrf()` in `SamlState::new()`.
    - **R231-AUD-1 (HIGH):** PostgreSQL `prev_hash` column NOT NULL prevents genesis row — changed to nullable `TEXT`.
    - **R231-DISC-4 (HIGH):** `from_snapshot()` unbounded edge count — added `MAX_SNAPSHOT_EDGES` (100K) check.
    - **R231-MCP-1 (HIGH):** Extension method injection scanning — added `scan_notification_for_injection()` after DLP check in `handle_extension_method`.
    - **R231-MCP-2 (HIGH):** Sampling DLP + injection scanning — added DLP and injection scanning before forwarding in `handle_sampling_request`.
    - **R231-TYP-4 (HIGH):** Cherokee→Latin confusables — added 12 mappings (U+13AA→'g', U+13B3→'w', U+13CB→'h', etc.).
    - **R231-TYP-8 (HIGH):** Cyrillic Palochka confusables — added U+04C0→'i' and U+04CF→'l' mappings.
  - **Sprint 2 — MEDIUMs part 1 (13 fixes):**
    - **R231-ENG-1 (MEDIUM):** Path normalization `decode_utf8_lossy` → strict `decode_utf8` with fail-closed error.
    - **R231-ENG-2 (MEDIUM):** ResourceIndicator matching without normalization — added `normalize_full()` before matching.
    - **R231-ENG-3 (MEDIUM):** Context conditions received un-normalized tool names — added `normalize_full()` in `lib.rs` and `traced.rs`.
    - **R231-ENG-4 (MEDIUM):** Collusion detector HashMap keys not normalized — added `normalize_full()` to all 4 recording methods.
    - **R231-SRV-3 (MEDIUM):** Phantom session on `create_session()` failure — changed return type to `Result<IamSession, IamError>` (fail-closed).
    - **R231-SRV-4 (MEDIUM):** `M2mTokenRequest` `derive(Debug)` leaks `client_secret` — custom `Debug` impl with `[REDACTED]`.
    - **R231-SRV-5 (MEDIUM):** SCIM response unbounded — added `MAX_SCIM_RESPONSE_SIZE` (10MB), 30s timeout, `bytes()` check.
    - **R231-SRV-6 (MEDIUM):** SAML metadata response unbounded — added `MAX_SAML_METADATA_SIZE` (2MB), 30s timeout, `bytes()` check.
    - **R231-AUD-2 (MEDIUM):** PostgreSQL ILIKE backslash escape — added `replace('\\', "\\\\")` before `%` and `_` escaping.
    - **R231-AUD-3 (MEDIUM):** OCSF sequence 0 omitted — removed conditional, always include sequence field.
    - **R231-AUD-4 (MEDIUM):** `OcsfEvent` missing `deny_unknown_fields` — added serde attribute.
    - **R231-MCP-3 (MEDIUM):** Elicitation DLP scanning — added `scan_parameters_for_secrets()` before forwarding.
    - **R231-MCP-4 (MEDIUM):** Wildcard model pattern matching — replaced exact comparison with prefix/suffix wildcard-aware matching.
  - **Sprint 3 — MEDIUMs part 2 (6 fixes):**
    - **R231-DISC-1 (MEDIUM):** Tool description and URI template unbounded — added `MAX_TOOL_DESCRIPTION_LEN` and `MAX_URI_TEMPLATE_LEN` enforcement.
    - **R231-DISC-2 (MEDIUM):** Resource name validation missing — added length, dangerous chars, and URI template length checks.
    - **R231-DISC-3 (MEDIUM):** Inference engine unbounded edge generation — added `MAX_INFERRED_EDGES` (50K) cap with labeled break.
    - **R231-DISC-6 (MEDIUM):** Topology diff ignores DataFlow edges — added `added_data_flow_edges`/`removed_data_flow_edges` to `TopologyDiff`.
    - **R231-DISC-7 (MEDIUM):** Server names with `::` separator collision — added `contains("::")` rejection.
    - **R231-A2A-1 (MEDIUM):** Signature cache key missing `exp` claim — added `claims.exp` to cache key for expiration-aware caching.
  - **Sprint 4 — LOWs (4 fixes):**
    - **R231-SRV-8 (LOW):** Signup email `is_control()` too permissive — changed to `is_unsafe_char()`.
    - **R231-SRV-9 (LOW):** `SamlAcsForm` missing `deny_unknown_fields` — added serde attribute.
    - **R231-ENG-6 (LOW):** Workflow template log injection — added `sanitize_for_log()` for `current_tool`.
    - **R231-PROXY-1 (LOW):** Proxy TZ environment variable forwarding — removed TZ from forwarded list, set explicit `UTC`.
  - **8,790 Rust tests passing, 0 failures.**

- **R231 Supplementary — Threat Intelligence + SAML Hardening (21 findings, 49 new tests):**
  Combined adversarial code audit (7 findings) and threat intelligence sweep (14 threats).
  - **TI-2026-001 (P0):** Sharded exfiltration tracker — per-session DLP aggregation.
  - **TI-2026-002 (P0):** Unicode confusable JSON-RPC key smuggling (U+017F, U+212A).
  - **TI-2026-003 (P0):** Log-To-Leak justification-framed injection (6 patterns).
  - **TI-2026-004/005 (P1):** Memory persistence + viral loop patterns (10 patterns).
  - **TI-2026-006 (P1):** Parameter name exfiltration detection (13 blocked names).
  - **TI-2026-007 (P1):** SAML metadata URL SSRF validation.
  - **TI-2026-010 (P2):** MetaBreak FIM special token detection.
  - **R231-SRV-8 (MEDIUM):** SAML ACS error redaction (timestamps, entity IDs, algorithms, certs).
  - **R231-TYP-6 (MEDIUM):** Percent-decode URL host before SSRF checks.
  - **R231-CFG-3 (MEDIUM):** OIDC issuer_url https:// scheme enforcement at config validation.

- **Adversarial Audit Round 230 (53 findings across 6 parallel agents, 19 fixed):**
  Full-codebase adversarial security audit across engine, MCP, server, audit+proxy, types+config, and discovery+A2A+cluster. 53 raw findings (9 HIGH, 27 MEDIUM, 17 LOW), 19 fixed across 3 sprints, remainder triaged as false positives/design limitations.
  - **Sprint 1 — Engine + Discovery + Proxy (5 HIGH + 2 MEDIUM):**
    - **R230-ENG-5 (MEDIUM):** Missing topology pre-filter in `evaluate_action_traced_ctx()` — unknown tools bypassed topology guard via context-aware traced path.
    - **R230-PROXY-1 (HIGH):** Audit chain init failure was warn-only — proxy now refuses to start with broken audit chain (fail-closed).
    - **R230-DISC-1 (HIGH):** `upsert_server()` TOCTOU race condition — now holds write lock for entire read-modify-write cycle.
    - **R230-DISC-2 (HIGH):** `build_server_decl_from_tools_list()` missing validation — added tool count, name length, description length, and input_schema size bounds.
    - **R230-DISC-4 (MEDIUM):** `StaticProbe` unbounded server list — now enforces `MAX_SERVERS` capacity.
    - **R230-DISC-5 (MEDIUM):** Forced guard bypass via crawl failures — retains stale topology instead of clearing on max failures.
    - **R230-DISC-8 (MEDIUM):** Unbounded `input_schema` in StaticToolDecl — 1 MB cap on serialized schema size.
  - **Sprint 2 — Server + MCP (4 HIGH + 3 MEDIUM):**
    - **R230-SRV-2 (HIGH):** SAML assertion replay — added assertion ID deduplication cache with 1-hour TTL and 100K capacity.
    - **R230-SRV-5 (MEDIUM):** M2M JWT secret length was warn-only — now enforces minimum 32 bytes at startup (fail-closed).
    - **R230-SRV-6 (MEDIUM):** OIDC discovery endpoint SSRF — `token_endpoint`, `jwks_uri`, `authorization_endpoint` now validated via `validate_url_no_ssrf()`.
    - **R230-SRV-1 (HIGH):** Topology + discovery endpoints missing from RBAC `endpoint_permission()` — added explicit permission mappings.
    - **R230-SRV-4 (MEDIUM):** Mutating topology endpoints had no audit logging — added `tracing::info` audit events.
    - **R230-SRV-3 (MEDIUM):** Unbounded topology snapshot response — capped at 5,000 nodes with truncation.
    - **R230-SRV-8 (LOW):** Path traversal chars not validated in topology server name — added `..`/`/`/`\` rejection.
  - **Sprint 3 — Types + Engine + MCP (4 MEDIUM + 1 LOW):**
    - **R230-TYP-1 (MEDIUM):** Unicode Variation Selectors U+FE00-U+FE0F missing from `is_unicode_format_char`.
    - **R230-TYP-2 (LOW):** Khmer invisible Cf chars U+17B4-U+17B5 missing from `is_unicode_format_char`.
    - **R230-ENG-1 (MEDIUM):** Legacy conditions size limit (100KB) diverged from compiled path (65KB) — unified to `MAX_CONDITIONS_SIZE`.
    - **R230-MCP-2 (MEDIUM):** ROT13 stop-word bypass — single stop word no longer skips decoding; now requires >30% stop-word density.
    - **R230-TYP-5 (MEDIUM):** Cedar `strip_line_comments` didn't handle backslash-escaped quotes — fixed parser to track escape state.
  - **False positives (34):** R230-DISC-3 (topology guard Bypassed on lock poisoning — defense-in-depth, policy engine evaluates after), R230-ENG-6 (ForbiddenActionSequence truncation — acknowledged design limitation FIND-CREATIVE-004), R230-AUD-3 (ZK circuit chain-linkage only — documented, Merkle root cross-validation), R230-AUD-4 (Pedersen from_bytes_mod_order — theoretical, requires SHA-256 collision), R230-MCP-7 (DPoP verify without crypto — function is unused/dead code), and 29 LOW-severity items triaged as acceptable risk or mitigated by defense-in-depth.
  - **8,681 Rust tests passing, 0 failures.**

### Added

- **Consumer Shield Sprint 1 + License Restructuring (Phase 67):**
  Consumer AI interaction firewall — bidirectional PII sanitization, encrypted local audit, session isolation, and warrant canary verification. Also restructures licensing from monolithic AGPL-3.0 to three tiers.
  - **License restructuring:** MPL-2.0 for 8 core crates (types, engine, audit, canonical, config, discovery, approval, proxy), Apache-2.0 for canary crate, BUSL-1.1 for server/integration/operator (initially AGPL-3.0, subsequently changed to BUSL-1.1). New `LICENSE-MPL-2.0` and `LICENSE-APACHE-2.0` files, `LICENSING.md` rewritten for three-tier model.
  - **`vellaveto-mcp-shield` (NEW, MPL-2.0):** Core shield logic — `QuerySanitizer` (bidirectional PII mapping with `[PII_{CAT}_{SEQ:06}]` placeholders, fail-closed at 50K mappings), `SessionIsolator` (per-session PII isolation with bounded history), `EncryptedAuditStore` (XChaCha20-Poly1305 + Argon2id KDF), `LocalAuditManager` (encrypted audit with Merkle proofs). 24 tests.
  - **`vellaveto-canary` (NEW, Apache-2.0):** Warrant canary — `create_canary()` / `verify_canary()` with Ed25519 signatures, expiration checking, tamper detection. 6 tests.
  - **`vellaveto-http-proxy-shield` (NEW, MPL-2.0):** Stub for Sprint 2+ (traffic padding, request splitting).
  - **`vellaveto-shield` (NEW, MPL-2.0 binary):** Consumer shield binary — CLI with passphrase prompting, encrypted audit, canary verification, supply chain verification, ProxyBridge with shield sanitizer.
  - **Shield config:** `ShieldConfig` added to `PolicyConfig` (11 fields: enabled, audit_mode, sanitize/desanitize toggles, session isolation, Merkle proofs, ZK commitments, custom PII patterns, capacity bounds). 7 config tests.
  - **PiiScanner extension:** `find_matches()` method returning match spans with categories for bidirectional mapping. 3 audit tests.
  - **Feature gate:** `consumer-shield` feature in `vellaveto-mcp` with outbound sanitize and inbound desanitize hooks in ProxyBridge relay.
  - **Preset:** `examples/presets/consumer-shield.toml` template.
  - 40 new tests. **8,747 Rust tests passing, 0 failures, 0 warnings.**

- **Topology Runtime Wiring (TopologyCrawler + RecrawlScheduler):**
  Wire the discovery crate's topology pipeline into the server lifecycle for live topology management.
  - **`StaticProbe`** — In-memory `McpServerProbe` implementation backed by `RwLock<Vec<StaticServerDecl>>`, fed by relay-intercepted `tools/list` responses. Supports `upsert_server()` and `remove_server()` for dynamic updates.
  - **`TopologyGraph::to_static()`** — Round-trip reconstitution of `StaticServerDecl` from graph nodes, enabling incremental merge without full rebuild.
  - **`TopologyGuard::upsert_server()`** — Incremental single-server update (read → merge → rebuild → swap) for live topology updates from relay intercepts.
  - **Relay intercept** — `ProxyBridge` gains `topology_guard` field + `with_topology_guard()` builder. `handle_tools_list_response` now parses MCP `tools/list` JSON and upserts into the guard via `build_server_decl_from_tools_list()` helper.
  - **RecrawlScheduler lifecycle** — `StaticProbe` → `TopologyCrawler` → `RecrawlScheduler` spawned as background task with `CancellationToken` for graceful shutdown on server exit.
  - **REST endpoints** — `GET /api/topology` (snapshot), `GET /api/topology/status` (guard status), `POST /api/topology/recrawl` (trigger immediate re-crawl), `DELETE /api/topology/servers/:name` (remove server + re-crawl).
  - **AppState fields** — `topology_probe` and `recrawl_trigger` added for runtime access.
  - 25 new tests (11 StaticProbe, 5 to_static round-trip, 4 upsert_server, 5 integration). **8,671 Rust tests passing, 0 failures.**

### Security

- **Adversarial Audit Round 230 (10 findings — 4 HIGH, 3 MEDIUM, 1 LOW + 3 threat intel):**
  Full-codebase adversarial audit + threat intelligence sweep. Transport parity gaps in extension/task handlers, signup key persistence, JSON-RPC smuggling defense.
  - **Sprint 1 — 4 HIGH + 1 P0 threat intel:**
    - **R230-RELAY-1 (HIGH):** Extension method handler missing injection scanning — `handle_extension_method` had DLP + memory poisoning but no Aho-Corasick injection scan. Parity with `handle_tool_call`. (`vellaveto-mcp/src/proxy/bridge/relay.rs`)
    - **R230-RELAY-2 (HIGH):** Extension method handler missing circuit breaker — cascading failures not prevented for `x-` extension methods. Added circuit breaker check parity with tool calls.
    - **R230-RELAY-3 (HIGH):** Task request handler missing injection scanning — `handle_task_request` forwarded parameters without injection scan. Added parity with `handle_tool_call`.
    - **R230-SRV-1 (HIGH):** Signup API key generated but hash never persisted — returned key unverifiable for per-tenant auth. Fixed: SHA-256 hash stored in tenant metadata.
    - **TI-2026-002 (P0):** Sampling/createMessage system prompt not scanned for injection — malicious MCP server can inject hidden instructions via `systemPrompt` field. Added full injection pipeline scan on sampling params.
  - **Sprint 2 — 3 MEDIUM + 2 P1 threat intel:**
    - **R230-RELAY-4 (MEDIUM):** Resource read handler missing injection scan on URI.
    - **R230-RELAY-5 (MEDIUM):** Extension method handler missing shadow agent detection.
    - **R230-ENG-1 (MEDIUM):** 2 remaining `as u32` casts in collusion → `u32::try_from().unwrap_or(u32::MAX)`.
    - **R230-SRV-2 (LOW):** Tenant ID 24-bit suffix → 64-bit (collision resistance).
    - **TI-2026-001 (P1):** JSON-RPC key case-folding smuggle defense (CVE-2026-27896) — reject `"Method"`, `"PARAMS"` etc. at framing layer. (`vellaveto-mcp/src/framing.rs`)
    - **TI-2026-004 (P1):** Tool output error message social engineering patterns (CyberArk "Poison Everywhere") — 10 new patterns: `provide contents of`, `try using the`, `provide your api key`, etc.
    - DPoP `htu` case-insensitive scheme matching fix (RFC 3986 §3.1).
  - **Sprint 3 — 2 MEDIUM + 3 LOW:**
    - **R230-ENG-4 (LOW):** Deny reasons leaked internal glob patterns, domain patterns, CIDR ranges, and circuit breaker failure counts/timing to API clients. Genericized all deny messages; details logged server-side at debug level. Covers `rule_check.rs`, `legacy.rs`, `circuit_breaker.rs`.
    - **R230-MCP-1 (MEDIUM):** `InjectionScanner::from_config()` doc comment clarified: documents two reasons for `None` return (all patterns disabled vs. compilation failure). Resolves R228-CFG-1 doc debt.
    - **R230-SRV-5 (LOW):** SAML base64 decoding now padding-indifferent via `DecodePaddingMode::Indifferent`. Handles IdPs that emit unpadded certificates/responses.
    - **R230-SRV-6 (LOW):** Added timestamp precision tests (fractional seconds, timezone variants). Confirmed chrono handles all RFC 3339 variants correctly.
    - **R230-ENG-3 (MEDIUM):** Triaged safe — decision cache not wired into evaluation flow; context-dependent verdicts never cached.
  - **29 new tests total. 8,707 Rust tests passing, 0 failures, 0 warnings.**

- **Adversarial Audit Round 229 (9 adversarial + additional hardening):**
  Full-codebase adversarial security audit with parallel threat intelligence sweep (9 CVEs, Promptware Kill Chain, Parasitic Toolchain research).
  - **Key adversarial findings fixed:**
    - **R229-SRV-1 (HIGH):** JWK thumbprint JSON injection via unescaped format string — attacker-controlled JWK member values (crv, x, y, e, n) interpolated without validation, enabling controlled thumbprint for DPoP token binding bypass. Fixed: reject values containing double quotes or backslashes (`vellaveto-server/src/dpop.rs`).
    - **R229-ENG-1 (HIGH):** Cascading pipeline tracker fail-open on capacity exhaustion — `record_pipeline_event()` returned `Ok(())` at capacity, silently dropping errors. Attacker fills with 10K dummy pipeline IDs then operates undetected. Fixed: returns `Err(ChainDepthExceeded)`.
    - **R229-ENG-2 (HIGH):** Collusion detection systematic fail-open on capacity (5 instances) — all 5 trackers (entropy, resource, timing, recon, drift) returned `Ok(None)` when full. Fixed: returns `CapacityExhaustion` alert with High severity.
    - **R229-SRV-2 (MEDIUM):** DPoP nonce/ath fields missing `has_dangerous_chars()` validation.
    - **R229-SRV-3 (MEDIUM):** DPoP counters `fetch_add` → saturating add per Trap 9.
    - **R229-SRV-4 (MEDIUM):** DpopHeader missing `#[serde(deny_unknown_fields)]`.
    - **R229-ENG-3 (MEDIUM):** Unchecked `usize as u32` cast in collusion — `try_from` with `u32::MAX` fallback.
  - **Additional hardening:** SAML SubjectConfirmation validation (bearer method + Recipient + NotOnOrAfter), SAML decompression bomb prevention, CollusionConfig entropy_threshold bounded at 8.0, CascadingConfig min_window_events bounded at 100K, `to_policies()` calls `Policy::validate()`.
  - **Test fixes:** SAML assertion template updated with SubjectConfirmation element, negative priority Policy::validate() rejection removed (negative priorities are valid).
  - **8,656 Rust tests passing, 0 failures, 0 warnings.**

- **Adversarial Audit Round 228 (11 findings — 1 CRITICAL, 3 HIGH, 4 MEDIUM, 3 LOW):**
  Full-codebase adversarial security audit with parallel threat intelligence sweep. 9 real findings fixed, 2 triaged as documentation-only (LOW).
  - **Sprint 1 — 1 CRITICAL + 3 HIGHs:**
    - **R228-SRV-1 (CRITICAL):** API key auth bypass via RBAC JWT passthrough — any non-empty Authorization header (including `Basic`, `Digest`, plain tokens) bypassed API key validation when RBAC was enabled. Fixed: only pass through when header starts with `Bearer ` prefix (`vellaveto-server/src/routes/main.rs`).
    - **R228-MCP-1 (HIGH):** Base64-encoded injection payloads bypassed Aho-Corasick scanner — LLMs decode base64 inline but the injection scanner only matched plaintext. Added base64 decode pass on whitespace-split tokens in both `InjectionScanner::inspect()` and `inspect_for_injection()`. Uses original text (not lowercased) since base64 is case-sensitive.
    - **R228-MCP-2 (HIGH):** Schema poisoning `detect_poisoning()` used decayed `trust_score` (meaningless after 3 changes) instead of computing actual schema similarity. Fixed: calls `calculate_similarity()` + `detect_changes()` when `schema_content` available (`vellaveto-mcp/src/schema_poisoning.rs`).
    - **R228-INJ-1 (HIGH):** ROT13 decode produced unbounded false positives on English text — any 4+ alpha-char token was decoded. Added stop-word heuristic: text containing common English words ("the", "and", "is", etc.) skips ROT13 decode. Actual ROT13 injection payloads don't contain natural-language stop words.
  - **Sprint 2 — 4 MEDIUMs + 1 LOW:**
    - **R228-DLP-1 (MEDIUM):** URL exfiltration detection only checked http/https schemes. Extended to ftp://, ftps://, and protocol-relative (//) URLs (`vellaveto-mcp/src/inspection/dlp.rs`).
    - **R228-ENG-1 (MEDIUM):** Decision cache key omitted `resolved_ips` — DNS rebinding after initial Allow verdict served stale cached result. Added `resolved_ips_hash` to `CacheKey` (`vellaveto-engine/src/cache.rs`).
    - **R228-MCP-3 (MEDIUM):** Elicitation `title` field not scanned for injection patterns — attacker could inject via title while message scanning caught the same payload. Added title scanning before message scan (`vellaveto-mcp/src/elicitation.rs`).
    - **R228-AUD-1 (MEDIUM):** Mixed UTC timestamp suffixes (Z vs +00:00) broke lexicographic monotonicity verification — `2026-02-27T10:00:00Z` < `2026-02-27T10:00:01+00:00` is true but represents correct ordering. Added `strip_utc_suffix()` normalization (`vellaveto-audit/src/verification.rs`).
    - **R228-PROXY-1 (LOW):** `sampling_per_tool` HashMap grows unbounded with distinct tool names. Added `MAX_SAMPLING_PER_TOOL_ENTRIES` (10,000) capacity bound (`vellaveto-mcp/src/proxy/bridge/relay.rs`).
  - **Clippy fixes:** 3 warnings — `manual_contains` in types/config (loopback check), `needless_borrow` in engine ABAC.
  - **Not actioned (LOW, docs-only):** R228-CFG-1 (InjectionScanner::from_config None ambiguity), R228-SCHEMA-1 (schema hash canonicalization).
  - 38 new tests. **8,646 Rust tests passing, 0 failures, 0 warnings.**

- **Adversarial Audit Round 227 (31 findings — 3 CRITICAL, 9 HIGH, 13 MEDIUM, 6 LOW):**
  Full-codebase adversarial security audit across 6 parallel agents (engine, MCP, server, audit+proxy, types+config, A2A+cluster). 10 real findings fixed across 3 sprints, 21 triaged as false positives.
  - **Sprint 1 — 3 CRITICALs + 2 HIGHs:**
    - **R227-MCP-1 (CRITICAL):** Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF) bypass NFKC normalization. Added `math_alpha_to_latin()` covering 13 font variant blocks (Bold, Italic, Script, Fraktur, Sans-Serif, Monospace, etc.) in injection detection.
    - **R227-AUD-1 (CRITICAL):** PQC field injection in Ed25519 manifest verification. Strips `pqc_signature`, `pqc_verifying_key`, `signature_version` before recomputing Ed25519 digest.
    - **R227-AUD-2 (HIGH):** UTC enforcement in audit timestamp monotonicity. Accepts Z and +00:00 as valid UTC; rejects non-UTC offsets that break lexicographic ordering.
    - **R227-MCP-4 (HIGH):** Scans singular `example` field (JSON Schema draft-07) in elicitation schema defaults.
  - **Sprint 2 — 1 HIGH:**
    - **R227-ENG-1 (HIGH):** Decision cache keys now lowercase tool/function names before hashing, matching engine's case-insensitive evaluation.
  - **Sprint 3 — 1 MEDIUM + 3 LOWs:**
    - **R227-TYP-1 (MEDIUM):** Unified `normalize_full()` (NFKC + lowercase + homoglyph) across policy evaluation, compilation, and pattern matching. Previously the eval path used `normalize_homoglyphs()` only, allowing circled letters (Ⓑ) to bypass primary Deny policies.
    - **R227-SRV-2 (LOW):** Explicit "null" origin rejection in CORS validation (previously implicit via URL parse failure).
    - **R227-CFG-2 (LOW):** RPS/burst config fields capped at MAX_RPS (1,000,000) to prevent u32::MAX misconfiguration.
    - **R227-PROXY-1 (LOW):** Test helper SSE trim now includes NBSP (U+00A0), matching production paths.
  - **Also includes:** ROT13 decode pass for injection detection, per-tool sampling rate limiting, schema drift detection, imperative tool description scanning, discovery engine wiring, UTC suffix normalization.
  - **False positives (21):** R227-SRV-1 (DPoP fail-closed by design), R227-MCP-5 (already uses subtle::ConstantTimeEq), R227-ENG-3 (saturating_add with .min(5)), R227-A2A-1 (cached after verification), R227-A2A-2 (strict issuer binding), R227-TYP-3 (NaN handled at ABAC boundary), R227-AUD-3 (unsigned manifests rejected), R227-ENG-2 (deterministic 3-level tiebreaker), R227-MCP-2 (depth bounded at 8), R227-CFG-1 (async Mutex serializes reload), R227-TYP-2 (param size checked), R227-PROXY-2 (blob in parameters), R227-AUD-4 (cef_escape applied), R227-SRV-3 (bucket selection by design), R227-CLU-1 (no distributed election), R227-MCP-3 (fingerprint side effects only).
  - 32 new tests. **8,540 Rust tests passing, 0 failures.**

- **Adversarial Audit Round 226 (23 findings — 4 CRITICAL, 6 HIGH, 8 MEDIUM, 5 LOW):**
  Full-codebase adversarial security audit across engine, MCP, server, audit, A2A, config, and types crates. 13 real findings fixed, 10 triaged as false positives (already defended).
  - **Sprint 1 — 4 CRITICAL + 3 HIGH:**
    - **R226-AUD-1 (CRITICAL):** PQC rotation manifest signature mismatch — ML-DSA-65 was signing content that already included the Ed25519 signature, causing verification failure. Fixed: unsigned digest computed once before any signatures added (`vellaveto-audit/src/rotation.rs`).
    - **R226-MCP-1 (CRITICAL):** MAX_SCAN_MATCHES bypass — `reversed_matches` appended without cap check, allowing unbounded Vec growth. Fixed: truncate before extend (`vellaveto-mcp/src/inspection/injection.rs`).
    - **R226-A2A-1 (CRITICAL):** Agent Card `name`, `url`, `version`, and `provider.url` fields not scanned for injection — attacker-controlled metadata bypassed content inspection (`vellaveto-mcp/src/a2a/agent_card.rs`).
    - **R226-TYP-1 (CRITICAL):** ISO 8601 parser accepted invalid dates (Feb 31, Apr 31, Feb 29 in non-leap years) enabling credential expiry bypass. Fixed: month-specific day validation with leap year support (`vellaveto-types/src/time_util.rs`).
    - **R226-TYP-2 (HIGH):** 30-day month approximation in epoch calculation caused ~99-day skew by December, enabling time-window policy bypass. Fixed: correct cumulative day-of-year offsets with leap year adjustment.
    - **R226-ENG-1 (HIGH):** Decision cache identity collision — `None` and `Some("")` hashed identically via `unwrap_or("")`. Fixed: hash `Option<String>` discriminant directly (`vellaveto-engine/src/cache.rs`).
    - **R226-MCP-3 (HIGH):** JSON Schema 2020-12 keywords `unevaluatedProperties`, `unevaluatedItems`, `propertyNames`, `contentSchema` not scanned for injection payloads (`vellaveto-mcp/src/inspection/tool_description.rs`).
  - **Sprint 2 — 2 HIGH:**
    - **R226-MCP-4 (HIGH):** Regional indicator emoji smuggling — ZWJ (U+200D), ZWNJ, variation selectors, BOM, and zero-width spaces interleaved between regional indicator codepoints broke Aho-Corasick pattern matching. Fixed: strip invisible characters in `decode_regional_indicators()`.
    - **R226-SRV-5 (HIGH):** SAML `<Conditions>` element missing was silently accepted, allowing assertion replay without NotBefore/NotOnOrAfter enforcement. Fixed: require element presence (fail-closed) (`vellaveto-server/src/iam.rs`).
  - **Sprint 3 — 4 MEDIUM + 2 LOW:**
    - **R226-MCP-2 (MEDIUM):** Leetspeak normalization expanded from 7→14 substitutions (`$→s, !→i, |→l, 8→b, 6→g, 9→g, 2→z`) — covers Analytics Vidhya 36% bypass rate research.
    - **R226-SRV-2 (MEDIUM):** Cross-tenant rate limit collision — rate limit key now includes `X-Tenant-ID` prefix preventing Tenant A's burst from throttling Tenant B.
    - **R226-CROSS-1 (MEDIUM):** Audit chain verification now validates timestamp monotonicity — detects clock tampering and log reordering attacks (`vellaveto-audit/src/verification.rs`).
    - **R226-MCP-8 (LOW):** Tool description DoS — scanning bounded at 64KB per description, 1MB total (`vellaveto-mcp/src/inspection/tool_description.rs`).
    - **R226-ENG-3 (LOW):** Circuit breaker deny reason no longer leaks internal `tool_pattern` to API clients (`vellaveto-engine/src/policy_compile.rs`).
    - **R226-AUD-5 (LOW):** CEF timestamps without timezone indicator get `Z` appended per CEF spec (`vellaveto-audit/src/export/mod.rs`).
  - **False positives (no action):** R226-SRV-1 (setup wizard TOCTOU already fixed by FIND-R101-001), R226-MCP-5 (response body scanning complete), R226-SRV-3 (CORS already case-insensitive), R226-SRV-6 (wizard uses auto-generated API key), R226-CFG-1 (Cedar import already bounded at 10K), R226-CFG-2 (config reload already atomic via ArcSwap), R226-SRV-4 (health cache by design), R226-MCP-9 (schema defaults already scanned), R226-ENG-2 (cache LRU eviction documented), R226-AUD-3 (PQC test alignment only).
  - 6 new tests. **8,508 Rust tests passing, 0 failures.**

- **R226: Threat Intelligence Sweep — 17-Item Security Hardening**
  Comprehensive sweep informed by 50+ new threats (Feb 2026) across MCP vulnerabilities, agentic AI attacks, supply chain compromises, and compliance deadlines.
  - **Sprint 1 (P0 Critical — 6 items):** ML-DSA `use_hint` edge-case verification, MCP-ITP implicit tool poisoning defense (tool descriptions referencing other tools), Policy Puppetry injection detection (`<override>`, `<system_prompt>`, `[SYSTEM]` XML/JSON/INI policy disguise), Google AIza DLP severity upgrade (LOW→HIGH) + Supabase/HuggingFace/W&B patterns, URL-embedded data exfiltration entropy analysis (>4.5 bits/byte threshold), tool namespace collision fail-closed mode (`governance.tool_namespace_strict`).
  - **Sprint 2 (P1 High — 6 items):** Reconnaissance probe detection (>10 distinct policy denials in 60s window flags `ReconnaissanceProbe`), leetspeak normalization (`4→a 3→e 1→i 0→o 7→t 5→s @→a $→s !→i |→l 8→b 6→g 9→g 2→z`), NeighborJack bind-address `0.0.0.0` warning, output poisoning in error.message/error.data (verified covered), WebSocket Origin validation (verified covered), log-to-LLM header sanitization (verified covered).
  - **Sprint 3 (P2 Medium — 5 items):** OWASP MCP Top 10 compliance registry (22 controls mapped across MCP-01 through MCP-10, `vellaveto-audit/src/owasp_mcp.rs`), cross-regulation incident reporting with DORA 24h/72h timelines + NIS2 sector categorization + EU AI Act Art 62 obligations (`vellaveto-audit/src/incident_report.rs`), gradual constraint drift detection (denial-rate shift across configurable windows), SANDWORM rogue tool test patterns (6 integration tests), new DLP patterns (already present).
  - **Additional hardening:** CEF timestamp timezone normalization (append Z for SIEM), audit chain timestamp monotonicity verification, cross-tenant rate-limit key isolation (X-Tenant-ID prefix), circuit-breaker deny reason redaction, tool description DoS size limits (64KB/desc, 1MB total), regional indicator ZWJ injection fix.
  - 274 new tests. **8,502 Rust tests passing, 0 failures.**

- **SANDWORM-P1: Threat Intelligence Hardening (5 P1 defenses)**
  Defenses informed by comprehensive threat intelligence sweep analyzing 100+ attack vectors, 30+ CVEs, and 14 research papers across MCP, A2A, supply chain, injection bypass, and compliance domains.
  - **FlipAttack reversal detection** (`vellaveto-mcp/src/inspection/injection.rs`): Detects character-level and word-level text reversal used to evade pattern matchers (98% ASR in academic research). Both `inspect_for_injection()` and `InjectionScanner::inspect()` now scan reversed text against the full pattern automaton.
  - **Full-Schema Poisoning coverage** (`vellaveto-mcp/src/inspection/tool_description.rs`): `collect_schema_descriptions()` now scans 8 additional JSON Schema keywords hiding injection payloads: `$comment`, `const`, `if/then/else`, `not`, `patternProperties`, `dependentSchemas`, `prefixItems`, `contains`. Achieves parity with elicitation scanner. Addresses CyberArk FSP research.
  - **Emoji smuggling detection** (`vellaveto-mcp/src/inspection/injection.rs`): Decodes regional indicator sequences (U+1F1E6–U+1F1FF) that map to A–Z letters, preventing attackers from spelling injection commands as innocent flag emoji sequences. 100% bypass rate against commercial guardrails without this defense.
  - **Unicode Tag Character stripping verified** (U+E0000–U+E007F): Confirmed coverage in `is_invisible_char()` — all 128 tag characters stripped during sanitization.
  - **A2A Agent Card content injection scanning** (`vellaveto-mcp/src/a2a/agent_card.rs`): New `scan_agent_card_for_injection()` scans LLM-visible Agent Card fields (description, skill descriptions, skill names, tags, examples, provider organization) for injection patterns. Even cryptographically signed cards can carry injection payloads in content fields.
  - **Tool namespace strict mode** (`vellaveto-mcp/src/tool_registry.rs`): `with_namespace_strict()` rejects tool name collisions across different MCP servers outright (Deny) instead of just penalizing trust score. Fail-closed defense against cross-server tool shadowing (Acuvity).
  - 22 new tests. 8,245 Rust tests passing, 0 failures.

- **SANDWORM-001 Hardening & Fail-Closed Integration Tests**
  - 6 integration tests corrected to assert fail-closed behavior for non-boolean `require_approval` values (FIND-IMP-013). Engine correctly uses `as_bool().unwrap_or(true)` — non-boolean types (string, integer, null) now consistently produce `RequireApproval`, not `Allow`.
  - New engine modules: adaptive rate limiting (`adaptive_rate.rs`), coverage analysis (`coverage.rs`), impact analysis (`impact.rs`), policy linting (`lint.rs`), audit analytics (`analytics.rs`), bulk config operations (`bulk.rs`).
  - Hardening across audit (PQC, OCSF, NIST AI 600-1, checkpoints, rotation), engine (cascading circuit breakers, collusion detection, Wasm plugins, cache), MCP (A2A signatures, NHI lifecycle, registry client, relay), server (DPoP, IAM, RBAC, signup, routes).
  - Socket.dev badge added to README. `@clack/prompts` upgraded 0.9.1 → 1.0.1 (removes unmaintained `sisteransi` transitive dep).
  - 8,228 Rust tests passing, zero warnings.

- **SANDWORM-001: Rogue MCP Server Injection Hardening**
  Defends against the SANDWORM_MODE npm supply-chain worm (Feb 2026) that injects malicious MCP servers into AI coding assistant configs.
  - **`governance.require_server_registration`** (`vellaveto-config/src/governance.rs`): New fail-closed enforcement gate — when enabled with a populated `known_servers` list, tool calls from unknown MCP servers are denied. Mirrors `require_agent_registration` for agents.
  - **`ShadowAiDiscovery::should_deny_unknown_server()`** (`vellaveto-mcp/src/shadow_ai_discovery.rs`): Server allowlist enforcement with fail-closed lock poisoning behavior. New `with_server_registration()` constructor.
  - **`ToolEntry.server_id` origin binding** (`vellaveto-mcp/src/tool_registry.rs`): Binds tools to their originating MCP server. Tools seen from multiple servers flagged with `server_id_conflict` and penalized -0.3 in trust score.
  - **`sandworm-hardened.toml` preset** (`examples/presets/sandworm-hardened.toml`): Maximum-security config enabling all 10 defensive layers (supply chain verification, ETDI signatures required, server allowlist, injection blocking, DLP, credential path blocking, git hook protection, default-deny).
  - **Threat model update** (`docs/THREAT_MODEL.md`): Full SANDWORM_MODE attack chain diagram, 10-layer defense mapping table, recommended configuration, residual risk analysis.
  - 15 new tests (8 shadow_ai_discovery + 7 tool_registry). 8,228 Rust tests passing, 0 failures.

- **Adversarial Audit Round 225 (4 findings fixed):**
  - **FIND-038 (P2):** `OidcConfig` custom `Debug` impl redacts `client_secret` — prevents OIDC credential leakage in logs (`vellaveto-config/src/iam.rs`)
  - **FIND-039 (P2):** `ScimConfig` custom `Debug` impl redacts `bearer_token` — prevents SCIM credential leakage in logs (`vellaveto-config/src/iam.rs`)
  - **FIND-040 (P2):** Stdio proxy injection detection on outbound tool call parameters — closes transport parity gap with HTTP/WS/gRPC handlers (`vellaveto-mcp/src/proxy/bridge/relay.rs`)
  - **FIND-041 (P3):** `ExecutionGraphStore::cleanup_expired` fail-closed — graphs without `started_at` timestamps now treated as expired instead of retained indefinitely (`vellaveto-audit/src/exec_graph.rs`)
  - 5 new tests (4 Debug redaction + 1 cleanup fail-closed). 8,213 Rust tests passing.

### Added

- **Topology Discovery (`vellaveto-discovery` crate):** ActionEngine-inspired topology crawling and pre-policy filtering for MCP tool calls. `TopologyGraph` (petgraph DiGraph mapping servers → tools → resources with Owns/DataFlow/Consumes edges, SHA-256 fingerprinting). `TopologyGuard` pre-policy filter with `RwLock<Option<Arc<TopologyGraph>>>` for thread-safe hot-swap; fail-closed unknown tool denial with Levenshtein-based suggestions. `McpCrawler` discovers tools/resources from live MCP servers with configurable timeouts and concurrent crawling. `DataFlowInference` detects implicit data flows between tools via output→input schema overlap (Jaccard similarity with configurable threshold). `TopologyDiff` tracks added/removed/changed tools and resources between topology versions. `RecrawlScheduler` with configurable intervals and error tracking. JSON and bincode serialization with fingerprint consistency. Feature-gated engine integration (`discovery` feature on `vellaveto-engine`): `TopologyGuard` wired as pre-filter in `PolicyEngine.evaluate_action()` — unknown tools denied before policy evaluation, known tools pass through, bypass when no topology loaded. `TopologyConfig` (10 fields: enabled, recrawl_interval, server_timeout, fallback_mode, inference_threshold, etc.) with full validation. 10 integration tests in `vellaveto-integration/tests/topology_pipeline.rs`. ~100 unit tests in `vellaveto-discovery/tests/`. 8,640 Rust tests passing.

- **v6.0 Platform Expansion (Phases 56–66):**
  - **Phase 56: MCP 2025-11-25 Specification Update** — Tasks primitive support (create/get/cancel with policy evaluation), CIMD (Client ID Metadata Documents) for OAuth, URL-mode elicitation for credential acquisition, Cross App Access (XAA) with enterprise IdP tokens, machine-to-machine auth (OAuth client credentials), step-up authorization with required_scopes. `vellaveto-mcp/src/task_state.rs`.
  - **Phase 57: New SDK Integrations** — Anthropic Claude Agent SDK (Python + TypeScript), AWS Strands Agents SDK (Python), Microsoft Agent Framework SDK (Python). Integration via tool permission enforcement callbacks and allowedTools configuration.
  - **Phase 58: Compliance Registry Updates** — Singapore MGF for Agentic AI (`vellaveto-audit/src/singapore_mgf.rs`), NIST AI RMF + AI 600-1 GenAI Profile with 200+ mitigation actions (`vellaveto-audit/src/nist_ai600.rs`), CSA Agentic Trust Framework with progressive autonomy levels (`vellaveto-audit/src/csa_atf.rs`). Total: 11 compliance frameworks.
  - **Phase 59: Observability & SIEM Modernization** — OCSF (Open Cybersecurity Schema Framework) export compatible with AWS Security Lake, Datadog, Splunk (`vellaveto-audit/src/export/ocsf.rs`). OTLP exporter for OpenTelemetry Collector deployments.
  - **Phase 60: Wasm Policy Plugin System** — Wasmtime-based plugin host with WIT interface, fuel metering (5ms budget), memory limits, and hot-reload on policy file change (`vellaveto-engine/src/wasm_plugin.rs`).
  - **Phase 61: Rust Ecosystem Modernization** — Enhanced `cargo-deny` configuration (advisories, licenses with Unicode-DFS-2016, sources). Tokio LTS pinned to 1.42. SBOM generation script (`scripts/generate-sbom.sh`). Rust Edition 2024 migration plan (`docs/RUST_EDITION_2024.md`).
  - **Phase 62: Advanced Security Features** — Multi-agent collusion detection via Shannon entropy, Pearson correlation, and coordinated resource access analysis (`vellaveto-engine/src/collusion.rs`, 36 tests). Cascading failure circuit breakers with chain depth limits, sliding window error rates, and auto-recovery (`vellaveto-engine/src/cascading.rs`, 32 tests). NHI identity lifecycle with ephemeral JIT credentials, rotation enforcement, and identity inventory (`vellaveto-mcp/src/nhi.rs`, 23 tests).
  - **Phase 63: Performance & Data Structure Optimization** — LRU decision cache with TTL and generation-based invalidation (`vellaveto-engine/src/cache.rs`). Batch policy evaluation API.
  - **Phase 64: Cedar Policy Compatibility** — Cedar policy import/export for AWS AgentCore and CNCF Cedar interoperability. Permit/forbid with conditions, entity type mapping (`vellaveto-config/src/cedar.rs`).
  - **Phase 65: A2A Protocol Hardening & MCP Registry** — Agent Card Ed25519 signature enforcement with constant-time comparison (`vellaveto-mcp/src/a2a/signature.rs`, 33 tests). MCP Registry client with TTL-based cache and identity verification (`vellaveto-mcp/src/discovery/registry.rs`, 35 tests). DPoP (RFC 9449) token binding with JWK thumbprint computation and JTI replay detection (`vellaveto-server/src/dpop.rs`, 37 tests).
  - **Phase 66: Formal Verification Expansion** — TLA+ MCPTaskLifecycle model (5 safety + 2 liveness properties for Tasks primitive state machine). TLA+ CascadingFailure model (5 safety + 2 liveness properties for circuit breaker state machine). 5 Kani proof harnesses for fail-closed invariant, path normalization idempotence/safety, saturating arithmetic, and error-produces-deny (`formal/kani/proofs.rs`). Total: 33 TLA+ properties + 3 Lean lemmas + 5 Kani harnesses.

- **`--open` flag for `vellaveto serve`** (`vellaveto-server/src/main.rs`): Auto-launches the admin dashboard in the default browser on server startup. Uses platform-native commands (`xdg-open` on Linux, `open` on macOS, `cmd /c start` on Windows). Non-blocking via `tokio::task::spawn_blocking`; logs a warning if browser launch fails.

- **`npx create-vellaveto` Setup Wizard** (`packages/create-vellaveto/`): Terminal-native, zero-install onboarding wizard that generates all configuration and deployment files before the server starts. 8-step interactive flow (Welcome → Security → Policies → Detection → Audit → Compliance → SDK → Review) powered by `@clack/prompts`. Three policy presets (Strict/Balanced/Permissive) with TOML output matching `setup_wizard.rs` byte-for-byte. Four deployment targets: Docker (hardened `docker-compose.yml` + `.env`), Binary (`setup.sh` download script), Kubernetes (Helm `values.yaml` + ConfigMap), Source (`vellaveto.toml` only). SDK integration snippets for Python, TypeScript, Go, and Java. CLI flags: `--output <dir>`, `--help`, `--version`. 2 runtime dependencies (`@clack/prompts`, `picocolors`). Node 18+.

- **Developer Experience & SDK Ecosystem (Phase 36):**
  - **Java SDK** (`sdk/java/`): Full-parity client (33 API methods matching Go/Python/TypeScript SDKs) targeting Java 11+ with `java.net.http.HttpClient`. Single dependency: Jackson. Builder pattern with URL validation (scheme, userinfo, empty host), timeout clamping [100ms, 300s], CRLF header injection prevention, secret redaction in `toString()`. Retry: 3 retries, jittered exponential backoff on 429/502/503/504. 10MB response body limit. Input validation: control chars, Unicode format chars (soft hyphen, zero-width, bidi, annotation anchors, TAG chars), length bounds on all fields. `Verdict` enum with `@JsonCreator` fail-closed default to DENY. `Action.Builder` with validate(), `EvaluationContext` with validate(), `ParameterRedactor` (38 sensitive key patterns + value pattern detection). Exception hierarchy: `VellavetoException` → `PolicyDeniedException`, `ApprovalRequiredException`. `ValidationUtils` with tenant ID, approval ID, reason, period, format validators. Maven build (`pom.xml`, `--release 11`). 120 JUnit 5 tests.
  - **VS Code Extension** (`vscode-vellaveto/`): TypeScript extension for `.vellaveto.toml` policy files. On-save validation via `POST /api/simulator/validate` with offline fallback (missing `[[policies]]`/`name`/`tool_pattern`, unclosed quotes). `mapDiagnostics()` converts `ValidationFinding[]` to VS Code diagnostics with location parsing (`line N`, `policies[N]`, name-based search). TOML completion provider (8 section completions, 6 field completions, enum value completions for policy_type/on_no_match/on_match/on_missing/op/redaction_level). Simulator webview panel (test actions against loaded policies). 9 snippets: 5 preset templates (dev-laptop, ci-agent, database-agent, browser-agent, rag-agent) + 4 structural (policy, conditional, network, paths). 26 tests (16 validator + 10 diagnostics).
  - **Execution Graph SVG Export:** `ExecutionGraph::to_svg()` renders hierarchical layout directly from node parent/child relationships (no Graphviz dependency). Nodes colored by verdict (`v-allow` green, `v-deny` red, `v-pending` yellow, `v-approval` orange). Curved Bezier edge paths with arrow markers. XSS prevention via `svg_escape()` (HTML entity encoding + bidi character stripping + null byte removal). `svg_truncate()` with Unicode char boundary safety. `GET /api/graphs/{session}/svg` endpoint (`image/svg+xml`). Dashboard "Recent Execution Graphs" section with SVG/DOT export links. 12 new tests.
  - **Roadmap Consolidation:** Merged `ROADMAP.md` + `ROADMAP_ACP.md` into single unified roadmap. PQC renumbered to Phase 54 (resolves conflict with OWASP ASI Phase 41). Performance & Scale merged as Phase 55.

- **Kubernetes Operator (Phase 49):** Standalone `vellaveto-operator` binary crate (`kube-rs 0.98`, `k8s-openapi 0.24`) with three Custom Resource Definitions for declarative, GitOps-friendly management of Vellaveto deployments. `VellavetoCluster` CRD manages StatefulSet/Service/ConfigMap via Kubernetes server-side apply with owner references for garbage collection; supports config overrides (security mode, compliance flags, rate limits), resource requirements, and replica scaling (1-10). `VellavetoPolicy` CRD syncs policies to the Vellaveto server REST API with finalizer-based cleanup on CRD deletion; mirrors `vellaveto-types::Policy` fields (id, name, policyType, priority, pathRules, networkRules) with full JSON Schema validation. `VellavetoTenant` CRD manages tenants with create-or-update semantics and finalizer cleanup; supports quotas and metadata. Typed `VellavetoApiClient` wrapping `reqwest` for all server endpoints (policies CRUD, tenants CRUD, health) with SSRF validation (userinfo rejection, scheme enforcement), 16 MiB response body limit, and path parameter validation. `OperatorError` enum with 8 variants and `From` impls. Shared `Context` with in-cluster DNS URL builder (`{name}.{namespace}.svc.cluster.local:3000`). Three concurrent `kube::runtime::Controller` instances via `tokio::select!` with graceful shutdown on SIGINT. Helm chart extended: 3 CRD YAML manifests with OpenAPI v3 schema validation (including regex patterns and enum constraints), operator Deployment + ServiceAccount + ClusterRole + ClusterRoleBinding templates (gated on `operator.enabled: false` by default). All CRD specs have `validate()` methods enforcing bounds, dangerous character rejection, and type-specific constraints. Fully backward-compatible — no changes to existing crates or APIs. 41 new tests.
- **Compliance Evidence Packs (Phase 48):** Pre-packaged compliance evidence bundles for DORA, NIS2, ISO 42001, and EU AI Act — reducing auditor preparation from weeks to hours. New types in `vellaveto-types`: `EvidenceFramework` (`#[non_exhaustive]`, `rename_all = "lowercase"`, `Display`), `EvidenceConfidence` (None/Low/Medium/High/Full with `Ord`), `EvidenceItem`, `EvidenceSection`, `EvidencePack`, `EvidencePackStatus` — all with `deny_unknown_fields`, `validate()`, and bounded constants (`MAX_EVIDENCE_SECTIONS=100`, `MAX_EVIDENCE_ITEMS_PER_SECTION=200`, `MAX_EVIDENCE_PACK_GAPS=500`, `MAX_EVIDENCE_RECOMMENDATIONS=100`, `MAX_EVIDENCE_STRING_LEN=4096`). `DoraRegistry` in `vellaveto-audit` mapping 27 DORA articles (Art 5–16 ICT risk, Art 17–23 incidents, Art 24–27 testing, Art 28–33 third-party, Art 45 information sharing) to 13 Vellaveto capabilities. `Nis2Registry` mapping 16 NIS2 articles (Art 21.1–21.2.j, Art 22, Art 23.1–23.4) to 12 capabilities. Evidence pack generator converts framework-specific registry reports into unified `EvidencePack` format with per-section coverage percentages, gap detection, and recommendations. HTML renderer with inline CSS, color-coded confidence badges (green/blue/orange/red/gray), print-friendly `@media print` layout, `html_escape()` on all user content. `DoraConfig` and `Nis2Config` in `vellaveto-config` with `enabled` (default false), `organization_name`, `system_id`, `deny_unknown_fields`, `validate()` with `has_dangerous_chars()`. Gap analysis extended from 8 → 10 frameworks. REST API: `GET /api/compliance/evidence-pack/{framework}` (JSON/HTML with format allowlist, per-framework 60s TTL cache, framework path param allowlist: dora/nis2/iso42001/eu-ai-act, config enabled flag check), `GET /api/compliance/evidence-pack/status` (list available frameworks). SDK methods: Python `evidence_pack(framework, export_format)` + `evidence_pack_status()` (sync+async), TypeScript `evidencePack(framework, format?)` + `evidencePackStatus()`, Go `EvidencePack(ctx, framework, format)` + `EvidencePackStatus(ctx)` — all with framework allowlist validation. ~70 new tests (14 types + 27 audit + 11 config + inline module tests).
- **Policy Lifecycle Management (Phase 47):** Versioned policies with approval workflows, staging shadow evaluation, structural diffs, and rollback. New types in `vellaveto-types`: `PolicyVersionStatus` (Draft/Staging/Active/Archived, `#[non_exhaustive]`), `PolicyVersion`, `PolicyApproval`, `PolicyVersionDiff`, `StagingComparisonEntry`, `StagingReport`, `PolicyLifecycleStatus` — all with `deny_unknown_fields`, `validate()`, and bounded constants (`MAX_VERSIONS_PER_POLICY=100`, `MAX_TOTAL_VERSIONS=10_000`, `MAX_APPROVALS_PER_VERSION=50`). `PolicyLifecycleConfig` in `vellaveto-config` with `enabled` (default false, fail-closed), `required_approvals`, `staging_period_secs` (default 3600), SSRF-validated webhook URL, per-policy version limit. `PolicyVersionStore` trait + `InMemoryPolicyVersionStore` in `vellaveto-server` (tokio RwLock, bounded HashMap with `MAX_TRACKED_POLICIES=1000`, monotonic version numbers, oldest-archived pruning). Self-approval prevention via NFKC + Unicode case fold + homoglyph normalization (parity with `vellaveto-approval`). Duplicate approval detection with same normalization pipeline. `staging_period_secs` enforcement with `staged_at` timestamp tracking. 9 REST API endpoints: `GET/POST /api/policies/{id}/versions`, `GET /api/policies/{id}/versions/{v}`, `POST .../approve`, `POST .../promote`, `POST .../archive`, `POST /api/policies/{id}/rollback`, `GET .../diff/{v2}`, `GET /api/policy-lifecycle/status`. Promote-to-Active uses compile-first pattern (pre-compile candidate set, then promote in store, then ArcSwap atomic swap). Staging shadow evaluation: `StagingSnapshot` holds a compiled `PolicyEngine` in `Arc<ArcSwap<Option<StagingSnapshot>>>`, runs non-blocking comparison after active verdict in evaluate handler, logs divergences without affecting hot-path latency or correctness. All handlers require admin tenant, validate path params, bind identity to auth context via `derive_resolver_identity()`. Round 206 hardening: audit events log auth-bound identity (FIND-R206-001), archive handler acquires `policy_write_lock` (FIND-R206-002), legacy add/remove/reload clear staging snapshot (FIND-R206-003), u64::MAX version overflow guard (FIND-R206-004). 49 new tests (21 store + 20 types + 8 config). 7,469 Rust tests passing.
- **Multi-Tenancy Foundation (Phase 44):** Per-tenant policy filtering, rate limiting, audit scoping, quota enforcement, and SDK tenant parameters. Evaluate handler filters policies through `TenantContext.policy_matches()` (default tenant sees all, named tenants see own + global + legacy). `PerTenantRateLimiter` with DashMap + governor token-bucket enforcing `TenantQuotas.max_evaluations_per_minute` (stale cleanup, fail-closed on capacity, quota change detection). `AuditEntry.tenant_id: Option<String>` with backward-compatible serde defaults; PostgreSQL DDL updated to 14 columns (`tenant_id TEXT` + index, `MAX_BATCH_SIZE` adjusted to 4600). `AuditQueryParams.tenant_id` filter in both file and Postgres query backends; route auto-injects tenant_id for non-default tenants. Per-tenant `max_policies` quota enforcement in `add_policy` handler. SDK `tenant` parameter added to Python (sync+async), TypeScript, and Go clients with validation (1–64 chars, `[a-zA-Z0-9_-]`) and `X-Tenant-ID` header. Fully backward-compatible in single-tenant mode.
- **Centralized Audit Store (Phase 43):** Optional dual-write to PostgreSQL alongside the existing JSONL file log, with structured query support. `AuditSink` trait (`sink`, `flush`, `shutdown`, `is_healthy`, `pending_count`) for pluggable external stores. `PostgresAuditSink` with bounded mpsc channel (configurable 1–10K buffer), background tokio task for batch INSERT (configurable batch size/flush interval), exponential backoff retry (max 3 attempts), `ON CONFLICT (id) DO NOTHING` for idempotent inserts, DDL with B-tree indexes on sequence/timestamp/tool/verdict_type, GIN index on metadata JSONB, partial index on deny entries. `AuditQueryService` trait with two backends: `FileAuditQuery` (in-memory filtering on existing `load_entries()`, capped at 500K entries) and `PostgresAuditQuery` (SQL with parameterized queries — never string interpolation — ILIKE text search with wildcard escaping, GIN `@>` for metadata filtering). `AuditStoreConfig` with SSRF validation (rejects localhost/127.x/10.x/172.16–31.x/192.168.x/169.254.x/::1/metadata.google.internal), URL scheme enforcement (`postgres://`/`postgresql://`), SQL identifier validation for `table_name` (alphanumeric + underscore only), `deny_unknown_fields`, custom Debug redacting `database_url`. REST API: `GET /api/audit/search` (paginated with time range/tool/verdict/agent_id/text/sequence filters), `GET /api/audit/store/status` (backend type, enabled, sink health, pending count), `GET /api/audit/entry/{id}` (single entry lookup). Feature-gated behind `postgres-store` (sqlx 0.8). File log remains source of truth; sink failures non-fatal by default (`sink_failure_fatal: false`). ~55 new tests across types, config, audit, and server crates.
- **OWASP Agentic Security Index (Phase 41):** 10-category, 33-control compliance registry mapping ASI01–ASI10 to Vellaveto detection capabilities. `GET /api/compliance/owasp-agentic` endpoint with 60s cache TTL, gated on `OwaspAsiConfig.enabled`. Integrated into gap analysis (8 frameworks), compliance status summary, and dashboard. SDK methods: Python `owasp_asi_coverage()` (sync+async), TypeScript `owaspAsiCoverage()` (typed response), Go `OwaspAsiCoverage()` (with nested types). `OwaspAsiConfig` with `deny_unknown_fields` and `validate()`. `AsiCoverageReport::validate()` with bounds on collections and `f32` range checks.
- **Interactive Setup Wizard** (`/setup`): Web-based 7-step configuration wizard for first-time users (Welcome → Security → Policies → Detection → Audit → Compliance → Review/Apply). Server-side rendered HTML, CSRF protection, bounded session management, TOML config generation with hot-reload. Guard middleware locks wizard after initial setup via `.setup-complete` marker file.
- **Cloudflare Pages deployment** for [vellaveto.online](https://vellaveto.online): `deploy-site.yml` workflow, apex-canonical `_redirects`, `_headers` (security headers), Astro site URL updated from `vellaveto.dev`.

### Fixed

- **`create-vellaveto` TOML field name mismatches (v4.0.3–v4.0.6):** Fixed generated TOML config to match server's `#[serde(deny_unknown_fields)]` struct definitions — `blocking` → `block_on_injection`/`block_on_finding`, `tool`/`function` → `tool_pattern`/`function_pattern`, `blocked_patterns` → `blocked`, removed nonexistent `RequireApproval` policy type, `target` → `webhook_url`, redaction level values `"off"`/`"low"`/`"high"` → `"Off"`/`"KeysOnly"`/`"KeysAndPatterns"`. Same fixes applied to `setup_wizard.rs` web wizard. Affects `packages/create-vellaveto/` and `vellaveto-server/src/setup_wizard.rs`.
- **`create-vellaveto` generated instructions include `--open` flag (v4.0.7):** Binary and Source deployment next-steps now include `--open` so the dashboard auto-launches.

### Refactored

- **Canonical `has_dangerous_chars()` dedup campaign:** Replaced ~100 inline `is_control()`/`is_unicode_format_char()` patterns with canonical `vellaveto_types::has_dangerous_chars()` across ~35 files (vellaveto-types 82, vellaveto-config 71, vellaveto-mcp 7). Removed 4 local helper functions (`a2a_contains_control_chars`, `cluster_contains_control_chars`, `is_valid_id` in shadow_ai_discovery, redundant `c == '\0'` in tool_namespace). All previously control-only checks now also reject Unicode format characters. Updated ~40 test assertions for new error message format.

### Security

#### Round 215 Adversarial Audit (25 findings — 11 P2 + 14 P3)

**P2 — High (11):**
- **ABAC principal ID homoglyph bypass** (`vellaveto-engine/src/abac.rs`): `matches_principal()` matched `ctx.principal_id` against compiled patterns without `normalize_homoglyphs()`, allowing Cyrillic/fullwidth characters to bypass Forbid policies.
- **ABAC principal claims homoglyph bypass** (`vellaveto-engine/src/abac.rs`): JWT claim values matched raw against compiled patterns, allowing homoglyph-crafted claim values to bypass Forbid policies.
- **CapabilityRequired homoglyph bypass** (`vellaveto-engine/src/context_check.rs`, `policy_compile.rs`): Capability names normalized with `to_ascii_lowercase()` only, missing `normalize_homoglyphs()`. Blocked capabilities could be bypassed with Cyrillic homoglyphs.
- **SessionStateRequired homoglyph bypass** (`vellaveto-engine/src/context_check.rs`, `policy_compile.rs`): Same pattern — `to_ascii_lowercase()` without `normalize_homoglyphs()`.
- **ResourceIndicator unsanitized denial reason** (`vellaveto-engine/src/context_check.rs`): Raw JWT `resource` claim value interpolated into denial reason without `sanitize_for_log()`, enabling log injection.
- **Missing audit trail on circuit breaker reset** (`vellaveto-server/src/routes/circuit_breaker.rs`): `POST /api/circuit-breaker/{tool}/reset` had no audit entry.
- **Missing audit trail on auth level upgrade/clear** (`vellaveto-server/src/routes/auth_level.rs`): Auth level mutations unlogged.
- **Missing audit trail on schema lineage trust/removal** (`vellaveto-server/src/routes/schema_lineage.rs`): Trust score changes unlogged.
- **Missing audit trail on delegation register/remove** (`vellaveto-server/src/routes/deputy.rs`): Delegation lifecycle unlogged.
- **Missing audit trail on shadow agent register/trust** (`vellaveto-server/src/routes/shadow_agent.rs`): Agent registration unlogged.
- **Splunk/ES exporter missing config validation** (`vellaveto-audit/src/streaming.rs`): `SplunkExporter::new()` and `ElasticsearchExporter::new()` never called `ExporterConfig::validate()`, accepting `batch_size=0` or `timeout_secs=0`.

**P3 — Low (14):**
- ABAC `compare_numbers()` NaN/Infinity guard via `.is_finite()` — fail-closed on non-finite operands
- ABAC `principal_type` homoglyph normalization added
- `AccountabilityAttestation.did` validation (MAX_DID_LEN=256 + dangerous chars)
- Hex-only validation on `policy_hash`/`signature`/`public_key` fields
- `AbacCondition.field` validation (MAX_FIELD_LEN=256 + empty + dangerous chars)
- `deny_unknown_fields` on `DoraAssessment`, `DoraReport`, `Nis2Assessment`, `Nis2Report`
- `deny_unknown_fields` on `ExecutionNode`, `ExecutionEdge`, `ExecutionGraph`, `GraphMetadata`, `GraphStatistics`
- `ExecutionGraphStore` session_id bounded at MAX_SESSION_ID_LEN=256
- `ExecutionNode.metadata` bounded (MAX_METADATA_ENTRIES=50, key 256, value 4096)
- `DataFlowTracker.records` Vec→VecDeque for O(1) eviction (was O(n²) under capacity)
- `GoalTracker::with_config()` fail-safe defaults on invalid config (was warn-and-proceed)
- WS extension method Allow path strict audit mode enforcement parity
- `remove_shadow_agent` returns 501 Not Implemented instead of misleading 200

#### Round 216 Adversarial Audit (52 findings — 27 P2 + 25 P3)

**P2 — High (27):**
- **ABAC per-entry validation gaps** (`vellaveto-types/src/abac.rs`): PrincipalConstraint `id_patterns`/`claims`, ActionConstraint `patterns`, ResourceConstraint `path_patterns`/`domain_patterns`/`tags`, AbacEntity `parents` lacked per-element length bounds and `has_dangerous_chars()` checks. Added `MAX_PATTERN_LEN=1024`, `MAX_CLAIM_KEY_LEN=256`, `MAX_TAG_LEN=256`, `MAX_PARENT_ID_LEN=256` with per-entry validation.
- **PermissionUsage missing validate()** (`vellaveto-types/src/abac.rs`): No bounds on `permission_id`/`entity_id`/`resource` fields.
- **CapabilityVerification missing deny_unknown_fields** (`vellaveto-types/src/capability.rs`): External deserialization accepted extra fields. Also added `issuer_public_key` Debug redaction.
- **NhiDelegationLink per-entry validation** (`vellaveto-types/src/nhi.rs`): `permissions` and `scope_constraints` vectors lacked per-element length and dangerous char checks.
- **NhiBehavioralBaseline per-entry validation** (`vellaveto-types/src/nhi.rs`): `tool_call_patterns` HashMap keys and `typical_source_ips` lacked per-entry validation.
- **DidPlcGenesisOperation per-entry validation** (`vellaveto-types/src/did_plc.rs`): String entries in `rotation_keys`, `verification_methods`, `also_known_as`, `services` lacked `has_dangerous_chars()`.
- **SyslogConfig missing validate()** (`vellaveto-audit/src/streaming.rs`): No validation on `app_name`, `facility`, `hostname`; missing RFC 5424 SD-ID grammar enforcement.
- **WebhookExporter/DatadogExporter missing config.validate()** (`vellaveto-audit/src/streaming.rs`): Constructor accepted unvalidated config with dangerous chars in string fields.
- **DORA/NIS2 fail-open on empty** (`vellaveto-audit/src/dora.rs`, `nis2.rs`): `calculate_coverage()` returned 100.0% for empty assessment vectors (should fail-closed to 0.0%).
- **DoraReport/Nis2Report/GapAnalysisReport missing validate()** (`vellaveto-audit/src/*.rs`): No bounds on report struct fields.
- **Config injection extra/disabled patterns** (`vellaveto-config/src/config_validate.rs`): `has_dangerous_chars()` missing on `extra_patterns`, `disabled_patterns`, sampling `allowed_models`, custom PII patterns, DLP `extra_patterns`.
- **Shadow agent fingerprint validation** (`vellaveto-config/src/config_validate.rs`): Fingerprint component validation was inside `enabled` guard — bypassed when detection disabled.
- **AuditConfig/RateLimitConfig missing validate()** (`vellaveto-config/src/detection.rs`): Zero-RPS rejection missing; `MultimodalPolicyConfig` lacked per-entry validation.
- **TlsConfig/SpiffeConfig/OpaConfig dangerous chars** (`vellaveto-config/src/enterprise.rs`): TLS path fields, SPIFFE `id_to_role` values, OPA `bundle_path` missing `has_dangerous_chars()`.
- **CrossAgentConfig trusted_agents** (`vellaveto-config/src/threat_detection.rs`): Per-entry validation missing on `trusted_agents` strings.
- **Operator CRD missing DNS label validation** (`vellaveto-operator/src/crd.rs`): `validate_k8s_name()` accepted non-DNS-label characters.
- **Operator CRD missing deny_unknown_fields** (`vellaveto-operator/src/crd.rs`): 8 spec structs accepted unknown fields.
- **Operator ResourceRequirements/TenantQuotasSpec missing validate()** (`vellaveto-operator/src/crd.rs`).
- **Operator delete-then-add race** (`vellaveto-operator/src/reconciler/policy.rs`): Policy reconciler deleted then re-added instead of direct upsert.
- **Operator client redirect following** (`vellaveto-operator/src/client.rs`): Reqwest followed redirects by default, enabling SSRF.

**P3 — Low (25):**
- `deny_unknown_fields` on 6 trace/explanation structs in `core.rs`
- `DiscoveryResult::validate()` added (MAX_TOOLS=10000, query bounds)
- `EvidencePackStatus::validate()` added
- `TaskResumeResult`/`TaskIntegrityResult`/`SecureTaskStats` validate() added
- `AttestationVerificationResult::validate()` added
- `NhiBehavioralDeviation::validate()` added
- `GapAnalysisReport` deny_unknown_fields on 3 structs
- Streaming exporter string fields `has_dangerous_chars()` parity
- Data flow zero-value rejection for tracking configuration
- Operator `Condition::new()` truncation for Kubernetes status conditions
- Operator per-element path/network rule validation in CRD specs
- Operator conditions serialization fail-closed
- Operator image whitespace validation
- Operator `validate_path_param` Unicode format char check

#### Round 224 Adversarial Audit (3 findings — 1 P1 + 2 P2)

**P1 — Critical:**
- **Approval expiry persist rollback** (`vellaveto-approval/src/lib.rs`): When `persist_approval()` failed during expiry handling in `approve()`/`deny()`, in-memory state was set to Expired but the on-disk record remained Pending. On restart, the stale Pending record was reloaded and the removed dedup key allowed a duplicate approval. Added rollback of in-memory state and dedup index restoration on persist failure.

**P2 — High:**
- **DnsServiceDiscovery refresh_interval busy-loop** (`vellaveto-cluster/src/discovery_dns.rs`): Zero or sub-second `refresh_interval` caused the `watch()` loop to spin, saturating CPU and flooding the DNS resolver. Added `MIN_REFRESH_INTERVAL=1s` and `MAX_REFRESH_INTERVAL=86400s` bounds.
- **StaticServiceDiscovery endpoint validation** (`vellaveto-cluster/src/discovery_static.rs`): Constructor accepted endpoints with control characters in `id`/`url` or excessively long labels without validation. Added per-endpoint `validate()` at construction time.

#### Round 222 Adversarial Audit (4 findings — 1 P1 + 3 P2)

**P1 — Critical:**
- **HTTP proxy missing injection scanning on task/extension parameters** (`vellaveto-http-proxy/src/proxy/handlers.rs`): Task request parameters and extension method parameters bypassed injection detection that was present in PassThrough and gRPC handlers. Added full scanning parity.

**P2 — High:**
- **SessionState.pending_tool_calls pub visibility** (`vellaveto-http-proxy/src/session.rs`): `pub` field allowed direct push bypassing bounded insertion checks. Changed to `pub(crate)`.
- **SessionState.action_history pub visibility** (`vellaveto-http-proxy/src/session.rs`): Same pattern — direct push bypassed bounded insertion. Changed to `pub(crate)`.
- **WitnessStore::restore() unbounded growth** (`vellaveto-audit/src/zk/witness.rs`): Persistent prover failure caused restore to accumulate witnesses beyond capacity cap. Now enforces capacity bound on restore.

#### Round 130 WS+gRPC Injection Scanning Parity (4 findings — 1 P1 + 3 P2)

- **FIND-R130-001 (P1):** WS PassThrough arm missing injection scanning — injection payloads in `prompts/get`, `completion/complete` passed undetected while HTTP and gRPC both had the check. Added `extract_strings_recursive` + `inspect_for_injection` scanning.
- **FIND-R130-003 (P2):** WS+gRPC upstream `tools/list` missing tool-description injection scanning — malicious MCP servers could embed injection in tool descriptions. Added `scan_tool_descriptions()` to both handlers.
- **FIND-R130-004 (P2):** WS `extract_scannable_text()` had reduced scan coverage vs HTTP — missing `resource.blob` (base64), `annotations`, `_meta`. Rewritten to delegate to shared `inspection::extract_text_from_result()`.

#### Round 82 Adversarial Audit (9 findings — 4 P2 + 5 P3)

**P2 — High:**
- **UTF-8 truncation panic in `SchemaRecord::push_version()`** (`vellaveto-types/src/threat.rs`): Byte-slice `hash[..MAX_HASH_LEN]` panicked on multi-byte UTF-8 character boundaries. Fixed with `is_char_boundary()` guard.
- **UTF-8 truncation panic in `SamplingStats::reset_window()`** (`vellaveto-types/src/threat.rs`): `String::truncate(MAX_PATTERN_ENTRY_LEN)` panicked on multi-byte boundaries. Fixed with char boundary search.
- **`owasp_asi.enabled` config flag was no-op** (`vellaveto-server/src/routes/compliance.rs`): `GET /api/compliance/owasp-agentic` and `compliance_status()` ignored the config flag. Now gates on `OwaspAsiConfig.enabled`, matching other compliance endpoints.
- **Python SDK `soc2_access_review()` missing period validation** (`sdk/python/vellaveto/client.py`): Added max length (32), character set (`[a-zA-Z0-9\-:]`), and non-empty checks matching TS SDK.

**P3 — Low:**
- Added `deny_unknown_fields` to `AsiControl`, `CategoryCoverage`, `AsiCoverageReport`, `ControlMatrixRow`
- Added `AsiCoverageReport::validate()` with bounds on collections and `f32` range checks
- TypeScript SDK: typed `OwaspAsiCoverageResponse` interface replacing `Record<string, unknown>`
- Go SDK: `AsiCategoryCoverage`, `AsiControlMatrixRow` nested types for full report access

#### Round 58 Adversarial Audit (78 findings — 3 P1 + 24 P2 + 18 P3 + 11 P4)

**P1 — Critical:**
- **Redis self-approval homoglyph bypass** (`vellaveto-cluster/src/redis_backend.rs`): `approval_approve()` applied NFKC + case folding but NOT `normalize_homoglyphs()`. Cyrillic homoglyphs (e.g., U+0430 for Latin 'a') bypassed the self-approval check, allowing an attacker to approve their own request when the Redis backend was used.
- **Redis self-denial prevention absent** (`vellaveto-cluster/src/redis_backend.rs`): `approval_deny()` had NO self-denial check at all, breaking the separation-of-privilege contract that the local `ApprovalStore` enforces.
- **TypeScript SDK `Action` missing `resolved_ips`** (`sdk/typescript/src/types.ts`): SDK parity gap — Python and Go SDKs included `resolved_ips` but TypeScript did not, preventing DNS rebinding defense for TS clients.

**P2 — High:**
- Engine: `from_snapshot()` unbounded agents/tools OOM, `validate_regex_safety` negative paren_depth bypass
- MCP: `session_baselines`/`session_contexts` unbounded HashMaps capped (MAX 100K), `DataFlowConfig` deny_unknown_fields + upper bounds, `request_count`/`sample_count`/`total_tokens` saturating_add (4 counters), division-by-zero guard in `detect_homoglyph_stego`
- Config: `deny_unknown_fields` on ~28 config structs (A2A, cluster, 6 observability, 5 memory/NHI, 10 threat-detection, tool registry), `A2aConfig`/`ClusterConfig` validate() with bounds
- SDK: Go retry with exponential backoff on 429/502/503/504

**P3 — Medium:**
- Config: `MemorySecurityConfig`/`ToolRegistryConfig`/`GoalTrackerConfig`/`TokenSecurityConfig`/`OutputSecurityConfig` validate() with float threshold validation (NaN/Infinity/range), `BehavioralDetectionConfig`/`SemanticDetectionConfig`/`SchemaPoisoningConfig`/`CrossAgentConfig` validate(), `ObservabilityConfig` sample_rate NaN check
- Engine: unclosed parentheses detection, circuit_breaker/traced counters saturating_add, ABAC Forbid early return, RwLock recovery documentation, case-sensitivity contract documentation
- MCP: GoalTracker post-cleanup capacity re-check, budget==0 fail-closed guard
- Server: Tenant validate() with RFC 3339 timestamps + control chars + metadata bounds, JIT control char validation, OPA context 1MB limit
- SDK: TypeScript retry with exponential backoff (parity with Python)

**P4 — Low:**
- MCP: Homoglyph detection OnceLock+HashSet for O(1) lookup, export.rs error JSON on serialization failure, SteganographyAlert confidence invariant documented, GoalFingerprint hash type documented
- Server: ThreatIndicator tags bounded (MAX 50), TelemetryConfig validate() wired, validate_origin comment corrected, IdempotencyStore eviction documented
- Config: Compliance structs PartialEq derive, MultimodalPolicyConfig ocr_confidence wired to PolicyConfig validate()
- Engine: thundering herd comment on cache.clear(), time window/circuit breaker no-op already correct

#### 2026-02-19 Hardening Follow-up

- **Config loading fail-closed**: `PolicyConfig::load_file` now rejects empty/whitespace-only files and accepts only `.toml` and `.json` config extensions.
- **Config validation coverage expanded**: Added and tightened bounds/control-character checks for A2A, cluster, memory security, semantic templates, cross-agent trusted agents, and schema-poisoning observation thresholds.
- **Sandbox-safe integration tests**: Local socket bind failures with `PermissionDenied` now trigger targeted test-path skips in restricted environments, while unexpected bind errors still fail tests.
- **Webhook safety posture**: Billing webhook endpoints acknowledge probe events only; business events are validated but return `received=false` until billing state synchronization is implemented (fail-closed).
- **Gateway/mcpsec robustness**: Gateway health-check fallback and mcpsec report/output paths now return explicit errors instead of panic-based failure behavior.

#### Round 57 Adversarial Audit (100 P4, ~84 fixed)

- **Code deduplication**: `glob_match`/`glob_match_bytes` extracted into shared `vellaveto-mcp/src/util.rs` from 4 duplicate copies (transparency, extension_registry, capability_token, nl_policy); `html_escape` deduplicated — `dashboard::html_escape` made `pub(crate)`, setup_wizard delegates; `FORWARDED_HEADERS`/`MAX_RESPONSE_BODY_BYTES` centralized in `proxy/mod.rs`; `validate_path_param_core` extracted in routes
- **thiserror migration**: `AttestationError`, `NamespaceError`, `SamplingDenied` migrated from manual `Display`+`Error` impls to `#[derive(thiserror::Error)]`
- **deny_unknown_fields**: Added to ~25 config structs — `GatewayConfig`/`BackendConfig`/`FipsConfig` + 8 detection + 5 enterprise + 4 ETDI structs
- **New validate() methods**: `ZkBatchProof`, `ZkVerifyResult`, `ZkSchedulerStatus`, `DeploymentInfo`, `ServiceEndpoint`, `NhiStats`, `NhiCredentialRotation`, `ToolAttestation`, `FipsConfig` (wired into `PolicyConfig::validate()`)
- **Method normalization**: `validate_finite()` → `validate()` on `UnregisteredAgent`, `ShadowAiReport`, `NhiBehavioralBaseline`, `NhiBehavioralCheckResult`, `DiscoveredTool` with `#[deprecated]` aliases for backward compatibility
- **Named constants**: `MAX_SIGNATURE_ID_LEN=256`, `MAX_SIGNATURE_LEN=512`, `MAX_PUBLIC_KEY_LEN=512`, `MAX_ANALYSIS_CACHE_SIZE=10_000`, `SUSPICION_SATURATION_COUNT=10.0`, `TRUST_DECAY_FACTOR=0.5`, `CAPACITY_EXCEEDED_RETRY_SECS=60`, `MAX_FORM_FIELDS=100`
- **Deprecations**: `check_auto_revoke` deprecated in favor of `revoke_stale_permissions()`; server call site updated
- **Safety**: Custom `Debug` on `EscalationDetector` redacting analysis cache; `saturating_add` on suspicious pair counter; `Display` for `InjectionAlert`; `.map_err(AuditError::Io)` idiomatic conversion
- **Derive additions**: `PartialEq`+`Eq` on `FipsConfig`, `GrpcTransportConfig`, `LimitsConfig`; `Eq` on `LimitsConfig`
- **Visibility tightening**: `MAX_CONDITIONS_SIZE` made private; `html_escape` `pub(crate)` in dashboard/access_review; `SdkCapabilities::MAX_CAPABILITIES`/`MAX_VERSIONS` made `pub`; `MAX_BACKEND_ID_LEN`/`MAX_TOOL_PREFIX_LEN` made `pub`
- **Removed dead code**: Placeholder `"2026-06"` protocol version removed from `SUPPORTED_PROTOCOL_VERSIONS` (+ 3 test files updated); unused `grpc_requests_count()` removed; `#[allow(dead_code)]` on `MCP_TRANSPORT_PREFERENCE_HEADER` removed
- **SDK fixes**: Python `format` → `export_format` parameter in `soc2_access_review`; async client docstrings; TypeScript format validation in `soc2AccessReview`; Go `EvaluateOrError` doc comment
- **Documentation**: Comprehensive doc comments on `Action`, `Verdict`, `Policy`, `PolicyType`, `McpServer` struct + all handler methods, `ToolSignature` fields, `PermissionTracker` fields, `TransportCircuitStats` fields, `AgentAccumulator` fields, `VersionDriftAlert` fields, `NhiBehavioralDeviation`, `MemorySecurityStats` fields, `NamespaceSharingRequest.approved` tri-state, `TransportAttempt.error`, `projector.rs` module, `routes/mod.rs` module (27 submodules), `is_loopback_addr`, `LimitsConfig` TOML example (all 11 fields)
- **Config improvements**: `FipsConfig::validate()` checking `signature_algorithm`; `GatewayConfig`/`GrpcTransportConfig` doc comments explaining validation patterns; `LimitsConfig` TOML example updated
- **Timestamp parsing dedup**: New `vellaveto-types/src/time_util.rs` module with shared `parse_iso8601_secs()`, replacing duplicated ISO 8601 parsing in `minja.rs` (11 new tests)
- **Rate limiter dedup**: Extracted `governor_check_to_retry_after()` in `vellaveto-server/src/lib.rs`, eliminating ~20 lines of duplicated match arms across `PerIpRateLimiter` and `PerKeyRateLimiter`
- **Naming fixes**: `_trace` → `trace` in evaluation.rs; `_path` → `path` in setup_wizard; log_trace helper extracted; stale comments updated in schema_poisoning; consistent tracing target

#### Round 56 Adversarial Audit (91 P3, ~72 fixed)

- **deny_unknown_fields** added to 20+ config structs: `DiscoveryConfig`, `ProjectorConfig`, `ZkAuditConfig`, `AbacConfig`, `LeastAgencyConfig`, `FederationConfig`, `ContinuousAuthConfig`, 6 compliance structs, `LimitsConfig`, `TransportConfig`, `MultimodalConfig`
- **Custom Debug impls** redacting secrets on 6 types: `AgentFingerprint` (jwt_sub/jwt_iss/client_id), `SessionGuardConfig` (admin_unlock_token), `SessionEvent` (admin_token), `FederationResolver`, `BillingState`, `WizardSession` (api_key/csrf_token)
- **Code deduplication**: `is_unicode_format_char` single source in `core.rs` (removed from EvaluationContext), `derive_resolver_identity` single source, `default_true()` deduplicated in governance config
- **Constant extraction**: `MAX_CONDITIONS_SIZE=65536`, `MAX_TIMESTAMP_LEN=64`, `MAX_CALL_CHAIN_FIELD_LEN=512`, `MAX_REQUEST_BODY_SIZE=1048576`, `MAX_SESSION_ID_LENGTH=128`, `THRESHOLD_OPTIMAL=0.8`/`THRESHOLD_REVIEW=0.5`/`THRESHOLD_NARROW=0.2`, `DEFAULT_AUTO_REVOKE_SECS=3600`
- **Bounds enforcement**: `MAX_DLP_FINDINGS=1000` cap in DLP scanner, `MAX_SESSIONS=100000` in sampling detector, `MultimodalConfig.validate()` with min_ocr_confidence [0.0,1.0] range
- **Safety improvements**: Safe `u128→u64` conversions in red_team (4) and multimodal (3) via `u64::try_from().unwrap_or(u64::MAX)`, `saturating_add` on tool_namespace access_count
- **API correctness**: `#[must_use]` on `evaluate_action`/`evaluate_action_with_context`/`evaluate_action_traced_with_context`, `#[non_exhaustive]` on `AbacDecision`, `pub(crate)` tightening on `TrustedProxyContext.from_trusted_proxy`
- **Validation**: `GrpcTransportConfig.validate()` with `MAX_GRPC_MESSAGE_SIZE=256MB`, `validate_path_param()` in governance routes, `previous_actions` format char check, federation failure events use `Verdict::Deny`
- **OWASP**: `html_escape` now escapes `/` to `&#x2F;`, CORS `allow_methods` includes PUT
- **SDK alignment**: Default timeout aligned to 10s across Python/TypeScript/Go, Python approval ID validation aligned (non-empty + max 256 + no control chars), `AsyncVellavetoClient.__repr__`, Go `Client.String()`
- **Documentation**: Security doc comments on `Action.resolved_ips`, `EntityStore`, `compute_risk_score()`, `McpServer` fields, `AgentAccumulator`, `MAX_JSON_DEPTH`, cluster/approval types

#### Round 55 Adversarial Audit

- SDK input validation hardening (Go `ProjectSchema` modelFamily, Python/TypeScript parity)
- gRPC transport parity fixes for injection/DLP/behavioral detection
- RAG defense config validation with bounds
- Least-agency tracker bounds enforcement
- Injection detection improvements
- Route handler hardening across server endpoints

#### Round 53 Adversarial Audit (2 P0, 8 P1)

- **FIND-R53-P0-1 (P0):** `constant_time_eq` in licensing HMAC verification vulnerable to compiler optimization — `std::hint::black_box` added to accumulator preventing LLVM early-exit optimization
- **FIND-R53-P0-2 (P0):** `tier_override` silently bypasses license key validation — now logs at `warn!` level with explicit bypass message
- **FIND-R53-P1-1 (P1):** `LicensingConfig` `derive(Debug)` leaks `license_key` — custom Debug impl redacts to `[REDACTED]`
- **FIND-R53-P1-2 (P1):** `SystemTime` failure in license expiry sets `now=0` (fail-open: all keys appear valid) — changed to `u64::MAX` (fail-closed: expired)
- **FIND-R53-P1-3 (P1):** `generate_license_key` exposed as `pub` in non-test builds — restricted to `#[cfg(test)]`
- **FIND-R53-P1-4 (P1):** Webhook signature timestamp replay attack — added 300s tolerance window for both Paddle and Stripe
- **FIND-R53-P1-5 (P1):** Billing webhook routes missing rate limiting — rate limiter applied to `/api/billing/paddle/webhook` and `/api/billing/stripe/webhook`
- **FIND-R53-P1-6 (P1):** `BillingConfig::validate()` and `LicensingConfig::validate()` not wired into `PolicyConfig::validate()` — both now called during config load
- **FIND-R53-P1-7 (P1):** Landing page missing Content-Security-Policy meta tag — CSP added to Base.astro
- **FIND-R53-P1-8 (P1):** Email addresses in site HTML not entity-encoded — HTML entity encoding across 3 site files
- Also: `#[serde(deny_unknown_fields)]` added to `BillingConfig`, `PaddleConfig`, `StripeConfig`, `LicensingConfig`, `TierLimits`
- Also: `LicensingConfig::validate()` added with license_key length bound (256) and control character rejection (C0/C1/DEL)
- Also: 9 new edge case tests for licensing validation (null bytes, newlines, tabs, C1 control chars, oversized keys, deny_unknown_fields)

#### Round 52 Adversarial Audit (8 P1, 18 P2, 11 P3)

- **FIND-R52-001 (P1):** `EvaluationContext.previous_actions` missing control character validation — allows ForbiddenActionSequence bypass via null byte injection (`"read_secret\x00"` does not match compiled `"read_secret"`)
- **FIND-R52-002 (P1):** `ToolSignature` `derive(Debug)` leaks `signature` and `public_key` fields — custom Debug impl now redacts both
- **FIND-R52-003 (P1):** WebSocket proxy missing outbound DLP parameter scanning (`scan_parameters_for_secrets`) — security parity with HTTP handler restored
- **FIND-R52-004 (P1):** WebSocket proxy missing memory poisoning detection (`memory_tracker.check_parameters`) — OWASP ASI06 parity with HTTP handler restored
- **FIND-R52-005 (P1):** WebSocket sessions never validate OAuth token expiry after upgrade — per-message token expiry check added with close code 1008
- **FIND-R52-006 (P1):** SessionState bounded fields remain `pub` with bypass in `helpers.rs` — 5 fields changed to `pub(crate)`, read-only accessors added, `helpers.rs` uses bounded `insert_known_tool`
- **FIND-R52-007 (P1):** Audit sequence counter `Ordering::Relaxed` race with `initialize_chain` — all `entry_count` operations upgraded to `Ordering::SeqCst`
- **FIND-R52-008 (P1):** Shadow AI discovery `known_servers` lock poisoning fail-open — changed `unwrap_or(false)` to `unwrap_or(true)` for fail-closed
- **FIND-R52-009 (P2):** `NhiBehavioralDeviation.severity` not range-validated to [0.0, 1.0] + deviations Vec unbounded — added range check and MAX_DEVIATIONS=256
- **FIND-R52-010 (P2):** `RiskFactor.weight`/`value` not range-validated — added [0.0, 1.0] range checks
- **FIND-R52-011 (P2):** `RiskScore.factors` Vec unbounded — added MAX_FACTORS=256
- **FIND-R52-012 (P2):** `StatelessContextBlob.signature` accepts mixed-case hex — now requires lowercase for canonical representation
- **FIND-R52-013 (P2):** `call_chain` validation misses Unicode format chars (zero-width, bidi overrides, BOM) — extended with `is_unicode_format_char()` check
- **FIND-R52-014 (P2):** `EvaluationContext.call_counts` key lengths unbounded — added MAX_ACTION_NAME_LEN check per key
- **FIND-R52-015 (P2):** `StatelessContextBlob` `call_counts` keys and `recent_actions` entries unbounded — added per-entry 256-byte length checks
- **FIND-R52-016 (P2):** `ToolSignature.validate()` only checks `rekor_entry` — added bounds for all 7 string fields (signature_id 256, signature 512, public_key 512, signed_at 64, expires_at 64, key_fingerprint 256, signer_spiffe_id 2048)
- **FIND-R52-017 (P2):** C1 control chars (0x80-0x9F) missing from `FederationConfig.expected_audience`, `GovernanceConfig`, and transport config — extended all checks to `(0x7F..=0x9F).contains(&b)`
- **FIND-R52-018 (P2):** Merkle proof `siblings` count unbounded — added MAX_PROOF_DEPTH=64
- **FIND-R52-019 (P2):** Archive `compress_rotated_file` reads entire file without size check — added MAX_ARCHIVE_FILE_SIZE=512MB metadata check
- **FIND-R52-020 (P2):** Access review `usage_ratio` NaN/Infinity in HTML render — added `is_finite()` guard
- **FIND-R52-021 (P2):** Per-agent `session_ids`/`tools_accessed`/`functions_called` unbounded — added MAX_PER_AGENT_SET_SIZE=10,000
- **FIND-R52-022 (P2):** A2A `process_response()` unbounded response clone — added MAX_A2A_RESPONSE_SIZE=16MB
- **FIND-R52-023 (P2):** Missing audit log for allowed (Forward) tool calls and resource reads — added audit entries in Forward branch
- **FIND-R52-024 (P2):** Relay `handle_passthrough` orphans `pending_requests` on DLP/injection block — added cleanup in block paths
- **FIND-R52-025 (P2):** Semantic guardrails intent chain has no eviction — replaced silent skip with LRU-style eviction
- **FIND-R52-026 (P3):** `CapabilityToken` `expires_at` == `issued_at` boundary semantics unclear — documented case-insensitivity design choice
- Plus 10 additional P3 findings (JIT saturating_add, ISO 8601 month-day, Kahn debug_assert, successor dedup warning, async SSL warning, NhiBehavioralBaseline negatives, is_valid_iso8601_basic unwrap_or style, AccountabilityAttestation/TaskCheckpoint Debug leak, various validate() additions)

#### Round 51 Adversarial Audit (2 P1, 14 P2, 11 P3)

- **FIND-R51-001 (P1):** Float scores (`trust_score`, `risk_score`, `anomaly_score`, `confidence`, `relevance_score`) now range-validated to `[0.0, 1.0]` in all `validate()`/`validate_finite()` methods across 6 types files — negative values could bypass threshold checks in continuous authorization
- **FIND-R51-002 (P1):** `ToolSignature.is_expired()` validates ISO 8601 timestamp format (length 20, digit ranges for month/day/hour/minute/second) before lexicographic comparison — malformed timestamps like `"9999-99-99T99:99:99Z"` fail-closed (treated as expired)
- **FIND-R51-001 (P2, http-proxy):** `backend_sessions` and `gateway_tools` HashMaps in `SessionState` bounded at 128 entries each with per-backend tool cap of 1000
- **FIND-R51-002 (P2, http-proxy):** `abac_granted_policies` Vec bounded at 1024 with deduplication
- **FIND-R51-003 (P2, SDK):** Python `AsyncVellavetoClient._request()` now has retry logic with exponential backoff matching sync client (transient 502/503/504)
- **FIND-R51-005 (P2, types):** `EvaluationContext.validate()` now validates `call_chain` entry contents for control characters, null bytes, and excessive length
- **FIND-R51-007 (P2, types):** `StatelessContextBlob.signature` validated for format (64 hex chars for HMAC-SHA256)
- **FIND-R51-007 (P2, http-proxy):** `request_count` uses `saturating_add` for debug-build safety
- **FIND-R51-008 (P2, types):** `CapabilityToken` validates `expires_at > issued_at` temporal ordering
- **FIND-R51-009 (P2, types):** `NhiDelegationLink` rejects self-delegation (`from_agent == to_agent`)
- **FIND-R51-010 (P2, config):** `expected_audience` in `FederationConfig` bounded at 512 chars with control character rejection
- **FIND-R51-011 (P2, http-proxy):** Origin validation logs security warning when wildcard `"*"` is in `allowed_origins`
- **FIND-R51-014 (P2, http-proxy):** `flagged_tools` HashSet bounded at 2048
- **FIND-R51-015 (P2, config):** Governance `approved_tools`, `known_servers`, `registered_agents` reject control characters
- **FIND-R51-005 (P3, SDK):** Python `Content-Length` parsing handles malformed values via try/except
- **FIND-R51-008 (P3, http-proxy):** `elicitation_count` uses `saturating_add` for consistency
- **FIND-R51-011 (P3, types):** `UpstreamBackend.validate()` rejects SSRF vectors (localhost, private IPs)
- **FIND-R51-012 (P3, types):** `NhiDelegationLink` validates `expires_at > created_at` temporal ordering
- **FIND-R51-012 (P3, http-proxy):** `known_tools` HashMap bounded at 2048
- **FIND-R51-013 (P3, types):** `ExtensionDescriptor` capabilities vector bounded at 64 entries, 256 bytes each
- **FIND-R51-013 (P3, server):** `tenant.rs` no longer leaks tenant ID in 404 error responses
- **FIND-R51-014 (P3, types):** `ProvenanceNode` string fields bounded (`id` 256, `source` 2048, `content_hash` 512)
- **FIND-R51-015 (P3, types):** `ToolMetadata.input_schema` bounded at 64KB serialized
- **FIND-R51-015 (P3, server):** `JitAccessManager` global session cap at 100K
- **FIND-R51-016 (P3, types):** `CanonicalToolSchema`/`CanonicalToolCall`/`CanonicalToolResponse` `validate()` methods with 64KB size bounds
- **FIND-R51-016 (P3, server):** `JitRequest` fields bounded (`principal` 256, `reason` 1024, `permissions`/`tools` 100)
- **FIND-R51-017 (P3, types):** `ModelFamily::Custom` string bounded at 256 bytes

#### Round 50 Adversarial Audit (6 P1, 12 P2, 10 P3)

- **FIND-R50-001 (P1):** `Policy::validate()` fail-open on Conditional conditions serialization — `unwrap_or_default()` returned empty string bypassing 65536-byte size check; replaced with `map_err()?` (fail-closed)
- **FIND-R50-002 (P1):** `NhiDelegationChain.max_depth` attacker-controlled — added `MAX_DELEGATION_DEPTH` constant (20) as hard upper bound; `exceeds_max_depth()` now uses `min(self.max_depth, MAX_DELEGATION_DEPTH)`
- **FIND-R50-003 (P1):** TypeScript SDK `evaluate()` dropped `target_paths` and `target_domains` from request body — added both fields to match Python/Go SDKs
- **FIND-R50-004 (P1):** Federation JWT `nbf` (not-before) validation disabled — enabled `validate_nbf = true`
- **FIND-R50-005 (P1):** Federation JWT audience validation disabled (`validate_aud = false`) — enabled with configurable `expected_audience`
- **FIND-R50-006 (P1):** Federation JWKS body fully downloaded before size check (OOM) — added `Content-Length` pre-check and chunked bounded read (1MB max)
- **FIND-R50-007 (P2):** `SecureTask` state_chain/seen_nonces unbounded on deserialization — bounded at `MAX_STATE_CHAIN` (1000) with per-element 256-byte limit
- **FIND-R50-008 (P2):** `CapabilityGrant` allowed_paths/allowed_domains unbounded — bounded at 1000 entries, 2048 bytes per entry via `validate()`
- **FIND-R50-009 (P2):** `DidPlcGenesisOperation` 4 unbounded vectors — added `validate()` with 100-entry, 4096-byte per-element bounds
- **FIND-R50-010 (P2):** `ToolSignature.rekor_entry` unbounded `serde_json::Value` — bounded at 64KB serialized via `validate()`
- **FIND-R50-011 (P2):** Identity mapping template injection via unsanitized JWT claims — added `sanitize_claim_for_template()` stripping control chars, template syntax, and truncating to 1024 bytes
- **FIND-R50-012 (P2):** Issuer extracted from unverified JWT for anchor selection — added post-verification issuer re-check against anchor's `issuer_pattern`
- **FIND-R50-013 (P2):** `find_key_in_jwks` accepted kidless JWK as wildcard — now requires `kid` field, skips kidless with warning
- **FIND-R50-014 (P2):** JWK algorithm matching used `format!("{:?}")` Debug comparison — replaced with explicit `key_algorithm_to_algorithm()` enum mapping
- **FIND-R50-015 (P2):** Federation `issuer_pattern` unbounded, bare `*` not rejected — bounded at 2048 bytes, bare `*` rejected in `validate()`
- **FIND-R50-016 (P2):** Federation `jwks_uri` not validated for SSRF — added private IP/hostname rejection in `validate()`
- **FIND-R50-017 (P2):** OAuth JWKS fetch same OOM pattern — added Content-Length check and chunked bounded read
- **FIND-R50-018 (P2):** `issuer_pattern_matches` consecutive wildcard edge cases — normalized `**` → `*`, bounded pattern complexity at 10 segments
- **FIND-R50-019 (P3):** `SecureTask.resume_token` not redacted in Debug — manual Debug impl with `[REDACTED]`
- **FIND-R50-020 (P3):** `TaskResumeRequest.resume_token` not redacted in Debug — manual Debug impl with `[REDACTED]`
- **FIND-R50-021 (P3):** `NhiBehavioralBaseline.active_hours` no 0-23 validation — added range check and 24-entry max in `validate_finite()`
- **FIND-R50-022 (P3):** `AbacCondition.value` unbounded `serde_json::Value` — bounded at 8KB serialized via `validate()`
- **FIND-R50-023 (P3):** `FederatedClaims` unbounded extra claims via `#[serde(flatten)]` — bounded at 50 entries post-deserialization
- **FIND-R50-024 (P3):** RwLock poisoning recovery used partial cache data — write lock poisoning now clears cache
- **FIND-R50-025 (P3):** `call_chain` serde `unwrap_or(Value::Null)` swallowed errors — added `tracing::warn` on failure
- **FIND-R50-026 (P3):** SSE injection scanner `all_matches` vector unbounded — capped at 1000 matches
- **FIND-R50-027 (P3):** Federation JWKS cache TTL/fetch timeout no minimum bounds — enforced 60s min TTL, 1000ms min timeout
- **FIND-R50-028 (P3):** `extract_claim_value` joins array elements without bounds — capped at 64 elements, 1024 bytes each, 8192 total

#### Round 49 Adversarial Audit (6 P1, 22 P2, 17 P3)

- **FIND-R49-001 (P1):** `EvaluationContext` and `StatelessContextBlob` collection bounds enforced — `call_counts` (10K), `previous_actions` (10K), `call_chain` (100) validated to prevent pre-sanitization OOM via oversized deserialized payloads
- **FIND-R49-002 (P1):** `AccessReviewEntry.usage_ratio` missing `validate_finite()` — NaN could propagate to SDK consumers and silently bypass threshold checks in compliance reporting
- **FIND-R49-003 (P1):** ZK audit mutex poison details leaked to client in 3 endpoints — replaced with generic "Internal server error" and server-side logging
- **FIND-R49-004 (P1):** `list_graphs` tool filter scanned all sessions without bound — capped at 10K with input validation (length 256, control chars)
- **FIND-R49-005 (P1):** Session guard `violation_count`/`anomaly_count` used wrapping `+=` — u32 overflow could reset counters preventing session lock; replaced with `saturating_add`
- **FIND-R49-006 (P2):** ETDI `is_expired()` timezone bypass — non-UTC timestamps (e.g., `+05:30`) break lexicographic ordering; now rejects as expired (fail-closed)
- **FIND-R49-007 (P2):** `AgentIdentity.claims` unbounded `HashMap<String, Value>` — bounded at 64 entries with `validate()` method
- **FIND-R49-008 (P2):** `ShadowAiReport` vectors unbounded on deserialization — bounded to match runtime caps (1000/500/100)
- **FIND-R49-009 (P2):** Governance inner HashSets (`tools_used`, `requesting_agents`, `advertised_tools`) unbounded — bounded at 1000 each
- **FIND-R49-010 (P2):** `FederationTrustAnchor.identity_mappings` unbounded — bounded at 64
- **FIND-R49-011 (P2):** ABAC path normalization ignores engine's `max_path_decode_iterations` — now uses `normalize_path_bounded`
- **FIND-R49-012 (P2):** `MaxChainDepth` off-by-one (`>` vs `>=`) — fixed to `>=` for consistency with `MaxCalls`
- **FIND-R49-013 (P2):** Circuit breaker `failure_count`/`success_count` non-saturating `+= 1` — replaced with `saturating_add(1)`
- **FIND-R49-014 (P2):** Dashboard approve/deny error responses leak debug-formatted internal errors + missing control char validation
- **FIND-R49-015 (P2):** Audit export `since`/`format` parameters unbounded — validated (64/16 char max, control chars rejected)
- **FIND-R49-016 (P2):** Shadow AI discovery `approved_tools` lock poisoning fail-open — changed to `unwrap_or(true)` (fail-closed)
- **FIND-R49-017 (P2):** Access review timestamp comparison fails for non-UTC RFC 3339 — normalized `+00:00` to `Z` before comparison
- **FIND-R49-018 (P2):** SOC 2 access review loads entire audit log without entry count guard — bounded at 500K
- **FIND-R49-019 (P2):** `ZkVerifyRequest` missing `deny_unknown_fields` — added; batch_id echo and entry count leak removed
- **FIND-R49-020 (P3):** `SecureTask.state_chain` unbounded — bounded at 1000 transitions
- **FIND-R49-021 (P3):** `SdkCapabilities` capability vectors unbounded — bounded at 100/20 with `validate()`
- **FIND-R49-022 (P3):** `PolicyType::Conditional.conditions` unbounded JSON — size-checked at 64KB in `Policy::validate()`
- **FIND-R49-023 (P3):** Legacy infix wildcard treated as prefix (fail-open) — changed to match-all (fail-closed)
- **FIND-R49-024 (P3):** ABAC absent claim treated as empty string matching `*` — absent claims now return no-match
- **FIND-R49-025 (P3):** Duplicate `[inst]` injection pattern removed; `unreachable!()` replaced with `unsafe { new_unchecked(1) }`
- **FIND-R49-026 (P3):** Compliance category filter reflects user input in error — fixed message; `GraphListQuery` offset capped at 1M
- **FIND-R49-027 (P2):** `AbacPolicy` missing `validate()` — conditions (256), principal/action/resource constraint bounds now enforced
- **FIND-R49-028 (P2):** `FederationTrustAnchor.validate()` incomplete — org_id, issuer_pattern, jwks_uri scheme, identity_mappings all validated
- **FIND-R49-029 (P2):** `ToolAttestation` missing `MAX_ATTESTATION_CHAIN_DEPTH` constant — added at 64
- **FIND-R49-030 (P2):** `html_escape()` missing `/` escape — added `&#x2F;` per OWASP recommendation
- **FIND-R49-031 (P2):** Dashboard and audit routes load entire audit log without entry count guard — bounded at 500K
- **FIND-R49-032 (P3):** `BehavioralAnomaly` tool decay sessions unbounded — added MAX_DECAY_SESSIONS (200) eviction
- **FIND-R49-033 (P3):** `AsyncTaskPolicy` error logged at warn instead of error — upgraded
- **FIND-R49-034 (P3):** Domain normalization uses lossy UTF-8 decode — changed to strict (fail-closed on invalid UTF-8)
- **FIND-R49-035 (P3):** `build_tool_index()` sorted invariant undocumented — added debug_assert! checks
- **FIND-R49-036 (P3):** No-op policy conditions compiled silently — added compile-time tracing::warn
- **FIND-R49-037 (P3):** `InjectionDetector::from_config()` returns None silently when all patterns disabled — added warning
- **FIND-R49-038 (P3):** `FallbackBehavior::Allow` configured without warning — added tracing::error
- **FIND-R49-039 (P3):** Session guard Init-to-Active transition could exceed MAX_TRANSITION_HISTORY — added bounds check
- **FIND-R49-040 (P3):** 19 POST body structs missing `deny_unknown_fields` — added to prevent config typo/field smuggling

### Added

#### Phase 40: Workflow-Level Policy Constraints

Engine-only addition of three new `CompiledContextCondition` variants enabling operators to define multi-tool sequence requirements, forbidden patterns, and full workflow DAGs as context conditions on policies. Motivated by the SciAgentGym finding that agents make more errors in longer, multi-step workflows.

- **`RequiredActionSequence`** (`vellaveto-engine/src/compiled.rs`): Ordered or unordered multi-tool sequence prerequisites. Ordered mode uses greedy left-to-right subsequence matching; unordered mode uses set semantics. Max 20 steps. Fail-closed: empty/shorter history → Deny. Case-insensitive.
- **`ForbiddenActionSequence`** (`vellaveto-engine/src/compiled.rs`): Ordered or unordered forbidden sequence detection. Detects exfiltration patterns like `read_secret` → `http_request`. Empty history → Allow. Max 20 steps.
- **`WorkflowTemplate`** (`vellaveto-engine/src/compiled.rs`): DAG-based tool transition enforcement. Non-governed tools pass through. Governed tools must follow DAG edges: current tool must be a valid successor of the most recent governed tool, or an entry point. Cycle detection via Kahn's algorithm at compile time. Strict mode denies violations; warn mode logs only. Max 50 steps.
- **Compilation** (`vellaveto-engine/src/policy_compile.rs`): `compile_action_sequence()` and `compile_workflow_template()` with full input validation (bounds, control chars, empty strings, cycle detection)
- **Evaluation** (`vellaveto-engine/src/context_check.rs`): `current_tool` parameter added to `check_context_conditions()` for WorkflowTemplate DAG lookup
- **TLA+ Spec** (`formal/tla/WorkflowConstraint.tla`): S8 (WorkflowPredecessor) and S9 (AcyclicDAG) invariants verified
- **Tests**: 55 new tests (18 RequiredActionSequence + 17 ForbiddenActionSequence + 20 WorkflowTemplate)

#### Phase 39: Agent Identity Federation (placeholder)

- `FederationResolver` type with config/status methods in vellaveto-server
- `FederationConfig` with trust anchor validation in vellaveto-config
- Dashboard federation status section
- Server and http-proxy federation API routes (`/api/federation/status`, `/api/federation/trust-anchors`)
- SDK methods: Python (sync+async), TypeScript, Go with input validation
- Audit events for federation lifecycle

#### Round 48 Adversarial Audit (2 P1, 10 P2, 4 P3)

- **FIND-R48-001 (P1):** WebSocket canonicalization fail-closed — 6 message type handlers (SamplingRequest, TaskRequest, ExtensionMethod, Elicitation, PassThrough, upstream response) now return errors instead of falling back to original bytes when re-serialization fails, closing TOCTOU gap
- **FIND-R48-001 (P2):** `Action::validate()` fail-closed on `serde_json::to_string()` failure — previously skipped size check silently
- **FIND-R48-002 (P2):** ABAC `resolve_field` treats non-finite `risk.score` (NaN/Inf) as 1.0 (maximum risk) to prevent Forbid policy bypass
- **FIND-R48-003 (P2):** `ProvenanceNode::validate()` enforces `MAX_PARENTS` (64) and `MAX_METADATA_ENTRIES` (64) on deserialized data
- **FIND-R48-004 (P2):** `AbacEntity::validate()` enforces `MAX_PARENTS` (256) and `MAX_ATTRIBUTES` (256)
- **FIND-R48-005 (P2):** `NhiAgentIdentity::validate()` enforces `MAX_TAGS` (100), `MAX_METADATA_ENTRIES` (100), `MAX_ATTESTATIONS` (100)
- **FIND-R48-006 (P2):** `NhiDelegationLink::validate()` enforces `MAX_PERMISSIONS` (256) and `MAX_SCOPE_CONSTRAINTS` (256)
- **FIND-R48-008 (P2):** `MemoryNamespace::validate()` enforces `MAX_ACL_ENTRIES` (1000)
- **FIND-R48-009 (P2):** `NhiBehavioralBaseline::validate_finite()` now also checks `MAX_TOOL_CALL_PATTERNS` (10K) and `MAX_SOURCE_IPS` (1K)
- **FIND-R48-003 (P2, server):** Exec graph session path parameter validated for length (128) and control characters
- **FIND-R48-005 (P2, server):** Discovery sensitivity parameter validated before reflection in error messages
- **FIND-R48-010 (P3):** `SamplingStats::reset_window()` truncates `flagged_patterns` at 1000
- **FIND-R48-011 (P3):** `Policy` struct gets `#[serde(deny_unknown_fields)]`
- **FIND-R48-014 (P3):** `truncate_for_log` handles `max_len < 4` without exceeding requested maximum
- **FIND-R48-007 (P3):** WS `extract_strings_recursive` bounded at 1000 parts

### Added

#### Phase 38: SOC 2 Type II Access Review Reports

Dynamic report generation for SOC 2 Type II auditors, scanning audit entries and cross-referencing with least-agency data to produce CC6-focused access review reports with reviewer attestation fields.

- **Types** (`vellaveto-types/src/compliance.rs`): `AttestationStatus` (Pending/Approved/FindingsNoted/Rejected), `ReviewerAttestation`, `AccessReviewEntry` (per-agent verdict counts, tools/functions, permission usage ratio, recommendation), `Cc6Evidence` (CC6.1/CC6.2/CC6.3 with agent tier counts), `AccessReviewReport`, `ReviewSchedule` (Daily/Weekly/Monthly), `ReportExportFormat` (Json/Html)
- **Config** (`vellaveto-config/src/compliance.rs`): `Soc2AccessReviewConfig` with `enabled`, `schedule`, `default_period_days` (1–366), `reviewers` (max 50, 256-char names, no control chars). Added to `Soc2Config` with `#[serde(default)]`
- **Generator** (`vellaveto-audit/src/access_review.rs`): `generate_access_review()` — period-filtered audit scanning, per-agent aggregation via BTreeMap (deterministic ordering), least-agency cross-reference, CC6 evidence by recommendation tier. Memory-bounded: MAX_ENTRIES=1M, MAX_AGENTS=10K
- **HTML renderer** (`vellaveto-audit/src/access_review.rs`): `render_html()` — self-contained HTML with embedded CSS, HTML-escaped user data, summary table, per-agent details, attestation section
- **Server route** (`vellaveto-server/src/routes/compliance.rs`): `GET /api/compliance/soc2/access-review` with query params `period` (e.g. "30d"), `format` ("json"/"html"), `agent_id` (optional filter, max 128 chars). Gates on `soc2.enabled` and `soc2.access_review.enabled`
- **Scheduled generation** (`vellaveto-server/src/main.rs`): tokio interval task when `schedule` is configured (Daily=86400s, Weekly=604800s, Monthly=2592000s). Errors logged via `access_review.error` event (fail-safe)
- **Audit events** (`vellaveto-audit/src/events.rs`): `log_access_review_event()` for `access_review.generated`, `access_review.scheduled`, `access_review.exported`, `access_review.error`
- **Python SDK**: `soc2_access_review(period, format, agent_id)` on both sync and async clients with agent_id validation (max 128 chars)
- **TypeScript SDK**: `soc2AccessReview(period?, format?, agentId?)` method + `AccessReviewReport`, `AccessReviewEntry`, `Cc6Evidence`, `ReviewerAttestation` interfaces
- **Go SDK**: `Soc2AccessReview(ctx, period, format, agentID)` method + corresponding types

#### Test Count Updates
- Rust: 6,055 → 6,099 (+44)
- Python SDK: 298 (+3 new access review tests)
- TypeScript SDK: 34 → 64 (+30 new tests)
- Go SDK: 40 (+3 new access review tests)
- **Total: 6,501 tests across all languages**

### Fixed (Adversarial Hardening — Round 47: P2/P3 Hardening)

52 findings resolved (30 P2, 22 P3) across 51 files (+972/-173 lines).

#### Engine & Types P2/P3 Fixes
- **FIND-P2-001**: ABAC IDNA normalization via `normalize_domain_for_match()` (fail-closed on normalization failure)
- **FIND-P2-003/P3-014**: RwLock poison recovery with `unwrap_or_else(|e| e.into_inner())` pattern in glob matcher cache
- **FIND-P2-004**: `max_calls_in_window` overflow now returns `PolicyValidationError` instead of silent saturation
- **FIND-P2-005**: No-op context conditions (AsyncTaskPolicy, CircuitBreaker, etc.) upgraded from `trace!` to `warn!`
- **FIND-P2-006**: Infix wildcard detection with warning in legacy matcher
- **FIND-P2-007**: Float validation (`validate_finite()`) added to `UnregisteredAgent`, `ShadowAiReport`, `DiscoveredTool`, `NhiBehavioralCheckResult`, `LeastAgencyReport`
- **FIND-P2-008**: `Policy::validate()` checking id/name non-empty and priority >= 0
- **FIND-P2-009**: `UpstreamBackend::validate()` checking id/url non-empty and URL scheme http/https
- **FIND-P2-010/011**: `AuthLevel::from_u8()` and `TrustLevel::from_u8()` fail-closed design documentation
- **FIND-P3-012**: `LeastAgencyTracker` poisoned lock logging with `tracing::error!` before 6 early returns
- **FIND-P3-015**: `async_task_policy` max_concurrent `usize` conversion returns error
- **FIND-P3-016**: `MAX_PARAMETERS_SIZE` (1MB) with `ParametersTooLarge` validation error
- **FIND-P3-017**: `MemoryNamespace::new()` clone optimization
- **FIND-P3-018**: `validate_name()` `pub(crate)` visibility documentation

#### Audit P2/P3 Fixes
- **GAP-S04**: URL scheme validation (http/https only) in `WebhookExporter::new()`
- **GAP-F05**: URL scheme validation in streaming exporters (Splunk, Webhook, Elasticsearch)
- **GAP-S06**: Redaction fail-closed at max depth — returns `[REDACTED]` instead of unredacted value
- **GAP-S07**: Merkle `compute_siblings()` edge case documentation
- **GAP-S08**: `glob_match()` O(n*m) memory behavior documentation
- **GAP-F06**: `generate_report()` memory limitation documentation
- **GAP-Q04**: Serialization error logging in `to_json_lines()` and streaming exporters (Datadog, Syslog)
- **GAP-F01**: ZK scheduler exponential backoff on proving failures (`MAX_BACKOFF_SECS=300`)
- **GAP-F03/F04**: ZK error handling philosophy and Pedersen blinding security documentation
- Witness backpressure mechanism documentation

#### MCP & Server P2/P3 Fixes
- `MAX_COMPILED_POLICIES=10,000` in NL policy compiler with reject-on-capacity
- `FallbackBehavior::Allow` warning on semantic guardrail timeout/error
- `EvaluationCache` config validation (warns on zero max_size/ttl_secs)
- Agent card expired-entry eviction before capacity check
- Dead code justification comments in 8 locations
- Serialization errors return HTTP 500 (governance, discovery, zk_audit, exec_graph routes)
- `MAX_DASHBOARD_AUDIT_ENTRIES=1,000` with truncation notice
- `ErrorResponse` doc comment, WebSocket output schema validation TODO

#### HTTP Proxy P2/P3 Fixes
- `MAX_DISCOVERED_TOOLS_PER_SESSION=10,000` with expired-entry eviction
- Proxy environment clearing (`.env_clear()` + minimal variable forwarding)
- Fallback dead_code justification, JSON-RPC error format documentation

#### Test Count Updates
- Rust: 6,099 → 6,103 (+4 new URL scheme validation tests)

### Fixed (Adversarial Hardening — Round 47: P0/P1 Deep Fix)

15 findings resolved (3 P0, 12 P1) across 23 files (+1,824/-161 lines).

#### P0 Fixes (Critical)
- **P0-1** (P0): Unbounded `intent_chains` HashMap in semantic guardrails — capped at 10,000 sessions with warning on capacity.
- **P0-2** (P0): SDK payload format mismatch — Python and Go SDKs sent nested `{"action": {...}}` but server expects flattened fields due to `#[serde(flatten)]` on `EvaluateRequest`. All three SDKs (Python, Go, TypeScript) now send `{"tool": "...", "function": "...", ...}` at root level. `trace` moved from body field to query parameter (`?trace=true`).
- **P0-3** (P0): Python async client `_request()` had no response body size limit — added `_MAX_RESPONSE_BYTES` check.

#### P1 Fixes (High)
- **P1-1** (P1): ZK `WitnessStore` drain-before-prove data loss — `try_prove_batch()` now restores witnesses on failure via new `WitnessStore::restore()` method.
- **P1-2** (P1): Elasticsearch exporter missing retry — added bounded exponential backoff matching other exporters.
- **P1-3** (P1): OTLP exporter stub silently discarded batches — now returns error for non-empty batches with `tracing::warn!` on construction.
- **P1-4** (P1): Elasticsearch bulk API partial failures not detected — response body now parsed for per-item errors.
- **P1-5** (P1): ABAC `matches_resource` lacked globset parity with main engine — new `CompiledPathMatcher` enum with `globset::Glob` support (literal_separator=true so `*` doesn't cross `/`). Fail-closed on invalid glob patterns.
- **P1-6** (P1): MINJA `hours_since()` returned 0.0 on parse failure, bypassing trust decay entirely — `decayed_trust_score()` now returns 0.0 (fail-closed) on corrupt timestamps. `parse_timestamp()` validates month/day/year/hour/min/sec ranges.
- **P1-7** (P1): ZK audit commitments endpoint loaded unbounded entries — capped at 500,000 with HTTP 503 response.
- **P1-8** (P1): A2A proxy `request_timeout_ms` advisory documentation added (callers must enforce at transport layer).
- **P1-9** (P1): Python SDK approval API paths corrected to `/api/approvals/pending`, `/api/approvals/{id}/approve`, `/api/approvals/{id}/deny`.
- **P1-10** (P1): TypeScript `evaluate()` now extracts `reason`, `policy_id`, `policy_name` from verdict object.
- **P1-11** (P1): Go and TypeScript SDKs now have ZK Audit methods: `zkStatus()`, `zkProofs()`, `zkVerify()`, `zkCommitments()` with full type definitions.
- **P1-12** (P1): Python async `evaluate()` now validates inputs via shared `_validate_evaluate_inputs()` helper (parity with sync client).

#### Test Count Updates
- Rust: 6,042 → 6,055 (+13)
- Python SDK: 288 → 298 (+10 new tests)
- Go SDK: 33 → 40 (+7 new tests including ZK Audit)
- TypeScript SDK: 34 (unchanged, ZK tests added in Round 46)
- **Total: 6,427 tests across all languages**

### Fixed (Adversarial Hardening — Round 46: Full-Codebase Audit)

~177 findings resolved across all crates and SDKs (21 P1, 66 P2, ~90 P3).

#### P1 Fixes (Critical)
- **FIND-R46-001** (P1): `ToolSensitivity::default()` changed from `Low` to `High` — fail-closed for unknown tool sensitivity.
- **FIND-R46-002** (P1): `NhiIdentityStatus::default()` changed from `Active` to `Probationary` — new non-human identities start restricted.
- **FIND-R46-003** (P1): ABAC `NotIn` operator fails closed on non-array attribute values instead of silently passing.
- **FIND-R46-004** (P1): `deny_unknown_fields` added to security-critical serde structs (`Action`, `PathRules`, `NetworkRules`, `IpRules`) preventing silent field injection.
- **FIND-R46-005** (P1): `EvaluationContext::builder()` validation — rejects empty agent_id, empty session_id, zero max_calls, empty call chain entries.
- **FIND-R46-013** (P1): Merkle rotation `start_hash` verification hardened.
- **FIND-R46-014** (P1): Rotation manifest skip-missing-files verification.
- **FIND-R46-015** (P1): Relay `PassThrough` mode audit logging — previously silent.
- **FIND-R46-016** (P1): Relay `PassThrough` mode DLP/injection scanning — previously bypassed.
- **FIND-R46-017** (P1): WebSocket proxy security parity with HTTP path.
- **FIND-R46-018** (P1): `MemoryEntry` trust/taint consistency — Untrusted entries now start at trust_score 0.5 instead of contradictory 1.0.

#### P2 Fixes (Medium)
- 66 findings across all crates: relay channel buffer reduction (256→64), 4MB message size limits, `SchemaRecord.version_history` bounded, domain cache eviction, BFS scan ordering, JSON depth limits, Python SDK `__repr__` redacts API keys, `ConnectionError` renamed to `VellavetoConnectionError`, exponential retry backoff with jitter, thread-safe LangChain call chains, TypeScript baseUrl HTTPS validation, Go `Action.Validate()`, config pattern length limits (4096), empty pattern rejection, unknown extension error reporting.

#### P3 Fixes (Low)
- ~90 findings: archive TOCTOU documentation, OTLP PII redaction docs, syslog limits, relay allowed-decision audit, infix wildcard documentation, mutex poisoning documentation, scanner circular reference protection (seen-set), bytes handling and total work limit in Composio scanner, snippet truncation bounds, PolicyDenied docstrings, path traversal warnings, key variant casefold normalization, checkpoint fixes in LangGraph, thread_id validation, TLS warning for non-HTTPS, JSON depth validation on projector routes (max 32), token_budget cap (1M) on discovery routes, batch_size>0 validation.

#### Test Count Updates
- Rust: 6,032 → 6,042 (+10)
- Python SDK: 245 → 288 (+43 new tests)
- TypeScript SDK: 15 → 34 (+19 new tests)
- Go SDK: 28 → 33 (+5 new tests)
- **Total: 6,397 tests across all languages**

### Added

#### Codebase Improvement Campaign — Tests, Benchmarks, Formal Verification, CI
- **Engine unit tests** (~120 new tests in `vellaveto-engine/src/engine_tests.rs`) — Comprehensive coverage for `policy_compile.rs` (30 tests: sort order, tiebreakers, error collection, all constraint operators, DFA size limits), `constraint_eval.rs` (30 tests: per-operator dispatch, wildcard param scan, nested paths, fail-closed semantics, `require_approval`), `context_check.rs` (35 tests: all 17 `CompiledContextCondition` variants including TimeWindow midnight-wrap, MaxCalls saturation, AgentId case-insensitive, MinVerificationTier, RequireCapabilityToken), `legacy.rs` (25 tests: action matching, path/network/IP rules, fail-closed on invalid globs/CIDRs, IPv6-embedded-IPv4), differential compiled-vs-legacy testing (10 tests: systematic verdict equivalence verification). Engine now at 687 tests.
- **Relay tests** (19 new tests) — `RelayState` unit tests (11 tests in `relay.rs`: initialization, flag_tool capacity rejection, call_counts MAX_CALL_COUNTS cap, action_history FIFO eviction, pending request tracking/limit/null-id, evaluation context construction) and evaluation tests (8 tests in `tests.rs`: flagged tool blocking, path rules allowed/blocked, network rules allowed/blocked, conditional glob constraint, priority ordering, deny-overrides-allow). MCP crate now at 1,083 tests.
- **Audit hardening tests** (~25 new tests in `vellaveto-audit/src/tests.rs`) — Redaction boundary tests (depth 63/64/65 vs MAX_REDACTION_DEPTH=64, NFKC fullwidth digit SSN/phone/email normalization, number PII matching, case-insensitive value prefix, scanner depth boundary, empty object, null value preservation) and verification/rotation edge cases (Merkle 1000-leaf batch proof, max leaf count boundary, audit line size boundary, corrupted UTF-8 line handling, embedded null in JSON, empty-file rotation, sequential checkpoint creation with signing key). Audit crate now at 441 tests.
- **Criterion benchmarks** (14 new benchmarks across 4 files) — ABAC evaluation (`evaluation.rs`: single permit, forbid-overrides with 10 policies, entity store with 100 entities, transitive group membership depth 10), Merkle tree operations (`audit.rs`: append leaf, generate proof 100/10,000 leaves, verify proof), injection/DLP long text (`inspection.rs`: 10KB clean/hit injection scan, embedded API key DLP), E2E pipeline (`e2e_pipeline.rs`: compile+evaluate 10/100 mixed policies, evaluate with full session context including call chain, ABAC claims, and 50-action history).
- **Formal verification updates** — TLA+ `RequireApproval` verdict + `ApplyConditionalApproval` transition + safety invariant S7 (`InvariantS7_RequireApprovalOnlyFromConditional`) in `MCPPolicyEngine.tla`. Alloy stale comment fix in `CapabilityDelegation.als` line 27. VERIFIED markers linking source code to formal properties: S1/S2/S3/L1 in `vellaveto-engine/src/lib.rs`, S4 in `context_check.rs`, S7 in `abac.rs`, S11/S12 in `vellaveto-mcp/src/capability_token.rs`.
- **CI improvements** (4 new jobs in `.github/workflows/ci.yml`) — `supply-chain-audit` (cargo-vet), `semver-check` (cargo-semver-checks, PR-only), `msrv-check` (rust-version 1.75.0 in workspace Cargo.toml), `feature-matrix` (default, discovery, projector, discovery+projector feature combinations). Total: 11 CI jobs.
- **Relay security hardening** — `VELLAVETO_AGENT_ID` environment variable for stdio proxy agent identification in context-aware policy evaluation, relay channel buffer reduction (256→64, bounding worst-case memory to ~4MB), oversized child response dropping (4MB limit per message).
- 6,032 Rust tests passing, 0 failures, clippy clean.

#### Phase 37 — Zero-Knowledge Audit Trails
- **ZK Audit types** (`vellaveto-types/src/zk_audit.rs`) — `PedersenCommitment` (hex-encoded Ristretto point + blinding hint), `ZkBatchProof` (Groth16 proof bytes, batch_id, entry_range, merkle_root, public inputs, entry_count), `ZkVerifyResult` (valid, batch_id, entry_range, verified_at, error), `ZkSchedulerStatus` (active, pending_witnesses, completed_proofs, last_proved_sequence, last_proof_at).
- **ZK Audit config** (`vellaveto-config/src/zk_audit.rs`) — `ZkAuditConfig` with `enabled` (default false), `pedersen_commitments` (default true when enabled), `batch_proof_enabled` (default false), `batch_size` (default 100, range 10–10,000), `batch_interval_secs` (default 300), `proving_key_path`, `verifying_key_path`. Validation: batch_size bounds, interval minimum 10s.
- **Pedersen commitments** (`vellaveto-audit/src/zk/pedersen.rs`) — `PedersenCommitter` with domain-separated generators (G = Ristretto basepoint, H = hash-to-point of "vellaveto-pedersen-generator-h"). `commit()` binds entry hash as `hash * G + blinding * H`. `verify()` checks commitment against known hash and blinding factor. Feature-gated behind `zk-audit`.
- **Witness store** (`vellaveto-audit/src/zk/witness.rs`) — `WitnessStore` with `Mutex`-protected bounded `Vec<EntryWitness>` (configurable max capacity). `add()` fails gracefully at capacity. `drain()` returns accumulated witnesses for batch proving. `len()`, `is_empty()` for scheduler coordination.
- **Groth16 circuit** (`vellaveto-audit/src/zk/circuit.rs`) — `AuditChainCircuit` implementing `ConstraintSynthesizer<Fr>` for BN254. Public inputs: first_prev_hash, final_entry_hash, entry_count. Private witnesses: per-entry hashes and prev_hashes. Constraints: chain link verification (prev_hash_{i+1} == entry_hash_i), endpoint binding (first prev_hash and final entry hash match public inputs), entry count consistency.
- **Batch prover** (`vellaveto-audit/src/zk/prover.rs`) — `ZkBatchProver` with `setup()` (trusted setup for max batch size), `from_files()`/`save_keys()` (serialized key I/O), `prove()` (generate Groth16 proof from entry witnesses), `verify()` (verify proof against public inputs). All operations return `Result<_, ZkError>`.
- **Batch scheduler** (`vellaveto-audit/src/zk/scheduler.rs`) — `ZkBatchScheduler` with async `run()` loop (tokio::spawn-compatible, graceful shutdown via `watch::Receiver`). Triggers batch proof on size threshold (`batch_size`) or interval (`batch_interval_secs`). `prove_now()` for manual/test triggering. `proofs()` returns all stored proofs. `status()` returns `ZkSchedulerStatus`.
- **Audit entry integration** (`vellaveto-audit/src/types.rs`) — `commitment: Option<String>` field on `AuditEntry`. Logger computes Pedersen commitment after Merkle append when `zk-audit` feature is enabled.
- **Audit event helper** (`vellaveto-audit/src/events.rs`) — `log_zk_event()` for ZK audit observability (`zk_audit.commitment_created`, `zk_audit.batch_proved`, `zk_audit.proof_verified`, `zk_audit.scheduler_started`, `zk_audit.scheduler_stopped`, `zk_audit.error`).
- **REST API** (`vellaveto-server/src/routes/zk_audit.rs`) — `GET /api/zk-audit/status` (scheduler status), `GET /api/zk-audit/proofs` (paginated proof listing, max 100), `POST /api/zk-audit/verify` (structural validation by batch_id with input validation — empty/length/control chars), `GET /api/zk-audit/commitments` (Pedersen commitments for entry range, max span 10,000). `AppState` extended with `zk_proofs`, `zk_audit_enabled`, `zk_audit_config`.
- **Python SDK** (`sdk/python/vellaveto/client.py`, `sdk/python/vellaveto/types.py`) — 4 sync methods (`zk_status()`, `zk_proofs()`, `zk_verify()`, `zk_commitments()`) + 4 async methods on `AsyncVellavetoClient`. `ZkBatchProof`, `ZkVerifyResult`, `ZkSchedulerStatus` dataclasses exported from `vellaveto`.
- **Feature-gated** — `zk-audit` feature in `vellaveto-audit/Cargo.toml` with `curve25519-dalek` (Pedersen) and `ark-groth16`/`ark-bn254`/`ark-relations`/`ark-ff`/`ark-ec`/`ark-serialize`/`ark-std` (Groth16) as optional dependencies. Server uses only `vellaveto-types` for proof storage (no heavy deps).
- ~190 new tests across Rust (Pedersen roundtrip, witness store, circuit satisfaction, prover roundtrip, scheduler, config validation, REST API, serde) and Python SDK (client sync/async, types).

#### Phase 35 — Model Projector
- **Canonical types** (`vellaveto-types/src/projector.rs`) — `CanonicalToolSchema`, `CanonicalToolCall`, `CanonicalToolResponse`, `ModelFamily` enum (Claude, OpenAi, DeepSeek, Qwen, Generic, Custom). Model-agnostic representations for tool schema transformation across LLM families.
- **Projector config** (`vellaveto-config/src/projector.rs`) — `ProjectorConfig` with `enabled`, `default_model_family`, `auto_detect_model`, `compress_schemas`, `max_schema_tokens`, `repair_malformed_calls`. Validation: model family must be one of claude/openai/deepseek/qwen/generic, max_schema_tokens bounded.
- **ModelProjection trait** (`vellaveto-mcp/src/projector/mod.rs`) — `project_schema()`, `parse_call()`, `format_response()`, `estimate_tokens()` methods. `ProjectorRegistry` with RwLock-based concurrent access, `register()`, `get()`, `get_or_default()`, `list_families()`.
- **Claude projection** (`vellaveto-mcp/src/projector/claude.rs`) — Anthropic `tool_use` format with `cache_control: {"type": "ephemeral"}` hints. Token estimate: chars/3.5.
- **OpenAI projection** (`vellaveto-mcp/src/projector/openai.rs`) — OpenAI `functions` array format with `function_call` response parsing. Handles JSON string arguments. Token estimate: chars/4.
- **DeepSeek projection** (`vellaveto-mcp/src/projector/deepseek.rs`) — First-sentence description truncation for R1 efficiency, `<think>` block stripping, markdown code block JSON extraction from tool call content. Token estimate: chars/3.
- **Qwen projection** (`vellaveto-mcp/src/projector/qwen.rs`) — 200-character description truncation for CJK tokenizer efficiency. Token estimate: chars/3.
- **Generic projection** (`vellaveto-mcp/src/projector/generic.rs`) — Passthrough with flexible field name tolerance (`tool_name`/`name`, `arguments`/`parameters`). Token estimate: chars/4.
- **Schema compressor** (`vellaveto-mcp/src/projector/compress.rs`) — `SchemaCompressor::compress()` with 5 progressive strategies: strip redundant root `"type": "object"`, inline single-value enums as constants, truncate descriptions to first sentence, collapse single-property nested objects, remove optional parameter descriptions. `estimate_tokens()` for budget tracking.
- **Call repairer** (`vellaveto-mcp/src/projector/repair.rs`) — `CallRepairer::repair()` with type coercion (string→number, string→boolean), missing-required-field default injection, Levenshtein fuzzy tool name matching against known tools, DeepSeek markdown code block extraction.
- **Projector REST API** (`vellaveto-server/src/routes/projector.rs`) — `GET /api/projector/models` lists supported model families. `POST /api/projector/transform` projects a canonical schema for a target model family.
- **Audit helper** (`vellaveto-audit/src/events.rs`) — `log_projector_event()` for schema transformation audit trail.
- **Feature-gated** — `projector` feature in `vellaveto-mcp/Cargo.toml`, forwarded via server and http-proxy. Default on in `vellaveto-server`, opt-in in `vellaveto-http-proxy`.
- ~230 new tests across projector module (trait, registry, 5 projections, compressor, repairer, REST API).

#### Phase 34 — Tool Discovery Service
- **Discovery types** (`vellaveto-types/src/discovery.rs`) — `ToolMetadata` (tool_id, name, description, server_id, input_schema, schema_hash, sensitivity, domain_tags, token_cost), `ToolSensitivity` (Low/Medium/High), `DiscoveryResult`, `DiscoveredTool` with relevance scoring and TTL.
- **Discovery config** (`vellaveto-config/src/discovery.rs`) — `DiscoveryConfig` with `enabled`, `max_results` (default 5, max 20), `default_ttl_secs` (300), `max_index_entries` (10,000), `min_relevance_score` (0.1), `token_budget`, `auto_index_on_tools_list`. Validation: bounds checking on all numeric fields.
- **TF-IDF inverted index** (`vellaveto-mcp/src/discovery/index.rs`) — `ToolIndex` with RwLock-protected `HashMap`-based entries, IDF weights, and token inverted index. `ingest()`, `remove()`, `search()` (TF-IDF cosine similarity + exact name bonus 0.3 + domain tag bonus 0.2), `rebuild_idf()`, `len()`, `tool_ids()`, `get()`. Capacity-bounded at `max_entries`. Pure Rust, zero new dependencies.
- **Discovery engine** (`vellaveto-mcp/src/discovery/engine.rs`) — `DiscoveryEngine::discover()` with policy filtering closure, token budget enforcement, and configurable `min_relevance_score` cutoff. `ingest_tools_list()` for batch indexing from MCP `tools/list` responses.
- **Session TTL lifecycle** (`vellaveto-http-proxy/src/session.rs`) — `DiscoveredToolSession` with `discovered_at`, `ttl`, `used` tracking. `SessionState::record_discovered_tools()`, `is_tool_discovery_expired()`, `mark_tool_used()`, `evict_expired_discoveries()`. Tools expire after configurable TTL, requiring re-discovery.
- **Discovery REST API** (`vellaveto-server/src/routes/discovery.rs`) — `POST /api/discovery/search` (query + max_results + token_budget), `GET /api/discovery/index/stats`, `POST /api/discovery/reindex` (IDF rebuild), `GET /api/discovery/tools` (list with server_id/sensitivity filters, capped at 100). Input validation: query length 1024, control character rejection, server_id length 256.
- **SDK methods** — Python (sync+async): `discover()`, `discovery_stats()`, `discovery_reindex()`, `discovery_tools()`. TypeScript: same 4 methods. Go: `Discover()`, `DiscoveryStats()`, `DiscoveryReindex()`, `DiscoveryTools()`.
- **Audit helper** (`vellaveto-audit/src/events.rs`) — `log_discovery_event()` for query and reindex audit trail.
- **Feature-gated** — `discovery` feature in `vellaveto-mcp/Cargo.toml`, forwarded via server and http-proxy. Default on in `vellaveto-server`, opt-in in `vellaveto-http-proxy`.
- ~260 new tests across discovery module (index, engine, session TTL, REST API, config validation, SDK types).

#### Composio Integration (Python SDK)
- **ComposioGuard** (`sdk/python/vellaveto/composio/guard.py`) — High-level guard with `before_execute_modifier()` and `after_execute_modifier()` factory methods for Composio's native modifier system. Standalone `execute()` wrapper for direct tool calls. Works with any Composio provider (OpenAI, LangChain, CrewAI, AutoGen, Google ADK) — no framework-specific code.
- **Modifier factories** (`sdk/python/vellaveto/composio/modifiers.py`) — `create_before_execute_modifier()` evaluates tool calls against Vellaveto policies before execution (allow/deny/require_approval). `create_after_execute_modifier()` scans responses for DLP/injection findings. `CallChainTracker` maintains bounded FIFO chain (max 20 entries).
- **Response scanner** (`sdk/python/vellaveto/composio/scanner.py`) — Client-side defense-in-depth scanning with 10 injection patterns and `ParameterRedactor`-based secret detection. Recursive scanning up to configurable depth.
- **Slug normalization + target extraction** (`sdk/python/vellaveto/composio/extractor.py`) — Converts Composio `TOOLKIT_ACTION_NAME` slugs to `(tool, function)` pairs. Extracts `target_paths` and `target_domains` from arguments using the same heuristic as the LangChain adapter.
- **Optional dependency** — `composio>=1.0.0` in `pyproject.toml` optional deps group. Zero new hard dependencies.
- **Fail-closed by default** — API/network errors produce `PolicyDenied`. Configurable `fail_closed=False` for fail-open mode.
- 84 tests in `sdk/python/tests/test_composio.py` (7 test classes: slug normalization, target extraction, before/after modifiers, call chain tracker, response scanner, guard API — including 49 adversarial tests).

### Fixed (Adversarial Hardening — Composio Integration)
- **TOCTOU prevention** — `ComposioGuard.execute()` deep-copies arguments before policy check to prevent mutation between check and use.
- **Unicode injection bypass** — Scanner applies NFKC normalization and strips zero-width/invisible characters (U+200B, U+200C, U+200D, U+FEFF, etc.) before pattern matching, preventing fullwidth and zero-width character bypass.
- **Secret snippet redaction** — Secret findings now report `snippet="[REDACTED]"` instead of the detected value, preventing information leakage through scan results.
- **Thread-safe CallChainTracker** — All methods protected by `threading.Lock` for concurrent access safety. Tool names truncated at 256 chars to prevent memory abuse.
- **Resource exhaustion bounds** — Scan findings capped at 100 (`_MAX_FINDINGS`), string scan length at 64KB (`_MAX_SCAN_STRING_LEN`), targets at 256, extraction depth at 5 levels, scan depth validated (1–50).
- **Non-dict/non-string response handling** — After-execute modifier and standalone execute now handle bare string responses (wrapped in `{"_raw": ...}` for scanning) and non-scannable types (blocked in fail-closed mode).
- **Scanner exception safety** — Both modifier and guard catch scanner exceptions: fail-closed returns sanitized error, fail-open passes response through.
- **Error message sanitization** — Fail-closed error messages expose only `type(exc).__name__`, not full exception messages or stack traces, preventing internal information leakage.
- **Fail-open call chain poisoning** — When evaluation fails and `fail_closed=False`, unevaluated tool calls are not appended to the call chain (tracked via `evaluated` flag).
- **Slug validation hardening** — `normalize_slug_to_tool_function()` rejects empty, non-string, whitespace-only, and non-ASCII slugs (including Cyrillic homoglyphs) with `ValueError`.
- **Recursive nested target extraction** — `extract_targets()` walks nested dicts/lists up to 5 levels deep with independent if-chains (not elif) for path/domain classification, `file://` URI support, `ws://`/`wss://` scheme detection, and case-insensitive URL matching.
- **scan_responses=False consistency** — `ComposioGuard.after_execute_modifier()` returns a true no-op passthrough when scanning is disabled.
- **Import narrowing** — `vellaveto/__init__.py` narrowed from `except Exception` to `except ImportError` for `ComposioGuard` import.

#### Phase 30 — MCP 2025-11-25 Spec Adoption
- **Tool name validation** (`vellaveto-types/src/core.rs`) — `validate_mcp_tool_name()` enforces MCP 2025-11-25 format: 1–64 chars, `[a-zA-Z0-9_\-./]`, no leading/trailing dots/slashes, no consecutive dots (`..`). Re-exported at crate root.
- **StreamableHttpConfig** (`vellaveto-config/src/mcp_protocol.rs`) — new config struct with `resumability_enabled` (default false), `strict_tool_name_validation` (default false), `max_event_id_length` (default 128, range 1–512), `sse_retry_ms` (optional, range 100–60000). Wired into `PolicyConfig.streamable_http`.
- **GET /mcp handler** (`vellaveto-http-proxy/src/proxy/handlers.rs`) — `handle_mcp_get()` implements SSE stream initiation/resumption per MCP 2025-11-25. Validates `Accept: text/event-stream`, protocol version, `Last-Event-ID` length and content. Gated behind `resumability_enabled` (returns 405 when disabled).
- **Last-Event-ID forwarding** (`vellaveto-http-proxy/src/proxy/upstream.rs`) — `forward_get_to_upstream()` for GET requests, `forward_to_upstream_url()` extended with optional `last_event_id` parameter for POST resumption.
- **OAuth WWW-Authenticate header** (`vellaveto-http-proxy/src/proxy/auth.rs`) — `InsufficientScope` errors now return `WWW-Authenticate: Bearer error="insufficient_scope", scope="<required>"` per RFC 6750 §3.1. Scope string sanitized (no quotes, no control chars). JSON body includes `required_scope` field.
- **Strict tool name validation in proxy** (`vellaveto-http-proxy/src/proxy/handlers.rs`) — when `strict_tool_name_validation` is true, tool calls with non-spec names rejected with JSON-RPC error -32602.
- **Default off:** `resumability_enabled: false`, `strict_tool_name_validation: false`. WWW-Authenticate header always on (spec-mandated, backward compatible).
- ~42 new tests across 4 crates. Integration tests in `vellaveto-integration/tests/mcp_2025_11_25_compliance.rs`.

### Fixed (Adversarial Hardening — Round 45: Phase 30 GET /mcp Security Parity)
- **FIND-R45-001** (P1): Session ownership validation in GET handler — `handle_mcp_get` now binds OAuth claims to session (atomic ownership check), preventing SSE stream hijacking via session fixation.
- **FIND-R45-002** (P1): Agent identity validation in GET handler — `handle_mcp_get` now calls `validate_agent_identity()` and stores identity in session, matching POST path.
- **FIND-R45-003** (P2): Call chain validation in GET handler — `handle_mcp_get` now validates `X-Upstream-Agents` header via `validate_call_chain_header()`, preventing malformed headers from bypassing validation.
- **FIND-R45-004** (P1): Audit logging in GET handler — `handle_mcp_get` now logs `sse_resumption` audit entries with session, event ID presence, and OAuth context.
- **FIND-R45-005** (P1): Rug-pull detection in GET SSE path — `forward_get_to_upstream` now calls `check_sse_for_rug_pull_and_manifest()`, `register_schemas_from_sse()` matching POST SSE path.
- **FIND-R45-006** (P2): Output schema validation in GET SSE path — `forward_get_to_upstream` now calls `scan_sse_events_for_output_schema()` and blocks invalid structuredContent.
- **FIND-R45-008** (P2): Gateway mode GET /mcp rejection — GET handler now returns 501 Not Implemented in gateway mode (backend selection requires tool-based routing, not available for SSE resumption).
- **FIND-R45-009** (P3): Session touch in GET handler — `handle_mcp_get` now calls `session.touch()` to update activity timestamp and increment `request_count`.
- **FIND-R45-010** (P3): Last-Event-ID error messages genericized — control char and oversized event ID errors now return "Invalid request" instead of detailed messages.
- **FIND-R45-011** (P2): DoS via repeated GET connections — mitigated by session touch + request_count tracking (enables rate limiting integration).
- **FIND-R45-013** (P3): Error message normalization — GET handler now uses JSON-RPC format and generic messages consistent with POST path ("Method not allowed" instead of "GET /mcp not supported (resumability disabled)").
- **FIND-R45-014** (P3): Request count increment — covered by session.touch() fix (FIND-R45-009).
- 6 new tests for R45 findings. Error responses normalized to JSON-RPC format.

#### Phase 29 — Cross-Transport Smart Fallback
- **Transport health tracker** (`vellaveto-http-proxy/src/proxy/transport_health.rs`) — per-transport circuit breaker keyed by `(upstream_id, TransportProtocol)` with Closed/Open/HalfOpen state machine, exponential backoff (2^trip_count, max 32x), RwLock fail-closed semantics. API: `can_use()`, `record_success()`, `record_failure()`, `available_transports()`, `summary()`, `reset()`.
- **Smart fallback chain** (`vellaveto-http-proxy/src/proxy/smart_fallback.rs`) — ordered transport fallback orchestrator (gRPC → WebSocket → HTTP → stdio). Per-attempt and total timeout budgets, transport-specific dispatch (HTTP POST, WebSocket one-shot via tokio-tungstenite, gRPC HTTP bridge, stdio subprocess). Circuit breaker integration skips Open transports.
- **Transport priority resolution** (`vellaveto-http-proxy/src/proxy/discovery.rs`) — `resolve_transport_priority()` with 4-level resolution: per-tool glob overrides → client `mcp-transport-preference` header → config `upstream_priorities` → default `[Grpc, WebSocket, Http]`. Restricted transports filtered in all paths.
- **Fallback audit types** (`vellaveto-types/src/transport.rs`) — `TransportAttempt` (protocol, endpoint, success, duration, error) and `FallbackNegotiationHistory` (attempts, successful_transport, total_duration) for full audit trail of fallback negotiations.
- **Smart fallback config** (`vellaveto-config/src/transport.rs`) — `cross_transport_fallback: bool` (default false), `transport_overrides: HashMap<String, Vec<TransportProtocol>>`, circuit breaker threshold/duration, `stdio_fallback_enabled`/`stdio_command`. Per-backend `transport_urls` in `BackendConfig`.
- **Handler integration** (`vellaveto-http-proxy/src/proxy/handlers.rs`) — smart fallback branch in `handle_mcp_post` gated behind `cross_transport_fallback` flag. `build_transport_targets()` derives targets from gateway `BackendConfig.transport_urls` or single-server URL derivation.
- **Default off:** `cross_transport_fallback: false` — zero behavioral change without opt-in. Fail-closed: all transports failed → deny.
- 71 new tests across 6 crates. Integration tests in `vellaveto-integration/tests/cross_transport_fallback.rs`.

### Fixed (Adversarial Hardening — Round 41: Phase 29)
- **FIND-R41-001** (Critical): Header allowlist for upstream proxy — `dispatch_http` now filters forwarded headers through `FORWARDED_HEADERS` allowlist (content-type, accept, user-agent, traceparent, tracestate, x-request-id) preventing cookie/auth header leakage to upstream servers.
- **FIND-R41-002** (High): Shell injection in stdio fallback — replaced `sh -c <command>` with direct `Command::new(command)`, added config validation requiring absolute paths with no shell metacharacters.
- **FIND-R41-003** (High): Unbounded circuit breaker state — `TransportHealthTracker` capped at `MAX_TRACKED_CIRCUITS = 10,000` entries with fail-closed (Open) for new circuits at capacity.
- **FIND-R41-004** (High): Unbounded HTTP response body — added `MAX_RESPONSE_BODY_BYTES = 16MB` limit in `dispatch_http` and `MAX_STDERR_BYTES = 4096` in `dispatch_stdio`.
- **FIND-R41-006** (High): Zombie stdio processes on timeout — restructured `dispatch_stdio` with `tokio::select!` to call `child.kill().await` on timeout branch instead of leaking the process.
- **FIND-R41-007** (Medium): Unbounded execution graph — `ExecGraph::add_node` capped at `MAX_NODES_PER_GRAPH = 50,000` with skip-and-warn on overflow.
- **FIND-R41-008** (Medium): URL scheme mismatch in gateway — `BackendConfig::validate` now checks URL schemes match transport protocol (http/https for HTTP/gRPC, ws/wss for WebSocket).
- **FIND-R41-009** (Medium): Unbounded transport overrides map — `TransportConfig::validate` rejects >100 entries in `transport_overrides`.
- **FIND-R41-010** (Medium): Discarded stdio stderr — `dispatch_stdio` now captures stderr via `Stdio::piped()` and includes it in error diagnostics.
- **FIND-R41-011** (Medium): Log injection via control chars — `validate_field` in deputy/NHI routes now rejects ALL control characters (including `\n`, `\t`) to prevent log injection.
- **FIND-R41-014** (Medium): Glob key validation — transport override glob keys validated for max length (256), empty key, and null byte content.
- 7 new tests for config validation (stdio path, metacharacters, override bounds, glob keys, URL schemes).

### Fixed (Adversarial Hardening — Round 43)
- **FIND-R43-001** (High): Stdio pipe deadlock — restructured `dispatch_stdio` to read stdout concurrently with `child.wait()` via `tokio::join!`, preventing deadlock on >64KB subprocess output.
- **FIND-R43-002** (High): Stdio environment inheritance — added `.env_clear()` with minimal safe variables (PATH, HOME, LANG) to prevent secret leakage to subprocess.
- **FIND-R43-003** (High): Smart fallback bypasses response inspection — documented as known limitation; status code validation added (FIND-R43-013) as immediate mitigation.
- **FIND-R43-004** (High): Open→HalfOpen bypass via stale success — `record_success` in Open state now discards the signal instead of transitioning, forcing recovery only through `can_use()` after `open_duration_secs`.
- **FIND-R43-005** (High): Merkle leaf file pruning — `list_rotated_files()` now excludes `.merkle-leaves` and `.rotation-manifest.jsonl` files; `prune_rotated_files()` also deletes companion Merkle leaf files.
- **FIND-R43-006** (High): Unbounded trust collections — `AgentTrustGraph` now enforces `MAX_REGISTERED_AGENTS=10,000`, `MAX_TRUSTED_AGENTS=1,000`, `MAX_TRUST_EDGES=50,000`, `MAX_TRUST_TARGETS_PER_AGENT=1,000`.
- **FIND-R43-007** (High): NHI terminal state bypass — `update_status()` now rejects transitions from Revoked/Expired states, enforcing them as terminal.
- **FIND-R43-008** (Medium): Subprocess orphan — added `.kill_on_drop(true)` to stdio `Command` builder.
- **FIND-R43-009** (Medium): Gateway counter overflow — `consecutive_successes` and `consecutive_failures` now use `saturating_add(1)`.
- **FIND-R43-010** (Medium): success_count overflow — replaced `+= 1` with `saturating_add(1)` consistent with failure_count.
- **FIND-R43-012** (Medium): 5xx recorded as success — smart fallback now calls `record_failure` for status >= 500 and continues to next transport.
- **FIND-R43-013** (Medium): Dangerous status codes forwarded — smart fallback now maps 3xx, <200, and 407 to 502 Bad Gateway.
- **FIND-R43-014** (Medium): WebSocket URL replace-all — changed to prefix-only scheme replacement.
- **FIND-R43-015** (Medium): Edges to non-existent nodes — `add_data_flow()`/`add_delegation()` now validate both endpoints exist in graph.
- **FIND-R43-016** (Medium): Duplicate edges — edge deduplication before push prevents budget exhaustion.
- **FIND-R43-017** (Medium): Manifest references pruned files — `verify_across_rotations()` now skips missing files with info log instead of failing.
- **FIND-R43-018** (Medium): cleanup() never called — `AgentTrustGraph::record_request()` now triggers opportunistic cleanup every 1000 calls.
- **FIND-R43-019** (Medium): Unicode format char bypass — `validate_field`/`validate_string_field` now reject ZWSP, bidi overrides, BOM, and other invisible Unicode characters.
- **FIND-R43-020** (Medium): NHI delegation TOCTOU — `create_delegation()` restructured to hold single write lock for capacity check + insert.
- **FIND-R43-021** (Medium): NHI body fields unvalidated — added validation for `tool_call`, `source_ip`, `new_public_key`, `new_key_algorithm`, `trigger`, `agent_id`.
- **FIND-R43-022** (Medium): Match-all glob bypass — extended wildcard rejection from exact `"*"` to any pattern consisting entirely of `*` and `?` characters.
- **FIND-R43-023** (Medium): URL-encoded %40 bypass — `extract_host_from_url` now also strips `%40`-encoded userinfo.
- **FIND-R43-024** (Medium): Case-sensitive self-delegation — changed to `eq_ignore_ascii_case` comparison.
- **FIND-R43-026** (Low): WebSocket body mutation — replaced `from_utf8_lossy` with `from_utf8` that returns error on invalid data.
- **FIND-R43-027** (Low): trip_count not incremented on Closed→Open — added `saturating_add(1)` for backoff escalation on rapid flapping.
- **FIND-R43-029** (Low): IPv6 gRPC URL — host containing `:` now wrapped in brackets for valid URL.
- **FIND-R43-030** (Low): Self-loop edges — `add_data_flow()`/`add_delegation()` reject `from == to`.
- **FIND-R43-031** (Low): escape_dot incomplete — added pipe `|` escaping and null byte stripping.
- **FIND-R43-032** (Low): Roots vector dedup — guarded push prevents duplicate entries on node overwrites.
- **FIND-R43-033** (Low): NHI self-delegation — `create_nhi_delegation` now rejects `from_agent == to_agent`.
- **FIND-R43-034** (Low): DeputyError info leak — error responses now use generic message; details logged server-side.
- **FIND-R43-035** (Low): Circular detection self-ref — `detect_privilege_escalation` now catches `from_agent == to_agent`.
- Config agent fixes: `stdio_command` validated when disabled, UTF-8 safe gateway truncation, `restricted_transports` duplicate check, backend ID length/character validation, tool prefix uniqueness/empty/length validation.
- 18 new config tests + 1 updated rotation test across 3 crates.

### Fixed (Adversarial Hardening — Round 44)
- **FIND-R44-001** (P2): Stale `half_open_in_flight` with no timeout recovery — added `half_open_in_flight_since` timestamp field and `HALF_OPEN_PROBE_TIMEOUT_SECS = 60` constant; stale probes auto-cleared in `can_use()`.
- **FIND-R44-002** (P2): `available_transports()` consumes probe slot as hidden side effect — added `peek_available_transports()` read-only query method using read lock only.
- **FIND-R44-003** (P2): `forward_with_fallback` retries oversize responses (11x16MB bandwidth amplification) — changed to immediate `Err` on body-too-large instead of `continue`.
- **FIND-R44-004** (P3): Fragment `#` in URL causes host extraction discrepancy — strip fragment before authority parsing in `extract_host_from_url`.
- **FIND-R44-005** (P3): `stdio_command` missing null byte validation — reject `\0` in `stdio_command` even when `stdio_fallback_enabled` is false (validate-on-store, not validate-on-use).
- **FIND-R44-006** (P3): URL scheme validation case-sensitive in `gateway.rs` — `to_ascii_lowercase()` before scheme comparison per RFC 3986 Section 3.1.
- **FIND-R44-007** (P3): Glob key allows ASCII control characters — reject all control chars (0x00–0x1F, 0x7F) in `transport_overrides` keys to prevent log injection.
- **FIND-R44-008** (P3): `escape_dot` bidi override stripping — single-pass rewrite with Unicode bidi character removal (U+200E-200F, U+202A-202E, U+2066-2069).
- 13 new adversarial tests across 3 crates.

### Fixed (Adversarial Hardening — Round 42)
- **FIND-R42-002** (High): Transport preference header DoS — `parse_transport_preference` now deduplicates and caps at 4 entries (one per protocol variant), preventing unbounded Vec from malicious `mcp-transport-preference` headers.
- **FIND-R42-003** (High): URL host parser SSRF — `extract_host_from_url` now strips userinfo (`user:pass@host`) via `rfind('@')` to prevent @-smuggling, and handles IPv6 addresses in brackets (`[::1]:8080`).
- **FIND-R42-020** (High): Unbounded response body in fallback — `forward_with_fallback` now reads response body in chunks with `MAX_RESPONSE_BODY_BYTES = 16MB` bound (matching `smart_fallback.rs`).
- **FIND-R42-005** (Medium): Circuit breaker bypass at capacity — `can_use()` now returns `Err` for unknown circuits when tracker is at capacity, preventing untracked requests from bypassing fail-closed semantics.
- **FIND-R42-006** (Medium): Exec graph metadata leak — `ExecutionGraph::add_node` now checks `MAX_NODES_PER_GRAPH` bound BEFORE updating metadata (`total_calls`, `unique_tools`, `unique_agents`, parent `children`).
- **FIND-R42-007** (Medium): Agent trust graph session exhaustion — `AgentTrustGraph::record_request` now enforces `MAX_TRACKED_SESSIONS = 10,000` to prevent unbounded memory growth from unique session IDs.
- **FIND-R42-008** (Medium): Backend URL scheme validation — `GatewayConfig::validate` now requires `backend.url` to use `http://` or `https://` scheme (previously only validated non-empty).
- **FIND-R42-009** (Medium): Wildcard glob override shadowing — `TransportConfig::validate` rejects `"*"` wildcard in `transport_overrides` when other patterns exist, since lexicographic sort makes `"*"` match first and shadow all specific overrides.
- **FIND-R42-010** (Medium): Half-open thundering herd — `TransportHealthTracker` now tracks `half_open_in_flight` per circuit, allowing only one concurrent probe request in HalfOpen state.
- **FIND-R42-011** (Medium): DOT language injection — `ExecutionGraph::to_dot()` now escapes all user-controlled strings (node IDs, tool names, function names) via `escape_dot()` to prevent injection of DOT constructs.
- **FIND-R42-012** (Low): Failure count overflow — `failure_count += 1` replaced with `saturating_add(1)` in both Closed and Open branches of `record_failure`.
- **FIND-R42-013** (Low): Duplicate protocols in overrides — `TransportConfig::validate` rejects duplicate protocols within `transport_overrides` values.
- **FIND-R42-014** (Low): Clock error logging — `now_secs()` now logs `tracing::error!` when system clock is before Unix epoch instead of silently returning 0.
- **FIND-R42-015** (Low): Duplicate upstream priorities — `TransportConfig::validate` rejects duplicate protocols in `upstream_priorities`.
- **FIND-R42-016** (Low): Path parameter validation — `remove_delegation`, `get_nhi_agent`, and all NHI path-based endpoints now validate path parameter length and content.
- **FIND-R42-017** (Low): Rotation manifest chain linking — manifest entries now include `start_hash` (prev_hash of first entry) for cross-rotation segment verification.
- **FIND-R42-018** (Low): Self-delegation rejection — `register_delegation` now rejects `from_principal == to_principal`.
- 17 new tests across 4 crates (discovery, transport_health, exec_graph, config).

#### Phase 25.1 — Audio Metadata Inspection (WAV + MP3)
- **WAV LIST/INFO chunk parser** (`extract_text_from_wav`) — walks RIFF container for INFO sub-chunks (INAM, IART, ICMT, IGNR, ISFT), extracts null-terminated text, bounded at 200 sub-chunks and 1MB aggregate text.
- **MP3 ID3v2 tag parser** (`extract_text_from_mp3`) — parses ID3v2.3/2.4 headers with syncsafe integer decoding, extracts text from TIT2, TPE1, TALB, COMM, USLT, TXXX frames. Supports 4 encodings: ISO-8859-1, UTF-16 with BOM, UTF-16BE, UTF-8. Bounded at 200 frames and 1MB aggregate.
- **Audio extraction wired into `scan_content()`** — extracted text feeds into existing `scan_text_for_injection()` pipeline for injection detection.
- **FLAC/OGG magic bytes** — `fLaC` and `OggS` detected as `ContentType::Audio`.
- 15 new tests.

#### Phase 25.2 — Video Metadata Inspection (MP4 + WebM)
- **MP4 ISO BMFF box walker** (`extract_text_from_mp4`) — traverses ftyp → moov → udta → meta → ilst for iTunes-style metadata (©nam, ©ART, ©cmt, ©des) and legacy QuickTime format. Bounded at 500 boxes, 10 nesting levels, 1MB aggregate text.
- **WebM EBML tag parser** (`extract_text_from_webm`) — parses variable-length element IDs/sizes (VINT encoding), walks Segment → Tags → Tag → SimpleTag to extract TagString values. Bounded at 200 elements per level and 1MB aggregate text.
- **Video extraction wired into `scan_content()`** — extracted text feeds into injection detection pipeline.
- **MP4/WebM/AVI magic bytes** — ftyp at offset 4 → Video, EBML header `\x1A\x45\xDF\xA3` → Video, RIFF....AVI → Video.
- 12 new tests.

#### Phase 25 — Multimodal Enforcement & Fuzz Targets
- **Per-content-type size limits** — `max_audio_size` (50MB default), `max_video_size` (100MB default) in `MultimodalConfig`. Image/PDF keep `max_image_size`. Fail-closed on oversize.
- **Blocked content types** — `blocked_content_types` field rejects specified types before scanning (priority over `content_types`). Returns `MultimodalError::BlockedContentType`.
- **Fuzz targets for audio/video** — `fuzz_audio_metadata` and `fuzz_video_metadata` exercise WAV/MP3/MP4/WebM parsers with arbitrary bytes. Total fuzz targets: 24.
- 9 new tests for enforcement policies (blocked types, per-type size limits, config defaults).

#### Phase 25.6 — Stateless Protocol Abstraction
- **`RequestContext` trait** (`vellaveto-types/src/identity.rs`) — abstracts session state access for policy evaluation. Methods: `call_counts()`, `previous_actions()`, `call_chain()`, `agent_identity()`, `session_guard_state()`, `risk_score()`. Default `to_evaluation_context()` builder populates `EvaluationContext` from any implementor.
- **`StatelessContextBlob` struct** — signed per-request context for future stateless HTTP mode (MCP June 2026). Carries agent_id, call_counts, recent_actions, call_chain, risk_score, issued_at timestamp, and HMAC-SHA256 signature. 5-minute expiry. Implements `RequestContext`.
- **`StatefulContext` adapter** (`vellaveto-http-proxy/src/session.rs`) — wraps `&SessionState` to implement `RequestContext`, zero-cost migration for existing stateful code.
- 8 new tests.

#### Phase 33 — Formal Verification (TLA+/Alloy)
- **TLA+ policy engine specification** (`formal/tla/MCPPolicyEngine.tla`) — state machine modeling `PolicyEngine::evaluate_action` with 6 safety invariants (fail-closed default, priority ordering, blocked-paths-override, blocked-domains-override, errors-produce-deny, missing-context-deny) and 2 liveness properties (eventual verdict, no stuck states).
- **TLA+ ABAC forbid-overrides specification** (`formal/tla/AbacForbidOverrides.tla`) — models `AbacEngine::evaluate` with 4 safety invariants: forbid dominance, forbid ignores priority, permit-only-without-forbid, no-match result.
- **TLA+ shared operators** (`formal/tla/MCPCommon.tla`) — abstract pattern matching, policy sorting predicate, path/domain rule checking operators.
- **Alloy capability delegation model** (`formal/alloy/CapabilityDelegation.als`) — models capability token delegation with 6 assertions: monotonic attenuation, transitive attenuation across chains, depth budget, temporal monotonicity, terminal-cannot-delegate, issuer chain integrity.
- **TLC model checker configs** for both TLA+ specs with small-bound verification (3 policies, 2 actions).
- **19 verified properties total** (16 safety + 3 liveness), each mapped to exact source locations in the Rust codebase.
- First formal model of MCP policy enforcement in any framework (TLA+, Alloy, Lean, Coq) — addresses Gap #1 from `docs/MCP_SECURITY_GAPS.md`.

#### Phase 28 — Distributed Tracing & Observability
- **W3C Trace Context propagation** (`vellaveto-http-proxy/src/proxy/trace_propagation.rs`) — `extract_trace_context()` parses `traceparent`/`tracestate` headers per W3C Trace Context spec. Generates new trace context when missing (fail-open for observability). `inject_trace_headers()` adds headers to upstream requests.
- **TraceContext helpers** (`vellaveto-audit/src/observability/mod.rs`) — `TraceContext::parse_traceparent()` with strict validation (version-00, 32-char trace_id, 16-char span_id, hex-only), `child()` for child span generation with random span IDs, `with_vellaveto_verdict()` for injecting verdict into tracestate, `with_parsed_tracestate()`, `ensure_trace_id()`.
- **SpanKind::Gateway** — new span kind for gateway-specific trace spans in multi-backend routing.
- **HTTP handler integration** (`vellaveto-http-proxy/src/proxy/handlers.rs`) — incoming trace context extracted from request headers, Vellaveto verdict appended to tracestate, trace headers injected into upstream requests. Gateway mode creates per-backend child spans.
- **WebSocket trace context** (`vellaveto-http-proxy/src/proxy/websocket/mod.rs`) — trace context extracted from HTTP upgrade request headers and used for correlating all audit entries during the WebSocket session.
- **gRPC trace propagation** (`vellaveto-http-proxy/src/proxy/grpc/interceptors.rs`) — `extract_grpc_trace_context()` reads `traceparent`/`tracestate` from gRPC metadata, `inject_grpc_trace_context()` adds to outbound metadata. gRPC-to-HTTP fallback generates fresh trace context.
- **A2A trace context** (`vellaveto-mcp/src/a2a/proxy.rs`) — `extract_a2a_trace_context()` reads trace context from A2A message `metadata.traceparent` field.
- **GenAI semantic conventions** (`vellaveto-audit/src/observability/otlp.rs`, `vellaveto-server/src/routes/main.rs`) — `gen_ai.agent.id` attribute on security spans for agent identity correlation in observability platforms.
- **Upstream header injection** (`vellaveto-http-proxy/src/proxy/upstream.rs`) — W3C `traceparent`/`tracestate` headers injected into upstream HTTP requests.

#### Phase 27 — Kubernetes-Native Deployment
- **Leader election trait** (`vellaveto-cluster/src/leader.rs`) — `LeaderElection` async trait with `acquire()`, `renew()`, `release()`, `is_leader()`, `leader_info()` methods for pluggable leader election backends.
- **Local leader election** (`vellaveto-cluster/src/leader_local.rs`) — `LocalLeaderElection` implementation (always-leader) for single-instance standalone deployments.
- **Service discovery trait** (`vellaveto-cluster/src/discovery.rs`) — `ServiceDiscovery` async trait with `discover()`, `watch()`, `register()`, `deregister()` methods for pluggable service discovery backends.
- **Static service discovery** (`vellaveto-cluster/src/discovery_static.rs`) — `StaticServiceDiscovery` with explicit endpoint list for known topologies.
- **DNS service discovery** (`vellaveto-cluster/src/discovery_dns.rs`) — `DnsServiceDiscovery` with tokio `lookup_host` resolution and periodic refresh via `watch()`.
- **Deployment types** (`vellaveto-types/src/deployment.rs`) — `DeploymentMode`, `LeaderElectionConfig`, `ServiceDiscoveryConfig`, `LeaderStatus`, `ServiceEndpoint`, `DeploymentInfo` types.
- **Deployment config** (`vellaveto-config/src/deployment.rs`) — `DeploymentConfig` with mode, leader election, service discovery, and instance ID settings. Validation: instance_id max length 253, RFC 1123 characters, dot-only rejection.
- **Deployment API endpoint** (`vellaveto-server/src/routes/deployment.rs`) — `GET /api/deployment/info` returns deployment mode, leader status, and discovered endpoints.
- **Health endpoint extensions** (`vellaveto-server/src/routes/main.rs`) — `/health` response includes `leader_status`, `instance_id`, and `discovered_endpoints` fields (omitted in standalone mode). FIND-P27-001: uses cached values (never calls `discover()` from `/health`).
- **Deployment event logging** (`vellaveto-audit/src/events.rs`) — audit event helpers for `leader_election.{acquired,renewed,released,lost,failed}` and `service_discovery.{endpoint_added,endpoint_removed,endpoint_updated,refresh_failed}`.
- **Server integration** (`vellaveto-server/src/main.rs`, `vellaveto-server/src/lib.rs`) — leader election and service discovery bootstrapped at server startup with `DeploymentConfig` validation.
- **Helm chart v4.0.0** (`helm/vellaveto/`) — StatefulSet with PVC for audit log persistence, init container for volume permissions, log-shipping sidecar (Fluent Bit), headless Service for DNS-based discovery, gRPC and WebSocket port exposure, configurable deployment mode, and deployment config in ConfigMap.
- ~45 new tests across `vellaveto-types`, `vellaveto-config`, `vellaveto-audit`, `vellaveto-cluster`, and `vellaveto-server`.

### Fixed (Adversarial Hardening — Round 1)
- **P0-1/P0-2**: Moved TLC record definitions to `MC_*.tla` model companion modules (TLC `.cfg` parser cannot handle set-of-record literals).
- **P0-3**: Removed `SafetyFailClosed` operator that used primed variables in state predicate (invalid for TLC invariant checking).
- **P0-4**: Replaced tautological `InvariantS1_FailClosed` (was `TRUE`) with real fail-closed invariant: no-match implies Deny.
- **P0-5**: Fixed Alloy `minus` → `sub` (correct Alloy integer subtraction function).
- **P0-6**: Fixed Alloy module-level `let MAX_DEPTH = 4` → `fun MAX_DEPTH : one Int { 3 }`.
- **P1-1**: Fixed S3/S4 invariants to restrict blocked-path/domain check to first matching policy only (first-match-wins semantics).
- **P1-2**: Reformulated S5 invariant — Allow verdicts require a matching Allow policy (previously failed when prior evaluations produced Allow).
- **P1-6**: Removed weak fairness on `HandleError` — errors are possible but don't preempt normal evaluation.
- **P1-7**: Fixed Alloy `add` → `plus` for integer addition.
- **P1-8**: Reduced Alloy `MAX_DEPTH` from 4→3, increased scope from 5→7 tokens so S13 (depth budget) is non-vacuous.
- **P2-3**: Fixed `CheckPathRules`/`CheckDomainRules` to deny on empty targets with configured allowlist (fail-closed R28-ENG-1).
- **P2-7**: Restructured Alloy facts/assertions — structural well-formedness as facts, delegation constraints separated, making S12 (transitive attenuation) a genuine theorem.
- **P3-2**: Added ABAC policy with `conditions=FALSE` to test condition-exclusion logic.
- **P3-4**: Added ABAC liveness property L3 (eventual decision for all pending evaluations).
- Added grant ownership fact (each Grant belongs to exactly one Token).
- Added `FirstMatchIndex` helper operator for correct first-match-wins invariant formulation.
- Documented all known abstraction gaps in `formal/README.md`.

## [4.0.0-dev] — Phase 26: Shadow AI Detection & Governance Visibility (2026-02-15)

### Added
- **Shadow AI Discovery Engine** (`vellaveto-mcp/src/shadow_ai_discovery.rs`): Passive traffic analysis detects unregistered agents, unapproved tools, and unknown MCP servers with bounded tracking (max 1000/500/100 entities)
- **Governance Types** (`vellaveto-types/src/governance.rs`): `EnforcementMode`, `UnregisteredAgent`, `UnapprovedTool`, `UnknownMcpServer`, `ShadowAiReport`
- **Governance Config** (`vellaveto-config/src/governance.rs`): `GovernanceConfig` with shadow AI discovery, agent registration enforcement, approved tools/servers lists, least agency enforcement mode, auto-revocation window
- **Governance API** (`vellaveto-server/src/routes/governance.rs`): `GET /api/governance/shadow-report`, `/unregistered-agents`, `/unapproved-tools`, `/least-agency/{agent_id}/{session_id}`
- **Least Agency Enforcement** (`vellaveto-engine/src/least_agency.rs`): `new_with_config()` constructor with `EnforcementMode`, `check_auto_revoke()` method with per-permission `last_used` tracking
- **Audit Events** (`vellaveto-audit/src/events.rs`): `log_shadow_ai_discovery_event()` and `log_least_agency_event()` helpers for governance audit trail
- **Dashboard Governance Section** (`vellaveto-server/src/dashboard.rs`): Unregistered agents table with risk scores, unapproved tools/unknown servers counters
- 43 new tests across 4 crates (17 shadow_ai_discovery, 8 governance config, 5 least agency enforcement, 13 engine)

### Design Decisions
- Passive discovery only — observe traffic, don't scan network
- Bounded tracking prevents memory growth (LRU eviction at capacity)
- `require_agent_registration` enables fail-closed mode for unregistered agents
- `EnforcementMode::Monitor` (default) → safe rollout; `Enforce` → auto-revocation

## [3.0.0] — 2026-02-14

### Added

#### Go SDK
- **Zero-dependency Go client** — stdlib-only (`net/http`, `encoding/json`) HTTP client with full API parity: `Evaluate`, `EvaluateOrError`, `Health`, `ListPolicies`, `ReloadPolicies`, `Simulate`, `BatchEvaluate`, `ValidateConfig`, `DiffConfigs`, `ListPendingApprovals`, `ApproveApproval`, `DenyApproval` (`sdk/go/`).
- Functional options pattern: `WithAPIKey()`, `WithTimeout()`, `WithHTTPClient()`, `WithHeaders()`.
- `context.Context` on all public methods.
- Fail-closed verdict parsing — unknown verdict strings map to `VerdictDeny`.
- Both string and object verdict form parsing (matching Python/TypeScript behavior).
- Typed errors: `VellavetoError`, `PolicyDeniedError`, `ApprovalRequiredError`.
- 28 table-driven tests using `net/http/httptest`.

#### HTTP Proxy Benchmarks
- **35 Criterion benchmarks** for the production hot path (`vellaveto-http-proxy/benches/http_proxy.rs`):
  - Origin validation (5 benchmarks): `is_loopback` variants, `build_loopback_origins`, `extract_authority` (5 URL formats), `validate_origin` (4 scenarios).
  - HMAC operations (7 benchmarks): signing content, compute (small/4KB), verify (valid/invalid), build entry (with/without HMAC).
  - Call chain parsing (4 benchmarks): header extraction with 0/1/5 entries, with/without HMAC.
  - Privilege escalation (4 benchmarks): 0/1/5/10-hop chains.
  - Audit context (3 benchmarks): minimal, with OAuth, with 3-hop chain.
- Made `origin` and `call_chain` modules `pub` (from `pub(super)`) to enable benchmark access.
- All operations sub-microsecond to low-microsecond: origin validation <440ns, HMAC <1.6µs, privilege escalation <76ns.

### Changed

- **Local contributor guide trimmed** — 47,834 bytes → 11,675 bytes (76% reduction). Collapsed the oversized status summary, trimmed the file locations table from ~120 to ~52 rows, and simplified the local coordination guidance to reference `.claude/rules/`.

### Documentation

- **Roadmap v3.0**: Replaced v2.2 roadmap with 12-month v3.0 plan (Q1–Q4 2026) covering 7 phases:
  - Phase 17 (P0): MCP next spec preparation — WebSocket transport (SEP-1288), gRPC transport (Google), async operations (SEP-1391), protocol extensions framework
  - Phase 18 (P0): MCP June 2026 spec compliance — spec delta adoption, SDK tiering, transport negotiation and fallback
  - Phase 19 (P0): Regulatory compliance — EU AI Act Article 50 transparency (Aug 2 2026 deadline), OpenTelemetry GenAI semantic conventions, CoSAI/Adversa AI threat gap closure, SOC 2 Type II audit enhancements
  - Phase 20 (P1): MCP gateway mode — session-aware routing, multi-server tool discovery, health-aware upstream routing, Kubernetes-native StatefulSet deployment
  - Phase 21 (P1): Advanced authorization — Cedar-style ABAC engine, least-agency enforcement, identity federation, continuous authorization
  - Phase 22 (P2): Developer experience — visual execution graph UI, VS Code extension, policy playground, GitHub Action CI gate, SDK ecosystem (Go, Java, TypeScript)
  - Phase 23 (P3): Research — multimodal injection detection, continuous autonomous red teaming, FIPS 140-3 compliance, Sigstore/Rekor transparency logs, stateful session reasoning guards
- Added expanded competitor comparison (Cisco AI Defense, Prisma AIRS, Radware, CalypsoAI, Akamai, Microsoft MCP Gateway)
- Added CoSAI 12-category and Adversa AI TOP 25 threat coverage matrices
- Added updated OWASP ASI Top 10 coverage with v3.0 enhancement mapping
- Added 25-entry research bibliography with links
- Archived all v2.0–v2.2 completed phases (1–15) in collapsible appendix

### Security

#### Phase 23 Adversarial Hardening (Round 2 — Medium Findings)
- **FIND-P23-005**: JPEG stego `get_image_data_region` loop now bounded to `MAX_MARKER_ITERATIONS=500` — prevents infinite loop on malformed JPEG with no SOS marker.
- **FIND-P23-006**: PDF dictionary look-back window increased from 256 to 4096 bytes — correctly detects `/FlateDecode` in large PDF object dictionaries.
- **FIND-P23-007**: `scan_text_for_injection` now normalizes whitespace before scanning — detects injection payloads split across multiple PNG tEXt chunks joined by newlines.
- **FIND-P23-008**: EXIF ASCII string minimum lowered from 8 to 4 characters — catches short injection keywords like "exec", "eval", "sudo".
- **FIND-P23-009**: PDF `extract_pdf_text_operators` now parses hex strings `<...>` in addition to literal strings `(...)` — `<<` dictionary delimiters correctly excluded.
- **FIND-P23-010**: `detect_steganography` documented with comprehensive limitations section (adaptive stego, low-payload evasion, JPEG DCT, false positives, non-LSB methods).
- **8 new integration tests** in `pentest_phase23_hardening.rs` (total 23).

### Added

#### Phase 23: Research & Future (23.1–23.5)
- **Multimodal injection detection (23.1)** — Pure-Rust PNG tEXt/zTXt/iTXt chunk extraction, JPEG COM/EXIF comment extraction, PDF stream/FlateDecode text extraction with Tj/TJ operator parsing, chi-squared LSB steganography detection. No `image`/`pdf`/OCR crates — uses `flate2` for decompression with 10MB zip bomb protection. (`vellaveto-mcp/src/inspection/multimodal.rs`). 12 tests.
- **Continuous autonomous red teaming (23.2)** — `MutationEngine` with 8 mutation types (URL encode, double encode, null byte inject, homoglyph replace, case variation, whitespace inject, parameter alias, context wrapping). `RedTeamRunner` evaluates mutated payloads against `PolicyEngine`, reports `BypassFinding` gaps. `CoverageReport` tracks by category and mutation type. (`vellaveto-mcp/src/red_team.rs`). 15 tests.
- **Red team API** — `POST /api/simulator/red-team` runs mutation engine against server's current policies, returns `RedTeamReport` with bypass findings and coverage gaps.
- **FIPS 140-3 compliance mode (23.3)** — `FipsMode` with approved algorithm list (ECDSA P-256, SHA-256/384/512, AES-256-GCM, HMAC-SHA-256, RSA-PSS) and non-FIPS rejection list (Ed25519, ChaCha20-Poly1305, Blake2, Curve25519). Fail-closed for unknown algorithms. ECDSA P-256 sign/verify via `p256` crate, feature-gated behind `fips`. (`vellaveto-mcp/src/fips.rs`). 12 tests.
- **Sigstore/Rekor transparency log integration (23.4)** — `RekorEntry` types with full serde support. `RekorVerifier` with RFC 6962 domain-separated Merkle tree inclusion proof verification (leaf: `SHA-256(0x00||body)`, interior: `SHA-256(0x01||left||right)`). Offline tool hash matching and full `verify_entry()` combining proof + hash. (`vellaveto-mcp/src/rekor.rs`). 12 tests.
- **Stateful session reasoning guards (23.5)** — Formal state machine (Init→Active→Suspicious→Locked→Ended) with configurable `suspicious_threshold`, `lock_threshold`, `cooldown_secs`. `SessionGuard` integrates `WorkflowAlert` severity mapping and `GoalDriftAlert` similarity-to-severity conversion. Admin unlock, cooldown recovery, session eviction (max_sessions). (`vellaveto-mcp/src/session_guard.rs`). 20 tests.
- **Cross-crate integration** — `FipsConfig` in vellaveto-config with module + `PolicyConfig` field. `rekor_entry: Option<serde_json::Value>` on `ToolSignature` for Rekor provenance. `session_state: Option<String>` on `EvaluationContext` with builder support. `SessionStateRequired` compiled context condition with fail-closed evaluation and policy compilation.
- **74 new tests** across Phase 23 (12 multimodal + 15 red team + 12 FIPS + 12 Rekor + 20 session guard + 3 fips config)

#### Phase 22: Developer Experience (Backend Focus)
- **Policy simulator API** — 4 new endpoints: `POST /api/simulator/evaluate` (single action with trace), `/batch` (up to 100 actions), `/validate` (config validation), `/diff` (policy diff). Supports inline TOML policy configs for sandbox evaluation. (`vellaveto-server/src/routes/simulator.rs`). 9 tests.
- **CLI `simulate` subcommand** — Batch-evaluate actions from a JSON file against a policy config. Supports text table and JSON output formats.
- **GitHub Action `policy-check`** — Composite action that downloads Vellaveto binary and runs `vellaveto check` for CI policy gates. Supports version pinning, strict mode, and text/JSON output. (`.github/actions/policy-check/action.yml`). Example workflow at `examples/github-action-policy-check.yml`.
- **Dashboard SVG charts** — Verdict distribution bar chart (allow/deny/approval) and policy type pie chart (Allow/Deny/Conditional) rendered as inline SVG in the admin dashboard. 4 tests.
- **TypeScript SDK** — Zero runtime dependency HTTP client using native `fetch()` (Node 18+). Full API parity with Python SDK: `evaluate`, `health`, `listPolicies`, `reloadPolicies`, `simulate`, `batchEvaluate`, `validateConfig`, `diffConfigs`, `listPendingApprovals`, `approveApproval`, `denyApproval`. Error classes: `VellavetoError`, `PolicyDenied`, `ApprovalRequired`. (`sdk/typescript/`). 15 Jest tests.

#### Phase 20: MCP Gateway Mode (20.1–20.3)
- **Gateway types** — `BackendHealth` (Healthy/Degraded/Unhealthy), `UpstreamBackend`, `RoutingDecision`, `ToolConflict` in leaf crate (`vellaveto-types/src/gateway.rs`). 3 tests.
- **Gateway configuration** — `GatewayConfig` with backend list, health check interval/thresholds, `BackendConfig` with tool prefixes and weights (`vellaveto-config/src/gateway.rs`). Added to `PolicyConfig` with `#[serde(default)]`. Validation for duplicate IDs, zero weights, interval bounds, multiple defaults. 5 tests.
- **Gateway router** — `GatewayRouter` with longest-prefix-first tool name matching, configurable unhealthy/healthy thresholds, `route_with_affinity()` for session-sticky routing, fail-closed when all backends unhealthy (`vellaveto-http-proxy/src/proxy/gateway.rs`). 30 tests.
- **Health state machine** — Healthy→Unhealthy after `unhealthy_threshold` consecutive failures; Unhealthy→Degraded (1 success) →Healthy (`healthy_threshold` successes). Degraded backends remain routable.
- **Health checker background task** — Periodic JSON-RPC `ping` to each backend with 5s timeout. Updates `vellaveto_gateway_backends_total` and `vellaveto_gateway_backends_healthy` gauge metrics.
- **Handler wiring** — ToolCall match arm in `handle_mcp_post()` routes via gateway when `ProxyState.gateway` is `Some`. Records success/failure from HTTP response status.
- **`forward_to_upstream_url()`** — Extracted URL parameter from `forward_to_upstream()` enabling gateway routing without rewriting the 808-line forwarding function.
- **WebSocket gateway** — Default backend resolution for new WS connections; closes with 1008 if no healthy backend.
- **gRPC gateway** — Default backend resolution for HTTP fallback forwarding.
- **Tool conflict detection** — `detect_conflicts()` builds tool→backends map, returns entries served by multiple backends.
- **Session state** — `backend_sessions: HashMap<String, String>` and `gateway_tools: HashMap<String, Vec<String>>` for session affinity and tool discovery tracking.
- **38 new tests** across 4 files (3 types + 5 config + 30 router)

#### Phase 18: MCP June 2026 Spec Compliance
- **Transport & SDK tier types** — `TransportProtocol` (Grpc/WebSocket/Http/Stdio), `TransportEndpoint`, `SdkTier` (Core/Standard/Extended/Full), `SdkCapabilities` in leaf crate (`vellaveto-types/src/transport.rs`). 4 tests.
- **Transport configuration** — `TransportConfig` with `discovery_enabled`, `upstream_priorities`, `restricted_transports`, `advertise_capabilities`, `max_fallback_retries`, `fallback_timeout_secs` (`vellaveto-config/src/transport.rs`). Added to `PolicyConfig` with `#[serde(default)]`. Validation for bounds and conflict detection. 4 tests.
- **Transport discovery endpoint** — `GET /.well-known/mcp-transport` returns JSON with available transports, SDK tier (Extended with 12 capabilities), and supported protocol versions. 404 when `discovery_enabled=false`. (`vellaveto-http-proxy/src/proxy/discovery.rs`)
- **Protocol version `2026-06` placeholder** — Added to `SUPPORTED_PROTOCOL_VERSIONS` (first position) for forward compatibility with upcoming MCP June 2026 spec. All existing versions (2025-11-25, 2025-06-18, 2025-03-26) preserved for backward compatibility.
- **Transport preference negotiation** — `parse_transport_preference()` parses `mcp-transport-preference` header (aliases: ws=websocket, sse=http). `negotiate_transport()` pure logic finds best match respecting restrictions.
- **Upstream fallback foundation** — `forward_with_fallback()` with timeout-based retry for HTTP transport. Cross-transport fallback deferred to Phase 20 (`vellaveto-http-proxy/src/proxy/fallback.rs`).
- **SDK tier CI validation** — `test_sdk_tier_minimum_standard` and `test_extended_tier_required_capabilities` ensure Vellaveto maintains Extended tier (`vellaveto-integration/tests/sdk_tier_ci.rs`).
- **Backward compatibility tests** — Verify 2025-03-26, 2025-06-18, 2025-11-25 protocol versions remain supported and HTTP default works without negotiation headers (`vellaveto-integration/tests/transport_negotiation.rs`).
- **25 new tests** across 6 files (4 types + 4 config + 10 proxy + 5 transport integration + 2 SDK CI)

#### Phase 17.3: Async Operations Enhancements (SEP-1391)
- **TaskRequest policy enforcement across all transports** — `TaskRequest` messages (`tasks/get`, `tasks/cancel`, `tasks/resubscribe`, `tasks/send`) now receive full policy evaluation (extract action → evaluate → audit → forward/deny) in HTTP, WebSocket, gRPC, and stdio relay. Previously forwarded without policy checks.
- **`ProgressNotification` message classification** — `notifications/progress` messages classified as `ProgressNotification` variant with `progress_token`, `progress`, and optional `total` fields for future per-transport handling. Currently forwarded as PassThrough.
- **`ExtensionMethod` message classification** — Methods with `x-` prefix classified as `ExtensionMethod` variant with `extension_id` and `method` fields. Policy evaluation enforced on all transports.
- **`extract_extension_action()`** — Converts extension method calls to `Action` for policy evaluation (`vellaveto-mcp/src/extractor.rs`)
- **32+ new tests** across WebSocket, gRPC, HTTP, and extractor test suites

#### Phase 17.4: Protocol Extensions Framework
- **Extension types** — `ExtensionDescriptor`, `ExtensionResourceLimits`, `ExtensionNegotiationResult`, `ExtensionError` in leaf crate (`vellaveto-types/src/extension.rs`). 6 tests.
- **Extension configuration** — `ExtensionConfig` with `enabled`, `allowed_extensions`, `blocked_extensions`, `require_signatures`, `trusted_public_keys`, `default_resource_limits` (`vellaveto-config/src/extension.rs`). Added to `PolicyConfig` with `#[serde(default)]`. 2 tests.
- **Extension registry** — `ExtensionHandler` trait with `on_load`, `on_unload`, `handle_method`, `descriptor` lifecycle hooks. `ExtensionRegistry` with RwLock-based thread-safe registration, glob-based allow/block negotiation, and O(1) method dispatch via `route_method()` (`vellaveto-mcp/src/extension_registry.rs`). 12 tests.
- **Audit query example extension** — `AuditQueryExtension` implementing `ExtensionHandler`, handles `x-vellaveto-audit/stats` method (`vellaveto-mcp/src/extensions/audit_query.rs`). 4 tests.
- **`ProxyState.extension_registry`** — Optional `Arc<ExtensionRegistry>` field for extension method routing across HTTP, WebSocket, and gRPC transports (`vellaveto-http-proxy/src/proxy/mod.rs`)
- All Phase 17 exit criteria now complete (6/6)

#### Phase 19: Regulatory Compliance — Remaining Exit Criteria
- **Compliance dashboard section** — Real-time compliance status in admin dashboard (`vellaveto-server/src/dashboard.rs`) with 4 metric cards (EU AI Act %, SOC 2 Readiness %, Framework Coverage %, Critical Gaps) and a 7-framework coverage table with color-coded thresholds (green >=90%, yellow >=70%, red <70%)
- **EU AI Act Article 50 runtime transparency** — `mark_ai_mediated()` injects `result._meta.vellaveto_ai_mediated = true` into tool-call responses before forwarding to agent (`vellaveto-mcp/src/transparency.rs`). `requires_human_oversight()` checks tool names against configurable glob patterns and logs audit events. ProxyBridge extended with `with_transparency_marking(bool)` and `with_human_oversight_tools(Vec<String>)` builder methods. Art 50(1) status upgraded to Compliant in EU AI Act registry. 11 tests.
- **Immutable audit log archive** — gzip compression of rotated audit log files and retention enforcement (`vellaveto-audit/src/archive.rs`). `compress_rotated_file()` compresses `.log` → `.log.gz` via `flate2`. `enforce_retention()` deletes archives older than configured `retention_days`. `run_archive_maintenance()` combines both in a single pass. Feature-gated behind `archive`. 9 tests.
- **OTLP export with GenAI semantic conventions** — `OtlpExporter` implementing `ObservabilityExporter` trait maps `SecuritySpan` to OpenTelemetry spans (`vellaveto-audit/src/observability/otlp.rs`). GenAI attributes: `gen_ai.system` → `"vellaveto"`, `gen_ai.operation.name` → tool name. Vellaveto attributes: `vellaveto.verdict`, `vellaveto.policy.id`, `vellaveto.detection.type`, `vellaveto.tool.name`. `map_span_kind()` maps Chain→Server, Tool→Internal, Llm→Client. `verdict_to_status()` maps allow→Ok, deny→Error. Feature-gated behind `otlp-exporter`. 11 tests.
- **OtlpConfig** — New configuration type in `vellaveto-config/src/observability.rs` with endpoint, protocol (Grpc/HttpProto), headers, batch_size, flush_interval_secs, max_retries, timeout_secs, service_name. Validation rejects empty endpoints and zero timeouts when enabled. 6 tests.
- **`compress_archives` field** — Added to `EuAiActConfig` in `vellaveto-config/src/compliance.rs` (default: true)
- All Phase 19 exit criteria now complete (9/9)

#### Phase 17.1: WebSocket Transport Support (SEP-1288)
- **WebSocket reverse proxy** — Bidirectional MCP-over-WebSocket at `/mcp/ws` endpoint (`vellaveto-http-proxy/src/proxy/websocket/mod.rs`)
- **Full policy enforcement** — Client→upstream tool calls classified via `classify_message()`, evaluated against policies with fail-closed semantics; engine errors and unknown verdict variants produce Deny
- **Response scanning** — Upstream→client responses scanned for DLP secrets and injection patterns before forwarding
- **TOCTOU-safe canonicalization** — JSON re-serialized before forwarding to prevent time-of-check/time-of-use attacks
- **Per-connection rate limiting** — Sliding window rate limiter (configurable messages/sec, default 100/s) with atomic counter and 1-second window reset
- **Idle timeout** — Configurable inactivity timeout (default 300s) closes stale WebSocket connections
- **Max message size** — Configurable limit (default 1MB) rejects oversized frames with close code 1009
- **Session binding** — Each WebSocket connection bound to exactly one `SessionState` via query parameter or auto-created
- **Binary frame rejection** — Non-text frames rejected with close code 1003 (Unsupported Data)
- **Unparseable message rejection** — Invalid JSON or unclassifiable messages rejected with close code 1008 (Policy Violation)
- **Upstream connection** — `tokio-tungstenite` client with http→ws / https→wss URL scheme conversion and 10s connection timeout
- **Metrics** — `vellaveto_ws_connections_total` and `vellaveto_ws_messages_total` counters with direction labels
- **CLI args** — `--ws-max-message-size`, `--ws-idle-timeout`, `--ws-message-rate-limit`
- **WebSocketConfig** — New config struct in `ProxyState` for WebSocket transport parameters
- **29 unit tests** covering URL conversion, rate limiting, frame classification, error responses, scannable text extraction, config defaults, close codes, metrics, evaluation context, and query params
- **Fuzz target** — `fuzz_ws_frame` for arbitrary bytes → text frame → JSON parse → classify → extract action (21 fuzz targets total)
- **New dependencies**: `tokio-tungstenite = "0.26"` (workspace), `axum` `ws` feature

#### Phase 17.2: gRPC Transport Support
- **gRPC reverse proxy** — Protocol Buffers–based MCP transport on separate port (default 50051) using `tonic` (`vellaveto-http-proxy/src/proxy/grpc/mod.rs`), feature-gated behind `grpc`
- **Protobuf schema** — `proto/mcp/v1/mcp.proto` with `McpService` (Call, StreamCall, Subscribe RPCs) using `google.protobuf.Struct` for dynamic JSON-RPC params/result fields
- **Proto↔JSON conversion** — Bidirectional conversion between prost `Struct` and `serde_json::Value` with depth-bounded recursion (MAX_DEPTH=64) and NaN/Infinity float rejection (`vellaveto-http-proxy/src/proxy/grpc/convert.rs`)
- **Full policy enforcement** — Unary and bidirectional streaming calls classified via `classify_message()`, evaluated against policies with fail-closed semantics; policy denials returned as JSON-RPC errors inside successful gRPC responses (matching HTTP/WS behavior)
- **Auth interceptor** — Constant-time SHA-256 API key validation on gRPC metadata (FIND-008 pattern), returns `UNAUTHENTICATED` status on failure (`vellaveto-http-proxy/src/proxy/grpc/interceptors.rs`)
- **Response scanning** — DLP scanning and injection detection on upstream→client responses before proto conversion
- **gRPC-to-HTTP fallback** — When no upstream gRPC URL configured, converts proto→JSON, POSTs to upstream HTTP URL, converts response back to proto (`vellaveto-http-proxy/src/proxy/grpc/upstream.rs`)
- **gRPC Health Checking v1** — `tonic-health` service registered alongside McpService
- **Coordinated shutdown** — `CancellationToken` shared between HTTP and gRPC servers for graceful shutdown
- **Metrics** — `vellaveto_grpc_requests_total` and `vellaveto_grpc_messages_total` counters with direction labels
- **CLI args** — `--grpc` (enable), `--grpc-port` (default 50051), `--grpc-max-message-size` (default 4MB), `--upstream-grpc-url` (optional)
- **Config type** — `GrpcTransportConfig` in `vellaveto-config/src/grpc_transport.rs` with serde support
- **46 unit tests** covering proto↔JSON conversion (all 6 prost value types, NaN/Infinity, depth limits, roundtrips), config defaults/serde, message classification via proto, session/request-id extraction, error response construction, metadata constants
- **Fuzz target** — `fuzz_grpc_proto` for arbitrary bytes → prost decode → convert → classify (22 fuzz targets total)
- **New workspace dependencies**: `tonic = "0.13"`, `prost = "0.13"`, `prost-types = "0.13"`, `tonic-health = "0.13"`, `tonic-build = "0.13"`, `tokio-util = "0.7"`, `tokio-stream = "0.1"`
- **Zero impact on non-grpc builds** — All code behind `#[cfg(feature = "grpc")]`

#### Merkle Tree Inclusion Proofs (Phase 19.4)
- **Append-only Merkle tree** — Incremental construction with O(log n) peak-based append and RFC 6962 domain separation (`vellaveto-audit/src/merkle.rs`)
- **Domain separation** — `hash_leaf(data) = SHA-256(0x00 || data)`, `hash_internal(l, r) = SHA-256(0x01 || l || r)` prevents second-preimage attacks
- **Inclusion proof generation** — `generate_proof(index)` produces bottom-up sibling path for any leaf in the tree
- **Static proof verification** — `verify_proof(leaf_hash, proof)` verifies without disk access, suitable for external auditors
- **Audit logger integration** — `with_merkle_tree()` builder method; leaf hash appended automatically on each `log_entry()` call
- **Checkpoint integration** — `merkle_root: Option<String>` in `Checkpoint` struct with backward-compatible `signing_content()` (old checkpoints still verify)
- **Log rotation support** — `.merkle-leaves` file renamed alongside rotated log; tree reset for new segment
- **Crash recovery** — `initialize()` rebuilds peaks from existing leaf file after restart
- **24 unit tests** covering empty/single/multi-element trees, proof roundtrips, tampered leaf/sibling/root rejection, logger integration, rotation, crash recovery, domain separation, order dependence

#### Advanced Authorization — ABAC, Least-Agency, Federation, Continuous Auth (Phase 21.1–21.4)
- **ABAC types** — `AbacPolicy`, `AbacEntity`, `AbacEffect` (Permit/Forbid), `AbacOp` (10 operators), `PrincipalConstraint`, `ActionConstraint`, `ResourceConstraint`, `AbacCondition`, `RiskScore`, `RiskFactor`, `FederationTrustAnchor`, `IdentityMapping`, `PermissionUsage`, `LeastAgencyReport`, `AgencyRecommendation` (`vellaveto-types/src/abac.rs`)
- **AbacConfig** — `LeastAgencyConfig`, `FederationConfig`, `ContinuousAuthConfig` with validation (policy count bounds MAX_ABAC_POLICIES=512, entity count MAX_ENTITIES=4096, duplicate ID detection, threshold range checks) (`vellaveto-config/src/abac.rs`)
- **AbacEngine** — Compiled ABAC policies with pre-compiled pattern matchers, forbid-overrides evaluation (any forbid wins over all permits, Cedar semantics), `AbacDecision::Allow/Deny/NoMatch` (`vellaveto-engine/src/abac.rs`)
- **EntityStore** — In-memory entity store with transitive group membership lookup (bounded depth=16), `from_entities()` constructor
- **Condition evaluation** — 10 comparison operators (Eq, Ne, In, NotIn, Contains, StartsWith, Gt, Lt, Gte, Lte) evaluated against action parameters
- **Two-phase evaluation** — PolicyEngine runs first (coarse filter), AbacEngine refines Allow verdicts; if PolicyEngine says Deny, ABAC doesn't run
- **LeastAgencyTracker** — Per-agent-session permission usage tracking with `register_grants()`, `record_usage()`, `check_unused()`, `generate_report()`, `recommend_narrowing()` (`vellaveto-engine/src/least_agency.rs`)
- **4-tier recommendation system** — Optimal (>80%), ReviewGrants (50–80%), NarrowScope (20–50%), Critical (<20% usage ratio)
- **Identity federation** — `FederationTrustAnchor` with JWKS URI, issuer patterns, `IdentityMapping` (external JWT claims → internal principal via id_template)
- **Continuous authorization** — `ContinuousAuthConfig` with `risk_threshold`, `degradation_threshold`, `reevaluation_interval_secs`; `RiskScore` with weighted `RiskFactor` list
- **Transport wiring** — ABAC refinement integrated across HTTP handlers, WebSocket, and gRPC transports; deny with audit trail when forbid matches
- **ProxyState extended** — `abac_engine: Option<Arc<AbacEngine>>`, `least_agency: Option<Arc<LeastAgencyTracker>>`, `continuous_auth_config: Option<ContinuousAuthConfig>`
- **SessionState extended** — `risk_score: Option<RiskScore>`, `abac_granted_policies: Vec<String>`
- **Full backward compatibility** — `abac.enabled = false` (default) makes behavior identical to pre-Phase 21
- **~49 new tests** — 5 types + 6 config + 27 engine + 8 least-agency + 3 proxy wiring
- **No new dependencies** — Reuses existing serde, glob matchers, HashMap from workspace

#### Capability-Based Delegation Tokens (Phase 21.0)
- **CapabilityToken type** — Ed25519-signed tokens with delegation chain, depth budget, grants, and expiry (`vellaveto-types/src/capability.rs`)
- **CapabilityGrant** — Tool/function glob patterns with path and domain constraints and invocation limits
- **Token issuance** — `issue_capability_token()` creates root tokens with Ed25519 signature over length-prefixed canonical content (`vellaveto-mcp/src/capability_token.rs`)
- **Monotonic attenuation** — `attenuate_capability_token()` enforces: depth decrements, grants must be subset of parent, expiry clamped to parent's expiry; escalation rejected
- **Token verification** — `verify_capability_token()` validates signature, expiry, and holder match
- **Grant coverage** — `check_grant_coverage()` matches token grants against `Action` tool/function/paths/domains with glob support
- **RequireCapabilityToken policy condition** — Fail-closed evaluation in `vellaveto-engine/src/context_check.rs`; missing token = Deny, invalid holder/issuer = Deny, insufficient depth = Deny
- **Policy compilation** — `require_capability_token` condition compiled in `vellaveto-engine/src/policy_compile.rs` with `required_issuers`, `min_remaining_depth`, and `deny_reason`
- **EvaluationContext extended** — `capability_token: Option<CapabilityToken>` field added to `vellaveto-types/src/identity.rs` with builder support
- **Structural validation** — `validate_structure()` enforces MAX_GRANTS=64, MAX_DELEGATION_DEPTH=16, MAX_TOKEN_SIZE=65536, rejects empty fields
- **31 unit tests** — 4 types tests (serde, validation), 5 engine tests (context condition), 22 mcp tests (sign/verify, attenuation, grant coverage, expiry, holder/issuer mismatch)
- **No new dependencies** — Reuses ed25519-dalek, hex, serde already in workspace

#### CoSAI/Adversa Threat Coverage Registries (Phase 19.3)
- **CoSAI 12-category threat registry** — 38 threats across all 12 Coalition for Secure AI categories with `VellavetoDetection` runtime mappings and structural mitigation coverage (`vellaveto-audit/src/cosai.rs`)
- **Adversa AI TOP 25 coverage matrix** — All 25 ranked MCP vulnerabilities (Critical/High/Medium) with detection mappings and mitigation tracking (`vellaveto-audit/src/adversa_top25.rs`)
- **Cross-framework gap analysis** — Unified report across 7 frameworks (MITRE ATLAS, NIST AI RMF, ISO 27090, EU AI Act, CoSAI, Adversa TOP 25, ISO 42001) with weighted-average coverage, identified gaps, and recommendations (`vellaveto-audit/src/gap_analysis.rs`)
- **Threat coverage API endpoint** — `GET /api/compliance/threat-coverage` returns ATLAS, CoSAI, and Adversa coverage summaries
- **Gap analysis API endpoint** — `GET /api/compliance/gap-analysis` returns consolidated 7-framework gap report
- **100% CoSAI coverage** (38/38 threats across 12/12 categories), **100% Adversa TOP 25 coverage** (25/25 vulnerabilities)
- **35 unit tests** — 14 CoSAI (registry, categories, detection mappings, coverage report, serde), 14 Adversa (registry, ranks, mitigations, matrix, serde), 7 gap analysis (generation, framework presence, coverage threshold, recommendations, serde)
- **No new dependencies** — Reuses serde, chrono, HashMap from existing audit crate

#### Compliance Evidence Generation (Phase 19.1 / 19.4)
- **Shared compliance types** — `AiActRiskClass` (Minimal/Limited/HighRisk/Unacceptable) and `TrustServicesCategory` (CC1-CC9) in `vellaveto-types/src/compliance.rs` (leaf crate, no dependency violations)
- **ComplianceConfig** — `EuAiActConfig` and `Soc2Config` with validation (MAX_HUMAN_OVERSIGHT_TOOLS=500, MIN_RETENTION_DAYS=30, MAX_SOC2_CATEGORIES=9) (`vellaveto-config/src/compliance.rs`)
- **EU AI Act registry** — `EuAiActRegistry` with 10 obligations (Art 5, 6, 9, 12, 13, 14, 15, 43, 50(1), 50(2)) and 18 capability mappings across `TransparencyCapability` enum (`vellaveto-audit/src/eu_ai_act.rs`)
- **EU AI Act conformity assessment** — `generate_assessment(risk_class, deployer_name, system_id)` produces `ConformityAssessmentReport` with compliance percentage, applicable/compliant/partial articles
- **EU AI Act entry classification** — `classify_entry_transparency()` classifies audit entries at read-time into transparency records
- **SOC 2 registry** — `Soc2Registry` with 22 criteria across CC1-CC9 and ~30 capability mappings with `ReadinessLevel` (NotStarted through Optimizing, scored 0-5) (`vellaveto-audit/src/soc2.rs`)
- **SOC 2 evidence report** — `generate_evidence_report(org_name, period_start, period_end, tracked_categories)` produces `Soc2EvidenceReport` with overall readiness, scores, and gaps
- **SOC 2 coverage analysis** — `coverage_by_category()` returns per-category coverage with readiness levels
- **SOC 2 entry classification** — `classify_entry()` classifies audit entries at read-time into evidence records
- **Compliance API endpoints** — Three new routes registered in `vellaveto-server`:
  - `GET /api/compliance/status` — Overall compliance posture (EU AI Act + SOC 2 + optional NIST RMF + ISO 27090)
  - `GET /api/compliance/eu-ai-act/report` — Full conformity assessment report per Art 43
  - `GET /api/compliance/soc2/evidence?category=CC1` — SOC 2 evidence collection with optional category filter
- **PolicySnapshot extended** — `compliance_config` field for atomic policy reload with compliance configuration
- **34 unit tests** — 9 config tests (defaults, validation, TOML parsing, serde roundtrip), 11 EU AI Act tests (registry, assessment, entry classification), 14 SOC 2 tests (registry, evidence report, coverage, entry classification, category filtering)
- **No new dependencies** — Reuses serde, serde_json, sha2 already in workspace

- Docker Compose for local deployment (`docker-compose.yml`)
- Docker image build and publish workflow (GHCR + Trivy scanning)
- GitHub release automation workflow (static binaries, checksums, SBOM, provenance)
- Rustdoc GitHub Pages deployment workflow
- CONTRIBUTING.md with development rules and release checklist
- LICENSING.md with dual license terms and AI training opt-out
- 5 new fuzz targets: agent card URL/parse, A2A classify, homoglyph, attestation verify (15 → 20 total, now 21 with Phase 17.1)
- Machine-readable AI training opt-out (`.well-known/ai-policy.txt`)
- GitHub issue templates (bug report, feature request) with structured forms
- GitHub pull request template with testing checklist
- Python SDK test suite: 86 tests covering types, client, langchain, and langgraph modules
- crates.io publishing workflow (manual trigger, dependency-ordered, dry-run support)
- PyPI publishing workflow (tag trigger, trusted publishing OIDC, multi-version matrix)
- Security Model document (`docs/SECURITY_MODEL.md`): trust boundaries, data flows, storage guarantees, residual risks
- Benchmark guide (`docs/BENCHMARKS.md`): reproducible performance benchmarks with methodology and CI integration
- 5 curated policy presets: `dev-laptop`, `ci-agent`, `rag-agent`, `database-agent`, `browser-agent`
- Framework quickstart guide (`docs/QUICKSTART.md`): step-by-step Anthropic, OpenAI, LangChain, LangGraph, MCP proxy integration
- Python SDK parameter redaction (`vellaveto.redaction`): client-side secret stripping with 3 modes (keys_only, values, all), 56 tests
- `.dockerignore` for faster, smaller Docker builds
- OCI image labels on Dockerfile (title, description, source, license, vendor)
- Helm NetworkPolicy template with configurable ingress/egress rules
- Helm PodDisruptionBudget template for HA during K8s maintenance
- Helm ServiceMonitor template for Prometheus metrics discovery

### Changed

- Docker Compose: added resource limits (1 CPU, 256MB) and log rotation (10MB x 3 files)

- Default server port standardized from 8080 to 3000 across CLI, SDK, and documentation

- License switched from Apache-2.0 to AGPL-3.0 dual license
- All crate versions synced from 2.0.0 to 2.2.1
- Helm chart version synced to 2.2.1, license annotation corrected
- Python SDK version synced to 2.2.1 (including `__init__.py`)

## [2.2.1] - 2026-02-13

### Security

- **Adversarial Audit Hardening (FIND-055–074)**:
  - FIND-055 (P1): Agent card SSRF prevention — `validate_agent_card_base_url()` rejects non-HTTPS schemes, localhost, private IPs, IPv6 private ranges, path traversal, and userinfo-based host spoofing (9 tests)
  - FIND-057 (P2): Bounded stack size in `collect_string_leaves()` (MAX_STACK_SIZE=10,000) to prevent memory exhaustion from wide JSON fan-out in A2A messages
  - FIND-063 (P2): Regex pattern length validation (MAX_PATTERN_LEN=2,048) for DLP and PII patterns before regex compilation to prevent ReDoS
  - FIND-065 (P3): Audit log file permission failures now logged as `tracing::warn!` instead of silently ignored with `let _ =`
  - FIND-068 (P3): Accountability attestation `sign_attestation()` rejects empty agent_id, statement, and policy_hash (3 tests)
  - FIND-071 (P3): `ObservabilityExporterConfig` validation with MAX_BATCH_SIZE=10,000 and timeout_secs>0 bounds (5 tests)
  - FIND-074 (P3): Audit logger now rejects ALL control characters (U+0000–U+009F) in tool/function names, not just \n, \r, and \0 — prevents log injection via tabs, backspaces, escape sequences
  - Updated 4 integration test files to match new control character rejection behavior

- **Adversarial Pentest Round 3 Fixes (FIND-077–084)**:
  - FIND-077 (P1): Circuit breaker case-sensitivity bypass — tool names normalized to lowercase before all HashMap operations, preventing evasion via case variation (`MyTool` vs `mytool`)
  - FIND-078 (P1): Circuit breaker HalfOpen state never entered — `can_proceed()` now transitions Open→HalfOpen via double-check locking (read→write lock upgrade) when open duration expires, enforcing `half_open_max_requests` limit
  - FIND-079 (P1): Circuit breaker no exponential backoff — added `trip_count: u32` to `CircuitStats` with `#[serde(default)]`, incremented on HalfOpen→Open transitions, `effective_open_duration = base * 2^trip_count` (max 32x), reset on full recovery
  - FIND-080 (P2): Behavioral EMA gradual ramp evasion — added `absolute_ceiling: Option<u64>` to `BehavioralConfig`, produces `Critical` alert when tool call count exceeds ceiling regardless of EMA baseline
  - FIND-081 (P2): Behavioral cold-start baseline poisoning — added `max_initial_ema: Option<f64>` to `BehavioralConfig`, caps first observation's EMA to prevent artificially high baselines
  - FIND-082 (P2): Deputy re-delegation scope overwrite — `register_delegation()` now intersects requested `allowed_tools` with parent's granted scope, enforcing monotonic attenuation
  - FIND-083 (P2): Capability grant path traversal — `normalize_path_for_grant()` resolves `.`/`..` components before matching; null bytes and above-root traversal fail-closed
  - FIND-084 (P3): Fullwidth digit SSN bypass — NFKC normalization via `unicode-normalization` crate before PII regex matching converts fullwidth digits (U+FF10–FF19) to ASCII
  - Updated 8 pentest tests across 4 integration test files to verify all fixes

### Testing

- **Adversarial Audit Test Coverage (FIND-043–054)**:
  - 4,300+ tests total (up from 4,200+), 18 audit rounds (up from 17)
  - FIND-043 (P1): 25 context condition tests covering all 10 condition types (MaxChainDepth, AgentIdentityMatch, AsyncTaskPolicy, ResourceIndicator, CapabilityRequired, StepUpAuth, CircuitBreaker, DeputyValidation, SchemaPoisoningCheck, ShadowAgentCheck)
  - FIND-044 (P1): Circuit breaker HalfOpen→Closed recovery and Open→HalfOpen auto-transition tests
  - FIND-045 (P1): 16 end-to-end OAuth JWT validation tests with mock JWKS server (sign → fetch → verify flow covering expiry, algorithm confusion, issuer/audience/scope/resource enforcement, kid matching, signature tampering, DPoP mode, RFC 7235 case-insensitivity)
  - FIND-046 (P2): Domain homoglyph tests (Cyrillic, zero-width, fullwidth, mixed-script, combining diacritics)
  - FIND-047 (P2): Windows path normalization tests (UNC paths, drive letters, mixed separators)
  - FIND-048 (P2): Audit rotation manifest tamper detection tests (entry deletion, reordering)
  - FIND-049 (P2): Memory tracker fingerprint evasion tests (case sensitivity, percent-encoding, query param reordering)
  - FIND-050 (P2): 13 semantic scanner Unicode evasion tests documenting known gaps (fullwidth Latin, Cyrillic homoglyphs, zero-width insertion, combining diacritics, RTL override, mixed-script, superscript digits, chaos inputs)
  - FIND-051 (P2): Agent card URL edge case tests (file:// scheme, internal IPs, path traversal, trailing slashes, case-sensitive cache keys, XSS in name)
  - FIND-052 (P3): Behavioral EMA edge case tests (epsilon guard, u64::MAX, overflow, saturation)
  - FIND-053 (P3): Output validation depth bomb tests (nested schemas at and beyond MAX_VALIDATION_DEPTH=32)
  - FIND-054 (P3): Elicitation rate limit boundary tests (u32::MAX, exact boundary, boundary minus one)

### Changed

- **Server Route Modularization (IMP-001)**:
  - Extracted 17 route handler modules from `routes/main.rs` (~800 lines removed)
  - Created dedicated modules: approval, audit, auth_level, circuit_breaker, deputy, etdi, exec_graph, memory, nhi, observability, policy, registry, sampling, schema_lineage, shadow_agent, task_state, tenant
  - Improved code organization and maintainability

- **Documentation Sync**:
  - Updated `README.md` to reflect v2.2.1 metadata, MCP `2025-11-25` support (with compatibility notes), current container tags, and roadmap link.
  - Updated `ROADMAP.md` to mark Phase 15 complete and v2.2 timeline complete.
  - Expanded `README.md` with a full workspace module architecture map and feature ownership matrix (owners, entrypoints, and primary tests).
  - Expanded `README.md` project structure coverage to include SDK, Helm, docs, policies, security testing, and local collaboration surfaces.
  - Updated `ROADMAP.md` with an explicit Phase 16.6 architecture split/modularization track.
  - Added `MODULE_EXTRACTION_PLAYBOOK.md` and linked it from `README.md`; marked Phase 16.6 playbook/contract-check tasks complete in `ROADMAP.md`.
  - Added a post-quantum readiness section to `README.md` with standards status and migration milestones (2028/2031/2035 alignment).
  - Added Phase 16.7 post-quantum cryptography transition track to `ROADMAP.md` with TLS policy, observability, and rollout tasks.
  - Published `docs/quantum-migration.md` runbook with staged `tls.kex_policy` rollout/rollback guidance and canary verification steps.
  - Clarified OPA runtime status in `README.md` and `ROADMAP.md`: request-path enforcement is active with fail-open/fail-closed controls and runtime observability.
  - Added 2026-02-11 research-backed hardening backlog updates across `README.md`, `ROADMAP.md`, and `docs/SECURITY.md`:
    - P0 CI supply-chain hardening pack
    - P0 sender-constrained OAuth (DPoP) enforcement path in `vellaveto-http-proxy`
    - P1 `cargo-deny` policy gate and OPA runtime decision-path completion

### Added

- **CI Supply-Chain Baseline Hardening**:
  - Added Dependabot config for Cargo and GitHub Actions (`.github/dependabot.yml`)
  - Added PR dependency review workflow (`.github/workflows/dependency-review.yml`)
  - Added `cargo-deny` policy workflow (`.github/workflows/cargo-deny.yml`) with baseline config in `deny.toml`
  - Added provenance + SBOM workflow (`.github/workflows/provenance-sbom.yml`) with immutable action pins, lockfile immutability checks, release attestations, and CycloneDX artifact publishing
  - Added attestation verification gate in provenance workflow using `gh attestation verify` for release binaries
  - Added OpenSSF Scorecard workflow (`.github/workflows/scorecard.yml`) with SARIF upload for continuous repository hardening visibility
  - Added CODEOWNERS policy (`.github/CODEOWNERS`) for workflow and security-sensitive paths

- **Post-Quantum TLS KEX Policy (initial implementation)**:
  - Added `tls.kex_policy` to `TlsConfig` with values:
    - `classical_only`
    - `hybrid_preferred`
    - `hybrid_required_when_supported`
  - Added config validation guardrails:
    - Hybrid policies require `tls.mode` to be `tls` or `mtls`
    - Hybrid policies require `tls.min_version = "1.3"`
    - `tls.min_version` now validates accepted values (`"1.2"` or `"1.3"`)
  - Added rustls provider KEX-group policy application in `vellaveto-server` TLS setup with explicit downgrade warnings when hybrid is requested but unavailable.
  - Added example config snippet documenting `tls.kex_policy` usage.

- **Source distribution packaging**:
  - Added repository source ZIP artifact under `dist/` generated from tracked files at `HEAD` (`git archive`).
  - Added README guidance for generating and checksumming source distribution ZIPs locally.

### Refactor

- **HTTP proxy modularization**:
  - Split `vellaveto-http-proxy/src/proxy.rs` (6,712 lines) into 8 focused submodules under `proxy/`
  - Created: `mod.rs` (187), `handlers.rs` (2,082), `tests.rs` (1,729), `inspection.rs` (817), `upstream.rs` (805), `call_chain.rs` (464), `auth.rs` (395), `helpers.rs` (195), `origin.rs` (174)
  - Public API unchanged: `ProxyState`, `handle_mcp_post`, `handle_mcp_delete`, `handle_protected_resource_metadata`, `TrustedProxyContext`, `McpQueryParams`, `PrivilegeEscalationCheck`
  - All 169 proxy unit tests pass, zero clippy warnings
  - Follows the `vellaveto-mcp/src/proxy/bridge/` split pattern

- **DPoP audit function parameter consolidation**:
  - Introduced `DpopAuditParams` struct to group OAuth DPoP audit parameters
  - Reduces `audit_dpop_validation_failure()` function arguments from 8 to 2
  - Fixes `clippy::too_many_arguments` warning

- **Scanner infrastructure consolidation (IMP-002)**:
  - Added `scanner_base.rs` module with shared types for DLP and injection scanning
  - New unified `ScanFinding` type for consistent finding representation across scanners
  - New `ScannerType` enum for categorizing findings by scanner
  - Shared `MAX_SCAN_DEPTH` constant (32) replaces per-module depth limits
  - Common utilities: `normalize_text`, `traverse_json_strings`, `extract_response_text`, `extract_notification_text`
  - Added `to_scan_finding()` conversion methods to `DlpFinding` and `ToolDescriptionFinding`
  - Refactored `scan_response_for_injection()` to use shared `extract_response_text()` utility
  - Added `traverse_json_strings_with_keys()` for security scanning that includes object keys (R42-MCP-1)
  - Refactored `scan_notification_for_injection()` to use shared key-scanning utility
  - Reduces code duplication while maintaining security properties across scanners

- **HTTP proxy test helper simplification**:
  - Reduced `build_oauth_test_state_full` argument count in `vellaveto-http-proxy` integration tests.
  - Improves maintainability and readability of OAuth test setup paths.

- **MCP code hygiene cleanup**:
  - Removed unnecessary `#[allow(dead_code)]` annotations where no longer needed.

### Style

- **Format string interpolation**:
  - Replaced `format!("{}", var)` with `format!("{var}")` across core crates
  - Applied to vellaveto-types, vellaveto-engine, vellaveto-audit, vellaveto-approval, vellaveto-mcp
  - Cleaner, more readable format strings
  - Fixes `clippy::uninlined_format_args` pedantic warnings

- **Option chain simplification**:
  - Replaced `map().unwrap_or()` with `map_or()` for cleaner Option handling
  - Applied to vellaveto-types, vellaveto-engine (deputy, legacy, lib)
  - Fixes `clippy::map_unwrap_or` pedantic warnings

- **Numeric literal formatting**:
  - Added digit separators to large numeric literals for improved readability
  - Timestamps: `1704067200` → `1_704_067_200`
  - Time durations: `604800` → `604_800`
  - IP addresses: `167772160` → `167_772_160`
  - File sizes: `1048576` → `1_048_576`
  - Fixes `clippy::unreadable_literal` pedantic warnings

- **Documentation formatting**:
  - Added backticks around code items in doc comments (types, fields, algorithms)
  - Improves rustdoc rendering and consistency

### Performance

- **Pre-compiled regex optimization (IMP-007)**:
  - Moved base64 detection regex in `output_security.rs` to static `OnceLock`
  - Eliminates per-call regex compilation in steganography detection

- **Runtime allocation tuning**:
  - Added bounded `HashMap::with_capacity` hints in `vellaveto-mcp` runtime/session managers:
    - `token_security`
    - `task_state`
    - `auth_level`
    - `output_validation`
    - `workflow_tracker`
  - Updated `PolicyEngine` constructors to initialize `domain_norm_cache` using `MAX_DOMAIN_NORM_CACHE_ENTRIES`-bounded capacity.

### Security

- **Call-chain header hardening (`vellaveto-http-proxy`)**:
  - Enforced fail-closed `X-Upstream-Agents` validation across MCP method paths.
  - Added explicit rejection for headers whose entry count exceeds `limits.max_call_chain_length` (instead of truncation).
  - Added regression coverage for malformed and over-limit call-chain headers on tool-call, pass-through, sampling, resource, and task paths.

- **OPA runtime decision enforcement (`vellaveto-server`)**:
  - Runtime OPA verdict wiring is active in evaluation request paths with fail-open/fail-closed controls and runtime query/error metrics.
  - Added route-level regression coverage for fail-open and fail-closed behavior when OPA is unreachable.
  - Added `opa.require_https` hardening control to require `https://` OPA endpoints.
  - Added config validation for OPA endpoint URL shape (scheme, host, and userinfo rejection) and startup/runtime rejection when `require_https=true` is paired with plaintext OPA endpoints.
  - Added startup security warnings for plaintext OPA control-plane traffic and remote OPA endpoints configured without auth headers.

- **OPA fail-closed defaults hardening (R43-OPA-1)**:
  - Changed `opa.require_https` default from `false` to `true` (encrypt policy decisions in transit)
  - Added `opa.fail_open_acknowledged` field requiring explicit acknowledgment to enable `fail_open=true`
  - Validation now rejects `fail_open=true` without `fail_open_acknowledged=true`
  - Changed `injection.block_on_injection` default from `false` to `true` (fail-closed behavior)
  - Prevents accidental misconfiguration that could allow bypass during OPA unavailability

- **Provenance verification hardening (CI)**:
  - Strengthened `gh attestation verify` checks to require the expected signer workflow path and exact source ref (`GITHUB_REF`), and deny attestations generated on self-hosted runners.

- **Dependency audit policy hygiene**:
  - Removed stale `RUSTSEC-2024-0384` ignore from `.cargo/audit.toml`; lockfile no longer includes the affected transitive crate.

- **DPoP failure observability (`vellaveto-http-proxy`)**:
  - Added dedicated DPoP counters: `vellaveto_oauth_dpop_failures_total` (reason-labeled) and `vellaveto_oauth_dpop_replay_total`.
  - Added explicit audit events for DPoP validation failures with `dpop_reason`, `dpop_mode`, `oauth_subject`, and header/session context.
  - Added integration coverage for missing-proof and replay-detected audit paths.

- **OAuth/DPoP startup and replay hardening (`vellaveto-http-proxy`)**:
  - Added startup guardrails for pass-through mode: `--oauth-pass-through` now requires explicit `--unsafe-oauth-pass-through`, RFC 8707 expected resource binding, and DPoP `required` mode.
  - Added hardened OAuth profile support (`--oauth-security-profile hardened`) to enforce sender-constrained posture at startup.
  - Added startup warnings when OAuth is enabled with weak defaults (`dpop_mode=off` or missing expected resource) in standard profile.
  - Enforced sender-constrained token binding in DPoP `required` mode: access tokens must contain `cnf.jkt`, and runtime now verifies `cnf.jkt` against the presented DPoP proof key thumbprint (RFC 7638).
  - Hardened DPoP replay cache input handling by bounding untrusted `jti`/replay-key size and keying replays by `jti:ath` when token binding is available.

- **TLS metadata observability (`vellaveto-server`)**:
  - Added evaluate-path extraction of sanitized forwarded TLS handshake metadata (`protocol`, `cipher`, `kex_group`).
  - Trusted forwarded TLS metadata headers only when the direct connection peer is a configured trusted proxy.
  - Trusted `X-Forwarded-Proto` for HSTS decisions only when the direct connection peer is a configured trusted proxy.
  - Fixed `X-Principal` trust check to use direct trusted-proxy peer identity (not derived client IP), preserving per-principal rate-limit attribution behind trusted proxy chains.
  - Added per-principal rate-limit integration coverage for trusted proxy + `X-Forwarded-For` chains with stable `X-Principal` identity.
  - Rejected control characters in trusted `X-Principal` header values before principal-key derivation.
  - Treated missing trusted-proxy request context as untrusted when evaluating forwarded TLS metadata (fail-safe default).
  - Added `vellaveto_forwarded_header_rejections_total{header=...}` metric and incremented it when untrusted `X-Forwarded-Proto` or forwarded TLS metadata headers are ignored.
  - Included TLS metadata in audit entry metadata for `/api/evaluate` decisions.

- **HTTP proxy request-id hardening (`vellaveto-http-proxy`)**:
  - Rejected control characters in client-supplied `X-Request-Id` values before echoing to response headers.

- **HTTP proxy forwarded-header trust hardening (`vellaveto-http-proxy`)**:
  - Added trusted-proxy context propagation based on direct peer IP (`ConnectInfo`) and `VELLAVETO_TRUSTED_PROXIES`.
  - Trusted `X-Forwarded-Proto` for HSTS decisions only when the direct connection peer is a configured trusted proxy.
  - Trusted `X-Forwarded-Proto` / `X-Forwarded-Host` for OAuth effective request URI construction only when the direct connection peer is a configured trusted proxy.
  - Added regression coverage for trusted vs untrusted forwarded-header URI reconstruction and trusted-proxy peer detection helpers.
  - Added the same TLS attributes to observability spans when exporters are enabled.
  - Added unit/integration coverage for TLS metadata extraction and audit emission.
  - Hardened extraction to reject ambiguous duplicate/alias values for each TLS metadata field (fail-closed on conflicts).
  - Preserved fallback to lower-priority alias headers when a higher-priority alias is malformed.
  - Added route-level audit integration coverage for conflicting alias/duplicate TLS protocol headers and safe fallback behavior.
  - Added TLS KEX negotiation integration tests for `classical_only`, `hybrid_preferred`, and `hybrid_required_when_supported` including classical-only client failure-mode coverage when PQ/hybrid groups are available.

- **Workspace outbound TLS backend standardization**:
  - Standardized workspace `reqwest` backend to rustls by setting `default-features = false` and enabling `rustls-tls` at the workspace dependency root.
  - Keeps outbound HTTP client behavior consistent across `vellaveto-server`, `vellaveto-http-proxy`, `vellaveto-audit` exporters, and `vellaveto-mcp` cloud backends.
  - Updated `vellaveto-server` TLS provider selection to explicitly use rustls `aws-lc-rs` provider, avoiding runtime panics when multiple rustls providers are enabled in the dependency graph.
  - Verified compile coverage for key reqwest consumers, including `vellaveto-audit --features observability-exporters` and `vellaveto-mcp --features llm-cloud`.

- **DLP pattern validation at startup (SEC-006)**:
  - Both `vellaveto-server` and `vellaveto-http-proxy` now validate all DLP patterns compile successfully during startup
  - If any pattern fails to compile, the application fails to start rather than silently skipping secret detection
  - Prevents silent gaps in DLP coverage from malformed patterns

- **Injection pattern validation at startup**:
  - Added `validate_injection_patterns()`, `is_injection_available()`, and `injection_pattern_count()` functions
  - Both server and proxy now validate injection patterns compile at startup
  - Consistent with DLP validation for defense-in-depth

- **Health endpoint security scanning status (SEC-006)**:
  - Enhanced `/health` endpoint in both `vellaveto-server` and `vellaveto-http-proxy` to report scanning subsystem availability
  - New response fields: `scanning.dlp_available` and `scanning.injection_available`
  - Health status reports "degraded" if either DLP or injection detection is unavailable
  - Provides visibility into security posture for monitoring and alerting

- **Metrics endpoint scanning pattern counts**:
  - Extended `/api/metrics` JSON response to include scanning subsystem details
  - New fields: `scanning.dlp.available`, `scanning.dlp.pattern_count`, `scanning.injection.available`, `scanning.injection.pattern_count`
  - Provides operational visibility into active pattern counts for monitoring

### Dependencies

- **Minor/patch updates (IMP-006)**:
  - `proptest` 1.9.0 → 1.10.0
  - `regex` 1.12.2 → 1.12.3
  - `tempfile` 3.24.0 → 3.25.0
  - `clap` 4.5.56 → 4.5.57
  - `criterion` 0.8.1 → 0.8.2
  - `x509-parser` 0.17 → 0.18 (ASN.1 parsing improvements)
  - `metrics-exporter-prometheus` 0.16 → 0.18 (metrics 0.24 ecosystem)
  - `serde_json_canonicalizer` 0.3.1 → 0.3.2
  - `toml` 0.9 → 1.0 (first stable release)

- **GitHub Actions updates**:
  - `actions/checkout` 4.3.1 → 6.0.2
  - `actions/cache` 4.3.0 → 5.0.3
  - `actions/upload-artifact` 4.6.2 → 6.0.0
  - `Swatinem/rust-cache`, `actions/dependency-review-action`, `actions/attest-build-provenance`, `ossf/scorecard-action`, `github/codeql-action` — commit hash updates
  - All actions pinned to specific commit SHAs for supply chain security

## [2.2.1] - 2026-02-10

### Changed

- **MCP Protocol Version**: Updated from `2025-06-18` to `2025-11-25` with backwards compatibility for `2025-06-18` and `2025-03-26`
- **DELETE Session Termination**: Changed response from 200 OK to 204 No Content per MCP specification
- **Memory Tracking Configuration**: `MAX_FINGERPRINTS` and `MIN_TRACKABLE_LENGTH` are now configurable via `MemorySecurityConfig.max_fingerprints` and `MemorySecurityConfig.min_trackable_length`
- **Dependency Updates**:
  - Upgraded `jsonwebtoken` from 9 to 10 with `aws_lc_rs` feature (FIPS-validated cryptography)
  - Upgraded `notify` from 7 to 8
  - Note: `rand` 0.8 → 0.9 blocked by ed25519-dalek incompatibility (deferred)

### Added

#### Protocol Version Validation
- Validate `MCP-Protocol-Version` header on incoming requests
- Accept versions: `2025-11-25`, `2025-06-18`, `2025-03-26`
- Return 400 Bad Request for unrecognized protocol versions

#### RFC 9728 OAuth Protected Resource Metadata
- Added `GET /.well-known/oauth-protected-resource` endpoint
- Returns `resource`, `authorization_servers`, `scopes_supported` when OAuth configured
- Returns 404 when OAuth not configured

#### AI Service Credential DLP Patterns (OWASP ASI03)
- `anthropic_api_key` — Anthropic API keys (`sk-ant-api...`)
- `openai_api_key` — OpenAI API keys (`sk-`, `sk-proj-`)
- `huggingface_token` — HuggingFace tokens (`hf_...`)
- `cohere_api_key` — Cohere API keys
- `replicate_token` — Replicate tokens (`r8_...`)
- `together_api_key` — Together.ai API keys
- `groq_api_key` — Groq API keys (`gsk_...`)

#### MCPTox Directive Injection Detection
- Added directive insertion patterns: `IMPORTANT:`, `NOTE:`, `REQUIRED:`, `CRITICAL:`, `WARNING:`, `ATTENTION:`, `MUST:`

#### Phonetic/Emoji Encoding Detection
- NATO phonetic alphabet decoding (`alpha bravo charlie` → `abc`)
- Common emoji command decoding (`🐱📁` → `cat file`)
- Integrated into injection detection pipeline

#### Mixed-Script Spoofing Detection
- New `SquattingKind::MixedScript` for detecting tool names with mixed Unicode scripts
- Detects Latin + Cyrillic, Latin + Greek, Latin + Mathematical combinations
- Higher priority detection than homoglyph normalization

#### Multimodal Content Safety (Phase 1)
- `MultimodalScanner` for detecting injection attempts in non-text content
- `ContentType` enum with magic byte and MIME type detection (Image, Audio, PDF, Video)
- `scan_blob_for_injection()` for scanning MCP resource.blob fields
- OCR integration placeholder (feature-gated with `multimodal` feature)
- Steganography detection scaffolding

#### Hallucination/Grounding Detection (Phase 1)
- `GroundingChecker` for validating LLM responses against RAG context
- Lexical overlap scoring (Jaccard similarity) as NLI fallback
- `GroundingResult` with claim scores, contradictions, and source attributions
- Sentence-based claim extraction with configurable min/max thresholds
- `GroundingConfig` in `RagDefenseConfig` for runtime configuration

#### Python SDK (Phase 1)
- New `sdk/python/vellaveto` package for LangChain/LangGraph integration
- `VellavetoClient` — Sync/async HTTP client supporting httpx and requests backends
- `VellavetoCallbackHandler` — LangChain callback for intercepting tool calls
- `VellavetoToolGuard` — Decorator for guarding individual tools
- `create_guarded_toolkit()` — Wraps existing LangChain toolkits with Vellaveto guards
- `create_vellaveto_node()` — LangGraph node factory for policy evaluation
- `create_vellaveto_tool_node()` — Combined tool execution + policy evaluation node

#### API Stability (Phase 2)
- Added `#[non_exhaustive]` to core enums for forward compatibility:
  - `Verdict` — Allow/Deny/RequireApproval variants
  - `PolicyType` — Allow/Deny/Conditional variants
  - `ApprovalStatus` — Pending/Approved/Denied/Expired variants
  - `SquattingKind` — Levenshtein/Homoglyph/MixedScript variants
- All match statements updated with fail-closed wildcard patterns for unknown variants

#### MCP Tasks Primitive Support (Phase 2)
- Extended `MessageType::TaskRequest` classification to include:
  - `tasks/list` — List active tasks
  - `tasks/resubscribe` — Resume task event subscriptions
- Full parity with MCP 2025-11-25 task primitives

#### Configuration Validation (Phase 2)
- Added Ed25519 public key format validation at config load time
- Validates trusted_keys are exactly 64 hex characters (32 bytes)
- Returns descriptive error messages for invalid key formats

#### Additional DLP Patterns (Phase 3)
- `supabase_api_key` — Supabase API keys (`sbp_...`)
- `vercel_token` — Vercel tokens (`vercel_`, `vc_...`)
- `databricks_token` — Databricks tokens (`dapi...`)
- `linear_api_key` — Linear API keys (`lin_api_...`)
- `planetscale_token` — Planetscale tokens (`pscale_...`)
- `neon_token` — Neon database tokens

#### Additional Injection Detection Patterns (Phase 3)
- Gemma format: `<start_of_turn>`, `<end_of_turn>`
- Phi format: `<|endoftext|>`
- DeepSeek format: `<|begin▁of▁sentence|>`, `<|end▁of▁sentence|>`
- Command R format: `<|start_header_id|>`, `<|end_header_id|>`, `<|eot_id|>`

#### Tool Squatting Detection Improvement (FIND-005)
- Increased Levenshtein distance threshold from 2 to 3 for tool names > 8 characters
- Catches typosquats like `read_files` vs `read_file` or `write_filed` vs `write_file`

#### DLP Pattern Validation at Config Load (FIND-002)
- Added regex validation for `dlp.extra_patterns` at config load time
- Invalid regex patterns now fail startup instead of being silently skipped
- Added `regex` dependency to `vellaveto-config`

#### Call Chain Security Hardening
- Added `MAX_CALL_CHAIN_LENGTH` (20) and `MAX_CALL_CHAIN_HEADER_SIZE` (8KB) limits
- New `validate_call_chain_header()` rejects oversized/malformed headers fail-closed
- Prevents CPU exhaustion in privilege-escalation checks
- Prevents memory exhaustion from oversized JSON header values

#### A2A Proxy Security Improvements
- Use shared injection/DLP scanners for consistency with MCP proxy
- Handle `#[non_exhaustive]` Verdict fail-closed (unknown variants → deny)
- Scan data/file/error-data text surfaces for injection

### Fixed

- **Error Handling**: Added logging for previously silent error discards in:
  - Config reload channel send failures
  - Telemetry provider shutdown errors
  - Added TODO documentation for deferred structured content validation
- **Zero unwrap() in library code**: Removed 2 remaining unwrap() calls:
  - `injection.rs`: Replaced with safe if-let in emoji variation selector handling
  - `idempotency.rs`: Replaced builder unwrap() with Response::new() in error fallback

### Security

- **RUSTSEC-2023-0071 (Marvin Attack)**: Switched `jsonwebtoken` from `rust_crypto` to `aws_lc_rs` backend to eliminate timing side-channel vulnerability in RSA PKCS#1 v1.5 decryption. The `rsa` crate (used by `rust_crypto`) was vulnerable to Marvin Attack timing oracle; AWS-LC provides constant-time RSA operations.

---

## [2.2.0] - 2026-02-09

### Changed

- **Dependency cleanup**: Removed `rustls-pemfile` crate, now using `rustls::pki_types::pem::PemObject` trait for PEM parsing
- **JSON-RPC error code consolidation**: Moved hardcoded error codes into `vellaveto-types/src/json_rpc.rs` module with named constants for all standard JSON-RPC 2.0 codes and Vellaveto application-specific codes (-32001 to -32021)
- **OpenTelemetry upgrade**: Upgraded from 0.22 to 0.30, eliminating major dependency duplicates (axum 0.6→0.8, hyper 0.14→1.x, http 0.2→1.x, h2 0.3→0.4, tower 0.4→0.5)
- **Workspace dependency unification**: Unified reqwest to 0.13 as workspace dependency with "json" and "query" features
- **Security manager initialization**: Phase 1-10 security managers (task_state, circuit_breaker, auth_level, deputy, shadow_agent, schema_lineage, sampling_detector, etdi, memory_security, nhi) now properly initialized from PolicyConfig instead of TODO placeholders
- **Crate metadata**: Added description field to all 9 crates that were missing it (vellaveto-types, vellaveto-engine, vellaveto-audit, vellaveto-mcp, vellaveto-canonical, vellaveto-config, vellaveto-approval, vellaveto-proxy, vellaveto-integration)

### Added

- **Bracket notation for parameter paths**: Support `params.items[0].value` syntax in parameter constraints for array element access
- **Evaluation tracing**: Add `?trace=true` query parameter to get full OPA-style decision traces
- **Audit heartbeat entries**: Periodic heartbeat entries for detecting log truncation/deletion attacks
- **DLP observability metrics**: `vellaveto_dlp_findings_total`, `vellaveto_dlp_scan_duration_seconds` histograms
- **Anomaly detection metrics**: `vellaveto_anomaly_detections_total` counter with agent/tool labels
- **Circuit breaker metrics**: `vellaveto_circuit_breaker_state_changes_total`, state duration histograms
- **DlpConfig**: Configurable DLP scanning with `enabled`, `block_on_finding`, `max_decode_depth`, `time_budget_ms`, `extra_patterns`, `disabled_patterns`

### Security

#### DLP Hardening
- **Unicode NFKC Normalization** — DLP scanning now applies NFKC normalization to detect secrets obfuscated with Unicode homoglyphs (e.g., Cyrillic 'а' vs Latin 'a') and fullwidth characters
- **2-Part JWT Detection** — Extended JWT pattern to detect header.payload tokens without signature, which still contain sensitive claims attackers could exfiltrate and re-sign
- **Size Limit Protection** — Added 1MB (`MAX_DLP_STRING_SIZE`) limit to prevent CPU exhaustion from regex scanning very large strings; truncated strings still scanned with warning logged
- **New Tests**: `test_dlp_detects_aws_key_with_fullwidth_unicode`, `test_dlp_detects_jwt_without_signature`

#### Legacy Policy Path Security Fix (P0)
- **Policy Bypass Fix** — Legacy policy evaluation path (`apply_policy`) now enforces `path_rules`, `network_rules`, and `ip_rules` before returning verdicts, matching compiled policy behavior
- **Path Rules Enforcement** — Added `check_path_rules_legacy()` with glob matching, path normalization, and fail-closed behavior for invalid patterns
- **Network Rules Enforcement** — Added `check_network_rules_legacy()` with IDNA normalization and domain pattern matching
- **IP Rules Enforcement** — Added `check_ip_rules_legacy()` with DNS rebinding protection, IPv6 transition mechanism canonicalization, and CIDR enforcement
- **Invalid Glob Handling** — Malformed glob patterns now produce `Deny` verdicts instead of 500 errors (fail-closed)

#### Code Quality Fixes
- **FIND-027** — Eliminated `expect()`/`unwrap()` violations in `vellaveto-mcp` library code per no-panic policy:
  - `cache.rs`: Replaced `expect()` with const `FALLBACK_CACHE_SIZE` and `unwrap_or()`
  - `task_security.rs`: Changed `generate_resume_token` to return `Result`, propagating HMAC and RNG errors
- **FIND-021/FIND-002** — Standardized workspace dependency management:
  - `vellaveto-config`: Use `workspace = true` for serde, serde_json
  - `vellaveto-audit`: Use `workspace = true` for tokio, tracing
  - `vellaveto-proxy`: Use `workspace = true` for tracing

### Added

#### Phase 14: A2A Protocol Security
- **A2A Message Classification** — Parse and classify A2A JSON-RPC messages (message/send, message/stream, tasks/get, tasks/cancel, tasks/resubscribe) with method normalization to prevent Unicode bypass attacks
- **Action Extraction** — Convert A2A messages to Vellaveto Actions for policy evaluation using tool pattern "a2a" with function-specific mapping (message_send, message_stream, task_get, task_cancel, task_resubscribe)
- **Agent Card Handling** — Fetch, parse, and cache A2A Agent Cards from `/.well-known/agent.json` with TTL-based expiration, capability validation, and authentication scheme detection
- **A2A Proxy Service** — HTTP proxy for A2A traffic with policy evaluation, security scanning integration (DLP, injection detection), circuit breaker support, and configurable task operation restrictions
- **Batch Rejection** — JSON-RPC batch requests rejected at transport layer to prevent TOCTOU attacks (matching MCP security pattern)
- **Security Integration** — Reuse existing security managers (circuit breaker, shadow agent detection, DLP scanning, injection detection) for A2A traffic
- **New Types**: `A2aMessageType`, `TaskState`, `PartContent`, `FileContent`, `MessagePart`, `A2aMessage`, `AgentCard`, `AgentCardCache`, `A2aProxyService`, `A2aProxyConfig`, `A2aProxyDecision`
- **New Config**: `A2aConfig` with upstream URL, listen address, agent card verification, auth method filtering, security feature toggles, message size limits, and task operation restrictions
- **New Errors**: `A2aError` with variants for invalid messages, agent card failures, authentication, task operations, policy denial, security violations, and upstream errors
- **Feature Flag**: `a2a`

#### Phase 13: RAG Poisoning Defense
- **Document Verification** — Trust scoring with age bonuses (+0.1/week, capped at 0.3), admin approval (+0.2), Ed25519 signature verification (+0.2), version stability bonuses, and mutation penalties (-0.3 per change)
- **Document Provenance** — SHA-256 content hashing, version chain tracking, source attribution, and timestamp management for knowledge base documents
- **Retrieval Security** — Inspection of retrieval results with configurable limits, DLP scanning integration, and result filtering for sensitive data
- **Diversity Enforcement** — Jaccard similarity-based duplicate detection to prevent context flooding with near-identical content
- **Embedding Anomaly Detection** — Per-agent baseline tracking with cosine similarity comparison, configurable thresholds, and automatic anomaly flagging
- **Context Budget Enforcement** — Token-based budget tracking per session with per-retrieval limits, total session limits, and configurable enforcement modes (truncate/reject/warn)
- **RagDefenseService** — High-level facade combining document verification, retrieval inspection, embedding anomaly detection, and context budget tracking
- **New Types**: `DocumentMetadata`, `DocumentTrustScore`, `TrustFactor`, `DocumentVerifier`, `RetrievalResult`, `RetrievalInspection`, `RetrievalInspector`, `RagDlpFinding`, `EmbeddingVector`, `EmbeddingBaseline`, `AnomalyDetection`, `EmbeddingAnomalyDetector`, `BudgetUsage`, `BudgetEnforcement`, `ContextBudgetTracker`, `RagDefenseService`
- **New Config**: `RagDefenseConfig` with `DocumentVerificationConfig`, `RetrievalSecurityConfig`, `EmbeddingAnomalyConfig`, `ContextBudgetConfig`
- **New Errors**: `RagDefenseError` with variants for low trust scores, content hash mismatches, retrieval limits, embedding anomalies, budget exceeded, and more
- **Feature Flag**: `rag-defense`

#### Phase 12: Semantic Guardrails (LLM-Based Policy Evaluation)
- **Intent Classification** — Structured taxonomy of action intents (DataRead, DataWrite, SystemExecute, NetworkFetch, CredentialAccess, etc.) with confidence scoring and risk category detection
- **Natural Language Policies** — Define policies in plain English with glob-based tool/function matching, compiled to efficient matchers
- **LLM Evaluator Interface** — Pluggable backend abstraction supporting cloud (OpenAI, Anthropic) and local (GGUF, ONNX) model evaluation
- **Evaluation Caching** — LRU + TTL cache for LLM evaluations to minimize latency and cost on repeated patterns
- **Jailbreak Detection** — LLM-based detection of adversarial prompts resistant to pattern evasion, with configurable thresholds
- **Intent Chain Tracking** — Per-session tracking of action intents to detect suspicious patterns like reconnaissance→exfiltration sequences
- **SemanticGuardrailsService** — High-level service combining evaluator, cache, intent tracking, and NL policies
- **Mock Backend** — Configurable mock implementation for testing with pattern-based response rules and simulated latency
- **New Types**: `Intent`, `IntentClassification`, `IntentChain`, `RiskCategory`, `SuspiciousPattern`, `LlmEvalInput`, `LlmEvaluation`, `LlmEvaluator`, `NlPolicy`, `NlPolicyCompiler`, `JailbreakDetection`, `FallbackBehavior`
- **New Config**: `SemanticGuardrailsConfig` with OpenAI/Anthropic backend configs, intent classification settings, jailbreak detection thresholds, cache TTL, and fallback behavior
- **Feature Flag**: `semantic-guardrails` (core), `llm-cloud` (OpenAI/Anthropic), `llm-local-gguf`, `llm-local-onnx`

#### Phase 11: MCP Tasks Primitive Security
- **Task State Encryption** — ChaCha20-Poly1305 AEAD encryption for task state data, protecting sensitive information at rest
- **Resume Token Authentication** — HMAC-SHA256 tokens for authenticated task resumption, preventing unauthorized access to long-running tasks
- **Hash Chain Integrity** — SHA-256 hash chain tracking all state transitions with sequence numbers, timestamps, and agent IDs for tamper detection
- **Checkpoint Verification** — Ed25519 signed checkpoints of task state for non-repudiation and point-in-time verification
- **Replay Protection** — Nonce-based anti-replay with configurable FIFO eviction (default 1000 nonces per task)
- **SecureTaskManager** — New manager combining encryption, integrity, and authentication for MCP Tasks primitive
- **New Types**: `SecureTask`, `TaskStateTransition`, `TaskCheckpoint`, `TaskResumeRequest`, `TaskResumeResult`, `TaskIntegrityResult`, `SecureTaskStats`
- **New Config**: Extended `AsyncTaskConfig` with `encrypt_state`, `enable_hash_chain`, `require_resume_token`, `replay_protection`, `max_nonces`, `enable_checkpoints`, `checkpoint_interval`, `task_retention_secs`

#### Phase 10: NHI (Non-Human Identity) Lifecycle Management
- **Agent Identity Registration** — Multiple attestation types (JWT, mTLS, SPIFFE, DPoP, API key) with configurable TTL, public key binding, and metadata tags
- **Identity Lifecycle States** — Full lifecycle management: Probationary → Active → Suspended → Revoked → Expired with automatic status transitions
- **Behavioral Attestation** — Continuous authentication via behavioral baselines using Welford's online variance algorithm for request intervals, tool call patterns, and source IP tracking
- **Anomaly Detection** — Configurable anomaly thresholds with recommendations (Allow, AllowWithLogging, StepUpAuth, Suspend, Revoke) based on deviation severity
- **Delegation Chains** — Agent-to-agent permission delegation with scope constraints, depth limits, and chain resolution for accountability tracking
- **Credential Rotation** — Automatic credential lifecycle with expiration warnings, rotation history, and thumbprint tracking
- **DPoP Support** — RFC 9449 Demonstration of Proof-of-Possession with nonce generation, replay prevention, and access token hash binding
- **NHI API Endpoints**:
  - `GET/POST /api/nhi/agents` — List and register agent identities
  - `GET/DELETE /api/nhi/agents/{id}` — Get or revoke agent identity
  - `POST /api/nhi/agents/{id}/activate` — Activate probationary identity
  - `POST /api/nhi/agents/{id}/suspend` — Suspend active identity
  - `GET /api/nhi/agents/{id}/baseline` — Get behavioral baseline
  - `POST /api/nhi/agents/{id}/check` — Check behavior against baseline
  - `GET/POST /api/nhi/delegations` — List and create delegations
  - `GET/DELETE /api/nhi/delegations/{from}/{to}` — Get or revoke delegation
  - `GET /api/nhi/delegations/{id}/chain` — Resolve full delegation chain
  - `POST /api/nhi/agents/{id}/rotate` — Rotate credentials
  - `GET /api/nhi/expiring` — Get identities expiring soon
  - `POST /api/nhi/dpop/nonce` — Generate DPoP nonce
  - `GET /api/nhi/stats` — NHI statistics
- **New Types**: `NhiAgentIdentity`, `NhiIdentityStatus`, `NhiAttestationType`, `NhiBehavioralBaseline`, `NhiBehavioralCheckResult`, `NhiBehavioralDeviation`, `NhiBehavioralRecommendation`, `NhiDelegationLink`, `NhiDelegationChain`, `NhiDpopProof`, `NhiDpopVerificationResult`, `NhiCredentialRotation`, `NhiStats`
- **New Config**: `NhiConfig`, `DpopConfig` with comprehensive defaults for credential TTL, attestation types, anomaly thresholds, delegation limits, and rotation warnings

#### Phase 9: MINJA (Memory Injection Defense)
- **Taint Propagation** — Data from untrusted sources tagged with taint labels (`UserInput`, `ExternalApi`, `AgentOutput`, `DerivedData`, `Sanitized`) that propagate to derived data automatically
- **Provenance Graph** — DAG tracking data lineage with FIFO eviction, detects suspicious patterns (notification→replay chains, feedback loops, data laundering)
- **Trust Decay** — Exponential decay with configurable λ (default 0.029 for 24-hour half-life), time-based trust erosion for stale data
- **Quarantine Management** — Automatic quarantine on injection detection, manual quarantine/release via API, detection metadata tracking
- **Namespace Isolation** — Per-agent namespaces with configurable isolation levels:
  - `Session` — Data isolated per session
  - `Agent` — Data isolated per agent identity
  - `Shared` — Explicit sharing with approval
- **Sharing Approval** — Cross-namespace data sharing requires explicit approval with access type specification (Read/Write/Admin)
- **Memory Security API Endpoints**:
  - `GET /api/memory/entries` — List memory entries with taint filtering
  - `GET /api/memory/entries/{id}` — Get memory entry details
  - `GET /api/memory/entries/{id}/provenance` — Get provenance chain for entry
  - `POST /api/memory/quarantine/{id}` — Quarantine a memory entry
  - `DELETE /api/memory/quarantine/{id}` — Release entry from quarantine
  - `GET /api/memory/quarantine` — List quarantined entries
  - `GET /api/memory/namespaces` — List namespaces
  - `POST /api/memory/namespaces/{ns}/share` — Request namespace sharing
  - `POST /api/memory/namespaces/{ns}/share/approve` — Approve sharing request
  - `GET /api/memory/stats` — Get memory security statistics
- **New Types**: `TaintLabel`, `MemoryEntry`, `ProvenanceNode`, `ProvenanceEventType`, `QuarantineEntry`, `QuarantineDetection`, `MemoryNamespace`, `NamespaceIsolation`, `MemoryAccessDecision`, `NamespaceSharingRequest`, `NamespaceAccessType`, `MemorySecurityStats`
- **New Config**: `MemorySecurityConfig`, `NamespaceConfig` with decay λ, max provenance depth, quarantine policies

#### Phase 8: ETDI Cryptographic Tool Security
- **Tool Signature Verification** — Ed25519/ECDSA P-256 cryptographic signing of tool definitions with trusted signer allowlists (fingerprints + SPIFFE IDs) and expiration support
- **Attestation Chain** — Provenance tracking for tool definitions with initial registration, version updates, and chain integrity verification
- **Version Pinning** — Semantic versioning constraints (`^1.0.0`, `~2.1.0`, exact) with hash-based drift detection for rug-pull prevention
- **ETDI Store** — Persistent storage for signatures, attestations, and pins with optional HMAC integrity protection
- **ETDI API Endpoints**:
  - `GET /api/etdi/signatures` — List all tool signatures
  - `GET /api/etdi/signatures/{tool}` — Get signature for a tool
  - `POST /api/etdi/signatures/{tool}/verify` — Verify tool signature
  - `GET /api/etdi/attestations` — List all attestations
  - `GET /api/etdi/attestations/{tool}` — Get attestation chain for a tool
  - `GET /api/etdi/attestations/{tool}/verify` — Verify attestation chain integrity
  - `GET/POST/DELETE /api/etdi/pins/{tool}` — Manage version pins
- **Tool Registry Integration** — Signature verification on tool registration with configurable `require_signatures` mode for fail-closed enforcement
- **ETDI CLI Commands**:
  - `vellaveto generate-key` — Generate Ed25519 keypair for tool signing
  - `vellaveto sign-tool` — Sign a tool definition with expiration support
  - `vellaveto verify-signature` — Verify a tool signature against its definition

### Security

- **R33-001**: Add monotonic sequence counter to audit hash chain to prevent collision attacks under high load
- **R33-002**: Add per-line size limits (64KB checkpoints, 1MB audit entries) to prevent memory exhaustion attacks
- **R33-003**: Use safe string slicing with char-based truncation to prevent UTF-8 boundary panics
- **R33-004**: Increase injection detection depth from 10 to 32 levels for deeply nested payloads
- **R33-005**: Add triple-encoding detection layers (6-8) to DLP for double-base64 and mixed encoding evasion
- **R33-006**: Store actual schema content for real field-level diff detection in schema poisoning

### Changed

- Security audit rounds: 34 → 35
- Test suite: 3,343 → 3,643 tests

### Documentation

- **ROADMAP.md**: Added v2.1 and v2.2 roadmap based on security research
  - Phase 8: ETDI Cryptographic Tool Security
  - Phase 9: Memory Injection Defense (MINJA)
  - Phase 10: Non-Human Identity (NHI) Lifecycle
  - Phase 11: MCP Tasks Primitive
  - Phase 12: Semantic Guardrails (LLM-based)
  - Phase 13: RAG Poisoning Defense
  - Phase 14: A2A Protocol Security
  - Phase 15: Observability Platform Integration
- Updated gap analysis vs competitor landscape (NeMo Guardrails, Guardrails AI, Zenity, Prisma AIRS)
- Added research bibliography with 10 academic/industry references

---

## [2.0.0] - 2026-02-08

### Added

#### Phase 6: Observability & Tooling
- **Execution Graph Data Model** — Comprehensive call chain visualization with `ExecutionNode` (tool, function, verdict, timing, depth), `ExecutionEdge` (call/data-flow/delegation edges), and `ExecutionGraph` (session-scoped graphs with metadata)
- **Execution Graph Store** — In-memory store with configurable max graphs and age limits, session-based lookup, node lifecycle tracking (add, complete), and automatic cleanup
- **Graph Export Formats** — DOT (Graphviz) and JSON export with color-coded verdicts (green=allow, red=deny), edge styling by type, and full graph statistics
- **Graph Export API** — RESTful endpoints for graph management:
  - `GET /api/graphs` — List sessions with pagination and tool filtering
  - `GET /api/graphs/{session}` — Get graph in JSON format
  - `GET /api/graphs/{session}/dot` — Get graph in DOT (Graphviz) format
  - `GET /api/graphs/{session}/stats` — Get graph statistics (node count, depths, tool distribution)
- **Policy Validation CLI** — Enhanced `vellaveto check` command with:
  - `--strict` mode (warnings become errors)
  - `--format json|text` output format
  - `--no-best-practices` to skip best practice checks
  - `--no-security-checks` to skip security checks
  - Shadow policy, wide pattern, and dangerous configuration detection
- **Attack Simulation Framework** — Automated red-teaming based on OWASP ASI Top 10 and MCPTox benchmarks:
  - 10 attack categories (Prompt Injection, Data Disclosure, Sandboxing, etc.)
  - 40+ built-in attack payloads with severity ratings
  - Multi-step attack sequences, schema mutations, parameter manipulation
  - Result summarization by category and severity
  - JSON import/export for custom scenarios

#### Phase 5.5: Enterprise Hardening (Runtime)
- **TLS/mTLS Runtime** — TLS termination via tokio-rustls with client certificate extraction, SPIFFE identity parsing from X.509 SAN URIs, and configurable TLS/mTLS modes
- **OPA Client Runtime** — Async HTTP client for Open Policy Agent with LRU decision caching (configurable TTL), fail-open/fail-closed modes, and structured decision parsing
- **Threat Intelligence Runtime** — Full TAXII 2.1 (STIX format) and MISP client implementations with custom REST endpoint support, confidence filtering, and configurable actions on IOC match
- **JIT Access Runtime** — Session-based temporary elevated permissions with approval workflows, per-principal session limits, auto-revocation on security alerts, and permission/tool access checking

#### Phase 5: Enterprise Hardening (Configuration)
- **TLS/mTLS Configuration** — Server-side TLS and mutual TLS support with configurable cert paths, client CA verification, CRL/OCSP revocation checking, minimum TLS version, and cipher suite selection
- **SPIFFE/SPIRE Integration** — Zero-trust workload identity configuration with trust domain, workload API socket, allowed SPIFFE IDs allowlist, and ID-to-role mapping for RBAC
- **OPA Integration** — Open Policy Agent configuration for external policy evaluation with endpoint URL, decision path, caching (TTL), timeout, fail-open/closed mode, and local bundle support
- **Threat Intelligence Feeds** — Configuration for TAXII, MISP, and custom threat intelligence providers with IOC type filtering, confidence thresholds, refresh intervals, and configurable actions (deny/alert/require_approval)
- **Just-In-Time Access** — Temporary elevated permissions with configurable TTL, max sessions per principal, approval requirements, automatic revocation on security events, and notification webhooks

#### Phase 4.1: Standards Alignment
- **MITRE ATLAS Threat Mapping** — Registry of 14 ATLAS techniques (AML.T0051-T0065) with detection mappings for 30+ Vellaveto detection types, coverage reports, and audit event enrichment
- **OWASP AIVSS Integration** — AI Vulnerability Scoring System with CVSS-style base scores plus AI-specific multipliers (autonomy, persistence, reversibility), severity levels (None/Low/Medium/High/Critical), vector string parsing, and predefined profiles for common detections
- **NIST AI RMF Alignment** — Complete mapping to all 4 RMF functions (Govern, Map, Measure, Manage) with 25+ subcategory mappings, coverage statistics, compliance reports, and audit metadata enrichment
- **ISO/IEC 27090 Preparation** — Readiness assessment for 5 control domains (Data Security, Model Security, Operational Security, Supply Chain Security, Privacy & Ethics), gap analysis, recommendations engine, and certification readiness scoring

#### Phase 3.3: Advanced Threat Detection
- **Goal State Tracking** (ASI01) — Detects objective drift mid-session with similarity-based alignment checks, manipulation keyword detection, and configurable drift thresholds
- **Workflow Intent Tracking** — Long-horizon attack detection with step budget enforcement, cumulative effect analysis, and suspicious exfiltration pattern detection
- **Tool Namespace Security** (ASI03) — Prevents tool shadowing attacks via Levenshtein distance typosquatting detection, protected name patterns, and collision detection (exact, similar, version, trust)
- **Output Security Analysis** (ASI07) — Covert channel detection including steganography (zero-width chars, homoglyphs, invisible Unicode), Shannon entropy analysis, and output normalization
- **Token Security Analysis** — Token-level attack detection including special token injection (`<|endoftext|>`, etc.), context flooding/budget tracking, glitch token patterns (SolidGoldMagikarp, etc.), and Unicode normalization attacks
- **AdvancedThreatConfig** — Configuration for all advanced threat detection features with goal drift threshold, workflow step budget, context budget, and protected tool patterns

#### Phase 3.2: Cross-Agent Security
- **Agent Trust Graph** — Multi-agent trust relationship tracking with privilege levels (None, Basic, Standard, Elevated, Admin), delegation chain validation, and escalation detection
- **Inter-Agent Message Signing** — Ed25519 signed message envelopes with nonce-based anti-replay protection for secure inter-agent communication
- **Privilege Escalation Detector** — Second-order prompt injection detection with configurable thresholds, Unicode manipulation checks, delimiter injection detection, and suspicious agent pair tracking
- **CrossAgentConfig** — Configuration for cross-agent security features including message signing requirements, chain depth limits, trusted agents, nonce expiry, and escalation thresholds

#### Phase 3.1: Runtime Integration for Security Managers
- **Admin API endpoints** for all Phase 1 & 2 security managers:
  - Circuit breaker: `GET/POST /api/circuit-breaker/*` (list, stats, get state, reset)
  - Shadow agent: `GET/POST/PUT/DELETE /api/shadow-agents/*` (list, register, update trust)
  - Schema lineage: `GET/PUT/DELETE /api/schema-lineage/*` (list, get, reset trust, remove)
  - Task state: `GET/POST /api/tasks/*` (list, stats, get, cancel)
  - Auth level: `GET/POST/DELETE /api/auth-levels/*` (get, upgrade, clear)
  - Sampling detection: `GET/POST /api/sampling/*` (stats, reset)
  - Deputy validation: `GET/POST/DELETE /api/deputy/delegations/*` (list, register, remove)
- **Audit event helpers** for security events:
  - `log_circuit_breaker_event` - tracks open/closed/half-open/rejected states
  - `log_deputy_event` - tracks delegation and validation failures
  - `log_shadow_agent_event` - tracks agent impersonation detection
  - `log_schema_event` - tracks schema poisoning alerts
  - `log_task_event` - tracks async task lifecycle
  - `log_auth_event` - tracks step-up authentication
  - `log_sampling_event` - tracks sampling request denials
- **HTTP proxy integration** with circuit breaker check before forwarding tool calls
- Security managers integrated into ProxyBridge and AppState for runtime enforcement

#### Phase 2: Advanced Threat Detection (OWASP ASI Top 10)
- **Circuit Breaker** (ASI08) — Cascading failure prevention with configurable thresholds
- **Confused Deputy Prevention** (ASI02) — Delegation chain validation with depth limits
- **Shadow Agent Detection** — Agent fingerprinting and impersonation alerts
- **Schema Poisoning Detection** (ASI05) — Schema lineage tracking with mutation thresholds
- **Sampling Attack Detection** — Rate limiting and content inspection for sampling requests

#### Phase 1: MCP 2025-11-25 Compliance
- **Async Tasks Security** — Task state manager with lifecycle tracking
- **OAuth Resource Indicators** — RFC 8707 parsing and validation
- **CIMD** — Capability-indexed message dispatch routing
- **Step-Up Authentication** — Auth level tracking with upgrade flow

### Security
- Fix timing side-channel in CORS origin validation (R33-001) - origin matching now checks all configured origins to prevent timing-based enumeration

### Changed
- Security audit rounds: 32 → 33

---

## [1.0.0] - 2026-02-08

Initial production release of Vellaveto, a runtime security engine for AI agent tool calls.

### Core Features

#### Policy Engine
- Glob and regex-based policy matching for tools and functions
- Parameter constraint evaluation with multiple operators (glob, regex, domain_match, domain_in, domain_not_in)
- Priority-based policy ordering with deterministic evaluation
- Path traversal-safe normalization for filesystem rules
- RFC 1035-compliant domain validation for network rules
- Context-aware policies with time windows, call limits, and action sequences

#### Network Security
- DNS rebinding protection with private IP blocking
- CIDR-based allow/block lists for resolved IPs
- Domain allowlisting and blocklisting
- Carrier-grade NAT (100.64.0.0/10) blocking

#### Authentication & Authorization
- API key authentication for admin endpoints
- OAuth 2.1 / JWT support with JWKS validation
- Role-based access control (RBAC) with Admin, Operator, Auditor, and Viewer roles
- Agent identity attestation via signed JWTs
- Per-endpoint and per-principal rate limiting

#### Audit System
- Tamper-evident audit logging with SHA-256 hash chain
- Ed25519 signed checkpoints for integrity verification
- Configurable PII redaction (Off, Low, High)
- Audit log rotation support
- Multiple export formats: JSON Lines, CEF, syslog (RFC 5424)
- SIEM integrations: Splunk HEC, Datadog, Elasticsearch, webhook

#### Human-in-the-Loop Approvals
- Approval queue for dangerous operations
- Deduplication of pending approvals
- Full audit trail for approval decisions
- Configurable approval timeouts

#### Detection & Prevention
- Prompt injection scanning with Aho-Corasick pattern matching
- Unicode NFKC normalization for homoglyph attack prevention
- Semantic injection detection via n-gram TF-IDF similarity
- Data Loss Prevention (DLP) with 5-layer decode pipeline (raw, base64, percent, combinations)
- Rug-pull detection for tool schema changes
- Tool squatting detection via Levenshtein distance + homoglyph analysis
- Memory poisoning defense with cross-request data tracking
- Behavioral anomaly detection using EMA-based frequency tracking

#### Multi-Tenancy
- Tenant isolation for policy, audit, and approval data
- Tenant extraction from JWT claims, headers, or subdomains
- Per-tenant quotas and rate limiting
- Tenant management API endpoints

#### Observability
- Prometheus metrics endpoint with 24+ metrics
- OpenTelemetry instrumentation for distributed tracing
- Health and readiness endpoints
- Admin dashboard with server-rendered HTML

### Deployment

#### Docker
- Multi-stage Dockerfile for optimized builds
- Static musl-linked binaries (<50MB images)
- Non-root user execution
- Health checks included

#### Kubernetes
- Helm chart with comprehensive values.yaml
- Horizontal Pod Autoscaler support
- Ingress configuration
- Security contexts and pod disruption budgets

#### Clustering
- Redis backend for distributed state
- Shared approval state across instances
- Global rate limiting

### Security Hardening

- Fail-closed design: errors, missing policies, and unresolved context produce Deny
- Zero `unwrap()` in library code
- Constant-time API key comparison
- CSRF defense-in-depth via Origin/Referer validation
- Idempotency keys for at-most-once semantics
- 1MB request body limit
- Security headers (HSTS, X-Content-Type-Options, X-Frame-Options)
- CORS configuration
- 33 rounds of adversarial security audits

### Testing

- 3,167 tests across all crates
- Property-based testing with proptest
- Fuzz targets for:
  - JSON-RPC framing
  - Path normalization
  - Domain extraction
  - CIDR parsing
  - Message classification
  - Parameter scanning
  - Semantic similarity
- Criterion benchmarks for performance-critical paths
- Integration tests for OWASP MCP Top 10

### Documentation

- Comprehensive deployment guide (Docker, Kubernetes, bare metal)
- Operations runbook with troubleshooting procedures
- Security hardening guide
- Complete API reference
- Production configuration examples

### Breaking Changes from 0.x

This is the initial stable release. No breaking changes from previous versions.

---

## [0.1.0] - 2026-01-15

### Added
- Initial development release
- Core policy engine with basic glob matching
- Simple audit logging
- HTTP API server
- Stdio proxy mode
- Basic DLP scanning

---

## Types of Changes

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

[Unreleased]: https://github.com/paolovella/vellaveto/compare/v6.0.1...HEAD
[6.0.1]: https://github.com/paolovella/vellaveto/compare/v6.0.0...v6.0.1
[6.0.0]: https://github.com/paolovella/vellaveto/compare/v3.0.0...v6.0.0
[3.0.0]: https://github.com/paolovella/vellaveto/compare/v2.2.1...v3.0.0
[2.2.1]: https://github.com/paolovella/vellaveto/compare/v2.0.0...v2.2.1
[2.0.0]: https://github.com/paolovella/vellaveto/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/paolovella/vellaveto/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/paolovella/vellaveto/releases/tag/v0.1.0
