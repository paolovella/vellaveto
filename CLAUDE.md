# CLAUDE.md — Vellaveto Project Instructions

> **Project:** Vellaveto — MCP Tool Firewall
> **State:** shared substrate shipped; 2026 execution roadmap active (267 audit rounds)
> **Version:** 6.1.1
> **License:** Three-tier: MPL-2.0 / Apache-2.0 / BUSL-1.1 (see LICENSING.md)
> **Tests:** 11,571+ Rust + 59 React + 12 Terraform + 497 Python + 136 Go + 130 TypeScript + 135 Java + 26 VS Code, zero warnings, zero `unwrap()` in library code
> **Updated:** 2026-03-30

---

## Mission

Vellaveto is an agent interaction firewall — the runtime boundary where AI agents interact with tools, services, and users. It intercepts MCP (Model Context Protocol) and function-calling requests, enforces security policies on paths/domains/actions, and maintains a tamper-evident audit trail with structured ACIS decision envelopes.

**Non-negotiable properties:**
- **Fast:** <5ms P99 evaluation latency, <50MB memory baseline
- **Fail-closed:** Errors, missing policies, and unresolved context all produce `Deny`
- **Observable:** Every decision logged, every failure diagnosed
- **No panics:** Zero `unwrap()` in library code, `?` and `ok_or_else()` everywhere

---

## Current 2026 Execution Priorities

Treat `ROADMAP.md` as the current plan of record.

1. **Phase 0 — Sprint 2 closeout and worktree cleanup**
   Land the active HTTP proxy transport-convergence work, then close the formal/docs/paper and site/domain/package bundles in clean slices.
2. **Phase 1 — Protocol-complete runtime enforcement**
   Finish shared mediation coverage for sampling, elicitation, tasks, extensions, and stronger provenance/lineage enforcement across MCP and HTTP.
3. **Phase 2 — Policy, approval, and operator productization**
   Ship the buyer-facing controls still missing from the runtime core: approval workflows, policy DSL, richer authz, quotas, tracing, reputation, and inventory surfaces.
4. **Phase 3 — Multi-agent and advanced containment**
   Fund control-flow, per-value capability, lineage-drift, and counterfactual-containment work as mainline epics with explicit benchmarks and rollout gates.
5. **Phase 4 — Compliance evidence factory**
   Turn runtime evidence into Annex IV, Article 73, QMS, FRIA, and related buyer-facing artifacts.
6. **Phase 5 — Supply-chain and ecosystem trust**
   Add attestation, SBOM, rug-pull, registry reputation, and newer authorization/trust handling on top of the existing discovery substrate.

Execution rule: extend the shipped substrate in place; do not restart provenance, containment, ACIS, or mediation foundations that already exist.

---

## Before Every Session

```bash
git status
cargo check --workspace 2>&1 | head -50
cargo test --workspace --no-fail-fast 2>&1 | tail -5
cargo clippy --workspace
```

**If tests fail at session start:** STOP. Diagnose and fix before proceeding.

---

## Architecture

### Crate Dependency Graph (NEVER VIOLATE)

```
vellaveto-types          (leaf — no internal deps)
       |
vellaveto-canonical      (types only)
vellaveto-config         (types only)
       |
vellaveto-engine         (types, ipnet; optional: discovery)
vellaveto-discovery      (types only — topology graph, guard, crawler)
       |
vellaveto-audit          (types, engine)
vellaveto-approval       (types)
       |
vellaveto-mcp            (types, engine, audit, approval, config)
vellaveto-mcp-shield     (types, audit, config — consumer shield logic, MPL-2.0)
       |
vellaveto-cluster        (types, config, approval)
       |
vellaveto-tls            (config — rustls TLS/mTLS, SPIFFE, PQ KEX)
       |
vellaveto-server         (all above, discovery, tls)
vellaveto-http-proxy     (all above, tls)
vellaveto-proxy          (all above, stdio mode)
vellaveto-shield         (mcp, mcp-shield, canary — consumer shield binary, MPL-2.0)
vellaveto-http-proxy-shield (traffic padding, header stripping — MPL-2.0)
vellaveto-canary         (standalone — ed25519-dalek, Apache-2.0)
vellaveto-integration    (all above, test only)
vellaveto-operator       (standalone — kube-rs, no internal deps)
```

Lower crates MUST NOT depend on higher crates.
`vellaveto-operator` is a standalone binary crate with no internal deps — it talks to `vellaveto-server` via REST API.

### Key Types

```rust
Action { tool, function, parameters, target_paths, target_domains, resolved_ips }
Policy { id, name, policy_type, priority, path_rules, network_rules }
NetworkRules { allowed_domains, blocked_domains, ip_rules: Option<IpRules> }
IpRules { block_private, blocked_cidrs, allowed_cidrs }
Verdict::Allow | Verdict::Deny { reason } | Verdict::RequireApproval { .. }
```

### File Locations

| What | Where |
|------|-------|
| **vellaveto-types** | |
| Core types: Action, Verdict, Policy, PathRules, NetworkRules | `vellaveto-types/src/core.rs` |
| Identity: AgentIdentity, EvaluationContext, RequestContext, StatelessContextBlob | `vellaveto-types/src/identity.rs` |
| ETDI, Threat, ABAC, capability, compliance, NHI, governance, discovery, projector, ZK audit, audit store, policy lifecycle, evidence pack | `vellaveto-types/src/*.rs` |
| Shield types: BlindCredential, CredentialType, CredentialVaultStatus, SessionCredentialBinding | `vellaveto-types/src/shield.rs` |
| ACIS: AcisDecisionEnvelope, DecisionKind, DecisionOrigin, AcisActionSummary | `vellaveto-types/src/acis.rs` |
| Time utilities: parse_iso8601_secs | `vellaveto-types/src/time_util.rs` |
| Tests (~196) | `vellaveto-types/src/tests.rs` |
| **vellaveto-engine** | |
| ACIS action fingerprinting (SHA-256) | `vellaveto-engine/src/acis.rs` |
| Policy evaluation | `vellaveto-engine/src/lib.rs` |
| ABAC engine + Cedar-style evaluation | `vellaveto-engine/src/abac.rs` |
| Least-agency tracker | `vellaveto-engine/src/least_agency.rs` |
| Decision cache (LRU + TTL) | `vellaveto-engine/src/cache.rs` |
| Collusion detection (entropy, correlation) | `vellaveto-engine/src/collusion.rs` |
| Cascading failure circuit breakers | `vellaveto-engine/src/cascading.rs` |
| Wasm policy plugins (Wasmtime) | `vellaveto-engine/src/wasm_plugin.rs` |
| **vellaveto-audit** | |
| AuditLogger + rotation + verification | `vellaveto-audit/src/lib.rs` |
| Compliance registries (EU AI Act, SOC 2, CoSAI, Adversa, ISO 42001, OWASP ASI, OWASP MCP Top 10, DORA, NIS2, Singapore MGF, NIST AI 600-1, CSA ATF) | `vellaveto-audit/src/{eu_ai_act,soc2,cosai,adversa_top25,iso42001,owasp_asi,owasp_mcp,dora,nis2,singapore_mgf,nist_ai600,csa_atf,gap_analysis}.rs` |
| Cross-regulation incident reporting | `vellaveto-audit/src/incident_report.rs` |
| OCSF export | `vellaveto-audit/src/export/{mod,ocsf}.rs` |
| Evidence pack + ZK audit | `vellaveto-audit/src/evidence_pack.rs`, `vellaveto-audit/src/zk/*.rs` |
| Audit sink + PostgreSQL | `vellaveto-audit/src/sink.rs`, `vellaveto-audit/src/sink/postgres.rs` |
| Audit query (file/PostgreSQL) | `vellaveto-audit/src/query/{file,postgres}.rs` |
| Tests (~421) | `vellaveto-audit/src/tests.rs` |
| **vellaveto-config** | |
| PolicyConfig + validation | `vellaveto-config/src/lib.rs`, `vellaveto-config/src/config_validate.rs` |
| ACIS config (envelope emission, session/identity binding) | `vellaveto-config/src/acis.rs` |
| All config modules | `vellaveto-config/src/*.rs` |
| Tests (~301) | `vellaveto-config/src/tests.rs` |
| **vellaveto-mcp** | |
| MCP handling + proxy bridge | `vellaveto-mcp/src/lib.rs`, `vellaveto-mcp/src/proxy/bridge/*.rs` |
| DLP / inspection + multimodal | `vellaveto-mcp/src/inspection.rs`, `vellaveto-mcp/src/inspection/multimodal.rs` |
| Cross-call DLP (overlap buffers) | `vellaveto-mcp/src/inspection/cross_call_dlp.rs` |
| Capability tokens, accountability, DID:PLC, session guard | `vellaveto-mcp/src/{capability_token,accountability,did_plc,session_guard}.rs` |
| Semantic guardrails, A2A, transparency, discovery, projector | `vellaveto-mcp/src/{semantic_guardrails,a2a,transparency,discovery,projector}/` |
| A2A Agent Card signature enforcement | `vellaveto-mcp/src/a2a/signature.rs` |
| MCP Registry client + identity verification | `vellaveto-mcp/src/discovery/registry.rs` |
| MCP Task state lifecycle | `vellaveto-mcp/src/task_state.rs` |
| NHI identity lifecycle (ephemeral creds, rotation) | `vellaveto-mcp/src/nhi.rs` |
| **vellaveto-http-proxy** | |
| HTTP/WebSocket/gRPC proxy | `vellaveto-http-proxy/src/proxy/*.rs` |
| Transport health + smart fallback | `vellaveto-http-proxy/src/proxy/{transport_health,smart_fallback}.rs` |
| **vellaveto-server** | |
| HTTP API + routes (incl. topology) | `vellaveto-server/src/main.rs`, `vellaveto-server/src/routes/*.rs` |
| Dashboard + setup wizard | `vellaveto-server/src/{dashboard,setup_wizard}.rs` |
| DPoP token binding (RFC 9449) | `vellaveto-server/src/dpop.rs` |
| **vellaveto-operator** | |
| CRDs + reconcilers + client | `vellaveto-operator/src/{crd,client}.rs`, `vellaveto-operator/src/reconciler/*.rs` |
| Helm chart | `helm/vellaveto/` |
| **vellaveto-discovery** | |
| Topology graph (petgraph DiGraph) | `vellaveto-discovery/src/topology.rs` |
| TopologyGuard (pre-policy filter) | `vellaveto-discovery/src/guard.rs` |
| MCP server crawler + StaticProbe | `vellaveto-discovery/src/crawler.rs` |
| Data-flow inference | `vellaveto-discovery/src/inference.rs` |
| Topology diff (added/removed/changed) | `vellaveto-discovery/src/diff.rs` |
| Re-crawl scheduler | `vellaveto-discovery/src/schedule.rs` |
| Serialization (JSON/bincode) | `vellaveto-discovery/src/serialize.rs` |
| Tests (~100) | `vellaveto-discovery/tests/*.rs` |
| **vellaveto-mcp-shield** | |
| Shield error types | `vellaveto-mcp-shield/src/error.rs` |
| QuerySanitizer (bidirectional PII) | `vellaveto-mcp-shield/src/sanitizer.rs` |
| SessionIsolator (per-session PII) | `vellaveto-mcp-shield/src/session_isolator.rs` |
| EncryptedAuditStore (XChaCha20-Poly1305) | `vellaveto-mcp-shield/src/crypto.rs` |
| LocalAuditManager (encrypted + Merkle) | `vellaveto-mcp-shield/src/local_audit.rs` |
| CredentialVault (encrypted credential storage) | `vellaveto-mcp-shield/src/credential_vault.rs` |
| SessionUnlinker (credential rotation) | `vellaveto-mcp-shield/src/session_unlinker.rs` |
| ContextIsolator (per-session context window) | `vellaveto-mcp-shield/src/context_isolation.rs` |
| StylometricNormalizer (fingerprint resistance) | `vellaveto-mcp-shield/src/stylometric.rs` |
| Tests (~99) | `vellaveto-mcp-shield/src/tests.rs` |
| **vellaveto-tls** | |
| TLS/mTLS acceptor (rustls), SPIFFE, PQ KEX policy | `vellaveto-tls/src/lib.rs` |
| Tests (~11) | `vellaveto-tls/src/lib.rs` (inline) |
| **vellaveto-canary** | |
| WarrantCanary + create/verify | `vellaveto-canary/src/lib.rs` |
| Tests (~6) | `vellaveto-canary/src/tests.rs` |
| **vellaveto-shield** | |
| Consumer shield binary | `vellaveto-shield/src/main.rs` |
| **Other** | |
| Stdio proxy | `vellaveto-proxy/src/main.rs` |
| Cluster (leader election, service discovery) | `vellaveto-cluster/src/*.rs` |
| Integration tests (~110 files) | `vellaveto-integration/tests/` |
| SDKs: Python, TypeScript, Go, Java | `sdk/{python,typescript,go,java}/` |
| VS Code Extension | `vscode-vellaveto/` |
| Admin Console (React SPA) | `admin-console/` |
| Enterprise IAM (OIDC/SAML/RBAC) | `vellaveto-server/src/iam.rs`, `vellaveto-server/src/rbac.rs` |
| Self-service signup | `vellaveto-server/src/routes/signup.rs` |
| Terraform provider | `terraform-provider-vellaveto/` |
| OpenAPI 3.0 spec | `docs/openapi.yaml` |
| Policy preset templates (12) | `examples/presets/*.toml` |
| Cloud marketplace docs | `docs/MARKETPLACE.md` |
| SI pilot kit | `docs/si-pilot-kit/` |
| Cedar policy import/export | `vellaveto-config/src/cedar.rs` |
| Formal verification (TLA+, Alloy, Kani, Verus, Lean 4, Coq) | `formal/` |
| Coverage CI | `.github/workflows/coverage.yml` |
| Fuzz CI (dynamic analysis) | `.github/workflows/fuzz-ci.yml` |
| Reproducible builds docs | `docs/REPRODUCIBLE_BUILDS.md` |
| Security review docs | `docs/SECURITY_REVIEW.md` |
| Hardening docs | `docs/HARDENING.md` |
| OpenSSF Gold self-assessment | `docs/OPENSSF_GOLD.md` |

---

## Foundation Already Shipped (DO NOT rebuild)

The shared substrate and major platform foundations are implemented, tested, and hardened through 254 audit rounds. Extend them; do not rebuild them. See `CHANGELOG.md` for delivered rounds and `ROADMAP.md` for current 2026 sequencing.

**Core:** Policy evaluation (glob/regex/domain), path traversal protection, DNS rebinding, context-aware policies, decision cache (LRU+TTL), Wasm policy plugins (Wasmtime with fuel metering) | **Discovery:** Topology graph (petgraph DiGraph mapping MCP servers→tools→resources), TopologyGuard pre-policy filter (fail-closed, unknown tool denial with Levenshtein suggestions), MCP server crawler, StaticProbe (relay-fed in-memory probe), data-flow inference, topology diff, re-crawl scheduler with graceful shutdown, JSON/bincode serialization, feature-gated engine integration (`discovery` feature on vellaveto-engine), TopologyConfig (10 fields with validation), REST API (`/api/topology/*`), relay intercept for live `tools/list` topology updates | **Consumer Shield:** Bidirectional PII sanitization (QuerySanitizer with `[PII_{CAT}_{SEQ}]` placeholders), encrypted local audit (XChaCha20-Poly1305 + Argon2id), per-session isolation (SessionIsolator), Merkle proof generation, warrant canary sign/verify tooling + daily freshness check (Ed25519, Apache-2.0; no canary published yet — see docs/WARRANT_CANARY.md), consumer shield binary (`vellaveto-shield`), feature-gated ProxyBridge integration (`consumer-shield`), ShieldConfig (16 fields with validation, including traffic_padding), blind credential types (BlindCredential, CredentialType, CredentialVaultStatus), credential vault (CredentialVault with encrypted persistence, epoch expiration), session unlinkability (SessionUnlinker — each session consumes a fresh credential, fail-closed), context window isolation (ContextIsolator — per-session context, bounded entries/bytes, JSON request/response recording), stylometric fingerprint resistance (Level 1-2: whitespace/punctuation/emoji/quote/dash normalization, filler word removal, JSON recursive normalize), traffic padding (fixed-size buckets, privacy header stripping), full ProxyBridge pipeline wiring (sanitize→stylometric→context record outbound, desanitize→context record inbound, credential consumption per session), DLP + sampling + elicitation config wiring in shield binary, session cleanup on relay exit (ContextIsolator + SessionUnlinker end_session), credential vault auto-replenishment (background tokio task), desanitize_responses config flag wired, audit_mode local/remote config wired, ZK commitments feature-gated wiring (PedersenCommitter in LocalAuditManager) | **Audit:** Tamper-evident logging (SHA-256, Merkle, Ed25519), export (CEF/JSONL/webhook/syslog/OCSF), PostgreSQL dual-write, ZK proofs (Pedersen + Groth16) | **Security:** Injection (Aho-Corasick + NFKC), DLP (5-layer decode), tool squatting, memory poisoning, behavioral anomaly, multimodal injection, multi-agent collusion detection, cascading failure circuit breakers, NHI identity lifecycle (ephemeral creds, rotation enforcement) | **Auth:** OAuth 2.1/JWT/JWKS, ABAC forbid-overrides, capability delegation, least-agency, DPoP (RFC 9449) token binding | **Enterprise IAM:** OIDC (Okta/AzureAD/Keycloak), SAML 2.0, RBAC (4 roles, 14 perms), session management, SCIM 2.0 | **Transport:** HTTP, stdio, WebSocket, gRPC, MCP gateway, smart fallback | **MCP:** 2025-11-25 spec (Tasks primitive, CIMD, XAA, M2M auth, step-up authorization) | **Compliance:** EU AI Act, SOC 2, CoSAI, Adversa, ISO 42001, OWASP ASI, OWASP MCP Top 10, DORA, NIS2, Singapore MGF, NIST AI 600-1, CSA ATF, evidence packs, cross-regulation incident reporting | **Infra:** K8s operator (3 CRDs), multi-tenancy, policy lifecycle (Draft→Active), setup wizard | **Admin Console:** React SPA (10 pages), OIDC+API-key auth, RBAC navigation, dark theme, 59 vitest tests | **SDKs:** Python (sync+async, LangChain/LangGraph/CrewAI/Google ADK/OpenAI Agents/Composio/Claude Agent/Strands/MS Agents), TypeScript, Go, Java (120 tests) | **DevEx:** VS Code extension (validation, completions, snippets, simulator), execution graph SVG export | **Terraform:** Provider with policy resource + data sources (health, policies) | **Billing:** Per-tenant metering (atomic counters), quota enforcement, Stripe/Paddle webhooks, tiered licensing | **Marketplace:** Self-service signup (POST /api/signup), 18 policy preset templates, OpenAPI 3.0 spec (147+ paths), cloud deployment docs (AWS/Azure/GCP) | **PQC:** Hybrid Ed25519+ML-DSA-65 (FIPS 204) checkpoint/manifest signatures, backward-compatible, feature-gated | **Cedar:** Policy import/export for AWS AgentCore/CNCF Cedar interoperability | **A2A Hardening:** Agent Card Ed25519 signature enforcement, MCP Registry integration, DPoP token binding | **Formal (682 Verus + 116 Kani + 14 TLA+ specs + 45 Coq + 32 Lean + 10 Alloy = 910+ verification instances):** TLA+ (14 specs in CI: policy engine, ABAC, workflow, task lifecycle, cascading failure, credential vault, audit chain, trust containment, source taint containment, intent scope containment, sequence containment, NHI credential rotation), Alloy (capability delegation — now in CI), Kani (108 CBMC proof harnesses + 240 unit tests: K1-K132), Verus (47 kernels, 668 verified items: V1-V12 verdict/rule core, V9-V10 path normalization, D1-D6 DLP buffer, ENG-CON-1–4 constraint eval, AUD-APP/CHAIN/MERKLE audit integrity, ROT-MAN rotation manifests, CAP-ATT/GLOB/GRANT/LIT/PAT/ID capability delegation, NHI-DEL-1–8 NHI delegation + revocation chain, ENT-GATE entropy alert, CC-DLP cross-call DLP, R-MCP 9/9 refinement obligations complete, ACIS envelope + action summary invariants, TAINT-1–5 source-class containment, SCOPE-1–5 intent scope narrowing, SEQ-1–6 sequence analysis monotonicity, EPIPE-1–6 entropy pipeline composition), Lean 4 (fail-closed, determinism, path idempotence), Coq (45 theorems: S1/S5 fail-closed, determinism, path idempotence, S7-S10 ABAC forbid-override, S11-S16 capability delegation attenuation, C1-C5 circuit breaker, T1-T3 task lifecycle)

**Adversarial hardening:** 267 audit rounds, 1,750+ findings fixed. Key patterns enforced: `deny_unknown_fields` on all deserialized structs, `validate()` with bounded collections, `has_dangerous_chars()` on all external strings, custom `Debug` redacting secrets, `saturating_add` on all counters, transport parity across HTTP/WS/gRPC/stdio/SSE.

**R230 transport parity + threat intel (Feb 2026):** Extension method handler injection/circuit-breaker/shadow-agent parity, task request injection scanning, resource read URI injection scanning, sampling/createMessage injection scanning (TI-2026-002 P0), JSON-RPC key case-folding smuggle defense (CVE-2026-27896), error message social engineering patterns (CyberArk "Poison Everywhere"), signup API key hash persistence, tenant ID 64-bit entropy, DPoP htu scheme case-insensitivity. 21 new tests.

**SANDWORM-001 hardening (Feb 2026):** Defends against npm supply-chain worms that inject rogue MCP servers into AI assistant configs. Server allowlist enforcement (`governance.require_server_registration`), tool-to-server origin binding with conflict detection (`ToolEntry.server_id`), `sandworm-hardened.toml` preset with all 10 defensive layers enabled. See `docs/THREAT_MODEL.md` for full attack chain analysis.

**SANDWORM-P1 threat intelligence hardening (Feb 2026):** 5 P1 defenses from threat intelligence sweep (100+ attack vectors, 30+ CVEs analyzed): FlipAttack reversal detection (98% ASR defense — char-level + word-level), Full-Schema Poisoning coverage (`$comment`, `const`, `if/then/else`, `not`, `patternProperties`, `dependentSchemas`, `prefixItems`, `contains`), emoji smuggling via regional indicator sequences (U+1F1E6-U+1F1FF), Unicode Tag Character stripping verified (U+E0000-U+E007F), A2A Agent Card content injection scanning (description, skills, tags, examples). 22 new tests.

**R226 threat intelligence sweep (Feb 2026):** 17-item hardening across 3 sprints (P0/P1/P2). MCP-ITP implicit tool poisoning defense, Policy Puppetry injection (`<override>`/`<system_prompt>`/`[SYSTEM]`), URL exfiltration entropy analysis, reconnaissance probe detection (denial-rate sliding window), leetspeak normalization (14-char map), gradual constraint drift detection, OWASP MCP Top 10 compliance registry (`vellaveto-audit/src/owasp_mcp.rs`), cross-regulation incident reporting with DORA/NIS2/EU AI Act timelines (`vellaveto-audit/src/incident_report.rs`), CEF timestamp timezone normalization, audit chain timestamp monotonicity, cross-tenant rate-limit isolation, SANDWORM integration tests. 274 new tests.

**R227 code quality + discovery wiring + threat hardening (Feb 2026):** 8-item round: 3 clippy fixes (is_multiple_of, clamp, let_and_return), R24-MCP-1 discovery engine wired to production (`ingest_tools_list()` called from `handle_tools_list_response()`), ROT13 decode pass in injection scanner (compound obfuscation defense), per-tool sampling rate limiting (`max_per_tool`: 50/60s window), tool capability drift detection (`governance.block_tool_drift`), imperative instruction detection in tool descriptions (10 patterns, threshold 2+). 30 new tests.

**R228 adversarial audit (Feb 2026):** 11 findings (1 CRITICAL, 3 HIGH, 4 MEDIUM, 3 LOW). API key auth bypass via RBAC JWT passthrough (Bearer prefix validation), base64-encoded injection bypass (LLMs decode base64 inline), schema poisoning actual similarity vs decayed trust_score, ROT13 natural-language false-positive suppression, URL exfiltration extended to ftp/ftps/protocol-relative, cache key DNS rebinding fix (resolved_ips_hash), elicitation title injection scanning, UTC timestamp suffix normalization, sampling_per_tool capacity bound. 38 new tests.

**R229 adversarial audit (Feb 2026):** 9 findings (3 HIGH, 4 MEDIUM, 2 LOW). JWK thumbprint JSON injection guard (DPoP token binding bypass), cascading pipeline tracker fail-closed on capacity exhaustion, collusion detection 5x fail-closed on capacity (CapacityExhaustion alert type), DPoP nonce/ath dangerous char validation, DPoP counters saturating_add, DpopHeader deny_unknown_fields, collusion usize→u32 safe cast. SAML SubjectConfirmation hardening. 10 new tests.

**R231 adversarial audit + threat intelligence (Feb 2026):** 21 findings (7 adversarial + 14 threat intel). Elicitation handler DLP + injection scanning parity (R231-RELAY-1), resource read + task request circuit breaker + shadow agent detection (R231-RELAY-2), `min_entropy_observations=0` alert flood fix (R231-COLL-1), topology snapshot serialization fail-closed (R231-SRV-2), topology server name echo sanitization (R231-SRV-3), Unicode confusable JSON-RPC key smuggling defense for U+017F/U+212A (TI-2026-002), memory persistence poisoning patterns (TI-2026-004), viral agent loop patterns (TI-2026-005), Log-To-Leak justification-framed injection patterns (TI-2026-003), MetaBreak special token detection (TI-2026-010), parameter name exfiltration detection (TI-2026-006), sharded exfiltration tracker (TI-2026-001), SAML metadata URL scheme + SSRF validation (TI-2026-007). 49 new tests.

**R259-R267 adversarial audit campaign (Mar 2026):** 9-round swarm audit campaign, 30 findings fixed (9 HIGH, 14 MEDIUM, 7 LOW). 11 architectural hardening changes: Ed25519 evidence pack signing (non-repudiation + tamper detection), SHA-256 plugin content-hash verification (TOCTOU defense), FallbackBehavior::Allow gated behind acknowledgment flag (OPA pattern), eager transitive NHI delegation revocation (BFS depth-bounded), transparency Full verbosity gated behind is_admin authorization, atomic signup capacity check (tokio::sync::Mutex TOCTOU fix), webhook idempotency tracking (DashMap + TTL dedup), SessionBackend trait + write-through persistence, warm restart restoring Locked/Suspicious sessions, per-tenant API key verification (SHA-256 + constant-time compare), cross-tenant integration test suite. 4 new Verus kernels (DRIFT-1–4, REVOKE-1–4, EVIDENCE-SIGN-1–3, WARM-1–3), 8 new Kani harnesses (K133-K140). SDK attestation validation hardened across Python/TypeScript/Go/Java (signature length, type safety, CRLF injection). Relay hot-path audit: approval lineage drift enforcement, ACIS audit entries for DoW/jailbreak/token-leakage/memory-query, store error fail-closed. 11,571+ Rust tests, 556+ SDK tests, 0 failures.

**OpenSSF Gold Badge (Mar 2026):** SPDX license headers on all 211 `.rs` files (CI-enforced), coverage CI with cargo-llvm-cov + Codecov, dynamic analysis CI (5 fuzz targets × 30s weekly), reproducible builds (`-Ctrim-paths=all` via RUSTFLAGS), security review documentation (267 audit rounds), hardening documentation, code review standards in CONTRIBUTING.md, 2FA requirement in SECURITY.md, Gold self-assessment (`docs/OPENSSF_GOLD.md`).

**Known Limitations Resolved (Mar 2026):** All four previously documented limitations closed. **Phase 71** — Cross-call DLP: `CrossCallDlpTracker` with overlap buffers (~150 bytes/field, 256 max fields) detects secrets split across tool calls within a session (12 tests). **Phase 71.1** — TLS termination: `vellaveto-tls` crate provides shared rustls-based TLS/mTLS with SPIFFE identity extraction and post-quantum KEX policy (ClassicalOnly/HybridPreferred/HybridRequiredWhenSupported, 11 tests). **Phase 72** — Grammar-validated injection: MCPSEC A13 (cross-call secret splitting) + A14 (JSON Schema output validation bypass) attack tests; registry expanded to 72 attacks across 14 classes. **Independent verification** — `SECURITY_BOUNTY.md` (HackerOne + Huntr), `docs/OSTIF_AUDIT_SCOPE.md`, `codecov.yml` (80% patch target). Test coverage expanded by 3,764 lines across 16 files (audit, cluster, gRPC, MCP modules).

**R233-R235 adversarial audits (Mar 2026):** Three 6-agent swarm audits. R233 found 4 P0 integration gaps (cross-call DLP, sharded exfil, TLS dedup, credential fail-open) — all wired. R234 found 42 findings (Sprint 1+2 fixed). R235 found 59 findings across engine, server, MCP relay, discovery, audit, config, and types. 40 fixed in 3 sprints: 13 HIGH (transport parity for CB/shadow-agent/deputy/DLP on all handlers, TopologyGuard fail-closed, OIDC redirect SSRF, credential persistence), 17 MEDIUM (deny reason genericization, DPoP fail-closed, threat intel validation, RwLock poisoning recovery, `has_dangerous_chars` parity, 3 new `validate()` methods), 10 LOW (saturating_add, SeqCst ordering, `try_from` casts, per-entry config validation). 246 audit rounds total, 1,720+ findings fixed.

**R236 adversarial audit (Mar 2026):** 20 findings fixed. See commit `ad4e4ee`.

**R237 adversarial audit (Mar 2026):** 31 findings (7 HIGH, 16 MEDIUM, 8 LOW), 22 fixed in 3 sprints. Sprint 1: Wasm reload_plugins case-insensitive duplicate (ENG-1), HTML named entity decode gap (MCP-1), OIDC/session error genericization (SRV-1/3), store_flow capacity fail-closed (SRV-2), shield passphrase env var (SHLD-1), audit log error surfacing (DIFF-1). Sprint 2: sampling/elicitation circuit breaker (MCP-2), cross-call DLP capacity finding (MCP-4), elicitation DLP tool name (MCP-5), SPIFFE trust_domain validation (TLS-1), context isolation method sanitization (SHLD-3), collusion window bounds (ENG-7), call_chain u64→i64 safe cast (PROXY-1). Sprint 3: regex constraint path normalization (ENG-2), ABAC normalize_full() for all string ops (ENG-3/5), cache risk_score awareness (ENG-6), temp file cleanup guard (SHLD-2), verify_client_cert validation (TLS-2), M2M per-client rate limiting (SRV-4), SAML InResponseTo replay protection (SRV-5), Punycode decode pass in injection scanner (MCP-3), semantic guardrails timeout audit logging (MCP-6), TLS path traversal validation (CFG-1). 10,990+ tests, 0 failures.

**E1 — ACIS Contract and Boundary Inventory (Sprint 1, Mar 2026):** Defines the Agent-Consumer Interaction Surface as a runtime contract shared by every enforcement path. E1-1: `AcisDecisionEnvelope`, `DecisionKind`, `DecisionOrigin`, `AcisActionSummary` types in `vellaveto-types/src/acis.rs` (16 tests). E1-2: `AcisConfig` in `vellaveto-config/src/acis.rs` — envelope emission, session/identity binding, transport defaults (11 tests). E1-3: Full transport interception inventory (stdio relay, HTTP handler, WebSocket, gRPC, server API). E1-4: `compute_action_fingerprint()` SHA-256 + `fingerprint_action()` in `vellaveto-engine/src/acis.rs` (6 tests). E1-5: `acis_envelope: Option<AcisDecisionEnvelope>` added to `AuditEntry` (backward-compatible). 33 new tests.

**R244 adversarial audit (Mar 2026):** 19 findings (2 CRITICAL, 5 HIGH, 7 MEDIUM, 5 LOW). Sprint 1: ACIS envelope validation before audit persistence (ACIS-1), approval consumption TOCTOU closure — moved atomically adjacent to match at all 6 relay sites (TOCTOU-1). Sprint 2: ACIS field bounds (MAX_TOOL_LEN/MAX_FUNCTION_LEN 256, agent_id 512, dangerous chars on all string fields), nested agent_identity validation, Cedar parser escape boundary fix (trailing backslash), Redis TLS enforcement for non-localhost. Sprint 3: session binding on all 6 `create_pending_approval()` sites, evaluation_us/call_chain_depth capping, formal proof for consumed-status blocking. Sprint 4: transport parity — `EvaluationContext` passed to all `build_acis_envelope()` across HTTP proxy (6 sites), gRPC (12 sites), WebSocket (12 sites). TLS UTF-8 validation on percent-decoded SPIFFE workload paths. Verus proof: `lemma_consumed_status_blocks_re_consumption()`. 10,990+ tests, 0 failures.

**Adversarial hardening:** 267 audit rounds, 1,750+ findings fixed. Key patterns enforced: `deny_unknown_fields` on all deserialized structs, `validate()` with bounded collections, `has_dangerous_chars()` on all external strings, custom `Debug` redacting secrets, `saturating_add` on all counters, transport parity across HTTP/WS/gRPC/stdio/SSE.

---

## Code Change Protocol

### Small Change (<20 lines)
```bash
cargo test -p <crate>
git add <files> && git commit -m "<type>(<scope>): <description>"
```

### Large Change (>100 lines)
```bash
# 1. Types first (compile, test)
# 2. Core logic (compile, test)
# 3. Integration points (compile, test)
# 4. Full validation
cargo test --workspace
cargo clippy --workspace
```

### Commit Format
```
<type>(<scope>): <subject>

<body>
```

Types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`
Scopes: `types`, `engine`, `audit`, `config`, `mcp`, `server`, `proxy`, `integration`, `discovery`

---

## Error Handling Rules

```rust
// CORRECT: Custom error type, no panics
pub fn evaluate(&self, action: &Action) -> Result<Verdict, EngineError> {
    let policy = self.find_policy(&action.tool)
        .ok_or_else(|| EngineError::NoPolicyFound(action.tool.clone()))?;
}

// WRONG: Panics in library code
pub fn evaluate(&self, action: &Action) -> Verdict {
    let policy = self.find_policy(&action.tool).unwrap(); // NEVER
}
```

---

## Testing Protocol

```bash
cargo test --lib --workspace          # Quick check
cargo test --workspace                # Full suite
cargo test -p vellaveto-engine        # Specific crate
cargo test -p vellaveto-engine -- --nocapture  # With output
```

Test naming: `test_<function>_<scenario>_<expected>`

---

## Security Checklist (before any PR)

- [ ] Fail-closed: errors produce Deny, not Allow
- [ ] No path traversal possible in PathRules
- [ ] Domain normalization handles edge cases
- [ ] Secrets never logged (parameters may contain API keys)
- [ ] Input validation on all external data
- [ ] No `unwrap()` or `expect()` in library code
- [ ] Rate limiting considered for new endpoints

---

## Common Mistakes to Avoid

> **Full orientation protocol:** See `docs/ONBOARDING.md` for the
> complete 17-trap checklist, transport parity matrix, and verification gates.
> Every instance MUST read it before modifying code.

### General
1. **Adding dependencies without justification** — every dep is attack surface
2. **Using `unwrap()` in library code** — use `?` or `ok_or_else()`
3. **Cloning when borrowing works** — check if `&T` suffices
4. **Skipping tests** — tests catch regressions you will introduce
5. **Ignoring warnings** — warnings become bugs
6. **Async where sync suffices** — the engine is synchronous by design
7. **Silent failures** — every error must be observable
8. **Premature optimization** — measure first, optimize proven hot spots

### Discovered from 226 audit rounds (top causes of breakage)
9. **Changing error messages without grepping tests** — tests assert on exact substrings; grep `tests.rs` for the old string before changing
10. **Using a name-similar constant** — `MAX_ID_LENGTH` vs `MAX_SERVER_ID_LENGTH` are different; verify the doc comment matches your domain
11. **Adding unbounded collections** — every `Vec`/`HashMap`/`HashSet` needs a `MAX_*` constant enforced in `validate()`
12. **Fail-open defaults** — defaults and error branches must produce `Deny`, not `Allow`; `unwrap_or(true)` on a lock is a security bypass
13. **Missing transport parity** — if HTTP handler has a check, WebSocket/gRPC/stdio/SSE must too; see `docs/ONBOARDING.md` Section 4
14. **Leaking secrets in `Debug`** — custom `Debug` impl required for types with keys, tokens, or signatures
15. **SDK payload format drift** — all 3 SDKs must match server's serde layout; test after any server format change
16. **Numeric fields without range validation** — `f64` scores need `[0.0, 1.0]` checks; `NaN`/`Infinity` bypass thresholds
17. **Counters without saturating arithmetic** — `+= 1` wraps to zero; use `saturating_add` for rate limits and circuit breakers

---

## References

- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP](https://arxiv.org/abs/2506.01333)
- [Enterprise-Grade Security for MCP (arxiv)](https://arxiv.org/pdf/2504.08623)

---

## Swarm Multi-Agent Protocol

This project uses local swarm-based multi-agent orchestration. See `.claude/rules/` for agent roles, communication protocols, coordination state management, and dangerous commands policy.
