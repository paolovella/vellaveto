# Vellaveto Security Model

This document defines Vellaveto's trust boundaries, data flows, storage guarantees, and residual risks. It is intended for security teams evaluating Vellaveto for production deployment.

---

## Trust Boundaries

```
                 +------------------+
  Agent/LLM ---->|  Vellaveto Proxy  |----> MCP Tool Server
                 |  (trust boundary)|
                 +------------------+
                    |            |
              Policy Engine   Audit Log
              (in-memory)     (on-disk)
```

**Vellaveto sits between the AI agent and the tool server.** Every tool call crosses the trust boundary twice: once on the request path (where policy is evaluated) and once on the response path (where output is inspected).

---

## Data That Enters Vellaveto

| Data | Source | Purpose |
|------|--------|---------|
| `tool` + `function` names | Agent request | Policy matching, squatting detection |
| `parameters` (JSON) | Agent request | Path/domain extraction, DLP scanning, injection detection |
| `target_paths` / `target_domains` | Extracted from parameters | Policy evaluation against path/network rules |
| `resolved_ips` | DNS resolution by proxy | DNS rebinding protection |
| `Authorization` header | Agent/client | OAuth 2.1 / JWT validation, scope enforcement |
| `X-Agent-Identity` header | Upstream proxy | Call chain tracking, identity attestation |
| HTTP response bodies | Tool server | Output validation, DLP scanning, injection detection |
| MCP elicitation/sampling | MCP server | Capability validation, rate limiting |

**All external input is validated:** tool/function names are length-bounded (256 bytes), control characters (U+0000-U+009F) are rejected, and parameters are depth-limited to prevent stack exhaustion.

---

## Data That Is Stored

### Audit Log (disk, append-only)

Each policy decision is written as a JSON Lines entry containing:
- Timestamp, tool name, function name, verdict, matched policy ID, reason
- **Redacted** parameters (secrets, PII, credentials replaced with `[REDACTED]`)
- SHA-256 hash chain linking each entry to the previous
- Optional Ed25519 checkpoint signatures every N entries
- Optional ACIS decision envelope — structured metadata containing decision ID, SHA-256 action fingerprint, verdict kind, decision origin (PolicyEngine or ApprovalGate), transport label, and session/tenant binding (backward-compatible: `acis_envelope` is `null` for pre-ACIS entries)

**Integrity:** The hash chain provides tamper *detection* (not prevention). An attacker with file-system write access could truncate the log, but this is detected on the next verification pass.

**What the chain proves, precisely:** entries form a hash-linked sequence whose
internal order is verifiable. It does **not** establish absolute times — see
[Signing and timestamps](#signing-and-timestamps) below. Timestamp monotonicity
is checked in `verify_chain()` only, as a lexicographic comparison of the
timestamp strings; nothing is checked when an entry is appended, so a backwards
host clock jump produces a log that later fails its own verification rather than
being rejected at write time. Entries with `sequence == 0` are accepted
unconditionally for backward compatibility and skip the sequence check.
Tracked as DOC-CRED-3 in [the audit log](AUDIT_LOG.md).

**Checkpoints are opt-in.** They are disabled by default
([Defaults](DEFAULTS.md)), and if `VELLAVETO_SIGNING_KEY` is unset a fresh key is
generated per process — which makes checkpoints unverifiable across restarts.
For the guarantee to mean anything, three things must be configured: enable
checkpoints, set `VELLAVETO_SIGNING_KEY` to a persistent value, and pin
`VELLAVETO_TRUSTED_KEY` on the verifying side.

**Rotation:** Logs rotate at 100 MB by default. Each rotated file gets a timestamped name and a manifest entry for chain continuity verification.

### Approval Queue (in-memory, optional file export)

Pending human approvals store the full `Action` (including unredacted parameters) so reviewers can make informed decisions. Approvals expire after 1 hour (configurable TTL) and are capped at 10,000 pending entries. When an approval is reused on `/api/evaluate`, Vellaveto fails closed unless the presented approval is already approved, its stored scope bindings (`session_id` and/or `action_fingerprint`) match the current request, and the approval has not already been consumed by a prior successful allow. Successful reuse transitions the approval to `Consumed`, so replay attempts fail closed.

**Self-approval prevention:** The `requested_by` identity must differ from the `resolved_by` identity.

### Policy Configuration (disk, operator-managed)

Vellaveto reads policies from TOML files. It does not write or modify policy files. Hot-reload is supported via filesystem watcher or API endpoint.

---

## Data That Is Redacted

Vellaveto applies multi-layer redaction before writing audit logs:

**Sensitive key names** (always redacted): `password`, `secret`, `token`, `api_key`, `authorization`, `credentials`, `private_key`, `client_secret`, `session_token`, `refresh_token`

**Sensitive value prefixes** (always redacted): `sk-` (OpenAI/Anthropic), `AKIA` (AWS), `ghp_`/`gho_`/`ghs_` (GitHub), `xoxb-`/`xoxp-` (Slack), `Bearer`/`Basic` (auth headers), `sk_live_` (Stripe), `AIza` (Google), `SG.` (SendGrid), `npm_`, `pypi-`

**PII patterns** (extensible): the built-in set is exactly seven — email
addresses, US SSNs, US phone numbers, credit card numbers (Luhn-validated),
IPv4 addresses, JWTs, and AWS key IDs.

These defaults are **US-centric and deliberately narrow**. Not covered: IBANs,
NHS numbers, EU/UK national IDs, passport numbers, non-US phone formats, IPv6
addresses, **filesystem paths**, and **personal names**. Add site-specific
patterns as `CustomPiiPattern` entries; each is checked by
`validate_regex_safety()` for ReDoS-prone constructs before being compiled.

The same pattern set backs the Consumer Shield's `QuerySanitizer`, so the
Shield's sanitization coverage is identical to the list above.

Redaction level is configurable: `Off`, `KeysOnly`, `KeysAndPatterns` (default), `High`.

---

## Data That Never Leaves the Process

| Data | Lifetime | Why |
|------|----------|-----|
| `EvaluationContext` (call counts, previous actions, call chain) | Per-request | Ephemeral session state, reconstructed each request |
| Behavioral anomaly baselines (EMA) | Per-session | Frequency tracking for tool usage patterns |
| Schema poisoning cache | Process lifetime | In-memory comparison of tool schema versions |
| Memory poisoning tracker | Per-session | Cross-request data laundering detection |
| Semantic injection n-grams | Process lifetime | TF-IDF similarity cache |
| DLP scan intermediate results | Per-request | Only the verdict is logged, not matched content |
| Raw JWT payload | Per-request | Only extracted claims (issuer, subject, audience) are logged |
| Circuit breaker state | Process lifetime | Open/HalfOpen/Closed per policy |

---

## Signing and Timestamps

### Why Ed25519

Ed25519 (RFC 8032) signs audit checkpoints, rotation manifests, evidence packs,
capability tokens, accountability attestations, ETDI tool signatures, A2A agent
cards, and warrant canaries. The reasons, in order of weight:

1. **Deterministic nonce derivation.** The per-signature secret is derived from
   the private key and the message rather than sampled from an RNG. ECDSA and
   DSA disclose the private key outright when the per-signature nonce repeats or
   is biased — the failure that broke the PS3 code-signing key and drained
   Bitcoin wallets on a faulty Android RNG. Vellaveto's signer runs unattended on
   operator-chosen hardware, including VMs that are snapshotted and forked, where
   RNG state can genuinely repeat. Taking the RNG out of the signing path removes
   that entire failure class. This is the deciding reason.
2. **Fixed, small artifacts.** 32-byte public keys and 64-byte signatures.
   Checkpoints are emitted every N entries and evidence packs are shipped to
   auditors, so per-signature overhead is a recurring cost.
3. **Fast verification, and batch verification is available** — verifying a long
   chain of checkpoints is a bulk operation.
4. **An audited implementation.** `ed25519-dalek` has a published third-party
   audit (Quarkslab, 2023). See [Trusted Computing Base](TRUSTED_COMPUTING_BASE.md).

**The trade-offs, stated plainly:**

- **Ed25519 is not FIPS 140-3 approved**, and Vellaveto's own `FipsMode`
  rejection list names it. Operators under a FIPS obligation must select the
  approved signing path (ECDSA P-256) and must not rely on Ed25519 checkpoints
  as compliance evidence. See [Compliance](COMPLIANCE.md).
- **Ed25519 is not post-quantum.** The `pqc-hybrid` feature adds ML-DSA-65
  (FIPS 204) alongside Ed25519, but only for **checkpoints and rotation
  manifests** — not evidence packs, canaries, agent cards, or capability tokens.
  The feature is not enabled by default.
- **There is no domain separation on the Ed25519 payloads.** Every one is a bare
  32-byte SHA-256 digest with no context prefix, so a checkpoint digest and an
  evidence-pack digest are indistinguishable to a verifier. The
  `CHECKPOINT_CONTEXT` / `MANIFEST_CONTEXT` separators apply to the ML-DSA half
  of the hybrid only. **Operator rule: never reuse one key seed across
  `VELLAVETO_SIGNING_KEY`, `create_canary`, `issue_capability_token`,
  `EtdiSigner`, and `sign_evidence_pack`.** Distinct artifact types must use
  distinct keys. Tracked as DOC-CRED-2 in [the audit log](AUDIT_LOG.md).

### Where signing time comes from

All timestamps in signed artifacts are read from the **signing host's wall
clock** (`chrono::Utc::now()`). Vellaveto does not use an RFC 3161 timestamp
authority, Roughtime, or any other external time anchor, and does not
cross-anchor signatures to a transparency log.

A valid signature therefore attests **that this content was signed by this key**.
It does **not** attest **when**. An operator holding the signing key can assign
any timestamp to any artifact, and nothing in the verification path can detect
it. Chain monotonicity constrains the *ordering* of audit entries relative to
each other; it does not constrain their absolute values.

This bounds what the signatures can be used for:

| Claim | Holds? |
|---|---|
| This artifact was produced by the holder of key *K* | Yes, against an out-of-band pinned *K* |
| This artifact has not been modified since signing | Yes |
| These audit entries are in the order they were written | Yes, if verification passes |
| This artifact existed at the time it states | **No** |
| The key holder cannot repudiate the stated time | **No** |

Accordingly, "non-repudiation" in this project means **tamper detection and
authorship attribution under a pinned key** — not proof of time, and not a
guarantee against the key holder.

### Warrant canary

The canary is an Ed25519-signed statement with a self-asserted `signed_date` and
`expires_date`. Three limits determine what it can be used for:

1. **`verify_canary()` does not authenticate the signer.** It verifies the
   signature against the verifying key carried *inside the canary*, so
   `signature_valid: true` means only that the canary is internally consistent.
   Anyone can generate a keypair and sign an arbitrary statement. A canary is
   meaningful only when checked against a publisher key obtained out of band.
2. **The date is self-asserted.** `signed_date` is the signer's own clock at day
   granularity, with no external anchor, so it can be back- or forward-dated.
3. **Issuance is not shipped.** `create_canary()` has no caller outside its own
   tests — there is no CLI, no route, no publication workflow, and no published
   cadence. Vellaveto can verify a canary; it does not yet issue one.

The fix for (2) is not a timestamp authority. The standard warrant-canary
construction is an **external unpredictable anchor**: the statement quotes a
recent public value that could not have been known earlier — a news headline, or
a recent Bitcoin block hash. That proves the canary was signed *no earlier than*
the anchor existed; a published renewal cadence bounds it from the other side.
Both are required, because a canary's signal is the **absence** of a renewal, and
without a stated period silence cannot be read.

Tracked as DOC-CRED-4 in [the audit log](AUDIT_LOG.md).

---

## Threats Covered

| Threat | Detection | Response |
|--------|-----------|----------|
| **Unauthorized tool access** | Policy engine (glob/regex matching) | Deny + audit |
| **Path traversal** | Normalization + blocked globs | Deny |
| **DNS rebinding** | IP resolution + private range blocking | Deny |
| **Prompt injection in parameters** | Aho-Corasick + semantic similarity | Deny or flag |
| **Tool squatting / rug-pull** | Levenshtein distance + homoglyph detection + schema pinning | Flag + persistent block |
| **Credential exfiltration** | DLP scanning (5-layer decode: raw/base64/percent/combos) | Deny |
| **Privilege escalation (multi-agent)** | Call chain depth limits + identity verification | Deny |
| **Schema poisoning** | Annotation change detection + persistent flagging | Block tool |
| **Behavioral anomaly** | EMA-based frequency tracking per agent | Alert |
| **Cross-request data laundering** | Session-level exfiltration chain detection | Alert |
| **Elicitation abuse** | Capability/schema/rate-limit validation | Deny |

---

## Threats NOT Covered

These are explicitly out of scope or represent residual risks:

### Out of Scope

1. **LLM-internal threats** — Model weight manipulation, training data poisoning, and in-model jailbreaks operate below Vellaveto's interception layer. Vellaveto evaluates the *output* of the LLM's decision, not the decision process itself.

2. **Credential provisioning** — How agents obtain credentials is outside Vellaveto's scope. Vellaveto blocks suspicious *use* of credentials but does not manage credential lifecycle.

3. **Physical/side-channel attacks** — Memory dumps, timing attacks, and electromagnetic emanations require OS-level and hardware-level mitigations.

### Residual Risks (Mitigated But Not Eliminated)

1. **Deep JSON parameter smuggling** — DLP scans flattened JSON leaves, but structures beyond `MAX_VALIDATION_DEPTH` are abandoned to prevent stack DoS. Secrets in very deep structures could evade scanning.

2. **Novel injection patterns** — Detection relies on known patterns (Aho-Corasick corpus) and semantic similarity. Entirely novel attack patterns not in the corpus may not be detected.

3. **Behavioral baseline manipulation** — An adversary could slowly ramp up tool usage over multiple sessions to shift the EMA baseline, then exploit the elevated threshold.

4. **Multi-agent collusion** — Call chain HMAC signatures prevent single-agent tampering, but two colluding agents in a chain could present a fabricated history.

5. **Audit log truncation** — Hash chains detect tampering but cannot prevent deletion. An attacker with filesystem write access could truncate the log. The deletion window persists until the next verification pass.

6. **DNS TOCTOU** — A domain may resolve to a public IP during the rebinding check but to a private IP during actual use. Mitigated by `block_private = true` default, but not eliminable at the application layer.

---

## Default Security Posture

Vellaveto is **fail-closed by design**:

- Missing policies produce `Deny`
- Policy evaluation errors produce `Deny`
- Unresolved evaluation context produces `Deny`
- Missing verification tier produces `Deny` (when `min_verification_tier` is set)
- Circuit breaker in `Open` state produces `Deny`
- Private IP ranges blocked by default (`block_private = true`)

No `unwrap()` or `expect()` calls exist in library code. All error paths are observable via structured logging.

---

## Deployment Recommendations

See [HARDENING.md](HARDENING.md) for detailed deployment guidance. Key points:

- Set `VELLAVETO_API_KEY` for all mutating endpoints
- Enable Ed25519 audit checkpoints in production
- Use OAuth 2.1 / JWT for agent authentication
- Run behind TLS termination (nginx, Caddy, cloud LB)
- Mount config files read-only (`:ro` in Docker)
- Set `read_only: true` and `no-new-privileges: true` in container runtime
- Forward audit logs to external SIEM for tamper-resistant archival
