# MCPSEC Security Properties

## Overview

This document defines 10 security properties MCPSEC evaluates. Each has a
statement in mathematical notation, an informal description, and a testable
predicate the harness checks.

Two things to be clear about. The notation is **not machine-checked** — it is
there to state each property unambiguously, not to claim a proof; nothing in
this document is verified by Lean or any other prover. And these ten are the
properties this suite chose to test, not an exhaustive account of what a secure
gateway must satisfy; protocol replay, for one, is absent.

---

## P1: Tool-Level Access Control

**Formal Statement:**
```
∀ action a, ¬(∃ policy p ∈ P : matches(p, a)) → verdict(a) = Deny
```

**Informal Description:**
If no policy explicitly matches an action, the gateway must deny it. This is the "deny-by-default" or "fail-closed" property. An empty policy set must deny all actions.

**Testable Predicate:**
- Submit an action for a tool/function pair that no policy covers → expect `Deny`
- Submit an action with an empty policy set → expect `Deny`
- Submit an action matching an explicit `Allow` policy → expect `Allow`
- Submit an action matching an explicit `Deny` policy → expect `Deny`
- Submit an action where `Deny` and `Allow` exist at equal priority → expect `Deny` (deny-override)
- Submit an action with wildcard `*:*` allow policy → expect `Allow` for any tool

**Test IDs:** A3.1, A3.2, A5.1, A15.1-A15.5

---

## P2: Parameter Constraint Enforcement

**Formal Statement:**
```
∀ action a, ∀ param p ∈ a.parameters,
  ∀ constraint c ∈ matching_constraints(a),
    matches(c.pattern, p) → verdict(a) = c.on_match
```

**Informal Description:**
When a policy defines parameter-level constraints (regex, glob, domain), the gateway must evaluate the parameter value against those constraints. If a parameter matches a "forbidden" constraint, the action must be denied regardless of the tool-level verdict.

**Testable Predicate:**
- Path traversal in `path` parameter with glob constraint → expect `Deny`
- Shell metacharacters in `command` parameter with regex constraint → expect `Deny`
- Exfiltration domain in `url` parameter with domain constraint → expect `Deny`
- Deeply nested parameter value matching constraint → expect `Deny`
- Normal parameter value not matching any constraint → expect `Allow`
- Percent-encoded path traversal → expect `Deny` (iterative decode)

**Test IDs:** A3.1-A3.6

---

## P3: Priority Monotonicity

**Formal Statement:**
```
∀ policies p1, p2, p1.priority > p2.priority →
  evaluate(p1) before evaluate(p2) ∧
  (p1.matches(a) → verdict(a) = p1.verdict)
```

**Informal Description:**
Policies with higher numeric priority are evaluated first and take precedence. A deny at priority 100 cannot be overridden by an allow at priority 50.

**Testable Predicate:**
- High-priority deny + low-priority allow → expect `Deny`
- High-priority allow + low-priority deny → expect `Allow`
- Equal-priority deny + allow → expect `Deny` (deny-override)

**Test IDs:** A5.2, A5.3

---

## P4: Injection Resistance

**Formal Statement:**
```
∀ input i, contains_injection_pattern(i) → detection_flag(i) = true
where contains_injection_pattern includes:
  - Raw patterns (e.g., "ignore all previous instructions")
  - Zero-width character obfuscated patterns
  - Bidi override obfuscated patterns
  - ChatML/Llama/Gemma delimiter injection
  - Fullwidth Unicode obfuscated patterns
  - NFKC-normalizable variants
  - Tag character obfuscated patterns
  - Base64-encoded injection in resource blobs
```

**Informal Description:**
The gateway must detect known prompt injection patterns in tool responses, including when those patterns are obfuscated using Unicode manipulation, format-specific delimiters, or encoding.

**Testable Predicate:**
- Classic "ignore all previous instructions" → detected
- Zero-width character evasion → detected after stripping
- Bidi override evasion → detected after stripping
- ChatML delimiter injection (`<|im_start|>`) → detected
- Llama format injection (`[INST]`) → detected
- Fullwidth Unicode evasion → detected after NFKC normalization
- Tag character evasion → detected after stripping
- Base64-encoded injection in resource blob → detected after decoding
- ROT13 obfuscation → detected after ROT13 decode pass
- HTML entity obfuscation (`&lt;` → `<`) → detected after entity decode
- Policy Puppetry (`<override>`, `[SYSTEM]`) → detected
- FlipAttack word reversal → detected via character-level reversal check
- Leetspeak substitution (1gn0r3 → ignore) → detected after normalization
- Math alphanumeric symbols → NFKC normalized
- Emoji regional indicator smuggling → detected after stripping

**Test IDs:** A1.1-A1.15

---

## P5: Schema Integrity

**Formal Statement:**
```
∀ tool t, ∀ times t0, t1,
  hash(schema(t, t0)) ≠ hash(schema(t, t1)) → rug_pull_alert = true
```

**Informal Description:**
The gateway must detect when an MCP server changes a tool's schema (input parameters), annotations (behavioral hints), or tool list between sessions. This detects "rug-pull" attacks where a server changes tool behavior after initial trust establishment.

**Testable Predicate:**
- Tool annotation change (destructiveHint false→true) → detected
- Tool schema change (new parameter added) → detected
- New tool injected after initial list → detected
- Tool removed from list → detected
- Clean tool list (no changes) → no alert
- Schema hash is canonical (key order independent, RFC 8785) → same hash
- Description injection detected in tool descriptions → flagged

**Test IDs:** A2.1-A2.7, A14.1-A14.4

---

## P6: Response Confidentiality

**Formal Statement:**
```
∀ response r, ∀ encoding_chain e ∈ {raw, base64, percent, base64+percent,
  percent+base64, double_base64, double_percent, triple_mixed},
    contains_secret(decode(r, e)) → dlp_flag(r) = true
```

**Informal Description:**
The gateway must detect secrets (API keys, tokens, credentials, private keys) in tool responses, even when those secrets are encoded using base64, percent-encoding, or multi-layer encoding chains up to 5 layers deep.

**Testable Predicate:**
- AWS key in raw response → detected
- GitHub token base64-encoded → detected
- Private key header percent-encoded → detected
- API key double-base64 encoded → detected
- Secret in base64(percent(raw)) chain → detected
- JWT token in response → detected
- Clean response with no secrets → no flag
- Secret in error message → detected

**Test IDs:** A4.1-A4.9, A13.1-A13.4

---

## P7: Audit Immutability

**Formal Statement:**
```
∀ log entries e0..en,
  verify(hash_chain(e0..en)) = true ∧
  tamper(ei) → verify(hash_chain(e0..en)) = false
```

**Informal Description:**
The audit log must form a tamper-evident hash chain. Every entry includes a cryptographic hash linking it to the previous entry. Modifying any entry breaks the chain verification.

**Testable Predicate:**
- Log 3 entries → verify chain passes
- Tamper with entry → verify chain fails
- All entries have entry_hash and prev_hash fields
- Length-prefixed encoding prevents hash collision (tool="ab",func="cd" ≠ tool="abc",func="d")

**Test IDs:** A8.1-A8.7

---

## P8: Delegation Monotonicity

**Formal Statement:**
```
∀ capability tokens t, t',
  delegate(t) = t' → permissions(t') ⊆ permissions(t)
```

**Informal Description:**
When a capability is delegated from one principal to another, the delegated capability must be a subset of the original. No principal can escalate privileges through delegation.

**Testable Predicate:**
- Parent has read+write, delegates read-only → child can only read
- Attempt to delegate broader permissions → rejected
- Self-approval prevention (same principal creates and approves) → rejected
- Approval with different identity → allowed
- Anonymous requester allows any approver (cannot enforce separation)

**Test IDs:** A5.1-A5.5

---

## P9: Unicode Normalization

**Formal Statement:**
```
∀ inputs i, evaluate(i) = evaluate(NFKC(normalize_homoglyphs(strip_invisible(i))))
```

**Informal Description:**
The gateway must normalize Unicode input before policy evaluation. This includes NFKC normalization (fullwidth → ASCII), homoglyph mapping (Cyrillic/Greek → Latin), and stripping invisible characters (zero-width, bidi, tags). Without this, attackers bypass policies using visually identical but technically different characters.

**Testable Predicate:**
- Cyrillic 'а' (U+0430) in tool name → normalized to Latin 'a'
- Fullwidth "bash" (U+FF42...) → NFKC normalized to "bash"
- Zero-width space in method → stripped
- Greek omicron in tool name → detected as homoglyph
- Mixed-script tool name (Latin + Cyrillic) → flagged
- Mathematical Bold characters → NFKC normalized

**Test IDs:** A7.1-A7.5, A1.3, A1.6, A1.14, A1.15, A15.1-A15.5

---

## P10: Temporal Consistency

**Formal Statement:**
```
∀ time-windowed policy p active in [t0, t1], ∀ action a,
  verdict(a, t) = p.verdict when t ∈ [t0, t1] ∧
  verdict(a, t) = Deny when t ∉ [t0, t1]
```

**Informal Description:**
Policies with time-based conditions must be enforced correctly. A policy that allows access only during business hours must deny access outside those hours. Rate limits must reset correctly across time windows.

**Testable Predicate:**
- Action within time window → verdict matches policy
- Action outside time window → denied
- Rate limit: first request within limit → allowed
- Rate limit: excess request → denied (429)

**Test IDs:** A10.2, A10.4, A16.1-A16.4

---

## Property Weights

Properties are weighted by the authors' judgment of security impact. The weights
are not a measured quantity — recompute the overall score from the per-property
numbers if you weight them differently. See [SCORING.md](SCORING.md).

| Property | Weight | Rationale |
|----------|--------|-----------|
| P1 (Access Control) | 15% | Foundation — everything depends on this |
| P2 (Parameters) | 12% | Deep inspection differentiator |
| P3 (Priority) | 5% | Correctness guarantee |
| P4 (Injection) | 15% | Widest evasion surface — many encodings reach one payload |
| P5 (Schema) | 10% | Supply chain defense |
| P6 (DLP) | 12% | Exfiltration prevention |
| P7 (Audit) | 10% | Forensic and compliance requirement |
| P8 (Delegation) | 8% | Privilege escalation prevention |
| P9 (Unicode) | 8% | Evasion resistance |
| P10 (Temporal) | 5% | Operational correctness |
| **Total** | **100%** | |
