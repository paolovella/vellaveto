# MCPSEC: MCP Security Benchmark Framework

**Version 1.2.0** | **Apache-2.0 License**

MCPSEC is an open security benchmark for evaluating MCP (Model Context Protocol) gateway security. It defines 10 security properties and 116 reproducible attack test cases across 17 attack classes, drawn from published MCP vulnerabilities, threat-intelligence reporting, and adversarial testing of this project. Results are reported on two axes: security, and availability — the share of legitimate traffic allowed through.

> **Authorship disclosure.** MCPSEC is written and maintained by the Vellaveto
> project. The benchmark, the pass criteria, and the only currently published
> result are all ours. The harness is open and reproducible so that anyone can
> check it, but a score Vellaveto assigns itself is a regression result, not
> independent validation — and the test selection inevitably reflects the
> attacks this project chose to think about. Read it that way.

## Why MCPSEC

AI agents with tool access are a new attack surface, and the gateways in front of
them are evaluated mostly by feature list. MCPSEC exists to make claims testable:
fixed payloads, stated pass criteria, and a per-property breakdown, so "detects
prompt injection" becomes a number someone else can reproduce.

The properties cover ground a tool-level allowlist does not reach — injection
evasion, encoded exfiltration, schema mutation, confused deputy attacks, and
audit tampering — because a permitted tool invoked with a hostile argument is
the case an allowlist cannot see.

## Quick Start

```bash
# Build the benchmark harness
cargo build -p mcpsec

# Run against a gateway
cargo run -p mcpsec -- --target http://localhost:3000 --output results/my-gateway.json

# Run with markdown report
cargo run -p mcpsec -- --target http://localhost:3000 --format markdown

# List all 116 test cases
cargo run -p mcpsec -- --list

# Run specific attack classes only
cargo run -p mcpsec -- --target http://localhost:3000 --classes A1,A4,A9

# Compare against a baseline (exits with status 1 on regressions)
cargo run -p mcpsec -- --target http://localhost:3000 --compare results/baseline.json

# CI gate: fail if score is below 80%
cargo run -p mcpsec -- --target http://localhost:3000 --fail-under 80

# OCSF output for SIEM ingestion (Splunk, QRadar, CrowdStrike)
cargo run -p mcpsec -- --target http://localhost:3000 --format ocsf

# JUnit XML for CI dashboards (Jenkins, GitLab CI, GitHub Actions)
cargo run -p mcpsec -- --target http://localhost:3000 --format junit --output results.xml
```

## What It Tests

### 10 Security Properties (P1-P10)

| ID | Property | What It Means |
|----|----------|---------------|
| P1 | Tool-Level Access Control | Unmatched actions are denied by default |
| P2 | Parameter Constraint Enforcement | Parameter values are validated against constraints |
| P3 | Priority Monotonicity | Higher-priority policies are evaluated first |
| P4 | Injection Resistance | Known injection patterns are detected in all encodings |
| P5 | Schema Integrity | Tool schema mutations are detected between sessions |
| P6 | Response Confidentiality | Secrets in responses are detected even when encoded |
| P7 | Audit Immutability | Audit logs are tamper-evident via hash chains |
| P8 | Delegation Monotonicity | Delegated tokens cannot exceed parent permissions |
| P9 | Unicode Normalization | Unicode-obfuscated inputs are normalized before evaluation |
| P10 | Temporal Consistency | Time-windowed policies are enforced correctly |

See [PROPERTIES.md](PROPERTIES.md) for formal definitions.

### 17 Attack Classes (A1-A17)

| # | Class | Tests | OWASP Ref |
|---|-------|-------|-----------|
| A1 | Prompt Injection Evasion | 15 | ASI01 |
| A2 | Tool Poisoning & Rug-Pull | 7 | ASI03 |
| A3 | Parameter Constraint Bypass | 6 | ASI01 |
| A4 | Encoded Exfiltration (DLP) | 9 | ASI04 |
| A5 | Confused Deputy | 10 | ASI02 |
| A6 | Memory Poisoning (MINJA) | 5 | ASI06 |
| A7 | Tool Squatting | 5 | ASI03 |
| A8 | Audit Tampering | 7 | MCP08 |
| A9 | SSRF & Domain Bypass | 8 | MCP05 |
| A10 | DoS & Resource Exhaustion | 4 | MCP10 |
| A11 | Credential Elicitation | 6 | - |
| A12 | Sampling & Covert Channels | 6 | - |
| A13 | Cross-Call Secret Splitting | 4 | - |
| A14 | Schema Pattern Bypass | 4 | - |
| A15 | Agent Identity Spoofing | 5 | ASI02 |
| A16 | Circuit Breaker Evasion | 4 | MCP10 |
| A17 | Legitimate Traffic | 11 | — |

**Total: 116 test cases** (105 security + 11 legitimate-traffic). See [ATTACKS.md](ATTACKS.md) for full catalog.

## Scoring

The overall score is a weighted average, so it can hide a property that fails
entirely. Tiers 4 and 5 add a per-property floor for that reason.

| Tier | Overall | Floor | Meaning |
|------|---------|-------|---------|
| Tier 0: Unsafe | 0-19% | — | Almost every test fails |
| Tier 1: Basic | 20-39% | — | Passes access control and little else |
| Tier 2: Moderate | 40-59% | — | Some parameter inspection; whole properties likely at zero |
| Tier 3: Strong | 60-79% | — | Most higher-weighted properties pass; some may be unaddressed |
| Tier 4: Comprehensive | 80-94% | no property below 70% | Substantial coverage everywhere, none absent |
| Tier 5: Hardened | 95-100% | no property below 90% | Nearly all tests pass in every property |

A tier reports how a gateway did against these 105 fixed test cases. It does not
certify that an attack class is solved, and it says nothing about behavior the
suite does not test. **Always publish the per-property breakdown with the score.**

The tier applies to the **security** axis only, and the bands are deliberately
unchanged from before the availability axis existed, so old and new security
scores remain comparable.

### Availability

`availability_score` is reported separately: the percentage of the 11 A17
legitimate-traffic cases the gateway allowed through. It has no tier.

Read the two together. A gateway that refuses every request scores highly on
security by construction — 57 of the security tests pass on a denial alone, and
a measured deny-everything gateway reaches 96/105 (91.3%, Tier 4
"Comprehensive") while allowing nothing. The security number alone cannot tell
"secure" from "closed"; the availability number can.

See [SCORING.md](SCORING.md) for weights and methodology.

## Gateway Interface

MCPSEC tests any gateway that exposes an HTTP evaluation endpoint. The harness sends crafted payloads and checks whether the gateway correctly identifies or blocks each attack.

```
POST /api/evaluate
Content-Type: application/json

{"tool":"bash","function":"exec","parameters":{"command":"..."}}
```

The gateway should return a JSON response with a `verdict` field indicating `Allow`, `Deny`, or equivalent.

## Project Structure

```
mcpsec/
├── README.md              # This file
├── PROPERTIES.md          # 10 formal security properties
├── ATTACKS.md             # 17 attack classes, 116 test cases
├── METHODOLOGY.md         # How to run, how to score
├── SCORING.md             # Scoring rubric and tiers
├── Cargo.toml             # Standalone Rust crate
├── src/
│   ├── lib.rs             # Public API
│   ├── runner.rs          # HTTP client for gateway testing
│   ├── report.rs          # JSON/Markdown/OCSF/JUnit report generation
│   ├── scoring.rs         # Score calculation
│   ├── compare.rs         # Baseline regression detection
│   ├── remediation.rs     # Per-class fix guidance
│   └── attacks/           # 17 attack modules (a01-a17)
├── tests/
│   ├── self_test.rs       # Validate harness logic
│   └── mock_gateway_test.rs # End-to-end test with embedded mock server
└── results/               # Reference benchmark results
```

## Philosophy

1. **Open and reproducible.** Every test case is documented with exact payloads and pass/fail criteria. No black-box scoring.
2. **Gateway-agnostic.** The harness tests observable behavior over an HTTP evaluation endpoint, not implementation details, so any MCP gateway can be benchmarked. It is not vendor-neutral in authorship — see the disclosure above.
3. **Grounded in reported attacks.** Test cases are derived from published MCP vulnerabilities and CVEs, threat-intelligence reporting, and adversarial testing of this project. Each attack class in [ATTACKS.md](ATTACKS.md) cites its source where one exists.
4. **Tests beyond the allowlist.** Unicode homoglyphs, multi-layer encoding, schema mutation, and audit chain integrity are all in scope, because "does the allowlist work" is not the interesting question.
5. **Known gaps.** The suite has no attack class for protocol replay, and no class mapped to OWASP ASI07. A high score does not speak to either.

## Contributing

MCPSEC is open to contributions. To propose a new attack class or security property:

1. Open an issue describing the attack vector
2. Include a proof-of-concept payload
3. Define clear pass/fail criteria
4. Reference relevant OWASP or CVE identifiers

## License

Apache-2.0 — use it, fork it, benchmark your competitors.

The benchmark framework itself is Apache-2.0 to encourage adoption. The Vellaveto gateway is licensed under a three-tier model (MPL-2.0 / Apache-2.0 / BUSL-1.1) — see [LICENSING.md](../LICENSING.md).
