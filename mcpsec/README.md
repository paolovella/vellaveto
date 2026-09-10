# MCPSEC: MCP Security Benchmark Framework

**Version 1.2.0** | **Apache-2.0 License**

MCPSEC is an open, vendor-neutral security benchmark for evaluating MCP (Model Context Protocol) gateway security. It defines 10 formal security properties and 116 reproducible attack test cases across 17 attack classes, derived from real-world penetration testing of MCP deployments. Results are reported on two axes: security, and availability — the share of legitimate traffic allowed through.

## Why MCPSEC?

AI agents with tool access are a new attack surface. OWASP defined the ASVS for web apps — MCPSEC does the same for MCP gateways.

Most MCP gateways offer tool-level allowlists and nothing more. MCPSEC tests for what actually matters: injection evasion, encoded exfiltration, schema mutation, confused deputy attacks, audit tampering, and more.

## Quick Start

```bash
# Build the benchmark harness
cargo build -p mcpsec

# Run against a gateway
cargo run -p mcpsec -- --target http://localhost:3000 --output results/my-gateway.json

# Run with markdown report
cargo run -p mcpsec -- --target http://localhost:3000 --format markdown

# List all 105 test cases
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

### 16 Attack Classes (A1-A16)

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

**Total: 116 test cases** (105 security + 11 legitimate-traffic). See [ATTACKS.md](ATTACKS.md) for full catalog.

## Scoring

| Tier | Score | Meaning |
|------|-------|---------|
| Tier 0: Unsafe | 0-19% | No meaningful security |
| Tier 1: Basic | 20-39% | Allowlist-only |
| Tier 2: Moderate | 40-59% | Some parameter inspection |
| Tier 3: Strong | 60-79% | Injection + DLP + audit |
| Tier 4: Comprehensive | 80-94% | Full threat coverage |
| Tier 5: Hardened | 95-100% | All properties verified |

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
│   └── attacks/           # 16 attack modules (a01-a16)
├── tests/
│   ├── self_test.rs       # Validate harness logic
│   └── mock_gateway_test.rs # End-to-end test with embedded mock server
└── results/               # Reference benchmark results
```

## Philosophy

1. **Open and reproducible.** Every test case is documented with exact payloads and pass/fail criteria. No black-box scoring.
2. **Vendor-neutral.** Any MCP gateway can be benchmarked. The harness tests observable behavior, not implementation details.
3. **Derived from real attacks.** Every test case corresponds to a real attack vector discovered through penetration testing of MCP deployments.
4. **No security theater.** We test what competitors miss: Unicode homoglyphs, multi-layer encoding, schema mutation, audit chain integrity — not just "does the allowlist work."

## Contributing

MCPSEC is open to contributions. To propose a new attack class or security property:

1. Open an issue describing the attack vector
2. Include a proof-of-concept payload
3. Define clear pass/fail criteria
4. Reference relevant OWASP or CVE identifiers

## License

Apache-2.0 — use it, fork it, benchmark your competitors.

The benchmark framework itself is Apache-2.0 to encourage adoption. The Vellaveto gateway is licensed under a three-tier model (MPL-2.0 / Apache-2.0 / BUSL-1.1) — see [LICENSING.md](../LICENSING.md).
