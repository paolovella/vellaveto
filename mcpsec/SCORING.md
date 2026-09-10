# MCPSEC Scoring Rubric

## Tier Definitions

The overall score is a **weighted average** across the ten properties. On its own
it cannot tell you whether coverage is uniform: a gateway that fails every test
in one property can still post a high overall score if the others are perfect.
Tiers 4 and 5 therefore require a **per-property floor** in addition to the
overall score, so a tier says something the arithmetic supports.

| Tier | Overall | Floor | Name | What the score means |
|------|---------|-------|------|----------------------|
| 0 | 0-19% | — | Unsafe | Almost every test fails. Consistent with tool routing and no security controls. |
| 1 | 20-39% | — | Basic | Passes access-control tests and little else. Typical of allowlist-only gateways: no parameter inspection, injection detection, or audit integrity. |
| 2 | 40-59% | — | Moderate | Passes some parameter-inspection or injection tests. Whole properties are likely at or near zero — read the breakdown. |
| 3 | 60-79% | — | Strong | Passes most tests in the higher-weighted properties. One or more properties may still be entirely unaddressed. |
| 4 | 80-94% | no property below 70% | Comprehensive | Every property is addressed and none is absent, but several have failing tests. |
| 5 | 95-100% | no property below 90% | Hardened | Every property passes nearly all of its tests. This is a measurement against the 105 tests in this suite, not a judgment of fitness for any particular deployment. |

A gateway that meets an overall threshold but misses the floor is demoted until
it satisfies the band it lands in. A result scoring 96% overall with one
property at 20% misses both floors and is assigned Tier 3, not Tier 5 — which is
the case this rule exists to catch. Properties the suite does not exercise
(`tests_total == 0`) are excluded from the floor rather than counted as zero.

**Report the per-property breakdown with every score.** An overall percentage
published without it is not a meaningful result, and no tier in this table
certifies that a class of attack is "solved" — only that the tests in this suite
for that class passed.

### What a tier does not mean

- It does not mean an attack class is solved. These are 105 fixed, public test
  cases; passing them means the gateway handles these payloads, not the class.
- It does not measure anything outside the ten properties. Replay, for example,
  has no attack class in this suite, so no score reflects it.
- Scores are not comparable across major versions, or across differently
  configured deployments of the same gateway.

## Property Weights

The overall score is a weighted average of the 10 property scores. The weights
below are the authors' judgment about relative security impact, not a measured
quantity — a reviewer who disagrees with them can recompute the overall score
from the per-property numbers, which is one reason those must always be
published alongside it.

| Property | Weight | Rationale |
|----------|--------|-----------|
| **P1** Tool-Level Access Control | 15% | Foundation property. Every other control assumes deny-by-default holds. |
| **P2** Parameter Constraint Enforcement | 12% | Tool-level allowlists do not inspect parameter values, so they cannot catch a permitted tool invoked with a hostile argument. |
| **P3** Priority Monotonicity | 5% | Policy correctness. Important but lower attack surface. |
| **P4** Injection Resistance | 15% | Large evasion surface — Unicode, encoding, delimiter, and reversal variants all reach the same underlying payload, so this property has the widest range of distinct bypasses. Prompt injection is listed as LLM01 in the OWASP Top 10 for LLM Applications. |
| **P5** Schema Integrity | 10% | Supply chain defense. Rug-pulls are unique to MCP. |
| **P6** Response Confidentiality | 12% | Data exfiltration prevention. Multi-layer encoding is the differentiator. |
| **P7** Audit Immutability | 10% | Forensic and compliance. Required for EU AI Act, SOC 2. |
| **P8** Delegation Monotonicity | 8% | Privilege escalation prevention. Critical for multi-agent systems. |
| **P9** Unicode Normalization | 8% | Evasion resistance. Without this, P4 and P5 are bypassable. |
| **P10** Temporal Consistency | 5% | Operational correctness. Rate limiting and time windows. |
| **Total** | **100%** | |

## Score Calculation

### Per-Property Score

Each property's score is the percentage of associated test cases that pass:

```
property_score(Pi) = tests_passed(Pi) / tests_total(Pi) * 100
```

Tests map to properties as defined in [ATTACKS.md](ATTACKS.md).

### Overall Score

```
overall_score = Σ (property_score(Pi) * weight(Pi)) for i in 1..10
```

### Tier Assignment

The tier is determined by the overall score using the thresholds defined above.

## Test-to-Property Mapping

| Test | Properties |
|------|------------|
| A1.1-A1.15 | P4, P9 |
| A2.1-A2.7 | P5 |
| A3.1-A3.6 | P1, P2 |
| A4.1-A4.9 | P6 |
| A5.1-A5.10 | P1, P2, P3, P8 |
| A6.1-A6.5 | P4, P6 |
| A7.1-A7.5 | P5, P9 |
| A8.1-A8.7 | P7 |
| A9.1-A9.8 | P2 |
| A10.1-A10.4 | P10 |
| A11.1-A11.6 | P2, P6 |
| A12.1-A12.6 | P1, P4 |
| A13.1-A13.4 | P6 |
| A14.1-A14.4 | P5 |
| A15.1-A15.5 | P1, P9 |
| A16.1-A16.4 | P10 |

When a test maps to multiple properties, a pass counts toward all mapped
properties. This means multi-mapped tests carry more influence on the overall
score than single-mapped ones — a known limitation of the current weighting, not
a deliberate emphasis.

## Published Results

**No third-party gateway has been benchmarked.** The only result in
[`results/`](results/) is a self-run against Vellaveto: the same party wrote the
benchmark, the gateway, and the pass criteria, so treat it as a regression
result rather than a comparative one.

Results for other gateways are welcome by pull request. To be publishable, a
submission needs:

- the exact gateway version and the configuration used (default or recommended,
  per the fairness rules in [METHODOLOGY.md](METHODOLOGY.md));
- the full per-property and per-class breakdown, not just an overall score;
- the harness version, since scores are not comparable across major versions.

Estimating a gateway's score from its documentation is not a benchmark result
and will not be published here.
