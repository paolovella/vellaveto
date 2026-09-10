# MCPSEC Methodology

## How to Run the Benchmark

### Prerequisites

1. A running MCP gateway with an HTTP evaluation endpoint
2. Rust toolchain (1.75+)
3. Network access to the gateway under test

### Step 1: Configure the Gateway Target

```bash
cargo run -p mcpsec -- \
  --target http://localhost:3000 \
  --evaluate-path /api/evaluate \
  --output results/my-gateway.json
```

**Configuration options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | (required) | Base URL of the gateway |
| `--evaluate-path` | `/api/evaluate` | Path to the evaluation endpoint |
| `--auth` | (none) | Bearer token for authenticated gateways |
| `--output` | stdout | Output file path for results |
| `--format` | `json` | Output format: `json` or `markdown` |
| `--timeout` | `30s` | Per-request timeout |
| `--concurrency` | `1` | Number of concurrent test requests |
| `--classes` | (all) | Comma-separated class filter (e.g., `A1,A4,A9`) |
| `--list` | - | List all test cases without running |
| `--compare` | (none) | Compare against a baseline JSON file |

### Step 2: Interpret Results

The harness produces a JSON report with:

- **Overall score** (0-100%)
- **Tier** (0-5)
- **Per-property scores** (P1-P10, each 0-100%)
- **Per-attack results** (116 tests, each pass/fail with latency)

### Step 3: Generate Report

```bash
# JSON report (machine-readable)
cargo run -p mcpsec -- --target http://localhost:3000 --format json

# Markdown report (human-readable)
cargo run -p mcpsec -- --target http://localhost:3000 --format markdown
```

## Gateway Interface Contract

MCPSEC assumes the gateway under test exposes an HTTP endpoint that accepts tool call evaluation requests:

### Request Format

```http
POST /api/evaluate
Content-Type: application/json
Authorization: Bearer <token>  (if required)

{
  "tool": "file",
  "function": "read",
  "parameters": {
    "path": "/etc/passwd"
  }
}
```

### Expected Response Format

```json
{
  "verdict": "Deny",
  "reason": "Blocked by policy 'Block credential files'",
  "matched_policy": "block-creds",
  "inspection": {
    "injection_detected": false,
    "dlp_findings": []
  }
}
```

The harness checks:
- `verdict` field: must be `"Allow"`, `"Deny"`, or `{"Deny":{"reason":"..."}}` (Vellaveto format)
- HTTP status codes: 200 for evaluated, 429 for rate-limited
- Response body for inspection findings

### Adapting to Different Gateways

If your gateway uses a different API format, implement a response adapter. The harness normalizes responses to a common verdict format internally.

## Fairness Rules

1. **No tuning for the benchmark.** Gateways should be tested with their default or recommended configuration. Custom rules that only exist to pass specific benchmark tests are not valid.

2. **Reproducible.** All tests use deterministic payloads. Running the benchmark twice against the same gateway configuration must produce the same score.

3. **Version pinning.** Results must include the exact gateway version tested. Scores are not comparable across versions.

4. **No Internet required.** All test payloads are self-contained. The harness does not make external network requests beyond the gateway under test.

5. **Time budget.** Each individual test has a 30-second timeout. Tests that timeout are marked as failures.

## Reporting Format

### JSON Schema

```json
{
  "framework": "MCPSEC",
  "version": "1.1.0",
  "timestamp": "2026-02-15T12:00:00Z",
  "gateway": {
    "name": "gateway-name",
    "version": "1.0.0",
    "base_url": "http://localhost:3000"
  },
  "overall_score": 97,
  "tier": 5,
  "tier_name": "Hardened",
  "properties": {
    "P1": { "score": 100, "tests_passed": 6, "tests_total": 6 },
    "P2": { "score": 100, "tests_passed": 8, "tests_total": 8 },
    "...": "..."
  },
  "attacks": [
    {
      "id": "A1.1",
      "name": "Classic injection phrase",
      "class": "Prompt Injection Evasion",
      "passed": true,
      "latency_ns": 28000,
      "details": "Injection pattern detected in response"
    }
  ],
  "summary": {
    "total_tests": 100,
    "passed": 98,
    "failed": 2,
    "skipped": 0
  }
}
```

### Markdown Report

The markdown report includes:
- Executive summary with tier badge
- Per-property score table
- Attack class breakdown with pass/fail status
- Failed test details with remediation guidance
- Comparison against reference results (if available)

## Versioning

MCPSEC follows semantic versioning:
- **Major:** New security properties or removal of existing tests
- **Minor:** New attack test cases within existing classes
- **Patch:** Clarifications, bug fixes in harness logic

Scores from different major versions are not comparable.
