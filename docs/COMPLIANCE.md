# Compliance Framework Coverage

> **Version:** 6.0.0
> **Frameworks:** 12 regulatory and industry standards
> **Evidence formats:** JSON, HTML, OCSF, CEF, syslog
> **Website:** [vellaveto.online/compliance](https://vellaveto.online/compliance)

---

## Overview

VellaVeto maps its runtime security controls to 12 regulatory and industry frameworks. Each framework has a dedicated Rust registry that:

1. **Curates requirements** — articles, clauses, controls, or threat categories from the standard
2. **Maps capabilities** — links VellaVeto features (policy engine, injection detection, DLP, audit, etc.) to each requirement
3. **Generates coverage reports** — per-requirement compliance status with percentages
4. **Produces evidence packs** — structured artifacts for auditor consumption (JSON + HTML)

These are **control mappings**, not certifications. VellaVeto provides the technical controls and evidence artifacts — compliance validation remains deployment-specific and requires assessment by qualified auditors.

### Two limits that affect evidence value

**Signed artifacts are not time-attested.** Checkpoints, rotation manifests, and
evidence packs are dated from the signing host's wall clock. There is no RFC 3161
timestamp authority and no external anchor, so a signature establishes authorship
and integrity but not *when* the artifact was produced — and the key holder can
assign any timestamp. Where a regime requires attested record-keeping times,
supply that attestation externally: forward entries to an append-only external
system (SIEM, WORM storage, or a notarization service) whose timestamps are
outside the operator's control. See
[Signing and timestamps](SECURITY_MODEL.md#where-signing-time-comes-from).

**Ed25519 is not FIPS 140-3 approved.** It is the default signing algorithm and
Vellaveto's own FIPS controller rejects it. Deployments under a FIPS obligation
must set `fips.enabled = true` and `fips.signature_algorithm = "ecdsa-p256"`
(the only value accepted in FIPS mode), and must not present Ed25519-signed
checkpoints as compliance evidence.

---

## Framework Summary

| Framework | Scope | Controls Mapped | Evidence Pack | Incident Reporting |
|-----------|-------|-----------------|---------------|--------------------|
| **EU AI Act** | AI system governance (Art 9, 10, 12, 14, 50) | Transparency, human oversight, risk management, record-keeping, data governance | Yes | Yes (Art 62) |
| **NIS2** | Cybersecurity for essential/important entities | Incident notification (24h/72h/1M), supply chain, access control, monitoring | Yes | Yes (Art 23) |
| **DORA** | Financial sector ICT resilience (Ch II, III, V) | ICT risk management, incident classification, third-party oversight | Yes | Yes (24h/72h) |
| **SOC 2 Type II** | Trust services criteria (CC1-CC9) | Access review (CC6), availability, processing integrity, confidentiality | Separate endpoint | — |
| **ISO 42001** | AI management system (Clauses 4-10) | Risk assessment, policy enforcement, monitoring, improvement | Yes | — |
| **NIST AI 600-1** | GenAI risk profile (12 risk areas) | Confabulation, data privacy, information security, toxicity/bias, and 8 more | Coverage report | — |
| **OWASP Agentic Top 10** | Agentic application risks (ASI01-ASI10) | Injection, tool poisoning, insecure output, rug pull, memory poisoning | — | — |
| **OWASP MCP Top 10** | MCP-specific risks (MCP01-MCP10) | Server spoofing, tool shadowing, data exfiltration, credential theft | — | — |
| **CoSAI** | Coalition for Secure AI (38 controls) | Tool manipulation, prompt injection, unauthorized access, supply chain | — | — |
| **Adversa TOP 25** | AI security vulnerabilities (25 ranked) | 25/25 covered with mitigation mappings | — | — |
| **Singapore MGF** | Model Governance Framework (4 dimensions) | Risk bounding, human accountability, technical controls, end-user responsibility | — | — |
| **CSA ATF** | Cloud Security Alliance AI Threat Framework (6 domains) | Identity, authorization, behavioral monitoring, data protection, audit, incident response | — | — |

---

## Regulatory Frameworks (Detailed)

### EU AI Act

**Regulation (EU) 2024/1689** — effective August 2, 2026.

VellaVeto provides controls mapped to five articles:

| Article | Requirement | VellaVeto Feature |
|---------|-------------|-------------------|
| Art 50(2) | Transparency: mark AI-generated output | `VerdictExplanation` with configurable verbosity injected into `_meta` |
| Art 10 | Data governance for training/validation | `DataGovernanceRecord` with classification, purpose, provenance, retention |
| Art 12 | Record-keeping and traceability | Tamper-evident audit: SHA-256 chains, Merkle proofs, signed checkpoints (Ed25519, optionally hybrid Ed25519+ML-DSA-65), ACIS decision envelopes with per-verdict fingerprints |
| Art 14 | Human oversight | `RequireApproval` verdict, human-in-the-loop workflow with configurable timeout |
| Art 9 | Risk management system | Policy engine with risk scoring, ABAC, behavioral anomaly detection, circuit breakers |

**Registry:** `vellaveto-audit/src/eu_ai_act.rs`
**Key type:** `EuAiActRegistry` — generates conformity assessment reports per risk class
**Evidence:** `generate_evidence_pack(EvidenceFramework::EuAiAct, org, system_id)`

### NIS2

**Directive (EU) 2022/2555** — transposed into national law (e.g., Italy D.Lgs. 138/2024).

| Requirement | VellaVeto Feature |
|-------------|-------------------|
| Incident notification (24h/72h/1M) | Cross-regulation incident reporting with automated timeline generation |
| Supply chain security | ETDI cryptographic tool verification, version pinning, SANDWORM hardening |
| Access control and identity | ABAC, RBAC (4 roles, 14 permissions), NHI lifecycle, OIDC/SAML/SCIM |
| Continuous monitoring | Real-time audit, SIEM export (CEF/syslog/OCSF/webhook), anomaly detection |
| Risk assessment | Policy simulation, 10-framework gap analysis, evidence pack generation |
| Business continuity | HA clustering, leader election, cascading failure circuit breakers, smart fallback |

**Registry:** `vellaveto-audit/src/nis2.rs`
**Key type:** `Nis2Registry` — generates compliance reports with per-article assessments
**Incident timeline:** `IncidentReport` with `DoraTimelineStage` and `Nis2Sector` classification

### DORA

**Regulation (EU) 2022/2554** — applies to financial entities and ICT third-party service providers.

| Chapter | Requirement | VellaVeto Feature |
|---------|-------------|-------------------|
| Ch II | ICT risk management framework | Policy engine, risk scoring, circuit breakers, behavioral monitoring |
| Ch III | ICT incident management | Structured audit events, incident workflow, automated classification and timelines |
| Ch V | ICT third-party risk | Supply chain verification, tool registry trust scoring, ETDI attestation chains |

**Registry:** `vellaveto-audit/src/dora.rs`
**Key type:** `DoraRegistry` — generates resilience reports grouped by chapter
**Evidence:** `generate_evidence_pack(EvidenceFramework::Dora, org, system_id)`

### SOC 2 Type II

**AICPA Trust Services Criteria** — CC1 through CC9.

VellaVeto provides automated access review reports (CC6), maps trust services criteria to runtime controls, and exports evidence in HTML and JSON formats. The registry covers 19 capabilities across all 9 categories.

**Registry:** `vellaveto-audit/src/soc2.rs`
**Key type:** `Soc2Registry` — generates evidence reports with per-category coverage
**Audit entry classification:** `classify_entry(entry)` maps individual audit events to SOC 2 criteria

### ISO 42001

**ISO/IEC 42001:2023** — AI management system standard (Clauses 4-10).

Maps 14 capabilities to AI management system clauses covering risk identification, policy enforcement, fail-closed design, threat detection, audit logging, metrics, human approval workflows, and continuous improvement evidence.

**Registry:** `vellaveto-audit/src/iso42001.rs`
**Key type:** `Iso42001Registry` — generates clause-level compliance reports
**Evidence:** `generate_evidence_pack(EvidenceFramework::Iso42001, org, system_id)`

---

## Industry & Security Frameworks

### NIST AI 600-1

GenAI risk profile covering 12 risk areas (CBRN, confabulation, data privacy, environmental, human-AI configuration, information integrity, information security, IP, obscene content, toxicity/bias, value chain, dangerous behavior) with 24 controls mapped to VellaVeto capabilities.

**Registry:** `vellaveto-audit/src/nist_ai600.rs`

### OWASP Top 10 for Agentic Applications (2026)

All 10 risks mitigated: prompt injection (ASI01), tool poisoning (ASI02), insecure output handling (ASI03), rug pull attacks (ASI04), memory poisoning (ASI05), and 5 more.

**Registry:** `vellaveto-audit/src/owasp_asi.rs`

### OWASP MCP Top 10

MCP-specific risks: server spoofing (MCP01), tool poisoning (MCP02), excessive permissions (MCP03), tool shadowing (MCP04), prompt injection (MCP05), data exfiltration (MCP06), insecure credentials (MCP07), lack of consent (MCP08), inadequate logging (MCP09), resource exhaustion (MCP10).

**Registry:** `vellaveto-audit/src/owasp_mcp.rs`

### CoSAI + Adversa TOP 25

- **CoSAI:** 38/38 controls from the Coalition for Secure AI MCP Security Whitepaper
- **Adversa TOP 25:** 25/25 AI security vulnerabilities covered with mitigation mappings
- **Gap analysis:** 10-framework consolidated gap analysis with remediation guidance

**Registries:** `vellaveto-audit/src/cosai.rs`, `vellaveto-audit/src/adversa_top25.rs`

### Singapore MGF

Model Governance Framework for Agentic AI — 4 dimensions (risk bounding, human accountability, technical controls, end-user responsibility) with per-requirement mitigation mappings.

**Registry:** `vellaveto-audit/src/singapore_mgf.rs`

### CSA Agentic Trust Framework

Cloud Security Alliance framework with progressive autonomy levels (Level 1-4) across 6 trust domains: identity/authentication, authorization/access control, behavioral monitoring, data protection, audit/accountability, incident response.

**Registry:** `vellaveto-audit/src/csa_atf.rs`

---

## Evidence Packs

Evidence packs are structured compliance artifacts that convert framework coverage reports into auditor-ready documents. Currently available for EU AI Act, NIS2, DORA, and ISO 42001.

### Generation

```rust
use vellaveto_audit::evidence_pack::generate_evidence_pack;
use vellaveto_types::EvidenceFramework;

let pack = generate_evidence_pack(
    EvidenceFramework::Dora,
    "Acme Corp",
    "prod-gateway-01",
);

// Render as HTML
let html = render_evidence_pack_html(&pack);
```

### Via API

```bash
# Generate DORA evidence pack (JSON)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/compliance/evidence-pack/dora

# Generate DORA evidence pack (HTML, print-to-PDF ready)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/compliance/evidence-pack/dora?format=html

# List available evidence pack frameworks
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/compliance/evidence-pack/status

# Generate gap analysis across all frameworks
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/compliance/gap-analysis
```

Available framework path values: `dora`, `nis2`, `iso42001`, `eu-ai-act`

### Pack Contents

Each evidence pack includes:
- **Sections** grouped by regulation chapter/clause/category
- **Items** with compliance status (Compliant / Partial / NotImplemented)
- **Confidence levels** for each item
- **Gaps** with severity and remediation recommendations
- **Overall coverage percentage**
- **Chain-of-custody metadata** (generated_at, organization, system_id)

---

## Cross-Regulation Incident Reporting

A single security incident maps automatically to the notification timelines and requirements of every applicable framework:

| Timeline | Obligation |
|----------|------------|
| **24 hours** | NIS2 pre-notification to CSIRT |
| **72 hours** | NIS2 full notification + DORA incident classification |
| **1 month** | NIS2 final report + EU AI Act risk review |

The `IncidentReport` type captures DORA timeline stages, NIS2 sector classification (essential/important), NIS2 incident type (significant impact, cross-border, supply chain), and EU AI Act obligations (serious incident, systemic risk, rights violation) — enabling a single incident workflow to satisfy all three regulations simultaneously.

**Implementation:** `vellaveto-audit/src/incident_report.rs`

---

## Gap Analysis

The consolidated gap analysis queries all framework registries and produces a unified report:

```rust
use vellaveto_audit::gap_analysis::generate_gap_analysis;

let report = generate_gap_analysis();
// report.overall_coverage_percentage — weighted average across all frameworks
// report.critical_gaps — priority-ranked gaps needing remediation
// report.recommendations — actionable next steps
```

**Implementation:** `vellaveto-audit/src/gap_analysis.rs`

---

## Compliance Presets

Three presets include compliance framework configurations:

| Preset | Frameworks Enabled | Use Case |
|--------|-------------------|----------|
| [`compliance-starter.toml`](../examples/presets/compliance-starter.toml) | All 6 configurable (EU AI Act, NIS2, DORA, SOC 2, OWASP ASI, Data Governance) + strict audit | Comprehensive compliance baseline |
| [`financial-agent.toml`](../examples/presets/financial-agent.toml) | DORA, NIS2, SOC 2, EU AI Act | Financial services |
| [`healthcare-agent.toml`](../examples/presets/healthcare-agent.toml) | SOC 2, NIS2 | Healthcare / HIPAA-aligned |

The remaining 6 frameworks (ISO 42001, NIST AI 600-1, CoSAI, Adversa TOP 25, OWASP MCP Top 10, Singapore MGF, CSA ATF) are always-on registries with coverage reports available via the API regardless of configuration.

---

## API Endpoints

All compliance endpoints require authentication. Available at `http://localhost:3000` when running `vellaveto serve`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/compliance/status` | GET | Overall compliance status (EU AI Act, SOC 2, ISO 42001, OWASP ASI) |
| `/api/compliance/eu-ai-act/report` | GET | EU AI Act conformity assessment |
| `/api/compliance/soc2/evidence` | GET | SOC 2 evidence report (optional `?category=CC6` filter) |
| `/api/compliance/soc2/access-review` | GET | SOC 2 CC6 access review (JSON or HTML) |
| `/api/compliance/iso42001/report` | GET | ISO 42001 clause compliance report |
| `/api/compliance/owasp-agentic` | GET | OWASP ASI coverage report (ASI01-ASI10) |
| `/api/compliance/threat-coverage` | GET | ATLAS, CoSAI, Adversa TOP 25 coverage |
| `/api/compliance/data-governance` | GET | Art 10 data governance summary |
| `/api/compliance/gap-analysis` | GET | Cross-framework gap analysis (10 frameworks) |
| `/api/compliance/evidence-pack/status` | GET | List available evidence pack frameworks |
| `/api/compliance/evidence-pack/{framework}` | GET | Generate evidence pack (`?format=json\|html`) |

Evidence pack frameworks: `dora`, `nis2`, `iso42001`, `eu-ai-act`

---

## File Reference

| File | Contents |
|------|----------|
| `vellaveto-audit/src/eu_ai_act.rs` | EU AI Act registry (Art 9, 10, 12, 14, 50) |
| `vellaveto-audit/src/soc2.rs` | SOC 2 Trust Services Criteria (CC1-CC9) |
| `vellaveto-audit/src/dora.rs` | DORA digital operational resilience (Ch II, III, V) |
| `vellaveto-audit/src/nis2.rs` | NIS2 cybersecurity directive (Art 21-23) |
| `vellaveto-audit/src/nist_ai600.rs` | NIST AI 600-1 GenAI risk profile |
| `vellaveto-audit/src/iso42001.rs` | ISO 42001 AI management system |
| `vellaveto-audit/src/singapore_mgf.rs` | Singapore Model Governance Framework |
| `vellaveto-audit/src/csa_atf.rs` | CSA Agentic Trust Framework |
| `vellaveto-audit/src/cosai.rs` | CoSAI MCP Security controls |
| `vellaveto-audit/src/adversa_top25.rs` | Adversa TOP 25 AI vulnerabilities |
| `vellaveto-audit/src/owasp_asi.rs` | OWASP Top 10 Agentic Applications |
| `vellaveto-audit/src/owasp_mcp.rs` | OWASP MCP Top 10 |
| `vellaveto-audit/src/evidence_pack.rs` | Evidence pack generator (DORA, NIS2, ISO 42001, EU AI Act) |
| `vellaveto-audit/src/incident_report.rs` | Cross-regulation incident reporting |
| `vellaveto-audit/src/gap_analysis.rs` | Consolidated gap analysis across all frameworks |
