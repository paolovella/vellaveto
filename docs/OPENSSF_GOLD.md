# OpenSSF Best Practices — Gold Self-Assessment

Project: [bestpractices.dev/projects/12042](https://www.bestpractices.dev/projects/12042)

This document provides a criterion-by-criterion self-assessment for the OpenSSF
Best Practices Gold badge. Criteria are organized by category.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| MET | Criterion satisfied with evidence |
| N/A | Not applicable to this project |
| BLOCKER | Organizational blocker (requires community growth) |

---

## Basics

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `description_good` | MET | README.md, docs/API.md, docs/openapi.yaml |
| `interact` | MET | GitHub Issues, Discussions |
| `contribution` | MET | CONTRIBUTING.md |
| `contribution_requirements` | MET | CONTRIBUTING.md (CLA, commit format, test requirements) |
| `license_standard` | MET | SPDX identifiers in all source files |
| `copyright_per_file` | MET | `// Copyright 2026 Paolo Vella` in all .rs files |
| `license_per_file` | MET | `// SPDX-License-Identifier:` in all .rs files (CI-enforced) |

## Change Control

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `repo_public` | MET | github.com/paolovella/vellaveto |
| `repo_track` | MET | Git |
| `repo_interim` | MET | Feature branches, PRs |
| `repo_distributed` | MET | Git (distributed VCS) |
| `version_unique` | MET | SemVer tags (v6.0.0) |
| `version_semver` | MET | cargo-semver-checks in CI |
| `version_tags` | MET | Git tags (vX.Y.Z) |
| `release_notes` | MET | CHANGELOG.md |
| `release_notes_vulns` | MET | CHANGELOG.md security sections |

## Reporting

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `report_process` | MET | SECURITY.md |
| `report_tracker` | MET | GitHub Issues |
| `report_responses` | MET | GitHub Issues |
| `report_archive` | MET | GitHub Issues (public) |
| `vulnerability_report_process` | MET | SECURITY.md (private reporting) |
| `vulnerability_report_private` | MET | Email to maintainer |
| `vulnerability_report_response` | MET | 14-day acknowledgment target |

## Quality

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `build` | MET | `cargo build --workspace --locked` |
| `build_common_tools` | MET | Cargo (standard Rust build tool) |
| `build_floss_tools` | MET | All tools are FLOSS |
| `build_reproducible` | MET | -Ctrim-paths=all (RUSTFLAGS), codegen-units=1, --locked (docs/REPRODUCIBLE_BUILDS.md) |
| `test` | MET | 11,571+ tests, `cargo test --workspace` |
| `test_invocation` | MET | `cargo test --workspace --locked` |
| `test_most` | MET | Unit + integration + adversarial + property-based tests |
| `test_continuous_integration` | MET | GitHub Actions CI on every push/PR |
| `test_policy` | MET | CONTRIBUTING.md requires tests for all changes |
| `test_statement_coverage90` | MET | cargo-llvm-cov in CI (coverage.yml) |
| `test_branch_coverage80` | MET | cargo-llvm-cov with branch coverage |
| `tests_are_added` | MET | CONTRIBUTING.md policy, PR review enforcement |
| `tests_documented_added` | MET | CONTRIBUTING.md testing rules, AGENTS.md verification order |
| `warnings` | MET | RUSTFLAGS=-Dwarnings in CI (all warnings are errors) |
| `warnings_fixed` | MET | Zero warnings policy enforced |
| `warnings_strict` | MET | `-D warnings` flag in CI |

## Security

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `know_secure_design` | MET | AGENTS.md fail-closed conventions, SECURITY.md principles |
| `know_common_errors` | MET | OWASP Top 10, CWE coverage in audit rounds |
| `crypto_published` | MET | Ed25519, XChaCha20-Poly1305, Argon2id (all published standards) |
| `crypto_call` | MET | Uses ed25519-dalek, chacha20poly1305, argon2 crates |
| `crypto_floss` | MET | All crypto crates are FLOSS |
| `crypto_keylength` | MET | Ed25519 (256-bit), XChaCha20 (256-bit) |
| `crypto_working` | MET | No deprecated algorithms |
| `crypto_pfs` | N/A | Not a TLS terminator (delegates to reverse proxy) |
| `crypto_password_storage` | MET | Argon2id for credential vault |
| `crypto_random` | MET | Uses `rand` crate with OS entropy |
| `delivery_mitigation` | MET | SHA-256 checksums, SLSA provenance, cargo-vet |
| `delivery_unsigned` | MET | Release artifacts include checksums |
| `vulnerabilities_fixed_60_days` | MET | Findings from each adversarial audit round are resolved in that round; see `CHANGELOG.md` for the per-round record |
| `no_unpatched_vulnerabilities` | MET | First-party gates: cargo-audit, cargo-deny and cargo-vet (Rust); `dependency-audit.yml` for npm (every discovered lockfile), Python build requirements (pip-audit) and Go modules (govulncheck), on push, PR and weekly. Thresholds and the gaps are below. |
| `vulnerabilities_critical_fixed` | MET | CRITICAL findings fixed within same session |
| `hardening` | MET | docs/HARDENING.md |
| `security_review` | MET | docs/SECURITY_REVIEW.md; per-round detail in `CHANGELOG.md` |
| `dynamic_analysis` | MET | 24 fuzz targets, all 24 run in CI (`fuzz-ci.yml` matrix, on push and weekly) |
| `dynamic_analysis_unsafe` | MET | Zero `unsafe` in library code |
| `dynamic_analysis_enable_assertions` | MET | `overflow-checks = true`, debug_assertions in test profile |
| `dynamic_analysis_fixed` | MET | All fuzz findings fixed |

### Dependency audit scope and thresholds

`no_unpatched_vulnerabilities` above rests on first-party CI gates, so what they
cover and where they stop belongs here rather than in the one-line justification.

| Ecosystem | Gate | Threshold |
|---|---|---|
| Rust (workspace + 4 sub-trees) | `Security Audit` (cargo-audit), `cargo-deny policy checks`, `Supply Chain Audit (cargo-vet)` | fails on a vulnerability; unmaintained reported as a warning |
| npm (every discovered `package-lock.json`) | `Dependency Audit (npm)` | fails on **high** and **critical**; moderate and low printed, not fatal |
| Python build requirements | `Dependency Audit (Python)` (pip-audit) | fails on any known vulnerability |
| Go (`sdk/go`, `terraform-provider-vellaveto`) | `Dependency Audit (Go)` (govulncheck) | fails on any reported vulnerability |

All three non-Rust jobs run on push to `main`, on pull requests, and weekly. The
weekly run is the point: an advisory published against a dependency that has not
changed produces no push and no pull request, so a change-triggered check alone
would never see it. `RUSTSEC-2026-0543` (chrono, unmaintained) arrived exactly
that way.

**Two surfaces are not gated, and Dependabot alone covers them:**

- **`sdk/java` (maven).** OWASP dependency-check needs an NVD feed and an API
  key and is slow and failure-prone; a gate that cannot be kept green is worse
  than an honest gap.
- **`sdk/python/requirements-dev.txt`.** It is hash-pinned (`--require-hashes`),
  and a transitive dependency of `langchain-core` (`langchain-protocol`) is
  specified as a range rather than `==`, which pip refuses in that mode. So
  pip-audit cannot resolve it. This is a structural limitation of the file, not
  a clean result. `requirements-build.txt` is gated.

**One caveat about reading govulncheck output.** It assesses the standard library
of the toolchain running the scan, not the version in `go.mod`. On a toolchain
that is behind, both modules report dozens of stdlib advisories that say nothing
about this repository — scanning them with go1.24.7 produced 36 and 28 findings,
every one of them stdlib and **none** from the modules' own dependencies. The
gate therefore installs `stable`. A stdlib finding on a current toolchain is
real; one from a stale local toolchain is not.

## Analysis

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `static_analysis` | MET | Clippy (-D warnings), cargo-audit, cargo-deny |
| `static_analysis_common_vulnerabilities` | MET | Clippy + cargo-audit + Kani proof harnesses |
| `static_analysis_fixed` | MET | Zero warnings policy |
| `static_analysis_often` | MET | Every CI run (push + PR) |

## Governance

| Criterion | Status | Evidence |
|-----------|--------|----------|
| `governance` | MET | CONTRIBUTING.md, CLA.md |
| `roles_responsibilities` | MET | CONTRIBUTING.md, .claude/rules/ |
| `access_continuity` | MET | GitHub organization, bus factor documented |
| `require_2FA` | MET | SECURITY.md (all committers require 2FA) |
| `code_review_standards` | MET | CONTRIBUTING.md code review section |

---

## Organizational Blockers

The following Gold criteria require multiple contributors and cannot be
satisfied by technical means alone:

| Criterion | Requirement | Current Status | Path Forward |
|-----------|-------------|----------------|--------------|
| `bus_factor` | >= 2 people familiar with each key area | Not met (solo maintainer) | `good first issue` labels, mentorship, community outreach |
| `contributors_unassociated` | >= 2 unassociated contributors in past year | Not met | Community growth via conferences, blog posts |
| `two_person_review` | 50%+ of changes reviewed by non-author | Not met | Requires external contributors with review access |

### Roadmap to Satisfy Blockers

1. Label issues with `good first issue` and `help wanted`
2. Write contributor onboarding tutorials
3. Present at MCP/AI security conferences
4. Engage with OWASP Agentic Security community
5. Establish a contributors program with review access

Once these organizational criteria are met, the project will qualify for the
Gold badge. All technical criteria are satisfied.
