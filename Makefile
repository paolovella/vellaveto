# Vellaveto — Top-level Makefile
#
# Primary target: `make verify` — runs all verification steps and produces
# a JSON evidence bundle that reviewers can attach to issues or PRs.

SHELL := /bin/bash
.DEFAULT_GOAL := help

EVIDENCE_DIR := target/evidence
EVIDENCE_FILE := $(EVIDENCE_DIR)/evidence.json
ALLOY_JAR ?= formal/alloy/alloy.jar
KANI_SHARD_COUNT ?= 8

# ─────────────────────────────────────────────────────────────────────
# Primary targets
# ─────────────────────────────────────────────────────────────────────

.PHONY: verify
verify: ## Run strict verification suite; missing formal tools fail
	@echo "═══════════════════════════════════════════════════════════════"
	@echo " Vellaveto Verification Suite (strict)"
	@echo "═══════════════════════════════════════════════════════════════"
	@mkdir -p $(EVIDENCE_DIR)
	@echo ""
	@echo "── [1/7] Format check ───────────────────────────────────────"
	$(MAKE) fmt
	@echo ""
	@echo "── [2/7] Clippy (deny warnings) ─────────────────────────────"
	$(MAKE) clippy
	@echo ""
	@echo "── [3/7] Test suite ─────────────────────────────────────────"
	$(MAKE) test
	@echo ""
	@echo "── [4/7] Formal verification (strict) ───────────────────────"
	$(MAKE) formal
	@echo ""
	@echo "── [5/7] Benchmark sanity check ─────────────────────────────"
	$(MAKE) bench-quick
	@echo ""
	@echo "── [6/7] Security regression suite ──────────────────────────"
	cargo test -p vellaveto-integration -- --test-threads=1
	@echo ""
	@echo "── [7/7] Evidence and claim checks ──────────────────────────"
	$(MAKE) evidence
	$(MAKE) claim-check
	@echo ""
	@echo "Evidence bundle: $(EVIDENCE_FILE)"
	@echo ""
	@echo "All checks passed."

.PHONY: verify-local
verify-local: ## Run local verification; unavailable formal toolchains are reported as skips
	@echo "═══════════════════════════════════════════════════════════════"
	@echo " Vellaveto Verification Suite (local)"
	@echo "═══════════════════════════════════════════════════════════════"
	@mkdir -p $(EVIDENCE_DIR)
	@echo ""
	@echo "── [1/7] Format check ───────────────────────────────────────"
	$(MAKE) fmt
	@echo ""
	@echo "── [2/7] Clippy (deny warnings) ─────────────────────────────"
	$(MAKE) clippy
	@echo ""
	@echo "── [3/7] Test suite ─────────────────────────────────────────"
	$(MAKE) test
	@echo ""
	@echo "── [4/7] Formal verification (local coverage) ───────────────"
	bash scripts/report-formal-tooling.sh
	$(MAKE) formal-local
	@echo ""
	@echo "── [5/7] Benchmark sanity check ─────────────────────────────"
	$(MAKE) bench-quick
	@echo ""
	@echo "── [6/7] Security regression suite ──────────────────────────"
	cargo test -p vellaveto-integration -- --test-threads=1
	@echo ""
	@echo "── [7/7] Evidence and claim checks ──────────────────────────"
	$(MAKE) evidence
	$(MAKE) claim-check
	@echo ""
	@echo "Evidence bundle: $(EVIDENCE_FILE)"
	@echo ""
	@echo "Local checks passed with any formal toolchain gaps reported above."

# ─────────────────────────────────────────────────────────────────────
# Individual targets
# ─────────────────────────────────────────────────────────────────────

.PHONY: test
test: ## Run full test suite
	cargo test --workspace --no-fail-fast

.PHONY: clippy
clippy: ## Run clippy with deny warnings
	cargo clippy --workspace -- -D warnings

.PHONY: fmt
fmt: ## Check formatting
	cargo fmt --all -- --check

.PHONY: bench
bench: ## Run full benchmark suite
	cargo bench --workspace

.PHONY: bench-quick
bench-quick: ## Run quick benchmark sanity check
	cargo bench -p vellaveto-engine --bench evaluation -- --quick
	cargo bench -p vellaveto-engine --bench e2e_pipeline -- --quick
	cargo bench -p vellaveto-engine --bench throughput -- --quick

.PHONY: evidence
evidence: ## Generate the canonical evidence manifest
	bash scripts/generate-evidence-manifest.sh --output $(EVIDENCE_FILE) --site-output site/src/data/evidence.json

.PHONY: evidence-sync
evidence-sync: ## Write the generated evidence block into the docs that carry it
	bash scripts/generate-evidence-manifest.sh --output $(EVIDENCE_FILE) --site-output site/src/data/evidence.json --sync

.PHONY: evidence-check
evidence-check: ## Validate the canonical evidence manifest schema
	bash scripts/generate-evidence-manifest.sh --output $(EVIDENCE_FILE) --check

.PHONY: claim-check
claim-check: evidence-check ## Validate public claim evidence anchors
	bash scripts/check-claim-anchors.sh

.PHONY: formal
formal: formal-trusted-assumptions formal-proof-completions formal-tla formal-alloy formal-lean formal-coq formal-kani formal-verus ## Run all formal verification tools

.PHONY: formal-local
formal-local: ## Run storage-light local formal coverage checks
	bash formal/tools/check-formal-trusted-assumptions.sh
	bash formal/tools/check-proof-completion-markers.sh
	bash formal/tools/check-verus-parity.sh
	RUN_KANI_PARITY_TESTS=0 KANI_PARITY_TARGET_DIR="$${KANI_PARITY_TARGET_DIR:-/tmp/vellaveto-formal-kani-parity-target}" bash formal/tools/check-kani-parity.sh
	bash formal/tools/check-formal-e2e-coverage.sh

.PHONY: formal-e2e-coverage
formal-e2e-coverage: ## Verify local end-to-end formal coverage anchors
	bash formal/tools/check-formal-e2e-coverage.sh

.PHONY: verify-all
verify-all: formal ## Run the full local formal verification mesh

.PHONY: formal-tla
formal-tla: ## Run TLA+ model checking (all local specs, requires Java 11+ and tla2tools.jar)
	@for cfg in formal/tla/*.cfg; do \
		spec="$${cfg##*/}"; \
		spec="$${spec%.cfg}"; \
		mc="formal/tla/MC_$${spec}.tla"; \
		main="formal/tla/$${spec}.tla"; \
		if [ -f "$$mc" ]; then \
			echo "TLA+ $$spec (via MC_$${spec})..."; \
			cd formal/tla && java -jar tla2tools.jar -config $${spec}.cfg MC_$${spec}.tla && cd ../..; \
		elif [ -f "$$main" ]; then \
			echo "TLA+ $$spec (direct)..."; \
			cd formal/tla && java -jar tla2tools.jar -config $${spec}.cfg $${spec}.tla && cd ../..; \
		fi; \
	done

.PHONY: formal-alloy
formal-alloy: ## Run Alloy bounded model checking (requires alloy.jar)
	ALLOY_JAR="$(ALLOY_JAR)" bash formal/tools/run-alloy-model.sh formal/alloy/CapabilityDelegation.als
	ALLOY_JAR="$(ALLOY_JAR)" bash formal/tools/run-alloy-model.sh formal/alloy/AbacForbidOverride.als

.PHONY: formal-lean
formal-lean: ## Run Lean 4 type checker (5 files, 32 theorems)
	cd formal/lean && lake build

.PHONY: formal-coq
formal-coq: ## Run Coq type checker (8 files, 45 theorems)
	cd formal/coq && coq_makefile -f _CoqProject -o CoqMakefile && make -f CoqMakefile

.PHONY: formal-kani
formal-kani: ## Run Kani bounded model checking through local shards
	@count="$(KANI_SHARD_COUNT)"; \
	case "$$count" in ''|*[!0-9]*) echo "FAIL: invalid KANI_SHARD_COUNT=$$count"; exit 2;; esac; \
	if [ "$$count" -eq 0 ]; then echo "FAIL: KANI_SHARD_COUNT must be greater than 0"; exit 2; fi; \
	for shard in $$(seq 0 $$((count - 1))); do \
		bash formal/tools/run-kani-shard.sh "$$shard" "$$count"; \
	done

.PHONY: formal-trusted-assumptions
formal-trusted-assumptions: ## Verify the trusted-assumption inventory matches the allowlist
	bash formal/tools/check-formal-trusted-assumptions.sh

.PHONY: formal-proof-completions
formal-proof-completions: ## Verify Lean/Coq sources contain no unfinished proof markers
	bash formal/tools/check-proof-completion-markers.sh

.PHONY: formal-verus
formal-verus: ## Run Verus parity checks and canonical verification
	bash formal/tools/check-verus-parity.sh
	FORMAL_USE_CARGO_VERUS=1 FORMAL_REQUIRE_CARGO_VERUS=1 CARGO_VERUS_TARGET_DIR="$${CARGO_VERUS_TARGET_DIR:-/tmp/vellaveto-formal-verus-target}" bash formal/tools/verify-verus.sh

.PHONY: formal-docker
formal-docker: ## Run formal verification in Docker (reproducible, all tools pinned)
	docker build -t vellaveto-formal formal/
	docker run --rm -v "$(CURDIR):/workspace" vellaveto-formal

.PHONY: formal-clean-local
formal-clean-local: ## Remove repo-local and default tmp-backed formal artifacts
	rm -rf formal/kani/target
	rm -rf formal/kani/states
	rm -rf formal/tla/states
	rm -rf /tmp/vellaveto-formal-kani-target
	rm -rf /tmp/vellaveto-formal-kani-parity-target
	rm -rf /tmp/vellaveto-formal-verus-target

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean
	rm -rf $(EVIDENCE_DIR)

# ─────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
