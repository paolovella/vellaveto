#!/usr/bin/env bash
#
# check-claim-anchors.sh — validate public claim surfaces have evidence hooks.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

failures=0

fail() {
    echo "FAIL: $*" >&2
    failures=1
}

search_pattern() {
    local pattern="$1"
    shift

    if command -v rg >/dev/null 2>&1; then
        rg -n "$pattern" "$@" 2>/dev/null
        return
    fi

    grep -EnH -- "$pattern" "$@" 2>/dev/null
}

count_pattern() {
    local pattern="$1"
    local file="$2"

    (search_pattern "$pattern" "$file" || true) | wc -l | tr -d ' '
}

require_pattern() {
    local file="$1"
    local pattern="$2"
    local label="$3"

    if ! search_pattern "$pattern" "$file" >/dev/null; then
        fail "$file missing $label"
    fi
}

# Read from scripts/evidence-docs.txt -- the same list the generator uses, so
# the two cannot drift. Resolved from BASH_SOURCE, not the cwd.
evidence_docs_file="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/evidence-docs.txt"
if [ ! -f "$evidence_docs_file" ]; then
    fail "missing $evidence_docs_file"
    exit 1
fi
public_evidence_docs=()
while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    public_evidence_docs+=("$line")
done < "$evidence_docs_file"
if [ "${#public_evidence_docs[@]}" -eq 0 ]; then
    fail "$evidence_docs_file lists no docs"
    exit 1
fi

for doc in "${public_evidence_docs[@]}"; do
    require_pattern "$doc" '<!-- VELLAVETO:EVIDENCE:START -->' "generated evidence block start marker"
    require_pattern "$doc" '<!-- VELLAVETO:EVIDENCE:END -->' "generated evidence block end marker"
done

claim_count="$(count_pattern '^### C[0-9]+\.' docs/ASSURANCE_CASE.md)"
scope_count="$(count_pattern '\| \*\*Scope\*\* \|' docs/ASSURANCE_CASE.md)"
reproduce_count="$(count_pattern '\| \*\*Reproduce\*\* \|' docs/ASSURANCE_CASE.md)"
evidence_count="$(count_pattern '\| \*\*(Formal evidence|Test evidence|Benchmark evidence|Evidence)\*\* \|' docs/ASSURANCE_CASE.md)"

if [ "$claim_count" -lt 7 ]; then
    fail "docs/ASSURANCE_CASE.md should contain at least 7 public claim sections"
fi

if [ "$scope_count" -lt "$claim_count" ]; then
    fail "docs/ASSURANCE_CASE.md has $claim_count claims but only $scope_count Scope rows"
fi

if [ "$reproduce_count" -lt "$claim_count" ]; then
    fail "docs/ASSURANCE_CASE.md has $claim_count claims but only $reproduce_count Reproduce rows"
fi

if [ "$evidence_count" -lt "$claim_count" ]; then
    fail "docs/ASSURANCE_CASE.md has $claim_count claims but only $evidence_count Evidence rows"
fi

require_pattern README.md 'ASSURANCE_CASE\.md' "assurance case link"
require_pattern README.md 'make evidence' "evidence reproduction command"
require_pattern docs/ASSURANCE_CASE.md 'make verify' "strict verification reproduction command"
require_pattern formal/README.md 'make evidence' "formal evidence reproduction command"

claim_surfaces=(
    README.md
    docs/ASSURANCE_CASE.md
    formal/README.md
    site/index.html
)

while IFS= read -r file; do
    claim_surfaces+=("$file")
done < <(find site/src/components -maxdepth 1 -type f -name '*.astro' | sort)

stale_patterns=(
    '10,990\+'
    '10,366\+'
    '11\.3k\+'
    '11\.5k\+'
    '9,900\+ tests'
    '11,571'
    '556 SDK'
    '668 Verus'
    '108 Kani'
    '14 TLA'
    '37 Lean'
    '779\+ formally'
    '882\+ formally'
    '767\+ properties'
    '855 properties'
    '682 verified items'
    '116 proof harnesses'
    '82 harnesses'
    '64 properties'
)

for pattern in "${stale_patterns[@]}"; do
    if search_pattern "$pattern" "${claim_surfaces[@]}" >/tmp/vellaveto-claim-check-hits.txt; then
        echo "FAIL: stale unsupported public count matched /$pattern/:" >&2
        cat /tmp/vellaveto-claim-check-hits.txt >&2
        failures=1
    fi
done

rm -f /tmp/vellaveto-claim-check-hits.txt

if [ "$failures" -ne 0 ]; then
    exit 1
fi

echo "Claim evidence anchors checked."
