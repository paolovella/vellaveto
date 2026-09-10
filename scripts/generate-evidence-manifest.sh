#!/usr/bin/env bash
#
# generate-evidence-manifest.sh — emit the canonical Vellaveto evidence manifest.
#
# The default counts are source-inventory counts so the manifest can be produced
# locally without running every proof tool. CI may pass EVIDENCE_* overrides from
# executed test/proof jobs when stricter run evidence is available.

set -euo pipefail

OUTPUT="target/evidence/evidence.json"
DOC_SUMMARY="target/evidence/evidence-summary.md"
SITE_OUTPUT=""
CHECK_ONLY=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            if [ "$#" -lt 2 ]; then
                echo "FAIL: --output requires a path" >&2
                exit 2
            fi
            OUTPUT="$2"
            shift 2
            ;;
        --docs-output)
            if [ "$#" -lt 2 ]; then
                echo "FAIL: --docs-output requires a path" >&2
                exit 2
            fi
            DOC_SUMMARY="$2"
            shift 2
            ;;
        --site-output)
            if [ "$#" -lt 2 ]; then
                echo "FAIL: --site-output requires a path" >&2
                exit 2
            fi
            SITE_OUTPUT="$2"
            shift 2
            ;;
        --check)
            CHECK_ONLY=1
            shift
            ;;
        *)
            echo "FAIL: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

count_matches() {
    local pattern="$1"
    shift

    if command -v rg >/dev/null 2>&1; then
        (rg -n "$pattern" "$@" 2>/dev/null || true) | wc -l | tr -d ' '
        return
    fi

    local glob=""
    local paths=()
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -g)
                if [ "$#" -lt 2 ]; then
                    echo "FAIL: -g requires a glob" >&2
                    exit 2
                fi
                glob="$2"
                shift 2
                ;;
            *)
                paths+=("$1")
                shift
                ;;
        esac
    done

    if [ "${#paths[@]}" -eq 0 ]; then
        paths=(.)
    fi

    local count=0
    local file
    local file_count
    while IFS= read -r -d '' file; do
        file_count="$( (grep -E -n "$pattern" "$file" 2>/dev/null || true) | wc -l | tr -d ' ')"
        count=$((count + file_count))
    done < <(
        if [ -n "$glob" ]; then
            find "${paths[@]}" -type f -name "$glob" -print0 2>/dev/null
        else
            find "${paths[@]}" -type f -print0 2>/dev/null
        fi
    )

    printf '%s' "$count"
}

contains_text() {
    local needle="$1"
    local file="$2"

    if command -v rg >/dev/null 2>&1; then
        rg -q --fixed-strings "$needle" "$file"
        return
    fi

    grep -Fq -- "$needle" "$file"
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

number_value() {
    case "${1:-}" in
        ''|*[!0-9]*) printf '0' ;;
        *) printf '%s' "$1" ;;
    esac
}

workspace_rust_dirs=(
    vellaveto-types
    vellaveto-engine
    vellaveto-audit
    vellaveto-mcp
    vellaveto-canonical
    vellaveto-config
    vellaveto-discovery
    vellaveto-cluster
    vellaveto-integration
    vellaveto-server
    vellaveto-approval
    vellaveto-proxy
    vellaveto-http-proxy
    vellaveto-operator
    mcpsec
    vellaveto-mcp-shield
    vellaveto-http-proxy-shield
    vellaveto-canary
    vellaveto-shield
    vellaveto-tls
)

git_sha="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' vellaveto-server/Cargo.toml | head -1)"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ] && [ -n "${GITHUB_RUN_ID:-}" ]; then
    ci_run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
else
    ci_run_url="local"
fi

rust_tests="${EVIDENCE_RUST_TESTS:-$(count_matches '^[[:space:]]*#\[(tokio::test|test|rstest|test_case)' "${workspace_rust_dirs[@]}" -g '*.rs')}"

python_sdk_tests="$(count_matches '^[[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_|^[[:space:]]*class[[:space:]]+Test' sdk/python/tests -g '*.py')"
typescript_sdk_tests="$(count_matches '\b(test|it)[[:space:]]*\(' sdk/typescript/tests -g '*.ts')"
java_sdk_tests="$(count_matches '@Test\b' sdk/java/src/test -g '*.java')"
go_sdk_tests="$(count_matches '^func[[:space:]]+Test' sdk/go -g '*.go')"
sdk_tests="${EVIDENCE_SDK_TESTS:-$((python_sdk_tests + typescript_sdk_tests + java_sdk_tests + go_sdk_tests))}"

verus_items="${EVIDENCE_VERUS_ITEMS:-$(count_matches '^[[:space:]]*(pub[[:space:]]+)?((open[[:space:]]+)?spec|proof)?[[:space:]]*fn[[:space:]]+[A-Za-z_]' formal/verus -g '*.rs')}"
kani_harnesses="${EVIDENCE_KANI_HARNESSES:-$(count_matches '#\[kani::proof\]' formal/kani -g '*.rs')}"
tla_specs="${EVIDENCE_TLA_SPECS:-$(find formal/tla -maxdepth 1 -name '*.cfg' -type f | wc -l | tr -d ' ')}"
lean_theorems="${EVIDENCE_LEAN_THEOREMS:-$(count_matches '^[[:space:]]*(theorem|lemma)[[:space:]]+' formal/lean -g '*.lean')}"
coq_theorems="${EVIDENCE_COQ_THEOREMS:-$(count_matches '^[[:space:]]*(Theorem|Lemma|Corollary|Fact)[[:space:]]+' formal/coq -g '*.v')}"
alloy_assertions="${EVIDENCE_ALLOY_ASSERTIONS:-$(count_matches '^[[:space:]]*assert[[:space:]]+' formal/alloy -g '*.als')}"

rust_tests="$(number_value "$rust_tests")"
sdk_tests="$(number_value "$sdk_tests")"
verus_items="$(number_value "$verus_items")"
kani_harnesses="$(number_value "$kani_harnesses")"
tla_specs="$(number_value "$tla_specs")"
lean_theorems="$(number_value "$lean_theorems")"
coq_theorems="$(number_value "$coq_theorems")"
alloy_assertions="$(number_value "$alloy_assertions")"
total_tests=$((rust_tests + sdk_tests))
formal_evidence_items=$((verus_items + kani_harnesses + tla_specs + lean_theorems + coq_theorems + alloy_assertions))

mkdir -p "$(dirname "$OUTPUT")"
mkdir -p "$(dirname "$DOC_SUMMARY")"

cat > "$OUTPUT" <<JSON
{
  "git_sha": "$(json_escape "$git_sha")",
  "version": "$(json_escape "$version")",
  "rust_tests": $rust_tests,
  "sdk_tests": $sdk_tests,
  "total_tests": $total_tests,
  "verus_items": $verus_items,
  "kani_harnesses": $kani_harnesses,
  "tla_specs": $tla_specs,
  "lean_theorems": $lean_theorems,
  "coq_theorems": $coq_theorems,
  "alloy_assertions": $alloy_assertions,
  "formal_evidence_items": $formal_evidence_items,
  "ci_run_url": "$(json_escape "$ci_run_url")",
  "generated_at": "$(json_escape "$generated_at")",
  "count_methods": {
    "rust_tests": "source attributes in canonical workspace crates unless EVIDENCE_RUST_TESTS is set; counts every #[test] in the tree including feature-gated ones, all of which the ci.yml feature-matrix job executes",
    "sdk_tests": "source test declarations across Python, TypeScript, Java, and Go SDKs unless EVIDENCE_SDK_TESTS is set",
    "formal": "source inventory unless EVIDENCE_* formal overrides are set"
  }
}
JSON

cat > "$DOC_SUMMARY" <<MD
<!-- VELLAVETO:EVIDENCE:START -->
| Evidence item | Count |
|---|---:|
| Rust tests | $rust_tests |
| SDK tests | $sdk_tests |
| Total tests tracked by manifest | $total_tests |
| Verus verified items | $verus_items |
| Kani proof harnesses | $kani_harnesses |
| TLA+ specs | $tla_specs |
| Lean theorems | $lean_theorems |
| Coq theorems | $coq_theorems |
| Alloy assertions | $alloy_assertions |
| Formal evidence items tracked by manifest | $formal_evidence_items |

Test counts are source-attribute inventories, not counts of tests that
passed in a given run. Every counted Rust test is executed by CI: those
behind a non-default feature run in the \`feature-matrix\` job in
\`.github/workflows/ci.yml\`, the rest in the main workspace test job.
<!-- VELLAVETO:EVIDENCE:END -->
MD

site_expected="target/evidence/site-evidence.json"
mkdir -p "$(dirname "$site_expected")"
cat > "$site_expected" <<JSON
{
  "version": "$(json_escape "$version")",
  "rustTests": $rust_tests,
  "sdkTests": $sdk_tests,
  "totalTests": $total_tests,
  "verusItems": $verus_items,
  "kaniHarnesses": $kani_harnesses,
  "tlaSpecs": $tla_specs,
  "leanTheorems": $lean_theorems,
  "coqTheorems": $coq_theorems,
  "alloyAssertions": $alloy_assertions,
  "formalEvidenceItems": $formal_evidence_items
}
JSON

if [ -n "$SITE_OUTPUT" ]; then
    mkdir -p "$(dirname "$SITE_OUTPUT")"
    cp "$site_expected" "$SITE_OUTPUT"
fi

extract_evidence_block() {
    local file="$1"
    local output="$2"
    awk '
        /<!-- VELLAVETO:EVIDENCE:START -->/ { in_block = 1 }
        in_block { print }
        /<!-- VELLAVETO:EVIDENCE:END -->/ { found = 1; in_block = 0 }
        END { exit(found ? 0 : 1) }
    ' "$file" > "$output"
}

if [ "$CHECK_ONLY" -eq 1 ]; then
    for field in git_sha version rust_tests sdk_tests total_tests verus_items kani_harnesses tla_specs lean_theorems coq_theorems alloy_assertions formal_evidence_items ci_run_url generated_at; do
        if ! contains_text "\"$field\"" "$OUTPUT"; then
            echo "FAIL: evidence manifest missing field: $field" >&2
            exit 1
        fi
    done

    for doc in README.md docs/ASSURANCE_CASE.md formal/README.md; do
        tmp="$(mktemp)"
        if ! extract_evidence_block "$doc" "$tmp"; then
            echo "FAIL: $doc missing VELLAVETO:EVIDENCE generated block" >&2
            rm -f "$tmp"
            exit 1
        fi
        if ! diff -u "$DOC_SUMMARY" "$tmp"; then
            echo "FAIL: $doc evidence block is out of sync with $OUTPUT" >&2
            rm -f "$tmp"
            exit 1
        fi
        rm -f "$tmp"
    done

    if ! diff -u "$site_expected" site/src/data/evidence.json; then
        echo "FAIL: site/src/data/evidence.json is out of sync with $OUTPUT" >&2
        exit 1
    fi
fi

echo "Evidence manifest: $OUTPUT"
echo "Evidence docs summary: $DOC_SUMMARY"
