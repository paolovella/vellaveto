#!/usr/bin/env bash
# Regression tests for the verdict classification in
# scripts/run-supply-chain-scan.sh.
#
# Why this file exists
# --------------------
# Its sibling, dependency-monitor-verdict.sh, exists because the cargo monitor
# spent three weeks announcing "advisory posture UNKNOWN" over 17 real
# vulnerabilities. The classifier had been asked whether a scan ran rather than
# what it found, and the hand-written fixtures that were supposed to catch that
# agreed with the bug because they were not the bytes the real tool emits.
#
# The supply-chain scanner has the same shape of hazard in a subtler form.
# osv-scanner's JSON `results` array is EMPTY on a clean scan: "examined 283
# packages, found nothing" and "examined nothing at all" are byte-identical
# unless --all-packages is passed. A classifier reading that output can report
# a silent no-op as a pass, which is the one failure mode a security gate must
# not have.
#
# So the fixtures below are real osv-scanner 2.7.1 output, trimmed in size but
# not in shape, including the exit codes it actually returns:
#
#   exit 0   clean scan, `results` populated by --all-packages
#   exit 0   go.mod with no requirements: {"results":[]}, 124 bytes
#   exit 1   findings present
#   exit 128 "No package sources found" -- EMPTY stdout, which is the shape a
#            lockfile that has stopped parsing produces
#
# Every one of those was observed directly rather than assumed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCANNER="${WORKSPACE_ROOT}/scripts/run-supply-chain-scan.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

failures=0
checks=0

# Re-implement nothing: pull the functions under test out of the script itself,
# so drift between this test and the script fails here rather than producing a
# copy that silently agrees with itself.
extract() {
  local name="$1"
  sed -n "/^${name}() {/,/^}/p" "${SCANNER}"
}

eval "$(extract json_number)"
eval "$(extract zero_packages_expected)"
eval "$(extract manifest_verdict)"
eval "$(extract verdict_is_failure)"

# The arrays the extracted functions close over. Parsed out of the script rather
# than restated, for the same reason.
eval "$(sed -n '/^ZERO_PACKAGE_EXPECTED=(/,/^)/p' "${SCANNER}")"
eval "$(sed -n '/^MANIFESTS=(/,/^)/p' "${SCANNER}")"

expect_eq() {
  local label="$1" got="$2" want="$3"
  checks=$((checks + 1))
  if [[ "${got}" == "${want}" ]]; then
    printf 'ok   %s\n' "${label}"
  else
    printf 'FAIL %s\n       got:  %s\n       want: %s\n' "${label}" "${got}" "${want}"
    failures=$((failures + 1))
  fi
}

expect_failure_verdict() {
  local label="$1" verdict="$2" want="$3" # want = blocking | passing
  checks=$((checks + 1))
  local got=passing
  verdict_is_failure "${verdict}" && got=blocking
  if [[ "${got}" == "${want}" ]]; then
    printf 'ok   %s\n' "${label}"
  else
    printf 'FAIL %s (verdict %q treated as %s, expected %s)\n' \
      "${label}" "${verdict}" "${got}" "${want}"
    failures=$((failures + 1))
  fi
}

# ---------------------------------------------------------------------------
# Fixtures: real osv-scanner 2.7.1 --all-packages output shapes.
# ---------------------------------------------------------------------------

# A clean scan. Note that the finding-free packages are present ONLY because
# --all-packages is passed; without it this document would be {"results":[]} and
# indistinguishable from a scan that examined nothing.
cat > "${TMP}/clean.json" <<'JSON'
{
  "results": [
    {
      "source": { "path": "/repo/sdk/java/pom.xml", "type": "lockfile" },
      "packages": [
        { "package": { "name": "com.fasterxml.jackson.core:jackson-databind",
                       "version": "2.22.4", "ecosystem": "Maven",
                       "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.22.4" } },
        { "package": { "name": "com.fasterxml.jackson.core:jackson-core",
                       "version": "2.22.4", "ecosystem": "Maven",
                       "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-core@2.22.4" } }
      ]
    }
  ],
  "experimental_config": { "licenses": { "summary": false, "allowlist": null } }
}
JSON

# A go.mod declaring no third-party requirements: exit 0, empty results. This is
# the one case where zero packages is the truth rather than a failure, and it is
# why ZERO_PACKAGE_EXPECTED exists.
printf '%s\n' '{"results":[],"experimental_config":{"licenses":{"summary":false,"allowlist":null}}}' \
  > "${TMP}/zero.json"

# Findings in dev-only packages, with the dependency_groups labelling that
# osv-scanner emits for them. Taken from a real admin-console scan.
cat > "${TMP}/dev.json" <<'JSON'
{
  "results": [
    {
      "source": { "path": "/repo/admin-console/package-lock.json", "type": "lockfile" },
      "packages": [
        { "package": { "name": "react", "version": "19.3.0", "ecosystem": "npm",
                       "purl": "pkg:npm/react@19.3.0" } },
        { "package": { "name": "minimatch", "version": "10.2.6", "ecosystem": "npm",
                       "purl": "pkg:npm/minimatch@10.2.6" },
          "dependency_groups": ["dev"],
          "vulnerabilities": [ { "id": "GHSA-g3hv-75wg-m249",
                                 "summary": "minimatch denial of service via globparts amplification" } ] },
        { "package": { "name": "zod", "version": "4.3.6", "ecosystem": "npm",
                       "purl": "pkg:npm/zod@4.3.6" },
          "dependency_groups": ["dev"],
          "vulnerabilities": [ { "id": "GHSA-mrhx-c7xc-m3w5",
                                 "summary": "Zod memory exhaustion on oversized constrained collections" } ] }
      ]
    }
  ]
}
JSON

# A finding in a production package, plus one dev finding alongside it. The
# production one must dominate: a gate that lets a shipped vulnerability through
# because a dev finding was also present would be worse than no gate.
cat > "${TMP}/prod.json" <<'JSON'
{
  "results": [
    {
      "source": { "path": "/repo/site/package-lock.json", "type": "lockfile" },
      "packages": [
        { "package": { "name": "astro", "version": "7.3.8", "ecosystem": "npm",
                       "purl": "pkg:npm/astro@7.3.8" },
          "vulnerabilities": [ { "id": "GHSA-r3h5-4585-7x3w" },
                               { "id": "GHSA-mh32-jxcr-mh9f" } ] },
        { "package": { "name": "minimatch", "version": "10.2.6", "ecosystem": "npm",
                       "purl": "pkg:npm/minimatch@10.2.6" },
          "dependency_groups": ["dev"],
          "vulnerabilities": [ { "id": "GHSA-g3hv-75wg-m249" } ] }
      ]
    }
  ]
}
JSON

# The group labels osv-scanner was observed to emit across this repository's
# eleven manifests: ['dev'], absent, ['dev','optional'], ['optional'],
# ['bundled','dev','optional'] and ['test']. Only an explicit dev or test label
# means a package is absent from the production install tree; "optional" alone
# does NOT, because an optionalDependency is installed in production when its
# platform matches.
cat > "${TMP}/groups.json" <<'JSON'
{
  "results": [
    {
      "source": { "path": "/repo/x/package-lock.json", "type": "lockfile" },
      "packages": [
        { "package": { "name": "a", "version": "1", "ecosystem": "npm" },
          "dependency_groups": ["dev"],
          "vulnerabilities": [ { "id": "V-DEV" } ] },
        { "package": { "name": "b", "version": "1", "ecosystem": "npm" },
          "dependency_groups": ["test"],
          "vulnerabilities": [ { "id": "V-TEST" } ] },
        { "package": { "name": "c", "version": "1", "ecosystem": "npm" },
          "dependency_groups": ["dev", "optional"],
          "vulnerabilities": [ { "id": "V-DEV-OPT" } ] },
        { "package": { "name": "d", "version": "1", "ecosystem": "npm" },
          "dependency_groups": ["bundled", "dev", "optional"],
          "vulnerabilities": [ { "id": "V-BUNDLED-DEV-OPT" } ] },
        { "package": { "name": "e", "version": "1", "ecosystem": "npm" },
          "dependency_groups": ["optional"],
          "vulnerabilities": [ { "id": "V-OPT-ONLY" } ] },
        { "package": { "name": "f", "version": "1", "ecosystem": "npm" },
          "dependency_groups": [],
          "vulnerabilities": [ { "id": "V-EMPTY-GROUPS" } ] },
        { "package": { "name": "g", "version": "1", "ecosystem": "npm" },
          "vulnerabilities": [ { "id": "V-NO-GROUPS" } ] }
      ]
    }
  ]
}
JSON

printf '' > "${TMP}/empty.json"                      # exit 128 writes no stdout
printf 'No package sources found\n' > "${TMP}/notjson.json"
printf '{"results":"not-a-list"}\n' > "${TMP}/badshape.json"

echo "--- json_number: counting, on real output shapes ---"
expect_eq "clean scan counts its packages"          "$(json_number "${TMP}/clean.json" packages)" "2"
expect_eq "clean scan reports no vulnerabilities"   "$(json_number "${TMP}/clean.json" vulns)"    "0"
expect_eq "dev fixture counts all three packages"   "$(json_number "${TMP}/dev.json" packages)"   "3"
expect_eq "dev fixture: two advisories in total"    "$(json_number "${TMP}/dev.json" vulns)"      "2"
expect_eq "dev fixture: none of them production"    "$(json_number "${TMP}/dev.json" vulns_prod)" "0"
expect_eq "dev fixture: both dev-only"              "$(json_number "${TMP}/dev.json" vulns_dev)"  "2"
expect_eq "prod fixture: two production advisories" "$(json_number "${TMP}/prod.json" vulns_prod)" "2"
expect_eq "prod fixture: one dev advisory beside"   "$(json_number "${TMP}/prod.json" vulns_dev)"  "1"
expect_eq "go.mod with no requirements: 0 packages" "$(json_number "${TMP}/zero.json" packages)"  "0"

echo "--- json_number: fail-closed on anything it cannot read ---"
expect_eq "empty stdout (the exit-128 shape)"  "$(json_number "${TMP}/empty.json" packages)"    "UNKNOWN"
expect_eq "output that is not JSON"            "$(json_number "${TMP}/notjson.json" packages)"  "UNKNOWN"
expect_eq "JSON of an unexpected shape"        "$(json_number "${TMP}/badshape.json" packages)" "UNKNOWN"
expect_eq "a file that does not exist"         "$(json_number "${TMP}/absent.json" packages)"   "UNKNOWN"

echo "--- dependency-group classification (fail-closed on anything unlabelled) ---"
# dev, test, dev+optional and bundled+dev+optional are unshipped: 4 findings.
# optional alone, an empty list and an absent list are production: 3 findings.
expect_eq "dev / test / dev+optional / bundled counted as dev" \
  "$(json_number "${TMP}/groups.json" vulns_dev)" "4"
expect_eq "optional-only, empty and absent groups counted as production" \
  "$(json_number "${TMP}/groups.json" vulns_prod)" "3"
expect_eq "every finding is classified exactly once" \
  "$(( $(json_number "${TMP}/groups.json" vulns_dev) + $(json_number "${TMP}/groups.json" vulns_prod) ))" \
  "$(json_number "${TMP}/groups.json" vulns)"

echo "--- manifest_verdict ---"
expect_eq "a populated clean scan is clean" \
  "$(manifest_verdict sdk/java/pom.xml "${TMP}/clean.json" 0)" "clean"
expect_eq "production findings block, and are named as advisories" \
  "$(manifest_verdict site/package-lock.json "${TMP}/prod.json" 1)" "2 advisories"
expect_eq "dev-only findings are labelled as such" \
  "$(manifest_verdict admin-console/package-lock.json "${TMP}/dev.json" 1)" "2 advisories (dev-only)"
expect_eq "zero packages is 'no packages' only where that is expected" \
  "$(manifest_verdict sdk/go/go.mod "${TMP}/zero.json" 0)" "no packages"
expect_eq "zero packages anywhere else is UNKNOWN, never clean" \
  "$(manifest_verdict site/package-lock.json "${TMP}/zero.json" 0)" "UNKNOWN"
expect_eq "exit 128 (no package sources found) is UNKNOWN" \
  "$(manifest_verdict site/package-lock.json "${TMP}/empty.json" 128)" "UNKNOWN"
expect_eq "any unexpected exit status is UNKNOWN" \
  "$(manifest_verdict site/package-lock.json "${TMP}/clean.json" 127)" "UNKNOWN"
expect_eq "unreadable output is UNKNOWN even on a success status" \
  "$(manifest_verdict site/package-lock.json "${TMP}/notjson.json" 0)" "UNKNOWN"

echo "--- verdict_is_failure: what stops the build ---"
expect_failure_verdict "clean passes"                  "clean"                    passing
expect_failure_verdict "expected zero packages passes" "no packages"              passing
expect_failure_verdict "dev-only findings pass"        "4 advisories (dev-only)"  passing
expect_failure_verdict "production findings block"     "2 advisories"             blocking
expect_failure_verdict "UNKNOWN blocks"                "UNKNOWN"                  blocking
# The important asymmetry: a verdict this test does not recognise must block.
# Adding a verdict string to the script without adding it here should fail the
# build, not sail through it.
expect_failure_verdict "an unrecognised verdict blocks" "something new" blocking

echo "--- drift guards ---"
checks=$((checks + 1))
if [[ "${#MANIFESTS[@]}" -eq 11 ]]; then
  printf 'ok   MANIFESTS still lists 11 manifests\n'
else
  printf 'FAIL MANIFESTS lists %s manifests, this test was written against 11.\n' "${#MANIFESTS[@]}"
  printf '     Adding coverage is welcome -- update this count and check the\n'
  printf '     new manifest is reflected in the cases above.\n'
  failures=$((failures + 1))
fi

checks=$((checks + 1))
if [[ "${#ZERO_PACKAGE_EXPECTED[@]}" -eq 1 && "${ZERO_PACKAGE_EXPECTED[0]}" == "sdk/go/go.mod" ]]; then
  printf 'ok   sdk/go/go.mod is the only manifest allowed to resolve to zero packages\n'
else
  printf 'FAIL ZERO_PACKAGE_EXPECTED is now %s. Each entry suppresses the\n' "${ZERO_PACKAGE_EXPECTED[*]}"
  printf '     "a lockfile stopped parsing" signal for that manifest, so each one\n'
  printf '     needs a reason recorded in the script and a case here.\n'
  failures=$((failures + 1))
fi

checks=$((checks + 1))
# Matched against the invocation line itself, not the whole file. An earlier
# version of this guard grepped for the flag anywhere in the script, and passed
# happily when the flag was removed from the osv-scanner call -- because the
# word still appeared in the comment explaining why it matters. Found by
# mutation-testing this file against a deliberately broken scanner.
if grep -qE '^[[:space:]]*--lockfile=.*--all-packages' "${SCANNER}"; then
  printf 'ok   the scanner still passes --all-packages\n'
else
  printf 'FAIL --all-packages is gone from the scanner. Without it osv-scanner\n'
  printf '     emits {"results":[]} for a clean scan, a clean scan and a scan\n'
  printf '     that examined nothing become indistinguishable, and every\n'
  printf '     package-count check above silently stops meaning anything.\n'
  failures=$((failures + 1))
fi

echo
if [[ "${failures}" -gt 0 ]]; then
  echo "supply-chain verdict tests: ${failures} of ${checks} checks FAILED"
  exit 1
fi
echo "supply-chain verdict tests: all ${checks} checks passed"
