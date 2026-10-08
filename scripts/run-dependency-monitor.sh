#!/usr/bin/env bash
# run-dependency-monitor.sh — composite dependency/telemetry scan for Batch 3
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR_INPUT="${1:-${WORKSPACE_ROOT}/target/security}"
mkdir -p "${OUTPUT_DIR_INPUT}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR_INPUT}" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
AUDIT_JSON="${OUTPUT_DIR}/cargo-audit-${TIMESTAMP}.json"
DENY_JSON="${OUTPUT_DIR}/cargo-deny-${TIMESTAMP}.txt"
VET_TXT="${OUTPUT_DIR}/cargo-vet-${TIMESTAMP}.txt"
DUPLICATES_TXT="${OUTPUT_DIR}/cargo-duplicates-${TIMESTAMP}.txt"
METADATA_JSON="${OUTPUT_DIR}/cargo-metadata-${TIMESTAMP}.json"
CARGO_HOME_DIR="${OUTPUT_DIR}/cargo-home"
VET_CACHE_DIR="${OUTPUT_DIR}/cargo-vet-cache"
AUDIT_FETCH_ARGS=()
DENY_FETCH_ARGS=()

require_cargo_subcommand() {
  local subcommand="$1"
  if ! cargo "${subcommand}" --version >/dev/null 2>&1; then
    echo "Missing cargo subcommand: cargo ${subcommand}. Install it with: cargo install cargo-${subcommand} --locked" >&2
    exit 2
  fi
}

require_cargo_subcommand audit
require_cargo_subcommand deny
require_cargo_subcommand vet

mkdir -p "${CARGO_HOME_DIR}"
mkdir -p "${VET_CACHE_DIR}"

# Seed the private CARGO_HOME from the caller's, but only where we have nothing
# already. The previous form was `cp -a "${HOME}/.cargo/advisory-db"
# "${CARGO_HOME_DIR}/"`, and `cp -a src dst/` copies *into* an existing
# destination directory -- so a repeat run nested `advisory-db/advisory-db`,
# silently, because `2>/dev/null || true` swallowed the evidence.
if [[ -d "${HOME}/.cargo" ]]; then
  for cached in registry advisory-db advisory-dbs; do
    if [[ -d "${HOME}/.cargo/${cached}" && ! -e "${CARGO_HOME_DIR}/${cached}" ]]; then
      cp -a "${HOME}/.cargo/${cached}" "${CARGO_HOME_DIR}/${cached}" 2>/dev/null || true
    fi
  done
fi

# CARGO_HOME_DIR lives under `target/`, which CI caches and prunes
# (Swatinem/rust-cache lists it in Cache Paths). An advisory database can
# therefore come back non-empty while no longer being a valid git clone, and
# neither tool recovers on its own: cargo-audit refuses to clone over it
# ("Refusing to initialize the non-empty directory") and cargo-deny fails to
# read FETCH_HEAD. Nothing healed that, so the daily job stayed red until the
# cache happened to rotate -- the alternating pass/fail in its run history.
#
# The two tools use different paths, and an earlier version of this fix that
# handled only the first would have left half the breakage in place:
#   cargo-audit -> $CARGO_HOME/advisory-db              (one clone)
#   cargo-deny  -> $CARGO_HOME/advisory-dbs/<hashed>    (one clone per source)
# Both are reconstructible by a fetch and hold nothing of the user's, so drop
# whichever is not a clone and let the tool re-fetch it.
heal_advisory_clone() {
  local dir="$1"
  if [[ -d "${dir}" && ! -d "${dir}/.git" ]]; then
    echo "Advisory DB at ${dir} is not a git clone; removing so it can be re-fetched."
    rm -rf "${dir}"
  fi
}

heal_advisory_clone "${CARGO_HOME_DIR}/advisory-db"
if [[ -d "${CARGO_HOME_DIR}/advisory-dbs" ]]; then
  for advisory_clone in "${CARGO_HOME_DIR}/advisory-dbs"/*; do
    if [[ -d "${advisory_clone}" ]]; then
      heal_advisory_clone "${advisory_clone}"
    fi
  done
fi

if [[ "${DEPENDENCY_MONITOR_NO_FETCH:-}" == "1" ]]; then
  AUDIT_FETCH_ARGS=(--no-fetch --stale)
  DENY_FETCH_ARGS=(--disable-fetch)
  echo "Dependency monitor running without advisory DB fetches; using cached advisory data only."
fi

echo "Running dependency monitoring scan..."
echo "  Audit output:      ${AUDIT_JSON}"
echo "  Deny output:       ${DENY_JSON}"
echo "  Vet output:        ${VET_TXT}"
echo "  Duplicates output: ${DUPLICATES_TXT}"
echo "  Metadata:          ${METADATA_JSON}"

# cargo-audit exits 1 both when it finds advisories and when it cannot fetch its
# database, so the exit code alone cannot tell "found something" from "never
# ran". Reporting the second as the first is worse than cosmetic: it trains a
# reader to discount the one message a real advisory arrives in, and it calls a
# run whose posture is *unknown* a run that is known-bad.
#
# With --json a completed scan leaves parseable JSON carrying a `vulnerabilities`
# key; a database failure leaves an empty or truncated file. Classify on that.
audit_report_is_complete() {
  python3 -c '
import json, sys
try:
    report = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(report, dict) and "vulnerabilities" in report else 1)
' "$1" 2>/dev/null
}

echo "1/5: cargo audit"
audit_status=0
audit_scan_ran=1
if CARGO_HOME="${CARGO_HOME_DIR}" cargo audit "${AUDIT_FETCH_ARGS[@]}" --json >"${AUDIT_JSON}"; then
  echo "cargo audit: no advisories"
else
  audit_status=$?
  if audit_report_is_complete "${AUDIT_JSON}"; then
    echo "cargo audit detected advisories (exit ${audit_status}). Review ${AUDIT_JSON}."
  else
    audit_scan_ran=0
    echo "cargo audit: SCAN DID NOT RUN (exit ${audit_status}). The advisory database was unavailable, so no advisory was assessed -- this is not a clean result, and not a finding either. See the error above."
  fi
fi

echo "2/5: cargo deny --locked check -A duplicate advisories bans sources licenses"
deny_status=0
deny_scan_ran=1
# Capture stderr as well. cargo-deny prints its verdict line to stdout on a
# normal run, but when the advisory database cannot be read it writes the error
# to stderr and stdout stays empty -- so the old `| tee` saved nothing at all in
# exactly the case where the artifact is wanted.
#
# Classify on the presence of an advisories verdict rather than on matching
# error text: the message differs by failure mode (CI saw "failed to load any
# advisories in the database", a local reproduction saw a FETCH_HEAD parse
# error), whereas a run that reached a conclusion always prints
# "advisories ok" or "advisories FAILED".
if CARGO_HOME="${CARGO_HOME_DIR}" cargo deny --locked check "${DENY_FETCH_ARGS[@]}" -A duplicate advisories bans sources licenses 2>&1 | tee "${DENY_JSON}"; then
  echo "cargo deny: clean"
else
  deny_status=$?
  if grep -qE 'advisories (ok|FAILED)' "${DENY_JSON}"; then
    echo "cargo deny reported issues (exit ${deny_status}). See ${DENY_JSON}."
  else
    deny_scan_ran=0
    echo "cargo deny: ADVISORY SCAN DID NOT RUN (exit ${deny_status}). The advisory database could not be loaded, so no advisory was assessed. See ${DENY_JSON}."
  fi
fi

echo "3/5: cargo vet --locked"
vet_status=0
if cargo vet --locked --cache-dir "${VET_CACHE_DIR}" --output-file "${VET_TXT}"; then
  cat "${VET_TXT}"
  echo "cargo vet: baseline satisfied"
else
  vet_status=$?
  cat "${VET_TXT}" 2>/dev/null || true
  echo "cargo vet reported issues (exit ${vet_status}). See ${VET_TXT}."
fi

echo "4/5: duplicate dependency baseline"
duplicates_status=0
if bash "${WORKSPACE_ROOT}/scripts/check-cargo-duplicates.sh" | tee "${DUPLICATES_TXT}"; then
  echo "duplicate dependency baseline: clean"
else
  duplicates_status=$?
  echo "duplicate dependency baseline reported issues (exit ${duplicates_status}). See ${DUPLICATES_TXT}."
fi

metadata_status=0
echo "5/5: cargo metadata --locked"
if cargo metadata --locked --format-version 1 >"${METADATA_JSON}"; then
  echo "cargo metadata: complete"
else
  metadata_status=$?
  echo "cargo metadata failed (exit ${metadata_status}). Inspect ${CARGO_HOME_DIR} for cached registry data."
fi

echo "Optional CISA Known Exploited Vulnerabilities matching"
CISA_FILE="${CISA_KEV_JSON:-}"
OSINT_DIR="${OSINT_SECURITY_DIR:-}"

if [[ -n "${CISA_FILE}" && -f "${CISA_FILE}" ]]; then
  python3 <<PY
import json, os
metadata_path = '${METADATA_JSON}'
cisa_path = '${CISA_FILE}'
output_dir = '${OUTPUT_DIR}'
with open(metadata_path) as f:
    metadata = json.load(f)
packages = {pkg['name'].lower() for pkg in metadata.get('packages', [])}
with open(cisa_path) as f:
    data = json.load(f)
kev_entries = data.get('vulnerabilities') or data.get('known_exploited_vulnerabilities', [])
matches = []
for entry in kev_entries:
    cve = entry.get('cveID') or entry.get('cveId') or entry.get('cve')
    vendor = entry.get('vendorProject', '')
    product = entry.get('product', '')
    candidates = []
    for value in (vendor, product):
        if isinstance(value, (list, tuple)):
            candidates.extend(value)
        elif value:
            candidates.append(value)
    for candidate in candidates:
        normalized = candidate.lower()
        for dep in packages:
            if dep and dep in normalized and not any(m['dep'] == dep and m['cve'] == cve for m in matches):
                matches.append({'dep': dep, 'cve': cve, 'vendor': vendor, 'product': product, 'entry': candidate})
if matches:
    out_path = os.path.join(output_dir, 'cisa-kev-matches.json')
    with open(out_path, 'w') as out_file:
        json.dump(matches, out_file, indent=2)
    print('CISA KEV matches found:')
    for match in matches:
        print('  -', match['dep'], match['cve'], match['product'])
    print('  Details saved to', out_path)
else:
    print('No CISA KEV matches detected with current CISA file')
PY
else
  echo "  Skipped (set CISA_KEV_JSON to a local Known Exploited Vulnerabilities JSON file)"
fi

if [[ -n "${OSINT_DIR}" && -d "${OSINT_DIR}" ]]; then
  echo "OSINT directory provided: ${OSINT_DIR}"
  echo "  You can drop supply-chain intel notes here (e.g., vendor warnings, malicious packages) and this script will remind you to review them."
  echo "  Latest files:"
  find "${OSINT_DIR}" -mindepth 1 -maxdepth 1 -printf '  %f\n' | sort | head -n 5 || true
else
  echo "Set OSINT_SECURITY_DIR to an OSINT note directory to link in supply-chain reporting."
fi

echo "Dependency monitoring summary written under ${OUTPUT_DIR}."

# State plainly which advisory scans actually assessed anything. Without this,
# a reader of the log or the uploaded artifact cannot tell a run that found
# nothing from a run that looked at nothing.
echo "Advisory scan coverage this run:"
if [[ ${audit_scan_ran} -eq 1 ]]; then
  echo "  cargo audit: completed"
else
  echo "  cargo audit: DID NOT RUN - advisory posture for this run is UNKNOWN"
fi
if [[ ${deny_scan_ran} -eq 1 ]]; then
  echo "  cargo deny:  completed"
else
  echo "  cargo deny:  advisory check DID NOT RUN - advisory posture for this run is UNKNOWN"
fi

# A scan that could not run is not a pass, so the job still fails either way.
# Only the wording and the coverage report above distinguish the two cases.
final_status=0
if [[ ${audit_status} -ne 0 || ${deny_status} -ne 0 || ${vet_status} -ne 0 || ${duplicates_status} -ne 0 || ${metadata_status} -ne 0 ]]; then
  final_status=1
fi
exit ${final_status}
