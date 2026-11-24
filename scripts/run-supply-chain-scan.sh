#!/usr/bin/env bash
# run-supply-chain-scan.sh — advisory scan for the ecosystems cargo does not cover
#
# Why this file exists
# --------------------
# Dependabot watches 17 ecosystems in this repository, but until this script
# every advisory-failing gate was Rust-only: run-dependency-monitor.sh,
# security-audit.yml and cargo-deny.yml all scan cargo trees, and trivy scans
# container images at publish and release time. Nothing failed on a known CVE in
# npm, Go, Python or Java.
#
# That gap was not hypothetical. golang.org/x/net sat at v0.58.0 in
# terraform-provider-vellaveto carrying seven advisories, with
# golang.org/x/net/http2 genuinely in the compiled graph through grpc, and
# nothing reported it. Dependabot could not: Go marks transitive modules
# `// indirect` and Dependabot's gomod default is direct dependencies only, so no
# PR was ever proposed. Two independent gaps, and the missing gate is what kept
# the first one invisible.
#
# Deliberately NOT scanning Cargo.lock
# ------------------------------------
# Rust already has three gates, and three justified advisory suppressions that
# live in .cargo/audit.toml. Scanning the cargo trees here too would create a
# second place where a Rust suppression has to be recorded and kept true, which
# is precisely the kind of drift this repository keeps having to repair. One
# source of truth per ecosystem.
#
# What this script reports, and why it is shaped this way
# ------------------------------------------------------
# It prints a verdict per manifest, never a bare "the scan ran". That
# distinction is the whole lesson of scripts/tests/dependency-monitor-verdict.sh:
# the monitor spent three weeks announcing "posture UNKNOWN" over 17 real
# vulnerabilities because a classifier was asked whether a scan had run instead
# of what it found. Coverage is not a verdict.
#
# The corresponding trap here is subtler. osv-scanner's JSON `results` array is
# EMPTY when a scan is clean -- the package count appears only on stderr. So
# "scanned 283 packages and found nothing" and "scanned nothing at all" produce
# byte-identical JSON unless `--all-packages` is passed, which lists every
# package examined. It is passed below for exactly that reason, and the package
# count is part of every verdict, so a lockfile that silently stops being parsed
# cannot read as clean.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR_INPUT="${1:-${WORKSPACE_ROOT}/target/security}"
mkdir -p "${OUTPUT_DIR_INPUT}"
OUTPUT_DIR="$(cd "${OUTPUT_DIR_INPUT}" && pwd)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SUMMARY_TXT="${OUTPUT_DIR}/supply-chain-scan-${TIMESTAMP}.txt"
OSV_SCANNER="${OSV_SCANNER_BIN:-osv-scanner}"

# Every manifest scanned, in report order. Adding a project here is the only
# supported way to extend coverage; discover_unlisted_manifests below fails the
# run if a scannable manifest exists on disk and is missing from this list, so a
# seventh npm project cannot quietly go unscanned.
MANIFESTS=(
  admin-console/package-lock.json
  packages/create-vellaveto/package-lock.json
  packages/vellaveto-desktop/package-lock.json
  sdk/typescript/package-lock.json
  site/package-lock.json
  vscode-vellaveto/package-lock.json
  sdk/go/go.mod
  terraform-provider-vellaveto/go.mod
  sdk/python/requirements-dev.txt
  sdk/python/requirements-build.txt
  sdk/java/pom.xml
)

# Manifests that legitimately resolve to zero dependencies. For every other
# manifest a zero package count means the file stopped being parsed, which is an
# UNKNOWN verdict and a failure -- not a clean one.
#
# sdk/go/go.mod declares no third-party requirements at all: the Go SDK is
# written against the standard library. If it ever gains a dependency its
# verdict becomes `clean` on its own, with no change needed here.
ZERO_PACKAGE_EXPECTED=(
  sdk/go/go.mod
)

# Patterns deliberately WIDER than MANIFESTS. The point is to notice a manifest
# shape this script does not yet scan -- a project switching to pnpm, a Python
# package gaining a uv.lock -- rather than only to notice a new copy of a shape
# it already handles.
DISCOVER_PATTERNS=(
  package-lock.json
  yarn.lock
  pnpm-lock.yaml
  go.mod
  pom.xml
  build.gradle
  build.gradle.kts
  uv.lock
  poetry.lock
  Pipfile.lock
  'requirements*.txt'
)

json_number() {
  # Reads an osv-scanner --all-packages JSON document and prints either a count
  # or the literal UNKNOWN. $1 = file, $2 = "packages" | "vulns".
  #
  # UNKNOWN on a missing, empty or unparseable document is the fail-closed
  # answer: it is what distinguishes "nothing was wrong" from "nothing was
  # looked at", and only the second one is a reason to stop trusting the run.
  local file="$1" what="$2"
  if [[ ! -s "${file}" ]]; then
    echo UNKNOWN
    return 0
  fi
  python3 - "${file}" "${what}" <<'PY'
import json, sys
path, what = sys.argv[1], sys.argv[2]
try:
    with open(path) as fh:
        doc = json.load(fh)
    results = doc.get("results")
    if not isinstance(results, list):
        print("UNKNOWN")
        sys.exit(0)
    packages = [p for r in results for p in r.get("packages", [])]
    if what == "packages":
        print(len(packages))
        sys.exit(0)

    # osv-scanner labels each package with the lockfile's own reachability
    # groups. A package carrying "dev" or "test" is not in the production
    # install tree -- npm install --omit=dev will not place it -- so a finding
    # there cannot reach a deployed artifact; it is a build-host concern.
    #
    # Everything else counts as production, deliberately including an absent
    # or empty group list and including "optional" on its own: an
    # optionalDependency IS installed in production when its platform matches.
    # Only an explicit dev or test label is treated as unshipped.
    def is_dev(pkg):
        groups = pkg.get("dependency_groups")
        if not isinstance(groups, list) or not groups:
            return False
        return any(g in ("dev", "test") for g in groups)

    total = 0
    for pkg in packages:
        count = len(pkg.get("vulnerabilities", []) or [])
        if not count:
            continue
        dev = is_dev(pkg)
        if what == "vulns" or (what == "vulns_dev" and dev) or (what == "vulns_prod" and not dev):
            total += count
    print(total)
except Exception:
    print("UNKNOWN")
PY
}

zero_packages_expected() {
  local manifest="$1" expected
  for expected in "${ZERO_PACKAGE_EXPECTED[@]}"; do
    [[ "${manifest}" == "${expected}" ]] && return 0
  done
  return 1
}

actions_report() {
  # Writes a JSON report of the GitHub Actions advisory check to $1.
  #
  # Why this is a query and not an osv-scanner invocation: osv-scanner 2.7.1 has
  # no extractor for workflow files (verified -- it reports 0 Extract calls and
  # "No package sources found" on .github/), so the actions are resolved here and
  # queried against OSV's "GitHub Actions" ecosystem directly.
  #
  # Why the ecosystem needed a gate at all: Dependabot watches it, but no gate
  # scanned it, and pypa/gh-action-pypi-publish sat on 1.14.2 with
  # GHSA-5xjx-3w67-w9x9 -- a CVSS 4.0 CRITICAL revoked root CA in the Sigstore
  # trust store used by PyPI Trusted Publishing -- while every gate read green.
  #
  # The version problem. Actions are pinned by SHA and OSV matches on versions,
  # so a version has to come from somewhere. Three sources, in order:
  #   1. the `# vX.Y.Z` comment on the same line;
  #   2. failing that, the same SHA's comment elsewhere in the repository --
  #      release.yml omits the comment on 23 lines whose SHAs are commented in
  #      other workflows, and they resolve from there;
  #   3. nothing, for an action pinned to a branch rather than a release
  #      (dtolnay/rust-toolchain carries `# master` and `# stable`).
  #
  # For (3) the action is queried WITHOUT a version, which returns every
  # advisory record OSV holds for the package. Zero records means there is
  # provably nothing to miss; one or more means this check cannot rule it out
  # and says so rather than implying coverage it does not have.
  #
  # One SHA carrying two DIFFERENT version comments is a stale comment, which
  # would silently mis-query. That is a conflict, and a conflict is UNKNOWN.
  local out="$1"
  python3 - "${WORKSPACE_ROOT}" "${out}" <<'PY'
import glob, json, os, re, sys, urllib.request

root, out_path = sys.argv[1], sys.argv[2]
files = sorted(glob.glob(os.path.join(root, ".github/workflows/*.yml"))) + \
        sorted(glob.glob(os.path.join(root, ".github/workflows/*.yaml")))

# The name class excludes @ and whitespace only -- a quote character inside a
# character class inside this heredoc is how the first version of this line
# failed to parse at all.
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^@\s]+)@([0-9a-f]{40})(.*)$")
SEMVER = re.compile(r"#\s*v?([0-9][0-9.]*)")

refs, sha_versions = [], {}
for path in files:
    rel = os.path.relpath(path, root)
    try:
        lines = open(path).read().splitlines()
    except Exception:
        refs.append({"unreadable": rel})
        continue
    for num, line in enumerate(lines, 1):
        m = USES.match(line)
        if not m:
            continue
        name = m.group(1).strip("'" + '"')
        sha, rest = m.group(2), m.group(3)
        vm = SEMVER.search(rest)
        version = vm.group(1) if vm else None
        if version:
            sha_versions.setdefault((name, sha), set()).add(version)
        refs.append({"name": name, "sha": sha, "version": version,
                     "source": f"{rel}:{num}"})

# A SHA claiming two versions means at least one comment is stale.
conflicts = [{"name": n, "sha": s, "versions": sorted(v)}
             for (n, s), v in sha_versions.items() if len(v) > 1]

# Resolve the uncommented lines from the same SHA seen elsewhere.
for r in refs:
    if r.get("version") or "name" not in r:
        continue
    seen = sha_versions.get((r["name"], r["sha"]))
    if seen and len(seen) == 1:
        r["version"] = next(iter(seen))
        r["version_from"] = "same sha elsewhere"

versioned = sorted({(r["name"], r["version"]) for r in refs
                    if r.get("name") and r.get("version")})
unversioned = sorted({r["name"] for r in refs
                      if r.get("name") and not r.get("version")})

report = {"workflow_files": len(files), "refs": len(refs),
          "distinct_versioned": len(versioned), "conflicts": conflicts,
          "unversioned": unversioned, "vulnerable": [], "unreviewable": [],
          "query_ok": False}

def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=120))

try:
    if versioned:
        body = {"queries": [{"package": {"ecosystem": "GitHub Actions", "name": n},
                             "version": v} for n, v in versioned]}
        res = post("https://api.osv.dev/v1/querybatch", body)
        for (n, v), r in zip(versioned, res.get("results", [])):
            ids = [x["id"] for x in (r.get("vulns") or [])]
            if ids:
                report["vulnerable"].append({"name": n, "version": v, "ids": ids})
    # Branch-pinned actions: no version to match, so ask whether OSV holds any
    # record for the package at all.
    for n in unversioned:
        r = post("https://api.osv.dev/v1/query",
                 {"package": {"ecosystem": "GitHub Actions", "name": n}})
        ids = [x["id"] for x in (r.get("vulns") or [])]
        if ids:
            report["unreviewable"].append({"name": n, "ids": ids})
    report["query_ok"] = True
except Exception as exc:
    report["error"] = f"{type(exc).__name__}: {exc}"

with open(out_path, "w") as fh:
    json.dump(report, fh, indent=1)
PY
}

actions_verdict() {
  # $1 = the JSON report actions_report wrote.
  # Prints exactly one of:
  #   clean | N advisories | N unreviewable | UNKNOWN
  #
  # UNKNOWN covers every case where the check did not reach a conclusion: an
  # unreadable report, a failed OSV query, no actions found at all (which would
  # mean the extraction regex stopped matching), or a stale version comment.
  # None of those is a pass.
  local file="$1" n
  if [[ ! -s "${file}" ]]; then
    echo UNKNOWN
    return 0
  fi
  n="$(python3 - "${file}" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        d = json.load(fh)
    if not d.get("query_ok") or d.get("conflicts") or not d.get("refs"):
        print("UNKNOWN")
    elif d.get("vulnerable"):
        print(f"{sum(len(v['ids']) for v in d['vulnerable'])} advisories")
    elif d.get("unreviewable"):
        print(f"{len(d['unreviewable'])} unreviewable")
    else:
        print("clean")
except Exception:
    print("UNKNOWN")
PY
)"
  echo "${n}"
}

manifest_verdict() {
  # $1 = manifest path, $2 = osv-scanner JSON output file, $3 = its exit status.
  # Prints exactly one of: clean | N advisories | no packages | UNKNOWN
  #
  # osv-scanner exits 0 with no findings, 1 with findings, and other codes for
  # its own failures (127 for an unresolvable path, for instance). Any status
  # outside {0,1} means the tool did not reach a conclusion, so neither does
  # this script.
  local manifest="$1" file="$2" status="$3" packages prod dev
  if [[ "${status}" != "0" && "${status}" != "1" ]]; then
    echo UNKNOWN
    return 0
  fi
  packages="$(json_number "${file}" packages)"
  prod="$(json_number "${file}" vulns_prod)"
  dev="$(json_number "${file}" vulns_dev)"
  if [[ "${packages}" == "UNKNOWN" || "${prod}" == "UNKNOWN" || "${dev}" == "UNKNOWN" ]]; then
    echo UNKNOWN
    return 0
  fi
  # A production finding blocks. A dev-only one is reported and counted but does
  # not fail the gate: it cannot reach a deployed artifact, and blocking on the
  # churn of jest and eslint transitives would stop unrelated work for a
  # build-host risk.
  #
  # This replaces what would otherwise be a list of suppressed advisory IDs with
  # expiry dates. The classification is recomputed from the lockfile on every
  # run, so it cannot rot: if one of these packages ever becomes reachable from
  # production, the same advisory starts blocking on its own, which an ID-based
  # ignore would instead have hidden.
  if [[ "${prod}" -gt 0 ]]; then
    echo "${prod} advisories"
    return 0
  fi
  if [[ "${dev}" -gt 0 ]]; then
    echo "${dev} advisories (dev-only)"
    return 0
  fi
  if [[ "${packages}" -eq 0 ]]; then
    if zero_packages_expected "${manifest}"; then
      echo "no packages"
    else
      echo UNKNOWN
    fi
    return 0
  fi
  echo clean
}

verdict_is_failure() {
  # A verdict fails the run unless it is positively good news. `no packages` is
  # the one tolerated non-clean verdict, and only for an allow-listed manifest,
  # which manifest_verdict has already checked.
  case "$1" in
    clean | "no packages") return 1 ;;
    *"(dev-only)") return 1 ;;
    # `N unreviewable` blocks: it means an action is pinned to a branch AND OSV
    # holds advisory records for it, so this check cannot establish whether the
    # pinned commit is affected. Not knowing is not the same as being clean.
    *) return 0 ;;
  esac
}

discover_unlisted_manifests() {
  # Prints any scannable manifest present on disk but absent from MANIFESTS.
  # Vendored and generated trees are excluded; Rust lives in the cargo gates.
  local pattern found listed manifest
  for pattern in "${DISCOVER_PATTERNS[@]}"; do
    while IFS= read -r found; do
      found="${found#./}"
      listed=0
      for manifest in "${MANIFESTS[@]}"; do
        [[ "${found}" == "${manifest}" ]] && listed=1 && break
      done
      [[ "${listed}" -eq 0 ]] && echo "${found}"
    done < <(
      cd "${WORKSPACE_ROOT}" && find . \
        \( -name node_modules -o -name .git -o -name target -o -name dist \
           -o -name build -o -name vendor -o -name .venv \) -prune -o \
        -type f -name "${pattern}" -print 2>/dev/null
    )
  done
}

if ! "${OSV_SCANNER}" --version >/dev/null 2>&1; then
  echo "Missing osv-scanner. Install it with: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1" >&2
  echo "Or point OSV_SCANNER_BIN at an existing binary." >&2
  exit 2
fi

: > "${SUMMARY_TXT}"
echo "osv-scanner: $("${OSV_SCANNER}" --version 2>&1 | head -1)" | tee -a "${SUMMARY_TXT}"
echo "manifests: ${#MANIFESTS[@]}" | tee -a "${SUMMARY_TXT}"
echo | tee -a "${SUMMARY_TXT}"

# Coverage guard runs first: a finding is less alarming than a project nobody is
# looking at, and the second is what this guard is for.
unlisted="$(discover_unlisted_manifests || true)"
if [[ -n "${unlisted}" ]]; then
  {
    echo "COVERAGE GAP: scannable manifests exist on disk that this script does not scan."
    echo "Add each to MANIFESTS in ${BASH_SOURCE[0]}, or exclude it deliberately:"
    echo "  ${unlisted//$'\n'/$'\n'  }"
  } | tee -a "${SUMMARY_TXT}" >&2
  exit 1
fi

failures=0
unknowns=0
dev_only=0
declare -a VERDICTS=()

for manifest in "${MANIFESTS[@]}"; do
  if [[ ! -f "${WORKSPACE_ROOT}/${manifest}" ]]; then
    # A listed manifest that has vanished is a coverage failure, not a clean
    # result. Renaming or deleting a project means editing MANIFESTS.
    verdict=UNKNOWN
    packages=UNKNOWN
    out=""
    echo "${manifest}: MISSING -- listed in MANIFESTS but not present on disk" | tee -a "${SUMMARY_TXT}" >&2
  else
    out="${OUTPUT_DIR}/osv-$(echo "${manifest}" | tr '/.' '__')-${TIMESTAMP}.json"
    status=0
    # No pipe around the scanner: `set -o pipefail` would help, but reading a
    # command's status through a pipe is the exact mistake that made the cargo
    # monitor misreport for three weeks. Redirect, then read $?.
    if ! (cd "${WORKSPACE_ROOT}" && "${OSV_SCANNER}" scan source \
            --lockfile="${manifest}" --all-packages --format=json \
            >"${out}" 2>"${out}.err"); then
      status=$?
    fi
    verdict="$(manifest_verdict "${manifest}" "${out}" "${status}")"
    packages="$(json_number "${out}" packages)"
  fi
  VERDICTS+=("${manifest}|${verdict}|${packages}")
  printf '%-48s %-16s (%s packages scanned)\n' "${manifest}" "${verdict}" "${packages}" \
    | tee -a "${SUMMARY_TXT}"
  if [[ "${verdict}" == UNKNOWN ]]; then
    unknowns=$((unknowns + 1))
    failures=$((failures + 1))
    if [[ -s "${out:-}.err" ]]; then
      sed 's/^/    osv-scanner: /' "${out}.err" | head -5 | tee -a "${SUMMARY_TXT}" >&2
    fi
  else
    if verdict_is_failure "${verdict}"; then
      failures=$((failures + 1))
    elif [[ "${verdict}" == *"(dev-only)" ]]; then
      dev_only=$((dev_only + 1))
    fi
    # Listed for every verdict that found something, blocking or not. A dev-only
    # finding still deserves a reader's attention -- a compromised build host is
    # a supply-chain problem -- it is just not grounds for stopping a release.
    if [[ "${verdict}" != clean && "${verdict}" != "no packages" ]]; then
      python3 - "${out:-}" <<'PY' | tee -a "${SUMMARY_TXT}"
import json, sys
try:
    with open(sys.argv[1]) as fh:
        doc = json.load(fh)
except Exception:
    sys.exit(0)
for result in doc.get("results", []):
    for pkg in result.get("packages", []):
        vulns = pkg.get("vulnerabilities") or []
        if not vulns:
            continue
        info = pkg.get("package", {})
        groups = pkg.get("dependency_groups")
        scope = "dev " if isinstance(groups, list) and any(
            g in ("dev", "test") for g in groups) else "prod"
        ids = ", ".join(v.get("id", "?") for v in vulns)
        print(f"    [{scope}] {info.get('name')}@{info.get('version')}  {ids}")
PY
    fi
  fi
done

# --- GitHub Actions ----------------------------------------------------------
# A separate surface from the lockfiles above, and the one that was missing
# entirely: Dependabot watches the github-actions ecosystem but nothing failed
# on an advisory in it.
echo | tee -a "${SUMMARY_TXT}"
ACTIONS_JSON="${OUTPUT_DIR}/github-actions-${TIMESTAMP}.json"
actions_report "${ACTIONS_JSON}"
actions_v="$(actions_verdict "${ACTIONS_JSON}")"
actions_counts="$(python3 - "${ACTIONS_JSON}" <<'AWC'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        d = json.load(fh)
    print(f"{d.get('refs','?')} refs in {d.get('workflow_files','?')} workflows, "
          f"{d.get('distinct_versioned','?')} distinct versions queried, "
          f"{len(d.get('unversioned') or [])} branch-pinned")
except Exception:
    print("counts unavailable")
AWC
)"
printf '%-48s %-16s (%s)\n' ".github/workflows (actions)" "${actions_v}" "${actions_counts}" \
  | tee -a "${SUMMARY_TXT}"
python3 - "${ACTIONS_JSON}" <<'ADET' | tee -a "${SUMMARY_TXT}"
import json, sys
try:
    with open(sys.argv[1]) as fh:
        d = json.load(fh)
except Exception:
    sys.exit(0)
for c in d.get("conflicts") or []:
    print(f"    [stale comment] {c['name']}@{c['sha'][:12]} is labelled "
          f"{', '.join(c['versions'])} in different workflows -- at least one is wrong")
for v in d.get("vulnerable") or []:
    print(f"    [prod] {v['name']}@{v['version']}  {', '.join(v['ids'])}")
for u in d.get("unreviewable") or []:
    print(f"    [unreviewable] {u['name']} is branch-pinned and OSV holds "
          f"{len(u['ids'])} record(s): {', '.join(u['ids'][:4])}")
if d.get("error"):
    print(f"    OSV query failed: {d['error']}")
for n in d.get("unversioned") or []:
    print(f"    [branch-pinned] {n}: no version to match; OSV holds no records for it")
ADET
if [[ "${actions_v}" == UNKNOWN ]]; then
  unknowns=$((unknowns + 1))
  failures=$((failures + 1))
elif verdict_is_failure "${actions_v}"; then
  failures=$((failures + 1))
fi
VERDICTS+=(".github/workflows (actions)|${actions_v}|${actions_counts}")

echo | tee -a "${SUMMARY_TXT}"
echo "Verdict per surface (not merely whether each scan ran):" | tee -a "${SUMMARY_TXT}"
for entry in "${VERDICTS[@]}"; do
  printf '  %-48s %s\n' "${entry%%|*}" "$(echo "${entry}" | cut -d'|' -f2)" \
    | tee -a "${SUMMARY_TXT}"
done

echo | tee -a "${SUMMARY_TXT}"
if [[ "${unknowns}" -gt 0 ]]; then
  echo "${unknowns} of ${#MANIFESTS[@]} manifests reached NO conclusion. Their advisory posture is UNKNOWN -- which is not a pass and not a finding either. Read ${SUMMARY_TXT} and the matching .err file for the reason." \
    | tee -a "${SUMMARY_TXT}" >&2
fi
if [[ "${dev_only}" -gt 0 ]]; then
  echo "${dev_only} manifest(s) carry dev-only advisories: reported above, not blocking. They sit in build and test tooling, absent from the production install tree, so they cannot reach a deployed artifact." \
    | tee -a "${SUMMARY_TXT}"
fi
if [[ "${failures}" -gt 0 ]]; then
  echo "supply-chain scan: FAILED (${failures} failing of ${#MANIFESTS[@]} manifests + 1 actions surface)" | tee -a "${SUMMARY_TXT}" >&2
  echo "Summary written to ${SUMMARY_TXT}." | tee -a "${SUMMARY_TXT}"
  exit 1
fi
echo "supply-chain scan: no production advisories (${#MANIFESTS[@]} manifests + GitHub Actions, all reached a verdict)" | tee -a "${SUMMARY_TXT}"
echo "Summary written to ${SUMMARY_TXT}." | tee -a "${SUMMARY_TXT}"
