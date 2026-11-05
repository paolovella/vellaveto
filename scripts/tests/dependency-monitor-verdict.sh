#!/usr/bin/env bash
# Regression tests for the cargo-deny verdict classification in
# scripts/run-dependency-monitor.sh.
#
# Why this file exists
# --------------------
# The monitor distinguishes "the advisory scan ran and found problems" from
# "the advisory scan did not reach a conclusion". It makes that call by
# counting per-tree verdict lines in the captured cargo-deny output.
#
# From 2026-10-13 it got that backwards in production, every day, for weeks:
# cargo-deny had run fine and reported `advisories FAILED` on 17 real
# vulnerabilities, and the monitor announced "ADVISORY SCAN DID NOT RUN ...
# posture UNKNOWN". The cause was that cargo-deny colours its verdict when
# CARGO_TERM_COLOR=always is set in the job environment, as CI sets it, so the
# real bytes were "advisories \033[31mFAILED\033[0m" and the grep matched
# nothing.
#
# It stayed hidden because the predicate is only consulted on the failure path.
# While no advisory existed, every tree exited 0, the script took its "clean"
# branch, and the predicate was never called.
#
# And the verification that should have caught it did not, because it fed the
# predicate hand-written PLAIN-TEXT fixtures. A classifier that parses another
# tool's output has to be tested against that tool's actual bytes, colour and
# all. That is what the colour cases below are for; the plain cases alone would
# still pass with the bug present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MONITOR="${WORKSPACE_ROOT}/scripts/run-dependency-monitor.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

failures=0
checks=0

# Re-implement nothing: pull the two functions under test out of the monitor so
# a drift between this test and the script shows up as a failure here rather
# than as a copy that silently agrees with itself.
extract() {
  local name="$1"
  sed -n "/^${name}() {/,/^}/p" "${MONITOR}"
}

for fn in strip_ansi deny_verdict_count deny_reached_verdict; do
  if ! extract "${fn}" | grep -q .; then
    echo "FAIL: ${fn}() not found in ${MONITOR} (renamed or removed?)"
    exit 1
  fi
done

# shellcheck disable=SC1090
eval "$(extract strip_ansi)"
# shellcheck disable=SC1090
eval "$(extract deny_verdict_count)"
# shellcheck disable=SC1090
eval "$(extract deny_reached_verdict)"

check() {
  local desc="$1" expected="$2" actual="$3"
  checks=$((checks + 1))
  if [[ "${expected}" == "${actual}" ]]; then
    printf '  ok    %s\n' "${desc}"
  else
    printf '  FAIL  %s (expected %s, got %s)\n' "${desc}" "${expected}" "${actual}"
    failures=$((failures + 1))
  fi
}

# Exactly the bytes cargo-deny emits with CARGO_TERM_COLOR=always, captured from
# a real CI run (dependency-monitor, 2026-11-05).
coloured_ok() {
  printf 'advisories \033[32mok\033[0m, bans \033[32mok\033[0m, licenses \033[32mok\033[0m, sources \033[32mok\033[0m\n'
}
coloured_failed() {
  printf 'advisories \033[31mFAILED\033[0m, bans \033[32mok\033[0m, licenses \033[32mok\033[0m, sources \033[32mok\033[0m\n'
}
plain_ok() {
  printf 'advisories ok, bans ok, licenses ok, sources ok\n'
}
plain_failed() {
  printf 'advisories FAILED, bans ok, licenses ok, sources ok\n'
}

echo "strip_ansi:"
esc_count() { grep -c $'\x1b' || true; }
check "removes escapes from a coloured ok verdict" \
  "0" "$(coloured_ok | strip_ansi | esc_count)"
check "removes escapes from a coloured FAILED verdict" \
  "0" "$(coloured_failed | strip_ansi | esc_count)"
check "leaves the verdict text intact" \
  "advisories FAILED, bans ok, licenses ok, sources ok" \
  "$(coloured_failed | strip_ansi)"
check "is a no-op on already-plain text" \
  "advisories ok, bans ok, licenses ok, sources ok" \
  "$(plain_ok | strip_ansi)"

echo
echo "deny_verdict_count (the regression: coloured input must still count):"
run_count() {
  DENY_JSON="${TMP}/deny.txt"
  : > "${DENY_JSON}"
  for emit in "$@"; do "${emit}" | strip_ansi >> "${DENY_JSON}"; done
  deny_verdict_count
}

check "3 coloured verdicts count as 3"  "3" "$(run_count coloured_ok coloured_failed coloured_ok)"
check "3 plain verdicts count as 3"     "3" "$(run_count plain_ok plain_failed plain_ok)"
check "mixed coloured/plain count as 3" "3" "$(run_count coloured_ok plain_failed coloured_ok)"
check "a coloured FAILED alone counts"  "1" "$(run_count coloured_failed)"
check "no verdict lines count as 0"     "0" "$(run_count)"

echo
echo "deny_reached_verdict (3 trees configured):"
# Mirror the script's tree count rather than hardcoding 3, so adding a fourth
# lockfile to DENY_TREES does not silently invalidate these expectations.
mapfile -t DENY_TREES < <(
  sed -n 's/^DENY_TREES=(\(.*\))$/\1/p' "${MONITOR}" | tr ' ' '\n' | grep -v '^$'
)
if [[ "${#DENY_TREES[@]}" -eq 0 ]]; then
  echo "  FAIL  could not parse DENY_TREES from ${MONITOR}"
  exit 1
fi
echo "  (DENY_TREES has ${#DENY_TREES[@]} entries: ${DENY_TREES[*]})"

reached() {
  DENY_JSON="${TMP}/deny.txt"
  : > "${DENY_JSON}"
  for emit in "$@"; do "${emit}" | strip_ansi >> "${DENY_JSON}"; done
  if deny_reached_verdict; then echo yes; else echo no; fi
}

n="${#DENY_TREES[@]}"
all_ok=(); for ((i = 0; i < n; i++)); do all_ok+=(coloured_ok); done
one_short=(); for ((i = 0; i < n - 1; i++)); do one_short+=(coloured_ok); done

check "all ${n} trees reporting (coloured) -> reached" "yes" "$(reached "${all_ok[@]}")"
check "$((n - 1)) of ${n} trees -> NOT reached"        "no"  "$(reached "${one_short[@]}")"
check "zero trees -> NOT reached"                      "no"  "$(reached)"
# The case that actually broke: every tree reported, but with colour. Before the
# fix this returned "no" and the monitor called 17 real findings UNKNOWN.
failed_all=(); for ((i = 0; i < n; i++)); do failed_all+=(coloured_failed); done
check "all ${n} trees FAILED (coloured) -> reached, i.e. a FINDING not UNKNOWN" \
  "yes" "$(reached "${failed_all[@]}")"

echo
if [[ "${failures}" -eq 0 ]]; then
  echo "dependency-monitor verdict tests: ${checks} checks, all passed"
else
  echo "dependency-monitor verdict tests: ${failures} of ${checks} checks FAILED"
  exit 1
fi
