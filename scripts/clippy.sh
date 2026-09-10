#!/usr/bin/env bash
#
# clippy.sh — run cargo clippy with the project's canonical lint flags.
#
# The single source of truth for the lint flags. Pass cargo's arguments; the
# flags after `--` are supplied here:
#
#   bash scripts/clippy.sh --workspace --all-targets --locked
#   bash scripts/clippy.sh -p vellaveto-audit --all-features --all-targets
#
# The flag list used to be pasted inline in ci.yml and rust-clippy.yml. Adding
# the feature matrix would have made a third copy, and a copy that drifts turns
# CI red on code that never changed.
#
# This is a wrapper rather than a script that echoes the flags for a caller to
# expand. `cargo clippy ... -- $(bash scripts/clippy-flags.sh)` needs the output
# to word-split into separate arguments, which is exactly what shellcheck SC2046
# warns about, and actionlint runs shellcheck over every `run:` block in CI.
# Quoting the substitution would pass all seven flags as one argument and break
# clippy; suppressing the warning at three call sites would hide a real class of
# bug. Keeping the flags on this side of the boundary means no caller ever needs
# an unquoted expansion.
#
# Each `-A` below suppresses a lint the codebase has deliberately not adopted;
# do not add one to make a specific finding go away — fix the finding.

set -euo pipefail

exec cargo clippy "$@" -- \
    -D warnings \
    -D unsafe-code \
    -A clippy::uninlined_format_args \
    -A clippy::field_reassign_with_default \
    -A clippy::const_is_empty \
    -A clippy::unnecessary_literal_unwrap \
    -A clippy::assertions_on_constants
