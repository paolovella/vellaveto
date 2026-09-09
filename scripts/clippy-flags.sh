#!/usr/bin/env bash
#
# clippy-flags.sh — the single source of truth for the clippy lint flags.
#
# Emits the flags that follow `--` in every `cargo clippy` invocation in CI.
# Call it as:
#
#   cargo clippy --workspace --all-targets --locked -- $(bash scripts/clippy-flags.sh)
#
# The list used to be pasted inline in ci.yml and rust-clippy.yml. Adding the
# feature matrix would have made a third copy, and a copy that drifts turns CI
# red on code that never changed. Keeping it here means a lint added or
# suppressed once applies everywhere.
#
# Each `-A` below suppresses a lint the codebase has deliberately not adopted;
# do not add one to make a specific finding go away — fix the finding.

set -euo pipefail

printf '%s' \
  '-D warnings' \
  ' -D unsafe-code' \
  ' -A clippy::uninlined_format_args' \
  ' -A clippy::field_reassign_with_default' \
  ' -A clippy::const_is_empty' \
  ' -A clippy::unnecessary_literal_unwrap' \
  ' -A clippy::assertions_on_constants'
printf '\n'
