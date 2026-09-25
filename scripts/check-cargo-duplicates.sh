#!/usr/bin/env bash
set -euo pipefail

metadata_file="$(mktemp)"

cleanup() {
  rm -f "$metadata_file"
}
trap cleanup EXIT

cargo metadata --locked --format-version=1 > "$metadata_file"

python3 - "$metadata_file" <<'PY'
import json
import sys
from collections import defaultdict

BASELINE = {
    # New duplicate, introduced by the semver-compatible batch update.
    # 1.3.2 arrives via a single chain and is not built for our targets:
    #   vellaveto-operator -> kube 3.1.0 -> k8s-openapi 0.27.1
    #                      -> jiff 0.2.35 -> defmt 1.1.1 -> bitflags 1.3.2
    # `cargo tree -i bitflags@1.3.2 --target all` finds no reachable path, so
    # this is a lockfile-resolve entry rather than compiled surface. Revisit if
    # kube/jiff ever pull defmt into an actually-built configuration.
    # New. The workspace moved to base64 0.23; axum 0.8.9 and hyper-util 0.1.20
    # still depend on 0.22. Both are compiled. Collapses when axum updates.
    "base64": ["0.22.1", "0.23.1"],
    "bitflags": ["1.3.2", "2.13.1"],
    "block-buffer": ["0.10.4", "0.12.1"],
    "cpufeatures": ["0.2.17", "0.3.0"],
    "crypto-common": ["0.1.7", "0.2.2"],
    "digest": ["0.10.7", "0.11.3"],
    "foldhash": ["0.1.5", "0.2.0"],
    "getrandom": ["0.2.17", "0.3.4", "0.4.3"],
    "hashbrown": ["0.14.5", "0.15.5", "0.16.1", "0.17.1"],
    "itertools": ["0.13.0", "0.14.0"],
    "r-efi": ["5.3.0", "6.0.0"],
    "rand": ["0.10.3", "0.9.5"],
    "rand_core": ["0.10.1", "0.6.4", "0.9.5"],
    "reqwest": ["0.12.28", "0.13.4"],
    # Transient, introduced by ed25519-dalek 3.0. ed25519 3 depends on
    # signature 3, while jsonwebtoken 10.4.0 still pins signature 2. This
    # collapses back to one version once jsonwebtoken 11 lands.
    # New, and all three share one cause: axum 0.8.9 pins its own WebSocket
    # stack. Its `ws` feature pulls tokio-tungstenite 0.29 -> tungstenite 0.29
    # -> sha1 0.10 (the handshake accept-key), while the workspace's own
    # WebSocket transport is on tokio-tungstenite 0.30 and sha1 0.11 arrives
    # through the digest 0.11 line. Compiled surface, not just a lockfile
    # entry, so two tungstenite implementations link into the server. Both are
    # maintained releases and neither is under an advisory. All three collapse
    # together when axum bumps; revisit then rather than pinning axum back.
    "sha1": ["0.10.7", "0.11.0"],
    "signature": ["2.2.0", "3.0.0"],
    # New duplicate, and expected to be transient. The proc-macro ecosystem
    # (serde_derive, thiserror-impl, clap_derive, async-trait, displaydoc,
    # ref-cast-impl, schemars_derive) has moved to syn 3. Only asn1-rs-derive,
    # reached through x509-parser 0.18.1, still pins syn 2 — this collapses back
    # to a single version once x509-parser updates.
    "syn": ["2.0.119", "3.0.3"],
    "tokio-tungstenite": ["0.29.0", "0.30.0"],
    # New. The workspace is on tower-http 0.7; kube-client 4.2.0 and both
    # reqwest lines (0.12.28 via mcpsec, 0.13.4 via opentelemetry-http 0.33)
    # still want 0.6. Collapses as those three move.
    "tower-http": ["0.6.11", "0.7.1"],
    "tungstenite": ["0.29.0", "0.30.0"],
    "untrusted": ["0.7.1", "0.9.0"],
    # The 0.48 line arrived with the RUSTSEC-2026-0258 fix. Bumping h2 made
    # cargo re-resolve windows-sys *downward* in anstyle-query, anstream and
    # errno (0.61.2 -> 0.60.2/0.52.0), which in turn made the winapi-util 0.1.11
    # chain reachable:
    #   vellaveto-server -> notify 8.2.0 -> walkdir -> same-file -> winapi-util
    # That is a normal (non-dev) path, so this is compiled surface on Windows
    # targets, not just a lockfile entry. This project builds and ships on
    # Linux, so nothing we distribute is affected today.
    #
    # Accepted rather than avoided: the alternatives were a full `cargo update`
    # (too broad for a security fix, and it still left one delta) or leaving two
    # advisories open. Revisit when notify/walkdir move off winapi-util, or
    # during the next dependency sweep.
    "windows-sys": ["0.48.0", "0.52.0", "0.59.0", "0.60.2", "0.61.2"],
    "windows-targets": ["0.48.5", "0.52.6", "0.53.5"],
    "windows_aarch64_gnullvm": ["0.48.5", "0.52.6", "0.53.1"],
    "windows_aarch64_msvc": ["0.48.5", "0.52.6", "0.53.1"],
    "windows_i686_gnu": ["0.48.5", "0.52.6", "0.53.1"],
    "windows_i686_gnullvm": ["0.52.6", "0.53.1"],
    "windows_i686_msvc": ["0.48.5", "0.52.6", "0.53.1"],
    "windows_x86_64_gnu": ["0.48.5", "0.52.6", "0.53.1"],
    "windows_x86_64_gnullvm": ["0.48.5", "0.52.6", "0.53.1"],
    "windows_x86_64_msvc": ["0.48.5", "0.52.6", "0.53.1"],
    # wit-bindgen dropped out of the duplicate set in this update; the entry is
    # removed rather than left behind, so a future reintroduction is flagged.
}

with open(sys.argv[1], encoding="utf-8") as f:
    metadata = json.load(f)

versions_by_name = defaultdict(set)
for package in metadata["packages"]:
    source = package.get("source")
    if source is None or not source.startswith("registry+"):
        continue
    versions_by_name[package["name"]].add(package["version"])

duplicates = {
    name: sorted(versions)
    for name, versions in versions_by_name.items()
    if len(versions) > 1
}

errors = []
for name, versions in sorted(duplicates.items()):
    allowed = BASELINE.get(name)
    if allowed is None:
        errors.append(f"new duplicate crate '{name}' has versions: {', '.join(versions)}")
        continue
    new_versions = [version for version in versions if version not in allowed]
    if new_versions:
        errors.append(
            f"duplicate crate '{name}' added version(s): {', '.join(new_versions)} "
            f"(current: {', '.join(versions)})"
        )

if errors:
    for error in errors:
        print(f"::error::{error}")
    print("")
    print("Current duplicate baseline:")
    for name, versions in sorted(duplicates.items()):
        print(f"  {name}: {', '.join(versions)}")
    sys.exit(1)

print(f"Cargo duplicate baseline OK ({len(duplicates)} duplicate crate names)")
PY
