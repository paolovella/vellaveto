// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Every shipped policy preset must compile — in BOTH directories.
//!
//! There are two copies of each preset and they are separate files with no sync
//! check between them:
//!
//! - `vellaveto-proxy/presets/*.toml` is what actually ships. It is embedded at
//!   compile time by `include_str!("../presets/...")` in
//!   `vellaveto-proxy/src/presets.rs`, and it is what `--preset`, `--protect`
//!   and `init --preset` load.
//! - `examples/presets/*.toml` is documentation. `examples/presets/README.md`
//!   recommends these by name and the docs tell people to start from one, but
//!   nothing loads them at runtime.
//!
//! This test originally covered `examples/` alone, on the stated grounds that
//! those are "user-facing". That was backwards, and it cost us: `devops-agent`
//! shipped for some time with `op = "exact"`, which is not a valid constraint
//! operator (`eq` is). `PolicyEngine::with_policies` rejects it, so
//! `vellaveto-proxy --preset devops-agent` exited at startup instead of running.
//! Issue #407 fixed the `examples/` copy; the embedded copy kept the bug, and
//! the regression test below — written for that exact bug — was watching the
//! wrong directory. Meanwhile the one test that does read the embedded copies
//! (`presets::tests::test_all_presets_parse_successfully`) only calls
//! `PolicyConfig::from_toml`, and `"exact"` is a perfectly valid TOML string, so
//! it parsed clean and passed.
//!
//! So: the copy users load had parse-only coverage, and the copy nobody loads
//! had the compile gate. Both are covered here now.
//!
//! The two directories legitimately differ in content — six of the `examples/`
//! copies lack the Phase 6 channel-separation block, and `consumer-shield`
//! differs only in comment prose — so this does not assert they are identical.
//! It asserts the property that actually matters: whatever is in either
//! directory must start the server.
//!
//! `vellaveto check` did not catch it either — it reported `0 errors` and exit
//! code 0 for the same file. That validator gap is tracked separately; this test
//! guards the narrower and more important property: what we ship must run.
//!
//! This mirrors the server's own startup gate (`cmd_serve` in
//! `vellaveto-server/src/main.rs`) rather than reimplementing validation, so a
//! preset that passes here is one the server will actually accept.

use std::path::{Path, PathBuf};

use vellaveto_config::PolicyConfig;
use vellaveto_engine::PolicyEngine;

/// Repository root, resolved from the crate root so the test does not depend on
/// the working directory the runner happens to use.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has a parent")
        .to_path_buf()
}

/// Both preset directories, labelled. The embedded one is listed first because
/// it is the one a failure here would actually break for a user.
fn preset_dirs() -> Vec<(&'static str, PathBuf)> {
    vec![
        (
            "embedded (shipped)",
            repo_root().join("vellaveto-proxy/presets"),
        ),
        ("examples (docs)", repo_root().join("examples/presets")),
    ]
}

/// Collect every `.toml` preset in `dir`, sorted so failures are reported in a
/// stable order.
fn preset_files_in(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    files
}

#[test]
fn test_shipped_presets_all_compile() {
    // Collect every failure across both directories rather than stopping at the
    // first, so one run tells you about all the broken presets instead of one
    // per fix-and-rerun cycle.
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (label, dir) in preset_dirs() {
        let files = preset_files_in(&dir);
        assert!(
            !files.is_empty(),
            "no presets found in {} — the glob or the directory moved",
            dir.display()
        );

        for path in &files {
            checked += 1;
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<non-utf8>");

            let config = match PolicyConfig::load_file(&path.to_string_lossy()) {
                Ok(c) => c,
                Err(e) => {
                    failures.push(format!("[{label}] {name}: failed to load: {e}"));
                    continue;
                }
            };

            // The same call the server makes at startup. `false` matches cmd_serve.
            if let Err(errors) = PolicyEngine::with_policies(false, &config.to_policies()) {
                let detail = errors
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                failures.push(format!("[{label}] {name}: failed to compile: {detail}"));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} shipped preset(s) will not start the server:\n  {}",
        failures.len(),
        checked,
        failures.join("\n  ")
    );
}

/// Guards the specific regression in issue #407, so a revert is loud.
///
/// Checks BOTH copies. The original version of this test read `examples/` only,
/// which is how the embedded copy kept `op = "exact"` long after #407 was
/// "fixed" — the test passed the whole time.
#[test]
fn test_devops_agent_preset_uses_a_valid_constraint_operator() {
    for (label, dir) in preset_dirs() {
        let path = dir.join("devops-agent.toml");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        assert!(
            !raw.contains(r#"op = "exact""#),
            "[{label}] devops-agent.toml uses op = \"exact\", which the policy \
             compiler rejects; the valid equality operator is \"eq\""
        );

        let config = PolicyConfig::load_file(&path.to_string_lossy())
            .unwrap_or_else(|e| panic!("[{label}] devops-agent.toml should load: {e}"));
        PolicyEngine::with_policies(false, &config.to_policies())
            .unwrap_or_else(|e| panic!("[{label}] devops-agent.toml should compile (#407): {e:?}"));
    }
}

/// Every preset the proxy embeds must exist on disk in the embedded directory.
///
/// Cheap guard against the inverse mistake: `presets.rs` gaining an
/// `include_str!` for a file that only exists under `examples/`, which would
/// compile (include_str resolves relative to the source file) but ship the wrong
/// content, or fail confusingly.
#[test]
fn embedded_preset_directory_holds_every_preset_examples_does() {
    let embedded: std::collections::BTreeSet<String> =
        preset_files_in(&repo_root().join("vellaveto-proxy/presets"))
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
            .collect();
    let examples: std::collections::BTreeSet<String> =
        preset_files_in(&repo_root().join("examples/presets"))
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
            .collect();

    let missing: Vec<&String> = examples.difference(&embedded).collect();
    assert!(
        missing.is_empty(),
        "preset(s) documented under examples/presets but not shipped in \
         vellaveto-proxy/presets: {missing:?}"
    );
}

/// The hardening presets must enable the four governance denial gates.
///
/// Those gates default to `false` globally — they shipped without a gate at all,
/// so defaulting them on would change what every existing deployment does. A
/// preset named for hardening is where they belong, and until now no test
/// asserted anything about `config.governance` for any preset, so the intent was
/// carried only by the TOML.
///
/// Checked in BOTH directories, so the two copies cannot drift: a gate removed
/// from the shipped copy alone would otherwise pass unnoticed, which is exactly
/// how `op = "exact"` survived in `devops-agent`.
#[test]
fn hardening_presets_enable_the_governance_denial_gates() {
    let mut failures: Vec<String> = Vec::new();

    for (label, dir) in preset_dirs() {
        for preset in ["fortress.toml", "sandworm-hardened.toml"] {
            let path = dir.join(preset);
            let config = PolicyConfig::load_file(&path.to_string_lossy())
                .unwrap_or_else(|e| panic!("[{label}] {preset} should load: {e}"));
            let g = &config.governance;

            for (name, on) in [
                ("block_on_jailbreak", g.block_on_jailbreak),
                ("block_on_token_leakage", g.block_on_token_leakage),
                ("block_on_memory_poisoning", g.block_on_memory_poisoning),
                ("block_on_denial_of_wallet", g.block_on_denial_of_wallet),
            ] {
                if !on {
                    failures.push(format!("[{label}] {preset}: {name} is not enabled"));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "a hardening preset that does not enable available hardening is the gap this \
         closes:\n  {}",
        failures.join("\n  ")
    );
}

/// The non-hardening presets must NOT enable them.
///
/// The gates are heuristic — jailbreak phrasing and call-rate patterns can
/// false-positive — so turning them on is a deliberate choice for presets whose
/// name promises it, not a default that creeps across the whole catalogue.
#[test]
fn ordinary_presets_leave_the_governance_denial_gates_off() {
    let hardening = ["fortress.toml", "sandworm-hardened.toml"];
    let mut unexpected: Vec<String> = Vec::new();

    for (label, dir) in preset_dirs() {
        for path in preset_files_in(&dir) {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<non-utf8>")
                .to_string();
            if hardening.contains(&name.as_str()) {
                continue;
            }
            let config = PolicyConfig::load_file(&path.to_string_lossy())
                .unwrap_or_else(|e| panic!("[{label}] {name} should load: {e}"));
            let g = &config.governance;
            if g.block_on_jailbreak
                || g.block_on_token_leakage
                || g.block_on_memory_poisoning
                || g.block_on_denial_of_wallet
            {
                unexpected.push(format!("[{label}] {name}"));
            }
        }
    }

    assert!(
        unexpected.is_empty(),
        "these presets are not named for hardening but enable heuristic denial gates:\n  {}",
        unexpected.join("\n  ")
    );
}
