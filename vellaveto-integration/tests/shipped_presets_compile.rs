// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Every shipped policy preset must compile.
//!
//! `examples/presets/*.toml` are user-facing: `examples/presets/README.md`
//! recommends them by name, and the docs tell people to start from one. Nothing
//! compiled them, so a preset could ship that the server refuses to start with.
//!
//! One did. `devops-agent.toml` used `op = "exact"`, which is not a valid
//! constraint operator (`eq` is), so `PolicyEngine::with_policies` rejected it
//! and the server exited rather than degrade to the legacy evaluation path. The
//! refusal was correct; the preset shipping in that state was not.
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

/// Absolute path to `examples/presets/`, resolved from the crate root so the
/// test does not depend on the working directory the runner happens to use.
fn presets_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has a parent")
        .join("examples/presets")
}

/// Collect every `.toml` preset, sorted so failures are reported in a stable order.
fn preset_files() -> Vec<PathBuf> {
    let dir = presets_dir();
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    files
}

#[test]
fn test_shipped_presets_all_compile() {
    let files = preset_files();
    assert!(
        !files.is_empty(),
        "no presets found in {} — the glob or the directory moved",
        presets_dir().display()
    );

    // Collect every failure rather than stopping at the first, so one run tells
    // you about all the broken presets instead of one per fix-and-rerun cycle.
    let mut failures: Vec<String> = Vec::new();

    for path in &files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<non-utf8>");

        let config = match PolicyConfig::load_file(&path.to_string_lossy()) {
            Ok(c) => c,
            Err(e) => {
                failures.push(format!("{name}: failed to load: {e}"));
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
            failures.push(format!("{name}: failed to compile: {detail}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} shipped preset(s) will not start the server:\n  {}",
        failures.len(),
        files.len(),
        failures.join("\n  ")
    );
}

/// Guards the specific regression in issue #407, so a revert is loud.
#[test]
fn test_devops_agent_preset_uses_a_valid_constraint_operator() {
    let path = presets_dir().join("devops-agent.toml");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    assert!(
        !raw.contains(r#"op = "exact""#),
        "devops-agent.toml uses op = \"exact\", which the policy compiler rejects; \
         the valid equality operator is \"eq\""
    );

    let config =
        PolicyConfig::load_file(&path.to_string_lossy()).expect("devops-agent.toml should load");
    PolicyEngine::with_policies(false, &config.to_policies())
        .expect("devops-agent.toml should compile — see issue #407");
}
