// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! `vellaveto check` must agree with `vellaveto serve` about what is valid.
//!
//! `check` used to validate schema, semantics, security and best practices, but
//! never compiled the policies. A config the server refuses to start with could
//! therefore pass `check` with "0 errors" and exit code 0 — and `check` would
//! even print the offending policy in its summary as though it had compiled.
//!
//! That is the worst direction for this tool to be wrong in: `check` exists to
//! be trusted in CI and before a deploy, so a false pass is worse than no tool
//! at all. `examples/presets/devops-agent.toml` shipped broken for exactly this
//! reason (issue #407): it used `op = "exact"`, which only the compiler rejects.
//!
//! These tests pin the invariant rather than any particular error text: whatever
//! the compiler refuses, `check` must refuse too.
//!
//! Requires: `cargo build -p vellaveto-server` to have completed.

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn vellaveto_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vellaveto"))
}

fn presets_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir has a parent")
        .join("examples/presets")
}

fn write_config(dir: &Path, content: &str) -> PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(&path, content).expect("write config");
    path
}

/// A policy whose only defect is an operator the compiler does not know.
/// Schema-valid TOML, so only compilation can reject it — which is the whole
/// point: this is the shape of config that used to slip through.
fn config_with_unknown_operator(op: &str) -> String {
    format!(
        r#"
[[policies]]
name = "Block production modifications"
tool_pattern = "*"
function_pattern = "*"
priority = 260
id = "*:*:test-block-prod"

[policies.policy_type.Conditional.conditions]
on_no_match = "continue"
parameter_constraints = [
  {{ param = "environment", op = "{op}", value = "production", on_match = "deny", on_missing = "skip" }},
]
"#
    )
}

#[test]
fn test_check_rejects_unknown_constraint_operator() {
    let dir = TempDir::new().expect("tempdir");
    let path = write_config(dir.path(), &config_with_unknown_operator("exact"));

    let output = vellaveto_bin()
        .args(["check", "--config"])
        .arg(&path)
        .output()
        .expect("run check");

    assert!(
        !output.status.success(),
        "check must exit non-zero on a config the server will not start with; \
         got {:?}\nstdout: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("POLICY_COMPILE"),
        "check should report the compile failure as a POLICY_COMPILE finding; got:\n{combined}"
    );
}

#[test]
fn test_check_json_reports_compile_failure_as_invalid() {
    let dir = TempDir::new().expect("tempdir");
    let path = write_config(dir.path(), &config_with_unknown_operator("exact"));

    let output = vellaveto_bin()
        .args(["check", "--format", "json", "--config"])
        .arg(&path)
        .output()
        .expect("run check");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("check --format json should emit valid JSON");

    assert_eq!(
        parsed["summary"]["valid"],
        serde_json::Value::Bool(false),
        "JSON summary must report valid=false so CI consumers see the failure; got:\n{stdout}"
    );

    let findings = parsed["findings"]
        .as_array()
        .expect("findings should be an array");
    assert!(
        findings
            .iter()
            .any(|f| f["code"] == "POLICY_COMPILE" && f["severity"] == "error"),
        "JSON findings must include the compile error; got:\n{stdout}"
    );
}

#[test]
fn test_check_accepts_the_valid_operator() {
    // `eq` is the real equality operator. Same policy, one word different:
    // check must pass, proving the rejection above is about the operator and
    // not about the surrounding policy shape.
    let dir = TempDir::new().expect("tempdir");
    let path = write_config(dir.path(), &config_with_unknown_operator("eq"));

    let output = vellaveto_bin()
        .args(["check", "--config"])
        .arg(&path)
        .output()
        .expect("run check");

    assert!(
        output.status.success(),
        "check must accept a compilable config; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_check_accepts_every_shipped_preset() {
    // Guards against the fix over-rejecting. A validator that fails everything
    // also "agrees" with the compiler on broken configs, so this is the other
    // half of the invariant.
    let dir = presets_dir();
    let mut presets: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    presets.sort();
    assert!(!presets.is_empty(), "no presets found in {}", dir.display());

    let mut rejected: Vec<String> = Vec::new();
    for preset in &presets {
        let output = vellaveto_bin()
            .args(["check", "--config"])
            .arg(preset)
            .output()
            .expect("run check");
        if !output.status.success() {
            rejected.push(format!(
                "{}: {}",
                preset.file_name().unwrap_or_default().to_string_lossy(),
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .find(|l| l.contains("[ERROR]"))
                    .unwrap_or("(no [ERROR] line)")
                    .trim()
            ));
        }
    }

    assert!(
        rejected.is_empty(),
        "check rejected {} of {} shipped preset(s):\n  {}",
        rejected.len(),
        presets.len(),
        rejected.join("\n  ")
    );
}
