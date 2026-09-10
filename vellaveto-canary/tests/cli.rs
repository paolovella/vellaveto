// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0

//! CLI behaviour tests.
//!
//! The library's create/verify/expiry/tamper paths are covered by unit tests.
//! What is new here is the command surface: the signing key coming from the
//! environment rather than argv, the self-verification before a canary is
//! emitted, and the `--min-days-remaining` threshold that the scheduled
//! freshness workflow relies on. That threshold is the mechanism's whole
//! point — a canary nobody notices going stale carries no signal — so it is
//! tested rather than assumed.

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_vellaveto-canary");

/// A unique scratch directory, avoiding a dev-dependency on tempfile for a
/// crate that keeps its dependency list deliberately tight.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vellaveto-canary-test-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn keygen() -> String {
    let out = Command::new(BIN)
        .arg("keygen")
        .output()
        .expect("run keygen");
    assert!(out.status.success(), "keygen should succeed");
    String::from_utf8(out.stdout)
        .expect("keygen stdout is utf-8")
        .trim()
        .to_string()
}

/// Create a canary, returning its path.
fn create(dir: &Path, key: &str, valid_days: u64) -> PathBuf {
    let statement = dir.join("STATEMENT.txt");
    std::fs::write(&statement, "No secret legal process has been received.\n")
        .expect("write statement");
    let out = dir.join("canary.json");

    let status = Command::new(BIN)
        .args([
            "create",
            "--statement-file",
            statement.to_str().expect("utf-8 path"),
            "--valid-days",
            &valid_days.to_string(),
            "--out",
            out.to_str().expect("utf-8 path"),
        ])
        .env("VELLAVETO_CANARY_SIGNING_KEY", key)
        .status()
        .expect("run create");

    assert!(status.success(), "create should succeed");
    out
}

#[test]
fn keygen_emits_a_usable_hex_key() {
    let key = keygen();
    assert_eq!(key.len(), 64, "an Ed25519 signing key is 32 bytes of hex");
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn create_then_verify_round_trips() {
    let dir = scratch("roundtrip");
    let key = keygen();
    let canary = create(&dir, &key, 90);

    let out = Command::new(BIN)
        .args(["verify", "--in", canary.to_str().expect("utf-8 path")])
        .output()
        .expect("run verify");

    assert!(out.status.success(), "a fresh canary must verify");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("VALID"), "got: {stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_refuses_without_the_signing_key_env_var() {
    // The key is deliberately not accepted as an argument, so its absence must
    // be a clear failure rather than a prompt or a default.
    let dir = scratch("nokey");
    let statement = dir.join("STATEMENT.txt");
    std::fs::write(&statement, "No secret legal process.\n").expect("write statement");

    let out = Command::new(BIN)
        .args([
            "create",
            "--statement-file",
            statement.to_str().expect("utf-8 path"),
            "--valid-days",
            "90",
        ])
        .env_remove("VELLAVETO_CANARY_SIGNING_KEY")
        .output()
        .expect("run create");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("VELLAVETO_CANARY_SIGNING_KEY"),
        "the error should name the variable to set; got: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_fails_below_the_freshness_threshold() {
    // This is what the scheduled workflow depends on: a canary that is still
    // valid but close to expiry must fail, leaving time to publish a
    // replacement before the signal lapses.
    let dir = scratch("threshold");
    let key = keygen();
    let canary = create(&dir, &key, 30);
    let path = canary.to_str().expect("utf-8 path");

    // Comfortably inside the window: passes.
    let ok = Command::new(BIN)
        .args(["verify", "--in", path, "--min-days-remaining", "7"])
        .status()
        .expect("run verify");
    assert!(ok.success(), "30 days remaining clears a 7-day threshold");

    // Threshold above the remaining validity: fails, with exit code 2.
    let stale = Command::new(BIN)
        .args(["verify", "--in", path, "--min-days-remaining", "365"])
        .output()
        .expect("run verify");
    assert_eq!(
        stale.status.code(),
        Some(2),
        "below-threshold must exit 2 so CI fails"
    );
    assert!(String::from_utf8_lossy(&stale.stderr).contains("STALE"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_rejects_a_tampered_statement() {
    let dir = scratch("tampered");
    let key = keygen();
    let canary = create(&dir, &key, 90);

    let json = std::fs::read_to_string(&canary).expect("read canary");
    let tampered = json.replace(
        "No secret legal process has been received.",
        "A secret legal process has been received.",
    );
    assert_ne!(tampered, json, "the statement should have been replaced");
    std::fs::write(&canary, tampered).expect("write tampered canary");

    let out = Command::new(BIN)
        .args(["verify", "--in", canary.to_str().expect("utf-8 path")])
        .output()
        .expect("run verify");

    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("INVALID"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_reports_a_missing_file_as_an_error_not_a_pass() {
    // A freshness check that silently passes on a missing canary would be
    // worse than no check: it would report health for a canary that is gone.
    let out = Command::new(BIN)
        .args(["verify", "--in", "/nonexistent/canary.json"])
        .output()
        .expect("run verify");

    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed to read"));
}
