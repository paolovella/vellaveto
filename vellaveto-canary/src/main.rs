// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: Apache-2.0

//! `vellaveto-canary` — create and verify Ed25519 warrant canaries.
//!
//! `create_canary` and `verify_canary` have existed and been tested since the
//! crate was written, but nothing ever invoked `create_canary`, so no canary
//! was ever produced and the documented "if it stops being updated, assume
//! legal pressure" signal had nothing to stop. This binary is the missing
//! half: it makes producing and checking a canary a single command.
//!
//! What it deliberately does not do is decide *what* the canary says or hold
//! the key that signs it. Both belong to whoever makes the legal attestation.
//!
//! # Usage
//!
//! ```text
//! # Sign a statement. The key comes from the environment, never argv.
//! VELLAVETO_CANARY_SIGNING_KEY=<64 hex chars> \
//!   vellaveto-canary create --statement-file STATEMENT.txt --valid-days 90 \
//!                           --out canary.json
//!
//! # Check a canary and report days remaining.
//! vellaveto-canary verify --in canary.json
//!
//! # Same, but exit non-zero when fewer than N days remain (for CI).
//! vellaveto-canary verify --in canary.json --min-days-remaining 14
//!
//! # Generate a fresh signing keypair. Prints the secret to stdout ONCE.
//! vellaveto-canary keygen
//! ```
//!
//! Uses `std::env` rather than an argument-parsing crate: this crate is
//! standalone Apache-2.0 with a deliberately tight dependency list, and three
//! flags do not justify pulling one in.

use std::process::ExitCode;

use vellaveto_canary::{create_canary, verify_canary, WarrantCanary};

/// Environment variable holding the hex-encoded Ed25519 signing key.
///
/// Read from the environment rather than a flag so the key never lands in
/// shell history, `ps` output, or CI command echoes.
const SIGNING_KEY_ENV: &str = "VELLAVETO_CANARY_SIGNING_KEY";

const USAGE: &str = "\
vellaveto-canary — create and verify Ed25519 warrant canaries

USAGE:
    vellaveto-canary create --statement-file <PATH> --valid-days <N> [--out <PATH>]
    vellaveto-canary verify --in <PATH> [--min-days-remaining <N>]
    vellaveto-canary keygen

CREATE:
    --statement-file <PATH>   File containing the canary statement text.
    --valid-days <N>          Days the canary remains valid (at least 1).
    --out <PATH>              Write the canary JSON here (default: stdout).

    The signing key is read from the VELLAVETO_CANARY_SIGNING_KEY environment
    variable (64 hex characters). It is never accepted as an argument.

VERIFY:
    --in <PATH>               Canary JSON to check.
    --min-days-remaining <N>  Exit non-zero if fewer than N days remain.
                              Use this in scheduled jobs: a canary nobody
                              notices going stale carries no signal.

EXIT CODES:
    0  success
    1  usage or I/O error
    2  signature invalid, canary expired, or below --min-days-remaining
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    match args.first().map(String::as_str) {
        Some("create") => cmd_create(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some("keygen") => cmd_keygen(),
        Some("--help") | Some("-h") | Some("help") | None => {
            print!("{USAGE}");
            Ok(ExitCode::SUCCESS)
        }
        Some(other) => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

/// Look up `--name <value>` in `args`.
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn cmd_create(args: &[String]) -> Result<ExitCode, String> {
    let statement_file =
        flag(args, "--statement-file").ok_or("create requires --statement-file <PATH>")?;
    let valid_days: u64 = flag(args, "--valid-days")
        .ok_or("create requires --valid-days <N>")?
        .parse()
        .map_err(|e| format!("--valid-days must be a positive integer: {e}"))?;

    let signing_key = std::env::var(SIGNING_KEY_ENV).map_err(|_| {
        format!(
            "{SIGNING_KEY_ENV} is not set. The signing key is read from the \
             environment so it never appears in shell history or process listings. \
             Run `vellaveto-canary keygen` to create one."
        )
    })?;

    let statement = std::fs::read_to_string(statement_file)
        .map_err(|e| format!("failed to read {statement_file}: {e}"))?;
    // Trailing newlines are an artifact of editing a text file, not part of
    // the attestation. Signing them would make an identical statement produce
    // a different signature depending on how the file was saved.
    let statement = statement.trim();

    let canary = create_canary(statement, valid_days, &signing_key)?;

    // Verify what we just produced before letting it out. A canary that fails
    // its own verification is worse than none: it reads as tampering.
    let check = verify_canary(&canary)?;
    if !check.signature_valid {
        return Err("refusing to emit a canary that fails its own signature check".to_string());
    }

    let json = serde_json::to_string_pretty(&canary)
        .map_err(|e| format!("failed to serialize canary: {e}"))?;

    match flag(args, "--out") {
        Some(path) => {
            std::fs::write(path, format!("{json}\n"))
                .map_err(|e| format!("failed to write {path}: {e}"))?;
            eprintln!(
                "Canary written to {path} — signed {}, expires {} ({} days).",
                canary.signed_date, canary.expires_date, check.days_remaining
            );
            eprintln!(
                "Publish it where consumers can fetch it, and record the verifying key \
                 out of band:\n  {}",
                canary.verifying_key
            );
        }
        None => println!("{json}"),
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(args: &[String]) -> Result<ExitCode, String> {
    let path = flag(args, "--in").ok_or("verify requires --in <PATH>")?;
    let min_days: Option<i64> = match flag(args, "--min-days-remaining") {
        Some(v) => Some(
            v.parse()
                .map_err(|e| format!("--min-days-remaining must be an integer: {e}"))?,
        ),
        None => None,
    };

    let json = std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    let canary: WarrantCanary =
        serde_json::from_str(&json).map_err(|e| format!("failed to parse {path}: {e}"))?;

    let result = verify_canary(&canary)?;

    if !result.signature_valid {
        eprintln!("INVALID: signature verification failed for {path}");
        return Ok(ExitCode::from(2));
    }

    if result.expired {
        eprintln!(
            "EXPIRED: canary expired {} days ago (signed {}, expired {})",
            -result.days_remaining, canary.signed_date, canary.expires_date
        );
        return Ok(ExitCode::from(2));
    }

    println!(
        "VALID: signed {}, expires {} ({} days remaining)",
        canary.signed_date, canary.expires_date, result.days_remaining
    );

    if let Some(min) = min_days {
        if result.days_remaining < min {
            eprintln!(
                "STALE: {} days remaining is below the {min}-day threshold. \
                 Publish a refreshed canary.",
                result.days_remaining
            );
            return Ok(ExitCode::from(2));
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn cmd_keygen() -> Result<ExitCode, String> {
    use ed25519_dalek::SigningKey;

    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();

    // Secret to stdout, public to stderr, so `keygen > key.txt` captures only
    // the secret and the operator still sees the public half.
    println!("{}", hex::encode(signing_key.to_bytes()));
    eprintln!(
        "verifying key (publish this): {}",
        hex::encode(verifying_key.to_bytes())
    );
    eprintln!(
        "\nStore the signing key offline. Anyone holding it can forge a canary, \
         which is the one failure that makes the whole signal worthless."
    );

    Ok(ExitCode::SUCCESS)
}
