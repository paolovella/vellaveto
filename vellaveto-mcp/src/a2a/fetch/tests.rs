// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

//! Tests for the parent module.
//!
//! Kept in a `tests.rs` child module rather than an inline `#[cfg(test)]`
//! block so the fixtures here — hard-coded test keys and `http://` URLs —
//! fall under the `paths-ignore` globs in `.github/codeql/codeql-config.yml`,
//! the same way every other test module in this repository does. Being a
//! child module, it keeps access to the parent's private items.

use super::*;
use crate::a2a::signature::{compute_card_hash, AgentSigningKey, SignatureEnforcementConfig};
use ed25519_dalek::{Signer, SigningKey};
use std::time::{SystemTime, UNIX_EPOCH};

const BASE_URL: &str = "https://agent.example.com";
const ISSUER: &str = "https://issuer.example.com";

fn card_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name": "Test Agent",
        "url": BASE_URL,
        "version": "1.0.0",
        "capabilities": {},
    }))
    .expect("card json")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn claims_for(body: &[u8], exp_offset: i64) -> AgentCardClaims {
    let now = now_secs();
    AgentCardClaims {
        iss: ISSUER.to_string(),
        sub: BASE_URL.to_string(),
        iat: now.saturating_sub(10),
        exp: now.saturating_add_signed(exp_offset),
        kid: Some("key-1".to_string()),
        card_hash: compute_card_hash(body),
    }
}

fn encode_claims(claims: &AgentCardClaims) -> String {
    let json = serde_json::to_vec(claims).expect("claims json");
    base64::engine::general_purpose::STANDARD.encode(json)
}

/// A fetcher whose verifier trusts `key-1`, plus the matching signing key.
fn fetcher_with_trust(require_signature: bool) -> (AgentCardFetcher, SigningKey) {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();

    let verifier = AgentCardSignatureVerifier::new(SignatureEnforcementConfig::default());
    let key = AgentSigningKey::new("key-1", verifying_key.as_bytes(), ISSUER).expect("trusted key");
    verifier.add_trusted_key(key).expect("add trusted key");

    let fetcher = AgentCardFetcher::new(
        Arc::new(verifier),
        Arc::new(AgentCardCache::new(3600)),
        Duration::from_secs(5),
        require_signature,
    )
    .expect("fetcher");

    (fetcher, signing_key)
}

fn sign(signing_key: &SigningKey, body: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_key.sign(body).to_bytes())
}

// ── The happy path ──────────────────────────────────────────────────

#[test]
fn test_valid_signature_admits_and_caches_card() {
    let (fetcher, signing_key) = fetcher_with_trust(true);
    let body = card_json();
    let claims = claims_for(&body, 3600);

    let card = fetcher
        .verify_and_admit(
            BASE_URL,
            &body,
            Some(sign(&signing_key, &body)),
            Some(encode_claims(&claims)),
        )
        .expect("valid card should be admitted");

    assert_eq!(card.name, "Test Agent");
    assert!(
        fetcher.cached(BASE_URL).is_some(),
        "a verified card should be cached"
    );
}

// ── The case that would have caught the original defect ─────────────

#[test]
fn test_unsigned_card_is_rejected_when_signature_required() {
    // With enforcement genuinely wired, a card with no signature headers
    // must not be admitted. Before this module existed, nothing called the
    // verifier at all, so every unsigned card sailed through.
    let (fetcher, _) = fetcher_with_trust(true);
    let body = card_json();

    let err = fetcher
        .verify_and_admit(BASE_URL, &body, None, None)
        .expect_err("unsigned card must be rejected");

    assert!(
        err.to_string().contains("unsigned"),
        "expected unsigned rejection, got: {err}"
    );
    assert!(
        fetcher.cached(BASE_URL).is_none(),
        "a rejected card must not be cached"
    );
}

#[test]
fn test_card_mutated_after_signing_is_rejected_by_hash_binding() {
    // Sign one card, serve another. The signature is valid over the bytes
    // it was made for, so only the card_hash binding catches this.
    let (fetcher, signing_key) = fetcher_with_trust(true);
    let signed_body = card_json();
    let claims = claims_for(&signed_body, 3600);

    let mut tampered = serde_json::from_slice::<serde_json::Value>(&signed_body).expect("parse");
    tampered["name"] = serde_json::json!("Evil Agent");
    let tampered_body = serde_json::to_vec(&tampered).expect("serialize");

    let err = fetcher
        .verify_and_admit(
            BASE_URL,
            &tampered_body,
            Some(sign(&signing_key, &signed_body)),
            Some(encode_claims(&claims)),
        )
        .expect_err("tampered card must be rejected");

    assert!(
        err.to_string().contains("hash does not match"),
        "expected hash binding rejection, got: {err}"
    );
    assert!(fetcher.cached(BASE_URL).is_none());
}

// ── Remaining fail-closed paths ─────────────────────────────────────

#[test]
fn test_signature_from_untrusted_key_is_rejected() {
    let (fetcher, _) = fetcher_with_trust(true);
    let attacker_key = SigningKey::generate(&mut rand::rng());
    let body = card_json();
    let claims = claims_for(&body, 3600);

    let err = fetcher
        .verify_and_admit(
            BASE_URL,
            &body,
            Some(sign(&attacker_key, &body)),
            Some(encode_claims(&claims)),
        )
        .expect_err("untrusted signer must be rejected");

    assert!(fetcher.cached(BASE_URL).is_none(), "got: {err}");
}

#[test]
fn test_expired_claims_are_rejected() {
    let (fetcher, signing_key) = fetcher_with_trust(true);
    let body = card_json();
    let claims = claims_for(&body, -3600); // expired an hour ago

    let err = fetcher
        .verify_and_admit(
            BASE_URL,
            &body,
            Some(sign(&signing_key, &body)),
            Some(encode_claims(&claims)),
        )
        .expect_err("expired claims must be rejected");

    assert!(fetcher.cached(BASE_URL).is_none(), "got: {err}");
}

#[test]
fn test_malformed_claims_header_is_rejected() {
    let (fetcher, signing_key) = fetcher_with_trust(true);
    let body = card_json();

    let err = fetcher
        .verify_and_admit(
            BASE_URL,
            &body,
            Some(sign(&signing_key, &body)),
            Some("!!!not base64!!!".to_string()),
        )
        .expect_err("malformed claims must be rejected");

    assert!(
        err.to_string().contains("not valid base64"),
        "expected base64 error, got: {err}"
    );
}

#[test]
fn test_oversized_signature_header_is_rejected() {
    let (fetcher, _) = fetcher_with_trust(true);
    let body = card_json();
    let claims = claims_for(&body, 3600);

    let err = fetcher
        .verify_and_admit(
            BASE_URL,
            &body,
            Some("A".repeat(MAX_SIGNATURE_LENGTH + 1)),
            Some(encode_claims(&claims)),
        )
        .expect_err("oversized signature must be rejected");

    assert!(
        err.to_string().contains("exceeds maximum"),
        "expected size rejection, got: {err}"
    );
}

#[test]
fn test_oversized_claims_header_is_rejected() {
    let (fetcher, signing_key) = fetcher_with_trust(true);
    let body = card_json();

    let err = fetcher
        .verify_and_admit(
            BASE_URL,
            &body,
            Some(sign(&signing_key, &body)),
            Some("A".repeat(MAX_CLAIMS_HEADER_LENGTH + 1)),
        )
        .expect_err("oversized claims must be rejected");

    assert!(
        err.to_string().contains("exceeds maximum"),
        "expected size rejection, got: {err}"
    );
}

#[test]
fn test_non_utf8_body_is_rejected() {
    let (fetcher, _) = fetcher_with_trust(false);
    let err = fetcher
        .verify_and_admit(BASE_URL, &[0xff, 0xfe, 0xfd], None, None)
        .expect_err("non-UTF-8 body must be rejected");

    assert!(
        err.to_string().contains("not valid UTF-8"),
        "expected UTF-8 error, got: {err}"
    );
}

#[test]
fn test_bad_signature_is_rejected_even_when_not_required() {
    // require_signature governs whether *absence* is fatal. A signature
    // that is present and wrong is always a rejection.
    let (fetcher, _) = fetcher_with_trust(false);
    let attacker_key = SigningKey::generate(&mut rand::rng());
    let body = card_json();
    let claims = claims_for(&body, 3600);

    let err = fetcher
        .verify_and_admit(
            BASE_URL,
            &body,
            Some(sign(&attacker_key, &body)),
            Some(encode_claims(&claims)),
        )
        .expect_err("a present-but-invalid signature must always be rejected");

    assert!(fetcher.cached(BASE_URL).is_none(), "got: {err}");
}

#[test]
fn test_unsigned_card_admitted_when_signature_not_required() {
    let (fetcher, _) = fetcher_with_trust(false);
    let body = card_json();

    let card = fetcher
        .verify_and_admit(BASE_URL, &body, None, None)
        .expect("unsigned card allowed when not required");
    assert_eq!(card.name, "Test Agent");
}

#[tokio::test]
async fn test_fetch_rejects_ssrf_base_url_before_any_request() {
    // The SSRF guard runs before the client is used at all.
    let (fetcher, _) = fetcher_with_trust(true);
    for target in [
        "http://169.254.169.254",
        "http://localhost:8080",
        "file:///etc/passwd",
    ] {
        assert!(
            fetcher.fetch_and_verify(target).await.is_err(),
            "{target} must be refused"
        );
    }
}

#[tokio::test]
async fn test_fetch_unreachable_upstream_fails_closed() {
    let (fetcher, _) = fetcher_with_trust(true);
    // Reserved TEST-NET-1 address: routable-looking, never answers.
    let result = fetcher.fetch_and_verify("https://192.0.2.1").await;
    assert!(result.is_err(), "unreachable upstream must not fail open");
    assert!(fetcher.cached("https://192.0.2.1").is_none());
}
