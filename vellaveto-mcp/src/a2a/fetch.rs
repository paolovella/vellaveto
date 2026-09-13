// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1

//! Agent Card ingestion: fetch, verify, and cache.
//!
//! This is the piece that was missing. `AgentCardSignatureVerifier` could
//! verify a card, `parse_agent_card` could parse one, `validate_agent_card`
//! could check it and `scan_agent_card_for_injection` could scan it — but
//! nothing ever fetched a card, so none of them ran in production and the
//! "Agent Card Ed25519 signature enforcement" claim held no weight.
//!
//! # Signature carriage
//!
//! The signature is **detached**, carried in response headers on the card
//! fetch, because [`AgentCard`] is declared `deny_unknown_fields` and has no
//! signature field — a signature cannot ride inside the card JSON. That also
//! matches [`AgentCardClaims::card_hash`] and
//! `SignatureEnforcementConfig::require_card_hash_match`, which only make
//! sense for a signature computed over the exact card bytes:
//!
//! - `x-agent-card-signature` — base64 Ed25519 signature over the raw card
//!   bytes as served.
//! - `x-agent-card-claims` — base64 JSON [`AgentCardClaims`].
//!
//! Both headers accept either the URL-safe-unpadded or the standard base64
//! alphabet, matching what [`AgentCardSignatureVerifier::verify_card`] already
//! accepts for signatures.
//!
//! # Fail-closed
//!
//! Every failure path rejects the card and leaves the cache untouched: an
//! unreachable host, a timeout, a non-200 status, an oversized body, missing
//! or malformed headers, claims that do not validate, a card hash that does
//! not match the bytes, a signature that does not verify, a card that fails
//! schema validation, or an injection hit in the card's own text.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;

use super::agent_card::{
    build_agent_card_url, parse_agent_card, scan_agent_card_for_injection, validate_agent_card,
    validate_agent_card_base_url, AgentCard, AgentCardCache,
};
use super::error::A2aError;
use super::signature::{
    AgentCardClaims, AgentCardSignatureVerifier, MAX_SIGNATURE_LENGTH, MAX_SIGNED_PAYLOAD_SIZE,
};

/// Header carrying the standard-base64 Ed25519 signature over the card bytes.
pub const AGENT_CARD_SIGNATURE_HEADER: &str = "x-agent-card-signature";

/// Header carrying the standard-base64 JSON claims for the card.
pub const AGENT_CARD_CLAIMS_HEADER: &str = "x-agent-card-claims";

/// Maximum size of the base64 claims header.
///
/// Claims are a handful of short fields; this is generous but bounded so a
/// hostile upstream cannot make us buffer an unbounded header.
const MAX_CLAIMS_HEADER_LENGTH: usize = 8192;

/// Fetches Agent Cards and admits them only if they verify.
///
/// Cheap to clone: the client, verifier, and cache are all shared.
#[derive(Clone)]
pub struct AgentCardFetcher {
    client: reqwest::Client,
    verifier: Arc<AgentCardSignatureVerifier>,
    cache: Arc<AgentCardCache>,
    /// Whether a card must carry a valid signature to be admitted.
    ///
    /// When false, the signature headers are still verified *if present* — a
    /// bad signature is always a rejection; this only governs whether their
    /// absence is fatal.
    require_signature: bool,
}

impl std::fmt::Debug for AgentCardFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentCardFetcher")
            .field("require_signature", &self.require_signature)
            .field("cached_cards", &self.cache.len())
            .finish()
    }
}

impl AgentCardFetcher {
    /// Build a fetcher.
    ///
    /// # Errors
    ///
    /// Fails if the HTTP client cannot be constructed.
    pub fn new(
        verifier: Arc<AgentCardSignatureVerifier>,
        cache: Arc<AgentCardCache>,
        request_timeout: Duration,
        require_signature: bool,
    ) -> Result<Self, A2aError> {
        // No redirect following: a redirect would take the fetch to a host the
        // SSRF check never saw, which is the whole point of that check.
        let client = reqwest::Client::builder()
            .timeout(request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| A2aError::Upstream(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            client,
            verifier,
            cache,
            require_signature,
        })
    }

    /// Return a cached card for `base_url`, if one is still fresh.
    ///
    /// Only cards that passed every check were ever stored, so a cache hit is
    /// a previously verified card.
    pub fn cached(&self, base_url: &str) -> Option<AgentCard> {
        self.cache.get_cached(base_url)
    }

    /// Fetch, verify, and cache the Agent Card for `base_url`.
    ///
    /// Returns a cached card when one is fresh; otherwise performs the full
    /// fetch-and-verify sequence. The card is cached only after every check
    /// passes.
    ///
    /// # Errors
    ///
    /// Fails closed on every error path. See the module docs.
    pub async fn fetch_and_verify(&self, base_url: &str) -> Result<AgentCard, A2aError> {
        if let Some(card) = self.cache.get_cached(base_url) {
            return Ok(card);
        }

        // SSRF guard runs before any request is made, and no redirects are
        // followed, so the host that was checked is the host that is reached.
        validate_agent_card_base_url(base_url)?;

        let url = build_agent_card_url(base_url);
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| A2aError::AgentCardNotFound {
                    url: format!("{url} ({e})"),
                })?;

        if !response.status().is_success() {
            return Err(A2aError::AgentCardNotFound {
                url: format!("{url} (HTTP {})", response.status()),
            });
        }

        let signature_b64 = header_value(&response, AGENT_CARD_SIGNATURE_HEADER)?;
        let claims_b64 = header_value(&response, AGENT_CARD_CLAIMS_HEADER)?;

        let body = read_capped_body(response, MAX_SIGNED_PAYLOAD_SIZE).await?;

        self.verify_and_admit(base_url, &body, signature_b64, claims_b64)
    }

    /// Verify already-fetched card bytes and admit the card on success.
    ///
    /// Split out from the network path so the whole verification sequence is
    /// testable without a live server.
    pub fn verify_and_admit(
        &self,
        base_url: &str,
        body: &[u8],
        signature_b64: Option<String>,
        claims_b64: Option<String>,
    ) -> Result<AgentCard, A2aError> {
        match (signature_b64, claims_b64) {
            (Some(sig), Some(claims_raw)) => {
                if sig.len() > MAX_SIGNATURE_LENGTH {
                    return Err(A2aError::AgentCardInvalid(format!(
                        "agent card signature length {} exceeds maximum {}",
                        sig.len(),
                        MAX_SIGNATURE_LENGTH
                    )));
                }

                let claims = decode_claims(&claims_raw)?;
                claims.validate()?;

                // verify_card binds the signature to these exact bytes via
                // claims.card_hash (constant-time, and tolerant of uppercase-hex
                // issuers per R228-A2A-12), so the hash check is deliberately not
                // duplicated here — a second, naive comparison would re-introduce
                // the case-sensitivity bug that fix removed.
                self.verifier.verify_card(body, &sig, &claims)?;
            }
            _ => {
                if self.require_signature {
                    return Err(A2aError::AgentCardInvalid(format!(
                        "agent card is unsigned: both {AGENT_CARD_SIGNATURE_HEADER} and \
                         {AGENT_CARD_CLAIMS_HEADER} are required"
                    )));
                }
            }
        }

        let card_json = std::str::from_utf8(body).map_err(|e| {
            A2aError::AgentCardInvalid(format!("agent card is not valid UTF-8: {e}"))
        })?;
        let card = parse_agent_card(card_json)?;
        validate_agent_card(&card)?;

        // The card's own text is attacker-controlled: it reaches an agent's
        // context the same way tool descriptions do.
        let injection_hits = scan_agent_card_for_injection(&card);
        if !injection_hits.is_empty() {
            let fields: Vec<&str> = injection_hits.iter().map(|(f, _)| f.as_str()).collect();
            return Err(A2aError::AgentCardInvalid(format!(
                "agent card contains injection patterns in: {}",
                fields.join(", ")
            )));
        }

        // Cache only after every check has passed.
        self.cache.store(base_url, card.clone());
        Ok(card)
    }
}

/// Read a response body, refusing to buffer more than `max_bytes`.
///
/// Streams and counts rather than trusting `Content-Length`, which a hostile
/// upstream controls independently of what it actually sends.
async fn read_capped_body(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, A2aError> {
    let mut response = response;
    let mut body = Vec::new();

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| A2aError::Upstream(format!("failed reading agent card body: {e}")))?
    {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(A2aError::MessageTooLarge {
                size: body.len().saturating_add(chunk.len()),
                max: max_bytes,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Extract a header as an owned `String`, rejecting non-ASCII values.
fn header_value(response: &reqwest::Response, name: &str) -> Result<Option<String>, A2aError> {
    match response.headers().get(name) {
        None => Ok(None),
        Some(value) => {
            let text = value.to_str().map_err(|_| {
                A2aError::AgentCardInvalid(format!("{name} header is not valid ASCII"))
            })?;
            Ok(Some(text.to_string()))
        }
    }
}

/// Decode the base64 claims header into [`AgentCardClaims`].
fn decode_claims(claims_b64: &str) -> Result<AgentCardClaims, A2aError> {
    if claims_b64.len() > MAX_CLAIMS_HEADER_LENGTH {
        return Err(A2aError::AgentCardInvalid(format!(
            "{AGENT_CARD_CLAIMS_HEADER} length {} exceeds maximum {}",
            claims_b64.len(),
            MAX_CLAIMS_HEADER_LENGTH
        )));
    }

    // Accept either alphabet, matching verify_card's handling of signatures.
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(claims_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(claims_b64))
        .map_err(|e| {
            A2aError::AgentCardInvalid(format!(
                "{AGENT_CARD_CLAIMS_HEADER} is not valid base64: {e}"
            ))
        })?;

    serde_json::from_slice(&decoded).map_err(|e| {
        A2aError::AgentCardInvalid(format!(
            "{AGENT_CARD_CLAIMS_HEADER} is not valid claims JSON: {e}"
        ))
    })
}

#[cfg(test)]
mod tests {
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
        let key =
            AgentSigningKey::new("key-1", verifying_key.as_bytes(), ISSUER).expect("trusted key");
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

        let mut tampered =
            serde_json::from_slice::<serde_json::Value>(&signed_body).expect("parse");
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
}
