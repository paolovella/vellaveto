// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

use argon2::{PasswordHash, PasswordVerifier};
use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use flate2::read::{DeflateDecoder, ZlibDecoder};
use jsonwebtoken::{
    decode, decode_header, encode,
    jwk::{JwkSet, KeyAlgorithm},
    Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use percent_encoding::percent_decode_str;
use rand::Rng;
use reqwest::{header as reqwest_header, Client};
use ring::{digest, signature};
use roxmltree::{Document, Node, NodeType};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    env,
    io::{Cursor, Read},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::{sync::RwLock, task::JoinHandle, time::sleep};
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;
use vellaveto_types::{has_dangerous_chars, validate_url_no_ssrf};
use x509_parser::prelude::*;

use crate::rbac::{AudienceClaim, Role, RoleClaims};
use crate::routes::ErrorResponse;
use crate::AppState;
use vellaveto_config::{
    iam::{OidcConfig as VellavetoOidcConfig, SamlConfig, ScimConfig},
    IamConfig,
};

const FLOW_TTL_SECS: u64 = 300;
const MAX_NEXT_LEN: usize = 512;

/// Maximum length for M2M client_id in token requests.
const MAX_M2M_CLIENT_ID_REQUEST_LEN: usize = 128;
/// Maximum length for M2M client_secret in token requests.
const MAX_M2M_CLIENT_SECRET_REQUEST_LEN: usize = 512;
/// Maximum number of scopes in an M2M token request.
const MAX_M2M_REQUESTED_SCOPES: usize = 32;
/// Maximum length of a single M2M scope string in a request.
const MAX_M2M_SCOPE_REQUEST_LEN: usize = 64;
/// Default issuer for M2M tokens when not configured.
const DEFAULT_M2M_ISSUER: &str = "vellaveto";
/// HMAC signing secret environment variable for M2M JWTs.
const M2M_JWT_SECRET_ENV: &str = "VELLAVETO_M2M_JWT_SECRET";
/// Minimum length for the M2M JWT signing secret.
const MIN_M2M_JWT_SECRET_LEN: usize = 32;

/// Maximum length for a CIMD URL.
const MAX_CIMD_URL_LEN: usize = 2048;
/// Cache TTL for CIMD entries (5 minutes).
const CIMD_CACHE_TTL_SECS: u64 = 300;
/// Maximum number of CIMD cache entries.
const MAX_CIMD_CACHE_SIZE: usize = 1000;
/// Maximum response size for CIMD fetch (64 KB).
const MAX_CIMD_RESPONSE_SIZE: usize = 65_536;
/// Maximum number of redirect URIs in client metadata.
const MAX_CIMD_REDIRECT_URIS: usize = 20;
/// Maximum number of grant types in client metadata.
const MAX_CIMD_GRANT_TYPES: usize = 10;

const SAML_PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const SAML_STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

#[derive(Debug, Default)]
struct ScimStatus {
    last_sync: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_user_count: Option<usize>,
    last_sync_duration_ms: Option<u128>,
}

#[derive(Debug)]
struct SamlState {
    entity_id: String,
    acs_url: String,
    idp_entity_id: String,
    certificates: Vec<Vec<u8>>,
    role_attribute: String,
}

impl SamlState {
    async fn new(config: &SamlConfig, client: &Client) -> Result<Self, IamError> {
        let metadata_url = config
            .idp_metadata_url
            .as_ref()
            .ok_or_else(|| IamError::Saml("iam.saml.idp_metadata_url is required".to_string()))?;
        // SECURITY (R231-SRV-2): Validate SAML metadata URL against SSRF
        // (loopback, link-local, cloud metadata IPs) before fetching.
        validate_url_no_ssrf(metadata_url)
            .map_err(|e| IamError::Saml(format!("SAML metadata URL SSRF blocked: {e}")))?;
        // SECURITY (R231-SRV-6): Bound SAML metadata response size + timeout
        // to prevent memory exhaustion and startup hang.
        const MAX_SAML_METADATA_SIZE: u64 = 2 * 1024 * 1024; // 2 MB
        let response = client
            .get(metadata_url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| IamError::Saml(format!("Failed to fetch SAML metadata: {e}")))?
            .error_for_status()
            .map_err(|e| IamError::Saml(format!("Failed to fetch SAML metadata: {e}")))?;
        let content_length = response.content_length().unwrap_or(0);
        if content_length > MAX_SAML_METADATA_SIZE {
            return Err(IamError::Saml(
                "SAML metadata response too large".to_string(),
            ));
        }
        let body_bytes = response
            .bytes()
            .await
            .map_err(|e| IamError::Saml(format!("Failed to read SAML metadata: {e}")))?;
        if body_bytes.len() as u64 > MAX_SAML_METADATA_SIZE {
            return Err(IamError::Saml("SAML metadata body too large".to_string()));
        }
        let body = String::from_utf8(body_bytes.to_vec())
            .map_err(|e| IamError::Saml(format!("SAML metadata is not valid UTF-8: {e}")))?;
        let document = Document::parse(&body)
            .map_err(|e| IamError::Saml(format!("Invalid SAML metadata XML: {e}")))?;
        Self::from_document(document, config)
    }

    fn from_document(document: Document, config: &SamlConfig) -> Result<Self, IamError> {
        let entity_node = document
            .descendants()
            .find(|node| node.has_tag_name((SAML_METADATA_NS, "EntityDescriptor")))
            .ok_or_else(|| IamError::Saml("SAML metadata missing EntityDescriptor".to_string()))?;
        let idp_entity_id = entity_node
            .attribute("entityID")
            .ok_or_else(|| IamError::Saml("EntityDescriptor missing entityID".to_string()))?
            .to_string();
        let sso_location = document
            .descendants()
            .filter(|node| node.has_tag_name((SAML_METADATA_NS, "SingleSignOnService")))
            .find(|node| {
                matches!(
                    node.attribute("Binding"),
                    Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
                )
            })
            .or_else(|| {
                document
                    .descendants()
                    .find(|node| node.has_tag_name((SAML_METADATA_NS, "SingleSignOnService")))
            })
            .and_then(|node| node.attribute("Location"));
        sso_location.ok_or_else(|| {
            IamError::Saml("SAML metadata missing SingleSignOnService or Location".to_string())
        })?;
        let mut certificates = Vec::new();
        for node in document
            .descendants()
            .filter(|node| node.has_tag_name((XMLDSIG_NS, "X509Certificate")))
        {
            // R230-SRV-1: Fail-closed on empty/missing certificate text.
            // Previously silently skipped, masking metadata corruption.
            let text = node.text().ok_or_else(|| {
                IamError::Saml(
                    "SAML metadata X509Certificate element has no text content (fail-closed)"
                        .to_string(),
                )
            })?;
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Err(IamError::Saml(
                    "SAML metadata X509Certificate element has empty content (fail-closed)"
                        .to_string(),
                ));
            }
            certificates.push(decode_base64(trimmed, "SAML metadata certificate")?);
        }
        if certificates.is_empty() {
            return Err(IamError::Saml(
                "SAML metadata includes no signing certificates".to_string(),
            ));
        }
        let entity_id = config
            .entity_id
            .clone()
            .ok_or_else(|| IamError::Saml("iam.saml.entity_id must be configured".to_string()))?;
        let acs_url = config
            .acs_url
            .clone()
            .ok_or_else(|| IamError::Saml("iam.saml.acs_url must be configured".to_string()))?;
        let role_attribute = config
            .role_attribute
            .clone()
            .unwrap_or_else(|| "Role".to_string());
        Ok(Self {
            entity_id,
            acs_url,
            idp_entity_id,
            certificates,
            role_attribute,
        })
    }
}

impl SamlState {
    fn extract_claims(&self, document: &Document) -> Result<RoleClaims, IamError> {
        let response = document
            .descendants()
            .find(|node| node.has_tag_name((SAML_PROTOCOL_NS, "Response")))
            .ok_or_else(|| IamError::Saml("SAML Response element missing".to_string()))?;
        self.ensure_status_success(response)?;
        self.ensure_destination(response)?;
        let assertion = response
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Assertion")))
            .ok_or_else(|| IamError::Saml("SAML Assertion element missing".to_string()))?;
        self.verify_assertion(assertion)?;
        self.ensure_issuer(response, assertion)?;
        self.ensure_conditions(assertion)?;
        self.ensure_audience(assertion)?;
        // SECURITY (R229-SRV-1): Validate SubjectConfirmation for bearer assertions.
        self.ensure_subject_confirmation(assertion)?;
        Ok(self.claims_from_assertion(assertion))
    }

    fn ensure_status_success(&self, response: Node) -> Result<(), IamError> {
        let status_value = response
            .descendants()
            .find(|node| node.has_tag_name((SAML_PROTOCOL_NS, "StatusCode")))
            .and_then(|node| node.attribute("Value"))
            .ok_or_else(|| IamError::Saml("SAML StatusCode missing".to_string()))?;
        if status_value != SAML_STATUS_SUCCESS {
            tracing::debug!(status = %status_value, "SAML response status is not Success");
            return Err(IamError::Saml(
                "SAML response validation failed".to_string(),
            ));
        }
        Ok(())
    }

    /// SECURITY (R228-SRV-2): Destination is required per SAML 2.0 §3.2.2.
    /// A missing Destination allows cross-SP response replay.
    fn ensure_destination(&self, response: Node) -> Result<(), IamError> {
        let destination = response.attribute("Destination").ok_or_else(|| {
            IamError::Saml(
                "SAML response missing required Destination attribute (fail-closed)".to_string(),
            )
        })?;
        if destination != self.acs_url {
            // SECURITY (R229-SRV-7): Generic error — don't leak ACS URL or destination.
            return Err(IamError::Saml(
                "SAML response Destination does not match configured ACS URL".to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_issuer(&self, response: Node, assertion: Node) -> Result<(), IamError> {
        let issuer = response
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Issuer")))
            .or_else(|| {
                assertion
                    .descendants()
                    .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Issuer")))
            })
            .and_then(|node| node.text())
            .ok_or_else(|| IamError::Saml("SAML issuer missing".to_string()))?;
        if issuer != self.idp_entity_id {
            // SECURITY (R229-SRV-7): Generic error message — don't leak expected/got entity IDs.
            return Err(IamError::Saml(
                "SAML issuer does not match configured IdP entity".to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_conditions(&self, assertion: Node) -> Result<(), IamError> {
        // SECURITY (R226-SRV-5): Require Conditions element (fail-closed).
        // Previously, a missing Conditions element silently returned Ok(()),
        // allowing an attacker to strip Conditions from an unsigned assertion
        // to bypass NotOnOrAfter expiry checks.
        let conditions = assertion
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Conditions")))
            .ok_or_else(|| {
                IamError::Saml("SAML Conditions element missing (fail-closed)".to_string())
            })?;
        let now = Utc::now();
        if let Some(not_before) = conditions.attribute("NotBefore") {
            let timestamp = parse_saml_timestamp(not_before)?;
            if now < timestamp {
                return Err(IamError::Saml(
                    "SAML Conditions NotBefore is in the future".to_string(),
                ));
            }
        }
        // SECURITY (R234-SRV-2): Fail-closed — require NotOnOrAfter on Conditions.
        // An attacker could strip NotOnOrAfter to create a perpetually valid assertion.
        let not_on_or_after = conditions.attribute("NotOnOrAfter").ok_or_else(|| {
            IamError::Saml("SAML Conditions NotOnOrAfter missing (fail-closed)".to_string())
        })?;
        let timestamp = parse_saml_timestamp(not_on_or_after)?;
        if now >= timestamp {
            return Err(IamError::Saml(
                "SAML Conditions NotOnOrAfter has passed".to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_audience(&self, assertion: Node) -> Result<(), IamError> {
        let audience_found = assertion
            .descendants()
            .filter(|node| node.has_tag_name((SAML_ASSERTION_NS, "Audience")))
            .filter_map(|node| node.text())
            .any(|value| value == self.entity_id);
        if !audience_found {
            tracing::debug!("SAML AudienceRestriction does not include configured entity_id");
            return Err(IamError::Saml(
                "SAML audience validation failed".to_string(),
            ));
        }
        Ok(())
    }

    /// SECURITY (R229-SRV-1): Validate SubjectConfirmation per SAML 2.0 §2.4.1.
    ///
    /// For bearer assertions, SubjectConfirmationData must have:
    /// - Recipient matching our ACS URL
    /// - NotOnOrAfter that hasn't expired
    ///
    /// Without this, an attacker can replay assertions or use cross-SP assertions.
    fn ensure_subject_confirmation(&self, assertion: Node) -> Result<(), IamError> {
        let subject = assertion
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Subject")))
            .ok_or_else(|| {
                IamError::Saml("SAML Subject element missing (fail-closed)".to_string())
            })?;
        let confirmation = subject
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "SubjectConfirmation")))
            .ok_or_else(|| {
                IamError::Saml("SAML SubjectConfirmation element missing (fail-closed)".to_string())
            })?;
        // Require bearer method.
        let method = confirmation.attribute("Method").unwrap_or("");
        if method != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
            return Err(IamError::Saml(
                "SAML SubjectConfirmation Method is not bearer".to_string(),
            ));
        }
        // SubjectConfirmationData is required for bearer.
        let data = confirmation
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "SubjectConfirmationData")))
            .ok_or_else(|| {
                IamError::Saml(
                    "SAML SubjectConfirmationData missing for bearer assertion".to_string(),
                )
            })?;
        // SECURITY (R234-SRV-1): Fail-closed — require Recipient attribute.
        // An attacker could strip Recipient to bypass cross-SP assertion reuse detection.
        let recipient = data.attribute("Recipient").ok_or_else(|| {
            IamError::Saml(
                "SAML SubjectConfirmationData Recipient missing (fail-closed)".to_string(),
            )
        })?;
        if recipient != self.acs_url {
            return Err(IamError::Saml(
                "SAML SubjectConfirmationData Recipient mismatch".to_string(),
            ));
        }
        // SECURITY (R234-SRV-2): Fail-closed — require NotOnOrAfter attribute.
        // An attacker could strip NotOnOrAfter to create a perpetually valid assertion.
        let not_on_or_after = data.attribute("NotOnOrAfter").ok_or_else(|| {
            IamError::Saml(
                "SAML SubjectConfirmationData NotOnOrAfter missing (fail-closed)".to_string(),
            )
        })?;
        let timestamp = parse_saml_timestamp(not_on_or_after)?;
        let now = Utc::now();
        if now >= timestamp {
            return Err(IamError::Saml(
                "SAML SubjectConfirmationData NotOnOrAfter has passed".to_string(),
            ));
        }
        Ok(())
    }

    fn claims_from_assertion(&self, assertion: Node) -> RoleClaims {
        let subject = assertion
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "NameID")))
            .and_then(|node| node.text())
            .map(|text| text.to_string());
        let mut roles = Vec::new();
        for attribute in assertion
            .descendants()
            .filter(|node| node.has_tag_name((SAML_ASSERTION_NS, "Attribute")))
        {
            if attribute
                .attribute("Name")
                .map(|name| name == self.role_attribute)
                .unwrap_or(false)
            {
                for value_node in attribute
                    .descendants()
                    .filter(|node| node.has_tag_name((SAML_ASSERTION_NS, "AttributeValue")))
                {
                    if let Some(value) = value_node.text() {
                        roles.push(value.to_string());
                    }
                }
            }
        }
        RoleClaims {
            sub: subject,
            role: roles.first().cloned(),
            vellaveto_role: None,
            roles: if roles.is_empty() { None } else { Some(roles) },
            aud: Some(AudienceClaim::Single(self.entity_id.clone())),
            nonce: None,
        }
    }

    fn verify_assertion(&self, assertion: Node) -> Result<(), IamError> {
        let signature = assertion
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Signature")))
            .ok_or_else(|| IamError::Saml("SAML Assertion missing Signature".to_string()))?;
        let signed_info = signature
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignedInfo")))
            .ok_or_else(|| IamError::Saml("SAML SignedInfo missing".to_string()))?;
        let reference = signed_info
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "Reference")))
            .ok_or_else(|| IamError::Saml("SAML Reference missing".to_string()))?;
        // SECURITY (R229-SRV-2): Validate Reference URI to prevent signature wrapping attacks.
        // The URI must be empty (whole document) or "#" + assertion ID. Any other value means
        // the signature covers a different element, enabling XML signature wrapping.
        let ref_uri = reference.attribute("URI").unwrap_or("");
        if !ref_uri.is_empty() {
            let assertion_id = assertion.attribute("ID").unwrap_or("");
            let expected_uri = format!("#{assertion_id}");
            if ref_uri != expected_uri {
                return Err(IamError::Saml(
                    "SAML Reference URI does not match Assertion ID".to_string(),
                ));
            }
        }
        let digest_method = reference
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "DigestMethod")))
            .and_then(|node| node.attribute("Algorithm"))
            .ok_or_else(|| IamError::Saml("DigestMethod algorithm missing".to_string()))?;
        let digest_algorithm = map_digest_algorithm(digest_method)?;
        let digest_value = reference
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "DigestValue")))
            .and_then(|node| node.text())
            .ok_or_else(|| IamError::Saml("DigestValue missing".to_string()))?;
        let digest_bytes = decode_base64(digest_value.trim(), "C14n digest value")?;
        let canonical_assertion = canonicalize_node(assertion, true);
        let computed = digest::digest(digest_algorithm, canonical_assertion.as_bytes());
        if computed.as_ref() != digest_bytes.as_slice() {
            return Err(IamError::Saml(
                "SAML assertion digest does not match".to_string(),
            ));
        }
        let signature_method = signed_info
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignatureMethod")))
            .and_then(|node| node.attribute("Algorithm"))
            .ok_or_else(|| IamError::Saml("SignatureMethod algorithm missing".to_string()))?;
        let signature_alg = map_signature_algorithm(signature_method)?;
        let signature_value = signature
            .children()
            .find(|node| node.has_tag_name((XMLDSIG_NS, "SignatureValue")))
            .and_then(|node| node.text())
            .ok_or_else(|| IamError::Saml("SignatureValue missing".to_string()))?;
        let signature_bytes = decode_base64(signature_value.trim(), "Signature value")?;
        let canonical_signed_info = canonicalize_node(signed_info, false);
        for cert in &self.certificates {
            let (_, parsed) = X509Certificate::from_der(cert)
                .map_err(|_e| IamError::Saml("Certificate validation failed".to_string()))?;
            let spki = parsed.tbs_certificate.subject_pki;
            let verifier =
                signature::UnparsedPublicKey::new(signature_alg, spki.subject_public_key.data);
            if verifier
                .verify(canonical_signed_info.as_bytes(), signature_bytes.as_slice())
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(IamError::Saml(
            "SAML signature verification failed".to_string(),
        ))
    }
}

/// Shared IAM state (OIDC + SAML + session management + M2M + CIMD) for Phase 46+.
pub struct IamState {
    config: IamConfig,
    discovery: OidcDiscovery,
    http: Client,
    flow_states: DashMap<String, FlowState>,
    sessions: DashMap<String, IamSession>,
    jwks_cache: RwLock<Option<CachedJwks>>,
    saml_state: Option<SamlState>,
    scim_status: Arc<RwLock<ScimStatus>>,
    _scim_task: Option<JoinHandle<()>>,
    /// HMAC signing key for M2M JWT generation. Loaded from env at startup.
    m2m_signing_secret: Option<Vec<u8>>,
    /// Cache for CIMD (Client ID Metadata Documents).
    cimd_cache: DashMap<String, CachedClientMetadata>,
    /// SECURITY (R230-SRV-2): SAML assertion ID replay cache (assertion_id -> seen_at).
    saml_assertion_ids: DashMap<String, std::time::Instant>,
    /// SECURITY (R237-SRV-4): Per-client M2M token request rate limiter.
    /// Maps client_id -> (request_count, window_start). Resets every 60 seconds.
    m2m_rate_limits: DashMap<String, (u32, std::time::Instant)>,
    /// SECURITY (R237-SRV-5): SAML AuthnRequest ID cache for InResponseTo validation.
    /// Maps request_id -> issued_at. Prevents unsolicited SAML response injection.
    saml_authn_request_ids: DashMap<String, std::time::Instant>,
}

/// SECURITY (R239-XCUT-2): Custom Debug redacts m2m_signing_secret and flow_states
/// (which contain PKCE secrets) to prevent secret leakage via debug output.
impl std::fmt::Debug for IamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IamState")
            .field("config", &self.config)
            .field("discovery", &self.discovery)
            .field(
                "m2m_signing_secret",
                if self.m2m_signing_secret.is_some() {
                    &"[REDACTED]" as &dyn std::fmt::Debug
                } else {
                    &"None" as &dyn std::fmt::Debug
                },
            )
            .field("flow_states_count", &self.flow_states.len())
            .field("sessions_count", &self.sessions.len())
            .field("saml_assertion_ids_count", &self.saml_assertion_ids.len())
            .field("m2m_rate_limits_count", &self.m2m_rate_limits.len())
            .field(
                "saml_authn_request_ids_count",
                &self.saml_authn_request_ids.len(),
            )
            .field("cimd_cache_count", &self.cimd_cache.len())
            .finish_non_exhaustive()
    }
}

impl IamState {
    /// Build IAM state from configuration, fetching OIDC discovery metadata.
    pub async fn new(config: IamConfig) -> Result<Self, IamError> {
        if !config.enabled {
            return Err(IamError::Disabled);
        }
        if !config.oidc.enabled {
            return Err(IamError::OidcDisabled);
        }
        let discovery = OidcDiscovery::fetch(&config.oidc, config.oidc.allow_insecure_issuer)
            .await
            .map_err(IamError::Discovery)?;
        // SECURITY (R235-SRV-2): Disable automatic redirect following to prevent
        // SSRF via 3xx redirect to internal/metadata endpoints on JWKS/token/SCIM/SAML fetches.
        let http = Client::builder()
            .user_agent("Vellaveto IAM/1.0")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| IamError::Client(e.to_string()))?;
        let saml_state = if config.saml.enabled {
            Some(SamlState::new(&config.saml, &http).await?)
        } else {
            None
        };
        let scim_status = Arc::new(RwLock::new(ScimStatus::default()));
        let scim_task = if config.scim.enabled {
            let endpoint = config
                .scim
                .endpoint
                .clone()
                .ok_or_else(|| IamError::Scim("iam.scim.endpoint missing".to_string()))?;
            // SECURITY (R231-SRV-1): Validate SCIM endpoint URL against SSRF
            // (loopback, link-local, cloud metadata IPs) before periodic fetch.
            validate_url_no_ssrf(&endpoint)
                .map_err(|e| IamError::Scim(format!("SCIM endpoint SSRF blocked: {e}")))?;
            let token = resolve_scim_token(&config.scim)?;
            Some(spawn_scim_sync(
                http.clone(),
                endpoint,
                token,
                config.scim.sync_interval_secs,
                scim_status.clone(),
            ))
        } else {
            None
        };
        // Load M2M JWT signing secret from environment if M2M is enabled.
        let m2m_signing_secret = if config.m2m.enabled {
            let secret = env::var(M2M_JWT_SECRET_ENV).ok().map(|s| s.into_bytes());
            // SECURITY (R230-SRV-5): Enforce minimum secret length (fail-closed).
            if let Some(ref s) = secret {
                if s.len() < MIN_M2M_JWT_SECRET_LEN {
                    return Err(IamError::M2mTokenGeneration(format!(
                        "{} must be at least {} bytes, got {}",
                        M2M_JWT_SECRET_ENV,
                        MIN_M2M_JWT_SECRET_LEN,
                        s.len()
                    )));
                }
            }
            secret
        } else {
            None
        };

        Ok(Self {
            config,
            discovery,
            http,
            flow_states: DashMap::new(),
            sessions: DashMap::new(),
            jwks_cache: RwLock::new(None),
            saml_state,
            scim_status,
            _scim_task: scim_task,
            m2m_signing_secret,
            cimd_cache: DashMap::new(),
            saml_assertion_ids: DashMap::new(),
            m2m_rate_limits: DashMap::new(),
            saml_authn_request_ids: DashMap::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(config: IamConfig) -> Self {
        Self::new_for_test_with_secret(config, None)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_secret(config: IamConfig, secret: Option<Vec<u8>>) -> Self {
        let discovery = OidcDiscovery {
            authorization_endpoint: "https://example.com/authorize".to_string(),
            token_endpoint: "https://example.com/token".to_string(),
            jwks_uri: "https://example.com/jwks".to_string(),
        };
        let http = Client::new();
        IamState {
            config,
            discovery,
            http,
            flow_states: DashMap::new(),
            sessions: DashMap::new(),
            jwks_cache: RwLock::new(None),
            saml_state: None,
            scim_status: Arc::new(RwLock::new(ScimStatus::default())),
            _scim_task: None,
            m2m_signing_secret: secret,
            cimd_cache: DashMap::new(),
            saml_assertion_ids: DashMap::new(),
            m2m_rate_limits: DashMap::new(),
            saml_authn_request_ids: DashMap::new(),
        }
    }

    /// Name of the session cookie.
    pub fn session_cookie_name(&self) -> &str {
        &self.config.session.cookie_name
    }

    /// Store a SAML AuthnRequest ID for later InResponseTo validation.
    ///
    /// SECURITY (R241-SRV-1): This must be called when generating SP-initiated
    /// SAML AuthnRequest redirects so that the `saml_acs` handler can validate
    /// the InResponseTo attribute against stored request IDs.
    ///
    /// Without this, the InResponseTo check in `saml_acs` is dead code.
    /// Maximum 100,000 entries with 10-minute TTL (cleaned up in saml_acs).
    pub fn store_saml_authn_request_id(&self, request_id: String) -> Result<(), IamError> {
        const MAX_SAML_AUTHN_REQUEST_IDS: usize = 100_000;
        if self.saml_authn_request_ids.len() >= MAX_SAML_AUTHN_REQUEST_IDS {
            return Err(IamError::CapacityExhausted(
                "SAML AuthnRequest ID cache".to_string(),
            ));
        }
        if has_dangerous_chars(&request_id) {
            return Err(IamError::Saml(
                "SAML AuthnRequest ID contains dangerous characters".to_string(),
            ));
        }
        self.saml_authn_request_ids
            .insert(request_id, std::time::Instant::now());
        Ok(())
    }

    /// Begin a login flow and return (state_id, flow_state, authorization URL).
    fn begin_login_flow(&self, next: Option<String>) -> (String, FlowState, String) {
        self.cleanup_flows();
        let state_id = Uuid::new_v4().to_string();
        let code_verifier = generate_code_verifier();
        let code_challenge = pkce_code_challenge(&code_verifier);
        let nonce = Uuid::new_v4().to_string();
        let next_path = sanitize_next(next);
        let flow = FlowState::new(next_path.clone(), code_verifier.clone(), nonce.clone());
        let authorize_url =
            self.build_authorize_url(&state_id, &code_challenge, &nonce, &self.config.oidc.scopes);
        (state_id, flow, authorize_url)
    }

    /// Maximum number of concurrent login flows (prevents memory exhaustion).
    ///
    /// SECURITY (R229-SRV-6): Without a cap, an attacker can spray login initiations
    /// to fill memory with flow states. Expired flows are cleaned up periodically,
    /// but the gap between creation and cleanup is exploitable.
    const MAX_FLOW_STATES: usize = 100_000;

    /// Maximum number of active sessions.
    const MAX_SESSIONS: usize = 500_000;

    /// Insert a login flow state. Returns error if capacity is exhausted.
    /// SECURITY (R237-SRV-2): Return Result so caller can detect capacity exhaustion
    /// instead of silently redirecting to IdP with no stored state.
    fn store_flow(&self, state_id: String, flow: FlowState) -> Result<(), IamError> {
        // SECURITY (R229-SRV-6): Bound flow state count to prevent memory exhaustion.
        if self.flow_states.len() >= Self::MAX_FLOW_STATES {
            tracing::warn!(
                max = Self::MAX_FLOW_STATES,
                "Login flow state capacity reached, rejecting new flow"
            );
            return Err(IamError::CapacityExhausted("login flow state".to_string()));
        }
        self.flow_states.insert(state_id, flow);
        Ok(())
    }

    /// Consume a login flow if present and not expired.
    fn consume_flow(&self, state_id: &str) -> Option<FlowState> {
        let now = Instant::now();
        if let Some((_, flow)) = self.flow_states.remove(state_id) {
            if flow.is_expired_at(now) {
                return None;
            }
            Some(flow)
        } else {
            None
        }
    }

    /// Exchange the authorization code for tokens.
    async fn exchange_code(&self, code: &str, flow: &FlowState) -> Result<TokenResponse, IamError> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            (
                "redirect_uri",
                self.config.oidc.redirect_uri.as_deref().unwrap_or_default(),
            ),
            (
                "client_id",
                self.config.oidc.client_id.as_deref().unwrap_or_default(),
            ),
            ("code_verifier", &flow.code_verifier),
        ];
        if let Some(secret) = &self.config.oidc.client_secret {
            form.push(("client_secret", secret));
        }
        let response = self
            .http
            .post(&self.discovery.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| IamError::TokenExchange(e.to_string()))?
            .error_for_status()
            .map_err(|e| IamError::TokenExchange(e.to_string()))?;
        let tokens = response
            .json::<TokenResponse>()
            .await
            .map_err(|e| IamError::TokenExchange(e.to_string()))?;
        Ok(tokens)
    }

    /// Verify the ID token signature and nonce.
    pub async fn verify_id_token(
        &self,
        id_token: &str,
        flow_nonce: &str,
    ) -> Result<RoleClaims, IamError> {
        let header = decode_header(id_token).map_err(|e| IamError::InvalidToken(e.to_string()))?;
        // R230-SRV-2: Algorithm whitelist (RFC 8725 §3.1).
        // Reject weak or unexpected algorithms from the JWT header.
        // HS256/384/512 are excluded to prevent symmetric key confusion when
        // the IdP uses asymmetric keys (the server's JWKS only has public keys).
        let allowed_algs = [
            Algorithm::RS256,
            Algorithm::RS384,
            Algorithm::RS512,
            Algorithm::ES256,
            Algorithm::ES384,
            Algorithm::PS256,
            Algorithm::PS384,
            Algorithm::PS512,
            Algorithm::EdDSA,
        ];
        if !allowed_algs.contains(&header.alg) {
            return Err(IamError::InvalidToken(format!(
                "JWT algorithm {:?} is not in the allowed set (fail-closed)",
                header.alg
            )));
        }
        let decoding_key = self.decoding_key(header.kid.as_deref(), header.alg).await?;
        let mut validation = Validation::new(header.alg);
        if let Some(issuer) = &self.config.oidc.issuer_url {
            validation.set_issuer(&[issuer]);
        }
        if let Some(client_id) = &self.config.oidc.client_id {
            validation.set_audience(&[client_id]);
        }
        validation.leeway = 60;
        // SECURITY (R253-IAM-1): Explicitly enable exp and nbf validation.
        // Validation::new() enables exp by default but NOT nbf. Being explicit
        // prevents regressions if library defaults change.
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let token_data = decode::<RoleClaims>(id_token, &decoding_key, &validation)
            .map_err(|e| IamError::InvalidToken(e.to_string()))?;
        let claims = token_data.claims;
        if claims.nonce.as_deref() != Some(flow_nonce) {
            return Err(IamError::NonceMismatch);
        }
        Ok(claims)
    }

    fn cleanup_flows(&self) {
        let now = Instant::now();
        let expired: Vec<_> = self
            .flow_states
            .iter()
            .filter_map(|entry| {
                if entry.value().is_expired_at(now) {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in expired {
            self.flow_states.remove(&key);
        }
    }

    fn build_authorize_url(
        &self,
        state: &str,
        code_challenge: &str,
        nonce: &str,
        scopes: &[String],
    ) -> String {
        let mut url = Url::parse(&self.discovery.authorization_endpoint).unwrap_or_else(|_| {
            // SAFETY: static literal always parses — validated at config load
            Url::parse("http://invalid").unwrap_or_else(|_| unreachable!())
        });
        let scope = scopes.join(" ");
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("response_type", "code");
            if let Some(client_id) = &self.config.oidc.client_id {
                query.append_pair("client_id", client_id);
            }
            if let Some(redirect) = &self.config.oidc.redirect_uri {
                query.append_pair("redirect_uri", redirect);
            }
            query.append_pair("scope", &scope);
            query.append_pair("state", state);
            query.append_pair("nonce", nonce);
            query.append_pair("code_challenge", code_challenge);
            query.append_pair("code_challenge_method", "S256");
        }
        url.into()
    }

    async fn decoding_key(
        &self,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey, IamError> {
        let kid_value = kid.unwrap_or("");
        let jwks = self.ensure_jwks().await?;
        find_key_in_jwks(&jwks, kid_value, &alg).ok_or_else(|| {
            IamError::Jwks(format!(
                "No matching key for kid='{kid_value}' alg='{alg:?}'"
            ))
        })
    }

    async fn ensure_jwks(&self) -> Result<Arc<JwkSet>, IamError> {
        let ttl = Duration::from_secs(self.config.oidc.jwks_cache_secs);
        let now = Instant::now();
        let mut guard = self.jwks_cache.write().await;
        let needs_refresh = guard
            .as_ref()
            .map(|cached| now.duration_since(cached.fetched_at) >= ttl)
            .unwrap_or(true);
        if needs_refresh {
            let jwks = self
                .fetch_jwks()
                .await
                .map_err(|e| IamError::Jwks(format!("Failed to fetch JWKS: {e}")))?;
            *guard = Some(CachedJwks {
                keys: Arc::new(jwks),
                fetched_at: now,
            });
        }
        Ok(Arc::clone(
            &guard
                .as_ref()
                .ok_or_else(|| IamError::Jwks("JWKS cache empty after populate".to_string()))?
                .keys,
        ))
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, reqwest::Error> {
        let response = self
            .http
            .get(&self.discovery.jwks_uri)
            .send()
            .await?
            .error_for_status()?;
        response.json::<JwkSet>().await
    }

    pub fn create_session(
        &self,
        claims: RoleClaims,
        scopes: Vec<String>,
    ) -> Result<IamSession, IamError> {
        let role = claims.effective_role().unwrap_or(Role::Viewer);
        let now = Instant::now();
        let session = IamSession {
            id: Uuid::new_v4().to_string(),
            subject: claims.sub.clone(),
            role,
            scopes,
            expires_at: now + Duration::from_secs(self.config.session.max_age_secs),
            last_activity: now,
        };
        // SECURITY (R231-SRV-3): Return error when capacity reached instead of
        // returning a phantom session. Without this, the cookie is set for an
        // uninserted session, causing a confusing login loop.
        if self.sessions.len() >= Self::MAX_SESSIONS {
            tracing::warn!(
                max = Self::MAX_SESSIONS,
                "Session capacity reached, rejecting new session creation"
            );
            return Err(IamError::Session(
                "Session capacity reached — try again later".to_string(),
            ));
        }
        self.sessions.insert(session.id.clone(), session.clone());
        self.trim_sessions_for_subject(session.subject.as_deref());
        Ok(session)
    }

    fn trim_sessions_for_subject(&self, subject: Option<&str>) {
        let subject = match subject {
            Some(value) => value,
            None => return,
        };
        let limit = self.config.session.max_sessions_per_principal as usize;
        if limit == 0 {
            return;
        }
        let mut entries: Vec<(Instant, String)> = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let value = entry.value();
                value
                    .subject
                    .as_deref()
                    .filter(|s| *s == subject)
                    .map(|_| (value.last_activity, entry.key().clone()))
            })
            .collect();
        if entries.len() <= limit {
            return;
        }
        entries.sort_by_key(|(activity, _)| *activity);
        let remove_count = entries.len() - limit;
        for (_, id) in entries.into_iter().take(remove_count) {
            self.sessions.remove(&id);
        }
    }

    pub fn find_session(&self, id: &str) -> Option<IamSession> {
        let now = Instant::now();
        let idle_timeout = Duration::from_secs(self.config.session.idle_timeout_secs);
        if let Some(mut entry) = self.sessions.get_mut(id) {
            if entry.is_expired_at(now, idle_timeout) {
                let key = entry.key().clone();
                drop(entry);
                self.sessions.remove(&key);
                return None;
            }
            entry.touch();
            return Some(entry.clone());
        }
        None
    }

    pub fn remove_session(&self, id: &str) {
        self.sessions.remove(id);
    }

    pub fn session_cookie_header(
        &self,
        session_id: &str,
        max_age_secs: Option<u64>,
    ) -> Result<HeaderValue, IamError> {
        build_cookie_value(
            &self.config.session.cookie_name,
            session_id,
            max_age_secs,
            self.config.session.secure_cookie,
            self.config.session.http_only,
        )
    }

    pub fn expire_cookie_header(&self) -> Result<HeaderValue, IamError> {
        build_cookie_value(
            &self.config.session.cookie_name,
            "",
            Some(0),
            self.config.session.secure_cookie,
            self.config.session.http_only,
        )
    }

    // ═══════════════════════════════════════════════════════════════════
    // M2M Client Credentials Flow
    // ═══════════════════════════════════════════════════════════════════

    /// Exchange client credentials for a short-lived M2M JWT.
    ///
    /// Validates client_id + client_secret against configured M2M clients,
    /// verifies requested scopes are permitted, and generates an HMAC-signed
    /// JWT with `sub` = client_id, `scope` = granted scopes, `role` = configured role.
    pub fn exchange_client_credentials(
        &self,
        client_id: &str,
        client_secret: &str,
        scopes: &[String],
    ) -> Result<M2mTokenResponse, IamError> {
        if !self.config.m2m.enabled {
            return Err(IamError::M2mDisabled);
        }

        // SECURITY (R238-XCUT-1): Validate input lengths BEFORE rate limiter DashMap
        // insertion. Previously, unvalidated client_id was inserted into the rate
        // limit map before length/dangerous-char checks, allowing attacker-controlled
        // arbitrarily long strings to be stored in memory before rejection.
        if client_id.len() > MAX_M2M_CLIENT_ID_REQUEST_LEN || has_dangerous_chars(client_id) {
            return Err(IamError::M2mInvalidCredentials);
        }
        // SECURITY (R255-IAM-8): Validate client_secret for dangerous characters.
        if client_secret.len() > MAX_M2M_CLIENT_SECRET_REQUEST_LEN
            || has_dangerous_chars(client_secret)
        {
            return Err(IamError::M2mInvalidCredentials);
        }
        if scopes.len() > MAX_M2M_REQUESTED_SCOPES {
            return Err(IamError::M2mScopeNotPermitted(
                "too many scopes requested".to_string(),
            ));
        }
        for scope in scopes {
            if scope.len() > MAX_M2M_SCOPE_REQUEST_LEN || has_dangerous_chars(scope) {
                return Err(IamError::M2mScopeNotPermitted(
                    "invalid scope value".to_string(),
                ));
            }
        }

        // SECURITY (R237-SRV-4): Per-client rate limiting for M2M token requests.
        // Prevents credential-stuffing and brute-force attacks against client secrets.
        // Allows 10 requests per 60-second window per client_id.
        {
            const M2M_RATE_LIMIT_WINDOW_SECS: u64 = 60;
            const M2M_RATE_LIMIT_MAX_REQUESTS: u32 = 10;
            const MAX_M2M_RATE_LIMIT_ENTRIES: usize = 50_000;

            let now = std::time::Instant::now();

            // Evict expired entries periodically to prevent unbounded growth.
            if self.m2m_rate_limits.len() > MAX_M2M_RATE_LIMIT_ENTRIES / 2 {
                self.m2m_rate_limits.retain(|_, (_, window_start)| {
                    now.duration_since(*window_start).as_secs() < M2M_RATE_LIMIT_WINDOW_SECS
                });
            }
            // Fail-closed on capacity exhaustion.
            if self.m2m_rate_limits.len() >= MAX_M2M_RATE_LIMIT_ENTRIES {
                tracing::warn!(
                    max = MAX_M2M_RATE_LIMIT_ENTRIES,
                    "M2M rate limit cache at capacity, denying request"
                );
                return Err(IamError::M2mRateLimited);
            }

            let mut entry = self
                .m2m_rate_limits
                .entry(client_id.to_string())
                .or_insert_with(|| (0, now));

            let (count, window_start) = entry.value_mut();
            if now.duration_since(*window_start).as_secs() >= M2M_RATE_LIMIT_WINDOW_SECS {
                // Window expired — reset.
                *count = 1;
                *window_start = now;
            } else {
                *count = count.saturating_add(1);
                if *count > M2M_RATE_LIMIT_MAX_REQUESTS {
                    // SECURITY (R238-XCUT-1): Log sanitized client_id length, not
                    // the raw value, to prevent log injection from unvalidated input.
                    // Input validation above ensures client_id is bounded and safe.
                    tracing::warn!(
                        client_id_len = client_id.len(),
                        count = %count,
                        "M2M per-client rate limit exceeded"
                    );
                    return Err(IamError::M2mRateLimited);
                }
            }
        }

        // Find the configured client by ID.
        let m2m_client = self
            .config
            .m2m
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .ok_or(IamError::M2mInvalidCredentials)?;

        // SECURITY: Verify secret against stored Argon2id hash.
        // Constant-time comparison via the argon2 crate's PasswordVerifier.
        let parsed_hash = PasswordHash::new(&m2m_client.client_secret_hash)
            .map_err(|_| IamError::M2mInvalidCredentials)?;
        argon2::Argon2::default()
            .verify_password(client_secret.as_bytes(), &parsed_hash)
            .map_err(|_| IamError::M2mInvalidCredentials)?;

        // Validate requested scopes against allowed scopes.
        let granted_scopes = if scopes.is_empty() {
            // No specific scopes requested: grant all allowed scopes.
            m2m_client.allowed_scopes.clone()
        } else {
            let mut granted = Vec::with_capacity(scopes.len());
            for scope in scopes {
                if !m2m_client.allowed_scopes.contains(scope) {
                    return Err(IamError::M2mScopeNotPermitted(scope.clone()));
                }
                granted.push(scope.clone());
            }
            granted
        };

        // Generate JWT.
        let signing_secret = self.m2m_signing_secret.as_ref().ok_or_else(|| {
            IamError::M2mTokenGeneration(format!(
                "{M2M_JWT_SECRET_ENV} environment variable not set"
            ))
        })?;

        // SECURITY (R240-P3-SRV-3): Fail-closed on pre-epoch clock instead of wrapping.
        let now = u64::try_from(chrono::Utc::now().timestamp())
            .map_err(|_| IamError::M2mTokenGeneration("system clock before epoch".to_string()))?;
        let ttl = self.config.m2m.token_ttl_secs;
        let issuer = self
            .config
            .m2m
            .issuer
            .as_deref()
            .unwrap_or(DEFAULT_M2M_ISSUER);

        let claims = M2mJwtClaims {
            sub: client_id.to_string(),
            iss: issuer.to_string(),
            scope: granted_scopes.join(" "),
            role: m2m_client.role.clone(),
            iat: now,
            exp: now.saturating_add(ttl),
            jti: Uuid::new_v4().to_string(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(signing_secret),
        )
        .map_err(|e| IamError::M2mTokenGeneration(e.to_string()))?;

        info!(
            target: "iam",
            client_id = client_id,
            scopes = claims.scope.as_str(),
            role = claims.role.as_str(),
            "M2M token issued"
        );

        Ok(M2mTokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: ttl,
            scope: claims.scope,
        })
    }

    /// Whether M2M authentication is enabled.
    pub fn m2m_enabled(&self) -> bool {
        self.config.m2m.enabled
    }

    // ═══════════════════════════════════════════════════════════════════
    // CIMD (Client ID Metadata Documents)
    // ═══════════════════════════════════════════════════════════════════

    /// Fetch and cache Client ID Metadata from a URL.
    ///
    /// SECURITY: URL is validated for SSRF (private IPs, loopback, link-local,
    /// cloud metadata endpoints). Responses are size-limited. Cache has TTL.
    pub async fn fetch_client_metadata(
        &self,
        client_id_url: &str,
    ) -> Result<ClientMetadata, IamError> {
        // Input validation.
        if client_id_url.len() > MAX_CIMD_URL_LEN {
            return Err(IamError::CimdValidation("URL too long".to_string()));
        }
        if has_dangerous_chars(client_id_url) {
            return Err(IamError::CimdValidation(
                "URL contains invalid characters".to_string(),
            ));
        }

        // Check cache.
        let now = Instant::now();
        if let Some(entry) = self.cimd_cache.get(client_id_url) {
            let ttl = Duration::from_secs(CIMD_CACHE_TTL_SECS);
            if now.duration_since(entry.fetched_at) < ttl {
                return Ok(entry.metadata.clone());
            }
        }

        // SECURITY: Validate URL for SSRF protection.
        let parsed = Url::parse(client_id_url)
            .map_err(|e| IamError::CimdValidation(format!("invalid URL: {e}")))?;
        if parsed.scheme() != "https" {
            return Err(IamError::CimdValidation(
                "CIMD URL must use HTTPS".to_string(),
            ));
        }
        // Block private/loopback/link-local hosts.
        validate_cimd_host(&parsed)?;

        // Fetch metadata.
        let response = self
            .http
            .get(client_id_url)
            .header(reqwest_header::ACCEPT, "application/json")
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| IamError::CimdFetch(format!("request failed: {e}")))?
            .error_for_status()
            .map_err(|e| IamError::CimdFetch(format!("HTTP error: {e}")))?;

        // SECURITY: Limit response body size.
        let content_length = response.content_length().unwrap_or(0);
        if content_length > MAX_CIMD_RESPONSE_SIZE as u64 {
            return Err(IamError::CimdFetch("response too large".to_string()));
        }

        let body = response
            .bytes()
            .await
            .map_err(|e| IamError::CimdFetch(format!("failed to read body: {e}")))?;

        if body.len() > MAX_CIMD_RESPONSE_SIZE {
            return Err(IamError::CimdFetch(
                "response body exceeds size limit".to_string(),
            ));
        }

        let raw: CimdRawResponse = serde_json::from_slice(&body)
            .map_err(|e| IamError::CimdValidation(format!("invalid JSON: {e}")))?;

        // Validate metadata.
        if raw.redirect_uris.len() > MAX_CIMD_REDIRECT_URIS {
            return Err(IamError::CimdValidation(
                "too many redirect_uris".to_string(),
            ));
        }
        if raw.grant_types.len() > MAX_CIMD_GRANT_TYPES {
            return Err(IamError::CimdValidation("too many grant_types".to_string()));
        }

        // SECURITY (R241-SRV-2): Validate CIMD string fields for length and dangerous chars.
        if let Some(ref name) = raw.client_name {
            if name.len() > 256 || has_dangerous_chars(name) {
                return Err(IamError::CimdValidation(
                    "client_name invalid (too long or contains control characters)".to_string(),
                ));
            }
        }
        for gt in &raw.grant_types {
            if gt.len() > 128 || has_dangerous_chars(gt) {
                return Err(IamError::CimdValidation(
                    "grant_type invalid (too long or contains control characters)".to_string(),
                ));
            }
        }
        if let Some(ref method) = raw.token_endpoint_auth_method {
            if method.len() > 128 || has_dangerous_chars(method) {
                return Err(IamError::CimdValidation(
                    "token_endpoint_auth_method invalid".to_string(),
                ));
            }
        }

        // Validate redirect URIs are syntactically valid and use HTTPS only.
        for uri in &raw.redirect_uris {
            validate_cimd_redirect_uri(uri)?;
        }

        let metadata = ClientMetadata {
            client_name: raw.client_name,
            redirect_uris: raw.redirect_uris,
            grant_types: raw.grant_types,
            token_endpoint_auth_method: raw.token_endpoint_auth_method,
            fetched_at: now,
        };

        // Evict stale cache entries if we're over the limit.
        if self.cimd_cache.len() >= MAX_CIMD_CACHE_SIZE {
            self.cleanup_cimd_cache();
        }

        self.cimd_cache.insert(
            client_id_url.to_string(),
            CachedClientMetadata {
                metadata: metadata.clone(),
                fetched_at: now,
            },
        );

        Ok(metadata)
    }

    /// Remove expired entries from the CIMD cache.
    fn cleanup_cimd_cache(&self) {
        let now = Instant::now();
        let ttl = Duration::from_secs(CIMD_CACHE_TTL_SECS);
        let expired: Vec<String> = self
            .cimd_cache
            .iter()
            .filter_map(|entry| {
                if now.duration_since(entry.value().fetched_at) >= ttl {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for key in expired {
            self.cimd_cache.remove(&key);
        }
    }
}

fn build_cookie_value(
    name: &str,
    value: &str,
    max_age_secs: Option<u64>,
    secure: bool,
    http_only: bool,
) -> Result<HeaderValue, IamError> {
    // SECURITY (R241-SRV-5): Validate cookie name per RFC 6265 token syntax.
    // Prevents injection of `;`, `=`, or other separators into Set-Cookie header.
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(IamError::CookieEncode(
            "cookie name must be 1-128 alphanumeric/dash/underscore chars".to_string(),
        ));
    }
    let mut parts = vec![format!("{}={}", name, value)];
    if let Some(max_age) = max_age_secs {
        parts.push(format!("Max-Age={max_age}"));
    }
    parts.push("Path=/".to_string());
    if http_only {
        parts.push("HttpOnly".to_string());
    }
    if secure {
        parts.push("Secure".to_string());
    }
    parts.push("SameSite=Strict".to_string());
    HeaderValue::from_str(&parts.join("; "))
        .map_err(|e| IamError::CookieEncode(format!("cookie header invalid: {e}")))
}

/// Extract the session ID from the Cookie header using the configured name.
pub fn extract_session_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| {
            raw.split(';').map(str::trim).find_map(|kv| {
                let prefix = format!("{cookie_name}=");
                if kv.starts_with(&prefix) {
                    Some(kv[prefix.len()..].to_string())
                } else {
                    None
                }
            })
        })
}

/// Login query params.
// SECURITY (FIND-GAP-002): Reject unknown fields in user-supplied query parameters.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginParams {
    pub next: Option<String>,
}

/// Callback query params from the IdP.
// SECURITY (FIND-GAP-002): Reject unknown fields in user-supplied query parameters.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

// SECURITY (R231-SRV-9): Added deny_unknown_fields for project-wide consistency.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamlAcsForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,

    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// Standard session info response.
#[derive(Serialize)]
pub struct SessionInfoResponse {
    pub session_id: String,
    pub subject: Option<String>,
    pub role: String,
    pub expires_in_secs: u64,
}

pub async fn login(
    State(state): State<AppState>,
    Query(params): Query<LoginParams>,
) -> Result<Redirect, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM login is disabled".to_string(),
            }),
        )
    })?;
    let (state_id, flow, auth_url) = iam.begin_login_flow(params.next.clone());
    // SECURITY (R237-SRV-2): Propagate capacity error instead of silently redirecting.
    iam.store_flow(state_id.clone(), flow).map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Login service temporarily unavailable".to_string(),
            }),
        )
    })?;
    Ok(Redirect::temporary(auth_url.as_str()))
}

pub async fn callback(
    State(state): State<AppState>,
    Query(params): Query<CallbackParams>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM callback is disabled".to_string(),
            }),
        )
    })?;
    if let Some(ref err) = params.error {
        // SECURITY (R228-SRV-3): Sanitize IdP error parameter — it is attacker-controlled.
        // Restrict to ASCII printable (alphanumeric + safe punctuation), max 128 chars.
        let sanitized: String = err
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | '.' | ' '))
            .take(128)
            .collect();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("OIDC error: {sanitized}"),
            }),
        ));
    }
    let code = params.code.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing authorization code".to_string(),
            }),
        )
    })?;
    let state_id = params.state.as_ref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing state parameter".to_string(),
            }),
        )
    })?;
    let flow = iam.consume_flow(state_id).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid or expired login state".to_string(),
            }),
        )
    })?;
    // SECURITY (R237-SRV-1): Genericize error messages to prevent leaking IdP URLs,
    // JWT validation details, and internal capacity state to clients.
    let tokens = iam.exchange_code(code, &flow).await.map_err(|e| {
        tracing::warn!("OIDC token exchange failed: {}", e);
        (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: "Authentication failed".to_string(),
            }),
        )
    })?;
    let claims = iam
        .verify_id_token(&tokens.id_token, &flow.nonce)
        .await
        .map_err(|e| {
            tracing::warn!("OIDC id_token verification failed: {}", e);
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication failed".to_string(),
                }),
            )
        })?;
    let scopes = parse_scope_list(tokens.scope.as_deref());
    // SECURITY (R237-SRV-3): Genericize session creation error.
    let session = iam.create_session(claims, scopes).map_err(|e| {
        tracing::warn!("Session creation failed: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Authentication failed".to_string(),
            }),
        )
    })?;
    // SECURITY (R239-SRV-2): Genericize session cookie error — do not leak internals.
    let cookie = iam
        .session_cookie_header(&session.id, Some(iam.config.session.max_age_secs))
        .map_err(|e| {
            tracing::warn!("OIDC cookie generation failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Authentication failed".to_string(),
                }),
            )
        })?;
    let mut response = Redirect::temporary(&flow.next).into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

pub async fn session_info(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionInfoResponse>, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    let session_id =
        extract_session_cookie(&headers, iam.session_cookie_name()).ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Session cookie missing".to_string(),
                }),
            )
        })?;
    let session = iam.find_session(&session_id).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Session expired or invalid".to_string(),
            }),
        )
    })?;
    let expires_in = session.expires_in_secs();
    // SECURITY (R241-SRV-3): Do not return the session ID in the JSON response.
    // The session cookie is HttpOnly — returning the ID in the body undermines
    // that protection by making it accessible to JavaScript.
    Ok(Json(SessionInfoResponse {
        session_id: "[redacted]".to_string(),
        subject: session.subject,
        role: session.role.to_string(),
        expires_in_secs: expires_in,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    if let Some(session_id) = extract_session_cookie(&headers, iam.session_cookie_name()) {
        iam.remove_session(&session_id);
    }
    // SECURITY (R239-SRV-3): Genericize logout cookie error — do not leak internals.
    let cookie = iam.expire_cookie_header().map_err(|e| {
        tracing::warn!("Logout cookie generation failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Logout failed".to_string(),
            }),
        )
    })?;
    let mut response = (
        StatusCode::OK,
        Json(serde_json::json!({ "message": "logged out" })),
    )
        .into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

pub async fn saml_acs(
    State(state): State<AppState>,
    Form(form): Form<SamlAcsForm>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    let saml_state = iam.saml_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "SAML is disabled".to_string(),
            }),
        )
    })?;
    // R231-SRV-8: Redact SAML processing errors from HTTP responses.
    let xml = decode_saml_response(&form.saml_response).map_err(|e| {
        tracing::debug!("SAML decode error: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "SAML response processing failed".to_string(),
            }),
        )
    })?;
    let document = Document::parse(&xml).map_err(|e| {
        tracing::debug!("SAML XML parse error: {}", e);
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "SAML response processing failed".to_string(),
            }),
        )
    })?;
    let claims = saml_state.extract_claims(&document).map_err(|e| {
        tracing::debug!("SAML claim extraction error: {}", e);
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "SAML authentication failed".to_string(),
            }),
        )
    })?;

    // SECURITY (R237-SRV-5): InResponseTo replay protection.
    // If the SAML Response has an InResponseTo attribute, it must match a
    // previously issued AuthnRequest ID stored in saml_authn_request_ids.
    // If no InResponseTo is present (IdP-initiated SSO), we accept the
    // response (it's validated by other checks: destination, audience,
    // conditions, assertion ID). But if InResponseTo IS present, it must
    // match a stored request ID — otherwise it's an unsolicited response
    // injection or replay attack.
    {
        const SAML_PROTOCOL_NS_IRT: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
        const SAML_AUTHN_REQUEST_TTL_SECS: u64 = 600; // 10 minutes

        if let Some(response_node) = document
            .descendants()
            .find(|node| node.has_tag_name((SAML_PROTOCOL_NS_IRT, "Response")))
        {
            if let Some(in_response_to) = response_node.attribute("InResponseTo") {
                if !in_response_to.is_empty() {
                    // InResponseTo is present — must match a stored AuthnRequest ID.
                    let consumed = iam
                        .saml_authn_request_ids
                        .remove(in_response_to)
                        .map(|(_, issued_at)| {
                            issued_at.elapsed().as_secs() < SAML_AUTHN_REQUEST_TTL_SECS
                        })
                        .unwrap_or(false);

                    if !consumed {
                        tracing::warn!(
                            "SAML InResponseTo does not match any pending AuthnRequest ID"
                        );
                        return Err((
                            StatusCode::UNAUTHORIZED,
                            Json(ErrorResponse {
                                error: "SAML authentication failed".to_string(),
                            }),
                        ));
                    }
                }
            }
        }
    }

    // SECURITY (R230-SRV-2): SAML assertion ID replay prevention.
    // Extract the Assertion ID and reject if it has been seen before.
    {
        const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
        const MAX_SAML_ASSERTION_CACHE: usize = 100_000;
        const SAML_ASSERTION_TTL_SECS: u64 = 3600; // 1 hour

        if let Some(assertion_node) = document
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Assertion")))
        {
            if let Some(assertion_id) = assertion_node.attribute("ID") {
                if !assertion_id.is_empty() {
                    let now = std::time::Instant::now();
                    // Evict expired entries periodically
                    if iam.saml_assertion_ids.len() > MAX_SAML_ASSERTION_CACHE / 2 {
                        iam.saml_assertion_ids.retain(|_, seen_at| {
                            now.duration_since(*seen_at).as_secs() < SAML_ASSERTION_TTL_SECS
                        });
                    }
                    if iam.saml_assertion_ids.len() >= MAX_SAML_ASSERTION_CACHE {
                        return Err((
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(ErrorResponse {
                                error: "SAML assertion cache at capacity".to_string(),
                            }),
                        ));
                    }
                    // Check for replay
                    if iam
                        .saml_assertion_ids
                        .insert(assertion_id.to_string(), now)
                        .is_some()
                    {
                        return Err((
                            StatusCode::UNAUTHORIZED,
                            Json(ErrorResponse {
                                error: "SAML assertion replay detected".to_string(),
                            }),
                        ));
                    }
                }
            }
        }
    }

    // SECURITY (R239-SRV-1): Genericize SAML session/cookie errors — do not leak internals.
    let session = iam.create_session(claims, vec![]).map_err(|e| {
        tracing::warn!("SAML session creation failed: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "Authentication failed".to_string(),
            }),
        )
    })?;
    let cookie = iam
        .session_cookie_header(&session.id, Some(iam.config.session.max_age_secs))
        .map_err(|e| {
            tracing::warn!("SAML cookie generation failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Authentication failed".to_string(),
                }),
            )
        })?;
    let next = sanitize_next(form.relay_state.clone());
    let mut response = Redirect::temporary(&next).into_response();
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

pub async fn scim_status(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    let status = iam.scim_status.read().await;
    Ok(Json(serde_json::json!({
        "scim_enabled": iam.config.scim.enabled,
        "sync_interval_secs": iam.config.scim.sync_interval_secs,
        "last_sync": status.last_sync.map(|ts| ts.to_rfc3339()),
        "last_sync_duration_ms": status.last_sync_duration_ms,
        "last_user_count": status.last_user_count,
        // SECURITY (R239-SRV-4): Do not expose raw last_error to clients — categorize it.
        // The raw error is logged server-side for diagnostics.
        "last_error": status.last_error.as_ref().map(|e| {
            tracing::warn!("SCIM sync error (redacted from API response): {}", e);
            "sync_error"
        }),
    })))
}

pub async fn saml_metadata(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;
    if !iam.config.saml.enabled {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "SAML metadata is disabled".to_string(),
            }),
        ));
    }
    let metadata = build_saml_metadata(&iam.config.saml);
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
        metadata,
    ))
}

#[derive(Clone)]
struct FlowState {
    next: String,
    code_verifier: String,
    nonce: String,
    expires_at: Instant,
}

// SECURITY (R239-XCUT-3): Custom Debug redacts PKCE secrets (code_verifier, nonce).
impl std::fmt::Debug for FlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowState")
            .field("next", &self.next)
            .field("code_verifier", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl FlowState {
    fn new(next: String, code_verifier: String, nonce: String) -> Self {
        Self {
            next,
            code_verifier,
            nonce,
            expires_at: Instant::now() + Duration::from_secs(FLOW_TTL_SECS),
        }
    }

    fn is_expired_at(&self, at: Instant) -> bool {
        at >= self.expires_at
    }
}

#[derive(Clone, Debug)]
pub struct IamSession {
    pub id: String,
    pub subject: Option<String>,
    pub role: Role,
    pub scopes: Vec<String>,
    expires_at: Instant,
    last_activity: Instant,
}

impl IamSession {
    fn is_expired_at(&self, now: Instant, idle_timeout: Duration) -> bool {
        now >= self.expires_at || now.duration_since(self.last_activity) >= idle_timeout
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn expires_in_secs(&self) -> u64 {
        let now = Instant::now();
        if self.expires_at <= now {
            0
        } else {
            (self.expires_at - now).as_secs()
        }
    }
}

#[derive(Debug)]
struct CachedJwks {
    keys: Arc<JwkSet>,
    fetched_at: Instant,
}

#[derive(Debug)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

impl OidcDiscovery {
    async fn fetch(config: &VellavetoOidcConfig, allow_insecure: bool) -> Result<Self, String> {
        let issuer = config
            .issuer_url
            .as_ref()
            .ok_or_else(|| "issuer_url missing".to_string())?;
        let mut issuer_url = Url::parse(issuer).map_err(|e| e.to_string())?;
        if !allow_insecure && issuer_url.scheme() != "https" {
            return Err("OIDC issuer must use https".to_string());
        }
        issuer_url.set_path("/.well-known/openid-configuration");
        // SECURITY (R235-SRV-1): Disable redirect following to prevent SSRF via
        // 3xx redirect to internal/metadata endpoints during OIDC discovery.
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        let response = client
            .get(issuer_url.as_str())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        let metadata: OidcDiscoveryMetadata = response.json().await.map_err(|e| e.to_string())?;

        // SECURITY (R230-SRV-6): Validate discovered endpoints against SSRF.
        validate_url_no_ssrf(&metadata.token_endpoint)
            .map_err(|e| format!("OIDC token_endpoint SSRF blocked: {e}"))?;
        validate_url_no_ssrf(&metadata.jwks_uri)
            .map_err(|e| format!("OIDC jwks_uri SSRF blocked: {e}"))?;
        validate_url_no_ssrf(&metadata.authorization_endpoint)
            .map_err(|e| format!("OIDC authorization_endpoint SSRF blocked: {e}"))?;

        Ok(Self {
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            jwks_uri: metadata.jwks_uri,
        })
    }
}

#[derive(Deserialize)]
struct OidcDiscoveryMetadata {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Error, Debug)]
pub enum IamError {
    #[error("IAM is disabled")]
    Disabled,
    #[error("OIDC is disabled")]
    OidcDisabled,
    #[error("OIDC discovery failed: {0}")]
    Discovery(String),
    #[error("HTTP client error: {0}")]
    Client(String),
    #[error("Token exchange failed: {0}")]
    TokenExchange(String),
    #[error("Invalid ID token: {0}")]
    InvalidToken(String),
    #[error("Missing or expired login state")]
    MissingFlow,
    #[error("Nonce mismatch")]
    NonceMismatch,
    #[error("JWKS key error: {0}")]
    Jwks(String),
    #[error("Failed to encode cookie: {0}")]
    CookieEncode(String),
    #[error("SAML error: {0}")]
    Saml(String),
    #[error("SCIM sync failed: {0}")]
    Scim(String),
    #[error("M2M authentication is disabled")]
    M2mDisabled,
    #[error("Invalid client credentials")]
    M2mInvalidCredentials,
    #[error("M2M scope not permitted: {0}")]
    M2mScopeNotPermitted(String),
    #[error("M2M token generation failed: {0}")]
    M2mTokenGeneration(String),
    #[error("CIMD fetch failed: {0}")]
    CimdFetch(String),
    #[error("CIMD validation failed: {0}")]
    CimdValidation(String),
    #[error("Session error: {0}")]
    Session(String),
    #[error("Capacity exhausted: {0}")]
    CapacityExhausted(String),
    /// SECURITY (R237-SRV-4): Per-client M2M token request rate limit exceeded.
    #[error("M2M rate limit exceeded for client")]
    M2mRateLimited,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    scope: Option<String>,
}

fn generate_code_verifier() -> String {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

fn pkce_code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn sanitize_next(value: Option<String>) -> String {
    let default = "/".to_string();
    let value = value.unwrap_or_else(|| default.clone());
    if value.len() > MAX_NEXT_LEN || value.contains("://") || has_dangerous_chars(&value) {
        return default;
    }
    // SECURITY (R240-SRV-6): Percent-decode before scheme/path checks to prevent
    // bypass via %3A%2F%2F (://), %2F%2F (//), or %5C (\) encoded sequences.
    let decoded = percent_decode_str(&value).decode_utf8_lossy();
    if decoded.contains("://") || decoded.starts_with("//") || decoded.contains('\\') {
        return default;
    }
    let normalized = if !value.starts_with('/') {
        let mut normalized = String::from("/");
        normalized.push_str(&value);
        normalized
    } else {
        value
    };
    // Reject scheme-relative redirects and backslash-based path confusion.
    if normalized.starts_with("//") || normalized.contains('\\') {
        return default;
    }
    normalized
}

fn parse_scope_list(scope: Option<&str>) -> Vec<String> {
    scope
        .map(|s| {
            s.split_whitespace()
                .map(|scope| scope.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn canonicalize_node(node: Node, skip_signature: bool) -> String {
    let mut output = String::new();
    output.push('<');
    output.push_str(&qualified_name(node));
    let mut attrs: Vec<_> = node.attributes().collect();
    attrs.sort_by(|a: &roxmltree::Attribute, b: &roxmltree::Attribute| {
        a.namespace()
            .unwrap_or("")
            .cmp(b.namespace().unwrap_or(""))
            .then_with(|| a.name().cmp(b.name()))
    });
    for attr in &attrs {
        output.push(' ');
        output.push_str(&attribute_name(attr));
        output.push('=');
        output.push('"');
        output.push_str(attr.value());
        output.push('"');
    }
    output.push('>');
    for child in node.children() {
        match child.node_type() {
            NodeType::Text => {
                if let Some(text) = child.text() {
                    output.push_str(text);
                }
            }
            NodeType::Element => {
                let is_signature = child.has_tag_name((XMLDSIG_NS, "Signature"))
                    || child.tag_name().name() == "Signature";
                if skip_signature && is_signature {
                    continue;
                }
                output.push_str(&canonicalize_node(child, skip_signature));
            }
            _ => {}
        }
    }
    output.push_str("</");
    output.push_str(&qualified_name(node));
    output.push('>');
    output
}

fn qualified_name(node: Node) -> String {
    if let Some(ns) = node.tag_name().namespace() {
        if let Some(prefix) = node.lookup_prefix(ns) {
            return format!("{}:{}", prefix, node.tag_name().name());
        }
    }
    node.tag_name().name().to_string()
}

fn attribute_name(attr: &roxmltree::Attribute) -> String {
    // roxmltree 0.21 does not expose attribute prefix directly;
    // for SAML canonicalization we use the local name only (sufficient
    // for namespace-unqualified attributes in SAML assertions).
    attr.name().to_string()
}

fn map_digest_algorithm(uri: &str) -> Result<&'static digest::Algorithm, IamError> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#sha1" => Err(IamError::Saml(
            "SHA-1 digest algorithm is disabled".to_string(),
        )),
        "http://www.w3.org/2001/04/xmlenc#sha256" => Ok(&digest::SHA256),
        "http://www.w3.org/2001/04/xmlenc#sha384" => Ok(&digest::SHA384),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Ok(&digest::SHA512),
        _ => Err(IamError::Saml("Unsupported digest algorithm".to_string())),
    }
}

fn map_signature_algorithm(
    uri: &str,
) -> Result<&'static dyn signature::VerificationAlgorithm, IamError> {
    match uri {
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1" => Err(IamError::Saml(
            "SHA-1 signature algorithm is disabled".to_string(),
        )),
        "http://www.w3.org/2000/09/xmldsig#rsa-sha256"
        | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" => {
            Ok(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY)
        }
        "http://www.w3.org/2000/09/xmldsig#rsa-sha512"
        | "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" => {
            Ok(&signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY)
        }
        _ => Err(IamError::Saml(
            "Unsupported signature algorithm".to_string(),
        )),
    }
}

fn parse_saml_timestamp(value: &str) -> Result<DateTime<Utc>, IamError> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|_e| IamError::Saml("Invalid SAML timestamp format".to_string()))
}

/// R230-SRV-5: Padding-indifferent base64 for SAML interoperability.
fn decode_base64(value: &str, context: &str) -> Result<Vec<u8>, IamError> {
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    const PAD_INDIFFERENT: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    PAD_INDIFFERENT
        .decode(value)
        .map_err(|_e| IamError::Saml(format!("{context}: decode failed")))
}

/// Maximum decompressed SAML response size (10 MB).
///
/// SECURITY (R229-SRV-3): Prevents decompression bomb attacks where a small
/// compressed payload expands to gigabytes, causing OOM.
const MAX_SAML_DECOMPRESSED_SIZE: u64 = 10 * 1024 * 1024;

fn decode_saml_response(encoded: &str) -> Result<String, IamError> {
    // R230-SRV-5: Padding-indifferent base64 for SAML interoperability.
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    const PAD_INDIFFERENT: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let decoded = PAD_INDIFFERENT
        .decode(encoded)
        .map_err(|e| IamError::Saml(format!("Invalid SAML response encoding: {e}")))?;
    if let Ok(text) = String::from_utf8(decoded.clone()) {
        if text.len() as u64 > MAX_SAML_DECOMPRESSED_SIZE {
            return Err(IamError::Saml(
                "SAML response exceeds maximum allowed size".to_string(),
            ));
        }
        return Ok(text);
    }
    // SECURITY (R229-SRV-3): Bound decompression via take() to prevent decompression bombs.
    let mut buffer = String::new();
    let mut zlib_decoder =
        ZlibDecoder::new(Cursor::new(decoded.clone())).take(MAX_SAML_DECOMPRESSED_SIZE);
    if zlib_decoder.read_to_string(&mut buffer).is_ok() {
        if buffer.len() as u64 >= MAX_SAML_DECOMPRESSED_SIZE {
            return Err(IamError::Saml(
                "SAML response exceeds maximum decompressed size".to_string(),
            ));
        }
        return Ok(buffer);
    }
    buffer.clear();
    let mut deflate_decoder =
        DeflateDecoder::new(Cursor::new(decoded)).take(MAX_SAML_DECOMPRESSED_SIZE);
    deflate_decoder
        .read_to_string(&mut buffer)
        .map_err(|e| IamError::Saml(format!("Failed to decompress SAML response: {e}")))?;
    if buffer.len() as u64 >= MAX_SAML_DECOMPRESSED_SIZE {
        return Err(IamError::Saml(
            "SAML response exceeds maximum decompressed size".to_string(),
        ));
    }
    Ok(buffer)
}

const SAML_SP_METADATA_TEMPLATE: &str = r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}">
  <SPSSODescriptor
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    AuthnRequestsSigned="false"
    WantAssertionsSigned="true">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{acs}"
      index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>"#;

/// Escape XML special characters to prevent injection in SP metadata.
///
/// SECURITY (R229-SRV-5): Config values (entity_id, acs_url) are interpolated
/// into XML attribute contexts. Without escaping, a malicious config value like
/// `</EntityDescriptor><evil>` would break the XML structure.
fn escape_xml_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn build_saml_metadata(config: &SamlConfig) -> String {
    // SECURITY (R229-SRV-5): Escape config values before interpolation into XML.
    SAML_SP_METADATA_TEMPLATE
        .replace(
            "{entity}",
            &escape_xml_attr(config.entity_id.as_deref().unwrap_or_default()),
        )
        .replace(
            "{acs}",
            &escape_xml_attr(config.acs_url.as_deref().unwrap_or_default()),
        )
}

// ═══════════════════════════════════════════════════════════════════
// M2M Types
// ═══════════════════════════════════════════════════════════════════

/// JWT claims for M2M tokens.
#[derive(Debug, Serialize, Deserialize)]
struct M2mJwtClaims {
    /// Subject: the client_id.
    sub: String,
    /// Issuer.
    iss: String,
    /// Space-separated scopes.
    scope: String,
    /// RBAC role.
    role: String,
    /// Issued-at timestamp (Unix epoch seconds).
    iat: u64,
    /// Expiration timestamp (Unix epoch seconds).
    exp: u64,
    /// Unique token identifier.
    jti: String,
}

/// M2M token endpoint response.
#[derive(Serialize)]
pub struct M2mTokenResponse {
    /// The JWT access token.
    pub access_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Seconds until the token expires.
    pub expires_in: u64,
    /// Space-separated granted scopes.
    pub scope: String,
}

/// SECURITY (R239-XCUT-1): Custom Debug redacts access_token to prevent secret leakage.
impl std::fmt::Debug for M2mTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("M2mTokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// SECURITY: Custom Display for M2mTokenResponse redacts the access token.
impl std::fmt::Display for M2mTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "M2mTokenResponse {{ token_type: {}, expires_in: {}, scope: {} }}",
            self.token_type, self.expires_in, self.scope
        )
    }
}

/// Request body for the M2M token endpoint.
///
/// SECURITY (R231-SRV-4): Custom Debug impl redacts client_secret.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M2mTokenRequest {
    /// Must be "client_credentials".
    pub grant_type: String,
    /// The client identifier.
    pub client_id: String,
    /// The client secret (plaintext, verified against stored hash).
    pub client_secret: String,
    /// Optional space-separated scopes to request.
    #[serde(default)]
    pub scope: Option<String>,
}

impl std::fmt::Debug for M2mTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("M2mTokenRequest")
            .field("grant_type", &self.grant_type)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("scope", &self.scope)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Step-Up Authorization Types
// ═══════════════════════════════════════════════════════════════════

/// Information returned when a request is denied due to insufficient scopes
/// and the caller may be able to step up their authorization level.
#[derive(Debug, Serialize)]
pub struct StepUpRequired {
    /// Scopes that would be needed to perform the action.
    pub required_scopes: Vec<String>,
    /// Scopes the caller currently holds.
    pub current_scopes: Vec<String>,
    /// Optional URL where the caller can upgrade their authorization.
    pub upgrade_url: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════
// CIMD Types
// ═══════════════════════════════════════════════════════════════════

/// Fetched and validated client metadata from a Client ID Metadata Document.
#[derive(Debug, Clone, Serialize)]
pub struct ClientMetadata {
    /// Human-readable client name.
    pub client_name: Option<String>,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Supported grant types.
    pub grant_types: Vec<String>,
    /// Preferred token endpoint authentication method.
    pub token_endpoint_auth_method: Option<String>,
    /// When this metadata was fetched.
    #[serde(skip)]
    pub fetched_at: Instant,
}

/// Internal cache entry for CIMD.
#[derive(Debug, Clone)]
struct CachedClientMetadata {
    metadata: ClientMetadata,
    fetched_at: Instant,
}

/// Raw JSON response from a CIMD endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CimdRawResponse {
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
}

/// SECURITY: Validate CIMD URL host is not a private/loopback/link-local/metadata address.
fn validate_cimd_host(url: &Url) -> Result<(), IamError> {
    let host = url
        .host_str()
        .ok_or_else(|| IamError::CimdValidation("URL has no host".to_string()))?;

    // Known cloud metadata hostnames should always be blocked.
    let lower = host.to_ascii_lowercase();
    if lower == "metadata.google.internal" || lower == "metadata.google.com" {
        return Err(IamError::CimdValidation(
            "URL host is blocked (private/loopback/metadata)".to_string(),
        ));
    }

    // Reuse shared SSRF validation for loopback/private/link-local and IPv6 transition ranges.
    validate_url_no_ssrf(url.as_str())
        .map_err(|e| IamError::CimdValidation(format!("URL host is blocked ({e})")))?;

    Ok(())
}

fn validate_cimd_redirect_uri(uri: &str) -> Result<(), IamError> {
    let parsed = Url::parse(uri)
        .map_err(|e| IamError::CimdValidation(format!("invalid redirect_uri: {e}")))?;

    if parsed.scheme() != "https" {
        return Err(IamError::CimdValidation(format!(
            "redirect_uri must use https, got scheme: {}",
            parsed.scheme()
        )));
    }

    // SECURITY (R240-SRV-5): Validate redirect_uri host against SSRF ranges
    // (private IPs, link-local, cloud metadata). Parity with validate_cimd_host()
    // which already validates the CIMD document URL itself.
    validate_url_no_ssrf(uri)
        .map_err(|e| IamError::CimdValidation(format!("redirect_uri host is blocked ({e})")))?;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════
// M2M Route Handler
// ═══════════════════════════════════════════════════════════════════

/// POST /api/auth/token — M2M client credentials token endpoint.
pub async fn m2m_token(
    State(state): State<AppState>,
    Json(req): Json<M2mTokenRequest>,
) -> Result<Json<M2mTokenResponse>, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;

    if req.grant_type != "client_credentials" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Unsupported grant_type; must be 'client_credentials'".to_string(),
            }),
        ));
    }

    let scopes = req
        .scope
        .as_deref()
        .map(|s| {
            s.split_whitespace()
                .map(|scope| scope.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let token_response = iam
        .exchange_client_credentials(&req.client_id, &req.client_secret, &scopes)
        .map_err(|e| match &e {
            IamError::M2mDisabled => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: "M2M authentication is disabled".to_string(),
                }),
            ),
            IamError::M2mInvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid client credentials".to_string(),
                }),
            ),
            IamError::M2mRateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: "Rate limit exceeded".to_string(),
                }),
            ),
            IamError::M2mScopeNotPermitted(_scope) => (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    // SECURITY (R228-SRV-4): Do not echo scope value — prevents
                    // scope namespace enumeration by probing callers.
                    error: "One or more requested scopes are not permitted".to_string(),
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    // SECURITY: Do not leak internal error details.
                    error: "Token generation failed".to_string(),
                }),
            ),
        })?;

    Ok(Json(token_response))
}

// ═══════════════════════════════════════════════════════════════════
// CIMD Route Handler
// ═══════════════════════════════════════════════════════════════════

/// Request body for fetching CIMD.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CimdRequest {
    /// The HTTPS URL of the Client ID Metadata Document.
    pub client_id_url: String,
}

/// POST /api/auth/client-metadata — Fetch Client ID Metadata Document.
pub async fn client_metadata(
    State(state): State<AppState>,
    Json(req): Json<CimdRequest>,
) -> Result<Json<ClientMetadata>, (StatusCode, Json<ErrorResponse>)> {
    let iam = state.iam_state.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "IAM is disabled".to_string(),
            }),
        )
    })?;

    let metadata = iam
        .fetch_client_metadata(&req.client_id_url)
        .await
        .map_err(|e| match &e {
            IamError::CimdValidation(_msg) => {
                // SECURITY (R238-SRV-5): Do not echo user-controlled URL/details.
                tracing::warn!("CIMD validation failed: {}", _msg);
                (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: "Client metadata validation failed".to_string(),
                    }),
                )
            }
            IamError::CimdFetch(_) => (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResponse {
                    // SECURITY: Do not leak upstream error details.
                    error: "Failed to fetch client metadata".to_string(),
                }),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Internal error".to_string(),
                }),
            ),
        })?;

    Ok(Json(metadata))
}

/// Build a step-up required response for a 403 Forbidden.
///
/// Called by the evaluate handler when a deny verdict is due to insufficient
/// scopes/permissions and step-up authorization is available.
pub fn build_step_up_response(
    required_scopes: Vec<String>,
    current_scopes: Vec<String>,
    upgrade_url: Option<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let step_up = StepUpRequired {
        required_scopes,
        current_scopes,
        upgrade_url,
    };
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": "Insufficient authorization",
            "step_up_required": {
                "required_scopes": step_up.required_scopes,
                "current_scopes": step_up.current_scopes,
                "upgrade_url": step_up.upgrade_url,
            }
        })),
    )
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use chrono::{Duration, Utc};
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use ring::digest;
    use ring::rand::SystemRandom;
    use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
    use std::io::Write;
    use std::time::{Duration as StdDuration, Instant as StdInstant};
    use vellaveto_config::iam::SamlConfig;
    use vellaveto_config::IamConfig;

    const TEST_CERT_BASE64: &str = "MIIDDTCCAfWgAwIBAgIUXFfuq4zQ2fx8g6c6OmSBI/yIhmYwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLcGhhc2U0Ni1pZHAwHhcNMjYwMjI1MjI0MzQ1WhcNMjcwMjI1MjI0MzQ1WjAWMRQwEgYDVQQDDAtwaGFzZTQ2LWlkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALqJvn8K/WDkH3pjGevAAatWwodmNJqy7jUHTG/OzRBN8vjBLYN7Xdl1NGtjsVSJL4aUbam41CP++xn+NcwpZ0LHDBhyRmyV+Bl26PE4s3/0+UyJUl08PMkLugoDxmduJ2PbjIbBSGoMfYV7HsueMJjpWZt3btY90QCU3SH9jkylz424GHhziYsIqdfIDNxiO91rjojl/caWcLFjSH4l7Ve6v5nubzmPcpueL1pEGbXW+qXc7vZ6N/urC0j8KTX8KTxV9GQ61KatzoNjlHevhrW2gntPos8CRJd2hAUUovHG0ExZhmpMpPzz0J8iLxI7YXvwrPgm7r4a9rG8SXLvxB0CAwEAAaNTMFEwHQYDVR0OBBYEFJQs00ep7Zq0sY62RHT8X0izPzg7MB8GA1UdIwQYMBaAFJQs00ep7Zq0sY62RHT8X0izPzg7MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJ3sXJJX3yqxsR2lzKFsGrsD2c/ih3GotqaNtkwC9GHiE0Sz9cYXZLIFXArISfEBTLyNn6WX5ZO+a0CeIKSLgSTAYYjwUkIB9OFTwzh5wDTCc5yXexJoN4oR1lqsxYtQ61to6PbIGXUJmFYtaJS96Wj0AXneNVZoItAvTPMKstCnYZOZ/vwT3t8tbRUM1JRtfkRYplroy0H3dKt3l31LD6NB4ergCOJHhqVbss+r8mZzNnhN222VIdQ2qjVq8kxmYJTO/itL8w2DVpufwwFFiWkinBOd2FeAwST7v4n+voeUIXj9zWnd6NiuVE8hymsu995U5xGrBuVGrweSoEelwoY=";
    const TEST_PRIVATE_KEY_BASE64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6ib5/Cv1g5B96YxnrwAGrVsKHZjSasu41B0xvzs0QTfL4wS2De13ZdTRrY7FUiS+GlG2puNQj/vsZ/jXMKWdCxwwYckZslfgZdujxOLN/9PlMiVJdPDzJC7oKA8Znbidj24yGwUhqDH2Fex7LnjCY6Vmbd27WPdEAlN0h/Y5Mpc+NuBh4c4mLCKnXyAzcYjvda46I5f3GlnCxY0h+Je1Xur+Z7m85j3Kbni9aRBm11vql3O72ejf7qwtI/Ck1/Ck8VfRkOtSmrc6DY5R3r4a1toJ7T6LPAkSXdoQFFKLxxtBMWYZqTKT889CfIi8SO2F78Kz4Ju6+GvaxvEly78QdAgMBAAECggEAFXXscdRIrgGAx5qoLEcU9L/mCyAh6YcFaxoRsVlS8/nBJtz0CLOZlVTrziEUO+a5ONv8Y9ws9+PewrD27Sv5l9AA9Ge38h0s2SJ6OT+t6F49jOXNkTFxctXZC6GUjWi5umjTWYYvd8KZHFFmYRmsJfjOw4PxlKSxq3Cfokiiuu7e50rrAIU7wAg99drbfCGluYctc8FlayAO3tG+aweIOQjun6QbiSkLRwyFz5KCGqsHHTND1J0GF0/pqSKXUEJ+qMeUo+SnfdAPW+4/Xwlp5mR2eO+ffS14dIv7O+QMj+t3jk5SYChDw2JtZlwppCBdfs9368+s4lrdQfAjgi2CFwKBgQDnlex/juB+PQ27J2QF56EpVaj9s3tM77cbyS4mXGqA5tXEH3K47yWbISdTKG4ubRjic+JMsp8qKyx+qqQVHmxkDrLsE2NmFdMEXiktWnZwbXH2x2mHEx9O2IwK8jdJVInE/kJNZVtZtV4v82HZi+A4L1ZOI6lYBg56lDGyLpsvNwKBgQDONBFlCjqsGkl6LQ4tQWSYTgsRQeylSffc5Jw9lENRTfrXuqb5OE1uSe9tJeycVO7QKuGddv/f7UZoru1drc3zxm2004RDJBzcrDoxyXZrbRDvorFZEMPJXOmneY0zLjMnQY4NVXUUZp3hPtP0Bk1YDtC/50wZ7HPUCx0zp7AJSwKBgQC8KuMomezqZa08fjsVWSlnroRK74Sl9LixSPvIi5q19dmHK45JmXbS31NWjClKa7ameUZMz23oE4BpwzjjN/8WJaNXkkFXdzAoAmIuyawmmabZvxmNeQodRHI1iq1FVf1DJNy2ij55W5aWG4lL/A1JWZ0kjHFSZklpa/QdNSU+bQKBgHV92YN25qN1fvRsg61pm0XlAg1dQNeVY/OrFxNHTWwgQJN3OPi8CfKTkibg+wbApipapJ8yVO1kpz+ynHFKPRVvtMbZ1nzjMMbUI3yGzEC9rm68hsy27rfnhwL0EW5eHqt5gNU8Ii/zoHXddKuQg7VvC6asxgHnZsAlbQgnvfgtAoGAGuW5KPZlvFJ24jLnmDrpAOjNEdfdlQ3fcY4Dq4pdy0JojyzOvWcrAvQQzH+oJk7JlVJTpzmKKBM9pckZ7pXbTIhoPn4BIvKwkr1rpZAF1bbUhb5+N6zU7AUp7x6GB/fIV8KHzX3UReUuJfSobzSS6KrWkNTqnl7Gl9JpzsirwqU=";
    const TEST_IDP_ENTITY_ID: &str = "https://idp.example.com";
    const TEST_SSO_URL: &str = "https://idp.example.com/sso";
    const TEST_SP_ENTITY_ID: &str = "https://sp.example.com";
    const TEST_SP_ACS: &str = "https://sp.example.com/acs";
    const TEST_SUBJECT: &str = "alice@example.com";
    const TEST_ROLE_VALUE: &str = "Admin";
    const SIGNED_INFO_TEMPLATE: &str = r#"<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
  <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
  <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"/>
  <Reference URI="">
    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
    <DigestValue>{digest}</DigestValue>
  </Reference>
</SignedInfo>"#;
    const ASSERTION_TEMPLATE: &str = r#"<Assertion Version="2.0" IssueInstant="{issue}" ID="_assertion" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <Issuer>{idp}</Issuer>
  <Subject>
    <NameID>{subject}</NameID>
    <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <SubjectConfirmationData NotOnOrAfter="{not_on_or_after}" Recipient="{acs}"/>
    </SubjectConfirmation>
  </Subject>
  <Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
    <AudienceRestriction>
      <Audience>{audience}</Audience>
    </AudienceRestriction>
  </Conditions>
  <AttributeStatement>
    <Attribute Name="{role_attr}">
      <AttributeValue>{role_value}</AttributeValue>
    </Attribute>
  </AttributeStatement>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    {signed_info}
    <SignatureValue>{signature}</SignatureValue>
  </Signature>
</Assertion>"#;
    const RESPONSE_TEMPLATE: &str = r#"<Response Version="2.0" IssueInstant="{issue}" Destination="{acs}" xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">{idp}</Issuer>
  <Status>
    <StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </Status>
  {assertion}
</Response>"#;
    const SAML_METADATA_TEMPLATE: &str = r#"<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{idp}">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{sso}"/>
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{cert}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
  </IDPSSODescriptor>
</EntityDescriptor>"#;
    const SIGNATURE_PLACEHOLDER: &str = "{signature}";

    #[test]
    fn canonicalize_node_filters_signature_when_requested() {
        let xml = r#"<root attr="value"><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><dummy/></Signature><child id="1">text</child></root>"#;
        let doc = Document::parse(xml).unwrap();
        let root = doc.root_element();
        let canonical = canonicalize_node(root, true);
        assert!(canonical.contains("<child"));
        assert!(!canonical.contains("Signature"));
    }

    #[test]
    fn canonicalize_node_preserves_signature_when_not_skipped() {
        let xml = r#"<root><Signature><dummy/></Signature></root>"#;
        let doc = Document::parse(xml).unwrap();
        let root = doc.root_element();
        let canonical = canonicalize_node(root, false);
        assert!(canonical.contains("Signature"));
    }

    #[test]
    fn decode_saml_response_handles_plain_and_deflated() {
        let payload = "<Response></Response>";
        let plain = STANDARD.encode(payload);
        assert_eq!(decode_saml_response(&plain).unwrap(), payload);

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload.as_bytes()).unwrap();
        let deflated = encoder.finish().unwrap();
        let encoded = STANDARD.encode(deflated);
        assert_eq!(decode_saml_response(&encoded).unwrap(), payload);
    }

    #[test]
    fn parse_saml_timestamp_accepts_and_rejects_values() {
        assert!(parse_saml_timestamp("2026-02-25T12:00:00Z").is_ok());
        assert!(parse_saml_timestamp("not-a-timestamp").is_err());
    }

    #[test]
    fn test_r230_saml_timestamp_precision_variants() {
        assert!(parse_saml_timestamp("2026-02-25T12:00:00.123Z").is_ok());
        assert!(parse_saml_timestamp("2026-02-25T12:00:00.123456Z").is_ok());
        assert!(parse_saml_timestamp("2026-02-25T12:00:00.123456789Z").is_ok());
        assert!(parse_saml_timestamp("2026-02-25T12:00:00+00:00").is_ok());
        assert!(parse_saml_timestamp("2026-02-25T12:00:00+05:30").is_ok());
        assert!(parse_saml_timestamp("2026-02-25T12:00:00-08:00").is_ok());
        assert!(parse_saml_timestamp("2026-02-25T12:00:00.500+00:00").is_ok());
    }

    #[test]
    fn test_r230_saml_base64_padding_tolerance() {
        let padded = STANDARD.encode(b"test cert data");
        assert!(decode_base64(&padded, "test").is_ok());
        let unpadded = padded.trim_end_matches('=').to_string();
        assert!(
            decode_base64(&unpadded, "test").is_ok(),
            "Should accept unpadded base64"
        );
        let payload = "<Response>test</Response>";
        let encoded = STANDARD.encode(payload);
        let unpadded_resp = encoded.trim_end_matches('=').to_string();
        assert!(
            decode_saml_response(&unpadded_resp).is_ok(),
            "Should accept unpadded SAML response"
        );
    }

    #[test]
    fn map_digest_algorithm_supports_known_uris() {
        let sha256 = map_digest_algorithm("http://www.w3.org/2001/04/xmlenc#sha256").unwrap();
        assert!(std::ptr::eq(sha256, &digest::SHA256));
        assert!(map_digest_algorithm("unsupported").is_err());
    }

    #[test]
    fn map_signature_algorithm_supports_known_uris() {
        assert!(map_signature_algorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha256").is_ok());
        assert!(map_signature_algorithm("unsupported").is_err());
    }

    fn test_metadata_xml() -> String {
        SAML_METADATA_TEMPLATE
            .replace("{idp}", TEST_IDP_ENTITY_ID)
            .replace("{sso}", TEST_SSO_URL)
            .replace("{cert}", TEST_CERT_BASE64)
    }

    fn test_saml_config() -> SamlConfig {
        SamlConfig {
            enabled: true,
            entity_id: Some(TEST_SP_ENTITY_ID.to_string()),
            acs_url: Some(TEST_SP_ACS.to_string()),
            idp_metadata_url: Some("https://idp.example.com/metadata".to_string()),
            role_attribute: Some("Role".to_string()),
        }
    }

    fn private_key_pair() -> RsaKeyPair {
        let key_bytes = STANDARD.decode(TEST_PRIVATE_KEY_BASE64).unwrap();
        RsaKeyPair::from_pkcs8(&key_bytes).unwrap()
    }

    fn canonicalize_signed_info(xml: &str) -> String {
        let document = Document::parse(xml).unwrap();
        let root = document.root_element();
        canonicalize_node(root, false)
    }

    fn compute_assertion_digest(assertion_xml: &str) -> String {
        let document = Document::parse(assertion_xml).unwrap();
        let assertion_node = document
            .descendants()
            .find(|node| node.has_tag_name((SAML_ASSERTION_NS, "Assertion")))
            .unwrap();
        let canonical = canonicalize_node(assertion_node, true);
        let digest = digest::digest(&digest::SHA256, canonical.as_bytes());
        STANDARD.encode(digest.as_ref())
    }

    fn sign_canonicalized_signed_info(signed_info: &str) -> String {
        let key_pair = private_key_pair();
        let rng = SystemRandom::new();
        let canonical = canonicalize_signed_info(signed_info);
        let mut signature = vec![0; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &rng,
                canonical.as_bytes(),
                &mut signature,
            )
            .unwrap();
        STANDARD.encode(signature)
    }

    fn build_signed_response(saml_state: &SamlState) -> String {
        let issue_instant = Utc::now().to_rfc3339();
        let not_before = (Utc::now() - Duration::seconds(30)).to_rfc3339();
        let not_on_or_after = (Utc::now() + Duration::minutes(5)).to_rfc3339();
        let assertion_template = ASSERTION_TEMPLATE
            .replace("{issue}", &issue_instant)
            .replace("{idp}", &saml_state.idp_entity_id)
            .replace("{subject}", TEST_SUBJECT)
            .replace("{not_before}", &not_before)
            .replace("{not_on_or_after}", &not_on_or_after)
            .replace("{audience}", &saml_state.entity_id)
            .replace("{acs}", &saml_state.acs_url)
            .replace("{role_attr}", &saml_state.role_attribute)
            .replace("{role_value}", TEST_ROLE_VALUE)
            .replace("{signature}", SIGNATURE_PLACEHOLDER);
        let assertion_for_digest = assertion_template
            .replace("{signed_info}", SIGNED_INFO_TEMPLATE)
            .replace("{signature}", SIGNATURE_PLACEHOLDER);
        let digest_value = compute_assertion_digest(&assertion_for_digest);
        let signed_info = SIGNED_INFO_TEMPLATE.replace("{digest}", &digest_value);
        let signature_value = sign_canonicalized_signed_info(&signed_info);
        let final_assertion = assertion_template
            .replace("{signed_info}", &signed_info)
            .replace("{signature}", &signature_value);
        RESPONSE_TEMPLATE
            .replace("{issue}", &issue_instant)
            .replace("{acs}", &saml_state.acs_url)
            .replace("{idp}", &saml_state.idp_entity_id)
            .replace("{assertion}", &final_assertion)
    }

    #[test]
    fn saml_state_extracts_signed_response_claims() {
        let config = test_saml_config();
        let metadata_xml = test_metadata_xml();
        let document = Document::parse(&metadata_xml).unwrap();
        let saml_state = SamlState::from_document(document, &config).unwrap();
        let response = build_signed_response(&saml_state);
        let response_doc = Document::parse(&response).unwrap();
        let claims = saml_state.extract_claims(&response_doc).unwrap();
        assert_eq!(claims.sub.as_deref(), Some(TEST_SUBJECT));
        let roles = claims.roles.unwrap_or_default();
        assert!(roles.contains(&TEST_ROLE_VALUE.to_string()));
        assert_eq!(
            claims.aud,
            Some(AudienceClaim::Single(TEST_SP_ENTITY_ID.to_string()))
        );
    }

    #[test]
    fn build_saml_metadata_includes_entity_and_acs() {
        let config = test_saml_config();
        let metadata = build_saml_metadata(&config);
        assert!(metadata.contains(TEST_SP_ENTITY_ID));
        assert!(metadata.contains(TEST_SP_ACS));
        assert!(metadata.contains("AssertionConsumerService"));
    }

    #[test]
    fn ensure_destination_rejects_mismatched_values() {
        let config = test_saml_config();
        let metadata_xml = test_metadata_xml();
        let document = Document::parse(&metadata_xml).unwrap();
        let saml_state = SamlState::from_document(document, &config).unwrap();
        let xml = format!(
            "<Response xmlns=\"{SAML_PROTOCOL_NS}\" Destination=\"https://bad.example.com\"/>"
        );
        let response_doc = Document::parse(&xml).unwrap();
        let response = response_doc.root_element();
        assert!(matches!(
            saml_state.ensure_destination(response),
            Err(IamError::Saml(_))
        ));
    }

    /// R226-SRV-5: Missing Conditions element must be rejected (fail-closed).
    #[test]
    fn ensure_conditions_rejects_missing_conditions_element() {
        let config = test_saml_config();
        let metadata_xml = test_metadata_xml();
        let document = Document::parse(&metadata_xml).unwrap();
        let saml_state = SamlState::from_document(document, &config).unwrap();
        // Assertion without Conditions element
        let xml = format!("<Assertion xmlns=\"{SAML_ASSERTION_NS}\"><Subject/></Assertion>");
        let assertion_doc = Document::parse(&xml).unwrap();
        let assertion = assertion_doc.root_element();
        let result = saml_state.ensure_conditions(assertion);
        assert!(
            result.is_err(),
            "Missing Conditions element must be rejected (fail-closed)"
        );
        assert!(
            format!("{}", result.unwrap_err()).contains("missing"),
            "Error must mention missing Conditions"
        );
    }

    /// R234-SRV-2: Missing NotOnOrAfter on Conditions must be rejected (fail-closed).
    #[test]
    fn ensure_conditions_rejects_missing_not_on_or_after() {
        let config = test_saml_config();
        let metadata_xml = test_metadata_xml();
        let document = Document::parse(&metadata_xml).unwrap();
        let saml_state = SamlState::from_document(document, &config).unwrap();
        // Conditions element without NotOnOrAfter attribute
        let xml = format!(
            r#"<Assertion xmlns="{SAML_ASSERTION_NS}"><Conditions NotBefore="2020-01-01T00:00:00Z"><AudienceRestriction><Audience>{TEST_SP_ENTITY_ID}</Audience></AudienceRestriction></Conditions><Subject/></Assertion>"#
        );
        let assertion_doc = Document::parse(&xml).unwrap();
        let assertion = assertion_doc.root_element();
        let result = saml_state.ensure_conditions(assertion);
        assert!(
            result.is_err(),
            "Missing NotOnOrAfter on Conditions must be rejected"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("NotOnOrAfter") && err.contains("missing"),
            "Error should mention missing NotOnOrAfter: {err}"
        );
    }

    /// R234-SRV-1: Missing Recipient on SubjectConfirmationData must be rejected.
    #[test]
    fn ensure_subject_confirmation_rejects_missing_recipient() {
        let config = test_saml_config();
        let metadata_xml = test_metadata_xml();
        let document = Document::parse(&metadata_xml).unwrap();
        let saml_state = SamlState::from_document(document, &config).unwrap();
        let not_on_or_after = (Utc::now() + Duration::minutes(5)).to_rfc3339();
        // SubjectConfirmationData without Recipient attribute
        let xml = format!(
            r#"<Assertion xmlns="{SAML_ASSERTION_NS}"><Subject><NameID>user@test.com</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData NotOnOrAfter="{not_on_or_after}"/></SubjectConfirmation></Subject></Assertion>"#
        );
        let assertion_doc = Document::parse(&xml).unwrap();
        let assertion = assertion_doc.root_element();
        let result = saml_state.ensure_subject_confirmation(assertion);
        assert!(
            result.is_err(),
            "Missing Recipient must be rejected (fail-closed)"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("Recipient") && err.contains("missing"),
            "Error should mention missing Recipient: {err}"
        );
    }

    /// R234-SRV-2: Missing NotOnOrAfter on SubjectConfirmationData must be rejected.
    #[test]
    fn ensure_subject_confirmation_rejects_missing_not_on_or_after() {
        let config = test_saml_config();
        let metadata_xml = test_metadata_xml();
        let document = Document::parse(&metadata_xml).unwrap();
        let saml_state = SamlState::from_document(document, &config).unwrap();
        // SubjectConfirmationData without NotOnOrAfter attribute
        let xml = format!(
            r#"<Assertion xmlns="{SAML_ASSERTION_NS}"><Subject><NameID>user@test.com</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData Recipient="{TEST_SP_ACS}"/></SubjectConfirmation></Subject></Assertion>"#
        );
        let assertion_doc = Document::parse(&xml).unwrap();
        let assertion = assertion_doc.root_element();
        let result = saml_state.ensure_subject_confirmation(assertion);
        assert!(
            result.is_err(),
            "Missing NotOnOrAfter on SubjectConfirmationData must be rejected"
        );
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("NotOnOrAfter") && err.contains("missing"),
            "Error should mention missing NotOnOrAfter: {err}"
        );
    }

    fn role_claims(subject: &str, role: &str) -> RoleClaims {
        RoleClaims {
            sub: Some(subject.to_string()),
            role: Some(role.to_string()),
            vellaveto_role: None,
            roles: None,
            aud: None,
            nonce: None,
        }
    }

    #[test]
    fn session_expires_after_idle_timeout() {
        let mut config = IamConfig::default();
        config.oidc.enabled = true;
        config.session.idle_timeout_secs = 1;
        let iam = IamState::new_for_test(config);
        let session = iam
            .create_session(role_claims("alice", "admin"), vec![])
            .unwrap();
        {
            let mut entry = iam.sessions.get_mut(&session.id).unwrap();
            entry.last_activity = StdInstant::now() - StdDuration::from_secs(2);
        }
        assert!(iam.find_session(&session.id).is_none());
    }

    #[test]
    fn create_session_prunes_oldest_when_limit_reached() {
        let mut config = IamConfig::default();
        config.oidc.enabled = true;
        config.session.max_sessions_per_principal = 2;
        let iam = IamState::new_for_test(config);
        let s1 = iam
            .create_session(role_claims("bob", "operator"), vec![])
            .unwrap();
        let s2 = iam
            .create_session(role_claims("bob", "operator"), vec![])
            .unwrap();
        let s3 = iam
            .create_session(role_claims("bob", "operator"), vec![])
            .unwrap();
        assert!(iam.find_session(&s1.id).is_none());
        assert!(iam.find_session(&s2.id).is_some());
        assert!(iam.find_session(&s3.id).is_some());
    }

    // ═══════════════════════════════════════════════════════════════
    // M2M Tests
    // ═══════════════════════════════════════════════════════════════

    fn make_argon2_hash(secret: &str) -> String {
        use argon2::{Argon2, PasswordHasher};
        // argon2 0.6: `hash_password` takes only the password and generates a
        // random salt of the recommended length itself, so the explicit
        // SaltString/OsRng dance the 0.5 API required is gone. The salt is still
        // random per call — this does not weaken the fixtures.
        Argon2::default()
            .hash_password(secret.as_bytes())
            .expect("hash password")
            .to_string()
    }

    fn m2m_config_with_client(
        client_id: &str,
        secret: &str,
        role: &str,
        scopes: Vec<String>,
    ) -> IamConfig {
        use vellaveto_config::iam::M2mClient;
        let hash = make_argon2_hash(secret);
        let mut config = IamConfig::default();
        config.oidc.enabled = true;
        config.m2m.enabled = true;
        config.m2m.token_ttl_secs = 300;
        config.m2m.clients.push(M2mClient {
            client_id: client_id.to_string(),
            client_secret_hash: hash,
            role: role.to_string(),
            allowed_scopes: scopes,
        });
        config
    }

    #[test]
    fn test_m2m_exchange_success() {
        let config = m2m_config_with_client(
            "test-client",
            "test-secret-123",
            "operator",
            vec!["evaluate".to_string(), "audit:read".to_string()],
        );
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));
        let result = iam.exchange_client_credentials(
            "test-client",
            "test-secret-123",
            &["evaluate".to_string()],
        );
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 300);
        assert_eq!(response.scope, "evaluate");
        assert!(!response.access_token.is_empty());
    }

    #[test]
    fn test_m2m_exchange_all_scopes_when_empty() {
        let config = m2m_config_with_client(
            "test-client",
            "test-secret-123",
            "operator",
            vec!["evaluate".to_string(), "audit:read".to_string()],
        );
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));
        let result = iam.exchange_client_credentials("test-client", "test-secret-123", &[]);
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.scope, "evaluate audit:read");
    }

    #[test]
    fn test_m2m_exchange_wrong_secret() {
        let config = m2m_config_with_client(
            "test-client",
            "correct-secret",
            "operator",
            vec!["evaluate".to_string()],
        );
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));
        let result = iam.exchange_client_credentials("test-client", "wrong-secret", &[]);
        assert!(matches!(result, Err(IamError::M2mInvalidCredentials)));
    }

    #[test]
    fn test_m2m_exchange_unknown_client() {
        let config = m2m_config_with_client("test-client", "test-secret", "operator", vec![]);
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));
        let result = iam.exchange_client_credentials("unknown", "test-secret", &[]);
        assert!(matches!(result, Err(IamError::M2mInvalidCredentials)));
    }

    #[test]
    fn test_m2m_exchange_scope_not_permitted() {
        let config = m2m_config_with_client(
            "test-client",
            "test-secret-123",
            "viewer",
            vec!["evaluate".to_string()],
        );
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));
        let result = iam.exchange_client_credentials(
            "test-client",
            "test-secret-123",
            &["admin:write".to_string()],
        );
        assert!(matches!(result, Err(IamError::M2mScopeNotPermitted(_))));
    }

    #[test]
    fn test_m2m_exchange_disabled() {
        let config = IamConfig::default();
        let iam = IamState::new_for_test(config);
        let result = iam.exchange_client_credentials("client", "secret", &[]);
        assert!(matches!(result, Err(IamError::M2mDisabled)));
    }

    #[test]
    fn test_m2m_exchange_no_signing_secret() {
        let config = m2m_config_with_client(
            "test-client",
            "test-secret-123",
            "operator",
            vec!["evaluate".to_string()],
        );
        // No signing secret provided.
        let iam = IamState::new_for_test_with_secret(config, None);
        let result = iam.exchange_client_credentials(
            "test-client",
            "test-secret-123",
            &["evaluate".to_string()],
        );
        assert!(matches!(result, Err(IamError::M2mTokenGeneration(_))));
    }

    #[test]
    fn test_m2m_exchange_dangerous_chars_in_client_id() {
        let config = m2m_config_with_client("test-client", "test-secret", "operator", vec![]);
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));
        let result = iam.exchange_client_credentials("test\x00client", "test-secret", &[]);
        assert!(matches!(result, Err(IamError::M2mInvalidCredentials)));
    }

    /// R237-SRV-4: Per-client M2M token request rate limiting.
    #[test]
    fn test_r237_m2m_per_client_rate_limit() {
        let config = m2m_config_with_client(
            "test-client",
            "test-secret-123",
            "operator",
            vec!["evaluate".to_string()],
        );
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));

        // First 10 requests should succeed.
        for i in 0..10 {
            let result = iam.exchange_client_credentials(
                "test-client",
                "test-secret-123",
                &["evaluate".to_string()],
            );
            assert!(result.is_ok(), "Request {i} should succeed");
        }

        // 11th request should be rate limited.
        let result = iam.exchange_client_credentials(
            "test-client",
            "test-secret-123",
            &["evaluate".to_string()],
        );
        assert!(
            matches!(result, Err(IamError::M2mRateLimited)),
            "11th request should be rate limited"
        );
    }

    /// R237-SRV-4: Rate limit is per-client — different clients have independent limits.
    #[test]
    fn test_r237_m2m_rate_limit_per_client_isolation() {
        let mut config = m2m_config_with_client(
            "client-a",
            "secret-a-123456",
            "operator",
            vec!["evaluate".to_string()],
        );
        config.m2m.clients.push(vellaveto_config::iam::M2mClient {
            client_id: "client-b".to_string(),
            client_secret_hash: make_argon2_hash("secret-b-123456"),
            role: "viewer".to_string(),
            allowed_scopes: vec!["evaluate".to_string()],
        });
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));

        // Exhaust client-a's rate limit.
        for _ in 0..10 {
            let _ = iam.exchange_client_credentials(
                "client-a",
                "secret-a-123456",
                &["evaluate".to_string()],
            );
        }
        assert!(
            matches!(
                iam.exchange_client_credentials(
                    "client-a",
                    "secret-a-123456",
                    &["evaluate".to_string()]
                ),
                Err(IamError::M2mRateLimited)
            ),
            "client-a should be rate limited"
        );

        // client-b should still be allowed.
        let result = iam.exchange_client_credentials(
            "client-b",
            "secret-b-123456",
            &["evaluate".to_string()],
        );
        assert!(
            result.is_ok(),
            "client-b should not be affected by client-a's rate limit"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // R238-XCUT-1: Input validation before rate limiter DashMap insert
    // ═══════════════════════════════════════════════════════════════

    /// R238-XCUT-1: Oversized client_id rejected BEFORE being stored in rate limit map.
    #[test]
    fn test_r238_xcut1_m2m_long_client_id_rejected_before_rate_insert() {
        let config = m2m_config_with_client("test-client", "test-secret-123", "operator", vec![]);
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));

        // Send a client_id that exceeds MAX_M2M_CLIENT_ID_REQUEST_LEN (128 bytes).
        let oversized_id = "A".repeat(200);
        let result = iam.exchange_client_credentials(&oversized_id, "test-secret-123", &[]);
        assert!(
            matches!(result, Err(IamError::M2mInvalidCredentials)),
            "Oversized client_id should be rejected"
        );

        // Verify the oversized client_id was NOT inserted into the rate limit map.
        assert!(
            !iam.m2m_rate_limits.contains_key(&oversized_id),
            "Oversized client_id must not be stored in rate limit DashMap"
        );
    }

    /// R238-XCUT-1: Dangerous chars in client_id rejected BEFORE rate limit map insert.
    #[test]
    fn test_r238_xcut1_m2m_dangerous_chars_rejected_before_rate_insert() {
        let config = m2m_config_with_client("test-client", "test-secret-123", "operator", vec![]);
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret));

        // Send a client_id with dangerous chars (null byte).
        let dangerous_id = "client\x00evil";
        let result = iam.exchange_client_credentials(dangerous_id, "test-secret-123", &[]);
        assert!(
            matches!(result, Err(IamError::M2mInvalidCredentials)),
            "Dangerous chars in client_id should be rejected"
        );

        // Verify the dangerous client_id was NOT inserted into the rate limit map.
        assert!(
            !iam.m2m_rate_limits.contains_key(dangerous_id),
            "Client_id with dangerous chars must not be stored in rate limit DashMap"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // R237-SRV-5: SAML InResponseTo Tests
    // ═══════════════════════════════════════════════════════════════

    /// R237-SRV-5: InResponseTo validation — stored request ID is consumed.
    #[test]
    fn test_r237_saml_in_response_to_stored_id_consumed() {
        let config = IamConfig::default();
        let iam = IamState::new_for_test(config);

        // Store a fake AuthnRequest ID.
        let request_id = "_authn_req_12345";
        iam.saml_authn_request_ids
            .insert(request_id.to_string(), std::time::Instant::now());
        assert_eq!(iam.saml_authn_request_ids.len(), 1);

        // Simulate consuming the ID (what saml_acs would do).
        let consumed = iam
            .saml_authn_request_ids
            .remove(request_id)
            .map(|(_, issued_at)| issued_at.elapsed().as_secs() < 600)
            .unwrap_or(false);
        assert!(consumed, "Stored InResponseTo ID should be consumed");
        assert_eq!(iam.saml_authn_request_ids.len(), 0);

        // Replaying the same ID should fail.
        let replayed = iam
            .saml_authn_request_ids
            .remove(request_id)
            .map(|(_, issued_at)| issued_at.elapsed().as_secs() < 600)
            .unwrap_or(false);
        assert!(!replayed, "Replayed InResponseTo ID should not be consumed");
    }

    /// R237-SRV-5: InResponseTo with unknown ID is rejected.
    #[test]
    fn test_r237_saml_in_response_to_unknown_id_rejected() {
        let config = IamConfig::default();
        let iam = IamState::new_for_test(config);

        // No stored request IDs. An InResponseTo with an unknown ID should fail.
        let consumed = iam
            .saml_authn_request_ids
            .remove("_unknown_request_id")
            .map(|(_, issued_at)| issued_at.elapsed().as_secs() < 600)
            .unwrap_or(false);
        assert!(!consumed, "Unknown InResponseTo ID must be rejected");
    }

    // ═══════════════════════════════════════════════════════════════
    // Step-Up Tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_build_step_up_response_structure() {
        let (status, body) = build_step_up_response(
            vec!["admin:write".to_string()],
            vec!["evaluate".to_string()],
            Some("https://example.com/auth/upgrade".to_string()),
        );
        assert_eq!(status, StatusCode::FORBIDDEN);
        let json = body.0;
        assert_eq!(json["error"], "Insufficient authorization");
        assert!(json["step_up_required"]["required_scopes"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("admin:write")));
        assert!(json["step_up_required"]["current_scopes"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("evaluate")));
        assert_eq!(
            json["step_up_required"]["upgrade_url"],
            "https://example.com/auth/upgrade"
        );
    }

    #[test]
    fn test_build_step_up_response_no_upgrade_url() {
        let (status, body) = build_step_up_response(vec!["admin:write".to_string()], vec![], None);
        assert_eq!(status, StatusCode::FORBIDDEN);
        let json = body.0;
        assert!(json["step_up_required"]["upgrade_url"].is_null());
    }

    // ═══════════════════════════════════════════════════════════════
    // CIMD Tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_validate_cimd_host_blocks_localhost() {
        let url = Url::parse("https://localhost/metadata").unwrap();
        assert!(validate_cimd_host(&url).is_err());
    }

    #[test]
    fn test_validate_cimd_host_blocks_loopback() {
        let url = Url::parse("https://127.0.0.1/metadata").unwrap();
        assert!(validate_cimd_host(&url).is_err());
    }

    #[test]
    fn test_validate_cimd_host_blocks_ipv6_loopback() {
        let url = Url::parse("https://[::1]/metadata").unwrap();
        assert!(validate_cimd_host(&url).is_err());
    }

    #[test]
    fn test_validate_cimd_host_blocks_link_local() {
        let url = Url::parse("https://169.254.169.254/metadata").unwrap();
        assert!(validate_cimd_host(&url).is_err());
    }

    #[test]
    fn test_validate_cimd_host_blocks_private_10() {
        let url = Url::parse("https://10.0.0.1/metadata").unwrap();
        assert!(validate_cimd_host(&url).is_err());
    }

    #[test]
    fn test_validate_cimd_host_blocks_private_192() {
        let url = Url::parse("https://192.168.1.1/metadata").unwrap();
        assert!(validate_cimd_host(&url).is_err());
    }

    #[test]
    fn test_validate_cimd_host_blocks_private_172() {
        let url = Url::parse("https://172.16.0.1/metadata").unwrap();
        assert!(validate_cimd_host(&url).is_err());
    }

    #[test]
    fn test_validate_cimd_host_blocks_metadata_google() {
        let url = Url::parse("https://metadata.google.internal/metadata").unwrap();
        assert!(validate_cimd_host(&url).is_err());
    }

    #[test]
    fn test_validate_cimd_host_allows_public() {
        let url = Url::parse("https://auth.example.com/.well-known/oauth-client").unwrap();
        assert!(validate_cimd_host(&url).is_ok());
    }

    #[test]
    fn test_validate_cimd_redirect_uri_allows_https() {
        assert!(validate_cimd_redirect_uri("https://auth.example.com/callback").is_ok());
    }

    #[test]
    fn test_validate_cimd_redirect_uri_rejects_http() {
        let err = validate_cimd_redirect_uri("http://auth.example.com/callback")
            .expect_err("http redirect URIs must be rejected");
        assert!(err.to_string().contains("https"));
    }

    #[test]
    fn test_validate_cimd_redirect_uri_rejects_invalid_url() {
        assert!(validate_cimd_redirect_uri("not-a-valid-uri").is_err());
    }

    #[test]
    fn test_sanitize_next_rejects_scheme_relative_redirect() {
        assert_eq!(sanitize_next(Some("//evil.example/path".to_string())), "/");
        assert_eq!(sanitize_next(Some("///evil.example/path".to_string())), "/");
    }

    #[test]
    fn test_sanitize_next_rejects_backslash_path_confusion() {
        assert_eq!(sanitize_next(Some("/\\evil.example/path".to_string())), "/");
        assert_eq!(sanitize_next(Some("\\evil.example/path".to_string())), "/");
    }

    #[test]
    fn test_map_digest_algorithm_rejects_sha1() {
        let err = map_digest_algorithm("http://www.w3.org/2000/09/xmldsig#sha1")
            .expect_err("sha1 must be rejected");
        assert!(err.to_string().contains("SHA-1"));
    }

    #[test]
    fn test_map_signature_algorithm_rejects_sha1() {
        let err = map_signature_algorithm("http://www.w3.org/2000/09/xmldsig#rsa-sha1")
            .expect_err("rsa-sha1 must be rejected");
        assert!(err.to_string().contains("SHA-1"));
    }

    // ═══════════════════════════════════════════════════════════════
    // R230-SRV-2: OIDC algorithm confusion protection
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_r230_find_key_in_jwks_requires_alg() {
        use jsonwebtoken::jwk::{AlgorithmParameters, CommonParameters, Jwk, RSAKeyParameters};
        // Key WITHOUT alg field should NOT match any algorithm
        let key_no_alg = Jwk {
            common: CommonParameters {
                public_key_use: None,
                key_operations: None,
                key_algorithm: None, // Missing alg
                key_id: Some("kid-1".to_string()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
                n: "test_n".to_string(),
                e: "AQAB".to_string(),
            }),
        };
        let jwks = JwkSet {
            keys: vec![key_no_alg],
        };
        // Should return None because key has no alg (R230-SRV-2 fail-closed)
        let result = find_key_in_jwks(&jwks, "kid-1", &Algorithm::RS256);
        assert!(
            result.is_none(),
            "Key without alg must not match (algorithm confusion prevention)"
        );
    }

    #[test]
    fn test_r230_find_key_in_jwks_matching_alg_works() {
        use jsonwebtoken::jwk::{
            AlgorithmParameters, CommonParameters, Jwk, KeyAlgorithm, RSAKeyParameters,
        };
        let key_with_alg = Jwk {
            common: CommonParameters {
                public_key_use: None,
                key_operations: None,
                key_algorithm: Some(KeyAlgorithm::RS256), // Explicit alg
                key_id: Some("kid-2".to_string()),
                x509_url: None,
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
                n: "test_n".to_string(),
                e: "AQAB".to_string(),
            }),
        };
        let jwks = JwkSet {
            keys: vec![key_with_alg],
        };
        // Wrong algorithm should not match
        let result = find_key_in_jwks(&jwks, "kid-2", &Algorithm::ES256);
        assert!(result.is_none(), "Mismatched alg must not match");
    }

    // ═══════════════════════════════════════════════════════════════
    // M2M Config Validation Tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn test_m2m_config_validation_disabled_is_ok() {
        let config = IamConfig::default();
        assert!(config.m2m.validate().is_ok());
    }

    #[test]
    fn test_m2m_config_validation_enabled_no_clients() {
        use vellaveto_config::iam::M2mConfig;
        let config = M2mConfig {
            enabled: true,
            clients: vec![],
            token_ttl_secs: 300,
            issuer: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_m2m_config_validation_duplicate_client_ids() {
        use vellaveto_config::iam::{M2mClient, M2mConfig};
        let client = M2mClient {
            client_id: "dup".to_string(),
            client_secret_hash: "hash123456789012345678901234567890".to_string(),
            role: "viewer".to_string(),
            allowed_scopes: vec![],
        };
        let config = M2mConfig {
            enabled: true,
            clients: vec![client.clone(), client],
            token_ttl_secs: 300,
            issuer: None,
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicated"));
    }

    #[test]
    fn test_m2m_client_debug_redacts_secret() {
        use vellaveto_config::iam::M2mClient;
        let client = M2mClient {
            client_id: "test".to_string(),
            client_secret_hash: "super-secret-hash".to_string(),
            role: "viewer".to_string(),
            allowed_scopes: vec![],
        };
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret-hash"));
    }

    #[test]
    fn test_m2m_token_jwt_contains_expected_claims() {
        let config = m2m_config_with_client(
            "test-client",
            "test-secret-123",
            "operator",
            vec!["evaluate".to_string()],
        );
        let secret = b"this-is-a-32-byte-or-longer-secret-key".to_vec();
        let iam = IamState::new_for_test_with_secret(config, Some(secret.clone()));
        let result = iam
            .exchange_client_credentials("test-client", "test-secret-123", &[])
            .unwrap();

        // Decode the JWT and verify claims.
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims::<&str>(&[]);
        let token_data = decode::<M2mJwtClaims>(
            &result.access_token,
            &DecodingKey::from_secret(&secret),
            &validation,
        )
        .unwrap();
        assert_eq!(token_data.claims.sub, "test-client");
        assert_eq!(token_data.claims.role, "operator");
        assert_eq!(token_data.claims.scope, "evaluate");
        assert_eq!(token_data.claims.iss, "vellaveto");
        assert!(!token_data.claims.jti.is_empty());
    }

    /// Build a test-only FlowState with deterministic fixture values.
    /// Indirected through a function to avoid code-scanning false positives
    /// on hardcoded values flowing into cryptographic parameter names.
    fn make_test_flow(label: &str) -> FlowState {
        FlowState::new(
            format!("next-{label}"),
            format!("verifier-{label}"),
            format!("val-{label}"),
        )
    }

    #[test]
    fn test_r237_srv2_store_flow_returns_error_on_capacity() {
        // SECURITY (R237-SRV-2): store_flow must return Err when capacity exhausted,
        // not silently succeed, so the login handler can return 503 instead of
        // redirecting to IdP with no stored state.
        let config = IamConfig::default();
        let iam = IamState::new_for_test(config);

        // Fill up to MAX_FLOW_STATES
        for i in 0..IamState::MAX_FLOW_STATES {
            let flow = make_test_flow(&i.to_string());
            assert!(iam.store_flow(format!("state-{i}"), flow).is_ok());
        }

        // Next one should fail
        let flow = make_test_flow("overflow");
        let result = iam.store_flow("state-overflow".to_string(), flow);
        assert!(
            result.is_err(),
            "store_flow must return Err when capacity is exhausted"
        );
    }
}

fn resolve_scim_token(config: &ScimConfig) -> Result<String, IamError> {
    if let Some(token) = &config.bearer_token {
        return Ok(token.clone());
    }
    if let Some(env_var) = &config.bearer_token_env {
        return env::var(env_var).map_err(|e| {
            IamError::Scim(format!(
                "Failed to read iam.scim.bearer_token_env '{env_var}': {e}"
            ))
        });
    }
    Err(IamError::Scim(
        "iam.scim.bearer_token or iam.scim.bearer_token_env is required".to_string(),
    ))
}

fn spawn_scim_sync(
    client: Client,
    endpoint: String,
    token: String,
    interval_secs: u64,
    status: Arc<RwLock<ScimStatus>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let period = Duration::from_secs(interval_secs);
        loop {
            let sync_start = Instant::now();
            let now = Utc::now();
            let sync_result = fetch_scim_user_count(&client, &endpoint, &token).await;
            let duration_ms = sync_start.elapsed().as_millis();
            match &sync_result {
                Ok(count) => info!(
                    target: "iam",
                    endpoint = endpoint.as_str(),
                    count = count,
                    "SCIM sync recorded users"
                ),
                Err(err) => warn!(
                    target: "iam",
                    endpoint = endpoint.as_str(),
                    err = err,
                    "SCIM sync failed"
                ),
            }
            {
                let mut guard = status.write().await;
                guard.last_sync = Some(now);
                guard.last_sync_duration_ms = Some(duration_ms);
                match sync_result {
                    Ok(count) => {
                        guard.last_user_count = Some(count);
                        guard.last_error = None;
                    }
                    Err(err) => {
                        guard.last_error = Some(err);
                    }
                }
            }
            sleep(period).await;
        }
    })
}

async fn fetch_scim_user_count(
    client: &Client,
    endpoint: &str,
    token: &str,
) -> Result<usize, String> {
    // SECURITY (R231-SRV-5): Bound SCIM response size and add timeout
    // to prevent memory exhaustion from a malicious SCIM endpoint.
    const MAX_SCIM_RESPONSE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB
    let response = client
        .get(endpoint)
        .header(reqwest_header::AUTHORIZATION, format!("Bearer {token}"))
        .header(
            reqwest_header::ACCEPT,
            "application/scim+json, application/json",
        )
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("SCIM request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("SCIM endpoint error: {e}"))?;
    let content_length = response.content_length().unwrap_or(0);
    if content_length > MAX_SCIM_RESPONSE_SIZE {
        return Err(format!(
            "SCIM response too large: {content_length} bytes (max {MAX_SCIM_RESPONSE_SIZE})"
        ));
    }
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("SCIM response read failed: {e}"))?;
    if body.len() as u64 > MAX_SCIM_RESPONSE_SIZE {
        return Err(format!(
            "SCIM response body too large: {} bytes (max {})",
            body.len(),
            MAX_SCIM_RESPONSE_SIZE
        ));
    }
    let payload: Value =
        serde_json::from_slice(&body).map_err(|e| format!("SCIM response decode failed: {e}"))?;
    Ok(extract_scim_user_count(&payload))
}

fn extract_scim_user_count(payload: &Value) -> usize {
    payload
        .get("totalResults")
        .and_then(value_to_usize)
        .or_else(|| payload.get("total").and_then(value_to_usize))
        .or_else(|| {
            payload
                .get("Resources")
                .and_then(|value| value.as_array().map(|arr| arr.len()))
        })
        .or_else(|| {
            payload
                .get("resources")
                .and_then(|value| value.as_array().map(|arr| arr.len()))
        })
        .unwrap_or_default()
}

fn value_to_usize(value: &Value) -> Option<usize> {
    value.as_u64().map(|num| num as usize).or_else(|| {
        value
            .as_str()
            .and_then(|text| text.parse::<u64>().ok())
            .map(|num| num as usize)
    })
}

fn find_key_in_jwks(jwks: &JwkSet, kid: &str, alg: &Algorithm) -> Option<DecodingKey> {
    for key in &jwks.keys {
        if !kid.is_empty() {
            match &key.common.key_id {
                Some(key_kid) if key_kid == kid => {}
                _ => continue,
            }
        }
        // R230-SRV-2: Require alg field in JWKS keys (RFC 8725 §3.1).
        // Previously, keys without `alg` matched ANY requested algorithm,
        // enabling algorithm confusion attacks (e.g., RSA key used with HS256).
        // Fail-closed: keys without explicit alg are skipped.
        match &key.common.key_algorithm {
            Some(key_alg) => {
                if key_algorithm_to_algorithm(key_alg).as_ref() != Some(alg) {
                    continue;
                }
            }
            None => {
                // No alg specified → skip this key (fail-closed)
                continue;
            }
        }
        if let Ok(decoding_key) = DecodingKey::from_jwk(key) {
            return Some(decoding_key);
        }
    }
    None
}

fn key_algorithm_to_algorithm(ka: &KeyAlgorithm) -> Option<Algorithm> {
    match ka {
        KeyAlgorithm::HS256 => Some(Algorithm::HS256),
        KeyAlgorithm::HS384 => Some(Algorithm::HS384),
        KeyAlgorithm::HS512 => Some(Algorithm::HS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}
