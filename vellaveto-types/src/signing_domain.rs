// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: BUSL-1.1
//
// Use of this software is governed by the Business Source License
// included in the LICENSE-BSL-1.1 file at the root of this repository.
//
// Change Date: Three years from the date of publication of this version.
// Change License: MPL-2.0

//! Domain separation for signed artifacts.
//!
//! Every artifact this project signs — checkpoints, evidence packs, rotation
//! manifests, capability tokens, canaries — hashes its fields into SHA-256 and
//! signs the resulting 32-byte digest. Each type already length-prefixes its
//! fields, so no two *field layouts within one type* can produce the same
//! preimage. Nothing distinguished one type from another: a digest is 32 opaque
//! bytes, and the signature over it says only "this key signed these 32 bytes",
//! not "…as a checkpoint".
//!
//! # What this does and does not fix
//!
//! This is defence in depth, not a patched exploit. Every verifier in the tree
//! recomputes the digest from the object it is checking rather than accepting a
//! caller-supplied one, so transferring a signature between artifact types would
//! require a SHA-256 collision across two different preimages. What was missing
//! is the *guarantee*: the safety of one key signing many artifact types rested
//! on an unstated assumption that no two types ever collide, rather than on
//! anything structural. Domain separation makes it structural, so the property
//! survives future changes — a new artifact type, or a verifier that one day
//! accepts a digest from its caller.
//!
//! # Usage
//!
//! Seed the hasher with a domain constant before any field data, then hash
//! fields as before:
//!
//! ```
//! use vellaveto_types::signing_domain::{domain_separated_hasher, hash_field, DOMAIN_CHECKPOINT};
//! use sha2::Digest;
//!
//! let mut hasher = domain_separated_hasher(DOMAIN_CHECKPOINT);
//! hash_field(&mut hasher, b"checkpoint-id");
//! let digest = hasher.finalize().to_vec();
//! ```
//!
//! Domain strings carry their own version suffix. Changing what a type signs
//! means bumping its domain constant, which by construction invalidates nothing
//! — old artifacts still verify against the old domain through each type's
//! legacy verification path.

use sha2::{Digest, Sha256};

/// Audit chain checkpoints (`vellaveto-audit`).
pub const DOMAIN_CHECKPOINT: &str = "vellaveto/checkpoint/v1";

/// Compliance evidence packs (`vellaveto-types::evidence_pack`).
pub const DOMAIN_EVIDENCE_PACK: &str = "vellaveto/evidence-pack/v1";

/// Audit log rotation manifests (`vellaveto-audit::rotation`).
pub const DOMAIN_ROTATION_MANIFEST: &str = "vellaveto/rotation-manifest/v1";

/// Delegated capability tokens (`vellaveto-mcp::capability_token`).
pub const DOMAIN_CAPABILITY_TOKEN: &str = "vellaveto/capability-token/v1";

/// Accountability attestation records (`vellaveto-mcp::accountability`).
pub const DOMAIN_ACCOUNTABILITY: &str = "vellaveto/accountability/v1";

/// Warrant canaries (`vellaveto-canary`).
pub const DOMAIN_WARRANT_CANARY: &str = "vellaveto/warrant-canary/v1";

/// Length-prefix a field into a hasher.
///
/// Prefixing with the length stops two different field layouts producing the
/// same byte stream — `("ab", "c")` and `("a", "bc")` hash differently. Every
/// signed type in the tree already does this; it lives here so the domain
/// prefix and the fields after it are framed the same way.
pub fn hash_field(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u64).to_le_bytes());
    hasher.update(data);
}

/// Start a SHA-256 hasher bound to one artifact type.
///
/// The domain is written as a length-prefixed field, so it cannot be confused
/// with the field data that follows: an attacker cannot choose field values that
/// "absorb" the prefix and reproduce another type's preimage.
pub fn domain_separated_hasher(domain: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, domain.as_bytes());
    hasher
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole module exists for: the same field data hashed
    /// under two domains must not produce the same digest, so a signature over
    /// one artifact type cannot be presented as another.
    #[test]
    fn test_distinct_domains_produce_distinct_digests() {
        let digest_for = |domain| {
            let mut h = domain_separated_hasher(domain);
            hash_field(&mut h, b"identical field data");
            h.finalize().to_vec()
        };

        let checkpoint = digest_for(DOMAIN_CHECKPOINT);
        let evidence = digest_for(DOMAIN_EVIDENCE_PACK);
        let rotation = digest_for(DOMAIN_ROTATION_MANIFEST);

        assert_ne!(checkpoint, evidence);
        assert_ne!(checkpoint, rotation);
        assert_ne!(evidence, rotation);
    }

    /// Every domain constant must be unique, or two types silently share one.
    #[test]
    fn test_all_domain_constants_are_distinct() {
        let domains = [
            DOMAIN_CHECKPOINT,
            DOMAIN_EVIDENCE_PACK,
            DOMAIN_ROTATION_MANIFEST,
            DOMAIN_CAPABILITY_TOKEN,
            DOMAIN_ACCOUNTABILITY,
            DOMAIN_WARRANT_CANARY,
        ];
        for (i, a) in domains.iter().enumerate() {
            for b in domains.iter().skip(i + 1) {
                assert_ne!(a, b, "domain constants must be unique");
            }
        }
    }

    /// A domain-separated digest must differ from the undomained digest of the
    /// same fields — otherwise migrating a type would be a no-op and old
    /// signatures would keep verifying under the new scheme.
    #[test]
    fn test_domain_changes_the_digest() {
        let mut undomained = Sha256::new();
        hash_field(&mut undomained, b"payload");

        let mut domained = domain_separated_hasher(DOMAIN_CHECKPOINT);
        hash_field(&mut domained, b"payload");

        assert_ne!(undomained.finalize().to_vec(), domained.finalize().to_vec());
    }

    /// The domain is length-prefixed, so a domain and a first field cannot be
    /// re-split to imitate a different domain with different fields.
    #[test]
    fn test_domain_boundary_is_unambiguous() {
        let mut a = domain_separated_hasher("vellaveto/x");
        hash_field(&mut a, b"yz");

        let mut b = domain_separated_hasher("vellaveto/xy");
        hash_field(&mut b, b"z");

        assert_ne!(
            a.finalize().to_vec(),
            b.finalize().to_vec(),
            "length prefixing must keep the domain boundary unambiguous"
        );
    }

    /// Hashing is deterministic — the same domain and fields always give the
    /// same digest, or signatures would not verify.
    #[test]
    fn test_digest_is_deterministic() {
        let build = || {
            let mut h = domain_separated_hasher(DOMAIN_CAPABILITY_TOKEN);
            hash_field(&mut h, b"issuer");
            hash_field(&mut h, b"holder");
            h.finalize().to_vec()
        };
        assert_eq!(build(), build());
    }

    /// Field order is bound: swapping two fields changes the digest.
    #[test]
    fn test_field_order_is_bound() {
        let mut a = domain_separated_hasher(DOMAIN_CAPABILITY_TOKEN);
        hash_field(&mut a, b"issuer");
        hash_field(&mut a, b"holder");

        let mut b = domain_separated_hasher(DOMAIN_CAPABILITY_TOKEN);
        hash_field(&mut b, b"holder");
        hash_field(&mut b, b"issuer");

        assert_ne!(a.finalize().to_vec(), b.finalize().to_vec());
    }
}
