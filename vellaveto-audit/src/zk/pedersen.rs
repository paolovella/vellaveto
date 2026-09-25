// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella
// SPDX-License-Identifier: MPL-2.0

//! Pedersen commitment scheme over Ristretto255.
//!
//! A Pedersen commitment `C = m * G + r * H` binds to a message `m` using
//! a random blinding factor `r`. It is computationally hiding (cannot
//! determine `m` without `r`) and computationally binding (cannot open
//! to a different `m'`).
//!
//! We use the Ristretto group over Curve25519, which provides a prime-order
//! group without cofactor issues. The second generator `H` is derived via
//! hash-to-point from a domain separator to ensure it has an unknown
//! discrete log relationship with `G`.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

use super::ZkError;

/// Domain separator for deriving the second generator H.
/// This ensures H has an unknown discrete log w.r.t. G.
const DOMAIN_SEPARATOR: &[u8] = b"vellaveto-zk-audit-pedersen-generator-H-v1";

/// Pedersen commitment scheme over Ristretto255.
///
/// Uses two generators:
/// - `G`: the Ristretto basepoint (from curve25519-dalek)
/// - `H`: derived via hash-to-point from a domain separator
#[derive(Clone)]
pub struct PedersenCommitter {
    /// Second generator, derived from domain separator.
    h: RistrettoPoint,
}

impl PedersenCommitter {
    /// Create a new Pedersen committer with a deterministically derived `H` generator.
    pub fn new() -> Self {
        // Derive H via hash-to-point: H = hash_to_point(DOMAIN_SEPARATOR)
        // Using SHA-512 output as input to from_uniform_bytes, which maps
        // 64 bytes to a Ristretto point using Elligator.
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_SEPARATOR);
        let hash_output: [u8; 64] = hasher.finalize().into();
        let h = RistrettoPoint::from_uniform_bytes(&hash_output);

        Self { h }
    }

    /// Commit to an audit entry hash.
    ///
    /// `C = entry_hash_scalar * G + blinding * H`
    ///
    /// Returns `(commitment_point, blinding_factor)` on success.
    ///
    /// ## Blinding Factor (GAP-F04)
    ///
    /// The blinding factor `r` is generated using `Scalar::random()` backed by
    /// the OS CSPRNG (`rand::rng()`). It provides information-theoretic
    /// hiding: without `r`, an observer cannot determine the committed value `m`
    /// even with unlimited computational power, because every commitment point
    /// maps to every possible message under some blinding factor.
    ///
    /// The blinding factor **must** be stored securely by the commitment holder
    /// for later opening/verification. Loss of the blinding factor makes the
    /// commitment unopenable. Disclosure of the blinding factor reveals the
    /// committed entry hash to anyone who has the commitment point.
    pub fn commit(&self, entry_hash: &[u8; 32]) -> Result<(CompressedRistretto, Scalar), ZkError> {
        // Convert entry hash to a scalar (reduce mod group order)
        let entry_scalar = Scalar::from_bytes_mod_order(*entry_hash);

        // Generate random blinding factor.
        //
        // curve25519-dalek 5 requires rand 0.10's `CryptoRng`, which rand_core
        // 0.6's `OsRng` cannot implement — it is a type from a different crate
        // version. `rand::rng()` is a ChaCha12 CSPRNG seeded from the operating
        // system and periodically reseeded, so the blinding factor is still
        // drawn from OS entropy. It is infallible, so this stays free of the
        // `expect()` that the fallible `OsRng` path would have needed.
        let blinding = Scalar::random(&mut rand::rng());

        // C = entry_hash * G + blinding * H
        let commitment = entry_scalar * RISTRETTO_BASEPOINT_POINT + blinding * self.h;

        Ok((commitment.compress(), blinding))
    }

    /// Verify a commitment against a known entry hash and blinding factor.
    ///
    /// Recomputes `C' = entry_hash * G + blinding * H` and checks equality.
    pub fn verify(
        &self,
        commitment: &CompressedRistretto,
        entry_hash: &[u8; 32],
        blinding: &Scalar,
    ) -> bool {
        let entry_scalar = Scalar::from_bytes_mod_order(*entry_hash);
        let expected = entry_scalar * RISTRETTO_BASEPOINT_POINT + *blinding * self.h;
        commitment == &expected.compress()
    }

    /// Decompress a commitment from its compressed form.
    ///
    /// Returns `Err` if the bytes don't represent a valid Ristretto point.
    pub fn decompress(compressed: &CompressedRistretto) -> Result<RistrettoPoint, ZkError> {
        compressed
            .decompress()
            .ok_or_else(|| ZkError::Commitment("Invalid compressed Ristretto point".to_string()))
    }

    /// Expose the H generator for testing determinism.
    #[cfg(test)]
    pub(crate) fn h_point(&self) -> RistrettoPoint {
        self.h
    }
}

impl Default for PedersenCommitter {
    fn default() -> Self {
        Self::new()
    }
}
