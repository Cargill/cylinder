// Copyright 2018-2020 Cargill Incorporated
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Signer/verifier implemenation for hashes instead of real signatures
//!
//! This implementation is intended for testing purposes only.

use openssl::hash::{hash, MessageDigest};

use super::{PublicKey, SignatureVerificationError, SignatureVerifier, Signer, SigningError};

/// Generates hashes from messages
pub struct HashSigner;

impl Signer for HashSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError> {
        hash(MessageDigest::sha512(), message)
            .map(|digest_bytes| digest_bytes.to_vec())
            .map_err(|err| SigningError::Internal(err.to_string()))
    }

    fn public_key(&self) -> Result<PublicKey, SigningError> {
        Ok(PublicKey::new(b"hash_signer".to_vec()))
    }
}

/// Verifies message hashes
pub struct HashSignatureVerifier;

impl SignatureVerifier for HashSignatureVerifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        _public_key: &PublicKey,
    ) -> Result<bool, SignatureVerificationError> {
        let expected_hash = hash(MessageDigest::sha512(), message)
            .map(|digest_bytes| digest_bytes.to_vec())
            .map_err(|err| SignatureVerificationError::Internal(err.to_string()))?;

        Ok(expected_hash == signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MSG: &[u8] = b"test message to be";

    /// A basic test that signs a message using the `HashSigner` and verifies the resulting
    /// signature using the `HashSignatureVerifier`
    #[test]
    fn sign_and_verify() {
        let signature = HashSigner.sign(TEST_MSG).expect("Failed to sign msg");
        let public_key = HashSigner.public_key().expect("Failed to get public key");
        assert!(HashSignatureVerifier
            .verify(TEST_MSG, &signature, &public_key)
            .expect("Failed to verify signature"));
    }
}
