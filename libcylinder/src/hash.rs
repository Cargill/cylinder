// Copyright 2018-2021 Cargill Incorporated
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

use sha2::{Digest, Sha512};

use super::{
    Context, ContextError, PrivateKey, PublicKey, Signature, Signer, SigningError,
    VerificationError, Verifier,
};

const ALGORITHM_NAME: &str = "sha512";

pub struct HashContext;

impl Context for HashContext {
    fn algorithm_name(&self) -> &str {
        ALGORITHM_NAME
    }

    fn new_signer(&self, _key: PrivateKey) -> Box<dyn Signer> {
        Box::new(HashSigner)
    }

    fn new_verifier(&self) -> Box<dyn Verifier> {
        Box::new(HashVerifier)
    }

    fn new_random_private_key(&self) -> PrivateKey {
        PrivateKey::new(vec![])
    }

    fn get_public_key(&self, _private_key: &PrivateKey) -> Result<PublicKey, ContextError> {
        Ok(PublicKey::new(vec![]))
    }
}

/// Generates hashes from messages
#[derive(Clone)]
pub struct HashSigner;

impl Signer for HashSigner {
    fn algorithm_name(&self) -> &str {
        ALGORITHM_NAME
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, SigningError> {
        Ok(Signature::new(Sha512::digest(message).to_vec()))
    }

    fn public_key(&self) -> Result<PublicKey, SigningError> {
        Ok(PublicKey::new(b"hash_signer".to_vec()))
    }

    fn clone_box(&self) -> Box<dyn Signer> {
        Box::new(self.clone())
    }
}

/// Verifies message hashes
pub struct HashVerifier;

impl Verifier for HashVerifier {
    fn algorithm_name(&self) -> &str {
        ALGORITHM_NAME
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        _public_key: &PublicKey,
    ) -> Result<bool, VerificationError> {
        Ok(signature.as_slice() == Sha512::digest(message).as_slice())
    }
}
