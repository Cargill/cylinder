/*
 * Copyright 2017 Intel Corporation
 * Copyright 2018-2021 Cargill Incorporated
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

#[cfg(feature = "key-load")]
#[macro_use]
extern crate log;

mod error;
#[cfg(feature = "hash")]
#[cfg_attr(docsrs, doc(cfg(feature = "hash")))]
pub mod hash;
mod hex;
#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub mod jwt;
mod key;
pub mod secp256k1;
mod signature;

#[cfg(feature = "key-load")]
pub use error::KeyLoadError;
pub use error::{ContextError, SignatureParseError, SigningError, VerificationError};
#[cfg(feature = "key-load")]
pub use key::load::current_user_key_name;
#[cfg(feature = "key-load")]
pub use key::load::current_user_search_path;
#[cfg(feature = "key-load")]
pub use key::load::load_key;
#[cfg(feature = "key-load")]
pub use key::load::load_key_from_path;
pub use key::{KeyParseError, PrivateKey, PublicKey};
pub use signature::Signature;

/// A signer for arbitrary messages
pub trait Signer: Send {
    /// Return the algorithm name used for signing.
    fn algorithm_name(&self) -> &str;

    /// Signs the given message
    fn sign(&self, message: &[u8]) -> Result<Signature, SigningError>;

    /// Returns the signer's public key
    fn public_key(&self) -> Result<PublicKey, SigningError>;

    /// Clone implementation for `Signer`. The implementation of the `Clone` trait for
    /// `Box<dyn Signer>` calls this method.
    fn clone_box(&self) -> Box<dyn Signer>;
}

impl Clone for Box<dyn Signer> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

/// Verifies message signatures
pub trait Verifier: Send {
    /// Return the algorithm name used for verification.
    fn algorithm_name(&self) -> &str;

    /// Verifies that the provided signature is valid for the given message and public key
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool, VerificationError>;
}

/// A factory for creating verifiers
pub trait VerifierFactory: Send {
    /// Creates a new signature verifier
    fn new_verifier(&self) -> Box<dyn Verifier>;
}

/// A context for creating signers and verifiers
pub trait Context: Send {
    /// Return the algorithm name provided by this context.
    fn algorithm_name(&self) -> &str;

    /// Creates a new signer with the given private key
    fn new_signer(&self, key: PrivateKey) -> Box<dyn Signer>;

    /// Creates a new signature verifier
    fn new_verifier(&self) -> Box<dyn Verifier>;

    /// Generates a new random private key
    fn new_random_private_key(&self) -> PrivateKey;

    /// Computes the public key that corresponds to the given private key
    fn get_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey, ContextError>;
}

impl<T: Context> VerifierFactory for T {
    fn new_verifier(&self) -> Box<dyn Verifier> {
        Context::new_verifier(self)
    }
}
