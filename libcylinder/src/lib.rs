/*
 * Copyright 2017 Intel Corporation
 * Copyright 2018-2020 Cargill Incorporated
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

mod error;
mod hex;
mod key;
mod signature;
pub mod signing;

pub use error::{SignatureParseError, SignatureVerificationError, SigningError};
pub use key::{KeyParseError, PrivateKey, PublicKey};
pub use signature::Signature;

/// A signer for arbitrary messages
pub trait Signer: Send {
    /// Signs the given message
    fn sign(&self, message: &[u8]) -> Result<Signature, SigningError>;

    /// Returns the signer's public key
    fn public_key(&self) -> Result<PublicKey, SigningError>;
}

/// Verifies message signatures
pub trait SignatureVerifier: Send {
    /// Verifies that the provided signature is valid for the given message and public key
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool, SignatureVerificationError>;
}
