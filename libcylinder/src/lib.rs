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
pub mod signing;

use error::HexError;
pub use error::{SignatureVerificationError, SigningError};

/// A public key
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Creates a new public key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the public key as a hex string
    pub fn as_hex(&self) -> String {
        bytes_to_hex_str(&self.bytes)
    }

    /// Returns the public key as bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the public key and returns it as bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.as_hex())
    }
}

/// A private key
pub struct PrivateKey {
    bytes: Vec<u8>,
}

impl PrivateKey {
    /// Creates a new private key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the private key as a hex string
    pub fn as_hex(&self) -> String {
        bytes_to_hex_str(&self.bytes)
    }

    /// Returns the private key as bytes
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the private key and returns it as bytes
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.as_hex())
    }
}

/// A signer for arbitrary messages
pub trait Signer: Send {
    /// Signs the given message
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningError>;

    /// Returns the signer's public key
    fn public_key(&self) -> Result<PublicKey, SigningError>;
}

// Verifies message signatures
pub trait SignatureVerifier: Send {
    /// Verifies that the provided signature is valid for the given message and public key
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &PublicKey,
    ) -> Result<bool, SignatureVerificationError>;
}

/// Converts the given hex string to bytes
fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>, HexError> {
    for (i, ch) in s.chars().enumerate() {
        if !ch.is_digit(16) {
            return Err(HexError(format!("invalid character position {}", i)));
        }
    }

    let input: Vec<_> = s.chars().collect();

    let decoded: Vec<u8> = input
        .chunks(2)
        .map(|chunk| {
            ((chunk[0].to_digit(16).unwrap() << 4) | (chunk[1].to_digit(16).unwrap())) as u8
        })
        .collect();

    Ok(decoded)
}

/// Converts the given bytes to a hex string
fn bytes_to_hex_str(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_BYTES: &[u8] = &[0x01, 0x02, 0x03, 0x04];

    /// Verifies the functionality of the `PublicKey` struct
    #[test]
    fn public_key() {
        let key = PublicKey::new(KEY_BYTES.into());
        assert_eq!(key.as_hex(), bytes_to_hex_str(KEY_BYTES));
        assert_eq!(key.as_slice(), KEY_BYTES);
        assert_eq!(key.into_bytes().as_slice(), KEY_BYTES);
    }

    /// Verifies the functionality of the `PrivateKey` struct
    #[test]
    fn private_key() {
        let key = PrivateKey::new(KEY_BYTES.into());
        assert_eq!(key.as_hex(), bytes_to_hex_str(KEY_BYTES));
        assert_eq!(key.as_slice(), KEY_BYTES);
        assert_eq!(key.into_bytes().as_slice(), KEY_BYTES);
    }
}
