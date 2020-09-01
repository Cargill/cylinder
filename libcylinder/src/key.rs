/*
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

//! Cryptographic keys

use std::error::Error;

use crate::hex::{bytes_to_hex_str, hex_str_to_bytes, HexError};

/// A public key
#[derive(Clone)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Creates a new public key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Creates a new public key from a hex string
    pub fn new_from_hex(hex: &str) -> Result<Self, KeyParseError> {
        Ok(Self::new(hex_str_to_bytes(hex)?))
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
#[derive(Clone)]
pub struct PrivateKey {
    bytes: Vec<u8>,
}

impl PrivateKey {
    /// Creates a new private key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Creates a new private key from a hex string
    pub fn new_from_hex(hex: &str) -> Result<Self, KeyParseError> {
        Ok(Self::new(hex_str_to_bytes(hex)?))
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

/// An error that can occur when parsing a key
#[derive(Debug)]
pub struct KeyParseError(pub String);

impl Error for KeyParseError {}

impl std::fmt::Display for KeyParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<HexError> for KeyParseError {
    fn from(err: HexError) -> Self {
        Self(err.to_string())
    }
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
