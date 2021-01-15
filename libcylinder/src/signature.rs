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

use crate::error::SignatureParseError;
use crate::hex;

/// A general signature value.
///
/// This signature type may wrap any signature that can be represented as bytes.
#[derive(PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// Constructs a new Signature from a given set of bytes.
    pub fn new(sig_bytes: Vec<u8>) -> Self {
        Self(sig_bytes)
    }

    /// Creates a new Signature from a hex string.
    ///
    /// # Errors
    ///
    /// Returns a SignatureParseError if the provided signature string is not valid hex.
    pub fn from_hex(sig_hex: &str) -> Result<Self, SignatureParseError> {
        hex::hex_str_to_bytes(sig_hex)
            .map(Self)
            .map_err(|e| SignatureParseError(e.to_string()))
    }

    /// Takes the bytes out of this Signature.
    pub fn take_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns a slice of the internal bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns a new hex representation of this Signature.
    pub fn as_hex(&self) -> String {
        hex::bytes_to_hex_str(&self.0)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_tuple("Signature").field(&self.as_hex()).finish()
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.as_hex())
    }
}
