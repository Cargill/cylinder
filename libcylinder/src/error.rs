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

//! Errors that can occur during the signing process

use std::error::Error;

/// An error that can occur with signing
#[derive(Debug)]
pub enum SigningError {
    Internal(String),
}

impl Error for SigningError {}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
        }
    }
}

impl From<HexError> for SigningError {
    fn from(err: HexError) -> Self {
        Self::Internal(err.to_string())
    }
}

/// An error that can occur with signature verification
#[derive(Debug)]
pub enum SignatureVerificationError {
    Internal(String),
}

impl Error for SignatureVerificationError {}

impl std::fmt::Display for SignatureVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Internal(msg) => f.write_str(msg),
        }
    }
}

/// An error that can occur when converting from hex
#[derive(Debug)]
pub struct HexError(pub String);

impl Error for HexError {}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
