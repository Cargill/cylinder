/*
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

use std::error::Error;
use std::fmt;

/// An error that may occur while building a JWT.
#[derive(Debug)]
pub struct JsonWebTokenBuildError {
    message: String,
    source: Box<dyn Error>,
}

impl JsonWebTokenBuildError {
    /// Constructs a new error.
    pub fn new<E: Into<Box<dyn Error>>>(message: String, source: E) -> Self {
        Self {
            message,
            source: source.into(),
        }
    }
}

impl fmt::Display for JsonWebTokenBuildError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for JsonWebTokenBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.source)
    }
}

/// An error that may occur while parsing or validating a JWT string.
#[derive(Debug)]
pub enum JsonWebTokenParseError {
    InvalidToken(String),
    InvalidSignature,
}

impl fmt::Display for JsonWebTokenParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            JsonWebTokenParseError::InvalidToken(msg) => f.write_str(&msg),
            JsonWebTokenParseError::InvalidSignature => f.write_str("The signature was invalid"),
        }
    }
}

impl Error for JsonWebTokenParseError {}
