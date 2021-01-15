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

//! Provides a set of APIs to both generate JSON Web Tokens (JWTs) with cylinder signing algorithms,
//! as well as parse and cryptographically validate the contents of the strings.
//!
//! The JWT header follows the standard, minimally consisting of a type (`"typ"`) of
//! `"cylinder+jwt"` and an algorithm (`"alg"`) value that depends on the Signer implementation.
//!
//! The claims section of the JWT automatically includes this issuer (`"iss"`) field.  This field
//! is set to public key of the token's signer.  In other words, a Cylinder JWT is issued by the
//! signing party.
//!
//! While this format will still be parseable by other JWT libraries, most likely the signing
//! algorithm specified in the header will not be understood.
//!
//! The token produced is actually JWT-like, as the algorithms currently provided by Cylinder are
//! not part of the standard set.  The implementation only provides the ability to create flat JSON
//! objects, both for the header and for the claims.  Complex, nested JSON objects are beyond the
//! scope of this initial design.
//!
//! Cylinder JWT is guarded by the feature `"jwt"`.
//!
//! # Example
//!
//! ## Creating a token
//!
//! The token is created via the `JsonWebTokenBuilder`, and may be signed with any `Signer`
//! implementation.
//!
//!
//! ```
//! use std::collections::HashMap;
//! use cylinder::{
//!     jwt::JsonWebTokenBuilder, PrivateKey, Context, Signer, secp256k1::Secp256k1Context
//! };
//!
//! let context = Secp256k1Context::new();
//! let private_key = context.new_random_private_key();
//! let signer = context.new_signer(private_key);
//!
//! let mut header = HashMap::new();
//! header.insert("example".into(), "header".into());
//!
//! let mut claims = HashMap::new();
//! claims.insert("example".into(), "claim".into());
//!
//! let encoded_token = JsonWebTokenBuilder::new()
//!     .with_header(header)
//!     .with_claims(claims)
//!     .build(&*signer)
//!     .expect("Unable to generate auth JWT");
//! ```
//!
//! The resulting string is
//!
//!  ```ignore
//!  "[Base-64-encoded bytes of the UTF-8 string of the header JSON].\
//!   [Base-64-encoded bytes of the UTF-8 string of the claims JSON].\
//!   [Base-64-encoded signature]"
//!  ```
//!
//! ## Parsing and Verifying
//!
//! The token produced can be parsed and validated, using a Verifier instance matching the signing
//! algorithm.
//!
//!```
//! # use std::collections::HashMap;
//! # use cylinder::jwt::JsonWebTokenBuilder;
//! # use cylinder::{PrivateKey, Signer};
//! use cylinder::{
//!     jwt::JsonWebTokenParser, Context, Verifier, secp256k1::Secp256k1Context
//! };
//!
//! let context = Secp256k1Context::new();
//! # let private_key = context.new_random_private_key();
//! # let signer = context.new_signer(private_key);
//! # let mut header = HashMap::new();
//! # header.insert("example".into(), "header".into());
//! # let mut claims = HashMap::new();
//! # claims.insert("example".into(), "claim".into());
//! # let encoded_token = JsonWebTokenBuilder::new()
//! #     .with_header(header)
//! #     .with_claims(claims)
//! #     .build(&*signer)
//! #     .expect("Unable to generate auth JWT");
//! let verifier = context.new_verifier();
//! let parser = JsonWebTokenParser::new(&*verifier);
//! let jwt = parser.parse(&encoded_token)
//!     .expect("Unable to parse token");
//!
//! assert_eq!(jwt.header().get("example"), Some(&String::from("header")));
//! assert_eq!(jwt.claims().get("example"), Some(&String::from("claim")));
//! ```

mod error;

use std::collections::HashMap;

use crate::{PublicKey, Signature, Signer, Verifier};

pub use error::{JsonWebTokenBuildError, JsonWebTokenParseError};

/// Builder for constructing the JWT string that would be included in HTTP request headers.
#[derive(Default)]
pub struct JsonWebTokenBuilder {
    header: HashMap<String, String>,
    claims: HashMap<String, String>,
}

impl JsonWebTokenBuilder {
    /// Constructs a new instance of the builder.
    pub fn new() -> Self {
        Self {
            header: HashMap::with_capacity(0),
            claims: HashMap::with_capacity(0),
        }
    }

    /// Sets the header of the token.
    ///
    /// The standard header keys of `alg` and `typ` will be added to the resulting JSON object. If
    /// these keys are included in the given map, they will be overridden at build time.
    pub fn with_header(mut self, header: HashMap<String, String>) -> Self {
        self.header = header;

        self
    }

    /// Sets the claims of the token.
    ///
    /// The standard header of `iss` (issuer) will be added to the resulting JSON object. This will
    /// be set to the public key value of the signer used at build time. If the key is included in
    /// the given map, it will be overridden.
    pub fn with_claims(mut self, claims: HashMap<String, String>) -> Self {
        self.claims = claims;

        self
    }

    /// Serializes and signs the JsonWebToken.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use cylinder::{
    ///     jwt::JsonWebTokenBuilder, PrivateKey, Context, Signer, secp256k1::Secp256k1Context
    /// };
    ///
    /// let context = Secp256k1Context::new();
    /// let private_key = context.new_random_private_key();
    /// let signer = context.new_signer(private_key);
    ///
    /// let mut header = HashMap::new();
    /// header.insert("example".into(), "header".into());
    ///
    /// let mut claims = HashMap::new();
    /// claims.insert("example".into(), "claim".into());
    ///
    /// let encoded_token = JsonWebTokenBuilder::new()
    ///     .with_header(header)
    ///     .with_claims(claims)
    ///     .build(&*signer)
    ///     .expect("Unable to generate auth JWT");
    /// ```
    ///
    /// The resulting string is
    ///
    ///  ```ignore
    ///  "[Base-64-encoded bytes of the UTF-8 string of the header JSON].\
    ///   [Base-64-encoded bytes of the UTF-8 string of the claims JSON].\
    ///   [Base-64-encoded signature]"
    ///  ```
    ///
    /// # Errors
    ///
    /// A [`JsonWebTokenBuildError`](struct.JsonWebTokenBuildError.html) may be returned if the
    /// token can not be properly built or signed.
    pub fn build(self, signer: &dyn Signer) -> Result<String, JsonWebTokenBuildError> {
        let mut jwt_header = json::JsonValue::new_object();

        for (k, v) in self.header {
            jwt_header[k] = v.into();
        }
        jwt_header["alg"] = signer.algorithm_name().into();
        jwt_header["typ"] = "cylinder+jwt".into();

        // Header bytes are UTF-8 bytes of the JSON string representation of the header
        let header_bytes = json::stringify(jwt_header).into_bytes();

        let public_key = signer.public_key().map_err(|e| {
            JsonWebTokenBuildError::new(
                "Unable to get the public key from the provided signer".into(),
                e,
            )
        })?;

        let mut claims = json::JsonValue::new_object();
        for (k, v) in self.claims {
            claims[k] = v.into()
        }

        claims["iss"] = public_key.as_hex().into();

        // Claims bytes are the UTF-8 bytes of the JSON string representation of the header
        let claims_bytes = json::stringify(claims).into_bytes();

        let mut token = String::new();

        token.push_str(&base64::encode(header_bytes));
        token.push('.');
        token.push_str(&base64::encode(claims_bytes));

        let signature = signer
            .sign(token.as_bytes())
            .map_err(|e| JsonWebTokenBuildError::new("Unable to sign the token".into(), e))?;

        token.push('.');
        token.push_str(&base64::encode(signature.as_slice()));

        Ok(token)
    }
}

/// Parses a [`JsonWebToken`](struct.JsonWebToken.html) from an encoded token.
pub struct JsonWebTokenParser<'a> {
    verifier: &'a dyn Verifier,
}

impl<'a> JsonWebTokenParser<'a> {
    /// Constructs a new parser instance around the given verifier.
    pub fn new(verifier: &'a dyn Verifier) -> Self {
        Self { verifier }
    }

    /// Parses the token string provided and verifies the included signature.
    ///
    /// # Errors
    ///
    /// A [`JsonWebTokenParseError`](enum.JsonWebTokenParseError.html) may be returned if the token
    /// is not properly formed or the signature is not valid.
    pub fn parse(&self, jwt_string: &str) -> Result<JsonWebToken, JsonWebTokenParseError> {
        let mut encoded_token_parts = jwt_string.split('.');
        let (encoded_header, encoded_claims, encoded_signature) = {
            match (
                encoded_token_parts.next(),
                encoded_token_parts.next(),
                encoded_token_parts.next(),
            ) {
                (Some(encoded_header), Some(encoded_claims), Some(encoded_signature)) => {
                    (encoded_header, encoded_claims, encoded_signature)
                }
                (Some(_), Some(_), None) => {
                    return Err(JsonWebTokenParseError::InvalidToken(
                        "Missing signature".into(),
                    ))
                }
                (Some(_), None, _) => {
                    return Err(JsonWebTokenParseError::InvalidToken(
                        "Missing claims".into(),
                    ))
                }
                (None, _, _) => unreachable!(),
            }
        };

        let header = Self::parse_object(encoded_header, |object| {
            if !object.has_key("typ") || object["typ"] != "cylinder+jwt" {
                return Err(JsonWebTokenParseError::InvalidToken(
                    "JWT does not support cylinder extensions".into(),
                ));
            }

            if !object.has_key("alg") || object["alg"] != self.verifier.algorithm_name() {
                return Err(JsonWebTokenParseError::InvalidToken(
                    "JWT does not use a supported algorithm".into(),
                ));
            }

            Ok(())
        })?;

        let claims = Self::parse_object(encoded_claims, |object| {
            if !object.has_key("iss") {
                Err(JsonWebTokenParseError::InvalidToken(
                    "JWT claims has not provided the \"iss\" field".into(),
                ))
            } else {
                Ok(())
            }
        })?;

        let signature_bytes = base64::decode(encoded_signature).map_err(|_| {
            JsonWebTokenParseError::InvalidToken(
                "JWT signature is not valid Base64 encoded bytes".into(),
            )
        })?;

        let public_key = PublicKey::new_from_hex(&claims["iss"]).map_err(|_| {
            JsonWebTokenParseError::InvalidToken(
                "JWT claims do not include a valid public key".into(),
            )
        })?;

        let verified = self
            .verifier
            .verify(
                format!("{}.{}", encoded_header, encoded_claims).as_bytes(),
                &Signature::new(signature_bytes),
                &public_key,
            )
            .map_err(|_| JsonWebTokenParseError::InvalidSignature)?;

        if verified {
            Ok(JsonWebToken {
                header,
                claims,
                issuer: public_key,
            })
        } else {
            Err(JsonWebTokenParseError::InvalidSignature)
        }
    }

    fn parse_object<F>(
        encoded_object: &str,
        validate: F,
    ) -> Result<HashMap<String, String>, JsonWebTokenParseError>
    where
        F: Fn(&json::JsonValue) -> Result<(), JsonWebTokenParseError>,
    {
        let object = base64::decode(encoded_object)
            .map_err(|_| {
                JsonWebTokenParseError::InvalidToken(
                    "JWT object is not valid Base64 encoded bytes".into(),
                )
            })
            .and_then(|object_bytes| {
                String::from_utf8(object_bytes).map_err(|_| {
                    JsonWebTokenParseError::InvalidToken(
                        "JWT object is not valid UTF-8 bytes".into(),
                    )
                })
            })
            .and_then(|object_str| {
                json::parse(&object_str).map_err(|_| {
                    JsonWebTokenParseError::InvalidToken("JWT object is not valid JSON".into())
                })
            })?;

        if !object.is_object() {
            return Err(JsonWebTokenParseError::InvalidToken(
                "Malformed JWT object: expected object".into(),
            ));
        }

        validate(&object)?;

        Ok(object
            .entries()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect())
    }
}

/// Native representation of a JSON web token used for validation.
#[derive(Debug)]
pub struct JsonWebToken {
    issuer: PublicKey,
    header: HashMap<String, String>,
    claims: HashMap<String, String>,
}

impl JsonWebToken {
    /// Returns the header map for this JWT
    pub fn header(&self) -> &HashMap<String, String> {
        &self.header
    }

    /// Returns the claims map for this JWT
    pub fn claims(&self) -> &HashMap<String, String> {
        &self.claims
    }

    /// Returns the public key of the issuer of this JWT
    pub fn issuer(&self) -> &PublicKey {
        &self.issuer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{secp256k1::Secp256k1Context, Context, PrivateKey};

    /// This test constructs a signed Json Web Token string and verifies that it can be read and
    /// verified by the parse method.
    #[test]
    fn test_round_trip() {
        let context = Secp256k1Context::new();
        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let signer = context.new_signer(private_key);

        let encoded_token = JsonWebTokenBuilder::new()
            .build(&*signer)
            .expect("Unable to generate auth JWT");

        let verifier = context.new_verifier();

        let json_web_token = JsonWebTokenParser::new(&*verifier)
            .parse(&encoded_token)
            .expect("Unable to get public key from JWT");

        assert_eq!(
            &signer.public_key().expect("could not get pubkey"),
            json_web_token.issuer()
        );
    }

    /// This test constructs a signed Json Web Token string using custom header values and verifies
    /// that it can be read and verified by the parse method.
    #[test]
    fn test_round_trip_with_custom_header_values() {
        let context = Secp256k1Context::new();
        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let signer = context.new_signer(private_key);

        let mut header = HashMap::new();
        header.insert("test".into(), "hello".into());
        let encoded_token = JsonWebTokenBuilder::new()
            .with_header(header)
            .build(&*signer)
            .expect("Unable to generate auth JWT");

        let verifier = context.new_verifier();

        let json_web_token = JsonWebTokenParser::new(&*verifier)
            .parse(&encoded_token)
            .expect("Unable to get public key from JWT");

        assert_eq!(
            &signer.public_key().expect("could not get pubkey"),
            json_web_token.issuer()
        );

        assert_eq!(
            Some(&"hello".to_string()),
            json_web_token.header().get("test")
        );
    }

    /// This test constructs a signed JsonWebToken and then replaces the signature with an invalid
    /// one.  The parse_and_verify method should return an InvalidSignature error variant.
    #[test]
    fn test_bad_signature() {
        let context = Secp256k1Context::new();
        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let signer = context.new_signer(private_key);

        let encoded_token = JsonWebTokenBuilder::new()
            .build(&*signer)
            .expect("Unable to generate auth JWT");

        // Take the first two parts (the header and the claims).
        let mut token_parts = encoded_token.splitn(3, '.');
        let header = token_parts.next().expect("no header");
        let claims = token_parts.next().expect("no claims");
        let sig = token_parts.next().expect("no signature");
        let bad_sig = std::iter::repeat('0').take(sig.len()).collect::<String>();
        let badly_signed_encoded_token = format!("{}.{}.{}", header, claims, bad_sig);

        let verifier = context.new_verifier();

        match JsonWebTokenParser::new(&*verifier).parse(&badly_signed_encoded_token) {
            Err(JsonWebTokenParseError::InvalidSignature) => (),
            Err(err) => panic!("Unexpected error {:?}", err),
            Ok(_) => panic!("Should not have validated the token"),
        }
    }

    /// This test constructs a signed JsonWebToken and then replaces the signature with a different
    /// signer's signature.  The parse_and_verify method should return an InvalidSignature error
    /// variant.
    #[test]
    fn test_alternate_signer() {
        let context = Secp256k1Context::new();
        let private_key = PrivateKey::new(vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ]);
        let signer = context.new_signer(private_key);

        let encoded_token = JsonWebTokenBuilder::new()
            .build(&*signer)
            .expect("Unable to generate auth JWT");

        // Take the first two parts (the header and the claims).
        let mut token_parts = encoded_token.splitn(3, '.');
        let header = token_parts.next().expect("no header");
        let claims = token_parts.next().expect("no claims");

        // construct an alternate signer and sign the token
        let alt_signer = context.new_signer(context.new_random_private_key());

        let bad_sig = alt_signer
            .sign(format!("{}.{}", header, claims).as_bytes())
            .expect("Unable to create new signature");
        let badly_signed_encoded_token = format!("{}.{}.{}", header, claims, bad_sig);

        let verifier = context.new_verifier();

        match JsonWebTokenParser::new(&*verifier).parse(&badly_signed_encoded_token) {
            Err(JsonWebTokenParseError::InvalidSignature) => (),
            Err(err) => panic!("Unexpected error {:?}", err),
            Ok(_) => panic!("Should not have validated the token"),
        }
    }

    /// This test create tokens with badly formatted claims and header values, then it confirms
    /// that the values fail to parse.
    #[test]
    fn test_invalid_claims_json_structure() {
        let context = Secp256k1Context::new();
        let verifier = context.new_verifier();
        let parser = JsonWebTokenParser::new(&*verifier);

        // Test badly formatted claims
        fn test_bad_claims(parser: &JsonWebTokenParser, bad_claims: &str) {
            let header = r#"{
              "typ": "cylinder+jwt",
              "alg": "secp256k1"
            }"#;

            let token = format!(
                "{}.{}.changeme",
                base64::encode(header.as_bytes()),
                base64::encode(bad_claims.as_bytes())
            );

            match parser.parse(&token) {
                Err(JsonWebTokenParseError::InvalidToken(_)) => (),
                Err(err) => panic!("Unexpected error: {:?}", err),
                Ok(_) => panic!("Should not have parsed the token"),
            }
        }

        // invalid JSON type
        test_bad_claims(&parser, "[1, 2, 3]");
        // Missing JSON token
        test_bad_claims(&parser, r#"{"iss": "foobar""#);
        // Invalid JSON
        test_bad_claims(&parser, "bad_json");

        // Test badly formatted claims
        fn test_bad_header(parser: &JsonWebTokenParser, bad_header: &str) {
            let claims = r#"{
              "iss": "somepubkey
            }"#;
            let token = format!(
                "{}.{}.changeme",
                base64::encode(bad_header.as_bytes()),
                base64::encode(claims.as_bytes())
            );

            match parser.parse(&token) {
                Err(JsonWebTokenParseError::InvalidToken(_)) => (),
                Err(err) => panic!("Unexpected error: {:?}", err),
                Ok(_) => panic!("Should not have parsed the token"),
            }
        }

        // invalid JSON type
        test_bad_header(&parser, "[1, 2, 3]");
        // missing opening token
        test_bad_header(
            &parser,
            r#"
          "typ": "cylinder+jwt",
          "alg": "secp256k1"
        }"#,
        );
        // invalid JSON
        test_bad_header(&parser, "invalid_json");
    }

    /// This test creates a token that has bad base64 values.  It should fail to parse.
    #[test]
    fn test_bad_base64() {
        let context = Secp256k1Context::new();
        let verifier = context.new_verifier();
        let parser = JsonWebTokenParser::new(&*verifier);

        match parser.parse("This is bad base64.because it has whitespace.but all the correct parts")
        {
            Err(JsonWebTokenParseError::InvalidToken(_)) => (),
            Err(err) => panic!("Unexpected error: {:?}", err),
            Ok(_) => panic!("Should not have parsed the token"),
        }
    }

    /// This test creates a token with an alternative signing algorithm as well as verifies it
    /// using the same algorithm.
    #[cfg(feature = "hash")]
    #[test]
    fn test_alternative_algorithm() {
        let context = crate::hash::HashContext;
        let private_key = context.new_random_private_key();
        let signer = context.new_signer(private_key);

        let mut header = HashMap::new();
        header.insert("test".into(), "hello".into());

        let encoded_token = JsonWebTokenBuilder::new()
            .with_header(header)
            .build(&*signer)
            .expect("Unable to generate auth JWT");

        let verifier = context.new_verifier();
        let json_web_token = JsonWebTokenParser::new(&*verifier)
            .parse(&encoded_token)
            .expect("Unable to get public key from JWT");

        assert_eq!(
            &signer.public_key().expect("could not get pubkey"),
            json_web_token.issuer()
        );

        assert_eq!(
            Some(&"hello".to_string()),
            json_web_token.header().get("test")
        );
    }

    /// This test creates a token with an alternate signer relative to the verifier used during
    /// parsing of the token.
    #[cfg(feature = "hash")]
    #[test]
    fn test_mismatched_algorithm() {
        let context = crate::hash::HashContext;
        let private_key = context.new_random_private_key();
        let signer = context.new_signer(private_key);

        let encoded_token = JsonWebTokenBuilder::new()
            .build(&*signer)
            .expect("Unable to generate auth JWT");

        let context = Secp256k1Context::new();
        let verifier = context.new_verifier();
        let parser = JsonWebTokenParser::new(&*verifier);

        match parser.parse(&encoded_token) {
            Err(JsonWebTokenParseError::InvalidToken(_)) => (),
            Err(err) => panic!("Unexpected error: {:?}", err),
            Ok(_) => panic!("Should not have parsed the token"),
        }
    }
}
