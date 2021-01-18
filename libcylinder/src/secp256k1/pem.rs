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

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    error::ErrorStack,
    nid::Nid,
    pkey::Private as EcPrivate,
    symm::Cipher,
};

use crate::{Context, ContextError, KeyParseError, PrivateKey};

use super::Secp256k1Context;

pub fn private_key_from_pem(s: &str) -> Result<PrivateKey, KeyParseError> {
    let ec_key = EcKey::private_key_from_pem(s.as_bytes())?;

    Ok(PrivateKey::new(ec_key.private_key().to_vec()))
}

pub fn private_key_from_pem_with_password(s: &str, pw: &str) -> Result<PrivateKey, KeyParseError> {
    let ec_key = EcKey::private_key_from_pem_passphrase(s.as_bytes(), pw.as_bytes())?;

    Ok(PrivateKey::new(ec_key.private_key().to_vec()))
}

fn to_ec_key(key: &PrivateKey) -> Result<EcKey<EcPrivate>, KeyParseError> {
    let mut bignum_ctx = BigNumContext::new()?;
    let group = EcGroup::from_curve_name(Nid::SECP256K1)?;
    let key_bytes = BigNum::from_slice(key.as_slice())?;
    let pubkey = Secp256k1Context::new().get_public_key(&key)?;
    let pubkey = EcPoint::from_bytes(&group, pubkey.as_slice(), &mut bignum_ctx)?;

    Ok(EcKey::from_private_components(&group, &key_bytes, &pubkey)?)
}

pub fn private_key_to_pem(key: &PrivateKey) -> Result<String, KeyParseError> {
    let key = to_ec_key(key)?;
    let pem_bytes = key.private_key_to_pem()?;

    Ok(String::from_utf8_lossy(&pem_bytes).to_string())
}

pub fn private_key_to_pem_with_password(
    key: &PrivateKey,
    password: &str,
) -> Result<String, KeyParseError> {
    let key = to_ec_key(key)?;
    let pem_bytes =
        key.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), password.as_bytes())?;

    Ok(String::from_utf8_lossy(&pem_bytes).to_string())
}

impl From<ErrorStack> for KeyParseError {
    fn from(err: ErrorStack) -> Self {
        Self(err.to_string())
    }
}

impl From<ContextError> for KeyParseError {
    fn from(err: ContextError) -> Self {
        Self(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static KEY1_PRIV_HEX: &'static str =
        "2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088";
    static KEY1_PUB_HEX: &'static str =
        "026a2c795a9776f75464aa3bda3534c3154a6e91b357b1181d3f515110f84b67c5";

    static KEY2_PRIV_HEX: &'static str =
        "51b845c2cdde22fe646148f0b51eaf5feec8c82ee921d5e0cbe7619f3bb9c62d";
    static KEY2_PUB_HEX: &'static str =
        "039c20a66b4ec7995391dbec1d8bb0e2c6e6fd63cd259ed5b877cb4ea98858cf6d";
    #[cfg(feature = "pem")]
    static KEY2_PASS: &'static str = "hunter2";

    #[test]
    fn pem_roundtrip() {
        let context = Secp256k1Context::new();

        // Without password
        let priv_key1 =
            PrivateKey::new_from_hex(KEY1_PRIV_HEX).expect("Failed to parse key from hex");
        let pem_contents = private_key_to_pem(&priv_key1).unwrap();

        let parsed_priv_key = private_key_from_pem(&pem_contents).unwrap();
        let parsed_pub_key = context.get_public_key(&parsed_priv_key).unwrap();
        assert_eq!(KEY1_PRIV_HEX, parsed_priv_key.as_hex());
        assert_eq!(KEY1_PUB_HEX, parsed_pub_key.as_hex());

        // With password. Can't test exact pem contents due to salt changing for every run,
        // but can still test roundtrip
        let priv_key2 =
            PrivateKey::new_from_hex(KEY2_PRIV_HEX).expect("Failed to parse key from hex");
        let pem_contents = private_key_to_pem_with_password(&priv_key2, KEY2_PASS).unwrap();

        let parsed_priv_key = private_key_from_pem_with_password(&pem_contents, KEY2_PASS).unwrap();
        let parsed_pub_key = context.get_public_key(&parsed_priv_key).unwrap();
        assert_eq!(KEY2_PRIV_HEX, parsed_priv_key.as_hex());
        assert_eq!(KEY2_PUB_HEX, parsed_pub_key.as_hex());
    }
}
