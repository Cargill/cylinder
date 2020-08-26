/*
 * Copyright 2017 Intel Corporation
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
use crypto::digest::Digest;
use crypto::sha2::Sha256;
#[cfg(feature = "pem")]
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    error::ErrorStack,
    nid::Nid,
    pkey::Private as EcPrivate,
    symm::Cipher,
};
use rand::{rngs::OsRng, RngCore};

use crate::signing::Context;
use crate::signing::Error;
use crate::{hex_str_to_bytes, PrivateKey, PublicKey};

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::SigningError(Box::new(e))
    }
}

#[cfg(feature = "pem")]
impl From<ErrorStack> for Error {
    fn from(e: ErrorStack) -> Self {
        Error::SigningError(Box::new(e))
    }
}

#[cfg(feature = "pem")]
impl PrivateKey {
    pub fn from_pem(s: &str) -> Result<Self, Error> {
        let ec_key = EcKey::private_key_from_pem(s.as_bytes())?;

        Ok(Self::new(ec_key.private_key().to_vec()))
    }

    pub fn from_pem_with_password(s: &str, pw: &str) -> Result<Self, Error> {
        let ec_key = EcKey::private_key_from_pem_passphrase(s.as_bytes(), pw.as_bytes())?;

        Ok(Self::new(ec_key.private_key().to_vec()))
    }

    fn to_ec_key(&self) -> Result<EcKey<EcPrivate>, Error> {
        let mut bignum_ctx = BigNumContext::new()?;
        let context = Secp256k1Context::new();
        let group = EcGroup::from_curve_name(Nid::SECP256K1)?;
        let key_bytes = BigNum::from_slice(self.bytes.as_slice())?;
        let pubkey = context.get_public_key(self)?;
        let pubkey = EcPoint::from_bytes(&group, pubkey.as_slice(), &mut bignum_ctx)?;

        Ok(EcKey::from_private_components(&group, &key_bytes, &pubkey)?)
    }

    pub fn to_pem(&self) -> Result<String, Error> {
        let key = self.to_ec_key()?;
        let pem_bytes = key.private_key_to_pem()?;

        Ok(String::from_utf8_lossy(&pem_bytes).to_string())
    }

    pub fn to_pem_with_password(&self, password: &str) -> Result<String, Error> {
        let key = self.to_ec_key()?;
        let pem_bytes =
            key.private_key_to_pem_passphrase(Cipher::aes_128_cbc(), password.as_bytes())?;

        Ok(String::from_utf8_lossy(&pem_bytes).to_string())
    }
}

pub struct Secp256k1Context {
    context: secp256k1::Secp256k1<secp256k1::All>,
}

impl Secp256k1Context {
    pub fn new() -> Self {
        Secp256k1Context {
            context: secp256k1::Secp256k1::new(),
        }
    }
}

impl Default for Secp256k1Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context for Secp256k1Context {
    fn get_algorithm_name(&self) -> &str {
        "secp256k1"
    }

    fn sign(&self, message: &[u8], key: &PrivateKey) -> Result<String, Error> {
        let mut sha = Sha256::new();
        sha.input(message);
        let hash: &mut [u8] = &mut [0; 32];
        sha.result(hash);

        let sk = secp256k1::key::SecretKey::from_slice(key.as_slice())?;
        let sig = self
            .context
            .sign(&secp256k1::Message::from_slice(hash)?, &sk);
        let compact = sig.serialize_compact();
        Ok(compact
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(""))
    }

    fn verify(&self, signature: &str, message: &[u8], key: &PublicKey) -> Result<bool, Error> {
        let mut sha = Sha256::new();
        sha.input(message);
        let hash: &mut [u8] = &mut [0; 32];
        sha.result(hash);

        let result = self.context.verify(
            &secp256k1::Message::from_slice(hash)?,
            &secp256k1::Signature::from_compact(
                &hex_str_to_bytes(&signature).map_err(|err| Error::ParseError(err.to_string()))?,
            )?,
            &secp256k1::key::PublicKey::from_slice(key.as_slice())?,
        );
        match result {
            Ok(()) => Ok(true),
            Err(secp256k1::Error::IncorrectSignature) => Ok(false),
            Err(err) => Err(Error::from(err)),
        }
    }

    fn get_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey, Error> {
        let sk = secp256k1::key::SecretKey::from_slice(private_key.as_slice())?;
        Ok(PublicKey::new(
            secp256k1::key::PublicKey::from_secret_key(&self.context, &sk)
                .serialize()
                .to_vec(),
        ))
    }

    fn new_random_private_key(&self) -> Result<PrivateKey, Error> {
        let mut key = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Ok(PrivateKey::new(Vec::from(&key[..])))
    }
}

#[cfg(test)]
mod secp256k1_test {
    use super::*;

    use crate::signing::{create_context, CryptoFactory, Signer};

    static KEY1_PRIV: &'static [u8] = &[
        47, 30, 123, 122, 19, 13, 123, 169, 218, 0, 104, 179, 187, 11, 161, 215, 158, 126, 119, 17,
        3, 2, 201, 247, 70, 195, 194, 166, 63, 228, 0, 136,
    ];
    static KEY1_PUB: &'static [u8] = &[
        2, 106, 44, 121, 90, 151, 118, 247, 84, 100, 170, 59, 218, 53, 52, 195, 21, 74, 110, 145,
        179, 87, 177, 24, 29, 63, 81, 81, 16, 248, 75, 103, 197,
    ];

    static KEY2_PRIV: &'static [u8] = &[
        81, 184, 69, 194, 205, 222, 34, 254, 100, 97, 72, 240, 181, 30, 175, 95, 238, 200, 200, 46,
        233, 33, 213, 224, 203, 231, 97, 159, 59, 185, 198, 45,
    ];
    static KEY2_PUB: &'static [u8] = &[
        3, 156, 32, 166, 107, 78, 199, 153, 83, 145, 219, 236, 29, 139, 176, 226, 198, 230, 253,
        99, 205, 37, 158, 213, 184, 119, 203, 78, 169, 136, 88, 207, 109,
    ];
    #[cfg(feature = "pem")]
    static KEY2_PASS: &'static str = "hunter2";

    static MSG1: &'static str = "test";
    static MSG1_KEY1_SIG: &'static str = "5195115d9be2547b720ee74c23dd841842875db6eae1f5da8605b050a49e702b4aa83be72ab7e3cb20f17c657011b49f4c8632be2745ba4de79e6aa05da57b35";

    static MSG2: &'static str = "test2";
    static MSG2_KEY2_SIG: &'static str = "d589c7b1fa5f8a4c5a389de80ae9582c2f7f2a5e21bab5450b670214e5b1c1235e9eb8102fd0ca690a8b42e2c406a682bd57f6daf6e142e5fa4b2c26ef40a490";

    #[test]
    fn priv_to_public_key() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let priv_key1 = PrivateKey::new(KEY1_PRIV.into());
        assert_eq!(priv_key1.as_slice(), KEY1_PRIV);

        let public_key1 = context.get_public_key(&priv_key1).unwrap();
        assert_eq!(public_key1.as_slice(), KEY1_PUB);

        let priv_key2 = PrivateKey::new(KEY2_PRIV.into());
        assert_eq!(priv_key2.as_slice(), KEY2_PRIV);

        let public_key2 = context.get_public_key(&priv_key2).unwrap();
        assert_eq!(public_key2.as_slice(), KEY2_PUB);
    }

    #[test]
    #[cfg(feature = "pem")]
    fn pem_roundtrip() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        // Without password
        let priv_key1 = PrivateKey::new(KEY1_PRIV.into());
        let pem_contents = priv_key1.to_pem().unwrap();

        let parsed_priv_key = PrivateKey::from_pem(&pem_contents).unwrap();
        let parsed_pub_key = context.get_public_key(&parsed_priv_key).unwrap();
        assert_eq!(KEY1_PRIV, parsed_priv_key.as_slice());
        assert_eq!(KEY1_PUB, parsed_pub_key.as_slice());

        // With password. Can't test exact pem contents due to salt changing for every run,
        // but can still test roundtrip
        let priv_key2 = PrivateKey::new(KEY2_PRIV.into());
        let pem_contents = priv_key2.to_pem_with_password(KEY2_PASS).unwrap();

        let parsed_priv_key = PrivateKey::from_pem_with_password(&pem_contents, KEY2_PASS).unwrap();
        let parsed_pub_key = context.get_public_key(&parsed_priv_key).unwrap();
        assert_eq!(KEY2_PRIV, parsed_priv_key.as_slice());
        assert_eq!(KEY2_PUB, parsed_pub_key.as_slice());
    }

    #[test]
    fn single_key_signing() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let factory = CryptoFactory::new(&*context);
        assert_eq!(factory.get_context().get_algorithm_name(), "secp256k1");

        let priv_key = PrivateKey::new(KEY1_PRIV.into());
        assert_eq!(priv_key.as_slice(), KEY1_PRIV);

        let signer = factory.new_signer(&priv_key);
        let signature = signer.sign(&String::from(MSG1).into_bytes()).unwrap();
        assert_eq!(signature, MSG1_KEY1_SIG);
    }

    fn create_signer() -> Signer<'static> {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let factory = CryptoFactory::new(&*context);
        assert_eq!(factory.get_context().get_algorithm_name(), "secp256k1");

        let priv_key = PrivateKey::new(KEY1_PRIV.into());
        assert_eq!(priv_key.as_slice(), KEY1_PRIV);

        Signer::new_boxed(context, priv_key)
    }

    #[test]
    fn single_key_signing_return_from_func() {
        let signer = create_signer();
        let signature = signer.sign(&String::from(MSG1).into_bytes()).unwrap();
        assert_eq!(signature, MSG1_KEY1_SIG);
    }

    #[test]
    fn many_key_signing() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let priv_key1 = PrivateKey::new(KEY1_PRIV.into());
        assert_eq!(priv_key1.as_slice(), KEY1_PRIV);

        let priv_key2 = PrivateKey::new(KEY2_PRIV.into());
        assert_eq!(priv_key2.as_slice(), KEY2_PRIV);

        let signature = context
            .sign(&String::from(MSG1).into_bytes(), &priv_key1)
            .unwrap();
        assert_eq!(signature, MSG1_KEY1_SIG);

        let signature = context
            .sign(&String::from(MSG2).into_bytes(), &priv_key2)
            .unwrap();
        assert_eq!(signature, MSG2_KEY2_SIG);
    }

    #[test]
    fn verification() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let pub_key1 = PublicKey::new(KEY1_PUB.into());
        assert_eq!(pub_key1.as_slice(), KEY1_PUB);

        let result = context.verify(MSG1_KEY1_SIG, &String::from(MSG1).into_bytes(), &pub_key1);
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn verification_error() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let pub_key1 = PublicKey::new(KEY1_PUB.into());
        assert_eq!(pub_key1.as_slice(), KEY1_PUB);

        // This signature doesn't match for MSG1/KEY1
        let result = context.verify(MSG2_KEY2_SIG, &String::from(MSG1).into_bytes(), &pub_key1);
        assert_eq!(result.unwrap(), false);
    }
}
