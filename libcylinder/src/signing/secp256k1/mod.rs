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

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
pub mod pem;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::{rngs::OsRng, RngCore};

use crate::signing::Context;
use crate::signing::Error;
use crate::{PrivateKey, PublicKey, Signature};

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Self {
        Error::SigningError(Box::new(e))
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

    fn sign(&self, message: &[u8], key: &PrivateKey) -> Result<Signature, Error> {
        let mut sha = Sha256::new();
        sha.input(message);
        let hash: &mut [u8] = &mut [0; 32];
        sha.result(hash);

        let sk = secp256k1::key::SecretKey::from_slice(key.as_slice())?;
        let sig = self
            .context
            .sign(&secp256k1::Message::from_slice(hash)?, &sk);
        let compact = sig.serialize_compact();
        Ok(Signature::new(compact.to_vec()))
    }

    fn verify(
        &self,
        signature: &Signature,
        message: &[u8],
        key: &PublicKey,
    ) -> Result<bool, Error> {
        let mut sha = Sha256::new();
        sha.input(message);
        let hash: &mut [u8] = &mut [0; 32];
        sha.result(hash);

        let result = self.context.verify(
            &secp256k1::Message::from_slice(hash)?,
            &secp256k1::Signature::from_compact(signature.as_slice())?,
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

    use crate::signing::{create_context, ContextSigner, CryptoFactory};

    static KEY1_PRIV_HEX: &'static str =
        "2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088";
    static KEY1_PUB_HEX: &'static str =
        "026a2c795a9776f75464aa3bda3534c3154a6e91b357b1181d3f515110f84b67c5";

    static KEY2_PRIV_HEX: &'static str =
        "51b845c2cdde22fe646148f0b51eaf5feec8c82ee921d5e0cbe7619f3bb9c62d";
    static KEY2_PUB_HEX: &'static str =
        "039c20a66b4ec7995391dbec1d8bb0e2c6e6fd63cd259ed5b877cb4ea98858cf6d";

    static MSG1: &'static str = "test";
    static MSG1_KEY1_SIG: &'static str = "5195115d9be2547b720ee74c23dd841842875db6eae1f5da8605b050a49e702b4aa83be72ab7e3cb20f17c657011b49f4c8632be2745ba4de79e6aa05da57b35";

    static MSG2: &'static str = "test2";
    static MSG2_KEY2_SIG: &'static str = "d589c7b1fa5f8a4c5a389de80ae9582c2f7f2a5e21bab5450b670214e5b1c1235e9eb8102fd0ca690a8b42e2c406a682bd57f6daf6e142e5fa4b2c26ef40a490";

    #[test]
    fn priv_to_public_key() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let priv_key1 =
            PrivateKey::new_from_hex(KEY1_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key1.as_hex(), KEY1_PRIV_HEX);

        let public_key1 = context.get_public_key(&priv_key1).unwrap();
        assert_eq!(public_key1.as_hex(), KEY1_PUB_HEX);

        let priv_key2 =
            PrivateKey::new_from_hex(KEY2_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key2.as_hex(), KEY2_PRIV_HEX);

        let public_key2 = context.get_public_key(&priv_key2).unwrap();
        assert_eq!(public_key2.as_hex(), KEY2_PUB_HEX);
    }

    #[test]
    fn single_key_signing() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let factory = CryptoFactory::new(&*context);
        assert_eq!(factory.get_context().get_algorithm_name(), "secp256k1");

        let priv_key =
            PrivateKey::new_from_hex(KEY1_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key.as_hex(), KEY1_PRIV_HEX);

        let signer = factory.new_signer(&priv_key);
        let signature = signer.sign(&String::from(MSG1).into_bytes()).unwrap();
        assert_eq!(signature, Signature::from_hex(MSG1_KEY1_SIG).unwrap());
    }

    fn create_signer() -> ContextSigner<'static> {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let factory = CryptoFactory::new(&*context);
        assert_eq!(factory.get_context().get_algorithm_name(), "secp256k1");

        let priv_key =
            PrivateKey::new_from_hex(KEY1_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key.as_hex(), KEY1_PRIV_HEX);

        ContextSigner::new_boxed(context, priv_key)
    }

    #[test]
    fn single_key_signing_return_from_func() {
        let signer = create_signer();
        let signature = signer.sign(&String::from(MSG1).into_bytes()).unwrap();
        assert_eq!(signature, Signature::from_hex(MSG1_KEY1_SIG).unwrap());
    }

    #[test]
    fn many_key_signing() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let priv_key1 =
            PrivateKey::new_from_hex(KEY1_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key1.as_hex(), KEY1_PRIV_HEX);

        let priv_key2 =
            PrivateKey::new_from_hex(KEY2_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key2.as_hex(), KEY2_PRIV_HEX);

        let signature = context
            .sign(&String::from(MSG1).into_bytes(), &priv_key1)
            .unwrap();
        assert_eq!(signature, Signature::from_hex(MSG1_KEY1_SIG).unwrap());

        let signature = context
            .sign(&String::from(MSG2).into_bytes(), &priv_key2)
            .unwrap();
        assert_eq!(signature, Signature::from_hex(MSG2_KEY2_SIG).unwrap());
    }

    #[test]
    fn verification() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let pub_key1 = PublicKey::new_from_hex(KEY1_PUB_HEX).expect("Failed to parse key from hex");
        assert_eq!(pub_key1.as_hex(), KEY1_PUB_HEX);

        let signature = Signature::from_hex(MSG1_KEY1_SIG).expect("Failed to parse signature");
        let result = context.verify(&signature, &String::from(MSG1).into_bytes(), &pub_key1);
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn verification_error() {
        let context = create_context("secp256k1").unwrap();
        assert_eq!(context.get_algorithm_name(), "secp256k1");

        let pub_key1 = PublicKey::new_from_hex(KEY1_PUB_HEX).expect("Failed to parse key from hex");
        assert_eq!(pub_key1.as_hex(), KEY1_PUB_HEX);

        // This signature doesn't match for MSG1/KEY1
        let signature = Signature::from_hex(MSG2_KEY2_SIG).expect("Failed to parse signature");
        let result = context.verify(&signature, &String::from(MSG1).into_bytes(), &pub_key1);
        assert_eq!(result.unwrap(), false);
    }
}
