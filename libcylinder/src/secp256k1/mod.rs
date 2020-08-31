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

#[cfg(feature = "pem")]
#[cfg_attr(docsrs, doc(cfg(feature = "pem")))]
pub mod pem;

use std::sync::Arc;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use rand::{rngs::OsRng, RngCore};

use crate::{
    Context, ContextError, PrivateKey, PublicKey, Signature, Signer, SigningError,
    VerificationError, Verifier,
};

pub struct Secp256k1Context {
    context: Arc<secp256k1::Secp256k1<secp256k1::All>>,
}

impl Secp256k1Context {
    pub fn new() -> Self {
        Secp256k1Context {
            context: Arc::new(secp256k1::Secp256k1::new()),
        }
    }
}

impl Default for Secp256k1Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context for Secp256k1Context {
    fn new_signer(&self, key: PrivateKey) -> Box<dyn Signer> {
        Box::new(Secp256k1Signer::new(self.context.clone(), key))
    }

    fn new_verifier(&self) -> Box<dyn Verifier> {
        Box::new(Secp256k1Verifier::new(self.context.clone()))
    }

    fn new_random_private_key(&self) -> PrivateKey {
        let mut key = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        PrivateKey::new(Vec::from(&key[..]))
    }

    fn get_public_key(&self, private_key: &PrivateKey) -> Result<PublicKey, ContextError> {
        let sk = secp256k1::key::SecretKey::from_slice(private_key.as_slice())?;
        Ok(PublicKey::new(
            secp256k1::key::PublicKey::from_secret_key(&self.context, &sk)
                .serialize()
                .to_vec(),
        ))
    }
}

#[derive(Clone)]
struct Secp256k1Signer {
    context: Arc<secp256k1::Secp256k1<secp256k1::All>>,
    key: PrivateKey,
}

impl Secp256k1Signer {
    pub fn new(context: Arc<secp256k1::Secp256k1<secp256k1::All>>, key: PrivateKey) -> Self {
        Self { context, key }
    }
}

impl Signer for Secp256k1Signer {
    fn sign(&self, message: &[u8]) -> Result<Signature, SigningError> {
        let mut sha = Sha256::new();
        sha.input(message);
        let hash: &mut [u8] = &mut [0; 32];
        sha.result(hash);

        let sk = secp256k1::key::SecretKey::from_slice(self.key.as_slice())?;
        let sig = self
            .context
            .sign(&secp256k1::Message::from_slice(hash)?, &sk);
        let compact = sig.serialize_compact();
        Ok(Signature::new(compact.to_vec()))
    }

    fn public_key(&self) -> Result<PublicKey, SigningError> {
        let sk = secp256k1::key::SecretKey::from_slice(self.key.as_slice())?;
        Ok(PublicKey::new(
            secp256k1::key::PublicKey::from_secret_key(&*self.context, &sk)
                .serialize()
                .to_vec(),
        ))
    }
}

#[derive(Clone)]
struct Secp256k1Verifier {
    context: Arc<secp256k1::Secp256k1<secp256k1::All>>,
}

impl Secp256k1Verifier {
    pub fn new(context: Arc<secp256k1::Secp256k1<secp256k1::All>>) -> Self {
        Self { context }
    }
}

impl Verifier for Secp256k1Verifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool, VerificationError> {
        let mut sha = Sha256::new();
        sha.input(message);
        let hash: &mut [u8] = &mut [0; 32];
        sha.result(hash);

        let result = self.context.verify(
            &secp256k1::Message::from_slice(hash)?,
            &secp256k1::Signature::from_compact(signature.as_slice())?,
            &secp256k1::key::PublicKey::from_slice(public_key.as_slice())?,
        );
        match result {
            Ok(()) => Ok(true),
            Err(secp256k1::Error::IncorrectSignature) => Ok(false),
            Err(err) => Err(VerificationError::from(err)),
        }
    }
}

impl From<secp256k1::Error> for ContextError {
    fn from(err: secp256k1::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<secp256k1::Error> for SigningError {
    fn from(err: secp256k1::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<secp256k1::Error> for VerificationError {
    fn from(err: secp256k1::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

#[cfg(test)]
mod secp256k1_test {
    use super::*;

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
        let context = Secp256k1Context::new();

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
        let priv_key =
            PrivateKey::new_from_hex(KEY1_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key.as_hex(), KEY1_PRIV_HEX);

        let signer = Secp256k1Context::new().new_signer(priv_key);
        let signature = signer.sign(&String::from(MSG1).into_bytes()).unwrap();
        assert_eq!(signature, Signature::from_hex(MSG1_KEY1_SIG).unwrap());
    }

    fn create_signer() -> Box<dyn Signer> {
        let key = PrivateKey::new_from_hex(KEY1_PRIV_HEX).expect("Failed to parse key from hex");
        Secp256k1Context::new().new_signer(key)
    }

    #[test]
    fn single_key_signing_return_from_func() {
        let signer = create_signer();
        let signature = signer.sign(&String::from(MSG1).into_bytes()).unwrap();
        assert_eq!(signature, Signature::from_hex(MSG1_KEY1_SIG).unwrap());
    }

    #[test]
    fn many_key_signing() {
        let context = Secp256k1Context::new();

        let priv_key1 =
            PrivateKey::new_from_hex(KEY1_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key1.as_hex(), KEY1_PRIV_HEX);

        let priv_key2 =
            PrivateKey::new_from_hex(KEY2_PRIV_HEX).expect("Failed to parse key from hex");
        assert_eq!(priv_key2.as_hex(), KEY2_PRIV_HEX);

        let signature = context
            .new_signer(priv_key1)
            .sign(&String::from(MSG1).into_bytes())
            .unwrap();
        assert_eq!(signature, Signature::from_hex(MSG1_KEY1_SIG).unwrap());

        let signature = context
            .new_signer(priv_key2)
            .sign(&String::from(MSG2).into_bytes())
            .unwrap();
        assert_eq!(signature, Signature::from_hex(MSG2_KEY2_SIG).unwrap());
    }

    #[test]
    fn verification() {
        let pub_key1 = PublicKey::new_from_hex(KEY1_PUB_HEX).expect("Failed to parse key from hex");
        assert_eq!(pub_key1.as_hex(), KEY1_PUB_HEX);

        let signature = Signature::from_hex(MSG1_KEY1_SIG).expect("Failed to parse signature");
        let result = Secp256k1Context::new().new_verifier().verify(
            &String::from(MSG1).into_bytes(),
            &signature,
            &pub_key1,
        );
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn verification_error() {
        let pub_key1 = PublicKey::new_from_hex(KEY1_PUB_HEX).expect("Failed to parse key from hex");
        assert_eq!(pub_key1.as_hex(), KEY1_PUB_HEX);

        // This signature doesn't match for MSG1/KEY1
        let signature = Signature::from_hex(MSG2_KEY2_SIG).expect("Failed to parse signature");
        let result = Secp256k1Context::new().new_verifier().verify(
            &String::from(MSG1).into_bytes(),
            &signature,
            &pub_key1,
        );
        assert_eq!(result.unwrap(), false);
    }
}
