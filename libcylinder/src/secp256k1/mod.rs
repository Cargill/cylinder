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

const ALGORITHM_NAME: &str = "secp256k1";

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
    fn algorithm_name(&self) -> &str {
        ALGORITHM_NAME
    }

    fn new_signer(&self, key: PrivateKey) -> Box<dyn Signer> {
        Box::new(Secp256k1Signer::new(self.context.clone(), key))
    }

    fn new_verifier(&self) -> Box<dyn Verifier> {
        Box::new(Secp256k1Verifier::new(self.context.clone()))
    }

    fn new_random_private_key(&self) -> PrivateKey {
        loop {
            let mut key = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
            OsRng.fill_bytes(&mut key);
            if secp256k1::SecretKey::from_slice(&key[..]).is_ok() {
                break PrivateKey::new(Vec::from(&key[..]));
            }
        }
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
    fn algorithm_name(&self) -> &str {
        ALGORITHM_NAME
    }

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

    fn clone_box(&self) -> Box<dyn Signer> {
        Box::new(self.clone())
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
    fn algorithm_name(&self) -> &str {
        ALGORITHM_NAME
    }

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
