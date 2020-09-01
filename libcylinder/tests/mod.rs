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

use std::thread;

use cylinder::{Context, PrivateKey, Signature};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Verifies that the round-trip of signing and verifying some bytes using a signer and verifier
/// produced using the given context and private key.
fn test_signing_and_verification<C: Context + 'static>(
    context: C,
    private_key: PrivateKey,
) -> TestResult {
    let signer = context.new_signer(private_key);
    let signature = signer.sign(b"Hello")?;

    let public_key = signer.public_key()?;
    let verifier = context.new_verifier();
    assert!(verifier.verify(b"Hello", &signature, &public_key)?);

    Ok(())
}

/// Verifies that the given context can be used to create and share signers across multiple threads.
fn test_multithreaded_signing<C: Context + 'static>(
    context: C,
    private_key: PrivateKey,
) -> TestResult {
    let signer = context.new_signer(private_key);

    let signer1 = signer.clone();
    let jh1: thread::JoinHandle<Signature> =
        thread::spawn(move || signer1.sign(b"Hello").expect("Unable to sign bytes"));

    let signer2 = signer.clone();
    let jh2: thread::JoinHandle<Signature> =
        thread::spawn(move || signer2.sign(b"Hello").expect("Unable to sign bytes"));

    let sig1 = jh1.join().expect("child thread 1 panicked");
    let sig2 = jh2.join().expect("child thread 2 panicked");

    assert_eq!(sig1, sig2);

    let public_key = signer.public_key()?;
    let verifier = context.new_verifier();
    assert!(verifier.verify(b"Hello", &sig1, &public_key)?);
    assert!(verifier.verify(b"Hello", &sig2, &public_key)?);

    Ok(())
}

#[cfg(feature = "hash")]
mod hash {
    use super::*;

    use cylinder::hash::HashContext;

    /// Verifies the round-trip signing and verifying of a message for the hash implementation
    #[test]
    fn signing_and_verification() -> TestResult {
        let private_key = PrivateKey::new(vec![]);
        test_signing_and_verification(HashContext, private_key)
    }

    /// Verifies the multithreaded signing capability of the hash implementation
    #[test]
    fn multithreaded_signing() -> TestResult {
        let private_key = PrivateKey::new(vec![]);
        test_multithreaded_signing(HashContext, private_key)
    }
}

mod secp256k1 {
    use super::*;

    use cylinder::secp256k1::Secp256k1Context;

    /// Verifies the multithreaded signing capability of the secp256k1 implementation
    #[test]
    fn multithreaded_signing() -> TestResult {
        let private_key = PrivateKey::new_from_hex(
            "2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088",
        )
        .expect("Unable to parse private key");
        test_multithreaded_signing(Secp256k1Context::new(), private_key)
    }
}
