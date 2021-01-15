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

use std::thread;

use cylinder::{Context, PrivateKey, PublicKey, Signature, Signer};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Verifies that signing the given message produces the expected signature.
fn test_signing<C: Context + 'static>(
    context: C,
    private_key: PrivateKey,
    message: &[u8],
    expected_signature: Signature,
) -> TestResult {
    assert_eq!(
        context.new_signer(private_key).sign(message)?,
        expected_signature
    );
    Ok(())
}

/// Verifies that the given signature/message match, as determined by the verifier that is created
/// from the given context.
fn test_verification<C: Context + 'static>(
    context: C,
    message: &[u8],
    signature: Signature,
    public_key: PublicKey,
) -> TestResult {
    assert!(context
        .new_verifier()
        .verify(message, &signature, &public_key)?);
    Ok(())
}

/// Verifies that the given signature/message do not match, as determined by the verifier that is
/// created from the given context.
fn test_verification_failure<C: Context + 'static>(
    context: C,
    message: &[u8],
    signature: Signature,
    public_key: PublicKey,
) -> TestResult {
    assert!(!context
        .new_verifier()
        .verify(message, &signature, &public_key)?);
    Ok(())
}

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

/// Verifies that multiple keys can be used to sign a message with a single context, and that the
/// resulting signatures can be correctly verified.
fn test_multiple_key_signing_and_verification<C: Context + 'static>(
    context: C,
    private_key1: PrivateKey,
    private_key2: PrivateKey,
) -> TestResult {
    let signer1 = context.new_signer(private_key1);
    let signature1 = signer1.sign(b"Hello")?;

    let signer2 = context.new_signer(private_key2);
    let signature2 = signer2.sign(b"Hello")?;

    let public_key1 = signer1.public_key()?;
    let public_key2 = signer2.public_key()?;
    let verifier = context.new_verifier();
    assert!(verifier.verify(b"Hello", &signature1, &public_key1)?);
    assert!(verifier.verify(b"Hello", &signature2, &public_key2)?);

    Ok(())
}

/// Verifies that the given context produces the expected public key from the given private key.
fn test_get_public_key<C: Context + 'static>(
    context: C,
    private_key: &PrivateKey,
    expected_public_key: PublicKey,
) -> TestResult {
    assert_eq!(context.get_public_key(&private_key)?, expected_public_key);
    Ok(())
}

/// Verifies that a signer with the given private key produces the expected public key.
fn test_signer_public_key<C: Context + 'static>(
    context: C,
    private_key: PrivateKey,
    expected_public_key: PublicKey,
) -> TestResult {
    let signer = context.new_signer(private_key);
    assert_eq!(signer.public_key()?, expected_public_key);
    Ok(())
}

/// Verifies that a signer can be returned from a function with only the private key supplied as an
/// argument.
fn test_signer_return_from_fn<F: FnOnce(PrivateKey) -> Box<dyn Signer>>(
    private_key: PrivateKey,
    function: F,
) -> TestResult {
    function(private_key);
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

    #[test]
    fn signer_return_from_fn() -> TestResult {
        let private_key = PrivateKey::new(vec![]);
        test_signer_return_from_fn(private_key, |key| HashContext.new_signer(key))
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

    const PRIV_KEY1: &str = "2f1e7b7a130d7ba9da0068b3bb0ba1d79e7e77110302c9f746c3c2a63fe40088";
    const PUB_KEY1: &str = "026a2c795a9776f75464aa3bda3534c3154a6e91b357b1181d3f515110f84b67c5";

    const PRIV_KEY2: &str = "51b845c2cdde22fe646148f0b51eaf5feec8c82ee921d5e0cbe7619f3bb9c62d";

    const MSG: &str = "test";
    const MSG_KEY1_SIG: &str = "5195115d9be2547b720ee74c23dd841842875db6eae1f5da8605b050a49e702b4aa83be72ab7e3cb20f17c657011b49f4c8632be2745ba4de79e6aa05da57b35";
    const INVALID_SIG: &str = "d589c7b1fa5f8a4c5a389de80ae9582c2f7f2a5e21bab5450b670214e5b1c1235e9eb8102fd0ca690a8b42e2c406a682bd57f6daf6e142e5fa4b2c26ef40a490";

    /// Verifies the signing capability of the secp256k1 implementation
    #[test]
    fn signing() -> TestResult {
        let private_key = PrivateKey::new_from_hex(PRIV_KEY1)?;
        let message = String::from(MSG).into_bytes();
        let expected_signature = Signature::from_hex(MSG_KEY1_SIG)?;
        test_signing(
            Secp256k1Context::new(),
            private_key,
            &message,
            expected_signature,
        )
    }

    /// Verifies the that a signature can be correctly verified by the secp256k1 implementation
    #[test]
    fn verification() -> TestResult {
        let message = String::from(MSG).into_bytes();
        let signature = Signature::from_hex(MSG_KEY1_SIG)?;
        let public_key = PublicKey::new_from_hex(PUB_KEY1)?;
        test_verification(Secp256k1Context::new(), &message, signature, public_key)
    }

    /// Verifies the that a signature can be correctly identified as invalid by the secp256k1
    /// implementation
    #[test]
    fn verification_failure() -> TestResult {
        let message = String::from(MSG).into_bytes();
        let signature = Signature::from_hex(INVALID_SIG)?;
        let public_key = PublicKey::new_from_hex(PUB_KEY1)?;
        test_verification_failure(Secp256k1Context::new(), &message, signature, public_key)
    }

    /// Verifies the round-trip signing and verifying of a message for the secp256k1 implementation
    #[test]
    fn signing_and_verification() -> TestResult {
        let private_key = PrivateKey::new_from_hex(PRIV_KEY1)?;
        test_signing_and_verification(Secp256k1Context::new(), private_key)
    }

    /// Verifies the signing and verifying of a message with multiple signers for the secp256k1
    /// implementation
    #[test]
    fn multiple_key_signing_and_verification() -> TestResult {
        let private_key1 = PrivateKey::new_from_hex(PRIV_KEY1)?;
        let private_key2 = PrivateKey::new_from_hex(PRIV_KEY2)?;
        test_multiple_key_signing_and_verification(
            Secp256k1Context::new(),
            private_key1,
            private_key2,
        )
    }

    /// Verifies the public key computation of the secp256k1 context implementation
    #[test]
    fn get_public_key() -> TestResult {
        let private_key = PrivateKey::new_from_hex(PRIV_KEY1)?;
        let public_key = PublicKey::new_from_hex(PUB_KEY1)?;
        test_get_public_key(Secp256k1Context::new(), &private_key, public_key)
    }

    /// Verifies the public key computation of the secp256k1 signer implementation
    #[test]
    fn signer_public_key() -> TestResult {
        let private_key = PrivateKey::new_from_hex(PRIV_KEY1)?;
        let public_key = PublicKey::new_from_hex(PUB_KEY1)?;
        test_signer_public_key(Secp256k1Context::new(), private_key, public_key)
    }

    #[test]
    fn signer_return_from_fn() -> TestResult {
        let private_key = PrivateKey::new_from_hex(PRIV_KEY1)?;
        test_signer_return_from_fn(private_key, |key| Secp256k1Context::new().new_signer(key))
    }

    /// Verifies the multithreaded signing capability of the secp256k1 implementation
    #[test]
    fn multithreaded_signing() -> TestResult {
        let private_key = PrivateKey::new_from_hex(PRIV_KEY1)?;
        test_multithreaded_signing(Secp256k1Context::new(), private_key)
    }
}
