# Release Notes

## Changes in Cylinder 0.2.1

* Add the `VerifierFactory` trait that provides a concise API for creating
  signature verifiers.
* Require the `Send` marker trait for all implementations of the `Context` trait.

### Experimental Changes

* Improve testing and documentation of the `jwt` module
* Add the `load_user_key` function for loading a key from a file. This function
  is guarded by the experimental `key-load` feature.

## Changes in Cylinder 0.2.0

* `Signer`, `Verifier` and `Context` traits now require a method
  `algorithm_name(&self) -> &str`,

### Experimental Changes

* Add an experimental module to produce Cylinder-extended JSON Web Tokens.
  These JWT's use Cylinder's core `Signer` and `Verifier` traits to provide an
  avenue for applying custom signing algorithm options. The JWT's assume the
  public key of the `Signer` to be the "issuer" of the token.  This module is
  guarded by the experimental `jwt` feature.

## Changes in Cylinder 0.1.2

* `PublicKey` now implements `PartialEq` and `Debug`
* Only return valid new random secp256k1 private keys.  This removes a rare, but
  possible, bug where invalid keys could be generated.

## Changes in Cylinder 0.1.1

### Experimental Changes

* Add a hash implementation of the `Context`, `Signer`, and `Verifier` traits to
  be used for testing; this implementation is guarded by the experimental `hash`
  feature.

## Changes in Cylinder 0.1.0

* Initialize the library with a simple public interface that encapsulates
  algorithm implementation details

* Provide a secp256k1 implementation for `Context`, `Signer`, and `Verifier`
