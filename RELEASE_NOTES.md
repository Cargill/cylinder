# Release Notes

## Changes in Cylinder 0.2.4

* Derives `Hash`, `PartialEq`, and `Eq` for `PublicKey` and `PrivateKey`. This
  allows `PublicKey` and/or `PrivateKey` to be contained in structs which derive
  `Hash`, `PartialEq`, and `Eq` themselves.

## Changes in Cylinder 0.2.3

* Update the `dirs` dependency version to 4.
* Update the `rand` dependency version to 0.8.
* Update the `secp256k1` dependency version to 0.20.
* Update the `whoami` dependency version to 1.1.
* Switch from Travis CI to GitHub Actions.

## Changes in Cylinder 0.2.2

* Stabilize the `jwt` and `key-load` features.
* Replace the `load_user_key` function with 4 new key loading functions:
  `current_user_search_path`, `current_user_key_name`, `load_key`, and
  `load_key_from_path`.

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
