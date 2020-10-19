# Release Notes

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
