
## Overview

Cylinder provides a simple and practical cryptographic signing and verification
API for Rust projects.  By building upon other cryptographic crates (such as
secp256k1), Cylinder avoids implementing any cryptography directly.

Features include:

* A Signer API for generating a signature by signing bytes with a private key
* A Verifier API for verifying a signature for a given message and public key
* A secp256k1 implementation of the Signer and Verifier APIs
* Functions for finding and loading keys in a consistent manner
* Support for Cylinder-compatible JSON Web Tokens (JWTs)

## Using Cylinder

The following resources are available for Cylinder:

  * [Crate](https://crates.io/crates/cylinder)
  * [Documentation](https://docs.rs/cylinder/latest/cylinder/)
  * [Git Repository](https://github.com/Cargill/cylinder)

## Projects using Cylinder

The following projects are currently using Cylinder:

* [Hyperledger Grid](https://grid.hyperledger.org/)
* [Hyperledger Sawtooth](https://sawtooth.hyperledger.org/)
* [Hyperledger Transact](https://github.com/hyperledger/transact)
* [Splinter](https://www.splinter.dev/)

## License

Cylinder is licensed under the [Apache License Version 2.0](LICENSE) software
license.
