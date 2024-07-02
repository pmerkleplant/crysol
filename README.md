<div align="center">

<h1>crysol</h1>

<a href="">[![Unit Tests][tests-shield]][tests-shield-url]</a>
<a href="">![Apache2/MIT licensed][license-shield]</a>
<a href="">[![Solidity][solidity-shield]][solidity-shield-url]</a>

</div>

`crysol` is a collection of **pure Solidity** libraries providing **elliptic curve cryptography** for **on- and offchain operations**.

## Libraries

```ml
src
├─ onchain
│  ├─ common
│  │  ├─ Message - "Functionality for constructing Ethereum Signed Message Hashes"
│  │  ├─ Nonce - "Deterministic nonce derivation"
│  │  └─ ModularArithmetic - "Provides modular arithmetic functionality"
│  ├─ secp256k1
│  │  ├─ Secp256k1 - "Cryptography-related functionality for the secp256k1 elliptic curve"
│  │  ├─ Secp256k1Arithmetic — "Arithmetic-related functionality for the secp256k1 elliptic curve"
│  │  └─ signatures
│  │     ├─ ECDSA — "ECDSA signature functionality for secp256k1"
│  │     └─ Schnorr — "Schnorr signature functionality for secp256k1"
│  └─ secp256r1
│     ├─ Secp256r1 - "Cryptography-related functionality for the secp256r1 elliptic curve"
│     └─ Secp256r1Arithmetic — "Arithmetic-related functionality for the secp256r1 elliptic curve"
├─ offchain
│  ├─ common
│  │  └─ RandomOffchain - "Access to cryptographically secure randomness"
│  └─ secp256k1
│     ├─ Secp256k1Offchain - "Cryptography-related functionality for the secp256k1 elliptic curve"
│     └─ signatures
│        ├─ ECDSAOffchain — "ECDSA signature functionality for secp256k1"
│        └─ SchnorrOffchain — "Schnorr signature functionality for secp256k1"
└─ unsafe
   └─ secp256k1
      └─ signatures
         └─ ECDSAUnsafe — "Unsafe ECDSA signature functionality for secp256k1"
```

## Installation

Install with [Foundry](https://getfoundry.sh/):

```bash
$ forge install verklegarden/crysol
```

## Examples

Several examples are provided in [`examples/`](./examples), such as:
- secure key pair and Ethereum address creation
- secp256k1 point arithmetic
- Schnorr and ECDSA signature creation and verification

## Contributing

The project uses the Foundry toolchain. You can find installation instructions [here](https://getfoundry.sh/).

Setup:

```bash
$ git clone https://github.com/verklegarden/crysol
$ cd crysol/
$ forge install
```

Run tests:

```bash
$ forge test
$ forge test -vvvv # Run with full stack traces
$ FOUNDRY_PROFILE=intense forge test # Run in intense mode
```

Lint:

```bash
$ forge fmt [--check]
```

## Safety

This is **experimental software** and is provided on an "as is" and "as available" basis.

We **do not give any warranties** and **will not be liable** for any loss incurred through any use of this codebase.

<!--- Shields -->
[tests-shield]: https://github.com/verklegarden/crysol/actions/workflows/unit-tests.yml/badge.svg
[tests-shield-url]: https://github.com/verklegarden/crysol/actions/workflows/unit-tests.yml
[license-shield]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[solidity-shield]: https://img.shields.io/badge/solidity-%3E=0.8.16%20%3C=0.8.26-aa6746
[solidity-shield-url]: https://github.com/verklegarden/crysol/actions/workflows/solc-version-tests.yml
