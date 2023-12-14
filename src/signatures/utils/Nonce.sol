/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Secp256k1, SecretKey} from "../../curves/Secp256k1.sol";

// TODO: Goal: Library to derive deterministic nonces following RFC 6979.
//
//       For Rust implementation (used by foundry), see:
//       - https://github.com/RustCrypto/signatures/blob/master/rfc6979/src/lib.rs#L77
//       - https://github.com/RustCrypto/signatures/blob/master/rfc6979/src/lib.rs#L135

/**
 * @title Nonce
 *
 * @notice Provides deterministic nonce derivation
 *
 * @dev ...
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 */
library Nonce {
    using Nonce for SecretKey;
    using Secp256k1 for PrivateKey;

    /// @dev Derives a deterministic nonce from secret key `sk` and message
    ///      `message`.
    ///
    /// @dev Note that a nonce is of type uint and not bounded by any field!
    ///
    /// @custom:invariant Keccak256 image is never zero
    ///     ∀ (sk, msg) ∊ (SecretKey, bytes): keccak256(sk ‖ keccak256(message)) != 0
    function deriveNonce(SecretKey sk, bytes memory message)
        internal
        pure
        returns (uint)
    {
        bytes32 digest = keccak256(message);

        return sk.deriveNonce(digest);
    }

    /// @dev Derives a deterministic nonce from secret key `sk` and message
    ///      `message`.
    ///
    /// @dev Note that a nonce is of type uint and not bounded by any field!
    ///
    /// @custom:invariant Keccak256 image is never zero
    ///     ∀ (sk, digest) ∊ (SecretKey, bytes32): keccak256(sk ‖ digest) != 0
    function deriveNonce(PrivateKey privKey, bytes32 digest)
        internal
        pure
        returns (uint)
    {
        return uint(keccak256(abi.encodePacked(sk.asUint(), digest)));
    }
}
