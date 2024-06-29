/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

/**
 * @title Nonce
 *
 * @notice Provides deterministic nonce derivation
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Nonce {
    /// @dev Derives a deterministic non-zero nonce from secret key `sk`,
    ///      public key `pk`, and message `message`.
    ///
    /// @dev Note that nonce is not bounded to any field.
    ///
    /// @dev The nonce is derived via H(sk ‖ pk ‖ digest).
    function deriveFrom(uint sk, bytes memory pk, bytes32 digest)
        internal
        pure
        returns (uint)
    {
        uint nonce = uint(keccak256(abi.encodePacked(sk, pk, digest)));
        // assert(nonce != 0);

        return nonce;
    }

    // TODO: Better docs that pk MUST be signer's public key, which is not
    //       necessarily the same as sk's public key.

    /// @dev Derives a deterministic non-zero nonce from secret key `sk`,
    ///      public key `pk`, message `message`, and salt `salt.
    ///
    /// @dev Note that nonce is not bounded to any field.
    ///
    /// @dev Providing a salt adds additional entropy to allow for multiple
    ///      tries in case returned nonce is not valid for the specific scheme.
    ///
    /// @dev The nonce is derived via H(sk ‖ pk ‖ digest ‖ salt).
    function deriveFrom(uint sk, bytes memory pk, bytes32 digest, bytes32 salt)
        internal
        pure
        returns (uint)
    {
        uint nonce = uint(keccak256(abi.encodePacked(sk, pk, digest, salt)));
        // assert(nonce != 0);

        return nonce;
    }
}
