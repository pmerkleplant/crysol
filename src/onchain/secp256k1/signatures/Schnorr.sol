/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Secp256k1, SecretKey, PublicKey} from "../Secp256k1.sol";

// TODO: Rename to (s, R)
// TODO: Also redefine to r = PublicKey
// TODO: Need SignatureCompressed type?
/**
 * @notice Signature is a Schnorr signature
 */
struct Signature {
    bytes32 signature; // s
    address commitment; // r
}

/**
 * @title Schnorr
 *
 * @notice Provides Schnorr signature functionality
 *
 * @dev Provides a Schnorr signature implementation in combination with the
 *      secp256k1 elliptic curve and keccak256 hash function.
 *
 * @custom:docs docs/signatures/Schnorr.md
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 * @author Inspired by Chronicle Protocol's Scribe (https://github.com/chronicleprotocol/scribe)
 */
library Schnorr {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using Schnorr for address;
    using Schnorr for Signature;
    using Schnorr for SecretKey;
    using Schnorr for PublicKey;

    //--------------------------------------------------------------------------
    // Signature Verification

    /// @dev Returns whether public key `pk` signs via Schnorr signature `sig`
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Schnorr signature trivial
    ///      ∨ Schnorr signature malleable
    function verify(
        PublicKey memory pk,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        bytes32 digest = keccak256(message);

        return pk.verify(digest, sig);
    }

    /// @dev Returns whether public key `pk` signs via Schnorr signature `sig`
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Schnorr signature trivial
    ///      ∨ Schnorr signature malleable
    function verify(PublicKey memory pk, bytes32 digest, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        // TODO: What about digest of zero?

        if (sig.signature == 0 || sig.commitment == address(0)) {
            revert("SignatureTrivial()");
        }

        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        // Construct challenge = H(Pkₓ ‖ Pkₚ ‖ m ‖ Rₑ) (mod Q)
        uint challenge = uint(
            keccak256(
                abi.encodePacked(
                    pk.x, uint8(pk.yParity()), digest, sig.commitment
                )
            )
        ) % Secp256k1.Q;

        // Compute ecrecover_msgHash = -sig * Pkₓ      (mod Q)
        //                           = Q - (sig * Pkₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_msgHash;
        unchecked {
            ecrecover_msgHash = bytes32(
                Secp256k1.Q - mulmod(uint(sig.signature), pk.x, Secp256k1.Q)
            );
        }

        // Compute ecrecover_v = Pkₚ + 27
        //
        // Unchecked because pk.yParity() ∊ {0, 1} which cannot overflow by
        // adding 27.
        uint8 ecrecover_v;
        unchecked {
            ecrecover_v = uint8(pk.yParity() + 27);
        }

        // Set ecrecover_r = Pkₓ
        bytes32 ecrecover_r = bytes32(pk.x);

        // Compute ecrecover_s = Q - (e * Pkₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_s;
        unchecked {
            ecrecover_s =
                bytes32(Secp256k1.Q - mulmod(challenge, pk.x, Secp256k1.Q));
        }

        // Compute ([sig]G - [e]Pk)ₑ via ecrecover.
        // forgefmt: disable-next-item
        address recovered = ecrecover(
            ecrecover_msgHash,
            ecrecover_v,
            ecrecover_r,
            ecrecover_s
        );

        // Verification succeeds iff ([sig]G - [e]Pk)ₑ = Rₑ.
        //
        // Note that commitment is guaranteed to not be zero.
        return sig.commitment == recovered;
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns whether signature `sig` is malleable.
    ///
    /// @dev Note that Schnorr signatures are non-malleable if constructed
    ///      correctly. A signature is only malleable if `sig.signature` is not
    ///      an secp256k1 field element.
    function isMalleable(Signature memory sig) internal pure returns (bool) {
        return uint(sig.signature) >= Secp256k1.Q;
    }

    //--------------------------------------------------------------------------
    // (De)Serialization
    //
    // TODO: Schnorr Serde defined via BIP-340.

    function toCompressedEncoded(Signature memory sig) internal pure returns (bytes memory) {
        return abi.encodePacked(sig.signature, sig.commitment);
    }

    function signatureFromCompressedEncoded(bytes memory blob)
        internal
        pure
        returns (Signature memory)
    {
        if (blob.length != 96) {
            revert("LengthInvalid()");
        }

        bytes32 s;
        uint rx;
        uint ry;
        assembly ("memory-safe") {
            s := mload(add(blob, 0x20))
            rx := mload(add(blob, 0x40))
            ry := mload(add(blob, 0x60))
        }

        PublicKey memory r = PublicKey(rx, ry);

        return Signature(s, r.toAddress());
    }

}
