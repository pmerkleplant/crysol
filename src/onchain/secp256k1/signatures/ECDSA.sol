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

/**
 * @notice Signature is an ECDSA signature
 */
struct Signature {
    uint8 v;
    bytes32 r;
    bytes32 s;
}

/**
 * @title ECDSA
 *
 * @notice Provides ECDSA signature functionality
 *
 * @dev Provides an Elliptic Curve Digital Signature Algorithm (ECDSA)
 *      implementation as defined in [SEC-1 v2] in combination with the
 *      secp256k1 elliptic curve and keccak256 hash function.
 *
 * @dev Note about ECDSA Malleability
 *
 *      Note that ECDSA signatures are malleable, meaning every valid ECDSA
 *      signature has two distinct representations. Furthermore, computing the
 *      second valid signature can be done without knowledge of the signer's
 *      secret key. This weakness has lead to numerous bugs in not just smart
 *      contract systems.
 *
 *      Therefore, crysol only creates and accepts signatures in one of the two
 *      possible representations. Signatures in the second representation are
 *      deemed invalid.
 *      For more info, see function `isMalleable(Signature)(bool)`.
 *
 *      This behaviour is sync with the broader Ethereum ecosystem as a general
 *      defensive mechanism against ECDSA malleability.
 *      For more info, see eg [EIP-2].
 *
 * @custom:references
 *      - [SEC-1 v2]: https://www.secg.org/sec1-v2.pdf
 *      - [EIP-2]: https://eips.ethereum.org/EIPS/eip-2
 *      - [EIP-2098]: https://eips.ethereum.org/EIPS/eip-2098
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library ECDSA {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using ECDSA for address;
    using ECDSA for Signature;
    using ECDSA for SecretKey;
    using ECDSA for PublicKey;

    //--------------------------------------------------------------------------
    // Private Constants

    /// @dev Mask to receive an ECDSA's s value from an EIP-2098 compact
    ///      signature representation.
    ///
    ///      Equals `(1 << 255) - 1`.
    bytes32 private constant _EIP2098_MASK =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

    /// @dev Used during malleability check.
    ///
    ///      Note that ECDSA signatures are malleable with regards to their s
    ///      value and deemed invalid if s > secp256k1's order / 2.
    uint private constant _SECP256K1_HALF = Secp256k1.Q / 2;

    //--------------------------------------------------------------------------
    // Signature Verification

    /// @dev Returns whether public key `pk` signs via ECDSA signature `sig`
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Signature malleable
    ///
    /// @custom:invariant No valid public key's address is zero.
    ///     ∀ pk ∊ PublicKey: pk.isValid() → pk.toAddress() != address(0)
    function verify(
        PublicKey memory pk,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        bytes32 digest = keccak256(message);

        return pk.toAddress().verify(digest, sig);
    }

    /// @dev Returns whether public key `pk` signs via ECDSA signature `sig`
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Signature malleable
    ///
    /// @custom:invariant No valid public key's address is zero.
    ///     ∀ pk ∊ PublicKey: pk.isValid() → pk.toAddress() != address(0)
    function verify(PublicKey memory pk, bytes32 digest, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        return pk.toAddress().verify(digest, sig);
    }

    /// @dev Returns whether address `signer` signs via ECDSA signature `sig`
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///        Signer zero address
    ///      ∨ Signature malleable
    function verify(address signer, bytes memory message, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        bytes32 digest = keccak256(message);

        return signer.verify(digest, sig);
    }

    /// @dev Returns whether address `signer` signs via ECDSA signature `sig`
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Signer zero address
    ///      ∨ Signature malleable
    function verify(address signer, bytes32 digest, Signature memory sig)
        internal
        pure
        returns (bool)
    {
        if (signer == address(0)) {
            revert("SignerZeroAddress()");
        }

        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        // Note that checking whether v ∊ {27, 28} is waived.
        // For more info, see https://github.com/ethereum/yellowpaper/pull/860.

        return signer == ecrecover(digest, sig.v, sig.r, sig.s);
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns whether signature `sig` is malleable.
    ///
    /// @dev A signature is malleable if `sig.s > Secp256k1.Q / 2`.
    function isMalleable(Signature memory sig) internal pure returns (bool) {
        return uint(sig.s) > _SECP256K1_HALF;
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    // TODO: Revert if malleable!

    /// @dev Decodes ECDSA signature from ABI-encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 65 bytes
    ///      ∨ Deserialized ECDSA signature malleable
    ///
    /// @dev Expects 65 bytes encoding:
    ///         [256-bit r value][256-bit s value][8-bit v value]
    function signatureFromEncoded(bytes memory blob)
        internal
        pure
        returns (Signature memory)
    {
        if (blob.length != 65) {
            revert("LengthInvalid()");
        }

        // Read (v, r, s) triplet.
        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly ("memory-safe") {
            r := mload(add(blob, 0x20))
            s := mload(add(blob, 0x40))
            v := byte(0, mload(add(blob, 0x60)))
        }

        // Make signature.
        Signature memory sig = Signature(v, r, s);

        // Revert if signature malleable.
        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        return sig;
    }

    /// @dev Encodes ECDSA signature `sig` as ABI-encoded bytes.
    ///
    /// @dev Reverts if:
    ///        ECDSA signature malleable
    ///
    /// @dev Provides 65 bytes encoding:
    ///         [256-bit r value][256-bit s value][8-bit v value]
    function toEncoded(Signature memory sig)
        internal
        pure
        returns (bytes memory)
    {
        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        return abi.encodePacked(sig.r, sig.s, sig.v);
    }

    /// @dev Decodes ECDSA signature from [EIP-2098] compact encoded bytes
    ///      `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 64 bytes
    ///      ∨ Deserialized ECDSA signature malleable
    ///
    /// @dev Expects compact 64 bytes encoding:
    ///         [256-bit r value][1-bit yParity value][255-bit s value]
    ///
    ///      See [EIP-2098].
    function signatureFromCompactEncoded(bytes memory blob)
        internal
        pure
        returns (Signature memory)
    {
        if (blob.length != 64) {
            revert("LengthInvalid()");
        }

        // Read (v, r, s) triplet.
        uint8 v;
        bytes32 r;
        bytes32 s;
        assembly ("memory-safe") {
            r := mload(add(blob, 0x20))
            let yParityAndS := mload(add(blob, 0x40))

            // Receive s via masking yParityAndS with EIP-2098 mask.
            s := and(yParityAndS, _EIP2098_MASK)

            // Receive v via reading yParity, encoded in the last bit, and
            // adding 27.
            //
            // Note that yParity ∊ {0, 1} which cannot overflow by adding 27.
            v := add(shr(255, yParityAndS), 27)
        }

        // Make signature.
        Signature memory sig = Signature(v, r, s);

        // Revert if signature malleable.
        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        return sig;
    }

    /// @dev Encodes ECDSA signature `sig` as [EIP-2098] compact encoded bytes.
    ///
    /// @dev Reverts if:
    ///        ECDSA signature malleable
    ///
    /// @dev Provides 64 bytes encoding:
    ///         [256-bit r value][1-bit yParity value][255-bit s value]
    ///
    ///      See [EIP-2098].
    function toCompactEncoded(Signature memory sig)
        internal
        pure
        returns (bytes memory)
    {
        if (sig.isMalleable()) {
            revert("SignatureMalleable()");
        }

        bytes memory blob;

        uint8 v = sig.v;
        bytes32 r = sig.r;
        bytes32 s = sig.s;
        assembly ("memory-safe") {
            // Signature consists of two words.
            mstore(blob, 0x40)

            // yParity is 0 or 1, normalized from the canonical 27 or 28.
            let yParity := sub(v, 27)
            // yParityAndS is (yParity << 255) | s.
            let yParityAndS := or(shl(255, yParity), s)

            mstore(add(blob, 0x20), r)
            mstore(add(blob, 0x40), yParityAndS)
        }

        return blob;
    }
}
