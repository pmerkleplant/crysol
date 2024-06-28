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
 * @notice Signature is an [EIP-XXX] Schnorr signature
 */
struct Signature {
    bytes32 s;
    PublicKey r;
}

/**
 * @notice SignatureCompressed is an [EIP-XXX] compressed Schnorr signature
 */
struct SignatureCompressed {
    bytes32 s;
    address rAddr;
}

/**
 * @title Schnorr
 *
 * @notice Provides Schnorr signature functionality
 *
 * @dev Provides an Schnorr signature implementation as defined in [EIP-XXX].
 *
 * @dev Note about Ethereum Schnorr Signed Messages
 *
 *      Note that [EIP-XXX] defines a message tag for Schnorr signed messages to
 *      prevent digests created in one context to be reinterpreted in another
 *      context.
 *
 *      For more information, see [EIP-XXX] and {Message.sol}.
 *
 * @custom:references
 *      - [EIP-XXX]: ...
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Schnorr2 {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using Schnorr2 for address;
    using Schnorr2 for Signature;
    using Schnorr2 for SignatureCompressed;
    using Schnorr2 for SecretKey;
    using Schnorr2 for PublicKey;

    //--------------------------------------------------------------------------
    // Signature Verification

    /// @dev Returns whether public key `pk` signs via Schnorr signature `sig`
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Schnorr signature insane
    function verify(
        PublicKey memory pk,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        // Note that checking whether signature's r value is a valid public key
        // is waived. Exploiting this behaviour would require knowledge of a
        // preimage non-equal to pk for the signer's Ethereum address.
        SignatureCompressed memory sigCompressed = sig.toCompressed();

        return pk.verifyCompressed(message, sigCompressed);
    }

    /// @dev Returns whether public key `pk` signs via Schnorr signature `sig`
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Schnorr signature insane
    function verify(
        PublicKey memory pk,
        bytes32 digest,
        Signature memory sig
    ) internal pure returns (bool) {
        // Note that checking whether signature's r value is a valid public key
        // is waived. Exploiting this behaviour would require knowledge of a
        // preimage non-equal to pk for the signer's Ethereum address.
        SignatureCompressed memory sigCompressed = sig.toCompressed();

        return pk.verifyCompressed(digest, sigCompressed);
    }

    /// @dev Returns whether public key `pk` signs via compressed Schnorr
    ///      signature `sig` message `message`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Schnorr signature insane
    function verifyCompressed(
        PublicKey memory pk,
        bytes memory message,
        SignatureCompressed memory sig
    ) internal pure returns (bool) {
        bytes32 digest = keccak256(message);

        return pk.verifyCompressed(digest, sig);
    }

    /// @dev Returns whether public key `pk` signs via compressed Schnorr
    ///      signature `sig` hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///      ∨ Schnorr signature insane
    function verifyCompressed(
        PublicKey memory pk,
        bytes32 digest,
        SignatureCompressed memory sig
    ) internal pure returns (bool) {
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        // Construct challenge = H(Pkₓ ‖ Pkₚ ‖ m ‖ Rₑ) (mod Q)
        uint challenge = uint(
            keccak256(
                abi.encodePacked(
                    pk.x, uint8(pk.yParity()), digest, sig.rAddr
                )
            )
        ) % Secp256k1.Q;

        // Compute ecrecover_msgHash = -s * Pkₓ      (mod Q)
        //                           = Q - (s * Pkₓ) (mod Q)
        //
        // Unchecked because the only protected operation performed is the
        // subtraction from Q where the subtrahend is the result of a (mod Q)
        // computation, i.e. the subtrahend is guaranteed to be less than Q.
        bytes32 ecrecover_msgHash;
        unchecked {
            ecrecover_msgHash = bytes32(
                Secp256k1.Q - mulmod(uint(sig.s), pk.x, Secp256k1.Q)
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

        // Compute ([s]G - [e]Pk)ₑ via ecrecover.
        // forgefmt: disable-next-item
        address recovered = ecrecover(
            ecrecover_msgHash,
            ecrecover_v,
            ecrecover_r,
            ecrecover_s
        );

        // Verification succeeds iff ([s]G - [e]Pk)ₑ = Rₑ.
        return recovered == sig.rAddr;
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns whether Schnorr signature `sig` is sane.
    ///
    /// @dev A Schnorr signature is deemed insane for any of:
    ///      - Schnorr signature's s value is zero
    ///      - Schnorr signature's s value is not a field element
    ///      - Schnorr signature's r value is not a valid public key
    function isSane(Signature memory sig) internal pure returns (bool) {
        if (sig.s == 0 || uint(sig.s) >= Secp256k1.Q || !sig.r.isValid()) {
            return false;
        }

        return true;
    }

    /// @dev A compressed Schnorr signature is deemed insane for any of:
    ///      - Schnorr signature's s value is zero
    ///      - Schnorr signature's s value is not a field element
    ///      - Schnorr signature's rAddr value is zero
    function isSane(SignatureCompressed memory sig) internal pure returns (bool) {
        if (sig.s == 0 || uint(sig.s) >= Secp256k1.Q || sig.rAddr == address(0)) {
            return false;
        }

        return true;
    }

    // TODO: Formulate project-wide rule:
    //       - De/Serialization functions ALWAYS revert if object is invalid/insane/etc
    //       - Type Conversion function DO NOT revert if object is invalid/insane/etc

    //--------------------------------------------------------------------------
    // Type Conversions

    function intoCompressed(Signature memory sig) internal pure returns (SignatureCompressed memory) {
        SignatureCompressed memory sigCompressed;

        address rAddr = sig.r.toAddress();
        // assert(rAddr != address(0));

        assembly ("memory-safe") {
            // TODO: Clean dirty upper bits from rAddr and clean y coordinate's
            //       slot.
            mstore(add(sig, 0x20), rAddr)

            sigCompressed := sig
        }

        return sigCompressed;
    }

    function toCompressed(Signature memory sig) internal pure returns (SignatureCompressed memory) {
        address rAddr = sig.r.toAddress();
        // assert(rAddr != address(0));

        return SignatureCompressed(sig.s, rAddr);
    }

    // TODO: Should define EthereumSignedSchnorrMessage? Need extra tag to
    //       prevent signing same message twice.

    //--------------------------------------------------------------------------
    // (De)Serialization

    /// @dev Decodes signature from bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 96 bytes
    ///      ∨ Deserialized Schnorr signature insane
    ///
    /// @dev Expects 96 bytes encoding:
    ///         [32 bytes s value][64 bytes r public key]
    function signatureFromEncoded(bytes memory blob) internal pure returns (Signature memory) {
        if (blob.length != 96) {
            revert("LengthInvalid()");
        }

        bytes32 s;
        uint rx;
        uint ry;
        assembly ("memory-safe") {
            s := mload(add(blob, 0x20))
            rx := mload(add(blob, 0x40))
            ry := mload(add(blob, 0x40))
        }

        Signature memory sig = Signature(s, PublicKey(rx, ry));

        if (sig.isSane()) {
            revert("SignatureInsane()");
        }

        return sig;
    }

    /// @dev Encodes Schnorr signature `sig` as [EIP-XXX] encoded bytes.
    ///
    /// @dev Reverts if:
    ///        Schnorr signature insane
    ///
    /// @dev Provides 96 bytes encoding:
    ///         [32 bytes s value][64 bytes r public key]
    function toEncoded(Signature memory sig) internal pure returns (bytes memory) {
        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        return abi.encodePacked(sig.s, sig.r.x, sig.r.y);
    }

    /// @dev Encodes Schnorr signature `sig` as [EIP-XXX] compressed encoded
    ///      bytes.
    ///
    /// @dev Reverts if:
    ///        Schnorr signature insane
    ///
    /// @dev Provides 52 bytes encoding:
    ///         [32 bytes s value][20 bytes r's address]
    ///
    ///      See [EIP-XXX].
    function toCompressedEncoded(Signature memory sig) internal pure returns (bytes memory) {
        return sig.toCompressed().toCompressedEncoded();
    }

    /// @dev Decodes compressed Schnorr signature from [EIP-XXX] compressed
    ///      encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Deserialized Schnorr signature insane
    ///
    /// @dev Provides 52 bytes encoding:
    ///         [32 bytes s value][20 bytes r's address]
    ///
    ///      See [EIP-XXX].
    function fromCompressedEncoded(bytes memory blob) internal pure returns (SignatureCompressed memory) {
        if (blob.length != 52) {
            revert("LengthInvalid()");
        }

        bytes32 s;
        address rAddr;
        assembly ("memory-safe") {
            s := mload(add(blob, 0x20))
            rAddr := mload(add(blob, 0x40))
        }

        SignatureCompressed memory sig = SignatureCompressed(s, rAddr);

        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        return sig;
    }

    /// @dev Encodes compact Schnorr signature `sig` as [EIP-XXX] compact
    ///      encoded bytes.
    ///
    /// @dev Reverts if:
    ///         Schnorr signature insane
    ///
    /// @dev Provides 52 bytes encoding:
    ///         [32 bytes s value][20 bytes r's address]
    ///
    ///      See [EIP-XXX].
    function toCompressedEncoded(SignatureCompressed memory sig) internal pure returns (bytes memory) {
        if (!sig.isSane()) {
            revert("SignatureInsane()");
        }

        return abi.encodePacked(sig.s, sig.rAddr);
    }
}
