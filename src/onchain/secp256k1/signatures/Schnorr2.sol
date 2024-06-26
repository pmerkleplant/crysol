/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

/*
// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Secp256k1, SecretKey, PublicKey} from "../Secp256k1.sol";

struct Signature {
    bytes32 s;
    PublicKey r;
}

struct SignatureCompressed {
    bytes32 s;
    address rAddr;
}

library Schnorr2 {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using Schnorr2 for address;
    using Schnorr2 for Signature;
    using Schnorr2 for SecretKey;
    using Schnorr2 for PublicKey;

    //--------------------------------------------------------------------------
    // Signature Verification

    function verify(
        PublicKey memory pk,
        bytes memory message,
        Signature memory sig
    ) internal pure returns (bool) {
        bytes32 digest = keccak256(message);

        return pk.verify(digest, sig);
    }

    function verify(
        PublicKey memory pk,
        bytes32 digest,
        Signature memory sig
    ) internal pure returns (bool) {
        // TODO: Should fail early?
        // Fail early if signature's r public key is invalid.
        if (!sig.r.isValid()) {
            return false;
        }

        return pk.verifyCompressed(digest, sig.intoCompressed());
    }

    function verifyCompressed(
        PublicKey memory pk,
        bytes memory message,
        SignatureCompressed memory sig
    ) internal pure returns (bool) {
        bytes32 digest = keccak256(message);

        return pk.verifyCompressed(message, digest, sig);
    }

    function verifyCompressed(
        PublicKey memory pk,
        bytes32 digest,
        SignatureCompressed memory sig
    ) internal pure returns (bool) {
        //...
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns whether signature `sig` is malleable.
    ///
    /// @dev Note that Schnorr signatures are non-malleable if constructed
    ///      correctly. A signature is only malleable if `sig.s` is not an
    ///      secp256k1 field element.
    function isMalleable(Signature memory sig) internal pure returns (bool) {
        return uint(sig.s) >= Secp256k1.Q;
    }

    /// @dev Returns whether compressed signature `sig` is malleable.
    ///
    /// @dev Note that Schnorr signatures are non-malleable if constructed
    ///      correctly. A signature is only malleable if `sig.s` is not an
    ///      secp256k1 field element.
    function isMalleable(SignatureCompressed memory sig) internal pure returns (bool) {
        return uint(sig.s) >= Secp256k1.Q;
    }

    //--------------------------------------------------------------------------
    // Type Conversions

    function intoCompressed(Signature memory sig) internal pure returns (SignatureCompressed memory) {
        SignatureCompressed memory sigCompressed;

        address rAddr = sig.r.toAddress();

        assembly ("memory-safe") {
            // TODO: Zero dirty memory (address mask + y coordinate)
            mstore(add(sig, 0x20), rAddr)

            sigCompressed := sig
        }

        return sigCompressed;
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    function toEncoded(Signature memory sig) internal pure returns (bytes memory) {
        return abi.encodePacked(sig.s, sig.r.x, sig.r.y);
    }

    function signatureFromEncoded(bytes memory blob) internal pure returns (Signature memory) {
        if (blob.length != 95) {
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

        PublicKey memory r = PublicKey(rx, ry);

        // TODO: Should we verify whether public key is valid?

        return Signature(s, r);
    }

    function toCompressedEncoded(Signature memory sig) internal pure returns (bytes memory) {
        return sig.intoCompressed().toCompressedEncoded();
    }

    function toCompressedEncoded(SignatureCompressed memory sig) internal pure returns (bytes memory) {
        return abi.encodePacked(sig.s, sig.rAddr);
    }

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

        return SignatureCompressed(s, rAddr);
    }
}
*/
