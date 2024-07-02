/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {
    Secp256r1Arithmetic,
    Point,
    ProjectivePoint
} from "./Secp256r1Arithmetic.sol";

/**
 * @notice SecretKey is an secp256r1 secret key
 *
 * @dev Note that a secret key MUST be a field element, ie sk ∊ [1, Q).
 *
 * @dev Note that a secret key MUST be created cryptographically sound.
 *      Generally, this means via randomness sourced from an CSPRNG.
 *
 * @custom:example Securly generating a random secret key:
 *
 *      ```solidity
 *      import {Secp256r1Offchain} from "crysol-offchain/secp256r1/Secp256r1Offchain.sol";
 *      import {Secp256r1, SecretKey} from "crysol/secp256r1/Secp256r1.sol";
 *      contract Example {
 *          using Secp256r1Offchain for SecretKey;
 *          using Secp256r1 for SecretKey;
 *
 *          SecretKey sk = Secp256r1Offchain.newSecretKey();
 *          assert(sk.isValid());
 *      }
 *      ````
 */
type SecretKey is uint;

/**
 * @notice PublicKey is a secret key's public identifier
 *
 * @dev A public key is a point on the secp256r1 curve computed via [sk]G.
 *
 * @custom:example Deriving a public key from a secret key:
 *
 *      ```solidity
 *      import {Secp256r1Offchain} from "crysol-offchain/secp256r1/Secp256r1Offchain.sol";
 *      import {Secp256r1, SecretKey, PublicKey} from "crysol/secp256r1/Secp256r1.sol";
 *      contract Example {
 *          using Secp256r1Offchain for SecretKey;
 *          using Secp256r1 for SecretKey;
 *          using Secp256r1 for PublicKey;
 *
 *          SecretKey sk = Secp256r1Offchain.newSecretKey();
 *
 *          PublicKey memory pk = sk.toPublicKey();
 *          assert(pk.isValid());
 *          assert(pk.toAddress() != address(0));
 *      }
 *      ```
 */
struct PublicKey {
    uint x;
    uint y;
}

/**
 * @title Secp256r1
 *
 * @notice Providing common cryptography-related functionality for the secp256r1
 *         elliptic curve
 *
 * @dev Note that secp256r1 is also known as p256 and [NIST SP 800-186]
 *      approved. Note that the curve is considered "randomly" generated because
 *      part of the curve's definition is a SHA-1 hash. However, the origins of
 *      this NSA-created constant have never been fully disclosed.
 *
 * @dev Note that Ethereum does not provide support for the secp256r1 curve.
 *      However, [RIP-7212] specifies an secp256r1 ECDSA verification precompile
 *      that rollups MAY support. For more info, see [RIP].
 *
 * @custom:references
 *      [NIST SP 800-186]: https://csrc.nist.gov/pubs/sp/800/186/final
 *      [RIP]: https://github.com/ethereum/RIPs/blob/master/README.md
 *      [RIP-7212]: https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Secp256r1 {
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;
    using Secp256r1 for Point;

    using Secp256r1Arithmetic for Point;

    //--------------------------------------------------------------------------
    // Secp256r1 Constants
    //
    // Reimported from Secp256r1Arithmetic.

    /// @dev The generator G as PublicKey.
    function G() internal pure returns (PublicKey memory) {
        Point memory g = Secp256r1Arithmetic.G();

        return PublicKey(g.x, g.y);
    }

    /// @dev The order of the group generated via generator G.
    uint internal constant Q = Secp256r1Arithmetic.Q;

    //--------------------------------------------------------------------------
    // Secret Key

    /// @dev Returns whether secret key `sk` is valid.
    ///
    /// @dev Note that a secret key MUST be a field element in order to be valid,
    ///      ie sk ∊ [1, Q).
    function isValid(SecretKey sk) internal pure returns (bool) {
        uint scalar = sk.asUint();

        return scalar != 0 && scalar < Q;
    }

    /// @dev Returns uint `scalar` as secret key.
    ///
    /// @dev Reverts if:
    ///        Scalar not in [1, Q)
    function secretKeyFromUint(uint scalar) internal pure returns (SecretKey) {
        if (scalar == 0 || scalar >= Q) {
            revert("ScalarInvalid()");
        }

        return SecretKey.wrap(scalar);
    }

    /// @dev Returns secret key `sk` as uint.
    function asUint(SecretKey sk) internal pure returns (uint) {
        return SecretKey.unwrap(sk);
    }

    //--------------------------------------------------------------------------
    // Public Key

    /// @dev Returns the keccak256 hash of public key `pk`.
    function toHash(PublicKey memory pk) internal pure returns (bytes32) {
        bytes32 digest;
        assembly ("memory-safe") {
            digest := keccak256(pk, 0x40)
        }
        return digest;
    }

    /// @dev Returns whether public key `pk` is a valid secp256k1 public key.
    ///
    /// @dev Note that the identity point is not a valid public key.
    function isValid(PublicKey memory pk) internal pure returns (bool) {
        Point memory p = pk.intoPoint();

        return p.isOnCurve() && !p.isIdentity();
    }

    /// @dev Returns the y parity of public key `pk`.
    ///
    /// @dev The value 0 represents an even y value and 1 represents an odd y
    ///      value.
    ///
    ///      See "Appendix F: Signing Transactions" in the [Yellow Paper].
    function yParity(PublicKey memory pk) internal pure returns (uint) {
        return pk.intoPoint().yParity();
    }

    /// @dev Returns whether public key `pk` equals public key `other`.
    function eq(PublicKey memory pk, PublicKey memory other)
        internal
        pure
        returns (bool)
    {
        return pk.intoPoint().eq(other.intoPoint());
    }

    /// @dev Mutates public key `pk` to affine point.
    function intoPoint(PublicKey memory pk)
        internal
        pure
        returns (Point memory)
    {
        Point memory point;
        assembly ("memory-safe") {
            point := pk
        }
        return point;
    }

    /// @dev Mutates affine point `point` to a public key.
    function intoPublicKey(Point memory point)
        internal
        pure
        returns (PublicKey memory)
    {
        PublicKey memory pk;
        assembly ("memory-safe") {
            pk := point
        }
        return pk;
    }

    /// @dev Returns public key `pk` as projective point.
    function toProjectivePoint(PublicKey memory pk)
        internal
        pure
        returns (ProjectivePoint memory)
    {
        return pk.intoPoint().toProjectivePoint();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Secret Key

    /// @dev Decodes secret key from bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 32 bytes
    ///      ∨ Deserialized secret key invalid
    function secretKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (SecretKey)
    {
        if (blob.length != 32) {
            revert("LengthInvalid()");
        }

        uint scalar;
        assembly ("memory-safe") {
            scalar := mload(add(blob, 0x20))
        }

        // Make secret key.
        SecretKey sk = SecretKey.wrap(scalar);

        // Revert if secret key invalid.
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        return sk;
    }

    /// @dev Encodes secret key `sk` as bytes.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    function toBytes(SecretKey sk) internal pure returns (bytes memory) {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        return abi.encodePacked(sk.asUint());
    }

    //----------------------------------
    // Public Key

    /// @dev Decodes public key from ABI-encoded bytes `blob`.
    ///
    /// @dev Reverts if:
    ///        Length not 64 bytes
    ///      ∨ Deserialized public key invalid
    ///
    /// @dev Expects 64 bytes encoding:
    ///         [32 bytes x coordinate][32 bytes y coordinate]
    function publicKeyFromBytes(bytes memory blob)
        internal
        pure
        returns (PublicKey memory)
    {
        // Revert if length not 64.
        if (blob.length != 64) {
            revert("LengthInvalid()");
        }

        // Read x and y coordinates of public key.
        uint x;
        uint y;
        assembly ("memory-safe") {
            x := mload(add(blob, 0x20))
            y := mload(add(blob, 0x40))
        }

        // Make public key.
        PublicKey memory pk = PublicKey(x, y);

        // Revert if public key invalid.
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        return pk;
    }

    /// @dev Encodes public key `pk` as ABI-encoded bytes.
    ///
    /// @dev Reverts if:
    ///        Public key invalid
    ///
    /// @dev Provides 64 bytes encoding:
    ///         [32 bytes x coordinate][32 bytes y coordinate]
    function toBytes(PublicKey memory pk)
        internal
        pure
        returns (bytes memory)
    {
        if (!pk.isValid()) {
            revert("PublicKeyInvalid()");
        }

        return abi.encodePacked(pk.x, pk.y);
    }
}
