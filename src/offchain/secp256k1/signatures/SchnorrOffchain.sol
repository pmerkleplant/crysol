/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";

import {Message} from "../../../onchain/common/Message.sol";
import {Nonce} from "../../../onchain/common/Nonce.sol";

import {Secp256k1Offchain} from "../Secp256k1Offchain.sol";
import {
    Secp256k1,
    SecretKey,
    PublicKey
} from "../../../onchain/secp256k1/Secp256k1.sol";

import {
    Schnorr,
    Signature,
    SignatureCompressed
} from "../../../onchain/secp256k1/signatures/Schnorr.sol";

/**
 * @title SchnorrOffchain
 *
 * @notice Provides offchain Schnorr signature functionality
 *
 * @custom:docs docs/signatures/Schnorr.md
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library SchnorrOffchain {
    using Secp256k1Offchain for SecretKey;
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;

    using SchnorrOffchain for SecretKey;

    // ~~~~~~~ Prelude ~~~~~~~
    // forgefmt: disable-start
    Vm private constant vm = Vm(address(uint160(uint(keccak256("hevm cheat code")))));
    modifier vmed() {
        if (block.chainid != 31337) revert("requireVm");
        _;
    }
    // forgefmt: disable-end
    // ~~~~~~~~~~~~~~~~~~~~~~~

    //--------------------------------------------------------------------------
    // Signature Creation

    /// @dev Returns a Schnorr signature signed by secret key `sk` signing
    ///      message `message`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm sign(SecretKey, bytes32)
    function sign(SecretKey sk, bytes memory message)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest = keccak256(message);

        return sk.sign(digest);
    }

    /// @dev Returns a Schnorr signature signed by secret key `sk` signing
    ///      hash digest `digest`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm curves/Secp256k1::toPublicKey(SecretKey)(PublicKey)
    function sign(SecretKey sk, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        // Note that public key derivation fails if secret key is invalid.
        PublicKey memory pk = sk.toPublicKey();

        // Derive deterministic nonce ∊ [1, Q).
        //
        // Note that modulo bias is acceptable on secp256k1.
        uint nonce =
            Nonce.deriveFrom(sk.asUint(), pk.toBytes(), digest) % Secp256k1.Q;
        // assert(nonce != 0);

        // Compute nonce's public key.
        PublicKey memory noncePk =
            Secp256k1.secretKeyFromUint(nonce).toPublicKey();

        // Derive commitment from nonce's public key.
        address commitment = noncePk.toAddress();

        // Construct challenge = H(Pkₓ ‖ Pkₚ ‖ m ‖ Rₑ) (mod Q)
        bytes32 challenge = bytes32(
            uint(
                keccak256(
                    abi.encodePacked(
                        pk.x, uint8(pk.yParity()), digest, commitment
                    )
                )
            ) % Secp256k1.Q
        );

        // Compute signature = k + (e * sk) (mod Q)
        bytes32 signature = bytes32(
            addmod(
                nonce,
                mulmod(uint(challenge), sk.asUint(), Secp256k1.Q),
                Secp256k1.Q
            )
        );

        return Signature(signature, commitment);
    }

    /// @dev Returns a Schnorr signature signed by secret key `sk` singing
    ///      message `message`'s keccak256 digest as Ethereum Schnorr Signed
    ///      Message.
    ///
    /// @dev For more info regarding Ethereum Signed Messages, see {Message.sol}.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm sign(SecretKey,bytes32)
    function signEthereumSchnorrSignedMessageHash(SecretKey sk, bytes memory message)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest = Message.deriveEthereumSchnorrSignedMessageHash(message);

        return sk.sign(digest);
    }

    /// @dev Returns a Schnorr signature signed by secret key `sk` singing
    ///      hash digest `digest` as Ethereum Schnorr Signed Message.
    ///
    /// @dev For more info regarding Ethereum Signed Messages, see {Message.sol}.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm sign(SecretKey,bytes32)
    function signEthereumSchnorrSignedMessageHash(SecretKey sk, bytes32 digest)
        internal
        vmed
        returns (Signature memory)
    {
        bytes32 digest2 = Message.deriveEthereumSchnorrSignedMessageHash(digest);

        return sk.sign(digest2);
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns a string representation of Schnorr signature `sig`.
    ///
    /// @custom:vm vm.toString(uint)
    function toString(Signature memory sig)
        internal
        view
        vmed
        returns (string memory)
    {
        // forgefmt: disable-start
        string memory str = "Schnorr::Signature({";
        str = string.concat(str, " s: ", vm.toString(sig.s), ",");
        str = string.concat(str, " r: ", sig.r.toString());
        str = string.concat(str, " })");
        return str;
        // forgefmt: disable-end
    }

    /// @dev Returns a string representation of compressed Schnorr signature
    ///      `sig`.
    ///
    /// @custom:vm vm.toString(uint)
    function toString(Signature memory sig)
        internal
        view
        vmed
        returns (string memory)
    {
        // forgefmt: disable-start
        string memory str = "Schnorr::CompressedSignature({";
        str = string.concat(str, " s: ", vm.toString(sig.s), ",");
        str = string.concat(str, " r: ", vm.toString(sig.rAddr));
        str = string.concat(str, " })");
        return str;
        // forgefmt: disable-end
    }
}
