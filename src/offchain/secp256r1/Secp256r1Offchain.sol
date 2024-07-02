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

import {RandomOffchain} from "../common/RandomOffchain.sol";

import {
    Secp256r1,
    SecretKey,
    PublicKey
} from "../../onchain/secp256r1/Secp256r1.sol";
import {
    Secp256r1Arithmetic,
    Point,
    ProjectivePoint
} from "../../onchain/secp256r1/Secp256r1Arithmetic.sol";

/**
 * @title Secp256r1Offchain
 *
 * @notice Providing offchain cryptography-related functionality for the secp256r1
 *         elliptic curve
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 */
library Secp256r1Offchain {
    using Secp256r1Offchain for SecretKey;
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;
    using Secp256r1 for Point;
    using Secp256r1Arithmetic for Point;
    using Secp256r1Arithmetic for ProjectivePoint;

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
    // Secret Key

    /// @dev Returns a new cryptographically secure secret key.
    ///
    /// @custom:vm RandomOffchain::readUint()(uint)
    function newSecretKey() internal vmed returns (SecretKey) {
        // Note to not introduce potential bias via bounding operation.
        uint scalar;
        do {
            scalar = RandomOffchain.readUint();
        } while (scalar == 0 || scalar >= Secp256r1Arithmetic.Q);

        return Secp256r1.secretKeyFromUint(scalar);
    }

    /// @dev Returns the public key of secret key `sk`.
    ///
    /// @dev Reverts if:
    ///        Secret key invalid
    ///
    /// @custom:vm vm.createWallet(uint)
    function toPublicKey(SecretKey sk)
        internal
        vmed
        returns (PublicKey memory)
    {
        if (!sk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        // TODO: Use vm to compute pk = [sk]G.
        //       Need to update forge-std lib.
        // forgefmt: disable-next-item
        Point memory p = Secp256r1.G().toProjectivePoint()
                                      .mul(sk.asUint())
                                      .intoPoint();

        return p.intoPublicKey();
    }

    //--------------------------------------------------------------------------
    // Public Key

    /// @dev Returns a string representation of public key `pk`.
    ///
    /// @custom:vm vm.toString(uint)
    function toString(PublicKey memory pk)
        internal
        view
        vmed
        returns (string memory)
    {
        string memory str = "Secp256r1::PublicKey({";
        str = string.concat(str, " x: ", vm.toString(pk.x), ",");
        str = string.concat(str, " y: ", vm.toString(pk.y));
        str = string.concat(str, " })");
        return str;
    }
}
