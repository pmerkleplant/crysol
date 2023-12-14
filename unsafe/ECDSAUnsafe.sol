/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {ECDSA, Signature} from "src/signatures/ECDSA.sol";
import {Secp256k1} from "src/curves/Secp256k1.sol";
import {Secp256k1Arithmetic} from "src/curves/Secp256k1Arithmetic.sol";

/**
 * @title ECDSAUnsafe
 *
 * @notice Library providing unsafe ECDSA functionality
 *
 * @dev             .oO WARNING Oo.
 */
library ECDSAUnsafe {
    using ECDSA for Signature;

    /// @dev Mutates signature `sig` to be malleable.
    function intoMalleable(Signature memory sig)
        internal
        pure
        returns (Signature memory)
    {
        if (sig.isMalleable()) {
            return sig;
        }

        // Flip sig.s to Secp256k1.Q - sig.s.
        sig.s = bytes32(Secp256k1.Q - uint(sig.s));

        // Flip v.
        sig.v = sig.v == 27 ? 28 : 27;

        return sig;
    }

    /// @dev Mutates signature `sig` to be non-malleable.
    function intoNonMalleable(Signature memory sig)
        internal
        pure
        returns (Signature memory)
    {
        if (!sig.isMalleable()) {
            return sig;
        }

        // Flip sig.s to Secp256k1.Q - sig.s.
        sig.s = bytes32(Secp256k1.Q - uint(sig.s));

        // Flip v.
        sig.v = sig.v == 27 ? 28 : 27;

        return sig;
    }
}
