/*

 ██████ ██████  ██    ██ ███████  ██████  ██
██      ██   ██  ██  ██  ██      ██    ██ ██
██      ██████    ████   ███████ ██    ██ ██
██      ██   ██    ██         ██ ██    ██ ██
 ██████ ██   ██    ██    ███████  ██████  ███████

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Vm} from "forge-std/Vm.sol";

import {Secp256k1, SecretKey, PublicKey} from "../curves/Secp256k1.sol";
import {
    Secp256k1Arithmetic,
    Point,
    ProjectivePoint
} from "../curves/Secp256k1Arithmetic.sol";

/**
 * @notice StealthMetaAddress encapsulates a receiver's spending and viewing
 *         public keys from which a [StealthAddress] can be computed
 *
 * @dev Stealth meta addresses offer TODO...
 *
 * @dev A stealth address' secret key is computed via the spending secret key.
 *      The viewing secret key is used to determine whether a tx belongs to its
 *      stealth meta address.
 *
 * @custom:example Generate a stealth meta address:
 *
 *      ```solidity
 *      import {Secp256k1, SecretKey, PublicKey} from "crysol/curves/Secp256k1.sol";
 *      import {StealthAdressesSecp256k1, StealthMetaAddress} from "crysol/stealth-addresses/StealthAdressesSecp256k1.sol";
 *      contract Example {
 *          using Secp256k1 for SecretKey;
 *
 *          // Create spending and viewing secret keys.
 *          SecretKey spendSk = Secp256k1.newSecretKey();
 *          SecretKey viewSk = Secp256k1.newSecretKey();
 *
 *          // Stealth meta address is their set of public keys.
 *          StealthMetaAddress memory sma = StealthMetaAddress({
 *              spendPk: spendSk.toPublicKey(),
 *              viewPk: viewSk.toPublicKey()
 *          });
 *      }
 *      ```
 */
struct StealthMetaAddress {
    PublicKey spendPk;
    PublicKey viewPk;
}

// TODO: Provide toString() function for StealthAddress
/**
 * @notice StealthAddress
 */
struct StealthAddress {
    address addr;
    PublicKey ephPk;
    uint8 viewTag;
}

/**
 * @title StealthAddressesSecp256k1
 *
 * @notice [ERC-5564] conforming stealth addresses for the secp256k1 curve
 *
 *
 *
 *
 * @custom:references
 *      - [ERC-5564]: https://eips.ethereum.org/EIPS/eip-5564
 *
 * @author crysol (https://github.com/pmerkleplant/crysol)
 */
library StealthAddressesSecp256k1 {
    using Secp256k1 for SecretKey;
    using Secp256k1 for PublicKey;
    using Secp256k1 for Point;

    using Secp256k1Arithmetic for Point;
    using Secp256k1Arithmetic for ProjectivePoint;

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
    // Constants

    // TODO: Scheme id docs.
    uint internal constant SCHEME_ID = 1;

    //--------------------------------------------------------------------------
    // Sender

    ///
    ///
    /// @custom:vm Secp256k1::newSecretKey()
    function generateStealthAddress(StealthMetaAddress memory stealthMeta)
        internal
        vmed
        returns (StealthAddress memory)
    {
        // Create ephemeral secret key.
        SecretKey ephSk = Secp256k1.newSecretKey();

        return generateStealthAddressGivenEphKey(stealthMeta, ephSk);
    }

    /// @custom:vm Secp256k1::SecretKey.toPublicKey()
    function generateStealthAddressGivenEphKey(
        StealthMetaAddress memory sma,
        SecretKey ephSk
    ) internal vmed returns (StealthAddress memory) {
        if (!ephSk.isValid()) {
            revert("SecretKeyInvalid()");
        }

        PublicKey memory ephPk = ephSk.toPublicKey();

        // Compute shared secret key from ephemeral secret key and sma's view
        // public key.
        SecretKey sharedSk = _deriveSharedSecret(ephSk, sma.viewPk);

        // Extract view tag from shared secret key.
        uint8 viewTag = _extractViewTag(sharedSk);

        // Derive shared secret key's public key.
        PublicKey memory sharedPk = sharedSk.toPublicKey();

        // Compute stealth address' public key.
        // forgefmt: disable-next-item
        PublicKey memory stealthPk = sma.spendPk.toProjectivePoint()
                                                .add(sharedPk.toProjectivePoint())
                                                .intoPoint()
                                                .intoPublicKey();

        // Return stealth address.
        return StealthAddress({
            addr: stealthPk.toAddress(),
            ephPk: ephPk,
            viewTag: viewTag
        });
    }

    //--------------------------------------------------------------------------
    // Receiver

    /// @custom:vm Secp256k1::PublicKey.toPublicKey()
    function checkStealthAddress(
        SecretKey viewSk,
        PublicKey memory spendPk,
        StealthAddress memory stealth
    ) internal vmed returns (bool) {
        // Compute shared secret key from view secret key and ephemeral public
        // key.
        SecretKey sharedSk = _deriveSharedSecret(viewSk, stealth.ephPk);

        // Extract view tag from shared secret key.
        uint8 viewTag = _extractViewTag(sharedSk);

        // Return early if view tags do not match.
        if (viewTag != stealth.viewTag) {
            return false;
        }

        // Derive shared secret key's public key.
        PublicKey memory sharedPk = sharedSk.toPublicKey();

        // Compute stealth address' public key.
        // forgefmt: disable-next-item
        PublicKey memory stealthPk = spendPk.toProjectivePoint()
                                            .add(sharedPk.toProjectivePoint())
                                            .intoPoint()
                                            .intoPublicKey();

        // Return true if computed address matches stealth address' address.
        return stealthPk.toAddress() == stealth.addr;
    }

    function computeStealthSecretKey(
        SecretKey spendSk,
        SecretKey viewSk,
        StealthAddress memory stealth
    ) internal view returns (SecretKey) {
        // Compute shared secret key from view secret key and ephemeral public
        // key.
        SecretKey sharedSk = _deriveSharedSecret(viewSk, stealth.ephPk);

        // Compute stealth secret key.
        SecretKey stealthSk = Secp256k1.secretKeyFromUint(
            addmod(spendSk.asUint(), sharedSk.asUint(), Secp256k1.Q)
        );

        return stealthSk;
    }

    //--------------------------------------------------------------------------
    // Utils

    /// @dev Returns the string representation of stealth meta address `sma` for
    ///      chain `chain`.
    ///
    /// @dev Note that `chain` should be the chain's short name as defined via
    ///      https://github.com/ethereum-lists/chains.
    ///
    /// @dev A stealth meta address' string representation is defined as:
    ///         `st:<chain>:0x<compressed spendPk><compressed  viewPk>`
    ///
    /// @custom:vm vm.toString(bytes)(string)
    function toString(StealthMetaAddress memory sma, string memory chain)
        internal
        view
        vmed
        returns (string memory)
    {
        string memory prefix = string.concat("st:", chain, ":0x");

        // Use hex string of 0x-removed compressed public key encoding.
        bytes memory spendPk;
        bytes memory viewPk;

        string memory buffer;

        buffer = vm.toString(sma.spendPk.toCompressedEncoded());
        spendPk = new bytes(bytes(buffer).length - 2);
        for (uint i = 2; i < bytes(buffer).length; i++) {
            spendPk[i - 2] = bytes(buffer)[i];
        }

        buffer = vm.toString(sma.viewPk.toCompressedEncoded());
        viewPk = new bytes(bytes(buffer).length - 2);
        for (uint i = 2; i < bytes(buffer).length; i++) {
            viewPk[i - 2] = bytes(buffer)[i];
        }

        return string.concat(prefix, string(spendPk), string(viewPk));
    }

    //--------------------------------------------------------------------------
    // Private Helpers

    function _deriveSharedSecret(SecretKey sk, PublicKey memory pk)
        private
        view
        returns (SecretKey)
    {
        // Compute shared public key.
        // forgefmt: disable-next-item
        PublicKey memory sharedPk = pk.toProjectivePoint()
                                      .mul(sk.asUint())
                                      .intoPoint()
                                      .intoPublicKey();

        // Derive secret key from hashed public key.
        bytes32 digest = sharedPk.toHash();

        // TODO: Bound to field?
        uint scalar = uint(digest) % Secp256k1.Q;

        if (uint(digest) == 0) {
            revert("ShouldBeImpossible()");
        }

        return Secp256k1.secretKeyFromUint(scalar);
    }

    function _extractViewTag(SecretKey sk) private pure returns (uint8) {
        return uint8(sk.asUint() >> 248);
    }
}
