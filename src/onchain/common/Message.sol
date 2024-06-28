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
 * @title Message
 *
 * @notice Functionality for constructing Ethereum Signed Message Hashes for
 *         ECDSA and Schnorr signatures
 *
 * @dev Ethereum (ECDSA) Signed Message Hash
 *
 *      An Ethereum (ECDSA) Signed Message Hash is a hash composed of a prefix
 *      and the actual message. The prefix makes an ECDSA signature for the hash
 *      recognizable as an Ethereum specific ECDSA signature.
 *
 *      An Ethereum Signed Message Hash is defined via the [`eth_sign`] RPC call:
 *
 *          keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
 *
 * @dev Ethereum Schnorr Signed Message Hash
 *
 *      An Ethereum Schnorr Signed Message Hash is a hash composed of a prefix
 *      and the actual message. The prefix makes a Schnorr signature for the hash
 *      recognizable as an Ethereum specific Schnorr signature.
 *
 *      An Etheruem Schnorr Signed Message Hash is defined via [EIP-XXX]:
 *
 *          keccak256("\x19Ethereum Schnorr Signed Message:\n" + len(message) + message)
 *
 * @custom:references
 *      - [eth_sign]: https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign
 *      - [EIP-XXX]: ...
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 * @author Inspired by OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts)
 */
library Message {
    //--------------------------------------------------------------------------
    // Ethereum (ECDSA) Signed Message Hash

    /// @dev Returns an Ethereum Signed Message Hash from message `message`'s
    ///      keccak256 digest.
    function deriveEthereumSignedMessageHash(bytes memory message)
        internal
        pure
        returns (bytes32)
    {
        bytes32 digest;
        assembly ("memory-safe") {
            let len := mload(message)
            let offset := add(message, 0x20)

            digest := keccak256(offset, len)
        }

        return deriveEthereumSignedMessageHash(digest);
    }

    /// @dev Returns an Ethereum Signed Message Hash from hash digest `digest`.
    function deriveEthereumSignedMessageHash(bytes32 digest)
        internal
        pure
        returns (bytes32)
    {
        bytes32 ethMessageHash;
        assembly ("memory-safe") {
            // Note that the prefix's length is 0x1c, leading to a total length
            // of 0x1c + 0x20 = 0x3c.
            mstore(0x00, "\x19Ethereum Signed Message:\n32")
            mstore(0x1c, digest)
            ethMessageHash := keccak256(0x00, 0x3c)
        }
        return ethMessageHash;
    }

    //--------------------------------------------------------------------------
    // Ethereum Schnorr Signed Message Hash

    /// @dev Returns an Ethereum Schnorr Signed Message Hash from message
    ///      `message`'s keccak256 digest.
    function deriveEthereumSchnorrSignedMessageHash(bytes memory message)
        internal
        pure
        returns (bytes32)
    {
        bytes32 digest;
        assembly ("memory-safe") {
            let len := mload(message)
            let offset := add(message, 0x20)

            digest := keccak256(offset, len)
        }

        return deriveEthereumSchnorrSignedMessageHash(digest);
    }

    /// @dev Returns an Ethereum Schnorr Signed Message Hash from hash digest
    ///      `digest`.
    function deriveEthereumSchnorrSignedMessageHash(bytes32 digest)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked("\x19Ethereum Schnorr Signed Message:\n32", digest));
    }
}
