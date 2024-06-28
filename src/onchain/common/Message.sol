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
 * @notice Functionality for constructing Ethereum Signed Message Hashes
 *
 * @dev An Ethereum Signed Message Hash is a hash composed of a prefix and the
 *      actual message. The prefix makes a signature for the hash recognizable
 *      as an Ethereum specific signature.
 *
 *      An Ethereum Signed Message Hash is defined via the [`eth_sign`] RPC call:
 *          keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
 *
 *      Note that this library only provides functionality for creating Ethereum
 *      Signed Message Hashes for keccak256 digests and not arbitrary bytes.
 *
 * @custom:references
 *      - [eth_sign]: https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign
 *
 * @author verklegarden
 * @custom:repository github.com/verklegarden/crysol
 * @author Inspired by OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts)
 */
library Message {
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

    // ----- Schnorr EIP message hashes -----

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

    function deriveEthereumSchnorrSignedMessageHash(bytes32 digest)
        internal
        pure
        returns (bytes32)
    {
        bytes32 ethSchnorrMessageHash;
        assembly ("memory-safe") {
            // Note that the prefix's length is 0x24, leading to a total length
            // of 0x24 + 0x20 = 0x44.
            mstore(0x00, "\x19Ethereum Schnorr Signed Message:\n32")
            mstore(0x24, digest)
            ethSchnorrMessageHash := keccak256(0x00, 0x44)
        }
        return ethSchnorrMessageHash;
    }
}
