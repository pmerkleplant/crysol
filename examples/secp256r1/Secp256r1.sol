// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {Secp256r1Offchain} from "src/offchain/secp256r1/Secp256r1Offchain.sol";
import {
    Secp256r1,
    SecretKey,
    PublicKey
} from "src/onchain/secp256r1/Secp256r1.sol";
import {
    Secp256r1Arithmetic,
    Point,
    ProjectivePoint
} from "src/onchain/secp256r1/Secp256r1Arithmetic.sol";

/**
 * @title Secp256r1Example
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/secp256r1/Secp256r1.sol:Secp256r1Example -vvvv
 *      ```
 *
 * @dev Note that some code is commented out to reduce compiler warnings
 *      regarding unused variables.
 */
contract Secp256r1Example is Script {
    using Secp256r1Offchain for SecretKey;
    using Secp256r1Offchain for PublicKey;
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;
    using Secp256r1Arithmetic for Point;
    using Secp256r1Arithmetic for ProjectivePoint;

    function run() public {
        // Create new cryptographically sound secret key.
        SecretKey sk = Secp256r1Offchain.newSecretKey();
        // assert(sk.isValid());
        console.log("Created new secret key:");
        console.log(sk.asUint());
        console.log("");

        // Derive public key.
        PublicKey memory pk = sk.toPublicKey();
        // assert(pk.isValid());
        console.log("Derived public key:");
        console.log(pk.toString());
        console.log("");

        // Arithmetic types.
        // into___() -> overwrites memory, no allocation / memory expansion cost
        // to___()   -> allocates new memory, may has expansion cost
        /*
        Point memory point = pk.intoPoint();
        ProjectivePoint memory jPoint = pk.toProjectivePoint();
        */

        // Derive common constructs.
        // bytes32 digest = pk.toHash();
        // uint yParity = pk.yParity();

        // Serialization.
        console.log("ABI serialized public key:");
        console.logBytes(pk.toBytes());
        console.log("");

        console.log("SEC encoded public key:");
        console.logBytes(pk.intoPoint().toEncoded());
        console.log("");

        console.log("SEC compressed encoded public key:");
        console.logBytes(pk.intoPoint().toCompressedEncoded());
        console.log("");
    }
}
