// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
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
 * @notice Secp256r1 Property Tests
 */
contract Secp256r1PropertiesTest is Test {
    using Secp256r1Offchain for SecretKey;
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;
    using Secp256r1 for Point;

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    //----------------------------------
    // Secret Key

    function testProperty_SecretKey_Bytes_SerializationLoop(SecretKey start)
        public
    {
        vm.assume(start.isValid());

        SecretKey end = Secp256r1.secretKeyFromBytes(start.toBytes());

        assertEq(start.asUint(), end.asUint());
    }

    //----------------------------------
    // Public Key

    function testProperty_PublicKey_Bytes_SerializationLoop(SecretKey sk)
        public
    {
        vm.assume(sk.isValid());

        PublicKey memory start = sk.toPublicKey();
        PublicKey memory end = Secp256r1.publicKeyFromBytes(start.toBytes());

        assertTrue(start.eq(end));
    }
}
