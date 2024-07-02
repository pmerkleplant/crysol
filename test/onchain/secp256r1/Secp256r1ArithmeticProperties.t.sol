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
 * @notice Secp256r1Arithmetic Property Tests
 */
contract Secp256r1ArithmeticPropertiesTest is Test {
    using Secp256r1Offchain for SecretKey;
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;
    using Secp256r1 for Point;
    using Secp256r1Arithmetic for Point;
    using Secp256r1Arithmetic for ProjectivePoint;

    //--------------------------------------------------------------------------
    // Test: Projective Point

    // -- add

    function testProperty_ProjectivePoint_add_NeverReturnsZeroPoint(
        SecretKey sr1,
        SecretKey sk2
    ) public {
        vm.assume(sr1.isValid());
        vm.assume(sk2.isValid());

        ProjectivePoint memory p1 = sr1.toPublicKey().toProjectivePoint();
        ProjectivePoint memory p2 = sk2.toPublicKey().toProjectivePoint();

        Point memory sum = p1.add(p2).intoPoint();

        assertFalse(sum.x == 0 && sum.y == 0);
    }

    function testProperty_ProjectivePoint_add_ResultIsOnCurve(
        SecretKey sr1,
        SecretKey sk2
    ) public {
        vm.assume(sr1.isValid());
        vm.assume(sk2.isValid());

        ProjectivePoint memory p1 = sr1.toPublicKey().toProjectivePoint();
        ProjectivePoint memory p2 = sk2.toPublicKey().toProjectivePoint();

        Point memory sum = p1.add(p2).intoPoint();

        assertTrue(sum.isOnCurve());
    }

    // -- mul

    function testProperty_ProjectivePoint_mul_ResultIsOnCurve(
        SecretKey sk,
        uint scalar
    ) public {
        vm.assume(sk.isValid());

        vm.assume(scalar < Secp256r1Arithmetic.Q);

        ProjectivePoint memory p = sk.toPublicKey().toProjectivePoint();

        Point memory product = p.mul(scalar).intoPoint();

        assertTrue(product.isOnCurve());
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    function testProperty_Point_Encoded_SerializationLoop(SecretKey sk)
        public
    {
        vm.assume(sk.isValid());

        Point memory start = sk.toPublicKey().intoPoint();

        Point memory end =
            Secp256r1Arithmetic.pointFromEncoded(start.toEncoded());

        assertTrue(start.eq(end));
    }

    function testProperty_Point_CompressedEncoded_SerializationLoop(
        SecretKey sk
    ) public {
        vm.assume(sk.isValid());

        Point memory start = sk.toPublicKey().intoPoint();

        Point memory end = Secp256r1Arithmetic.pointFromCompressedEncoded(
            start.toCompressedEncoded()
        );

        assertTrue(start.eq(end));
    }
}
