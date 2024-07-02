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
 * @notice Secp256r1 Unit Tests
 */
contract Secp256r1Test is Test {
    using Secp256r1Offchain for SecretKey;
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;
    using Secp256r1 for Point;
    using Secp256r1Arithmetic for Point;
    using Secp256r1Arithmetic for ProjectivePoint;

    // Uncompressed Generator G.
    // Copied from [SEC-2 v2].
    bytes constant GENERATOR_ENCODED =
        hex"046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";

    Secp256r1Wrapper wrapper;

    function setUp() public {
        wrapper = new Secp256r1Wrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Constants

    function test_G() public {
        PublicKey memory got = wrapper.G();
        PublicKey memory want = Secp256r1Arithmetic.pointFromEncoded(
            GENERATOR_ENCODED
        ).intoPublicKey();

        assertTrue(got.eq(want));
    }

    //--------------------------------------------------------------------------
    // Test: Secret Key

    // -- isValid

    function testFuzz_SecretKey_isValid(uint seed) public {
        uint scalar = _bound(seed, 1, Secp256r1.Q - 1);

        assertTrue(wrapper.isValid(SecretKey.wrap(scalar)));
    }

    function test_SecretKey_isValid_FailsIf_SecretKeyIsZero() public {
        assertFalse(wrapper.isValid(SecretKey.wrap(0)));
    }

    function testFuzz_SecretKey_isValid_FailsIf_SecretKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256r1.Q, type(uint).max);

        assertFalse(wrapper.isValid(SecretKey.wrap(scalar)));
    }

    // -- secretKeyFromUint

    function testFuzz_secretKeyFromUint(uint seed) public {
        uint scalar = _bound(seed, 1, Secp256r1.Q - 1);

        SecretKey sk = wrapper.secretKeyFromUint(scalar);

        assertTrue(sk.isValid());
        assertEq(sk.asUint(), scalar);
    }

    function test_secretKeyFromUint_RevertsIf_ScalarZero() public {
        vm.expectRevert("ScalarInvalid()");
        wrapper.secretKeyFromUint(0);
    }

    function test_secretKeyFromUint_RevertsIf_ScalarGreaterOrEqualToQ(uint seed)
        public
    {
        uint scalar = _bound(seed, Secp256r1.Q, type(uint).max);

        vm.expectRevert("ScalarInvalid()");
        wrapper.secretKeyFromUint(scalar);
    }

    // -- asUint

    function testFuzz_SecretKey_asUint(uint seed) public {
        assertEq(seed, wrapper.asUint(SecretKey.wrap(seed)));
    }

    //--------------------------------------------------------------------------
    // Test: Public Key

    // -- toHash

    function testFuzz_PublicKey_toHash(PublicKey memory pk) public {
        bytes32 got = wrapper.toHash(pk);
        bytes32 want = keccak256(abi.encodePacked(pk.x, pk.y));

        assertEq(got, want);
    }

    // -- isValid

    function testFuzz_PublicKey_isValid_If_CreatedViaValidSecretKey(uint seed)
        public
    {
        SecretKey sk =
            Secp256r1.secretKeyFromUint(_bound(seed, 1, Secp256r1.Q - 1));

        // Every public key created via valid secret key is valid.
        assertTrue(wrapper.isValid(sk.toPublicKey()));
    }

    function test_PublicKey_isValid_FailsIf_Identity() public {
        PublicKey memory pk = Secp256r1Arithmetic.Identity().intoPublicKey();

        assertFalse(wrapper.isValid(pk));
    }

    function test_PublicKey_isValid_FailsIf_PointNotOnCurve() public {
        PublicKey memory pk;

        pk.x = 1;
        pk.x = 3;
        assertFalse(wrapper.isValid(pk));
    }

    // -- yParity

    function testFuzz_PublicKey_yParity(uint x, uint y) public {
        // yParity is 0 if y is even and 1 if y is odd.
        uint want = y % 2 == 0 ? 0 : 1;
        uint got = wrapper.yParity(PublicKey(x, y));

        assertEq(want, got);
    }

    // -- eq

    function testFuzz_PublicKey_eq(PublicKey memory pr1, PublicKey memory pk2)
        public
    {
        bool want = pr1.x == pk2.x && pr1.y == pk2.y;
        bool got = wrapper.eq(pr1, pk2);

        assertEq(want, got);
    }

    // -- intoPoint

    // TODO: Add no memory expansion tests for `into__()` functions.
    //       Must directly use library, not wrapper.

    function testFuzz_PublicKey_intoPoint(PublicKey memory pk) public {
        Point memory point = wrapper.intoPoint(pk);

        assertEq(point.x, pk.x);
        assertEq(point.y, pk.y);
    }

    // -- Point::intoPublicKey

    function testFuzz_Point_intoPublicKey(Point memory point) public {
        PublicKey memory pk = wrapper.intoPublicKey(point);

        assertEq(pk.x, point.x);
        assertEq(pk.y, point.y);
    }

    // -- toProjectivePoint

    function testFuzz_PublicKey_toProjectivePoint(PublicKey memory pk) public {
        ProjectivePoint memory point = wrapper.toProjectivePoint(pk);

        if (pk.intoPoint().isIdentity()) {
            assertTrue(point.isIdentity());
        } else {
            assertEq(point.x, pk.x);
            assertEq(point.y, pk.y);
            assertEq(point.z, 1);
        }
    }

    //--------------------------------------------------------------------------
    // Test: (De)Serialization

    //----------------------------------
    // Secret Key

    // -- SecretKey <-> Bytes

    function testFuzz_secretKeyFromBytes(SecretKey sk) public {
        vm.assume(sk.isValid());

        bytes memory blob = abi.encodePacked(sk.asUint());

        SecretKey sk2 = wrapper.secretKeyFromBytes(blob);

        assertEq(sk.asUint(), sk2.asUint());
    }

    function testFuzz_secretKeyFromBytes_RevertsIf_LengthNot32Bytes(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 32);

        vm.expectRevert("LengthInvalid()");
        wrapper.secretKeyFromBytes(blob);
    }

    function test_secretKeyFromBytes_RevertsIf_DeserializedSecretKeyInvalid_SecretKeyZero(
    ) public {
        bytes memory blob = abi.encodePacked(uint(0));

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.secretKeyFromBytes(blob);
    }

    function testFuzz_secretKeyFromBytes_RevertsIf_DeserializedSecretKeyInvalid_SecretKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256r1.Q, type(uint).max);

        bytes memory blob = abi.encodePacked(scalar);

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.secretKeyFromBytes(blob);
    }

    function testFuzz_SecretKey_toBytes(SecretKey sk) public {
        vm.assume(sk.isValid());

        bytes memory blob = wrapper.toBytes(sk);

        assertEq(sk.asUint(), Secp256r1.secretKeyFromBytes(blob).asUint());
    }

    function test_SecretKey_toBytes_RevertsIf_SecretKeyInvalid_SecretKeyZero()
        public
    {
        SecretKey sk = SecretKey.wrap(0);

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.toBytes(sk);
    }

    function testFuzz_SecretKey_toBytes_RevertsIf_SecretKeyInvalid_SecretKeyGreaterOrEqualToQ(
        uint seed
    ) public {
        uint scalar = _bound(seed, Secp256r1.Q, type(uint).max);
        SecretKey sk = SecretKey.wrap(scalar);

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.toBytes(sk);
    }

    //----------------------------------
    // Public Key

    // -- PublicKey <-> Bytes

    // TODO: PublicKey <-> Bytes: Need test vectors.
    function testFuzz_publicKeyFromBytes(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory pr1 = sk.toPublicKey();
        bytes memory blob = pr1.toBytes();

        PublicKey memory pk2 = wrapper.publicKeyFromBytes(blob);

        assertTrue(pr1.eq(pk2));
    }

    function testFuzz_publicKeyFromBytes_RevertsIf_LengthNot64Bytes(
        bytes memory blob
    ) public {
        vm.assume(blob.length != 64);

        vm.expectRevert("LengthInvalid()");
        wrapper.publicKeyFromBytes(blob);
    }

    function testFuzz_publicKeyFromBytes_RevertsIf_DeserializedPublicKeyInvalid(
        PublicKey memory pk
    ) public {
        vm.assume(!pk.isValid());

        bytes memory blob = abi.encodePacked(pk.x, pk.y);

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.publicKeyFromBytes(blob);
    }

    function testFuzz_PublicKey_toBytes(SecretKey sk) public {
        vm.assume(sk.isValid());

        PublicKey memory pr1 = sk.toPublicKey();

        bytes memory blob = wrapper.toBytes(pr1);
        assertEq(blob.length, 64);

        PublicKey memory pk2 = Secp256r1.publicKeyFromBytes(blob);
        assertTrue(pr1.eq(pk2));
    }

    function testFuzz_PublicKey_toBytes_RevertsIf_PublicKeyInvalid(
        PublicKey memory pk
    ) public {
        vm.assume(!pk.isValid());

        vm.expectRevert("PublicKeyInvalid()");
        wrapper.toBytes(pk);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256r1Wrapper {
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;
    using Secp256r1 for Point;

    using Secp256r1Arithmetic for Point;

    //--------------------------------------------------------------------------
    // Constants

    function G() public pure returns (PublicKey memory) {
        return Secp256r1.G();
    }

    //--------------------------------------------------------------------------
    // Secret Key

    function isValid(SecretKey sk) public pure returns (bool) {
        return sk.isValid();
    }

    function secretKeyFromUint(uint scalar) public pure returns (SecretKey) {
        return Secp256r1.secretKeyFromUint(scalar);
    }

    function asUint(SecretKey sk) public pure returns (uint) {
        return sk.asUint();
    }

    //--------------------------------------------------------------------------
    // Public Key

    function toHash(PublicKey memory pk) public pure returns (bytes32) {
        return pk.toHash();
    }

    function isValid(PublicKey memory pk) public pure returns (bool) {
        return pk.isValid();
    }

    function yParity(PublicKey memory pk) public pure returns (uint) {
        return pk.yParity();
    }

    function eq(PublicKey memory pk, PublicKey memory other)
        public
        pure
        returns (bool)
    {
        return pk.eq(other);
    }

    function intoPoint(PublicKey memory pk)
        public
        pure
        returns (Point memory)
    {
        return pk.intoPoint();
    }

    function intoPublicKey(Point memory point)
        public
        pure
        returns (PublicKey memory)
    {
        return point.intoPublicKey();
    }

    function toProjectivePoint(PublicKey memory pk)
        public
        pure
        returns (ProjectivePoint memory)
    {
        return pk.toProjectivePoint();
    }

    //--------------------------------------------------------------------------
    // (De)Serialization

    //----------------------------------
    // Secret Key

    function secretKeyFromBytes(bytes memory blob)
        public
        pure
        returns (SecretKey)
    {
        return Secp256r1.secretKeyFromBytes(blob);
    }

    function toBytes(SecretKey sk) public pure returns (bytes memory) {
        return sk.toBytes();
    }

    //----------------------------------
    // Public Key

    function publicKeyFromBytes(bytes memory blob)
        public
        pure
        returns (PublicKey memory)
    {
        return Secp256r1.publicKeyFromBytes(blob);
    }

    function toBytes(PublicKey memory pk) public pure returns (bytes memory) {
        return pk.toBytes();
    }
}
