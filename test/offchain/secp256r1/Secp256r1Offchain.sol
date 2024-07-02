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

/**
 * @notice Secp256r1Offchain Unit Tests
 */
contract Secp256r1OffchainTest is Test {
    using Secp256r1Offchain for SecretKey;
    using Secp256r1Offchain for PublicKey;
    using Secp256r1 for SecretKey;
    using Secp256r1 for PublicKey;

    Secp256r1OffchainWrapper wrapper;

    function setUp() public {
        wrapper = new Secp256r1OffchainWrapper();
    }

    //--------------------------------------------------------------------------
    // Test: Secret Key

    // -- newSecretKey

    function test_newSecretKey() public {
        SecretKey sk = wrapper.newSecretKey();

        assertTrue(sk.isValid());

        // Verify [sk]G is valid public key.
        assertTrue(sk.toPublicKey().isValid());
    }

    // -- toPublicKey

    function testFuzz_SecretKey_toPublicKey(SecretKey sk) public {
        vm.skip(true);
        // TODO: Need vm support for p256 public key.
        //vm.assume(sk.isValid());
        //
        //address got = wrapper.toPublicKey(sk).toAddress();
        //address want = vm.p256PublicKey(sk.asUint());
        //
        //assertEq(got, want);
    }

    function testFuzz_SecretKey_toPublicKey_RevertsIf_SecretKeyInvalid(
        uint seed
    ) public {
        SecretKey sk = SecretKey.wrap(_bound(seed, Secp256r1.Q, type(uint).max));

        vm.expectRevert("SecretKeyInvalid()");
        wrapper.toPublicKey(sk);
    }

    //--------------------------------------------------------------------------
    // Public Key

    function test_PublicKey_toString(SecretKey sk) public {
        vm.assume(sk.isValid());

        string memory str = wrapper.toString(sk.toPublicKey());
        console.log(str);
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract Secp256r1OffchainWrapper {
    using Secp256r1Offchain for SecretKey;
    using Secp256r1Offchain for PublicKey;

    //--------------------------------------------------------------------------
    // Secret Key

    function newSecretKey() public returns (SecretKey) {
        return Secp256r1Offchain.newSecretKey();
    }

    function toPublicKey(SecretKey sk) public returns (PublicKey memory) {
        return sk.toPublicKey();
    }

    //--------------------------------------------------------------------------
    // Public Key

    function toString(PublicKey memory pk) public returns (string memory) {
        return pk.toString();
    }
}
