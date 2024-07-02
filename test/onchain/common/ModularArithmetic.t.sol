// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";
import {console2 as console} from "forge-std/console2.sol";

import {ModularArithmetic} from "src/onchain/common/ModularArithmetic.sol";

/**
 * @notice ModularArithmetic Unit Tests
 */
contract ModularArithmeticTest is Test {
    /// @dev Using secp256k1 prime for testing.
    uint internal constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    ModularArithmeticWrapper wrapper;

    function setUp() public {
        wrapper = new ModularArithmeticWrapper();
    }

    // -- computeInverse

    function testFuzz_computeInverse(uint x) public {
        vm.assume(x != 0);
        vm.assume(x < P);

        uint xInv = wrapper.computeInverse(x, P);
        assertEq(mulmod(x, xInv, P), 1);
    }

    function test_computeInverse_ReturnsIdentity_IfIdentity() public {
        assertEq(wrapper.computeInverse(1, P), 1);
    }

    function test_computeInverse_RevertsIf_XIsZero() public {
        vm.expectRevert("ModularInverseOfZeroDoesNotExist()");
        wrapper.computeInverse(0, P);
    }

    function testFuzz_computeInverse_RevertsIf_XGreaterThanOrEqualToPrime(
        uint x
    ) public {
        vm.assume(x != 0);
        vm.assume(x >= P);

        vm.expectRevert("ModularInverseOfXGreaterThanPrime()");
        wrapper.computeInverse(x, P);
    }

    // -- computeExponentiation

    function test_computeExponentiation() public {
        vm.skip(true);
        // TODO: Implement computeExponentiation() tests.
    }

    function testFuzz_computeExponentiation_RevertsIf_OutOfGas(
        uint base,
        uint exponent
    ) public {
        // Note that modexp's min gas cost is 200.
        try wrapper.computeExponentiation{gas: 200}(base, exponent, P) returns (
            uint
        ) {
            fail();
        } catch {}
    }
}

/**
 * @notice Library wrapper to enable forge coverage reporting
 *
 * @dev For more info, see https://github.com/foundry-rs/foundry/pull/3128#issuecomment-1241245086.
 */
contract ModularArithmeticWrapper {
    function computeInverse(uint x, uint prime) public view returns (uint) {
        return ModularArithmetic.computeInverse(x, prime);
    }

    function computeExponentiation(uint base, uint exponent, uint prime)
        public
        view
        returns (uint)
    {
        return ModularArithmetic.computeExponentiation(base, exponent, prime);
    }
}
