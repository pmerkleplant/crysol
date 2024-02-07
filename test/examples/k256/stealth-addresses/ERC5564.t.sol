// SPDX-License-Identifier: MIT
pragma solidity ^0.8.16;

import {Test} from "forge-std/Test.sol";

import {ERC5564Example} from "examples/k256/stealth-addresses/ERC5564.sol";

/**
 * @title ERC5564ExamplesTest
 *
 * @notice Tests StealthAddressesSecp256k1 examples in
 *         examples/k256/stealth-addresses/ERC5564.sol.
 */
contract ERC5564ExamplesTest is Test {
    ERC5564Example example;

    function setUp() public {
        example = new ERC5564Example();
    }

    function test_run() public {
        example.run();
    }
}
