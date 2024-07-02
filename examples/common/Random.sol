// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.16;

import {Script} from "forge-std/Script.sol";
import {console2 as console} from "forge-std/console2.sol";

import {RandomOffchain} from "src/offchain/common/RandomOffchain.sol";

/**
 * @title RandomExample
 *
 * @dev Run via:
 *
 *      ```bash
 *      $ forge script examples/common/Random.sol:RandomExample -vvvv
 *      ```
 */
contract RandomExample is Script {
    function run() public {
        // Create random uint.
        uint rand = RandomOffchain.readUint();
        console.log("Cryptographically secure random uint256: ", rand);
        console.log("");
    }
}
