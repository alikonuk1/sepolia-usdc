// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import {mockUSDC} from "src/mockUSDC.sol";

contract mockUSDCScript is Script {
    mockUSDC usdc;

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        usdc = new mockUSDC();
        vm.stopBroadcast();
    }
}
