// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/mockUSDC.sol";

contract mockUSDCTest is Test {
    mockUSDC public usdc;

    function setUp() public {
        usdc = new mockUSDC();
    }
}
