// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/mockUSDC.sol";

contract mockUSDCTest is Test {
    mockUSDC public usdc;

    function setUp() public {
        usdc = new mockUSDC();
        usdc.setNumber(0);
    }

    function testIncrement() public {
        usdc.increment();
        assertEq(usdc.number(), 1);
    }

    function testSetNumber(uint256 x) public {
        usdc.setNumber(x);
        assertEq(usdc.number(), x);
    }
}
