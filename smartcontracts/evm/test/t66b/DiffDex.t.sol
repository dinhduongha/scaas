// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UADexBase} from "../ua/UADex.t.sol";
import {LegacyDiff} from "./LegacyDiff.sol";

/// T66b §10, §4.2: the differential per entry on the DEX (its governance entries forwarded to D), the UA DEX fixture's
/// venue with its markets.
contract DiffDexTest is UADexBase, LegacyDiff {
    function setUp() public override {
        super.setUp();
        vm.etch(address(0xB0B), hex"00");
    }

    function _kindOf(address) internal pure override returns (uint8) { return type(uint8).max; }

    function test_diff_dex() public {
        address[] memory c = new address[](4);
        (c[0], c[1], c[2], c[3]) = (address(this), alice, dave, address(0x5757));
        _diffRows(address(dex), c);
    }

    function testFuzz_diff_dex(uint256 which, bytes calldata tail) public {
        _diffFuzz(address(dex), address(this), which, tail);
    }
}
