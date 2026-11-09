// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {RegFixture} from "../as/helpers/RegFixture.sol";
import {LegacyDiff} from "./LegacyDiff.sol";

/// T66b §10: the differential per entry on the regulated kinds 8 and 9 (the regulated fixture's tokens).
contract DiffRegulatedTest is RegFixture, LegacyDiff {
    function setUp() public override {
        super.setUp();
        vm.etch(address(0xB0B), hex"00"); // the rows' sample address: a contract (the allowance rule, CTR-TOK-01)
    }

    function _callers() internal view returns (address[] memory c) {
        c = new address[](6);
        (c[0], c[1], c[2], c[3], c[4], c[5]) = (alice, ownerA, issuer, compliance, relayer, address(0x5757));
    }

    function test_diff_normalRegulated() public {
        _diffRows(t8, _callers());
    }

    function test_diff_wrappedRegulated() public {
        _diffRows(t9, _callers());
    }

    function testFuzz_diff_regulated(bool wrapped, uint256 which, bytes calldata tail) public {
        _diffFuzz(wrapped ? t9 : t8, alice, which, tail);
    }
}
