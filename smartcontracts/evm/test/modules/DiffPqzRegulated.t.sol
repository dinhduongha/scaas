// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegFixture} from "../as/confidential/PqzRegFixture.sol";
import {LegacyDiff} from "./LegacyDiff.sol";

/// T66b §10: the differential per entry on the regulated PQZ kinds 12 and 13 (the regulated fixture's token).
abstract contract DiffPqzReg is PqzRegFixture, LegacyDiff {
    function setUp() public override {
        super.setUp();
        vm.etch(address(0xB0B), hex"00");
    }

    function test_diff() public {
        address[] memory c = new address[](4);
        (c[0], c[1], c[2], c[3]) = (address(this), issuer, registrar, address(0x5757));
        _diffRows(address(tok), c);
    }

    function testFuzz_diff(uint256 which, bytes calldata tail) public {
        _diffFuzz(address(tok), address(this), which, tail);
    }
}

contract DiffPqzReg12Test is DiffPqzReg {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract DiffPqzReg13Test is DiffPqzReg {
    function _isWrapped() internal pure override returns (bool) { return true; }
}
