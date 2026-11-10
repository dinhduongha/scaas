// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzFixture} from "../pqz/helpers/PqzFixture.sol";
import {LegacyDiff} from "./LegacyDiff.sol";

/// T66b §10: the differential per entry on the PQZ kinds 4 and 5 (the PQZ fixture's stack).
contract DiffPqzTest is PqzFixture, LegacyDiff {
    address internal n;
    address internal w;

    function setUp() public {
        _stack();
        n = address(_newToken("dn"));
        _releaseWrapped();
        w = address(_newWrapped("dw"));
        vm.etch(address(0xB0B), hex"00");
    }

    function _callers() internal view returns (address[] memory c) {
        c = new address[](3);
        (c[0], c[1], c[2]) = (address(this), registrar, address(0x5757));
    }

    function test_diff_normalPqz() public {
        _diffRows(n, _callers());
    }

    function test_diff_wrappedPqz() public {
        _diffRows(w, _callers());
    }

    function testFuzz_diff_pqz(bool wrapped, uint256 which, bytes calldata tail) public {
        _diffFuzz(wrapped ? w : n, address(this), which, tail);
    }
}
