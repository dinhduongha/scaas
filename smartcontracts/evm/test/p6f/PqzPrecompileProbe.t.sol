// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {PqzPrecompileProbe} from "./PqzPrecompileProbe.sol";

/// Answers with a fixed returndata of `n` bytes (word = 1) or reverts.
contract Answer {
    uint256 immutable n;
    bool immutable fail;

    constructor(uint256 n_, bool fail_) {
        n = n_;
        fail = fail_;
    }

    fallback() external {
        if (fail) revert();
        uint256 len = n;
        assembly {
            mstore(0, 1)
            mstore(32, 7)
            return(0, len)
        }
    }
}

contract PqzPrecompileProbeTest is Test {
    PqzPrecompileProbe probe = new PqzPrecompileProbe();
    address constant PQZ = 0x5cAA500000000000000000000000000000000F01;

    function _mock(uint256 n, bool fail) internal {
        vm.etch(PQZ, address(new Answer(n, fail)).code);
    }

    function test_answers() public {
        _mock(32, false);
        (uint256 w, uint256 g, uint256 r) = probe.call(PQZ, hex"0600000000");
        assertEq(w, 1);
        assertEq(r, 32);
        assertGt(g, 100);
        _mock(64, false);
        (w,, r) = probe.call(PQZ, hex"01");
        assertEq(w, 1);
        assertEq(r, 64);
        _mock(0, false);
        (w,, r) = probe.call(PQZ, hex"01");
        assertEq(w, 0);
        assertEq(r, 0);
        _mock(32, true);
        (w,, r) = probe.call(PQZ, hex"01");
        assertEq(w, type(uint256).max);
        assertEq(r, 0);
    }

    function test_empty_account_answers_nothing() public view {
        (uint256 w,, uint256 r) = probe.call(address(0x5caa500000000000000000000000000000000012), hex"0102");
        assertEq(w, 0);
        assertEq(r, 0);
    }

    function test_identity_precompile_gas() public view {
        // identity: 15 + 3 per word; the probe's constant overhead = gasUsed - 100 - that
        (uint256 w, uint256 g, uint256 r) = probe.call(address(4), abi.encode(uint256(5)));
        assertEq(w, 5);
        assertEq(r, 32);
        assertGt(g, 100 + 18);
        assertLt(g, 100 + 18 + 40);
    }

    function test_check_emits() public {
        _mock(32, false);
        vm.recordLogs();
        probe.check(PQZ, hex"0600000000");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], PqzPrecompileProbe.Probed.selector);
        assertEq(logs[0].topics[1], bytes32(uint256(uint160(PQZ))));
        (bytes32 h, uint256 w, uint256 g, uint256 r) = abi.decode(logs[0].data, (bytes32, uint256, uint256, uint256));
        assertEq(h, keccak256(hex"0600000000"));
        assertEq(w, 1);
        assertGt(g, 100);
        assertEq(r, 32);
    }
}
