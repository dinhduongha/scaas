// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";

contract SSTORE2Harness {
    function write(bytes calldata d) external returns (address) {
        return SSTORE2.write(d);
    }

    function read(address p) external view returns (bytes memory) {
        return SSTORE2.read(p);
    }
}

/// `SSTORE2` (CTR-UA-17 `keyPtr`): code = STOP ‖ data, read back exactly, inert, a failed CREATE reverts.
contract SSTORE2Test is Test {
    function test_sstore2() public {
        SSTORE2Harness h = new SSTORE2Harness();
        bytes[4] memory data = [bytes(""), hex"aa", new bytes(33), new bytes(9_525)];
        data[3][9_524] = 0x7f;
        for (uint256 i; i < data.length; ++i) {
            address p = h.write(data[i]);
            assertEq(p.code, bytes.concat(hex"00", data[i]), "code = STOP + data");
            assertEq(h.read(p), data[i]);
        }
        assertEq(h.read(address(0xdead)).length, 0, "no code: empty");
        // the data contract is inert: a call just STOPs
        address q = h.write(hex"ff");
        (bool ok, bytes memory ret) = q.call(hex"12345678");
        assertTrue(ok);
        assertEq(ret.length, 0);
        // a CREATE that fails (here: out of gas for the 200 gas/byte code deposit) reverts, never yields address 0
        bytes memory kb = new bytes(1_000);
        vm.expectRevert(SSTORE2.SSTORE2WriteFailed.selector);
        h.write{gas: 100_000}(kb);
    }
}
