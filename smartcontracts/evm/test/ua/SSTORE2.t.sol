// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {isAmsterdam} from "../helpers/EvmVersion.sol";
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
        // a CREATE that fails (here: out of gas for the code deposit) reverts, never yields address 0. F185: this holds under
        // Amsterdam, where the deposit is EIP-8037 state gas and the CREATE needs more than 100,000 (the call ran out of
        // gas before it could revert): 250,000, was 100,000 (Osaka's 200 gas/byte deposit; 250,000 would afford it)
        bytes memory kb = new bytes(1_000);
        uint256 gas_ = isAmsterdam() ? 250_000 : 100_000; // before `expectRevert`: the probe is a call
        vm.expectRevert(SSTORE2.SSTORE2WriteFailed.selector);
        h.write{gas: gas_}(kb);
        // P6c: data the 2-byte length of the init code cannot carry reverts instead of storing a truncated copy
        vm.expectRevert(SSTORE2.SSTORE2WriteFailed.selector);
        h.write(new bytes(0xffff));
    }
}
