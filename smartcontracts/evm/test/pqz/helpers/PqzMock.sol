// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PqzSafety} from "../../../src/pqz/PqzSafety.sol";

/// @notice The `PQZ` precompile mocked (P6g plan D6): op 6 answers the frozen self-test hash, an op byte the word the
///         test sets (a prefix match on the input's first byte, so every statement of that op). Everything else in the
///         PQZ tests is real code.
abstract contract PqzMock is Test {
    address internal constant PQZ = PqzSafety.PQZ;

    function _mockSelfTest() internal {
        vm.mockCall(PQZ, hex"0600000000", abi.encode(PqzSafety.SELFTEST));
    }

    /// `op` 1–5 ⇒ `word` for every input of that op.
    function _mockOp(uint8 op, uint256 word) internal {
        vm.mockCall(PQZ, abi.encodePacked(op), abi.encode(word));
    }

    /// The vectors (`smartcontracts/vectors/pqz/`): one hex field of a JSON file (no `0x` in the files).
    function _vecHex(string memory file, string memory key) internal view returns (bytes memory) {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/../vectors/pqz/", file));
        return vm.parseBytes(string.concat("0x", vm.parseJsonString(j, key)));
    }

    function _slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory r) {
        r = new bytes(len);
        for (uint256 i; i < len; ++i) r[i] = b[off + i];
    }
}
