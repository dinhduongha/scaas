// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PqzSafety} from "../../../src/pqz/PqzSafety.sol";
import {PqzSet} from "../../../src/pqz/PqzSet.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";

/// @notice The `PQZ` precompile mocked (P6g plan D6): op 6 answers the frozen self-test hash, an op byte the word the
///         test sets (a prefix match on the input's first byte, so every statement of that op). Everything else in the
///         PQZ tests is real code.
abstract contract PqzMock is Test {
    address internal constant PQZ = PqzSafety.PQZ;

    // statement offsets and lengths at the build's set (pq-zero-knowledge.md §7.7; the 640-byte header, then keys)
    uint256 internal constant O_PK1 = 640 + PqzCt.PK; // R_TX pk_t / R_TXM pk_0 / R_BURN T
    uint256 internal constant O_PK2 = 640 + 2 * PqzCt.PK; // R_TX pk_a
    uint256 internal constant O_T = 640 + 3 * PqzCt.PK; // R_TX T
    uint256 internal constant O_OUT = 640 + 3 * PqzCt.PK + PqzCt.CT; // R_TX out = u ‖ v_t ‖ v_f ‖ v_a
    uint256 internal constant O_BOUT = 640 + PqzCt.PK + PqzCt.CT; // R_BURN u' ‖ v_f
    uint256 internal constant O_DU = 288 + PqzCt.PK; // disclosure u
    uint256 internal constant O_DV = 288 + 2 * PqzCt.PK; // disclosure v
    uint256 internal constant ST_TX = PqzSet.STMT_TRANSFER;
    uint256 internal constant ST_TX0 = PqzSet.STMT_TRANSFER0;
    uint256 internal constant ST_BURN = PqzSet.STMT_BURN;
    uint256 internal constant ST_DISC = PqzSet.STMT_DISCLOSE;
    uint256 internal constant ST_REG = PqzSet.STMT_REGISTER;

    function _mockSelfTest() internal {
        vm.mockCall(PQZ, hex"0600000000", abi.encode(PqzSafety.SELFTEST));
    }

    /// `op` 1–5 ⇒ `word` for every input of that op.
    function _mockOp(uint8 op, uint256 word) internal {
        vm.mockCall(PQZ, abi.encodePacked(op), abi.encode(word));
    }

    /// The build's set's vectors (plan 5h Task 8d part 2: `smartcontracts/vectors/pqz/` for `n2048-kmax1024`, else
    /// `smartcontracts/vectors/pqz/<set>/`; the set is `PqzSet.NAME`).
    function _vecDir() internal view returns (string memory d) {
        d = string.concat(vm.projectRoot(), "/../vectors/pqz/");
        if (keccak256(bytes(PqzSet.NAME)) != keccak256("n2048-kmax1024")) d = string.concat(d, PqzSet.NAME, "/");
    }

    /// One hex field of a JSON file of the set's vectors (no `0x` in the files).
    function _vecHex(string memory file, string memory key) internal view returns (bytes memory) {
        string memory j = vm.readFile(string.concat(_vecDir(), file));
        return vm.parseBytes(string.concat("0x", vm.parseJsonString(j, key)));
    }

    /// The stored (P46-packed) form of 64-bit-lane PQZ bytes (`PqzCt.packMem`).
    function _packed(bytes memory c) internal pure returns (bytes memory) {
        return PqzCt.packMem(c);
    }

    function _slice(bytes memory b, uint256 off, uint256 len) internal pure returns (bytes memory r) {
        r = new bytes(len);
        for (uint256 i; i < len; ++i) r[i] = b[off + i];
    }
}
