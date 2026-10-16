// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzMock} from "./helpers/PqzMock.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSafety} from "../../src/pqz/PqzSafety.sol";

/// Calldata entry to the library (its inputs are calldata on every token path).
contract PqzCtHarness {
    function sum(bytes calldata acc, bytes[] calldata plus_, bytes[] calldata minus_, uint256 plain)
        external pure returns (bytes memory c)
    {
        c = PqzCt.load(acc);
        for (uint256 i; i < plus_.length; ++i) PqzCt.plus(c, plus_[i]);
        for (uint256 i; i < minus_.length; ++i) PqzCt.minus(c, minus_[i]);
        PqzCt.addTrivial(c, plain);
        PqzCt.reduce(c);
    }

    function canonical(bytes calldata b) external pure returns (bool) {
        return PqzCt.isCanonical(b);
    }
}

/// `PqzCt` on the P6e vectors (P6g plan Task 2, D6) and `PqzSafety`.
contract PqzCtTest is PqzMock {
    PqzCtHarness internal h;
    bytes internal stmt; // statement_transfer.json row 0 (R_TX, 83,072 B)

    function setUp() public {
        h = new PqzCtHarness();
        stmt = _vecHex("statement_transfer.json", ".rows[0].stmt");
    }

    function _T() internal view returns (bytes memory) {
        return _slice(stmt, 49_792, PqzCt.CT); // u_T ‖ v_T
    }

    /// u ‖ v_t of the transfer's out (u at 66,304, v_t at 82,688)
    function _X() internal view returns (bytes memory) {
        return bytes.concat(_slice(stmt, 66_304, PqzCt.PK), _slice(stmt, 82_688, PqzCt.V));
    }

    /// The test's own `− Trivial(m)` (the library has no use for it): v[i] −= Δ·digit_i mod q.
    function _subTrivial(bytes memory c, uint256 m) internal pure returns (bytes memory r) {
        r = bytes.concat(c);
        for (uint256 i; i < 16; ++i) {
            uint256 o = PqzCt.PK + 8 * i;
            uint256 x = uint64(bytes8(_word8(r, o)));
            x = (x + PqzCt.Q - (PqzCt.DELTA * ((m >> (4 * i)) & 15)) % PqzCt.Q) % PqzCt.Q;
            for (uint256 k; k < 8; ++k) r[o + k] = bytes1(uint8(x >> (8 * (7 - k))));
        }
    }

    function _word8(bytes memory b, uint256 o) internal pure returns (bytes8 w) {
        for (uint256 k; k < 8; ++k) w |= bytes8(b[o + k]) >> (8 * k);
    }

    /// T of the vector = Enc_F(1,000,000; 0x61…) + Trivial(1000) = enc.json ops[0]; T − Trivial(1000) is rows[0]
    /// (u by keccak, v exactly); rows[0] − Trivial(1000) is ops[1]; `addTrivial` takes it back to T.
    function test_trivialAgainstVectors() public view {
        bytes memory t = _T();
        assertEq(keccak256(t), bytes32(_vecHex("enc.json", ".ops[0].ct_keccak")), "T = Enc + Trivial(1000)");
        bytes memory row0 = _subTrivial(t, 1000);
        assertEq(keccak256(_slice(row0, 0, PqzCt.PK)), bytes32(_vecHex("enc.json", ".rows[0].u_keccak")));
        assertEq(_slice(row0, PqzCt.PK, PqzCt.V), _vecHex("enc.json", ".rows[0].legs[0].v"));
        assertEq(keccak256(_subTrivial(row0, 1000)), bytes32(_vecHex("enc.json", ".ops[1].ct_keccak")));
        bytes[] memory none = new bytes[](0);
        assertEq(h.sum(row0, none, none, 1000), t, "addTrivial(1000) + reduce");
        assertEq(h.sum(t, none, none, 0), t, "Trivial(0) is the identity");
        assertEq(keccak256(new bytes(PqzCt.CT)), PqzCt.ZERO_HASH);
        assertEq(PqzCt.stored(bytes32(0)), PqzCt.ZERO_HASH);
    }

    /// 16 ciphertexts in and out again (`INLINE_MAX`, the rollover's 16), mod q exact.
    function test_sumsAreExact() public view {
        bytes memory t = _T();
        bytes memory x = _X();
        bytes[] memory xs = new bytes[](16);
        for (uint256 i; i < 16; ++i) xs[i] = x;
        bytes[] memory none = new bytes[](0);
        bytes memory up = h.sum(t, xs, none, 0);
        assertTrue(keccak256(up) != keccak256(t));
        assertEq(h.sum(up, none, xs, 0), t, "(T + 16 X) - 16 X = T");
        assertEq(h.sum(t, xs, xs, 0), t, "T + 16 X - 16 X in one pass");
        bytes[] memory one = new bytes[](1);
        one[0] = t;
        assertEq(h.sum(x, one, none, 7), h.sum(t, _arr(x), none, 7), "commutative, with a plain term");
        assertEq(h.sum(new bytes(PqzCt.CT), _arr(t), _arr(t), 0), new bytes(PqzCt.CT), "x - x = 0");
        assertTrue(h.canonical(up));
    }

    function _arr(bytes memory b) internal pure returns (bytes[] memory a) {
        a = new bytes[](1);
        a[0] = b;
    }

    function test_canonical() public view {
        bytes memory c = _T();
        assertTrue(h.canonical(c));
        bytes memory bad = bytes.concat(c);
        // coefficient 5 := q
        uint256 q = PqzCt.Q;
        for (uint256 k; k < 8; ++k) bad[40 + k] = bytes1(uint8(q >> (8 * (7 - k))));
        assertFalse(h.canonical(bad));
        for (uint256 k; k < 8; ++k) bad[40 + k] = bytes1(uint8((q - 1) >> (8 * (7 - k))));
        assertTrue(h.canonical(bad));
        bad[PqzCt.CT - 8] = 0xff; // the last coefficient ≥ 2^56
        assertFalse(h.canonical(bad));
        assertFalse(h.canonical(new bytes(31)), "not whole words");
        assertTrue(h.canonical(""));
    }

    // ------------------------------------------------------------------ PqzSafety

    function test_safetyAllowlist() public {
        assertTrue(PqzSafety.isAllowedChain()); // 31337
        vm.chainId(7622);
        assertTrue(PqzSafety.isAllowedChain());
        vm.chainId(1337);
        assertTrue(PqzSafety.isAllowedChain());
        vm.chainId(22776);
        assertFalse(PqzSafety.isAllowedChain());
        vm.expectRevert(abi.encodeWithSelector(PqzSafety.NotAllowedChain.selector, 22776));
        this.requireChain();
    }

    function requireChain() external view {
        PqzSafety.requireAllowedChain();
    }

    function test_selfTest() public {
        assertFalse(PqzSafety.selfTest(PQZ), "empty account");
        _mockSelfTest();
        assertTrue(PqzSafety.selfTest(PQZ));
        vm.mockCall(PQZ, hex"0600000000", abi.encode(uint256(PqzSafety.SELFTEST) ^ 1));
        assertFalse(PqzSafety.selfTest(PQZ), "another word");
        vm.mockCall(PQZ, hex"0600000000", abi.encodePacked(PqzSafety.SELFTEST, uint8(0)));
        assertFalse(PqzSafety.selfTest(PQZ), "33 bytes");
        vm.mockCallRevert(PQZ, hex"0600000000", "");
        assertFalse(PqzSafety.selfTest(PQZ), "revert");
    }
}
