// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzMock} from "./helpers/PqzMock.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzSafety} from "../../src/pqz/PqzSafety.sol";
import {PqzCtHarness} from "./helpers/PqzCtHarness.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";

/// `PqzCt` on the P6e vectors of the build's set (P6g plan Task 2, D6), the P46 stored form, and `PqzSafety`.
contract PqzCtTest is PqzMock {
    PqzCtHarness internal h;
    bytes internal stmt; // statement_transfer.json row 0 (R_TX: header ‖ pk_f ‖ pk_t ‖ pk_a ‖ T ‖ u ‖ v_t ‖ v_f ‖ v_a)

    function setUp() public {
        h = new PqzCtHarness();
        stmt = _vecHex("statement_transfer.json", ".rows[0].stmt");
    }

    function _T() internal view returns (bytes memory) {
        return _slice(stmt, 640 + 3 * PqzCt.PK, PqzCt.CT); // u_T ‖ v_T
    }

    /// u ‖ v_t of the transfer's out
    function _X() internal view returns (bytes memory) {
        uint256 u = 640 + 3 * PqzCt.PK + PqzCt.CT;
        return bytes.concat(_slice(stmt, u, PqzCt.PK), _slice(stmt, u + PqzCt.PK, PqzCt.V));
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
        assertEq(keccak256(_packed(new bytes(PqzCt.CT))), PqzCt.ZERO_HASH, "ZERO_HASH: the packed Trivial(0)");
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

    // ------------------------------------------------------------------ the stored form (P46, plan 5h Task 8d part 2)

    /// A ciphertext: random coefficients `< q` (mode 0), all `q − 1` (1), all zero (2).
    function _ct(uint256 seed, uint256 mode) internal pure returns (bytes memory c) {
        c = new bytes(PqzCt.CT);
        for (uint256 o; o < PqzCt.CT; o += 32) {
            uint256 w;
            for (uint256 k; k < 4; ++k) {
                uint256 x = mode == 0 ? uint256(keccak256(abi.encode(seed, o, k))) % PqzCt.Q : mode == 1 ? PqzCt.Q - 1 : 0;
                w = w << 64 | x;
            }
            assembly ("memory-safe") { mstore(add(add(c, 32), o), w) }
        }
    }

    function _roundTrip(bytes memory c) internal pure {
        bytes memory p = _packed(c);
        assertEq(p.length, PqzCt.CTP, "packed length");
        assertEq(keccak256(PqzCt.unpackCt(p)), keccak256(c), "round trip");
    }

    /// Every canonical ciphertext packs to `CTP` bytes and unpacks to itself: random, all `q − 1`, all zero.
    function test_pack_roundTrip(uint256 seed) public pure {
        _roundTrip(_ct(seed, 0));
    }

    function test_pack_roundTripEdges() public pure {
        _roundTrip(_ct(0, 1));
        _roundTrip(_ct(0, 2));
    }

    /// The stored stream is the coefficients' `B`-bit fields concatenated big-endian, coefficient 0 first (what an
    /// off-chain reader of a blob, a hint or `accHash` unpacks; pq-zero-knowledge.md §8.1): checked bit by bit here.
    function test_pack_layout() public pure {
        bytes memory c = _ct(7, 0);
        bytes memory p = _packed(c);
        uint256 b = PqzSet.PACK_BITS;
        for (uint256 i; i < 64; ++i) { // the first 64 coefficients (16 groups)
            uint256 x = uint64(bytes8(_word8(c, 8 * i)));
            for (uint256 k; k < b; ++k) {
                uint256 bit = b * i + k; // stream bit, MSB first
                uint256 got = (uint8(p[bit / 8]) >> (7 - bit % 8)) & 1;
                assertEq(got, (x >> (b - 1 - k)) & 1, "stream bit");
            }
        }
    }

    /// The sizes of the stored form at the build's set, and the headroom the unreduced sums rely on: `B = ⌈log2 q⌉`
    /// (q < 2^B, so an all-ones field is never a coefficient: no `acc` slot stores 0); a rollover's lanes `< 2^64` with
    /// `ROLL_MAX + 1` terms; the accumulators' `B`-bit carry gaps hold far more than `ROLL_MAX` terms; a debit's window
    /// (`acc`, `INLINE_MAX` entries, `Trivial(shieldIn)`) within the lanes too.
    function test_pack_sizesAndHeadroom() public pure {
        uint256 b = PqzSet.PACK_BITS;
        assertTrue(PqzCt.Q < 1 << b && PqzCt.Q > 1 << (b - 1), "B = ceil(log2 q)");
        assertEq(b % 2, 0, "a packed word is whole bytes");
        assertEq(PqzCt.CTP, PqzCt.CT * b / 64, "CTP = CT * B / 64");
        assertEq(PqzCt.ACC_WORDS, (PqzCt.CTP + 31) / 32, "acc slots");
        assertEq(PqzCore.HALF_WORDS + (PqzCt.ACC_WORDS - PqzCore.HALF_WORDS), PqzCt.ACC_WORDS);
        assertLt((PqzCore.ROLL_MAX + 1) * PqzCt.Q, 1 << 64, "rollover lanes < 2^64");
        assertLt(PqzCore.ROLL_MAX, 1 << b, "accumulator carry gaps");
        assertLt((PqzCore.INLINE_MAX + 2) * PqzCt.Q, 1 << 64, "debit lanes < 2^64");
        assertLt(PqzCt.DELTA * 15, PqzCt.Q, "Trivial digits");
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

    /// The ids at the build's set (plan 5h Task 8d, CTR-PQZ-09): its PQZL id, its PQZH id only where the set has PQZH;
    /// the retired PQZL v2 / v3 and PQZH v1, the zero word and every other set's ids refused.
    function test_ids() public pure {
        assertEq(PqzSafety.PQZL_ID, PqzSet.PQZL_ID);
        assertTrue(PqzSafety.isPsid(PqzSet.PQZL_ID));
        assertEq(PqzSafety.isPsid(PqzSet.PQZH_ID), PqzSet.HAS_PQZH, "PQZH iff the set has it");
        if (!PqzSet.HAS_PQZH) assertEq(PqzSet.PQZH_ID, bytes32(0), "no PQZH: the zero word");
        assertFalse(PqzSafety.isPsid(0));
        bytes32[11] memory all = [
            bytes32(0x2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f), // retired PQZL v2
            0x8079d65b5e5c15e330f7e65c875776dfc1b0f6c93ced90c045e83865d116baef, // retired PQZL v3
            0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4, // retired PQZH v1
            0x19fad50a2dfdd6351dd0d52203ad440d7e6d5b345641f877bfcd7382079a326d, // n2048-kmax1024 PQZL
            0x9d945089e2a5c39b287888bcd87974934d20181176465b1ab099b5cd1ca7dca4, // n2048-kmax1024 PQZH
            0x15d16d775baed2374e6e41fd153eb6d0cfc75b3b59a7057943be2338e0cb608a, // n2304-kmax4096 PQZL
            0xe4bc6d17ac1395670158d149b01898476ea32ffa482ce3f4c3f495d6b9885730, // n2304-kmax4096 PQZH
            0xa3db21fc14c959e7e48b795b0819c0e856a0689765c80bda291602b6ff70262d, // n2560-kmax16384 PQZL
            0xe83ad1daa5aab5ebf86d484b303e607d76233c680ce87dd0b627021c48109851, // n2560-kmax16384 PQZH
            0x9d23a0de6403d1a37aefcf61821fcfb46dc53021d12a9232467b570ac3bd53a3, // n2816-kmax65536 PQZL
            bytes32(0)
        ];
        uint256 own;
        for (uint256 i; i < all.length; ++i) {
            bool mine = all[i] != 0 && (all[i] == PqzSet.PQZL_ID || (PqzSet.HAS_PQZH && all[i] == PqzSet.PQZH_ID));
            if (mine) ++own;
            assertEq(PqzSafety.isPsid(all[i]), mine);
        }
        assertEq(own, PqzSet.HAS_PQZH ? 2 : 1, "the set's own ids are in the list");
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
