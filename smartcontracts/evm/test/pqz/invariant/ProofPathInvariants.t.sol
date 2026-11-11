// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";

import {console2} from "forge-std/Test.sol";
import {PqzFixture} from "../helpers/PqzFixture.sol";
import {ProofPathHandler} from "./ProofPathHandler.t.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {nid} from "../../helpers/Ids.sol";

/// Group 3h, T64 (spec 2026-11-06-pqz-proof-path §11.2): invariants P1-P7 and P1′ over `ProofPathHandler`'s actions (credits,
/// same-block shields, rollovers, un-rolls, every `NORMAL_PQZ` debit form, 3g rotations and migrations across versions,
/// `setProofStore`, `disableFeature(24)`). P2 rebuilds each debit's `T` from that one record and state by §2.3 (`prevBlob`'s `(u,
/// v_f)` + `Σ pending[p − Δp, p)` + `Trivial(shieldIn)`). P7 (Zether byte-equal) is the Zether suite's unchanged pins, held here
/// by the plus-zero gas rows of 7558a364. Mocked proofs (the handler's note). UNAUDITED.
contract ProofPathInvariantsTest is PqzFixture {
    ProofPathHandler internal h;

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        bytes32[] memory u = new bytes32[](4);
        (u[0], u[1], u[2], u[3]) = (alice, bob, carol, _pqzUA(_pk(44), 44));
        h = new ProofPathHandler(reg, u);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        c.features |= uint256(1) << GovernanceBits.PQZ_PROOF;
        (c.admin, c.roles.issuer, c.lockedFeatures) = (nid(address(h)), nid(address(h)), 0);
        tok = NormalPqzToken(factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "proof-path-inv"));
        h.setToken(tok);
        _public(tok, address(h), 1_000_000 * SCALE);
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](9); // the actions; debit three times (the forms are what P2-P5 read)
        (sel[0], sel[1], sel[2], sel[3]) = (h.shield.selector, h.rollOver.selector, h.rotate.selector, h.setMode.selector);
        (sel[4], sel[5], sel[6], sel[7], sel[8]) = (h.disable24.selector, h.debit.selector, h.debit.selector, h.debit.selector,
            h.bulk.selector);
        targetSelector(FuzzSelector({addr: address(h), selectors: sel}));
    }

    function _uas(uint256 i) internal view returns (bytes32) {
        return h.uas(i);
    }

    /// P1: every `i < pendingCount` of every version holds a non-zero slot; `cleared ≤ floor ≤ rolled ≤ pendingCount` (the
    /// reason M16, `_trivial`'s bound `lo = rolled`, is equivalent on the built code: `max(floor, rolled) = rolled`).
    function _p1(bytes32 u) internal view {
        for (uint64 v; v <= reg.pqzKeyLatest(u); ++v) {
            IPqzToken.AccountState memory a = tok.pqzAccount(u, v);
            assertTrue(a.floor <= a.rolled && a.rolled <= a.pendingCount, "P1: floor <= rolled <= pendingCount");
            for (uint64 i; i < a.pendingCount; ++i) assertTrue(tok.pqzPending(u, v, i) != 0, "P1: no pending slot deleted");
        }
    }

    /// `(uOff, vOff)` of an op blob from `R` (`rOf`): a burn's `R` is `P(u')`, a transfer's `salt ‖ u ‖ …`; `v_f` follows `R`.
    function _uv(address blob) internal view returns (uint256, uint256) {
        uint256 r = PqzCore.rOf(blob).length;
        return r == PqzCt.PKP ? (0, PqzCt.PKP) : (16, r);
    }

    /// P2: `T_k` of `(u, k)` from its record alone (spec §2.3).
    function _t(bytes32 u, uint64 k) internal view returns (bytes memory) {
        IPqzToken.DebitRecordView memory r = tok.pqzDebitRecord(u, k);
        bytes memory c = new bytes(PqzCt.CT);
        if (r.prevBlob != address(0)) {
            (uint256 uo, uint256 vo) = _uv(r.prevBlob);
            PqzCt.loadBlob(r.prevBlob, uo, vo, c);
        }
        bytes[] memory plus = new bytes[](r.deltaP);
        for (uint256 i; i < r.deltaP; ++i) plus[i] = tok.pqzPendingCt(u, r.keyVersion, r.p - r.deltaP + uint64(i));
        return ct.sum(c, plus, new bytes[](0), r.shieldIn);
    }

    function _recWords(bytes32 u, uint64 k) internal view returns (uint256 w0, uint256 w1) {
        uint256 s0 = uint256(keccak256(abi.encode(uint256(k), keccak256(abi.encode(u, uint256(PqzCore._STORAGE) + 19)))));
        (w0, w1) = (uint256(vm.load(address(tok), bytes32(s0))), uint256(vm.load(address(tok), bytes32(s0 + 1))));
    }

    /// P2, P3, P5 for every debit of `u`.
    function _records(bytes32 u) internal view {
        uint64 n = tok.pqzAccount(u, 0).sendCounter;
        assertEq(n, h.debits(u), "P3: sendCounter = the debits that landed");
        (uint256 end,) = _recWords(u, n);
        assertEq(end, 0, "P3: no record at sendCounter");
        for (uint64 k; k < n; ++k) {
            (uint256 w0, uint256 w1) = _recWords(u, k);
            assertTrue(w0 != 0 && w0 & PqzCore.RECORD != 0, "P3: a record for every k < sendCounter");
            assertEq(keccak256(abi.encode(w0, w1)), h.recHash(u, k), "P3: a record never changes after it is written");
            uint64 last = h.lastBefore(u, k);
            if (w0 & PqzCore.WIDE != 0) {
                assertEq(uint64(w1 >> 64), last == 0 ? 0 : last - 1, "P3: prevCounter, the version's previous debit");
                assertEq(uint64(w1 >> 128), h.verOf(u, k), "P3: the record's key version");
            } else {
                assertEq(w1, 0, "P3: no w1 when narrow");
                assertTrue(last == 0 || last == k, "P3: a narrow record follows k - 1 of its version");
                assertEq(h.verOf(u, k), 0, "P3: a narrow record is of version 0");
            }
            assertEq(keccak256(_t(u, k)), h.tHash(u, k), string.concat("P2: T from the one record = the statement's T, ",
                vm.toString(u), " ", vm.toString(uint256(k))));
            assertEq(uint8(w0 >> 8), h.modeAt(u, k), "P5: the record's proofStore = the setting at its debit");
        }
        for (uint64 v; v <= reg.pqzKeyLatest(u); ++v) {
            uint64 ld = tok.pqzAccount(u, v).lastDebit;
            if (ld != 0) assertEq(h.verOf(u, ld - 1), v, "P3: lastDebit names a debit of its version");
        }
    }

    /// forge-config: default.invariant.runs = 24
    /// forge-config: default.invariant.depth = 32
    function invariant_proofPath() public view {
        for (uint256 i; i < h.uaCount(); ++i) {
            _p1(_uas(i));
            _records(_uas(i));
        }
        assertEq(h.changedBelow(), 0, "P1': a pending entry below a past max(floor, rolled) never changes");
        assertEq(h.badTail(), 0, "P4: every own blob ends with its ownTag, kv and n; memoHash = keccak256(memo || ownTag)");
        assertEq(h.badLog(), 0, "P5: LOG <=> exactly one PqzDebitProof with the verified header and the calldata proof");
        assertEq(h.badMode(), 0, "bit 24: setProofStore lands while the bit is set, never after disableFeature(24)");
        assertEq(tok.totalShielded(), h.shielded(), "P6: the pool");
        _assertConservation(tok);
        for (uint256 i; i < h.uaCount(); ++i) {
            bytes32 u = _uas(i);
            (uint64 cur,,,) = reg.pqzKeyOf(u);
            for (uint64 v = cur + 1; v <= reg.pqzKeyLatest(u); ++v) assertEq(tok.pqzAccount(u, v).pendingCount, 0, "P6: 3g J1");
        }
    }

    /// What each run reached (the log of `-vv`): debits that landed, those under `LOG`, rotations' effect on versions.
    function afterInvariant() public view {
        console2.log("proof-path run: debits landed / under LOG / rollovers", h.landed(), h.logged(), h.rolls());
    }

    /// The positive control: each action's path is reached and lands (the handler is not vacuous), under both modes, across a
    /// rotation, a migration, an un-roll and `disableFeature(24)`.
    function test_handler_reachesEveryPath() public {
        h.shield(0, 50, false);
        h.shield(0, 5, true); // merged into alice's tail entry
        h.shield(1, 50, false);
        h.shield(2, 50, false);
        assertEq(tok.pqzAccount(alice, 0).pendingCount, 1, "same block: one entry");
        h.debit(1, 1, 0, 1 << 4, false); // bob -> carol, op 1, shieldIn 1 (a wide record)
        assertEq(tok.pqzDebitRecord(bob, 0).shieldIn, 1, "wide by shieldIn");
        h.debit(2, 0, 1, 0, false); // carol -> alice, op 1 with the auditor
        h.setMode(1); // LOG
        h.debit(0, 0, 2, 3 << 8, false); // alice op 7 with the auditor
        h.debit(1, 0, 3, 1 << 8, false); // bob burns 1
        h.setMode(0); // NONE
        h.shield(0, 5, false);
        h.shield(0, 5, false);
        h.rollOver(0, 1); // alice: one of her two new entries rolled, so the refresh below at floor un-rolls it
        h.debit(0, 0, 4, 0, false); // alice refreshes at p = floor (an un-roll when below rolled)
        h.rotate(1); // bob: version 1 current
        h.debit(1, 0, 5, 0, true); // bob migrates from version 0
        h.disable24(0);
        h.setMode(1); // refused: frozen at NONE
        assertEq(h.landed(), 6, "every debit landed");
        assertEq(h.rolls(), 1, "the rollover landed");
        h.bulk(3, 17); // dave: 17 entries rolled, cleared moved to rolled - INLINE_MAX
        assertTrue(h.rolls() >= 2 && tok.pqzAccount(h.uas(3), 0).cleared > 0, "cleared moved");
        assertEq(h.logged(), 2, "two under LOG");
        assertEq(tok.proofStore(), PqzCore.NONE, "frozen");
        assertEq(abi.encode(h.badTail(), h.badLog(), h.badMode(), h.changedBelow()), abi.encode(0, 0, 0, 0));
        invariant_proofPath();
    }

    /// P7: no Zether gas pin moved in 3h (the plus-zero rows as at 7558a364; layout and selectors are the Zether suite's).
    /// The rows moved since, each with its task's old -> new (plus_zero_gas.json): T83 (ba280ade, the pay records) 86,106 /
    /// 86,084 / 69,133 / 69,133 / 46,434 / 46,456 / 142,438 / 142,450 -> 86,128 / 86,106 / 69,133 / 69,155 / 46,434 / 46,478 /
    /// 142,389 / 142,468; T66b (the body modules) -> 83,689 / 83,667 / 69,104 / 69,104 / 46,440 / 46,462 / 139,389 / 139,446;
    /// group 3l (7ba002dc, the faces' selector dispatch) mtxTransfer_wrappedZether 83,667 -> 83,645; merge3k (the merged faces'
    /// dispatch, 1bb15eac) uaExecuteTransfer_normalZether 139,389 -> 139,434, uaExecuteTransfer_wrappedZether 139,446 ->
    /// 139,424; round 3r T2 (the admin names in each face's dispatch) mtxTransfer_normalZether 83,689 -> 83,711,
    /// mtxTransfer_wrappedZether 83,645 -> 83,667. The test keeps P7's claim as: these rows are the pins.
    function test_P7_zetherPinsUnchanged() public view {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/plus_zero_gas.json"));
        string[8] memory k = ["mtxTransfer_normalZether", "mtxTransfer_wrappedZether", "transferToUA_normalZether",
            "transferToUA_wrappedZether", "transfer_normalZether", "transfer_wrappedZether", "uaExecuteTransfer_normalZether",
            "uaExecuteTransfer_wrappedZether"];
        uint256[8] memory at7558 = [uint256(83711), 83667, 69104, 69104, 46440, 46462, 139434, 139424]; // merge3k, round 3r T2
        for (uint256 i; i < 8; ++i) assertEq(vm.parseJsonUint(j, string.concat(".", k[i])), at7558[i], k[i]);
    }
}
