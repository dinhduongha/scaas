// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzFixture} from "../helpers/PqzFixture.sol";
import {PqzVerHandler} from "./PqzVerHandler.t.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";

/// Group 3g, T56 (spec 2026-11-06-pqz-key-versions §13): invariants J1-J6, J9, J10 over `PqzVerHandler`'s actions. J7 and J8
/// (version 0 and a UA that never rotates byte-equal to today's) are the vectors' (portable.json v0 rows, the
/// `smartcontracts/vectors/pqz/<set>/statement_*.json` rows, unchanged by T51-T54); J3's write-once and J9 are also
/// `test/ua/PqzKeyVersions.t.sol`'s, J5's account selection M-T5's control. Mocked proofs (the handler's note). UNAUDITED.
contract PqzVerInvariantsTest is PqzFixture {
    PqzVerHandler internal h;
    uint256 internal listed;

    function setUp() public {
        _stack();
        _mockOp(7, 1);
        tok = _newToken("pqzver-inv");
        bytes32[] memory u = new bytes32[](4);
        (u[0], u[1], u[2], u[3]) = (alice, bob, carol, _pqzUA(_pk(44), 44));
        h = new PqzVerHandler(tok, reg, u);
        _public(tok, address(h), 1_000_000 * SCALE);
        listed = reg.uaCount(UAKinds.PQZ_MLWE);
        targetContract(address(h));
    }

    function _each(function(bytes32, uint64, uint64) internal view f) internal view {
        for (uint256 i; i < h.uaCount(); ++i) {
            bytes32 u = h.uas(i);
            (uint64 cur,,,) = reg.pqzKeyOf(u);
            uint64 latest = reg.pqzKeyLatest(u);
            for (uint64 v; v <= latest; ++v) f(u, v, cur);
        }
    }

    /// J1 / J5: a version above current holds no credit (none landed under a key not yet current).
    function _credits(bytes32 u, uint64 v, uint64 cur) internal view {
        if (v > cur) assertEq(tok.pqzAccount(u, v).pendingCount, 0, "J1/J5: no credit above current");
    }

    /// J3: every version 0 ... latest stored; current is the highest proven and never went down.
    function _stored(bytes32 u, uint64 v, uint64 cur) internal view {
        (address p,,) = reg.pqzKeyAt(u, v);
        assertTrue(p != address(0), "J3: versions 0 ... latest all stored");
        if (v == 0) assertEq(cur, h.provenMax(u), "J3: current is the highest proven version");
    }

    /// J4: no two versions of one UA (nor two UAs) store one key; a proven version's key is owned by its UA.
    function _distinct(bytes32 u, uint64 v, uint64) internal view {
        (address p,, bool proven) = reg.pqzKeyAt(u, v);
        bytes32 hv = p.codehash;
        for (uint256 i; i < h.uaCount(); ++i) {
            bytes32 w = h.uas(i);
            for (uint64 x; x <= reg.pqzKeyLatest(w); ++x) {
                if (w == u && x == v) continue;
                (address q,,) = reg.pqzKeyAt(w, x);
                assertTrue(q.codehash != hv, "J4: one key per (ua, version), across UAs too");
            }
        }
        if (proven) assertEq(reg.keyOwner(UAKinds.keyHashOf(UAKinds.PQZ_MLWE, _code(p))), u, "J4: keyOwner of a proven version");
    }

    function _code(address p) internal view returns (bytes memory c) {
        c = p.code;
        assembly ("memory-safe") {
            mstore(add(c, 1), sub(mload(c), 1)) // past the SSTORE2 STOP byte
            c := add(c, 1)
        }
    }

    /// The positive control (the handler is not vacuous): each action's path is reached and lands, or is refused, as the rules say.
    function test_handler_reachesEveryPath() public {
        h.shield(0, 50); // alice, version 0
        h.shield(1, 50);
        assertEq(h.credited(), 2);
        h.transfer(0, 1, 1); // alice -> bob at current: lands
        assertEq(abi.encode(h.debits(alice), h.credited()), abi.encode(uint256(1), uint256(3)));
        h.rotate(0); // alice: version 1 current
        (uint64 cur,,,) = reg.pqzKeyOf(alice);
        assertEq(cur, 1);
        h.transfer(0, 1, 3); // stale (0) to bob: refused, nothing lands
        assertEq(h.debits(alice), 1);
        h.transfer(0, 0, 3); // stale (0) to alice herself: the migration lands in (alice, 1)
        assertEq(abi.encode(h.debits(alice), tok.pqzAccount(alice, 1).pendingCount), abi.encode(uint256(2), uint256(1)));
        h.multi(1, 1); // bob -> carol, the fourth UA, at current
        assertEq(h.debits(bob), 1);
        h.multi(0, 3); // alice from stale 0: refused
        assertEq(h.debits(alice), 2);
        h.burn(1, 1, 0); // bob refresh at current
        h.burn(0, 3, 0); // alice refresh at stale 0: lands
        h.burn(0, 3, 5); // alice unshield 5 at stale 0: refused
        assertEq(h.debits(alice), 3);
        h.burn(0, 1, 5); // alice unshield at current
        assertEq(abi.encode(h.debits(alice), h.shielded()), abi.encode(uint256(4), uint256(95)));
        h.addPending(1); // bob: version 1 stored, not current
        (cur,,,) = reg.pqzKeyOf(bob);
        assertEq(abi.encode(cur, reg.pqzKeyLatest(bob)), abi.encode(uint256(0), uint256(1)));
        h.shield(1, 1); // a credit while pending lands in (bob, 0)
        assertEq(tok.pqzAccount(bob, 1).pendingCount, 0);
        h.proveLate(1, 1);
        (cur,,,) = reg.pqzKeyOf(bob);
        assertEq(cur, 1);
        assertEq(abi.encode(h.bad(), h.misplaced(), h.downs()), abi.encode(uint256(0), uint256(0), uint256(0)));
        invariant_pqzVersions();
    }

    /// forge-config: default.invariant.runs = 32
    /// forge-config: default.invariant.depth = 40
    function invariant_pqzVersions() public view {
        _each(_credits);
        _each(_stored);
        _each(_distinct);
        for (uint256 i; i < h.uaCount(); ++i) {
            bytes32 u = h.uas(i);
            assertEq(tok.pqzAccount(u, 0).sendCounter, h.debits(u), "J2: sendCounter + 1 per debit of any version");
        }
        assertEq(h.misplaced(), 0, "J1/J5: every credit in (to, current(to)) as read before the call");
        assertEq(h.downs(), 0, "J3: current never goes down");
        assertEq(tok.totalShielded(), h.shielded(), "J6: the pool over every version");
        _assertConservation(tok);
        assertEq(reg.uaCount(UAKinds.PQZ_MLWE), listed, "J9: the 0x0142 list holds each UA once");
        assertEq(h.bad(), 0, "J10: a stale version only migrates or refreshes");
    }
}
