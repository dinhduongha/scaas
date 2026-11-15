// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzOffchainBase} from "../helpers/PqzOffchainBase.sol";
import {PqzMarkHandler} from "./PqzMarkHandler.t.sol";
import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";

/// Three-key spec §14 items 5 and 20 (K3-8, CTR-PQZ-41), step 9: invariants M1-M5 over `PqzMarkHandler`'s credits, signed
/// rollovers with marks, refreshes (un-rolls included) and passing blocks, on an `offchain-shared` token with the opening.
/// M1 a mark is never cleared, and no slot is marked that the holder did not name; M2 no slot or ciphertext is deleted or
/// changed (the slot's mark bit apart); M3 `acc` equals the wallet's model (the base plus every unmarked entry rolled since:
/// a marked slot adds zero, before and after an un-roll); M4 `rollSeq` counts the accepted signed rollovers; M5 no call the
/// rules refuse landed. UNAUDITED.
contract PqzMarkInvariantsTest is PqzOffchainBase {
    PqzMarkHandler internal h;
    NormalPqzToken internal c2;

    function setUp() public {
        _offStack();
        (vMode, vUA, vOwnKey, vOpening) = (PqzCore.OFFCHAIN, vA, false, true);
        c2 = _newToken("mark-inv");
        (vMode, vUA, vOwnKey, vOpening) = (0, bytes32(0), false, false);
        _shieldOn(c2, bob, 1_000_000);
        _shieldOn(c2, carol, 1_000_000);
        c2.mtxPrepareAcc(alice, 0, 0);
        c2.mtxPrepareAcc(alice, 0, 1);
        h = new PqzMarkHandler(c2, reg, ct, alice, bob, carol);
        targetContract(address(h));
    }

    function _check() internal view {
        uint256 n = h.entries();
        assertEq(c2.pqzAccount(alice, 0).pendingCount, n, "M2: pendingCount is the credits that landed");
        uint256 m;
        for (uint256 i; i < n; ++i) {
            uint256 e = c2.pqzPending(alice, 0, uint64(i));
            assertEq(e & ~uint256(PqzCore.SKIP), h.slot0(i), "M2: the slot unchanged apart from its mark");
            assertEq(c2.pqzPendingCt(alice, 0, uint64(i)), h.ctAt(i), "M2: the ciphertext stays");
            bool s = c2.pqzSkipped(alice, 0, uint64(i));
            assertEq(s, h.marked(i), "M1: marked exactly when the holder named it, never cleared");
            assertEq(s, e & PqzCore.SKIP != 0, "M1: the view reads the slot's mark");
            if (s) ++m;
        }
        assertEq(m, h.marks(), "M1: one mark per named index");
        assertEq(c2.pqzAcc(alice, 0), h.modelAcc(), "M3: acc is the wallet's (a marked slot adds zero)");
        assertEq(c2.pqzAccount(alice, 0).rollSeq, h.rolls(), "M4: rollSeq + 1 per accepted signed rollover");
        assertEq(h.bad(), 0, "M5: nothing the rules refuse landed");
    }

    /// forge-config: default.invariant.runs = 32
    /// forge-config: default.invariant.depth = 40
    function invariant_marks() public view {
        _check();
    }

    /// Positive control (the handler is not vacuous): credits, a mark-only call, a roll over a marked slot, a refresh below
    /// `rolled` (un-roll), a mark on an un-rolled entry, a re-roll; the invariants hold at every step.
    function test_handler_reachesEveryPath() public {
        for (uint256 i; i < 6; ++i) h.credit(i);
        assertEq(h.entries(), 6);
        h.age(2 * ROLL_AGE);
        h.roll(0, 1 << 1); // mark entry 1 only
        assertEq(abi.encode(h.marks(), h.rolls(), c2.pqzAccount(alice, 0).rolled), abi.encode(uint256(1), uint256(1), uint256(0)));
        _check();
        h.roll(4, 0); // roll 0..3 over the marked slot 1
        assertEq(c2.pqzAccount(alice, 0).rolled, 4);
        _check();
        h.refresh(2); // un-roll [2, 4)
        assertEq(abi.encode(h.refreshes(), h.unrolls(), c2.pqzAccount(alice, 0).rolled), abi.encode(uint256(1), uint256(1), uint256(2)));
        _check();
        h.age(2 * ROLL_AGE);
        h.roll(0, 1 << 1); // entry 3 (rolled 2: bit 1) marked after the un-roll
        assertTrue(c2.pqzSkipped(alice, 0, 3));
        h.roll(4, 0); // re-roll [2, 6): entry 3 adds zero
        assertEq(abi.encode(c2.pqzAccount(alice, 0).rolled, h.marks(), h.rolls()), abi.encode(uint256(6), uint256(2), uint256(4)));
        _check();
        assertTrue(keccak256(c2.pqzAcc(alice, 0)) != keccak256(new bytes(PqzCt.CT)), "acc moved");
    }
}
