// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";

import {PqzOffchainBase} from "../helpers/PqzOffchainBase.sol";
import {PqzVerdictHandler} from "./PqzVerdictHandler.t.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../../src/pqz/PqzCore.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";

/// Group 3f, T49 (PQZ verifier mode spec §14): invariants I1-I6 over `PqzVerdictHandler`'s actions. I1 the mode byte never
/// moves; I2 an OFFCHAIN debit lands only with the current, live, unchanged-shape verifier's verdict (and a valid one is never
/// refused); I3 no verdict of an older epoch lands (A -> B -> A, revocations); I4 the state a debit writes is the same in both
/// modes; I5 PRECOMPILE never reads the verdict and OFFCHAIN never calls the precompile (the handler makes the other path
/// revert); I6 the pool equals `totalShielded · shieldScale` in both. Mocked proofs (the fixture's). UNAUDITED.
contract PqzVerdictInvariantsTest is PqzOffchainBase {
    PqzVerdictHandler internal h;
    NormalPqzToken internal off;

    function setUp() public {
        _offStack();
        aMode = 0; // no auditor: the handler's ops carry no auditor copies
        tok = _newToken("inv-pre");
        h = new PqzVerdictHandler(tok, reg, alice, bob, carol);
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, vA, false);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        c.owner = bytes32(uint256(uint160(address(h))));
        off = NormalPqzToken(factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "inv-off"));
        h.setOff(off);
        _shieldOn(tok, alice, 1_000_000);
        _shieldOn(off, alice, 1_000_000);
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](6);
        (sel[0], sel[1], sel[2]) = (h.debit.selector, h.withhold.selector, h.replay.selector);
        (sel[3], sel[4], sel[5]) = (h.transfer.selector, h.revoke.selector, h.toggleCode.selector);
        targetSelector(FuzzSelector(address(h), sel));
    }

    function _mode(NormalPqzToken t) internal view returns (uint8) {
        return uint8(uint256(vm.load(address(t), PqzCore._STORAGE)) >> 176);
    }

    function invariant_I1_modeImmutable() public view {
        assertEq(_mode(tok), PqzCore.PRECOMPILE, "I1 pre");
        assertEq(_mode(off), PqzCore.OFFCHAIN, "I1 off");
        assertEq(off.pqzVerifyConfig().pqzVerifyMode, PqzCore.OFFCHAIN);
    }

    function invariant_I2_I3_onlyTheCurrentVerdict() public view {
        assertEq(h.acceptedBad(), 0, "I2/I3: a debit landed with a stale, revoked or changed verifier");
        assertEq(h.refusedValid(), 0, "I2/I5: a valid current verdict refused");
        assertEq(h.wrongRefusal(), 0, "I2: refused, but not as PqzVerifierRevoked / PqzVerifierChanged");
        assertEq(h.epochStuck(), 0, "I3: a verifier transfer or revocation left the epoch as it was");
    }

    function invariant_I4_sameWritesInBothModes() public view {
        bytes32[3] memory us = [alice, bob, carol];
        for (uint256 i; i < 3; ++i) {
            IPqzToken.AccountState memory a = tok.pqzAccount(us[i], 0);
            IPqzToken.AccountState memory b = off.pqzAccount(us[i], 0);
            assertEq(a.accBlob.code, b.accBlob.code, "I4: the op blob `acc` references (its own SSTORE2 pointer per token)");
            (a.accBlob, b.accBlob) = (address(0), address(0));
            assertEq(abi.encode(a), abi.encode(b), "I4: the account");
            assertEq(tok.pqzAcc(us[i], 0), off.pqzAcc(us[i], 0), "I4: acc");
            if (a.pendingCount != 0) assertEq(tok.pqzPendingCt(us[i], 0, a.pendingCount - 1),
                off.pqzPendingCt(us[i], 0, b.pendingCount - 1), "I4: the last entry");
        }
        assertEq(tok.totalShielded(), off.totalShielded(), "I4: totalShielded");
    }

    function invariant_I5_preNeverReadsTheVerdict() public view {
        assertEq(h.preRefused(), 0, "I5: PRECOMPILE refused (it read the garbage verdict)");
    }

    function invariant_I6_pools() public view {
        assertEq(tok.balanceOf(MetaTxLib.SHIELD_POOL), tok.totalShielded() * SCALE, "I6 pre");
        assertEq(off.balanceOf(MetaTxLib.SHIELD_POOL), off.totalShielded() * SCALE, "I6 off");
        assertEq(tok.totalSupply(), off.totalSupply(), "I6: the public supply");
    }

    /// The control (a positive one for the handler itself): a fixed sequence lands debits in both modes, moves the verifier
    /// A -> B -> A, revokes, and a withheld verdict of an older epoch is refused, every ghost still 0.
    function test_handler_acts() public {
        h.debit(0, 1);
        h.withhold(0, 2);
        h.transfer();
        h.transfer();
        h.replay();
        h.debit(1, 3);
        h.toggleCode();
        h.debit(3, 4);
        h.toggleCode();
        h.debit(2, 5);
        h.revoke();
        h.debit(0, 6);
        assertEq(h.debitsBoth(), 3, "three debits in both modes (two refused on `off` alone: coded, revoked)");
        assertEq(h.moves(), 3);
        assertEq(h.acceptedBad() + h.refusedValid() + h.preRefused() + h.wrongRefusal() + h.epochStuck(), 0);
        invariant_I4_sameWritesInBothModes();
        invariant_I6_pools();
    }
}
