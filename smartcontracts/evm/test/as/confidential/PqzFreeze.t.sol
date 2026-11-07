// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegFixture} from "./PqzRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";

/// Plan T31 (regulated-kinds spec §4, §4.2, §4.3; I9, I10; U4): `FREEZE` on the PQZ kinds 12 and 13. The sender of a transfer
/// or an unshield is `fromUA`, checked first in `_single` / `_multi` / `_burn`, before `_pullShieldIn` and the proof: a refused
/// op reaches no proof (the proof made to fail still reads `Frozen`) and reads no slot of the sender's PQZ account (no entry,
/// no `acc`); the `shieldIn` payer is a second account checked there too; the envelope's subject is never taken for the
/// sender; a frozen beneficiary is refused; a frozen account still receives and rolls over. Each refusal has its positive
/// controls (the same call unfrozen passes; unfrozen with the proof made to fail, it fails at the proof).
abstract contract PqzFreezeSuite is PqzRegFixture {
    address internal constant PAYER = address(0xFA1);

    function setUp() public override {
        super.setUp();
        _shieldTo(alice, BAL);
        _pub(PAYER, 10 * SCALE);
    }

    /// `cd` (from `gasProbe`): passes; with the proof rejected it fails at the proof, not `F`; after `frozen` is frozen it is
    /// refused `err` with the proof rejected, before the proof and without reading the sender's PQZ account, in `< 200 k`.
    function _refusedBeforeProof(bytes memory cd, bytes32 frozen, bytes memory err, bool direct) internal {
        uint256 snap = vm.snapshotState();
        vm.startStateDiffRecording();
        (bool ok,,) = _try(cd);
        assertTrue(ok, "control: the unfrozen op passes");
        assertGt(_pqzAccesses(alice, false), 0, "control: the op reads the sender's account");
        vm.revertToState(snap);
        _proofs(0);
        (bool ok1, bytes memory r1,) = _try(cd);
        assertFalse(ok1, "control: a rejected proof fails");
        assertTrue(keccak256(r1) != keccak256(err), "control: at the proof, not the freeze");
        _freeze(frozen);
        vm.startStateDiffRecording();
        (bool ok2, bytes memory ret, uint256 used) = _try(cd);
        uint256 reads = _pqzAccesses(alice, false);
        assertFalse(ok2);
        assertEq(ret, err, "refused before the proof");
        assertEq(reads, 0, "no slot of the sender's PQZ account read (no note, no acc)");
        if (direct) assertLt(used, PREFIX, "refused before the proof (I10)");
        emit log_named_uint("I10 refusal", used);
        _proofs(1);
        vm.revertToState(snap);
    }

    /// The four transfer entries and the unshield, direct: a frozen `fromUA` refused `Frozen(fromUA)`.
    function test_frozenSenderRefusedBeforeProof_direct() public {
        for (uint256 k; k < 5; ++k) {
            _refusedBeforeProof(_opCall(k, 0, 0), alice, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, alice), true);
        }
    }

    /// The signed forms (fee `NONE`, by `signer`'s EOA): the self-call refuses the proof's sender before the proof.
    function test_frozenSenderRefusedBeforeProof_signed() public {
        for (uint256 k; k < 5; ++k) {
            _refusedBeforeProof(_signedCall(k, _envOf(false), false), alice,
                abi.encodeWithSelector(IRegulatedToken.Frozen.selector, alice), false);
        }
    }

    /// The `shieldIn` payer (spec §4.2: a frozen public balance never funds another account's op): the caller paying
    /// `shieldIn` is refused `Frozen(payer)` on the five entries; control: unfrozen it passes.
    function test_frozenShieldInPayerRefused() public {
        bytes32 p = MetaTxLib.pad(PAYER);
        for (uint256 k; k < 5; ++k) {
            bytes memory cd = _opCall(k, 0, 1);
            uint256 snap = vm.snapshotState();
            vm.prank(PAYER);
            (bool ok,) = address(tok).call(cd);
            assertTrue(ok, "control: an unfrozen payer");
            vm.revertToState(snap);
            _freeze(p);
            vm.prank(PAYER);
            (bool ok2, bytes memory ret) = address(tok).call(cd);
            assertFalse(ok2);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, p));
            vm.revertToState(snap);
        }
    }

    /// The checks come before `_pullShieldIn`: a frozen sender whose `shieldIn` payer holds nothing is refused `Frozen`, not
    /// by the payer's balance; control: unfrozen, the same call fails at the pull.
    function test_checkBeforePullShieldIn() public {
        address broke = address(0xB0B0);
        for (uint256 k; k < 5; ++k) {
            bytes memory cd = _opCall(k, 0, 1);
            uint256 snap = vm.snapshotState();
            vm.prank(broke);
            (bool ok, bytes memory r0) = address(tok).call(cd);
            assertFalse(ok, "control: the pull fails");
            assertTrue(bytes4(r0) != IRegulatedToken.Frozen.selector);
            _freeze(alice);
            vm.prank(broke);
            (, bytes memory ret) = address(tok).call(cd);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, alice), "the check first");
            vm.revertToState(snap);
        }
    }

    /// U4, spec §4.3: the envelope's subject is never the proof's sender. A frozen `signer` at fee `NONE` submits `alice`'s
    /// proof (nothing read in the pre row); fee-bearing it is refused `Frozen(signer)` before the signature (a bad signature
    /// still reads `Frozen`).
    function test_envelopeSubjectNeverTheSender() public {
        bytes32 s = MetaTxLib.pad(signer);
        _freeze(s);
        for (uint256 k; k < 5; ++k) {
            uint256 snap = vm.snapshotState();
            vm.prank(relayer);
            (bool ok,) = address(tok).call(_signedCall(k, _envOf(false), false));
            assertTrue(ok, "a frozen envelope subject at fee NONE submits another's proof");
            vm.revertToState(snap);
            vm.prank(relayer);
            (bool ok2, bytes memory ret) = address(tok).call(_signedCall(k, _envOf(true), true));
            assertFalse(ok2);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, s), "fee-bearing: Frozen before the signature");
        }
    }

    /// Spec §4.2 `_regName`: a frozen beneficiary is refused `FeeRecipientFrozen` on the five entries.
    function test_frozenBeneficiaryRefused() public {
        for (uint256 k; k < 5; ++k) {
            bytes memory cd = _opCall(k, carol, 0);
            uint256 snap = vm.snapshotState();
            (bool ok,,) = _try(cd);
            assertTrue(ok, "control: an unfrozen beneficiary");
            vm.revertToState(snap);
            _freeze(carol);
            (bool ok2, bytes memory ret,) = _try(cd);
            assertFalse(ok2);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, carol));
            vm.revertToState(snap);
        }
    }

    /// Spec §4.3, I9: a frozen account still receives a shielded credit (a shield, a single transfer, a multi transfer leg)
    /// and prepares and rolls it over.
    function test_frozenReceivesAndRollsOver() public {
        _freeze(bob);
        _shieldTo(bob, 7);
        (bool ok,,) = _try(_opCall(2, 0, 0));
        assertTrue(ok, "a single transfer to a frozen account");
        (bool ok2,,) = _try(_opCall(0, 0, 0));
        assertTrue(ok2, "a frozen leg of a multi transfer");
        _prepare(tok, bob);
        vm.roll(block.number + ROLL_AGE);
        tok.mtxRollOver(bob, 0, 1);
        assertEq(tok.pqzAccount(bob, 0).rolled, 1, "rolled over");
    }
}

contract PqzFreeze12Test is PqzFreezeSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract PqzFreeze13Test is PqzFreezeSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }

    /// Spec §4.2: the unshield-unwrap's sender first in `_burn`, before the proof; direct and signed.
    function test_unshieldUnwrapFrozenRefused() public {
        _refusedBeforeProof(_unwrapCall(10, 0), alice, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, alice), true);
        _refusedBeforeProof(_signedUnwrap(_envOf(false), 10), alice,
            abi.encodeWithSelector(IRegulatedToken.Frozen.selector, alice), false);
    }
}
