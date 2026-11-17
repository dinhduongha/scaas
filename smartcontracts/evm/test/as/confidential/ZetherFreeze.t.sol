// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherRegFixture} from "./ZetherRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IMetaTx} from "../../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";

/// Plan T30 (regulated-kinds spec §4, §4.1, §4.3; I10; U4): `FREEZE` on the Zether kinds 10 and 11. The sender of a transfer
/// or an unshield is `uaOf(yFrom)`, checked at the direct entry before the proof (a refusal costs < 200 k, plus the signer
/// class's authorization on a signed entry); the envelope's subject is never taken for it; a frozen beneficiary is refused;
/// a frozen account still receives and rolls over. Each refusal has its positive control (the same call, unfrozen).
abstract contract ZetherFreezeSuite is ZetherRegFixture {
    uint256 internal constant BAL = 500;
    uint256 internal constant PREFIX = 200_000;

    function setUp() public override {
        super.setUp();
        _funded(BAL);
        _public(tok, payer, 1000); // the outer fee of the fee-bearing envelopes
    }

    /// The four direct entries (BUNDLE or the token's default, COMPACT, single, unshield): a frozen `uaOf(yFrom)` is refused
    /// `Frozen` before the proof, in < 200 k.
    function test_frozenSenderRefusedBeforeProof_direct() public {
        for (uint256 k; k < 4; ++k) {
            bytes memory cd = _opCall(k, BAL, 0);
            uint256 snap = vm.snapshotState();
            (bool ok,,) = _try(cd);
            assertTrue(ok, "control: the unfrozen sender's op passes");
            vm.revertToState(snap);
            _freeze(aId);
            (bool ok2, bytes memory ret, uint256 used) = _try(cd);
            assertFalse(ok2);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, aId), "Frozen(uaOf(yFrom))");
            assertLt(used, PREFIX, "refused before the proof (I10)");
            emit log_named_uint(string.concat("I10 direct refusal, entry ", vm.toString(k)), used);
            vm.revertToState(snap);
        }
    }

    /// The three signed transfer entries (fee-bearing, by `payer`'s EOA): `payer` passes the pre row, the proof's sender is
    /// refused in the self-call before the proof, within the ECDSA class's authorization + 200 k (I10). The class's
    /// authorization is measured: the same call with a signature over another digest fails at step 2.
    function test_frozenSenderRefusedBeforeProof_signed() public {
        MetaTxLib.UAEnvelope memory e = _envOf(MetaTxLib.pad(payer), true);
        for (uint256 k; k < 3; ++k) {
            bytes memory cd = _signedCall(k, e, BAL, false);
            uint256 snap = vm.snapshotState();
            (bool ok,,) = _try(cd);
            assertTrue(ok, "control: the unfrozen sender's signed op passes");
            vm.revertToState(snap);
            _freeze(aId);
            (bool bad, bytes memory badRet, uint256 auth) = _try(_signedCall(k, e, BAL, true));
            assertFalse(bad);
            assertEq(bytes4(badRet), IMetaTx.MetaTxBadSignature.selector, "the authorization step");
            (bool ok2, bytes memory ret, uint256 used) = _try(cd);
            assertFalse(ok2);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, aId), "Frozen(uaOf(yFrom))");
            assertLt(used, auth + PREFIX, "refused before the proof (I10)");
            emit log_named_uint(string.concat("I10 signed refusal (ECDSA), entry ", vm.toString(k), ", authorization"), auth);
            emit log_named_uint(string.concat("I10 signed refusal (ECDSA), entry ", vm.toString(k), ", refused at"), used);
            vm.revertToState(snap);
        }
    }

    /// U4, spec §4.3: the envelope's subject is never the proof's sender. A frozen `payer` at fee `NONE` submits `alice`'s
    /// proof (nothing read in the pre row); fee-bearing it is refused `Frozen(payer)` before the signature (a bad signature
    /// still reads `Frozen`), per signer class (the payer's EOA; `alice`'s own Zether key on her derived id).
    function test_envelopeSubjectNeverTheSender() public {
        bytes32 p = MetaTxLib.pad(payer);
        _freeze(p);
        for (uint256 k; k < 3; ++k) {
            uint256 snap = vm.snapshotState();
            (bool ok,,) = _try(_signedCall(k, _envOf(p, false), BAL, false));
            assertTrue(ok, "a frozen envelope subject at fee NONE submits another's proof");
            vm.revertToState(snap);
            (bool ok2, bytes memory ret,) = _try(_signedCall(k, _envOf(p, true), BAL, true));
            assertFalse(ok2);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, p), "fee-bearing: Frozen before the signature");
        }
        // the derived signer class: alice's own id, fee-bearing and frozen, refused before her Zether-key signature
        _public(tok, address(this), 1000);
        tok.transferToUA(aId, 1000);
        _freeze(aId);
        (bool ok3, bytes memory ret3,) = _try(_signedCall(0, _envOf(aId, true), BAL, true));
        assertFalse(ok3);
        assertEq(ret3, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, aId));
    }

    /// Spec §4.1 `_regName`: a frozen beneficiary is refused `FeeRecipientFrozen` on the multi, single and unshield entries.
    function test_frozenBeneficiaryRefused() public {
        User[] memory to = new User[](1);
        to[0] = bob;
        uint256[] memory vs = new uint256[](1);
        vs[0] = 10;
        bytes[3] memory cds;
        cds[0] = _multiTo(to, vs, BAL, carol.ua);
        Tx memory x = _proveTransfer(tok, alice, bob, 10, BAL, carol.ua, 0);
        cds[1] = abi.encodeWithSelector(_sel(2), _zSingle(x.payload, carol.ua), x.proof);
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 10, BAL, address(0xB0C), carol.ua, 0);
        cds[2] = abi.encodeWithSelector(IZetherToken.mtxUnshield.selector, _zBurn(pl, carol.ua), 10,
            MetaTxLib.pad(address(0xB0C)), pr);
        for (uint256 i; i < 3; ++i) {
            uint256 snap = vm.snapshotState();
            (bool ok,,) = _try(cds[i]);
            assertTrue(ok, "control: an unfrozen beneficiary");
            vm.revertToState(snap);
            _freeze(cId);
            (bool ok2, bytes memory ret,) = _try(cds[i]);
            assertFalse(ok2);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.FeeRecipientFrozen.selector, cId));
            vm.revertToState(snap);
        }
    }

    /// Spec §4.3: a frozen account still receives a shielded credit (a shield to it, a transfer to it) and rolls it over.
    function test_frozenReceivesAndRollsOver() public {
        _freeze(ZetherTypes.UA.unwrap(bob.ua));
        _fund(tok, bob, 7);
        User[] memory to = new User[](1);
        to[0] = bob;
        uint256[] memory vs = new uint256[](1);
        vs[0] = 10;
        (bool ok,,) = _try(_multiTo(to, vs, BAL, _none()));
        assertTrue(ok, "a transfer to a frozen account");
        tok.mtxRollOver(ZetherTypes.UA.unwrap(bob.ua), 1);
        assertTrue(_holds(tok, bob, 17, true), "rolled over");
    }
}

contract ZetherFreeze10Test is ZetherFreezeSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract ZetherFreeze11Test is ZetherFreezeSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }

    /// Spec §4.1: the unshield-unwrap's sender at the top, before the reserve quote and the proof.
    function test_unshieldUnwrapFrozenRefused() public {
        bytes memory cd = _unwrapCall(10, BAL);
        uint256 snap = vm.snapshotState();
        (bool ok,,) = _try(cd);
        assertTrue(ok, "control");
        vm.revertToState(snap);
        _freeze(aId);
        (bool ok2, bytes memory ret, uint256 used) = _try(cd);
        assertFalse(ok2);
        assertEq(ret, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, aId));
        assertLt(used, PREFIX, "refused before the proof (I10)");
    }
}
