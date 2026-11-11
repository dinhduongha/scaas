// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {noVerdict} from "../../pqz/helpers/PqzVerdicts.sol";
import {PqzRegFixture} from "./PqzRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {IGovernance} from "../../../src/governance/IGovernance.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";

/// Plan T31 (regulated-kinds spec §4.2, §4.3; CTR-GOV-17, CTR-GOV-18; I9): `DENYLIST` on the PQZ kinds 12 and 13. An
/// unshield's recipient is asked `R` when the amount is not 0; a refresh's zero recipient never is (no registry call); a
/// denied beneficiary is refused; a denied or frozen leg and a shield's `toUA` still receive (no leg, `toUA` or entry is
/// read). `ALLOWLIST` (8) is outside both kinds' masks.
abstract contract PqzReceiverSuite is PqzRegFixture {
    address internal constant PAYER = address(0xFA1);

    function _denylist() internal pure override returns (bool) { return true; }

    function setUp() public override {
        super.setUp();
        _shieldTo(alice, BAL);
    }

    /// The unshield of 5 to a denied `0xD00D` refused `NotEligible(recipient, 0)`; control: before the attestation it passes.
    function test_deniedUnshieldRecipientRefused() public {
        bytes32 r = MetaTxLib.pad(address(0xD00D));
        bytes memory cd = _opCall(4, 0, 0);
        uint256 snap = vm.snapshotState();
        (bool ok,,) = _try(cd);
        assertTrue(ok, "control");
        vm.revertToState(snap);
        _attestDenied(r);
        (bool ok2, bytes memory ret,) = _try(cd);
        assertFalse(ok2);
        assertEq(ret, _deniedErr(r));
    }

    /// A refresh (amount 0, recipient 0, no beneficiary) makes no registry call; control: the unshield of 5 makes one (its
    /// recipient).
    function test_refreshAsksNoRegistry() public {
        uint256 snap = vm.snapshotState();
        vm.startStateDiffRecording();
        (bool ok,,) = _try(_opCall(4, 0, 0));
        assertTrue(ok);
        assertEq(_registryCalls(), _lists() ? 0 : 1, "control: the unshield asks R of its recipient (the list: no call)");
        vm.revertToState(snap);
        vm.startStateDiffRecording();
        (bool ok2,,) = _try(abi.encodeWithSelector(IPqzToken.mtxUnshield.selector, _burnArgs(0, 0, 92), 0, bytes32(0), PROOF,
            _pqAuth(), bytes(""), noVerdict()));
        assertTrue(ok2);
        assertEq(_registryCalls(), 0, "R is never asked of a refresh's zero recipient");
    }

    /// `_regName` asks `R` of the beneficiary: a denied one refused `NotEligible(beneficiary, 0)` on the five entries.
    function test_deniedBeneficiaryRefused() public {
        for (uint256 k; k < 5; ++k) {
            bytes memory cd = _opCall(k, carol, 0);
            uint256 snap = vm.snapshotState();
            (bool ok,,) = _try(cd);
            assertTrue(ok, "control");
            vm.revertToState(snap);
            _attestDenied(carol);
            (bool ok2, bytes memory ret,) = _try(cd);
            assertFalse(ok2);
            assertEq(ret, _deniedErr(carol));
            vm.revertToState(snap);
        }
    }

    /// I9: a denied leg (`bob`) and a frozen leg (`carol`) still receive a multi transfer's credit; a denied account
    /// receives a shield and a single transfer. No registry call is made for them (the multi transfer asks nothing).
    function test_deniedAndFrozenLegsReceive() public {
        _attestDenied(bob);
        _freeze(carol);
        vm.startStateDiffRecording();
        (bool ok,,) = _try(_opCall(0, 0, 0));
        assertTrue(ok, "denied and frozen legs");
        assertEq(_registryCalls(), 0, "no leg is asked R");
        (bool ok2,,) = _try(_opCall(2, 0, 0));
        assertTrue(ok2, "a single transfer to a denied account");
        uint64 pc = tok.pqzAccount(bob, 0).pendingCount;
        if (_isWrapped()) {
            usd.mint(address(this), 3 * SCALE);
            usd.approve(address(tok), 3 * SCALE);
            w.mtxWrapShield(address(usd), 3 * SCALE, bob);
        } else {
            _pub(address(this), 3 * SCALE);
            tok.mtxShield(bob, 3);
        }
        assertGe(tok.pqzAccount(bob, 0).pendingCount, pc, "a shield to a denied account");
        assertEq(tok.totalShielded(), BAL + 3, "credited");
    }

    /// Round 3s (spec §4.3, M5): the proof's sender (`_regSender(fromUA)`) is checked by the deny list before the proof; the
    /// registry's check is receiver-only (CTR-AS-07). The `shieldIn` payer too (`_regPayer`). Controls: not denied, it passes.
    function test_deniedSenderAndShieldInPayer() public {
        bytes32 p = MetaTxLib.pad(PAYER);
        for (uint256 k; k < 5; ++k) {
            bytes memory cd = _opCall(k, 0, 0);
            uint256 snap = vm.snapshotState();
            (bool ok,,) = _try(cd);
            assertTrue(ok, "control: the sender not denied");
            vm.revertToState(snap);
            _attestDenied(alice);
            (bool ok2, bytes memory ret,) = _try(cd);
            if (_lists()) assertEq(ret, _deniedErr(alice), "the list checks the sender");
            else assertTrue(ok2, "the registry checks receivers only");
            vm.revertToState(snap);
            cd = _opCall(k, 0, 1);
            _attestDenied(p);
            vm.prank(PAYER);
            (, ret) = address(tok).call(cd);
            if (_lists()) assertEq(ret, _deniedErr(p), "the list checks the shieldIn payer, before the pull");
            vm.revertToState(snap);
        }
    }

    /// CTR-GOV-17: `ALLOWLIST` (8) is refused at creation on the confidential kinds (`FeatureInvalidForKind(8)`); the
    /// control creates.
    function test_allowlistOutsideMask() public {
        IFactoryToken.TokenConfig memory c = _regCfg();
        assertTrue(factory.createToken(_kind(), 1, abi.encode(c), "ok") != address(0), "control");
        c.features |= 1 << 8;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(8)));
        factory.createToken(_kind(), 1, abi.encode(c), "al");
    }
}

contract PqzReceiver12Test is PqzReceiverSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract PqzReceiver13Test is PqzReceiverSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }
}

/// Round 3s (spec 2026-11-10-token-lists.md §4.3, §13 (2)): the same suite with `DENYLIST` as the token's own list.
contract PqzLists12Test is PqzReceiver12Test {
    function _lists() internal pure override returns (bool) { return true; }
}

contract PqzLists13Test is PqzReceiver13Test {
    function _lists() internal pure override returns (bool) { return true; }
}
