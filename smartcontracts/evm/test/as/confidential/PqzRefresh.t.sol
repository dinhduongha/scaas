// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegFixture} from "./PqzRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IPqzToken} from "../../../src/pqz/IPqzToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";

/// Plan T31 (regulated-kinds spec §4.2 the refresh row, F-23, M-09; U1, U2): a refresh (`mtxUnshield` with `amount = 0`,
/// `recipient = 0`) moves nothing out, so it names no sender and stays open under `FREEZE` and `PAUSE`, as roll-over; a
/// `shieldIn ≠ 0` still takes `_regPayer()` and is refused under `P` and for a frozen payer.
abstract contract PqzRefreshSuite is PqzRegFixture {
    function setUp() public override {
        super.setUp();
        _shieldTo(alice, BAL);
        _pub(address(this), 10 * SCALE);
    }

    function _refresh(uint256 shieldIn, uint256 seed) internal view returns (bytes memory) {
        return abi.encodeWithSelector(IPqzToken.mtxUnshield.selector, _burnArgs(0, shieldIn, seed), 0, bytes32(0), PROOF,
            _pqAuth(), bytes(""));
    }

    /// The refresh of a frozen `alice` passes under `P` (its debit is written: a new `acc`); the control: the same account's
    /// unshield of 5 is refused there.
    function test_refreshOpenUnderFreezeAndPause() public {
        _freeze(alice);
        uint64 until = _pause();
        (bool ok0, bytes memory r0) = address(tok).call(_opCall(4, 0, 0));
        assertFalse(ok0);
        assertEq(r0, abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until), "control: the unshield is refused");
        bytes memory before = tok.pqzAcc(alice);
        (bool ok,) = address(tok).call(_refresh(0, 90));
        assertTrue(ok, "the refresh is open under F and P");
        assertTrue(keccak256(tok.pqzAcc(alice)) != keccak256(before), "the refresh's debit is written");
    }

    /// `shieldIn ≠ 0` on a refresh: `_regPayer()` (the caller) under `P` refused `TokenPaused`, frozen refused `Frozen`;
    /// control: unpaused and unfrozen it passes.
    function test_refreshShieldInChecksThePayer() public {
        bytes memory cd = _refresh(1, 91);
        uint256 snap = vm.snapshotState();
        (bool ok,) = address(tok).call(cd);
        assertTrue(ok, "control: a refresh with shieldIn");
        vm.revertToState(snap);
        uint64 until = _pause();
        (bool ok2, bytes memory r2) = address(tok).call(cd);
        assertFalse(ok2);
        assertEq(r2, abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until));
        vm.revertToState(snap);
        _freeze(MetaTxLib.pad(address(this)));
        (bool ok3, bytes memory r3) = address(tok).call(cd);
        assertFalse(ok3);
        assertEq(r3, abi.encodeWithSelector(IRegulatedToken.Frozen.selector, MetaTxLib.pad(address(this))));
        vm.revertToState(snap);
    }
}

contract PqzRefresh12Test is PqzRefreshSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract PqzRefresh13Test is PqzRefreshSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }
}
