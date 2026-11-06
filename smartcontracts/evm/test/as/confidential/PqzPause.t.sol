// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzRegFixture} from "./PqzRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../../src/confidential/IConfidentialToken.sol";

/// Plan T31 (regulated-kinds spec §4.2, §4.3 `PAUSE`; RK-7; U1, U2): on kinds 12 and 13 `PAUSE` stops shield, wrap-shield, the
/// four transfers, unshield and unshield-unwrap, direct and signed, each refused `TokenPaused` before the proof; prepare and
/// roll-over stay open (the refresh: PqzRefresh.t.sol). Each refusal has its positive control (unpaused).
abstract contract PqzPauseSuite is PqzRegFixture {
    function setUp() public override {
        super.setUp();
        _shieldTo(alice, BAL);
        _pub(address(this), 100 * SCALE); // what a shield pays
        _pub(signer, 1000); // the fee-bearing envelopes' fee
    }

    /// Each call of `cds` from `caller`: passes unpaused, refused `TokenPaused(until)` under `P`.
    function _pausedEach(bytes[] memory cds, address caller) internal {
        for (uint256 i; i < cds.length; ++i) {
            uint256 snap = vm.snapshotState();
            vm.prank(caller);
            (bool ok,) = address(tok).call(cds[i]);
            assertTrue(ok, "control: unpaused");
            vm.revertToState(snap);
            uint64 until = _pause();
            vm.prank(caller);
            (bool ok2, bytes memory ret) = address(tok).call(cds[i]);
            assertFalse(ok2);
            assertEq(ret, abi.encodeWithSelector(IRegulatedToken.TokenPaused.selector, until), "TokenPaused");
            vm.revertToState(snap);
        }
    }

    function test_pauseStopsShieldTransfersUnshield() public {
        bytes[] memory cds = new bytes[](6);
        cds[0] = abi.encodeWithSelector(IConfidentialToken.mtxShield.selector, bob, 3);
        for (uint256 k; k < 5; ++k) cds[k + 1] = _opCall(k, 0, 0);
        _pausedEach(cds, address(this));
    }

    /// The signed forms at fee `NONE` (nothing read in the pre row): the inner entry's `P`; fee-bearing: the pre row's.
    function test_pauseStopsSignedTransfers() public {
        bytes[] memory cds = new bytes[](10);
        for (uint256 k; k < 5; ++k) {
            cds[k] = _signedCall(k, _envOf(false), false);
            cds[k + 5] = _signedCall(k, _envOf(true), false);
        }
        _pausedEach(cds, relayer);
    }

    /// U1, U2: prepare and roll-over stay open under `P` and `F` (the account rolls its own credit in).
    function test_prepareAndRollOverOpenUnderPause() public {
        _shieldTo(bob, 4);
        _pause();
        _freeze(alice);
        _freeze(bob);
        _prepare(tok, alice);
        _prepare(tok, bob);
        vm.roll(block.number + ROLL_AGE);
        tok.mtxRollOver(alice, 1);
        tok.mtxRollOver(bob, 1);
        assertEq(tok.pqzAccount(alice).rolled, 1);
        assertEq(tok.pqzAccount(bob).rolled, 1);
    }
}

contract PqzPause12Test is PqzPauseSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract PqzPause13Test is PqzPauseSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }

    /// Kind 13: wrap-shield (`_regPayer()`) and unshield-unwrap (the sender, direct and signed) stop under `P` (no
    /// confidential selector is pause-open, RK-7).
    function test_pauseStopsWrapShieldAndUnshieldUnwrap() public {
        usd.mint(address(this), 10 * SCALE);
        usd.approve(address(tok), 10 * SCALE);
        bytes[] memory cds = new bytes[](2);
        cds[0] = abi.encodeWithSelector(IConfidentialWrappedToken.mtxWrapShield.selector, address(usd), 10 * SCALE, bob);
        cds[1] = _unwrapCall(10, 0);
        _pausedEach(cds, address(this));
        bytes[] memory sc = new bytes[](1);
        sc[0] = _signedUnwrap(_envOf(false), 10);
        _pausedEach(sc, relayer);
    }
}
