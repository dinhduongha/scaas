// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherRegFixture} from "./ZetherRegFixture.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../../src/confidential/IConfidentialToken.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";

/// Plan T30 (regulated-kinds spec §4.1, §4.3 `PAUSE`; RK-7; U1, U2): on kinds 10 and 11 `PAUSE` stops shield, wrap-shield,
/// the three transfers, unshield and unshield-unwrap, direct and signed (no confidential selector is pause-open), each
/// refused `TokenPaused` before the proof; the roll-overs stay open. Each refusal has its positive control (unpaused).
abstract contract ZetherPauseSuite is ZetherRegFixture {
    uint256 internal constant BAL = 500;

    function setUp() public override {
        super.setUp();
        _funded(BAL);
        _public(tok, address(this), 100 * SCALE); // what a shield pays
        _public(tok, payer, 1000);
    }

    /// Each call of `cds`: passes unpaused, refused `TokenPaused(until)` under `P`.
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
        bytes[] memory cds = new bytes[](5);
        cds[0] = abi.encodeWithSelector(IConfidentialToken.mtxShield.selector, ZetherTypes.UA.unwrap(bob.ua), 3);
        for (uint256 k; k < 4; ++k) cds[k + 1] = _opCall(k, BAL, 0);
        _pausedEach(cds, address(this));
    }

    /// The signed transfers at fee `NONE` (nothing read in the pre row): the inner entry's `P`; fee-bearing, the pre row's.
    function test_pauseStopsSignedTransfers() public {
        bytes[] memory cds = new bytes[](6);
        for (uint256 k; k < 3; ++k) {
            cds[k] = _signedCall(k, _envOf(MetaTxLib.pad(payer), false), BAL, false);
            cds[k + 3] = _signedCall(k, _envOf(MetaTxLib.pad(payer), true), BAL, false);
        }
        _pausedEach(cds, relayer);
    }

    /// U1, U2: roll-over, batch roll-over stay open under `P` (and `F`: the account rolls its own credit in).
    function test_rollOverOpenUnderPause() public {
        _fund(tok, alice, 9);
        _fund(tok, bob, 4);
        _pause();
        _freeze(aId);
        tok.mtxRollOver(aId, 1);
        assertTrue(_holds(tok, alice, BAL + 9, true));
        ZetherTypes.UA[] memory one = new ZetherTypes.UA[](1);
        one[0] = bob.ua;
        tok.mtxRollOverBatch(one);
        assertTrue(_holds(tok, bob, 4, true));
    }
}

contract ZetherPause10Test is ZetherPauseSuite {
    function _isWrapped() internal pure override returns (bool) { return false; }
}

contract ZetherPause11Test is ZetherPauseSuite {
    function _isWrapped() internal pure override returns (bool) { return true; }

    /// Kind 11: wrap-shield (`_regPayer()`) and unshield-unwrap (the Zether sender) stop under `P` (no confidential selector
    /// is pause-open, RK-7).
    function test_pauseStopsWrapShieldAndUnshieldUnwrap() public {
        usd.mint(address(this), 10 * SCALE);
        usd.approve(address(tok), 10 * SCALE);
        bytes[] memory cds = new bytes[](2);
        cds[0] = abi.encodeWithSelector(IConfidentialWrappedToken.mtxWrapShield.selector, address(usd), 10 * SCALE,
            ZetherTypes.UA.unwrap(bob.ua));
        cds[1] = _unwrapCall(10, BAL);
        _pausedEach(cds, address(this));
    }
}
