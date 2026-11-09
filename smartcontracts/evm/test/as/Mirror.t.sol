// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalToken} from "../../src/metatx/NormalToken.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {nid} from "../helpers/Ids.sol";

/// Plan T28 (regulated-kinds spec §2.2 mirror sync, §3.3 T9, Codex 3, RK-3, I12): `controls` follows `features` only when a
/// disable applied, through each kind's `disableFeature` (on 9 composed with `WrappedToken`'s). A `disableFeature(FREEZE)` or
/// `(PAUSE)` proposal, its cancellation, an early confirm and an expired confirm leave the frozen account frozen and the
/// pause on; the confirm in the window ends them (T9).
contract MirrorTest is RegFixture {
    bytes32 a;

    function setUp() public override {
        super.setUp();
        a = nid(alice);
    }

    function _mirrorHolds(address t) internal view {
        assertEq(uint256(_r(t).regulatedConfig().controls), (NormalToken(t).features() >> 5) & 0x3F, "I12");
    }

    function _on(address t, uint8 bit) internal view returns (bool) {
        return bit == 5 ? _r(t).isFrozen(a) : _r(t).regulatedConfig().pausedUntil > block.timestamp
            && _r(t).regulatedConfig().controls & 4 != 0;
    }

    /// Spec §2.3, I12: at creation and after each applied disable `controls == (features >> 5) & 0x3F`.
    function test_controlsEqualFeaturesMask() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            _mirrorHolds(t);
            assertEq(_r(t).regulatedConfig().controls, uint8(REG_FEATURES >> 5));
            assertEq(_r(t).regulatedConfig().termsHash, TERMS);
            _disable(t, 10); // one call
            _mirrorHolds(t);
            for (uint8 bit = 5; bit <= 7; ++bit) {
                _disable(t, bit); // proposes
                _mirrorHolds(t);
            }
            vm.warp(block.timestamp + GD);
            for (uint8 bit = 5; bit <= 7; ++bit) {
                _disable(t, bit); // confirms
                _mirrorHolds(t);
            }
            assertEq(_r(t).regulatedConfig().controls, 0);
            vm.warp(1_800_000_000);
        }
    }

    /// Codex 3 for `bit` (5 or 7): the proposal, the cancellation, an early confirm (`GrantNotReady`), and a confirm after
    /// the window (which proposes anew) each leave the control on; the confirm in the window ends it (T9).
    function _codex3(address t, uint8 bit) internal {
        if (bit == 5) _freeze(t, a);
        else _pause(t, _now() + 7 days);
        assertTrue(_on(t, bit), "on");
        _disable(t, bit); // proposal
        assertTrue(_on(t, bit), "after the proposal");
        _mirrorHolds(t);
        vm.prank(ownerA);
        NormalToken(t).cancelGrant(bit, 0);
        assertTrue(_on(t, bit), "after the cancellation");
        _disable(t, bit); // proposal again
        vm.warp(block.timestamp + GD - 1);
        vm.prank(ownerA);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotReady.selector, bit, bytes32(0), uint64(_now() + 1)));
        NormalToken(t).disableFeature(bit);
        assertTrue(_on(t, bit), "after an early confirm");
        vm.warp(block.timestamp + 1 + GD + 1); // past eta + grantDelay: the pending is dead
        _disable(t, bit); // proposes anew
        assertTrue(_on(t, bit), "after an expired confirm");
        _mirrorHolds(t);
        vm.warp(block.timestamp + GD);
        _disable(t, bit); // confirm in the window
        assertFalse(_on(t, bit), "T9: the confirmed disable ends it");
        _mirrorHolds(t);
        vm.prank(alice);
        IERC20(t).transfer(bob, 1);
    }

    function test_codex3Freeze_8() public {
        _codex3(t8, 5);
    }

    function test_codex3Freeze_9() public {
        _codex3(t9, 5);
    }

    function test_codex3Pause_8() public {
        _codex3(t8, 7);
    }

    /// Kind 9's `disableFeature` composes `WrappedToken`'s and the mirror sync.
    function test_codex3Pause_9() public {
        _codex3(t9, 7);
    }
}
