// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {RegFixture} from "./helpers/RegFixture.sol";
import {IRegulatedToken} from "../../src/regulated/IRegulatedToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {ERC20MetaTx} from "../../src/metatx/ERC20MetaTx.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// Plan T28 (regulated-kinds spec §3.2, §3.3 T1-T3, T5, T7; RK-4, RK-8): the issuer-only freeze on kinds 8 and 9. Every
/// refusal has its positive control: the same call on an unfrozen account passes.
contract FreezeTest is RegFixture {
    bytes32 a;

    function setUp() public override {
        super.setUp();
        a = nid(alice);
    }

    /// T1: `episodeStart = now`, `until = now + 30 d`, the cooldown `until + 30 d`; `F(alice)` stops her sends, not her
    /// receipts; bob, unfrozen, sends (the control).
    function test_T1_freeze() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.prank(alice);
            IERC20(t).transfer(bob, 10); // the control: before the freeze
            vm.expectEmit(t);
            emit IRegulatedToken.AccountFrozen(a, REF, 0, _now() + 30 days);
            _freeze(t, a);
            IRegulatedToken.FreezeState memory s = _r(t).freezeOf(a);
            assertEq(s.until, _now() + 30 days);
            assertEq(s.episodeStart, _now());
            assertEq(s.issuerCooldownUntil, _now() + 60 days);
            assertFalse(s.recordBacked);
            assertEq(s.recordId, 0);
            assertTrue(_r(t).isFrozen(a));
            vm.prank(alice);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, a));
            IERC20(t).transfer(bob, 1);
            vm.prank(bob);
            IERC20(t).transfer(alice, 5); // credits are never refused for a freeze (CTR-AS-05)
        }
    }

    /// T1's preconditions: `ref != 0`, the cooldown, a role; each refused, the control passes.
    function test_T1_refusals() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.prank(issuer);
            vm.expectRevert(IRegulatedToken.RefRequired.selector);
            _r(t).freeze(a, 0, 0);
            vm.prank(bob);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, uint8(5), nid(bob)));
            _r(t).freeze(a, REF, 0);
            _freeze(t, a);
            _unfreeze(t, a);
            uint64 cool = _now() + 30 days;
            assertEq(_r(t).freezeOf(a).issuerCooldownUntil, cool, "T5: the cooldown from now");
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FreezeCooldown.selector, cool));
            _r(t).freeze(a, REF, 0);
            vm.warp(cool);
            _freeze(t, a); // at the cooldown's end
            assertTrue(_r(t).isFrozen(a));
            vm.warp(1_800_000_000);
        }
    }

    /// Spec §3.3 T1: never 0, `UA_POOL`, `SHIELD_POOL` or the token itself; bob is the control.
    function test_freezeTargetsRefused() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32[4] memory bad = [bytes32(0), nid(MetaTxLib.UA_POOL), nid(MetaTxLib.SHIELD_POOL), nid(t)];
            for (uint256 k; k < 4; ++k) {
                vm.prank(issuer);
                vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FreezeTargetRefused.selector, bad[k]));
                _r(t).freeze(bad[k], REF, 0);
            }
            _freeze(t, nid(bob));
            assertTrue(_r(t).isFrozen(nid(bob)));
        }
    }

    /// T2: an issuer-only freeze extends to `min(now + 30 d, episodeStart + 60 d)`, never past 60 d per episode; one that
    /// would not extend is `FreezeTooLong(episodeStart + 60 d)`.
    function test_T2_extendWithinEpisode() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            uint64 start = _now();
            _freeze(t, a);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FreezeTooLong.selector, start + 60 days));
            _r(t).freeze(a, REF, 0); // the same second: n == until
            vm.warp(start + 20 days);
            _freeze(t, a);
            assertEq(_r(t).freezeOf(a).until, start + 50 days);
            assertEq(_r(t).freezeOf(a).issuerCooldownUntil, start + 80 days);
            vm.warp(start + 40 days);
            _freeze(t, a);
            assertEq(_r(t).freezeOf(a).until, start + 60 days, "capped at the episode");
            assertEq(_r(t).freezeOf(a).episodeStart, start);
            vm.warp(start + 50 days);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.FreezeTooLong.selector, start + 60 days));
            _r(t).freeze(a, REF, 0);
            vm.warp(1_800_000_000);
        }
    }

    /// T3: an issuer-only freeze of a record-frozen account is refused; T4 itself is `Record.t.sol`'s.
    function test_T3_recordFrozenRefusesIssuerFreeze() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            bytes32 r = _order(t, "o1", a, nid(bob), 100, _now() + 90 days);
            _freezeRecord(t, a, r);
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.AlreadyRecordFrozen.selector, a));
            _r(t).freeze(a, REF, 0);
            _freeze(t, nid(bob)); // the control: bob is not frozen yet
        }
    }

    /// T5: `unfreeze` of a freeze that counts: `until = now`, record cleared, cooldown from now, `AccountUnfrozen`; of an
    /// account not frozen `NotFrozen`; `ref` required.
    function test_T5_unfreeze() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            vm.prank(issuer);
            vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.NotFrozen.selector, a));
            _r(t).unfreeze(a, REF);
            _freeze(t, a);
            vm.prank(issuer);
            vm.expectRevert(IRegulatedToken.RefRequired.selector);
            _r(t).unfreeze(a, 0);
            vm.warp(block.timestamp + 5 days);
            vm.expectEmit(t);
            emit IRegulatedToken.AccountUnfrozen(a, REF);
            _unfreeze(t, a);
            IRegulatedToken.FreezeState memory s = _r(t).freezeOf(a);
            assertEq(s.until, _now());
            assertEq(s.issuerCooldownUntil, _now() + 30 days);
            assertFalse(_r(t).isFrozen(a));
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            vm.warp(1_800_000_000);
        }
    }

    /// T7: at `until` the freeze ends by itself; nothing is written.
    function test_T7_expiry() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            _freeze(t, a);
            IRegulatedToken.FreezeState memory s = _r(t).freezeOf(a);
            vm.warp(s.until - 1);
            assertTrue(_r(t).isFrozen(a));
            vm.warp(s.until);
            assertFalse(_r(t).isFrozen(a));
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            assertEq(keccak256(abi.encode(_r(t).freezeOf(a))), keccak256(abi.encode(s)), "nothing written");
            vm.warp(1_800_000_000);
        }
    }

    /// `F` needs a live issuer root of bit 5 (spec §3.2, §3.6): once the owner's delayed revoke of the only issuer is
    /// confirmed, no freeze counts; before the confirm it still does.
    function test_freezeNeedsALiveRoot() public {
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            _freeze(t, a);
            vm.prank(ownerA);
            NormalToken(t).revokeRole(5, nid(issuer), EnvKit.codeUidOf(address(NormalToken(t)))); // proposes
            assertTrue(_r(t).isFrozen(a), "a proposal changes nothing");
            vm.warp(block.timestamp + GD);
            vm.prank(ownerA);
            NormalToken(t).revokeRole(5, nid(issuer), EnvKit.codeUidOf(address(NormalToken(t))));
            assertFalse(_r(t).isFrozen(a), "no root of bit 5");
            vm.prank(alice);
            IERC20(t).transfer(bob, 1);
            vm.warp(1_800_000_000);
        }
    }

    /// F-09, RK-8: a relayed op of a frozen `from` stops in `_regPre`, before any signature is read: a garbage signature
    /// reverts `Frozen`, not a signature error, on every entry and signer class (a native EOA, a native contract, a
    /// derived UA). The control: the same garbage on an unfrozen `from` fails in the pipeline.
    function test_preRefusesFrozenBeforeSignature() public {
        bytes32[3] memory froms = [nid(bob), nid(issuer), UA_X];
        for (uint256 i; i < 2; ++i) {
            address t = _ks()[i];
            for (uint256 k; k < 3; ++k) {
                bytes32 fr = froms[k];
                bytes[] memory calls = _entries(t, fr);
                for (uint256 c; c < calls.length; ++c) {
                    assertTrue(_try(t, calls[c]) != IRegulatedToken.Frozen.selector, "control: unfrozen");
                }
                _freeze(t, fr);
                for (uint256 c; c < calls.length; ++c) {
                    assertEq(_try(t, calls[c]), IRegulatedToken.Frozen.selector, "frozen: before the signature");
                }
            }
        }
    }

    /// The relayed entries of `from` with a garbage signature: typed transfer, generic UA, named (`mtxBurn` / `mtxUnwrap`),
    /// `mtxCancelNonce`, and for a native id the address path.
    function _entries(address t, bytes32 from) internal view returns (bytes[] memory c) {
        bool native = uint256(from) >> 160 == 0;
        c = new bytes[](native ? 5 : 4);
        MetaTxLib.UAMetaTransfer memory x;
        (x.from, x.to, x.value, x.batch, x.validUntil) = (from, nid(alice), 1, 1, block.timestamp + 60);
        c[0] = abi.encodeCall(NormalToken.mtxExecuteTransfer, (x, _bad()));
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction(from, abi.encodeWithSignature("burn(uint256)", 1),
            1, 0, block.timestamp + 60, 0, address(0), 0, address(0));
        c[1] = abi.encodeCall(UAMetaTxBase.mtxExecute, (m, _bad()));
        MetaTxLib.UAEnvelope memory e = MetaTxLib.UAEnvelope(from, 3, 0, block.timestamp + 60, 0, address(0), 0, address(0));
        c[2] = t == t8 ? abi.encodeCall(NormalToken.mtxBurn, (e, 1, _bad()))
            : abi.encodeCall(WrappedToken.mtxUnwrap, (e, 1, alice, 0, _bad()));
        c[3] = abi.encodeCall(UAMetaTxBase.mtxCancelNonce, (e, 9, _bad()));
        if (native) {
            MetaTxLib.MetaTransaction memory am = MetaTxLib.MetaTransaction(address(uint160(uint256(from))),
                abi.encodeWithSignature("burn(uint256)", 1), 2, 0, block.timestamp + 60, 0, address(0), 0, address(0));
            c[4] = abi.encodeCall(IMetaTx.executeMetaTransaction, (am, new bytes(65)));
        }
    }

    /// RK-8, F-18: `mtxCancelNonce` of a frozen `from` is refused on 8 and 9; signed by bob unfrozen it runs (control).
    function test_cancelNonceFrozenRefused_8() public {
        _cancelNonceFrozen(t8);
    }

    function test_cancelNonceFrozenRefused_9() public {
        _cancelNonceFrozen(t9);
    }

    function _cancelNonceFrozen(address t) internal {
        MetaTxLib.UAEnvelope memory e = _env(bob, 0, 0);
        IUARegistry.UASig memory s = _namedSig(BOB_PK, t, "UACancelNonce(bytes32 from,uint256 lane,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)", e, abi.encode(uint256(9)));
        uint256 snap = vm.snapshotState();
        _freeze(t, nid(bob));
        vm.expectRevert(abi.encodeWithSelector(IRegulatedToken.Frozen.selector, nid(bob)));
        UAMetaTxBase(t).mtxCancelNonce(e, 9, s);
        vm.revertToState(snap);
        UAMetaTxBase(t).mtxCancelNonce(e, 9, s);
        assertEq(NormalToken(t).mtxNonce(nid(bob), 9), 1, "the control: the lane bumped");
    }
}
