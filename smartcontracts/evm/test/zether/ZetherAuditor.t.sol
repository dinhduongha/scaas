// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {NormalZetherToken} from "../../src/zether/NormalZetherToken.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {IZetherVerifier} from "../../src/zether/IZetherVerifier.sol";
import {ZetherLib} from "../../src/zether/ZetherLib.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {ZetherTranscript} from "../../src/zether/ZetherTranscript.sol";
import {IConfidentialToken} from "../../src/confidential/IConfidentialToken.sol";
import {ITransferDisclosure} from "../../src/zether/ITransferDisclosure.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// Test only: `ZetherLib`'s proof-of-possession equation, so a test can force the challenge `c = 0` (no hash preimage needed).
contract PopEquationHarness {
    function equation(IZetherVerifier v, bytes memory g, bytes memory y, bytes memory r, uint256 z, uint256 c)
        external view returns (bool)
    {
        return ZetherLib.popEquation(v, g, y, r, z, c);
    }

    /// `ZetherLib._auditorChecks`' proof part: the exact length `P + 32`, then `popHolds(Y, R, z, d)`.
    function holds(IZetherVerifier v, bytes calldata y, bytes calldata pop, bytes32 d) external view returns (bool) {
        return pop.length == 160 && ZetherLib.popHolds(v, y, pop[:128], uint256(bytes32(pop[128:])), d);
    }
}

/// Set-auditor spec §4-§8, §13 (Zether rows; plan A2, CTR-ZTH-95): bit 32 `AUDITOR` replaces the auditor key after
/// `max(noticePeriod, grantDelay)` on the proposer's confirm within 7 days, with the new key's proof of possession over its
/// `AuditorConsent`; each audited transfer at an epoch other than 0 records its epoch; `auditorKeyOf` answers the entry's key.
/// Every refusal has a positive control and changes one thing.
contract ZetherAuditorTest is ZetherFixture {
    uint8 internal constant BIT = 32;
    uint256 internal constant X_B = 0xB0D1E5;
    uint256 internal constant X_C = 0xC0D1E5;
    uint64 internal constant WINDOW = 7 days;
    address internal holder = address(0xA0D);
    address internal holder2 = address(0xA0E);
    uint64 internal gd;
    bytes internal yA;
    bytes internal yB;
    bytes internal yC;

    function _go(uint64 notice_, uint64 gd_) internal {
        (notice, gd) = (notice_, gd_);
        _stack();
        vm.warp(block.timestamp + notice_); // the release is usable after the notice
        _users();
        IFactoryToken.TokenConfig memory c = _cfg(true, uint256(1) << 40);
        c.features |= uint256(1) << BIT;
        (c.admin, c.lockedFeatures, c.grantDelay) = (nid(address(this)), 0, gd_);
        tok = NormalZetherToken(factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "aud"));
        (yA, yB, yC) = (ZetherKeys.pub(X_AUD, bls), ZetherKeys.pub(X_B, bls), ZetherKeys.pub(X_C, bls));
        _grant(holder);
    }

    function _uid() internal view returns (bytes32) {
        return EnvKit.codeUidOf(address(tok));
    }

    function _grant(address a) internal {
        IGovernance(address(tok)).grantRole(BIT, nid(a), _uid());
        if (gd != 0) {
            vm.warp(block.timestamp + gd);
            IGovernance(address(tok)).grantRole(BIT, nid(a), _uid());
        }
        assertTrue(IGovernance(address(tok)).hasRole(BIT, nid(a)), "holder");
    }

    /// The typed `AuditorConsent` under `tok`'s domain, for the key `y`, the epoch and the word (and the token) given.
    function _digest(bytes memory y, uint32 epoch, bytes32 uid, address token) internal view returns (bytes32) {
        return _typed(tok, keccak256(abi.encode(
            keccak256("AuditorConsent(address token,bytes32 auditor,uint32 epoch,bytes32 chainUid)"), token,
            ZetherTypes.UA.unwrap(ZetherTypes.toUA(y)), epoch, uid)));
    }

    /// The Schnorr proof of possession of `x` over `d` (spec §5.2): `R ‖ be32(z)`.
    function _pop(uint256 x, bytes32 d) internal view returns (bytes memory) {
        uint256 n = ver.groupOrder();
        uint256 k = uint256(keccak256(abi.encode("pop-k", x, d))) % n;
        bytes memory r = ver.g1MulBase(k);
        uint256 c = ZetherTranscript.hashToScalar(
            keccak256(abi.encodePacked("SCAAS-ZETHER-AUDITOR-POP-V1", d, ver.g1MulBase(1), ver.g1MulBase(x), r)), n);
        return bytes.concat(r, bytes32(addmod(k, mulmod(c, x, n), n)));
    }

    function _popOf(uint256 x, uint32 epoch) internal view returns (bytes memory) {
        return _pop(x, _digest(ZetherKeys.pub(x, bls), epoch, _uid(), address(tok)));
    }

    /// `who` calls `setAuditorKey` with `x`'s key and its proof of possession for `epoch`.
    function _set(address who, uint256 x, uint32 epoch) internal {
        (bytes memory key, bytes memory pop, bytes32 uid) = (ZetherKeys.pub(x, bls), _popOf(x, epoch), _uid());
        vm.prank(who);
        tok.setAuditorKey(key, epoch, pop, uid);
    }

    function _call(address who, bytes memory key, uint32 epoch, bytes memory pop) internal {
        bytes32 uid = _uid();
        vm.prank(who);
        tok.setAuditorKey(key, epoch, pop, uid);
    }

    function _status() internal view returns (uint8 st) {
        (,,,, st) = tok.auditorState();
    }

    function _epoch() internal view returns (uint32 e) {
        (e,,,,) = tok.auditorState();
    }

    // ------------------------------------------------------------------ the state machine

    function test_propose_waits_then_applies() public {
        _go(1 days, 0);
        uint64 eta = uint64(block.timestamp + 1 days);
        vm.expectEmit(address(tok));
        emit IZetherToken.AuditorKeyProposed(1, yB, nid(holder), eta);
        _set(holder, X_B, 1);
        (uint32 e, bytes32 pend, uint64 at, bytes32 prop, uint8 st) = tok.auditorState();
        assertEq(e, 0);
        assertEq(pend, keccak256(yB));
        assertEq(at, eta);
        assertEq(prop, nid(holder));
        assertEq(st, 1);
        assertEq(tok.auditorKey(), yA, "nothing applied");
        vm.warp(eta - 1);
        bytes memory pop = _popOf(X_B, 1);
        vm.expectRevert(abi.encodeWithSelector(IConfidentialToken.AuditorNotReady.selector, eta));
        _call(holder, yB, 1, pop);
        vm.warp(eta);
        assertEq(_status(), 2);
        vm.expectEmit(address(tok));
        emit IZetherToken.AuditorKeySet(1, yA, yB);
        _set(holder, X_B, 1);
        assertEq(tok.auditorKey(), yB);
        (e, pend, at, prop, st) = tok.auditorState();
        assertEq(e, 1);
        assertEq(pend, 0);
        assertEq(at, 0);
        assertEq(prop, 0);
        assertEq(st, 0);
    }

    /// `D = max(noticePeriod, grantDelay)`: the grant delay the longer.
    function test_delay_grantDelayLonger() public {
        _go(1 days, 3 days);
        _set(holder, X_B, 1);
        (,, uint64 eta,,) = tok.auditorState();
        assertEq(eta, block.timestamp + 3 days);
    }

    /// The notice the longer.
    function test_delay_noticeLonger() public {
        _go(3 days, 1 days);
        _set(holder, X_B, 1);
        (,, uint64 eta,,) = tok.auditorState();
        assertEq(eta, block.timestamp + 3 days);
    }

    /// `D = 0` (owner O4): one call applies, both events in it.
    function test_delayZero_appliesAtOnce() public {
        _go(0, 0);
        vm.expectEmit(address(tok));
        emit IZetherToken.AuditorKeyProposed(1, yB, nid(holder), uint64(block.timestamp));
        vm.expectEmit(address(tok));
        emit IZetherToken.AuditorKeySet(1, yA, yB);
        _set(holder, X_B, 1);
        assertEq(tok.auditorKey(), yB);
        assertEq(_epoch(), 1);
        assertEq(_status(), 0);
    }

    /// A zero-notice chain with `grantDelay > 0`: the window `[eta, eta + 7 days]` is never empty; its last second confirms.
    function test_zeroNotice_grantDelay_confirmsInWindow() public {
        _go(0, 2 days);
        _set(holder, X_B, 1);
        (,, uint64 eta,,) = tok.auditorState();
        assertEq(eta, block.timestamp + 2 days);
        vm.warp(eta + WINDOW);
        assertEq(_status(), 2);
        _set(holder, X_B, 1);
        assertEq(tok.auditorKey(), yB);
    }

    /// A confirm after the window finds no live proposal: it proposes afresh (a new `eta`), nothing applied.
    function test_confirmAfterWindow_proposesAfresh() public {
        _go(1 days, 0);
        _set(holder, X_B, 1);
        (,, uint64 eta,,) = tok.auditorState();
        vm.warp(eta + WINDOW + 1);
        assertEq(_status(), 3);
        uint64 eta2 = uint64(block.timestamp + 1 days);
        vm.expectEmit(address(tok));
        emit IZetherToken.AuditorKeyProposed(1, yB, nid(holder), eta2);
        _set(holder, X_B, 1);
        assertEq(tok.auditorKey(), yA, "not applied");
        assertEq(_epoch(), 0);
        (,, uint64 at,, uint8 st) = tok.auditorState();
        assertEq(at, eta2);
        assertEq(st, 1);
    }

    /// Another value is `AuditorPending` while the proposal lives and takes the slot after the window, with no cancel.
    function test_otherValue_pendingUntilExpiry() public {
        _go(1 days, 0);
        _set(holder, X_B, 1);
        bytes memory pop = _popOf(X_C, 1);
        vm.expectRevert(IConfidentialToken.AuditorPending.selector);
        _call(holder, yC, 1, pop);
        (,, uint64 eta,,) = tok.auditorState();
        vm.warp(eta + WINDOW);
        vm.expectRevert(IConfidentialToken.AuditorPending.selector);
        _call(holder, yC, 1, pop);
        vm.warp(eta + WINDOW + 1);
        _set(holder, X_C, 1);
        (, bytes32 pend,,, uint8 st) = tok.auditorState();
        assertEq(pend, keccak256(yC));
        assertEq(st, 1);
    }

    /// The holder cancels its own proposal by proposing the current key (no consent read); a new proposal then takes the slot.
    function test_cancel_byProposingCurrent() public {
        _go(1 days, 0);
        _set(holder, X_B, 1);
        vm.expectEmit(address(tok));
        emit IConfidentialToken.AuditorProposalCancelled(1);
        _call(holder, yA, 1, "");
        (uint32 e, bytes32 pend, uint64 at, bytes32 prop, uint8 st) = tok.auditorState();
        assertEq(e, 0);
        assertEq(pend, 0);
        assertEq(at, 0);
        assertEq(prop, 0);
        assertEq(st, 0);
        _set(holder, X_C, 1);
        assertEq(_status(), 1);
    }

    /// `auditorState().status` 1 waiting, 2 confirmable, 3 expired, 4 void (the proposer revoked) in turn.
    function test_status_inTurn() public {
        _go(1 days, 0);
        _set(holder, X_B, 1);
        assertEq(_status(), 1);
        vm.warp(block.timestamp + 1 days);
        assertEq(_status(), 2);
        vm.warp(block.timestamp + WINDOW + 1);
        assertEq(_status(), 3);
        _set(holder, X_B, 1);
        assertEq(_status(), 1);
        IGovernance(address(tok)).revokeRole(BIT, nid(holder), _uid());
        (, bytes32 pend,, bytes32 prop, uint8 st) = tok.auditorState();
        assertEq(st, 4);
        assertEq(pend, keccak256(yB));
        assertEq(prop, nid(holder));
    }

    /// `disableFeature(32)`: the stored proposal reads 0, void.
    function test_state_zerosAfterDisable() public {
        _go(1 days, 0);
        _set(holder, X_B, 1);
        IGovernance(address(tok)).disableFeature(BIT, _uid());
        (uint32 e, bytes32 pend, uint64 at, bytes32 prop, uint8 st) = tok.auditorState();
        assertEq(e, 0);
        assertEq(pend, 0);
        assertEq(at, 0);
        assertEq(prop, 0);
        assertEq(st, 4);
        bytes memory pop = _popOf(X_B, 1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureNotSet.selector, BIT));
        _call(holder, yB, 1, pop);
    }

    /// Another holder neither confirms nor cancels (`NotProposer`) nor proposes over the live one (`AuditorPending`).
    function test_otherHolder_cannotConfirmOrCancel() public {
        _go(1 days, 0);
        _grant(holder2);
        _set(holder, X_B, 1);
        vm.warp(block.timestamp + 1 days);
        bytes memory pop = _popOf(X_B, 1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotProposer.selector, BIT, bytes32(0), nid(holder)));
        _call(holder2, yB, 1, pop);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotProposer.selector, BIT, bytes32(0), nid(holder)));
        _call(holder2, yA, 1, "");
        bytes memory popC = _popOf(X_C, 1);
        vm.expectRevert(IConfidentialToken.AuditorPending.selector);
        _call(holder2, yC, 1, popC);
        _set(holder, X_B, 1); // the control: the proposer confirms
        assertEq(tok.auditorKey(), yB);
    }

    /// A revoke kills the proposal by the role epoch, for good: after a re-grant the confirm proposes afresh.
    function test_revokedProposer_deadAfterRegrant() public {
        _go(1 days, 0);
        _set(holder, X_B, 1);
        IGovernance(address(tok)).revokeRole(BIT, nid(holder), _uid());
        _grant(holder);
        vm.warp(block.timestamp + 1 days);
        assertEq(_status(), 4);
        uint64 eta2 = uint64(block.timestamp + 1 days);
        vm.expectEmit(address(tok));
        emit IZetherToken.AuditorKeyProposed(1, yB, nid(holder), eta2);
        _set(holder, X_B, 1);
        assertEq(tok.auditorKey(), yA, "not applied");
        assertEq(_status(), 1);
    }

    /// The wrong epoch on a proposal, a confirm and a cancel.
    function test_wrongEpoch() public {
        _go(1 days, 0);
        bytes memory pop2 = _popOf(X_B, 2);
        vm.expectRevert(abi.encodeWithSelector(IConfidentialToken.AuditorEpochMismatch.selector, uint32(1), uint32(2)));
        _call(holder, yB, 2, pop2);
        bytes memory pop0 = _popOf(X_B, 0);
        vm.expectRevert(abi.encodeWithSelector(IConfidentialToken.AuditorEpochMismatch.selector, uint32(1), uint32(0)));
        _call(holder, yB, 0, pop0);
        _set(holder, X_B, 1);
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(abi.encodeWithSelector(IConfidentialToken.AuditorEpochMismatch.selector, uint32(1), uint32(2)));
        _call(holder, yB, 2, pop2);
        vm.expectRevert(abi.encodeWithSelector(IConfidentialToken.AuditorEpochMismatch.selector, uint32(1), uint32(2)));
        _call(holder, yA, 2, "");
        _set(holder, X_B, 1);
        assertEq(_epoch(), 1);
    }

    /// `AuditorSame` without a live proposal; `AuditorKeyInvalid` for a short key, `O` and a point off the curve.
    function test_same_and_keyInvalid() public {
        _go(1 days, 0);
        bytes memory popA = _popOf(X_AUD, 1);
        vm.expectRevert(IConfidentialToken.AuditorSame.selector);
        _call(holder, yA, 1, popA);
        bytes memory shortKey = new bytes(127);
        bytes memory p_shortKey = _pop(X_B, _digest(shortKey, 1, _uid(), address(tok)));
        vm.expectRevert(IZetherToken.AuditorKeyInvalid.selector);
        _call(holder, shortKey, 1, p_shortKey);
        bytes memory o = ver.identity();
        bytes memory p_o = _pop(X_B, _digest(o, 1, _uid(), address(tok)));
        vm.expectRevert(IZetherToken.AuditorKeyInvalid.selector);
        _call(holder, o, 1, p_o);
        bytes memory off = bytes.concat(yB);
        off[127] = bytes1(uint8(off[127]) ^ 1);
        bytes memory p_off = _pop(X_B, _digest(off, 1, _uid(), address(tok)));
        vm.expectRevert(IZetherToken.AuditorKeyInvalid.selector);
        _call(holder, off, 1, p_off);
        _set(holder, X_B, 1);
        assertEq(_status(), 1);
    }

    /// Consent refused at the proposal: missing, another token, another epoch, another word, another key.
    function test_consent_refusedAtProposal() public {
        _go(1 days, 0);
        bytes[5] memory bad = [bytes(""), _pop(X_B, _digest(yB, 1, _uid(), address(0xD0C))), _pop(X_B, _digest(yB, 2, _uid(),
            address(tok))), _pop(X_B, _digest(yB, 1, bytes32(uint256(_uid()) ^ 1), address(tok))), _pop(X_C, _digest(yB, 1,
            _uid(), address(tok)))];
        for (uint256 i; i < 5; ++i) {
            vm.expectRevert(IZetherToken.AuditorConsentInvalid.selector);
            _call(holder, yB, 1, bad[i]);
        }
        _set(holder, X_B, 1);
        assertEq(_status(), 1);
    }

    /// The confirm carries the consent again: a bad one is refused at the apply, a good one applies.
    function test_consent_refusedAtApply() public {
        _go(1 days, 0);
        _set(holder, X_B, 1);
        vm.warp(block.timestamp + 1 days);
        bytes memory bad = _pop(X_C, _digest(yB, 1, _uid(), address(tok)));
        vm.expectRevert(IZetherToken.AuditorConsentInvalid.selector);
        _call(holder, yB, 1, bad);
        _set(holder, X_B, 1);
        assertEq(tok.auditorKey(), yB);
    }

    /// The proof of possession: `z ≥ r`, `R` not a point, a proof for another `d`, a wrong length.
    function test_pop_refusals() public {
        _go(1 days, 0);
        bytes memory good = _popOf(X_B, 1);
        uint256 n = ver.groupOrder();
        bytes memory zHigh = bytes.concat(good);
        uint256 z = uint256(_zWord(good, 128)) + n;
        assembly ("memory-safe") { mstore(add(add(zHigh, 32), 128), z) }
        bytes memory rBad = bytes.concat(good);
        rBad[127] = bytes1(uint8(rBad[127]) ^ 1);
        bytes memory otherD = _pop(X_B, keccak256("another digest"));
        bytes memory long = bytes.concat(good, hex"00");
        bytes[4] memory bad = [zHigh, rBad, otherD, long];
        for (uint256 i; i < 4; ++i) {
            vm.expectRevert(IZetherToken.AuditorConsentInvalid.selector);
            _call(holder, yB, 1, bad[i]);
        }
        _call(holder, yB, 1, good);
        assertEq(_status(), 1);
    }

    /// The equation refuses `c = 0` even when `[z]G − R == O` holds (a forged `R = [z]G`); with `c ≠ 0` it is the check.
    function test_pop_challengeZeroRefused() public {
        _go(1 days, 0);
        PopEquationHarness h = new PopEquationHarness();
        bytes memory g = ver.g1MulBase(1);
        uint256 z = 0x1234567;
        assertFalse(h.equation(ver, g, yB, ver.g1MulBase(z), z, 0), "c = 0 refused");
        uint256 n = ver.groupOrder();
        uint256 c = 5;
        uint256 k = 0x777;
        assertTrue(h.equation(ver, g, yB, ver.g1MulBase(k), addmod(k, mulmod(c, X_B, n), n), c), "control");
        assertFalse(h.equation(ver, g, yB, ver.g1MulBase(k), addmod(k, mulmod(c + 1, X_B, n), n), c), "wrong z");
    }

    /// The known answers of `smartcontracts/vectors/zether/auditor_pop.json` (zether-prover `zether-cli auditor-pop`, plan A3):
    /// every row's proof holds, every refused row's does not.
    function test_pop_vectors() public {
        _go(0, 0);
        PopEquationHarness h = new PopEquationHarness();
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/../vectors/zether/auditor_pop.json"));
        uint256 rows;
        for (uint256 i; vm.keyExistsJson(j, string.concat(".rows[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".rows[", vm.toString(i), "]");
            assertTrue(h.holds(ver, vm.parseJsonBytes(j, string.concat(r, ".y")), vm.parseJsonBytes(j, string.concat(r, ".pop")),
                vm.parseJsonBytes32(j, string.concat(r, ".d"))), r);
            ++rows;
        }
        uint256 refused;
        for (uint256 i; vm.keyExistsJson(j, string.concat(".refused[", vm.toString(i), "]")); ++i) {
            string memory r = string.concat(".refused[", vm.toString(i), "]");
            assertFalse(h.holds(ver, vm.parseJsonBytes(j, string.concat(r, ".y")), vm.parseJsonBytes(j, string.concat(r, ".pop")),
                vm.parseJsonBytes32(j, string.concat(r, ".d"))), vm.parseJsonString(j, string.concat(r, ".name")));
            ++refused;
        }
        assertEq(rows, 2);
        assertEq(refused, 8);
    }

    /// CTR-GOV-28: a sibling word is refused, nothing written; a stranger is `MissingRole` first, whatever its word.
    function test_word_and_stranger() public {
        _go(1 days, 0);
        bytes memory pop = _popOf(X_B, 1);
        bytes32 other = bytes32(uint256(_uid()) ^ 1);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, _uid(), other));
        tok.setAuditorKey(yB, 1, pop, other);
        assertEq(_status(), 0, "nothing written");
        vm.prank(address(0x5757));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, BIT, nid(address(0x5757))));
        tok.setAuditorKey(yB, 1, pop, other);
        _set(holder, X_B, 1);
        assertEq(_status(), 1);
    }

    /// Every call is one use: `maxUses = 1` proposes and cannot confirm; `maxUses = 2` does both.
    function test_twoUsesPerReplacement() public {
        _go(1 days, 0);
        IGovernance.GrantTerms memory g;
        (g.max, g.maxUses) = (type(uint128).max, 1);
        IGovernance(address(tok)).setGrant(BIT, nid(holder2), g, _uid());
        _set(holder2, X_B, 1);
        vm.warp(block.timestamp + 1 days);
        bytes memory pop = _popOf(X_B, 1);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(5)));
        _call(holder2, yB, 1, pop);
        g.maxUses = 2;
        address h3 = address(0xA0F);
        IGovernance(address(tok)).setGrant(BIT, nid(h3), g, _uid());
        vm.warp(block.timestamp + WINDOW + 1); // holder2's proposal expired
        _set(h3, X_B, 1);
        vm.warp(block.timestamp + 1 days);
        _set(h3, X_B, 1);
        assertEq(tok.auditorKey(), yB);
    }

    // ------------------------------------------------------------------ epochs per entry (spec §7)

    /// `entryAuditorEpoch[ref]`'s slot (ZetherStorage slot 17).
    function _epochSlot(bytes32 ref) internal pure returns (bytes32) {
        return keccak256(abi.encode(ref, uint256(0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce00) + 17));
    }

    function _single(User memory from, User memory to, uint256 v, uint256 b) internal returns (bytes32) {
        return _direct(tok, _proveTransfer(tok, from, to, v, b, _none(), 0), _none());
    }

    function _funded() internal {
        _fund(tok, alice, 1000);
        tok.mtxRollOver(ZetherTypes.UA.unwrap(alice.ua), 1);
    }

    /// No `SSTORE` to `entryAuditorEpoch[ref]` during the recorded calls (a write of 0 would leave the word 0 too).
    function _notWritten(bytes32 ref) internal {
        (, bytes32[] memory writes) = vm.accesses(address(tok));
        for (uint256 i; i < writes.length; ++i) assertTrue(writes[i] != _epochSlot(ref), "entryAuditorEpoch written");
    }

    /// Epoch 0: an audited transfer writes no row (no `SSTORE` at all to it) and its key is the current one.
    function test_epoch0_auditedTransfer_writesNothing() public {
        _go(0, 0);
        _funded();
        bytes32 ref = _ref(tok, alice, 0);
        vm.record();
        assertEq(_single(alice, bob, 10, 1000), ref);
        _notWritten(ref);
        assertEq(vm.load(address(tok), _epochSlot(ref)), 0);
        assertEq(tok.auditorKeyOf(ref), yA);
    }

    /// Epoch 1: an audited transfer writes 1 (encrypted to the new key); an opt-out writes nothing and answers epoch 0's key.
    function test_epoch1_writes_optOutDoesNot() public {
        _go(0, 0);
        _funded();
        bytes32 r0 = _single(alice, bob, 10, 1000);
        _set(holder, X_B, 1);
        bytes32 r1 = _single(alice, bob, 10, 990);
        assertEq(uint256(vm.load(address(tok), _epochSlot(r1))), 1);
        assertEq(tok.auditorKeyOf(r1), yB);
        assertEq(tok.auditorKeyOf(r0), yA, "an epoch-0 entry keeps its key");
        audOut = true;
        vm.record();
        bytes32 r2 = _single(alice, bob, 10, 980);
        _notWritten(r2);
        assertEq(vm.load(address(tok), _epochSlot(r2)), 0, "opt-out: no row");
        assertEq(tok.auditorKeyOf(r2), yA, "opt-out answers epoch 0's key");
    }

    /// Multi-recipient BUNDLE and HASH at epoch 1 write 1.
    function test_epoch1_multi_bothForms() public {
        _go(0, 0);
        _funded();
        _set(holder, X_B, 1);
        User[] memory to = new User[](2);
        (to[0], to[1]) = (bob, carol);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (5, 7);
        Tx memory t = _proveMulti(tok, alice, to, vs, 1000, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes32 r1 = tok.mtxConfidentialTransfer(_zMulti(t.payload, _none()), t.proof);
        assertEq(uint256(vm.load(address(tok), _epochSlot(r1))), 1);
        t = _proveMulti(tok, alice, to, vs, 988, _none(), ZetherTypes.TransferMode.HASH);
        bytes32 r2 = tok.mtxConfidentialTransferCompact(_zMulti(t.payload, _none()), t.proof);
        assertEq(uint256(vm.load(address(tok), _epochSlot(r2))), 1);
        assertEq(tok.auditorKeyOf(r2), yB);
    }

    /// Three epochs: each entry answers its own key; the key returning at epoch 2 leaves the history of epochs 0 and 1.
    function test_threeEpochs_history() public {
        _go(0, 0);
        _funded();
        bytes32 r0 = _single(alice, bob, 10, 1000);
        _set(holder, X_B, 1);
        bytes32 r1 = _single(alice, bob, 10, 990);
        vm.expectEmit(address(tok));
        emit IZetherToken.AuditorKeySet(2, yB, yA);
        _set(holder, X_AUD, 2);
        bytes32 r2 = _single(alice, bob, 10, 980);
        assertEq(uint256(vm.load(address(tok), _epochSlot(r2))), 2);
        assertEq(tok.auditorKeyOf(r0), yA);
        assertEq(tok.auditorKeyOf(r1), yB);
        assertEq(tok.auditorKeyOf(r2), yA);
        assertEq(_epoch(), 2);
    }

    /// The way back (review A4): revoke the hostile holder, grant another, restore the previous key with its consent; the
    /// entries in between keep their epoch.
    function test_wayBack() public {
        _go(0, 0);
        _funded();
        _set(holder, X_B, 1); // hostile
        bytes32 r1 = _single(alice, bob, 10, 1000);
        IGovernance(address(tok)).revokeRole(BIT, nid(holder), _uid());
        bytes memory popC = _popOf(X_C, 2);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, BIT, nid(holder)));
        _call(holder, yC, 2, popC);
        _grant(holder2);
        _set(holder2, X_AUD, 2);
        assertEq(tok.auditorKey(), yA);
        assertEq(tok.auditorKeyOf(r1), yB, "the entry in between keeps its epoch");
    }

    // ------------------------------------------------------------------ disclosure across epochs (spec §9, plan A3)

    /// `D_aud` of leg `j` (the AUDITOR base: `D_out` on the single format), from `ZetherDisclosure.transferCiphertext`.
    function _audBase(bytes32 ref, uint256 j) internal view returns (bytes memory b) {
        (bytes memory ct,) = dis.transferCiphertext(address(tok), ref, j);
        b = new bytes(128);
        for (uint256 i; i < 128; ++i) b[i] = ct[384 + i];
    }

    /// An AUDITOR opening of leg `j` of `ref` for `amount`, made with the key `x`: does `ZetherDisclosure` accept it?
    function _audOpens(bytes32 ref, uint256 j, uint256 amount, uint256 x) internal view returns (bool) {
        bytes memory o = _cpOpening(tok, x, ref, j, amount, ITransferDisclosure.OpeningKind.AUDITOR, _audBase(ref, j));
        return _vta(tok, ref, j, amount, ITransferDisclosure.OpeningKind.AUDITOR, o);
    }

    /// Three epochs (keys A, B, C), one single-format entry each: each opens with its own epoch's key only; an opt-out entry at
    /// epoch 2 answers epoch 0's key from the view and opens with none.
    function test_disclosure_threeEpochs_single() public {
        _go(0, 0);
        _funded();
        bytes32[3] memory rs;
        rs[0] = _single(alice, bob, 10, 1000);
        _set(holder, X_B, 1);
        rs[1] = _single(alice, bob, 11, 990);
        _set(holder, X_C, 2);
        rs[2] = _single(alice, bob, 12, 979);
        audOut = true;
        bytes32 out = _single(alice, bob, 13, 967);
        uint256[3] memory xs = [X_AUD, X_B, X_C];
        for (uint256 i; i < 3; ++i) {
            for (uint256 k; k < 3; ++k) assertEq(_audOpens(rs[i], 0, 10 + i, xs[k]), i == k, "the entry's own epoch key only");
        }
        assertEq(tok.auditorKeyOf(out), yA, "opt-out: epoch 0's key");
        for (uint256 k; k < 3; ++k) assertFalse(_audOpens(out, 0, 13, xs[k]), "opt-out: no auditor opening");
    }

    /// Multi-recipient: an epoch-0 entry still opens with the old key after the replacement, an epoch-1 entry with the new.
    function test_disclosure_multi_acrossEpochs() public {
        _go(0, 0);
        _funded();
        User[] memory to = new User[](2);
        (to[0], to[1]) = (bob, carol);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (5, 7);
        Tx memory t = _proveMulti(tok, alice, to, vs, 1000, _none(), ZetherTypes.TransferMode.BUNDLE);
        bytes32 r0 = tok.mtxConfidentialTransfer(_zMulti(t.payload, _none()), t.proof);
        _set(holder, X_B, 1);
        t = _proveMulti(tok, alice, to, vs, 988, _none(), ZetherTypes.TransferMode.HASH);
        bytes32 r1 = tok.mtxConfidentialTransferCompact(_zMulti(t.payload, _none()), t.proof);
        for (uint256 j; j < 2; ++j) {
            assertTrue(_audOpens(r0, j, vs[j], X_AUD), "epoch 0 entry, old key");
            assertFalse(_audOpens(r0, j, vs[j], X_B), "epoch 0 entry, new key");
            assertTrue(_audOpens(r1, j, vs[j], X_B), "epoch 1 entry, new key");
            assertFalse(_audOpens(r1, j, vs[j], X_AUD), "epoch 1 entry, old key");
        }
    }
}
