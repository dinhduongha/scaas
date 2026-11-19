// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {console2, Vm} from "forge-std/Test.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {PQZ_UID} from "./helpers/PqzRegistryBase.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IConfidentialToken} from "../../src/confidential/IConfidentialToken.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {UACall} from "../ua/UACall.sol";

/// Set-auditor spec §4-§10, §13 (PQZ rows; plan A4, CTR-PQZ-43): bit 32 `AUDITOR` replaces the auditor UA after
/// `max(noticePeriod, grantDelay)` on the proposer's confirm within 7 days, with the new auditor's signed `AuditorConsent`
/// (`PURPOSE_AUDITOR_CONSENT`) and its key of the token's class and scope (proven where the registry has a `0x0142` verifier);
/// each audited transfer at an epoch other than 0 records its epoch; the `AUDITOR` disclosure checks against the entry's
/// auditor. Every refusal has a positive control and changes one thing. The proofs are mocked (the fixture).
contract PqzAuditorTest is PqzOffchainBase {
    uint8 internal constant BIT = 32;
    uint64 internal constant WINDOW = 7 days;
    bytes32 internal constant CONSENT_TYPEHASH =
        keccak256("AuditorConsent(address token,bytes32 auditor,uint32 epoch,bytes32 chainUid)");
    address internal holder = address(0xA0D);
    address internal holder2 = address(0xA0E);
    bool internal bit32 = true;
    uint64 internal gd;
    bytes32 internal a1; // a second auditor UA (registry key `_pk(41)`)
    bytes32 internal a2; // a third (`_pk(42)`)
    bytes32 internal plain; // an `mldsa65` UA without any PQZ key

    function setUp() public {}

    /// The fixture's PRECOMPILE stack with the factory notice `notice_` and `grantDelay` `gd_`; a token with bit 32, the
    /// test as its admin, `holder` granted the bit.
    function _go(uint64 notice_, uint64 gd_) internal {
        (notice, gd) = (notice_, gd_);
        _stack();
        vm.warp(block.timestamp + notice_); // the release is usable after the notice
        a1 = _pqzUA(_pk(41), 11);
        a2 = _pqzUA(_pk(42), 12);
        plain = _mldsaUA(13);
        tok = _newToken("aud");
        _grant(holder);
    }

    function _cfg(uint256 maxShielded) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = super._cfg(maxShielded);
        if (bit32) {
            c.features |= uint256(1) << BIT;
            (c.admin, c.lockedFeatures, c.grantDelay) = (nid(address(this)), 0, gd);
        }
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

    /// The typed `AuditorConsent` of `ua` for `epoch` under `t`'s domain.
    function _digest(NormalPqzToken t, bytes32 ua, uint32 epoch) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(
            _sepOf(address(t)),
            keccak256(abi.encode(CONSENT_TYPEHASH, address(t), ua, epoch, EnvKit.codeUidOf(address(t))))
        );
    }

    function _set(address who, bytes32 ua, uint32 epoch) internal {
        (IUARegistry.UASig memory c, bytes32 uid) = (_pqAuth(), _uid());
        vm.prank(who);
        tok.setAuditorUA(ua, epoch, c, uid);
    }

    function _status() internal view returns (uint8 st) {
        (,,,, st) = tok.auditorState();
    }

    function _epoch() internal view returns (uint32 e) {
        (e,,,,) = tok.auditorState();
    }

    // ------------------------------------------------------------------ the state machine

    /// A `PRECOMPILE` token waits the factory notice (`PqzStorage.noticePeriod` is 0 there): propose, `AuditorNotReady`, apply.
    function test_precompile_waitsFactoryNotice() public {
        _go(1 days, 0);
        assertEq(tok.pqzVerifyConfig().noticePeriod, 0, "the namespace's notice is 0 on PRECOMPILE");
        uint64 eta = uint64(block.timestamp + 1 days);
        vm.expectEmit(address(tok));
        emit IPqzToken.AuditorUAProposed(1, a1, nid(holder), eta);
        _set(holder, a1, 1);
        (uint32 e, bytes32 pend, uint64 at, bytes32 prop, uint8 st) = tok.auditorState();
        assertEq(e, 0);
        assertEq(pend, a1);
        assertEq(at, eta);
        assertEq(prop, nid(holder));
        assertEq(st, 1);
        vm.warp(eta - 1);
        (IUARegistry.UASig memory c, bytes32 uid) = (_pqAuth(), _uid());
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IConfidentialToken.AuditorNotReady.selector, eta));
        tok.setAuditorUA(a1, 1, c, uid);
        vm.warp(eta);
        vm.expectEmit(address(tok));
        emit IPqzToken.AuditorUASet(1, aud, a1);
        _set(holder, a1, 1);
        assertEq(tok.auditorUA(), a1);
        assertEq(_epoch(), 1);
        assertEq(_status(), 0);
    }

    /// `D = max(noticePeriod, grantDelay)`, each the longer in turn; `D = 0` applies at once.
    function test_delay_maxAndZero() public {
        _go(1 days, 3 days);
        _set(holder, a1, 1);
        (,, uint64 eta,,) = tok.auditorState();
        assertEq(eta, block.timestamp + 3 days, "grant delay the longer");
        _go(3 days, 1 days);
        _set(holder, a1, 1);
        (,, eta,,) = tok.auditorState();
        assertEq(eta, block.timestamp + 3 days, "notice the longer");
        _go(0, 0);
        vm.expectEmit(address(tok));
        emit IPqzToken.AuditorUAProposed(1, a1, nid(holder), uint64(block.timestamp));
        vm.expectEmit(address(tok));
        emit IPqzToken.AuditorUASet(1, aud, a1);
        _set(holder, a1, 1);
        assertEq(tok.auditorUA(), a1, "at once");
    }

    /// The window, expiry, another value, the cancel and the statuses, as on Zether (one rule, `AuditorRules`).
    function test_window_cancel_status() public {
        _go(0, 2 days);
        _set(holder, a1, 1);
        assertEq(_status(), 1);
        (IUARegistry.UASig memory c, bytes32 uid) = (_pqAuth(), _uid());
        vm.prank(holder);
        vm.expectRevert(IConfidentialToken.AuditorPending.selector);
        tok.setAuditorUA(a2, 1, c, uid);
        (,, uint64 eta,,) = tok.auditorState();
        vm.warp(eta + WINDOW);
        assertEq(_status(), 2, "the window's last second");
        vm.warp(eta + WINDOW + 1);
        assertEq(_status(), 3);
        _set(holder, a2, 1); // the expired proposal frees the slot: a new one, nothing applied
        assertEq(tok.auditorUA(), aud);
        (, bytes32 pend,,,) = tok.auditorState();
        assertEq(pend, a2);
        vm.expectEmit(address(tok));
        emit IConfidentialToken.AuditorProposalCancelled(1);
        _set(holder, aud, 1); // the holder's cancel: the current auditor
        assertEq(_status(), 0);
        vm.prank(holder);
        vm.expectRevert(IConfidentialToken.AuditorSame.selector);
        tok.setAuditorUA(aud, 1, c, uid);
        _set(holder, a1, 1);
        IGovernance(address(tok)).revokeRole(BIT, nid(holder), _uid());
        assertEq(_status(), 4, "void: the proposer revoked");
    }

    /// Another holder neither confirms nor cancels; the wrong epoch on a proposal and a confirm; a stranger is `MissingRole`
    /// first; a sibling word is refused with nothing written.
    function test_refusals_holder_epoch_word() public {
        _go(1 days, 0);
        _grant(holder2);
        (IUARegistry.UASig memory c, bytes32 uid) = (_pqAuth(), _uid());
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IConfidentialToken.AuditorEpochMismatch.selector, uint32(1), uint32(2)));
        tok.setAuditorUA(a1, 2, c, uid);
        bytes32 other = bytes32(uint256(uid) ^ 1);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.ChainUidMismatch.selector, uid, other));
        tok.setAuditorUA(a1, 1, c, other);
        assertEq(_status(), 0, "nothing written");
        vm.prank(address(0x5757));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, BIT, nid(address(0x5757))));
        tok.setAuditorUA(a1, 1, c, other);
        _set(holder, a1, 1);
        vm.warp(block.timestamp + 1 days);
        vm.prank(holder2);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotProposer.selector, BIT, bytes32(0), nid(holder)));
        tok.setAuditorUA(a1, 1, c, uid);
        vm.prank(holder2);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotProposer.selector, BIT, bytes32(0), nid(holder)));
        tok.setAuditorUA(aud, 1, c, uid);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IConfidentialToken.AuditorEpochMismatch.selector, uint32(1), uint32(2)));
        tok.setAuditorUA(a1, 2, c, uid);
        _set(holder, a1, 1);
        assertEq(tok.auditorUA(), a1);
    }

    // ------------------------------------------------------------------ consent and key checks (spec §5.2)

    /// The consent is `requireAuthorized(newAuditor, PURPOSE_AUDITOR_CONSENT, d, consent)` with `d` the token's typed
    /// `AuditorConsent` (token, UA, epoch, word), at the proposal and again at the apply; the registry's refusal is the setter's.
    function test_consent_exactAndRefusedAtBothSteps() public {
        _go(1 days, 0);
        IUARegistry.UASig memory c = _pqAuth();
        bytes32 d = _digest(tok, a1, 1);
        bytes memory call_ = abi.encodeCall(IUARegistry.requireAuthorized, (a1, UAKinds.PURPOSE_AUDITOR_CONSENT, d, c));
        bytes memory refusal = abi.encodeWithSignature("UAUnauthorized(bytes32)", a1);
        vm.mockCallRevert(address(reg), call_, refusal);
        bytes32 uid = _uid();
        vm.prank(holder);
        vm.expectRevert(refusal);
        tok.setAuditorUA(a1, 1, c, uid);
        vm.clearMockedCalls();
        _mockOps();
        vm.expectCall(address(reg), call_);
        _set(holder, a1, 1);
        vm.warp(block.timestamp + 1 days);
        vm.mockCallRevert(address(reg), call_, refusal);
        vm.prank(holder);
        vm.expectRevert(refusal);
        tok.setAuditorUA(a1, 1, c, uid);
        vm.clearMockedCalls();
        _mockOps();
        vm.expectCall(address(reg), call_);
        _set(holder, a1, 1);
        assertEq(tok.auditorUA(), a1);
    }

    /// Closing review C3.1: the consent checked by a real signer path. `a1` is an `mldsa65` UA (a native or secp256k1 UA cannot
    /// hold a PQZ key, `UARegistryCoreLib._holder`), its consent goes through the registry's own `requireAuthorized` to its
    /// `MldsaVerifier`, and the precompile accepts exactly one input: `a1`'s key, `a1`'s signature and the `pq_msg` of the
    /// signed digest. The signed struct moves one field at a time (token, epoch, word), then the signer (`a2`'s key and
    /// signature over `a1`'s digest): each `UAUnauthorized(a1)`, nothing written; the positive control proposes and applies.
    function test_consent_realSigner_oneChangeAtATime() public {
        _go(1 days, 0);
        NormalPqzToken tok2 = _newToken("aud2");
        bytes32 uid = _uid();
        bytes memory refusal = abi.encodeWithSignature("UAUnauthorized(bytes32)", a1);
        bytes32[4] memory signed = [
            _digestOf(address(tok2), a1, 1, uid),
            _digestOf(address(tok), a1, 2, uid),
            _digestOf(address(tok), a1, 1, bytes32(uint256(uid) ^ 1)),
            _digestOf(address(tok), a1, 1, uid)
        ];
        string[4] memory what = ["another token", "another epoch", "another word", "another signer"];
        for (uint256 i; i < 4; ++i) {
            uint8 seed = i == 3 ? 12 : 11; // a2's key and signature, else a1's
            _acceptOnly(seed, signed[i]);
            IUARegistry.UASig memory c;
            c.signature = _sigOf(seed);
            vm.prank(holder);
            vm.expectRevert(refusal);
            tok.setAuditorUA(a1, 1, c, uid);
            assertEq(_status(), 0, what[i]);
        }
        _acceptOnly(11, signed[3]);
        IUARegistry.UASig memory ok;
        ok.signature = _sigOf(11);
        vm.prank(holder);
        tok.setAuditorUA(a1, 1, ok, uid);
        assertEq(_status(), 1, "proposed");
        vm.warp(block.timestamp + 1 days);
        vm.prank(holder);
        tok.setAuditorUA(a1, 1, ok, uid);
        assertEq(tok.auditorUA(), a1, "applied");
    }

    /// The typed `AuditorConsent` of `ua` for `epoch` and `word` under `t`'s domain.
    function _digestOf(address t, bytes32 ua, uint32 epoch, bytes32 word) internal view returns (bytes32) {
        return MessageHashUtils.toTypedDataHash(_sepOf(t), keccak256(abi.encode(CONSENT_TYPEHASH, t, ua, epoch, word)));
    }

    /// A filler ML-DSA-65 signature that names its key's seed.
    function _sigOf(uint8 seed) internal pure returns (bytes memory sig) {
        sig = new bytes(ML65_SIG);
        sig[0] = bytes1(seed);
    }

    /// The mocked ML-DSA-65 precompile answers 1 for exactly `_mlPk(seed) ‖ _sigOf(seed) ‖ pq_msg(d)`, the consent of `d`
    /// signed by the key `seed`, and 0 for every other input.
    function _acceptOnly(uint8 seed, bytes32 d) internal {
        vm.clearMockedCalls();
        _mockOps();
        vm.mockCall(ML65, bytes(""), abi.encode(uint256(0)));
        bytes32 pq = keccak256(
            abi.encodePacked(
                PqUA.tag(UAKinds.MLDSA65), UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_AUDITOR_CONSENT, d)
            )
        );
        vm.mockCall(ML65, abi.encodePacked(_mlPk(seed), _sigOf(seed), pq), abi.encode(uint256(1)));
    }

    /// `clearMockedCalls` drops the fixture's mocked precompiles too: put them back.
    function _mockOps() internal {
        (bytes memory valid, bytes memory invalid) = _mockMlDsa();
        (valid, invalid);
        for (uint8 op = 1; op <= 5; ++op) {
            if (op != 3) _mockOp(op, 1);
        }
        vm.mockCall(PQZ, abi.encodePacked(uint8(3)), abi.encode(uint256(1)));
    }

    /// `PRECOMPILE`: a UA without a PQZ key is refused at the proposal; a key that becomes unusable before the apply is refused
    /// there (spec T8: a FULL token is never left with an auditor its transfers refuse).
    function test_precompile_keyCheckedAtBothSteps() public {
        _go(1 days, 0);
        (IUARegistry.UASig memory c, bytes32 uid) = (_pqAuth(), _uid());
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, plain));
        tok.setAuditorUA(plain, 1, c, uid);
        _set(holder, a1, 1);
        vm.warp(block.timestamp + 1 days);
        vm.mockCall(
            address(reg),
            abi.encodeCall(IUARegistry.pqzKeyOf, (a1)),
            abi.encode(uint64(0), address(0), bytes32(0), false)
        );
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, a1));
        tok.setAuditorUA(a1, 1, c, uid);
        vm.clearMockedCalls();
        _mockOps();
        _set(holder, a1, 1);
        assertEq(tok.auditorUA(), a1);
    }

    /// `offchain-token` (with the opening): the new auditor needs its key of this token, proven (the fixture's registry has
    /// the `0x0142` verifier) and with its opening KEM key; each missing piece refused, then the control.
    function test_offchainToken_keyProvenKem() public {
        notice = 0;
        _offStack();
        a1 = _pqzUA(_pk(41), 11);
        (vMode, vUA, vOwnKey, vOpening) = (PqzCore.OFFCHAIN, vA, true, true);
        tok = _newToken("aud-off");
        (vMode, vUA, vOwnKey, vOpening) = (0, bytes32(0), false, false);
        _grant(holder);
        (IUARegistry.UASig memory c, bytes32 uid) = (_pqAuth(), _uid());
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, a1));
        tok.setAuditorUA(a1, 1, c, uid); // no record of this token
        uint64 v = _scopedOn(reg, a1, address(tok), _spk(++keySeed), true, false);
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, a1));
        tok.setAuditorUA(a1, 1, c, uid); // stored, not proven, on a registry with the verifier
        reg.storePqzScopedPop(a1, address(tok), v, hex"aa");
        IUARegistry.KemKey memory none;
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.pqzOpenKemAt, (a1, address(tok), v)), abi.encode(none));
        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.AccountNotRegistered.selector, a1));
        tok.setAuditorUA(a1, 1, c, uid); // no opening KEM key
        vm.clearMockedCalls();
        _mockOps();
        _mockOp(7, 1);
        _set(holder, a1, 1);
        assertEq(tok.auditorUA(), a1, "proven, with its KEM key: applied (delay 0)");
    }

    /// The A4 ruling both ways: on a registry WITHOUT the `0x0142` verifier an unproven key of the token's scope is accepted
    /// (no proven check there; the T3 residual), while the consent is still required.
    function test_offchainToken_noVerifier_unprovenAccepted() public {
        notice = 0;
        _offStack();
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, address(mlv), 200_000);
        UARegistry r2 = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
        OpenFactory f2 = new OpenFactory(nid(registrar));
        EnvKit.configure(f2, PQZ_UID, 0, address(0));
        Catalogue.release(
            f2,
            IOpenFactory.TokenKind.NORMAL_PQZ,
            1,
            pqzEnv(address(f2), PQZ_UID, address(r2), address(0)),
            type(NormalPqzToken).creationCode
        );
        vm.prank(registrar);
        f2.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f2)));
        bytes32 audR = UACall.register(r2, UAKinds.MLDSA65, _mlPk(21), UACall.attrs("", 0, ""), new bytes(ML65_SIG), "");
        bytes32 newR = UACall.register(r2, UAKinds.MLDSA65, _mlPk(22), UACall.attrs("", 0, ""), new bytes(ML65_SIG), "");
        (vMode, vUA, vOwnKey) = (PqzCore.OFFCHAIN, vA, true);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (vMode, vUA, vOwnKey) = (0, bytes32(0), false);
        c.conf.auditorKey = abi.encode(audR);
        tok = NormalPqzToken(f2.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "noverifier-aud"));
        assertFalse(r2.kindEnabled(UAKinds.PQZ_MLWE), "no 0x0142 verifier");
        _grant(holder);
        _scopedOn(r2, newR, address(tok), _spk(++keySeed), false, true);
        (,,, bool proven) = r2.pqzScopedKeyOf(newR, address(tok));
        assertFalse(proven, "never proven without the verifier");
        bytes32 d = _digest(tok, newR, 1);
        IUARegistry.UASig memory s = _pqAuth();
        vm.expectCall(
            address(r2), abi.encodeCall(IUARegistry.requireAuthorized, (newR, UAKinds.PURPOSE_AUDITOR_CONSENT, d, s))
        );
        _set(holder, newR, 1);
        assertEq(tok.auditorUA(), newR, "accepted unproven");
    }

    /// A stranger's shield into the proposed UA does not block the apply (consent replaced the account-state check).
    function test_strangerShield_doesNotBlock() public {
        _go(1 days, 0);
        _set(holder, a1, 1);
        _fund(tok, a1, 1);
        vm.warp(block.timestamp + 1 days);
        _set(holder, a1, 1);
        assertEq(tok.auditorUA(), a1);
    }

    // ------------------------------------------------------------------ epochs per entry and the AUDITOR disclosure

    /// `entryAuditorEpoch[ref]`'s slot (`PqzStorage` slot 26).
    function _epochSlot(bytes32 ref) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(ref, uint256(0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521500) + 26));
    }

    function _notWritten(bytes32 ref) internal {
        (, bytes32[] memory writes) = vm.accesses(address(tok));
        for (uint256 i; i < writes.length; ++i) {
            assertTrue(writes[i] != _epochSlot(ref), "entryAuditorEpoch written");
        }
    }

    /// Epoch 0 writes nothing; at epoch 1 an audited op 1 writes 1 and an opt-out writes nothing; three epochs, the
    /// `AUDITOR` disclosure statement of each entry carries its own epoch's auditor key.
    function test_epochs_op1_and_disclosure() public {
        _go(0, 0);
        _fund(tok, alice, 100);
        _roll(tok, alice, 1);
        vm.record();
        (bytes32 r0,) = _transfer(tok, alice, bob, 0, 101, true);
        _notWritten(r0);
        _set(holder, a1, 1);
        (bytes32 r1,) = _transfer(tok, alice, bob, 0, 102, true);
        assertEq(uint256(vm.load(address(tok), _epochSlot(r1))), 1);
        vm.record();
        (bytes32 out,) = _transfer(tok, alice, bob, 0, 103, false);
        _notWritten(out);
        assertEq(tok.auditorUAOf(out), aud, "opt-out: epoch 0's auditor");
        _set(holder, a2, 2);
        (bytes32 r2,) = _transfer(tok, alice, bob, 0, 104, true);
        assertEq(uint256(vm.load(address(tok), _epochSlot(r2))), 2);
        assertEq(tok.auditorUAOf(r0), aud);
        assertEq(tok.auditorUAOf(r1), a1);
        assertEq(tok.auditorUAOf(r2), a2);
        bytes[3] memory keys = [_cut(txStmt, 640 + 2 * PqzCt.PK, PqzCt.PK), _pk(41), _pk(42)];
        bytes32[3] memory refs = [r0, r1, r2];
        for (uint256 i; i < 3; ++i) {
            bytes memory st = tok.disclosureStatement(refs[i], 0, 7, 2, 0);
            assertEq(_cut(st, 288, PqzCt.PK), keys[i], "the AUDITOR statement names the entry's epoch auditor");
        }
    }

    /// Op 7 with the auditor at epoch 1 writes 1.
    function test_epoch1_op7_writes() public {
        _go(0, 0);
        _fund(tok, alice, 100);
        _roll(tok, alice, 1);
        _set(holder, a1, 1);
        bytes32[] memory rec = new bytes32[](2);
        (rec[0], rec[1]) = (bob, carol);
        bytes memory pl = _mpayload(
            tok.pqzAccount(alice, 0).pendingCount, 0, alice, bytes32(0), rec, _blob(201, _outLen(2, true)), ""
        );
        _mockOp(7, 1);
        bytes32 ref = tok.mtxConfidentialTransfer(_ms(pl), hex"c0de", _pqAuth(), "", noVerdict());
        assertEq(uint256(vm.load(address(tok), _epochSlot(ref))), 1);
        assertEq(tok.auditorUAOf(ref), a1);
    }
}

/// Plan A4 step 3 (spec §7, A14 of the review): op 7 M = 8 (BUNDLE, the auditor on, a fee), the cell nearest the EIP-7825
/// cap of the plain gas table, at auditor epoch 0 and at epoch 1 on the same state, each its own transaction: epoch 1 writes
/// one new slot (`entryAuditorEpoch`), epoch 0 none; the regular gas of both stays within the cap less 1 % (forge does not
/// enforce the cap: asserted from the reported gas). The precompile is mocked: its schedule gas is not included, as in
/// `PqzStateGas`. Logged per set (`at-set.sh`).
/// forge-config: default.isolate = true
contract PqzAuditorGasTest is PqzOffchainBase {
    uint256 internal constant TX_CAP = 1 << 24;
    bytes32[8] internal xs;
    bytes32 internal a1;

    function _cfg(uint256 maxShielded) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = super._cfg(maxShielded);
        c.features |= uint256(1) << 32;
        (c.admin, c.lockedFeatures) = (nid(address(this)), 0);
    }

    function setUp() public {
        vm.pauseGasMetering();
        _stack();
        _mockOp(7, 1);
        tok = _newToken("aud-gas");
        for (uint8 i; i < 8; ++i) {
            xs[i] = _pqzUA(_pk(20 + i), 20 + i);
        }
        a1 = _pqzUA(_pk(41), 41);
        _transfer(tok, carol, bob, bytes32(0), 1, true); // carol's acc: a fresh blob reference
        _public(tok, address(this), 1000 * SCALE);
        _fund(tok, _pqzUA(_pk(12), 12), 100); // the pool holds the fee the debit pays out
        IGovernance(address(tok)).grantRole(32, nid(address(this)), EnvKit.codeUidOf(address(tok)));
        vm.resumeGasMetering();
    }

    function _op7() internal view returns (bytes memory) {
        bytes memory r;
        for (uint256 j; j < 8; ++j) {
            r = bytes.concat(r, xs[j]);
        }
        return abi.encodeCall(
            IPqzToken.mtxConfidentialTransfer,
            (
                _ms(
                    bytes.concat(
                        abi.encode(uint256(0), block.number + 100, uint256(0), carol, alice, uint256(8), uint256(0)),
                        salt,
                        r,
                        _blob(89, _outLen(8, true))
                    )
                ),
                hex"c0de",
                _pqAuth(),
                "",
                noVerdict()
            )
        );
    }

    function _measure(bytes memory cd) internal returns (uint256 reg, uint256 st) {
        (bool ok,) = address(tok).call{gas: TX_CAP + 80_000_000}(cd);
        assertTrue(ok, "settles");
        Vm.Gas memory g = vm.lastCallGas();
        (reg, st) = (g.gasTotalUsed, uint256(int256(g.gasStateUsed)));
    }

    function test_gas_op7_M8_epochs() public {
        bytes memory cd = _op7();
        uint256 snap = vm.snapshotState();
        (uint256 r0, uint256 s0) = _measure(cd);
        vm.revertToState(snap);
        tok.setAuditorUA(a1, 1, _pqAuth(), EnvKit.codeUidOf(address(tok)));
        (uint256 r1, uint256 s1) = _measure(_op7());
        console2.log(
            string.concat("op 7 M = 8 BUNDLE, auditor, fee, at ", PqzSet.NAME, ": epoch 0 regular / state"), r0, s0
        );
        console2.log(
            string.concat("op 7 M = 8 BUNDLE, auditor, fee, at ", PqzSet.NAME, ": epoch 1 regular / state"), r1, s1
        );
        assertLe(r0, TX_CAP - TX_CAP / 100, "epoch 0: within the cap less 1 %");
        assertLe(r1, TX_CAP - TX_CAP / 100, "epoch 1: within the cap less 1 %");
        assertGt(r1 + s1, r0 + s0, "epoch 1 writes the entry's epoch");
    }
}
