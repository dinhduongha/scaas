// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterTypes} from "../../src/governance/GovernanceRouterBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UACall} from "../ua/UACall.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {PQZ_UID} from "./helpers/PqzRegistryBase.sol";
import {MockERC20} from "../helpers/Mocks.sol";

/// Group 3f, T45 (PQZ verifier mode spec §5.3, §5.4, §4.2; CTR-PQZ-29 draft): the verdict on every proof-carrying entry of
/// kinds 4 and 5 (direct and signed: transfer, compact, single, single compact, unshield, refresh, unshield-unwrap), in both
/// modes; the signed forms' typehashes unchanged (the verdict outside the struct); a relayer's verdict swap; the disclosure
/// with and without a verdict; the three router ops; the allow-lists. The signed forms' subject is the derived `dId`
/// (`mldsa65`, its precompile mocked: the registry path is real) or, where a typehash is the point, the native `nKey`
/// (real ECDSA over the pre-3f type string). UNAUDITED.
contract PqzOffchainEntriesTest is PqzOffchainBase {
    uint256 internal constant LANE = 7;
    uint256 internal constant NKEY = 0x5161E5;
    bytes32 internal dId;
    bytes32 internal nId;
    NormalPqzToken internal off;
    WrappedPqzToken internal w; // PRECOMPILE wrapped
    WrappedPqzToken internal offW; // OFFCHAIN wrapped
    bytes32 internal constant TO = bytes32(uint256(0xD00D));

    function setUp() public {
        _offStack();
        _releaseWrapped();
        tok = _newToken("e-pre");
        off = _offToken("e-off", vA, false);
        w = _newWrapped("e-wpre");
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, vA, false);
        offW = _newWrapped("e-woff");
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        dId = _mldsaUA(9);
        nId = nid(vm.addr(NKEY));
        _shieldOn(tok, alice, 1000);
        _shieldOn(off, alice, 1000);
        _wrapShield(w, 1000);
        _wrapShield(offW, 1000);
    }

    function _wrapShield(WrappedPqzToken t, uint256 units) internal {
        MockERC20 u = MockERC20(t.underlyings()[0]);
        u.mint(address(this), units * SCALE);
        u.approve(address(t), units * SCALE);
        t.mtxWrapShield(address(u), units * SCALE, alice);
    }

    // ------------------------------------------------------------------ the envelope of a signed form

    function _u(bytes32 from, address t) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(from, LANE, NormalPqzToken(t).mtxNonce(from, LANE), block.timestamp + 300, 0, address(0), 0,
            address(0));
    }

    /// The merged entries' statement binding (CTR-PQZ-21, R36), computed here.
    function _tag(address t, MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-PQZ-UA-ENVELOPE-V1"), block.chainid, IMetaTx(t).chainUid(), t, u.from, u.batch),
            abi.encode(u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
    }

    function _dAuth() internal view returns (IUARegistry.UASig memory) {
        return UACall.auth(dId, _mlAuth());
    }

    // ------------------------------------------------------------------ every entry, both forms, both modes

    uint8 internal constant SINGLE = 0;
    uint8 internal constant SINGLE_COMPACT = 1;
    uint8 internal constant MULTI = 2;
    uint8 internal constant COMPACT = 3;
    uint8 internal constant UNSHIELD = 4;
    uint8 internal constant REFRESH = 5;
    uint8 internal constant UNWRAP = 6;

    function _p(NormalPqzToken t) internal view returns (uint256) {
        return t.pqzAccount(alice, 0).pendingCount;
    }

    function _singleA(NormalPqzToken t, bool compact) internal view returns (IPqzToken.PqzTransferArgs memory) {
        return _ts(_payload(_p(t), 0, alice, bob, bytes32(0), _out(11, false), compact ? _memo() : bytes("")));
    }

    function _multiA(NormalPqzToken t, bool compact) internal view returns (IPqzToken.PqzMultiArgs memory) {
        bytes32[] memory legs = new bytes32[](2);
        (legs[0], legs[1]) = (bob, carol);
        bytes memory memo = compact ? bytes.concat(salt, _slice(_blob(0x3e31, 352), 0, 2 + 40 * 2)) : bytes("");
        return _ms(_mpayload(_p(t), 0, alice, bytes32(0), legs, _blob(13, _outLen(2, false)), memo));
    }

    function _burnA(NormalPqzToken t) internal view returns (IPqzToken.PqzBurnArgs memory) {
        return _bs(bytes.concat(abi.encode(_p(t), block.number + 50, uint256(0), alice, bytes32(0)), _blob(14, PqzCt.CT)));
    }

    function _unwrapX(NormalPqzToken t) internal view returns (IConfidentialWrappedToken.Unwrap memory) {
        return IConfidentialWrappedToken.Unwrap(WrappedPqzToken(payable(address(t))).underlyings()[0], TO, 10, 10 * SCALE);
    }

    /// The statement entry `op` builds on `t` under binding `b` (0: direct).
    function _stmt(uint8 op, NormalPqzToken t, bytes32 b) internal view returns (bytes memory) {
        if (op == SINGLE || op == SINGLE_COMPACT) return t.transferSingleStatement(_singleA(t, op == SINGLE_COMPACT), b);
        if (op == MULTI || op == COMPACT) return t.transferStatement(_multiA(t, op == COMPACT), b);
        if (op == UNSHIELD) return t.burnStatement(_burnA(t), 5, TO, b);
        if (op == REFRESH) return t.burnStatement(_burnA(t), 0, 0, b);
        return WrappedPqzToken(payable(address(t))).unshieldUnwrapStatement(_burnA(t), _unwrapX(t), b);
    }

    /// The calldata of entry `op` on `t` (direct, or signed in envelope `u` by `dId`) with verdict `sv`.
    function _cd(uint8 op, NormalPqzToken t, MetaTxLib.UAEnvelope memory u, bool signed, IPqzToken.PqzSignedVerdict memory sv)
        internal view returns (bytes memory)
    {
        IUARegistry.UASig memory pa = _pqAuth();
        if (op == SINGLE || op == SINGLE_COMPACT) {
            IPqzToken.PqzTransferArgs memory a = _singleA(t, op == SINGLE_COMPACT);
            if (!signed) {
                return op == SINGLE ? abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (a, VPROOF, pa, "", sv))
                    : abi.encodeCall(IPqzToken.mtxConfidentialTransferSingleCompact, (a, VPROOF, pa, "", sv));
            }
            return abi.encodeWithSignature(string.concat(op == SINGLE ? "mtxConfidentialTransferSingle" :
                "mtxConfidentialTransferSingleCompact", SIG_SINGLE), u, a, VPROOF, pa, bytes(""), _dAuth(), sv);
        }
        if (op == MULTI || op == COMPACT) {
            IPqzToken.PqzMultiArgs memory m = _multiA(t, op == COMPACT);
            if (!signed) {
                return op == MULTI ? abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (m, VPROOF, pa, "", sv))
                    : abi.encodeCall(IPqzToken.mtxConfidentialTransferCompact, (m, VPROOF, pa, "", sv));
            }
            return abi.encodeWithSignature(string.concat(op == MULTI ? "mtxConfidentialTransfer" :
                "mtxConfidentialTransferCompact", SIG_MULTI), u, m, VPROOF, pa, bytes(""), _dAuth(), sv);
        }
        IPqzToken.PqzBurnArgs memory bb = _burnA(t);
        if (op == UNSHIELD || op == REFRESH) {
            (uint256 amt, bytes32 rcp) = op == UNSHIELD ? (uint256(5), TO) : (uint256(0), bytes32(0));
            if (!signed) return abi.encodeCall(IPqzToken.mtxUnshield, (bb, amt, rcp, VPROOF, pa, "", sv));
            return abi.encodeWithSignature(string.concat("mtxUnshield", SIG_UNSHIELD), u, bb, IPqzToken.Payout(amt, rcp),
                VPROOF, pa, bytes(""), _dAuth(), sv);
        }
        IConfidentialWrappedToken.Unwrap memory x = _unwrapX(t);
        if (!signed) return abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (bb, x, VPROOF, pa, "", sv));
        return abi.encodeWithSignature(string.concat("mtxUnshieldUnwrap", SIG_UNWRAP), u, bb, x, VPROOF, pa, bytes(""),
            _dAuth(), sv);
    }

    string internal constant ENV_T = "(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
    string internal constant SIG_T = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
    string internal constant VERDICT_T =
        "((address,uint256,bytes32,bytes32,bytes32,uint32,uint64),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))";
    string internal constant TARGS_T =
        "(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes32,bytes16,bytes32,bytes,bytes,bytes,bytes,bytes)";
    string internal constant MARGS_T =
        "(uint64,uint256,uint256,bytes32,uint64,bytes32,uint256,bytes16,bytes32,bytes[],(bytes32,bytes,bytes)[],bytes,bytes)";
    string internal constant BARGS_T = "(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes32,bytes,bytes)";
    string internal SIG_SINGLE = string.concat("(", ENV_T, ",", TARGS_T, ",bytes,", SIG_T, ",bytes,", SIG_T, ",", VERDICT_T, ")");
    string internal SIG_MULTI = string.concat("(", ENV_T, ",", MARGS_T, ",bytes,", SIG_T, ",bytes,", SIG_T, ",", VERDICT_T, ")");
    string internal SIG_UNSHIELD = string.concat("(", ENV_T, ",", BARGS_T, ",(uint256,bytes32),bytes,", SIG_T, ",bytes,", SIG_T,
        ",", VERDICT_T, ")");
    string internal SIG_UNWRAP = string.concat("(", ENV_T, ",", BARGS_T, ",(address,bytes32,uint256,uint256),bytes,", SIG_T,
        ",bytes,", SIG_T, ",", VERDICT_T, ")");

    /// Runs entry `op` on the matching token (direct, or signed by `dId`): an OFFCHAIN token with the verifier's verdict, after
    /// the same call with the empty verdict is refused; a PRECOMPILE token with the empty verdict (the precompile mocked 1).
    function _entry(uint8 op, bool signed, bool offchain) internal {
        NormalPqzToken t = NormalPqzToken(op == UNWRAP ? address(offchain ? offW : w) : address(offchain ? off : tok));
        MetaTxLib.UAEnvelope memory u = _u(dId, address(t));
        bytes memory st = _stmt(op, t, signed ? _tag(address(t), u) : bytes32(0));
        if (offchain) {
            (bool bad, bytes memory err) = address(t).call(_cd(op, t, u, signed, noVerdict()));
            assertFalse(bad, "OFFCHAIN without a verdict");
            assertEq(bytes4(err), IPqzToken.PqzVerdictMismatch.selector, "the empty verdict's token is 0");
        }
        if (offchain) {
            vm.expectEmit(address(t));
            emit IPqzToken.PqzVerified(keccak256(st), keccak256(VPROOF), vA, 0);
        }
        (bool ok, bytes memory ret) = address(t).call(_cd(op, t, u, signed, offchain ? _sv(t, st) : noVerdict()));
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function test_entry_transfer_direct_offchain() public { _entry(MULTI, false, true); }
    function test_entry_transfer_signed_offchain() public { _entry(MULTI, true, true); }
    function test_entry_compact_direct_offchain() public { _entry(COMPACT, false, true); }
    function test_entry_compact_signed_offchain() public { _entry(COMPACT, true, true); }
    function test_entry_single_direct_offchain() public { _entry(SINGLE, false, true); }
    function test_entry_single_signed_offchain() public { _entry(SINGLE, true, true); }
    function test_entry_singleCompact_direct_offchain() public { _entry(SINGLE_COMPACT, false, true); }
    function test_entry_singleCompact_signed_offchain() public { _entry(SINGLE_COMPACT, true, true); }
    function test_entry_unshield_direct_offchain() public { _entry(UNSHIELD, false, true); }
    function test_entry_unshield_signed_offchain() public { _entry(UNSHIELD, true, true); }
    function test_entry_refresh_direct_offchain() public { _entry(REFRESH, false, true); }
    function test_entry_refresh_signed_offchain() public { _entry(REFRESH, true, true); }
    function test_entry_unshieldUnwrap_direct_offchain() public { _entry(UNWRAP, false, true); }
    function test_entry_unshieldUnwrap_signed_offchain() public { _entry(UNWRAP, true, true); }

    function test_entry_transfer_direct_precompile() public { _entry(MULTI, false, false); }
    function test_entry_transfer_signed_precompile() public { _entry(MULTI, true, false); }
    function test_entry_compact_direct_precompile() public { _entry(COMPACT, false, false); }
    function test_entry_compact_signed_precompile() public { _entry(COMPACT, true, false); }
    function test_entry_single_direct_precompile() public { _entry(SINGLE, false, false); }
    function test_entry_single_signed_precompile() public { _entry(SINGLE, true, false); }
    function test_entry_singleCompact_direct_precompile() public { _entry(SINGLE_COMPACT, false, false); }
    function test_entry_singleCompact_signed_precompile() public { _entry(SINGLE_COMPACT, true, false); }
    function test_entry_unshield_direct_precompile() public { _entry(UNSHIELD, false, false); }
    function test_entry_unshield_signed_precompile() public { _entry(UNSHIELD, true, false); }
    function test_entry_refresh_direct_precompile() public { _entry(REFRESH, false, false); }
    function test_entry_refresh_signed_precompile() public { _entry(REFRESH, true, false); }
    function test_entry_unshieldUnwrap_direct_precompile() public { _entry(UNWRAP, false, false); }
    function test_entry_unshieldUnwrap_signed_precompile() public { _entry(UNWRAP, true, false); }

    // ------------------------------------------------------------------ the signed struct, the relayer

    /// The native subject signs `UAPqzTransferSingle` over the pre-3f type string (legacy/ua-mtx-merge/3f/src/pqz/
    /// PqzLayer.sol; group 3h T59: with `bytes32 ownTag` after `salt`, the one change since), the words `hashTransfer(args) ‖ keccak(proof) ‖ keccak(accHint)`: accepted, so no typehash moved and the
    /// verdict is outside the struct; then a relayer swaps the verdict for another valid one over the same hashes (a
    /// later `validUntil`): the same signature lands (unbound, like `relayer`).
    function test_signedForms_typehashesUnchanged() public {
        _public(off, vm.addr(NKEY), 0);
        IPqzToken.PqzTransferArgs memory a = _singleA(off, false);
        MetaTxLib.UAEnvelope memory u = _u(nId, address(off));
        bytes memory st = off.transferSingleStatement(a, _tag(address(off), u));
        bytes32 th = keccak256(
            "UAPqzTransferSingle(bytes32 from,PqzTransferArgs args,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzTransferArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes32 ownTag,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo)");
        bytes32 sh = keccak256(bytes.concat(abi.encode(th, u.from), abi.encode(_hashT(a), keccak256(VPROOF), keccak256("")),
            abi.encode(u.batch, u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
        (uint8 vv, bytes32 r, bytes32 ss) = vm.sign(NKEY, MessageHashUtils.toTypedDataHash(_sepOf(address(off)), sh));
        IUARegistry.UASig memory auth;
        auth.signature = abi.encodePacked(r, ss, vv);
        IPqzToken.PqzSignedVerdict memory sv1 = _sv(off, st);
        IPqzToken.PqzVerdict memory v2 = _verdict(off, st, VPROOF);
        v2.validUntil += 1000;
        IPqzToken.PqzSignedVerdict memory sv2 = _sign(off, VKEY, v2);
        bytes memory c1 = abi.encodeWithSignature(string.concat("mtxConfidentialTransferSingle", SIG_SINGLE), u, a, VPROOF,
            _pqAuth(), bytes(""), auth, sv1);
        bytes memory c2 = abi.encodeWithSignature(string.concat("mtxConfidentialTransferSingle", SIG_SINGLE), u, a, VPROOF,
            _pqAuth(), bytes(""), auth, sv2);
        uint256 snap = vm.snapshotState();
        vm.prank(address(0x4E1A));
        (bool ok,) = address(off).call(c1);
        assertTrue(ok, "the pre-3f struct (3h: + ownTag), verdict 1");
        vm.revertToState(snap);
        vm.prank(address(0x4E1A));
        (ok,) = address(off).call(c2);
        assertTrue(ok, "the relayer's verdict 2, the same auth");
    }

    /// A relayer's swap to an invalid verdict only refuses the call (the nonce stays): harmless.
    function test_pqzVerdictSwapByRelayer_harmless() public {
        IPqzToken.PqzTransferArgs memory a = _singleA(off, false);
        MetaTxLib.UAEnvelope memory u = _u(dId, address(off));
        bytes memory st = off.transferSingleStatement(a, _tag(address(off), u));
        IPqzToken.PqzSignedVerdict memory bad = _sign(off, VKEY2, _verdict(off, st, VPROOF));
        (bool ok,) = address(off).call(_cdSingle(u, a, bad));
        assertFalse(ok, "another signer's verdict");
        assertEq(off.mtxNonce(dId, LANE), u.nonce, "the nonce not spent");
        (ok,) = address(off).call(_cdSingle(u, a, _sv(off, st)));
        assertTrue(ok);
    }

    function _cdSingle(MetaTxLib.UAEnvelope memory u, IPqzToken.PqzTransferArgs memory a, IPqzToken.PqzSignedVerdict memory sv)
        internal view returns (bytes memory)
    {
        return abi.encodeWithSignature(string.concat("mtxConfidentialTransferSingle", SIG_SINGLE), u, a, VPROOF, _pqAuth(),
            bytes(""), _dAuth(), sv);
    }

    // ------------------------------------------------------------------ disclosure (spec §5.4)

    function _disclose6(NormalPqzToken t, bytes32 ref, uint256 amount) internal view returns (bool) {
        return t.verifyTransferAmount(ref, 0, amount, 1, 0, VPROOF);
    }

    function _disclose8(NormalPqzToken t, bytes32 ref, uint256 amount, IPqzToken.PqzSignedVerdict memory sv)
        internal view returns (bool)
    {
        return t.verifyTransferAmount(ref, 0, amount, 1, 0, VPROOF, sv);
    }

    /// A transfer on `off` to bob; its entry and bob's disclosure statement for `amount`.
    function _sent(uint256 amount) internal returns (bytes32 ref, bytes memory st) {
        IPqzToken.PqzTransferArgs memory a = _singleA(off, false);
        ref = off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", _sv(off, off.transferSingleStatement(a, 0)));
        st = off.disclosureStatement(ref, 0, amount, 1, 0);
    }

    function test_disclosure_fiveArgCannotVerify() public {
        (bytes32 ref,) = _sent(7);
        vm.expectRevert(IPqzToken.PqzVerdictRequired.selector);
        _disclose6(off, ref, 7);
        // PRECOMPILE: the precompile's answer, the verdict form ignoring the verdict
        (IPqzToken.PqzTransferArgs memory a) = _singleA(tok, false);
        bytes32 r2 = tok.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", noVerdict());
        assertTrue(_disclose6(tok, r2, 7));
        assertTrue(_disclose8(tok, r2, 7, noVerdict()));
    }

    function test_disclosure_sevenArgTrue() public {
        (bytes32 ref, bytes memory st) = _sent(7);
        assertTrue(_disclose8(off, ref, 7, _sv(off, st)));
        assertFalse(_disclose8(off, ref, 7, noVerdict()), "no verdict: false");
        assertFalse(off.verifyTransferAmount(ref, 0, 7, 1, 0, "", _sv(off, st)), "empty proof: false");
    }

    /// A verdict for 7 does not disclose 8, nor another leg or kind.
    function test_disclosure_sevenArgWrongAmount() public {
        (bytes32 ref, bytes memory st) = _sent(7);
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        assertFalse(_disclose8(off, ref, 8, sv), "amount");
        assertFalse(off.verifyTransferAmount(ref, 0, 7, 0, 0, VPROOF, sv), "kind");
        assertFalse(off.verifyTransferAmount(ref, 1, 7, 1, 0, VPROOF, sv), "no leg 1");
    }

    function test_disclosure_sevenArgRevoked() public {
        IFactoryToken.TokenConfig memory c;
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, vA, false);
        c = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        c.admin = nid(address(this));
        off = NormalPqzToken(factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "e-owned"));
        _shieldOn(off, alice, 100);
        (bytes32 ref, bytes memory st) = _sent(7);
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        assertTrue(_disclose8(off, ref, 7, sv));
        off.pqzRevokeVerifier(EnvKit.codeUidOf(address(off)));
        assertFalse(_disclose8(off, ref, 7, sv), "revoked: false");
    }

    // ------------------------------------------------------------------ the router ops (spec §4.2)

    /// The three ops relayed through a router at fee 0 for the owner `nId` (its own key, no registry call).
    function test_router_pqzVerifierOps() public {
        GovernanceRouter router = new GovernanceRouter(PQZ_UID, address(reg), address(0), false);
        OpenFactory f = new OpenFactory(nid(registrar));
        EnvKit.configure(f, PQZ_UID, 0, address(router));
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(f), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f)));
        (vMode, vUA, vFixed) = (PqzCore.OFFCHAIN, vA, false);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        (vMode, vUA, vFixed) = (0, bytes32(0), false);
        c.admin = nId;
        NormalPqzToken t = NormalPqzToken(f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "e-router"));
        bytes32 tu = EnvKit.codeUidOf(address(t)); // the token's chain word, the ops' last field (CTR-GOV-28)
        _rop(router, GovernanceRouterTypes.UA_PQZ_SET_VERIFIER, address(t), abi.encode(vB, tu));
        assertEq(t.pqzVerifyConfig().verifier, vB, "notice 0: at once");
        _rop(router, GovernanceRouterTypes.UA_PQZ_CANCEL_VERIFIER, address(t), abi.encode(tu));
        _rop(router, GovernanceRouterTypes.UA_PQZ_REVOKE_VERIFIER, address(t), abi.encode(tu));
        assertEq(t.pqzVerifyConfig().verifier, 0, "revoked");
        assertEq(t.pqzVerifyConfig().pqzVerifierEpoch, 2);
    }

    function _rop(GovernanceRouter router, bytes32 th, address target, bytes memory args) internal {
        MetaTxLib.UAEnvelope memory u = MetaTxLib.UAEnvelope(nId, LANE, router.mtxNonce(nId, LANE), block.timestamp + 300, 0,
            address(0), 0, address(0));
        bytes32 sh = keccak256(bytes.concat(abi.encode(th, u.from), abi.encode(target), args,
            abi.encode(u.batch, u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
        (uint8 vv, bytes32 r, bytes32 ss) = vm.sign(NKEY, MessageHashUtils.toTypedDataHash(_sepOf(address(router)), sh));
        IUARegistry.UASig memory auth;
        auth.signature = abi.encodePacked(r, ss, vv);
        vm.prank(address(0x4E1A));
        if (th == GovernanceRouterTypes.UA_PQZ_SET_VERIFIER) {
            (bytes32 next, bytes32 cu) = abi.decode(args, (bytes32, bytes32));
            router.mtxPqzSetVerifier(u, target, next, cu, auth);
        } else if (th == GovernanceRouterTypes.UA_PQZ_CANCEL_VERIFIER) {
            router.mtxPqzCancelVerifier(u, target, abi.decode(args, (bytes32)), auth);
        } else {
            router.mtxPqzRevokeVerifier(u, target, abi.decode(args, (bytes32)), auth);
        }
    }

    // ------------------------------------------------------------------ the allow-lists (CTR-MTX-19)

    function _has(address t, bytes4 sel) internal view returns (bool found) {
        (bytes4[] memory s,,) = IMetaTx(t).mtxSelectors();
        for (uint256 i; i < s.length; ++i) if (s[i] == sel) found = true;
    }

    function _selectors(address t, bool wrapped) internal view {
        string memory v = string.concat(",bytes,", SIG_T, ",bytes,", VERDICT_T, ")");
        assertTrue(_has(t, bytes4(keccak256(bytes(string.concat("mtxConfidentialTransfer(", MARGS_T, v))))), "op 7");
        assertTrue(_has(t, bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferCompact(", MARGS_T, v))))), "compact");
        assertTrue(_has(t, bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferSingle(", TARGS_T, v))))), "op 1");
        assertTrue(_has(t, bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferSingleCompact(", TARGS_T, v))))));
        assertTrue(_has(t, bytes4(keccak256(bytes(string.concat("mtxUnshield(", BARGS_T, ",uint256,bytes32", v))))), "unshield");
        assertFalse(_has(t, bytes4(keccak256(bytes(string.concat("mtxConfidentialTransferSingle(", TARGS_T,
            ",bytes,", SIG_T, ",bytes)"))))), "the pre-3f op 1");
        if (wrapped) {
            assertTrue(_has(t, bytes4(keccak256(bytes(string.concat("mtxUnshieldUnwrap(", BARGS_T,
                ",(address,bytes32,uint256,uint256)", v))))), "unwrap");
        }
    }

    function test_mtxSelectors_pqzVerdict_4() public view {
        _selectors(address(tok), false);
        _selectors(address(off), false);
    }

    function test_mtxSelectors_pqzVerdict_5() public view {
        _selectors(address(w), true);
        _selectors(address(offW), true);
    }
}
