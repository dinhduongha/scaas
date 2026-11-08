// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {noVerdict} from "../pqz/helpers/PqzVerdicts.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {UACall} from "../ua/UACall.sol";
import {n, a, h, eJson, ecdsa} from "../metatx/NamedEntry.t.sol";
import {typedDigest, hexJson} from "../zether/ZetherTyped.t.sol";
import {PqzNamedBase, transferJson, multiJson, burnJson, T_TRANSFER, T_LEG, T_MULTI, T_BURN, T_UNWRAP} from "../pqz/PqzTyped.t.sol";
import {PqzPackedRef} from "../pqz/helpers/PqzPackedRef.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {PqzLayer} from "../../src/pqz/PqzLayer.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";

/// The merged PQZ entries of ua-mtx-merge T5 (R36), called by their own signatures: this file compiles on the tree before
/// T5 too, so each test is red there on its own (plan T5 step 3).
interface IPqzMergedT5 {
    function mtxShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxConfidentialTransfer(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzMultiArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth, IPqzToken.PqzSignedVerdict calldata pqzVerdict) external returns (bytes32);
    function mtxConfidentialTransferCompact(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzMultiArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth, IPqzToken.PqzSignedVerdict calldata pqzVerdict)
        external returns (bytes32);
    function mtxConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzTransferArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth, IPqzToken.PqzSignedVerdict calldata pqzVerdict)
        external returns (bytes32);
    function mtxConfidentialTransferSingleCompact(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzTransferArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth, IPqzToken.PqzSignedVerdict calldata pqzVerdict)
        external returns (bytes32);
    function mtxUnshield(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzBurnArgs calldata b, IPqzToken.Payout calldata p,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth, IPqzToken.PqzSignedVerdict calldata pqzVerdict)
        external returns (bytes memory);
    function mtxUnshieldUnwrap(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzBurnArgs calldata b,
        IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IUARegistry.UASig calldata auth, IPqzToken.PqzSignedVerdict calldata pqzVerdict) external returns (bytes memory);
    function mtxRollOver(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint256 n_, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxPrepareAcc(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint256 half, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function envelopeBinding(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32);
}

/// The retired forms (invariant 3): the address signed entries, the `ua*` names and the address binding view. After T5
/// no PQZ token serves these selectors.
interface IPqzOldT5 {
    function mtxShield(MetaTxLib.Envelope calldata e, bytes32 toUA, uint256 amount, bytes calldata sig)
        external returns (bytes memory);
    function mtxConfidentialTransfer(MetaTxLib.Envelope calldata e, IPqzToken.PqzMultiArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, bytes calldata sig) external returns (bytes32);
    function mtxConfidentialTransferCompact(MetaTxLib.Envelope calldata e, IPqzToken.PqzMultiArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, bytes calldata sig)
        external returns (bytes32);
    function mtxConfidentialTransferSingle(MetaTxLib.Envelope calldata e, IPqzToken.PqzTransferArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, bytes calldata sig)
        external returns (bytes32);
    function mtxConfidentialTransferSingleCompact(MetaTxLib.Envelope calldata e, IPqzToken.PqzTransferArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, bytes calldata sig)
        external returns (bytes32);
    function mtxUnshield(MetaTxLib.Envelope calldata e, IPqzToken.PqzBurnArgs calldata b, IPqzToken.Payout calldata p,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, bytes calldata sig)
        external returns (bytes memory);
    function mtxUnshieldUnwrap(MetaTxLib.Envelope calldata e, IPqzToken.PqzBurnArgs calldata b,
        IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, bytes calldata sig) external returns (bytes memory);
    function mtxRollOver(MetaTxLib.Envelope calldata e, bytes32 ua, uint256 n_, bytes calldata sig) external returns (bytes memory);
    function mtxPrepareAcc(MetaTxLib.Envelope calldata e, bytes32 ua, uint256 half, bytes calldata sig)
        external returns (bytes memory);
    function uaShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function uaConfidentialTransfer(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzMultiArgs calldata t, bytes calldata proof,
        IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth) external returns (bytes32);
    function uaConfidentialTransferCompact(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzMultiArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth)
        external returns (bytes32);
    function uaConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzTransferArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth)
        external returns (bytes32);
    function uaConfidentialTransferSingleCompact(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzTransferArgs calldata t,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth)
        external returns (bytes32);
    function uaUnshield(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzBurnArgs calldata b, IPqzToken.Payout calldata p,
        bytes calldata proof, IUARegistry.UASig calldata pqzAuth, bytes calldata accHint, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function uaUnshieldUnwrap(MetaTxLib.UAEnvelope calldata e, IPqzToken.PqzBurnArgs calldata b,
        IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, IUARegistry.UASig calldata pqzAuth,
        bytes calldata accHint, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function uaRollOver(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint256 n_, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function uaPrepareAcc(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint256 half, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    function uaEnvelopeBinding(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32);
}

/// T5: the PQZ pairs in today's `ua*` form under the `mtx*` name, for native and derived ids (R36). On every merged entry
/// a relayed proof binds `SCAAS-PQZ-UA-ENVELOPE-V1` over the `UAMetaTransaction` (`from` as `bytes32`), native subjects
/// included; `executeMetaTransaction` keeps `SCAAS-PQZ-ENVELOPE-V1` over its `MetaTransaction` (spec §2.1). Every binding
/// here is the spec formula computed in the test, never read from the token. The `PQZ` precompile is mocked to refuse every
/// statement of ops 1, 2, 7 but the one a test names, so a proof is "bound" to exactly one statement. Every relayed call is
/// at fee mode `NONE` by a relayer nobody bound (invariant 4). `tok` is `NORMAL_PQZ`, `w` `WRAPPED_PQZ` over `usd`; the
/// native subject is `signer` (ECDSA), the derived one `dId` (`mldsa65`, its precompile mocked).
contract PqzPairsTest is PqzNamedBase {
    address internal constant TO = address(0xD00D);
    bytes internal constant PROOF = hex"c0de";
    bytes32 internal nId;
    bytes32 internal dId;

    function setUp() public {
        _named();
        _fund(tok, alice, 1000);
        _wrapFund(alice, 100);
        _public(tok, signer, 100 * SCALE);
        nId = MetaTxLib.pad(signer);
        dId = _mldsaUA(9);
        NormalPqzToken(address(tok)).mintToUA(dId, 40 * SCALE);
        minted += 40 * SCALE;
        _mockOp(1, 0);
        _mockOp(2, 0);
        _mockOp(7, 0);
    }

    // ------------------------------------------------------------------ the envelope, the bindings, the signatures

    function _u(bytes32 from, address t) internal view returns (MetaTxLib.UAEnvelope memory u) {
        u = MetaTxLib.UAEnvelope(from, LANE, PqzLayer(t).mtxNonce(from, LANE), block.timestamp + 300, 0, address(0), 0, address(0));
    }

    /// CTR-PQZ-21 / R36: the merged entries' binding, `from` as `bytes32`.
    function _uaTag(address t, MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-PQZ-UA-ENVELOPE-V1"), block.chainid, IMetaTx(t).chainUid(), t, u.from, u.batch),
            abi.encode(u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
    }

    /// CTR-PQZ-21: `executeMetaTransaction`'s binding over the same fields, `from` an address.
    function _addrTag(address t, MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-PQZ-ENVELOPE-V1"), block.chainid, IMetaTx(t).chainUid(), t,
                address(uint160(uint256(u.from))), u.batch),
            abi.encode(u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
    }

    function _tag(address t, MetaTxLib.UAEnvelope memory u, bool ua) internal view returns (bytes32) {
        return ua ? _uaTag(t, u) : _addrTag(t, u);
    }

    /// What the subject of `u` signs over `primary` (a wallet's digest of the JSON it is handed); `fields` start with `from`.
    /// The derived subject's `mldsa65` signature is filler (its precompile mocked); the registry's path is real.
    function _auth(address t, MetaTxLib.UAEnvelope memory u, string memory primary, string memory fields, string memory nested,
        string memory op) internal view returns (IUARegistry.UASig memory s)
    {
        if (u.from != nId) return UACall.auth(u.from, _mlAuth());
        string memory m = string.concat('"from":', h(u.from), ',', op, ',', eJson(u.batch, u.nonce, u.validUntil, u.mode, u.fee));
        s.signature = ecdsa(PK, typedDigest(t, primary, fields, nested, m));
    }

    /// The precompile accepts exactly `st` with the test's proof (op `op`).
    function _accept(uint8 op, bytes memory st) internal {
        vm.mockCall(PQZ, abi.encodePacked(op, uint32(st.length), st, PROOF), abi.encode(uint256(1)));
    }

    function _go(address t, bytes memory cd) internal returns (bool ok, bytes memory ret) {
        vm.prank(relayer);
        (ok, ret) = t.call(cd);
    }

    // ------------------------------------------------------------------ each proof-carrying merged entry

    /// Op 1 by `from`, its proof bound to the UA tag (`ua`) or to the address tag of the same fields.
    function _singleCd(bytes32 from, bool compact, bool ua) internal returns (bytes memory) {
        MetaTxLib.UAEnvelope memory u = _u(from, address(tok));
        IPqzToken.PqzTransferArgs memory t = _ts(_sPl(tok, alice, true, compact ? _memo() : bytes(""), 50));
        _accept(1, tok.transferSingleStatement(t, _tag(address(tok), u, ua)));
        IUARegistry.UASig memory s = _auth(address(tok), u, compact ? "UAPqzTransferSingleCompact" : "UAPqzTransferSingle",
            _argFields(true, "PqzTransferArgs", ""), string.concat(',', T_TRANSFER), _argMsg(transferJson(t), "", PROOF, ""));
        return compact
            ? abi.encodeCall(IPqzMergedT5.mtxConfidentialTransferSingleCompact, (u, t, PROOF, _pqAuth(), "", s, noVerdict()))
            : abi.encodeCall(IPqzMergedT5.mtxConfidentialTransferSingle, (u, t, PROOF, _pqAuth(), "", s, noVerdict()));
    }

    /// Op 7, `M` = 2 (bob, carol), auditor on.
    function _multiCd(bytes32 from, bool compact, bool ua) internal returns (bytes memory) {
        MetaTxLib.UAEnvelope memory u = _u(from, address(tok));
        IPqzToken.PqzMultiArgs memory t = _ms(_mPl(tok, alice, _legsN(2), true, compact ? _mem(2) : bytes(""), 51));
        _accept(7, tok.transferStatement(t, _tag(address(tok), u, ua)));
        IUARegistry.UASig memory s = _auth(address(tok), u, compact ? "UAPqzTransferCompact" : "UAPqzTransfer",
            _argFields(true, "PqzMultiArgs", ""), string.concat(',', T_LEG, ',', T_MULTI), _argMsg(multiJson(t), "", PROOF, ""));
        return compact
            ? abi.encodeCall(IPqzMergedT5.mtxConfidentialTransferCompact, (u, t, PROOF, _pqAuth(), "", s, noVerdict()))
            : abi.encodeCall(IPqzMergedT5.mtxConfidentialTransfer, (u, t, PROOF, _pqAuth(), "", s, noVerdict()));
    }

    /// The burn of 5 to `TO`.
    function _unshieldCd(bytes32 from, bool ua) internal returns (bytes memory) {
        MetaTxLib.UAEnvelope memory u = _u(from, address(tok));
        IPqzToken.PqzBurnArgs memory b = _bs(_bPl(tok, alice, 52));
        IPqzToken.Payout memory p = IPqzToken.Payout(5, MetaTxLib.pad(TO));
        _accept(2, tok.burnStatement(b, p.amount, p.recipient, _tag(address(tok), u, ua)));
        IUARegistry.UASig memory s = _auth(address(tok), u, "UAPqzUnshield",
            _argFields(true, "PqzBurnArgs", '{"name":"amount","type":"uint256"},{"name":"recipient","type":"bytes32"},'),
            string.concat(',', T_BURN), _argMsg(burnJson(b), string.concat('"amount":', n(5), ',"recipient":', h(p.recipient), ','), PROOF, ""));
        return abi.encodeCall(IPqzMergedT5.mtxUnshield, (u, b, p, PROOF, _pqAuth(), "", s, noVerdict()));
    }

    /// The burn of 10 on `w`, leg `usd` paying 10 · SCALE to `TO`.
    function _unwrapCd(bytes32 from, bool ua) internal returns (bytes memory) {
        MetaTxLib.UAEnvelope memory u = _u(from, address(w));
        IPqzToken.PqzBurnArgs memory b = _bs(_bPl(w, alice, 53));
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(TO), 10, 10 * SCALE);
        _accept(2, w.unshieldUnwrapStatement(b, x, _tag(address(w), u, ua)));
        string memory xj = string.concat('"unwrap":{"underlying":', a(x.underlying), ',"recipient":', h(x.recipient), ',"amount":',
            n(x.amount), ',"minOut":', n(x.minOut), '},');
        IUARegistry.UASig memory s = _auth(address(w), u, "UAPqzUnshieldUnwrap",
            _argFields(true, "PqzBurnArgs", '{"name":"unwrap","type":"Unwrap"},'), string.concat(',', T_BURN, ',', T_UNWRAP),
            _argMsg(burnJson(b), xj, PROOF, ""));
        return abi.encodeCall(IPqzMergedT5.mtxUnshieldUnwrap, (u, b, x, PROOF, _pqAuth(), "", s, noVerdict()));
    }

    function _refused(address t, bytes memory cd, string memory what) internal {
        (bool ok, bytes memory ret) = _go(t, cd);
        assertFalse(ok, what);
        assertEq(bytes4(ret), IPqzToken.ProofRejected.selector, what);
    }

    function _settles(address t, bytes memory cd, string memory what) internal returns (bytes memory ret) {
        bool ok;
        (ok, ret) = _go(t, cd);
        assertTrue(ok, what);
    }

    /// Each proof-carrying merged entry by `from`: a proof bound to the address tag over the same fields is refused, the one
    /// bound to the UA tag settles (R36).
    function _eachProofEntry(bytes32 from) internal {
        for (uint256 k; k < 2; ++k) {
            _refused(address(tok), _singleCd(from, k == 1, false), "single: address tag");
            uint64 c = tok.pqzAccount(alice, 0).sendCounter;
            _settles(address(tok), _singleCd(from, k == 1, true), "single: UA tag");
            assertEq(tok.pqzAccount(alice, 0).sendCounter, c + 1, "single settled");
            _refused(address(tok), _multiCd(from, k == 1, false), "multi: address tag");
            _settles(address(tok), _multiCd(from, k == 1, true), "multi: UA tag");
        }
        _refused(address(tok), _unshieldCd(from, false), "unshield: address tag");
        uint256 before = tok.balanceOf(TO);
        _settles(address(tok), _unshieldCd(from, true), "unshield: UA tag");
        assertEq(tok.balanceOf(TO), before + 5 * SCALE);
        _refused(address(w), _unwrapCd(from, false), "unshieldUnwrap: address tag");
        _settles(address(w), _unwrapCd(from, true), "unshieldUnwrap: UA tag");
        assertEq(usd.balanceOf(TO), 10 * SCALE, "the leg paid");
        assertEq(tok.mtxNonce(from, LANE), 5, "one lane, five entries");
        assertEq(w.mtxNonce(from, LANE), 1);
    }

    function test_pqzRelayedProofBindsUATag_native() public {
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, nId), 0);
        _eachProofEntry(nId);
    }

    function test_pqzRelayedProofBindsUATag_derived() public {
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, dId));
        _eachProofEntry(dId);
        // a derived signer's shield: `Shielded.from` is `UA_POOL` (`_msgSender()` in the self-call), its UA balance pays
        MetaTxLib.UAEnvelope memory u = _u(dId, address(tok));
        IUARegistry.UASig memory s = UACall.auth(dId, _mlAuth());
        vm.expectEmit(true, true, false, false, address(tok));
        emit IConfidentialToken.Shielded(bob, MetaTxLib.UA_POOL, 3, 0);
        vm.prank(relayer);
        IPqzMergedT5(address(tok)).mtxShield(u, bob, 3, s);
        assertEq(tok.balanceOfUA(dId), 37 * SCALE);
    }

    /// The binding the token computes is the spec formula (the merged view under the plain name, R36, spec §2.3).
    function test_pqzEnvelopeBindingViewIsTheUATag() public view {
        MetaTxLib.UAEnvelope memory u = _u(dId, address(tok));
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction(u.from, hex"beef", u.batch, u.nonce, u.validUntil,
            u.mode, address(0x1234), u.fee, address(0x5678)); // unbound relayer / fee recipient: not in the binding
        assertEq(IPqzMergedT5(address(tok)).envelopeBinding(m), _uaTag(address(tok), u));
    }

    // ------------------------------------------------------------------ executeMetaTransaction keeps the address tag

    function _asUA(MetaTxLib.MetaTransaction memory m) internal pure returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(MetaTxLib.pad(m.from), m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient);
    }

    /// The direct op 1 call a relayed envelope carries, its proof bound to `binding`.
    function _singleCall(bytes32 binding) internal returns (bytes memory) {
        IPqzToken.PqzTransferArgs memory t = _ts(_sPl(tok, alice, true, "", 60));
        _accept(1, tok.transferSingleStatement(t, binding));
        return abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (t, PROOF, _pqAuth(), bytes(""), noVerdict()));
    }

    /// The EIP-1776 alias (R3) keeps `SCAAS-PQZ-ENVELOPE-V1`: a proof bound to the UA tag is refused there, the address-tag
    /// one settles; on the merged `mtxExecute` the reverse.
    function test_pqzExecuteMetaTransactionBindsAddressTag() public {
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(signer, "", LANE, 0, block.timestamp + 300, 0,
            address(0), 0, address(0));
        m.data = _singleCall(_uaTag(address(tok), _asUA(m)));
        bytes memory sig = ecdsa(PK, MtxDigest.metaTx(address(tok), m));
        vm.prank(relayer);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.executeMetaTransaction(m, sig);
        m.data = _singleCall(_addrTag(address(tok), _asUA(m)));
        sig = ecdsa(PK, MtxDigest.metaTx(address(tok), m));
        vm.prank(relayer);
        assertTrue(tok.executeMetaTransaction(m, sig));
        assertEq(tok.pqzAccount(alice, 0).sendCounter, 1);
    }

    function test_pqzMtxExecuteBindsUATag() public {
        MetaTxLib.UAMetaTransaction memory um = MetaTxLib.UAMetaTransaction(nId, "", LANE, 0, block.timestamp + 300, 0,
            address(0), 0, address(0));
        MetaTxLib.UAEnvelope memory u = MetaTxLib.UAEnvelope(nId, LANE, 0, um.validUntil, 0, address(0), 0, address(0));
        um.data = _singleCall(_addrTag(address(tok), u));
        IUARegistry.UASig memory s;
        s.signature = ecdsa(PK, tok.mtxDigest(um));
        vm.prank(relayer);
        vm.expectRevert(IPqzToken.ProofRejected.selector);
        tok.mtxExecute(um, s);
        um.data = _singleCall(_uaTag(address(tok), u));
        s.signature = ecdsa(PK, tok.mtxDigest(um));
        vm.prank(relayer);
        tok.mtxExecute(um, s);
        assertEq(tok.pqzAccount(alice, 0).sendCounter, 1);
    }

    // ------------------------------------------------------------------ fee 0 on every merged entry (invariant 4)

    /// Every merged PQZ entry at fee mode `NONE`, a native signer, a relayer nobody bound: it runs, the relayer is paid
    /// nothing, and the subject is checked by its own key with no `requireAuthorized` call for it.
    function test_pqzFeeZero_everyMergedEntry() public {
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, nId), 0);
        uint256 relayerPublic = tok.balanceOf(relayer);

        // shield: `Shielded.from` is the subject's address (`_msgSender()` in the self-call, not `msg.sender`)
        MetaTxLib.UAEnvelope memory u = _u(nId, address(tok));
        IUARegistry.UASig memory s = _auth(address(tok), u, "UAShield",
            '{"name":"from","type":"bytes32"},{"name":"toUA","type":"bytes32"},{"name":"amount","type":"uint256"}', '',
            string.concat('"toUA":', h(bob), ',"amount":', n(5)));
        uint256 pub = tok.balanceOf(signer);
        vm.expectEmit(true, true, false, false, address(tok));
        emit IConfidentialToken.Shielded(bob, signer, 5, 0);
        vm.prank(relayer);
        IPqzMergedT5(address(tok)).mtxShield(u, bob, 5, s);
        assertEq(tok.balanceOf(signer), pub - 5 * SCALE);

        _settles(address(tok), _singleCd(nId, false, true), "single");
        _settles(address(tok), _singleCd(nId, true, true), "singleCompact");
        _settles(address(tok), _multiCd(nId, false, true), "multi");
        _settles(address(tok), _multiCd(nId, true, true), "compact");
        _settles(address(tok), _unshieldCd(nId, true), "unshield");
        _settles(address(w), _unwrapCd(nId, true), "unshieldUnwrap");
        _feeZeroStatics();

        assertEq(tok.balanceOf(relayer), relayerPublic, "fee 0: the relayer is paid nothing");
        assertEq(w.balanceOf(relayer), 0);
        assertEq(tok.mtxNonce(nId, LANE), 8, "eight merged entries on the one lane (the ninth on `w`)");
        assertEq(w.mtxNonce(nId, LANE), 1);
    }

    /// The prepare and the rollover of `test_pqzFeeZero_everyMergedEntry` (bob holds the shield's and the transfers' credits).
    function _feeZeroStatics() internal {
        // group 3g T52 (KV-10): `UAPrepareAcc` / `UARollOver` carry `uint64 keyVersion` after `ua` (version 0 here)
        string memory f = '{"name":"from","type":"bytes32"},{"name":"ua","type":"bytes32"},{"name":"keyVersion","type":"uint64"},'
            '{"name":"half","type":"uint256"}';
        MetaTxLib.UAEnvelope memory u = _u(nId, address(tok));
        IUARegistry.UASig memory s =
            _auth(address(tok), u, "UAPrepareAcc", f, '', string.concat('"ua":', h(bob), ',"keyVersion":', n(0), ',"half":', n(0)));
        vm.prank(relayer);
        tok.mtxPrepareAcc(u, bob, 0, 0, s);
        assertEq(tok.pqzAccount(bob, 0).flags & 2, 2, "prepareAcc");
        tok.mtxPrepareAcc(bob, 0, 1);
        vm.roll(block.number + ROLL_AGE);
        f = '{"name":"from","type":"bytes32"},{"name":"ua","type":"bytes32"},{"name":"keyVersion","type":"uint64"},'
            '{"name":"n","type":"uint256"}';
        u = _u(nId, address(tok));
        s = _auth(address(tok), u, "UARollOver", f, '', string.concat('"ua":', h(bob), ',"keyVersion":', n(0), ',"n":', n(1)));
        uint64 r = tok.pqzAccount(bob, 0).rolled;
        vm.prank(relayer);
        tok.mtxRollOver(u, bob, 0, 1, s);
        assertEq(tok.pqzAccount(bob, 0).rolled, r + 1, "rollOver");
    }

    // ------------------------------------------------------------------ never lose ciphertext

    /// A merged relayed transfer leaves every ciphertext in contract state: the op blob (`R ‖ v_f`, byte for byte the
    /// reference's), the receiver's credit `u ‖ v_t`, the sender's `acc` `u ‖ v_f`; commit-reveal, `hash(R) ‖ memo`.
    function test_pqzCiphertextInState() public {
        bytes memory pl = _sPl(tok, alice, true, "", 50); // `_singleCd`'s payload
        bytes memory blob = ref_.blobSingle(pl, false);
        bytes32 ref = abi.decode(_settles(address(tok), _singleCd(nId, false, true), "single"), (bytes32));
        assertEq(tok.pqzEntryBlob(ref), blob, "the op blob in state");
        assertEq(tok.pqzPendingCt(bob, 0, tok.pqzAccount(bob, 0).pendingCount - 1), _cut(pl, T_OUT, PqzCt.CT), "the credit u || v_t");
        assertEq(tok.pqzAcc(alice, 0), bytes.concat(_cut(pl, T_OUT, PqzCt.PK), _cut(pl, T_OUT + PqzCt.CT, PqzCt.V)), "acc u || v_f");

        pl = _mPl(tok, alice, _legsN(2), true, _mem(2), 51);
        blob = ref_.blobMulti(pl, true);
        ref = abi.decode(_settles(address(tok), _multiCd(nId, true, true), "compact"), (bytes32));
        assertEq(tok.pqzEntryBlob(ref), blob, "the commit-reveal op blob in state");
        bytes memory r = _slice(blob, 0, blob.length - PqzCt.VP - PqzCore._tailLen(3)); // group 3h: R ends before v_f and the tail (M 2, the auditor)
        assertEq(tok.transferEntry(ref), bytes.concat(keccak256(r), _mem(2)), "hash(R) || memo in state");
    }

    // ------------------------------------------------------------------ the retired forms (invariant 3), the ids

    function _noEntry(address t, bytes memory cd, string memory what) internal {
        vm.prank(relayer);
        (bool ok, bytes memory ret) = t.call(cd);
        assertFalse(ok, what);
        assertEq(ret.length, 0, what);
    }

    /// The address signed entries, the `ua*` names and both old binding views: no function serves them (valid calldata, so
    /// a function that existed would answer or revert by name).
    function test_pqzRetiredFormsHaveNoEntry() public {
        MetaTxLib.Envelope memory e = MetaTxLib.Envelope(signer, LANE, 0, block.timestamp + 300, 0, address(0), 0, address(0));
        address t = address(tok);
        IPqzToken.PqzMultiArgs memory mt;
        IPqzToken.PqzTransferArgs memory st;
        IPqzToken.PqzBurnArgs memory bt;
        IUARegistry.UASig memory x;
        _noEntry(t, abi.encodeCall(IPqzOldT5.mtxShield, (e, bob, 1, "")), "address mtxShield");
        _noEntry(t, abi.encodeCall(IPqzOldT5.mtxConfidentialTransfer, (e, mt, "", x, "", "")), "address mtxConfidentialTransfer");
        _noEntry(t, abi.encodeCall(IPqzOldT5.mtxConfidentialTransferCompact, (e, mt, "", x, "", "")), "address compact");
        _noEntry(t, abi.encodeCall(IPqzOldT5.mtxConfidentialTransferSingle, (e, st, "", x, "", "")), "address single");
        _noEntry(t, abi.encodeCall(IPqzOldT5.mtxConfidentialTransferSingleCompact, (e, st, "", x, "", "")), "address singleCompact");
        _noEntry(t, abi.encodeCall(IPqzOldT5.mtxUnshield, (e, bt, IPqzToken.Payout(1, bob), "", x, "", "")), "address mtxUnshield");
        _noEntry(t, abi.encodeCall(IPqzOldT5.mtxRollOver, (e, bob, 1, "")), "address mtxRollOver");
        _noEntry(t, abi.encodeCall(IPqzOldT5.mtxPrepareAcc, (e, bob, 0, "")), "address mtxPrepareAcc");
        _noEntry(address(w), abi.encodeCall(IPqzOldT5.mtxUnshieldUnwrap, (e, bt, _x(), "", x, "", "")), "address mtxUnshieldUnwrap");
        _retiredUA();
        MetaTxLib.MetaTransaction memory m;
        _noEntry(t, abi.encodeCall(IPqzOldT5.envelopeBinding, (m)), "address envelopeBinding view");
        _noEntry(address(w), abi.encodeCall(IPqzOldT5.envelopeBinding, (m)), "address envelopeBinding view (wrapped)");
        MetaTxLib.UAMetaTransaction memory um;
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaEnvelopeBinding, (um)), "uaEnvelopeBinding view");
    }

    /// The `ua*` names of `test_pqzRetiredFormsHaveNoEntry`.
    function _retiredUA() internal {
        MetaTxLib.UAEnvelope memory u = _u(nId, address(tok));
        address t = address(tok);
        IPqzToken.PqzMultiArgs memory mt;
        IPqzToken.PqzTransferArgs memory st;
        IPqzToken.PqzBurnArgs memory bt;
        IUARegistry.UASig memory x;
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaShield, (u, bob, 1, x)), "uaShield");
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaConfidentialTransfer, (u, mt, "", x, "", x)), "uaConfidentialTransfer");
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaConfidentialTransferCompact, (u, mt, "", x, "", x)), "uaConfidentialTransferCompact");
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaConfidentialTransferSingle, (u, st, "", x, "", x)), "uaConfidentialTransferSingle");
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaConfidentialTransferSingleCompact, (u, st, "", x, "", x)),
            "uaConfidentialTransferSingleCompact");
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaUnshield, (u, bt, IPqzToken.Payout(1, bob), "", x, "", x)), "uaUnshield");
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaRollOver, (u, bob, 1, x)), "uaRollOver");
        _noEntry(t, abi.encodeCall(IPqzOldT5.uaPrepareAcc, (u, bob, 0, x)), "uaPrepareAcc");
        _noEntry(address(w), abi.encodeCall(IPqzOldT5.uaUnshieldUnwrap, (u, bt, _x(), "", x, "", x)), "uaUnshieldUnwrap");
    }

    function _x() internal pure returns (IConfidentialWrappedToken.Unwrap memory t) {}

    /// The PQZ interfaces declare no signed entry and no binding view, so no id moves (R36).
    function test_pqzInterfaceIdsArePinned() public pure {
        // group 3g T52: the three args structs gain `keyVersion`, the versioned rollover / prepare and views; the shared interface
        // is `mtxShield` alone (§10 row 21): IPqzToken 0x5313635f -> 0xd37edfc5, IConfidentialToken 0x69d6bb06 -> mtxShield's
        // group 3f T45: the verdict on the five direct proof entries, the three verifier ops and `pqzVerifyConfig`:
        // IPqzToken 0xd37edfc5 -> 0x4c91dc6a; IPqzWrappedToken moves with its `mtxUnshieldUnwrap`'s selector
        // group 3h T58: `pqzDebitRecord`: IPqzToken 0x4c91dc6a -> 0x5037795c; T59: `ownTag` in the three args structs (the six
        // proof-carrying selectors): -> 0xd8bbf337; T60: `proofStore()`: -> 0x191d0352
        assertEq(type(IPqzToken).interfaceId, bytes4(0x191d0352), "IPqzToken");
        assertEq(type(IConfidentialToken).interfaceId, IConfidentialToken.mtxShield.selector, "IConfidentialToken");
        assertEq(type(IPqzWrappedToken).interfaceId, IPqzWrappedToken.mtxUnshieldUnwrap.selector, "IPqzWrappedToken");
    }
}

/// Risk 9: on a merged entry only the binding value changes, not the statement's layout. Each statement (op 1, op 7, burn,
/// unshield-unwrap) built by the token for the address tag is the reference's byte for byte (`PqzPackedRef`, the
/// pre-merge packed form); built for the UA tag of the same fields it has the same length and differs in the binding word
/// (header word 17, bytes 544–575) alone. A layout change here stops the task (a new `proofSystemId` is not this round).
contract PqzStatementLayoutTest is PqzNamedBase {
    uint256 internal constant W17 = 544;

    function setUp() public {
        _named();
        _fund(tok, alice, 1000);
        _wrapFund(alice, 100);
    }

    function _env(address t, bool ua) internal view returns (bytes32) {
        bytes32 from = MetaTxLib.pad(signer);
        return keccak256(bytes.concat(
            abi.encode(keccak256(ua ? bytes("SCAAS-PQZ-UA-ENVELOPE-V1") : bytes("SCAAS-PQZ-ENVELOPE-V1")), block.chainid,
                IMetaTx(t).chainUid(), t, ua ? from : bytes32(uint256(uint160(signer))), uint256(7)),
            abi.encode(uint256(3), uint256(1_800_000_000), uint32(0), address(0), uint256(0), address(0))));
    }

    /// `s1` is `s0` but its word 17.
    function _onlyBindingDiffers(bytes memory s0, bytes memory s1, string memory what) internal pure {
        assertEq(s1.length, s0.length, string.concat(what, ": same length"));
        bytes memory x = bytes.concat(s1);
        bytes32 w0;
        bytes32 w1;
        assembly ("memory-safe") {
            w0 := mload(add(add(s0, 32), W17))
            w1 := mload(add(add(x, 32), W17))
            mstore(add(add(x, 32), W17), w0)
        }
        assertTrue(w0 != w1, string.concat(what, ": the binding word moved"));
        assertEq(x, s0, string.concat(what, ": only the binding word differs"));
    }

    function test_pqzStatementLayoutUnchanged() public {
        (bytes32 b0, bytes32 b1) = (_env(address(tok), false), _env(address(tok), true));
        bytes memory pl = _sPl(tok, alice, true, "", 11);
        bytes memory s0 = tok.transferSingleStatement(_ts(pl), b0);
        assertEq(s0, _onRef(address(tok), abi.encodeCall(PqzPackedRef.single,
            (_envAt(tok, b0, 0, 0, ZetherTypes.TransferMode.BUNDLE), pl))), "op 1: the reference's bytes");
        _onlyBindingDiffers(s0, tok.transferSingleStatement(_ts(pl), b1), "op 1");

        pl = _mPl(tok, alice, _legsN(4), true, _mem(4), 12);
        s0 = tok.transferStatement(_ms(pl), b0);
        assertEq(s0, _onRef(address(tok), abi.encodeCall(PqzPackedRef.multi,
            (_envAt(tok, b0, 0, 0, ZetherTypes.TransferMode.HASH), pl))), "op 7: the reference's bytes");
        _onlyBindingDiffers(s0, tok.transferStatement(_ms(pl), b1), "op 7");

        pl = _bPl(tok, alice, 13);
        bytes32 to = MetaTxLib.pad(address(0xD00D));
        s0 = tok.burnStatement(_bs(pl), 7, to, b0);
        assertEq(s0, _onRef(address(tok), abi.encodeCall(PqzPackedRef.burn,
            (_envAt(tok, b0, 7, to, ZetherTypes.TransferMode.BUNDLE), pl))), "burn: the reference's bytes");
        _onlyBindingDiffers(s0, tok.burnStatement(_bs(pl), 7, to, b1), "burn");

        _unwrapLayout();
    }

    function _unwrapLayout() internal {
        (bytes32 b0, bytes32 b1) = (_env(address(w), false), _env(address(w), true));
        bytes memory pl = _bPl(w, alice, 14);
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), 40, 40 * SCALE);
        bytes32 word = keccak256(abi.encode(b0, w.unwrapBinding(address(usd), x.minOut)));
        bytes memory s0 = w.unshieldUnwrapStatement(_bs(pl), x, b0);
        assertEq(s0, _onRef(address(w), abi.encodeCall(PqzPackedRef.burn,
            (_envAt(w, word, 40, x.recipient, ZetherTypes.TransferMode.BUNDLE), pl))), "unshieldUnwrap: the reference's bytes");
        _onlyBindingDiffers(s0, w.unshieldUnwrapStatement(_bs(pl), x, b1), "unshieldUnwrap");
    }
}
