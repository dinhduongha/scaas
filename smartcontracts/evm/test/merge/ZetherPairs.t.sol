// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {n, a, h, eJson, ecdsa} from "../metatx/NamedEntry.t.sol";
import {typedDigest, singleJson, multiJson, burnJson, hexJson, T_G1, T_SINGLE, T_LEG, T_MULTI, T_BURN, T_UNWRAP,
    StatementHarness} from "../zether/ZetherTyped.t.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedgerViews} from "../../src/metatx/IUALedgerViews.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {ZetherLib} from "../../src/zether/ZetherLib.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IZetherToken, IZetherWrappedToken} from "../../src/zether/IZetherToken.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "../../src/zether/IZetherVerifier.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";

/// The merged Zether entries of ua-mtx-merge T4 (R35), called by their own signatures: this file compiles on the tree
/// before T4 too, so each test is red there on its own (plan T4 step 3).
interface IZetherMergedT4 {
    function mtxShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxConfidentialTransfer(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherMulti calldata t,
        bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes32);
    function mtxConfidentialTransferCompact(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherMulti calldata t,
        bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes32);
    function mtxConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherSingle calldata t,
        bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes32);
    function mtxUnshield(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherBurn calldata b, uint256 amount,
        bytes32 recipient, bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxRollOver(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint256 n_, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxRollOverBatch(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA[] calldata uas,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function mtxRollOverSigned(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA ua, uint64 expectedPendingSeq,
        uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxSetRollOverMode(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA ua, ZetherTypes.RollOverMode rollOverMode,
        uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function mtxUnshieldUnwrap(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherBurn calldata b,
        IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function envelopeBinding(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32);
}

/// The retired forms (invariant 3): the address signed entries, the `ua*` names and the address binding view. After T4
/// no Zether token serves these selectors.
interface IZetherOldT4 {
    function mtxShield(MetaTxLib.Envelope calldata e, bytes32 toUA, uint256 amount, bytes calldata sig)
        external returns (bytes memory);
    function mtxConfidentialTransfer(MetaTxLib.Envelope calldata e, IZetherToken.ZetherMulti calldata t,
        bytes calldata proof, bytes calldata sig) external returns (bytes32);
    function mtxConfidentialTransferCompact(MetaTxLib.Envelope calldata e, IZetherToken.ZetherMulti calldata t,
        bytes calldata proof, bytes calldata sig) external returns (bytes32);
    function mtxConfidentialTransferSingle(MetaTxLib.Envelope calldata e, IZetherToken.ZetherSingle calldata t,
        bytes calldata proof, bytes calldata sig) external returns (bytes32);
    function mtxUnshield(MetaTxLib.Envelope calldata e, IZetherToken.ZetherBurn calldata b, uint256 amount,
        bytes32 recipient, bytes calldata proof, bytes calldata sig) external returns (bytes memory);
    function mtxRollOver(MetaTxLib.Envelope calldata e, bytes32 ua, uint256 n_, bytes calldata sig)
        external returns (bytes memory);
    function mtxRollOverBatch(MetaTxLib.Envelope calldata e, ZetherTypes.UA[] calldata uas, bytes calldata sig)
        external returns (bytes memory);
    function mtxRollOverSigned(MetaTxLib.Envelope calldata e, ZetherTypes.UA ua, uint64 expectedPendingSeq,
        uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig, bytes calldata sig) external returns (bytes memory);
    function mtxSetRollOverMode(MetaTxLib.Envelope calldata e, ZetherTypes.UA ua, ZetherTypes.RollOverMode rollOverMode,
        uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig, bytes calldata sig) external returns (bytes memory);
    function mtxUnshieldUnwrap(MetaTxLib.Envelope calldata e, IZetherToken.ZetherBurn calldata b,
        IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, bytes calldata sig) external returns (bytes memory);
    function uaShield(MetaTxLib.UAEnvelope calldata e, bytes32 toUA, uint256 amount, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function uaConfidentialTransfer(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherMulti calldata t,
        bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes32);
    function uaConfidentialTransferCompact(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherMulti calldata t,
        bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes32);
    function uaConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherSingle calldata t,
        bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes32);
    function uaUnshield(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherBurn calldata b, uint256 amount,
        bytes32 recipient, bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes memory);
    function uaRollOver(MetaTxLib.UAEnvelope calldata e, bytes32 ua, uint256 n_, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function uaRollOverBatch(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA[] calldata uas,
        IUARegistry.UASig calldata auth) external returns (bytes memory);
    function uaRollOverSigned(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA ua, uint64 expectedPendingSeq,
        uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function uaSetRollOverMode(MetaTxLib.UAEnvelope calldata e, ZetherTypes.UA ua, ZetherTypes.RollOverMode rollOverMode,
        uint64 validUntilBlock, IUARegistry.UASig calldata ownerSig, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function uaUnshieldUnwrap(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherBurn calldata b,
        IConfidentialWrappedToken.Unwrap calldata x, bytes calldata proof, IUARegistry.UASig calldata auth)
        external returns (bytes memory);
    function envelopeBinding(MetaTxLib.MetaTransaction calldata m) external view returns (bytes32);
    function uaEnvelopeBinding(MetaTxLib.UAMetaTransaction calldata m) external view returns (bytes32);
}

/// T4: the Zether pairs in today's `ua*` form under the `mtx*` name, for native and derived ids (R35). On every merged
/// entry a relayed proof binds `SCAAS-ZETHER-UA-ENVELOPE-V1` over the `UAMetaTransaction` (`from` as `bytes32`), native
/// subjects included; `executeMetaTransaction` keeps `SCAAS-ZETHER-ENVELOPE-V1` over its `MetaTransaction` (spec §2.1).
/// Every binding here is the spec formula computed in the test, never read from the token. Every relayed call is at fee
/// mode `NONE` by a relayer nobody bound (invariant 4). `tok` is `NORMAL_ZETHER`, `w` `WRAPPED_ZETHER` over `usd`.
contract ZetherPairsTest is ZetherFixture {
    uint256 internal constant PK = 0x9A7E5;
    address internal payer = vm.addr(PK);
    address internal constant ANY = address(0xA9E);
    address internal constant TO = address(0xB0C);
    uint256 internal constant LANE = 9;

    WrappedZetherToken internal w;
    MockERC20 internal usd;
    bytes32 internal aId;
    bytes32 internal bId;
    bytes32 internal nId;

    string internal constant F_FROM = '{"name":"from","type":"bytes32"}';

    function setUp() public {
        _deploy(true);
        aId = ZetherTypes.UA.unwrap(alice.ua);
        bId = ZetherTypes.UA.unwrap(bob.ua);
        nId = MetaTxLib.pad(payer);
        _fund(tok, alice, 500);
        tok.mtxRollOver(aId, 1);
        _public(tok, payer, 100 * SCALE);
        vm.prank(payer);
        tok.transferToUA(aId, 40 * SCALE); // alice's UA balance: what a derived shield takes

        usd = new MockERC20("USD", "USD", 6);
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        IFactoryToken.TokenConfig memory c;
        c.name = "Zether wrapped";
        c.symbol = "zW";
        c.decimals = 6;
        c.features = 1 << GovernanceBits.PAYABLE;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(bytes(""), SCALE, uint256(1) << 40, FEE, dMode, 0, 0, 0, bytes32(0), false);
        w = WrappedZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "zw")));
        usd.mint(payer, 1_000 * SCALE);
        vm.startPrank(payer);
        usd.approve(address(w), 1_000 * SCALE);
        w.mtxWrapShield(address(usd), 300 * SCALE, aId);
        vm.stopPrank();
        w.mtxRollOver(aId, 1);
    }

    // ------------------------------------------------------------------ the envelope, the bindings, the signatures

    function _u(bytes32 from, address t) internal view returns (MetaTxLib.UAEnvelope memory u) {
        u = MetaTxLib.UAEnvelope(from, LANE, IUALedgerViews(t).mtxNonce(from, LANE), block.timestamp + 300, 0, address(0), 0,
            address(0));
    }

    /// CTR-ZTH-51 / R35: the merged entries' binding, `from` as `bytes32`.
    function _uaTag(address t, MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-ZETHER-UA-ENVELOPE-V1"), block.chainid, IMetaTx(t).chainUid(), t, u.from, u.batch),
            abi.encode(u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
    }

    /// CTR-ZTH-06: `executeMetaTransaction`'s binding over the same fields, `from` an address.
    function _addrTag(address t, MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-ZETHER-ENVELOPE-V1"), block.chainid, IMetaTx(t).chainUid(), t,
                address(uint160(uint256(u.from))), u.batch),
            abi.encode(u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
    }

    /// What the subject of `u` signs over `primary` (a wallet's digest of the JSON it is handed).
    function _auth(address t, MetaTxLib.UAEnvelope memory u, string memory primary, string memory fields, string memory nested,
        string memory op) internal view returns (IUARegistry.UASig memory s)
    {
        bytes32 d = typedDigest(t, primary, string.concat(F_FROM, ',', fields), nested, _msgOf(u, op));
        s.signature = u.from == nId ? ecdsa(PK, d)
            : ZetherKeys.schnorr(alice.x, reg.uaMessage(_zkind(), UAKinds.PURPOSE_METATX, d), bls);
    }

    function _msgOf(MetaTxLib.UAEnvelope memory u, string memory op) internal pure returns (string memory) {
        string memory e = eJson(u.batch, u.nonce, u.validUntil, u.mode, u.fee);
        return string.concat('"from":', h(u.from), ',', op, ',', e);
    }

    function _proofMsg(string memory args, bytes memory proof) internal pure returns (string memory) {
        return string.concat('"args":', args, ',"proof":', hexJson(proof));
    }

    // ------------------------------------------------------------------ each proof-carrying merged entry

    function _bind(address t, MetaTxLib.UAEnvelope memory u, bytes32 binding) internal view returns (bytes32) {
        return binding == 0 ? _uaTag(t, u) : binding;
    }

    function _go(address t, bytes memory cd) internal returns (bool ok, bytes memory ret) {
        vm.prank(ANY);
        (ok, ret) = t.call(cd);
    }

    /// `binding` 0: the UA tag of the entry's own envelope; else the proof is bound to `binding` instead.
    function _single(bytes32 from, uint256 bal, bytes32 binding) internal returns (bool, bytes memory) {
        return _go(address(tok), _singleCd(_u(from, address(tok)), bal, binding));
    }

    function _singleCd(MetaTxLib.UAEnvelope memory u, uint256 bal, bytes32 binding) internal view returns (bytes memory) {
        Tx memory x = _proveTransfer(tok, alice, bob, 10, bal, _none(), _bind(address(tok), u, binding));
        IZetherToken.ZetherSingle memory t = _zSingle(x.payload, _none());
        IUARegistry.UASig memory s = _auth(address(tok), u, "UAZetherTransferSingle",
            '{"name":"args","type":"ZetherSingle"},{"name":"proof","type":"bytes"}', string.concat(',', T_G1, ',', T_SINGLE),
            _proofMsg(singleJson(t), x.proof));
        return abi.encodeCall(IZetherMergedT4.mtxConfidentialTransferSingle, (u, t, x.proof, s));
    }

    function _multi(bytes32 from, uint256 bal, bool compact, bytes32 binding) internal returns (bool, bytes memory) {
        return _go(address(tok), _multiCd(_u(from, address(tok)), bal, compact, binding));
    }

    function _multiTx(uint256 bal, ZetherTypes.TransferMode mode, bytes32 b) internal view returns (Tx memory) {
        User[] memory to = new User[](2);
        (to[0], to[1]) = (bob, carol);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (10, 0);
        return _proveMulti(tok, alice, to, vs, bal, _none(), mode, b);
    }

    function _multiCd(MetaTxLib.UAEnvelope memory u, uint256 bal, bool compact, bytes32 binding)
        internal view returns (bytes memory)
    {
        Tx memory x = _multiTx(bal, compact ? ZetherTypes.TransferMode.HASH : ZetherTypes.TransferMode.BUNDLE,
            _bind(address(tok), u, binding));
        IZetherToken.ZetherMulti memory t = _zMulti(x.payload, _none());
        IUARegistry.UASig memory s = _auth(address(tok), u, compact ? "UAZetherTransferCompact" : "UAZetherTransfer",
            '{"name":"args","type":"ZetherMulti"},{"name":"proof","type":"bytes"}',
            string.concat(',', T_G1, ',', T_LEG, ',', T_MULTI), _proofMsg(multiJson(t), x.proof));
        return compact
            ? abi.encodeCall(IZetherMergedT4.mtxConfidentialTransferCompact, (u, t, x.proof, s))
            : abi.encodeCall(IZetherMergedT4.mtxConfidentialTransfer, (u, t, x.proof, s));
    }

    function _unshield(bytes32 from, uint256 bal, bytes32 binding) internal returns (bool, bytes memory) {
        return _go(address(tok), _unshieldCd(_u(from, address(tok)), bal, binding));
    }

    function _unshieldCd(MetaTxLib.UAEnvelope memory u, uint256 bal, bytes32 binding) internal view returns (bytes memory) {
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 10, bal, TO, _none(), _bind(address(tok), u, binding));
        IZetherToken.ZetherBurn memory b = _zBurn(pl, _none());
        IUARegistry.UASig memory s = _auth(address(tok), u, "UAZetherUnshield",
            '{"name":"args","type":"ZetherBurn"},{"name":"amount","type":"uint256"},{"name":"recipient","type":"bytes32"},{"name":"proof","type":"bytes"}',
            string.concat(',', T_G1, ',', T_BURN), _unshieldMsg(b, pr));
        return abi.encodeCall(IZetherMergedT4.mtxUnshield, (u, b, 10, MetaTxLib.pad(TO), pr, s));
    }

    function _unshieldMsg(IZetherToken.ZetherBurn memory b, bytes memory pr) internal pure returns (string memory) {
        return string.concat('"args":', burnJson(b), ',"amount":', n(10), ',"recipient":', h(MetaTxLib.pad(TO)), ',"proof":',
            hexJson(pr));
    }

    function _unshieldUnwrap(bytes32 from, uint256 bal, bytes32 binding) internal returns (bool, bytes memory) {
        return _go(address(w), _unshieldUnwrapCd(_u(from, address(w)), bal, binding));
    }

    function _uwProof(IZetherToken.ZetherBurn memory b, IConfidentialWrappedToken.Unwrap memory x, uint256 bal, bytes32 bd)
        internal view returns (bytes memory)
    {
        return _proveU(alice, stm.unshieldUnwrapStatement(address(w), b, x.amount, x.recipient, x.underlying, x.minOut, bd),
            x.amount, bal, _none(), ZetherLayer(address(w)));
    }

    function _uwMsg(IZetherToken.ZetherBurn memory b, IConfidentialWrappedToken.Unwrap memory x, bytes memory pr)
        internal pure returns (string memory)
    {
        string memory uw = string.concat('{"underlying":', a(x.underlying), ',"recipient":', h(x.recipient), ',"amount":',
            n(x.amount), ',"minOut":', n(x.minOut), '}');
        return string.concat('"args":', burnJson(b), ',"unwrap":', uw, ',"proof":', hexJson(pr));
    }

    function _unshieldUnwrapCd(MetaTxLib.UAEnvelope memory u, uint256 bal, bytes32 binding) internal view returns (bytes memory) {
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(TO), 10, 10 * SCALE);
        IZetherToken.ZetherBurn memory b = _zBurn(_unshieldPayload(ZetherLayer(address(w)), alice), _none());
        bytes memory pr = _uwProof(b, x, bal, _bind(address(w), u, binding));
        IUARegistry.UASig memory s = _auth(address(w), u, "UAZetherUnshieldUnwrap",
            '{"name":"args","type":"ZetherBurn"},{"name":"unwrap","type":"Unwrap"},{"name":"proof","type":"bytes"}',
            string.concat(',', T_G1, ',', T_UNWRAP, ',', T_BURN), _uwMsg(b, x, pr));
        return abi.encodeCall(IZetherMergedT4.mtxUnshieldUnwrap, (u, b, x, pr, s));
    }

    function _refused(bool ok, bytes memory ret, string memory what) internal pure {
        assertFalse(ok, what);
        assertEq(bytes4(ret), IZetherToken.ProofRejected.selector, what);
    }

    /// Each proof-carrying merged entry by `from`: a proof bound to the address tag over the same fields is refused, the
    /// one bound to the UA tag settles (R35).
    function _eachProofEntry(bytes32 from) internal {
        uint256 bal = 500;
        // the address tag of the same fields (an address `from` only exists for a native; a derived id's low bits)
        MetaTxLib.UAEnvelope memory u = _u(from, address(tok));
        (bool ok, bytes memory ret) = _single(from, bal, _addrTag(address(tok), u));
        _refused(ok, ret, "single: address tag");
        (ok, ret) = _single(from, bal, 0);
        assertTrue(ok, "single: UA tag");
        assertEq(abi.decode(ret, (bytes32)), _ref(tok, alice, 0));
        bal -= 10;
        assertTrue(_holds(tok, bob, 10, false), "single settled");

        u = _u(from, address(tok));
        (ok, ret) = _multi(from, bal, false, _addrTag(address(tok), u));
        _refused(ok, ret, "multi: address tag");
        (ok, ret) = _multi(from, bal, false, 0);
        assertTrue(ok, "multi: UA tag");
        bal -= 10;

        u = _u(from, address(tok));
        (ok, ret) = _multi(from, bal, true, _addrTag(address(tok), u));
        _refused(ok, ret, "compact: address tag");
        (ok, ret) = _multi(from, bal, true, 0);
        assertTrue(ok, "compact: UA tag");
        bal -= 10;

        u = _u(from, address(tok));
        (ok, ret) = _unshield(from, bal, _addrTag(address(tok), u));
        _refused(ok, ret, "unshield: address tag");
        uint256 before = tok.balanceOf(TO);
        (ok, ret) = _unshield(from, bal, 0);
        assertTrue(ok, "unshield: UA tag");
        assertEq(tok.balanceOf(TO), before + 10 * SCALE);

        u = _u(from, address(w));
        (ok, ret) = _unshieldUnwrap(from, 300, _addrTag(address(w), u));
        _refused(ok, ret, "unshieldUnwrap: address tag");
        (ok, ret) = _unshieldUnwrap(from, 300, 0);
        assertTrue(ok, "unshieldUnwrap: UA tag");
        assertEq(usd.balanceOf(TO), 10 * SCALE);

        assertEq(tok.mtxNonce(from, LANE), 4, "one lane, four entries");
        assertEq(w.mtxNonce(from, LANE), 1);
    }

    function test_zetherRelayedProofBindsUATag_native() public {
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, nId), 0);
        _eachProofEntry(nId);
    }

    function test_zetherRelayedProofBindsUATag_derived() public {
        _eachProofEntry(aId);
        // a derived signer's shield: `_msgSender()` is `UA_POOL` (the passed subject, not the library's `msg.sender`)
        MetaTxLib.UAEnvelope memory u = _u(aId, address(tok));
        IUARegistry.UASig memory s = _auth(address(tok), u, "UAShield",
            '{"name":"toUA","type":"bytes32"},{"name":"amount","type":"uint256"}', '', string.concat('"toUA":', h(bId), ',"amount":', n(3)));
        vm.expectEmit(address(tok));
        emit IConfidentialToken.Shielded(bId, MetaTxLib.UA_POOL, 3, tok.accountState(bob.ua).pendingSeq + 1);
        vm.prank(ANY);
        IZetherMergedT4(address(tok)).mtxShield(u, bId, 3, s);
        assertEq(tok.balanceOfUA(aId), 40 * SCALE - 3 * SCALE);
    }

    /// The binding the token computes is the spec formula (the merged view under the plain name, R35, spec §2.3).
    function test_zetherEnvelopeBindingViewIsTheUATag() public view {
        MetaTxLib.UAEnvelope memory u = _u(aId, address(tok));
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction(u.from, hex"beef", u.batch, u.nonce, u.validUntil,
            u.mode, address(0x1234), u.fee, address(0x5678)); // unbound relayer / fee recipient: not in the binding
        assertEq(IZetherMergedT4(address(tok)).envelopeBinding(m), _uaTag(address(tok), u));
    }

    // ------------------------------------------------------------------ executeMetaTransaction keeps the address tag

    function _meta(bytes memory data) internal view returns (MetaTxLib.MetaTransaction memory) {
        return MetaTxLib.MetaTransaction(payer, data, LANE, tok.mtxNonce(nId, LANE), block.timestamp + 300, 0, address(0), 0,
            address(0));
    }

    function _asUA(MetaTxLib.MetaTransaction memory m) internal pure returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(MetaTxLib.pad(m.from), m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient);
    }

    function _singleCall(uint256 bal, bytes32 binding) internal view returns (bytes memory) {
        Tx memory x = _proveTransfer(tok, alice, bob, 10, bal, _none(), binding);
        return abi.encodeCall(IZetherToken.mtxConfidentialTransferSingle, (_zSingle(x.payload, _none()), x.proof));
    }

    /// The EIP-1776 alias (R3) keeps `SCAAS-ZETHER-ENVELOPE-V1`: a proof bound to the UA tag is refused there, the
    /// address-tag one settles; on the merged `mtxExecute` the reverse.
    function test_zetherExecuteMetaTransactionBindsAddressTag() public {
        MetaTxLib.MetaTransaction memory m = _meta("");
        m.data = _singleCall(500, _uaTag(address(tok), _asUA(m)));
        bytes memory sig = ecdsa(PK, MtxDigest.metaTx(address(tok), m));
        vm.prank(ANY);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.executeMetaTransaction(m, sig);
        m.data = _singleCall(500, _addrTag(address(tok), _asUA(m)));
        sig = ecdsa(PK, MtxDigest.metaTx(address(tok), m));
        vm.prank(ANY);
        assertTrue(tok.executeMetaTransaction(m, sig));
        assertTrue(_holds(tok, bob, 10, false));

        MetaTxLib.MetaTransaction memory n2 = _meta("");
        MetaTxLib.UAMetaTransaction memory um = MetaTxLib.UAMetaTransaction(nId, "", n2.batch, n2.nonce, n2.validUntil, 0,
            address(0), 0, address(0));
        um.data = _singleCall(490, _addrTag(address(tok), _asUA(n2)));
        IUARegistry.UASig memory s;
        s.signature = ecdsa(PK, tok.mtxDigest(um));
        vm.prank(ANY);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxExecute(um, s);
        um.data = _singleCall(490, _uaTag(address(tok), _asUA(n2)));
        s.signature = ecdsa(PK, tok.mtxDigest(um));
        vm.prank(ANY);
        tok.mtxExecute(um, s);
        assertTrue(_holds(tok, bob, 20, false));
    }

    // ------------------------------------------------------------------ fee 0 on every merged entry (invariant 4)

    /// Every merged Zether entry at fee mode `NONE`, a native signer, a relayer nobody bound: it runs, the relayer is paid
    /// nothing, and the subject is checked by its own key with no `requireAuthorized` call for it.
    function test_zetherFeeZero_everyMergedEntry() public {
        vm.expectCall(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, nId), 0);
        uint256 relayerPublic = tok.balanceOf(ANY);

        // shield: `Shielded.from` is the subject's address (the passed subject, not the library's `msg.sender`)
        MetaTxLib.UAEnvelope memory u = _u(nId, address(tok));
        IUARegistry.UASig memory s = _auth(address(tok), u, "UAShield",
            '{"name":"toUA","type":"bytes32"},{"name":"amount","type":"uint256"}', '', string.concat('"toUA":', h(bId), ',"amount":', n(5)));
        uint256 pub = tok.balanceOf(payer);
        vm.expectEmit(address(tok));
        emit IConfidentialToken.Shielded(bId, payer, 5, tok.accountState(bob.ua).pendingSeq + 1);
        vm.prank(ANY);
        IZetherMergedT4(address(tok)).mtxShield(u, bId, 5, s);
        assertEq(tok.balanceOf(payer), pub - 5 * SCALE);

        (bool ok,) = _single(nId, 500, 0);
        assertTrue(ok, "single");
        (ok,) = _multi(nId, 490, false, 0);
        assertTrue(ok, "multi");
        (ok,) = _multi(nId, 480, true, 0);
        assertTrue(ok, "compact");
        (ok,) = _unshield(nId, 470, 0);
        assertTrue(ok, "unshield");
        (ok,) = _unshieldUnwrap(nId, 300, 0);
        assertTrue(ok, "unshieldUnwrap");

        _feeZeroRollOvers();

        assertEq(tok.balanceOf(ANY), relayerPublic, "fee 0: the relayer is paid nothing");
        assertEq(tok.mtxNonce(nId, LANE), 9, "nine merged entries on the one lane");
        assertEq(w.mtxNonce(nId, LANE), 1);
    }

    /// The four roll-over entries of `test_zetherFeeZero_everyMergedEntry` (bob has pending credits from its transfers).
    function _feeZeroRollOvers() internal {
        MetaTxLib.UAEnvelope memory u = _u(nId, address(tok));
        IUARegistry.UASig memory s = _auth(address(tok), u, "UARollOver", '{"name":"ua","type":"bytes32"},{"name":"n","type":"uint256"}', '',
            string.concat('"ua":', h(bId), ',"n":', n(1)));
        uint64 acc = tok.accountState(bob.ua).accSeq;
        vm.prank(ANY);
        IZetherMergedT4(address(tok)).mtxRollOver(u, bId, 1, s);
        assertEq(tok.accountState(bob.ua).accSeq, acc + 1, "rollOver");

        _fund(tok, bob, 3);
        ZetherTypes.UA[] memory uas = new ZetherTypes.UA[](1);
        uas[0] = bob.ua;
        u = _u(nId, address(tok));
        s = _auth(address(tok), u, "UARollOverBatch", '{"name":"uas","type":"bytes32[]"}', '', string.concat('"uas":[', h(bId), ']'));
        vm.prank(ANY);
        IZetherMergedT4(address(tok)).mtxRollOverBatch(u, uas, s);
        assertEq(tok.accountState(bob.ua).accSeq, acc + 2, "rollOverBatch");

        _rollOverSignedAt(acc);
    }

    function _rollOverSignedAt(uint64 acc) internal {
        _fund(tok, bob, 3);
        uint64 until = uint64(block.number + 10);
        uint64 seq = tok.accountState(bob.ua).pendingSeq;
        IUARegistry.UASig memory owner = _ownerAuth(bob, _rollOverDigest(tok, bob.ua, acc + 2, seq, until));
        MetaTxLib.UAEnvelope memory u = _u(nId, address(tok));
        IUARegistry.UASig memory s = _auth(address(tok), u, "UARollOverSigned",
            '{"name":"ua","type":"bytes32"},{"name":"expectedPendingSeq","type":"uint64"},{"name":"validUntilBlock","type":"uint64"}', '',
            string.concat('"ua":', h(bId), ',"expectedPendingSeq":', n(seq), ',"validUntilBlock":', n(until)));
        vm.prank(ANY);
        IZetherMergedT4(address(tok)).mtxRollOverSigned(u, bob.ua, seq, until, owner, s);
        assertEq(tok.accountState(bob.ua).accSeq, acc + 3, "rollOverSigned");

        owner = _ownerAuth(bob, _setModeDigest(tok, bob.ua, 1, 0, until));
        u = _u(nId, address(tok));
        s = _auth(address(tok), u, "UASetRollOverMode",
            '{"name":"ua","type":"bytes32"},{"name":"rollOverMode","type":"uint8"},{"name":"validUntilBlock","type":"uint64"}', '',
            string.concat('"ua":', h(bId), ',"rollOverMode":', n(1), ',"validUntilBlock":', n(until)));
        vm.prank(ANY);
        IZetherMergedT4(address(tok)).mtxSetRollOverMode(u, bob.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, owner, s);
        assertEq(uint8(tok.accountState(bob.ua).mode), 1, "setRollOverMode");
    }

    // ------------------------------------------------------------------ never lose ciphertext

    /// A merged relayed transfer leaves every ciphertext in contract state: the receiver's pending, the sender's acc, the
    /// record (`salt ‖ Y_t ‖ C_out ‖ D_out ‖ C_aud`, read back from storage) and, commit-reveal, the record by SSTORE2
    /// with the memo.
    function test_zetherCiphertextInState() public {
        MetaTxLib.UAEnvelope memory u = _u(nId, address(tok));
        Tx memory x = _proveTransfer(tok, alice, bob, 10, 500, _none(), _uaTag(address(tok), u));
        IZetherToken.ZetherSingle memory t = _zSingle(x.payload, _none());
        IUARegistry.UASig memory s = _auth(address(tok), u, "UAZetherTransferSingle",
            '{"name":"args","type":"ZetherSingle"},{"name":"proof","type":"bytes"}', string.concat(',', T_G1, ',', T_SINGLE),
            _proofMsg(singleJson(t), x.proof));
        vm.prank(ANY);
        bytes32 ref = IZetherMergedT4(address(tok)).mtxConfidentialTransferSingle(u, t, x.proof, s);
        assertEq(tok.transferEntry(ref), _singleRecord(x.payload), "the record in state");
        IZetherToken.AccountState memory st = tok.accountState(bob.ua);
        assertEq(st.pendingC, abi.encode(t.cOut), "C_out in the receiver's pending");
        assertEq(st.pendingD, abi.encode(t.dOut), "D_out in the receiver's pending");
        assertTrue(_holds(tok, bob, 10, false));
        assertTrue(_holds(tok, alice, 490, true));

        (bool ok, bytes memory ret) = _multi(nId, 490, true, 0);
        assertTrue(ok);
        ref = abi.decode(ret, (bytes32));
        assertGt(tok.transferEntry(ref).length, 0, "the commit-reveal record by SSTORE2");
        assertEq(tok.transferMemo(ref), _memo(2), "the memo in state");
    }

    function _singleRecord(bytes memory p) internal pure returns (bytes memory) {
        return bytes.concat(_cut(p, 96, 16), _cut(p, 112 + 128, 128), _cut(p, 112 + 2 * 128, 128), _cut(p, 112 + 3 * 128, 128),
            _cut(p, 112 + 5 * 128, 128));
    }

    function _cut(bytes memory b, uint256 from, uint256 len) internal pure returns (bytes memory r) {
        r = new bytes(len);
        for (uint256 i; i < len; ++i) r[i] = b[from + i];
    }

    // ------------------------------------------------------------------ the retired forms (invariant 3), the ids

    function _noEntry(address t, bytes memory cd, string memory what) internal {
        vm.prank(ANY);
        (bool ok, bytes memory ret) = t.call(cd);
        assertFalse(ok, what);
        assertEq(ret.length, 0, what);
    }

    /// The address signed entries, the `ua*` names and both old binding views: no function serves them (valid calldata,
    /// so a function that existed would answer or revert by name).
    function test_zetherRetiredFormsHaveNoEntry() public {
        MetaTxLib.Envelope memory e = MetaTxLib.Envelope(payer, LANE, 0, block.timestamp + 300, 0, address(0), 0, address(0));
        address t = address(tok);
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxShield, (e, bId, 1, "")), "address mtxShield");
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxConfidentialTransfer, (e, _mt(), "", "")), "address mtxConfidentialTransfer");
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxConfidentialTransferCompact, (e, _mt(), "", "")), "address compact");
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxConfidentialTransferSingle, (e, _st(), "", "")), "address single");
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxUnshield, (e, _bt(), 1, bId, "", "")), "address mtxUnshield");
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxRollOver, (e, bId, 1, "")), "address mtxRollOver");
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxRollOverBatch, (e, _uas(), "")), "address mtxRollOverBatch");
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxRollOverSigned, (e, bob.ua, 0, 0, _s(), "")), "address mtxRollOverSigned");
        _noEntry(t, abi.encodeCall(IZetherOldT4.mtxSetRollOverMode, (e, bob.ua, ZetherTypes.RollOverMode.PUBLIC, 0, _s(), "")),
            "address mtxSetRollOverMode");
        _noEntry(address(w), abi.encodeCall(IZetherOldT4.mtxUnshieldUnwrap, (e, _bt(), _x(), "", "")), "address mtxUnshieldUnwrap");
        _retiredUA();
        MetaTxLib.MetaTransaction memory m = _meta("");
        _noEntry(t, abi.encodeCall(IZetherOldT4.envelopeBinding, (m)), "address envelopeBinding view");
        MetaTxLib.UAMetaTransaction memory um;
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaEnvelopeBinding, (um)), "uaEnvelopeBinding view");
    }

    /// The `ua*` names of `test_zetherRetiredFormsHaveNoEntry`.
    function _retiredUA() internal {
        MetaTxLib.UAEnvelope memory u = _u(nId, address(tok));
        address t = address(tok);
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaShield, (u, bId, 1, _s())), "uaShield");
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaConfidentialTransfer, (u, _mt(), "", _s())), "uaConfidentialTransfer");
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaConfidentialTransferCompact, (u, _mt(), "", _s())), "uaConfidentialTransferCompact");
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaConfidentialTransferSingle, (u, _st(), "", _s())), "uaConfidentialTransferSingle");
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaUnshield, (u, _bt(), 1, bId, "", _s())), "uaUnshield");
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaRollOver, (u, bId, 1, _s())), "uaRollOver");
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaRollOverBatch, (u, _uas(), _s())), "uaRollOverBatch");
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaRollOverSigned, (u, bob.ua, 0, 0, _s(), _s())), "uaRollOverSigned");
        _noEntry(t, abi.encodeCall(IZetherOldT4.uaSetRollOverMode, (u, bob.ua, ZetherTypes.RollOverMode.PUBLIC, 0, _s(), _s())),
            "uaSetRollOverMode");
        _noEntry(address(w), abi.encodeCall(IZetherOldT4.uaUnshieldUnwrap, (u, _bt(), _x(), "", _s())), "uaUnshieldUnwrap");
    }

    function _mt() internal pure returns (IZetherToken.ZetherMulti memory t) {}
    function _st() internal pure returns (IZetherToken.ZetherSingle memory t) {}
    function _bt() internal pure returns (IZetherToken.ZetherBurn memory t) {}
    function _x() internal pure returns (IConfidentialWrappedToken.Unwrap memory t) {}
    function _uas() internal pure returns (ZetherTypes.UA[] memory t) {}
    function _s() internal pure returns (IUARegistry.UASig memory t) {}

    /// `IZetherToken`'s id moves with its binding views (R35); `IConfidentialToken`'s and the wrapped one's do not.
    function test_zetherInterfaceIdsArePinned() public pure {
        // 0xaefc54bc before T4; group 3g T52: 0x66b526f6 -> 0xe65bc5f0 (`mtxRollOver(bytes32,uint256)` moved here from
        // `IConfidentialToken`, the same selector; the PQZ rollover takes a key version)
        assertEq(type(IZetherToken).interfaceId, bytes4(0xe65bc5f0), "IZetherToken");
        assertEq(type(IConfidentialToken).interfaceId, IConfidentialToken.mtxShield.selector, "IConfidentialToken");
        assertEq(type(IZetherWrappedToken).interfaceId, IZetherWrappedToken.mtxUnshieldUnwrap.selector, "IZetherWrappedToken");
    }
}

/// Risk 9: on a merged entry only the binding value changes, not the statement's layout. The s3 vectors' statements
/// (the prover's bytes for a relayed proof, binding `0x33…33`) rebuilt on their own context through the token's builders
/// are equal byte for byte; built with a UA binding instead they differ in the binding word alone. A layout change here
/// stops the task (a new `proofSystemId` is not this round).
contract ZetherStatementLayoutTest is ZetherFixture {
    using stdJson for string;

    string constant DIR = "test/vectors/zether/s3/";
    StatementHarness internal hs;
    address internal registry = address(0xEE11);

    function setUp() public {
        _stack();
        hs = new StatementHarness();
        vm.mockCall(registry, abi.encodeWithSelector(IUARegistry.kindOf.selector), abi.encode(UAKinds.ZETHER_BLS12381));
    }

    function _ctxOf(string memory j) internal view returns (ZetherLib.Ctx memory c, ZetherLib.Acct memory a_) {
        c.ver = ver;
        c.burnVer = burnVer;
        c.registry = registry;
        c.token = j.readAddress(".request.token");
        c.chainUid = j.readBytes32(".request.chainUid");
        c.psid = ver.proofSystemId();
        c.p = 128;
        c.fee = vm.keyExistsJson(j, ".request.fee") ? j.readUint(".request.fee") : 0;
        c.maxShielded = 1 << 54;
        c.disclosureMode = ZetherTypes.DisclosureMode.BUNDLE;
        c.binding = j.readBytes32(".request.envelopeBinding");
        c.tag = keccak256("ZTX_V1_RELAYED");
        if (vm.keyExistsJson(j, ".request.yAud") && bytes(j.readString(".request.yAud")).length > 2) {
            c.auditorKey = j.readBytes(".request.yAud");
            c.auditorMode = ZetherTypes.AuditorMode.FULL;
        }
        a_.accC = j.readBytes(".request.acc.C");
        a_.accD = j.readBytes(".request.acc.D");
        a_.accSeq = uint64(j.readUint(".request.accSeq"));
        a_.sendCounter = uint64(j.readUint(".request.sendCounter"));
    }

    function _ben(string memory j) internal view returns (ZetherTypes.UA) {
        if (!vm.keyExistsJson(j, ".request.beneficiary") || bytes(j.readString(".request.beneficiary")).length < 66) return _none();
        return ZetherTypes.UA.wrap(j.readBytes32(".request.beneficiary"));
    }

    /// A UA binding of a fixed envelope on the vector's token (the spec formula).
    function _uaBinding(ZetherLib.Ctx memory c) internal view returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-ZETHER-UA-ENVELOPE-V1"), block.chainid, c.chainUid, c.token,
                bytes32(uint256(0xD0D0) << 160 | 0xA11CE), uint256(7)),
            abi.encode(uint256(3), uint256(1_800_000_000), uint32(0), address(0), uint256(0), address(0))));
    }

    /// `s0` with its binding word (bytes 192–223, after the tag word) replaced by `b`.
    function _withBinding(bytes memory s0, bytes32 b) internal pure returns (bytes memory s) {
        s = bytes.concat(s0);
        assembly ("memory-safe") { mstore(add(s, 224), b) }
    }

    function _word(bytes memory s, uint256 off) internal pure returns (bytes32 x) {
        assembly ("memory-safe") { x := mload(add(add(s, 32), off)) }
    }

    function test_zetherStatementLayoutUnchanged() public {
        string memory j = vm.readFile(string.concat(DIR, "transfer_bls12381.json"));
        vm.chainId(j.readUint(".request.chainId"));
        (ZetherLib.Ctx memory c, ZetherLib.Acct memory a_) = _ctxOf(j);
        IZetherToken.ZetherSingle memory t = _zSingle(j.readBytes(".payload"), _ben(j));
        bytes memory s0 = hs.single(c, a_, t);
        assertEq(s0, j.readBytes(".statement"), "transfer: the prover's relayed statement");
        assertEq(_word(s0, 160), keccak256("ZTX_V1_RELAYED"));
        assertEq(_word(s0, 192), c.binding);
        c.binding = _uaBinding(c);
        bytes memory s1 = hs.single(c, a_, t);
        assertEq(s1.length, s0.length, "transfer: same length");
        assertEq(s1, _withBinding(s0, c.binding), "transfer: only the binding word differs");
        _burnLayout();
    }

    function _burnLayout() internal {
        string memory j = vm.readFile(string.concat(DIR, "burn_bls12381.json"));
        vm.chainId(j.readUint(".request.chainId"));
        (ZetherLib.Ctx memory c, ZetherLib.Acct memory a_) = _ctxOf(j);
        IZetherToken.ZetherBurn memory b = _zBurn(j.readBytes(".payload"), _ben(j));
        uint256 amount = j.readUint(".request.amount");
        bytes32 rcpt = MetaTxLib.pad(j.readAddress(".request.recipient"));
        bytes memory s0 = hs.burn(c, a_, b, amount, rcpt);
        assertEq(s0, j.readBytes(".statement"), "burn: the prover's relayed statement");
        c.binding = _uaBinding(c);
        bytes memory s1 = hs.burn(c, a_, b, amount, rcpt);
        assertEq(s1.length, s0.length, "burn: same length");
        assertEq(s1, _withBinding(s0, c.binding), "burn: only the binding word differs");
    }
}
