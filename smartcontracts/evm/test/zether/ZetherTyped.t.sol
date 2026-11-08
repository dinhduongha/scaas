// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {UACall} from "../ua/UACall.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZetherFixture} from "./helpers/ZetherFixture.sol";
import {ZetherKeys} from "./helpers/ZetherKeys.sol";
import {VM, E_TYPES, TYPED_OPS, TYPED_OPS_LEGACY, n, a, h, eJson, domainJson, ecdsa, checkRow, onChain, domainOf, rowEnvelope, rowEnvelope2, msgField, domainField}
    from "../metatx/NamedEntry.t.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {TokenStore} from "../../src/metatx/TokenStore.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {ZetherLayer} from "../../src/zether/ZetherLayer.sol";
import {ZetherLib} from "../../src/zether/ZetherLib.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";
import {IZetherToken} from "../../src/zether/IZetherToken.sol";
import {IZetherVerifier, IZetherBurnVerifier} from "../../src/zether/IZetherVerifier.sol";
import {WrappedZetherToken} from "../../src/zether/WrappedZetherToken.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";

string constant SIG_G1 = '{"name":"x0","type":"bytes32"},{"name":"x1","type":"bytes32"},{"name":"y0","type":"bytes32"},{"name":"y1","type":"bytes32"}';
string constant T_G1 = string.concat('"G1":[', SIG_G1, ']');
string constant T_SINGLE = '"ZetherSingle":[{"name":"accSeq","type":"uint64"},{"name":"sendCounter","type":"uint64"},{"name":"validUntilBlock","type":"uint256"},'
    '{"name":"salt","type":"bytes16"},{"name":"beneficiaryUA","type":"bytes32"},{"name":"yFrom","type":"G1"},{"name":"yTo","type":"G1"},'
    '{"name":"cOut","type":"G1"},{"name":"dOut","type":"G1"},{"name":"cDeb","type":"G1"},{"name":"cAud","type":"G1"}]';
string constant T_LEG = '"ZetherLeg":[{"name":"yTo","type":"G1"},{"name":"cOut","type":"G1"},{"name":"cAud","type":"G1"},{"name":"dAud","type":"G1"}]';
string constant T_MULTI = '"ZetherMulti":[{"name":"accSeq","type":"uint64"},{"name":"sendCounter","type":"uint64"},{"name":"validUntilBlock","type":"uint256"},'
    '{"name":"salt","type":"bytes16"},{"name":"beneficiaryUA","type":"bytes32"},{"name":"decoyFee","type":"uint256"},{"name":"yFrom","type":"G1"},'
    '{"name":"dOut","type":"G1"},{"name":"cDeb","type":"G1"},{"name":"legs","type":"ZetherLeg[]"},{"name":"sealedMemo","type":"bytes"}]';
string constant T_BURN = '"ZetherBurn":[{"name":"accSeq","type":"uint64"},{"name":"sendCounter","type":"uint64"},{"name":"validUntilBlock","type":"uint256"},'
    '{"name":"beneficiaryUA","type":"bytes32"},{"name":"yFrom","type":"G1"}]';
string constant T_UNWRAP = '"Unwrap":[{"name":"underlying","type":"address"},{"name":"recipient","type":"bytes32"},{"name":"amount","type":"uint256"},{"name":"minOut","type":"uint256"}]';

/// The digest a wallet computes for the JSON it is handed (`eth_signTypedData_v4`), nothing from the contract's hash.
function typedDigest(address c, string memory primary, string memory fields, string memory nested, string memory message)
    view returns (bytes32)
{
    return VM.eip712HashTypedData(string.concat(
        '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},',
        '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"},{"name":"salt","type":"bytes32"}],"',
        primary, '":[', fields, ',', E_TYPES, ']', nested, '},"primaryType":"', primary, '","domain":', domainJson(c),
        ',"message":{', message, '}}'
    ));
}

function g1Json(IZetherToken.G1 memory g) pure returns (string memory) {
    return string.concat('{"x0":', h(g.x0), ',"x1":', h(g.x1), ',"y0":', h(g.y0), ',"y1":', h(g.y1), '}');
}

function hexJson(bytes memory b) pure returns (string memory) {
    return string.concat('"', VM.toString(b), '"');
}

function singleJson(IZetherToken.ZetherSingle memory t) pure returns (string memory) {
    return string.concat(
        string.concat('{"accSeq":', n(t.accSeq), ',"sendCounter":', n(t.sendCounter), ',"validUntilBlock":', n(t.validUntilBlock),
            ',"salt":', hexJson(abi.encodePacked(t.salt)), ',"beneficiaryUA":', h(t.beneficiaryUA)),
        string.concat(',"yFrom":', g1Json(t.yFrom), ',"yTo":', g1Json(t.yTo), ',"cOut":', g1Json(t.cOut), ',"dOut":', g1Json(t.dOut),
            ',"cDeb":', g1Json(t.cDeb), ',"cAud":', g1Json(t.cAud), '}'));
}

function multiJson(IZetherToken.ZetherMulti memory t) pure returns (string memory) {
    string memory legs;
    for (uint256 j; j < t.legs.length; ++j) {
        IZetherToken.ZetherLeg memory l = t.legs[j];
        legs = string.concat(legs, j == 0 ? '' : ',', '{"yTo":', g1Json(l.yTo), ',"cOut":', g1Json(l.cOut), ',"cAud":', g1Json(l.cAud),
            ',"dAud":', g1Json(l.dAud), '}');
    }
    return string.concat(
        string.concat('{"accSeq":', n(t.accSeq), ',"sendCounter":', n(t.sendCounter), ',"validUntilBlock":', n(t.validUntilBlock),
            ',"salt":', hexJson(abi.encodePacked(t.salt)), ',"beneficiaryUA":', h(t.beneficiaryUA), ',"decoyFee":', n(t.decoyFee)),
        string.concat(',"yFrom":', g1Json(t.yFrom), ',"dOut":', g1Json(t.dOut), ',"cDeb":', g1Json(t.cDeb), ',"legs":[', legs, '],"sealedMemo":',
            hexJson(t.sealedMemo), '}'));
}

function burnJson(IZetherToken.ZetherBurn memory b) pure returns (string memory) {
    return string.concat('{"accSeq":', n(b.accSeq), ',"sendCounter":', n(b.sendCounter), ',"validUntilBlock":', n(b.validUntilBlock),
        ',"beneficiaryUA":', h(b.beneficiaryUA), ',"yFrom":', g1Json(b.yFrom), '}');
}

/// `ZetherLib`'s statement builders on a row's own context: what the token would build, with no chain state of its own.
contract StatementHarness {
    function single(ZetherLib.Ctx calldata c, ZetherLib.Acct calldata a, IZetherToken.ZetherSingle calldata t)
        external view returns (bytes memory)
    {
        return ZetherLib.prepareSingle(c, a, t).statement;
    }

    function multi(ZetherLib.Ctx calldata c, ZetherLib.Acct calldata a, IZetherToken.ZetherMulti calldata t, ZetherTypes.TransferMode m)
        external view returns (bytes memory)
    {
        return ZetherLib.prepareMulti(c, a, t, m).statement;
    }

    function burn(ZetherLib.Ctx calldata c, ZetherLib.Acct calldata a, IZetherToken.ZetherBurn calldata b, uint256 amount, bytes32 recipient)
        external view returns (bytes memory)
    {
        return ZetherLib.prepareUnshield(c, a, b, amount, recipient).statement;
    }
}

/// typed-signing C3 (TS-D14, TS-D17, TS-D19): the explicit parameters are the old packed bytes, statement and record, byte for
/// byte; every signed Zether entry takes a wallet's typed signature, on the kept pipeline and the proof's envelope binding.
abstract contract ZetherNamedBase is ZetherFixture {
    using stdJson for string;

    uint256 internal constant PAYER_PK = 0x9A7E5;
    uint256 internal constant LANE = 7;
    address internal payer = vm.addr(PAYER_PK);
    uint32 internal constant FIX = MetaTxLib.MODE_FEE_FIXED;

    bytes32 internal aId;
    bytes32 internal bId;

    function _ids() internal {
        aId = ZetherTypes.UA.unwrap(alice.ua);
        bId = ZetherTypes.UA.unwrap(bob.ua);
    }

    function _env(uint256 nonce, uint256 fee) internal view returns (MetaTxLib.Envelope memory e) {
        e.from = payer;
        e.batch = LANE;
        e.nonce = nonce;
        e.validUntil = block.timestamp + 300;
        e.mode = FIX;
        e.fee = fee;
    }

    function _uaEnv(bytes32 from, uint256 nonce, uint256 fee) internal view returns (MetaTxLib.UAEnvelope memory u) {
        u.from = from;
        u.batch = LANE;
        u.nonce = nonce;
        u.validUntil = block.timestamp + 300;
        u.mode = FIX;
        u.fee = fee;
    }

    /// The address binding of `e` (`executeMetaTransaction`'s, CTR-ZTH-06), as a client computes it.
    function _bindingOf(ZetherLayer t, MetaTxLib.Envelope memory e) internal view returns (bytes32) {
        return _addrBinding(t, MetaTxLib.MetaTransaction(e.from, "", e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient));
    }

    function _uaBindingOf(ZetherLayer t, MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return t.envelopeBinding(MetaTxLib.UAMetaTransaction(u.from, "", u.batch, u.nonce, u.validUntil, u.mode, u.relayer, u.fee, u.feeRecipient));
    }

    /// ua-mtx-merge T4 (R35): the payer EOA's envelope on a merged entry, its id padded; it signs the entry's `UA*` struct
    /// by its own key (`_eoa`), its proof bound to the UA tag.
    function _nEnv(uint256 nonce, uint256 fee) internal view returns (MetaTxLib.UAEnvelope memory) {
        return _uaEnv(MetaTxLib.pad(payer), nonce, fee);
    }

    function _eoa(bytes32 digest) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = ecdsa(PAYER_PK, digest);
    }

    /// The message's fields around the op's own, the op's first (`from`, op, `E`).
    function _msg(address from, string memory op, MetaTxLib.Envelope memory e) internal pure returns (string memory) {
        return string.concat('"from":', a(from), ',', op, ',', eJson(e.batch, e.nonce, e.validUntil, e.mode, e.fee));
    }

    function _msg(bytes32 from, string memory op, MetaTxLib.UAEnvelope memory u) internal pure returns (string memory) {
        return string.concat('"from":', h(from), ',', op, ',', eJson(u.batch, u.nonce, u.validUntil, u.mode, u.fee));
    }

    function _argsMsg(string memory args, bytes memory proof) internal pure returns (string memory) {
        return string.concat('"args":', args, ',"proof":', hexJson(proof));
    }

    string internal constant F_FROM = '{"name":"from","type":"address"}';
    string internal constant F_UA = '{"name":"from","type":"bytes32"}';

    function _fields(bool ua, string memory arg, string memory rest) internal pure returns (string memory) {
        return string.concat(ua ? F_UA : F_FROM, ',{"name":"args","type":"', arg, '"},', rest);
    }

    function _ownerSig(User memory u, bytes32 digest) internal view returns (IUARegistry.UASig memory s) {
        s.signature = ZetherKeys.schnorr(u.x, reg.uaMessage(_zkind(), UAKinds.PURPOSE_ZETHER_OWNER, digest), bls);
    }

    function _uaAuth(User memory u, bytes32 digest) internal view returns (IUARegistry.UASig memory s) {
        s.signature = ZetherKeys.schnorr(u.x, reg.uaMessage(_zkind(), UAKinds.PURPOSE_METATX, digest), bls);
    }
}

contract ZetherTypedTest is ZetherNamedBase {
    function setUp() public {
        _deploy(true);
        _ids();
        _public(tok, payer, 1000);
        _fund(tok, alice, 500);
        tok.mtxRollOver(aId, 1);
        vm.prank(payer);
        tok.transferToUA(aId, 1000 - 900); // alice's UA pays the outer fee of the `ua*` twins
    }

    // ------------------------------------------------------------------ shield

    function test_zetherNamedShield() public {
        _public(tok, payer, 15 * SCALE);
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 2);
        string memory op = string.concat('"toUA":', h(bId), ',"amount":', n(10));
        IUARegistry.UASig memory sig = _eoa(typedDigest(address(tok), "UAShield",
            '{"name":"from","type":"bytes32"},{"name":"toUA","type":"bytes32"},{"name":"amount","type":"uint256"}', '', _msg(e.from, op, e)));
        uint256 before = tok.balanceOf(payer);
        vm.prank(relayer);
        tok.mtxShield(e, bId, 10, sig);
        assertEq(tok.balanceOf(payer), before - 10 * SCALE - 2);
        assertEq(tok.balanceOf(relayer), 2);
        assertEq(tok.totalShielded(), 510);
        assertEq(tok.mtxNonce(MetaTxLib.pad(payer), LANE), 1);

        // a derived id on the same entry, its auth an explicit `UASig` (ua-mtx-merge T1, R47; it kept `bytes auth` at C0)
        vm.prank(payer);
        tok.transferToUA(aId, 5 * SCALE);
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 1);
        bytes32 d = typedDigest(address(tok), "UAShield",
            '{"name":"from","type":"bytes32"},{"name":"toUA","type":"bytes32"},{"name":"amount","type":"uint256"}', '',
            _msg(aId, string.concat('"toUA":', h(bId), ',"amount":', n(5)), u));
        vm.prank(relayer);
        tok.mtxShield(u, bId, 5, UACall.auth(u.from, abi.encode(bytes(""), _uaAuth(alice, d).signature)));
        assertEq(tok.totalShielded(), 515);
        assertEq(tok.mtxNonce(aId, LANE), 1);
    }

    // ------------------------------------------------------------------ transfer, the three forms and their twins

    function _singleSig(MetaTxLib.UAEnvelope memory e, IZetherToken.ZetherSingle memory t, bytes memory proof)
        internal view returns (IUARegistry.UASig memory)
    {
        return _eoa(typedDigest(address(tok), "UAZetherTransferSingle", _fields(true, "ZetherSingle", '{"name":"proof","type":"bytes"}'),
            string.concat(',', T_G1, ',', T_SINGLE), _msg(e.from, _argsMsg(singleJson(t), proof), e)));
    }

    function test_zetherTransferTyped_single() public {
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 3);
        Tx memory x = _proveTransfer(tok, alice, bob, 100, 500, carol.ua, _uaBindingOf(tok, e));
        IZetherToken.ZetherSingle memory t = _zSingle(x.payload, carol.ua);
        IUARegistry.UASig memory sig = _singleSig(e, t, x.proof);
        vm.prank(relayer);
        bytes32 ref = tok.mtxConfidentialTransferSingle(e, t, x.proof, sig);
        assertEq(ref, _ref(tok, alice, 0));
        assertTrue(_holds(tok, bob, 100, false));
        assertTrue(_holds(tok, alice, 500 - 100 - FEE, true));
        assertEq(tok.balanceOf(relayer), 3, "the outer fee from the signer");
        assertEq(tok.balanceOfUA(ZetherTypes.UA.unwrap(carol.ua)), FEE * SCALE, "the inner fee to the beneficiary");
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        tok.mtxConfidentialTransferSingle(e, t, x.proof, sig);
    }

    function test_zetherTransferTyped_singleUA() public {
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 3);
        Tx memory x = _proveTransfer(tok, alice, bob, 100, 500, _none(), _uaBindingOf(tok, u));
        IZetherToken.ZetherSingle memory t = _zSingle(x.payload, _none());
        bytes32 d = typedDigest(address(tok), "UAZetherTransferSingle", _fields(true, "ZetherSingle", '{"name":"proof","type":"bytes"}'),
            string.concat(',', T_G1, ',', T_SINGLE), _msg(aId, _argsMsg(singleJson(t), x.proof), u));
        vm.prank(relayer);
        assertEq(tok.mtxConfidentialTransferSingle(u, t, x.proof, _uaAuth(alice, d)), _ref(tok, alice, 0));
        assertTrue(_holds(tok, bob, 100, false));
        assertEq(tok.mtxNonce(aId, LANE), 1);
    }

    function _multiArgs(ZetherTypes.TransferMode mode, ZetherTypes.UA ben, bytes32 binding)
        internal view returns (IZetherToken.ZetherMulti memory t, Tx memory x)
    {
        User[] memory to = new User[](2);
        (to[0], to[1]) = (bob, carol);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (40, 0);
        x = _proveMulti(tok, alice, to, vs, 500, ben, mode, binding);
        t = _zMulti(x.payload, ben);
    }

    function _multiDigest(string memory primary, bool ua, string memory message) internal view returns (bytes32) {
        return typedDigest(address(tok), primary, _fields(ua, "ZetherMulti", '{"name":"proof","type":"bytes"}'),
            string.concat(',', T_G1, ',', T_LEG, ',', T_MULTI), message);
    }

    function test_zetherTransferTyped_bundle() public {
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 3);
        (IZetherToken.ZetherMulti memory t, Tx memory x) = _multiArgs(ZetherTypes.TransferMode.BUNDLE, carol.ua, _uaBindingOf(tok, e));
        IUARegistry.UASig memory sig = _eoa(_multiDigest("UAZetherTransfer", true, _msg(e.from, _argsMsg(multiJson(t), x.proof), e)));
        vm.prank(relayer);
        bytes32 ref = tok.mtxConfidentialTransfer(e, t, x.proof, sig);
        assertEq(ref, _ref(tok, alice, 0));
        assertTrue(_holds(tok, bob, 40, false));
        assertEq(tok.transferMemo(ref).length, 0);
    }

    function test_zetherTransferTyped_compact() public {
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 3);
        (IZetherToken.ZetherMulti memory t, Tx memory x) = _multiArgs(ZetherTypes.TransferMode.HASH, carol.ua, _uaBindingOf(tok, e));
        assertEq(t.sealedMemo.length, 1 + 40 * 2);
        IUARegistry.UASig memory sig = _eoa(_multiDigest("UAZetherTransferCompact", true, _msg(e.from, _argsMsg(multiJson(t), x.proof), e)));
        vm.prank(relayer);
        bytes32 ref = tok.mtxConfidentialTransferCompact(e, t, x.proof, sig);
        assertEq(tok.transferMemo(ref), _memo(2));
    }

    function test_zetherTransferTyped_bundleUA() public {
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 3);
        (IZetherToken.ZetherMulti memory t, Tx memory x) = _multiArgs(ZetherTypes.TransferMode.BUNDLE, _none(), _uaBindingOf(tok, u));
        bytes32 d = _multiDigest("UAZetherTransfer", true, _msg(aId, _argsMsg(multiJson(t), x.proof), u));
        vm.prank(relayer);
        assertEq(tok.mtxConfidentialTransfer(u, t, x.proof, _uaAuth(alice, d)), _ref(tok, alice, 0));
        assertTrue(_holds(tok, bob, 40, false));
    }

    function test_zetherTransferTyped_compactUA() public {
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 3);
        (IZetherToken.ZetherMulti memory t, Tx memory x) = _multiArgs(ZetherTypes.TransferMode.HASH, _none(), _uaBindingOf(tok, u));
        bytes32 d = _multiDigest("UAZetherTransferCompact", true, _msg(aId, _argsMsg(multiJson(t), x.proof), u));
        vm.prank(relayer);
        bytes32 ref = tok.mtxConfidentialTransferCompact(u, t, x.proof, _uaAuth(alice, d));
        assertEq(tok.transferMemo(ref), _memo(2));
    }

    /// A signature over one field set fails on another: a changed point, the proof, a form's name.
    function test_zetherTypedTamperRefused() public {
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 3);
        (IZetherToken.ZetherMulti memory t, Tx memory x) = _multiArgs(ZetherTypes.TransferMode.BUNDLE, carol.ua, _uaBindingOf(tok, e));
        IUARegistry.UASig memory sig = _eoa(_multiDigest("UAZetherTransfer", true, _msg(e.from, _argsMsg(multiJson(t), x.proof), e)));
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxConfidentialTransferCompact(e, t, x.proof, sig);
        t.legs[1].cAud.x0 = bytes32(uint256(t.legs[1].cAud.x0) ^ 1);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxConfidentialTransfer(e, t, x.proof, sig);
        t.legs[1].cAud.x0 = bytes32(uint256(t.legs[1].cAud.x0) ^ 1);
        bytes memory other = bytes.concat(x.proof);
        other[0] ^= 0x01;
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxConfidentialTransfer(e, t, other, sig);
    }

    /// TS-D14: a confidential op is `ABSOLUTE` on the named entry as on the generic path.
    function test_zetherNamedFeeClass() public {
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 3);
        e.mode = MetaTxLib.MODE_FEE_PERCENT;
        Tx memory x = _proveTransfer(tok, alice, bob, 100, 500, _none(), _uaBindingOf(tok, e));
        IZetherToken.ZetherSingle memory t = _zSingle(x.payload, _none());
        IUARegistry.UASig memory sig = _singleSig(e, t, x.proof);
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MtxFeeClass.selector, IZetherToken.mtxConfidentialTransferSingle.selector, e.mode));
        tok.mtxConfidentialTransferSingle(e, t, x.proof, sig);
    }

    /// TAG_RELAYED with the named entry's envelope: the statement names it, a proof lifted out fails, the same envelope
    /// through the generic path shares the lane.
    function test_zetherEnvelopeBindingNamed() public {
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 3);
        bytes32 b = _uaBindingOf(tok, e);
        Tx memory x = _proveTransfer(tok, alice, bob, 100, 500, _none(), b);
        IZetherToken.ZetherSingle memory t = _zSingle(x.payload, _none());
        bytes memory st = stm.transferStatementSingle(address(tok), t, b);
        bytes32 tag;
        bytes32 word;
        assembly ("memory-safe") {
            tag := mload(add(st, 192))
            word := mload(add(st, 224))
        }
        assertEq(tag, keccak256("ZTX_V1_RELAYED"));
        assertEq(word, b);
        IUARegistry.UASig memory sig = _singleSig(e, t, x.proof);

        // lifted out of the envelope, the proof is not a direct one
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(t, x.proof);

        // nor one of another envelope: a fee changed by the relayer is another signature and another binding
        MetaTxLib.UAEnvelope memory e2 = _nEnv(0, 4);
        IUARegistry.UASig memory sig2 = _singleSig(e2, t, x.proof);
        vm.expectRevert(IZetherToken.ProofRejected.selector);
        tok.mtxConfidentialTransferSingle(e2, t, x.proof, sig2);

        vm.prank(relayer);
        tok.mtxConfidentialTransferSingle(e, t, x.proof, sig);

        // the same lane as `mtxExecute`: nonce 0 is gone for the generic form of the same envelope
        MetaTxLib.MetaTransaction memory m = MetaTxLib.MetaTransaction(payer, abi.encodeCall(IZetherToken.mtxConfidentialTransferSingle, (t, x.proof)),
            e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient);
        bytes memory generic = ecdsa(PAYER_PK, MtxDigest.metaTx(address(tok), m));
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        tok.executeMetaTransaction(m, generic);
    }

    // ------------------------------------------------------------------ unshield

    function test_zetherUnshieldExplicit() public {
        // direct
        address to = address(0xB0C);
        bytes32 rcpt = MetaTxLib.pad(to);
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 60, 500, to, carol.ua, 0);
        IZetherToken.ZetherBurn memory b = _zBurn(pl, carol.ua);
        tok.mtxUnshield(b, 60, rcpt, pr);
        assertEq(tok.balanceOf(to), 60 * SCALE);
        assertTrue(_holds(tok, alice, 500 - 60 - FEE, true));

        // named: `amount` and `recipient` flat in the entry and in the struct
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 3);
        uint256 bal = 500 - 60 - FEE;
        (pl, pr) = _proveUnshield(tok, alice, 30, bal, to, _none(), _uaBindingOf(tok, e));
        b = _zBurn(pl, _none());
        string memory op = string.concat('"args":', burnJson(b), ',"amount":', n(30), ',"recipient":', h(rcpt), ',"proof":', hexJson(pr));
        string memory f = string.concat(F_UA, ',{"name":"args","type":"ZetherBurn"},{"name":"amount","type":"uint256"},{"name":"recipient","type":"bytes32"},{"name":"proof","type":"bytes"}');
        IUARegistry.UASig memory sig = _eoa(typedDigest(address(tok), "UAZetherUnshield", f, string.concat(',', T_G1, ',', T_BURN), _msg(e.from, op, e)));
        // the amount is signed: the same signature on another amount fails
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        tok.mtxUnshield(e, b, 31, rcpt, pr, sig);
        vm.prank(relayer);
        tok.mtxUnshield(e, b, 30, rcpt, pr, sig);
        assertEq(tok.balanceOf(to), 90 * SCALE);

        // a derived id on the same entry
        bal -= 30;
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 1);
        (pl, pr) = _proveUnshield(tok, alice, 10, bal, to, _none(), _uaBindingOf(tok, u));
        b = _zBurn(pl, _none());
        op = string.concat('"args":', burnJson(b), ',"amount":', n(10), ',"recipient":', h(rcpt), ',"proof":', hexJson(pr));
        f = string.concat(F_UA, ',{"name":"args","type":"ZetherBurn"},{"name":"amount","type":"uint256"},{"name":"recipient","type":"bytes32"},{"name":"proof","type":"bytes"}');
        bytes32 d = typedDigest(address(tok), "UAZetherUnshield", f, string.concat(',', T_G1, ',', T_BURN), _msg(aId, op, u));
        vm.prank(relayer);
        tok.mtxUnshield(u, b, 10, rcpt, pr, _uaAuth(alice, d));
        assertEq(tok.balanceOf(to), 100 * SCALE);
    }

    /// `amount` is bound before the header as before: the fold's precondition (zether-msm review) holds on the explicit form.
    function test_zetherUnshieldBoundsKept() public {
        (bytes memory pl, bytes memory pr) = _proveUnshield(tok, alice, 60, 500, address(0xB0C), _none(), 0);
        IZetherToken.ZetherBurn memory b = _zBurn(pl, _none());
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, 0, tok.maxDecryptableShielded()));
        tok.mtxUnshield(b, 0, MetaTxLib.pad(address(0xB0C)), pr);
        uint256 over = tok.maxDecryptableShielded() + 1;
        vm.expectRevert(abi.encodeWithSelector(IZetherToken.AmountOutOfRange.selector, over, tok.maxDecryptableShielded()));
        tok.mtxUnshield(b, over, MetaTxLib.pad(address(0xB0C)), pr);
    }

    // ------------------------------------------------------------------ the typed owner ops (TS-D19)

    function _rollOverDigest(bytes32 ua, uint64 accSeq, uint64 expected, uint64 until) internal view returns (bytes32) {
        return VM.eip712HashTypedData(string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},',
            '{"name":"verifyingContract","type":"address"},{"name":"salt","type":"bytes32"}],"ZetherRollOver":[{"name":"ua","type":"bytes32"},',
            '{"name":"accSeq","type":"uint64"},{"name":"expectedPendingSeq","type":"uint64"},{"name":"validUntilBlock","type":"uint64"}]},',
            '"primaryType":"ZetherRollOver","domain":', domainJson(address(tok)), ',"message":{"ua":', h(ua), ',"accSeq":', n(accSeq),
            ',"expectedPendingSeq":', n(expected), ',"validUntilBlock":', n(until), '}}'));
    }

    function _modeDigest(bytes32 ua, uint8 mode, uint64 modeNonce, uint64 until) internal view returns (bytes32) {
        return VM.eip712HashTypedData(string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},',
            '{"name":"verifyingContract","type":"address"},{"name":"salt","type":"bytes32"}],"ZetherSetRollOverMode":[{"name":"ua","type":"bytes32"},',
            '{"name":"mode","type":"uint8"},{"name":"modeNonce","type":"uint64"},{"name":"validUntilBlock","type":"uint64"}]},',
            '"primaryType":"ZetherSetRollOverMode","domain":', domainJson(address(tok)), ',"message":{"ua":', h(ua), ',"mode":', n(mode),
            ',"modeNonce":', n(modeNonce), ',"validUntilBlock":', n(until), '}}'));
    }

    string internal constant F_MODE = ',{"name":"ua","type":"bytes32"},{"name":"rollOverMode","type":"uint8"},{"name":"validUntilBlock","type":"uint64"}';
    string internal constant F_ROLL = ',{"name":"ua","type":"bytes32"},{"name":"expectedPendingSeq","type":"uint64"},{"name":"validUntilBlock","type":"uint64"}';

    function _modeMsg(uint8 mode, uint64 until) internal view returns (string memory) {
        return string.concat('"ua":', h(aId), ',"rollOverMode":', n(mode), ',"validUntilBlock":', n(until));
    }

    function _rollMsg(uint64 seq, uint64 until) internal view returns (string memory) {
        return string.concat('"ua":', h(aId), ',"expectedPendingSeq":', n(seq), ',"validUntilBlock":', n(until));
    }

    function test_zetherSetRollOverModeTyped() public {
        uint64 until = uint64(block.number + 10);
        IUARegistry.UASig memory s = _ownerSig(alice, _modeDigest(aId, 1, 0, until));
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, s);
        assertEq(uint8(tok.accountState(alice.ua).mode), 1);
        assertEq(tok.accountState(alice.ua).modeNonce, 1);

        // the digest binds `modeNonce`: no replay
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, aId));
        tok.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, s);

        // bound to this token's domain: another token's owner digest does not pass (`modeNonce` 0 there, so only the domain differs)
        ZetherLayer other = _newToken(true, "other");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, aId));
        other.mtxSetRollOverMode(alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, s);
    }

    /// The named entry: `UASetRollOverMode` under the outer signer (an EOA, then a derived id), the owner's signature beside it.
    function test_zetherNamedSetRollOverMode() public {
        uint64 until = uint64(block.number + 10);
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 2);
        IUARegistry.UASig memory s = _ownerSig(alice, _modeDigest(aId, 1, 0, until));
        IUARegistry.UASig memory sig = _eoa(typedDigest(address(tok), "UASetRollOverMode", string.concat(F_UA, F_MODE), '', _msg(e.from, _modeMsg(1, until), e)));
        vm.prank(relayer);
        tok.mtxSetRollOverMode(e, alice.ua, ZetherTypes.RollOverMode.OWNER_ONLY, until, s, sig);
        assertEq(uint8(tok.accountState(alice.ua).mode), 1);
        assertEq(tok.mtxNonce(MetaTxLib.pad(payer), LANE), 1);

        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 1);
        s = _ownerSig(alice, _modeDigest(aId, 0, 1, until));
        bytes32 d = typedDigest(address(tok), "UASetRollOverMode", string.concat(F_UA, F_MODE), '', _msg(aId, _modeMsg(0, until), u));
        vm.prank(relayer);
        tok.mtxSetRollOverMode(u, alice.ua, ZetherTypes.RollOverMode.PUBLIC, until, s, _uaAuth(alice, d));
        assertEq(uint8(tok.accountState(alice.ua).mode), 0);
    }

    function test_zetherOwnerRollOverTyped() public {
        _fund(tok, alice, 20);
        uint64 until = uint64(block.number + 10);
        uint64 seq = tok.accountState(alice.ua).pendingSeq;
        uint64 acc = tok.accountState(alice.ua).accSeq;
        tok.mtxRollOverSigned(alice.ua, seq, until, _ownerSig(alice, _rollOverDigest(aId, acc, seq, until)));
        assertEq(tok.accountState(alice.ua).accSeq, acc + 1);

        // a signature is for one `accSeq`: it moved
        _fund(tok, alice, 20);
        seq = tok.accountState(alice.ua).pendingSeq;
        IUARegistry.UASig memory s = _ownerSig(alice, _rollOverDigest(aId, acc, seq, until));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, aId));
        tok.mtxRollOverSigned(alice.ua, seq, until, s);
    }

    function test_zetherNamedRollOverSigned() public {
        uint64 until = uint64(block.number + 10);
        _fund(tok, alice, 20);
        uint64 seq = tok.accountState(alice.ua).pendingSeq;
        uint64 acc = tok.accountState(alice.ua).accSeq;
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 2);
        IUARegistry.UASig memory s = _ownerSig(alice, _rollOverDigest(aId, acc, seq, until));
        IUARegistry.UASig memory sig = _rollEntrySig(e, seq, until);
        vm.prank(relayer);
        tok.mtxRollOverSigned(e, alice.ua, seq, until, s, sig);
        assertEq(tok.accountState(alice.ua).accSeq, acc + 1);
    }

    function test_zetherUARollOverSigned() public {
        uint64 until = uint64(block.number + 10);
        _fund(tok, alice, 20);
        uint64 seq = tok.accountState(alice.ua).pendingSeq;
        uint64 acc = tok.accountState(alice.ua).accSeq;
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 1);
        IUARegistry.UASig memory s = _ownerSig(alice, _rollOverDigest(aId, acc, seq, until));
        IUARegistry.UASig memory au = _rollEntryAuth(u, seq, until);
        vm.prank(relayer);
        tok.mtxRollOverSigned(u, alice.ua, seq, until, s, au);
        assertEq(tok.accountState(alice.ua).accSeq, acc + 1);
    }

    function _rollEntrySig(MetaTxLib.UAEnvelope memory e, uint64 seq, uint64 until) internal view returns (IUARegistry.UASig memory) {
        return _eoa(typedDigest(address(tok), "UARollOverSigned", string.concat(F_UA, F_ROLL), '', _msg(e.from, _rollMsg(seq, until), e)));
    }

    function _rollEntryAuth(MetaTxLib.UAEnvelope memory u, uint64 seq, uint64 until) internal view returns (IUARegistry.UASig memory) {
        return _uaAuth(alice, typedDigest(address(tok), "UARollOverSigned", string.concat(F_UA, F_ROLL), '', _msg(aId, _rollMsg(seq, until), u)));
    }

    /// The anonymous roll-overs: `UARollOver`, `UARollOverBatch`, by an EOA then a derived id (R35).
    function test_zetherNamedRollOver() public {
        _fund(tok, alice, 20);
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 2);
        string memory op = string.concat('"ua":', h(aId), ',"n":', n(1));
        string memory f = ',{"name":"ua","type":"bytes32"},{"name":"n","type":"uint256"}';
        IUARegistry.UASig memory sig = _eoa(typedDigest(address(tok), "UARollOver", string.concat(F_UA, f), '', _msg(e.from, op, e)));
        uint64 acc = tok.accountState(alice.ua).accSeq;
        vm.prank(relayer);
        tok.mtxRollOver(e, aId, 1, sig);
        assertEq(tok.accountState(alice.ua).accSeq, acc + 1);

        _fund(tok, alice, 20);
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 1);
        bytes32 d = typedDigest(address(tok), "UARollOver", string.concat(F_UA, f), '', _msg(aId, op, u));
        vm.prank(relayer);
        tok.mtxRollOver(u, aId, 1, _uaAuth(alice, d));
        assertEq(tok.accountState(alice.ua).accSeq, acc + 2);
    }

    function test_zetherNamedRollOverBatch() public {
        _fund(tok, alice, 20);
        ZetherTypes.UA[] memory uas = new ZetherTypes.UA[](1);
        uas[0] = alice.ua;
        uint64 acc = tok.accountState(alice.ua).accSeq;
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 2);
        string memory op = string.concat('"uas":[', h(aId), ']');
        IUARegistry.UASig memory sig = _eoa(typedDigest(address(tok), "UARollOverBatch", string.concat(F_UA, ',{"name":"uas","type":"bytes32[]"}'), '', _msg(e.from, op, e)));
        vm.prank(relayer);
        tok.mtxRollOverBatch(e, uas, sig);
        assertEq(tok.accountState(alice.ua).accSeq, acc + 1);

        _fund(tok, alice, 20);
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 1);
        bytes32 d = typedDigest(address(tok), "UARollOverBatch", string.concat(F_UA, ',{"name":"uas","type":"bytes32[]"}'), '', _msg(aId, op, u));
        vm.prank(relayer);
        tok.mtxRollOverBatch(u, uas, _uaAuth(alice, d));
        assertEq(tok.accountState(alice.ua).accSeq, acc + 2);
    }

    // ------------------------------------------------------------------ stored bytes

    /// `salt ‖ B`: the record as the packed payload made it, from the explicit parameters; every point in state.
    function test_zetherTransferStoredBytesUnchanged() public {
        // single (`salt ‖ Y_t ‖ C_out ‖ D_out ‖ C_aud`)
        Tx memory x = _proveTransfer(tok, alice, bob, 100, 500, _none(), 0);
        bytes32 ref = tok.mtxConfidentialTransferSingle(_zSingle(x.payload, _none()), x.proof);
        bytes memory p = x.payload;
        assertEq(tok.transferEntry(ref), bytes.concat(_cut(p, 96, 16), _cut(p, 112 + 128, 128), _cut(p, 112 + 2 * 128, 128),
            _cut(p, 112 + 3 * 128, 128), _cut(p, 112 + 5 * 128, 128)), "the single record");

        // bundle: `salt ‖ (Y_tj ‖ C_out_j ‖ D_out ‖ C_aud_j ‖ D_aud_j)_j`
        tok.mtxRollOver(bId, 1);
        uint256 bal = 500 - 100;
        (IZetherToken.ZetherMulti memory t, Tx memory y) = _multiFrom(bal, ZetherTypes.TransferMode.BUNDLE);
        ref = tok.mtxConfidentialTransfer(t, y.proof);
        assertEq(tok.transferEntry(ref), _recordOf(y.payload, 2), "the bundle record");
        assertEq(tok.transferMemo(ref).length, 0);

        // commit-reveal: the record by SSTORE2, the memo as given, `salt ‖ sealed`
        (t, y) = _multiFrom(bal - 40, ZetherTypes.TransferMode.HASH);
        ref = tok.mtxConfidentialTransferCompact(t, y.proof);
        assertEq(tok.transferEntry(ref), _recordOf(y.payload, 2), "the commit-reveal record");
        assertEq(tok.transferMemo(ref), _memo(2));
        assertEq(tok.transferMemo(ref), _cut(y.payload, 176 + 3 * 128 + 2 * 512, 16 + 81), "the memo bytes of the packed payload");
    }

    function _multiFrom(uint256 bal, ZetherTypes.TransferMode mode) internal view returns (IZetherToken.ZetherMulti memory t, Tx memory x) {
        User[] memory to = new User[](2);
        (to[0], to[1]) = (carol, bob);
        uint256[] memory vs = new uint256[](2);
        (vs[0], vs[1]) = (40, 0);
        x = _proveMulti(tok, alice, to, vs, bal, _none(), mode);
        t = _zMulti(x.payload, _none());
    }

    function _recordOf(bytes memory p, uint256 m) internal pure returns (bytes memory r) {
        r = _cut(p, 96, 16);
        for (uint256 j; j < m; ++j) {
            uint256 o = 176 + 3 * 128 + 512 * j;
            r = bytes.concat(r, _cut(p, o, 2 * 128), _cut(p, 176 + 128, 128), _cut(p, o + 2 * 128, 2 * 128));
        }
    }

    function _cut(bytes memory b, uint256 from, uint256 len) internal pure returns (bytes memory r) {
        r = new bytes(len);
        for (uint256 i; i < len; ++i) r[i] = b[from + i];
    }
}

/// The wrapped kind's two leg paths, signed.
contract ZetherTypedWrappedTest is ZetherNamedBase {
    WrappedZetherToken internal w;
    MockERC20 internal usd = new MockERC20("USD", "USD", 6);

    function setUp() public {
        _stack();
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
        tok = ZetherLayer(address(w));
        _users();
        _ids();
        usd.mint(payer, 1_000 * SCALE);
        vm.startPrank(payer);
        usd.approve(address(w), 1_000 * SCALE);
        w.wrap(100 * SCALE);
        vm.stopPrank();
    }

    function test_zetherNamedWrapShield() public {
        MetaTxLib.Envelope memory e = _env(0, 2);
        string memory op = string.concat('"underlying":', a(address(usd)), ',"amountIn":', n(10 * SCALE), ',"toUA":', h(aId));
        bytes memory sig = ecdsa(PAYER_PK, typedDigest(address(w), "WrapShield", string.concat(F_FROM,
            ',{"name":"underlying","type":"address"},{"name":"amountIn","type":"uint256"},{"name":"toUA","type":"bytes32"}'), '', _msg(payer, op, e)));
        vm.prank(relayer);
        w.mtxWrapShield(e, address(usd), 10 * SCALE, aId, sig);
        assertEq(w.totalShielded(), 10);
        assertEq(w.balanceOf(SHIELD_POOL_), 10 * SCALE);
        assertEq(w.mtxNonce(MetaTxLib.pad(payer), LANE), 1);
        assertEq(w.balanceOf(relayer), 2, "the outer fee from the signer's public units");
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        w.mtxWrapShield(e, address(usd), 10 * SCALE, aId, sig);
    }

    function _shielded() internal {
        vm.prank(payer);
        w.mtxWrapShield(address(usd), 300 * SCALE, aId);
        w.mtxRollOver(aId, 1);
    }

    function _unwrapMsg(IZetherToken.ZetherBurn memory b, IConfidentialWrappedToken.Unwrap memory x, bytes memory pr) internal pure returns (string memory) {
        string memory uw = string.concat('{"underlying":', a(x.underlying), ',"recipient":', h(x.recipient), ',"amount":', n(x.amount), ',"minOut":', n(x.minOut), '}');
        return string.concat('"args":', burnJson(b), ',"unwrap":', uw, ',"proof":', hexJson(pr));
    }

    function _unwrapProof(IConfidentialWrappedToken.Unwrap memory x, uint256 bal, bytes32 bd)
        internal view returns (IZetherToken.ZetherBurn memory b, bytes memory pr)
    {
        b = _zBurn(_unshieldPayload(tok, alice), _none());
        pr = _proveU(alice, stm.unshieldUnwrapStatement(address(w), b, x.amount, x.recipient, x.underlying, x.minOut, bd), x.amount, bal, _none(), tok);
    }

    function _unwrapOf(uint256 amount) internal view returns (IConfidentialWrappedToken.Unwrap memory) {
        return IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xB0C)), amount, amount * SCALE);
    }

    function _unwrapFields(string memory from) internal pure returns (string memory) {
        return string.concat(from, ',{"name":"args","type":"ZetherBurn"},{"name":"unwrap","type":"Unwrap"},{"name":"proof","type":"bytes"}');
    }

    function test_zetherUnshieldUnwrapExplicit() public {
        _shielded();
        IConfidentialWrappedToken.Unwrap memory x = _unwrapOf(60);
        (IZetherToken.ZetherBurn memory b, bytes memory pr) = _unwrapProof(x, 300, 0); // direct: the leg and `minOut` in the binding
        w.mtxUnshieldUnwrap(b, x, pr);
        assertEq(usd.balanceOf(address(0xB0C)), 60 * SCALE);
    }

    function test_zetherNamedUnshieldUnwrap() public {
        _shielded();
        MetaTxLib.UAEnvelope memory e = _nEnv(0, 2);
        IConfidentialWrappedToken.Unwrap memory x = _unwrapOf(30);
        (IZetherToken.ZetherBurn memory b, bytes memory pr) = _unwrapProof(x, 300, _uaBindingOf(tok, e));
        IUARegistry.UASig memory sig = _eoa(typedDigest(address(w), "UAZetherUnshieldUnwrap", _unwrapFields(F_UA),
            string.concat(',', T_G1, ',', T_UNWRAP, ',', T_BURN), _msg(e.from, _unwrapMsg(b, x, pr), e)));
        vm.prank(relayer);
        w.mtxUnshieldUnwrap(e, b, x, pr, sig);
        assertEq(usd.balanceOf(address(0xB0C)), 30 * SCALE);
    }

    function test_zetherUAUnshieldUnwrap() public {
        _shielded();
        vm.prank(payer);
        w.transferToUA(aId, 100);
        MetaTxLib.UAEnvelope memory u = _uaEnv(aId, 0, 1);
        IConfidentialWrappedToken.Unwrap memory x = _unwrapOf(10);
        (IZetherToken.ZetherBurn memory b, bytes memory pr) = _unwrapProof(x, 300, _uaBindingOf(tok, u));
        bytes32 d = typedDigest(address(w), "UAZetherUnshieldUnwrap", _unwrapFields(F_UA),
            string.concat(',', T_G1, ',', T_UNWRAP, ',', T_BURN), _msg(aId, _unwrapMsg(b, x, pr), u));
        vm.prank(relayer);
        w.mtxUnshieldUnwrap(u, b, x, pr, _uaAuth(alice, d));
        assertEq(usd.balanceOf(address(0xB0C)), 10 * SCALE);
    }
}

/// The prover's bytes (`test/vectors/zether/s3`): the explicit struct of each row's packed payload rebuilds its statement
/// byte for byte, on the row's own context, through the token's builders.
contract ZetherExplicitStatementTest is ZetherFixture {
    using stdJson for string;

    string constant DIR = "test/vectors/zether/s3/";
    StatementHarness internal hs;
    address internal registry = address(0xEE11);

    function setUp() public {
        (ver, burnVer) = _verifiers();
        hs = new StatementHarness();
        vm.mockCall(registry, abi.encodeWithSelector(IUARegistry.kindOf.selector), abi.encode(UAKinds.ZETHER_BLS12381));
    }

    function _verifiers() internal returns (IZetherVerifier, IZetherBurnVerifier) {
        _stack();
        return (ver, burnVer);
    }

    function _ctxOf(string memory j, bool burn_) internal view returns (ZetherLib.Ctx memory c, ZetherLib.Acct memory a_) {
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
        bytes32 b = vm.keyExistsJson(j, ".request.envelopeBinding") ? j.readBytes32(".request.envelopeBinding") : bytes32(0);
        c.binding = b;
        c.tag = keccak256(b == 0 ? bytes("ZTX_V1_DIRECT") : bytes("ZTX_V1_RELAYED"));
        if (!burn_ && vm.keyExistsJson(j, ".request.yAud") && bytes(j.readString(".request.yAud")).length > 2) {
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

    function _single(string memory file) internal {
        string memory j = vm.readFile(string.concat(DIR, file));
        vm.chainId(j.readUint(".request.chainId"));
        (ZetherLib.Ctx memory c, ZetherLib.Acct memory a_) = _ctxOf(j, false);
        assertEq(hs.single(c, a_, _zSingle(j.readBytes(".payload"), _ben(j))), j.readBytes(".statement"), file);
    }

    function _multi(string memory file) internal {
        string memory j = vm.readFile(string.concat(DIR, file));
        vm.chainId(j.readUint(".request.chainId"));
        (ZetherLib.Ctx memory c, ZetherLib.Acct memory a_) = _ctxOf(j, false);
        c.ver = ver;
        ZetherTypes.TransferMode m = keccak256(bytes(j.readString(".mode"))) == keccak256("compact")
            ? ZetherTypes.TransferMode.HASH : ZetherTypes.TransferMode.BUNDLE;
        assertEq(hs.multi(c, a_, _zMulti(j.readBytes(".payload"), _ben(j)), m), j.readBytes(".statement"), file);
    }

    function test_zetherTransferExplicitStatementBytes() public {
        _single("transfer_bls12381.json");
        _single("transfer_noaud_bls12381.json");
        _multi("transfer_multi_bls12381.json");
        _multi("transfer_multi_noaud_bls12381.json");

        string memory j = vm.readFile(string.concat(DIR, "burn_bls12381.json"));
        vm.chainId(j.readUint(".request.chainId"));
        (ZetherLib.Ctx memory c, ZetherLib.Acct memory a_) = _ctxOf(j, true);
        assertEq(hs.burn(c, a_, _zBurn(j.readBytes(".payload"), _ben(j)), j.readUint(".request.amount"),
            MetaTxLib.pad(j.readAddress(".request.recipient"))), j.readBytes(".statement"), "burn");
    }
}

/// Every Zether row of `typed_ops.json`: its calldata is the message's fields on this ABI, and under a token's own domain the
/// row's struct hash is the one the entry hashes: the entry passes the signature and runs into the op's own check.
contract ZetherTypedRowsTest is ZetherNamedBase {
    using stdJson for string;

    string internal j;

    function setUp() public {
        _deploy(true);
        j = vm.readFile(TYPED_OPS);
    }

    function _p(string memory op, string memory f) internal pure returns (string memory) {
        return msgField(op, f);
    }

    function _pt(string memory path) internal view returns (IZetherToken.G1 memory g) {
        g.x0 = j.readBytes32(string.concat(path, ".x0"));
        g.x1 = j.readBytes32(string.concat(path, ".x1"));
        g.y0 = j.readBytes32(string.concat(path, ".y0"));
        g.y1 = j.readBytes32(string.concat(path, ".y1"));
    }

    function _uaE(string memory op) internal view returns (MetaTxLib.UAEnvelope memory u) {
        MetaTxLib.Envelope memory e = rowEnvelope2(j, op);
        u = MetaTxLib.UAEnvelope(j.readBytes32(_p(op, "from")), e.batch, e.nonce, e.validUntil, e.mode, e.relayer, e.fee, e.feeRecipient);
    }

    function _sig(string memory op) internal view returns (bytes memory) {
        return j.readBytes(domainField(op, "zether", "signature"));
    }

    function _uaSigOf(string memory op) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sig(op);
    }

    function _owner(string memory op) internal view returns (IUARegistry.UASig memory s) {
        s.signature = j.readBytes(string.concat(".ops.", op, ".domains.zether.extra.ownerSig.signature"));
    }

    function _single(string memory op) internal view returns (IZetherToken.ZetherSingle memory t) {
        string memory q = _p(op, "args");
        t.accSeq = uint64(j.readUint(string.concat(q, ".accSeq")));
        t.sendCounter = uint64(j.readUint(string.concat(q, ".sendCounter")));
        t.validUntilBlock = j.readUint(string.concat(q, ".validUntilBlock"));
        t.salt = bytes16(j.readBytes(string.concat(q, ".salt")));
        t.beneficiaryUA = j.readBytes32(string.concat(q, ".beneficiaryUA"));
        t.yFrom = _pt(string.concat(q, ".yFrom"));
        t.yTo = _pt(string.concat(q, ".yTo"));
        t.cOut = _pt(string.concat(q, ".cOut"));
        t.dOut = _pt(string.concat(q, ".dOut"));
        t.cDeb = _pt(string.concat(q, ".cDeb"));
        t.cAud = _pt(string.concat(q, ".cAud"));
    }

    /// @dev From the row's calldata: each of the 40 points read from the JSON would copy the whole file to memory. The entry
    ///      hashes what it decodes, so a calldata that differs from the row's message fails the signature in `_reach`.
    function _multi(string memory op) internal view returns (IZetherToken.ZetherMulti memory t) {
        bytes memory cd = j.readBytes(domainField(op, "zether", "calldata"));
        assembly ("memory-safe") {
            mstore(add(cd, 4), sub(mload(cd), 4)) // the arguments, past the selector
            cd := add(cd, 4)
        }
        (, t) = abi.decode(cd, (bytes32[8], IZetherToken.ZetherMulti));
    }

    function _burn(string memory op) internal view returns (IZetherToken.ZetherBurn memory b) {
        string memory q = _p(op, "args");
        b.accSeq = uint64(j.readUint(string.concat(q, ".accSeq")));
        b.sendCounter = uint64(j.readUint(string.concat(q, ".sendCounter")));
        b.validUntilBlock = j.readUint(string.concat(q, ".validUntilBlock"));
        b.beneficiaryUA = j.readBytes32(string.concat(q, ".beneficiaryUA"));
        b.yFrom = _pt(string.concat(q, ".yFrom"));
    }

    function _unwrap(string memory op) internal view returns (IConfidentialWrappedToken.Unwrap memory x) {
        x.underlying = j.readAddress(_p(op, "unwrap.underlying"));
        x.recipient = j.readBytes32(_p(op, "unwrap.recipient"));
        x.amount = j.readUint(_p(op, "unwrap.amount"));
        x.minOut = j.readUint(_p(op, "unwrap.minOut"));
    }

    /// The row's calldata, the fields' call, and the row's own call under `c`'s domain passing the signature: the revert is
    /// the op's, `want`.
    function _reach(string memory op, address c, bytes memory built, bytes4 want) internal {
        assertEq(built, j.readBytes(domainField(op, "zether", "calldata")), string.concat(op, ": calldata"));
        _reachAs(op, c, built, want);
    }

    /// `_reach` of the row's call `cd` (its own, or under the merged name).
    function _reachAs(string memory op, address c, bytes memory cd, bytes4 want) internal {
        checkRow(j, op, "zether");
        bytes memory rowSig = _sig(op);
        bytes memory sig = onChain(j, op, c);
        for (uint256 i; i + 65 <= cd.length; ++i) {
            bool same = true;
            for (uint256 k; k < 65 && same; ++k) same = cd[i + k] == rowSig[k];
            if (same) {
                for (uint256 k; k < 65; ++k) cd[i + k] = sig[k];
                break;
            }
        }
        vm.prank(j.readAddress(_p(op, "relayer")));
        (bool ok, bytes memory ret) = c.call(cd);
        if (want == bytes4(0)) {
            assertTrue(ok, op);
        } else {
            assertFalse(ok, op);
            assertEq(bytes4(ret), want, string.concat(op, ": the op's own check, the signature passed"));
        }
    }

    /// ua-mtx-merge T11 (R35, MD-7): a `UA…` row names its merged `mtx` entry and runs verbatim (T4 ran the rows' `ua*`
    /// calldata under the `mtx` name, until the rows were regenerated).
    function _reachRenamed(string memory op, address c, bytes memory built, bytes4 want) internal {
        bytes memory name = bytes(j.readString(domainField(op, "zether", "abi")));
        assertEq(abi.encodePacked(name[0], name[1], name[2]), bytes("mtx"), op);
        assertEq(built, j.readBytes(domainField(op, "zether", "calldata")), string.concat(op, ": the merged calldata"));
        _reachAs(op, c, built, want);
    }

    /// ua-mtx-merge T4: the row of a retired address entry (R35): its own calldata finds no function on `c` (MD-7: T11
    /// retires the row).
    function _rowHasNoEntry(string memory op, address c, bytes memory built) internal {
        checkRow(j, op, "zether");
        bytes memory cd = j.readBytes(domainField(op, "zether", "calldata"));
        assertEq(built, cd, string.concat(op, ": the old calldata"));
        vm.prank(j.readAddress(_p(op, "relayer")));
        (bool ok, bytes memory ret) = c.call(cd);
        assertFalse(ok, string.concat(op, ": a retired entry runs"));
        assertEq(ret.length, 0, string.concat(op, ": no function"));
    }

    function _wrapped() internal returns (WrappedZetherToken w) {
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, _zenv(), type(WrappedZetherToken).creationCode);
        IFactoryToken.TokenConfig memory c;
        c.name = "Zether wrapped";
        c.symbol = "zW";
        c.decimals = 6;
        c.features = 1 << GovernanceBits.PAYABLE;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(new MockERC20("USD", "USD", 6)), 1, 1);
        c.conf = IFactoryToken.ConfidentialConfig(bytes(""), SCALE, uint256(1) << 40, FEE, dMode, 0, 0, 0, bytes32(0), false);
        w = WrappedZetherToken(payable(factory.createToken(IOpenFactory.TokenKind.WRAPPED_ZETHER, 1, abi.encode(c), "zw")));
    }

    function test_typedOpsVectors_ZetherTransferSingleRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // ua-mtx-merge T11 (MD-7): the row retired
        string memory op = "ZetherTransferSingle";
        MetaTxLib.Envelope memory e = rowEnvelope(j, op);
        _rowHasNoEntry(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), e, _single(op),
            j.readBytes(_p(op, "proof")), _sig(op)));
    }

    function test_typedOpsVectors_UAZetherTransferSingle() public {
        string memory op = "UAZetherTransferSingle";
        _reachRenamed(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), _uaE(op), _single(op),
            j.readBytes(_p(op, "proof")), _uaSigOf(op)), IZetherToken.AccountNotRegistered.selector);
    }

    function test_typedOpsVectors_ZetherTransferRowsHaveNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // ua-mtx-merge T11 (MD-7): the row retired
        for (uint256 k; k < 2; ++k) {
            string memory op = k == 0 ? "ZetherTransfer" : "ZetherTransferCompact";
            _rowHasNoEntry(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), rowEnvelope(j, op), _multi(op),
                j.readBytes(_p(op, "proof")), _sig(op)));
        }
    }

    function test_typedOpsVectors_UAZetherTransfer() public {
        for (uint256 k; k < 2; ++k) {
            string memory op = k == 0 ? "UAZetherTransfer" : "UAZetherTransferCompact";
            _reachRenamed(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), _uaE(op), _multi(op),
                j.readBytes(_p(op, "proof")), _uaSigOf(op)), IZetherToken.AccountNotRegistered.selector);
        }
    }

    function test_typedOpsVectors_ZetherUnshieldRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // ua-mtx-merge T11 (MD-7): the row retired
        string memory op = "ZetherUnshield";
        _rowHasNoEntry(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), rowEnvelope(j, op), _burn(op),
            j.readUint(_p(op, "amount")), j.readBytes32(_p(op, "recipient")), j.readBytes(_p(op, "proof")), _sig(op)));
    }

    function test_typedOpsVectors_UAZetherUnshield() public {
        string memory op = "UAZetherUnshield";
        _reachRenamed(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), _uaE(op), _burn(op),
            j.readUint(_p(op, "amount")), j.readBytes32(_p(op, "recipient")), j.readBytes(_p(op, "proof")), _uaSigOf(op)),
            IUALedger.UANotRegistered.selector);
    }

    function test_typedOpsVectors_ZetherUnshieldUnwrapRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // ua-mtx-merge T11 (MD-7): the row retired
        string memory op = "ZetherUnshieldUnwrap";
        WrappedZetherToken w = _wrapped();
        _rowHasNoEntry(op, address(w), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), rowEnvelope(j, op), _burn(op), _unwrap(op),
            j.readBytes(_p(op, "proof")), _sig(op)));
    }

    function test_typedOpsVectors_UAZetherUnshieldUnwrap() public {
        string memory op = "UAZetherUnshieldUnwrap";
        WrappedZetherToken w = _wrapped();
        _reachRenamed(op, address(w), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), _uaE(op), _burn(op), _unwrap(op),
            j.readBytes(_p(op, "proof")), _uaSigOf(op)), bytes4(keccak256("UnknownUnderlying(address)")));
    }

    function test_typedOpsVectors_WrapShield() public {
        string memory op = "WrapShield";
        WrappedZetherToken w = _wrapped();
        _reach(op, address(w), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), rowEnvelope(j, op),
            j.readAddress(_p(op, "underlying")), j.readUint(_p(op, "amountIn")), j.readBytes32(_p(op, "toUA")), _sig(op)),
            bytes4(keccak256("UnknownUnderlying(address)")));
    }

    function test_typedOpsVectors_RollOverSignedRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // ua-mtx-merge T11 (MD-7): the row retired
        string memory op = "RollOverSigned";
        _rowHasNoEntry(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), rowEnvelope(j, op), j.readBytes32(_p(op, "ua")),
            uint64(j.readUint(_p(op, "expectedPendingSeq"))), uint64(j.readUint(_p(op, "validUntilBlock"))), _owner(op), _sig(op)));
    }

    function test_typedOpsVectors_UARollOverSigned() public {
        string memory op = "UARollOverSigned";
        _reachRenamed(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), _uaE(op), j.readBytes32(_p(op, "ua")),
            uint64(j.readUint(_p(op, "expectedPendingSeq"))), uint64(j.readUint(_p(op, "validUntilBlock"))), _owner(op), _uaSigOf(op)),
            IZetherToken.AccountNotRegistered.selector);
    }

    function test_typedOpsVectors_SetRollOverModeRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // ua-mtx-merge T11 (MD-7): the row retired
        string memory op = "SetRollOverMode";
        _rowHasNoEntry(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), rowEnvelope(j, op), j.readBytes32(_p(op, "ua")),
            uint8(j.readUint(_p(op, "rollOverMode"))), uint64(j.readUint(_p(op, "validUntilBlock"))), _owner(op), _sig(op)));
    }

    function test_typedOpsVectors_UASetRollOverMode() public {
        string memory op = "UASetRollOverMode";
        _reachRenamed(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), _uaE(op), j.readBytes32(_p(op, "ua")),
            uint8(j.readUint(_p(op, "rollOverMode"))), uint64(j.readUint(_p(op, "validUntilBlock"))), _owner(op), _uaSigOf(op)),
            IZetherToken.AccountNotRegistered.selector);
    }

    /// The owner's inner rows: the row's struct hash is its fields under its own typehash, its calldata is the direct entry's, and a
    /// real owner signing that typehash in the token's domain passes `requireAuthorized` through the row's `abi`.
    function _ownerRow(string memory op, bytes memory fields, bytes memory built) internal view returns (bytes32 th) {
        checkRow(j, op, "zether");
        th = j.readBytes32(string.concat(".ops.", op, ".typehash"));
        assertEq(keccak256(bytes.concat(abi.encode(th), fields)), j.readBytes32(string.concat(".ops.", op, ".structHash")), "structHash");
        assertEq(built, j.readBytes(domainField(op, "zether", "calldata")), "calldata");
    }

    function _rowSig(string memory op) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sig(op);
    }

    function _ownerOf(bytes32 th, bytes memory fields) internal view returns (IUARegistry.UASig memory) {
        return _ownerSig(alice, keccak256(abi.encodePacked(hex"1901", domainOf(address(tok)), keccak256(bytes.concat(abi.encode(th), fields)))));
    }

    function test_typedOpsVectors_ZetherRollOver() public {
        string memory op = "ZetherRollOver";
        string memory sigOf = j.readString(domainField(op, "zether", "abi"));
        (uint64 rowSeq, uint64 until) = (uint64(j.readUint(_p(op, "expectedPendingSeq"))), uint64(j.readUint(_p(op, "validUntilBlock"))));
        bytes32 rowUa = j.readBytes32(_p(op, "ua"));
        bytes32 th = _ownerRow(op, abi.encode(rowUa, uint64(j.readUint(_p(op, "accSeq"))), rowSeq, until),
            abi.encodeWithSignature(sigOf, rowUa, rowSeq, until, _rowSig(op)));

        _rollOverThrough(sigOf, th, until);
    }

    function _rollOverThrough(string memory sigOf, bytes32 th, uint64 until) internal {
        _fund(tok, alice, 20);
        bytes32 ua = ZetherTypes.UA.unwrap(alice.ua);
        IZetherToken.AccountState memory st = tok.accountState(alice.ua);
        IUARegistry.UASig memory s = _ownerOf(th, abi.encode(ua, st.accSeq, st.pendingSeq, until));
        (bool ok, bytes memory ret) = address(tok).call(abi.encodeWithSignature(sigOf, ua, st.pendingSeq, until, s));
        assertTrue(ok, string(ret));
        assertEq(tok.accountState(alice.ua).accSeq, st.accSeq + 1);
    }

    function test_typedOpsVectors_ZetherSetRollOverMode() public {
        string memory op = "ZetherSetRollOverMode";
        string memory sigOf = j.readString(domainField(op, "zether", "abi"));
        (uint8 mode, uint64 until) = (uint8(j.readUint(_p(op, "mode"))), uint64(j.readUint(_p(op, "validUntilBlock"))));
        bytes32 rowUa = j.readBytes32(_p(op, "ua"));
        bytes32 th = _ownerRow(op, abi.encode(rowUa, mode, uint64(j.readUint(_p(op, "modeNonce"))), until),
            abi.encodeWithSignature(sigOf, rowUa, mode, until, _rowSig(op)));

        bytes32 ua = ZetherTypes.UA.unwrap(alice.ua);
        (bool ok, bytes memory ret) = address(tok).call(abi.encodeWithSignature(sigOf, ua, mode, until,
            _ownerOf(th, abi.encode(ua, mode, uint64(0), until))));
        assertTrue(ok, string(ret));
        assertEq(uint8(tok.accountState(alice.ua).mode), mode);
        assertEq(tok.accountState(alice.ua).modeNonce, 1);
    }

    /// The other half of `entry_point_selectors_match_the_spec` (zether-prover): the head of each builder's calldata is this ABI's.
    function test_zetherEntrySelectorPins() public pure {
        assertEq(IZetherToken.mtxConfidentialTransferSingle.selector, bytes4(0x923dc4c9));
        assertEq(IZetherToken.mtxConfidentialTransfer.selector, bytes4(0x42459440));
        assertEq(IZetherToken.mtxConfidentialTransferCompact.selector, bytes4(0x3624c406));
        assertEq(IZetherToken.mtxUnshield.selector, bytes4(0x52da3629));
        assertEq(IConfidentialToken.mtxShield.selector, bytes4(0xe9385800));
    }

    function test_typedOpsVectors_RollOverRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // ua-mtx-merge T11 (MD-7): the row retired
        string memory op = "RollOver";
        _public(tok, j.readAddress(".key.address"), 1 << 40); // the outer fee
        _rowHasNoEntry(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), rowEnvelope(j, op), j.readBytes32(_p(op, "ua")),
            j.readUint(_p(op, "n")), _sig(op)));
    }

    function test_typedOpsVectors_UARollOver() public {
        string memory op = "UARollOver";
        _public(tok, j.readAddress(".key.address"), 1 << 40);
        _reachRenamed(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), _uaE(op), j.readBytes32(_p(op, "ua")),
            j.readUint(_p(op, "n")), _uaSigOf(op)), bytes4(0));
    }

    function _uas(string memory op) internal view returns (bytes32[] memory) {
        return j.readBytes32Array(_p(op, "uas"));
    }

    function test_typedOpsVectors_RollOverBatchRowHasNoEntry() public {
        j = vm.readFile(TYPED_OPS_LEGACY); // ua-mtx-merge T11 (MD-7): the row retired
        string memory op = "RollOverBatch";
        _public(tok, j.readAddress(".key.address"), 1 << 40);
        _rowHasNoEntry(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), rowEnvelope(j, op), _uas(op), _sig(op)));
    }

    function test_typedOpsVectors_UARollOverBatch() public {
        string memory op = "UARollOverBatch";
        _public(tok, j.readAddress(".key.address"), 1 << 40);
        _reachRenamed(op, address(tok), abi.encodeWithSignature(j.readString(domainField(op, "zether", "abi")), _uaE(op), _uas(op), _uaSigOf(op)), bytes4(0));
    }
}
