// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalZetherToken} from "../../../src/zether/NormalZetherToken.sol";

import {ZetherNamedBase, typedDigest, multiJson, singleJson, T_G1, T_LEG, T_MULTI, T_SINGLE} from "../../zether/ZetherTyped.t.sol";
import {Holder} from "../helpers/RegFixture.sol";
import {MockERC20} from "../../helpers/Mocks.sol";
import {Catalogue, regArgs} from "../../helpers/Catalogue.sol";
import {nid} from "../../helpers/Ids.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {WrappedToken} from "../../../src/metatx/WrappedToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {ZetherLayer} from "../../../src/zether/ZetherLayer.sol";
import {ZetherTypes} from "../../../src/zether/ZetherTypes.sol";
import {IZetherToken} from "../../../src/zether/IZetherToken.sol";
import {IConfidentialToken, IConfidentialWrappedToken} from "../../../src/confidential/IConfidentialToken.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {NormalZetherRegulatedToken} from "../../../src/regulated/NormalZetherRegulatedToken.sol";
import {WrappedZetherRegulatedToken} from "../../../src/regulated/WrappedZetherRegulatedToken.sol";
import {ComplianceRegistry} from "../../../src/regulated/ComplianceRegistry.sol";

/// The signed transfer entries alone (no overload), so `abi.encodeCall` can name each.
interface IZetherSigned {
    function mtxConfidentialTransfer(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherMulti calldata t, bytes calldata proof,
        IUARegistry.UASig calldata auth) external returns (bytes32);
    function mtxConfidentialTransferCompact(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherMulti calldata t,
        bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes32);
    function mtxConfidentialTransferSingle(MetaTxLib.UAEnvelope calldata e, IZetherToken.ZetherSingle calldata t,
        bytes calldata proof, IUARegistry.UASig calldata auth) external returns (bytes32);
}

/// The direct unshield-unwrap of kind 11 alone.
interface IZetherUnwrapDirect {
    function mtxUnshieldUnwrap(IZetherToken.ZetherBurn calldata b, IConfidentialWrappedToken.Unwrap calldata x,
        bytes calldata proof) external;
}

/// Measures a call's execution inside one frame: the outer transaction's intrinsic and calldata gas (large for a proof's
/// calldata under `isolate`) is not part of `used`, so `used` is the token's own prefix (I10).
contract GasProbe {
    function probe(address t, bytes calldata cd) external returns (bool ok, bytes memory ret, uint256 used) {
        uint256 g = gasleft();
        (ok, ret) = t.call(cd);
        used = g - gasleft();
    }
}

/// Plan T30's fixture (regulated-kinds spec §4.1, §4.3; Zether only, Zether ≠ PQZ): the real Zether stack (`ZetherFixture`,
/// BLS12-381, the Solidity test prover) with the releases of kinds 10 and 11, and `tok` one token of kind 10 or 11
/// (`_isWrapped`) with `FREEZE`, `FORCE`, `PAUSE`, `RECORD` (the issuer and the compliance holders two contracts, the owner an
/// EOA, `grantDelay` one day) and, when `_denylist`, `DENYLIST` on one canonical `ComplianceRegistry` (`creg`, flag
/// `SANCTIONED`). Public units come from a mint (10) or a 1:1 wrap of `usd` (11). `payer` signs the named entries by its EOA
/// key (ZetherNamedBase); `dave` is a fourth Zether UA.
abstract contract ZetherRegFixture is ZetherNamedBase {
    bytes32 internal constant REF = bytes32(uint256(0x5EF));
    uint256 internal constant REG_FEATURES = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10);
    uint64 internal constant SANCTIONED = 1 << 16;

    address internal ownerA = address(0x0A11);
    address internal issuer;
    address internal compliance;
    address internal cadmin;
    address internal attester = address(0xA77E);
    ComplianceRegistry internal creg;
    MockERC20 internal usd;
    User internal dave;
    bytes32 internal cId;
    bytes32 internal dId;

    function _isWrapped() internal pure virtual returns (bool);

    /// `DENYLIST` on the token `setUp` creates.
    function _denylist() internal pure virtual returns (bool) { return false; }

    /// Round 3s (spec 2026-11-10-token-lists.md §4.3): `DENYLIST` as the token's own list (`setDenied` by the issuer seat)
    /// instead of the registry; `_attestDenied` writes the list and `_deniedErr` is `Denied(a)`.
    function _lists() internal pure virtual returns (bool) { return false; }

    /// The refusal of a denied account at a checked site: the list's `Denied(a)` or the registry's `NotEligible(a, 0)`.
    function _deniedErr(bytes32 a) internal pure returns (bytes memory) {
        return _lists() ? abi.encodeWithSelector(bytes4(keccak256("Denied(bytes32)")), a)
            : abi.encodeWithSelector(IRegulatedToken.NotEligible.selector, a, uint8(0));
    }

    function setUp() public virtual {
        _stack();
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, 1, _zenv(),
            type(NormalZetherRegulatedToken).creationCode, regArgs());
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, 1, _zenv(),
            type(WrappedZetherRegulatedToken).creationCode, regArgs());
        vm.startPrank(registrar);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED, true);
        factory.setTokenKindEnabled(IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED, true);
        vm.stopPrank();
        issuer = address(new Holder());
        compliance = address(new Holder());
        cadmin = address(new Holder());
        creg = new ComplianceRegistry(nid(cadmin), address(0));
        vm.prank(cadmin);
        creg.setKycProvider(nid(attester), true);
        usd = new MockERC20("USD", "USD", 6);
        _users();
        dave = _user(0xDA7E, address(0xD4));
        _ids();
        (cId, dId) = (ZetherTypes.UA.unwrap(carol.ua), ZetherTypes.UA.unwrap(dave.ua));
        tok = _newToken(true, "zr");
    }

    /// The regulated config of kind 10 (`_cfg`'s, an owner, the four controls, the minter this test) or 11 (one leg `usd`
    /// 1:1, `PAYABLE` and the four controls); `DENYLIST` on `creg` when `_denylist`.
    function _regCfg(bool auditor, uint256 maxShielded) internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(auditor, maxShielded);
        c.lockedFeatures = 0;
        c.admin = nid(ownerA);
        c.grantDelay = 1 days;
        c.features |= REG_FEATURES;
        (c.roles.issuer, c.roles.compliance) = (nid(issuer), nid(compliance));
        c.reg.termsHash = keccak256("terms");
        if (_lists()) {
            c.features |= 1 << GovernanceBits.DENYLIST; // round 3s: the token's own deny list, no registry
        } else if (_denylist()) {
            c.features |= 1 << GovernanceBits.DENYLIST;
            (c.reg.complianceRegistry, c.reg.deniedFlags) = (address(creg), SANCTIONED);
        }
        if (_isWrapped()) {
            c.features = (1 << GovernanceBits.PAYABLE) | (c.features & ~uint256(0x1F));
            c.roles.minter = 0;
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        }
    }

    function _kind() internal pure returns (IOpenFactory.TokenKind) {
        return _isWrapped() ? IOpenFactory.TokenKind.WRAPPED_ZETHER_REGULATED : IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED;
    }

    function _newToken(bool auditor, bytes32 s, uint256 maxShielded) internal override returns (NormalZetherToken) {
        return NormalZetherToken(factory.createToken(_kind(), 1, abi.encode(_regCfg(auditor, maxShielded)), s));
    }

    /// Kind 10: a mint; kind 11: a 1:1 wrap of `usd` by this test, then a transfer.
    function _public(NormalZetherToken t, address to, uint256 units) internal override {
        if (!_isWrapped()) return super._public(t, to, units);
        usd.mint(address(this), units);
        usd.approve(address(t), units);
        WrappedToken(payable(address(t))).wrap(address(usd), units);
        if (to != address(this)) t.transfer(to, units);
        minted[address(t)] += units;
    }

    function _r() internal view returns (IRegulatedToken) {
        return IRegulatedToken(address(tok));
    }

    function _freeze(bytes32 a) internal {
        vm.prank(issuer);
        _r().freeze(a, REF, 0);
    }

    function _pause() internal returns (uint64 until) {
        until = uint64(block.timestamp + 1 days);
        vm.prank(issuer);
        _r().pause(REF, until);
    }

    function _attestDenied(bytes32 a) internal {
        if (_lists()) {
            bytes32[] memory one = new bytes32[](1);
            one[0] = a;
            vm.prank(issuer);
            (bool ok,) = address(tok).call(abi.encodeWithSignature("setDenied(bytes32[],bool)", one, true));
            require(ok, "setDenied");
            return;
        }
        bytes32[] memory as_ = new bytes32[](1);
        uint64[] memory fl = new uint64[](1);
        uint64[] memory vu = new uint64[](1);
        (as_[0], fl[0], vu[0]) = (a, SANCTIONED, type(uint64).max);
        vm.prank(attester);
        creg.setCompliance(as_, fl, vu);
    }

    /// `alice` holds `b` shielded units in `acc`.
    function _funded(uint256 b) internal {
        _fund(tok, alice, b);
        tok.mtxRollOver(aId, 1);
    }

    // ------------------------------------------------------------------ the transfer and unshield entries

    /// The three direct transfer entries (spec §4.1): 0 `mtxConfidentialTransfer` (the token's default form), 1 `…Compact`,
    /// 2 `…Single`.
    function _sel(uint256 k) internal pure returns (bytes4) {
        return k == 0 ? IZetherToken.mtxConfidentialTransfer.selector
            : k == 1 ? IZetherToken.mtxConfidentialTransferCompact.selector : IZetherToken.mtxConfidentialTransferSingle.selector;
    }

    /// The direct call of entry `k` (0-2: the transfers, 10 to `bob`; 3: an unshield of 10 to `0xB0C`), `alice` with `bal` in
    /// `acc`, no beneficiary, binding `b` (0: direct).
    function _opCall(uint256 k, uint256 bal, bytes32 b) internal view returns (bytes memory) {
        return _zetherOpCall(k == 3 ? IZetherToken.mtxUnshield.selector : _sel(k), bal, b);
    }

    /// `alice`'s multi transfer of `vs[j]` to `to[j]` with beneficiary `ben` in the token's default form, its direct call.
    function _multiTo(User[] memory to, uint256[] memory vs, uint256 bal, ZetherTypes.UA ben) internal view returns (bytes memory) {
        Tx memory x = _proveMulti(tok, alice, to, vs, bal, ben, _defaultForm(tok));
        return abi.encodeCall(IZetherToken.mtxConfidentialTransfer, (_zMulti(x.payload, ben), x.proof));
    }

    /// The named (signed) call of transfer entry `k` (0-2), `alice`'s proof bound to envelope `e`; the signature by `payer`
    /// (`e.from == pad(payer)`) or by `alice`'s Zether key (`e.from == aId`); `bad`: over another digest.
    function _signedCall(uint256 k, MetaTxLib.UAEnvelope memory e, uint256 bal, bool bad) internal view returns (bytes memory) {
        return k == 2 ? _signedSingle(e, bal, bad) : _signedMulti(k == 1, e, bal, bad);
    }

    function _signedSingle(MetaTxLib.UAEnvelope memory e, uint256 bal, bool bad) internal view returns (bytes memory) {
        Tx memory x = _proveTransfer(tok, alice, bob, 10, bal, _none(), _uaBindingOf(tok, e));
        IZetherToken.ZetherSingle memory t = _zSingle(x.payload, _none());
        bytes32 d = typedDigest(address(tok), "UAZetherTransferSingle",
            _fields(true, "ZetherSingle", '{"name":"proof","type":"bytes"}'), string.concat(',', T_G1, ',', T_SINGLE),
            _msg(e.from, _argsMsg(singleJson(t), x.proof), e));
        return abi.encodeCall(IZetherSigned.mtxConfidentialTransferSingle, (e, t, x.proof, _auth(e, d, bad)));
    }

    function _signedMulti(bool compact, MetaTxLib.UAEnvelope memory e, uint256 bal, bool bad) internal view returns (bytes memory) {
        Tx memory y = _proveOne(compact, bal, _uaBindingOf(tok, e));
        IZetherToken.ZetherMulti memory m = _zMulti(y.payload, _none());
        IUARegistry.UASig memory s = _auth(e, _multiDigest(compact, e, m, y.proof), bad);
        return compact ? abi.encodeCall(IZetherSigned.mtxConfidentialTransferCompact, (e, m, y.proof, s))
            : abi.encodeCall(IZetherSigned.mtxConfidentialTransfer, (e, m, y.proof, s));
    }

    /// `alice`'s multi transfer of 10 to `bob`, no beneficiary, COMPACT or the default form, bound to `bd`.
    function _proveOne(bool compact, uint256 bal, bytes32 bd) internal view returns (Tx memory) {
        User[] memory to = new User[](1);
        to[0] = bob;
        uint256[] memory vs = new uint256[](1);
        vs[0] = 10;
        return _proveMulti(tok, alice, to, vs, bal, _none(), compact ? ZetherTypes.TransferMode.HASH : _defaultForm(tok), bd);
    }

    function _multiDigest(bool compact, MetaTxLib.UAEnvelope memory e, IZetherToken.ZetherMulti memory m, bytes memory proof)
        internal view returns (bytes32)
    {
        return typedDigest(address(tok), compact ? "UAZetherTransferCompact" : "UAZetherTransfer",
            _fields(true, "ZetherMulti", '{"name":"proof","type":"bytes"}'), string.concat(',', T_G1, ',', T_LEG, ',', T_MULTI),
            _msg(e.from, _argsMsg(multiJson(m), proof), e));
    }

    /// `payer`'s ECDSA (`e.from == pad(payer)`) or `alice`'s Zether key (`e.from == aId`) over `d`, or over another digest.
    function _auth(MetaTxLib.UAEnvelope memory e, bytes32 d, bool bad) internal view returns (IUARegistry.UASig memory) {
        if (bad) d = keccak256(abi.encode(d));
        return e.from == aId ? _uaAuth(alice, d) : _eoa(d);
    }

    /// An envelope of `from` on lane `LANE`, nonce 0: fee-bearing (`FIXED`, 3) or not (`NONE`, 0).
    function _envOf(bytes32 from, bool feeBearing) internal view returns (MetaTxLib.UAEnvelope memory e) {
        e = _uaEnv(from, 0, feeBearing ? 3 : 0);
        if (!feeBearing) e.mode = MetaTxLib.MODE_FEE_NONE;
    }

    GasProbe internal gasProbe = new GasProbe();

    /// `cd` on `tok`, relayed by `gasProbe`: success, the revert data and the gas the token's frame used.
    function _try(bytes memory cd) internal returns (bool ok, bytes memory ret, uint256 used) {
        return gasProbe.probe(address(tok), cd);
    }

    /// The unshield-unwrap (kind 11) of `amount` to `0xB0C` through leg `usd`, `alice` with `bal` in `acc`, direct.
    function _unwrapCall(uint256 amount, uint256 bal) internal view returns (bytes memory) {
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xB0C)), amount, amount * SCALE);
        IZetherToken.ZetherBurn memory b = _zBurn(_unshieldPayload(tok, alice), _none());
        bytes memory pr = _proveU(alice, stm.unshieldUnwrapStatement(address(tok), b, x.amount, x.recipient, x.underlying,
            x.minOut, 0), x.amount, bal, _none(), tok);
        return abi.encodeCall(IZetherUnwrapDirect.mtxUnshieldUnwrap, (b, x, pr));
    }
}
