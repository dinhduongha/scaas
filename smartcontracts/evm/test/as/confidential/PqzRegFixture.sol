// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";

import {noVerdict} from "../../pqz/helpers/PqzVerdicts.sol";
import {Vm, VmSafe} from "forge-std/Vm.sol";
// via PqzPairs.t.sol: it and PqzTyped.t.sol import each other, and entering at PqzTyped orders PqzPairsTest before its base
import {PqzNamedBase, transferJson, multiJson, burnJson, T_TRANSFER, T_LEG, T_MULTI, T_BURN, T_UNWRAP} from "../../merge/PqzPairs.t.sol";
import {PQZ_UID} from "../../pqz/helpers/PqzRegistryBase.sol";
import {n, a, h, eJson, ecdsa} from "../../metatx/NamedEntry.t.sol";
import {typedDigest} from "../../zether/ZetherTyped.t.sol";
import {Holder} from "../helpers/RegFixture.sol";
import {GasProbe} from "./ZetherRegFixture.sol";
import {MockERC20} from "../../helpers/Mocks.sol";
import {Catalogue, pqzEnv, regArgs} from "../../helpers/Catalogue.sol";
import {nid} from "../../helpers/Ids.sol";
import {IOpenFactory} from "../../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../../src/factory/IFactoryToken.sol";
import {GovernanceBits} from "../../../src/governance/GovernanceBits.sol";
import {WrappedToken} from "../../../src/metatx/WrappedToken.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {IUARegistry} from "../../../src/ua/IUARegistry.sol";
import {PqzLayer} from "../../../src/pqz/PqzLayer.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {PQZ_ACC_WORDS} from "../../../src/pqz/PqzSet.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {IPqzToken, IPqzWrappedToken} from "../../../src/pqz/IPqzToken.sol";
import {IConfidentialWrappedToken} from "../../../src/confidential/IConfidentialToken.sol";
import {IRegulatedToken} from "../../../src/regulated/IRegulatedToken.sol";
import {NormalPqzRegulatedToken} from "../../../src/regulated/NormalPqzRegulatedToken.sol";
import {WrappedPqzRegulatedToken} from "../../../src/regulated/WrappedPqzRegulatedToken.sol";
import {ComplianceRegistry} from "../../../src/regulated/ComplianceRegistry.sol";

/// The signed PQZ entries alone (no overload), so `abi.encodeCall` can name each.
interface IPqzSigned {
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
}

/// Plan T31's fixture (regulated-kinds spec §4.2, §4.3; PQZ only, Zether ≠ PQZ): the PQZ stack of `PqzFixture` (the gen-1
/// registry, the `PQZ` precompile mocked: a proof passes unless a test makes the op answer 0) with the releases of kinds 12
/// and 13, and `tok` one token of kind 12 or 13 (`_isWrapped`) with `FREEZE`, `FORCE`, `PAUSE`, `RECORD` (the issuer and the
/// compliance holders two contracts, the owner an EOA, `grantDelay` one day) and, when `_denylist`, `DENYLIST` on one
/// canonical `ComplianceRegistry` (`creg`, flag `SANCTIONED`). Public units come from a mint (12) or a 1:1 wrap of `usd` (13);
/// shielded units from a shield (12) or a wrap-shield (13). `signer` signs the named entries by its EOA key (PqzNamedBase).
abstract contract PqzRegFixture is PqzNamedBase {
    bytes32 internal constant REF = bytes32(uint256(0x5EF));
    uint256 internal constant REG_FEATURES = (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10);
    uint64 internal constant SANCTIONED = 1 << 16;
    uint256 internal constant BAL = 500;
    uint256 internal constant PREFIX = 200_000;
    bytes internal constant PROOF = hex"c0de";
    /// keccak256(abi.encode(uint256(keccak256("scaas.pqz")) - 1)) & ~bytes32(uint256(0xff)) (PqzCore._STORAGE)
    bytes32 internal constant PQZ_SLOT = 0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521500;
    uint256 internal constant FIELDS = 19; // pqz ‖ modes … minDecoyFee, sendCounter (group 3g), the verifier state (3f)
    uint256 internal constant ACCT_FIELD = 8; // PqzStorage.acct

    address internal ownerA = address(0x0A11);
    address internal issuer;
    address internal compliance;
    address internal cadmin;
    address internal attester = address(0xA77E);
    ComplianceRegistry internal creg;
    GasProbe internal gasProbe;

    function _isWrapped() internal pure virtual returns (bool);

    /// `DENYLIST` on the token `setUp` creates.
    function _denylist() internal pure virtual returns (bool) { return false; }

    function setUp() public virtual {
        _stack();
        _mockOp(7, 1);
        for (uint256 j = 2; j < 8; ++j) more[j] = _pqzUA(_pk(uint8(60 + j)), uint8(60 + j));
        IFactoryToken.Env memory e = pqzEnv(address(factory), PQZ_UID, address(reg), address(pqv));
        Catalogue.release(factory, IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, 1, e,
            type(NormalPqzRegulatedToken).creationCode, regArgs());
        Catalogue.release(factory, IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, 1, e,
            type(WrappedPqzRegulatedToken).creationCode, regArgs());
        vm.startPrank(registrar);
        factory.setKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED, true);
        factory.setKindEnabled(IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED, true);
        vm.stopPrank();
        issuer = address(new Holder());
        compliance = address(new Holder());
        cadmin = address(new Holder());
        creg = new ComplianceRegistry(nid(cadmin), address(0));
        vm.prank(cadmin);
        creg.setKycProvider(nid(attester), true);
        usd = new MockERC20("USD", "USD", 6);
        gasProbe = new GasProbe();
        tok = NormalPqzToken(factory.createToken(_kind(), 1, abi.encode(_regCfg()), "pr"));
        w = WrappedPqzToken(payable(address(tok)));
    }

    function _kind() internal pure returns (IOpenFactory.TokenKind) {
        return _isWrapped() ? IOpenFactory.TokenKind.WRAPPED_PQZ_REGULATED : IOpenFactory.TokenKind.NORMAL_PQZ_REGULATED;
    }

    /// Kind 12: `_cfg`'s with an owner, the four controls, the minter this test; 13: one leg `usd` 1:1, `PAYABLE` and the four
    /// controls; `DENYLIST` on `creg` when `_denylist`.
    function _regCfg() internal view returns (IFactoryToken.TokenConfig memory c) {
        c = _cfg(uint256(1) << 40);
        c.lockedFeatures = 0;
        c.admin = nid(ownerA);
        c.grantDelay = 1 days;
        c.features |= REG_FEATURES;
        (c.roles.issuer, c.roles.compliance) = (nid(issuer), nid(compliance));
        c.reg.termsHash = keccak256("terms");
        if (_denylist()) {
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

    // ------------------------------------------------------------------ balances

    /// `units` public units to `to`: a mint (12) or a 1:1 wrap of `usd` by this test, then a transfer (13).
    function _pub(address to, uint256 units) internal {
        if (!_isWrapped()) {
            _public(tok, to, units);
            return;
        }
        usd.mint(address(this), units);
        usd.approve(address(tok), units);
        WrappedToken(payable(address(tok))).wrap(address(usd), units);
        if (to != address(this)) tok.transfer(to, units);
    }

    /// `amount` shielded units to `ua`: a shield (12) or a wrap-shield (13), a TRIVIAL entry.
    function _shieldTo(bytes32 ua, uint256 amount) internal {
        if (_isWrapped()) _wrapFund(ua, amount);
        else _fund(tok, ua, amount);
    }

    function _r() internal view returns (IRegulatedToken) {
        return IRegulatedToken(address(tok));
    }

    function _freeze(bytes32 x) internal {
        vm.prank(issuer);
        _r().freeze(x, REF, 0);
    }

    function _pause() internal returns (uint64 until) {
        until = uint64(block.timestamp + 1 days);
        vm.prank(issuer);
        _r().pause(REF, until);
    }

    function _attestDenied(bytes32 x) internal {
        bytes32[] memory as_ = new bytes32[](1);
        uint64[] memory fl = new uint64[](1);
        uint64[] memory vu = new uint64[](1);
        (as_[0], fl[0], vu[0]) = (x, SANCTIONED, type(uint64).max);
        vm.prank(attester);
        creg.setCompliance(as_, fl, vu);
    }

    /// Every proof op answers `word` (1 valid, 0 rejected).
    function _proofs(uint256 word) internal {
        _mockOp(1, word);
        _mockOp(2, word);
        _mockOp(7, word);
    }

    // ------------------------------------------------------------------ the payloads (alice the sender, at her `p`)

    /// A single transfer of `alice` to `to`, beneficiary `ben`, `shieldIn` from the caller's public balance.
    function _single(bool compact, bytes32 to, bytes32 ben, uint256 shieldIn, uint256 seed)
        internal view returns (IPqzToken.PqzTransferArgs memory)
    {
        return _ts(_payload(tok.pqzAccount(alice, 0).pendingCount, shieldIn, alice, to, ben, _out(seed, true),
            compact ? _memo() : bytes("")));
    }

    /// A multi transfer of `alice` to `rec`, beneficiary `ben`, `shieldIn` from the caller's public balance.
    function _multi(bool compact, bytes32[] memory rec, bytes32 ben, uint256 shieldIn, uint256 seed)
        internal view returns (IPqzToken.PqzMultiArgs memory)
    {
        return _ms(_mpayload(tok.pqzAccount(alice, 0).pendingCount, shieldIn, alice, ben, rec,
            _blob(seed, _outLen(rec.length, true)), compact ? _mem(rec.length) : bytes("")));
    }

    /// A burn (or, with amount 0, a refresh) of `alice`, beneficiary `ben`, `shieldIn` from the caller's public balance.
    function _burnArgs(bytes32 ben, uint256 shieldIn, uint256 seed) internal view returns (IPqzToken.PqzBurnArgs memory) {
        return _bs(bytes.concat(abi.encode(uint256(tok.pqzAccount(alice, 0).pendingCount), block.number + 5, shieldIn, alice, ben),
            _blob(seed, PqzCt.CT)));
    }

    function _two() internal view returns (bytes32[] memory r) {
        r = new bytes32[](2);
        (r[0], r[1]) = (bob, carol);
    }

    /// The direct call of entry `k`: 0 `mtxConfidentialTransfer` (the token's default form), 1 `…Compact`, 2 `…Single`,
    /// 3 `…SingleCompact` (to `bob`, `carol`; `bob`), 4 `mtxUnshield` of 5 to `0xD00D`; beneficiary `ben`, `shieldIn` from
    /// the caller.
    function _opCall(uint256 k, bytes32 ben, uint256 shieldIn) internal view returns (bytes memory) {
        if (k < 2) {
            IPqzToken.PqzMultiArgs memory m = _multi(k == 1, _two(), ben, shieldIn, 70 + k);
            return k == 0 ? abi.encodeWithSelector(IPqzToken.mtxConfidentialTransfer.selector, m, PROOF, _pqAuth(), bytes(""), noVerdict())
                : abi.encodeWithSelector(IPqzToken.mtxConfidentialTransferCompact.selector, m, PROOF, _pqAuth(), bytes(""), noVerdict());
        }
        if (k < 4) {
            IPqzToken.PqzTransferArgs memory t = _single(k == 3, bob, ben, shieldIn, 70 + k);
            return k == 2 ? abi.encodeWithSelector(IPqzToken.mtxConfidentialTransferSingle.selector, t, PROOF, _pqAuth(), bytes(""), noVerdict())
                : abi.encodeWithSelector(IPqzToken.mtxConfidentialTransferSingleCompact.selector, t, PROOF, _pqAuth(), bytes(""), noVerdict());
        }
        return abi.encodeWithSelector(IPqzToken.mtxUnshield.selector, _burnArgs(ben, shieldIn, 74), 5,
            MetaTxLib.pad(address(0xD00D)), PROOF, _pqAuth(), bytes(""), noVerdict());
    }

    /// The direct unshield-unwrap (kind 13) of `amount` to `0xD00D` through leg `usd`.
    function _unwrapCall(uint256 amount, bytes32 ben) internal view returns (bytes memory) {
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), amount, amount * SCALE);
        return abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (_burnArgs(ben, 0, 75), x, PROOF, _pqAuth(), bytes(""), noVerdict()));
    }

    // ------------------------------------------------------------------ the signed entries (`signer`'s EOA, lane LANE)

    /// An envelope of `signer` at nonce 0: fee-bearing (`FIXED`, fee 3) or not (`NONE`).
    function _envOf(bool feeBearing) internal view returns (MetaTxLib.UAEnvelope memory u) {
        u = _uaEnv(0);
        if (feeBearing) (u.mode, u.fee) = (MetaTxLib.MODE_FEE_FIXED, 3);
    }

    function _msgOf(MetaTxLib.UAEnvelope memory u, string memory op) internal pure returns (string memory) {
        return string.concat('"from":', h(u.from), ',', op, ',', eJson(u.batch, u.nonce, u.validUntil, u.mode, u.fee));
    }

    function _sig(bytes32 d, bool bad) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = ecdsa(PK, bad ? keccak256(abi.encode(d)) : d);
    }

    /// The signed call of entry `k` (0-4, as `_opCall`; no beneficiary, no `shieldIn`), the proof bound to `u`; `bad`: the
    /// signature over another digest.
    function _signedCall(uint256 k, MetaTxLib.UAEnvelope memory u, bool bad) internal view returns (bytes memory) {
        if (k < 2) {
            IPqzToken.PqzMultiArgs memory m = _multi(k == 1, _two(), 0, 0, 80 + k);
            string memory mm = _msgOf(u, _argMsg(multiJson(m), "", PROOF, ""));
            IUARegistry.UASig memory s = _sig(typedDigest(address(tok), k == 1 ? "UAPqzTransferCompact" : "UAPqzTransfer",
                _argFields(true, "PqzMultiArgs", ""), string.concat(',', T_LEG, ',', T_MULTI), mm), bad);
            return k == 1 ? abi.encodeCall(IPqzSigned.mtxConfidentialTransferCompact, (u, m, PROOF, _pqAuth(), "", s, noVerdict()))
                : abi.encodeCall(IPqzSigned.mtxConfidentialTransfer, (u, m, PROOF, _pqAuth(), "", s, noVerdict()));
        }
        if (k < 4) {
            IPqzToken.PqzTransferArgs memory t = _single(k == 3, bob, 0, 0, 80 + k);
            string memory mt = _msgOf(u, _argMsg(transferJson(t), "", PROOF, ""));
            IUARegistry.UASig memory s = _sig(typedDigest(address(tok), k == 3 ? "UAPqzTransferSingleCompact" : "UAPqzTransferSingle",
                _argFields(true, "PqzTransferArgs", ""), string.concat(',', T_TRANSFER), mt), bad);
            return k == 3 ? abi.encodeCall(IPqzSigned.mtxConfidentialTransferSingleCompact, (u, t, PROOF, _pqAuth(), "", s, noVerdict()))
                : abi.encodeCall(IPqzSigned.mtxConfidentialTransferSingle, (u, t, PROOF, _pqAuth(), "", s, noVerdict()));
        }
        IPqzToken.PqzBurnArgs memory b = _burnArgs(0, 0, 84);
        IPqzToken.Payout memory p = IPqzToken.Payout(5, MetaTxLib.pad(address(0xD00D)));
        string memory mb = _msgOf(u, _argMsg(burnJson(b), string.concat('"amount":', n(p.amount), ',"recipient":',
            h(p.recipient), ','), PROOF, ""));
        IUARegistry.UASig memory sb = _sig(typedDigest(address(tok), "UAPqzUnshield", _argFields(true, "PqzBurnArgs",
            '{"name":"amount","type":"uint256"},{"name":"recipient","type":"bytes32"},'), string.concat(',', T_BURN), mb), bad);
        return abi.encodeCall(IPqzSigned.mtxUnshield, (u, b, p, PROOF, _pqAuth(), "", sb, noVerdict()));
    }

    /// The signed unshield-unwrap (kind 13) of `amount` to `0xD00D` through `usd`, bound to `u`.
    function _signedUnwrap(MetaTxLib.UAEnvelope memory u, uint256 amount) internal view returns (bytes memory) {
        IPqzToken.PqzBurnArgs memory b = _burnArgs(0, 0, 85);
        IConfidentialWrappedToken.Unwrap memory x =
            IConfidentialWrappedToken.Unwrap(address(usd), MetaTxLib.pad(address(0xD00D)), amount, amount * SCALE);
        string memory xj = string.concat('"unwrap":{"underlying":', a(x.underlying), ',"recipient":', h(x.recipient), ',"amount":',
            n(x.amount), ',"minOut":', n(x.minOut), '},');
        IUARegistry.UASig memory s = _sig(typedDigest(address(tok), "UAPqzUnshieldUnwrap", _argFields(true, "PqzBurnArgs",
            '{"name":"unwrap","type":"Unwrap"},'), string.concat(',', T_BURN, ',', T_UNWRAP), _msgOf(u, _argMsg(burnJson(b), xj,
            PROOF, ""))), false);
        return abi.encodeCall(IPqzSigned.mtxUnshieldUnwrap, (u, b, x, PROOF, _pqAuth(), "", s, noVerdict()));
    }

    // ------------------------------------------------------------------ probes

    /// `cd` on `tok` from `caller`, relayed by `gasProbe` when `caller` is 0: success, the revert data and the gas the token's
    /// frame used.
    function _try(bytes memory cd) internal returns (bool ok, bytes memory ret, uint256 used) {
        return gasProbe.probe(address(tok), cd);
    }

    /// Whether `slot` of `tok` is in `ua`'s PQZ `Account` (its words, its pending entries below `pendingCount + 4`, its `acc`
    /// words) or, when `fields`, in the `scaas.pqz` fields (`totalShielded` among them).
    function _pqzSlotOf(bytes32 ua, bytes32 slot, bool fields) internal view returns (bool) {
        uint256 s = uint256(slot);
        uint256 base = uint256(PQZ_SLOT);
        if (fields && s >= base && s < base + FIELDS) return true;
        // group 3g T52 (KV-6): `acct[ua][version 0]`; `pending` at +3, `accWords` from +4; `sendCounter[ua]` a field (+12)
        uint256 acct = uint256(keccak256(abi.encode(uint64(0), keccak256(abi.encode(ua, base + ACCT_FIELD)))));
        if (s >= acct && s < acct + 4 + PQZ_ACC_WORDS) return true;
        if (s == uint256(keccak256(abi.encode(ua, base + 12)))) return true;
        uint256 pc = tok.pqzAccount(ua, 0).pendingCount + 4;
        for (uint256 i; i < pc; ++i) if (s == uint256(keccak256(abi.encode(uint64(i), acct + 3)))) return true;
        return false;
    }

    /// The reads and writes of `tok`'s storage (its frames and the libraries' `DELEGATECALL`s) since
    /// `vm.startStateDiffRecording` that fall in `_pqzSlotOf(ua, ·, fields)`.
    function _pqzAccesses(bytes32 ua, bool fields) internal returns (uint256 k) {
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        for (uint256 i; i < acc.length; ++i) {
            VmSafe.StorageAccess[] memory sa = acc[i].storageAccesses;
            for (uint256 j; j < sa.length; ++j) if (sa[j].account == address(tok) && _pqzSlotOf(ua, sa[j].slot, fields)) ++k;
        }
    }

    /// The registry's `STATICCALL`s since `vm.startStateDiffRecording`.
    function _registryCalls() internal returns (uint256 k) {
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        for (uint256 i; i < acc.length; ++i) if (acc[i].account == address(creg) && acc[i].kind == VmSafe.AccountAccessKind.StaticCall) ++k;
    }
}
