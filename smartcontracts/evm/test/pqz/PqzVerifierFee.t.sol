// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PqzOffchainBase} from "./helpers/PqzOffchainBase.sol";
import {noVerdict} from "./helpers/PqzVerdicts.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {GovernanceRouter} from "../../src/governance/GovernanceRouter.sol";
import {GovernanceRouterTypes} from "../../src/governance/GovernanceRouterBase.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UACall} from "../ua/UACall.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";
import {PQZ_UID} from "./helpers/PqzRegistryBase.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {ZetherFixture} from "../zether/helpers/ZetherFixture.sol";
import {ZetherTypes} from "../../src/zether/ZetherTypes.sol";

/// Round 3t (CTR-PQZ-36, verifier fee spec §15 (1)-(6)): the verifier fee of an `OFFCHAIN` PQZ token. Init (the mode rows, the
/// cap, the range row with the cap, the order); the fee word of every proof-carrying form (`txFee + vf (+ M·d)`, `vf` once per
/// op), the `PRECOMPILE` bytes and slot 20 untouched, the direct binding word 544 folding `vf` (Fable P1-1); the payouts and
/// conservation per form; the setter (decrease at once, increase after the notice, cancel, the refusals, the router); a built
/// op after a fee change and the split test (Fable P1-1); the disclosure charges nothing. Every negative beside its positive
/// control. The holder's `PqzAuth` is the fixture's mocked ML-DSA consent unless a test pins it to exact digests (`_authOnly`).
/// UNAUDITED.
contract PqzVerifierFeeTest is PqzOffchainBase {
    uint64 internal constant F = 2; // the fee of `off` / `offW` at creation
    uint64 internal constant CAP = 10;
    uint64 internal constant NOTICE = 3 days;
    uint256 internal constant LANE = 7;
    uint256 internal constant NKEY = 0x5161E5;
    bytes32 internal constant TO = bytes32(uint256(0xD00D));
    bytes32 internal me;
    bytes32 internal dId; // a registered `mldsa65` UA without a PQZ key: the beneficiary (C0-7) and a derived verifier
    bytes32 internal nId; // the native envelope subject of `NKEY`
    NormalPqzToken internal off;
    WrappedPqzToken internal w; // PRECOMPILE wrapped
    WrappedPqzToken internal offW; // OFFCHAIN wrapped
    OpenFactory internal fN; // a factory whose notice period is 3 days

    function _cfg(uint256 m) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = super._cfg(m);
        c.admin = me;
    }

    function setUp() public {
        me = nid(address(this));
        _offStack();
        _releaseWrapped();
        decoy = 3;
        dId = _mldsaUA(9);
        nId = nid(vm.addr(NKEY));
        tok = _newToken("f-pre");
        off = _feeToken("f-off", F, CAP, false);
        w = _newWrapped("f-wpre");
        _setNext(PqzCore.OFFCHAIN, vA, false, F, CAP);
        offW = _newWrapped("f-woff");
        _setNext(0, 0, false, 0, 0);
        _shieldOn(tok, alice, 1000);
        _shieldOn(off, alice, 1000);
        _wrapShield(w, 1000);
        _wrapShield(offW, 1000);
        fN = new OpenFactory(nid(registrar));
        EnvKit.configure(fN, PQZ_UID, NOTICE, address(0));
        Catalogue.release(fN, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(fN), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        fN.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(fN)));
        vm.warp(block.timestamp + NOTICE); // the release usable
    }

    // ------------------------------------------------------------------ tokens

    function _setNext(uint8 m, bytes32 v, bool fixed_, uint64 fee, uint64 max) internal {
        (vMode, vUA, vFixed, vFee, vFeeMax) = (m, v, fixed_, fee, max);
    }

    function _feeToken(bytes32 s, uint64 fee, uint64 max, bool fixed_) internal returns (NormalPqzToken t) {
        _setNext(PqzCore.OFFCHAIN, vA, fixed_, fee, max);
        t = _newToken(s);
        _setNext(0, 0, false, 0, 0);
    }

    /// An `OFFCHAIN` token of `fN` (notice 3 days), fee `F`, cap `CAP`, admin this test.
    function _onN(bytes32 s) internal returns (NormalPqzToken t) {
        _setNext(PqzCore.OFFCHAIN, vA, false, F, CAP);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        _setNext(0, 0, false, 0, 0);
        t = NormalPqzToken(fN.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), s));
    }

    function _wrapShield(WrappedPqzToken t, uint256 units) internal {
        MockERC20 u = MockERC20(t.underlyings()[0]);
        u.mint(address(this), units * SCALE);
        u.approve(address(t), units * SCALE);
        t.mtxWrapShield(address(u), units * SCALE, alice);
    }

    function _fee(address t, uint64 next) internal {
        IPqzToken(t).setVerifierFee(next);
    }

    function _cfgOf(address t) internal view returns (IPqzToken.PqzVerifyConfig memory) {
        return IPqzToken(t).pqzVerifyConfig();
    }

    /// The revert data of creating `c` on the fixture's factory (empty: created).
    function _tryCreate(IFactoryToken.TokenConfig memory c, bytes32 s) internal returns (bytes memory err) {
        try factory.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), s) returns (address) {}
        catch (bytes memory e) {
            err = e;
            if (e.length == 0) err = hex"00";
        }
    }

    function _offCfg(uint64 fee, uint64 max) internal returns (IFactoryToken.TokenConfig memory c) {
        _setNext(PqzCore.OFFCHAIN, vA, false, fee, max);
        c = _cfg(uint256(1) << 40);
        _setNext(0, 0, false, 0, 0);
    }

    // ------------------------------------------------------------------ (1) init

    function test_init_precompileRefusesEitherField() public {
        _setNext(0, 0, false, 1, 1);
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        _setNext(0, 0, false, 0, 0);
        bytes memory inv = abi.encodeWithSelector(IPqzToken.PqzVerifyConfigInvalid.selector);
        assertEq(_tryCreate(c, "p1"), inv, "fee and cap");
        c.conf.verifierFee = 0;
        assertEq(_tryCreate(c, "p2"), inv, "the cap alone");
        (c.conf.verifierFee, c.conf.verifierFeeMax) = (1, 0);
        assertEq(_tryCreate(c, "p3"), inv, "the fee alone");
        c.conf.verifierFee = 0;
        assertEq(_tryCreate(c, "p4"), "", "control: both 0");
    }

    function test_init_feeAboveCap() public {
        assertEq(_tryCreate(_offCfg(5, 4), "a1"),
            abi.encodeWithSelector(IPqzToken.VerifierFeeAboveMax.selector, uint64(5), uint64(4)));
        assertEq(_tryCreate(_offCfg(4, 4), "a2"), "", "control: fee = cap");
        IPqzToken.PqzVerifyConfig memory v = _cfgOf(address(off));
        assertEq(v.verifierFee, F);
        assertEq(v.verifierFeeMax, CAP);
    }

    /// The range row with the cap (controller call 2): `confidentialFee + verifierFeeMax + 8·minDecoyFee < maxShielded`
    /// (the cap `≤ 2^62` makes it the binding one), each term at the boundary refused, one below created; a fee below and a cap
    /// at the boundary refused (M7).
    function test_init_rangeRowWithTheCap() public {
        uint256 cap = uint256(1) << 40;
        IFactoryToken.TokenConfig memory c = _offCfg(0, uint64(cap - FEE));
        assertEq(_tryCreate(c, "r1"), abi.encodeWithSelector(IPqzToken.BadInit.selector), "fee 0, the cap at the boundary");
        c.conf.verifierFeeMax = uint64(cap - FEE - 1);
        assertEq(_tryCreate(c, "r2"), "", "one below");
        (c.conf.confidentialFee, c.conf.verifierFeeMax) = (0, uint64(cap));
        assertEq(_tryCreate(c, "r3"), abi.encodeWithSelector(IPqzToken.BadInit.selector), "the cap alone");
        c.conf.verifierFeeMax = uint64(cap - 1);
        assertEq(_tryCreate(c, "r4"), "", "the cap alone, one below");
        (c.conf.verifierFeeMax, c.conf.minDecoyFee) = (8, (cap - 8) / 8);
        assertEq(_tryCreate(c, "r5"), abi.encodeWithSelector(IPqzToken.BadInit.selector), "the cap with the decoy term");
        c.conf.minDecoyFee = (cap - 8) / 8 - 1;
        assertEq(_tryCreate(c, "r6"), "", "the decoy term one below");
    }

    /// Fable P3-3: the range row first, so a `PRECOMPILE` config with a fee and a cap that also breaks it is `BadInit`.
    function test_init_order() public {
        _setNext(0, 0, false, 1, uint64(uint256(1) << 40));
        IFactoryToken.TokenConfig memory c = _cfg(uint256(1) << 40);
        _setNext(0, 0, false, 0, 0);
        assertEq(_tryCreate(c, "o1"), abi.encodeWithSelector(IPqzToken.BadInit.selector));
        c.conf.verifierFeeMax = 1;
        assertEq(_tryCreate(c, "o2"), abi.encodeWithSelector(IPqzToken.PqzVerifyConfigInvalid.selector), "then the mode row");
    }

    // ------------------------------------------------------------------ the forms

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

    function _singleA(NormalPqzToken t, bool compact, bytes32 ben) internal view returns (IPqzToken.PqzTransferArgs memory) {
        return _ts(_payload(_p(t), 0, alice, bob, ben, _out(11, false), compact ? _memo() : bytes("")));
    }

    function _multiA(NormalPqzToken t, bool compact, bytes32 ben, uint256 m) internal view returns (IPqzToken.PqzMultiArgs memory) {
        bytes32[] memory legs = new bytes32[](m);
        legs[0] = bob;
        if (m > 1) legs[1] = carol;
        bytes memory memo = compact ? bytes.concat(salt, _slice(_blob(0x3e31, 352), 0, 2 + 40 * m)) : bytes("");
        return _ms(_mpayload(_p(t), 0, alice, ben, legs, _blob(13, _outLen(m, false)), memo));
    }

    function _burnA(NormalPqzToken t, bytes32 ben) internal view returns (IPqzToken.PqzBurnArgs memory) {
        return _bs(bytes.concat(abi.encode(_p(t), block.number + 50, uint256(0), alice, ben), _blob(14, PqzCt.CT)));
    }

    function _unwrapX(NormalPqzToken t) internal view returns (IConfidentialWrappedToken.Unwrap memory) {
        return IConfidentialWrappedToken.Unwrap(WrappedPqzToken(payable(address(t))).underlyings()[0], TO, 10, 10 * SCALE);
    }

    function _token(uint8 op, bool offchain) internal view returns (NormalPqzToken) {
        return NormalPqzToken(op == UNWRAP ? address(offchain ? offW : w) : address(offchain ? off : tok));
    }

    /// The direct statement of form `op` on `t` with beneficiary `ben` (op 7: two legs).
    function _stmt(uint8 op, NormalPqzToken t, bytes32 ben) internal view returns (bytes memory) {
        if (op == SINGLE || op == SINGLE_COMPACT) return t.transferSingleStatement(_singleA(t, op == SINGLE_COMPACT, ben), 0);
        if (op == MULTI || op == COMPACT) return t.transferStatement(_multiA(t, op == COMPACT, ben, 2), 0);
        if (op == UNSHIELD) return t.burnStatement(_burnA(t, ben), 5, TO, 0);
        if (op == REFRESH) return t.burnStatement(_burnA(t, ben), 0, 0, 0);
        return WrappedPqzToken(payable(address(t))).unshieldUnwrapStatement(_burnA(t, ben), _unwrapX(t), 0);
    }

    function _call(uint8 op, NormalPqzToken t, bytes32 ben, IPqzToken.PqzSignedVerdict memory sv)
        internal view returns (bytes memory)
    {
        IUARegistry.UASig memory pa = _pqAuth();
        if (op == SINGLE) return abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (_singleA(t, false, ben), VPROOF, pa, "", sv));
        if (op == SINGLE_COMPACT) {
            return abi.encodeCall(IPqzToken.mtxConfidentialTransferSingleCompact, (_singleA(t, true, ben), VPROOF, pa, "", sv));
        }
        if (op == MULTI) return abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (_multiA(t, false, ben, 2), VPROOF, pa, "", sv));
        if (op == COMPACT) {
            return abi.encodeCall(IPqzToken.mtxConfidentialTransferCompact, (_multiA(t, true, ben, 2), VPROOF, pa, "", sv));
        }
        if (op == UNSHIELD) return abi.encodeCall(IPqzToken.mtxUnshield, (_burnA(t, ben), 5, TO, VPROOF, pa, "", sv));
        if (op == REFRESH) return abi.encodeCall(IPqzToken.mtxUnshield, (_burnA(t, ben), 0, bytes32(0), VPROOF, pa, "", sv));
        return abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (_burnA(t, ben), _unwrapX(t), VPROOF, pa, "", sv));
    }

    /// Runs form `op` directly on `t` (the verifier's verdict on an `OFFCHAIN` token), reverting with the op's own data.
    function _run(uint8 op, NormalPqzToken t, bytes32 ben) internal returns (bytes memory st) {
        st = _stmt(op, t, ben);
        bool offchain = address(t) != address(tok) && address(t) != address(w); // no view call: the access test reads none
        (bool ok, bytes memory ret) = address(t).call(_call(op, t, ben, offchain ? _sv(t, st) : noVerdict()));
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    function _wd(bytes memory st, uint256 off_) internal pure returns (uint256) {
        return uint256(bytes32(_slice(st, off_, 32)));
    }

    function _legs(uint8 op) internal pure returns (uint256) {
        return op == MULTI || op == COMPACT ? 2 : 0;
    }

    function _amount(uint8 op) internal pure returns (uint256) {
        return op == UNSHIELD ? 5 : op == UNWRAP ? 10 : 0;
    }

    // ------------------------------------------------------------------ (2) the fee word

    /// Every form, both tokens, with and without a beneficiary: word 256 is `txFee + vf (+ M·d)`, `vf` once on op 7 (M3), 0
    /// on `PRECOMPILE`.
    function test_feeWord_everyForm() public view {
        for (uint8 op; op <= UNWRAP; ++op) {
            for (uint256 b; b < 2; ++b) {
                bytes32 ben = b == 0 ? bytes32(0) : dId;
                uint256 tx_ = b == 0 ? 0 : FEE;
                assertEq(_wd(_stmt(op, _token(op, true), ben), 256), tx_ + F + _legs(op) * decoy, "OFFCHAIN");
                assertEq(_wd(_stmt(op, _token(op, false), ben), 256), tx_ + _legs(op) * decoy, "PRECOMPILE");
            }
        }
    }

    /// I-V2, M2: a `PRECOMPILE` debit (and its statement view) reads no slot of the fee state.
    function test_feeWord_precompileReadsNoFeeSlot() public {
        bytes32 root = PqzCore._STORAGE;
        vm.record();
        _run(SINGLE, tok, dId);
        _run(MULTI, tok, 0);
        _run(UNSHIELD, tok, 0);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(tok));
        for (uint256 i; i < reads.length; ++i) {
            for (uint256 k = 20; k <= 22; ++k) assertTrue(reads[i] != bytes32(uint256(root) + k), "a fee slot read");
        }
        for (uint256 i; i < writes.length; ++i) {
            for (uint256 k = 20; k <= 22; ++k) assertTrue(writes[i] != bytes32(uint256(root) + k), "a fee slot written");
        }
        assertEq(_cfgOf(address(tok)).verifierFee, 0, "PRECOMPILE: 0");
    }

    function test_tagDirectModeVfIsPinned() public pure {
        assertEq(PqzCore.TAG_DIRECT_MODE_VF, keccak256("SCAAS-PQZ-DIRECT-MODE-VF-V1"));
        assertEq(PqzCore.TAG_DIRECT_MODE_VF, 0x822f04ee19aa5a54b870d8babefc1258b09f62ef5bdd149928367a05388476a8);
        assertEq(PqzCore.TAG_DIRECT_MODE, keccak256("SCAAS-PQZ-DIRECT-MODE-V1"), "control: today's tag");
    }

    uint8 internal constant HASH_ = uint8(ZetherTypes.TransferMode.HASH); // 0
    uint8 internal constant BUNDLE_ = uint8(ZetherTypes.TransferMode.BUNDLE); // 1

    function _vfBinding(uint8 mode, uint256 vf) internal pure returns (bytes32) {
        return keccak256(abi.encode(PqzCore.TAG_DIRECT_MODE_VF, mode, vf));
    }

    /// Fable P1-1: on `OFFCHAIN` the direct op 1 and op 7 binding word 544 folds the fee in force, at `vf` 0, 1 and the cap,
    /// both modes; the burn, refresh and unwrap words and the relayed word unchanged; `PRECOMPILE` keeps today's (M24).
    function test_bindingWord_direct() public {
        uint64[3] memory fees = [uint64(0), 1, CAP];
        NormalPqzToken ow = NormalPqzToken(address(offW));
        uint256 unwrap0 = _wd(_stmt(UNWRAP, ow, 0), 544); // the unwrap binding (TAG_UNWRAP over the leg), at vf = F
        for (uint256 i; i < 3; ++i) {
            _fee(address(off), fees[i]);
            _fee(address(offW), fees[i]);
            assertEq(_wd(_stmt(UNWRAP, ow, 0), 544), unwrap0, "unwrap direct: unchanged");
            uint256 vf = fees[i];
            assertEq(bytes32(_wd(_stmt(SINGLE, off, 0), 544)), _vfBinding(BUNDLE_, vf), "op 1 BUNDLE");
            assertEq(bytes32(_wd(_stmt(SINGLE_COMPACT, off, 0), 544)), _vfBinding(HASH_, vf), "op 1 HASH");
            assertEq(bytes32(_wd(_stmt(MULTI, off, 0), 544)), _vfBinding(BUNDLE_, vf), "op 7 BUNDLE");
            assertEq(bytes32(_wd(_stmt(COMPACT, off, 0), 544)), _vfBinding(HASH_, vf), "op 7 HASH");
            assertEq(_wd(_stmt(UNSHIELD, off, 0), 544), 0, "burn: unchanged");
            assertEq(_wd(_stmt(REFRESH, off, 0), 544), 0, "refresh: unchanged");
            bytes32 env = keccak256("an envelope binding");
            assertEq(bytes32(_wd(off.transferSingleStatement(_singleA(off, false, 0), env), 544)),
                keccak256(abi.encode(env, BUNDLE_)), "relayed: unchanged");
        }
        assertEq(bytes32(_wd(_stmt(SINGLE, tok, 0), 544)), _direct(ZetherTypes.TransferMode.BUNDLE), "PRECOMPILE op 1: TAG_DIRECT_MODE");
        assertEq(bytes32(_wd(_stmt(COMPACT, tok, 0), 544)), _direct(ZetherTypes.TransferMode.HASH), "PRECOMPILE op 7: TAG_DIRECT_MODE");
    }

    // ------------------------------------------------------------------ (3) payment

    struct Bal {
        uint256 verifier;
        uint256 ben;
        uint256 bob;
        uint256 carol;
        uint256 to;
        uint256 pool;
        uint256 shielded;
        uint256 supply;
    }

    function _bal(NormalPqzToken t, address v, bytes32 ben) internal view returns (Bal memory b) {
        b.verifier = t.balanceOf(v);
        b.ben = ben == 0 ? 0 : IUALedger(address(t)).balanceOfUA(ben);
        (b.bob, b.carol) = (IUALedger(address(t)).balanceOfUA(bob), IUALedger(address(t)).balanceOfUA(carol));
        b.to = t.balanceOf(address(uint160(uint256(TO))));
        (b.pool, b.shielded, b.supply) = (t.balanceOf(MetaTxLib.SHIELD_POOL), t.totalShielded(), t.totalSupply());
    }

    /// Per form, with and without a beneficiary: the verifier `+vf·s` (its ERC-20 balance), the beneficiary `+txFee·s`, each
    /// leg `+d·s`, the recipient `+amount·s`, the pool and `totalShielded` `−(fee + amount)`, `totalSupply` unchanged (the
    /// unwrap `−amount·s`) (M4, M5, M21).
    function test_payment_everyForm() public {
        address v = vm.addr(VKEY);
        for (uint8 op; op <= UNWRAP; ++op) {
            for (uint256 b; b < 2; ++b) {
                bytes32 ben = b == 0 ? bytes32(0) : dId;
                NormalPqzToken t = _token(op, true);
                Bal memory x = _bal(t, v, ben);
                _run(op, t, ben);
                Bal memory y = _bal(t, v, ben);
                uint256 txf = b == 0 ? 0 : FEE;
                uint256 fee = txf + F + _legs(op) * decoy;
                assertEq(y.verifier - x.verifier, F * SCALE, "the verifier");
                assertEq(y.ben - x.ben, txf * SCALE, "the beneficiary: txFee only");
                assertEq(y.bob - x.bob, _legs(op) == 0 ? 0 : decoy * SCALE, "leg bob");
                assertEq(y.carol - x.carol, _legs(op) == 0 ? 0 : decoy * SCALE, "leg carol");
                assertEq(y.to - x.to, op == UNSHIELD ? 5 * SCALE : 0, "the recipient");
                assertEq(x.pool - y.pool, (fee + _amount(op)) * SCALE, "the pool");
                assertEq(x.shielded - y.shielded, fee + _amount(op), "totalShielded");
                assertEq(x.supply - y.supply, op == UNWRAP ? 10 * SCALE : 0, "totalSupply");
                assertEq(y.pool, y.shielded * SCALE, "pool = totalShielded * scale");
            }
        }
    }

    /// `vf = 0` moves nothing to the verifier (and no zero-unit move); a `PRECOMPILE` debit pays no verifier.
    function test_payment_zeroFee() public {
        address v = vm.addr(VKEY);
        _fee(address(off), 0);
        uint256 b0 = off.balanceOf(v);
        _run(MULTI, off, dId);
        assertEq(off.balanceOf(v), b0, "vf 0: nothing");
        _run(SINGLE, tok, dId);
        assertEq(tok.balanceOf(v), 0, "PRECOMPILE");
    }

    /// A derived verifier (`mldsa65`, its precompile mocked) without a ledger balance: the first payout creates it.
    function test_payment_derivedVerifierFromZero() public {
        bytes32 dv = _mldsaUA(21);
        _setNext(PqzCore.OFFCHAIN, dv, false, F, CAP);
        NormalPqzToken t = _newToken("f-derived");
        _setNext(0, 0, false, 0, 0);
        _shieldOn(t, alice, 100);
        assertEq(IUALedger(address(t)).balanceOfUA(dv), 0);
        bytes memory st = _stmt(SINGLE, t, 0);
        IPqzToken.PqzSignedVerdict memory sv;
        sv.pqzVerdict = _verdict(t, st, VPROOF);
        sv.sig = UACall.auth(dv, _mlAuth());
        t.mtxConfidentialTransferSingle(_singleA(t, false, 0), VPROOF, _pqAuth(), "", sv);
        assertEq(IUALedger(address(t)).balanceOfUA(dv), F * SCALE, "the ledger balance from 0");
    }

    /// The payee is the current verifier while a transfer to another is pending (M6).
    function test_payment_currentVerifierWhilePending() public {
        NormalPqzToken t = _onN("f-pending");
        _shieldOn(t, alice, 100);
        t.pqzSetVerifier(vB);
        assertEq(_cfgOf(address(t)).pending, vB);
        _run(SINGLE, t, dId);
        assertEq(t.balanceOf(vm.addr(VKEY)), F * SCALE, "the current verifier");
        assertEq(t.balanceOf(vm.addr(VKEY2)), 0, "not the pending one");
        assertEq(IUALedger(address(t)).balanceOfUA(dId), FEE * SCALE, "nor the beneficiary");
    }

    // ------------------------------------------------------------------ (4) the setter

    function test_setter_decreaseAtOnce() public {
        NormalPqzToken t = _onN("s-dec");
        vm.expectEmit(address(t));
        emit IPqzToken.VerifierFeeSet(F, 1);
        _fee(address(t), 1);
        assertEq(_cfgOf(address(t)).verifierFee, 1);
        vm.expectEmit(address(t));
        emit IPqzToken.VerifierFeeSet(1, 0);
        _fee(address(t), 0);
        assertEq(_cfgOf(address(t)).verifierFee, 0, "to 0");
        assertEq(_cfgOf(address(t)).verifierFeeMax, CAP, "I-V1");
    }

    function test_setter_increaseAfterTheNotice() public {
        NormalPqzToken t = _onN("s-inc");
        uint64 eta = uint64(block.timestamp) + NOTICE;
        vm.expectEmit(address(t));
        emit IPqzToken.VerifierFeeProposed(F, 5, eta);
        _fee(address(t), 5);
        IPqzToken.PqzVerifyConfig memory c = _cfgOf(address(t));
        (uint64 fee, uint64 pend_, uint64 eta_) = (c.verifierFee, c.verifierFeePending, c.verifierFeeEta);
        assertEq(fee, F, "not yet");
        assertEq(pend_, 5);
        assertEq(eta_, eta);
        vm.warp(eta - 1);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.VerifierFeeNotReady.selector, eta));
        _fee(address(t), 5);
        vm.warp(eta);
        vm.expectEmit(address(t));
        emit IPqzToken.VerifierFeeSet(F, 5);
        _fee(address(t), 5);
        c = _cfgOf(address(t));
        assertEq(c.verifierFee, 5);
        assertEq(c.verifierFeePending, 0);
        assertEq(c.verifierFeeEta, 0);
        // a passed window: a late confirm is a new proposal
        _fee(address(t), 7);
        vm.warp(block.timestamp + 2 * NOTICE + 1);
        c = _cfgOf(address(t));
        assertEq(c.verifierFeePending, 0, "M20: a dead pending reads 0");
        assertEq(c.verifierFeeEta, 0);
        vm.expectEmit(address(t));
        emit IPqzToken.VerifierFeeProposed(5, 7, uint64(block.timestamp) + NOTICE);
        _fee(address(t), 7);
        assertEq(_cfgOf(address(t)).verifierFee, 5, "the dead pending did not apply");
        assertEq(_cfgOf(address(t)).verifierFeeMax, CAP, "I-V1");
    }

    /// An admin change kills the pending; another caller's confirm is `NotProposer` (before `NotAdmin`); a stranger's
    /// proposal `NotAdmin`.
    function test_setter_proposerAndGeneration() public {
        NormalPqzToken t = _onN("s-gen");
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(stranger)));
        _fee(address(t), 5);
        _fee(address(t), 5);
        vm.warp(block.timestamp + NOTICE);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotProposer.selector, uint8(0), bytes32(uint256(5)), me));
        _fee(address(t), 5);
        address o2 = address(0x0A2);
        IGovernance(address(t)).transferAdmin(nid(o2), EnvKit.codeUidOf(address(IGovernance(address(t)))));
        vm.prank(o2);
        IGovernance(address(t)).acceptAdmin();
        assertEq(_cfgOf(address(t)).verifierFeePending, 0, "dead after the admin change");
        vm.prank(o2);
        _fee(address(t), 5); // a new proposal, not a confirm
        assertEq(_cfgOf(address(t)).verifierFee, F);
        assertEq(_cfgOf(address(t)).verifierFeePending, 5);
    }

    function test_setter_refusals() public {
        NormalPqzToken t = _onN("s-ref");
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.VerifierFeeAboveMax.selector, CAP + 1, CAP));
        _fee(address(t), CAP + 1);
        vm.expectRevert(IPqzToken.VerifierFeeSame.selector);
        _fee(address(t), F);
        _fee(address(t), 5);
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.VerifierFeePending.selector, uint64(5)));
        _fee(address(t), 6);
        _fee(address(t), 1); // control: a decrease lands (and drops the pending)
        assertEq(_cfgOf(address(t)).verifierFee, 1);
    }

    /// Fable P3-1 (M25): with a live pending, the current value cancels it (`VerifierFeeSet(cur, cur)`), the fee unmoved, a
    /// built op still lands; at `cur = 0` too.
    function test_setter_cancelByTheCurrentValue() public {
        NormalPqzToken t = _onN("s-cancel");
        _shieldOn(t, alice, 100);
        bytes memory st = _stmt(SINGLE, t, 0);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        _fee(address(t), 5);
        vm.expectEmit(address(t));
        emit IPqzToken.VerifierFeeSet(F, F);
        _fee(address(t), F);
        assertEq(_cfgOf(address(t)).verifierFeePending, 0, "cancelled");
        assertEq(_cfgOf(address(t)).verifierFee, F);
        t.mtxConfidentialTransferSingle(_singleA(t, false, 0), VPROOF, _pqAuth(), "", sv); // built before: lands
        vm.warp(block.timestamp + NOTICE);
        _fee(address(t), 5); // the old eta no longer confirms: a new proposal
        assertEq(_cfgOf(address(t)).verifierFee, F);
        _fee(address(t), 0);
        _fee(address(t), 3);
        vm.expectEmit(address(t));
        emit IPqzToken.VerifierFeeSet(0, 0);
        _fee(address(t), 0);
        assertEq(_cfgOf(address(t)).verifierFeePending, 0, "cancelled at 0");
    }

    /// Controller call 3 (M13): a decrease during a live pending applies at once, cancels the pending, emits only
    /// `VerifierFeeSet`; the old `eta` no longer confirms.
    function test_setter_decreaseCancelsThePending() public {
        NormalPqzToken t = _onN("s-deccancel");
        _fee(address(t), 5);
        vm.recordLogs();
        _fee(address(t), 1);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "one event");
        assertEq(logs[0].topics[0], IPqzToken.VerifierFeeSet.selector);
        assertEq(_cfgOf(address(t)).verifierFeePending, 0);
        vm.warp(block.timestamp + NOTICE);
        _fee(address(t), 5);
        assertEq(_cfgOf(address(t)).verifierFee, 1, "a new proposal, not a confirm");
    }

    /// Notice 0 (the fixture's factory): an increase applies at once with both events; a fixed verifier's fee changes (M15).
    function test_setter_noticeZeroAndFixed() public {
        vm.expectEmit(address(off));
        emit IPqzToken.VerifierFeeProposed(F, 5, uint64(block.timestamp));
        vm.expectEmit(address(off));
        emit IPqzToken.VerifierFeeSet(F, 5);
        _fee(address(off), 5);
        assertEq(_cfgOf(address(off)).verifierFee, 5);
        NormalPqzToken fx = _feeToken("s-fixed", F, CAP, true);
        assertTrue(_cfgOf(address(fx)).fixed_);
        _fee(address(fx), 1);
        _fee(address(fx), 9);
        assertEq(_cfgOf(address(fx)).verifierFee, 9, "a fixed verifier's fee moves");
    }

    function test_setter_precompileRefused() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(address(0xBEEF))));
        _fee(address(tok), 0);
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        _fee(address(tok), 0);
        vm.expectRevert(IPqzToken.PqzVerifyConfigInvalid.selector);
        _fee(address(tok), 1);
    }

    // ------------------------------------------------------------------ the router op (§7.2) and its binding (B1)

    function _router() internal returns (GovernanceRouter router, NormalPqzToken t) {
        router = new GovernanceRouter(PQZ_UID, address(reg), address(0), false);
        OpenFactory f = new OpenFactory(nid(registrar));
        EnvKit.configure(f, PQZ_UID, 0, address(router));
        Catalogue.release(f, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(f), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        f.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f)));
        IFactoryToken.TokenConfig memory c = _offCfg(F, CAP);
        c.admin = nId;
        t = NormalPqzToken(f.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(c), "f-router"));
    }

    /// `UASetVerifierFee(from, target, next, …)` signed by `NKEY` for `signedNext`, `signedTarget`.
    function _routerAuth(GovernanceRouter router, MetaTxLib.UAEnvelope memory u, address signedTarget, uint64 signedNext)
        internal view returns (IUARegistry.UASig memory auth)
    {
        bytes32 sh = keccak256(bytes.concat(abi.encode(GovernanceRouterTypes.UA_SET_VERIFIER_FEE, u.from), abi.encode(signedTarget),
            abi.encode(signedNext), abi.encode(u.batch, u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
        (uint8 vv, bytes32 r, bytes32 ss) = vm.sign(NKEY, MessageHashUtils.toTypedDataHash(_sepOf(address(router)), sh));
        auth.signature = abi.encodePacked(r, ss, vv);
    }

    function _env(GovernanceRouter router) internal view returns (MetaTxLib.UAEnvelope memory) {
        return MetaTxLib.UAEnvelope(nId, LANE, router.mtxNonce(nId, LANE), block.timestamp + 300, 0, address(0), 0, address(0));
    }

    /// Relayed at fee 0 by a stranger relayer; `next` and `target` bound (B1): another `next` or target under the same
    /// signature refused, the signed one lands.
    function test_router_setVerifierFee() public {
        (GovernanceRouter router, NormalPqzToken t) = _router();
        NormalPqzToken other = _feeToken("f-other", F, CAP, false);
        MetaTxLib.UAEnvelope memory u = _env(router);
        IUARegistry.UASig memory auth = _routerAuth(router, u, address(t), 1);
        vm.prank(address(0x4E1A));
        (bool ok,) = address(router).call(abi.encodeCall(GovernanceRouter.mtxSetVerifierFee, (u, address(t), 0, auth)));
        assertFalse(ok, "B1: next bound");
        vm.prank(address(0x4E1A));
        (ok,) = address(router).call(abi.encodeCall(GovernanceRouter.mtxSetVerifierFee, (u, address(other), 1, auth)));
        assertFalse(ok, "target bound");
        vm.prank(address(0x4E1A));
        router.mtxSetVerifierFee(u, address(t), 1, auth);
        assertEq(_cfgOf(address(t)).verifierFee, 1, "relayed at fee 0");
        u = _env(router);
        vm.prank(address(0x4E1A));
        router.mtxSetVerifierFee(u, address(t), 4, _routerAuth(router, u, address(t), 4));
        assertEq(_cfgOf(address(t)).verifierFee, 4, "an increase at notice 0");
    }

    /// The setter is a direct governance entry: not on the token's allow-list (`mtxSelectors`).
    function test_setter_notAllowListed() public view {
        address[2] memory ts = [address(off), address(offW)];
        for (uint256 k; k < 2; ++k) {
            (bytes4[] memory s,,) = IMetaTx(ts[k]).mtxSelectors();
            for (uint256 j; j < s.length; ++j) assertTrue(s[j] != IPqzToken.setVerifierFee.selector);
        }
    }

    // ------------------------------------------------------------------ (5) a built op after a fee change

    /// The `PqzAuth` digest of statement `st` of op byte `op` on `t` (PqzCore.authDigest, recomputed).
    function _authD(address t, uint8 op, bytes memory st) internal view returns (bytes32) {
        bytes32 h = keccak256(bytes.concat(abi.encode(PqzCore.AUTH_TYPEHASH, uint256(op)), _slice(st, 0, 640),
            abi.encode(keccak256(_slice(st, 640, st.length - 640)))));
        return MessageHashUtils.toTypedDataHash(_sepOf(t), h);
    }

    /// `alice`'s `PqzAuth` accepted for exactly statement `st` (and any added later by `_authAlso`): any other digest refused.
    function _authOnly(address t, uint8 op, bytes memory st) internal {
        vm.mockCallRevert(address(reg), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector, alice), "no");
        _authAlso(t, op, st);
    }

    function _authAlso(address t, uint8 op, bytes memory st) internal {
        vm.mockCall(address(reg), abi.encodeCall(IUARegistry.requireAuthorized,
            (alice, UAKinds.PURPOSE_ZETHER_AUTH, _authD(t, op, st), _pqAuth())), "");
    }

    /// A built op 1 refuses `AuthRejected` after a decrease, and with a re-signed `pqzAuth` `PqzVerdictMismatch(3)`; the
    /// control: the same op at the unchanged fee lands.
    function test_builtOp_afterAChange() public {
        bytes memory st = _stmt(SINGLE, off, 0);
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        IPqzToken.PqzTransferArgs memory a = _singleA(off, false, 0);
        _authOnly(address(off), 1, st);
        uint256 snap = vm.snapshotState();
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        vm.revertToState(snap);
        _fee(address(off), F - 1);
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        _authAlso(address(off), 1, _stmt(SINGLE, off, 0));
        vm.expectRevert(abi.encodeWithSelector(IPqzToken.PqzVerdictMismatch.selector, uint8(3)));
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
        // an increase kills it too
        _fee(address(off), F + 1);
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        off.mtxConfidentialTransferSingle(a, VPROOF, _pqAuth(), "", sv);
    }

    /// Fable P1-1, the split, direct form: an op 7 built at `vf` with `d`, after `Δvf = ±M·k` resubmitted with `d ∓ k` (the
    /// same fee word): word 544 moved, so `AuthRejected`; `k` both signs, `M` 2 and 1. Control: the op unchanged lands.
    function test_split_direct() public {
        _split(2, 1, true);
        _split(2, 1, false);
        _split(1, 1, true);
    }

    function _split(uint256 m, uint256 k, bool up) internal {
        uint256 snap = vm.snapshotState();
        IPqzToken.PqzMultiArgs memory a = _multiA(off, false, 0, m);
        bytes memory st = off.transferStatement(a, 0);
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        _authOnly(address(off), 7, st);
        uint256 s2 = vm.snapshotState();
        off.mtxConfidentialTransfer(a, VPROOF, _pqAuth(), "", sv);
        vm.revertToState(s2);
        _fee(address(off), uint64(up ? F + m * k : F - m * k));
        a.decoyFee = up ? decoy - k : decoy + k;
        assertEq(_wd(off.transferStatement(a, 0), 256), _wd(st, 256), "the same fee word");
        vm.expectRevert(IPqzToken.AuthRejected.selector);
        off.mtxConfidentialTransfer(a, VPROOF, _pqAuth(), "", sv);
        vm.revertToState(snap);
    }

    /// The split, envelope form: the subject's signature covers `args.decoyFee`, so `d ∓ k` after `Δvf = ±M·k` refuses under
    /// the same signature (the statement and its verdict unchanged); the control lands.
    function test_split_envelope() public {
        _public(off, vm.addr(NKEY), 0);
        IPqzToken.PqzMultiArgs memory a = _multiA(off, false, 0, 2);
        MetaTxLib.UAEnvelope memory u = MetaTxLib.UAEnvelope(nId, LANE, off.mtxNonce(nId, LANE), block.timestamp + 300, 0,
            address(0), 0, address(0));
        bytes32 tag = _envTag(u);
        bytes memory st = off.transferStatement(a, tag);
        IUARegistry.UASig memory auth = _envAuth(u, a);
        IPqzToken.PqzSignedVerdict memory sv = _sv(off, st);
        uint256 snap = vm.snapshotState();
        vm.prank(address(0x4E1A));
        (bool ok,) = address(off).call(_envCall(u, a, auth, sv));
        assertTrue(ok, "control: the signed op lands");
        vm.revertToState(snap);
        _fee(address(off), F + 2);
        a.decoyFee = decoy - 1;
        assertEq(keccak256(off.transferStatement(a, tag)), keccak256(st), "the same statement: only the signature binds d");
        vm.prank(address(0x4E1A));
        (ok,) = address(off).call(_envCall(u, a, auth, sv));
        assertFalse(ok, "d - k under the same envelope signature");
    }

    function _envTag(MetaTxLib.UAEnvelope memory u) internal view returns (bytes32) {
        return keccak256(bytes.concat(
            abi.encode(keccak256("SCAAS-PQZ-UA-ENVELOPE-V1"), block.chainid, off.chainUid(), address(off), u.from, u.batch),
            abi.encode(u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
    }

    /// `NKEY`'s signature over `UAPqzTransfer` (args by `_hashM`, `decoyFee` among them) in `off`'s domain.
    function _envAuth(MetaTxLib.UAEnvelope memory u, IPqzToken.PqzMultiArgs memory a)
        internal view returns (IUARegistry.UASig memory auth)
    {
        bytes32 th = keccak256(
            "UAPqzTransfer(bytes32 from,PqzMultiArgs args,bytes proof,bytes accHint,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)PqzLeg(bytes32 ua,bytes v,bytes vAuditor)PqzMultiArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes32 ownTag,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo)");
        bytes32 sh = keccak256(bytes.concat(abi.encode(th, u.from), abi.encode(_hashM(a), keccak256(VPROOF), keccak256("")),
            abi.encode(u.batch, u.nonce, u.validUntil, u.mode, address(0), u.fee, address(0))));
        (uint8 vv, bytes32 r, bytes32 ss) = vm.sign(NKEY, MessageHashUtils.toTypedDataHash(_sepOf(address(off)), sh));
        auth.signature = abi.encodePacked(r, ss, vv);
    }

    function _envCall(MetaTxLib.UAEnvelope memory u, IPqzToken.PqzMultiArgs memory a, IUARegistry.UASig memory auth,
        IPqzToken.PqzSignedVerdict memory sv) internal pure returns (bytes memory)
    {
        return abi.encodeWithSignature("mtxConfidentialTransfer((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),(uint64,uint256,uint256,bytes32,uint64,bytes32,uint256,bytes16,bytes32,bytes[],(bytes32,bytes,bytes)[],bytes,bytes),bytes,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]),bytes,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]),((address,uint256,bytes32,bytes32,bytes32,uint32,uint64),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])))",
            u, a, VPROOF, _pqAuth(), bytes(""), auth, sv);
    }

    // ------------------------------------------------------------------ (6) the disclosure charges nothing

    function test_disclosure_movesNoBalance() public {
        bytes32 ref = off.mtxConfidentialTransferSingle(_singleA(off, false, 0), VPROOF, _pqAuth(), "",
            _sv(off, _stmt(SINGLE, off, 0)));
        address v = vm.addr(VKEY);
        (uint256 b0, uint256 p0) = (off.balanceOf(v), off.balanceOf(MetaTxLib.SHIELD_POOL));
        bytes memory st = off.disclosureStatement(ref, 0, 7, 1, 0);
        off.verifyTransferAmount(ref, 0, 7, 1, 0, VPROOF, _sv(off, st));
        assertEq(off.balanceOf(v), b0, "the verifier");
        assertEq(off.balanceOf(MetaTxLib.SHIELD_POOL), p0, "the pool");
    }
}

/// Round 3t (§15 (1)): a Zether kind refuses either verifier fee field with the other kind's field error (Zether ≠ PQZ; the
/// `ZetherLib.init` check 3f's and 3h's fields have; kinds 2, 3, 10, 11 share it); both 0 creates.
contract PqzVerifierFeeZetherTest is ZetherFixture {
    function setUp() public {
        _stack();
    }

    function test_verifierFee_zether_refused() public {
        IFactoryToken.TokenConfig memory c = _cfg(false, uint256(1) << 40);
        c.conf.verifierFee = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "z-fee");
        (c.conf.verifierFee, c.conf.verifierFeeMax) = (0, 1);
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, 4));
        factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "z-cap");
        c.conf.verifierFeeMax = 0;
        assertTrue(factory.createToken(IOpenFactory.TokenKind.NORMAL_ZETHER, 1, abi.encode(c), "z-none") != address(0));
    }
}
