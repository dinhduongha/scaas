// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {noVerdict} from "../helpers/PqzVerdicts.sol";
import {PqzOffchainBase} from "../helpers/PqzOffchainBase.sol";
import {PqzCt} from "../../../src/pqz/PqzCt.sol";
import {IPqzToken, IPqzWrappedToken} from "../../../src/pqz/IPqzToken.sol";
import {IConfidentialWrappedToken} from "../../../src/confidential/IConfidentialToken.sol";
import {NormalPqzToken} from "../../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../../src/pqz/WrappedPqzToken.sol";
import {IUALedger} from "../../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../../src/common/MetaTxLib.sol";
import {MockERC20} from "../../helpers/Mocks.sol";
import {WrappedToken} from "../../../src/metatx/WrappedToken.sol";
import {UARegistry} from "../../../src/ua/UARegistry.sol";
import {EnvKit} from "../../helpers/EnvKit.sol";

/// Round 3t (verifier fee spec §15 (8), controller A3): the handler of F1-F6 and I-V1..I-V3. Three tokens, `toks[0]` a
/// `PRECOMPILE` kind 4, `toks[1]` an `OFFCHAIN` kind 4 and `toks[2]` an `OFFCHAIN` kind 5 (this handler their admin, the
/// factory's notice 1 day), three holders. Actions: shields of any amount into any holder (a wrap-shield on kind 5), op 1 and
/// op 7 (with and without a beneficiary, `d ≥ minDecoyFee = 0`), burns, refreshes and unwraps (kind 5), each with a random
/// `shieldIn` top-up and an amount drawn across the sender's ghost `T`; fee changes (decrease, propose, warp, confirm); a held
/// direct op replayed after a fee change, op 7 with `d` shifted by `Δvf / 2` (Fable P1-1). Proofs are mocked under an honest
/// model: the precompile mock (`PRECOMPILE`) and the verifier's key (`OFFCHAIN`; another key otherwise) accept a debit only
/// when the ghost `T` at `p` covers `v + fee` (or `amount + fee`). The ghost mirrors each account (`acc`, `rolled`, every
/// pending amount, the token's TRIVIAL merge read back). Ghosts count what a rule forbids and happened anyway; no action
/// reverts. UNAUDITED.
contract PqzFeeHandler is PqzOffchainBase {
    uint256 internal constant INLINE = 16; // PqzCore.INLINE_MAX
    NormalPqzToken[3] public toks;
    bytes32[3] internal us;
    bytes32 public ben; // a registered UA without a PQZ key (C0-7)
    address internal constant RCP = address(0xD00D);

    // the ghost: per token, per holder
    mapping(uint256 => mapping(uint256 => uint256)) public gAcc;
    mapping(uint256 => mapping(uint256 => uint256)) public gRolled;
    mapping(uint256 => mapping(uint256 => uint256[])) internal gPend;
    // per token, in shielded units unless named
    mapping(uint256 => uint256) public shields;
    mapping(uint256 => uint256) public shieldIns;
    mapping(uint256 => uint256) public outs; // Σ (fee + amount) of landed debits
    mapping(uint256 => uint256) public paidPublic; // Σ public payouts observed (public units; an unwrap's burn included)
    mapping(uint256 => uint256) public supplyWant; // totalSupply as wraps, mints and unwraps move it
    uint256 public landedShort; // F5: landed with T < v + fee
    uint256 public refusedHonest; // an honest debit refused
    uint256 public badWord; // F6: a fee word not txFee + vf_now (+ M·d)
    uint256 public replayLanded; // F6: a held op landed after a fee change (shifted d included)
    uint256 public debits; // landed debits (the control)
    uint256 public feeMoves; // fee changes applied

    // a held op
    bytes internal heldCd;
    IPqzToken.PqzVerdict internal heldV; // the held verdict (a native verifier: its signature bytes only)
    bytes internal heldSig;
    D internal heldX;
    uint256 internal heldTok;
    uint64 internal heldFee;
    bool internal held;

    constructor(UARegistry r, bytes32 a_, bytes32 b_, bytes32 c_, bytes32 ben_) {
        (reg, alice, bob, carol, ben) = (r, a_, b_, c_, ben_);
        us = [a_, b_, c_];
    }

    /// Once, by the suite's setUp (not an action): the tokens, this handler's public units of kind 5 (a wrap of its leg).
    function setTokens(NormalPqzToken pre_, NormalPqzToken off_, WrappedPqzToken offW_) external {
        if (address(toks[0]) != address(0)) return;
        toks = [pre_, off_, NormalPqzToken(address(offW_))];
        MockERC20 u = MockERC20(offW_.underlyings()[0]);
        u.approve(address(offW_), type(uint256).max);
        u.mint(address(this), 100_000 * SCALE);
        WrappedToken(payable(address(offW_))).wrap(address(u), 100_000 * SCALE);
        for (uint256 t; t < 3; ++t) supplyWant[t] = toks[t].totalSupply();
    }

    // ------------------------------------------------------------------ the ghost

    function _vf(uint256 t) internal view returns (uint64) {
        return t == 0 ? 0 : toks[t].pqzVerifyConfig().verifierFee;
    }

    /// The sender's `p`: the inline window's end (at most `INLINE` past `rolled`).
    function _pOf(uint256 t, uint256 i) internal view returns (uint256 p) {
        p = toks[t].pqzAccount(us[i], 0).pendingCount;
        if (p > gRolled[t][i] + INLINE) p = gRolled[t][i] + INLINE;
    }

    /// The ghost `T` of holder `i` at `p` (before `shieldIn`).
    function _T(uint256 t, uint256 i, uint256 p) internal view returns (uint256 s) {
        s = gAcc[t][i];
        for (uint256 k = gRolled[t][i]; k < p; ++k) s += gPend[t][i][k];
    }

    /// A credit of `amount` to holder `j`: appended, or merged into the tail as the token did (read back).
    function _credit(uint256 t, uint256 j, uint256 amount) internal {
        uint256 n = toks[t].pqzAccount(us[j], 0).pendingCount;
        uint256[] storage pd = gPend[t][j];
        if (n == pd.length) pd[n - 1] += amount;
        else pd.push(amount);
    }

    function _settle(uint256 t, uint256 i, uint256 p, uint256 left) internal {
        (gAcc[t][i], gRolled[t][i]) = (left, p);
    }

    function hidden(uint256 t) public view returns (uint256 s) {
        for (uint256 i; i < 3; ++i) {
            s += gAcc[t][i];
            for (uint256 k = gRolled[t][i]; k < gPend[t][i].length; ++k) s += gPend[t][i][k];
        }
    }

    /// Every public balance a debit can pay into (the verifier, the beneficiary, the legs' ledgers, the recipient).
    function _payees(uint256 t) internal view returns (uint256 s) {
        NormalPqzToken k = toks[t];
        s = k.balanceOf(vm.addr(VKEY)) + IUALedger(address(k)).balanceOfUA(ben) + k.balanceOf(RCP);
        for (uint256 i; i < 3; ++i) s += IUALedger(address(k)).balanceOfUA(us[i]);
    }

    // ------------------------------------------------------------------ actions

    /// Shield `amount` into holder `j` of token `t` (kind 5: a wrap-shield of the leg).
    function shield(uint256 t, uint256 j, uint256 amount) external {
        (t, j, amount) = (t % 3, j % 3, bound(amount, 1, 10_000));
        bool ok;
        if (t == 2) {
            WrappedPqzToken w_ = WrappedPqzToken(payable(address(toks[2])));
            MockERC20 u = MockERC20(w_.underlyings()[0]);
            u.mint(address(this), amount * SCALE);
            (ok,) = address(w_).call(abi.encodeCall(IConfidentialWrappedToken.mtxWrapShield, (address(u), amount * SCALE, us[j])));
            if (ok) supplyWant[2] += amount * SCALE;
        } else {
            (ok,) = address(toks[t]).call(abi.encodeWithSignature("mtxShield(bytes32,uint256)", us[j], amount));
        }
        if (!ok) return;
        shields[t] += amount;
        _credit(t, j, amount);
    }

    struct D {
        uint256 t;
        uint256 i;
        uint256 kind; // 0 op 1, 1 op 7, 2 burn, 3 refresh, 4 unwrap
        uint256 p;
        uint256 tt; // the ghost T at p
        uint256 shieldIn;
        uint256 v; // op 1's value; op 7: leg 0's (leg 1 gets w)
        uint256 w;
        uint256 amount; // burn / unwrap
        uint256 d;
        bool withBen;
        uint256 fee;
        bool honest;
    }

    /// One debit of holder `i` on token `t`.
    function debit(uint256 t, uint256 i, uint256 kind, uint256 seed) external {
        D memory x;
        (x.t, x.i, x.kind) = (t % 3, i % 3, kind % 5);
        if (x.kind == 4 && x.t != 2) x.kind = 2;
        x.p = _pOf(x.t, x.i);
        x.tt = _T(x.t, x.i, x.p);
        x.shieldIn = seed % 4 == 0 ? bound(seed >> 8, 1, 50) : 0;
        x.withBen = (seed >> 16) % 2 == 1;
        x.d = x.kind == 1 ? (seed >> 24) % 4 : 0;
        uint256 span = x.tt + x.shieldIn + 8;
        if (x.kind == 0) x.v = (seed >> 32) % span;
        if (x.kind == 1) (x.v, x.w) = ((seed >> 32) % span, (seed >> 64) % span / 2);
        if (x.kind == 2 || x.kind == 4) x.amount = 1 + (seed >> 32) % span;
        x.fee = (x.withBen ? FEE : 0) + _vf(x.t) + (x.kind == 1 ? 2 * x.d : 0);
        x.honest = x.tt + x.shieldIn >= x.v + x.w + x.amount + x.fee;
        (bytes memory st, bytes memory cd) = _build(x, x.honest ? VKEY : VKEY2);
        if (_wd(st) != x.fee) ++badWord;
        _exec(x, cd);
    }

    /// The call under the honest model (the precompile answers whether `T` covers it), then the ghost.
    function _exec(D memory x, bytes memory cd) internal {
        uint8 op = x.kind == 0 ? 1 : x.kind == 1 ? 7 : 2;
        if (x.t == 0) _mockOp(op, x.honest ? 1 : 0);
        uint256 pay0 = _payees(x.t);
        uint256 sup0 = toks[x.t].totalSupply();
        (bool ok,) = address(toks[x.t]).call(cd);
        if (x.t == 0) _mockOp(op, 1);
        if (ok && !x.honest) ++landedShort;
        if (!ok && x.honest) ++refusedHonest;
        if (!ok) return;
        ++debits;
        paidPublic[x.t] += _payees(x.t) - pay0 + (sup0 - toks[x.t].totalSupply());
        if (x.kind == 4) supplyWant[2] -= x.amount * SCALE;
        shieldIns[x.t] += x.shieldIn;
        outs[x.t] += x.fee + x.amount;
        _settle(x.t, x.i, x.p, x.tt + x.shieldIn - x.v - x.w - x.amount - x.fee);
        if (x.kind == 0) _credit(x.t, (x.i + 1) % 3, x.v);
        if (x.kind == 1) {
            _credit(x.t, (x.i + 1) % 3, x.v);
            _credit(x.t, (x.i + 2) % 3, x.w);
        }
    }

    function _wd(bytes memory st) internal pure returns (uint256) {
        return uint256(bytes32(_slice(st, 256, 32)));
    }

    /// The statement and the call of `x` (direct), the verdict signed by `key` on an `OFFCHAIN` token.
    function _build(D memory x, uint256 key) internal returns (bytes memory st, bytes memory cd) {
        if (x.kind == 0) return _b1(x, key);
        if (x.kind == 1) return _b7(x, key);
        if (x.kind == 4) return _bUnwrap(x, key);
        return _bBurn(x, key);
    }

    function _ben(D memory x) internal view returns (bytes32) {
        return x.withBen ? ben : bytes32(0);
    }

    function _b1(D memory x, uint256 key) internal view returns (bytes memory st, bytes memory cd) {
        IPqzToken.PqzTransferArgs memory a =
            _ts(_payload(x.p, x.shieldIn, us[x.i], us[(x.i + 1) % 3], _ben(x), _out(x.p + 7, false), ""));
        st = toks[x.t].transferSingleStatement(a, 0);
        cd = abi.encodeCall(IPqzToken.mtxConfidentialTransferSingle, (a, VPROOF, _pqAuth(), "", _svOf(x.t, st, key)));
    }

    function _b7(D memory x, uint256 key) internal returns (bytes memory st, bytes memory cd) {
        decoy = x.d;
        IPqzToken.PqzMultiArgs memory m = _multi(x, _ben(x));
        st = toks[x.t].transferStatement(m, 0);
        cd = abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (m, VPROOF, _pqAuth(), "", _svOf(x.t, st, key)));
    }

    function _burnArgs(D memory x) internal view returns (IPqzToken.PqzBurnArgs memory) {
        return _bs(bytes.concat(abi.encode(x.p, block.number + 50, x.shieldIn, us[x.i], _ben(x)), _blob(x.p + 9, PqzCt.CT)));
    }

    function _bBurn(D memory x, uint256 key) internal view returns (bytes memory st, bytes memory cd) {
        IPqzToken.PqzBurnArgs memory bb = _burnArgs(x);
        (uint256 amt, bytes32 rcp) = x.kind == 2 ? (x.amount, MetaTxLib.pad(RCP)) : (uint256(0), bytes32(0));
        st = toks[x.t].burnStatement(bb, amt, rcp, 0);
        cd = _cdBurn(bb, amt, rcp, _svOf(x.t, st, key));
    }

    function _cdBurn(IPqzToken.PqzBurnArgs memory bb, uint256 amt, bytes32 rcp, IPqzToken.PqzSignedVerdict memory sv)
        internal pure returns (bytes memory)
    {
        return abi.encodeCall(IPqzToken.mtxUnshield, (bb, amt, rcp, VPROOF, _pqAuth(), "", sv));
    }

    function _bUnwrap(D memory x, uint256 key) internal view returns (bytes memory st, bytes memory cd) {
        IPqzToken.PqzBurnArgs memory bb = _burnArgs(x);
        WrappedPqzToken k = WrappedPqzToken(payable(address(toks[x.t])));
        IConfidentialWrappedToken.Unwrap memory u =
            IConfidentialWrappedToken.Unwrap(k.underlyings()[0], MetaTxLib.pad(RCP), x.amount, 0);
        st = k.unshieldUnwrapStatement(bb, u, 0);
        cd = _cdUnwrap(bb, u, _svOf(x.t, st, key));
    }

    function _cdUnwrap(IPqzToken.PqzBurnArgs memory bb, IConfidentialWrappedToken.Unwrap memory u,
        IPqzToken.PqzSignedVerdict memory sv) internal pure returns (bytes memory)
    {
        return abi.encodeCall(IPqzWrappedToken.mtxUnshieldUnwrap, (bb, u, VPROOF, _pqAuth(), "", sv));
    }

    function _multi(D memory x, bytes32 b) internal view returns (IPqzToken.PqzMultiArgs memory) {
        bytes32[] memory legs = new bytes32[](2);
        (legs[0], legs[1]) = (us[(x.i + 1) % 3], us[(x.i + 2) % 3]);
        return _ms(_mpayload(x.p, x.shieldIn, us[x.i], b, legs, _blob(x.p + 8, _outLen(2, false)), ""));
    }

    function _svOf(uint256 t, bytes memory st, uint256 key) internal view returns (IPqzToken.PqzSignedVerdict memory) {
        if (t == 0) return noVerdict();
        return _sign(toks[t], key, _verdict(toks[t], st, VPROOF));
    }

    // ------------------------------------------------------------------ the fee (tokens 1, 2)

    function feeDecrease(uint256 t, uint256 to) external {
        t = 1 + t % 2;
        uint64 cur = _vf(t);
        if (cur == 0) return;
        try IPqzToken(address(toks[t])).setVerifierFee(uint64(to % cur), EnvKit.codeUidOf(address(IPqzToken(address(toks[t]))))) { ++feeMoves; } catch {}
    }

    function feePropose(uint256 t, uint256 to) external {
        t = 1 + t % 2;
        IPqzToken.PqzVerifyConfig memory c = toks[t].pqzVerifyConfig();
        if (c.verifierFee == c.verifierFeeMax || c.verifierFeePending != 0) return;
        try IPqzToken(address(toks[t])).setVerifierFee(uint64(c.verifierFee + 1 + to % (c.verifierFeeMax - c.verifierFee)), EnvKit.codeUidOf(address(IPqzToken(address(toks[t]))))) {} catch {}
    }

    function feeConfirm(uint256 t) external {
        t = 1 + t % 2;
        IPqzToken.PqzVerifyConfig memory c = toks[t].pqzVerifyConfig();
        if (c.verifierFeePending == 0 || block.timestamp < c.verifierFeeEta) return;
        try IPqzToken(address(toks[t])).setVerifierFee(c.verifierFeePending, EnvKit.codeUidOf(address(IPqzToken(address(toks[t]))))) { ++feeMoves; } catch {}
    }

    function warp(uint256 s) external {
        vm.warp(block.timestamp + bound(s, 1 hours, 2 days));
    }

    /// Holds an honest direct op 1 or op 7 (M = 2) of holder `i` on an `OFFCHAIN` token and its verdict.
    function hold(uint256 t, uint256 i, uint256 seed) external {
        D memory x;
        (x.t, x.i, x.kind) = (1 + t % 2, i % 3, seed % 2);
        x.p = _pOf(x.t, x.i);
        x.d = 2 + (seed >> 8) % 3;
        bytes memory st;
        (st, heldCd) = _build(x, VKEY);
        IPqzToken.PqzSignedVerdict memory sv = _svOf(x.t, st, VKEY);
        (heldV, heldSig) = (sv.pqzVerdict, sv.sig.signature);
        heldX = x;
        (heldTok, heldFee, held) = (x.t, _vf(x.t), true);
    }

    /// After a fee change the held op must not land, nor op 7 resubmitted with `d ∓ Δvf / 2` (the same fee word) under the
    /// held verdict.
    function replay() external {
        if (!held) return;
        uint64 now_ = _vf(heldTok);
        if (now_ == heldFee) return;
        held = false;
        (bool ok,) = address(toks[heldTok]).call(heldCd);
        if (ok) ++replayLanded;
        uint256 delta = now_ > heldFee ? now_ - heldFee : heldFee - now_;
        D memory x = heldX;
        if (x.kind != 1 || delta % 2 != 0 || (now_ > heldFee && x.d < delta / 2)) return;
        x.d = now_ > heldFee ? x.d - delta / 2 : x.d + delta / 2;
        decoy = x.d;
        (bool ok2,) = address(toks[heldTok]).call(_shifted(_multi(x, _ben(x))));
        if (ok2) ++replayLanded;
    }

    /// Op 7 `m` under the held verdict.
    function _shifted(IPqzToken.PqzMultiArgs memory m) internal view returns (bytes memory) {
        IPqzToken.PqzSignedVerdict memory sv;
        (sv.pqzVerdict, sv.sig.signature) = (heldV, heldSig);
        return abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (m, VPROOF, _pqAuth(), "", sv));
    }
}
