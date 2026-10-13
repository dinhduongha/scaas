// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {UnderlyingToken} from "../../src/metatx/UnderlyingToken.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {FeeMode} from "../../src/common/FeePolicy.sol";
import {UALedgerBase} from "./UALedgerBase.sol";

/// Random mixes of native moves, mints, burns, `transferToUA`, the UA transfer entries (`uaExecuteTransfer`, the named
/// `uaTransfer` / `uaTransferWithFee`, `uaBatchTransfer`; any side native or derived, with or without a fee) on the NONE
/// clone and on the 1:1 UNDERLYING clone `wrp`, plus wrap, wrap→UA and the burn under a derived UA (`unwrap` through
/// `uaExecute` with a fee after the self-call, or the named `uaUnwrap`), and the `UA_POOL` `transferFrom` refusal.
/// UA-5a (CTR-UA-28, CTR-UA-26, CTR-MTX-05): `wrapToUA` on `wrp` and on the native-leg `wrpN`, `mintToUA`,
/// `payWithFeeToUA`, `burn` under a derived UA, wraps of the ledger-leg `wrpL` (leg `tok`, wrapped by this handler, a
/// contract), `unwrapToUA` from `wrpL` (direct by a native, or under `uaExecute` by a UA), `uaPayReceiverFee`.
/// After every call the handler replays the tokens' `Transfer` logs per native holder and `UATransfer` logs per
/// derived id, and checks `UATransfer` is emitted exactly for the moves with a derived side.
contract UALedgerHandler is Test {
    bytes32 internal constant TRANSFER_SIG = keccak256("Transfer(address,address,uint256)");
    bytes32 internal constant UATRANSFER_SIG = keccak256("UATransfer(bytes32,bytes32,uint256)");
    address internal constant RELAYER = address(0xBEEF);
    address internal constant FEE_TO = address(0xFEE);

    MetaTokenBase internal immutable tok;
    MetaTokenBase internal immutable wrp;
    MetaTokenBase internal immutable wrpL;
    MetaTokenBase internal immutable wrpN;
    MockERC20 internal immutable und;
    UARegistry internal immutable reg;
    address internal immutable minter;
    uint256[3] internal pks = [uint256(0xA11CE), 0xB0B, 0xCA401];
    bytes32[2] public uas;
    bytes[2] internal keys;
    uint16[2] internal kinds;
    mapping(address => mapping(address => int256)) public replay; // token => native holder
    mapping(address => mapping(bytes32 => int256)) public uaReplay; // token => derived id
    uint256 internal refs;

    constructor(
        NoUnderlyingToken tok_, UnderlyingToken wrp_, UnderlyingToken wrpL_, UnderlyingToken wrpN_, MockERC20 und_,
        UARegistry reg_, address minter_, bytes32[2] memory uas_, bytes[2] memory keys_, uint16[2] memory kinds_
    ) {
        (tok, wrp, wrpL, wrpN, und, reg, minter) = (tok_, wrp_, wrpL_, wrpN_, und_, reg_, minter_);
        (uas, keys, kinds) = (uas_, keys_, kinds_);
        replay[address(tok_)][vm.addr(pks[0])] = int256(tok_.balanceOf(vm.addr(pks[0])));
        vm.recordLogs();
    }

    /// Every native holder of every tracked token: `wrpL` holds `tok` (its reserve), this handler wraps `wrpL`.
    function natives() public view returns (address[8] memory a) {
        a = [vm.addr(pks[0]), vm.addr(pks[1]), vm.addr(pks[2]), RELAYER, FEE_TO, MetaTxLib.UA_POOL, address(wrpL),
            address(this)];
    }

    // ----- ops: NONE clone -----

    function mint(uint256 who, uint256 amount) external {
        amount = bound(amount, 0, 1e12);
        vm.prank(minter);
        NoUnderlyingToken(address(tok)).mint(vm.addr(pks[who % 3]), amount);
        _settle(tok, 0, 1);
    }

    function burn(uint256 who, uint256 amount) external {
        address a = vm.addr(pks[who % 3]);
        amount = bound(amount, 0, tok.balanceOf(a));
        vm.prank(a);
        NoUnderlyingToken(address(tok)).burn(amount);
        _settle(tok, 0, 1);
    }

    function nativeTransfer(uint256 from, uint256 to, uint256 amount) external {
        address a = vm.addr(pks[from % 3]);
        amount = bound(amount, 0, tok.balanceOf(a));
        vm.prank(a);
        tok.transfer(vm.addr(pks[to % 3]), amount);
        _settle(tok, 0, 1);
    }

    function transferToUA(uint256 from, uint256 ua, uint256 amount) external {
        address a = vm.addr(pks[from % 3]);
        amount = bound(amount, 0, tok.balanceOf(a));
        vm.prank(a);
        tok.transferToUA(uas[ua % 2], amount);
        _settle(tok, 1, 1);
    }

    // ----- ops: UNDERLYING clone (1:1, one leg) -----

    function wrapNative(uint256 who, uint256 amount) external {
        address a = vm.addr(pks[who % 3]);
        amount = bound(amount, 1, 1e12); // wrap(0) reverts
        und.mint(a, amount);
        vm.startPrank(a);
        und.approve(address(wrp), amount);
        UnderlyingToken(address(wrp)).wrap(amount);
        vm.stopPrank();
        _settle(wrp, 0, 1);
    }

    function wrpToUA(uint256 from, uint256 ua, uint256 amount) external {
        address a = vm.addr(pks[from % 3]);
        amount = bound(amount, 0, wrp.balanceOf(a));
        vm.prank(a);
        wrp.transferToUA(uas[ua % 2], amount);
        _settle(wrp, 1, 1);
    }

    /// The burn under a derived UA: `unwrap(und, amt, recipient, 0)` as `uaExecute` (optionally with a 1 % fee paid
    /// after the self-call) or the fee-less named `uaUnwrap`. `amt + fee` is bounded to the UA's balance.
    function unwrapUnder(uint256 fromIdx, uint256 amount, bool withFee, bool viaNamed) external {
        bytes32 f = uas[fromIdx % 2];
        uint256 have = wrp.balanceOfUA(f);
        // fee = amt / 100 exactly: amt is a multiple of 100 and `amt + amt / 100 ≤ have`
        amount = bound(amount, 0, have * 100 / 101) / 100 * 100;
        if (amount == 0) return;
        address recipient = vm.addr(pks[1]);
        uint256 fee = withFee && !viaNamed ? amount / 100 : 0;
        MetaTxLib.UAMetaTransaction memory m = MetaTxLib.UAMetaTransaction({
            from: f, data: abi.encodeWithSignature("unwrap(address,uint256,address,uint256)", address(und), amount, recipient, 0),
            batch: 1, nonce: wrp.uaNonce(f, 1), validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER,
            relayer: RELAYER, fee: 0, feeRecipient: address(0)
        });
        if (fee != 0) {
            m.mode |= MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT | MetaTxLib.MODE_FEE_PERCENT;
            (m.fee, m.feeRecipient) = (10_000, FEE_TO);
        }
        bytes memory auth = _auth(3 + fromIdx % 2, wrp.uaDigest(m));
        vm.prank(RELAYER);
        if (viaNamed) {
            wrp.uaUnwrap(f, address(und), amount, recipient, 0, 1, m.nonce, m.validUntil, m.mode, RELAYER, auth);
        } else {
            wrp.uaExecute(m, auth);
        }
        uint256 n = fee != 0 ? 2 : 1; // the burn, and the fee move out of the UA
        _settle(wrp, n, n);
    }

    // ----- ops: UA-5a receivers, the UA allowlist, receiver-pays -----

    /// `wrapToUA` by a native: on `wrp` (ERC-20 leg) or on `wrpN` (the native coin, `msg.value`).
    function wrapToUA(uint256 who, uint256 ua, uint256 amount, bool nativeLeg) external {
        address a = vm.addr(pks[who % 3]);
        amount = bound(amount, 1, 1e12);
        vm.startPrank(a);
        if (nativeLeg) {
            vm.deal(a, amount);
            UnderlyingToken(address(wrpN)).wrapToUA{value: amount}(address(0), amount, uas[ua % 2]);
        } else {
            und.mint(a, amount);
            und.approve(address(wrp), amount);
            UnderlyingToken(address(wrp)).wrapToUA(address(und), amount, uas[ua % 2]);
        }
        vm.stopPrank();
        _settle(nativeLeg ? wrpN : wrp, 1, 1);
    }

    function mintToUA(uint256 ua, uint256 amount) external {
        amount = bound(amount, 0, 1e12);
        vm.prank(minter);
        NoUnderlyingToken(address(tok)).mintToUA(uas[ua % 2], amount);
        _settle(tok, 1, 1);
    }

    /// A native pays a UA with an optional FIXED fee of 1 % to `FEE_TO` on top.
    function payWithFeeToUA(uint256 from, uint256 ua, uint256 amount, bool withFee) external {
        address a = vm.addr(pks[from % 3]);
        amount = bound(amount, 0, tok.balanceOf(a) * 100 / 101);
        uint256 fee = withFee ? amount / 100 : 0;
        vm.prank(a);
        tok.payWithFeeToUA(uas[ua % 2], amount, fee != 0 ? FeeMode.FIXED : FeeMode.NONE, fee, FEE_TO, keccak256("pay"));
        _settle(tok, 1, fee != 0 ? 2 : 1);
    }

    /// `burn` under a derived UA (`uaExecute`), optionally with the `AMOUNT(0)` fee of 1 % after the self-call.
    function burnUnderUA(uint256 fromIdx, uint256 amount, bool withFee) external {
        bytes32 f = uas[fromIdx % 2];
        amount = bound(amount, 0, tok.balanceOfUA(f) * 100 / 101) / 100 * 100;
        uint256 fee = withFee ? amount / 100 : 0;
        MetaTxLib.UAMetaTransaction memory m = _uaCall(tok, f, abi.encodeCall(NoUnderlyingToken.burn, (amount)), fee);
        bytes memory auth = _auth(3 + fromIdx % 2, tok.uaDigest(m));
        vm.prank(RELAYER);
        tok.uaExecute(m, auth);
        uint256 n = fee != 0 ? 2 : 1;
        _settle(tok, n, n);
    }

    /// `wrpL` units for a native or a UA: this handler (a contract, so it may approve) gets `tok` from the minter, wraps
    /// it and passes the units on (`transfer`, or `transferToUA`).
    function wrapLedger(uint256 to, uint256 amount) external {
        amount = bound(amount, 1, 1e12);
        vm.prank(minter);
        NoUnderlyingToken(address(tok)).mint(address(this), amount);
        tok.approve(address(wrpL), amount);
        UnderlyingToken(address(wrpL)).wrap(amount);
        bool toUA = to % 5 > 2;
        if (toUA) wrpL.transferToUA(_id(to % 5), amount);
        else wrpL.transfer(vm.addr(pks[to % 5]), amount);
        _settle2(tok, 0, 2, wrpL, toUA ? 1 : 0, 2);
    }

    /// `unwrapToUA` from `wrpL` into a UA of `tok`: direct by a native, or under `uaExecute` by a UA (optionally with
    /// the `AMOUNT(1)` fee of 1 %).
    function unwrapToUA(uint256 fromIdx, uint256 toUa, uint256 amount, bool viaUA, bool withFee) external {
        bytes32 to = uas[toUa % 2];
        bytes memory data;
        if (!viaUA) {
            address a = vm.addr(pks[fromIdx % 3]);
            amount = bound(amount, 0, wrpL.balanceOf(a));
            if (amount == 0) return;
            vm.prank(a);
            UnderlyingToken(address(wrpL)).unwrapToUA(address(tok), amount, to, 0);
            _settle2(wrpL, 0, 1, tok, 1, 1);
            return;
        }
        bytes32 f = uas[fromIdx % 2];
        amount = bound(amount, 0, wrpL.balanceOfUA(f) * 100 / 101) / 100 * 100;
        if (amount == 0) return;
        uint256 fee = withFee ? amount / 100 : 0;
        data = abi.encodeCall(UnderlyingToken.unwrapToUA, (address(tok), amount, to, 0));
        MetaTxLib.UAMetaTransaction memory m = _uaCall(wrpL, f, data, fee);
        bytes memory auth = _auth(3 + fromIdx % 2, wrpL.uaDigest(m));
        vm.prank(RELAYER);
        wrpL.uaExecute(m, auth);
        uint256 n = fee != 0 ? 2 : 1;
        _settle2(wrpL, n, n, tok, 1, 1);
    }

    /// Receiver-pays on `tok`: payer and payee index 0–2 a native, 3–4 a UA (distinct); the payee pays `fee` (1 … value)
    /// to `FEE_TO` out of the payment.
    function uaPayReceiverFee(uint256 payer, uint256 payee, uint256 amount, uint256 fee) external {
        (payer, payee) = (payer % 5, payee % 5);
        if (payer == payee) return;
        bytes32 p = _id(payer);
        bytes32 q = _id(payee);
        amount = bound(amount, 0, tok.balanceOfUA(p));
        if (amount == 0) return;
        fee = bound(fee, 1, amount);
        bytes32 ref = keccak256(abi.encode("scaas.ua5a.inv", ++refs));
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({
            from: p, to: q, value: amount, entryRef: ref, batch: tok.payLane(ref), nonce: 0,
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: RELAYER, fee: 0,
            feeRecipient: address(0)
        });
        bytes32 d = tok.uaTransferDigest(x);
        bytes memory payerAuth = _auth(payer, d);
        bytes memory payeeAuth = _sign(payee, UAKinds.PURPOSE_RECEIVER_FEE,
            tok.receiverFeeDigest(d, fee, FEE_TO, block.timestamp));
        vm.prank(RELAYER);
        tok.uaPayReceiverFee(x, payerAuth, fee, FEE_TO, block.timestamp, payeeAuth);
        bool pUA = payer > 2;
        bool qUA = payee > 2;
        // the payment (UATransfer iff a derived side, Transfer iff a native side), then the fee from the payee to FEE_TO
        _settle(tok, (pUA || qUA ? 1 : 0) + (qUA ? 1 : 0), (pUA && qUA ? 0 : 1) + 1);
    }

    // ----- ops: UA transfers on either token -----

    /// `from`/`to` index 0–2 a native holder, 3–4 a UA; `withFee` adds a FIXED fee to `FEE_TO` (1 % cap). `seed` picks
    /// the token (NONE or `wrp`) and the entry (`uaExecuteTransfer`, the named form, `uaBatchTransfer`).
    function uaTransfer(uint256 from, uint256 to, uint256 amount, bool withFee, uint256 seed) external {
        MetaTokenBase t_ = seed % 2 == 0 ? tok : wrp;
        bytes32 f = _id(from % 5);
        bytes32 t = _id(to % 5);
        uint256 have = t_.balanceOfUA(f);
        MetaTxLib.UAMetaTransfer memory x = MetaTxLib.UAMetaTransfer({
            from: f, to: t, value: bound(amount, 0, have), entryRef: 0, batch: 1, nonce: t_.uaNonce(f, 1),
            validUntil: block.timestamp + 300, mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: RELAYER, fee: 0,
            feeRecipient: address(0)
        });
        uint256 fee = withFee ? x.value / 100 : 0;
        if (fee != 0 && x.value + fee <= have) {
            x.mode |= MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT | MetaTxLib.MODE_FEE_FIXED;
            (x.fee, x.feeRecipient) = (fee, FEE_TO);
        } else {
            fee = 0;
        }
        bytes memory auth = _auth(from % 5, t_.uaTransferDigest(x));
        vm.prank(RELAYER);
        _submit(t_, x, auth, (seed / 2) % 3);
        bool fromUA = from % 5 > 2;
        bool toUA = to % 5 > 2;
        uint256 moves = fee != 0 ? 2 : 1;
        // derived side ⇒ UATransfer per move; a native side ⇒ Transfer per move (the fee always lands natively)
        _settle(t_, fromUA || toUA ? (fromUA ? moves : 1) : 0, fromUA && toUA ? moves - 1 : moves);
    }

    /// A contract spender cannot pull from `UA_POOL` outside a UA self-call: `transferFrom(UA_POOL, x, 0)` reverts.
    function poolTransferFrom(uint256 seed, uint256 to) external {
        MetaTokenBase t_ = seed % 2 == 0 ? tok : wrp;
        try t_.transferFrom(MetaTxLib.UA_POOL, vm.addr(pks[to % 3]), 0) returns (bool) {
            revert("transferFrom(UA_POOL) must revert");
        } catch (bytes memory err) {
            assertEq(bytes4(err), IUALedger.UAPoolNotPayable.selector, "UAPoolNotPayable");
        }
    }

    // ----- helpers -----

    function _submit(MetaTokenBase t_, MetaTxLib.UAMetaTransfer memory x, bytes memory auth, uint256 entry) internal {
        if (entry == 1 && x.fee == 0) {
            t_.uaTransfer(x.from, x.to, x.value, x.batch, x.nonce, x.validUntil, x.mode, x.relayer, auth);
        } else if (entry == 1) {
            t_.uaTransferWithFee(
                x.from, x.to, x.value, x.batch, x.nonce, x.validUntil, x.mode, x.relayer, x.fee, x.feeRecipient, auth
            );
        } else if (entry == 2) {
            MetaTxLib.UAMetaTransfer[] memory xs = new MetaTxLib.UAMetaTransfer[](1);
            bytes[] memory as_ = new bytes[](1);
            (xs[0], as_[0]) = (x, auth);
            t_.uaBatchTransfer(xs, as_);
        } else {
            t_.uaExecuteTransfer(x, auth);
        }
    }

    function _id(uint256 i) internal view returns (bytes32) {
        return i < 3 ? bytes32(uint256(uint160(vm.addr(pks[i])))) : uas[i - 3];
    }

    function _auth(uint256 i, bytes32 digest) internal view returns (bytes memory) {
        return _sign(i, UAKinds.PURPOSE_METATX, digest);
    }

    /// A native signs `digest` itself; a UA `ua_msg(kind, purpose, digest)` (the stand-in verifier's "signature").
    function _sign(uint256 i, bytes32 purpose, bytes32 digest) internal view returns (bytes memory) {
        if (i < 3) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], digest);
            return abi.encodePacked(r, s, v);
        }
        bytes memory k = keys[i - 3];
        bytes32 message = reg.uaMessage(kinds[i - 3], purpose, digest);
        return abi.encode(k, abi.encodePacked(keccak256(abi.encode(k, message))));
    }

    /// A `UAMetaTransaction` of `f` on `t_`, lane 1, with a bound FIXED fee to `FEE_TO` when `fee ≠ 0`.
    function _uaCall(MetaTokenBase t_, bytes32 f, bytes memory data, uint256 fee)
        internal view returns (MetaTxLib.UAMetaTransaction memory m)
    {
        m = MetaTxLib.UAMetaTransaction({
            from: f, data: data, batch: 1, nonce: t_.uaNonce(f, 1), validUntil: block.timestamp + 300,
            mode: MetaTxLib.MODE_RESTRICT_RELAYER, relayer: RELAYER, fee: 0, feeRecipient: address(0)
        });
        if (fee != 0) {
            m.mode |= MetaTxLib.MODE_RESTRICT_FEE_RECIPIENT | MetaTxLib.MODE_FEE_FIXED;
            (m.fee, m.feeRecipient) = (fee, FEE_TO);
        }
    }

    /// Replays this call's `Transfer` and `UATransfer` logs and checks the event counts.
    function _settle(MetaTokenBase t_, uint256 wantUATransfers, uint256 wantTransfers) internal {
        _replay(vm.getRecordedLogs(), t_, wantUATransfers, wantTransfers);
        vm.recordLogs();
    }

    /// The same for a call that moves two tokens.
    function _settle2(MetaTokenBase a, uint256 uaA, uint256 trA, MetaTokenBase b, uint256 uaB, uint256 trB) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        _replay(logs, a, uaA, trA);
        _replay(logs, b, uaB, trB);
        vm.recordLogs();
    }

    function _replay(Vm.Log[] memory logs, MetaTokenBase t_, uint256 wantUATransfers, uint256 wantTransfers) internal {
        uint256 transfers;
        uint256 uaTransfers;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(t_)) continue;
            if (logs[i].topics[0] == UATRANSFER_SIG) {
                ++uaTransfers;
                bytes32 f = logs[i].topics[1];
                bytes32 t = logs[i].topics[2];
                int256 u = int256(abi.decode(logs[i].data, (uint256)));
                if (!UAKinds.inNativeSpace(f)) uaReplay[address(t_)][f] -= u;
                if (!UAKinds.inNativeSpace(t)) uaReplay[address(t_)][t] += u;
                continue;
            }
            if (logs[i].topics[0] != TRANSFER_SIG) continue;
            ++transfers;
            address from = address(uint160(uint256(logs[i].topics[1])));
            address to = address(uint160(uint256(logs[i].topics[2])));
            int256 v = int256(abi.decode(logs[i].data, (uint256)));
            if (from != address(0)) replay[address(t_)][from] -= v;
            if (to != address(0)) replay[address(t_)][to] += v;
        }
        assertEq(uaTransfers, wantUATransfers, "UATransfer iff a side is derived");
        assertEq(transfers, wantTransfers, "Transfer iff a native balance changes");
    }
}

/// T-V3-2, on the NONE clone and on the 1:1 UNDERLYING clones (`wrp`; UA-5a: the ledger-leg `wrpL`, the native-leg
/// `wrpN`): `totalSupply == Σ balanceOf(native incl. UA_POOL)`, `balanceOf(UA_POOL) == Σ balanceOfUA`, replaying
/// `Transfer` logs equals `balanceOf` for every native holder (`UA_POOL` included), replaying `UATransfer` logs equals
/// `balanceOfUA` for every tracked UA; `UATransfer` iff a side is derived (checked per call by the handler); each
/// wrapper backed 1:1 by its leg; `wrpL` solvent (CTR-TOK-05) over `unwrapToUA`'s pay-outs into `tok`'s UA ledger.
contract UALedgerInvariantTest is UALedgerBase {
    UALedgerHandler internal h;

    function setUp() public override {
        super.setUp();
        bytes32[2] memory u = [uaP, uaB];
        bytes[2] memory k = [_key(UAKinds.P256), _key(UAKinds.BIP340)];
        uint16[2] memory kd = [UAKinds.P256, UAKinds.BIP340];
        h = new UALedgerHandler(tok, wrp, wrpL, wrpN, und, lreg, address(this), u, k, kd); // this fixture is tok's minter
        targetContract(address(h));
    }

    function _check(MetaTokenBase t) internal view {
        address[8] memory a = h.natives();
        uint256 sum;
        for (uint256 i; i < a.length; ++i) {
            sum += t.balanceOf(a[i]);
            assertEq(h.replay(address(t), a[i]), int256(t.balanceOf(a[i])), "Transfer replay");
        }
        assertEq(t.totalSupply(), sum, "supply");
        uint256 uaSum;
        for (uint256 i; i < 2; ++i) {
            bytes32 ua = h.uas(i);
            uaSum += t.balanceOfUA(ua);
            assertEq(h.uaReplay(address(t), ua), int256(t.balanceOfUA(ua)), "UATransfer replay");
        }
        assertEq(t.balanceOf(POOL), uaSum, "pool");
    }

    function invariant_T_V3_2_none() public view {
        _check(tok);
    }

    function invariant_T_V3_2_underlying() public view {
        _check(wrp);
        assertEq(wrp.totalSupply(), und.balanceOf(address(wrp)), "1:1 backing");
    }

    function invariant_T_V3_2_ledgerLeg() public view {
        _check(wrpL);
        assertEq(wrpL.totalSupply(), tok.balanceOf(address(wrpL)), "1:1 backing");
    }

    function invariant_T_V3_2_nativeLeg() public view {
        _check(wrpN);
        assertEq(wrpN.totalSupply(), address(wrpN).balance, "1:1 backing");
    }

    /// CTR-TOK-05 on the ledger leg: the leg balance covers the reserve, the reserve covers the supply.
    function invariant_ledgerLegSolvent() public view {
        (,, uint256 reserve,,) = wrpL.legOf(address(tok));
        assertGe(tok.balanceOf(address(wrpL)), reserve, "leg balance >= reserve");
        assertGe(wrpL.collateralValue(), wrpL.totalSupply(), "collateral >= supply");
    }
}
