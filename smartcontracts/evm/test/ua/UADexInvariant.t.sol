// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {NoUnderlyingToken} from "../../src/metatx/NoUnderlyingToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UADexBase, UARouter} from "./UADex.t.sol";

/// Random settlements between four parties — two natives (alice, bob) and two derived UAs (`p256`, `bip340`) — on the
/// listed pair A/B: either side sells, a native signs shape 0 or shape 1 (a padded id), a UA always shape 1, any
/// destination its shape allows, random fee rates, the taker Path A or Path B (refund); and the exchange path with a
/// surplus. Per call the handler checks every party's, the relayer's and the treasury's balance delta in both tokens
/// against the figures of the match (gross, ⌈fee⌉ split 20 / 80, the refund).
contract UADexHandler is Test {
    address internal constant RELAYER = address(0xBEEF);
    address internal constant TREASURY = address(0x7EA5);
    uint256 internal constant PPM = 1_000_000;

    NoUnderlyingToken internal immutable A;
    NoUnderlyingToken internal immutable B;
    SCaaSDex internal immutable dex;
    UARegistry internal immutable reg;
    UARouter internal immutable router;
    uint256[2] internal pks = [uint256(0xA11CE), 0xB0B];
    bytes32[4] internal ids;
    bytes[2] internal keys;
    uint16[2] internal kinds;
    uint256 internal nonce;
    uint256 public settled;
    uint256 public exchanged;

    constructor(NoUnderlyingToken a, NoUnderlyingToken b, SCaaSDex d, UARegistry r, UARouter ro, bytes32[2] memory uas,
        bytes[2] memory keys_, uint16[2] memory kinds_)
    {
        (A, B, dex, reg, router) = (a, b, d, r, ro);
        ids = [bytes32(uint256(uint160(vm.addr(pks[0])))), bytes32(uint256(uint160(vm.addr(pks[1])))), uas[0], uas[1]];
        (keys, kinds) = (keys_, kinds_);
    }

    /// Every native holder of A and B.
    function natives() external view returns (address[7] memory) {
        return [vm.addr(pks[0]), vm.addr(pks[1]), RELAYER, TREASURY, MetaTxLib.UA_POOL, address(router), address(dex)];
    }

    function uaIds() external view returns (bytes32, bytes32) {
        return (ids[2], ids[3]);
    }

    // ----- ops -----

    struct Plan {
        uint256 ti;
        uint256 mi;
        uint256 amt;
        uint256 tAmount;
        uint256 tf;
        uint256 mf;
        bool t1;
        bool m1;
        bytes32 tDest;
        bytes32 mDest;
    }

    function settle(uint256 ti, uint256 mi, bool aSells, uint256 amt, uint256 extra, uint256 fees, uint256 dest,
        uint256 shapes) external
    {
        Plan memory p;
        (p.ti, p.mi) = (ti % 4, mi % 4);
        if (p.ti == p.mi) return;
        (NoUnderlyingToken X, NoUnderlyingToken Y) = aSells ? (A, B) : (B, A); // the taker sells X, the maker Y
        p.amt = bound(amt, 2, 5_000);
        bool escrow = shapes & 4 != 0;
        p.tAmount = escrow ? p.amt + bound(extra, 0, p.amt) : p.amt;
        if (X.balanceOfUA(ids[p.ti]) < p.tAmount || Y.balanceOfUA(ids[p.mi]) < p.amt) return;
        (p.tf, p.mf) = (fees % 10_001, (fees / 10_001) % 10_001);
        p.t1 = p.ti >= 2 || shapes & 1 != 0;
        p.m1 = p.mi >= 2 || shapes & 2 != 0;
        p.tDest = _dest(p.t1, dest % 5);
        p.mDest = _dest(p.m1, (dest / 5) % 5);
        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](1);
        ss[0].ref = bytes32(++nonce);
        ss[0].taker = _leg(X, _order(Y, ids[p.ti], p.tDest, p.tAmount, p.tf, escrow ? 3 : 0), p.t1, p.amt);
        ss[0].makers = new ISCaaSDex.Leg[](1);
        ss[0].makers[0] = _leg(Y, _order(X, ids[p.mi], p.mDest, p.amt, p.mf, 0), p.m1, p.amt);
        int256[6][2] memory before = _snap();
        vm.prank(RELAYER);
        assertTrue(dex.mtxSettle(ss)[0], "settles");
        int256[6][2] memory want = _expect(before, aSells, p);
        _checkDeltas(want);
        ++settled;
    }

    /// The exchange path: party `pi` (shape 1 for a UA, shape 0 or 1 for a native) sells `amt` A for a floor of `amt` B;
    /// the router pays `amt + surplus` B; the party (or its destination) gets the floor less the fee plus the surplus.
    function exchange(uint256 pi, uint256 amt, uint256 surplus, uint256 fee, bool shape1) external {
        pi = pi % 4;
        amt = bound(amt, 1, 5_000);
        surplus = bound(surplus, 0, 100);
        if (A.balanceOfUA(ids[pi]) < amt || B.balanceOf(address(router)) < amt + surplus) return;
        fee = fee % 10_001;
        bool ua = pi >= 2 || shape1;
        ISCaaSDex.Leg memory l = _leg(A, _order(B, ids[pi], 0, amt, fee, 0), ua, amt);
        ISCaaSDex.ExchangePlan memory p;
        p.ref = bytes32(++nonce);
        p.legs = new ISCaaSDex.ExchangeLeg[](1);
        p.legs[0] = ISCaaSDex.ExchangeLeg(address(A), l.shape, l.order, l.sig, amt, amt);
        ISCaaSDex.Interaction[] memory xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(address(A), abi.encodeCall(IERC20.approve, (address(router), amt)));
        xs[1] = ISCaaSDex.Interaction(address(router),
            abi.encodeCall(UARouter.swap, (address(A), address(B), amt, amt + surplus, address(dex))));
        int256[6][2] memory w = _snap();
        vm.prank(RELAYER);
        dex.mtxExchange(p, xs);
        uint256 f = Math.mulDiv(amt, fee, PPM, Math.Rounding.Ceil);
        w[0][pi] -= int256(amt);
        w[1][pi] += int256(amt - f + surplus);
        w[1][4] += int256(f * 200_000 / PPM);
        w[1][5] += int256(f - f * 200_000 / PPM);
        _checkDeltas(w);
        ++exchanged;
    }

    // ----- helpers -----

    /// 0 (= from), or a party id the shape can name (shape 0: a native address only).
    function _dest(bool shape1, uint256 k) internal view returns (bytes32) {
        if (k == 4) return 0;
        if (!shape1 && k >= 2) return 0;
        return ids[k];
    }

    /// An order at 1:1 (`receiveAmount = amount`) on a fresh nonce.
    function _order(NoUnderlyingToken recv, bytes32 from, bytes32 dest, uint256 amount, uint256 fee, uint8 flags)
        internal returns (ITradeToken.UATradeOrder memory o)
    {
        o = ITradeToken.UATradeOrder({
            from: from, receiveToken: address(recv), amount: amount, receiveAmount: amount, minFill: 0, fee: fee,
            relayer: RELAYER, dex: address(dex), destination: dest, flags: flags, batch: 1, nonce: ++nonce,
            validUntil: block.timestamp + 300
        });
    }

    /// Shape 1 as is; shape 0 the same fields as a `TradeOrder` (a native `from` and `destination`).
    function _leg(NoUnderlyingToken sell, ITradeToken.UATradeOrder memory o, bool shape1, uint256 fill)
        internal view returns (ISCaaSDex.Leg memory)
    {
        if (shape1) return ISCaaSDex.Leg(address(sell), 1, abi.encode(o), _sign(o.from, sell.uaTradeOrderDigest(o)), fill);
        // the same 13 words: a native id is its address zero-padded
        ITradeToken.TradeOrder memory t = abi.decode(abi.encode(o), (ITradeToken.TradeOrder));
        return ISCaaSDex.Leg(address(sell), 0, abi.encode(t), _sign(o.from, sell.tradeOrderDigest(t)), fill);
    }

    /// A native id signs `digest` itself; a UA `ua_msg(kind, trade, digest)` (the stand-in verifier).
    function _sign(bytes32 from, bytes32 digest) internal view returns (bytes memory) {
        for (uint256 i; i < 2; ++i) {
            if (from == ids[i]) {
                (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[i], digest);
                return abi.encodePacked(r, s, v);
            }
        }
        uint256 j = from == ids[2] ? 0 : 1;
        bytes32 message = reg.uaMessage(kinds[j], UAKinds.PURPOSE_TRADE, digest);
        return abi.encode(keys[j], abi.encodePacked(keccak256(abi.encode(keys[j], message))));
    }

    /// Per token (0 = A, 1 = B): the four parties by id, then the relayer and the treasury.
    function _snap() internal view returns (int256[6][2] memory s) {
        NoUnderlyingToken[2] memory t = [A, B];
        for (uint256 k; k < 2; ++k) {
            for (uint256 i; i < 4; ++i) s[k][i] = int256(t[k].balanceOfUA(ids[i]));
            s[k][4] = int256(t[k].balanceOf(RELAYER));
            s[k][5] = int256(t[k].balanceOf(TREASURY));
        }
    }

    function _idx(bytes32 dest, uint256 self) internal view returns (uint256) {
        if (dest == 0) return self;
        for (uint256 i; i < 4; ++i) if (ids[i] == dest) return i;
        revert("dest");
    }

    function _expect(int256[6][2] memory w, bool aSells, Plan memory p) internal view returns (int256[6][2] memory) {
        (uint256 x, uint256 y) = aSells ? (0, 1) : (1, 0); // token indexes: the taker sells x, the maker y
        uint256 tFee = Math.mulDiv(p.amt, p.tf, PPM, Math.Rounding.Ceil); // the taker receives amt of Y
        uint256 mFee = Math.mulDiv(p.amt, p.mf, PPM, Math.Rounding.Ceil); // the maker receives amt of X
        w[x][p.ti] -= int256(p.amt); // Path B: pulled tAmount, refunded tAmount - amt
        w[y][p.mi] -= int256(p.amt);
        w[y][_idx(p.tDest, p.ti)] += int256(p.amt - tFee);
        w[x][_idx(p.mDest, p.mi)] += int256(p.amt - mFee);
        w[y][4] += int256(tFee * 200_000 / PPM);
        w[y][5] += int256(tFee - tFee * 200_000 / PPM);
        w[x][4] += int256(mFee * 200_000 / PPM);
        w[x][5] += int256(mFee - mFee * 200_000 / PPM);
        return w;
    }

    function _checkDeltas(int256[6][2] memory want) internal view {
        int256[6][2] memory got = _snap();
        for (uint256 k; k < 2; ++k) for (uint256 i; i < 6; ++i) assertEq(got[k][i], want[k][i], "delta");
    }
}

/// DEX conservation with UA handlers (CTR-DEX-16 step 5 on CTR-DEX-26 legs): between calls the DEX holds nothing of
/// either token; per token `balanceOf(UA_POOL) == Σ balanceOfUA` (the payouts and refunds by `transferToUA` keep the
/// UA ledger whole) and `totalSupply == Σ native holders`.
contract UADexInvariantTest is UADexBase {
    UADexHandler internal h;

    function setUp() public override {
        super.setUp();
        UARouter router = new UARouter();
        vm.startPrank(alice);
        A.transfer(bob, 300_000);
        A.transferToUA(uaB, 100_000);
        A.transfer(address(router), 100_000);
        vm.stopPrank();
        vm.startPrank(bob);
        B.transfer(alice, 300_000);
        B.transferToUA(uaP, 100_000);
        B.transfer(address(router), 100_000);
        vm.stopPrank();
        h = new UADexHandler(A, B, dex, lreg, router, [uaP, uaB], [_key(UAKinds.P256), _key(UAKinds.BIP340)],
            [UAKinds.P256, UAKinds.BIP340]);
        targetContract(address(h));
    }

    function _check(NoUnderlyingToken t) internal view {
        address[7] memory a = h.natives();
        uint256 sum;
        for (uint256 i; i < a.length; ++i) sum += t.balanceOf(a[i]);
        assertEq(t.totalSupply(), sum, "supply");
        (bytes32 p, bytes32 b) = h.uaIds();
        assertEq(t.balanceOf(POOL), t.balanceOfUA(p) + t.balanceOfUA(b), "pool");
        assertEq(t.balanceOf(address(dex)), 0, "the DEX holds nothing");
    }

    function invariant_conservation_A() public view {
        _check(A);
    }

    function invariant_conservation_B() public view {
        _check(B);
    }

    function afterInvariant() public {
        emit log_named_uint("settlements", h.settled());
        emit log_named_uint("exchanges", h.exchanged());
    }
}
