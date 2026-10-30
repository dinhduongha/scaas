// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {UADexBase} from "../ua/UADex.t.sol";
import {MockRouter, MockExecutor} from "./DexExchange.t.sol";

/// Builds only valid calls (`fail_on_revert`) of `mtxSettle`, `mtxExchange`, `mtxHybrid` / `mtxHybridVia` and
/// `mtxExchangeBatch` over the listed pairs A/B (SCaaS, UA ledgers on) and A/usdc (outside, natives only). Five
/// parties: alice, bob, dave (native; shape 0, or shape 1 as a padded id on A/B) and the derived UAs uaP, uaB (shape 1).
/// Each order is Path A (IOC or resting) or Path B (`ESCROW`, not on usdc), random fee, relayer binding and
/// `LISTED_POOLS` (every target is listed); each fill is one its signer allows (≥ `minFill`, or the remainder). A leg is
/// a new order or a resting one from the pool, so orders fill over many calls — a hybrid taker's refunded leftover too
/// (DX7 `restorePulled`). Every party appears at most once per call (destination = `from`), so the handler measures each
/// order's sold and received amounts from balances; it keeps the pulled amount each order must show (ghost) and each
/// hybrid maker's exact due `⌈fill · receiveAmount / amount⌉` less its fee.
contract DexHandler is Test {
    address internal constant RELAYER = address(0xBEEF);
    uint256 internal constant PPM = 1_000_000;
    uint8 internal constant IOC = 1;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant LISTED_POOLS = 4;
    uint256 internal constant MAX = 5_000; // per order amount and receive amount
    uint8 internal constant NP = 5; // parties

    SCaaSDex internal immutable dex;
    UARegistry internal immutable reg;
    MockRouter internal immutable router;
    MockExecutor internal immutable exec;
    address internal immutable A;
    address internal immutable B;
    address internal immutable usdc;
    uint256[3] internal pks;
    bytes32[5] internal ids; // alice, bob, dave (zero-padded), uaP, uaB
    bytes[2] internal keys;
    uint16[2] internal kinds;
    uint256 internal nonce;

    struct Ord {
        uint8 party;
        uint8 shape;
        address sell;
        bytes order; // abi.encode of the shape's struct
        bytes sig;
        bytes32 h;
        ITradeToken.UATradeOrder o;
        uint256 ghostPulled; // what `pulled(h)` must read
        bool restored; // a hybrid leftover was restored to it
    }

    /// One order in the call under way: its planned fill, the hybrid leftover refunded to it, balances before.
    struct Use {
        uint256 k;
        uint256 fill;
        uint256 leftover;
        bool hybridMaker;
        uint256 sell0;
        uint256 recv0;
    }

    /// One settled fill as measured: `sold` (sell-token balance drop), `net` (receive-token balance rise).
    struct Fill {
        uint256 k;
        uint256 sold;
        uint256 net;
    }

    struct Pick {
        uint256 k;
        uint256 fill;
        uint8 p;
    }

    Ord[] internal ords;
    Use[] internal uses;
    Fill[] internal fills;
    uint256[5] public makerWant;
    uint256[5] public makerGot;

    // call counts (settled calls only)
    uint256 public settled;
    uint256 public exchanged;
    uint256 public hybridsA;
    uint256 public hybridsB;
    uint256 public batches;
    uint256 public batchPlansOk;
    uint256 public batchPlansFailed;
    uint256 public refunds; // hybrids with a leftover refunded
    uint256 public restores; // of which restored (not IOC)
    uint256 public refills; // fills of an order already partly pulled
    uint256 public refillsAfterRestore;
    uint256 public skipped;

    constructor(SCaaSDex d, UARegistry r, MockRouter ro, MockExecutor ex, address[3] memory toks, uint256[3] memory pks_,
        bytes32[2] memory uas, bytes[2] memory keys_, uint16[2] memory kinds_)
    {
        (dex, reg, router, exec) = (d, r, ro, ex);
        (A, B, usdc) = (toks[0], toks[1], toks[2]);
        pks = pks_;
        for (uint256 i; i < 3; ++i) ids[i] = bytes32(uint256(uint160(vm.addr(pks_[i]))));
        (ids[3], ids[4]) = (uas[0], uas[1]);
        (keys, kinds) = (keys_, kinds_);
    }

    // ------------------------------------------------------------------ handlers

    /// One settlement: a new taker against 1..2 makers (new or resting) at the makers' prices.
    function settle(uint256 seed) external {
        (address x, address y) = _pair(seed);
        (bool okT, uint8 tp) = _party(_r(seed, 1), x, y, 0);
        if (!okT) return _skip();
        Ms memory m = _makers(seed, y, x, uint8(1 << tp), 1 + _r(seed, 2) % 2);
        if (!m.ok) return _skip();
        uint256 tk = _taker(tp, x, y, m.sell, m.fill, m.sell, _r(seed, 3));
        if (tk == type(uint256).max) return _skip();
        ISCaaSDex.Settlement[] memory ss = new ISCaaSDex.Settlement[](1);
        (ss[0].ref, ss[0].taker, ss[0].makers) = (bytes32(seed), _leg(tk, m.sell), m.legs);
        _use(tk, m.sell, 0, false);
        for (uint256 j; j < m.picks.length; ++j) _use(m.picks[j].k, m.picks[j].fill, 0, false);
        vm.prank(RELAYER);
        assertTrue(dex.mtxSettle(ss)[0], "settles");
        _commit();
        ++settled;
    }

    /// The makers of a settlement or a hybrid.
    struct Ms {
        bool ok;
        uint8 used;
        uint256 sell; // Σ maker receive: what the taker sells them
        uint256 fill; // Σ maker fill: what the taker receives from them
        ISCaaSDex.Leg[] legs;
        Pick[] picks;
    }

    /// `n` makers selling `sell` for `recv`, each of a party not yet used (new or resting orders, as `_order`).
    function _makers(uint256 seed, address sell, address recv, uint8 used, uint256 n)
        internal returns (Ms memory m)
    {
        (m.used, m.legs, m.picks) = (used, new ISCaaSDex.Leg[](n), new Pick[](n));
        for (uint256 j; j < n; ++j) {
            (bool ok, Pick memory q) = _order(_r(seed, 10 + j), sell, recv, m.used);
            if (!ok) return m;
            m.used |= uint8(1 << q.p);
            m.picks[j] = q;
            m.sell += _ceil(q.fill, ords[q.k].o.receiveAmount, ords[q.k].o.amount);
            m.fill += q.fill;
            m.legs[j] = _leg(q.k, q.fill);
        }
        m.ok = true;
    }

    /// One exchange plan: 1..2 legs (new or resting) selling x for y, one router swap of their sum (approved with
    /// room to spare: the DEX must reset it), the floors plus a surplus back.
    function exchange(uint256 seed) external {
        (address x, address y) = _pair(seed);
        uint256 n = 1 + _r(seed, 1) % 2;
        ISCaaSDex.ExchangePlan memory p;
        p.ref = bytes32(seed);
        p.legs = new ISCaaSDex.ExchangeLeg[](n);
        Pick[] memory qs = new Pick[](n);
        uint8 used;
        uint256 sold;
        uint256 floors;
        for (uint256 j; j < n; ++j) {
            (bool ok, Pick memory q, uint256 floor) = _xleg(_r(seed, 10 + j), x, y, used);
            if (!ok) return _skip();
            used |= uint8(1 << q.p);
            qs[j] = q;
            p.legs[j] = _xl(q, floor);
            sold += q.fill;
            floors += floor;
        }
        uint256 out = floors + _pick(_r(seed, 2), 0, 100);
        if (IERC20(y).balanceOf(address(router)) < out) return _skip();
        ISCaaSDex.Interaction[] memory xs = _swap(x, y, sold + _pick(_r(seed, 3), 0, 50), sold, out);
        for (uint256 j; j < n; ++j) _use(qs[j].k, qs[j].fill, 0, false);
        vm.prank(RELAYER);
        dex.mtxExchange(p, xs);
        _commit();
        ++exchanged;
    }

    struct Hy {
        address x;
        address y;
        uint256 outsideSell;
        uint256 leftover;
        uint256 outsideFloor;
        uint256 surplus;
        uint256 tk;
        bool via;
    }

    /// One hybrid: a new taker against 0..2 makers (new or resting) at their price, `outsideSell` routed (path (a):
    /// the router; path (b): the executor), the route spending all of it or leaving a leftover (DX7 refund).
    function hybrid(uint256 seed) external {
        Hy memory c;
        (c.x, c.y) = _pair(seed);
        (bool okT, uint8 tp) = _party(_r(seed, 1), c.x, c.y, 0);
        if (!okT) return _skip();
        Ms memory m = _makers(seed, c.y, c.x, uint8(1 << tp), _r(seed, 2) % 3);
        if (!m.ok) return _skip();
        c.outsideSell = _pick(_r(seed, 3), m.legs.length == 0 ? 1 : 0, MAX);
        uint256 fill = m.sell + c.outsideSell;
        if (c.outsideSell != 0) {
            c.leftover = _pick(_r(seed, 4), 0, Math.min(c.outsideSell, fill - 1));
            // the taker must receive something: any receiveAmount > 0 refuses a floor of 0
            c.outsideFloor = _pick(_r(seed, 5), m.fill == 0 ? 1 : 0, 2 * c.outsideSell);
            c.surplus = _pick(_r(seed, 6), 0, 100);
        }
        c.via = _r(seed, 7) & 1 == 1;
        c.tk = _taker(tp, c.x, c.y, fill, m.fill + c.outsideFloor, fill - c.leftover, _r(seed, 8));
        if (c.tk == type(uint256).max) return _skip();
        if (IERC20(c.y).balanceOf(c.via ? address(exec) : address(router)) < c.outsideFloor + c.surplus) return _skip();
        ISCaaSDex.HybridPlan memory p;
        (p.ref, p.taker, p.makers) = (bytes32(seed), _leg(c.tk, fill), m.legs);
        (p.outsideSell, p.outsideFloor) = (c.outsideSell, c.outsideFloor);
        _use(c.tk, fill, c.leftover, false);
        for (uint256 j; j < m.picks.length; ++j) _use(m.picks[j].k, m.picks[j].fill, 0, true);
        _hybridCall(p, c);
        _commit();
        if (c.via) ++hybridsB;
        else ++hybridsA;
        if (c.leftover != 0) {
            ++refunds;
            if (ords[c.tk].o.flags & IOC == 0) ++restores;
        }
    }

    function _hybridCall(ISCaaSDex.HybridPlan memory p, Hy memory c) internal {
        if (c.via) {
            // the executor sends the leftover of x back, then pays the floor plus the surplus of y
            if (c.leftover != 0) exec.setCall(c.x, abi.encodeCall(IERC20.transfer, (address(dex), c.leftover)));
            else exec.setCall(address(0), "");
            vm.prank(RELAYER);
            dex.mtxHybridVia(p, address(exec), abi.encode(int256(c.surplus)));
        } else {
            ISCaaSDex.Interaction[] memory xs = c.outsideSell == 0 ? new ISCaaSDex.Interaction[](0)
                : _swap(c.x, c.y, c.outsideSell, c.outsideSell - c.leftover, c.outsideFloor + c.surplus);
            vm.prank(RELAYER);
            dex.mtxHybrid(p, xs);
        }
    }

    /// 1..3 single-leg plans, distinct parties; with two or more, one may be paid short (`InsufficientOutput`) and must
    /// fail alone (`ExchangeFailed`), leaving its order untouched.
    function batch(uint256 seed) external {
        uint256 m = 1 + seed % 3;
        uint256 bad = m > 1 && (seed >> 2) % 3 == 0 ? (seed >> 4) % m : type(uint256).max;
        ISCaaSDex.ExchangePlan[] memory ps = new ISCaaSDex.ExchangePlan[](m);
        ISCaaSDex.Interaction[][] memory xs = new ISCaaSDex.Interaction[][](m);
        uint256[3] memory spend; // router outflow per token (A, B, usdc)
        uint8 used;
        for (uint256 i; i < m; ++i) {
            uint256 r = _r(seed, 10 + i);
            (address x, address y) = _pair(r);
            (bool ok, Pick memory q, uint256 floor) = _xleg(_r(r, 1), x, y, used);
            if (!ok) return _skip();
            used |= uint8(1 << q.p);
            uint256 out = i == bad ? floor - 1 : floor + _pick(_r(r, 2), 0, 100);
            spend[_ti(y)] += out;
            if (IERC20(y).balanceOf(address(router)) < spend[_ti(y)]) return _skip();
            ps[i].ref = bytes32(r);
            ps[i].legs = new ISCaaSDex.ExchangeLeg[](1);
            ps[i].legs[0] = _xl(q, floor);
            xs[i] = _swap(x, y, q.fill + _pick(_r(r, 3), 0, 50), q.fill, out);
            if (i != bad) _use(q.k, q.fill, 0, false);
        }
        vm.prank(RELAYER);
        bool[] memory ok_ = dex.mtxExchangeBatch(ps, xs);
        for (uint256 i; i < m; ++i) assertEq(ok_[i], i != bad, "plan outcome");
        _commit();
        ++batches;
        batchPlansOk += bad == type(uint256).max ? m : m - 1;
        if (bad != type(uint256).max) ++batchPlansFailed;
    }

    // ------------------------------------------------------------------ views for the invariants

    function ordCount() external view returns (uint256) {
        return ords.length;
    }

    /// The order's sell token, hash, amount, ghost pulled, and whether the DEX keeps its state (an outside token).
    function ordAt(uint256 k) external view returns (address, bytes32, uint256, uint256, bool) {
        Ord storage o = ords[k];
        return (o.sell, o.h, o.o.amount, o.ghostPulled, o.sell == usdc);
    }

    function fillCount() external view returns (uint256) {
        return fills.length;
    }

    /// A measured fill with its order's signed limit and fee rate.
    function fillAt(uint256 i) external view returns (uint256 sold, uint256 net, uint256 amount, uint256 receiveAmount,
        uint256 fee)
    {
        Fill storage f = fills[i];
        ITradeToken.UATradeOrder storage o = ords[f.k].o;
        return (f.sold, f.net, o.amount, o.receiveAmount, o.fee);
    }

    // ------------------------------------------------------------------ orders

    /// One order selling `sell` for `recv` of a party not in `used`: a resting order of the pool (`r` odd) or a new one,
    /// with a fill its signer allows; `ok` false when none fits.
    function _order(uint256 r, address sell, address recv, uint8 used) internal returns (bool, Pick memory q) {
        uint256 n = ords.length;
        if (r & 1 == 1 && n != 0) {
            uint256 s = (r >> 1) % n;
            for (uint256 i; i < n; ++i) {
                uint256 k = (s + i) % n;
                Ord storage o = ords[k];
                if (o.sell != sell || o.o.receiveToken != recv || o.o.flags & IOC != 0 || o.ghostPulled >= o.o.amount
                    || (used >> o.party) & 1 != 0) continue;
                uint256 f = _fill(_r(r, 9), o.o.amount - o.ghostPulled, o.o.minFill);
                if (_bal(o.party, sell) < f) continue;
                return (true, Pick(k, f, o.party));
            }
        }
        (bool okp, uint8 p) = _party(_r(r, 1), sell, recv, used);
        if (!okp) return (false, q);
        q = _fresh(r, p, sell, recv);
        return (q.fill != 0, q);
    }

    /// A new order of party `p` and a fill its signer allows; fill 0 when its balance is short.
    function _fresh(uint256 r, uint8 p, address sell, address recv) internal returns (Pick memory q) {
        ITradeToken.UATradeOrder memory o = _o(recv, 1 + _r(r, 2) % MAX, 1 + _r(r, 6) % MAX, 0, _flags(_r(r, 4), sell));
        o.minFill = _pick(_r(r, 3), 0, o.amount);
        q.p = p;
        q.fill = _fill(_r(r, 5), o.amount, o.minFill);
        if (_bal(p, sell) < (o.flags & ESCROW != 0 ? o.amount : q.fill)) {
            q.fill = 0;
            return q;
        }
        q.k = _new(p, sell, o, _r(r, 7));
    }

    /// An exchange leg: an order as `_order` and a floor at or a little above its signed limit.
    function _xleg(uint256 r, address sell, address recv, uint8 used)
        internal returns (bool ok, Pick memory q, uint256 floor)
    {
        (ok, q) = _order(r, sell, recv, used);
        if (ok) floor = _ceil(q.fill, ords[q.k].o.receiveAmount, ords[q.k].o.amount) + _pick(_r(r, 8), 0, 3);
    }

    /// A new taker of party `p` selling `fill` of x for at least `recv` of y (its price fitted below that), `minFill` at
    /// most `soldMax` (its sold part after any leftover); max when its balance is short.
    function _taker(uint8 p, address x, address y, uint256 fill, uint256 recv, uint256 soldMax, uint256 r)
        internal returns (uint256)
    {
        uint256 amount = fill + _pick(_r(r, 1), 0, fill);
        uint8 flags = _flags(_r(r, 2), x);
        if (_bal(p, x) < (flags & ESCROW != 0 ? amount : fill)) return type(uint256).max;
        uint256 rAmt = _pick(_r(r, 3), 1, recv * amount / fill); // fill · rAmt <= recv · amount
        return _new(p, x, _o(y, amount, rAmt, _pick(_r(r, 4), 0, soldMax), flags), _r(r, 5));
    }

    function _o(address recv, uint256 amount, uint256 rAmt, uint256 minFill, uint8 flags)
        internal pure returns (ITradeToken.UATradeOrder memory o)
    {
        (o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.flags) = (recv, amount, rAmt, minFill, flags);
    }

    /// Signs and stores `o` for party `p` selling `sell`: shape 1 for a UA, 0 or 1 (padded) for a native on A/B, 0 on
    /// usdc (a `DexOrder`).
    function _new(uint8 p, address sell, ITradeToken.UATradeOrder memory o, uint256 r) internal returns (uint256 k) {
        o.from = ids[p];
        o.fee = r % 10_001;
        o.relayer = (r >> 16) & 1 == 0 ? address(0) : RELAYER;
        o.dex = address(dex);
        o.batch = 1;
        o.nonce = ++nonce;
        o.validUntil = block.timestamp + 1 days;
        k = ords.length;
        Ord storage s = ords.push();
        (s.party, s.sell, s.o) = (p, sell, o);
        if (p >= 3 || (sell != usdc && (r >> 17) & 1 == 1)) {
            s.shape = 1;
            s.h = ITradeToken(sell).uaTradeOrderDigest(o);
            s.order = abi.encode(o);
        } else {
            ITradeToken.TradeOrder memory t = abi.decode(abi.encode(o), (ITradeToken.TradeOrder));
            s.h = sell == usdc ? dex.dexOrderDigest(sell, t) : ITradeToken(sell).tradeOrderDigest(t);
            s.order = abi.encode(t);
        }
        s.sig = _sign(p, s.h);
    }

    function _leg(uint256 k, uint256 fill) internal view returns (ISCaaSDex.Leg memory) {
        Ord storage o = ords[k];
        return ISCaaSDex.Leg(o.sell, o.shape, o.order, o.sig, fill);
    }

    function _xl(Pick memory q, uint256 floor) internal view returns (ISCaaSDex.ExchangeLeg memory) {
        Ord storage o = ords[q.k];
        return ISCaaSDex.ExchangeLeg(o.sell, o.shape, o.order, o.sig, q.fill, floor);
    }

    /// A native signs `digest` itself; a UA `ua_msg(kind, trade, digest)` (the stand-in verifier).
    function _sign(uint8 p, bytes32 digest) internal view returns (bytes memory) {
        if (p < 3) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pks[p], digest);
            return abi.encodePacked(r, s, v);
        }
        uint256 j = p - 3;
        bytes32 message = reg.uaMessage(kinds[j], UAKinds.PURPOSE_TRADE, digest);
        return abi.encode(keys[j], abi.encodePacked(keccak256(abi.encode(keys[j], message))));
    }

    // ------------------------------------------------------------------ accounting

    function _use(uint256 k, uint256 fill, uint256 leftover, bool hybridMaker) internal {
        Ord storage o = ords[k];
        uses.push(Use(k, fill, leftover, hybridMaker, _bal(o.party, o.sell), _bal(o.party, o.o.receiveToken)));
    }

    /// After a call: each used order's measured sold / received, its ghost pulled (IOC and Path B: closed at `amount`;
    /// else + the fill less a restored leftover), a hybrid maker's due against what it got.
    function _commit() internal {
        for (uint256 i; i < uses.length; ++i) {
            Use memory u = uses[i];
            Ord storage o = ords[u.k];
            uint256 s1 = _bal(o.party, o.sell);
            uint256 r1 = _bal(o.party, o.o.receiveToken);
            assertGe(u.sell0, s1, "sell balance rose");
            assertGe(r1, u.recv0, "receive balance fell");
            uint256 sold = u.sell0 - s1;
            uint256 net = r1 - u.recv0;
            assertEq(sold, u.fill - u.leftover, "sold = fill - refunded leftover");
            fills.push(Fill(u.k, sold, net));
            if (o.ghostPulled != 0) {
                ++refills;
                if (o.restored) ++refillsAfterRestore;
            }
            if (o.o.flags & IOC != 0) {
                o.ghostPulled = o.o.amount;
            } else {
                o.ghostPulled += u.fill - u.leftover;
                if (u.leftover != 0) o.restored = true;
            }
            if (u.hybridMaker) {
                makerWant[o.party] += _net(_ceil(u.fill, o.o.receiveAmount, o.o.amount), o.o.fee);
                makerGot[o.party] += net;
            }
        }
        delete uses;
    }

    // ------------------------------------------------------------------ helpers

    /// [x, y]: A/B or A/usdc, either side selling.
    function _pair(uint256 seed) internal view returns (address x, address y) {
        (x, y) = (A, seed & 1 == 0 ? B : usdc);
        if ((seed >> 1) & 1 == 1) (x, y) = (y, x);
    }

    /// A party not in `used` that can hold both tokens (a UA: A and B only).
    function _party(uint256 r, address sell, address recv, uint8 used) internal view returns (bool, uint8) {
        for (uint256 i; i < NP; ++i) {
            uint8 p = uint8((r + i) % NP);
            if ((used >> p) & 1 != 0) continue;
            if (p >= 3 && (sell == usdc || recv == usdc)) continue;
            return (true, p);
        }
        return (false, 0);
    }

    /// IOC, `ESCROW | IOC` (Path B, not on usdc) and `LISTED_POOLS` at random.
    function _flags(uint256 r, address sell) internal view returns (uint8 f) {
        if (r & 1 == 1) f = IOC;
        if (sell != usdc && (r >> 1) % 4 == 0) f = IOC | ESCROW;
        if ((r >> 3) & 1 == 1) f |= LISTED_POOLS;
    }

    /// A fill of `rem` its signer allows: at least `minFill`, or the whole remainder.
    function _fill(uint256 r, uint256 rem, uint256 minFill) internal pure returns (uint256) {
        if (minFill >= rem) return rem;
        return _pick(r, Math.max(minFill, 1), rem);
    }

    /// `[approve(router, approved)` on x, `router.swap(x, y, amountIn, amountOut, dex)]`.
    function _swap(address x, address y, uint256 approved, uint256 amountIn, uint256 amountOut)
        internal view returns (ISCaaSDex.Interaction[] memory xs)
    {
        xs = new ISCaaSDex.Interaction[](2);
        xs[0] = ISCaaSDex.Interaction(x, abi.encodeCall(IERC20.approve, (address(router), approved)));
        xs[1] = ISCaaSDex.Interaction(address(router),
            abi.encodeCall(MockRouter.swap, (x, y, amountIn, amountOut, address(dex))));
    }

    function _bal(uint8 p, address t) internal view returns (uint256) {
        if (p < 3) return IERC20(t).balanceOf(address(uint160(uint256(ids[p]))));
        return NormalToken(t).balanceOfUA(ids[p]);
    }

    function _ti(address t) internal view returns (uint256) {
        return t == A ? 0 : t == B ? 1 : 2;
    }

    function _ceil(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return Math.mulDiv(a, b, c, Math.Rounding.Ceil);
    }

    /// What a gross receive `g` leaves the party after its fee `⌈g · fee / 10⁶⌉`.
    function _net(uint256 g, uint256 fee) internal pure returns (uint256) {
        return g - _ceil(g, fee, PPM);
    }

    function _r(uint256 seed, uint256 i) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(seed, i)));
    }

    /// `lo`, `hi` or uniform in between (the edges a quarter of the time each).
    function _pick(uint256 r, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (hi <= lo) return lo;
        uint256 m = r % 4;
        if (m == 0) return lo;
        if (m == 1) return hi;
        return lo + (r >> 2) % (hi - lo + 1);
    }

    function _skip() internal {
        ++skipped;
    }
}

/// The DEX invariant suite (spec §12, dex.md §14): between calls of `mtxSettle`, `mtxExchange`, `mtxHybrid` /
/// `mtxHybridVia` and `mtxExchangeBatch` the DEX holds nothing and no allowance; every order's `pulled` is the amount
/// its fills (less restored leftovers) add up to and never above its `amount`; every fill received at least its signed
/// limit; a hybrid maker got exactly its price, never the surplus.
/// forge-config: default.invariant.runs = 128
/// forge-config: default.invariant.depth = 64
contract DexInvariantTest is UADexBase {
    DexHandler internal h;
    MockRouter internal router;
    MockExecutor internal exec;

    function setUp() public override {
        super.setUp();
        router = new MockRouter();
        exec = new MockExecutor();
        address puller = dex.puller();
        vm.startPrank(alice);
        A.transfer(bob, 100_000);
        A.transfer(dave, 100_000);
        A.transferToUA(uaB, 100_000);
        A.transfer(address(router), 300_000);
        A.transfer(address(exec), 100_000);
        usdc.approve(puller, type(uint256).max);
        vm.stopPrank();
        vm.startPrank(bob);
        B.transfer(alice, 100_000);
        B.transfer(dave, 100_000);
        B.transferToUA(uaP, 100_000);
        B.transfer(address(router), 300_000);
        B.transfer(address(exec), 100_000);
        usdc.approve(puller, type(uint256).max);
        vm.stopPrank();
        usdc.mint(alice, 200_000);
        usdc.mint(bob, 200_000);
        usdc.mint(address(router), 300_000);
        usdc.mint(address(exec), 200_000);
        // every target listed: a `LISTED_POOLS` order still settles
        address[5] memory targets = [address(router), address(exec), address(A), address(B), address(usdc)];
        for (uint256 i; i < targets.length; ++i) dex.setExchangeTarget(targets[i], true);
        h = new DexHandler(dex, lreg, router, exec, [address(A), address(B), address(usdc)],
            [ALICE_PK, BOB_PK, DAVE_PK], [uaP, uaB], [_key(UAKinds.P256), _key(UAKinds.BIP340)],
            [UAKinds.P256, UAKinds.BIP340]);
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](4);
        (sel[0], sel[1], sel[2], sel[3]) =
            (DexHandler.settle.selector, DexHandler.exchange.selector, DexHandler.hybrid.selector, DexHandler.batch.selector);
        targetSelector(FuzzSelector(address(h), sel));
    }

    function _tokens() internal view returns (address[4] memory) {
        return [address(A), address(B), address(C), address(usdc)];
    }

    function invariant_dexHoldsNothing() public view {
        address[4] memory t = _tokens();
        for (uint256 i; i < t.length; ++i) assertEq(IERC20(t[i]).balanceOf(address(dex)), 0, "the DEX holds a token");
        assertEq(address(dex).balance, 0, "the DEX holds native coin");
    }

    function invariant_dexHoldsNoAllowance() public view {
        address[4] memory t = _tokens();
        address[3] memory spenders = [address(router), address(exec), dex.puller()];
        for (uint256 i; i < t.length; ++i) {
            for (uint256 j; j < spenders.length; ++j) {
                assertEq(IERC20(t[i]).allowance(address(dex), spenders[j]), 0, "the DEX left an allowance");
            }
        }
    }

    /// `pulled(h)` (the token's, or the DEX's for an outside token) equals the handler's ghost — Σ fills less the
    /// leftovers `restorePulled` gave back, `amount` once IOC / Path B — and never exceeds `amount`.
    function invariant_pulledNeverAboveAmount() public view {
        uint256 n = h.ordCount();
        for (uint256 k; k < n; ++k) {
            (address sell, bytes32 oh, uint256 amount, uint256 ghost, bool outside) = h.ordAt(k);
            uint256 p = outside ? dex.pulled(oh) : ITradeToken(sell).pulled(oh);
            assertLe(p, amount, "pulled above amount");
            assertEq(p, ghost, "pulled != fills less restored");
        }
    }

    /// Every fill: what the party received net ≥ what its signed limit `⌈sold · receiveAmount / amount⌉` leaves after
    /// the fee (net is monotone in the gross, so gross ≥ the limit implies it).
    function invariant_everyReceiveAtLeastTheLimit() public view {
        uint256 n = h.fillCount();
        for (uint256 i; i < n; ++i) {
            (uint256 sold, uint256 net, uint256 amount, uint256 receiveAmount, uint256 fee) = h.fillAt(i);
            assertGt(sold, 0, "a fill sold nothing");
            uint256 limit = Math.mulDiv(sold, receiveAmount, amount, Math.Rounding.Ceil);
            assertGe(net, limit - Math.mulDiv(limit, fee, 1_000_000, Math.Rounding.Ceil), "below the signed limit");
        }
    }

    /// Per party, Σ over its hybrid maker fills of `⌈fill · receiveAmount / amount⌉` less the fee equals exactly what it
    /// received: no surplus and no leftover ever reaches a maker (DX5, DX7).
    function invariant_makersNeverGetHybridSurplus() public view {
        for (uint256 p; p < 5; ++p) assertEq(h.makerGot(p), h.makerWant(p), "a hybrid maker got other than its price");
    }

    function afterInvariant() public {
        emit log_named_uint("settled", h.settled());
        emit log_named_uint("exchanged", h.exchanged());
        emit log_named_uint("hybrids (a)", h.hybridsA());
        emit log_named_uint("hybrids (b)", h.hybridsB());
        emit log_named_uint("batches", h.batches());
        emit log_named_uint("batch plans ok", h.batchPlansOk());
        emit log_named_uint("batch plans failed", h.batchPlansFailed());
        emit log_named_uint("hybrid refunds", h.refunds());
        emit log_named_uint("restores", h.restores());
        emit log_named_uint("refills", h.refills());
        emit log_named_uint("refills after restore", h.refillsAfterRestore());
        emit log_named_uint("skipped", h.skipped());
    }
}
