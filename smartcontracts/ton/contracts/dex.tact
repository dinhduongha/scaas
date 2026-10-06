// Escrow DEX (R35 on TON, R10-7). No atomicity across contracts on TON, so each signed order leg is a
// jetton transfer into escrow here; a match pays both legs out; unmatched legs are refundable by anyone
// after expiry (review S8); a signed `revoke` cancels. Fill-or-kill: an order fills completely or not at all.
// Every leg and cancel arrives as a TEP-74 notification from one of the DEX's own jetton wallets.
import "./jetton";

const PAYOUT_TON: Int = ton("0.05");
const MATCH_GAS: Int = ton("0.03");
const MAX_FEE_PPM: Int = 10000; // 1 %

struct Market {
    enabled: Bool;
    makerPpm: Int as uint32;
    takerPpm: Int as uint32;
}

struct Order {
    owner: Address;
    tokenIn: Address;
    amountIn: Int as coins;
    validUntil: Int as uint64;
    seq: Int as uint64;
    params: Cell; // the signed TradeParams cell
}

message(0x5b0a1d20) SetMarket {
    a: Address;
    b: Address;
    enabled: Bool;
    makerPpm: Int as uint32;
    takerPpm: Int as uint32;
}

message(0x5b0a1d21) Match {
    a: Int as uint256;
    b: Int as uint256;
}

message(0x5b0a1d22) Refund {
    orderHash: Int as uint256;
}

message(0x5b0a1d23) WithdrawFees {
    master: Address;
    to: Address;
    amount: Int as coins;
}

fun pairKey(x: Address, y: Address): Int {
    let hx = parseStdAddress(x.asSlice()).address;
    let hy = parseStdAddress(y.asSlice()).address;
    if (hx < hy) {
        return beginCell().storeAddress(x).storeAddress(y).endCell().hash();
    }
    return beginCell().storeAddress(y).storeAddress(x).endCell().hash();
}

struct Leg {
    ok: Bool;
    digest: Int;
    order: Order?;
}

contract ScaasDex(
    admin: Address,
    seq: Int as uint64,
    markets: map<Int as uint256, Market>,
    wallets: map<Address, Address>, // our jetton wallet -> its master: O(1) whatever the number of markets
    orders: map<Int as uint256, Cell>,
    fees: map<Address, Int as coins>, // fees, plus payouts that bounced (admin-held, returned from the bounce trail)
) {
    receive() {} // deploy / TON top-up

    receive(msg: SetMarket) {
        throwUnless(E_SENDER, sender() == self.admin);
        throwUnless(E_PARAMS, msg.makerPpm <= MAX_FEE_PPM && msg.takerPpm <= MAX_FEE_PPM);
        self.markets.set(pairKey(msg.a, msg.b), Market { enabled: msg.enabled, makerPpm: msg.makerPpm, takerPpm: msg.takerPpm });
        self.wallets.set(walletAddress(myAddress(), msg.a), msg.a);
        self.wallets.set(walletAddress(myAddress(), msg.b), msg.b);
        cashback(sender());
    }

    /// A leg arrives through the DEX's own jetton wallet. Never throw here: the tokens are already ours —
    /// anything wrong is refunded instead.
    receive(msg: JettonNotification) {
        let master = self.wallets.get(sender());
        if (master == null) {
            return; // not one of our wallets: nothing was credited to us
        }
        let body = forwardBody(msg.forwardPayload);
        if (body.bits() == 32 + 256 && body.refs() == 0 && body.preloadUint(32) == CANCEL_TAG) {
            body.skipBits(32);
            self.cancel(master!!, msg.sender, body.loadUint(256));
            return;
        }
        let leg = self.parseLeg(master!!, msg);
        if (!leg.ok || self.orders.get(leg.digest) != null) {
            self.refundLeg(master!!, msg.sender, msg.amount);
            return;
        }
        let o = leg.order!!;
        self.orders.set(leg.digest, o.toCell());
        self.seq += 1;
        let hint = forwardBody(msg.forwardPayload);
        hint.skipBits(32);
        let matchWith = hint.loadUint(256);
        if (matchWith != 0 && context().value >= PAYOUT_TON * 2 + MATCH_GAS && self.canMatch(matchWith, leg.digest)) {
            self.settle(matchWith, leg.digest);
        }
    }

    /// The owner's signed `revoke`, sent as a zero-amount transfer of the order's token after its leg: on the same
    /// path (owner wallet -> our wallet -> us) TON delivers it after the leg, so an unknown order is one that is
    /// gone (matched, refunded) or never came — nothing to remember (review L11). The wallet sends it with at
    /// least CANCEL_TON, which pays the payout.
    fun cancel(master: Address, owner: Address, orderHash: Int) {
        let c = self.orders.get(orderHash);
        if (c == null) {
            return;
        }
        let o = Order.fromCell(c!!);
        if (o.owner != owner || o.tokenIn != master || context().value < PAYOUT_TON + MATCH_GAS) {
            return;
        }
        self.orders.del(orderHash);
        self.payout(o.tokenIn, o.owner, o.amountIn, PAYOUT_TON);
    }

    /// A payout or refund the DEX's own wallet refused: keep the tokens on record instead of losing them
    /// (review L14). Only our wallets' bounces count.
    bounced(msg: bounced<JettonTransfer>) {
        let master = self.wallets.get(sender());
        if (master != null) {
            self.addFee(master!!, msg.amount);
        }
    }

    receive(msg: Match) {
        throwUnless(E_VALUE, context().value >= PAYOUT_TON * 2 + MATCH_GAS);
        throwUnless(731, self.canMatch(msg.a, msg.b));
        self.reserveBalance();
        self.settle(msg.a, msg.b);
        self.returnExcess();
    }

    receive(msg: Refund) {
        throwUnless(E_VALUE, context().value >= PAYOUT_TON + MATCH_GAS);
        let c = self.orders.get(msg.orderHash);
        throwUnless(732, c != null);
        let o = Order.fromCell(c!!);
        throwUnless(733, now() >= o.validUntil);
        self.orders.del(msg.orderHash);
        self.reserveBalance();
        self.payout(o.tokenIn, o.owner, o.amountIn, PAYOUT_TON);
        self.returnExcess();
    }

    receive(msg: WithdrawFees) {
        throwUnless(E_SENDER, sender() == self.admin);
        let f = self.fees.get(msg.master);
        throwUnless(E_BALANCE, f != null && f!! >= msg.amount && msg.amount > 0);
        self.fees.set(msg.master, f!! - msg.amount);
        self.payout(msg.master, msg.to, msg.amount, PAYOUT_TON);
    }

    // ---------------------------------------------------------------- internals

    fun parseLeg(master: Address, n: JettonNotification): Leg {
        let fail = Leg { ok: false, digest: 0, order: null };
        let body = forwardBody(n.forwardPayload);
        if (body.bits() != 32 + 256 || body.refs() != 2 || body.preloadUint(32) != TRADE_TAG) {
            return fail;
        }
        let opCell = body.preloadRef();
        let b2 = body;
        b2.skipRef();
        let paramsCell = b2.preloadRef();
        try {
            let m = parseMetaOp(opCell);
            let p = parseTradeParams(paramsCell);
            if (m.op != OP_TRADE || m.network != globalId() || m.from != n.sender || m.to != myAddress() ||
                m.amount != n.amount || m.extra != paramsCell.hash() || m.validUntil <= now() ||
                p.tokenIn != master || p.maxFeePpm > MAX_FEE_PPM) {
                return fail;
            }
            let mk = self.markets.get(pairKey(p.tokenIn, p.tokenOut));
            if (mk == null || !mk!!.enabled) {
                return fail;
            }
            return Leg {
                ok: true,
                digest: m.digest,
                order: Order { owner: m.from, tokenIn: master, amountIn: n.amount, validUntil: m.validUntil, seq: self.seq, params: paramsCell },
            };
        } catch (e) {
            return fail;
        }
    }

    /// Fee (in the token received) charged to `o` when trading against `other`; -1 = not allowed.
    fun feeFor(o: Order, other: Order, received: Int): Int {
        let p = parseTradeParams(o.params);
        let mk = self.markets.get(pairKey(o.tokenIn, p.tokenOut))!!;
        let ppm = o.seq < other.seq ? mk.makerPpm : mk.takerPpm;
        if (ppm > p.maxFeePpm) {
            return -1;
        }
        return received * ppm / 1000000;
    }

    fun canMatch(ha: Int, hb: Int): Bool {
        if (ha == hb) {
            return false;
        }
        let ca = self.orders.get(ha);
        let cb = self.orders.get(hb);
        if (ca == null || cb == null) {
            return false;
        }
        let a = Order.fromCell(ca!!);
        let b = Order.fromCell(cb!!);
        let pa = parseTradeParams(a.params);
        let pb = parseTradeParams(b.params);
        if (pa.tokenOut != b.tokenIn || pb.tokenOut != a.tokenIn) {
            return false;
        }
        if (now() >= a.validUntil || now() >= b.validUntil) {
            return false;
        }
        let mk = self.markets.get(pairKey(a.tokenIn, b.tokenIn));
        if (mk == null || !mk!!.enabled) {
            return false;
        }
        if ((pa.counterparty != null && pa.counterparty!! != b.owner) || (pb.counterparty != null && pb.counterparty!! != a.owner)) {
            return false;
        }
        let feeA = self.feeFor(a, b, b.amountIn);
        let feeB = self.feeFor(b, a, a.amountIn);
        if (feeA < 0 || feeB < 0) {
            return false;
        }
        return b.amountIn - feeA >= pa.minOut && a.amountIn - feeB >= pb.minOut;
    }

    fun settle(ha: Int, hb: Int) {
        let a = Order.fromCell(self.orders.get(ha)!!);
        let b = Order.fromCell(self.orders.get(hb)!!);
        let feeA = self.feeFor(a, b, b.amountIn);
        let feeB = self.feeFor(b, a, a.amountIn);
        self.orders.del(ha);
        self.orders.del(hb);
        self.addFee(b.tokenIn, feeA);
        self.addFee(a.tokenIn, feeB);
        emit(TradeSettled { a: ha, b: hb }.toCell());
        self.payout(b.tokenIn, a.owner, b.amountIn - feeA, PAYOUT_TON);
        self.payout(a.tokenIn, b.owner, a.amountIn - feeB, PAYOUT_TON);
    }

    fun addFee(master: Address, amount: Int) {
        if (amount > 0) {
            let f = self.fees.get(master);
            self.fees.set(master, (f == null ? 0 : f!!) + amount);
        }
    }

    /// Keep the DEX's own balance; payouts then spend the caller's TON and `returnExcess` hands back the rest
    /// (R10-11: unspent gas goes back to the caller, not into the DEX).
    fun reserveBalance() {
        nativeReserve(max(myBalance() - context().value, MIN_STORAGE), ReserveAtMost);
    }

    fun returnExcess() {
        message(MessageParameters { to: sender(), value: 0, mode: SendRemainingBalance | SendIgnoreErrors, bounce: false, body: JettonExcesses { queryId: 0 }.toCell() });
    }

    /// A bad or duplicate leg goes back on the TON it came with, never on the DEX's balance (review agy #2):
    /// The payer wallet sends a leg with at least MIN_LEG_TON; a refund that still fails bounces into `fees`.
    fun refundLeg(master: Address, to: Address, amount: Int) {
        if (amount <= 0) {
            return;
        }
        message(MessageParameters {
            to: walletAddress(myAddress(), master),
            value: 0,
            mode: SendRemainingValue,
            bounce: true,
            body: JettonTransfer {
                queryId: 0,
                amount,
                destination: to,
                responseDestination: to,
                customPayload: null,
                forwardTonAmount: 0,
                forwardPayload: emptyForwardPayload(),
            }.toCell(),
        });
    }

    /// Jetton transfer out of the DEX's wallet for `master`; TON for gas comes from the DEX balance, which
    /// the incoming message topped up (each entry point checks its value).
    fun payout(master: Address, to: Address, amount: Int, ton: Int) {
        if (amount <= 0) {
            return;
        }
        message(MessageParameters {
            to: walletAddress(myAddress(), master),
            value: ton,
            mode: SendDefaultMode,
            bounce: true,
            body: JettonTransfer {
                queryId: 0,
                amount,
                destination: to,
                responseDestination: null,
                customPayload: null,
                forwardTonAmount: 0,
                forwardPayload: emptyForwardPayload(),
            }.toCell(),
        });
    }

    get fun get_order(h: Int): Order? {
        let c = self.orders.get(h);
        return c == null ? null : Order.fromCell(c!!);
    }

    get fun get_fees(master: Address): Int {
        let f = self.fees.get(master);
        return f == null ? 0 : f!!;
    }
}
