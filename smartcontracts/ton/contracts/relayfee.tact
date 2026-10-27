// CTR-MTX-27 on TON (spec §7.2 TON row): the relay-fee escrow router. TON has no cross-contract atomicity, so the
// payer's router-bound payment moves into escrow first (keyed by (payer, ref)), a one-shot executor then sends the
// call, and the escrow settles on the call's provable outcome:
// - the executor sends the call and right after it a probe, both bounceable, to the target. TON delivers the messages
//   of one account pair in order, so the target handles the call before the probe and its replies come back in that
//   order: a bounced probe with no bounced call before it proves the call ran -> release to the relayer;
// - the call's bounce (a failure, or no account at the target) -> refund to the payer;
// - no outcome by `deadline` (a target that swallows the probe) -> anyone's RelayRefund refunds.
// The call carries at least the chain's largest compute fee (config param 21), so a failed call always has the TON
// for its bounce: no failure is silent. Release and refund delete the entry first, so they are exclusive, and the
// escrow holds nothing once settled. No admin, no code upgrade: the router's code is fixed at deploy.
import "./jetton";

message(0x5b0a1d30) RelayCall {
    target: Address;
    call: Cell;
    salt: Int as uint256;
    payWallet: Address;
    payOp: Cell;
    payAuth: Cell;
    payStateInit: Cell?;
    master: Address;
    deadline: Int as uint32;
}

message(0x5b0a1d31) RelayRefund {
    from: Address;
    ref: Int as uint256;
}

/// Router -> executor (deploys it): send `call` to `target`, then the probe.
message(0x5b0a1d33) RelayExec {
    ref: Int as uint256;
    target: Address;
    call: Cell;
}

/// Executor -> target, right after the call; the target is expected to refuse it (its bounce is the success signal).
message(0x5b0a1d32) RelayProbe {
    queryId: Int as uint64;
}

/// Executor -> router: the call's outcome.
message(0x5b0a1d34) RelayOutcome {
    from: Address;
    ref: Int as uint256;
    ok: Bool;
}

/// CTR-MTX-27 event: the escrow went to `payee` (the relayer, open mode).
message(0x9b1c0d05) RelayFeePaid {
    ref: Int as uint256;
    target: Address;
    token: Address;
    payer: Address;
    payee: Address;
    amount: Int as coins;
}

struct Escrow {
    from: Address;
    ref: Int as uint256;
    target: Address;
    call: Cell;
    salt: Int as uint256;
    master: Address;
    relayer: Address;
    amount: Int as coins;
    deadline: Int as uint32;
    funded: Bool;
}

// Exit codes (stable; 72x are Mandate's, 73x the DEX's).
const E_RELAY_SHAPE: Int = 741;    // the payment is not exactly the router-bound pay for this call, or a bad target
const E_RELAY_PENDING: Int = 742;  // (payer, ref) already escrowed, or the payer wallet has a payment in flight
const E_RELAY_DEADLINE: Int = 743; // deadline not in (now, now + RELAY_TIMEOUT]
const E_RELAY_UNKNOWN: Int = 744;  // no escrow for (payer, ref)
const E_RELAY_EARLY: Int = 745;    // RelayRefund before the deadline

const RELAY_TIMEOUT: Int = 3600;          // the latest deadline a RelayCall may set, seconds after it arrives
const PAY_HOP_TON: Int = ton("0.1");      // the payer wallet's SignedOp (0.05 floor) and the router's own gas
const PROBE_TON: Int = ton("0.02");
const SETTLE_TON: Int = ton("0.05");      // kept by the executor for the release / refund transfer
const EXEC_TON: Int = ton("0.05");        // router notification, executor deploy and gas, the report
const CALL_MARGIN: Int = ton("0.02");     // the call's bounce forward fee on top of the largest compute fee

fun escrowKey(from: Address, ref: Int): Int {
    return beginCell().storeAddress(from).storeUint(ref, 256).endCell().hash();
}

/// `keccak256("scaas.relayfee" ‖ global id:int32 ‖ target workchain:int8 ‖ target hash:uint256 ‖ cellHash(call) ‖ salt)`.
/// The call's representation hash covers every ref (Tact's keccak256(Slice) would follow the first ref only); the
/// payer-signed `salt` (committed through `payRef`) makes two relays of the same call distinct payments.
fun relayRef(target: Address, call: Cell, salt: Int): Int {
    let t = parseStdAddress(target.asSlice());
    return keccak256(beginCell().storeSlice("scaas.relayfee".asSlice()).storeInt(globalId(), 32).storeInt(t.workchain, 8)
        .storeUint(t.address, 256).storeUint(call.hash(), 256).storeUint(salt, 256).asSlice());
}

/// The TON a call must carry: the largest compute fee of a basechain transaction (config param 21: gas_limit at
/// the current prices) plus its bounce, so a failed call can always bounce.
fun callFloor(): Int {
    let s = getConfigParam(21)!!.beginParse();
    if (s.preloadUint(8) == 0xd1) {
        s.skipBits(8 + 128); // gas_flat_pfx flat_gas_limit flat_gas_price, then the prices
    }
    s.skipBits(8 + 64); // gas_prices#dd / gas_prices_ext#de, gas_price
    return getComputeFee(s.loadUint(64), false) + CALL_MARGIN;
}

/// The forward TON the payment must carry to the router (the executor's whole budget).
fun execFloor(): Int {
    return callFloor() + PROBE_TON + SETTLE_TON + EXEC_TON;
}

fun executorInit(router: Address, from: Address, salt: Int): StateInit {
    return initOf RelayExecutor(router, from, salt, 0, null, 0, false);
}

contract ScaasRelayFee {
    escrows: map<Int as uint256, Escrow>;
    busy: map<Address, Int as uint256>; // payer wallet -> escrow key while its payment is in flight (its bounce names no ref)

    receive() {} // deploy / TON top-up

    receive(msg: RelayCall) {
        let ctx = context();
        let m = parseMetaOp(msg.payOp);
        let ref = relayRef(msg.target, msg.call, msg.salt);
        throwUnless(E_RELAY_SHAPE, m.op == OP_PAY && m.payRef == ref && m.lane == payLane(ref) && m.nonce == 0 &&
            m.relayer != null && m.relayer!! == myAddress() && m.to == myAddress() && m.amount > 0 &&
            msg.payWallet == walletAddress(m.from, msg.master) && msg.target != myAddress() &&
            parseStdAddress(msg.target.asSlice()).workchain == 0);
        self.refuseCall(msg.call);
        throwUnless(E_RELAY_DEADLINE, msg.deadline > now() && msg.deadline <= now() + RELAY_TIMEOUT);
        let key = escrowKey(m.from, ref);
        throwUnless(E_RELAY_PENDING, !self.escrows.exists(key) && !self.busy.exists(msg.payWallet));
        let forward = max(m.extra, execFloor());
        throwUnless(E_VALUE, ctx.value >= forward + PAY_HOP_TON);
        self.escrows.set(key, Escrow {
            from: m.from, ref, target: msg.target, call: msg.call, salt: msg.salt, master: msg.master,
            relayer: ctx.sender, amount: m.amount, deadline: msg.deadline, funded: false,
        });
        self.busy.set(msg.payWallet, key);
        // CTR-MTX-26: params = null (a non-null params on OP_PAY is a pay-meta).
        message(MessageParameters {
            to: msg.payWallet,
            value: 0,
            mode: SendRemainingValue,
            bounce: true,
            body: SignedOp {
                op: msg.payOp, auth: msg.payAuth, params: null, stateInit: msg.payStateInit,
                responseDestination: ctx.sender, forwardTon: forward, matchWith: 0,
            }.toCell(),
        });
    }

    /// R18: a call is never a router-bound op (a SignedOp or MandatePay whose MetaOp names the router as relayer), and
    /// never the probe (whose bounce is the success signal).
    fun refuseCall(call: Cell) {
        let s = call.beginParse();
        if (s.bits() < 32) {
            return;
        }
        let op = s.preloadUint(32);
        throwIf(E_RELAY_SHAPE, op == 0x5b0a1d32);
        if ((op == 0x5b0a1d01 || op == 0x5b0a1d10) && s.refs() > 0) {
            let r = parseMetaOp(s.preloadRef()).relayer;
            throwIf(E_RELAYER, r != null && r!! == myAddress());
        }
    }

    /// The payment arrives through the router's own jetton wallet of the escrow's token. Never throw: anything that is
    /// not an escrow payment is handed back to its sender.
    receive(msg: JettonNotification) {
        let body = forwardBody(msg.forwardPayload);
        if (body.bits() == 288 && body.refs() == 0 && body.preloadUint(32) == PAY_TAG) {
            body.skipBits(32);
            let key = escrowKey(msg.sender, body.loadUint(256));
            let e = self.escrows.get(key);
            if (e != null && !e!!.funded && msg.amount == e!!.amount && sender() == walletAddress(myAddress(), e!!.master)) {
                let x = e!!;
                x.funded = true;
                self.escrows.set(key, x);
                self.busy.del(walletAddress(x.from, x.master));
                deploy(DeployParameters {
                    init: executorInit(myAddress(), x.from, x.salt),
                    value: 0,
                    mode: SendRemainingValue,
                    bounce: false,
                    body: RelayExec { ref: x.ref, target: x.target, call: x.call }.toCell(),
                });
                return;
            }
        }
        // A plain transfer, a payment whose escrow timed out, a foreign wallet: only a real wallet of ours moves
        // anything, and then exactly what it just received.
        if (msg.amount > 0) {
            self.transfer(sender(), msg.sender, msg.amount, msg.sender);
        }
    }

    /// The payment's SignedOp bounced at the payer wallet: nothing was escrowed.
    bounced(msg: Slice) {
        let k = self.busy.get(sender());
        if (k == null) {
            return;
        }
        self.busy.del(sender());
        let e = self.escrows.get(k!!);
        if (e != null && !e!!.funded) {
            self.escrows.del(k!!);
            message(MessageParameters { to: e!!.relayer, value: 0, mode: SendRemainingValue | SendIgnoreErrors, bounce: false, body: JettonExcesses { queryId: 0 }.toCell() });
        }
    }

    receive(msg: RelayOutcome) {
        let key = escrowKey(msg.from, msg.ref);
        let e = self.escrows.get(key);
        if (e == null || !e!!.funded || sender() != contractAddress(executorInit(myAddress(), msg.from, e!!.salt))) {
            return; // settled already (exclusive), or not our executor
        }
        let x = e!!;
        self.escrows.del(key);
        if (msg.ok) {
            emit(RelayFeePaid { ref: x.ref, target: x.target, token: x.master, payer: x.from, payee: x.relayer, amount: x.amount }.toCell());
            self.transfer(walletAddress(myAddress(), x.master), x.relayer, x.amount, x.relayer);
        } else {
            self.transfer(walletAddress(myAddress(), x.master), x.from, x.amount, x.relayer);
        }
    }

    /// Anyone, after the deadline: a funded escrow goes back to the payer, an unfunded entry is dropped.
    receive(msg: RelayRefund) {
        let key = escrowKey(msg.from, msg.ref);
        let e = self.escrows.get(key);
        throwUnless(E_RELAY_UNKNOWN, e != null);
        let x = e!!;
        throwUnless(E_RELAY_EARLY, now() >= x.deadline);
        self.escrows.del(key);
        if (x.funded) {
            throwUnless(E_VALUE, context().value >= SETTLE_TON);
            self.transfer(walletAddress(myAddress(), x.master), x.from, x.amount, sender());
            return;
        }
        let w = walletAddress(x.from, x.master);
        let b = self.busy.get(w);
        if (b != null && b!! == key) {
            self.busy.del(w);
        }
        cashback(sender());
    }

    /// A transfer out of our jetton wallet `wallet`, on the incoming message's TON.
    fun transfer(wallet: Address, to: Address, amount: Int, response: Address) {
        message(MessageParameters {
            to: wallet,
            value: 0,
            mode: SendRemainingValue,
            bounce: true,
            body: JettonTransfer {
                queryId: 0, amount, destination: to, responseDestination: response, customPayload: null,
                forwardTonAmount: 0, forwardPayload: emptyForwardPayload(),
            }.toCell(),
        });
    }

    get fun get_relay_ref(target: Address, call: Cell, salt: Int): Int {
        return relayRef(target, call, salt);
    }

    /// The executor of a (payer, salt): the sender the target sees, and the call's `responseDestination` (client rule).
    get fun get_executor(from: Address, salt: Int): Address {
        return contractAddress(executorInit(myAddress(), from, salt));
    }

    get fun get_pending(from: Address, ref: Int): Escrow? {
        return self.escrows.get(escrowKey(from, ref));
    }

    /// 0 = none, 1 = payment in flight, 2 = funded (the call is out).
    get fun get_escrow_state(key: Int): Int {
        let e = self.escrows.get(key);
        return e == null ? 0 : (e!!.funded ? 2 : 1);
    }

    /// The least TON a RelayCall carries for a payment whose signed forward floor is `extra`.
    get fun get_relay_value(extra: Int): Int {
        return max(extra, execFloor()) + PAY_HOP_TON;
    }
}

/// One-shot: deployed per (router, payer, salt) when the escrow is funded. It holds nothing and only its router may
/// start it; the target sees it as the sender, never the router (R18).
contract RelayExecutor(
    router: Address,
    from: Address,
    salt: Int as uint256,
    ref: Int as uint256,
    target: Address?,
    probe: Int as uint64,
    done: Bool,
) {
    receive(msg: RelayExec) {
        throwUnless(E_SENDER, sender() == self.router);
        if (self.target != null) {
            // a second escrow on the same (payer, salt): refused, so its payer is refunded
            self.report(msg.ref, false, SendRemainingValue);
            return;
        }
        self.ref = msg.ref;
        self.target = msg.target;
        self.probe = curLt();
        let v = context().value - PROBE_TON - SETTLE_TON - ton("0.02");
        if (v < callFloor()) {
            self.done = true;
            self.report(msg.ref, false, SendRemainingValue);
            return;
        }
        message(MessageParameters { to: msg.target, value: v, mode: SendDefaultMode, bounce: true, body: msg.call });
        message(MessageParameters { to: msg.target, value: PROBE_TON, mode: SendDefaultMode, bounce: true, body: RelayProbe { queryId: self.probe }.toCell() });
    }

    /// The call's excess TON (its responseDestination is this executor) rides back with the report.
    receive(msg: JettonExcesses) {}

    bounced(msg: bounced<RelayProbe>) {
        if (!self.done && self.target != null && sender() == self.target!! && msg.queryId == self.probe) {
            self.done = true;
            self.report(self.ref, true, SendRemainingBalance);
        }
    }

    /// Any other bounce from the target is the call's: it failed.
    bounced(msg: Slice) {
        if (!self.done && self.target != null && sender() == self.target!!) {
            self.done = true;
            self.report(self.ref, false, SendRemainingBalance);
        }
    }

    fun report(ref: Int, ok: Bool, mode: Int) {
        message(MessageParameters { to: self.router, value: 0, mode, bounce: false, body: RelayOutcome { from: self.from, ref, ok }.toCell() });
    }
}
