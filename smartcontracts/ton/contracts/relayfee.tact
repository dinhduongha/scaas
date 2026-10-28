// CTR-MTX-27 on TON (spec §7.2 TON row): the relay-fee escrow router. TON has no cross-contract atomicity, so the
// payer's router-bound payment moves into escrow first (keyed by (payer, ref)), a one-shot executor then sends the
// call, and the escrow settles on a positive acknowledgment (T16 fix 1, controller call 2026-10-28):
// - targets are SCaaS contracts of a fixed code set only (the jetton wallet, the Mandate): the RelayCall carries the
//   target's StateInit, whose address must be the target and whose code hash must be one of ours; the call must be a
//   served fee-less entry (wallet `set_key` / `revoke`, Mandate owner `revoke`). Anything else is refused before escrow.
// - a served entry sends `RelayAck { digest }` to its sender at the end of a successful handling; a failed action
//   phase sends no message at all, so the ack proves compute and action ran;
// - the executor sends the call and right after it a bounceable probe. TON delivers one account pair's messages in
//   order: the ack (in the call's transaction) comes before the probe's bounce (a later transaction). Probe bounce
//   after an ack -> release to the relayer; probe bounce without one, or the call's bounce -> refund to the payer;
//   no outcome by `deadline` -> anyone's RelayRefund refunds. Refund wins whenever success is not proven.
// Every TON amount is priced from the chain's config at the time (compute, forward and storage fees), only gas units
// and message sizes are constants. Release and refund are exclusive; a settlement transfer that bounces restores the
// escrow so it can be settled again. No admin, no code upgrade: the router's code is fixed at deploy.
import "./mandate";

message(0x5b0a1d30) RelayCall {
    target: Address;
    targetInit: StateInit;
    call: Cell;
    salt: Int as uint256;
    payWallet: Address;
    payOp: Cell;
    payAuth: Cell;
    payStateInit: Cell?;
    master: Address;
    deadline: Int as uint32;
}

/// Anyone: after `deadline` refunds a funded escrow (drops an unfunded one); at any time re-sends a settlement whose
/// transfer bounced.
message(0x5b0a1d31) RelayRefund {
    from: Address;
    ref: Int as uint256;
}

/// Router -> executor (deploys it): send `call` to `target`, then the probe.
message(0x5b0a1d33) RelayExec {
    ref: Int as uint256;
    target: Address;
    call: Cell;
    relayer: Address;      // who gets the executor's TON that arrives after the outcome (a revoke-cancel's late excess)
    callMin: Int as coins; // the least TON the call carries (callFloor, or the served entry's own floor if higher)
    keep: Int as coins; // what the executor keeps after the call and the probe (its gas, the report, the settlement)
}

/// Executor -> target, right after the call; the target refuses it (its bounce marks the end of the call's replies).
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

/// The escrow went back to the payer (`amount` 0: the payment never arrived, nothing was escrowed). `relayer` = the
/// relayer of that escrow, so a node only counts the outcome of its own relay (T16 fix 2).
message(0x9b1c0d06) RelayFeeRefunded {
    ref: Int as uint256;
    payer: Address;
    relayer: Address;
    amount: Int as coins;
}

const STAGE_PAYING: Int = 0;
const STAGE_FUNDED: Int = 1;
const STAGE_RELEASE_OWED: Int = 2; // the release transfer bounced: RelayRefund sends it again
const STAGE_REFUND_OWED: Int = 3;  // the refund transfer bounced: RelayRefund sends it again

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
    stage: Int as uint8;
    callMin: Int as coins;
}

// Exit codes (stable; 72x are Mandate's, 73x the DEX's).
const E_RELAY_SHAPE: Int = 741;    // not the router-bound pay for this call, or not a served SCaaS target / entry
const E_RELAY_PENDING: Int = 742;  // (payer, ref) already escrowed, or the payer wallet has a payment in flight
const E_RELAY_DEADLINE: Int = 743; // deadline not in (now, now + RELAY_TIMEOUT]
const E_RELAY_UNKNOWN: Int = 744;  // no escrow for (payer, ref)
const E_RELAY_EARLY: Int = 745;    // RelayRefund of a funded escrow before the deadline

const RELAY_TIMEOUT: Int = 3600; // the latest deadline a RelayCall may set, seconds after it arrives
const SETTLE_RING: Int = 16;     // settlements kept to undo on a bounce (it arrives in the next transaction)
const MAX_CELLS: Int = 1024;     // the largest message tree priced (a larger call is refused, exit 8)

// Gas units per step, about ×2 the use measured in @ton/sandbox 0.45.0 (tests/relayfee.spec.ts logs it: RelayCall
// 61.5 k, notification 31.7 k, outcome 23.6 k, wallet transfer 9.8 k / 12.1 k, executor start 16.1 k, its bounce 6.8 k,
// the target's probe refusal 2.3 k). Prices come from the config at run time.
const ROUTER_CALL_GAS: Int = 120000;  // RelayCall (grows with the message: it prices every hop by size)
const ROUTER_NOTE_GAS: Int = 64000;   // JettonNotification -> executor deploy
const ROUTER_SETTLE_GAS: Int = 48000; // RelayOutcome / RelayRefund, with its transfer
const WALLET_GAS: Int = 25000;        // one jetton wallet step of a transfer
const EXEC_GAS: Int = 32000;          // the executor's start
const EXEC_BOUNCE_GAS: Int = 14000;   // the executor's bounce handlers and report
const PROBE_GAS: Int = 10000;         // the target refusing the probe

fun gasFee(g: Int): Int {
    return getComputeFee(g, false);
}

/// Forward fee of a message whose body (and init) is `c`, plus one header cell.
fun fwdOf(c: Cell): Int {
    let d = c.computeDataSize(MAX_CELLS);
    return getForwardFee(d.cells + 1, d.bits + 1023, false);
}

/// Forward fee of a one-cell message (a probe, an ack, a report, a bounce).
fun fwd1(): Int {
    return getForwardFee(1, 1023, false);
}

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

/// The TON a call carries: the largest compute fee of a basechain transaction (config param 21: gas_limit at the
/// current prices), then its bounce and the executor's handling of it.
fun callFloor(): Int {
    let s = getConfigParam(21)!!.beginParse();
    if (s.preloadUint(8) == 0xd1) {
        s.skipBits(8 + 128); // gas_flat_pfx flat_gas_limit flat_gas_price, then the prices
    }
    s.skipBits(8 + 64); // gas_prices#dd / gas_prices_ext#de, gas_price
    return gasFee(s.loadUint(64)) + fwd1() + gasFee(EXEC_BOUNCE_GAS);
}

/// The probe: the target's refusal, its bounce, the executor's handling of the bounce (its forward fee paid apart).
fun probeValue(): Int {
    return gasFee(PROBE_GAS + EXEC_BOUNCE_GAS) + fwd1();
}

/// One settlement transfer out of the router's jetton wallet: the router's step, the jetton wallet's own floor
/// (`MIN_TRANSFER_TON`), two wallet steps and the recipient wallet's deploy.
fun settleValue(): Int {
    return MIN_TRANSFER_TON + gasFee(ROUTER_SETTLE_GAS + 2 * WALLET_GAS) + 2 * fwd1() + fwdOf(walletInit(myAddress(), myAddress()).code) + 1;
}

/// What the executor keeps after sending the call and the probe: its own start, the report, the settlement (priced by
/// the router and passed in `RelayExec`, so the executor's code carries no wallet code).
fun execKeep(): Int {
    return gasFee(EXEC_GAS) + fwd1() + settleValue();
}

/// The least TON the executor starts with: the call (at least `callMin`) and its forward fee, the probe, `keep`.
fun execStart(call: Cell, callMin: Int, keep: Int): Int {
    return fwdOf(call) + callMin + probeValue() + fwd1() + keep;
}

/// The call's TON: `callFloor`, or more where the served entry's own floor is higher (the wallet's `SignedOp` wants
/// `MIN_SIGNED_OP_TON` plus the call's `forwardTon`, which a revoke's cancel carries on; the Mandate's `2 · MANDATE_GAS`).
fun callMinOf(init: StateInit, call: Cell): Int {
    let h = init.code.hash();
    let own = h == mandateCodeHash() ? 2 * MANDATE_GAS : 0;
    let s = call.beginParse();
    if (h == walletCodeHash() && s.bits() >= 32 && s.preloadUint(32) == 0x5b0a1d01) { // else refused by servedCall
        own = MIN_SIGNED_OP_TON + SignedOp.fromCell(call).forwardTon;
    }
    return max(callFloor(), own);
}

fun executorInit(router: Address, from: Address, salt: Int): StateInit {
    return initOf RelayExecutor(router, from, salt, 0, null, 0, 0, false, false, null);
}

fun walletCodeHash(): Int {
    return walletInit(myAddress(), myAddress()).code.hash();
}

fun mandateCodeHash(): Int {
    return (initOf Mandate(myAddress(), myAddress(), MandateState {
        revoked: false, periodStart: 0, spent: 0, balance: 0,
        terms: MandateTerms { perPayment: 0, perPeriod: 0, periodSeconds: 0, expiresAt: 0 }, ownerPubkey: 0, delegatePubkey: 0,
    }, emptyMap(), emptyMap(), emptyMap(), 0, emptyMap())).code.hash();
}

struct Budget {
    forward: Int; // the payment's forwardTon: the executor's whole budget
    value: Int;   // the least TON the RelayCall carries
}

/// Priced from the RelayCall's own message sizes and the config at the time (the getter `get_relay_value` runs it on
/// the body the relayer is about to send).
fun relayBudget(msg: RelayCall, extra: Int): Budget {
    let e = executorInit(myAddress(), msg.target, 0);
    let deploy = fwdOf(RelayExec { ref: 0, target: msg.target, call: msg.call, relayer: msg.target, callMin: 0, keep: 0 }.toCell()) + fwdOf(e.code) + fwdOf(e.data);
    let forward = max(extra, deploy + gasFee(ROUTER_NOTE_GAS) + execStart(msg.call, callMinOf(msg.targetInit, msg.call), execKeep()));
    let pay = SignedOp {
        op: msg.payOp, auth: msg.payAuth, params: null, stateInit: msg.payStateInit, responseDestination: msg.target,
        forwardTon: forward, matchWith: 0,
    }.toCell();
    return Budget { forward, value: forward + MIN_SIGNED_OP_TON + gasFee(ROUTER_CALL_GAS) + fwdOf(pay) + storageKeep(msg.call) };
}

/// The router's own rent for one escrow over its longest life, kept from each relay so the router never freezes.
fun storageKeep(call: Cell): Int {
    let d = call.computeDataSize(MAX_CELLS);
    return getStorageFee(d.cells + 8, d.bits + 8 * 1023, RELAY_TIMEOUT, false);
}

contract ScaasRelayFee {
    escrows: map<Int as uint256, Escrow>;
    busy: map<Address, Int as uint256>;   // payer wallet -> escrow key while its payment is in flight (its bounce names no ref)
    settling: map<Int as uint64, Escrow>; // recent settlement transfers by queryId, to restore on a bounce
    settled: Int as uint64 = 0;

    receive() {} // deploy / TON top-up

    receive(msg: RelayCall) {
        let ctx = context();
        let m = parseMetaOp(msg.payOp);
        let ref = relayRef(msg.target, msg.call, msg.salt);
        throwUnless(E_RELAY_SHAPE, m.op == OP_PAY && m.payRef == ref && m.lane == payLane(ref) && m.nonce == 0 &&
            m.relayer != null && m.relayer!! == myAddress() && m.to == myAddress() && m.amount > 0 &&
            msg.payWallet == walletAddress(m.from, msg.master));
        self.servedCall(msg, m.from);
        throwUnless(E_RELAY_DEADLINE, msg.deadline > now() && msg.deadline <= now() + RELAY_TIMEOUT);
        let key = escrowKey(m.from, ref);
        throwUnless(E_RELAY_PENDING, !self.escrows.exists(key) && !self.busy.exists(msg.payWallet));
        let b = relayBudget(msg, m.extra);
        throwUnless(E_VALUE, ctx.value >= b.value);
        self.escrows.set(key, Escrow {
            from: m.from, ref, target: msg.target, call: msg.call, salt: msg.salt, master: msg.master,
            relayer: ctx.sender, amount: m.amount, deadline: msg.deadline, stage: STAGE_PAYING, callMin: callMinOf(msg.targetInit, msg.call),
        });
        self.busy.set(msg.payWallet, key);
        // Keep this escrow's rent; everything else of the relay's TON goes on with the payment.
        nativeReserve(myBalance() - ctx.value + storageKeep(msg.call), ReserveExact);
        // CTR-MTX-26: params = null (a non-null params on OP_PAY is a pay-meta).
        message(MessageParameters {
            to: msg.payWallet,
            value: 0,
            mode: SendRemainingBalance,
            bounce: true,
            body: SignedOp {
                op: msg.payOp, auth: msg.payAuth, params: null, stateInit: msg.payStateInit,
                responseDestination: ctx.sender, forwardTon: b.forward, matchWith: 0,
            }.toCell(),
        });
    }

    /// The target is a SCaaS contract of our code set (its StateInit derives its address), and the call one of its
    /// served fee-less entries, its excess back to the executor (the relayer's TON), never a router-bound op (R18).
    fun servedCall(msg: RelayCall, from: Address) {
        throwUnless(E_RELAY_SHAPE, contractAddress(msg.targetInit) == msg.target);
        let code = msg.targetInit.code.hash();
        let wallet = code == walletCodeHash();
        throwUnless(E_RELAY_SHAPE, wallet || code == mandateCodeHash());
        let s = msg.call.beginParse();
        throwUnless(E_RELAY_SHAPE, s.bits() >= 32 && s.preloadUint(32) == 0x5b0a1d01);
        let so = SignedOp.fromCell(msg.call);
        let m = parseMetaOp(so.op);
        throwIf(E_RELAYER, m.relayer != null && m.relayer!! == myAddress());
        throwUnless(E_RELAY_SHAPE, (m.op == OP_REVOKE || (wallet && m.op == OP_SET_KEY)) &&
            so.responseDestination == contractAddress(executorInit(myAddress(), from, msg.salt)));
    }

    /// The payment arrives through the router's own jetton wallet of the escrow's token. Never throw: anything that is
    /// not an escrow payment is handed back to its sender.
    receive(msg: JettonNotification) {
        let body = forwardBody(msg.forwardPayload);
        if (body.bits() == 288 && body.refs() == 0 && body.preloadUint(32) == PAY_TAG) {
            body.skipBits(32);
            let key = escrowKey(msg.sender, body.loadUint(256));
            let e = self.escrows.get(key);
            if (e != null && e!!.stage == STAGE_PAYING && msg.amount == e!!.amount && sender() == walletAddress(myAddress(), e!!.master)) {
                let x = e!!;
                x.stage = STAGE_FUNDED;
                self.escrows.set(key, x);
                self.busy.del(walletAddress(x.from, x.master));
                deploy(DeployParameters {
                    init: executorInit(myAddress(), x.from, x.salt),
                    value: 0,
                    mode: SendRemainingValue,
                    bounce: false,
                    body: RelayExec { ref: x.ref, target: x.target, call: x.call, relayer: x.relayer, callMin: x.callMin, keep: execKeep() }.toCell(),
                });
                return;
            }
        }
        // A plain transfer, a payment whose escrow timed out, a foreign wallet: only a real wallet of ours moves
        // anything, and then exactly what it just received.
        if (msg.amount > 0) {
            self.keepOwn();
            self.transfer(sender(), msg.sender, msg.amount, msg.sender, 0);
        }
    }

    /// A settlement transfer our wallet refused: the escrow comes back, owed, until a RelayRefund sends it again.
    bounced(msg: bounced<JettonTransfer>) {
        let e = self.settling.get(msg.queryId);
        if (e == null || sender() != walletAddress(myAddress(), e!!.master)) {
            return;
        }
        self.settling.del(msg.queryId);
        self.escrows.set(escrowKey(e!!.from, e!!.ref), e!!);
    }

    /// The payment's SignedOp bounced at the payer wallet: nothing was escrowed.
    bounced(msg: Slice) {
        let k = self.busy.get(sender());
        if (k == null) {
            return;
        }
        self.busy.del(sender());
        let e = self.escrows.get(k!!);
        if (e != null && e!!.stage == STAGE_PAYING) {
            self.escrows.del(k!!);
            self.keepOwn();
            emit(RelayFeeRefunded { ref: e!!.ref, payer: e!!.from, relayer: e!!.relayer, amount: 0 }.toCell());
            message(MessageParameters { to: e!!.relayer, value: 0, mode: SendRemainingBalance | SendIgnoreErrors, bounce: false, body: JettonExcesses { queryId: 0 }.toCell() });
        }
    }

    receive(msg: RelayOutcome) {
        let key = escrowKey(msg.from, msg.ref);
        let e = self.escrows.get(key);
        if (e == null || e!!.stage != STAGE_FUNDED || sender() != contractAddress(executorInit(myAddress(), msg.from, e!!.salt))) {
            return; // settled already (exclusive), or not our executor
        }
        self.escrows.del(key);
        self.settle(e!!, msg.ok, e!!.relayer);
    }

    /// Anyone. A funded escrow after its deadline goes back to the payer; an unfunded entry is dropped; a settlement
    /// whose transfer bounced is sent again (any time).
    receive(msg: RelayRefund) {
        let key = escrowKey(msg.from, msg.ref);
        let e = self.escrows.get(key);
        throwUnless(E_RELAY_UNKNOWN, e != null);
        let x = e!!;
        if (x.stage == STAGE_PAYING) {
            throwUnless(E_RELAY_EARLY, now() >= x.deadline);
            self.escrows.del(key);
            let w = walletAddress(x.from, x.master);
            let b = self.busy.get(w);
            if (b != null && b!! == key) {
                self.busy.del(w);
            }
            self.keepOwn();
            emit(RelayFeeRefunded { ref: x.ref, payer: x.from, relayer: x.relayer, amount: 0 }.toCell());
            message(MessageParameters { to: sender(), value: 0, mode: SendRemainingBalance | SendIgnoreErrors, bounce: false, body: JettonExcesses { queryId: 0 }.toCell() });
            return;
        }
        throwUnless(E_RELAY_EARLY, x.stage != STAGE_FUNDED || now() >= x.deadline);
        throwUnless(E_VALUE, context().value >= settleValue());
        self.escrows.del(key);
        self.settle(x, x.stage == STAGE_RELEASE_OWED, sender());
    }

    fun settle(e: Escrow, release: Bool, response: Address) {
        self.keepOwn();
        let x = e;
        x.stage = release ? STAGE_RELEASE_OWED : STAGE_REFUND_OWED;
        self.settled += 1;
        let kept = x;
        kept.call = emptyCell(); // a restore needs no call: the ring holds only what a re-sent settlement uses (rent)
        self.settling.set(self.settled, kept);
        if (self.settled > SETTLE_RING) {
            self.settling.del(self.settled - SETTLE_RING);
        }
        if (release) {
            emit(RelayFeePaid { ref: x.ref, target: x.target, token: x.master, payer: x.from, payee: x.relayer, amount: x.amount }.toCell());
            self.transfer(walletAddress(myAddress(), x.master), x.relayer, x.amount, response, self.settled);
        } else {
            emit(RelayFeeRefunded { ref: x.ref, payer: x.from, relayer: x.relayer, amount: x.amount }.toCell());
            self.transfer(walletAddress(myAddress(), x.master), x.from, x.amount, response, self.settled);
        }
    }

    /// The router's own TON stays: what a message costs (its gas, its events, its sends) comes out of that message.
    fun keepOwn() {
        nativeReserve(myBalance() - context().value, ReserveExact);
    }

    /// A transfer out of our jetton wallet `wallet`, on what is left of the incoming message's TON (after `keepOwn`).
    fun transfer(wallet: Address, to: Address, amount: Int, response: Address, queryId: Int) {
        message(MessageParameters {
            to: wallet,
            value: 0,
            mode: SendRemainingBalance,
            bounce: true,
            body: JettonTransfer {
                queryId, amount, destination: to, responseDestination: response, customPayload: null,
                forwardTonAmount: 0, forwardPayload: emptyForwardPayload(),
            }.toCell(),
        });
    }

    get fun get_relay_ref(target: Address, call: Cell, salt: Int): Int {
        return relayRef(target, call, salt);
    }

    /// The executor of a (payer, salt): the sender the target sees, and the call's required `responseDestination`.
    get fun get_executor(from: Address, salt: Int): Address {
        return contractAddress(executorInit(myAddress(), from, salt));
    }

    get fun get_pending(from: Address, ref: Int): Escrow? {
        return self.escrows.get(escrowKey(from, ref));
    }

    /// 0 none, 1 payment in flight, 2 funded (the call is out), 3 release owed, 4 refund owed (a transfer bounced).
    get fun get_escrow_state(key: Int): Int {
        let e = self.escrows.get(key);
        return e == null ? 0 : e!!.stage + 1;
    }

    /// The least TON for this RelayCall `body` (priced from its sizes and the current config).
    get fun get_relay_value(body: Cell): Int {
        let msg = RelayCall.fromCell(body);
        return relayBudget(msg, parseMetaOp(msg.payOp).extra).value;
    }

    /// The least TON for a RelayRefund that settles a funded escrow.
    get fun get_refund_value(): Int {
        return settleValue();
    }

    /// The least TON an executor starts `call` with at `callMin` (below it, it reports a failure: refund).
    get fun get_exec_start(call: Cell, callMin: Int): Int {
        return execStart(call, callMin, execKeep());
    }

    get fun get_call_floor(): Int {
        return callFloor();
    }

    get fun get_exec_keep(): Int {
        return execKeep();
    }

    get fun get_codes(): CodeSet {
        return CodeSet { wallet: walletCodeHash(), mandate: mandateCodeHash() };
    }
}

struct CodeSet {
    wallet: Int;
    mandate: Int;
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
    digest: Int as uint256,
    acked: Bool,
    done: Bool,
    relayer: Address?,
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
        self.relayer = msg.relayer;
        self.probe = curLt();
        self.digest = msg.call.beginParse().preloadRef().hash(); // the MetaOp the served entry acknowledges
        if (context().value < execStart(msg.call, msg.callMin, msg.keep)) {
            self.done = true;
            self.report(msg.ref, false, SendRemainingValue);
            return;
        }
        let v = context().value - fwdOf(msg.call) - probeValue() - fwd1() - msg.keep; // ≥ msg.callMin
        message(MessageParameters { to: msg.target, value: v, mode: SendPayFwdFeesSeparately, bounce: true, body: msg.call });
        message(MessageParameters { to: msg.target, value: probeValue(), mode: SendPayFwdFeesSeparately, bounce: true, body: RelayProbe { queryId: self.probe }.toCell() });
    }

    /// The served entry's acknowledgment: sent in the call's own transaction, so before the probe's bounce.
    receive(msg: RelayAck) {
        if (!self.done && self.target != null && sender() == self.target!! && msg.digest == self.digest) {
            self.acked = true;
        }
    }

    /// The call's excess TON (its responseDestination is this executor) rides back with the report; one that arrives
    /// after the report (a revoke's cancel excess, back along the DEX path) goes on to the relayer.
    receive(msg: JettonExcesses) {
        self.flush();
    }

    /// Every reply of the call's transaction has arrived: released iff it acknowledged.
    bounced(msg: bounced<RelayProbe>) {
        if (!self.done && self.target != null && sender() == self.target!! && msg.queryId == self.probe) {
            self.done = true;
            self.report(self.ref, self.acked, SendRemainingBalance);
            return;
        }
        self.flush();
    }

    /// Any other bounce from the target is the call's: it failed.
    bounced(msg: Slice) {
        if (!self.done && self.target != null && sender() == self.target!!) {
            self.done = true;
            self.report(self.ref, false, SendRemainingBalance);
            return;
        }
        self.flush();
    }

    /// After the report the executor holds nothing: late TON goes to the relayer.
    fun flush() {
        if (self.done && self.relayer != null) {
            message(MessageParameters { to: self.relayer!!, value: 0, mode: SendRemainingBalance | SendIgnoreErrors, bounce: false, body: JettonExcesses { queryId: 0 }.toCell() });
        }
    }

    fun report(ref: Int, ok: Bool, mode: Int) {
        message(MessageParameters { to: self.router, value: 0, mode, bounce: false, body: RelayOutcome { from: self.from, ref, ok }.toCell() });
    }
}
