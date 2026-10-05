// Mandate (R25 on TON): funds sit in the Mandate's own jetton wallet; a delegate key (Odoo custody, ed25519)
// signs payments within per-payment / per-period caps to listed payees until expiry; each payRef pays once.
// The owner revokes or withdraws with TON Connect-signed ops on the Mandate's own lanes.
import "./jetton";

const MANDATE_GAS: Int = ton("0.05");
// A transfer to our own wallet bounces in the next transaction; 64 in-flight payouts is far more than can be
// pending at once. ponytail: ring of 64, a bounce older than that restores nothing (the owner can still withdraw).
const INFLIGHT_RING: Int = 64;

message(0x5b0a1d10) MandatePay {
    op: Cell;
    signature: Slice as bytes64;
    responseDestination: Address;
}

struct MandateTerms {
    perPayment: Int as coins;
    perPeriod: Int as coins;
    periodSeconds: Int as uint32;
    expiresAt: Int as uint64;
}

/// What a payout took, to undo it if our wallet bounces the transfer (review L9).
struct Inflight {
    payRef: Int as uint256; // delegate pays only (0 for the owner's withdrawals)
    debited: Int as coins;
    spent: Int as coins;
    periodStart: Int as uint64;
}

struct MandateState {
    revoked: Bool;
    periodStart: Int as uint64;
    spent: Int as coins;
    balance: Int as coins;
    terms: MandateTerms;
    ownerPubkey: Int as uint256;
    delegatePubkey: Int as uint256;
}

contract Mandate(
    owner: Address,
    master: Address,
    st: MandateState,
    payees: map<Address, Bool>,
    usedRefs: map<Int as uint256, Bool>,
    lanes: map<Int as uint256, Int as uint64>,
    payouts: Int as uint64,
    inflight: map<Int as uint64, Inflight>,
) {
    receive() {} // deploy / TON top-up

    receive(msg: JettonNotification) {
        // Only deposits that arrive through the Mandate's own wallet of its token count.
        if (sender() == self.myWallet()) {
            self.st.balance += msg.amount;
        }
    }

    receive(msg: MandatePay) {
        let ctx = context();
        throwUnless(E_VALUE, ctx.value >= MANDATE_GAS * 2);
        let m = parseMetaOp(msg.op);
        checkMetaOpEnvelope(m, ctx.sender);
        throwUnless(E_OP, m.op == OP_MANDATE_PAY);
        throwUnless(E_FROM, m.from == myAddress());
        throwUnless(E_SIG, checkSignature(m.digest, msg.signature, self.st.delegatePubkey));
        throwUnless(721, !self.st.revoked);
        throwUnless(722, now() < self.st.terms.expiresAt);
        throwUnless(723, self.payees.get(m.to) == true);
        throwUnless(724, m.amount > 0 && m.amount <= self.st.terms.perPayment);
        if (now() >= self.st.periodStart + self.st.terms.periodSeconds) {
            self.st.periodStart = now();
            self.st.spent = 0;
        }
        throwUnless(725, self.st.spent + m.amount <= self.st.terms.perPeriod);
        throwUnless(E_BALANCE, self.st.balance >= m.amount);
        throwUnless(726, self.usedRefs.get(m.payRef) == null);
        self.usedRefs.set(m.payRef, true);
        self.st.spent += m.amount;
        self.payOut(m, msg.responseDestination, Inflight { payRef: m.payRef, debited: m.amount, spent: m.amount, periodStart: self.st.periodStart });
    }

    /// Owner ops: `revoke` (stops the delegate) and `pay` (withdraw to `to`), signed like any MetaOp.
    receive(msg: SignedOp) {
        let ctx = context();
        throwUnless(E_VALUE, ctx.value >= MANDATE_GAS * 2);
        let m = parseMetaOp(msg.op);
        checkMetaOpEnvelope(m, ctx.sender);
        throwUnless(E_FROM, m.from == self.owner);
        let a = msg.auth.beginParse();
        throwUnless(E_AUTH, a.loadUint(8) == AUTH_TONCONNECT);
        checkTonConnect(a, self.owner, msg.op, self.st.ownerPubkey);
        let used = self.lanes.get(m.lane);
        throwUnless(E_NONCE, (used == null ? 0 : used!!) == m.nonce);
        self.lanes.set(m.lane, m.nonce + 1);
        if (m.op == OP_REVOKE) {
            self.st.revoked = true;
            nativeReserve(max(myBalance() - ctx.value, MIN_STORAGE), ReserveAtMost);
            emit(MetaTransactionExecuted { master: self.master, from: self.owner, digest: m.digest }.toCell());
            message(MessageParameters { to: msg.responseDestination, value: 0, mode: SendRemainingBalance | SendIgnoreErrors, bounce: false, body: JettonExcesses { queryId: 0 }.toCell() });
            return;
        }
        throwUnless(E_OP, m.op == OP_PAY);
        // Not capped by the tracked balance: our wallet holds the real one and refuses more. So tokens that reached
        // the wallet without a notification (a deposit with no forward TON, a payee's bounce) stay withdrawable.
        throwUnless(E_BALANCE, m.amount > 0);
        let debited = min(m.amount, self.st.balance);
        self.payOut(m, msg.responseDestination, Inflight { payRef: 0, debited, spent: 0, periodStart: self.st.periodStart });
    }

    /// Our wallet refused a payout: undo what it took — balance, period spend, and the payRef so the same signed
    /// payment can run again (review L9).
    bounced(msg: bounced<JettonTransfer>) {
        let p = self.inflight.get(msg.queryId);
        if (p == null) {
            return;
        }
        self.inflight.del(msg.queryId);
        self.st.balance += p!!.debited;
        if (p!!.periodStart == self.st.periodStart) {
            self.st.spent -= min(p!!.spent, self.st.spent);
        }
        if (p!!.payRef != 0) {
            self.usedRefs.del(p!!.payRef);
        }
    }

    fun payOut(m: MetaOp, response: Address, undo: Inflight) {
        self.st.balance -= undo.debited;
        self.payouts += 1;
        self.inflight.set(self.payouts, undo);
        if (self.payouts > INFLIGHT_RING) {
            self.inflight.del(self.payouts - INFLIGHT_RING);
        }
        nativeReserve(max(myBalance() - context().value, MIN_STORAGE), ReserveAtMost);
        emit(MetaTransactionExecuted { master: self.master, from: m.from, digest: m.digest }.toCell());
        message(MessageParameters {
            to: self.myWallet(),
            value: 0,
            mode: SendRemainingBalance,
            bounce: true,
            body: JettonTransfer {
                queryId: self.payouts,
                amount: m.amount,
                destination: m.to,
                responseDestination: response,
                customPayload: null,
                forwardTonAmount: 0,
                forwardPayload: payTag(m.payRef),
            }.toCell(),
        });
    }

    fun myWallet(): Address {
        return walletAddress(myAddress(), self.master);
    }

    get fun get_state(): MandateState {
        return self.st;
    }

    get fun get_wallet(): Address {
        return self.myWallet();
    }
}
