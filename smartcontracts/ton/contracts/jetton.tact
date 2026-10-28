// SCaaS jetton (TEP-74) with contract-level meta-transactions in the wallet (R67, R30).
import "./common";

const MIN_STORAGE: Int = ton("0.01");
const MIN_TRANSFER_TON: Int = ton("0.02");
const MIN_SIGNED_OP_TON: Int = ton("0.05");
// Storage kept per replay entry (~0.00015 TON per entry-year at basechain prices): an idle wallet that once ran
// many ops is never frozen for rent (review M4). ponytail: a fixed per-entry reserve, ~13 idle years.
const LANE_RESERVE: Int = ton("0.002");
// Floors under the signed ones: a DEX leg and a cancel must carry enough TON for the DEX to act or refund.
const MIN_LEG_TON: Int = ton("0.1");
const CANCEL_TON: Int = ton("0.1");

struct JettonData {
    totalSupply: Int;
    mintable: Bool;
    adminAddress: Address;
    jettonContent: Cell;
    jettonWalletCode: Cell;
}

struct JettonWalletData {
    balance: Int;
    owner: Address;
    master: Address;
    code: Cell;
}

/// StateInit of `owner`'s wallet for `master`: the single derivation every party uses (master, sibling
/// wallets, DEX, Mandate, Odoo, relayer). Changing the wallet's parameters changes every address.
fun walletInit(owner: Address, master: Address): StateInit {
    return initOf ScaasJettonWallet(owner, master, 0, 0, null, emptyMap(), emptyMap(), 0, 0, 0);
}

fun walletAddress(owner: Address, master: Address): Address {
    return contractAddress(walletInit(owner, master));
}

contract ScaasJettonMaster(
    admin: Address,
    totalSupply: Int as coins,
    content: Cell,
) {
    receive(msg: Mint) {
        throwUnless(E_SENDER, sender() == self.admin);
        self.totalSupply += msg.amount;
        let init = walletInit(msg.to, myAddress());
        deploy(DeployParameters {
            init,
            value: 0,
            mode: SendRemainingValue,
            bounce: true,
            body: JettonTransferInternal {
                queryId: msg.queryId,
                amount: msg.amount,
                sender: myAddress(),
                responseDestination: msg.responseDestination,
                forwardTonAmount: 0,
                forwardPayload: emptyForwardPayload(),
            }.toCell(),
        });
    }

    receive(msg: JettonBurnNotification) {
        throwUnless(E_SENDER, sender() == walletAddress(msg.sender, myAddress()));
        self.totalSupply -= msg.amount;
        if (msg.responseDestination != null) {
            message(MessageParameters {
                to: msg.responseDestination!!,
                value: 0,
                mode: SendRemainingValue | SendIgnoreErrors,
                bounce: false,
                body: JettonExcesses { queryId: msg.queryId }.toCell(),
            });
        }
    }

    receive(msg: ProvideWalletAddress) {
        let owner: Cell? = msg.includeAddress ? beginCell().storeAddress(msg.ownerAddress).endCell() : null;
        message(MessageParameters {
            to: sender(),
            value: 0,
            mode: SendRemainingValue,
            bounce: false,
            body: TakeWalletAddress {
                queryId: msg.queryId,
                walletAddress: walletAddress(msg.ownerAddress, myAddress()),
                ownerAddress: owner,
            }.toCell(),
        });
    }

    bounced(msg: bounced<JettonTransferInternal>) {
        self.totalSupply -= msg.amount;
    }

    get fun get_jetton_data(): JettonData {
        return JettonData {
            totalSupply: self.totalSupply,
            mintable: true,
            adminAddress: self.admin,
            jettonContent: self.content,
            jettonWalletCode: walletInit(myAddress(), myAddress()).code,
        };
    }

    get fun get_wallet_address(owner: Address): Address {
        return walletAddress(owner, myAddress());
    }
}

contract ScaasJettonWallet(
    owner: Address,
    master: Address,
    balance: Int as coins,
    pubkey: Int as uint256,          // owner's Ed25519 key; 0 = not bound yet (R10-5)
    passkey: Cell?,                  // PasskeyRecord (R10-6)
    // Per-contract lane -> next nonce (R30, R9), in two generations rotated every LANE_TTL (review M4): an entry
    // written at t is kept until >= t + LANE_TTL, and no MetaOp executed at t is valid past t + LANE_TTL, so a
    // dropped entry can never be replayed. A lane unused for two windows starts again at nonce 0.
    lanes: map<Int as uint256, Int as uint64>,
    oldLanes: map<Int as uint256, Int as uint64>,
    rotatedAt: Int as uint32,
    laneCount: Int as uint32,
    oldCount: Int as uint32,
) {
    // ---------------------------------------------------------------- TEP-74

    receive(msg: JettonTransfer) {
        throwUnless(E_SENDER, sender() == self.owner);
        throwUnless(E_VALUE, context().value > msg.forwardTonAmount + MIN_TRANSFER_TON);
        self.sendOut(msg.destination, msg.amount, msg.queryId, msg.responseDestination,
                     msg.forwardTonAmount, msg.forwardPayload, SendRemainingValue);
    }

    receive(msg: JettonTransferInternal) {
        let ctx = context();
        if (ctx.sender != self.master) {
            throwUnless(E_SENDER, ctx.sender == walletAddress(msg.sender, self.master));
        }
        self.balance += msg.amount;
        nativeReserve(max(myBalance() - ctx.value, self.storageReserve()), ReserveAtMost);
        let body = forwardBody(msg.forwardPayload);
        if (body.bits() == 288 && body.refs() == 0 && body.preloadUint(32) == PAY_TAG) {
            let b = body;
            b.skipBits(32);
            emit(PaymentSettled { from: msg.sender, to: self.owner, amount: msg.amount, payRef: b.loadUint(256) }.toCell());
        }
        if (msg.forwardTonAmount > 0) {
            message(MessageParameters {
                to: self.owner,
                value: msg.forwardTonAmount,
                mode: SendPayFwdFeesSeparately,
                bounce: false,
                body: JettonNotification {
                    queryId: msg.queryId,
                    amount: msg.amount,
                    sender: msg.sender,
                    forwardPayload: msg.forwardPayload,
                }.toCell(),
            });
        }
        if (msg.responseDestination != null) {
            message(MessageParameters {
                to: msg.responseDestination!!,
                value: 0,
                mode: SendRemainingBalance | SendIgnoreErrors,
                bounce: false,
                body: JettonExcesses { queryId: msg.queryId }.toCell(),
            });
        }
    }

    receive(msg: JettonBurn) {
        throwUnless(E_SENDER, sender() == self.owner);
        throwUnless(E_BALANCE, msg.amount > 0 && self.balance >= msg.amount);
        self.balance -= msg.amount;
        message(MessageParameters {
            to: self.master,
            value: 0,
            mode: SendRemainingValue,
            bounce: true,
            body: JettonBurnNotification {
                queryId: msg.queryId,
                amount: msg.amount,
                sender: self.owner,
                responseDestination: msg.responseDestination,
            }.toCell(),
        });
    }

    bounced(msg: bounced<JettonTransferInternal>) {
        self.balance += msg.amount;
    }

    bounced(msg: bounced<JettonBurnNotification>) {
        self.balance += msg.amount;
    }

    // ---------------------------------------------------------------- meta-tx (R30)

    receive(msg: SignedOp) {
        let ctx = context();
        throwUnless(E_VALUE, ctx.value >= MIN_SIGNED_OP_TON + msg.forwardTon);
        let m = parseMetaOp(msg.op);
        checkMetaOpEnvelope(m, ctx.sender);
        throwUnless(E_TTL, m.validUntil <= now() + LANE_TTL);
        throwUnless(E_FROM, m.from == self.owner);
        if (self.pubkey == 0) {
            throwUnless(E_NO_KEY, msg.stateInit != null);
            self.pubkey = pubkeyFromStateInit(self.owner, msg.stateInit!!);
        }
        let a = msg.auth.beginParse();
        let kind = a.loadUint(8);
        if (kind == AUTH_TONCONNECT) {
            checkTonConnect(a, self.owner, msg.op, self.pubkey);
        } else if (kind == AUTH_PASSKEY) {
            throwUnless(E_NO_KEY, self.passkey != null);
            throwUnless(E_AUTH, m.op != OP_SET_KEY); // a passkey cannot rotate keys on its own
            checkPasskey(a, self.passkey!!, m.digest);
        } else {
            throw(E_AUTH);
        }

        self.rotateLanes();
        let next = self.laneNext(m.lane);
        // A revoke may name an order that already left this wallet (its nonce is spent): it takes the next nonce.
        // Both forms leave the lane at nonce + 2 (NET-TON-18): the first form also spends the second form's slot, so a
        // resend of the same signed revoke is refused (E_NONCE) and never sends a cancel (review L11; T16 fix 2).
        throwUnless(E_NONCE, next == m.nonce || (m.op == OP_REVOKE && next == m.nonce + 1));
        self.setLane(m.lane, m.op == OP_REVOKE ? m.nonce + 2 : next + 1);

        nativeReserve(max(myBalance() - ctx.value, self.storageReserve()), ReserveAtMost);
        emit(MetaTransactionExecuted { master: self.master, from: self.owner, digest: m.digest }.toCell());
        if (m.op == OP_PAY) {
            throwUnless(E_VALUE, msg.forwardTon >= m.extra);
            throwUnless(E_BALANCE, m.amount > 0);
            if (msg.params != null) {
                // CTR-MTX-26 pay-meta: `params = salt:uint256 ^meta`; the signed payRef commits to (salt, meta), and
                // lane payLane(payRef) at nonce 0 pays a (payer, payId) at most once (this wallet is the payer's).
                let p = msg.params!!.beginParse();
                let salt = p.loadUint(256);
                let meta = p.loadRef();
                p.endParse();
                throwUnless(E_PARAMS, m.payRef == metaPayId(salt, meta) && m.lane == payLane(m.payRef) && m.nonce == 0);
                requireSnake(meta);
                emit(PaymentMeta { master: self.master, payId: m.payRef, meta }.toCell());
            }
            self.sendOut(m.to, m.amount, 0, msg.responseDestination, msg.forwardTon, payTag(m.payRef), SendRemainingBalance);
        } else if (m.op == OP_TRADE) {
            throwUnless(E_PARAMS, msg.params != null && msg.params!!.hash() == m.extra);
            throwUnless(E_VALUE, msg.forwardTon >= max(parseTradeParams(msg.params!!).forwardTon, MIN_LEG_TON));
            throwUnless(E_BALANCE, m.amount > 0);
            let leg = beginCell()
                .storeUint(TRADE_TAG, 32)
                .storeRef(msg.op)
                .storeRef(msg.params!!)
                .storeUint(msg.matchWith, 256)
                .endCell();
            self.sendOut(m.to, m.amount, 0, msg.responseDestination, msg.forwardTon,
                         beginCell().storeBit(true).storeRef(leg).asSlice(), SendRemainingBalance);
        } else if (m.op == OP_REVOKE) {
            relayAck(ctx.sender, m.digest);
            if (next == m.nonce) {
                // The order never left this wallet and now never will: spending its nonce is the whole cancel.
                self.excessTo(msg.responseDestination);
            } else {
                throwUnless(E_VALUE, msg.forwardTon >= CANCEL_TON);
                self.sendOut(m.to, 0, 0, msg.responseDestination, msg.forwardTon,
                             beginCell().storeBit(true).storeRef(beginCell().storeUint(CANCEL_TAG, 32).storeUint(m.extra, 256).endCell()).asSlice(),
                             SendRemainingBalance);
            }
        } else if (m.op == OP_SET_KEY) {
            if (m.extra == 0) {
                self.passkey = null;
            } else {
                throwUnless(E_PARAMS, msg.params != null && msg.params!!.hash() == m.extra);
                let rec = msg.params!!.beginParse();
                rec.skipBits(264 + 256);
                rec.skipRef();
                rec.endParse();
                self.passkey = msg.params;
            }
            relayAck(ctx.sender, m.digest);
            self.excessTo(msg.responseDestination);
        } else {
            throw(E_OP);
        }
    }

    fun storageReserve(): Int {
        return MIN_STORAGE + (self.laneCount + self.oldCount) * LANE_RESERVE;
    }

    fun excessTo(to: Address) {
        message(MessageParameters {
            to,
            value: 0,
            mode: SendRemainingBalance | SendIgnoreErrors,
            bounce: false,
            body: JettonExcesses { queryId: 0 }.toCell(),
        });
    }

    fun rotateLanes() {
        if (now() < self.rotatedAt + LANE_TTL) {
            return;
        }
        if (now() < self.rotatedAt + 2 * LANE_TTL) {
            self.oldLanes = self.lanes;
            self.oldCount = self.laneCount;
        } else {
            self.oldLanes = emptyMap(); // the current generation was written before rotatedAt + LANE_TTL
            self.oldCount = 0;
        }
        self.lanes = emptyMap();
        self.laneCount = 0;
        self.rotatedAt = now();
    }

    /// Next nonce of `lane` as the rotation at `now()` would leave it (the getter answers without rotating).
    fun laneNext(lane: Int): Int {
        if (now() >= self.rotatedAt + 2 * LANE_TTL) {
            return 0;
        }
        let n = self.lanes.get(lane);
        if (n != null) {
            return n!!;
        }
        if (now() >= self.rotatedAt + LANE_TTL) {
            return 0;
        }
        let o = self.oldLanes.get(lane);
        return o == null ? 0 : o!!;
    }

    fun setLane(lane: Int, next: Int) {
        if (self.lanes.get(lane) == null) {
            self.laneCount += 1;
            if (self.oldLanes.exists(lane)) {
                self.oldLanes.del(lane);
                self.oldCount -= 1;
            }
        }
        self.lanes.set(lane, next);
    }

    fun sendOut(to: Address, amount: Int, queryId: Int, response: Address?, forwardTon: Int, payload: Slice, mode: Int) {
        throwUnless(E_BALANCE, amount >= 0 && self.balance >= amount);
        self.balance -= amount;
        deploy(DeployParameters {
            init: walletInit(to, self.master),
            value: 0,
            mode,
            bounce: true,
            body: JettonTransferInternal {
                queryId,
                amount,
                sender: self.owner,
                responseDestination: response,
                forwardTonAmount: forwardTon,
                forwardPayload: payload,
            }.toCell(),
        });
    }

    // ---------------------------------------------------------------- getters

    get fun get_wallet_data(): JettonWalletData {
        return JettonWalletData { balance: self.balance, owner: self.owner, master: self.master, code: myCode() };
    }

    get fun get_lane_nonce(lane: Int): Int {
        return self.laneNext(lane);
    }

    get fun get_owner_pubkey(): Int {
        return self.pubkey;
    }

    get fun get_passkey(): Cell? {
        return self.passkey;
    }

    get fun get_meta_pay_id(salt: Int, meta: Cell): Int {
        return metaPayId(salt, meta);
    }

    get fun get_pay_lane(p: Int): Int {
        return payLane(p);
    }
}
