// Bamboo jetton (TEP-74) with contract-level meta-transactions in the wallet (R67, R30).
import "./common";

const MIN_STORAGE: Int = ton("0.01");
const MIN_TRANSFER_TON: Int = ton("0.02");
const MIN_SIGNED_OP_TON: Int = ton("0.05");

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
    return initOf BambooJettonWallet(owner, master, 0, 0, null, emptyMap());
}

fun walletAddress(owner: Address, master: Address): Address {
    return contractAddress(walletInit(owner, master));
}

contract BambooJettonMaster(
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

contract BambooJettonWallet(
    owner: Address,
    master: Address,
    balance: Int as coins,
    pubkey: Int as uint256,          // owner's Ed25519 key; 0 = not bound yet (R10-5)
    passkey: Cell?,                  // PasskeyRecord (R10-6)
    lanes: map<Int as uint256, Int as uint64>, // per-contract lane -> next nonce (R30, R9)
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
        nativeReserve(max(myBalance() - ctx.value, MIN_STORAGE), ReserveAtMost);
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

        let used = self.lanes.get(m.lane);
        let next = used == null ? 0 : used!!;
        if (next == m.nonce) {
            self.lanes.set(m.lane, next + 1);
        } else {
            // A revoke may name an order whose lane/nonce the order itself already consumed (the order was
            // sent): it still has to reach the DEX to release the escrow.
            throwUnless(E_NONCE, m.op == OP_REVOKE && next > m.nonce);
        }

        nativeReserve(max(myBalance() - ctx.value, MIN_STORAGE), ReserveAtMost);
        emit(MetaTransactionExecuted { master: self.master, from: self.owner, digest: m.digest }.toCell());
        if (m.op == OP_PAY) {
            self.sendOut(m.to, m.amount, 0, msg.responseDestination, msg.forwardTon, payTag(m.payRef), SendRemainingBalance);
        } else if (m.op == OP_TRADE) {
            throwUnless(E_PARAMS, msg.params != null && msg.params!!.hash() == m.extra);
            let leg = beginCell()
                .storeUint(TRADE_TAG, 32)
                .storeRef(msg.op)
                .storeRef(msg.params!!)
                .storeUint(msg.matchWith, 256)
                .endCell();
            self.sendOut(m.to, m.amount, 0, msg.responseDestination, msg.forwardTon,
                         beginCell().storeBit(true).storeRef(leg).asSlice(), SendRemainingBalance);
        } else if (m.op == OP_REVOKE) {
            message(MessageParameters {
                to: m.to,
                value: 0,
                mode: SendRemainingBalance,
                bounce: false,
                body: CancelOrder { orderHash: m.extra, owner: self.owner, master: self.master }.toCell(),
            });
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
            message(MessageParameters {
                to: msg.responseDestination,
                value: 0,
                mode: SendRemainingBalance | SendIgnoreErrors,
                bounce: false,
                body: JettonExcesses { queryId: 0 }.toCell(),
            });
        } else {
            throw(E_OP);
        }
    }

    fun sendOut(to: Address, amount: Int, queryId: Int, response: Address?, forwardTon: Int, payload: Slice, mode: Int) {
        throwUnless(E_BALANCE, amount > 0 && self.balance >= amount);
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
        let n = self.lanes.get(lane);
        return n == null ? 0 : n!!;
    }

    get fun get_owner_pubkey(): Int {
        return self.pubkey;
    }

    get fun get_passkey(): Cell? {
        return self.passkey;
    }
}
