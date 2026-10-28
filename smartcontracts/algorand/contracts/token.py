"""SCaaS token on Algorand (near-algorand T11; spec §2, §4.1, §4.2, §4.4–§4.6, §4.9).

An app-held ARC-200 ledger in boxes (not an ASA): `"b" ‖ address` → uint256 (native holders), `"u" ‖ UA id` → uint256,
lanes `"l" ‖ sha256(kind ‖ holder ‖ lane)` → uint64 next nonce, allowances `"a" ‖ sha256(owner ‖ spender)` → uint256;
every name 33 bytes, prefixes disjoint; nothing is ever deleted. Each call that creates boxes is preceded in its group
by a payment to the app address of exactly their MBR (§2 row 15: the app's `AcctMinBalance` after minus before; no
payment when nothing is created). No local state (OptIn refused); Update / Delete refused (the ARC-4 router accepts
neither). Supply ≤ 2^128 − 1, so every balance fits the `MetaOp` uint128 amount.

UA balances: the token's own address is the UA pool in ARC-200 terms (`arc200_balanceOf(app) =` the UA total, a move
with a UA side shows as an `arc200_Transfer` to / from it, plus `UaTransfer`), as NEAR's token account. UA signers are
verified by the `account` app (T12); this task signs natively only.
"""
import typing

from algopy import (Account, BigUInt, Bytes, BoxMap, FixedBytes, Global, GlobalState, TransactionType, Txn, UInt64,
                    arc4, gtxn, op, subroutine)

from common import (KIND_ADDRESS, KIND_UA, OP_EXECUTE_TRANSFER, OP_PAY, OP_TRANSFER, Bytes32, Holder, MetaOp, digest, lane_key,
                    meta_pay_id, pay_lane, verify_native)

Bytes8 = FixedBytes[typing.Literal[8]]
U128_MAX = 2**128 - 1
BOX_FLAT = 2500  # protocol box MBR: 2,500 + 400 per name + value byte (µALGO)
BOX_BYTE = 400
MBR_AMOUNT_BOX = BOX_FLAT + BOX_BYTE * (33 + 32)  # "b" / "u" / "a" boxes
MBR_LANE_BOX = BOX_FLAT + BOX_BYTE * (33 + 8)


class Token(arc4.ARC4Contract):
    def __init__(self) -> None:
        self.name = GlobalState(Bytes32, key="name")
        self.symbol = GlobalState(Bytes8, key="symbol")
        self.decimals = GlobalState(UInt64, key="decimals")
        self.admin = GlobalState(Account, key="admin")
        self.supply = GlobalState(BigUInt, key="supply")
        self.ua_total = GlobalState(BigUInt, key="ua_total")
        self.balances = BoxMap(Account, arc4.UInt256, key_prefix=b"b")
        self.ua = BoxMap(Bytes32, arc4.UInt256, key_prefix=b"u")
        self.lanes = BoxMap(Bytes32, UInt64, key_prefix=b"l")
        self.allowances = BoxMap(Bytes32, arc4.UInt256, key_prefix=b"a")

    @arc4.abimethod(create="require")
    def create(self, name: Bytes32, symbol: Bytes8, decimals: arc4.UInt8, admin: Account) -> None:
        self.name.value = name
        self.symbol.value = symbol
        self.decimals.value = decimals.as_uint64()
        self.admin.value = admin
        self.supply.value = BigUInt(0)
        self.ua_total.value = BigUInt(0)

    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:
        """Opcode budget for the group (700 per app call, pooled); the relayer adds these as simulate reports."""

    # ------------------------------------------------------------ ARC-200
    @arc4.abimethod(readonly=True)
    def arc200_name(self) -> Bytes32:
        return self.name.value

    @arc4.abimethod(readonly=True)
    def arc200_symbol(self) -> Bytes8:
        return self.symbol.value

    @arc4.abimethod(readonly=True)
    def arc200_decimals(self) -> arc4.UInt8:
        return arc4.UInt8(self.decimals.value)

    @arc4.abimethod(readonly=True)
    def arc200_totalSupply(self) -> arc4.UInt256:
        return arc4.UInt256(self.supply.value)

    @arc4.abimethod(readonly=True)
    def arc200_balanceOf(self, owner: Account) -> arc4.UInt256:
        if owner == Global.current_application_address:
            return arc4.UInt256(self.ua_total.value)
        return self.balances.get(owner, default=arc4.UInt256(0))

    @arc4.abimethod(readonly=True)
    def arc200_allowance(self, owner: Account, spender: Account) -> arc4.UInt256:
        return self.allowances.get(allowance_key(owner, spender), default=arc4.UInt256(0))

    @arc4.abimethod
    def arc200_transfer(self, to: Account, value: arc4.UInt256) -> bool:
        before = Global.current_application_address.min_balance
        self._move(addr_holder(Txn.sender), addr_holder(to), value.as_biguint())
        mbr_paid(before)
        return True

    @arc4.abimethod
    def arc200_transferFrom(self, owner: Account, to: Account, value: arc4.UInt256) -> bool:
        """CTR-TOK-01: only an app spends an allowance (the sender is the calling app's own address)."""
        before = Global.current_application_address.min_balance
        assert called_by_app(), "transferFrom: only an app (CTR-TOK-01)"
        key = allowance_key(owner, Txn.sender)
        left = self.allowances.get(key, default=arc4.UInt256(0)).as_biguint()
        assert left >= value.as_biguint(), "allowance exceeded"
        if key in self.allowances:
            self.allowances[key] = arc4.UInt256(left - value.as_biguint())
        self._move(addr_holder(owner), addr_holder(to), value.as_biguint())
        mbr_paid(before)
        return True

    @arc4.abimethod
    def arc200_approve(self, spender: Account, value: arc4.UInt256) -> bool:
        """CTR-TOK-01 / README principle 4: an app approves an app. The spender's app id is the call's first foreign
        app (`Txn.applications(1)`), whose address must equal `spender` (an address alone cannot show it is an app's)."""
        before = Global.current_application_address.min_balance
        assert called_by_app(), "approve: only an app (CTR-TOK-01)"
        assert Txn.num_applications >= 1 and Txn.applications(1).address == spender, "approve: spender must be an app"
        self.allowances[allowance_key(Txn.sender, spender)] = value
        arc4.emit("arc200_Approval", arc4.Address(Txn.sender), arc4.Address(spender), value)
        mbr_paid(before)
        return True

    # ------------------------------------------------------------ admin, UA ledger
    @arc4.abimethod
    def mint(self, to: Account, amount: arc4.UInt256) -> None:
        before = Global.current_application_address.min_balance
        assert Txn.sender == self.admin.value, "mint: admin only"
        supply = self.supply.value + amount.as_biguint()
        assert supply <= U128_MAX, "mint: supply above 2^128 - 1"
        self.supply.value = supply
        self._credit(addr_holder(to), amount.as_biguint())
        arc4.emit("arc200_Transfer", arc4.Address(Global.zero_address), arc4.Address(to), amount)
        mbr_paid(before)

    @arc4.abimethod
    def transfer_to_ua(self, id: Bytes32, amount: arc4.UInt256) -> None:
        """The sender's native balance → UA `id` (NEAR `transfer_to_ua`, EVM `transferToUA`)."""
        before = Global.current_application_address.min_balance
        self._move(addr_holder(Txn.sender), Holder(arc4.UInt8(KIND_UA), id), amount.as_biguint())
        mbr_paid(before)

    @arc4.abimethod(readonly=True)
    def ua_balance_of(self, id: Bytes32) -> arc4.UInt256:
        return self.ua.get(id, default=arc4.UInt256(0))

    # ------------------------------------------------------------ signed entries (§3.4 names, op codes)
    @arc4.abimethod
    def mtx_pay(self, op: MetaOp, auth: Bytes, open_payee: Account) -> None:
        """Op 0 with a pay_ref. Open mode (CTR-MTX-27 step 5): when the caller is an app and `op.to == op.relayer ==`
        its address (the router), `open_payee` (the relayer that submitted the outer group) is paid; else `op.to`."""
        before = Global.current_application_address.min_balance
        payee = op.to
        if (called_by_app() and op.to.kind.as_uint64() == KIND_ADDRESS and op.to.id == op.relayer
                and op.relayer.bytes == Txn.sender.bytes):
            payee = addr_holder(open_payee)
        self._value(op, auth, UInt64(OP_PAY), payee)
        mbr_paid(before)

    @arc4.abimethod
    def mtx_pay_meta(self, op: MetaOp, auth: Bytes, salt: Bytes32, meta: Bytes) -> None:
        """CTR-MTX-26: the plain pay of `pay_ref = metaPayId(salt, meta)` on `payLane(pay_ref)` at nonce 0; `meta`
        never parsed, logged in `PaymentMeta` before `PaymentSettled`."""
        before = Global.current_application_address.min_balance
        assert (op.pay_ref == meta_pay_id(salt, meta) and op.lane == pay_lane(op.pay_ref)
                and op.nonce.as_uint64() == 0), "pay-meta shape (pay_ref = metaPayId(salt, meta), lane = payLane, nonce 0)"
        arc4.emit("PaymentMeta", op.pay_ref, arc4.DynamicBytes(meta))
        self._value(op, auth, UInt64(OP_PAY), op.to)
        mbr_paid(before)

    @arc4.abimethod
    def mtx_transfer(self, op: MetaOp, auth: Bytes) -> None:
        before = Global.current_application_address.min_balance
        self._value(op, auth, UInt64(OP_TRANSFER), op.to)
        mbr_paid(before)

    @arc4.abimethod
    def mtx_execute_transfer(self, op: MetaOp, auth: Bytes) -> None:
        before = Global.current_application_address.min_balance
        self._value(op, auth, UInt64(OP_EXECUTE_TRANSFER), op.to)
        mbr_paid(before)

    @arc4.abimethod(readonly=True)
    def mbr_needed(self, op: MetaOp) -> UInt64:
        """The exact payment a value entry of `op` needs: its new lane box and `op.to`'s new balance box (for an
        open-mode pay ask with `to` = the open payee)."""
        need = UInt64(0)
        if lane_key(op.from_, op.lane) not in self.lanes:
            need += MBR_LANE_BOX
        if not self._exists(op.to):
            need += MBR_AMOUNT_BOX
        return need

    @arc4.abimethod(readonly=True)
    def lane_nonce(self, kind: arc4.UInt8, holder: Bytes32, lane: Bytes32) -> UInt64:
        return self.lanes.get(lane_key(Holder(kind, holder), lane), default=UInt64(0))

    # ------------------------------------------------------------ internals
    @subroutine
    def _value(self, o: MetaOp, auth: Bytes, code: UInt64, payee: Holder) -> None:
        """Every value entry: op code and pay_ref rule, the signed op (rules 1, 2, 7; §4.6), the payee (rule 12),
        the payer's lane at `nonce` (rule 6), the move, then MetaTransactionExecuted and (pay_ref ≠ 0) PaymentSettled."""
        assert o.op.as_uint64() == code, "wrong op code"
        if code == OP_PAY:
            assert o.pay_ref != zero(), "mtx_pay needs a pay_ref"
        if code == OP_TRANSFER:
            assert o.pay_ref == zero(), "mtx_transfer carries no pay_ref"
        assert o.network.bytes == Global.genesis_hash, "wrong network"
        assert o.contract.bytes == Global.current_application_address.bytes, "wrong contract"
        assert Global.latest_timestamp <= o.valid_until.as_uint64(), "expired"
        assert o.relayer == zero() or o.relayer.bytes == Txn.sender.bytes, "relayer is not the sender"
        assert o.from_.kind.as_uint64() == KIND_ADDRESS, "UA signer: verified by the account app (T12)"
        d = digest(o)
        assert verify_native(Account(o.from_.id.bytes), d, auth), "bad signature"
        assert o.amount.as_biguint() > 0, "The amount should be a positive number"
        assert o.from_.bytes != payee.bytes, "Sender and receiver should be different"
        key = lane_key(o.from_, o.lane)
        nonce = self.lanes.get(key, default=UInt64(0))
        assert nonce == o.nonce.as_uint64(), "wrong lane nonce"
        self.lanes[key] = nonce + 1
        arc4.emit("MetaTransactionExecuted", o.from_, arc4.Address(Txn.sender), o.lane, o.nonce, d)
        self._move(o.from_, payee, o.amount.as_biguint())
        if o.pay_ref != zero():
            arc4.emit("PaymentSettled", o.from_, payee, arc4.UInt256(o.amount.as_biguint()), o.pay_ref)

    @subroutine
    def _exists(self, h: Holder) -> bool:
        if h.kind.as_uint64() == KIND_ADDRESS:
            return Account(h.id.bytes) in self.balances
        return h.id in self.ua

    @subroutine
    def _credit(self, h: Holder, amount: BigUInt) -> None:
        if h.kind.as_uint64() == KIND_ADDRESS:
            a = Account(h.id.bytes)
            assert a != Global.current_application_address, "token refuses a transfer to the token itself"
            self.balances[a] = arc4.UInt256(self.balances.get(a, default=arc4.UInt256(0)).as_biguint() + amount)
        else:
            assert h.kind.as_uint64() == KIND_UA, "unknown holder kind"
            self.ua[h.id] = arc4.UInt256(self.ua.get(h.id, default=arc4.UInt256(0)).as_biguint() + amount)
            self.ua_total.value += amount

    @subroutine
    def _move(self, frm: Holder, to: Holder, amount: BigUInt) -> None:
        """Debit, credit, events: `arc200_Transfer` between the native views (a UA side shows as the app address),
        `UaTransfer` when a side is a UA."""
        if frm.kind.as_uint64() == KIND_ADDRESS:
            a = Account(frm.id.bytes)
            have = self.balances.get(a, default=arc4.UInt256(0)).as_biguint()
            assert have >= amount, "insufficient balance"
            self.balances[a] = arc4.UInt256(have - amount)
        else:
            have = self.ua.get(frm.id, default=arc4.UInt256(0)).as_biguint()
            assert have >= amount, "insufficient balance"
            self.ua[frm.id] = arc4.UInt256(have - amount)
            self.ua_total.value -= amount
        self._credit(to, amount)
        old, new = native_view(frm), native_view(to)
        if old != new:
            arc4.emit("arc200_Transfer", arc4.Address(old), arc4.Address(new), arc4.UInt256(amount))
        if frm.kind.as_uint64() == KIND_UA or to.kind.as_uint64() == KIND_UA:
            arc4.emit("UaTransfer", frm, to, arc4.UInt256(amount))


@subroutine
def mbr_paid(before: UInt64) -> None:
    """§2 row 15: the group transaction just before this call is a payment to the app address of exactly the MBR
    this call added (the app's AcctMinBalance after minus `before`), and there is none when it added nothing."""
    need = Global.current_application_address.min_balance - before
    paid = UInt64(0)
    has = False
    if Txn.group_index > 0:
        p = gtxn.Transaction(Txn.group_index - 1)
        if p.type == TransactionType.Payment and p.receiver == Global.current_application_address:
            has = True
            paid = p.amount
    assert has == (need > 0) and paid == need, "MBR payment must equal the new boxes' MBR exactly"


@subroutine
def called_by_app() -> bool:
    """An inner call whose sender is the calling app's own address (not an account rekeyed to that app)."""
    return Global.caller_application_id != 0 and Txn.sender == Global.caller_application_address


@subroutine
def addr_holder(a: Account) -> Holder:
    return Holder(arc4.UInt8(KIND_ADDRESS), Bytes32.from_bytes(a.bytes))


@subroutine
def native_view(h: Holder) -> Account:
    return Account(h.id.bytes) if h.kind.as_uint64() == KIND_ADDRESS else Global.current_application_address


@subroutine
def allowance_key(owner: Account, spender: Account) -> Bytes32:
    return Bytes32.from_bytes(op.sha256(owner.bytes + spender.bytes))


@subroutine
def zero() -> Bytes32:
    return Bytes32.from_bytes(op.bzero(32))
