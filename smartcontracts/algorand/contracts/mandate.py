"""SCaaS `mandate` app on Algorand (near-algorand T13; spec §4.7 → §3.6, README §3 item 2, CTR-ACC-06 / CTR-ACC-07;
rulings R4, R9, R11, T13 pre-flight (a)–(f); the NEAR mandate of Task 7 is the reference).

A delegate pays from funds the owner moved in, within limits checked here — per payment, per period (fixed windows on
a grid, CTR-ACC-07), one payee, an expiry, revocation, each `pay_ref` once. No pay-meta entry (metatx-split §6.2).
One-shot: a revoked (or refunded) mandate stays closed; a new one is a new open. One app per deployment serves every
token: the funds sit in each token's ledger under this app's address (R4) and move by inner token calls (sender = this
app); what each mandate holds is its own `remaining`, here.

State, keyed by (token app id, mandate id) so a token can only ever move its own funds (a fake token app passed as
`token` only reaches mandates opened with it, and only calls itself):

    "m" ‖ token u64 ‖ id            → Mandate (204 B)
    "l" ‖ sha256(token u64 ‖ id ‖ lane) → u64 1  (a paid `pay_ref`: its lane payLane(pay_ref), nonce 0, once)

Entries (op codes as every family; `contract` = this app's address; the token is bound by `extra`):

- `mtx_mandate_open(token, op, auth, terms)`, op 13 signed by the owner (`op.from`): `id = sha256(ARC-4(from, terms,
  lane, nonce))`, `to = Ua(id)`, `amount = terms.funding` (R9), `pay_ref` zero, `extra = sha256(token u64 ‖ id ‖
  terms)`. Group: `[MBR → token]? [token.mtx_pay(funding)] [MBR → mandate] [mtx_mandate_open]` — the funding is the
  owner's own `mtx_pay` of `terms.funding` to this app's address with `pay_ref = id`, read from the group (no token
  entry, A20); the open's exact-MBR payment (the mandate box, plus the payee's token balance box when new: the open
  creates it by a zero transfer, so a pay never needs MBR at the token) sits between them (§2 row 15).
- `mtx_mandate_pay(token, op, auth)`, op 2 signed by `terms.delegate` (its POLICY_PASSKEY_FOR_VALUE applies): `from =
  Ua(id)`, `to = terms.payee`, `pay_ref ≠ 0`, `lane = payLane(pay_ref)`, nonce 0, `extra = sha256(token u64)`.
- `mtx_revoke(token, op, auth)`, op 3 signed by the owner or the delegate (kill switch, no nonce): `to = Ua(id)`,
  amount, pay_ref, lane and nonce zero, `extra = sha256(token u64)`; refused once closed (no fee for a no-op). The
  remaining funds go back to the owner.
- `mandate_refund(token, id)`, anyone, after the expiry: the remaining funds back to the owner; closes the mandate.

Signers: a native address's 64-byte wallet signature here (its current authority), else the `account` app's `verify`
(fixed at creation; a delegate's record opens lazily, its MBR forwarded). Budget: the entries' own work fits the pooled
budget of their minimal group (the token / account inner calls raise their own, Ruling T12-budget; pinned in the tests). No local state (OptIn refused); Update /
Delete refused (the ARC-4 router accepts neither); no inner transaction rekeys or closes.
"""
from algopy import (Account, Application, BigUInt, Bytes, BoxMap, Global, GlobalState, TransactionType, Txn, UInt64, arc4,
                    gtxn, itxn, op, subroutine)

from common import (KIND_ADDRESS, KIND_UA, OP_MANDATE_OPEN, OP_MANDATE_PAY, OP_REVOKE, Bytes32, Holder, MetaOp,
                    account_verify, check_envelope, digest, mbr_paid, mbr_payment, pay_lane, verify_native, zero)

MANDATE_LEN = 204  # owner 33 ‖ terms 130 ‖ period_start 8 ‖ spent 16 ‖ remaining 16 ‖ revoked 1
MBR_MANDATE_BOX = 2500 + 400 * (41 + MANDATE_LEN)
MBR_LANE_BOX = 2500 + 400 * (33 + 8)
MTX_PAY = ("mtx_pay((byte[32],byte[32],uint8,(uint8,byte[32]),(uint8,byte[32]),byte[32],uint128,byte[32],byte[32],"
           "uint64,uint64,byte[32]),byte[],address)void")


class MandateTerms(arc4.Struct, frozen=True):
    """As NEAR's (Task 7), ARC-4: `delegate` signs every pay (a UA may delegate, CTR-ACC-12)."""
    delegate: Holder
    payee: Holder
    per_payment: arc4.UInt128
    per_period: arc4.UInt128
    period_s: arc4.UInt64
    expiry: arc4.UInt64   # seconds; a pay after it is refused
    funding: arc4.UInt128  # moved in at the open: equals op.amount (R9)


class Mandate(arc4.Struct, frozen=True):
    owner: Holder
    terms: MandateTerms
    period_start: arc4.UInt64
    spent: arc4.UInt128
    remaining: arc4.UInt128
    revoked: arc4.Bool  # closed: revoked, or refunded after the expiry


class MandateApp(arc4.ARC4Contract, name="Mandate"):
    def __init__(self) -> None:
        self.account_app = GlobalState(UInt64, key="account_app")
        self.mandates = BoxMap(Bytes, Mandate, key_prefix=b"m")
        self.lanes = BoxMap(Bytes32, UInt64, key_prefix=b"l")

    @arc4.abimethod(create="require")
    def create(self, account_app: arc4.UInt64) -> None:
        """`account_app`: the deployment's `account` app (fixed: no method changes it)."""
        self.account_app.value = account_app.as_uint64()

    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:
        """Opcode budget / box references for the group (700 per app call, pooled)."""

    @arc4.abimethod
    def mtx_mandate_open(self, token: arc4.UInt64, op_: MetaOp, auth: Bytes, terms: MandateTerms) -> None:
        before = Global.current_application_address.min_balance
        t = token.as_uint64()
        assert op_.op.as_uint64() == OP_MANDATE_OPEN, "wrong op code"
        assert op_.pay_ref == zero(), "mtx_mandate_open carries no pay_ref"
        assert terms.funding == op_.amount, "terms.funding must equal op.amount"
        assert (terms.period_s.as_uint64() > 0 and terms.per_payment.as_biguint() > 0
                and terms.per_payment.as_biguint() <= terms.per_period.as_biguint()), \
            "bad mandate limits (period_s > 0, 0 < per_payment <= per_period)"
        assert terms.expiry.as_uint64() > Global.latest_timestamp, "mandate expiry is past"
        assert terms.delegate.kind.as_uint64() <= KIND_UA and terms.payee.kind.as_uint64() <= KIND_UA, \
            "unknown holder kind"
        id = Bytes32.from_bytes(op.sha256(op_.from_.bytes + terms.bytes + op_.lane.bytes + op_.nonce.bytes))
        assert op_.to.bytes == ua(id).bytes, "to must be the mandate id"
        assert op_.extra.bytes == op.sha256(op.itob(t) + id.bytes + terms.bytes), \
            "extra is not sha256 of the token, the mandate id and terms"
        assert terms.payee.bytes != this().bytes, "mandate app refuses itself as payee"
        key = mkey(t, id)
        assert key not in self.mandates, "mandate exists"
        funded(t, op_.from_, id, op_.amount)
        check_envelope(op_)
        tok = rest(UInt64(MBR_MANDATE_BOX))  # → the token: the payee's new box (the funding opened the owner's record)
        acc = signed_by(self.account_app.value, op_.from_, digest(op_), auth, UInt64(0))
        self.mandates[key] = Mandate(op_.from_, terms, arc4.UInt64(Global.latest_timestamp), arc4.UInt128(0),
                                     terms.funding, arc4.Bool(False))
        send(t, terms.payee, BigUInt(0), tok)  # the payee's balance box exists from here on: a pay never needs MBR
        arc4.emit("Mandate", token, id, arc4.String("open"), op_.from_)
        mbr_paid(before, tok + acc)

    @arc4.abimethod
    def mtx_mandate_pay(self, token: arc4.UInt64, op_: MetaOp, auth: Bytes) -> None:
        before = Global.current_application_address.min_balance
        t = token.as_uint64()
        assert op_.op.as_uint64() == OP_MANDATE_PAY, "wrong op code"
        key, m = self._load(t, op_.from_)
        assert (op_.pay_ref != zero() and op_.lane == pay_lane(op_.pay_ref) and op_.nonce.as_uint64() == 0
                and op_.extra.bytes == op.sha256(op.itob(t))), \
            "mandate pay shape (pay_ref set, lane = payLane(pay_ref), nonce 0, extra = sha256(token))"
        assert not m.revoked.native, "mandate revoked"
        now = Global.latest_timestamp
        assert now <= m.terms.expiry.as_uint64(), "mandate expired"
        assert op_.to.bytes == m.terms.payee.bytes, "payee not allowed"
        amount = op_.amount.as_biguint()
        assert amount > 0, "The amount should be a positive number"
        assert amount <= m.terms.per_payment.as_biguint(), "over the per-payment cap"
        # CTR-ACC-07: fixed windows on the grid from the open, never restarted at `now`
        p = m.terms.period_s.as_uint64()
        start = m.period_start.as_uint64()
        spent = m.spent.as_biguint()
        elapsed = now - start if now > start else UInt64(0)
        if elapsed >= p:
            start += elapsed // p * p
            spent = BigUInt(0)
        # compared by subtraction: spent <= per_period always
        assert amount <= m.terms.per_period.as_biguint() - spent, "over the per-period cap"
        check_envelope(op_)
        d = digest(op_)
        fwd = signed_by(self.account_app.value, m.terms.delegate, d, auth, rest(UInt64(MBR_LANE_BOX)))
        lane = Bytes32.from_bytes(op.sha256(key + op_.lane.bytes))
        assert lane not in self.lanes, "pay_ref already paid under this mandate"
        left = m.remaining.as_biguint()
        assert left >= amount, "the mandate's balance is short"
        self.lanes[lane] = UInt64(1)
        self.mandates[key] = m._replace(period_start=arc4.UInt64(start), spent=arc4.UInt128(spent + amount),
                                        remaining=arc4.UInt128(left - amount))
        arc4.emit("MetaTransactionExecuted", op_.from_, arc4.Address(Txn.sender), op_.lane, op_.nonce, d)
        send(t, op_.to, amount, UInt64(0))
        arc4.emit("PaymentSettled", op_.from_, op_.to, arc4.UInt256(amount), op_.pay_ref)
        mbr_paid(before, fwd)

    @arc4.abimethod
    def mtx_revoke(self, token: arc4.UInt64, op_: MetaOp, auth: Bytes) -> None:
        before = Global.current_application_address.min_balance
        t = token.as_uint64()
        assert (op_.op.as_uint64() == OP_REVOKE and op_.amount.as_biguint() == 0 and op_.pay_ref == zero()
                and op_.lane == zero() and op_.nonce.as_uint64() == 0 and op_.extra.bytes == op.sha256(op.itob(t))), \
            "revoke shape (op 3, amount 0, pay_ref, lane and nonce zero, extra = sha256(token))"
        key, m = self._load(t, op_.to)
        assert op_.from_.bytes == m.owner.bytes or op_.from_.bytes == m.terms.delegate.bytes, \
            "only the owner or the delegate revokes"
        assert not m.revoked.native, "mandate revoked"
        check_envelope(op_)
        fwd = signed_by(self.account_app.value, op_.from_, digest(op_), auth, rest(UInt64(0)))
        self._close(t, key, m)
        arc4.emit("Mandate", token, op_.to.id, arc4.String("revoke"), op_.from_)
        mbr_paid(before, fwd)

    @arc4.abimethod
    def mandate_refund(self, token: arc4.UInt64, id: Bytes32) -> None:
        """Anyone, after the expiry: the remaining funds back to the owner (funds reach a mandate only at its open, so
        a revoked one has none left)."""
        t = token.as_uint64()
        key, m = self._load(t, ua(id))
        assert m.remaining.as_biguint() > 0, "nothing to refund"
        assert Global.latest_timestamp > m.terms.expiry.as_uint64(), "mandate live: no refund before the expiry"
        self._close(t, key, m)
        arc4.emit("Mandate", token, id, arc4.String("refund"), Holder(arc4.UInt8(KIND_ADDRESS),
                                                                      Bytes32.from_bytes(Txn.sender.bytes)))

    @arc4.abimethod(readonly=True)
    def mandate(self, token: arc4.UInt64, id: Bytes32) -> Mandate:
        _key, m = self._load(token.as_uint64(), ua(id))
        return m

    # ------------------------------------------------------------ internals
    @subroutine
    def _load(self, token: UInt64, h: Holder) -> tuple[Bytes, Mandate]:
        key = mkey(token, h.id)
        assert h.kind.as_uint64() == KIND_UA and key in self.mandates, "no such mandate"
        return key, self.mandates[key]

    @subroutine
    def _close(self, token: UInt64, key: Bytes, m: Mandate) -> None:
        """Closed for good; the remaining funds back to the owner (its token box exists: it funded the mandate)."""
        left = m.remaining.as_biguint()
        self.mandates[key] = m._replace(remaining=arc4.UInt128(0), revoked=arc4.Bool(True))
        if left:
            send(token, m.owner, left, UInt64(0))


@subroutine
def mkey(token: UInt64, id: Bytes32) -> Bytes:
    """State key of a mandate: (token app id, mandate id)."""
    return op.itob(token) + id.bytes


@subroutine
def ua(id: Bytes32) -> Holder:
    return Holder(arc4.UInt8(KIND_UA), id)


@subroutine
def this() -> Holder:
    return Holder(arc4.UInt8(KIND_ADDRESS), Bytes32.from_bytes(Global.current_application_address.bytes))


@subroutine
def funded(token: UInt64, owner: Holder, id: Bytes32, amount: arc4.UInt128) -> None:
    """Ruling (a): the group transaction before the open's MBR payment is `token.mtx_pay(op, …)` with op.from = the
    owner, op.to = this app's address, op.amount = terms.funding, op.pay_ref = the mandate id. The token checked that
    op's signature and moved the funds (the group is atomic)."""
    assert Txn.group_index >= 2, "funding: the token's mtx_pay must come just before the open's MBR payment"
    f = gtxn.Transaction(Txn.group_index - 2)
    assert (f.type == TransactionType.ApplicationCall and f.app_id.id == token and f.num_app_args >= 2
            and f.app_args(0) == arc4.arc4_signature(MTX_PAY)), \
        "funding: the token's mtx_pay must come just before the open's MBR payment"
    p = MetaOp.from_bytes(f.app_args(1))
    assert p.from_.bytes == owner.bytes, "funding: from must be the owner"
    assert p.to.bytes == this().bytes, "funding: to must be the mandate app"
    assert p.amount == amount, "funding: amount must equal terms.funding"
    assert p.pay_ref == id, "funding: pay_ref must be the mandate id"


@subroutine
def rest(need: UInt64) -> UInt64:
    """The MBR payment beyond `need` (this app's new boxes): forwarded to another app's exact-MBR call."""
    paid = mbr_payment()
    assert paid >= need, "MBR payment must equal the new boxes' MBR exactly"
    return paid - need


@subroutine
def signed_by(account_app: UInt64, h: Holder, d: Bytes32, auth: Bytes, forward: UInt64) -> UInt64:
    """`auth` signs `d` for `h`: a native address's 64-byte wallet signature here, else the account app's `verify`
    after `forward` µALGO (a lazy record open). Returns what was forwarded."""
    if h.kind.as_uint64() == KIND_ADDRESS and auth.length == 64:
        assert verify_native(Account(h.id.bytes), d, auth), "bad signature"
        return UInt64(0)
    account_verify(account_app, h, d, auth, forward)
    return forward


@subroutine
def send(token: UInt64, to: Holder, amount: BigUInt, forwarded: UInt64) -> None:
    """This app's token balance → `to` by an inner token call (arc200_transfer to an address, transfer_to_ua to a UA
    id), after the MBR of the receiver's new box when `forwarded` (inner fees 0: the relayer pools them)."""
    app = Application(token)
    sel = arc4.arc4_signature("arc200_transfer(address,uint256)bool")
    if to.kind.as_uint64() == KIND_UA:
        sel = arc4.arc4_signature("transfer_to_ua(byte[32],uint256)void")
    call = itxn.ApplicationCall(app_id=app, fee=0, app_args=(sel, to.id.bytes, arc4.UInt256(amount).bytes))
    if forwarded:
        itxn.submit_txns(itxn.Payment(receiver=app.address, amount=forwarded, fee=0), call)
    else:
        call.submit()
