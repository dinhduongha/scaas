"""SCaaS relay-fee router on Algorand (near-algorand T15; spec §4.8, §2 rows 8–15, CTR-MTX-16 / CTR-MTX-27; rulings R2,
R3, T15 pre-flight (a)–(j)). Stateless: no box, no global or local state, no admin.

A payer pays a relayer for one call on any app (the token's own entries, `account` key ops, `mandate`, `dex`, third-party
apps) in one atomic group — no escrow, no refund, no residual (CTR-MTX-16):

    [Payment → router (optional)] [Payment → target app (optional)] [target call, sender = executor] [router.relay] …

- The target call is sent by the keyless executor LogicSig (`executor.py`), so the target never sees the lane (rule
  11); it keeps its own exact-MBR payment just before it (§2 row 15). The router's MBR payment — what the token's pay
  needs (the payer's lane box, the payee's balance box, a UA payer's record) — is the payment to the router address
  just before that block (before the target's payment when there is one, else before the target): one fixed place, a
  receiver no target payment can have (the target is never the router). The router forwards it whole to the token,
  whose own exact check makes a short or surplus payment fail the group; the router keeps nothing.
- `relay(token, op, auth)` (any lane, `Txn.Sender`): the target (`gtxn[Txn.group_index − 1]`) is a NoOp call on an
  existing app other than this router (rule 13: a `ClearState` call cannot fail, an app create is not a call), sent by
  the executor, not `add_key_native` (no key is ever registered for the executor: T12 m5); `call = target app id (u64)
  ‖ u8 n ‖ (u16 len ‖ arg)×n` of its application arguments (foreign arrays and boxes are resource references, not
  semantics: controller call), `ref = keccak256("scaas.relayfee" ‖ GenesisHash ‖ target app address ‖ keccak256(call)
  ‖ salt)` with salt = the payment op's payer-signed `extra` (§2 row 8, always); the payment op is a plain pay of that
  `ref` on `payLane(ref)` at nonce 0 with `relayer =` this app's address (the marker, rule 10: no transaction can
  sign for it, so the token's rule 7 refuses the op anywhere but here); its payee is never the executor (rule 12).
  Then the inner group `[Payment (the router's MBR payment, if any) → token] [token.mtx_pay(op, auth, open_payee =
  Txn.Sender)]`: the token checks the rest (op code, signature, POLICY_PASSKEY_FOR_VALUE, network, contract, expiry,
  lane nonce, balance) and pays `op.to`, or in open mode (`op.to == op.relayer ==` this app) the submitting lane — the
  router never holds the payment. A failing target, router or pay fails the whole group.
- Event `RelayFeePaid(ref, target app id, token app id, payer, payee, amount)` (success only: a failed group logs
  nothing). T16 books it only for configured tokens (a fake token's "pay" proves nothing).

Inner fees 0 (the lane pools them); no inner transaction rekeys or closes. No local state (OptIn refused); Update /
Delete refused (the ARC-4 router accepts neither).
"""
from algopy import (Account, Application, Bytes, Global, OnCompleteAction, OpUpFeeSource, TemplateVar, TransactionType,
                    Txn, UInt64, arc4, ensure_budget, gtxn, itxn, op, subroutine, urange)

from common import KIND_ADDRESS, MTX_PAY, Bytes32, Holder, MetaOp, pay_lane, relay_ref

ADD_KEY_NATIVE = "add_key_native((uint16,byte[]),byte[])void"  # the account app's direct (sender = the address) key add
# Ruling T12-budget: the relay raises its own opcode budget to its work (rule 13, the call bytes, three keccak256, the
# executor derivation, the inner pay's set-up; measured, limits log) by inner budget calls on the lane's pooled fee —
# the target before it may have used the whole group pool. The token's pay raises its own.
RELAY_COST = 1000


class RelayFee(arc4.ARC4Contract):
    @arc4.abimethod(create="require")
    def create(self) -> None:
        pass

    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:
        """Opcode budget / resource references for the group (700 per app call, pooled)."""

    @arc4.abimethod
    def relay(self, token: arc4.UInt64, op_: MetaOp, auth: Bytes) -> None:
        ensure_budget(RELAY_COST, OpUpFeeSource.GroupCredit)
        at = Txn.group_index - 1  # the target: fails when the relay is first in the group
        t = gtxn.ApplicationCallTransaction(at)
        target = t.app_id
        assert target.id != 0, "target app missing (rule 13)"  # an app create (app_params_get(0) is this app)
        taddr, exists = op.AppParamsGet.app_address(target)
        assert exists, "target app missing (rule 13)"
        assert target != Global.current_application_id, "target is the router"
        assert t.on_completion == OnCompleteAction.NoOp, "target call must be NoOp (rule 13)"
        exe = executor_address()
        assert t.sender == exe, "target sender is not the executor"
        assert t.num_app_args == 0 or t.app_args(0) != arc4.arc4_signature(ADD_KEY_NATIVE), \
            "add_key_native is never relayed (no key for the executor)"
        call = op.itob(target.id) + op.extract(op.itob(t.num_app_args), 7, 1)
        for i in urange(t.num_app_args):
            a = t.app_args(i)
            call += op.extract(op.itob(a.length), 6, 2) + a
        r = relay_ref(Bytes32.from_bytes(Global.genesis_hash), Bytes32.from_bytes(taddr.bytes), call, op_.extra)
        assert (op_.pay_ref == r and op_.lane == pay_lane(r) and op_.nonce.as_uint64() == 0
                and op_.relayer.bytes == Global.current_application_address.bytes), \
            "payment shape (pay_ref = ref of the target call, lane = payLane(ref), nonce 0, relayer = router)"
        assert op_.to.bytes != addr_holder(exe).bytes, "the executor is never paid"
        payee = op_.to
        if op_.to.bytes == addr_holder(Global.current_application_address).bytes:
            payee = addr_holder(Txn.sender)  # open mode: the token pays the lane that submitted this call
        fwd = router_payment(at, taddr)
        app = Application(token.as_uint64())
        pay = itxn.ApplicationCall(app_id=app, fee=0, app_args=(arc4.arc4_signature(MTX_PAY), op_.bytes,
                                                                arc4.DynamicBytes(auth).bytes, Txn.sender.bytes))
        if fwd:
            itxn.submit_txns(itxn.Payment(receiver=app.address, amount=fwd, fee=0), pay)
        else:
            pay.submit()
        arc4.emit("RelayFeePaid", r, arc4.UInt64(target.id), token, op_.from_, payee,
                  arc4.UInt256(op_.amount.as_biguint()))

    @arc4.abimethod(readonly=True)
    def relay_ref(self, call: Bytes, salt: Bytes32) -> Bytes32:
        """`ref` of `call` on this network (target = the app address of the call's first 8 bytes) with `salt`."""
        target = Bytes32.from_bytes(op.sha512_256(b"appID" + op.extract(call, 0, 8)))
        return relay_ref(Bytes32.from_bytes(Global.genesis_hash), target, call, salt)

    @arc4.abimethod(readonly=True)
    def executor(self) -> arc4.Address:
        return arc4.Address(executor_address())


@subroutine
def executor_address() -> Account:
    """The executor LogicSig of this router: `sha512_256("Program" ‖ EXEC_PREFIX ‖ itob(app id) ‖ EXEC_SUFFIX)`."""
    return Account(op.sha512_256(b"Program" + TemplateVar[Bytes]("EXEC_PREFIX")
                                 + op.itob(Global.current_application_id.id) + TemplateVar[Bytes]("EXEC_SUFFIX")))


@subroutine
def router_payment(target: UInt64, target_address: Account) -> UInt64:
    """The router's MBR payment: the payment to this app's address just before the target's own MBR payment (a payment
    to the target's address just before the target) when there is one, else just before the target; 0 when none. It
    neither closes nor rekeys (a close-out would leave the payer's rest here)."""
    at = target
    if at > 0:
        p = gtxn.Transaction(at - 1)
        if p.type == TransactionType.Payment and p.receiver == target_address:
            at -= 1
    if at > 0:
        p = gtxn.Transaction(at - 1)
        if p.type == TransactionType.Payment and p.receiver == Global.current_application_address:
            assert p.close_remainder_to == Global.zero_address and p.rekey_to == Global.zero_address, \
                "router MBR payment must not close or rekey"
            return p.amount
    return UInt64(0)


@subroutine
def addr_holder(a: Account) -> Holder:
    return Holder(arc4.UInt8(KIND_ADDRESS), Bytes32.from_bytes(a.bytes))
