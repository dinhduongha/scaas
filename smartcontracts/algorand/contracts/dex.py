"""SCaaS `dex` app on Algorand (near-algorand T14; spec §4.7, §4.1; CTR-DEX-09 / -10; README §11 item 1 (EVM shape), no
partial fill; rulings R3, T14 pre-flight (a)–(g); the NEAR DEX of Task 8 is the reference, minus its escrow: Algorand
settles both legs in one call, so nothing is held between transactions).

- `settle(order_a, op_a, auth_a, order_b, op_b, auth_b, mbr)`, any submitter: each order's `relayer` is zero or the
  submitter (`Txn.Sender`, CTR-DEX-09); the pair crosses (each buys what the other sells) and is fill-or-kill
  (`a.sell_amount ≥ b.min_buy`, `b.sell_amount ≥ a.min_buy`: each side receives the other's whole `sell_amount`). Then,
  inside this one call: the inner `mtx_trade(op, auth, order)` of each order's sell token — leg op 1 with `to = relayer
  =` this app's address, so only this app pulls it; the token checks the rest (signature, the order, its lane and
  `min_nonce`, expiries) and moves the whole `sell_amount` into this app's balance there — and each amount straight on
  to the other leg's seller (inner `arc200_transfer` to an address, `transfer_to_ua` to a UA id). Any failure fails the
  whole group: no order closes, nothing moves (ruling R3, unlike NEAR's async escrow). This app holds nothing after a
  settle and keeps no state at all.
- `mbr` = the exact MBR forwarded by an inner payment before each of the four inner token calls (leg a, leg b, the
  payout at token a, the payout at token b); each token checks its own part exactly, and the relayer's one payment just
  before `settle` equals their sum (§2 row 15: this app creates nothing itself).
- An auth too large for `settle`'s 2,048 B of arguments (a passkey msig leg) is passed empty and carried by a `carry`
  call to this app after `settle` in the same group (the first ones after it, in group order: a's first when both are
  carried; other calls may sit between, so several settles share a group, each consuming the carries that follow it);
  it is only a signature, which the token verifies.
- Event `Matched(settle_id, token_a, token_b, leg_a, leg_b)`: `settle_id = sha256(digest(op_a) ‖ digest(op_b))`, the
  two leg digests are the tokens' `OrderFilled.digest`; logged only on success (a failed group logs nothing).

Inner fees are 0 (the relayer pools them); no inner transaction rekeys or closes. No local or global state (OptIn
refused); Update / Delete refused (the ARC-4 router accepts neither).
"""
import typing

from algopy import Application, Bytes, Global, TransactionType, Txn, UInt64, arc4, gtxn, itxn, op, subroutine, urange

from common import Bytes32, MetaOp, Order, digest, mbr_paid, send, zero

MTX_TRADE = ("mtx_trade((byte[32],byte[32],uint8,(uint8,byte[32]),(uint8,byte[32]),byte[32],uint128,byte[32],byte[32],"
             "uint64,uint64,byte[32]),byte[],(uint64,uint64,uint128,uint128,byte[32],uint64))void")


class Dex(arc4.ARC4Contract):
    @arc4.abimethod(create="require")
    def create(self) -> None:
        pass

    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:
        """Opcode budget / resource references for the group (700 per app call, pooled)."""

    @arc4.abimethod
    def carry(self, auth: Bytes) -> None:
        """Holds a leg's auth for the `settle` before it in the group (see the module docstring); does nothing."""

    @arc4.abimethod
    def settle(self, order_a: Order, op_a: MetaOp, auth_a: Bytes, order_b: Order, op_b: MetaOp, auth_b: Bytes,
               mbr: arc4.StaticArray[arc4.UInt64, typing.Literal[4]]) -> None:
        before = Global.current_application_address.min_balance
        bound(order_a)
        bound(order_b)
        assert (order_a.sell_token == order_b.buy_token and order_b.sell_token == order_a.buy_token
                and order_a.sell_token != order_a.buy_token), "orders do not pair (each buys what the other sells)"
        assert (order_a.sell_amount.as_biguint() >= order_b.min_buy.as_biguint()
                and order_b.sell_amount.as_biguint() >= order_a.min_buy.as_biguint()), \
            "fill-or-kill: each side's sell_amount covers the other's min_buy"
        at = Txn.group_index + 1  # this settle's carries follow it (several settles may share a group)
        a = auth_a
        if not a:
            a, at = carried(at)
        b = auth_b
        if not b:
            b, at = carried(at)
        pull(order_a, op_a, a, mbr[0].as_uint64())
        pull(order_b, op_b, b, mbr[1].as_uint64())
        send(order_a.sell_token.as_uint64(), op_b.from_, order_a.sell_amount.as_biguint(), mbr[2].as_uint64())
        send(order_b.sell_token.as_uint64(), op_a.from_, order_b.sell_amount.as_biguint(), mbr[3].as_uint64())
        da = digest(op_a)
        db = digest(op_b)
        arc4.emit("Matched", Bytes32.from_bytes(op.sha256(da.bytes + db.bytes)), order_a.sell_token,
                  order_b.sell_token, da, db)
        mbr_paid(before, mbr[0].as_uint64() + mbr[1].as_uint64() + mbr[2].as_uint64() + mbr[3].as_uint64())


@subroutine
def bound(o: Order) -> None:
    """CTR-DEX-09: a relayer-bound order settles only when its relayer submits."""
    assert o.relayer == zero() or o.relayer.bytes == Txn.sender.bytes, "order relayer is not the submitter"


@subroutine
def carried(start: UInt64) -> tuple[Bytes, UInt64]:
    """The `byte[]` argument of the first `carry` call to this app at group index ≥ `start`, and the index after it
    (other calls may sit between: the T15 relay shape puts the router call right after `settle`)."""
    for i in urange(start, Global.group_size):
        t = gtxn.Transaction(i)
        if (t.type == TransactionType.ApplicationCall and t.app_id == Global.current_application_id
                and t.num_app_args == 2):  # this app's only 2-argument method is `carry`
            return arc4.DynamicBytes.from_bytes(t.app_args(1)).native, i + 1
    op.err("a carried auth needs a carry call to this DEX")


@subroutine
def pull(order: Order, o: MetaOp, auth: Bytes, forwarded: UInt64) -> None:
    """Inner `[Payment forwarded → token][token.mtx_trade(o, auth, order)]` on the order's sell token."""
    app = Application(order.sell_token.as_uint64())
    call = itxn.ApplicationCall(app_id=app, fee=0, app_args=(arc4.arc4_signature(MTX_TRADE), o.bytes,
                                                             arc4.DynamicBytes(auth).bytes, order.bytes))
    if forwarded:
        itxn.submit_txns(itxn.Payment(receiver=app.address, amount=forwarded, fee=0), call)
    else:
        call.submit()
