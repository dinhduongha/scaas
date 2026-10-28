"""Test-only app (never deployed; not in artifacts.json): exposes `common.py`'s derivations on the AVM for the vector
tests, and calls the token as an app (inner transactions) for the app-only paths (approve / transferFrom, the open-mode
payee of `mtx_pay`). Inner fees are 0 (the outer group pays by fee pooling); MBR forwards come from its own balance.
"""
from algopy import Account, Application, Bytes, UInt64, arc4, itxn

from common import Bytes32, MetaOp, Order, digest, meta_pay_id, pay_lane, relay_ref, sign_bytes, verify_native


class Probe(arc4.ARC4Contract):
    @arc4.abimethod(readonly=True)
    def op_digest(self, o: MetaOp) -> Bytes32:
        return digest(o)

    @arc4.abimethod(readonly=True)
    def op_sign_bytes(self, d: Bytes32) -> Bytes:
        return sign_bytes(d)

    @arc4.abimethod(readonly=True)
    def native_ok(self, a: Account, d: Bytes32, sig: Bytes) -> bool:
        return verify_native(a, d, sig)

    @arc4.abimethod(readonly=True)
    def pay_id(self, salt: Bytes32, meta: Bytes) -> Bytes32:
        return meta_pay_id(salt, meta)

    @arc4.abimethod(readonly=True)
    def lane_of(self, pay_ref: Bytes32) -> Bytes32:
        return pay_lane(pay_ref)

    @arc4.abimethod(readonly=True)
    def ref_of(self, network: Bytes32, target: Bytes32, call: Bytes, salt: Bytes32) -> Bytes32:
        return relay_ref(network, target, call, salt)

    @arc4.abimethod
    def verify(self, holder_kind: arc4.UInt8, holder: Bytes32, digest: Bytes32, auth: Bytes) -> bool:
        """An `account.verify` stand-in that answers false (a token must not take that as a signature)."""
        return False

    @arc4.baremethod(allow_actions=["NoOp"], create="allow")
    def budget(self) -> None:
        pass

    @arc4.abimethod
    def approve(self, token: Application, spender: Account, value: arc4.UInt256, spender_app: Application,
                mbr: UInt64) -> None:
        call = itxn.ApplicationCall(
            app_id=token, fee=0, apps=(spender_app,),
            app_args=(arc4.arc4_signature("arc200_approve(address,uint256)bool"), spender.bytes, value.bytes))
        if mbr:
            itxn.submit_txns(itxn.Payment(receiver=token.address, amount=mbr, fee=0), call)
        else:
            call.submit()

    @arc4.abimethod
    def approve_as(self, token: Application, owner: Account, spender: Account, value: arc4.UInt256,
                   spender_app: Application, mbr: UInt64) -> None:
        """`approve` sent from `owner`, an account rekeyed to this app (CTR-TOK-01: still not an app)."""
        call = itxn.ApplicationCall(
            app_id=token, sender=owner, fee=0, apps=(spender_app,),
            app_args=(arc4.arc4_signature("arc200_approve(address,uint256)bool"), spender.bytes, value.bytes))
        if mbr:
            itxn.submit_txns(itxn.Payment(receiver=token.address, amount=mbr, fee=0), call)
        else:
            call.submit()

    @arc4.abimethod
    def transfer_from(self, token: Application, owner: Account, to: Account, value: arc4.UInt256,
                      mbr: UInt64) -> None:
        call = itxn.ApplicationCall(
            app_id=token, fee=0,
            app_args=(arc4.arc4_signature("arc200_transferFrom(address,address,uint256)bool"), owner.bytes, to.bytes,
                      value.bytes))
        if mbr:
            itxn.submit_txns(itxn.Payment(receiver=token.address, amount=mbr, fee=0), call)
        else:
            call.submit()

    @arc4.abimethod
    def pay(self, token: Application, o: MetaOp, auth: Bytes, open_payee: Account, mbr: UInt64) -> None:
        call = itxn.ApplicationCall(
            app_id=token, fee=0,
            app_args=(arc4.arc4_signature(
                "mtx_pay((byte[32],byte[32],uint8,(uint8,byte[32]),(uint8,byte[32]),byte[32],uint128,byte[32],"
                "byte[32],uint64,uint64,byte[32]),byte[],address)void"),
                o.bytes, arc4.DynamicBytes(auth).bytes, open_payee.bytes))
        if mbr:
            itxn.submit_txns(itxn.Payment(receiver=token.address, amount=mbr, fee=0), call)
        else:
            call.submit()

    @arc4.abimethod
    def trade(self, token: Application, o: MetaOp, auth: Bytes, order: Order, mbr: UInt64) -> None:
        """`token.mtx_trade` from this app (a stand-in for another DEX)."""
        call = itxn.ApplicationCall(
            app_id=token, fee=0,
            app_args=(arc4.arc4_signature(
                "mtx_trade((byte[32],byte[32],uint8,(uint8,byte[32]),(uint8,byte[32]),byte[32],uint128,byte[32],"
                "byte[32],uint64,uint64,byte[32]),byte[],(uint64,uint64,uint128,uint128,byte[32],uint64))void"),
                o.bytes, arc4.DynamicBytes(auth).bytes, order.bytes))
        if mbr:
            itxn.submit_txns(itxn.Payment(receiver=token.address, amount=mbr, fee=0), call)
        else:
            call.submit()
