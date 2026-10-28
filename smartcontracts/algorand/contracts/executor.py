"""SCaaS relay-fee executor on Algorand (near-algorand T15; spec §4.8, §2 rows 11 / 12; ruling T15 pre-flight (c)).

A keyless LogicSig account: it sends a relay group's target call, so the target sees the executor as its sender, never
the lane (rule 11). Its program approves only an `ApplicationCall` (`OnCompletion` NoOp) whose next group transaction
is `relay` on the router app named by the template constant, with `RekeyTo`, `CloseRemainderTo` and `AssetCloseTo`
zero and fee 0 (the lane pays by fee pooling): it never pays, rekeys or closes, and holds nothing. The router checks
the rest (rule 13: the target app exists and is not the router, no `add_key_native`, the payer signed this very call).

Template `ROUTER_APP_ID`: 8 bytes, the router app id big-endian. `build.sh algorand` splits the compiled program around
it into `EXEC_PREFIX ‖ ROUTER_APP_ID ‖ EXEC_SUFFIX` and bakes both parts into the router, which derives this address on
chain: `sha512_256("Program" ‖ EXEC_PREFIX ‖ itob(router app id) ‖ EXEC_SUFFIX ‖ 20 01 salt)` (no admin step; the
salt, fixed at the router's creation, is dead code after the final return that makes the address off-curve).
"""
from algopy import Bytes, Global, OnCompleteAction, TemplateVar, TransactionType, Txn, arc4, gtxn, logicsig, op

from common import RELAY


# no puyapy salt (it picks one per program hash, so it would depend on the router id and break the split): the
# router appends its own creation-time salt `intcblock 1 s` after the final return instead (T15 fix 1)
@logicsig(name="Executor", autosalt=False)
def executor() -> bool:
    assert Txn.type_enum == TransactionType.ApplicationCall, "only an app call"
    assert Txn.on_completion == OnCompleteAction.NoOp, "only NoOp"
    assert Txn.rekey_to == Global.zero_address, "never rekeys"
    assert Txn.close_remainder_to == Global.zero_address, "never closes"
    assert Txn.asset_close_to == Global.zero_address, "never closes an asset"
    assert Txn.fee == 0, "never pays a fee"
    nxt = gtxn.Transaction(Txn.group_index + 1)  # fails when this is the last transaction of the group
    assert nxt.type == TransactionType.ApplicationCall, "next is the router's relay"
    assert nxt.app_id.id == op.btoi(TemplateVar[Bytes]("ROUTER_APP_ID")), "next is the router's relay"
    assert nxt.on_completion == OnCompleteAction.NoOp, "next is the router's relay"
    assert nxt.app_args(0) == arc4.arc4_signature(RELAY), "next is the router's relay"
    return True
