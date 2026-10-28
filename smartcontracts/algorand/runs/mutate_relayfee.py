#!/usr/bin/env python3
"""T15 mutation spot-checks: each mutant removes or weakens one guard of contracts/relayfee.py (router),
contracts/executor.py (executor LogicSig) or contracts/dex.py (the relayed-settle submitter rule); the build + the named
tests must then fail (killed). Mutants marked "(by construction)" guard what another layer also refuses (the protocol,
the executor, the router's ARC-4 dispatch): they are expected to survive and are listed so the report says so. The loop
is runs/mutate_account.py's (two-pass build). Run on a live localnet under scripts/capped:
python3 runs/mutate_relayfee.py > runs/2026-10-29-algorand-relayfee-mutations.txt"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutate_account import main  # noqa: E402

F, E, D = 'contracts/relayfee.py', 'contracts/executor.py', 'contracts/dex.py'
T = 'tests/test_relayfee.py::'
(OPEN, BOUND, FAIL, DIRECT, NOTEXEC, CLEAR, MISSING, SELF, PAYEE_EX, KEY, SHAPE, REKEY, NEXT, NAMING, LANE, MOVES,
 ADDR, VEC, HOLDS, MBR, NOOP, KINDS, DEX, ACTIONS, INNER, FIG) = (T + n for n in (
    'test_relay_open_mode_pays_lane', 'test_relay_bound_payee', 'test_target_failure_rejects_group',
    'test_algorand_router_bound_pay_refused_direct', 'test_target_not_by_executor_refused',
    'test_clearstate_target_refused', 'test_missing_app_refused', 'test_target_relayfee_refused',
    'test_payee_executor_refused', 'test_add_key_native_target_refused', 'test_payment_shape_refused',
    'test_executor_rejects_rekey_close_fee', 'test_executor_without_relay_next_rejected',
    'test_target_pay_naming_router_fails', 'test_lane_transfer_as_target_refused',
    'test_executor_transfer_moves_nothing', 'test_executor_address_matches_offchain_derivation',
    'test_relay_ref_vectors', 'test_router_holds_nothing_after_relay', 'test_router_mbr_forward_exact',
    'test_relayed_noop_refused', 'test_relay_every_target_kind', 'test_dex_bound_order_via_router',
    'test_router_update_delete_optin_refused', 'test_inner_txns_never_rekey_or_close', 'test_figures_pinned'))
AT = 'assert True, '
M = [
    # router: rule 13, executor, add_key_native
    ('R1 target app id != 0 (an app create)', F, 'assert target.id != 0, ', AT, MISSING),
    ('R2 target app exists (by construction: the protocol)', F, 'assert exists, ', AT, MISSING),
    ('R3 target != router', F, 'assert target != Global.current_application_id, ', AT, SELF),
    ('R4 target NoOp (by construction: the executor)', F, 'assert t.on_completion == OnCompleteAction.NoOp, ', AT,
     CLEAR),
    ('R5 target sent by the executor', F, 'assert t.sender == exe, ', AT, NOTEXEC + ' ' + LANE),
    ('R6 add_key_native refused', F, 'assert t.num_app_args == 0 or t.app_args(0) != ', 'assert True or t.app_args(0) != ',
     KEY),
    ('R7 call bytes: arg length prefix dropped', F, 'call += op.extract(op.itob(a.length), 6, 2) + a', 'call += a',
     OPEN),
    ('R8 ref salt = a constant, not op.extra', F, 'Bytes32.from_bytes(taddr.bytes), call, op_.extra)',
     'Bytes32.from_bytes(taddr.bytes), call, Bytes32.from_bytes(op.bzero(32)))', OPEN),
    # router: payment shape, payee
    ('R9 pay_ref = ref', F, 'assert (op_.pay_ref == r and op_.lane', 'assert (op_.lane', SHAPE),
    ('R10 lane = payLane(ref)', F, 'op_.lane == pay_lane(r) and op_.nonce', 'op_.nonce', SHAPE),
    ('R11 nonce 0', F, 'and op_.nonce.as_uint64() == 0\n', '\n', SHAPE),
    ('R12 relayer = router', F, '\n                and op_.relayer.bytes == Global.current_application_address.bytes)', ')',
     SHAPE),
    ('R13 payee != executor', F, 'assert op_.to.bytes != addr_holder(exe).bytes, ', AT, PAYEE_EX),
    ('R14 open payee = the router, not the lane', F, 'arc4.DynamicBytes(auth).bytes, Txn.sender.bytes))',
     'arc4.DynamicBytes(auth).bytes, Global.current_application_address.bytes))', OPEN + ' ' + HOLDS),
    # router: MBR forward
    ('R15 MBR not forwarded', F, '        if fwd:\n            itxn.submit_txns', '        if False:\n            itxn.submit_txns',
     MBR),
    ('R16 MBR forward short by 1', F, 'amount=fwd, fee=0)', 'amount=fwd - 1, fee=0)', MBR),
    ('R17 router payment: the target\'s own not skipped', F, '            at -= 1\n', '            at = at\n', MBR),
    ('R18 router payment: any receiver', F,
     'if p.type == TransactionType.Payment and p.receiver == Global.current_application_address:',
     'if p.type == TransactionType.Payment:', MBR),
    ('R19 router payment may close / rekey', F, 'assert p.close_remainder_to == Global.zero_address and p.rekey_to', 
     'assert True or p.rekey_to', MBR),
    # router: event, budget, actions
    ('R20 RelayFeePaid not emitted', F, '        arc4.emit("RelayFeePaid", r,', '        if False:\n            arc4.emit("RelayFeePaid", r,', OPEN),
    ('R21 RelayFeePaid payee = op.to (open mode)', F, 'token, op_.from_, payee,', 'token, op_.from_, op_.to,', OPEN),
    ('R22 no budget raise', F, '        ensure_budget(RELAY_COST, OpUpFeeSource.GroupCredit)\n', '', FIG + ' ' + KINDS),
    ('R23 Update / Delete allowed', F, '''    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:''', '''    @arc4.baremethod(allow_actions=["UpdateApplication", "DeleteApplication"])
    def upd(self) -> None:
        pass

    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:''', ACTIONS),
    ('R24 OptIn allowed', F, '''    @arc4.baremethod(allow_actions=["NoOp"])
    def budget(self) -> None:''', '''    @arc4.baremethod(allow_actions=["NoOp", "OptIn", "CloseOut"])
    def budget(self) -> None:''', ACTIONS),
    ('R25 inner payment closes to the token', F, 'itxn.Payment(receiver=app.address, amount=fwd, fee=0)',
     'itxn.Payment(receiver=app.address, amount=fwd, fee=0, close_remainder_to=app.address)', INNER),
    # router: creation salt (T15 fix 1)
    ('S1 salt >= 128 accepted', F, 'assert salt.as_uint64() < 128, ', AT, T + 'test_router_salt_below_128'),
    ('S2 salt not in the derivation', F, '+ b"\\x20\\x01" + op.extract(op.itob(self.salt.value), 7, 1)))', '))', ADDR),
    ('S3 salt not stored', F, '        self.salt.value = salt.as_uint64()\n', '        self.salt.value = UInt64(0)\n', ADDR),
    # executor LogicSig
    ('E1 only an app call', E, 'assert Txn.type_enum == TransactionType.ApplicationCall, ', AT, REKEY),
    ('E2 only NoOp', E, 'assert Txn.on_completion == OnCompleteAction.NoOp, "only NoOp"', 'assert True, "only NoOp"', CLEAR),
    ('E3 never rekeys', E, 'assert Txn.rekey_to == Global.zero_address, ', AT, REKEY),
    ('E4 never closes (by construction: no close field on an app call)', E,
     'assert Txn.close_remainder_to == Global.zero_address, ', AT, REKEY),
    ('E5 never closes an asset (by construction)', E, 'assert Txn.asset_close_to == Global.zero_address, ', AT, REKEY),
    ('E6 never pays a fee', E, 'assert Txn.fee == 0, ', AT, REKEY),
    ('E7 next is an app call (by construction: its app id is then 0)', E,
     'assert nxt.type == TransactionType.ApplicationCall, ', AT, NEXT),
    ('E8 next is on the router app (weakened to >=: the template constant must stay in the program)', E,
     'assert nxt.app_id.id == op.btoi(TemplateVar[Bytes]("ROUTER_APP_ID")), ',
     'assert nxt.app_id.id >= op.btoi(TemplateVar[Bytes]("ROUTER_APP_ID")), ', NEXT),
    ('E9 next is NoOp (by construction: ClearState by the protocol opt-in requirement, OptIn / CloseOut by the '
     'router\'s ARC-4 dispatch)', E,
     'assert nxt.on_completion == OnCompleteAction.NoOp, ', AT, NEXT),
    ('E10 next is relay (selector)', E, 'assert nxt.app_args(0) == arc4.arc4_signature(RELAY), ', AT, NEXT),
    # dex: relayed settle submitter
    ('D1 submitter = Txn.Sender only', D, '        by = submitter(self.router_app.value)\n',
     '        by = Txn.sender\n', DEX),
    ('D2 any app\'s relay counts', D, 'n.app_id.id == router\n', 'n.app_id.id != 0\n', DEX),
    ('D3 any router call counts (not only relay)', D, '\n                and n.app_args(0) == arc4.arc4_signature(RELAY)):',
     '):', DEX),
]

if __name__ == '__main__':
    sys.exit(main(M, 'algorand-relayfee-mutations', 'T15'))
