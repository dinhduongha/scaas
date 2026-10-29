#!/usr/bin/env python3
"""T14 mutation spot-checks: each mutant removes or weakens one guard of contracts/dex.py or the token's trade legs
(contracts/token.py: mtx_trade, mtx_cancel, mtx_invalidate_nonces); the build + the named tests must then fail
(killed). The loop is runs/mutate_account.py's. Run on a live localnet under scripts/capped:
python3 runs/mutate_dex.py > runs/2026-10-29-algorand-dex-mutations.txt"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutate_account import main  # noqa: E402

D, K = 'contracts/dex.py', 'contracts/token.py'
T = 'tests/test_dex.py::'
SETTLE, FAILS, RELAYER, NONDEX, CANCEL, MINN, FOK, REPLAY, VALUE, ACTIONS, FIG, CARRY = (T + n for n in (
    'test_settle_both_legs_atomic', 'test_one_leg_fails_group_fails', 'test_order_relayer_mismatch_refused',
    'test_leg_by_non_dex_refused', 'test_cancel_filled_refused', 'test_min_nonce_cap_refused', 'test_no_partial_fill',
    'test_replay_across_dexes_tokens_networks', 'test_trade_leg_is_a_value_op', 'test_dex_update_delete_optin_refused',
    'test_figures_pinned', 'test_carried_auth_after_the_settle'))
AT = 'assert True, '
M = [
    # token: mtx_trade
    ('X1 trade: caller must be an app', K, 'assert called_by_app(), "a leg is pulled only by an app', 'assert True, "', NONDEX),
    ('X2 trade: op code', K, 'assert op.op.as_uint64() == OP_TRADE, ', AT, REPLAY),
    ('X3 trade: to = the caller', K, 'assert op.to == dex and op.relayer.bytes', 'assert op.relayer.bytes', REPLAY),
    ('X4 trade: relayer = the caller', K, ' and op.relayer.bytes == Txn.sender.bytes, \\', ', \\', RELAYER),
    ('X5 trade: order sells this token', K, 'assert order.sell_token.as_uint64() == Global.current_application_id.id, ',
     AT, NONDEX),
    ('X6 trade: amount = sell_amount', K, 'assert amount == order.sell_amount.as_biguint() and amount > 0, ',
     'assert amount > 0, ', FOK),
    ('X7 trade: amount > 0', K, 'assert amount == order.sell_amount.as_biguint() and amount > 0, ',
     'assert amount == order.sell_amount.as_biguint(), ', FOK),
    ('X8 trade: no pay_ref', K, 'assert op.pay_ref == zero(), "a trade leg', 'assert True, "a trade leg', REPLAY),
    ('X9 trade: extra = sha256(order)', K, 'assert op.extra == order_hash(order), ', AT, REPLAY),
    ('X10 trade: order expiry', K, 'assert Global.latest_timestamp <= order.expiry.as_uint64(), ', AT, REPLAY),
    ('X11 trade: envelope (network, contract, valid_until)', K,
     '        check_envelope(op)\n        key = self._open_order(op.from_, op.lane', '        key = self._open_order(op.from_, op.lane',
     REPLAY),
    ('X12 open order: filled', K, 'assert st != FILLED, ', AT, SETTLE),
    ('X13 open order: cancelled', K, 'assert st != CANCELLED, ', AT, CANCEL),
    ('X14 open order: below min_nonce', K, 'assert nonce >= self.min_nonces.get(', 'assert True or nonce >= self.min_nonces.get(',
     MINN),
    ('X15 trade: order not closed', K, '        self.orders[key] = arc4.UInt8(FILLED)\n', '', SETTLE),
    ('X16 trade: signature', K, '''fwd = signed_by(self.account_app.value, arc4.arc4_signature(VERIFY), op.from_, d, auth,
                        rest(self._trade_need(dex)))''', 'fwd = rest(self._trade_need(dex))', FAILS),
    ('X17 trade under verify_key (no value policy)', K, 'arc4.arc4_signature(VERIFY), op.from_, d, auth',
     'arc4.arc4_signature(VERIFY_KEY), op.from_, d, auth', VALUE),
    ('X18 trade: funds not moved', K, '        self._move(op.from_, dex, amount)\n', '', SETTLE),
    ('X19 trade: MBR exactness', K, '''        self._move(op.from_, dex, amount)
        mbr_paid(before, fwd)''', '''        self._move(op.from_, dex, amount)''', SETTLE),
    ('X20 trade: DEX box MBR not counted', K, '        if not self._exists(dex):\n            need += MBR_AMOUNT_BOX\n',
     '', SETTLE),
    ('X21 trade: OrderFilled event', K,
     '        arc4.emit("OrderFilled", op.from_, arc4.Address(Txn.sender), op.lane, op.nonce, arc4.UInt256(amount), d)\n',
     '', SETTLE),
    # token: cancel / invalidate
    ('X22 admin: shape', K, 'assert (o.op.as_uint64() == code and o.to == o.from_ and', 'assert (True and', CANCEL),
    ('X23 admin: extra = sha256(params)', K, 'assert o.extra.bytes == op.sha256(params), ', AT, CANCEL),
    ('X24 admin: envelope', K, '''        "cancel / invalidate shape (to = from; amount, pay_ref, lane and nonce zero)"
    assert o.extra.bytes == op.sha256(params), "extra is not sha256 of the parameters"
    check_envelope(o)''', '''        "cancel / invalidate shape (to = from; amount, pay_ref, lane and nonce zero)"
    assert o.extra.bytes == op.sha256(params), "extra is not sha256 of the parameters"''', CANCEL),
    ('X25 cancel: signature', K, '''fwd = signed_by(self.account_app.value, arc4.arc4_signature(VERIFY_KEY), op.from_, digest(op), auth,
                        rest(UInt64(MBR_ORDER_BOX)))''', 'fwd = rest(UInt64(MBR_ORDER_BOX))', CANCEL),
    ('X26 cancel under verify (value policy)', K, '''arc4.arc4_signature(VERIFY_KEY), op.from_, digest(op), auth,
                        rest(UInt64(MBR_ORDER_BOX)))''', '''arc4.arc4_signature(VERIFY), op.from_, digest(op), auth,
                        rest(UInt64(MBR_ORDER_BOX)))''', VALUE),
    ('X27 cancel: not recorded', K, '        self.orders[key] = arc4.UInt8(CANCELLED)\n', '', CANCEL),
    ('X28 cancel: order box MBR', K, 'MBR_ORDER_BOX = BOX_FLAT + BOX_BYTE * (33 + 1)',
     'MBR_ORDER_BOX = BOX_FLAT + BOX_BYTE * (33 + 2)', CANCEL),
    ('X29 invalidate: cap', K, 'assert n < MIN_NONCE_CAP, ', AT, MINN),
    ('X30 invalidate: cap off by one', K, 'assert n < MIN_NONCE_CAP, ', 'assert n <= MIN_NONCE_CAP, ', MINN),
    ('X31 invalidate: only increases', K, 'assert n > self.min_nonces.get(key, default=UInt64(0)), ', AT, MINN),
    ('X32 invalidate: equal allowed', K, 'assert n > self.min_nonces.get(key, default=UInt64(0)), ',
     'assert n >= self.min_nonces.get(key, default=UInt64(0)), ', MINN),
    ('X33 invalidate: box MBR charged again', K, 'need = UInt64(0) if key in self.min_nonces else UInt64(MBR_LANE_BOX)',
     'need = UInt64(MBR_LANE_BOX)', MINN),
    ('X34 invalidate: not recorded', K, '        self.min_nonces[key] = n\n', '', MINN),
    ('X35 invalidate: signature', K, '''fwd = signed_by(self.account_app.value, arc4.arc4_signature(VERIFY_KEY), op.from_, digest(op), auth,
                        rest(need))''', 'fwd = rest(need)', MINN),
    # dex
    ('Y1 settle: order a relayer-bound', D, '        bound(order_a)\n', '', RELAYER),
    ('Y2 settle: order b relayer-bound', D, '        bound(order_b)\n', '', RELAYER),
    ('Y3 settle: pair crosses', D, 'assert (order_a.sell_token == order_b.buy_token and order_b.sell_token == '
     'order_a.buy_token\n', 'assert (True\n', FOK),
    ('Y4 settle: not the same token', D, '\n                and order_a.sell_token != order_a.buy_token), ', '), ', FOK),
    ('Y5 settle: a covers b.min_buy', D, 'assert (order_a.sell_amount.as_biguint() >= order_b.min_buy.as_biguint()\n',
     'assert (True\n', FOK),
    ('Y6 settle: b covers a.min_buy', D, '\n                and order_b.sell_amount.as_biguint() >= order_a.min_buy.as_biguint()), ',
     '), ', FOK),
    ('Y7 settle: payout to the wrong seller', D, 'send(order_a.sell_token.as_uint64(), op_b.from_,',
     'send(order_a.sell_token.as_uint64(), op_a.from_,', SETTLE),
    ('Y8 settle: payout amount = min_buy (partial)', D,
     'send(order_a.sell_token.as_uint64(), op_b.from_, order_a.sell_amount.as_biguint()',
     'send(order_a.sell_token.as_uint64(), op_b.from_, order_b.min_buy.as_biguint()', FOK),
    ('Y9 settle: Matched without the token ids', D, 'arc4.emit("Matched", Bytes32.from_bytes(op.sha256(da.bytes + db.bytes)), '
     'order_a.sell_token,\n                  order_b.sell_token, da, db)', 'arc4.emit("Matched", Bytes32.from_bytes('
     'op.sha256(da.bytes + db.bytes)), arc4.UInt64(0),\n                  arc4.UInt64(0), da, db)', SETTLE),
    ('Y10 settle: settle_id order swapped', D, 'op.sha256(da.bytes + db.bytes)', 'op.sha256(db.bytes + da.bytes)', SETTLE),
    ('Y11 settle: MBR sum unchecked', D, '        mbr_paid(before, mbr[0]', '        pass  # (before, mbr[0]', SETTLE),
    ("Y12 settle: b reads a's carried auth", D, '            b, at = carried(at)\n',
     '            b, at = carried(UInt64(0))\n', FIG),
    ('Y15 carried: a carry to another app counts', D, 't.app_id == Global.current_application_id\n                and ',
     '', CARRY),
    ('Y16 carried: any app call to this DEX counts (settle itself)', D,
     '\n                and t.num_app_args == 2):', '):', CARRY),
    ('Y17 carried: scan from the group start (fix 1 m1)', D, '        at = Txn.group_index + 1  #',
     '        at = UInt64(0)  #', CARRY),
    ('Y13 Update / Delete allowed', D, '    @arc4.baremethod(allow_actions=["NoOp"])',
     '    @arc4.baremethod(allow_actions=["NoOp", "UpdateApplication", "DeleteApplication"])', ACTIONS),
    ('Y14 OptIn allowed', D, '    @arc4.baremethod(allow_actions=["NoOp"])', '    @arc4.baremethod(allow_actions=["NoOp", "OptIn"])',
     ACTIONS),
]

if __name__ == '__main__':
    sys.exit(main(M, 'algorand-dex-mutations', 'T14'))
