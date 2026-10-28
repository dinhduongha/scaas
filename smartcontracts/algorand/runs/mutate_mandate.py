#!/usr/bin/env python3
"""T13 mutation spot-checks: each mutant removes or weakens one guard of contracts/mandate.py; the build + the named
tests must then fail (killed). The loop is runs/mutate_account.py's. Run on a live localnet under scripts/capped:
python3 runs/mutate_mandate.py > runs/2026-10-28-algorand-mandate-mutations.txt"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mutate_account import main  # noqa: E402

D = 'contracts/mandate.py'
T = 'tests/test_mandate.py::'
OPEN, FUND, LIM, PAYEE = (T + n for n in ('test_open_funding_equals_op_amount', 'test_funding_pay_checked',
                                          'test_limits_exceeded_refused', 'test_wrong_payee_refused'))
WITHIN, EXP, REV, ONCE = (T + n for n in ('test_mandate_pay_within_limits', 'test_expired_refused',
                                          'test_revoked_refused_then_funds_back', 'test_pay_ref_once'))
REPLAY, FAKE, NATIVE = (T + n for n in ('test_replay_across_tokens_networks_apps',
                                        'test_fake_token_cannot_touch_other_funds', 'test_native_owner_ua_payee'))
AT = 'assert True, '
M = [
    # open
    ('D1 open: op code', D, 'assert op_.op.as_uint64() == OP_MANDATE_OPEN, ', AT, OPEN),
    ('D2 open: pay_ref zero', D, 'assert op_.pay_ref == zero(), "mtx_mandate_open', 'assert True, "mtx_mandate_open', OPEN),
    ('D3 open: funding == op.amount (R9)', D, 'assert terms.funding == op_.amount, ', AT, OPEN),
    ('D4 open: limits', D, 'assert (terms.period_s.as_uint64() > 0 and', 'assert True or (terms.period_s.as_uint64() > 0 and',
     OPEN),
    ('D5 open: per_payment <= per_period', D, 'and terms.per_payment.as_biguint() <= terms.per_period.as_biguint()), ',
     '), ', OPEN),
    ('D6 open: expiry past', D, 'assert terms.expiry.as_uint64() > Global.latest_timestamp, ', AT, OPEN),
    ('D7 open: holder kinds', D, 'assert terms.delegate.kind.as_uint64() <= KIND_UA and', 'assert True or', OPEN),
    ('D8 open: to = Ua(id)', D, 'assert op_.to.bytes == ua(id).bytes, ', AT, OPEN),
    ('D9 open: extra binds token, id, terms', D, 'assert op_.extra.bytes == op.sha256(op.itob(t) + id.bytes + terms.bytes), ',
     AT, OPEN),
    ('D10 open: payee = this app', D, 'assert terms.payee.bytes != this().bytes, ', AT, OPEN),
    ('D11 open: one-shot (mandate exists)', D, 'assert key not in self.mandates, ', AT, OPEN),
    ('D12 open: envelope', D, '        check_envelope(op_)\n        tok = rest(', '        tok = rest(', OPEN),
    ('D13 open: owner signature', D,
     '        acc = signed_by(self.account_app.value, op_.from_, digest(op_), auth, UInt64(0))\n',
     '        acc = UInt64(0)\n', OPEN),
    ('D14 open: payee box created (zero transfer)', D, '        send(t, terms.payee, BigUInt(0), tok)', '        pass',
     WITHIN),
    ('D15 open: MBR constant', D, 'MBR_MANDATE_BOX = 2500 + 400 * (41 + MANDATE_LEN)',
     'MBR_MANDATE_BOX = 2500 + 400 * (42 + MANDATE_LEN)', WITHIN),
    ('D16 open: Mandate event', D, '        arc4.emit("Mandate", token, id, arc4.String("open"), op_.from_)\n', '',
     WITHIN),
    # funding (ruling a)
    ('D17 funding: shape (app call, token, mtx_pay)', D,
     'assert (f.type == TransactionType.ApplicationCall and f.app_id.id == token', 'assert True or (f.type == '
     'TransactionType.ApplicationCall and f.app_id.id == token', FUND),
    ('D18 funding: on the named token', D, 'and f.app_id.id == token and', 'and', FUND),
    ('D19 funding: mtx_pay only', D, '\n            and f.app_args(0) == arc4.arc4_signature(MTX_PAY)), ', '), ', FUND),
    ('D20 funding: position (just before the MBR payment)', D, 'gtxn.Transaction(Txn.group_index - 2)',
     'gtxn.Transaction(Txn.group_index - 1)', FUND),
    ('D21 funding: from = owner', D, 'assert p.from_.bytes == owner.bytes, ', AT, FUND),
    ('D22 funding: to = this app', D, 'assert p.to.bytes == this().bytes, ', AT, FUND),
    ('D23 funding: amount', D, 'assert p.amount == amount, ', AT, FUND),
    ('D24 funding: pay_ref = id', D, 'assert p.pay_ref == id, ', AT, FUND),
    # pay
    ('D25 pay: op code', D, 'assert op_.op.as_uint64() == OP_MANDATE_PAY, ', AT, ONCE),
    ('D26 pay: from must be a UA (mandate id)', D, 'assert h.kind.as_uint64() == KIND_UA and key in', 'assert key in', ONCE),
    ('D27 pay: pay_ref set', D, 'assert (op_.pay_ref != zero() and op_.lane', 'assert (op_.lane', ONCE),
    ('D28 pay: lane = payLane(pay_ref)', D, 'op_.lane == pay_lane(op_.pay_ref) and ', '', ONCE),
    ('D29 pay: nonce 0', D, 'and op_.nonce.as_uint64() == 0\n                and op_.extra.bytes == op.sha256(op.itob(t))), \\\n'
     '            "mandate pay', '\n                and op_.extra.bytes == op.sha256(op.itob(t))), \\\n            "mandate pay', ONCE),
    ('D30 pay: extra binds the token', D, '\n                and op_.extra.bytes == op.sha256(op.itob(t))), \\\n'
     '            "mandate pay', '), \\\n            "mandate pay', REPLAY),
    ('D31 pay: revoked', D, '        assert not m.revoked.native, "mandate revoked"\n        now', '        now', REV),
    ('D32 pay: expiry', D, 'assert now <= m.terms.expiry.as_uint64(), ', AT, EXP),
    ('D33 pay: expiry boundary (now == expiry allowed)', D, 'assert now <= m.terms.expiry.as_uint64(), ',
     'assert now < m.terms.expiry.as_uint64(), ', EXP),
    ('D34 pay: payee', D, 'assert op_.to.bytes == m.terms.payee.bytes, ', AT, PAYEE),
    ('D35 pay: amount > 0', D, 'assert amount > 0, ', AT, LIM),
    ('D36 pay: per payment', D, 'assert amount <= m.terms.per_payment.as_biguint(), ', AT, LIM),
    ('D37 pay: per period', D, 'assert amount <= m.terms.per_period.as_biguint() - spent, ', AT, LIM),
    ('D38 pay: window restarts at now (not the grid)', D, 'start += elapsed // p * p', 'start = now', LIM),
    ('D39 pay: spent not reset in a new window', D, '            spent = BigUInt(0)\n', '            pass\n', LIM),
    ('D40 pay: spent not counted', D, 'spent=arc4.UInt128(spent + amount)', 'spent=arc4.UInt128(spent)', LIM),
    ('D41 pay: envelope', D, '        check_envelope(op_)\n        d = digest(op_)', '        d = digest(op_)', REPLAY),
    ('D42 pay: delegate signature', D,
     'fwd = signed_by(self.account_app.value, m.terms.delegate, d, auth, rest(UInt64(MBR_LANE_BOX)))',
     'fwd = rest(UInt64(MBR_LANE_BOX))', WITHIN),
    ('D43 pay: pay_ref once', D, 'assert lane not in self.lanes, ', AT, ONCE),
    ('D44 pay: lane not recorded', D, '        self.lanes[lane] = UInt64(1)\n', '', ONCE),
    ('D45 pay: lane keyed per (token, mandate)', D, 'op.sha256(key + op_.lane.bytes)', 'op.sha256(op_.lane.bytes)', ONCE),
    ('D46 pay: balance short', D, "assert left >= amount, ", AT, WITHIN),
    ('D47 pay: remaining not debited', D, 'remaining=arc4.UInt128(left - amount))', 'remaining=arc4.UInt128(left))',
     WITHIN),
    ('D48 pay: nothing sent', D, '        send(t, op_.to, amount, UInt64(0))\n', '', WITHIN),
    ('D49 pay: MBR exactness (native signer)', D, '''        arc4.emit("PaymentSettled", op_.from_, op_.to, arc4.UInt256(amount), op_.pay_ref)
        mbr_paid(before, fwd)''', '''        arc4.emit("PaymentSettled", op_.from_, op_.to, arc4.UInt256(amount), op_.pay_ref)''', NATIVE),
    ('D50 pay: PaymentSettled event', D,
     '        arc4.emit("PaymentSettled", op_.from_, op_.to, arc4.UInt256(amount), op_.pay_ref)\n', '', WITHIN),
    # revoke, refund, close
    ('D51 revoke: shape', D, 'assert (op_.op.as_uint64() == OP_REVOKE and op_.amount.as_biguint() == 0', 'assert (True',
     REV),
    ('D52 revoke: extra binds the token', D, '\n                and op_.lane == zero() and op_.nonce.as_uint64() == 0 and '
     'op_.extra.bytes == op.sha256(op.itob(t))), ', '\n                and op_.lane == zero() and op_.nonce.as_uint64() '
     '== 0), ', REPLAY),
    ('D53 revoke: owner or delegate', D, 'assert op_.from_.bytes == m.owner.bytes or', 'assert True or', REV),
    ('D54 revoke: no-op revoke refused', D, '        assert not m.revoked.native, "mandate revoked"\n        check_envelope',
     '        check_envelope', REV),
    ('D55 revoke: envelope', D, '        check_envelope(op_)\n        fwd = signed_by(self.account_app.value, op_.from_',
     '        fwd = signed_by(self.account_app.value, op_.from_', REPLAY),
    ('D56 revoke: signature', D, 'fwd = signed_by(self.account_app.value, op_.from_, digest(op_), auth, rest(UInt64(0)))',
     'fwd = UInt64(0)', REV),
    ('D57 revoke: MBR exactness', D, '''        arc4.emit("Mandate", token, op_.to.id, arc4.String("revoke"), op_.from_)
        mbr_paid(before, fwd)''', '''        arc4.emit("Mandate", token, op_.to.id, arc4.String("revoke"), op_.from_)''', NATIVE),
    ('D58 close: not marked closed', D, 'revoked=arc4.Bool(True))', 'revoked=m.revoked)', REV),
    ('D59 close: remaining kept (double spend)', D, 'm._replace(remaining=arc4.UInt128(0), ', 'm._replace(', REV),
    ('D60 close: funds to the payee, not the owner', D, '            send(token, m.owner, left, UInt64(0))',
     '            send(token, m.terms.payee, left, UInt64(0))', REV),
    ('D61 refund: nothing to refund', D, 'assert m.remaining.as_biguint() > 0, ', AT, REV),
    ('D62 refund: live', D, 'assert Global.latest_timestamp > m.terms.expiry.as_uint64(), ', AT, EXP),
    ('D63 refund: at now == expiry', D, 'assert Global.latest_timestamp > m.terms.expiry.as_uint64(), ',
     'assert Global.latest_timestamp >= m.terms.expiry.as_uint64(), ', EXP),
    # state keys, signer routing, authority
    ('D64 state not keyed by token', D, '    return op.itob(token) + id.bytes', '    return id.bytes', REPLAY),
    ('D65 native path for a UA holder', D, 'if h.kind.as_uint64() == KIND_ADDRESS and auth.length == 64:',
     'if auth.length == 64:', T + 'test_msig_delegate'),
    ('D66 Update / Delete allowed', D, '    @arc4.baremethod(allow_actions=["NoOp"])',
     '    @arc4.baremethod(allow_actions=["NoOp", "UpdateApplication", "DeleteApplication"])',
     T + 'test_mandate_update_delete_optin_refused'),
    ('D67 OptIn allowed', D, '    @arc4.baremethod(allow_actions=["NoOp"])', '    @arc4.baremethod(allow_actions=["NoOp", "OptIn"])',
     T + 'test_mandate_update_delete_optin_refused'),
]

if __name__ == '__main__':
    sys.exit(main(M, 'algorand-mandate-mutations', 'T13'))
