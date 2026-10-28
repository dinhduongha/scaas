"""Token app on localnet (near-algorand T11; spec §2, §4.1, §4.2, §4.4–§4.6, §4.9; plan Review Focus 1, 2, 5)."""
import json
import os
import re

import pytest
from algosdk import encoding, transaction
from algosdk.error import AlgodHTTPError

from conftest import (ALGOD, BUDGET, MBR_ALLOWANCE, MBR_BALANCE, MBR_LANE, MBR_UA, MIN_FEE, REPO,
                      U128_MAX, Z32, Refused, digest, latest_ts, meta_pay_id, native, pay_lane, run, sha256, sim, sp,
                      ua, view, wait)

ZERO_ADDR = encoding.encode_address(Z32)
PAYMETA = json.load(open(os.path.join(REPO, 'smartcontracts', 'vectors', 'metatx', 'paymeta.json')))
# Largest `meta` of `mtx_pay_meta` on its costliest log path (native payer → UA receiver: PaymentMeta,
# MetaTransactionExecuted, arc200_Transfer, UaTransfer, PaymentSettled ≤ 1,024 B of logs); measured, pinned in
# runs/2026-10-28-algorand-limits.txt. The app-call argument limit (2,048 B) is looser.
MAX_PAY_META_BYTES = 507
# Opcode budget pinned per entry (pooled, 700 per app call; the relayer adds BUDGET bare calls).
BUDGET_PIN = {'mtx_pay': 2900, 'mtx_pay_meta': 3400, 'mtx_transfer': 2900, 'arc200_transfer': 300}


def no(*msgs):
    return pytest.raises(Refused, match='.*'.join(re.escape(m) for m in msgs))


def norm(v):
    if isinstance(v, list):
        return bytes(v) if v and all(isinstance(x, int) for x in v) else [norm(x) for x in v]
    return v


def events(t, res):
    """ARC-28 events of `t` in log order: (name, [fields…]), byte arrays as bytes."""
    out = []
    for log in res.logs:
        e = t.app.events.get(log[:4])
        if e:
            out.append((e[0], norm(e[1].decode(log[4:]))))
    return out


def names(t, res):
    return [n for n, _ in events(t, res)]


def bal(t, who):
    return view(t, 'arc200_balanceOf', who if isinstance(who, str) else who.addr)


def ua_bal(t, i):
    return view(t, 'ua_balance_of', i)


def signed(t, signer, to, amount, **kw):
    o = t.op(signer, to, amount, **kw)
    return o, signer.sign_op(digest(o))


def pay(t, by, signer, to, amount, pay_ref=b'\x01' * 32, open_payee=ZERO_ADDR, mbr='auto', **kw):
    """`signer` signs a pay op (fields `kw`), `by` submits it."""
    o, a = signed(t, signer, to, amount, pay_ref=pay_ref, **kw)
    return t.mtx(by, 'mtx_pay', o, a, open_payee, mbr=mbr)


@pytest.fixture
def relayer(make):
    return make(100_000_000)


# ---------------------------------------------------------------- ARC-200 surface
def test_arc200_getters(token, make):
    assert bytes(view(token, 'arc200_name')) == b'SCaaS Test Token'.ljust(32, b'\0')
    assert bytes(view(token, 'arc200_symbol')) == b'SCT'.ljust(8, b'\0')
    assert view(token, 'arc200_decimals') == 6
    assert view(token, 'arc200_totalSupply') == 1_000_000
    assert bal(token, token.alice) == 1_000_000 and bal(token, make()) == 0
    assert view(token, 'arc200_allowance', token.alice.addr, token.address) == 0


def test_mint_admin_only(token, make):
    bob = make()
    with no('mint: admin only'):
        run(token.alice, token, 'mint', [bob.addr, 5], mbr=MBR_BALANCE, boxes=[b'b' + bob.key])
    r = run(token.admin, token, 'mint', [bob.addr, 5], mbr=MBR_BALANCE, boxes=[b'b' + bob.key])
    assert events(token, r) == [('arc200_Transfer', [ZERO_ADDR, bob.addr, 5])]
    assert bal(token, bob) == 5 and view(token, 'arc200_totalSupply') == 1_000_005


def test_arc200_transfer_new_receiver_needs_exact_mbr(token, make):
    alice, bob = token.alice, make()
    boxes = [b'b' + alice.key, b'b' + bob.key]
    for m in (None, 0, MBR_BALANCE - 1, MBR_BALANCE + 1):
        with no('MBR payment'):
            run(alice, token, 'arc200_transfer', [bob.addr, 10], mbr=m, boxes=boxes)
    before = token.min_balance()
    r = run(alice, token, 'arc200_transfer', [bob.addr, 10], mbr=MBR_BALANCE, boxes=boxes)
    assert r.ret is True and token.min_balance() - before == MBR_BALANCE
    assert events(token, r) == [('arc200_Transfer', [alice.addr, bob.addr, 10])]
    with no('MBR payment'):           # the receiver exists: a payment when 0 is needed is refused
        run(alice, token, 'arc200_transfer', [bob.addr, 1], mbr=0, boxes=boxes)
    run(alice, token, 'arc200_transfer', [bob.addr, 1], boxes=boxes)
    assert bal(token, bob) == 11 and bal(token, alice) == 1_000_000 - 11


def test_mbr_payment_exact(token, make, relayer):
    alice, bob = token.alice, make()
    o, a = signed(token, alice, native(bob), 5, pay_ref=b'\x02' * 32)
    need = view(token, 'mbr_needed', o)
    assert need == MBR_LANE + MBR_BALANCE
    for m in (None, 0, need - 1, need + 1):
        with no('MBR payment'):
            token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=m)
    for bent in ({'to': relayer.addr},                   # the exact amount, but to another receiver
                 {'gap': True}):                          # in the group, but not right before the call
        with no('MBR payment must equal'):
            token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=need, pay=bent)
    payer = make(1_000_000)
    for bent in ({'close': token.address}, {'rekey': relayer.addr}):     # ruling m4: no close-out, no rekey
        with no('MBR payment must not close or rekey'):
            token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=need, pay={'payer': payer, **bent})
    before = token.min_balance()
    token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=need)
    assert token.min_balance() - before == need          # the app's AcctMinBalance delta
    with no('wrong lane nonce'):                         # replay
        token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=None)
    o2, a2 = signed(token, alice, native(bob), 5, pay_ref=b'\x02' * 32, nonce=1)
    assert view(token, 'mbr_needed', o2) == 0
    for m in (0, 1):
        with no('MBR payment'):
            token.mtx(relayer, 'mtx_pay', o2, a2, ZERO_ADDR, mbr=m)
    before = token.min_balance()
    token.mtx(relayer, 'mtx_pay', o2, a2, ZERO_ADDR, mbr=None)
    assert token.min_balance() == before and bal(token, bob) == 10
    o3, a3 = signed(token, alice, ua(b'\x77' * 32), 5, pay_ref=b'\x03' * 32, lane=b'\x03' * 32)
    assert view(token, 'mbr_needed', o3) == MBR_LANE + MBR_UA
    before = token.min_balance()
    token.mtx(relayer, 'mtx_pay', o3, a3, ZERO_ADDR)
    assert token.min_balance() - before == MBR_LANE + MBR_UA


# ---------------------------------------------------------------- pay-meta (CTR-MTX-26)
def test_pay_meta_emits_meta_then_settled(token, make, relayer):
    alice, bob = token.alice, make()
    row = PAYMETA[0]
    salt, meta = bytes.fromhex(row['salt'][2:]), bytes.fromhex(row['meta'][2:])
    pid = meta_pay_id(salt, meta)
    o, a = signed(token, alice, native(bob), 9, pay_ref=pid, lane=pay_lane(pid))
    r = token.mtx(relayer, 'mtx_pay_meta', o, a, salt, meta)
    ev = events(token, r)
    assert [n for n, _ in ev] == ['PaymentMeta', 'MetaTransactionExecuted', 'arc200_Transfer', 'PaymentSettled']
    assert ev[0][1] == [pid, meta]                                    # PaymentMeta(pay_ref, meta)
    assert ev[3][1] == [[0, alice.key], [0, bob.key], 9, pid]          # PaymentSettled(from, to, amount, pay_ref)
    assert ev[1][1] == [[0, alice.key], relayer.addr, pay_lane(pid), 0, digest(o)]   # MetaTransactionExecuted
    assert bal(token, bob) == 9


def test_algorand_pay_meta_mismatch_and_replay(token, make, relayer):
    alice, bob = token.alice, make()
    row = PAYMETA[1]
    salt, meta = bytes.fromhex(row['salt'][2:]), bytes.fromhex(row['meta'][2:])
    pid = meta_pay_id(salt, meta)
    o, a = signed(token, alice, native(bob), 3, pay_ref=pid, lane=pay_lane(pid))
    with no('pay-meta shape'):
        token.mtx(relayer, 'mtx_pay_meta', o, a, b'\x00' * 32, meta)          # wrong salt
    with no('pay-meta shape'):
        token.mtx(relayer, 'mtx_pay_meta', o, a, salt, meta + b'\x00')        # other meta
    for kw in ({'lane': b'\x05' * 32}, {'nonce': 1}):                        # lane ≠ payLane, nonce ≠ 0
        ob, ab = signed(token, alice, native(bob), 3, pay_ref=pid, **{'lane': pay_lane(pid), **kw})
        with no('pay-meta shape'):
            token.mtx(relayer, 'mtx_pay_meta', ob, ab, salt, meta)
    token.mtx(relayer, 'mtx_pay_meta', o, a, salt, meta)
    with no('wrong lane nonce'):                                             # replay of (from, pay_ref)
        token.mtx(relayer, 'mtx_pay_meta', o, a, salt, meta)
    with no('wrong lane nonce'):                                             # the same op through mtx_pay
        token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR)
    assert bal(token, bob) == 3


def test_pay_meta_cap_measured(token, make, relayer):
    """Ruling (d): MAX_PAY_META_BYTES succeeds, one byte more is refused (the AVM's 1,024 B log limit)."""
    alice = token.alice
    for size, ok in ((MAX_PAY_META_BYTES, True), (MAX_PAY_META_BYTES + 1, False)):
        salt = sha256(b'cap', size.to_bytes(4, 'big'))
        meta = bytes([0xab]) * size
        pid = meta_pay_id(salt, meta)
        o, a = signed(token, alice, ua(sha256(b'ua', salt)), 1, pay_ref=pid, lane=pay_lane(pid))
        args = 4 + 291 + 2 + 64 + 32 + 2 + size     # selector, op, auth (len ‖ 64), salt, meta (len ‖ bytes)
        assert args <= 2048
        if ok:
            r = token.mtx(relayer, 'mtx_pay_meta', o, a, salt, meta)
            logged = sum(len(x) for x in r.logs)
            print('\nMAX_PAY_META_BYTES = %d (logs %d / 1024 B, app args %d / 2048 B)' % (size, logged, args))
            assert logged <= 1024 and 'UaTransfer' in names(token, r)
        else:
            with no('logs'):
                token.mtx(relayer, 'mtx_pay_meta', o, a, salt, meta)


# ---------------------------------------------------------------- signatures (§4.3, §4.6; R7)
def test_rekeyed_address_signs_with_auth_addr(token, make, relayer):
    alice, bob = token.alice, make(200_000)
    wait(ALGOD.send_transaction(transaction.PaymentTxn(alice.addr, sp(), alice.addr, 0, rekey_to=bob.addr)
                                .sign(alice.sk)))
    with no('bad signature'):
        pay(token, relayer, alice, native(bob), 1)
    o = token.op(alice, native(bob), 1, pay_ref=b'\x01' * 32)
    token.mtx(relayer, 'mtx_pay', o, bob.sign_op(digest(o)), ZERO_ADDR)
    assert bal(token, bob) == 1


def test_rekeyed_to_logicsig_refused_natively(token, make, relayer):
    alice, bob = token.alice, make()
    pay(token, relayer, alice, native(bob), 1, lane=b'\x0a' * 32)            # not rekeyed: her own key signs
    prog = ALGOD.compile('#pragma version 10\nint 1')['result']
    lsig = transaction.LogicSigAccount(__import__('base64').b64decode(prog))
    wait(ALGOD.send_transaction(transaction.PaymentTxn(alice.addr, sp(), alice.addr, 0, rekey_to=lsig.address())
                                .sign(alice.sk)))
    with no('bad signature'):
        pay(token, relayer, alice, native(bob), 1, lane=b'\x0b' * 32)
    dave = make(300_000)                                                     # rekeyed to a 2-of-2 multisig
    msig = transaction.Multisig(1, 2, [dave.addr, bob.addr])
    wait(ALGOD.send_transaction(transaction.PaymentTxn(dave.addr, sp(), dave.addr, 0, rekey_to=msig.address())
                                .sign(dave.sk)))
    o = token.op(dave, native(bob), 1, pay_ref=b'\x01' * 32, lane=b'\x0c' * 32)
    for signer in (dave, bob):                       # neither the old key nor a member's key alone verifies
        with no('bad signature'):
            token.mtx(relayer, 'mtx_pay', o, signer.sign_op(digest(o)), ZERO_ADDR)
    assert bal(token, bob) == 1


def test_wrong_network_refused(token, make, relayer):
    alice, bob = token.alice, make()
    with no('wrong network'):
        pay(token, relayer, alice, native(bob), 1, network=sha256(b'another genesis'))
    with no('wrong contract'):
        pay(token, relayer, alice, native(bob), 1, contract=sha256(b'another app'))
    with no('bad signature'):                       # a signature over another op
        o, _ = signed(token, alice, native(bob), 1, pay_ref=b'\x01' * 32)
        _, a2 = signed(token, alice, native(bob), 2, pay_ref=b'\x01' * 32)
        token.mtx(relayer, 'mtx_pay', o, a2, ZERO_ADDR)


def test_valid_until_seconds(token, make, relayer):
    alice, bob = token.alice, make()
    ts = latest_ts()
    with no('expired'):
        pay(token, relayer, alice, native(bob), 1, valid_until=ts - 1)
    pay(token, relayer, alice, native(bob), 1, valid_until=ts + 1)
    ts2 = latest_ts()
    pay(token, relayer, alice, native(bob), 1, valid_until=ts2, nonce=1)     # valid through its last second
    assert bal(token, bob) == 2


def test_relayer_bound_to_sender(token, make, relayer):
    alice, bob, other = token.alice, make(), make(10_000_000)
    with no('relayer is not the sender'):
        pay(token, other, alice, native(bob), 1, relayer=relayer.key)
    r = pay(token, relayer, alice, native(bob), 1, relayer=relayer.key)
    assert dict(events(token, r))['MetaTransactionExecuted'][1] == relayer.addr
    pay(token, other, alice, native(bob), 1, lane=b'\x0c' * 32)              # relayer zero: any sender
    assert bal(token, bob) == 2


def test_ua_signer_needs_the_account_app(token, make, relayer):
    i = b'\x55' * 32
    run(token.alice, token, 'transfer_to_ua', [i, 10], mbr=MBR_UA, boxes=[b'b' + token.alice.key, b'u' + i])
    o = token.op(ua(i), native(make()), 1, pay_ref=b'\x01' * 32)
    with no('UA signer'):
        token.mtx(relayer, 'mtx_pay', o, b'\x00' * 64, ZERO_ADDR, mbr=None)


# ---------------------------------------------------------------- entries
def test_pay_to_token_app_refused(token, relayer):
    alice = token.alice
    with no('token itself'):
        pay(token, relayer, alice, native(token.key), 1, mbr=None)
    o, a = signed(token, alice, native(token.key), 1, code=4)
    with no('token itself'):
        token.mtx(relayer, 'mtx_transfer', o, a, mbr=None)
    with no('token itself'):
        run(alice, token, 'arc200_transfer', [token.address, 1], boxes=[b'b' + alice.key, b'b' + token.key])
    with no('token itself'):
        run(token.admin, token, 'mint', [token.address, 1], boxes=[b'b' + token.key])
    assert bal(token, alice) == 1_000_000


def test_transfer_and_execute_transfer(token, make, relayer):
    alice, bob = token.alice, make()
    o, a = signed(token, alice, native(bob), 4, code=4, lane=b'\x21' * 32)
    r = token.mtx(relayer, 'mtx_transfer', o, a)
    assert names(token, r) == ['MetaTransactionExecuted', 'arc200_Transfer']          # no pay_ref, no settlement
    for code, ref, method, msg in ((4, b'\x01' * 32, 'mtx_transfer', 'mtx_transfer carries no pay_ref'),
                                   (0, b'\x01' * 32, 'mtx_transfer', 'wrong op code'),
                                   (4, Z32, 'mtx_pay', 'wrong op code'),
                                   (0, Z32, 'mtx_pay', 'mtx_pay needs a pay_ref'),
                                   (0, b'\x01' * 32, 'mtx_execute_transfer', 'wrong op code')):
        ob, ab = signed(token, alice, native(bob), 1, code=code, pay_ref=ref, lane=b'\x22' * 32)
        extra = (ZERO_ADDR,) if method == 'mtx_pay' else ()
        with no(msg):
            token.mtx(relayer, method, ob, ab, *extra, mbr=None)
    o, a = signed(token, alice, native(bob), 5, code=5, pay_ref=b'\x07' * 32, lane=b'\x23' * 32)
    r = token.mtx(relayer, 'mtx_execute_transfer', o, a)
    assert names(token, r) == ['MetaTransactionExecuted', 'arc200_Transfer', 'PaymentSettled']
    o, a = signed(token, alice, native(bob), 6, code=5, lane=b'\x23' * 32, nonce=1)
    assert names(token, token.mtx(relayer, 'mtx_execute_transfer', o, a)) == ['MetaTransactionExecuted',
                                                                              'arc200_Transfer']
    for amount, to, msg in ((0, native(bob), 'positive'), (1, native(alice), 'Sender and receiver')):
        ob, ab = signed(token, alice, to, amount, code=4, lane=b'\x24' * 32)
        with no(msg):
            token.mtx(relayer, 'mtx_transfer', ob, ab, mbr=None)
    with no('balance'):
        o, a = signed(token, alice, native(bob), 1_000_001, code=4, lane=b'\x25' * 32)
        token.mtx(relayer, 'mtx_transfer', o, a, mbr=None)
    assert bal(token, bob) == 15 and view(token, 'lane_nonce', 0, alice.key, b'\x23' * 32) == 2


def test_transfer_to_ua_and_ua_balance_of(token):
    alice, i = token.alice, sha256(b'some UA')
    boxes = [b'b' + alice.key, b'u' + i]
    with no('MBR payment'):
        run(alice, token, 'transfer_to_ua', [i, 100], boxes=boxes)
    r = run(alice, token, 'transfer_to_ua', [i, 100], mbr=MBR_UA, boxes=boxes)
    ev = events(token, r)
    assert [n for n, _ in ev] == ['arc200_Transfer', 'UaTransfer']
    assert ev[0][1] == [alice.addr, token.address, 100]                  # the UA pool, as NEAR
    assert ev[1][1] == [[0, alice.key], [1, i], 100]
    run(alice, token, 'transfer_to_ua', [i, 50], boxes=boxes)
    assert ua_bal(token, i) == 150 and ua_bal(token, b'\x01' * 32) == 0
    assert bal(token, token.address) == 150 and view(token, 'arc200_totalSupply') == 1_000_000


def test_open_payee_only_in_open_mode(token, probe, make, relayer):
    alice, bob, carol = token.alice, make(), make()

    def via_probe(o, a, open_payee, payee):
        mbr = MBR_LANE + (MBR_BALANCE if bal(token, payee) == 0 else 0)
        return run(relayer, probe, 'pay', [token.id, o, a, open_payee.addr, mbr], apps=[token.id],
                   accounts=[alice.addr], fee_extra=2 * MIN_FEE, budget=BUDGET, box_app=token,
                   boxes=token.boxes(o, native(payee)))
    o, a = signed(token, alice, native(probe.key), 7, pay_ref=b'\x31' * 32, relayer=probe.key, lane=b'\x31' * 32)
    via_probe(o, a, bob, bob)                                     # open mode: to == relayer == the calling app
    assert bal(token, bob) == 7 and bal(token, probe.address) == 0
    o, a = signed(token, alice, native(carol), 8, pay_ref=b'\x32' * 32, relayer=probe.key, lane=b'\x32' * 32)
    via_probe(o, a, bob, carol)                                   # bound payee: open_payee ignored
    assert bal(token, carol) == 8 and bal(token, bob) == 7
    o, a = signed(token, alice, native(Z32), 6, pay_ref=b'\x34' * 32, lane=b'\x34' * 32)
    run(relayer, probe, 'pay', [token.id, o, a, bob.addr, MBR_LANE + MBR_BALANCE], apps=[token.id],
        accounts=[alice.addr], fee_extra=2 * MIN_FEE, budget=BUDGET, box_app=token,
        boxes=token.boxes(o, native(Z32)))        # to == relayer == zero: no open mode (relayer ≠ the calling app)
    assert bal(token, ZERO_ADDR) == 6 and bal(token, bob) == 7
    o, a = signed(token, alice, native(relayer), 9, pay_ref=b'\x33' * 32, relayer=relayer.key, lane=b'\x33' * 32)
    token.mtx(relayer, 'mtx_pay', o, a, bob.addr)                 # to == relayer, but no app: op.to is paid
    assert bal(token, relayer) == 9 and bal(token, bob) == 7


def test_approve_only_app_to_app(token, probe, make, dispenser):
    from conftest import deploy_probe
    alice, bob, p2 = token.alice, make(), deploy_probe(dispenser)
    run(token.admin, token, 'mint', [probe.address, 100], mbr=MBR_BALANCE, boxes=[b'b' + probe.key])
    akey = b'a' + sha256(probe.key, p2.key)

    def approve(spender, spender_app, value=100, mbr=MBR_ALLOWANCE):
        return run(dispenser, probe, 'approve', [token.id, spender, value, spender_app.id, mbr],
                   apps=[token.id, spender_app.id], fee_extra=2 * MIN_FEE, box_app=token, boxes=[akey])
    with no('only an app'):
        run(alice, token, 'arc200_approve', [p2.address, 1], boxes=[b'a' + sha256(alice.key, p2.key)],
            mbr=MBR_ALLOWANCE)
    carol = make(300_000)                                           # an account rekeyed to the probe app
    wait(ALGOD.send_transaction(transaction.PaymentTxn(carol.addr, sp(), carol.addr, 0, rekey_to=probe.address)
                                .sign(carol.sk)))
    with no('only an app'):                                         # sender = carol, caller app = probe
        run(dispenser, probe, 'approve_as', [token.id, carol.addr, p2.address, 5, p2.id, MBR_ALLOWANCE],
            accounts=[carol.addr], apps=[token.id, p2.id], fee_extra=2 * MIN_FEE, box_app=token,
            boxes=[b'a' + sha256(carol.key, p2.key)])
    with no('spender must be an app'):
        approve(bob.addr, p2)                                       # an ordinary account as spender
    with no('spender must be an app'):
        approve(p2.address, probe)                                  # named app ≠ spender
    r = approve(p2.address, p2)
    assert events(token, r) == [('arc200_Approval', [probe.address, p2.address, 100])]
    assert view(token, 'arc200_allowance', probe.address, p2.address) == 100
    with no('only an app'):
        run(alice, token, 'arc200_transferFrom', [probe.address, bob.addr, 1],
            boxes=[b'a' + sha256(probe.key, alice.key), b'b' + probe.key, b'b' + bob.key])
    run(dispenser, p2, 'transfer_from', [token.id, probe.address, bob.addr, 60, MBR_BALANCE], apps=[token.id],
        fee_extra=2 * MIN_FEE, box_app=token, boxes=[akey, b'b' + probe.key, b'b' + bob.key])
    assert view(token, 'arc200_allowance', probe.address, p2.address) == 40 and bal(token, bob) == 60
    with no('allowance'):
        run(dispenser, p2, 'transfer_from', [token.id, probe.address, bob.addr, 41, 0], apps=[token.id],
            fee_extra=2 * MIN_FEE, box_app=token, boxes=[akey, b'b' + probe.key, b'b' + bob.key])


# ---------------------------------------------------------------- amounts (Review Focus 5)
def test_amount_u128_max_and_supply_cap(token, make, relayer):
    alice, bob, carol = token.alice, make(), make()
    run(token.admin, token, 'mint', [bob.addr, U128_MAX - 1_000_000], mbr=MBR_BALANCE, boxes=[b'b' + bob.key])
    assert view(token, 'arc200_totalSupply') == U128_MAX
    with no('supply above 2^128 - 1'):
        run(token.admin, token, 'mint', [bob.addr, 1], boxes=[b'b' + bob.key])
    run(alice, token, 'arc200_transfer', [bob.addr, 1_000_000], boxes=[b'b' + alice.key, b'b' + bob.key])
    assert bal(token, bob) == U128_MAX
    r = pay(token, relayer, bob, native(carol), U128_MAX)
    assert bal(token, carol) == U128_MAX and bal(token, bob) == 0
    assert dict(events(token, r))['PaymentSettled'][2] == U128_MAX


# ---------------------------------------------------------------- storage and authority (§4.1, §4.9)
def test_box_prefixes_disjoint(token, make, relayer):
    alice = token.alice
    run(alice, token, 'transfer_to_ua', [alice.key, 7], mbr=MBR_UA, boxes=[b'b' + alice.key, b'u' + alice.key])
    assert ua_bal(token, alice.key) == 7 and bal(token, alice) == 1_000_000 - 7       # same 32 bytes, two boxes
    pay(token, relayer, alice, native(make()), 1)
    boxes = [bytes(__import__('base64').b64decode(b['name'])) for b in ALGOD.application_boxes(token.id)['boxes']]
    assert sorted({b[:1] for b in boxes}) == [b'b', b'l', b'u'] and all(len(b) == 33 for b in boxes)


def refused_actions(token, who, kinds):
    """Each OnCompletion in `kinds`, bare and with an ABI selector: the bare form is the router's `budget` path
    (`return OnCompletion == NoOp && app ≠ 0` → "rejected by ApprovalProgram"), the ABI form fails the router's
    `OnCompletion == NoOp` assert (the same pc for every kind)."""
    a, sel = token.app, token.app.methods['arc200_name'].get_selector()
    make_ = {'update': lambda **k: transaction.ApplicationUpdateTxn(who.addr, sp(), token.id, a.approval, a.clear, **k),
             'delete': lambda **k: transaction.ApplicationDeleteTxn(who.addr, sp(), token.id, **k),
             'optin': lambda **k: transaction.ApplicationOptInTxn(who.addr, sp(), token.id, **k),
             'closeout': lambda **k: transaction.ApplicationCloseOutTxn(who.addr, sp(), token.id, **k)}
    pcs = set()
    for kind in kinds:
        with pytest.raises(AlgodHTTPError, match='rejected by ApprovalProgram'):
            wait(ALGOD.send_transaction(make_[kind]().sign(who.sk)))
        with pytest.raises(AlgodHTTPError, match=r'logic eval error: assert failed pc=\d+') as e:
            wait(ALGOD.send_transaction(make_[kind](app_args=[sel]).sign(who.sk)))
        pcs.add(re.search(r'assert failed pc=(\d+)', str(e.value)).group(1))
    assert len(pcs) == 1


def test_update_and_delete_refused(token, make):
    refused_actions(token, token.admin, ['update', 'delete'])          # the creator included
    assert ALGOD.application_info(token.id)['params']['approval-program'] == __import__('base64').b64encode(
        token.app.approval).decode()


def test_optin_refused(token):
    refused_actions(token, token.alice, ['optin', 'closeout'])


# ---------------------------------------------------------------- figures (§11: measured and pinned)
def test_figures_pinned(token, make, relayer):
    alice, bob = token.alice, make()
    o, a = signed(token, alice, native(bob), 1, pay_ref=b'\x41' * 32, lane=b'\x41' * 32)
    zero = ZERO_ADDR
    out = {}
    for method, args, mbr in (('mtx_pay', [o, a, zero], MBR_LANE + MBR_BALANCE),
                              ('mtx_transfer', None, None), ('mtx_pay_meta', None, None),
                              ('arc200_transfer', [bob.addr, 1], MBR_BALANCE)):
        if method == 'mtx_transfer':
            ob, ab = signed(token, alice, native(bob), 1, code=4, lane=b'\x42' * 32)
            args, mbr = [ob, ab], MBR_LANE + MBR_BALANCE
        if method == 'mtx_pay_meta':
            salt, meta = b'\x43' * 32, b'\xab' * MAX_PAY_META_BYTES
            pid = meta_pay_id(salt, meta)
            ob, ab = signed(token, alice, ua(b'\x44' * 32), 1, pay_ref=pid, lane=pay_lane(pid))
            args, mbr = [ob, ab, salt, meta], MBR_LANE + MBR_UA
        sender = alice if method == 'arc200_transfer' else relayer
        _, used, fail, _ = sim(sender, token, method, args, mbr=mbr, budget=BUDGET if method != 'arc200_transfer'
                               else 0)
        assert fail is None, fail
        out[method] = used
        assert used <= BUDGET_PIN[method] <= 700 * (1 + (BUDGET if method != 'arc200_transfer' else 0)), (method, used)
    print('\nopcode budget used: %s (pins %s; pooled 700 per app call, BUDGET = %d bare calls per mtx_*)'
          % (out, BUDGET_PIN, BUDGET))
    print('MBR per box (µALGO): balance %d, ua %d, lane %d, allowance %d'
          % (MBR_BALANCE, MBR_UA, MBR_LANE, MBR_ALLOWANCE))
    print('program sizes (B): approval %d, clear %d' % (len(token.app.approval), len(token.app.clear)))
