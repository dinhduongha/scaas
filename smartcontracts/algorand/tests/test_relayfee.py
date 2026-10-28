"""Relay-fee router + executor LogicSig on localnet (near-algorand T15; spec §4.8, §4.9, §2 rows 8–15, CTR-MTX-16 /
CTR-MTX-27; rulings R2, R3, R5, R7, R11, T15 pre-flight (a)–(j); NEAR router (Task 10) and TON router lessons).

One atomic group, no escrow: `[Payment → router]? [Payment → target]? [target call, sender = executor] [router.relay(
token, op, auth)] [box / budget calls]`. The executor LogicSig sends the target (the target never sees the lane); the
router checks rule 13 and the payment shape (pay_ref = ref of the call actually run, salt = op.extra, lane =
payLane(ref), nonce 0, relayer = the router) and runs `[Payment → token]? [token.mtx_pay(op, auth, open_payee = lane)]`
as inner transactions. Anything failing fails the group: the payer is never charged for a call that did not happen."""
import base64
import json
import os
import re

import pytest
from algosdk import encoding, logic, transaction
from algosdk.atomic_transaction_composer import (AtomicTransactionComposer, LogicSigTransactionSigner,
                                                 TransactionWithSigner)
from algosdk.error import AlgodHTTPError
from algosdk.v2client import models

from conftest import (ALGOD, DEPLOYED, EXEC_PREFIX, EXEC_SUFFIX, MBR_BALANCE, MBR_LANE, MIN_FEE, OUT, ROOT, SLOT, Z32,
                      EdKey, MsigKey, Refused, deploy, deploy_router, digest, exec_salt, explain, fund, genesis, holder,
                      keccak, native, on_curve, exec_program, pay_lane, rec_mbr, refused_actions, run, sha256,
                      sign_as, sp, spec, view)
from test_account import ChromeKey, arg_bytes
from test_dex import LANE_A, MBR_ORDER, deploy_dex, min_nonce_key, order_key, pair, setup_legs  # noqa: F401 (pair)
from test_mandate import (FEE_CREDIT, MBR_MANDATE, Group, Man, amount_box, bal, events, fund_ua, patch, sim_view,
                          token_mbr, u64)

NOOP, OPTIN, CLEAR = transaction.OnComplete.NoOpOC, transaction.OnComplete.OptInOC, transaction.OnComplete.ClearStateOC
SALT = b'\x5a' * 32
SHAPE = 'payment shape (pay_ref = ref of the target call, lane = payLane(ref), nonce 0, relayer = router)'
MISSING = 'target app missing (rule 13)'
NOT_EXEC = 'target sender is not the executor'
MBR = 'MBR payment must equal'
SENTINEL = bytes.fromhex('5ca5ec0de0e1ec01')
EXEC_MAP = json.load(open(os.path.join(OUT, 'Executor.puya.map')))
EXEC_ERRORS = {int(pc): e['op'].split('// ', 1)[1] for pc, e in EXEC_MAP['pc_events'].items()
               if e.get('op', '').startswith('assert //')}
# Opcode budget of a relay group (simulate, no bare budget calls: the token / account raise their own by inner budget
# calls on the lane's pooled fee), (consumed, inner app calls) — runs/2026-10-28-algorand-limits.txt
BUDGET_PIN = {'ping, native payer': (3950, 6), 'ping, ed25519 UA payer': (4650, 6), 'ping, passkey UA payer': (6850, 9),
              'ed25519 UA transfer, passkey UA payer': (10250, 14),
              'msig 3 passkey transfer, passkey UA payer': (23400, 32),
              'msig 3 passkey transfer, msig 3 passkey payer': (35000, 47)}


def no(*msgs):
    return pytest.raises(Refused, match='.*'.join(re.escape(m) for m in msgs))


def lsig_explain(msg):
    """A LogicSig rejection's pc → the executor's assert message."""
    m = re.search(r'rejected by logic err=.*?pc=(\d+)', msg)
    return ('executor: ' + EXEC_ERRORS.get(int(m.group(1)), '?') + ' :: ') if m else ''


def app_key(app_id):
    return encoding.decode_address(logic.get_application_address(app_id))


def call_bytes(app_id, app_args):
    """§4.8: target app id (u64) ‖ u8 n ‖ (u16 len ‖ arg)×n."""
    return u64(app_id) + bytes([len(app_args)]) + b''.join(len(a).to_bytes(2, 'big') + a for a in app_args)


def ref_of(app_id, app_args, salt=SALT, network=None):
    return keccak(b'scaas.relayfee', network or genesis(), app_key(app_id), keccak(call_bytes(app_id, app_args)), salt)


def abi_args(d, method, args):
    m = d.app.methods[method]
    return [m.get_selector()] + [a.type.encode(v) for a, v in zip(m.args, args)]


class Tgt:
    """A relay target: `app_args` on app `app_id` (0 with `create` = an app create), sent by the executor unless
    `sender`; `mbr` = its own exact-MBR payment just before it; `boxes` / `accounts` / `apps` its resources; `before`
    transactions placed ahead of both."""

    def __init__(self, d, method=None, args=(), app_args=None, app_id=None, oc=NOOP, sender=None, mbr=None,
                 boxes=(), accounts=(), apps=(), rekey=None, fee=0, create=False, before=()):
        self.d = d
        self.app_id = d.id if app_id is None else app_id
        self.app_args = app_args if app_args is not None else abi_args(d, method, args)
        self.oc, self.sender, self.mbr, self.boxes = oc, sender, mbr, list(boxes)
        self.accounts, self.apps, self.rekey, self.fee, self.create = list(accounts), list(apps), rekey, fee, create
        self.before = list(before)

    def ref(self, salt=SALT):
        return ref_of(self.app_id, self.app_args, salt)

    def txns(self, router, lane):
        out = list(self.before)
        if self.mbr:
            out.append(TransactionWithSigner(
                transaction.PaymentTxn(lane.addr, sp(), logic.get_application_address(self.app_id), self.mbr),
                lane.signer))
        addr = self.sender.addr if self.sender else router.executor
        signer = self.sender.signer if self.sender else LogicSigTransactionSigner(router.lsig)
        if self.create:
            a = self.d.app
            t = transaction.ApplicationCreateTxn(addr, sp(self.fee), NOOP, a.approval, a.clear,
                                                 transaction.StateSchema(a.schema['ints'], a.schema['bytes']),
                                                 transaction.StateSchema(0, 0), app_args=self.app_args)
        else:
            t = transaction.ApplicationCallTxn(addr, sp(self.fee), self.app_id, self.oc, app_args=self.app_args,
                                               accounts=self.accounts or None, foreign_apps=self.apps or None,
                                               rekey_to=self.rekey)
        out.append(TransactionWithSigner(t, signer))
        return out


def fee_op(token, router, payer, tgt, amount=10, to=None, salt=SALT, **kw):
    """The payer's op: a plain pay of `ref` on payLane(ref) at nonce 0, relayer = the router, extra = salt; `to` the
    router (open mode: the submitting lane is paid) unless a bound payee."""
    r = tgt.ref(salt)
    o = token.op(holder(payer), list(holder(to)) if to is not None else [0, router.key], amount, pay_ref=r,
                 lane=pay_lane(r), nonce=0, relayer=router.key, extra=salt)
    return patch(o, kw)


def pay_mbr(token, o, auth, payee):
    """The token's exact part: its boxes for `payee` (the lane in open mode) + a UA payer's record when it opens."""
    need = view(token, 'mbr_needed', patch(o, {'to': list(payee)}))
    if not (o[3][0] == 0 and len(auth) == 64):
        v, _, fail, _ = sim_view(token.account, 'verify_mbr', [o[3][0], bytes(o[3][1]), digest(o), auth])
        need += 0 if fail else v
    return need


def payee_of(router, lane, o):
    return native(lane) if (o[4][0], bytes(o[4][1])) == (0, router.key) else (o[4][0], bytes(o[4][1]))


def relay(lane, router, token, tgt, o, auth, router_mbr='auto', mbr_delta=0, pay_kw=None, after=(), boxes=(),
          simulate=False, fee=None, mbr_payer=None):
    """`lane` submits `[Payment → router]? [target MBR]? [target] [router.relay(token, o, auth)] [after…] [budget calls
    on the token carrying the boxes]`; `router_mbr` = what the router forwards to the token (auto: exact), paid by
    `mbr_payer` (default the lane)."""
    if router_mbr == 'auto':
        router_mbr = pay_mbr(token, o, auth, payee_of(router, lane, o)) + mbr_delta
    atc = AtomicTransactionComposer()
    if router_mbr:
        p = mbr_payer or lane
        atc.add_transaction(TransactionWithSigner(
            transaction.PaymentTxn(p.addr, sp(), router.address, router_mbr, **(pay_kw or {})), p.signer))
    for t in tgt.txns(router, lane):
        atc.add_transaction(t)
    frm, payee = (o[3][0], bytes(o[3][1])), payee_of(router, lane, o)
    accounts = [encoding.encode_address(frm[1])] if frm[0] == 0 else []
    atc.add_method_call(router.id, router.app.methods['relay'], lane.addr,
                        sp(2 * MIN_FEE + FEE_CREDIT if fee is None else fee), lane.signer, [token.id, o, auth],
                        accounts=accounts or None, foreign_apps=[token.id, token.account.id])
    for t in after:
        atc.add_transaction(t)
    acc = token.account
    names = [(token, b'l' + sha256(bytes([frm[0]]), frm[1], o[8])), (token, amount_box(frm)),
             (token, amount_box(payee)), (acc, acc.name(frm))] + tgt.boxes + list(boxes)
    if not simulate:
        box_calls(atc, lane, token, names)
    if simulate:
        r = atc.simulate(ALGOD, models.SimulateRequest(txn_groups=[], allow_unnamed_resources=True))
        g = r.simulate_response['txn-groups'][0]
        calls = sum(1 for t in atc.txn_list if t.txn.type == 'appl')
        inner = g.get('app-budget-added', 0) // 700 - calls
        fail = r.failure_message
        return g.get('app-budget-consumed'), inner, (lsig_explain(fail) + explain(fail) if fail else None)
    try:
        res = atc.execute(ALGOD, 4)
    except AlgodHTTPError as e:
        raise Refused(lsig_explain(str(e)) + explain(str(e))) from None
    return Group([ALGOD.pending_transaction_info(t) for t in res.tx_ids])


def box_calls(atc, lane, token, names):
    """Box references on bare budget calls to the token, 5 per call with their apps (group resource sharing)."""
    names = list(dict.fromkeys(names))
    for i in range((len(names) + 4) // 5):
        chunk = names[5 * i:5 * i + 5]
        apps = sorted({a.id for a, _ in chunk if a.id != token.id})
        atc.add_transaction(TransactionWithSigner(transaction.ApplicationNoOpTxn(
            lane.addr, sp(), token.id, note=b'box%d' % i, foreign_apps=apps or None,
            boxes=[(a.id, b) for a, b in chunk]), lane.signer))


def algo(addr):
    return ALGOD.account_info(addr)['amount']


@pytest.fixture
def lane(make):
    return make(50_000_000)


@pytest.fixture
def target(dispenser):
    d = deploy(dispenser, 'RelayTarget', [])
    DEPLOYED[d.id] = d
    return d


@pytest.fixture
def fresh_router(dispenser):
    """A router of its own (tests that fund its executor leave the shared one clean)."""
    return deploy_router(dispenser)


def gstate(d):
    out = {}
    for g in ALGOD.application_info(d.id)['params'].get('global-state', []):
        v = g['value']
        out[base64.b64decode(g['key']).decode()] = v['uint'] if v['type'] == 2 else base64.b64decode(v['bytes'])
    return out


def ping(target, x=7, **kw):
    return Tgt(target, 'ping', [x], **kw)


# ---------------------------------------------------------------- plan Step 1
def test_relay_open_mode_pays_lane(router, token, target, lane):
    """Open mode (`to == relayer ==` the router, CTR-MTX-27 step 5): the lane that submitted the relay is paid,
    atomically with the call; the target saw the executor as its sender, never the lane; RelayFeePaid names the ref,
    target, token, payer, payee and amount, and the token's PaymentSettled the lane as payee."""
    alice = token.alice
    t = ping(target)
    o = fee_op(token, router, alice, t)
    r = relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert (bal(token, native(alice)), bal(token, native(lane))) == (1_000_000 - 10, 10)
    s = gstate(target)
    assert s['calls'] == 1 and encoding.encode_address(s['last']) == router.executor != lane.addr
    ref = t.ref()
    assert norm(r.own(router)) == [('RelayFeePaid', [ref, target.id, token.id, [0, alice.key], [0, lane.key], 10])]
    assert ('PaymentSettled', [[0, alice.key], [0, lane.key], 10, ref]) in norm(events(token.app, r.logs))
    assert ('Pinged', [7, router.executor]) in norm(events(target.app, r.logs))
    assert bytes(view(router, 'relay_ref', call_bytes(target.id, t.app_args), SALT)) == ref
    with no('wrong lane nonce'):                           # the same payment never runs twice
        relay(lane, router, token, t, o, alice.sign_op(digest(o)), router_mbr=None)


def norm(evs):
    """ARC-4 decoded events with byte arrays as bytes (static byte arrays decode as lists of ints)."""
    def n(x):
        if isinstance(x, list):
            return bytes(x) if x and all(isinstance(i, int) and 0 <= i < 256 for i in x) and len(x) == 32 else [
                n(i) for i in x]
        return x
    return [(name, n(v)) for name, v in evs]


def test_relay_bound_payee(router, token, target, lane, make):
    """A bound payee (`to` = an address or a UA id) is paid directly; the lane gets nothing (CTR-MTX-27 step 5)."""
    alice, bob, erin = token.alice, make(), EdKey('erin-bound')
    for i, payee in enumerate((native(bob), erin.ua())):
        t = ping(target, 100 + i)
        o = fee_op(token, router, alice, t, amount=10, to=payee)
        r = relay(lane, router, token, t, o, alice.sign_op(digest(o)))
        assert ('RelayFeePaid', [t.ref(), target.id, token.id, [0, alice.key], [payee[0], bytes(payee[1])], 10]) in \
            norm(r.own(router))
    assert (bal(token, native(bob)), bal(token, erin.ua()), bal(token, native(lane))) == (10, 10, 0)


def test_target_failure_rejects_group(router, token, target, lane):
    """CTR-MTX-16: a failing target fails the whole group — the payer pays nothing, its lane stays unused."""
    alice = token.alice
    t = Tgt(target, 'fail')
    o = fee_op(token, router, alice, t)
    with no('target failed'):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert (bal(token, native(alice)), bal(token, native(lane))) == (1_000_000, 0)
    assert view(token, 'lane_nonce', 0, alice.key, o[8]) == 0


def test_algorand_router_bound_pay_refused_direct(router, token, target, lane, probe):
    """A router-bound op (relayer = the router address, which no transaction can sign for) settles only inside a
    relay: the token's rule 7 refuses it at the top level and through any other app (the probe)."""
    alice = token.alice
    o = fee_op(token, router, alice, ping(target), to=native(lane))
    a = alice.sign_op(digest(o))
    with no('relayer is not the sender'):
        token.mtx(lane, 'mtx_pay', o, a, lane.addr)
    with no('relayer is not the sender'):
        run(lane, probe, 'pay', [token.id, o, a, lane.addr, MBR_LANE + MBR_BALANCE], apps=[token.id, token.account.id],
            boxes=[(token, n) for n in token.boxes(o)], accounts=[alice.addr], fee_extra=FEE_CREDIT)
    assert bal(token, native(alice)) == 1_000_000


def test_target_not_by_executor_refused(router, token, target, lane, make):
    """Rule 11: the target must be sent by this router's executor — not the lane, not another account (another router's
    executor cannot sign it: its program wants its own router's relay next)."""
    alice = token.alice
    for sender in (lane, make(1_000_000)):
        t = ping(target, sender=sender)
        o = fee_op(token, router, alice, t)
        with no(NOT_EXEC):
            relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert bal(token, native(alice)) == 1_000_000


def test_clearstate_target_refused(router, token, target, lane):
    """Rule 13: a ClearState call cannot fail, so it is never a target; nor any OnCompletion but NoOp (the executor's
    program refuses it first; the router checks it again)."""
    alice = token.alice
    for oc in (CLEAR, OPTIN):
        t = Tgt(target, 'join', oc=oc)
        o = fee_op(token, router, alice, t)
        with no('executor: only NoOp'):
            relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert bal(token, native(alice)) == 1_000_000


def test_missing_app_refused(fresh_router, token, target, lane, dispenser):
    """Rule 13: the target app exists. An app create (id 0: `app_params_get(0)` would read the router itself) is refused
    by the router even when someone funded the executor so the create could pay its MBR; an id with no app fails at
    the protocol."""
    router, alice = fresh_router, token.alice
    fund(dispenser, router.executor, 1_000_000)
    t = Tgt(target, app_args=abi_args(target, 'create', []), app_id=0, create=True)
    o = fee_op(token, router, alice, t)
    with no(MISSING):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    gone = 2**40
    t = Tgt(target, app_args=abi_args(target, 'ping', [1]), app_id=gone)
    o = fee_op(token, router, alice, t)
    with pytest.raises(Refused):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert bal(token, native(alice)) == 1_000_000


def test_target_relayfee_refused(router, token, lane):
    """§4.8: `target == relayfee` refused — here a call of the router's own relay_ref by the executor, signed for."""
    alice = token.alice
    t = Tgt(router, 'relay_ref', [b'\x00' * 8, SALT])
    o = fee_op(token, router, alice, t)
    with no('target is the router'):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert bal(token, native(alice)) == 1_000_000


def test_payee_executor_refused(router, token, target, lane):
    """Rule 12: the executor is never paid (it could not spend it, and anyone could move it by a relayed transfer)."""
    alice = token.alice
    t = ping(target)
    o = fee_op(token, router, alice, t, to=(0, encoding.decode_address(router.executor)))
    with no('the executor is never paid'):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert bal(token, native(alice)) == 1_000_000


def test_add_key_native_target_refused(router, token, lane):
    """T12 m5: no key is ever registered for the executor — `add_key_native` (sender = the address) is never relayed."""
    alice, acc = token.alice, token.account
    k = EdKey('exec-key')
    t = Tgt(acc, 'add_key_native', [k.record(), b''], mbr=rec_mbr(1),
            boxes=[(acc, acc.name((0, encoding.decode_address(router.executor))))])
    o = fee_op(token, router, alice, t)
    with no('add_key_native is never relayed'):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert acc.record((0, encoding.decode_address(router.executor))) is None


def test_payment_shape_refused(router, token, target, lane):
    """Step 1 as NEAR: pay_ref = the ref of the call actually run (salt = op.extra, always), lane = payLane(ref),
    nonce 0, relayer = the router; each field off → refused, nothing moves."""
    alice = token.alice
    t = ping(target, 55)
    other = ping(target, 56)
    o = fee_op(token, router, alice, t)
    r = t.ref()
    cases = (({'pay_ref': other.ref(), 'lane': pay_lane(other.ref())}, SHAPE),   # signed for another call
             ({'pay_ref': other.ref()}, SHAPE),                                  # … on this call's lane
             ({'extra': b'\x01' * 32}, SHAPE),                                  # salt ≠ extra
             ({'lane': b'\x02' * 32}, SHAPE), ({'nonce': 1}, SHAPE),
             ({'relayer': Z32}, SHAPE), ({'relayer': lane.key}, SHAPE))
    for kw, err in cases:
        x = patch(o, kw)
        with no(err):
            relay(lane, router, token, t, x, alice.sign_op(digest(x)))
    # nonce 1 on a lane already at 1 (a direct pay on payLane(ref) first): the router's own nonce check refuses it
    d = patch(o, {'relayer': Z32, 'to': [0, lane.key], 'amount': 1})
    token.mtx(lane, 'mtx_pay', d, alice.sign_op(digest(d)), lane.addr)
    assert view(token, 'lane_nonce', 0, alice.key, pay_lane(r)) == 1
    x = patch(o, {'nonce': 1})
    with no(SHAPE):
        relay(lane, router, token, t, x, alice.sign_op(digest(x)))
    assert bal(token, native(alice)) == 1_000_000 - 1


def test_executor_rejects_rekey_close_fee(fresh_router, token, target, lane, dispenser, make):
    """The executor never rekeys, closes or pays a fee, and sends nothing but an app call: each refused by its program
    (the executor funded by a stranger, so a fee could be paid). Close fields exist only on payments / asset
    transfers, which its first check refuses."""
    router, alice = fresh_router, token.alice
    fund(dispenser, router.executor, 1_000_000)
    thief = make()
    for kw, err in (({'rekey': thief.addr}, 'never rekeys'), ({'fee': MIN_FEE}, 'never pays a fee')):
        t = ping(target, **kw)
        o = fee_op(token, router, alice, t)
        with no('executor: ' + err):
            relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    ex = router.executor
    o = fee_op(token, router, alice, ping(target))
    for txn in (transaction.PaymentTxn(ex, sp(0), thief.addr, 1, close_remainder_to=thief.addr),
                transaction.PaymentTxn(ex, sp(0), thief.addr, 1),
                transaction.AssetTransferTxn(ex, sp(0), thief.addr, 0, 1, close_assets_to=thief.addr)):
        atc = AtomicTransactionComposer()
        atc.add_transaction(TransactionWithSigner(txn, LogicSigTransactionSigner(router.lsig)))
        atc.add_method_call(router.id, router.app.methods['relay'], lane.addr, sp(2 * MIN_FEE + FEE_CREDIT),
                            lane.signer, [token.id, o, alice.sign_op(digest(o))], foreign_apps=[token.id])
        with pytest.raises(AlgodHTTPError, match='rejected by logic') as e:
            atc.execute(ALGOD, 4)
        assert lsig_explain(str(e.value)) == 'executor: only an app call :: '
    assert algo(ex) == 1_000_000 and ALGOD.account_info(ex).get('auth-addr') is None
    assert bal(token, native(alice)) == 1_000_000


def test_executor_without_relay_next_rejected(router, token, target, lane, dispenser):
    """The executor approves only a target whose next transaction is `relay` on its own router: not alone, not before
    another router method (here `executor()`, the T12 m5 shape: `add_key_native` for the executor), not before
    another router app's relay."""
    alice, acc = token.alice, token.account
    ex = LogicSigTransactionSigner(router.lsig)
    other = deploy_router(dispenser)
    k = EdKey('exec-key-2')

    def group(target_txn, nxt):
        atc = AtomicTransactionComposer()
        atc.add_transaction(TransactionWithSigner(target_txn, ex))
        for n in nxt:
            atc.add_transaction(n)
        return atc
    tx = lambda: transaction.ApplicationCallTxn(router.executor, sp(0), target.id, NOOP,  # noqa: E731
                                                app_args=abi_args(target, 'ping', [1]))
    akn = lambda: transaction.ApplicationCallTxn(router.executor, sp(0), acc.id, NOOP,  # noqa: E731
                                                 app_args=abi_args(acc, 'add_key_native', [k.record(), b'']),
                                                 boxes=[(acc.id, acc.name((0, encoding.decode_address(router.executor))))])
    o = fee_op(token, router, alice, ping(target, 1))
    a = alice.sign_op(digest(o))
    view_call = lambda: TransactionWithSigner(transaction.ApplicationCallTxn(  # noqa: E731
        lane.addr, sp(3 * MIN_FEE), router.id, NOOP, app_args=abi_args(router, 'executor', [])), lane.signer)
    m = other.app.methods['relay']
    other_relay = lambda: TransactionWithSigner(transaction.ApplicationCallTxn(  # noqa: E731
        lane.addr, sp(3 * MIN_FEE), other.id, NOOP, foreign_apps=[token.id],
        app_args=[m.get_selector(), u64(token.id), m.args[1].type.encode(o), m.args[2].type.encode(a)]), lane.signer)
    pay = lambda: TransactionWithSigner(  # noqa: E731
        transaction.PaymentTxn(lane.addr, sp(3 * MIN_FEE), lane.addr, 0), lane.signer)
    with pytest.raises(AlgodHTTPError):                   # alone (it pays no fee either)
        group(tx(), []).execute(ALGOD, 4)
    for atc in (group(tx(), [pay()]), group(tx(), [view_call()]), group(akn(), [view_call()]),
                group(tx(), [other_relay()])):
        with pytest.raises(AlgodHTTPError) as e:
            atc.execute(ALGOD, 4)
        assert lsig_explain(str(e.value)) == "executor: next is the router's relay :: ", str(e.value)
    assert acc.record((0, encoding.decode_address(router.executor))) is None


def test_target_pay_naming_router_fails(router, token, lane):
    """A forwarded call cannot spend a router-bound payment: the target `token.mtx_pay` of an op whose relayer is the
    router is sent by the executor, so the token's rule 7 (relayer == Txn.Sender) refuses it."""
    alice = token.alice
    victim = fee_op(token, router, alice, Tgt(token, app_args=[b'x'], app_id=token.id), to=native(lane))
    va = alice.sign_op(digest(victim))
    t = Tgt(token, 'mtx_pay', [victim, va, lane.addr], accounts=[alice.addr])
    o = fee_op(token, router, alice, t, amount=1)
    with no('relayer is not the sender'):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert bal(token, native(alice)) == 1_000_000


def test_lane_transfer_as_target_refused(router, token, lane, make):
    """The lane's own call is never a target (a lane could otherwise charge a payer for its own transfer)."""
    alice, bob = token.alice, make()
    t = Tgt(token, 'arc200_transfer', [bob.addr, 5], sender=alice, mbr=MBR_BALANCE,
            boxes=[(token, b'b' + bob.key)])
    o = fee_op(token, router, alice, t)
    with no(NOT_EXEC):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert (bal(token, native(alice)), bal(token, native(bob))) == (1_000_000, 0)


def test_executor_transfer_moves_nothing(router, token, lane):
    """A relayed `arc200_transfer` is the executor's own: it holds nothing, so a transfer of value fails and a zero
    transfer moves nothing — no one's funds move by the executor."""
    alice = token.alice
    ex = (0, encoding.decode_address(router.executor))
    t = Tgt(token, 'arc200_transfer', [alice.addr, 5], boxes=[(token, amount_box(ex))])
    o = fee_op(token, router, alice, t)
    with no('insufficient balance'):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    t = Tgt(token, 'arc200_transfer', [alice.addr, 0], mbr=MBR_BALANCE, boxes=[(token, amount_box(ex))])
    o = fee_op(token, router, alice, t)
    relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert (bal(token, native(alice)), bal(token, native(lane)), bal(token, ex)) == (1_000_000 - 10, 10, 0)


def test_executor_address_matches_offchain_derivation(router, fresh_router):
    """`executor()` = sha512_256("Program" ‖ EXEC_PREFIX ‖ itob(router id) ‖ EXEC_SUFFIX ‖ 20 01 salt), the LogicSig
    address the SDK derives: the template is the built program around the router-id constant (artifacts.json records
    it), the salt (T15 fix 1) a dead-code `intcblock 1 salt` after the final return, fixed at the router's creation —
    the lowest < 128 that makes the address off-curve (no ed25519 key can exist for the executor). Off-chain
    `on_curve` agrees with puya's go-algorand predicate on salted and unsalted programs."""
    import hashlib
    from puya.utils import is_ed25519_point
    art = json.load(open(os.path.join(ROOT, 'artifacts.json')))['relayfee']
    assert bytes.fromhex(art['executor_prefix']) == EXEC_PREFIX and bytes.fromhex(art['executor_suffix']) == EXEC_SUFFIX
    assert EXEC_PREFIX + SENTINEL + EXEC_SUFFIX == open(os.path.join(OUT, 'Executor.bin'), 'rb').read()
    for r in (router, fresh_router):
        salt = gstate(r)['salt']
        prog = EXEC_PREFIX + r.id.to_bytes(8, 'big') + EXEC_SUFFIX + bytes([0x20, 1, salt])
        key = hashlib.new('sha512_256', b'Program' + prog).digest()
        mine = encoding.encode_address(key)
        assert view(r, 'executor') == mine == transaction.LogicSigAccount(prog).address() == r.executor
        assert salt == exec_salt(r.id) < 128 and not on_curve(key)
    assert router.executor != fresh_router.executor
    seen = set()
    for i in range(1, 400):     # the predicate, and that a salt is needed for some ids (about half are on-curve)
        for s in (None, 0):
            p = EXEC_PREFIX + i.to_bytes(8, 'big') + EXEC_SUFFIX + (bytes([0x20, 1, s]) if s is not None else b'')
            k = hashlib.new('sha512_256', b'Program' + p).digest()
            assert on_curve(k) == is_ed25519_point(k)
            seen.add(on_curve(k))
    assert seen == {True, False} and max(exec_salt(i) for i in range(1, 400)) > 0


def test_router_salt_below_128(dispenser):
    """The creation salt is one byte below 128 (a single-byte `intcblock` immediate): 128 and above refused; any lower
    one is stored and enters `executor()` (the deployer's job to pick the lowest off-curve one: deploy_router)."""
    a = spec('RelayFee')
    for salt in (128, 255):
        with pytest.raises(AlgodHTTPError) as e:     # the app never exists, so its pc is read from the spec
            deploy(dispenser, 'RelayFee', [salt], fund_app=0)
        assert a.errors[int(re.search(r'assert failed pc=(\d+)', str(e.value)).group(1))] == 'salt must be below 128'
    assert a.schema == {'ints': 1, 'bytes': 0}
    d = deploy(dispenser, 'RelayFee', [127], fund_app=0)   # any salt below 128 is stored and derived (here: not the lowest)
    DEPLOYED[d.id] = d
    assert gstate(d) == {'salt': 127}
    assert view(d, 'executor') == transaction.LogicSigAccount(exec_program(d.id, 127)).address()


def test_relay_ref_vectors(router):
    """R5: the router's `relay_ref(call, salt)` is the shared derivation (§2 row 8): every relayRefs row of
    algorand-vectors.json recomputed from its own bytes, and the router's on this network; the executor vector."""
    V = json.load(open(os.path.join(ROOT, 'vectors', 'algorand-vectors.json')))
    net = bytes.fromhex(V['network'][2:])
    rows = V['relayRefs']
    assert rows
    for r in rows:
        call, salt = bytes.fromhex(r['call'][2:]), bytes.fromhex(r['salt'][2:])
        app_id = int.from_bytes(call[:8], 'big')
        assert keccak(b'scaas.relayfee', net, app_key(app_id), keccak(call), salt).hex() == r['ref'][2:], r['name']
        if len(call) > 1900:   # above the 2,048 B argument limit: a hash vector only
            continue
        mine = keccak(b'scaas.relayfee', genesis(), app_key(app_id), keccak(call), salt)
        assert bytes(view(router, 'relay_ref', call, salt)) == mine, r['name']
    e = V['executor']
    prog = (bytes.fromhex(e['prefix'][2:]) + e['routerApp'].to_bytes(8, 'big') + bytes.fromhex(e['suffix'][2:])
            + bytes([0x20, 1, e['salt']]))
    assert prog.hex() == e['program'][2:] and transaction.LogicSigAccount(prog).address() == e['address']
    assert e['salt'] == exec_salt(e['routerApp']) and not on_curve(encoding.decode_address(e['address']))
    assert (bytes.fromhex(e['prefix'][2:]), bytes.fromhex(e['suffix'][2:])) == (EXEC_PREFIX, EXEC_SUFFIX)


def test_router_holds_nothing_after_relay(router, token, target, lane, make):
    """The router forwards the MBR payment whole and never holds the payment: its ALGO and token balances are what they
    were after open, bound and UA-payer relays; the executor holds nothing either."""
    alice, bob, erin = token.alice, make(), EdKey('erin-holds')
    fund_ua(token, erin, 100)
    before = (algo(router.address), router.min_balance())
    for i, (payer, to) in enumerate(((alice, None), (alice, native(bob)), (erin, None))):
        t = ping(target, 200 + i)
        o = fee_op(token, router, payer, t, to=to)
        relay(lane, router, token, t, o, sign_as(payer, digest(o)))
        assert (algo(router.address), router.min_balance()) == before
    assert bal(token, native(router.key)) == 0 and bal(token, (0, encoding.decode_address(router.executor))) == 0
    assert algo(router.executor) == 0 and before[0] == 100_000
    assert (bal(token, native(lane)), bal(token, native(bob)), bal(token, erin.ua())) == (20, 10, 90)


def test_router_mbr_forward_exact(router, token, target, lane, make):
    """A30 / §2 row 15: the router's payment (just before the target's own when it has one) is forwarded whole to the
    token, whose check is exact: missing, short or surplus fails the group; one that closes or rekeys is refused; a
    payment to the router after the relay is not the router's."""
    erin = EdKey('erin-mbr')
    fund_ua(token, erin, 100)
    t = ping(target, 300)
    o = fee_op(token, router, erin, t)
    a = erin.auth(digest(o))
    need = pay_mbr(token, o, a, native(lane))
    assert need == MBR_LANE + MBR_BALANCE + rec_mbr(1)   # the lane box, the lane's new balance box, erin's record
    for kw in ({'router_mbr': None}, {'mbr_delta': -1}, {'mbr_delta': 1}):
        with no(MBR):
            relay(lane, router, token, t, o, a, **kw)
    relay(lane, router, token, t, o, a)
    t = ping(target, 301)
    o = fee_op(token, router, erin, t)
    a = erin.auth(digest(o))
    need = pay_mbr(token, o, a, native(lane))
    assert need == MBR_LANE
    for pay_kw in ({'close_remainder_to': router.address}, {'rekey_to': lane.addr}):
        payer = make(1_000_000)
        with no('router MBR payment must not close or rekey'):
            relay(lane, router, token, t, o, a, pay_kw=pay_kw, mbr_payer=payer)
        assert algo(payer.addr) == 1_000_000
    late = TransactionWithSigner(transaction.PaymentTxn(lane.addr, sp(), router.address, need), lane.signer)
    with no(MBR):                                 # after the relay: not the router's payment
        relay(lane, router, token, t, o, a, router_mbr=None, after=[late])
    stray = TransactionWithSigner(transaction.PaymentTxn(lane.addr, sp(), lane.addr, need), lane.signer)
    t2 = ping(target, 302, before=[stray])
    o2 = fee_op(token, router, erin, t2)
    with no(MBR):                                 # a payment to another receiver just before the target: not the router's
        relay(lane, router, token, t2, o2, erin.auth(digest(o2)), router_mbr=None)
    assert bal(token, erin.ua()) == 90
    # the target's own exact payment sits between: the router finds its own before it
    k, acc = EdKey('erin-mbr-key'), token.account
    ko = acc.op(6, erin, params=abi_key(k))
    x = Tgt(acc, 'mtx_add_key', [ko, erin.auth(digest(ko)), k.record(), b''], mbr=SLOT,
            boxes=[(acc, acc.name(erin))])
    o = fee_op(token, router, erin, x)
    m0 = acc.min_balance()
    relay(lane, router, token, x, o, erin.auth(digest(o)))
    assert acc.min_balance() - m0 == SLOT and bal(token, erin.ua()) == 80 and bal(token, native(lane)) == 20


def abi_key(k):
    from conftest import key_params
    return key_params('mtx_add_key', [k.record(), b''])


def test_relayed_noop_refused(router, token, lane):
    """Owner rule (no fee for a no-op) by atomicity: the targets refuse no-ops — a relayed cancel of an order already
    cancelled fails the group, and the payer pays nothing."""
    alice, erin = token.alice, EdKey('erin-noop')
    params = LANE_A + u64(4)
    h = erin.ua()
    c = token.op(h, h, 0, lane=Z32, code=14, extra=sha256(params))
    ca = erin.auth(digest(c))
    acc = token.account
    rec = sim_view(acc, 'verify_mbr', [1, erin.id, digest(c), ca])[0]
    ob = [order_key(h, LANE_A, 4), min_nonce_key(h, LANE_A)]
    token.mtx(lane, 'mtx_cancel', c, ca, LANE_A, 4, mbr=MBR_ORDER + rec, extra_boxes=ob, fee_extra_=FEE_CREDIT)
    t = Tgt(token, 'mtx_cancel', [c, ca, LANE_A, 4], apps=[acc.id], boxes=[(token, b) for b in ob] + [
        (acc, acc.name(h))])
    o = fee_op(token, router, alice, t)
    with no('order cancelled'):
        relay(lane, router, token, t, o, alice.sign_op(digest(o)))
    assert bal(token, native(alice)) == 1_000_000


def test_relay_every_target_kind(router, token, target, lane, dispenser, make):
    """§4.8: every target goes through the one router — the token's own entry (a UA's mtx_transfer), an account key
    op, a mandate open, a third-party app (the DEX: test_dex_bound_order_via_router). Each keeps its exact-MBR payment
    just before it."""
    alice, acc = token.alice, token.account
    erin, bob = EdKey('erin-kinds'), make()
    fund_ua(token, erin, 1_000)
    # token: erin's mtx_transfer (op 4) to bob, sent by the executor (its relayer zero: any submitter)
    to = token.op(erin.ua(), native(bob), 50, code=4, lane=b'\x41' * 32)
    ta_ = erin.auth(digest(to))
    tt = Tgt(token, 'mtx_transfer', [to, ta_], mbr=token_mbr(token, to, ta_), apps=[acc.id],
             boxes=[(token, b'l' + sha256(b'\x01', erin.id, to[8])), (token, b'b' + bob.key),
                    (token, b'u' + erin.id), (acc, acc.name(erin))])
    o = fee_op(token, router, alice, tt)
    relay(lane, router, token, tt, o, alice.sign_op(digest(o)))
    assert (bal(token, erin.ua()), bal(token, native(bob)), bal(token, native(lane))) == (950, 50, 10)
    # account: erin adds a key (op 6)
    k = EdKey('erin-kinds-key')
    ko = acc.op(6, erin, params=abi_key(k))
    tk = Tgt(acc, 'mtx_add_key', [ko, erin.auth(digest(ko)), k.record(), b''], mbr=SLOT,
             boxes=[(acc, acc.name(erin))])
    o = fee_op(token, router, alice, tk)
    relay(lane, router, token, tk, o, alice.sign_op(digest(o)))
    assert k.id in acc.record(erin)['keys']
    # mandate: erin opens a mandate (the funding op executed inside the open, relayer = the mandate app)
    d = deploy(dispenser, 'Mandate', [acc.id])
    man = Man(d.app, d.id)
    DEPLOYED[man.id] = man
    terms = man.terms(EdKey('dele-kinds').ua(), native(bob), 10, 100, 200)
    mo, mid = man.open_op(token, erin.ua(), terms, b'\xb0' * 32, 0)
    ma = erin.auth(digest(mo))
    fund_mbr = token_mbr(token, mo, ma)
    tm = Tgt(man, 'mtx_mandate_open', [token.id, mo, ma, terms, fund_mbr], mbr=MBR_MANDATE + fund_mbr,
             apps=[token.id, acc.id],
             boxes=man.boxes(token, erin.ua(), native(bob), mid=mid) + [
                 (token, b'l' + sha256(b'\x01', erin.id, mo[8]))])
    o = fee_op(token, router, alice, tm)
    relay(lane, router, token, tm, o, alice.sign_op(digest(o)))
    assert man.get(token, mid)['remaining'] == 200 and bal(token, erin.ua()) == 750
    assert bal(token, native(lane)) == 30


def test_dex_bound_order_via_router(router, pair, lane, make, dispenser):
    """CTR-DEX-09 through the router (ruling (b)): a settle sent by the executor takes the sender of the router.relay
    right after it as its submitter — an order bound to the lane settles when that lane relays it, not when another
    lane does, nor through another router app, nor when another account sends the settle and the lane's next call to
    the router is not `relay`; an order bound to the executor never settles (it would be an open order)."""
    ta, tb = pair
    dex = deploy_dex(dispenser, router)
    other = make(50_000_000)

    def settle_tgt(la, lb):
        parts = dex.mbr(la, lb)
        boxes, accounts = dex.refs(la, lb)
        args = [la.order, la.op, la.auth, lb.order, lb.op, lb.auth, parts]
        x = Tgt(dex, 'settle', args, mbr=sum(parts), apps=[ta.id, tb.id, ta.account.id], accounts=accounts,
                boxes=boxes)
        x.args_ = args
        return x

    class Ex:
        key = encoding.decode_address(router.executor)
    erin, la, lb = setup_legs(dex, ta, tb, lane, a_relayer=Ex)
    t = settle_tgt(la, lb)
    o = fee_op(ta, router, ta.alice, t)
    with no('order relayer is not the submitter'):        # bound to the executor: never
        relay(lane, router, ta, t, o, ta.alice.sign_op(digest(o)))
    la = dex.leg(ta, erin, dex.order(ta, tb, 100, 50, relayer=lane.key))
    t = settle_tgt(la, lb)
    o = fee_op(ta, router, ta.alice, t)
    with no('order relayer is not the submitter'):        # bound to `lane`, relayed by another lane
        relay(other, router, ta, t, o, ta.alice.sign_op(digest(o)))
    router2 = deploy_router(dispenser)                    # another router's executor + relay: not the DEX's router
    o2 = fee_op(ta, router2, ta.alice, t)
    with no('order relayer is not the submitter'):
        relay(lane, router2, ta, t, o2, ta.alice.sign_op(digest(o2)))
    # sent directly by another account, the lane's next call to the router is not a relay: the sender submits
    atc = AtomicTransactionComposer()
    for x in Tgt(dex, 'settle', t.args_, mbr=t.mbr, sender=other).txns(router, lane):
        atc.add_transaction(x)
    atc.add_transaction(TransactionWithSigner(transaction.ApplicationCallTxn(
        lane.addr, sp(MIN_FEE + FEE_CREDIT), router.id, NOOP, app_args=abi_args(router, 'executor', [])), lane.signer))
    box_calls(atc, lane, ta, t.boxes)
    with pytest.raises(AlgodHTTPError) as e:
        atc.execute(ALGOD, 4)
    assert 'order relayer is not the submitter' in explain(str(e.value))
    r = relay(lane, router, ta, t, o, ta.alice.sign_op(digest(o)))
    assert (bal(ta, erin.ua()), bal(tb, erin.ua()), bal(ta, native(lane))) == (900, 60, 10)
    assert ('Matched' in [n for n, _ in events(dex.app, r.logs)])


def test_router_update_delete_optin_refused(router, dispenser, make):
    """R11 / §4.9: the router refuses Update / Delete (creator included) and OptIn / CloseOut; its only state is the
    creation salt (one global uint, no method writes it)."""
    refused_actions(router, dispenser, ['update', 'delete'])
    refused_actions(router, make(1_000_000), ['optin', 'closeout'])
    assert ALGOD.application_info(router.id)['params']['approval-program'] == base64.b64encode(
        router.app.approval).decode()
    s = router.app.spec['state']['schema']
    assert s['local'] == {'ints': 0, 'bytes': 0} and s['global'] == {'ints': 1, 'bytes': 0}
    assert gstate(router) == {'salt': router.salt}


INNER_FIELDS = re.compile(r'itxn_field (RekeyTo|CloseRemainderTo|AssetCloseTo)\b')


def test_inner_txns_never_rekey_or_close(router, token, target, lane):
    """§4.9: no app issues an inner transaction with RekeyTo, CloseRemainderTo or AssetCloseTo — every program in out/
    disassembled (algod) sets none of these fields (an unset field is zero), and a relay group's inner transactions
    (router → token → account) carry none."""
    progs = sorted(f for f in os.listdir(OUT) if f.endswith('.approval.bin'))
    assert {'Token.approval.bin', 'Account.approval.bin', 'Mandate.approval.bin', 'Dex.approval.bin',
            'RelayFee.approval.bin'} <= set(progs)
    sets = 0
    for f in progs:
        teal = ALGOD.disassemble(open(os.path.join(OUT, f), 'rb').read())['result']
        assert not INNER_FIELDS.search(teal), f
        sets += teal.count('itxn_field')
    assert sets > 0      # the scan sees inner transactions at all
    erin = EdKey('erin-inner')
    fund_ua(token, erin, 100)
    t = ping(target, 400)
    o = fee_op(token, router, erin, t)
    r = relay(lane, router, token, t, o, erin.auth(digest(o)))
    seen = []

    def walk(x):
        for it in x.get('inner-txns', []):
            tx = it['txn']['txn']
            seen.append(tx['type'])
            assert not {'rekey', 'close', 'aclose'} & set(tx), tx
            walk(it)
    for i in r.infos:
        walk(i)
    assert {'pay', 'appl'} <= set(seen)


def test_figures_pinned(router, token, target, lane, make):
    """Budget of a relay group per payer / target kind (no bare budget calls), incl. the worst cases — a 3-member
    Chrome-passkey msig target (token mtx_transfer) paid by a Chrome passkey UA (ruling (j)), and by the msig itself —
    pinned; argument bytes of each call ≤ 2,048 and the inner fees within the lane's FEE_CREDIT; program sizes. The
    router's own work is ≈ 760 opcodes with a 2-argument target (exec trace, limits log), under RELAY_COST."""
    alice = token.alice
    out = {}
    pk = ChromeKey('fee-pk')
    fund_ua(token, pk, 1_000)
    ed = EdKey('fee-ed')
    fund_ua(token, ed, 1_000)
    m = MsigKey(3, [(ChromeKey('fee-m%d' % i), 1) for i in range(3)])
    fund_ua(token, m, 1_000)
    bob = make()
    acc = token.account

    def transfer_tgt(signer, n):
        to = token.op(signer.ua(), native(bob), 5, code=4, lane=bytes([0x70 + n]) * 32)
        a = signer.auth(digest(to))
        return Tgt(token, 'mtx_transfer', [to, a], mbr=token_mbr(token, to, a) or None, apps=[acc.id],
                   boxes=[(token, b'l' + sha256(b'\x01', signer.id, to[8])), (token, b'b' + bob.key),
                          (token, b'u' + signer.id), (acc, acc.name(signer.ua()))])
    cases = (('ping, native payer', lambda n: ping(target, 500 + n), alice),
             ('ping, ed25519 UA payer', lambda n: ping(target, 500 + n), ed),
             ('ping, passkey UA payer', lambda n: ping(target, 500 + n), pk),
             ('ed25519 UA transfer, passkey UA payer', lambda n: transfer_tgt(ed, n), pk),
             ('msig 3 passkey transfer, passkey UA payer', lambda n: transfer_tgt(m, n), pk),
             ('msig 3 passkey transfer, msig 3 passkey payer', lambda n: transfer_tgt(m, n), m))
    sizes = {}
    for n, (name, mk, payer) in enumerate(cases):
        t = mk(n)
        o = fee_op(token, router, payer, t)
        a = sign_as(payer, digest(o))
        used, inner, fail = relay(lane, router, token, t, o, a, simulate=True)
        assert fail is None, (name, fail)
        out[name] = (used, inner)
        sizes[name] = (sum(len(x) for x in t.app_args), arg_bytes(router, 'relay', [token.id, o, a]))
        relay(lane, router, token, t, o, a)
    print('\nrelay group opcode budget, minimal group (consumed, inner app calls): %s\npins %s' % (out, BUDGET_PIN))
    print('argument bytes (target call, relay call): %s (limit 2,048)' % sizes)
    print('program size (B): relayfee approval %d, clear %d; executor %d (template %d + 8 + %d); dex %d' % (
        len(router.app.approval), len(router.app.clear), len(router.program()), len(EXEC_PREFIX), len(EXEC_SUFFIX),
        len(open(os.path.join(OUT, 'Dex.approval.bin'), 'rb').read())))
    print('MBR (µALGO): router none (stateless; its address keeps the 100,000 base); per relay the token part '
          '(lane box %d + payee balance box %d when new + a UA payer record when it opens) forwarded whole' % (
              MBR_LANE, MBR_BALANCE))
    assert max(max(s) for s in sizes.values()) <= 2048
    assert max(c for _, c in out.values()) + 2 <= FEE_CREDIT // MIN_FEE
    for k, (used, calls) in out.items():
        assert used <= BUDGET_PIN[k][0] and calls <= BUDGET_PIN[k][1], (k, used, calls)
