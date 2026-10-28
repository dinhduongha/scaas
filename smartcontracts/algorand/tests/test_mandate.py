"""Mandate app on localnet (near-algorand T13; spec §4.7 → §3.6, README §3 item 2, CTR-ACC-06 / CTR-ACC-07; rulings R4,
R9, R11, T13 pre-flight (a)–(f); parity with the NEAR mandate of Task 7: smartcontracts/near/integration/tests/mandate.rs).

The owner signs one op to open a mandate (Ruling T13-open, fix 1 C1): a token `mtx_pay` of `terms.funding` with relayer
= to = the mandate app address, pay_ref = the mandate id, extra = sha256(token ‖ id ‖ terms); only
`mtx_mandate_open(token, op, auth, terms, fund_mbr)` can execute it (by an inner call, so the token's rule 7 refuses it
anywhere else); the delegate signs each `mtx_mandate_pay` (op 2, from = Ua(id), lane payLane(pay_ref), nonce 0) within the
caps, to the payee, until the expiry; the owner or the delegate revokes (op 3); anyone refunds after the expiry. State
is keyed by (token, id); pay / revoke ops bind the token by `extra = sha256(token id)`."""
import base64
import re

import pytest
from algosdk import abi, encoding, transaction
from algosdk.atomic_transaction_composer import AtomicTransactionComposer, TransactionWithSigner
from algosdk.error import AlgodHTTPError
from algosdk.v2client import models

from conftest import (VIEWER, sim, ALGOD, DEPLOYED, FAR, MBR_BALANCE, MBR_LANE, MBR_UA, MIN_FEE, ORIGIN, POLICY_PASSKEY_FOR_VALUE,
                      Z32, Acct, Deployed, EdKey, MsigKey, PasskeyKey, Refused, Result, Tok, advance, box_mbr, deploy,
                      digest, explain, genesis, holder, latest_ts, make_token, native, pay_lane, rec_mbr,
                      refused_actions, run, SLOT, sha256, sign_as, sp, view, wait, fund, NONE_HOLDER)

ZERO_ADDR = encoding.encode_address(Z32)
PERIOD_S = 3_600
FEE_CREDIT = 64 * MIN_FEE          # the relayer's fee pooling for inner calls (verify, transfers, budget)
TERMS = '((uint8,byte[32]),(uint8,byte[32]),uint128,uint128,uint64,uint64,uint128)'
TERMS_T = abi.ABIType.from_string(TERMS)
MANDATE_LEN = 33 + 130 + 8 + 16 + 16 + 1           # owner, terms, period_start, spent, remaining, revoked
MBR_MANDATE = box_mbr(1 + 8 + 32, MANDATE_LEN)      # "m" ‖ token id ‖ mandate id
MBR_MLANE = box_mbr(33, 8)                          # "l" ‖ sha256(token id ‖ mandate id ‖ lane) → u64
# Opcode budget per entry in the minimal group (simulate, no bare budget calls: the app raises its own budget by inner
# budget calls on the relayer's pooled fee), (consumed, inner app calls) — pinned in runs/2026-10-28-algorand-limits.txt
BUDGET_PIN = {'open ed25519': (4550, 7), 'open passkey': (5350, 10), 'open native': (3800, 7),
              'pay ed25519 (delegate opened)': (4150, 7), 'pay ed25519': (4000, 7),
              'pay passkey (delegate opened)': (5000, 9), 'pay passkey': (4850, 9),
              'revoke ed25519': (3650, 7), 'revoke passkey': (4450, 9), 'refund': (470, 1)}

PER_PAYMENT = 'over the per-payment cap'
PER_PERIOD = 'over the per-period cap'
PAYEE = 'payee not allowed'
EXPIRED = 'mandate expired'
REVOKED = 'mandate revoked'
PAID = 'pay_ref already paid under this mandate'
PAY_SHAPE = 'mandate pay shape (pay_ref set, lane = payLane(pay_ref), nonce 0, extra = sha256(token))'
TO_RELAYER = 'to and relayer must be the mandate app'


def no(*msgs):
    return pytest.raises(Refused, match='.*'.join(re.escape(m) for m in msgs))


def u64(n):
    return n.to_bytes(8, 'big')


def mandate_id(frm, terms, lane, nonce):
    """`sha256(ARC-4(from, terms, lane, nonce))` of the funding op (a static tuple: the concatenation)."""
    return sha256(bytes([frm[0]]) + bytes(frm[1]), TERMS_T.encode(terms), lane, u64(nonce))


def parse(v):
    terms = TERMS_T.decode(v[33:163])
    return {'owner': (v[0], v[1:33]), 'terms': [(t[0], bytes(t[1])) if i < 2 else t for i, t in enumerate(terms)],
            'period_start': int.from_bytes(v[163:171], 'big'), 'spent': int.from_bytes(v[171:187], 'big'),
            'remaining': int.from_bytes(v[187:203], 'big'), 'revoked': v[203] == 0x80, 'length': len(v)}


def box(d, name):
    try:
        return base64.b64decode(ALGOD.application_box_by_name(d.id, name)['value'])
    except AlgodHTTPError:
        return None


def amount_box(h):
    return (b'b' if h[0] == 0 else b'u') + bytes(h[1])


def events(app, logs):
    out = []
    for log in logs:
        e = app.events.get(log[:4])
        if e:
            out.append((e[0], e[1].decode(log[4:])))
    return out


class Group:
    """The results of one group: every log (inner included) and each top-level transaction's own logs."""

    def __init__(self, infos):
        self.infos = infos
        self.logs = [x for i in infos for x in Result(i).logs]

    def own(self, d):
        """Events the app `d` logged itself (top-level calls to it)."""
        logs = [base64.b64decode(x) for i in self.infos if i['txn']['txn'].get('apid') == d.id
                for x in i.get('logs', [])]
        return events(d.app, logs)


class Man(Deployed):
    """The mandate app plus the group shapes of its entries (relayer-submitted, relayer-paid MBR and fees)."""

    def terms(self, delegate, payee, per_payment, per_period, funding, period_s=PERIOD_S, expiry=FAR):
        return [list(holder(delegate)), list(holder(payee)), per_payment, per_period, period_s, expiry, funding]

    def mkey(self, token, mid):
        return b'm' + u64(token.id) + mid

    def lane_box(self, token, mid, lane):
        return b'l' + sha256(u64(token.id), mid, lane)

    def get(self, token, mid):
        v = box(self, self.mkey(token, mid))
        return parse(v) if v else None

    def open_op(self, token, owner, terms, at_lane, at_nonce, **kw):
        """The owner's one signed op: token.mtx_pay of `funding` with relayer = to = this app, pay_ref = the id (from the
        op's own lane and nonce), extra = sha256(token ‖ id ‖ terms)."""
        mid = mandate_id(owner, terms, at_lane, at_nonce)
        o = token.op(tuple(owner), native(self.key), terms[6], pay_ref=mid, lane=at_lane, nonce=at_nonce, relayer=self.key,
                     extra=sha256(u64(token.id), mid, TERMS_T.encode(terms)))
        return patch(o, kw), mid

    def pay_op(self, token, mid, payee, value, ref, **kw):
        o = [genesis(), self.key, 2, [1, mid], list(holder(payee)), Z32, value, ref, pay_lane(ref), 0, FAR,
             sha256(u64(token.id))]
        return patch(o, kw)

    def revoke_op(self, token, by, mid, **kw):
        o = [genesis(), self.key, 3, list(holder(by)), [1, mid], Z32, 0, Z32, Z32, 0, FAR, sha256(u64(token.id))]
        return patch(o, kw)

    def boxes(self, token, *hs, mid=None):
        acc = token.account
        out = [(token, b'b' + self.key)] + [(token, amount_box(h)) for h in hs]
        out += [(acc, acc.name(h)) for h in hs]
        if mid:
            out.append((self, self.mkey(token, mid)))
        return out

    def open(self, relayer, token, owner, terms, lane=b'\xb0' * 32, nonce=0, sign=None, op_kw=None, mbr='auto',
             fund_mbr='auto', mbr_delta=0, fund_delta=0, simulate=False):
        """`owner` (an `Acct` or a `Key`) signs the funding op; the relayer submits [MBR → mandate][mtx_mandate_open]:
        the mandate box + `fund_mbr` (the token's part, forwarded with the funding) + the payee's new box."""
        oh = holder(owner)
        o, mid = self.open_op(token, oh, terms, lane, nonce, **(op_kw or {}))
        a = (sign or (lambda d: sign_as(owner, d)))(digest(o))
        if fund_mbr == 'auto':
            fund_mbr = token_mbr(token, o, a)
        if mbr == 'auto':
            mbr = MBR_MANDATE + fund_mbr + (0 if box(token, amount_box(terms[1])) else MBR_BALANCE) + mbr_delta
        items = ([('pay', self.address, mbr)] if mbr is not None else []) + [
            (self, 'mtx_mandate_open', [token.id, o, a, terms, fund_mbr + fund_delta],
             {'apps': [token.id, token.account.id]})]
        boxes = self.boxes(token, oh, tuple(terms[1]), mid=mid) + [
            (token, b'l' + sha256(bytes([o[3][0]]), bytes(o[3][1]), o[8]))]
        accounts = [encoding.encode_address(bytes(oh[1]))] if oh[0] == 0 else []
        r = send(relayer, self, items, boxes, accounts, simulate)
        return (r, mid) if not simulate else r

    def pay(self, relayer, token, mid, signer, payee, amount, pay_ref, op_kw=None, mbr='auto', sign=None,
            simulate=False, accounts=()):
        o = self.pay_op(token, mid, payee, amount, pay_ref, **(op_kw or {}))
        a = (sign or (lambda d: sign_as(signer, d)))(digest(o))
        sh = holder(signer)
        m = self.get(token, mid)
        dh = m['terms'][0] if m else sh
        if mbr == 'auto':
            mbr = MBR_MLANE
            if not (dh[0] == 0 and len(a) == 64):
                v, _, fail, _ = sim_view(token.account, 'verify_mbr', [dh[0], bytes(dh[1]), digest(o), a])
                mbr += 0 if fail else v
        items = ([('pay', self.address, mbr)] if mbr else []) + [
            (self, 'mtx_mandate_pay', [token.id, o, a], {'apps': [token.id, token.account.id]})]
        # the delegate's record is the one `verify` reads
        boxes = self.boxes(token, dh, tuple(holder(payee)), mid=mid) + [(self, self.lane_box(token, mid, o[8]))]
        acc = [encoding.encode_address(bytes(h[1])) for h in (sh, dh) if h[0] == 0]
        return send(relayer, self, items, boxes, acc + list(accounts), simulate)

    def revoke(self, relayer, token, mid, signer, by=None, op_kw=None, mbr=None, sign=None, simulate=False):
        bh = holder(by if by is not None else signer)
        o = self.revoke_op(token, bh, mid, **(op_kw or {}))
        a = (sign or (lambda d: sign_as(signer, d)))(digest(o))
        m = self.get(token, mid)
        owner = m['owner'] if m else bh
        items = ([('pay', self.address, mbr)] if mbr else []) + [
            (self, 'mtx_revoke', [token.id, o, a], {'apps': [token.id, token.account.id]})]
        boxes = self.boxes(token, bh, owner, mid=mid)
        acc = [encoding.encode_address(bytes(h[1])) for h in (bh, owner) if h[0] == 0]
        return send(relayer, self, items, boxes, acc, simulate)

    def refund(self, relayer, token, mid, simulate=False, mbr=None):
        m = self.get(token, mid)
        owner = m['owner'] if m else (1, mid)
        return send(relayer, self, ([('pay', self.address, mbr)] if mbr else []) + [
            (self, 'mandate_refund', [token.id, mid], {'apps': [token.id]})],
                    self.boxes(token, owner, mid=mid), [], simulate)


def patch(o, kw):
    fields = ['network', 'contract', 'op', 'from', 'to', 'relayer', 'amount', 'pay_ref', 'lane', 'nonce',
              'valid_until', 'extra']
    o = list(o)
    for k, v in kw.items():
        o[fields.index(k)] = v
    return o


def sim_view(d, method, args):
    return sim(VIEWER, d, method, args, extra_budget=20_000)


def send(relayer, man, items, boxes, accounts, simulate=False, fee_extra=FEE_CREDIT):
    """One atomic group: `items` = ('pay', address, µALGO) or (Deployed, method, args, {apps}); the first app call
    carries the fee credit for every inner transaction; box references ride bare budget calls on the mandate app (5
    per call, with their apps). `simulate` → (consumed, inner app calls, failure)."""
    atc = AtomicTransactionComposer()
    first, accounts = True, list(dict.fromkeys(accounts)) or None
    for it in items:
        if it[0] == 'pay':
            atc.add_transaction(TransactionWithSigner(transaction.PaymentTxn(relayer.addr, sp(), it[1], it[2]),
                                                      relayer.signer))
            continue
        d, method, args, kw = it
        atc.add_method_call(d.id, d.app.methods[method], relayer.addr, sp(MIN_FEE + (fee_extra if first else 0)),
                            relayer.signer, args, accounts=accounts, foreign_apps=kw.get('apps'))
        first = False
    boxes = list(dict.fromkeys(boxes))
    for i in range(0 if simulate else (len(boxes) + 4) // 5):
        chunk = boxes[5 * i:5 * i + 5]
        apps = sorted({a.id for a, _ in chunk if a.id != man.id})
        t = transaction.ApplicationNoOpTxn(relayer.addr, sp(), man.id, note=b'box%d' % i, foreign_apps=apps or None,
                                           boxes=[(a.id, b) for a, b in chunk])
        atc.add_transaction(TransactionWithSigner(t, relayer.signer))
    if simulate:
        r = atc.simulate(ALGOD, models.SimulateRequest(txn_groups=[], allow_unnamed_resources=True))
        g = r.simulate_response['txn-groups'][0]
        calls = sum(1 for it in items if it[0] != 'pay')
        inner = g.get('app-budget-added', 0) // 700 - calls
        return g.get('app-budget-consumed'), inner, (explain(r.failure_message) if r.failure_message else None)
    try:
        res = atc.execute(ALGOD, 4)
    except AlgodHTTPError as e:
        raise Refused(explain(str(e))) from None
    return Group([ALGOD.pending_transaction_info(t) for t in res.tx_ids])


# ---------------------------------------------------------------- fixtures
@pytest.fixture
def relayer(make):
    return make(200_000_000)


@pytest.fixture
def mandate(dispenser, account):
    d = deploy(dispenser, 'Mandate', [account.id])
    m = Man(d.app, d.id)
    DEPLOYED[m.id] = m
    return m


def fund_ua(token, k, amount):
    run(token.alice, token, 'transfer_to_ua', [k.id, amount], mbr=None if box(token, b'u' + k.id) else MBR_UA,
        boxes=[b'b' + token.alice.key, b'u' + k.id])


def bal(token, h):
    h = holder(h)
    if h[0] == 0:
        return view(token, 'arc200_balanceOf', encoding.encode_address(bytes(h[1])))
    return view(token, 'ua_balance_of', bytes(h[1]))


def opened(mandate, relayer, token, owner, fund, terms, **kw):
    """`owner` (a UA key) funded with `fund`, then a mandate with `terms` opened on lane b0 at nonce 0."""
    fund_ua(token, owner, fund)
    return mandate.open(relayer, token, owner, terms, **kw)[1]


# ---------------------------------------------------------------- plan Step 1 (as Task 7)
def test_mandate_pay_within_limits(mandate, token, make, relayer):
    erin, dele, bob = EdKey('erin'), EdKey('dele'), make()
    h, b = erin.ua(), native(bob)
    fund_ua(token, erin, 1_000)
    terms = mandate.terms(dele.ua(), b, 100, 1_000, 300)
    # one payment: the mandate box + the token's part (fund_mbr: the owner's lane box, the mandate address's balance
    # box, the owner's record) + the payee's new balance box; each app checks its own part exactly
    for kw in ({'mbr': None}, {'mbr_delta': -1}, {'mbr_delta': 1}, {'fund_delta': -1}, {'fund_delta': 1},
               {'mbr': MBR_MANDATE - 1, 'fund_mbr': 0}):
        with no('MBR payment must equal'):
            mandate.open(relayer, token, erin, terms, **kw)
    m0, t0 = mandate.min_balance(), token.min_balance()
    r, mid = mandate.open(relayer, token, erin, terms)
    grew = mandate.min_balance() - m0
    assert grew == MBR_MANDATE, 'measured = charged'
    print('\nmandate box: %d B name + %d B value, MBR %d µALGO; payee balance box forwarded to the token %d µALGO'
          % (41, MANDATE_LEN, grew, MBR_BALANCE))
    # the token grew by the mandate address's balance box, the funding lane box and bob's box (the open's forward)
    assert token.min_balance() - t0 == MBR_BALANCE + MBR_LANE + MBR_BALANCE
    m = mandate.get(token, mid)
    assert (m['owner'], m['terms'], m['spent'], m['remaining'], m['revoked'], m['length']) == (
        (1, erin.id), [(1, dele.id), b, 100, 1_000, PERIOD_S, FAR, 300], 0, 300, False, MANDATE_LEN)
    assert r.own(mandate) == [('Mandate', [token.id, list(mid), 'open', [1, list(erin.id)]])]
    assert (bal(token, h), bal(token, native(mandate.key)), bal(token, b)) == (700, 300, 0)
    tev = events(token.app, r.logs)
    assert ('PaymentSettled', [[1, list(erin.id)], [0, list(mandate.key)], 300, list(mid)]) in tev
    # the delegate pays (its record opened lazily); anyone may submit
    lane_rec = rec_mbr(1)
    with no('MBR payment must equal'):
        mandate.pay(relayer, token, mid, dele, b, 100, b'\x01' * 32, mbr=MBR_MLANE)
    m0, a0 = mandate.min_balance(), token.account.min_balance()
    r = mandate.pay(relayer, token, mid, dele, b, 100, b'\x01' * 32)
    assert mandate.min_balance() - m0 == MBR_MLANE and token.account.min_balance() - a0 == lane_rec
    print('mtx_mandate_pay (first, delegate opened): lane box %d µALGO + record %d µALGO forwarded'
          % (MBR_MLANE, lane_rec))
    assert r.own(mandate) == [('MandatePaymentSettled', [token.id, [1, list(mid)], [0, list(bob.key)], 100, [1] * 32])]
    assert ('arc200_Transfer', [mandate.address, bob.addr, 100]) in events(token.app, r.logs)
    # the owner's own key is not the delegate
    with no('not a key of the subject'):
        mandate.pay(relayer, token, mid, erin, b, 100, b'\x02' * 32, mbr=MBR_MLANE)
    m0, a0, t0 = mandate.min_balance(), token.account.min_balance(), token.min_balance()
    mandate.pay(relayer, token, mid, dele, b, 100, b'\x02' * 32, mbr=MBR_MLANE)
    assert (mandate.min_balance() - m0, token.account.min_balance() - a0, token.min_balance() - t0) == (MBR_MLANE, 0, 0)
    assert (bal(token, b), bal(token, native(mandate.key)), bal(token, h)) == (200, 100, 700)
    assert (mandate.get(token, mid)['spent'], mandate.get(token, mid)['remaining']) == (200, 100)
    # a relayer-bound pay is only for that relayer
    other = make(10_000_000)
    with no('relayer is not the sender'):
        mandate.pay(other, token, mid, dele, b, 10, b'\x03' * 32, op_kw={'relayer': relayer.key})
    mandate.pay(relayer, token, mid, dele, b, 10, b'\x03' * 32, op_kw={'relayer': relayer.key})
    # a pay above the mandate's remaining funds (90 left) is refused
    with no("the mandate's balance is short"):
        mandate.pay(relayer, token, mid, dele, b, 100, b'\x04' * 32)


def test_open_terms_bound_by_the_funding_op(mandate, token, make, relayer):
    """Ruling T13-open + R9: the owner's one signed op binds the terms — amount == terms.funding, relayer = to = the
    mandate app, pay_ref = the id from the op's own lane / nonce, extra = sha256(token ‖ id ‖ terms); the token checks
    the rest (op code, network, contract, expiry, signature, policy, lane nonce)."""
    erin, dele, bob = EdKey('erin'), EdKey('dele'), make()
    h, b = erin.ua(), native(bob)
    fund_ua(token, erin, 1_000)
    terms = mandate.terms(dele.ua(), b, 100, 250, 300)
    for kw, err in (({'amount': 299}, 'terms.funding must equal op.amount'),
                    ({'extra': Z32}, 'extra is not sha256 of the token, the mandate id and terms'),
                    ({'to': [0, bob.key]}, TO_RELAYER), ({'relayer': Z32}, TO_RELAYER),
                    ({'relayer': relayer.key}, TO_RELAYER),
                    ({'pay_ref': b'\x07' * 32}, 'pay_ref must be the mandate id'),
                    ({'lane': b'\xb1' * 32}, 'pay_ref must be the mandate id'),
                    ({'nonce': 1}, 'pay_ref must be the mandate id'),
                    ({'op': 4}, 'wrong op code'),
                    ({'network': sha256(b'another genesis')}, 'wrong network'),
                    ({'contract': sha256(b'another token app')}, 'wrong contract'),
                    ({'valid_until': 1}, 'expired')):
        with no(err):
            mandate.open(relayer, token, erin, terms, op_kw=kw, fund_mbr=0, mbr=MBR_MANDATE + MBR_BALANCE)
    with no('the key does not derive the UA id'):         # signed by another key (erin's record not open yet)
        mandate.open(relayer, token, erin, terms, sign=lambda d: EdKey('zed').auth(d), fund_mbr=MBR_LANE + MBR_BALANCE)
    # the extra binds the token: an open signed for another token
    _, mid = mandate.open_op(token, h, terms, b'\xb0' * 32, 0)
    with no('extra is not sha256 of the token'):
        mandate.open(relayer, token, erin, terms, op_kw={'extra': sha256(u64(token.id + 1), mid, TERMS_T.encode(terms))})
    now = latest_ts()
    for tm, err in ((mandate.terms(dele.ua(), b, 100, 250, 300, period_s=0), 'bad mandate limits'),
                    (mandate.terms(dele.ua(), b, 0, 250, 300), 'bad mandate limits'),
                    (mandate.terms(dele.ua(), b, 251, 250, 300), 'bad mandate limits'),
                    (mandate.terms(dele.ua(), b, 100, 250, 300, expiry=now), 'mandate expiry is past'),
                    (mandate.terms(dele.ua(), (2, bob.key), 100, 250, 300), 'unknown holder kind'),
                    (mandate.terms((2, dele.id), b, 100, 250, 300), 'unknown holder kind'),
                    (mandate.terms(dele.ua(), native(mandate.key), 100, 250, 300), 'mandate app refuses itself'),
                    (mandate.terms(dele.ua(), native(token.key), 100, 250, 300), 'token refuses a transfer to the token')):
        with no(err):
            mandate.open(relayer, token, erin, tm)
    assert bal(token, h) == 1_000, 'nothing moved'
    mandate.open(relayer, token, erin, terms)
    with no('mandate exists'):                            # the same open again (one-shot)
        mandate.open(relayer, token, erin, terms, fund_mbr=0, mbr=MBR_MANDATE)
    assert bal(token, h) == 700
    # R8: a POLICY_PASSKEY_FOR_VALUE owner funds (opens) only with a passkey (the token's account.verify) …
    dave = PasskeyKey('dave-owner')
    token.account.key_op(relayer, 'mtx_add_key', erin, [dave.record(), ORIGIN.encode()], mbr=2 * SLOT)
    token.account.key_op(relayer, 'mtx_set_policy', erin, [POLICY_PASSKEY_FOR_VALUE], nonce=1)
    with no('POLICY_PASSKEY_FOR_VALUE'):
        mandate.open(relayer, token, erin, terms, nonce=1)
    assert bal(token, h) == 700
    mid2 = mandate.open(relayer, token, erin, terms, nonce=1, sign=lambda d: dave.auth(d))[1]
    assert bal(token, h) == 400
    # … but revokes with any of its keys: the kill switch is not a value op (fix 1 m3, NEAR's rule)
    mandate.revoke(relayer, token, mid2, erin)
    assert bal(token, h) == 700


def token_mbr(token, o, a):
    """The exact MBR of a token value entry: its own boxes plus the account record a UA's first op opens."""
    need = view(token, 'mbr_needed', o)
    if not (o[3][0] == 0 and len(a) == 64):
        v, _, fail, _ = sim_view(token.account, 'verify_mbr', [o[3][0], bytes(o[3][1]), digest(o), a])
        need += 0 if fail else v
    return need


def test_funding_only_through_the_open(mandate, token, probe, make, relayer):
    """Fix 1 C1 (reproducer): the owner's funding op names the mandate app as relayer, so the token's rule 7 refuses
    it at the top level and through any other app (the probe: a router or DEX stand-in) — nothing moves, nothing is
    stranded; only the open executes it. The token's part of the MBR (`fund_mbr`) is split exactly."""
    erin, dele, bob = EdKey('erin'), EdKey('dele'), make()
    h = erin.ua()
    fund_ua(token, erin, 1_000)
    terms = mandate.terms(dele.ua(), native(bob), 100, 250, 300)
    o, mid = mandate.open_op(token, h, terms, b'\xb0' * 32, 0)
    a = erin.auth(digest(o))
    with no('relayer is not the sender'):                 # front-run at the top level, by any relayer
        token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=None)
    with no('relayer is not the sender'):                 # through another app, with itself as the open payee
        run(relayer, probe, 'pay', [token.id, o, a, probe.address, 0], apps=[token.id, token.account.id],
            fee_extra=FEE_CREDIT)
    assert (bal(token, h), bal(token, native(mandate.key)), mandate.get(token, mid)) == (1_000, 0, None)
    for kw in ({'fund_delta': -1}, {'fund_delta': 1}):    # the token's part off by one (the total unchanged)
        with no('MBR payment must equal'):
            mandate.open(relayer, token, erin, terms, **kw)
    r, mid2 = mandate.open(relayer, token, erin, terms)
    assert mid2 == mid and (bal(token, h), bal(token, native(mandate.key))) == (700, 300)
    tev = events(token.app, r.logs)                       # the token paid the open payee: the mandate app itself
    assert ('PaymentSettled', [[1, list(erin.id)], [0, list(mandate.key)], 300, list(mid)]) in tev
    with no('mandate exists'):                            # replay through the open
        mandate.open(relayer, token, erin, terms, fund_mbr=0, mbr=MBR_MANDATE)
    with no('relayer is not the sender'):                 # replay at the top level
        token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=None)
    assert bal(token, h) == 700


def test_limits_exceeded_refused(mandate, token, make, relayer):
    """Per payment, per period (CTR-ACC-07: fixed windows on the grid from the open, never restarted at `now`)."""
    erin, dele, bob = EdKey('erin'), EdKey('dele'), make()
    b = native(bob)
    mid = opened(mandate, relayer, token, erin, 1_000, mandate.terms(dele.ua(), b, 50, 80, 300))

    def pay(amount, r):
        return mandate.pay(relayer, token, mid, dele, b, amount, bytes([r]) * 32)
    with no(PER_PAYMENT):
        pay(51, 1)
    pay(50, 2)
    with no(PER_PERIOD):
        pay(31, 3)
    pay(30, 4)
    with no(PER_PERIOD):
        pay(1, 5)
    # 1.5 periods later: the window moves on the grid (whole periods from the start), the budget is fresh
    start = mandate.get(token, mid)['period_start']
    advance(start + PERIOD_S + PERIOD_S // 2 - latest_ts())
    pay(1, 5)
    m = mandate.get(token, mid)
    assert (m['period_start'], m['spent']) == (start + PERIOD_S, 1), 'grid, not now'
    pay(50, 6)
    with no(PER_PERIOD):
        pay(30, 7)
    assert bal(token, b) == 131
    with no('The amount should be a positive number'):
        pay(0, 8)


def test_wrong_payee_refused(mandate, token, make, relayer):
    erin, dele, bob, alice = EdKey('erin'), EdKey('dele'), make(), make()
    b = native(bob)
    mid = opened(mandate, relayer, token, erin, 1_000, mandate.terms(dele.ua(), b, 100, 250, 300))
    for to in (native(alice), native(relayer), EdKey('zed').ua(), erin.ua(), native(mandate.key)):
        with no(PAYEE):
            mandate.pay(relayer, token, mid, dele, to, 10, b'\x01' * 32)
    mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32)
    assert bal(token, b) == 10


def test_expired_refused(mandate, token, make, relayer):
    """Expiry edges (review M3 of T7): a pay in the second now == expiry passes, one second later it is refused; no
    refund while live (now == expiry included); after the expiry anyone refunds the remainder to the owner, once; a
    refunded mandate refuses a revoke (no-op); a revoke after the expiry (not refunded) sweeps."""
    erin, dele, bob = EdKey('erin'), EdKey('dele'), make()
    h, b = erin.ua(), native(bob)
    expiry = latest_ts() + 600
    mid = opened(mandate, relayer, token, erin, 1_000, mandate.terms(dele.ua(), b, 100, 250, 300, expiry=expiry))
    with no('mandate live'):
        mandate.refund(relayer, token, mid)
    advance(expiry - latest_ts())
    assert latest_ts() == expiry
    mandate.pay(relayer, token, mid, dele, b, 10, b'\x02' * 32)        # Global.latest_timestamp == expiry
    with no('mandate live'):
        mandate.refund(relayer, token, mid)
    advance(1)
    with no(EXPIRED):
        mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32)
    with no('MBR payment must equal'):                                  # a stray payment is refused (fix 1 m2)
        mandate.refund(relayer, token, mid, mbr=1)
    m0 = mandate.min_balance()
    r = mandate.refund(make(1_000_000), token, mid)                     # anyone; no box, no MBR
    assert mandate.min_balance() == m0
    assert (bal(token, h), bal(token, native(mandate.key)), bal(token, b)) == (990, 0, 10)
    assert r.own(mandate)[0][1][2] == 'refund'
    m = mandate.get(token, mid)
    assert (m['remaining'], m['revoked']) == (0, True)
    with no('nothing to refund'):
        mandate.refund(relayer, token, mid)
    with no(REVOKED):                                                   # no fee for a no-op
        mandate.revoke(relayer, token, mid, erin)
    # a second mandate, expired: the owner's revoke after the expiry sweeps it (a state change, not a no-op)
    exp2 = latest_ts() + 600
    t2 = mandate.terms(dele.ua(), b, 100, 250, 300, expiry=exp2)
    mid2 = mandate.open(relayer, token, erin, t2, nonce=1)[1]
    advance(exp2 + 1 - latest_ts())
    mandate.revoke(relayer, token, mid2, erin)
    assert (bal(token, h), mandate.get(token, mid2)['revoked']) == (990, True)
    with no('nothing to refund'):
        mandate.refund(relayer, token, mid2)


def test_delegate_policy_passkey_for_value(mandate, token, make, relayer):
    """R8 for the pay: the delegate's own POLICY_PASSKEY_FOR_VALUE binds its mandate pays, never its revoke (the kill
    switch is not a value op: fix 1 m3, as NEAR)."""
    erin, dele, pk, bob = EdKey('erin'), EdKey('dele'), PasskeyKey('dele-pk'), make()
    d, b = dele.ua(), native(bob)
    mid = opened(mandate, relayer, token, erin, 1_000, mandate.terms(d, b, 100, 250, 300))
    acc = token.account
    acc.key_op(relayer, 'mtx_add_key', dele, [pk.record(), ORIGIN.encode()], mbr=rec_mbr(2, 1))
    acc.key_op(relayer, 'mtx_set_policy', dele, [POLICY_PASSKEY_FOR_VALUE], nonce=1)
    with no('POLICY_PASSKEY_FOR_VALUE'):
        mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32, sign=lambda x: dele.auth(x))
    assert bal(token, native(mandate.key)) == 300
    mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32, sign=lambda x: pk.auth(x))
    assert (bal(token, b), mandate.get(token, mid)['remaining']) == (10, 290)
    mandate.revoke(relayer, token, mid, dele)                    # its ed25519 key
    assert bal(token, erin.ua()) == 990


def test_revoked_refused_then_funds_back(mandate, token, make, relayer):
    erin, dele, mallory, bob = EdKey('erin'), EdKey('dele'), EdKey('mallory'), make()
    h, b = erin.ua(), native(bob)
    terms = mandate.terms(dele.ua(), b, 100, 250, 300)
    mid = opened(mandate, relayer, token, erin, 1_000, terms)
    mandate.pay(relayer, token, mid, dele, b, 40, b'\x01' * 32)
    with no('only the owner or the delegate revokes'):
        mandate.revoke(relayer, token, mid, mallory, mbr=rec_mbr(1))
    with no('not a key of the subject'):                  # the delegate's revoke signed by another key
        mandate.revoke(relayer, token, mid, mallory, by=dele)
    with no('revoke shape'):
        mandate.revoke(relayer, token, mid, dele, op_kw={'nonce': 1})
    with no('revoke shape'):
        mandate.revoke(relayer, token, mid, dele, op_kw={'amount': 1})
    with no('revoke shape'):
        mandate.revoke(relayer, token, mid, dele, op_kw={'extra': Z32})
    with no('no such mandate'):
        mandate.revoke(relayer, token, b'\x05' * 32, dele)
    # the delegate's kill switch: the remaining funds go back to the owner at once, no MBR
    m0, t0 = mandate.min_balance(), token.min_balance()
    r = mandate.revoke(relayer, token, mid, dele)
    assert (mandate.min_balance(), token.min_balance()) == (m0, t0), 'revoke creates no box'
    assert r.own(mandate) == [('Mandate', [token.id, list(mid), 'revoke', [1, list(dele.id)]])]
    m = mandate.get(token, mid)
    assert (m['revoked'], m['remaining']) == (True, 0)
    assert (bal(token, h), bal(token, native(mandate.key)), bal(token, b)) == (960, 0, 40)
    with no(REVOKED):
        mandate.pay(relayer, token, mid, dele, b, 10, b'\x02' * 32)
    with no(REVOKED):                                     # no-op revoke refused (owner ruling: no fee for a no-op)
        mandate.revoke(relayer, token, mid, erin)
    with no('nothing to refund'):                         # no double spend between revoke and refund
        mandate.refund(relayer, token, mid)
    # the owner revokes a second mandate (nonce 1)
    mid2 = mandate.open(relayer, token, erin, terms, nonce=1)[1]
    assert bal(token, h) == 660
    mandate.revoke(relayer, token, mid2, erin)
    assert (bal(token, h), bal(token, native(mandate.key))) == (960, 0)


def test_pay_ref_once(mandate, token, make, relayer):
    erin, dele, bob = EdKey('erin'), EdKey('dele'), make()
    h, b = erin.ua(), native(bob)
    terms = mandate.terms(dele.ua(), b, 100, 250, 300)
    mid = opened(mandate, relayer, token, erin, 1_000, terms)
    o = mandate.pay_op(token, mid, b, 10, b'\x01' * 32)
    a = dele.auth(digest(o))
    mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32, sign=lambda d: a)
    with no(PAID):
        mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32, sign=lambda d: a)
    with no(PAID):
        mandate.pay(relayer, token, mid, dele, b, 11, b'\x01' * 32)
    # the lane is derived from pay_ref, at nonce 0 (another lane or nonce would pay the ref twice); extra binds the token
    for kw in ({'lane': b'\x09' * 32}, {'nonce': 1}, {'pay_ref': Z32, 'lane': pay_lane(Z32)}, {'extra': Z32},
               {'extra': sha256(u64(token.id + 1))}):
        with no(PAY_SHAPE):
            mandate.pay(relayer, token, mid, dele, b, 10, b'\x02' * 32, op_kw=kw)
    with no('wrong op code'):
        mandate.pay(relayer, token, mid, dele, b, 10, b'\x02' * 32, op_kw={'op': 0})
    # the same pay_ref under another mandate of the same owner pays
    mid2 = mandate.open(relayer, token, erin, terms, nonce=1)[1]
    mandate.pay(relayer, token, mid2, dele, b, 10, b'\x01' * 32)
    assert (bal(token, b), mandate.get(token, mid)['remaining'], mandate.get(token, mid2)['remaining']) == (20, 290, 290)
    with no('no such mandate'):
        mandate.pay(relayer, token, b'\x05' * 32, dele, b, 10, b'\x01' * 32)
    with no('no such mandate'):                           # from must be the mandate (a UA id), not an address
        mandate.pay(relayer, token, mid, dele, b, 10, b'\x03' * 32, op_kw={'from': [0, mid]})


def test_no_pay_meta_entry(mandate, token, make, relayer):
    """metatx-split §6.2: the mandate has no pay-meta entry (nothing in the ABI, an unknown selector is refused)."""
    assert not [m for m in mandate.app.methods if 'meta' in m]
    assert sorted(mandate.app.methods) == ['create', 'mandate', 'mandate_refund', 'mtx_mandate_open',
                                           'mtx_mandate_pay', 'mtx_revoke']
    sel = abi.Method.from_signature('mtx_mandate_pay_meta(uint64,byte[],byte[],byte[32],byte[])void').get_selector()
    with pytest.raises(AlgodHTTPError, match='rejected by ApprovalProgram|err opcode|assert failed'):
        txn = transaction.ApplicationNoOpTxn(relayer.addr, sp(), mandate.id, app_args=[sel, b'x'])
        wait(ALGOD.send_transaction(txn.sign(relayer.sk)))


def test_native_owner_ua_payee(mandate, token, make, relayer):
    """The other holder kinds: a native owner signing with its wallet key (funding and open), a UA payee
    (`transfer_to_ua`), a native delegate; the sweep back to a native owner (`arc200_transfer`)."""
    alice, dele, payee = token.alice, make(), EdKey('payee')
    terms = mandate.terms(native(dele), payee.ua(), 100, 250, 300)
    t0 = token.min_balance()
    r, mid = mandate.open(relayer, token, alice, terms)
    assert token.min_balance() - t0 == MBR_BALANCE + MBR_LANE + MBR_UA     # mandate address, funding lane, payee UA
    assert bal(token, alice) == 1_000_000 - 300 and view(token, 'ua_balance_of', payee.id) == 0
    with no('MBR payment must equal'):                     # native delegate: exactly the lane box, nothing more
        mandate.pay(relayer, token, mid, dele, payee.ua(), 30, b'\x01' * 32, mbr=MBR_MLANE + 1)
    mandate.pay(relayer, token, mid, dele, payee.ua(), 30, b'\x01' * 32)
    assert view(token, 'ua_balance_of', payee.id) == 30
    with no('bad signature'):
        mandate.pay(relayer, token, mid, dele, payee.ua(), 30, b'\x02' * 32, sign=lambda d: Acct().sign_op(d))
    with no('MBR payment must equal'):                     # a revoke creates no box: no payment
        mandate.revoke(relayer, token, mid, alice, mbr=1)
    mandate.revoke(relayer, token, mid, alice)
    assert bal(token, alice) == 1_000_000 - 30
    # a payee box that exists: the open forwards nothing to the token
    r, mid = mandate.open(relayer, token, alice, terms, nonce=1)
    assert mandate.get(token, mid)['remaining'] == 300


def test_msig_delegate(mandate, token, make, relayer):
    """A msig UA delegate (2 ed25519 members) pays through the account app (as every UA signer, whatever its auth's
    length: a 64-byte auth is a wallet signature only for a native holder)."""
    erin, bob = EdKey('erin'), make()
    m = MsigKey(2, [(EdKey('ms-1'), 1), (EdKey('ms-2'), 1)])
    mid = opened(mandate, relayer, token, erin, 1_000, mandate.terms(m.ua(), native(bob), 100, 250, 300))
    with no('unknown auth tag'):                          # a 64-byte "wallet signature" for a UA: no such key kind
        mandate.pay(relayer, token, mid, m, native(bob), 25, b'\x01' * 32, sign=lambda d: b'\x00' * 64, mbr=MBR_MLANE)
    mandate.pay(relayer, token, mid, m, native(bob), 25, b'\x01' * 32)
    assert bal(token, native(bob)) == 25


def test_replay_across_tokens_networks_apps(mandate, token, dispenser, make, relayer, account):
    """The same mandate id on two tokens (same owner, terms, lane, nonce): state keyed by (token, id), so a pay or a
    revoke signed for one token is refused on the other (extra = sha256(token)); another network, another mandate
    app, an expired op are refused."""
    erin, dele, bob = EdKey('erin'), EdKey('dele'), make()
    b = native(bob)
    token2 = make_token(dispenser, make, account)
    terms = mandate.terms(dele.ua(), b, 100, 250, 300)
    mid = opened(mandate, relayer, token, erin, 1_000, terms)
    mid2 = opened(mandate, relayer, token2, erin, 1_000, terms)
    assert mid == mid2
    o = mandate.pay_op(token, mid, b, 10, b'\x01' * 32)
    a = dele.auth(digest(o))
    with no(PAY_SHAPE):                                   # token 1's pay submitted against token 2
        mandate.pay(relayer, token2, mid, dele, b, 10, b'\x01' * 32, op_kw={'extra': o[11]}, sign=lambda d: a)
    mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32, sign=lambda d: a)
    assert (bal(token, b), bal(token2, b)) == (10, 0)
    ro = mandate.revoke_op(token, erin.ua(), mid)
    with no('revoke shape'):
        mandate.revoke(relayer, token2, mid, erin, op_kw={'extra': ro[11]})
    for kw, err in (({'network': sha256(b'another genesis')}, 'wrong network'),
                    ({'contract': sha256(b'another mandate app')}, 'wrong contract'),
                    ({'valid_until': 1}, 'expired')):
        with no(err):
            mandate.pay(relayer, token, mid, dele, b, 10, b'\x02' * 32, op_kw=kw)
        with no(err):
            mandate.revoke(relayer, token, mid, erin, op_kw=kw)
    mandate.revoke(relayer, token2, mid, erin)
    assert (bal(token, erin.ua()), bal(token2, erin.ua())) == (700, 1_000)


def test_fake_token_cannot_touch_other_funds(mandate, token, make, relayer):
    """A fake token app (approves every call, answers true) passed as `token`: its mandate is keyed by the fake app,
    so its pays, revokes and refunds call only the fake app; the real token's funds under the mandate address stay."""
    erin, dele, bob = EdKey('erin'), EdKey('dele'), make()
    b = native(bob)
    mid = opened(mandate, relayer, token, erin, 1_000, mandate.terms(dele.ua(), b, 100, 250, 300))
    prog = base64.b64decode(ALGOD.compile('#pragma version 10\nbyte 0x151f7c7580\nlog\nint 1')['result'])
    clear = base64.b64decode(ALGOD.compile('#pragma version 10\nint 1')['result'])
    info = wait(ALGOD.send_transaction(transaction.ApplicationCreateTxn(
        relayer.addr, sp(), transaction.OnComplete.NoOpOC, prog, clear, transaction.StateSchema(0, 0),
        transaction.StateSchema(0, 0)).sign(relayer.sk)))
    fake = Tok(token.app, info['application-index'])
    fake.account = token.account
    fund(relayer, fake.address, 100_000)
    mallory, merchant = EdKey('mallory'), make()
    huge = mandate.terms(mallory.ua(), native(merchant), 10**6, 10**6, 10**6)
    r, fmid = mandate.open(relayer, fake, mallory, huge, fund_mbr=0, mbr=MBR_MANDATE)
    assert mandate.get(fake, fmid)['remaining'] == 10**6
    assert r.own(mandate) == [('Mandate', [fake.id, list(fmid), 'open', [1, list(mallory.id)]])]
    real0 = bal(token, native(mandate.key))
    # fix 1 I1 (reproducer): the pay on the fake token logs the fake token's id, so it books nothing for the real one
    r = mandate.pay(relayer, fake, fmid, mallory, tuple(huge[1]), 10**6, b'\x01' * 32)
    assert r.own(mandate) == [('MandatePaymentSettled', [fake.id, [1, list(fmid)], [0, list(merchant.key)], 10**6,
                                                         [1] * 32])]
    assert bal(token, native(merchant)) == 0
    r = mandate.revoke(relayer, fake, fmid, mallory)
    assert r.own(mandate)[0][1][:3] == [fake.id, list(fmid), 'revoke']
    assert bal(token, native(mandate.key)) == real0 == 300
    # the fake mandate's id has no state under the real token
    with no('no such mandate'):
        mandate.pay(relayer, token, fmid, mallory, tuple(huge[1]), 1, b'\x02' * 32)
    with no('no such mandate'):
        mandate.revoke(relayer, token, fmid, mallory)
    mandate.pay(relayer, token, mid, dele, b, 100, b'\x03' * 32)
    assert bal(token, b) == 100


def test_mandate_update_delete_optin_refused(mandate, dispenser, make):
    """R11: the mandate approval refuses Update / Delete (creator included) and OptIn / CloseOut; no local state."""
    refused_actions(mandate, dispenser, ['update', 'delete'])
    refused_actions(mandate, make(1_000_000), ['optin', 'closeout'])
    assert ALGOD.application_info(mandate.id)['params']['approval-program'] == base64.b64encode(
        mandate.app.approval).decode()
    assert mandate.app.spec['state']['schema']['local'] == {'ints': 0, 'bytes': 0}


def test_figures_pinned(mandate, token, make, relayer):
    """MBR per mandate box / lane box (measured above) and the opcode budget per entry in its minimal group, pinned:
    (consumed, inner app calls) per signer kind of the open / pay / revoke and the refund."""
    out = {}
    bob = make()
    b = native(bob)
    for name, owner, dele in (('ed25519', EdKey('fig-o'), EdKey('fig-d')),
                              ('passkey', PasskeyKey('fig-o-pk'), PasskeyKey('fig-d-pk'))):
        fund_ua(token, owner, 1_000)
        terms = mandate.terms(dele.ua(), b, 100, 250, 300, expiry=latest_ts() + 3_000)
        out['open ' + name] = mandate.open(relayer, token, owner, terms, simulate=True)
        mid = mandate.open(relayer, token, owner, terms)[1]
        out['pay ' + name + ' (delegate opened)'] = mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32,
                                                                simulate=True)
        mandate.pay(relayer, token, mid, dele, b, 10, b'\x01' * 32)
        out['pay ' + name] = mandate.pay(relayer, token, mid, dele, b, 10, b'\x02' * 32, simulate=True)
        out['revoke ' + name] = mandate.revoke(relayer, token, mid, owner, simulate=True)
    alice = token.alice
    terms = mandate.terms(native(make()), b, 100, 250, 300, expiry=latest_ts() + 60)
    mid = mandate.open(relayer, token, alice, terms)[1]
    out['open native'] = mandate.open(relayer, token, alice, terms, nonce=1, simulate=True)
    advance(61)
    out['refund'] = mandate.refund(relayer, token, mid, simulate=True)
    print('\nmandate opcode budget, minimal group (consumed, inner app calls, failure): %s\npins %s' % (out, BUDGET_PIN))
    print('MBR (µALGO): mandate box %d (name 41 B, value %d B), mandate lane box %d; open forwards the payee box %d '
          'when new' % (MBR_MANDATE, MANDATE_LEN, MBR_MLANE, MBR_BALANCE))
    print('program size (B): approval %d, clear %d' % (len(mandate.app.approval), len(mandate.app.clear)))
    for k, (used, calls, fail) in out.items():
        assert fail is None, (k, fail)
        assert used <= BUDGET_PIN[k][0] and calls <= BUDGET_PIN[k][1], (k, used, calls)
