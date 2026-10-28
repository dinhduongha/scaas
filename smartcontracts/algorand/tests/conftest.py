"""Localnet harness (near-algorand T11): `smartcontracts/scripts/devnet.sh algorand up` first; apps from `out/`
(`build.sh algorand`). Plain py-algorand-sdk: ABI methods from the ARC-56 specs, groups built by hand so every
test states its MBR payment, budget calls and box references; a refusal maps the failing pc to the program's
assert message (ARC-56 `sourceInfo`)."""
import base64
import hashlib
import json
import os
import re

import pytest
from algosdk import abi, account, encoding, kmd, logic, transaction, util
from algosdk.atomic_transaction_composer import (AccountTransactionSigner, AtomicTransactionComposer,
                                                 TransactionWithSigner)
from algosdk.error import AlgodHTTPError
from algosdk.v2client import algod, models

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(ROOT, '..', '..'))
OUT = os.path.join(ROOT, 'out')
TOKEN_ = 'a' * 64
ALGOD = algod.AlgodClient(TOKEN_, 'http://127.0.0.1:4001')
KMD = kmd.KMDClient(TOKEN_, 'http://127.0.0.1:4002')
LABEL = b'scaas.metaop.v1'
Z32 = bytes(32)
U128_MAX = 2**128 - 1
METAOP = ('(byte[32],byte[32],uint8,(uint8,byte[32]),(uint8,byte[32]),byte[32],uint128,byte[32],byte[32],uint64,'
          'uint64,byte[32])')
METAOP_T = abi.ABIType.from_string(METAOP)
MIN_FEE = 1000
BUDGET = 4  # bare budget calls per mtx_* entry (pooled 700 each; measured in test_figures_pinned)
FAR = 4_102_444_800  # 2100-01-01 (s)


def box_mbr(name_len, value_len):
    return 2500 + 400 * (name_len + value_len)


MBR_BALANCE = box_mbr(33, 32)   # "b" ‖ address → uint256
MBR_UA = box_mbr(33, 32)        # "u" ‖ id → uint256
MBR_LANE = box_mbr(33, 8)       # "l" ‖ sha256(kind ‖ holder ‖ lane) → uint64
MBR_ALLOWANCE = box_mbr(33, 32)  # "a" ‖ sha256(owner ‖ spender) → uint256


def sha256(*p):
    return hashlib.sha256(b''.join(p)).digest()


def keccak(*p):
    from Cryptodome.Hash import keccak as k  # pycryptodomex, a py-algorand-sdk dependency
    return k.new(digest_bits=256, data=b''.join(p)).digest()


def meta_pay_id(salt, meta):
    return keccak(b'scaas.pay.meta', salt, keccak(meta))


def pay_lane(p):
    return keccak(b'scaas.pay.lane', p)


# ---------------------------------------------------------------- accounts
class Acct:
    def __init__(self, sk=None):
        self.sk, self.addr = (sk, account.address_from_private_key(sk)) if sk else account.generate_account()
        self.key = encoding.decode_address(self.addr)
        self.signer = AccountTransactionSigner(self.sk)

    def sign_op(self, digest):
        """The wallet sign-bytes form: py-algorand-sdk `util.sign_bytes` prepends "MX" (ARC-60 style)."""
        return base64.b64decode(util.sign_bytes(text(digest), self.sk))


def text(digest):
    return LABEL + b':' + digest.hex().encode()


def native(a):
    return (0, a.key if isinstance(a, Acct) else a)


def ua(i):
    return (1, i)


@pytest.fixture(scope='session')
def dispenser():
    w = next(w for w in KMD.list_wallets() if w['name'] == 'unencrypted-default-wallet')
    h = KMD.init_wallet_handle(w['id'], '')
    try:
        addrs = KMD.list_keys(h)
        best = max(addrs, key=lambda a: ALGOD.account_info(a)['amount'])
        return Acct(KMD.export_key(h, '', best))
    finally:
        KMD.release_wallet_handle(h)


def sp(fee=MIN_FEE):
    p = ALGOD.suggested_params()
    p.flat_fee, p.fee = True, fee
    return p


def wait(txid):
    return transaction.wait_for_confirmation(ALGOD, txid, 4)


def fund(dispenser, to, amount):
    a = to if isinstance(to, str) else to.addr
    wait(ALGOD.send_transaction(transaction.PaymentTxn(dispenser.addr, sp(), a, amount).sign(dispenser.sk)))


@pytest.fixture
def make(dispenser):
    """`make(algo)` → a fresh account funded with `algo` µALGO (0 = never seen on chain)."""
    def f(algo=0):
        a = Acct()
        if algo:
            fund(dispenser, a, algo)
        return a
    return f


# ---------------------------------------------------------------- apps
class Refused(Exception):
    pass


class App:
    """An ARC-56 spec: methods by name, events by selector, assert messages by pc."""

    def __init__(self, name):
        self.name = name
        self.spec = json.load(open(os.path.join(OUT, name + '.arc56.json')))
        self.approval = open(os.path.join(OUT, name + '.approval.bin'), 'rb').read()
        self.clear = open(os.path.join(OUT, name + '.clear.bin'), 'rb').read()
        self.methods = {}
        for m in self.spec['methods']:
            sig = '%s(%s)%s' % (m['name'], ','.join(a['type'] for a in m['args']), m['returns']['type'])
            self.methods[m['name']] = abi.Method.from_signature(sig)
        self.errors = {}
        for e in self.spec['sourceInfo']['approval']['sourceInfo']:
            for pc in e['pc']:
                self.errors[pc] = e.get('errorMessage', '')
        self.events = {}
        for e in self.spec.get('events', []):
            sig = '%s(%s)' % (e['name'], ','.join(a['type'] for a in e['args']))
            self.events[hashlib.new('sha512_256', sig.encode()).digest()[:4]] = (
                e['name'], abi.ABIType.from_string('(%s)' % ','.join(a['type'] for a in e['args'])),
                [a.get('name') for a in e['args']])
        self.schema = self.spec['state']['schema']['global']


APPS = {}


def spec(name):
    if name not in APPS:
        APPS[name] = App(name)
    return APPS[name]


class Deployed:
    def __init__(self, app, app_id):
        self.app, self.id = app, app_id
        self.address = logic.get_application_address(app_id)
        self.key = encoding.decode_address(self.address)

    def min_balance(self):
        return ALGOD.account_info(self.address)['min-balance']


def explain(msg):
    """`pc=` of each failing program (innermost first) → its assert message."""
    found = []
    for app_id, pc in re.findall(r'app=(\d+), pc=(\d+)', msg):
        for d in DEPLOYED.values():
            if d.id == int(app_id) and int(pc) in d.app.errors:
                found.append(d.app.errors[int(pc)])
    return ' | '.join(found) + ' :: ' + msg


DEPLOYED = {}


def group(sender, calls, mbr=None, budget=0, boxes=(), fee_extra=0, box_app=None):
    """One atomic group: [payment `mbr` → the first call's app (when not None)] [calls…] [`budget` bare NoOp calls
    on the first call's app]; `boxes` (names on the first call's app) go on the budget calls, 8 per transaction
    (group resource sharing); `box_app` takes the budget calls instead (an app called through another).
    `calls` = [(Deployed, method, args, {accounts, apps, on_complete, sender})]."""
    atc = AtomicTransactionComposer()
    first = calls[0][0]
    bapp = box_app or first
    if mbr is not None:
        atc.add_transaction(TransactionWithSigner(
            transaction.PaymentTxn(sender.addr, sp(), first.address, mbr), sender.signer))
    for i, (d, method, args, kw) in enumerate(calls):
        atc.add_method_call(d.id, d.app.methods[method], kw.get('sender', sender).addr,
                            sp(MIN_FEE + (fee_extra if i == 0 else 0)), kw.get('sender', sender).signer, args,
                            accounts=kw.get('accounts'), foreign_apps=kw.get('apps'),
                            on_complete=kw.get('on_complete', transaction.OnComplete.NoOpOC))
    boxes = list(boxes)
    n = max(budget, (len(boxes) + 7) // 8)
    for i in range(n):
        t = transaction.ApplicationNoOpTxn(sender.addr, sp(), bapp.id, note=b'budget%d' % i,
                                           boxes=[(bapp.id, b) for b in boxes[8 * i:8 * i + 8]])
        atc.add_transaction(TransactionWithSigner(t, sender.signer))
    return atc


class Result:
    def __init__(self, info):
        self.info = info
        self.logs = []

        def walk(t):
            self.logs += [base64.b64decode(x) for x in t.get('logs', [])]
            for it in t.get('inner-txns', []):
                walk(it)
        walk(info)


def run(sender, d, method, args, **kw):
    """Send one call (plus the MBR payment / budget calls of `group`), wait; `Refused(assert message)` on failure."""
    call_kw = {k: kw.pop(k) for k in ('accounts', 'apps', 'on_complete') if k in kw}
    atc = group(sender, [(d, method, args, call_kw)], **kw)
    try:
        r = atc.execute(ALGOD, 4)
    except AlgodHTTPError as e:
        raise Refused(explain(str(e))) from None
    idx = 1 if kw.get('mbr') is not None else 0
    res = Result(ALGOD.pending_transaction_info(r.tx_ids[idx]))
    res.ret = r.abi_results[0].return_value
    return res


def sim(sender, d, method, args, **kw):
    """Simulate (no state change): (return value, budget consumed, failure message, logs of the call)."""
    call_kw = {k: kw.pop(k) for k in ('accounts', 'apps', 'on_complete') if k in kw}
    extra = kw.pop('extra_budget', 0)
    atc = group(sender, [(d, method, args, call_kw)], **kw)
    r = atc.simulate(ALGOD, models.SimulateRequest(txn_groups=[], allow_unnamed_resources=True,
                                                    extra_opcode_budget=extra))
    g = r.simulate_response['txn-groups'][0]
    fail = explain(r.failure_message) if r.failure_message else None
    idx = 1 if kw.get('mbr') is not None else 0
    logs = [base64.b64decode(x) for x in g['txn-results'][idx]['txn-result'].get('logs', [])]
    return (r.abi_results[0].return_value if not fail else None), g.get('app-budget-consumed'), fail, logs


def view(d, method, *args):
    v, _, fail, _ = sim(VIEWER, d, method, list(args), extra_budget=20_000)
    assert fail is None, fail
    return v


VIEWER = Acct()


def deploy(dispenser, name, create_args, fund_app=100_000):
    a = spec(name)
    atc = AtomicTransactionComposer()
    sch = a.schema
    atc.add_method_call(0, a.methods['create'], dispenser.addr, sp(), dispenser.signer, create_args,
                        approval_program=a.approval, clear_program=a.clear,
                        global_schema=transaction.StateSchema(sch['ints'], sch['bytes']),
                        local_schema=transaction.StateSchema(0, 0), extra_pages=(len(a.approval) - 1) // 2048)
    r = atc.execute(ALGOD, 4)
    app_id = ALGOD.pending_transaction_info(r.tx_ids[0])['application-index']
    d = Deployed(a, app_id)
    DEPLOYED[app_id] = d
    if fund_app:
        fund(dispenser, d.address, fund_app)
    return d


@pytest.fixture(scope='session', autouse=True)
def viewer(dispenser):
    fund(dispenser, VIEWER, 10_000_000)


@pytest.fixture
def probe(dispenser):
    return deploy_probe(dispenser)


def deploy_probe(dispenser):
    a = spec('Probe')
    txn = transaction.ApplicationCreateTxn(dispenser.addr, sp(), transaction.OnComplete.NoOpOC, a.approval, a.clear,
                                           transaction.StateSchema(0, 0), transaction.StateSchema(0, 0))
    info = wait(ALGOD.send_transaction(txn.sign(dispenser.sk)))
    d = Deployed(a, info['application-index'])
    DEPLOYED[d.id] = d
    fund(dispenser, d.address, 10_000_000)
    return d


# ---------------------------------------------------------------- token
class Tok(Deployed):
    """The token plus its admin; `mtx(...)` builds, signs and submits a MetaOp entry with its boxes and budget."""

    def op(self, signer_from, to, amount, pay_ref=Z32, lane=None, nonce=0, relayer=Z32, code=0, valid_until=FAR,
           extra=Z32, network=None, contract=None):
        frm = native(signer_from) if isinstance(signer_from, Acct) else signer_from
        return [network or genesis(), contract or self.key, code, list(frm), list(to), relayer, amount, pay_ref,
                lane if lane is not None else sha256(b'lane', pay_ref), nonce, valid_until, extra]

    def boxes(self, o, payee=None):
        frm, to = o[3], payee or o[4]
        names = [b'l' + sha256(bytes([frm[0]]), frm[1], o[8])]
        for h in (frm, to):
            names.append((b'b' if h[0] == 0 else b'u') + h[1])
        return names

    def mtx(self, relayer, method, o, auth, *extra_args, mbr='auto', budget=BUDGET,
            payee=None, extra_boxes=()):
        if mbr == 'auto':
            mbr = view(self, 'mbr_needed', o) or None
        acc = [encoding.encode_address(bytes(o[3][1]))] if o[3][0] == 0 else []
        return run(relayer, self, method, [o, auth, *extra_args], mbr=mbr, budget=budget,
                   boxes=self.boxes(o, payee) + list(extra_boxes), accounts=acc)


def digest(o):
    return sha256(LABEL, METAOP_T.encode(o))


_GEN = []


def genesis():
    if not _GEN:
        _GEN.append(base64.b64decode(ALGOD.suggested_params().gh))
    return _GEN[0]


def latest_ts():
    return ALGOD.block_info(ALGOD.status()['last-round'])['block']['ts']


NAME = b'SCaaS Test Token'.ljust(32, b'\0')
SYMBOL = b'SCT'.ljust(8, b'\0')


@pytest.fixture
def token(dispenser, make):
    """A fresh token (admin = the dispenser), 1,000,000 minted to `alice` (the MBR of her balance box paid)."""
    d = deploy(dispenser, 'Token', [NAME, SYMBOL, 6, dispenser.addr])
    t = Tok(d.app, d.id)
    DEPLOYED[t.id] = t
    t.admin = dispenser
    t.alice = make(1_000_000)
    run(dispenser, t, 'mint', [t.alice.addr, 1_000_000], mbr=MBR_BALANCE, boxes=[b'b' + t.alice.key])
    return t
