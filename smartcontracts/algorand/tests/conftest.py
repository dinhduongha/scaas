"""Localnet harness (near-algorand T11, T12): `smartcontracts/scripts/devnet.sh algorand up` first; apps from `out/`
(`build.sh algorand`). Plain py-algorand-sdk: ABI methods from the ARC-56 specs, groups built by hand so every
test states its MBR payment, budget calls and box references; a refusal maps the failing pc to the program's
assert message (ARC-56 `sourceInfo`). UA signers (T12) reuse the vector generator's keys (`famvec`)."""
import base64
import hashlib
import json
import os
import re
import sys

import pytest
from algosdk import abi, encoding, kmd, logic, transaction, util
from algosdk import account as sdk_account
from algosdk.atomic_transaction_composer import (AccountTransactionSigner, AtomicTransactionComposer,
                                                 TransactionWithSigner)
from algosdk.error import AlgodHTTPError
from algosdk.v2client import algod, models

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(ROOT, '..', '..'))
OUT = os.path.join(ROOT, 'out')
sys.path.insert(0, os.path.join(REPO, 'smartcontracts', 'vectors', 'metatx'))
import famvec as V  # noqa: E402

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
BUDGET = 5  # bare budget calls per native mtx_* entry (pooled 700 each; enough that the token needs no inner
            # budget call: test_figures_pinned)
UA_BUDGET = 12  # … when the signer goes through the account app (a passkey UA: ≈ 5,300 in all, test_account)
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
        self.sk, self.addr = (sk, sdk_account.address_from_private_key(sk)) if sk else sdk_account.generate_account()
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


def group(sender, calls, mbr=None, budget=0, boxes=(), fee_extra=0, box_app=None, pay=None, budget_by=None):
    """One atomic group: [payment `mbr` → the first call's app (when not None)] [calls…] [`budget` bare NoOp calls
    on the first call's app]; `boxes` (names on the first call's app) go on the budget calls, 8 per transaction
    (group resource sharing); `box_app` takes the budget calls instead (an app called through another).
    `calls` = [(Deployed, method, args, {accounts, apps, on_complete, sender, signer})]. A box `(Deployed, name)`
    names another app's box (that app goes in the budget call's foreign apps). `pay` bends the MBR payment for
    the refusal tests: {payer, to, close, rekey, gap (a budget call between the payment and the call)}.
    `budget_by` sends the budget calls (default `sender`; a rekeyed sender cannot sign them)."""
    pay = pay or {}
    atc = AtomicTransactionComposer()
    first = calls[0][0]
    bapp = box_app or first
    if mbr is not None:
        payer = pay.get('payer', sender)
        atc.add_transaction(TransactionWithSigner(
            transaction.PaymentTxn(payer.addr, sp(), pay.get('to', first.address), mbr,
                                   close_remainder_to=pay.get('close'), rekey_to=pay.get('rekey')), payer.signer))
        if pay.get('gap'):
            atc.add_transaction(TransactionWithSigner(
                transaction.ApplicationNoOpTxn(sender.addr, sp(), bapp.id, note=b'gap'), sender.signer))
    for i, (d, method, args, kw) in enumerate(calls):
        who = kw.get('sender', sender)
        atc.add_method_call(d.id, d.app.methods[method], who.addr,
                            sp(MIN_FEE + (fee_extra if i == 0 else 0)), kw.get('signer', who.signer), args,
                            accounts=kw.get('accounts'), foreign_apps=kw.get('apps'),
                            on_complete=kw.get('on_complete', transaction.OnComplete.NoOpOC))
    boxes = [b if isinstance(b, tuple) else (bapp, b) for b in boxes]
    n = max(budget, (len(boxes) + 7) // 8)
    for i in range(n):
        chunk = boxes[8 * i:8 * i + 8]
        apps = sorted({a.id for a, _ in chunk if a.id != bapp.id})
        by = budget_by or sender
        t = transaction.ApplicationNoOpTxn(by.addr, sp(), bapp.id, note=b'budget%d' % i, foreign_apps=apps or None,
                                           boxes=[(a.id, b) for a, b in chunk])
        atc.add_transaction(TransactionWithSigner(t, by.signer))
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
    call_kw = {k: kw.pop(k) for k in ('accounts', 'apps', 'on_complete', 'signer') if k in kw}
    atc = group(sender, [(d, method, args, call_kw)], **kw)
    try:
        r = atc.execute(ALGOD, 4)
    except AlgodHTTPError as e:
        raise Refused(explain(str(e))) from None
    res = Result(ALGOD.pending_transaction_info(r.abi_results[0].tx_id))
    res.ret = r.abi_results[0].return_value
    return res


def sim(sender, d, method, args, **kw):
    """Simulate (no state change): (return value, budget consumed, failure message, logs of the call)."""
    call_kw = {k: kw.pop(k) for k in ('accounts', 'apps', 'on_complete', 'signer') if k in kw}
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


def refused_actions(d, who, kinds):
    """Each OnCompletion in `kinds`, bare and with an ABI selector: the bare form is the router's bare path
    (`return OnCompletion == NoOp && app ≠ 0` → "rejected by ApprovalProgram"), the ABI form fails the router's
    `OnCompletion == NoOp` assert (the same pc for every kind)."""
    from algosdk.error import AlgodHTTPError as E
    a, sel = d.app, next(m for n, m in d.app.methods.items() if n != 'create').get_selector()
    make_ = {'update': lambda **k: transaction.ApplicationUpdateTxn(who.addr, sp(), d.id, a.approval, a.clear, **k),
             'delete': lambda **k: transaction.ApplicationDeleteTxn(who.addr, sp(), d.id, **k),
             'optin': lambda **k: transaction.ApplicationOptInTxn(who.addr, sp(), d.id, **k),
             'closeout': lambda **k: transaction.ApplicationCloseOutTxn(who.addr, sp(), d.id, **k)}
    pcs = set()
    for kind in kinds:
        with pytest.raises(E, match='rejected by ApprovalProgram'):
            wait(ALGOD.send_transaction(make_[kind]().sign(who.sk)))
        with pytest.raises(E, match=r'logic eval error: assert failed pc=\d+') as e:
            wait(ALGOD.send_transaction(make_[kind](app_args=[sel]).sign(who.sk)))
        pcs.add(re.search(r'assert failed pc=(\d+)', str(e.value)).group(1))
    assert len(pcs) == 1


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


# ---------------------------------------------------------------- relay-fee router + executor (T15)
EXEC_PREFIX = open(os.path.join(OUT, 'Executor.prefix.bin'), 'rb').read()
EXEC_SUFFIX = open(os.path.join(OUT, 'Executor.suffix.bin'), 'rb').read()


class Router(Deployed):
    def program(self):
        """The executor LogicSig of this router: the template around its app id (u64 big-endian)."""
        return EXEC_PREFIX + self.id.to_bytes(8, 'big') + EXEC_SUFFIX

    @property
    def lsig(self):
        return transaction.LogicSigAccount(self.program())

    @property
    def executor(self):
        return self.lsig.address()


def deploy_router(dispenser):
    """A router, funded with its 100,000 µALGO base minimum (an account below it cannot receive the MBR payment it
    forwards); stateless, so tests share one unless they fund its executor."""
    d = deploy(dispenser, 'RelayFee', [])
    r = Router(d.app, d.id)
    DEPLOYED[r.id] = r
    return r


@pytest.fixture(scope='session')
def router(dispenser):
    return deploy_router(dispenser)


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

    def mtx(self, relayer, method, o, auth, *extra_args, mbr='auto', budget=None,
            payee=None, extra_boxes=(), pay=None, accounts=(), fee_extra_=0):
        """A signer other than a native 64-byte wallet signature goes through `account.verify` (an inner call and,
        on a UA's first op, an inner MBR forward: 2 inner fees, the record box referenced on a budget call; budget
        UA_BUDGET). `mbr='auto'`: this token's `mbr_needed` + the account app's `verify_mbr` (0 when that refuses:
        the call then fails with the account app's message)."""
        via = o[3][0] != 0 or len(auth) != 64
        if budget is None:
            budget = UA_BUDGET if via else BUDGET
        if mbr == 'auto':
            rec = 0
            if via:
                v, _, fail, _ = sim(VIEWER, self.account, 'verify_mbr', [o[3][0], bytes(o[3][1]), digest(o), auth],
                                    extra_budget=20_000)
                rec = 0 if fail else v
            mbr = view(self, 'mbr_needed', o) + rec or None
        acc = ([encoding.encode_address(bytes(o[3][1]))] if o[3][0] == 0 else []) + list(accounts)
        boxes = self.boxes(o, payee) + list(extra_boxes)
        if via:
            boxes.append((self.account, self.account.name(o[3])))
        return run(relayer, self, method, [o, auth, *extra_args], mbr=mbr, budget=budget, boxes=boxes,
                   accounts=acc, pay=pay, apps=[self.account.id], fee_extra=(2 * MIN_FEE if via else 0) + fee_extra_)


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
def token(dispenser, make, account):
    """A fresh token (admin = the dispenser, `account` its account app), 1,000,000 minted to `alice` (the MBR of
    her balance box paid)."""
    return make_token(dispenser, make, account)


def make_token(dispenser, make, account):
    d = deploy(dispenser, 'Token', [NAME, SYMBOL, 6, dispenser.addr, account.id])
    t = Tok(d.app, d.id)
    t.account = account
    DEPLOYED[t.id] = t
    t.admin = dispenser
    t.alice = make(1_000_000)
    run(dispenser, t, 'mint', [t.alice.addr, 1_000_000], mbr=MBR_BALANCE, boxes=[b'b' + t.alice.key])
    return t


# ---------------------------------------------------------------- account app (T12)
KIND_ALGORAND_ADDRESS, KIND_P256, KIND_ED25519, KIND_SECP256K1, KIND_MSIG = 0x0018, 0x0100, 0x0102, 0x0108, 0x0120
ORIGIN, RP_ID = V.ORIGIN, V.RP_ID
HEADER = 118          # record header (account.py), then keys and origins, 32 B each
SLOT = 400 * 32       # MBR of one more key / origin in a record
ACC_BUDGET = 12       # bare budget calls per account entry (pooled 700 each; the payment + call + 12 ≤ 16)
KEYREC = '(uint16,byte[])'
POLICY_PASSKEY_FOR_VALUE = 1
RECOVERY_DELAY_S = 172_800


def u16(n):
    return n.to_bytes(2, 'big')


def rec_mbr(keys, origins=0):
    """MBR of a new record (name "s" ‖ kind ‖ id, 34 B)."""
    return box_mbr(34, HEADER + 32 * (keys + origins))


class Key:
    """A UA key: its kind, canonical key data, UA id; `auth(digest)` = the account app's tagged auth."""

    @property
    def id(self):
        return V.ua_of(self.kind, self.key_data)

    def ua(self):
        return (1, self.id)

    def record(self):
        return [self.kind, self.key_data]


class EdKey(Key):
    kind = KIND_ED25519

    def __init__(self, name):
        self.e = V.Ed(name)
        self.key_data = self.e.pk

    def auth(self, d):
        return b'\x01' + self.e.pk + self.e.sign(b'MX' + text(d))


class K1Key(Key):
    kind = KIND_SECP256K1

    def __init__(self, name):
        self.e = V.Ecdsa(name, V.SECP256K1)
        self.key_data = self.e.key

    def auth(self, d, high_s=False):
        sig, v = self.e.sign(d)
        if high_s:
            sig = V.high_s(sig, v, V.SECP256K1)[0]
        return b'\x02' + self.e.key + sig


CDJ = '{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}'


class PasskeyKey(Key):
    kind = KIND_P256

    def __init__(self, name, rp_id=RP_ID):
        self.e = V.Ecdsa(name, V.P256)
        self.rp = sha256(rp_id.encode())
        self.key_data = self.e.key + self.rp

    def auth(self, d, origin=ORIGIN, cdj=CDJ, flags=5, high_s=False, ad=None):
        """A WebAuthn assertion over challenge = b64url(d); `cdj` a template (challenge, origin) or bytes."""
        ad = self.rp + bytes([flags]) + bytes(4) if ad is None else ad
        cdj = (cdj % (V.b64url(d), origin)).encode() if isinstance(cdj, str) else cdj
        sig, v = self.e.sign(sha256(ad, sha256(cdj)))
        if high_s:
            sig = V.high_s(sig, v, V.P256)[0]
        return b'\x03' + self.e.key + sig + u16(len(ad)) + ad + cdj


class MsigKey(Key):
    """`msig` (kind 288) over `members` [(signer, weight)]: a `Key`, or an `Acct` (an algorand-address member)."""
    kind = KIND_MSIG

    def __init__(self, threshold, members):
        rows = [((KIND_ALGORAND_ADDRESS, m.key) if isinstance(m, Acct) else (m.kind, m.id)) + (w, m)
                for m, w in members]
        self.rows = sorted(rows, key=lambda r: r[1])
        self.key_data = u16(threshold) + u16(len(rows)) + b''.join(u16(k) + i + u16(w) for k, i, w, _ in self.rows)

    def index(self, m):
        return next(i for i, r in enumerate(self.rows) if r[3] is m)

    def auth(self, d, signers=None, sigs=None):
        """Each member in `signers` (default all) signs with its own key; `sigs` [(index, member auth)] overrides."""
        if sigs is None:
            sigs = [(i, sign_as(r[3], d)) for i, r in enumerate(self.rows) if signers is None or r[3] in signers]
        return (b'\x04' + u16(len(self.key_data)) + self.key_data
                + b''.join(bytes([i]) + u16(len(a)) + a for i, a in sigs))


def sign_as(signer, d):
    """A native `Acct` signs with its wallet key (64 B), a `Key` with its tagged auth."""
    return signer.sign_op(d) if isinstance(signer, Acct) else signer.auth(d)


def holder(x):
    return native(x) if isinstance(x, Acct) else x.ua() if isinstance(x, Key) else tuple(x)


def abi_enc(t, v):
    return abi.ABIType.from_string(t).encode(v)


def key_params(method, args):
    """The ARC-4 encoding of a key op's parameters (its `extra` = sha256 of this)."""
    if method in ('mtx_add_key', 'mtx_start_recovery'):
        return abi_enc('(%s,byte[])' % KEYREC, args)
    if method == 'mtx_remove_key':
        return abi_enc('(%s)' % KEYREC, args)
    if method in ('mtx_add_origin', 'mtx_remove_origin'):
        return abi_enc('(byte[])', args)
    if method == 'mtx_set_guardian':
        return bytes([args[0][0]]) + bytes(args[0][1])
    if method == 'mtx_set_policy':
        return bytes([6, args[0]])
    return b'\x07' if method == 'mtx_finish_recovery' else b''


KEY_CODES = {'mtx_add_key': 6, 'mtx_remove_key': 7, 'mtx_add_origin': 8, 'mtx_remove_origin': 9,
             'mtx_set_guardian': 10, 'mtx_set_policy': 10, 'mtx_start_recovery': 11, 'mtx_finish_recovery': 11,
             'mtx_cancel_recovery': 12}
NONE_HOLDER = [0, Z32]


def parse_record(v):
    nk, no = v[116], v[117]
    keys = [v[118 + 32 * i:150 + 32 * i] for i in range(nk)]
    at = 118 + 32 * nk
    return {'nonce': int.from_bytes(v[:8], 'big'), 'policy': v[8], 'n_pk': v[9], 'guardian': (v[10], v[11:43]),
            'ready_at': int.from_bytes(v[43:51], 'big'), 'recovery_key': v[51:83], 'recovery_pk': v[83],
            'recovery_origin': v[84:116], 'keys': keys, 'origins': [v[at + 32 * i:at + 32 + 32 * i] for i in range(no)],
            'length': len(v)}


class Acc(Deployed):
    def name(self, h):
        h = holder(h)
        return b's' + bytes([h[0]]) + bytes(h[1])

    def record(self, h):
        try:
            return parse_record(base64.b64decode(ALGOD.application_box_by_name(self.id, self.name(h))['value']))
        except AlgodHTTPError:
            return None

    def op(self, code, frm, to=None, params=b'', nonce=0, relayer=Z32, valid_until=FAR, network=None, contract=None,
           extra=None, amount=0, pay_ref=Z32, lane=Z32):
        frm = holder(frm)
        return [network or genesis(), contract or self.key, code, list(frm), list(holder(to) if to else frm), relayer,
                amount, pay_ref, lane, nonce, valid_until, sha256(params) if extra is None else extra]

    def call(self, relayer, method, o, auth, *args, mbr=None, budget=ACC_BUDGET, boxes=(), accounts=None, pay=None,
             fee_extra=0):
        names = list(dict.fromkeys([self.name(o[3]), self.name(o[4])] + list(boxes)))
        acc = [encoding.encode_address(bytes(h[1])) for h in (o[3], o[4]) if h[0] == 0] if accounts is None else accounts
        return run(relayer, self, method, [o, auth, *args], mbr=mbr, budget=budget, boxes=names,
                   accounts=list(dict.fromkeys(acc)) or None, pay=pay, fee_extra=fee_extra)

    def key_op(self, relayer, method, signer, args=(), nonce=0, frm=None, to=None, sign=None, op_kw=None, **kw):
        """`signer` signs `method`'s op for subject `frm` (default: the signer's own holder), `relayer` submits."""
        o = self.op(KEY_CODES[method], frm if frm is not None else holder(signer), to, key_params(method, list(args)),
                    nonce, **(op_kw or {}))
        auth = (sign or (lambda d: sign_as(signer, d)))(digest(o))
        return self.call(relayer, method, o, auth, *args, **kw)


@pytest.fixture
def account(dispenser):
    """A fresh account app (deployed first: the token's `account_app` is fixed at its creation, ruling (a))."""
    d = deploy(dispenser, 'Account', [])
    a = Acc(d.app, d.id)
    DEPLOYED[a.id] = a
    return a


def advance(seconds):
    """DevMode: the next block's timestamp is the last one's + `seconds` (algod's offset is per block), then the
    offset is cleared (later blocks: max(last, wall clock)); Global.latest_timestamp is the last block's."""
    ALGOD.set_timestamp_offset(seconds)
    try:
        wait(ALGOD.send_transaction(transaction.PaymentTxn(VIEWER.addr, sp(), VIEWER.addr, 0, note=os.urandom(8))
                                    .sign(VIEWER.sk)))
    finally:
        ALGOD.set_timestamp_offset(0)
