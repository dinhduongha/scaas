"""Account app on localnet (near-algorand T12; spec §4.1, §4.3, §4.6; NET-ALL-04, CTR-ACC-03; R7, R8, R11; parity with
the NEAR account of Task 5: smartcontracts/near/integration/tests/account.rs)."""
import base64
import json
import os
import re

import pytest
from algosdk import abi, encoding, transaction
from algosdk.atomic_transaction_composer import LogicSigTransactionSigner, MultisigTransactionSigner

from conftest import (ACC_BUDGET, ALGOD, CDJ, KEYREC, MBR_BALANCE, MBR_LANE, MBR_UA, MIN_FEE, NONE_HOLDER, ORIGIN,
                      POLICY_PASSKEY_FOR_VALUE, RECOVERY_DELAY_S, ROOT, SLOT, Z32, EdKey, K1Key, MsigKey, PasskeyKey,
                      Refused, V, advance, digest, latest_ts, make_token, native, rec_mbr, refused_actions, run,
                      sha256, sign_as, sim, sp, u16, view, wait)

ZERO_ADDR = encoding.encode_address(Z32)
VEC = json.load(open(os.path.join(ROOT, 'vectors', 'algorand-vectors.json')))
MSIG_MAX_MEMBERS = 2         # account.py; measured by test_msig_cap_fits_limits
GROUP_POOL = 15 * 700        # one 16-transaction group: the MBR payment + 15 app calls
# Opcode budget per signer kind (simulate, pooled), pinned in runs/2026-10-28-algorand-limits.txt
BUDGET_PIN = {
    'account mtx_set_guardian native': 2900, 'account mtx_set_guardian ed25519': 3100,
    'account mtx_set_guardian secp256k1': 2600, 'account mtx_set_guardian passkey': 3900,
    'account mtx_set_guardian msig 2 ed25519': 6400, 'account mtx_set_guardian msig %d passkey' % MSIG_MAX_MEMBERS: 8000,
    'token mtx_pay native': 3100, 'token mtx_pay ed25519 UA': 3700, 'token mtx_pay secp256k1 UA': 3100,
    'token mtx_pay passkey UA': 4500, 'token mtx_pay msig %d passkey UA' % MSIG_MAX_MEMBERS: 8500,
}


def no(*msgs):
    return pytest.raises(Refused, match='.*'.join(re.escape(m) for m in msgs))


def events(d, res):
    out = []
    for log in res.logs:
        e = d.app.events.get(log[:4])
        if e:
            out.append((e[0], e[1].decode(log[4:])))
    return out


@pytest.fixture
def relayer(make):
    return make(100_000_000)


def guardian_of(account, h):
    g = account.record(h)['guardian']
    return (g[0], bytes(g[1]))


# ---------------------------------------------------------------- opening, kinds (plan Step 1)
def test_ua_opened_lazily_relayer_pays_mbr(account, relayer):
    erin, k2 = EdKey('erin'), EdKey('erin-2')
    h = erin.ua()
    assert account.record(h) is None and view(account, 'key_nonce', *h) == 0
    need = rec_mbr(2)                                       # opened with erin's key, then k2 added
    for m in (None, need - 1, need + 1):
        with no('MBR payment must equal'):
            account.key_op(relayer, 'mtx_add_key', erin, [k2.record(), b''], mbr=m)
    before = account.min_balance()
    r = account.key_op(relayer, 'mtx_add_key', erin, [k2.record(), b''], mbr=need)
    print('\nUA record (ed25519, 2 keys): %d B, MBR %d µALGO; one more key or origin %d µALGO'
          % (account.record(h)['length'], need, SLOT))
    assert account.min_balance() - before == need          # the app's AcctMinBalance delta, paid exactly
    rec = account.record(h)
    assert (rec['keys'], rec['nonce'], rec['length']) == ([erin.id, k2.id], 1, 118 + 64)
    assert events(account, r) == [('KeyOp', [[1, list(erin.id)], 'add_key'])]
    assert view(account, 'key_nonce', *h) == 1
    with no('wrong key nonce'):                             # replay
        account.key_op(relayer, 'mtx_add_key', erin, [k2.record(), b''])
    account.key_op(relayer, 'mtx_remove_key', erin, [k2.record()], nonce=1)      # shrinks: no payment, no refund
    assert account.record(h)['keys'] == [erin.id] and account.min_balance() == before + need - SLOT
    account.key_op(relayer, 'mtx_add_key', erin, [k2.record(), b''], nonce=2, mbr=SLOT)   # pays the slot again
    account.key_op(relayer, 'mtx_set_guardian', k2, [NONE_HOLDER], nonce=3, frm=h)  # k2 signs through the record
    account.key_op(relayer, 'mtx_remove_key', erin, [erin.record()], nonce=4)       # the id-deriving key removed
    with no('the last key cannot be removed'):
        account.key_op(relayer, 'mtx_remove_key', k2, [k2.record()], nonce=5, frm=h)
    with no('unknown key'):
        account.key_op(relayer, 'mtx_remove_key', k2, [erin.record()], nonce=5, frm=h)
    with no('not a key of the subject'):                    # erin's own key no longer signs
        account.key_op(relayer, 'mtx_set_guardian', erin, [NONE_HOLDER], nonce=5)


def test_each_kind_accepted(account, relayer, make):
    bob = make()
    for name, k in (('ed25519', EdKey('erin')), ('secp256k1', K1Key('carol')), ('passkey', PasskeyKey('dave'))):
        h, origins = k.ua(), int(name == 'passkey')
        account.key_op(relayer, 'mtx_set_guardian', k, [list(native(bob))], mbr=rec_mbr(1, origins))
        rec = account.record(h)
        assert (rec['keys'], guardian_of(account, h), rec['nonce']) == ([k.id], native(bob), 1), name
        assert rec['origins'] == ([sha256(ORIGIN.encode())] if origins else []), name
        account.key_op(relayer, 'mtx_set_guardian', k, [NONE_HOLDER], nonce=1)       # the stored record's path
        assert guardian_of(account, h) == (0, Z32)
    # a native address with its wallet key (its current authority), no record before: one is opened
    alice = make()
    account.key_op(relayer, 'mtx_set_guardian', alice, [list(native(bob))], mbr=rec_mbr(0))
    assert account.record(native(alice))['keys'] == [] and view(account, 'key_nonce', 0, alice.key) == 1
    # the passkey vector: a software authenticator's real assertion (webauthn_soft.json), checked by `verify`
    w = VEC['passkey']['webauthnSoft']
    unhx = lambda x: bytes.fromhex(x[2:])  # noqa: E731
    ad, cdj = unhx(w['authenticatorData']), w['clientDataJSON'].encode()
    auth = b'\x03' + unhx(w['key']) + unhx(w['sig']) + u16(len(ad)) + ad + cdj
    uid = V.ua_of(0x0100, unhx(w['key']) + unhx(w['rpIdHash']))
    need = view(account, 'verify_mbr', 1, uid, unhx(w['challenge']), auth)
    assert need == rec_mbr(1, 1)
    r = run(relayer, account, 'verify', [1, uid, unhx(w['challenge']), auth], mbr=need, budget=ACC_BUDGET,
            boxes=[account.name((1, uid))])
    assert r.ret is True and account.record((1, uid))['origins'] == [sha256(w['origin'].encode())]
    assert view(account, 'verify_mbr', 1, uid, unhx(w['challenge']), auth) == 0


def test_high_s_refused(account, relayer):
    carol, dave = K1Key('carol'), PasskeyKey('dave')
    with no('secp256k1 signature (low s)'):
        account.key_op(relayer, 'mtx_set_guardian', carol, [NONE_HOLDER], mbr=rec_mbr(1),
                       sign=lambda d: carol.auth(d, high_s=True))
    account.key_op(relayer, 'mtx_set_guardian', carol, [NONE_HOLDER], mbr=rec_mbr(1))
    with no('passkey signature high s'):
        account.key_op(relayer, 'mtx_set_guardian', dave, [NONE_HOLDER], mbr=rec_mbr(1, 1),
                       sign=lambda d: dave.auth(d, high_s=True))
    account.key_op(relayer, 'mtx_set_guardian', dave, [NONE_HOLDER], mbr=rec_mbr(1, 1))
    with no('secp256k1 signature'):                          # a signature over another digest
        account.key_op(relayer, 'mtx_set_guardian', carol, [NONE_HOLDER], nonce=1, sign=lambda d: carol.auth(sha256(d)))
    erin = EdKey('erin')
    with no('ed25519 signature'):
        account.key_op(relayer, 'mtx_set_guardian', erin, [NONE_HOLDER], mbr=rec_mbr(1),
                       sign=lambda d: erin.auth(sha256(d)))


def test_ninth_key_refused(account, relayer, make):
    alice = make(2_000_000)
    keys = [EdKey('alice-%d' % i) for i in range(9)]
    for i, k in enumerate(keys[:8]):
        run(alice, account, 'add_key_native', [k.record(), b''], mbr=rec_mbr(1) if i == 0 else SLOT,
            boxes=[account.name(native(alice))])
    with no('MAX_KEYS (8) reached'):
        run(alice, account, 'add_key_native', [keys[8].record(), b''], mbr=SLOT, boxes=[account.name(native(alice))])
    with no('MAX_KEYS (8) reached'):
        account.key_op(relayer, 'mtx_add_key', keys[0], [keys[8].record(), b''], frm=native(alice), mbr=SLOT)
    with no('key already present'):
        run(alice, account, 'add_key_native', [keys[3].record(), b''], boxes=[account.name(native(alice))])
    assert account.record(native(alice))['keys'] == [k.id for k in keys[:8]]
    # a native holder's registered key signs as the address (relayed)
    account.key_op(relayer, 'mtx_set_guardian', keys[7], [list(native(make()))], frm=native(alice))


def test_add_key_native_sender_is_the_address(account, relayer, make):
    alice, k = make(1_000_000), EdKey('k')
    run(alice, account, 'add_key_native', [k.record(), ORIGIN.encode()], mbr=rec_mbr(1, 1),
        boxes=[account.name(native(alice))], pay={'payer': relayer})        # the relayer pays the MBR
    rec = account.record(native(alice))
    assert rec['keys'] == [k.id] and rec['origins'] == [sha256(ORIGIN.encode())] and rec['nonce'] == 0
    assert account.record(native(relayer)) is None
    with no('key data'):
        run(alice, account, 'add_key_native', [[0x0102, b'\x01' * 31], b''], boxes=[account.name(native(alice))])
    with no('key kind not accepted'):
        run(alice, account, 'add_key_native', [[0x0018, alice.key], b''], boxes=[account.name(native(alice))])
    with no('origin length'):
        run(alice, account, 'add_key_native', [EdKey('k2').record(), b'x' * 129], mbr=SLOT,
            boxes=[account.name(native(alice))])


# ---------------------------------------------------------------- passkeys (NET-ALL-04)
def test_origin_and_rp_checked(account, relayer):
    dave = PasskeyKey('dave')
    h, other = dave.ua(), 'https://app.scaas.test'
    n = [0]

    def op(method, args, mbr=None, **kw):
        r = account.key_op(relayer, method, dave, args, nonce=n[0], mbr=mbr, **kw)
        n[0] += 1
        return r
    op('mtx_set_guardian', [NONE_HOLDER], mbr=rec_mbr(1, 1))                         # opened at ORIGIN
    with no('passkey origin not listed'):
        op('mtx_set_guardian', [NONE_HOLDER], sign=lambda d: dave.auth(d, origin=other))
    op('mtx_add_origin', [other.encode()], mbr=SLOT)
    op('mtx_set_guardian', [NONE_HOLDER], sign=lambda d: dave.auth(d, origin=other))
    assert account.record(h)['origins'] == [sha256(ORIGIN.encode()), sha256(other.encode())]
    op('mtx_add_origin', [other.encode()])                                           # idempotent: no growth
    # the same key under another rpId is another key: not this subject's, and it does not derive this id
    evil = PasskeyKey('dave', 'evil.test')
    with no('not a key of the subject'):
        op('mtx_set_guardian', [NONE_HOLDER], sign=evil.auth)
    fresh = PasskeyKey('dave-5')
    with no('the key does not derive the UA id'):
        account.key_op(relayer, 'mtx_set_guardian', PasskeyKey('dave-5', 'evil.test'), [NONE_HOLDER],
                       frm=fresh.ua(), mbr=rec_mbr(1, 1))
    # the assertion's grammar and flags; every case is refused, nothing is written
    bad = {
        'UP only': dict(flags=1), 'UV only': dict(flags=4), 'short authData': dict(ad=dave.rp + b'\x05'),
        'crossOrigin true': dict(cdj='{"type":"webauthn.get","challenge":"%s","origin":"%s","crossOrigin":true}'),
        'topOrigin': dict(cdj=CDJ[:-1] + ',"topOrigin":"https://evil.test"}'),
        'second crossOrigin': dict(cdj=CDJ[:-1] + ',"crossOrigin":true}'),
        'member before crossOrigin': dict(cdj='{"type":"webauthn.get","challenge":"%s","origin":"%s","x":1,'
                                              '"crossOrigin":false}'),
        'whitespace': dict(cdj='{"type": "webauthn.get","challenge":"%s","origin":"%s","crossOrigin":false}'),
        'no closing brace': dict(cdj=CDJ[:-1]),
        'no closing brace after a member': dict(cdj=CDJ[:-1] + ',"other":"x"'),
        'type create': dict(cdj='{"type":"webauthn.create","challenge":"%s","origin":"%s","crossOrigin":false}'),
        'type of the same length': dict(cdj='{"type":"webauthn.got","challenge":"%s","origin":"%s","crossOrigin":false}'),
        'origin extended': dict(origin=ORIGIN + '.evil'),
        'origin prefix': dict(origin=ORIGIN[:-1]),
        'empty origin': dict(origin=''),
        'backslash in origin': dict(cdj='{"type":"webauthn.get","challenge":"%s","origin":"%s\\\\","crossOrigin":false}'),
        'challenge of another digest': None,
    }
    for case, kw in bad.items():
        sign = (lambda d, kw=kw: dave.auth(d, **kw)) if kw else (lambda d: dave.auth(sha256(d)))
        with pytest.raises(Refused, match='passkey') as e:
            account.key_op(relayer, 'mtx_set_guardian', dave, [NONE_HOLDER], nonce=n[0], sign=sign)
        print('%-32s refused: %s' % (case, str(e.value).split(' :: ')[0]))
    # accepted shapes: no crossOrigin, and a trailing member after crossOrigin:false (Chrome's random member)
    with no('passkey clientDataJSON'):                      # a lazy open takes no origin with a backslash
        fresh = PasskeyKey('dave-6')
        account.key_op(relayer, 'mtx_set_guardian', fresh, [NONE_HOLDER], mbr=rec_mbr(1, 1),
                       sign=lambda d: fresh.auth(d, origin=ORIGIN + '\\\\'))
    op('mtx_set_guardian', [NONE_HOLDER], sign=lambda d: dave.auth(
        d, cdj='{"type":"webauthn.get","challenge":"%s","origin":"%s"}'))
    chrome = CDJ[:-1] + (',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. '
                         'See https://goo.gl/yabPex"}')
    op('mtx_set_guardian', [NONE_HOLDER], sign=lambda d: dave.auth(d, cdj=chrome))
    # PASSKEY_FIELD_MAX: a 1,024-byte clientDataJSON verifies, 1,025 is refused
    for size, ok in ((1024, True), (1025, False)):
        def fat(d, size=size):
            base = (CDJ[:-1] % (V.b64url(d), ORIGIN)) + ',"pad":"'
            return dave.auth(d, cdj=(base + 'x' * (size - len(base) - 2) + '"}').encode())
        if ok:
            op('mtx_set_guardian', [NONE_HOLDER], sign=fat)
        else:
            with no('over 1024 bytes'):
                account.key_op(relayer, 'mtx_set_guardian', dave, [NONE_HOLDER], nonce=n[0], sign=fat)
    # removing the last origin of a passkey subject is refused
    op('mtx_remove_origin', [ORIGIN.encode()], sign=lambda d: dave.auth(d, origin=other))
    with no('a passkey needs an origin'):
        op('mtx_remove_origin', [other.encode()], sign=lambda d: dave.auth(d, origin=other))
    with no('unknown origin'):
        op('mtx_remove_origin', [ORIGIN.encode()], sign=lambda d: dave.auth(d, origin=other))


def test_origin_cap(account, relayer):
    erin = EdKey('erin')
    for i in range(8):
        account.key_op(relayer, 'mtx_add_origin', erin, [b'https://o%d.test' % i], nonce=i,
                       mbr=rec_mbr(1, 1) if i == 0 else SLOT)
    with no('MAX_ORIGINS (8) reached'):
        account.key_op(relayer, 'mtx_add_origin', erin, [b'https://o8.test'], nonce=8, mbr=SLOT)
    assert len(account.record(erin.ua())['origins']) == 8


# ---------------------------------------------------------------- recovery (CTR-ACC-03)
def recovery_setup(account, relayer):
    """`erin` (key nonce 1) with guardian `g` (a UA); `g` starts a recovery adding `frank` (a stranger cannot)."""
    erin, g, frank, mallory = EdKey('erin'), EdKey('guardian'), EdKey('frank'), EdKey('mallory')
    account.key_op(relayer, 'mtx_set_guardian', erin, [list(g.ua())], mbr=rec_mbr(1))
    with no("not the subject's guardian"):
        account.key_op(relayer, 'mtx_start_recovery', mallory, [frank.record(), b''], to=erin.ua(), mbr=rec_mbr(1))
    with no('a subject is not its own guardian'):
        account.key_op(relayer, 'mtx_start_recovery', erin, [frank.record(), b''], nonce=1)
    account.key_op(relayer, 'mtx_start_recovery', g, [frank.record(), b''], to=erin.ua(), mbr=rec_mbr(1))
    return erin, g, frank, mallory


def test_recovery_after_delay_only(account, relayer):
    erin, g, frank, mallory = recovery_setup(account, relayer)
    h = erin.ua()
    rec = account.record(h)
    now = latest_ts()
    assert rec['recovery_key'] == frank.id and now + RECOVERY_DELAY_S - 30 < rec['ready_at'] <= now + RECOVERY_DELAY_S
    with no('recovery delay (172,800 s) not over'):
        account.key_op(relayer, 'mtx_finish_recovery', g, nonce=1, to=h)
    advance(rec['ready_at'] - 60 - latest_ts())                                       # a minute early
    with no('recovery delay (172,800 s) not over'):
        account.key_op(relayer, 'mtx_finish_recovery', g, nonce=1, to=h)
    advance(120)
    with no("not the subject's guardian"):
        account.key_op(relayer, 'mtx_finish_recovery', mallory, to=h, mbr=rec_mbr(1))
    account.key_op(relayer, 'mtx_finish_recovery', g, nonce=1, to=h, mbr=SLOT)
    rec = account.record(h)                                     # CTR-ACC-03: the key is added, none removed
    assert (rec['keys'], rec['ready_at'], rec['nonce']) == ([erin.id, frank.id], 0, 2)
    with no('no recovery pending'):
        account.key_op(relayer, 'mtx_finish_recovery', g, nonce=2, to=h)
    account.key_op(relayer, 'mtx_set_guardian', erin, [list(g.ua())], nonce=2)
    account.key_op(relayer, 'mtx_set_guardian', frank, [list(g.ua())], nonce=3, frm=h)
    # fail fast: a key already present, or a full set, is refused at start and at finish
    with no('key already present'):
        account.key_op(relayer, 'mtx_start_recovery', g, [erin.record(), b''], nonce=2, to=h)
    more = [EdKey('erin-%d' % i) for i in range(6)]
    for i, k in enumerate(more[:5]):
        account.key_op(relayer, 'mtx_add_key', erin, [k.record(), b''], nonce=4 + i, mbr=SLOT)
    account.key_op(relayer, 'mtx_start_recovery', g, [more[5].record(), b''], nonce=2, to=h)     # 7 keys: a slot
    account.key_op(relayer, 'mtx_add_key', erin, [EdKey('erin-x').record(), b''], nonce=9, mbr=SLOT)  # now 8
    advance(RECOVERY_DELAY_S + 60)
    with no('MAX_KEYS (8) reached'):
        account.key_op(relayer, 'mtx_finish_recovery', g, nonce=3, to=h, mbr=SLOT)
    with no('MAX_KEYS (8) reached'):
        account.key_op(relayer, 'mtx_start_recovery', g, [EdKey('y').record(), b''], nonce=3, to=h)


def test_recovery_of_a_passkey_with_its_origin(account, relayer, make):
    """A native guardian (wallet signature) recovers a UA with a passkey key and its origin."""
    erin, dave, alice = EdKey('erin'), PasskeyKey('dave'), make()
    account.key_op(relayer, 'mtx_set_guardian', erin, [list(native(alice))], mbr=rec_mbr(1))
    with no('a passkey needs an origin'):
        account.key_op(relayer, 'mtx_start_recovery', alice, [dave.record(), b''], to=erin.ua(), mbr=rec_mbr(0))
    account.key_op(relayer, 'mtx_start_recovery', alice, [dave.record(), ORIGIN.encode()], to=erin.ua(),
                   mbr=rec_mbr(0))
    advance(RECOVERY_DELAY_S + 60)
    account.key_op(relayer, 'mtx_finish_recovery', alice, nonce=1, to=erin.ua(), mbr=2 * SLOT)
    rec = account.record(erin.ua())
    assert rec['keys'] == [erin.id, dave.id] and rec['origins'] == [sha256(ORIGIN.encode())] and rec['n_pk'] == 1
    account.key_op(relayer, 'mtx_set_guardian', dave, [NONE_HOLDER], nonce=2, frm=erin.ua())


def test_cancel_recovery_and_guardian_ops(account, relayer):
    erin, g, frank, _ = recovery_setup(account, relayer)
    h = erin.ua()
    nobody = EdKey('nobody')                                # no guardian: the zero holder (none) recovers nothing
    account.key_op(relayer, 'mtx_set_guardian', nobody, [NONE_HOLDER], mbr=rec_mbr(1))
    with no('no guardian'):
        account.key_op(relayer, 'mtx_start_recovery', nobody, [frank.record(), b''], frm=NONE_HOLDER, to=nobody.ua(),
                       sign=lambda d: bytes(64))
    account.key_op(relayer, 'mtx_cancel_recovery', erin, nonce=1)          # any current key cancels in the delay
    assert account.record(h)['ready_at'] == 0
    advance(RECOVERY_DELAY_S + 60)
    with no('no recovery pending'):
        account.key_op(relayer, 'mtx_finish_recovery', g, nonce=1, to=h)
    with no('no recovery pending'):
        account.key_op(relayer, 'mtx_cancel_recovery', erin, nonce=2)
    account.key_op(relayer, 'mtx_start_recovery', g, [frank.record(), b''], nonce=1, to=h)
    assert account.record(h)['ready_at'] != 0
    account.key_op(relayer, 'mtx_set_guardian', erin, [list(g.ua())], nonce=2)    # set_guardian cancels it
    assert account.record(h)['ready_at'] == 0
    with no('a subject is not its own guardian'):
        account.key_op(relayer, 'mtx_set_guardian', erin, [list(h)], nonce=3)
    with no('unknown holder kind'):
        account.key_op(relayer, 'mtx_set_guardian', erin, [[2, Z32]], nonce=3)


# ---------------------------------------------------------------- msig (kind 288)
def test_msig_native_member_by_current_authority(account, relayer, make):
    bob, carol, erin = make(1_000_000), make(), EdKey('erin')
    m = MsigKey(2, [(bob, 1), (erin, 1)])
    ib, ie = m.index(bob), m.index(erin)
    acc = [bob.addr]

    def setg(nonce, auth, mbr=None):
        return account.key_op(relayer, 'mtx_set_guardian', m, [NONE_HOLDER], nonce=nonce, sign=auth, mbr=mbr,
                              accounts=acc)
    with no('msig threshold not met'):
        setg(0, lambda d: m.auth(d, signers=[erin]), rec_mbr(1))
    setg(0, m.auth, rec_mbr(1))                                         # bob's own key: his current authority
    wait(ALGOD.send_transaction(transaction.PaymentTxn(bob.addr, sp(), bob.addr, 0, rekey_to=carol.addr)
                                .sign(bob.sk)))
    with no('msig member signature'):                                   # rekeyed: his old key no longer counts
        setg(1, m.auth)
    setg(1, lambda d: m.auth(d, sigs=sorted([(ib, carol.sign_op(d)), (ie, erin.auth(d))])))
    assert account.record(m.ua())['nonce'] == 2


def test_msig_rules(account, relayer):
    erin, frank, gina = EdKey('erin'), EdKey('frank'), EdKey('gina')
    m = MsigKey(2, [(erin, 1), (frank, 1)])
    by = {0: m.rows[0][3], 1: m.rows[1][3]}
    cases = [
        ('not in member order', lambda d: [(1, by[1].auth(d)), (0, by[0].auth(d))]),
        ('not in member order', lambda d: [(0, by[0].auth(d)), (0, by[0].auth(d))]),
        ('msig member index', lambda d: [(0, by[0].auth(d)), (2, gina.auth(d))]),
        ('msig member key mismatch', lambda d: [(0, by[0].auth(d)), (1, gina.auth(d))]),
        ('msig inside msig', lambda d: [(0, by[0].auth(d)), (1, m.auth(d))]),
    ]
    for msg, sigs in cases:
        with no(msg):
            account.key_op(relayer, 'mtx_set_guardian', m, [NONE_HOLDER], mbr=rec_mbr(1),
                           sign=lambda d, sigs=sigs: m.auth(d, sigs=sigs(d)))
    account.key_op(relayer, 'mtx_set_guardian', m, [NONE_HOLDER], mbr=rec_mbr(1))
    kd = m.key_data
    for msg, bad in (('msig member count out of range', u16(1) + u16(MSIG_MAX_MEMBERS + 1)
                      + b''.join(u16(0x0102) + bytes([0x10 + i]) * 32 + u16(1) for i in range(MSIG_MAX_MEMBERS + 1))),
                     ('msig key data length', kd + b'\x00'),
                     ('msig threshold out of range', u16(3) + kd[2:]),
                     ('msig members not strictly increasing', kd[:4] + kd[40:76] + kd[4:40]),
                     ('msig member weight 0', kd[:38] + u16(0) + kd[40:]),
                     ('msig member kind not accepted', kd[:4] + u16(0x0017) + kd[6:])):
        with no(msg):
            account.key_op(relayer, 'mtx_add_key', erin, [[0x0120, bad], b''], mbr=rec_mbr(2))


def test_msig_cap_fits_limits(account, relayer):
    """MSIG_MAX_MEMBERS = the largest all-passkey n-of-n msig whose lazily opening `mtx_add_key` (every member signs)
    fits the 2,048 B app-call arguments and one group's pooled budget (the MBR payment + the call + 14 budget
    calls); one member more fits neither the budget (measured increment per member) nor the cap."""
    method = account.app.methods['mtx_add_key']
    used = {}
    for n in (MSIG_MAX_MEMBERS - 1, MSIG_MAX_MEMBERS):
        m = MsigKey(n, [(PasskeyKey('cap-%d-%d' % (n, i)), 1) for i in range(n)])
        new = EdKey('cap-new-%d' % n)
        o = account.op(6, m.ua(), params=abi.ABIType.from_string('(%s,byte[])' % KEYREC).encode([new.record(), b'']))
        auth = m.auth(digest(o))
        args = 4 + sum(len(t.encode(v)) for t, v in zip([a.type for a in method.args],
                                                         [o, auth, new.record(), b'']))
        _, budget, fail, _ = sim(relayer, account, 'mtx_add_key', [o, auth, new.record(), b''], mbr=rec_mbr(2, 1),
                                 budget=14, boxes=[account.name(m.ua())])
        assert fail is None, fail
        used[n] = (budget, args)
        assert args <= 2048 and budget <= GROUP_POOL, (n, args, budget)
        if n == MSIG_MAX_MEMBERS:
            r = account.call(relayer, 'mtx_add_key', o, auth, new.record(), b'', mbr=rec_mbr(2, 1), budget=14)
            assert account.record(m.ua())['keys'] == [m.id, new.id]
    per = used[MSIG_MAX_MEMBERS][0] - used[MSIG_MAX_MEMBERS - 1][0]
    nxt = used[MSIG_MAX_MEMBERS][0] + per
    print('\nmsig mtx_add_key all-passkey n-of-n: %s (budget, args); +1 member ≈ %d budget > pool %d or args'
          % (used, nxt, GROUP_POOL))
    assert nxt > GROUP_POOL or used[MSIG_MAX_MEMBERS][1] + (used[MSIG_MAX_MEMBERS][1] - used[MSIG_MAX_MEMBERS - 1][1]) > 2048


# ---------------------------------------------------------------- figures (§4.6: measured per kind, pinned)
def test_budget_per_kind_pinned(account, token, make, relayer):
    bob = make()
    out = {}
    kp = MsigKey(MSIG_MAX_MEMBERS, [(PasskeyKey('pin-%d' % i), 1) for i in range(MSIG_MAX_MEMBERS)])
    signers = {'native': make(), 'ed25519': EdKey('pin-ed'), 'secp256k1': K1Key('pin-k1'),
               'passkey': PasskeyKey('pin-pk'), 'msig 2 ed25519': MsigKey(2, [(EdKey('pin-m1'), 1), (EdKey('pin-m2'), 1)]),
               'msig %d passkey' % MSIG_MAX_MEMBERS: kp}
    for name, k in signers.items():
        pk = name == 'passkey' or name.endswith('passkey')
        account.key_op(relayer, 'mtx_set_guardian', k, [NONE_HOLDER], mbr=rec_mbr(0 if name == 'native' else 1, pk))
        h = native(k) if name == 'native' else k.ua()
        o = account.op(10, h, params=bytes([0]) + Z32, nonce=1)
        _, used, fail, _ = sim(relayer, account, 'mtx_set_guardian', [o, sign_as(k, digest(o)), NONE_HOLDER],
                               budget=14, boxes=[account.name(h)], accounts=[k.addr] if name == 'native' else None)
        assert fail is None, (name, fail)
        out['account mtx_set_guardian ' + name] = used
    for name in ('native', 'ed25519', 'secp256k1', 'passkey', 'msig %d passkey' % MSIG_MAX_MEMBERS):
        k = token.alice if name == 'native' else signers[name]
        frm = native(k) if name == 'native' else k.ua()
        if name != 'native':
            run(token.alice, token, 'transfer_to_ua', [k.id, 10], mbr=MBR_UA, boxes=[b'b' + token.alice.key, b'u' + k.id])
        o = token.op(frm if name != 'native' else k, native(bob), 1, pay_ref=b'\x51' * 32, lane=b'\x51' * 32)
        a = sign_as(k, digest(o))
        via = name != 'native'
        boxes = token.boxes(o) + ([(account, account.name(frm))] if via else [])
        need = view(token, 'mbr_needed', o) + (view(account, 'verify_mbr', frm[0], frm[1], digest(o), a) if via else 0)
        _, used, fail, _ = sim(relayer, token, 'mtx_pay', [o, a, ZERO_ADDR], mbr=need, budget=14, boxes=boxes,
                               apps=[account.id], accounts=[token.alice.addr] if not via else None,
                               fee_extra=2 * MIN_FEE)
        assert fail is None, (name, fail)
        out['token mtx_pay ' + name + ('' if name == 'native' else ' UA')] = used
    print('\nopcode budget per signer kind (simulate): %s\npins %s' % (out, BUDGET_PIN))
    for k, used in out.items():
        assert used <= BUDGET_PIN[k] <= GROUP_POOL + 700, (k, used)


# ---------------------------------------------------------------- the token's UA path
def test_token_ua_pay_via_account_verify(token, make, relayer):
    account, alice, bob, dave = token.account, token.alice, make(), PasskeyKey('dave')
    run(alice, token, 'transfer_to_ua', [dave.id, 100], mbr=MBR_UA, boxes=[b'b' + alice.key, b'u' + dave.id])
    pool = view(token, 'arc200_balanceOf', token.address)
    o = token.op(dave.ua(), native(bob), 30, pay_ref=b'\x61' * 32, lane=b'\x61' * 32)
    a = dave.auth(digest(o))
    own, rec = MBR_LANE + MBR_BALANCE, rec_mbr(1, 1)
    assert view(token, 'mbr_needed', o) == own and view(account, 'verify_mbr', 1, dave.id, digest(o), a) == rec
    for m in (None, own, own + rec - 1, own + rec + 1):
        with no('MBR payment must equal'):
            token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=m)
    with no('the key does not derive the UA id'):                               # another passkey's assertion
        token.mtx(relayer, 'mtx_pay', o, PasskeyKey('eve').auth(digest(o)), ZERO_ADDR, mbr=own + rec)
    bad = bytearray(a)
    bad[70] ^= 1                                                                # the signature's r
    with no('passkey signature'):
        token.mtx(relayer, 'mtx_pay', o, bytes(bad), ZERO_ADDR, mbr=own + rec)
    t0, a0 = token.min_balance(), account.min_balance()
    r = token.mtx(relayer, 'mtx_pay', o, a, ZERO_ADDR, mbr=own + rec)
    assert token.min_balance() - t0 == own and account.min_balance() - a0 == rec   # the record's MBR forwarded
    assert account.record(dave.ua())['keys'] == [dave.id]                           # opened lazily
    ev = events(token, r)
    assert [n for n, _ in ev] == ['MetaTransactionExecuted', 'arc200_Transfer', 'UaTransfer', 'PaymentSettled']
    assert ev[1][1] == [token.address, bob.addr, 30]                                # out of the UA pool
    assert view(token, 'ua_balance_of', dave.id) == 70 and view(token, 'arc200_balanceOf', bob.addr) == 30
    assert view(token, 'arc200_balanceOf', token.address) == pool - 30              # ua_total debited (T11 N4)
    # the record exists: no forward, only this token's lane box
    o = token.op(dave.ua(), native(bob), 5, pay_ref=b'\x62' * 32, lane=b'\x62' * 32)
    a0 = account.min_balance()
    token.mtx(relayer, 'mtx_pay', o, dave.auth(digest(o)), ZERO_ADDR, mbr=MBR_LANE)
    assert account.min_balance() == a0 and view(token, 'arc200_balanceOf', token.address) == pool - 35
    with no('wrong lane nonce'):                                                    # replay
        token.mtx(relayer, 'mtx_pay', o, dave.auth(digest(o)), ZERO_ADDR, mbr=None)
    # UA → UA keeps the pool; transfer and execute_transfer take the same path
    o = token.op(dave.ua(), (1, sha256(b'other ua')), 5, code=4, lane=b'\x63' * 32)
    token.mtx(relayer, 'mtx_transfer', o, dave.auth(digest(o)))
    assert view(token, 'arc200_balanceOf', token.address) == pool - 35


def test_token_takes_only_a_true_verify(token, dispenser, make, relayer, probe):
    """The token reads `verify`'s answer: an account app answering false (here the test-only probe) pays nothing."""
    t = make_token(dispenser, make, probe)
    erin = EdKey('erin')
    run(t.alice, t, 'transfer_to_ua', [erin.id, 5], mbr=MBR_UA, boxes=[b'b' + t.alice.key, b'u' + erin.id])
    o = t.op(erin.ua(), native(make()), 1, pay_ref=b'\x74' * 32, lane=b'\x74' * 32)
    probe.name = lambda h: b's'
    with no('bad signature'):
        t.mtx(relayer, 'mtx_pay', o, erin.auth(digest(o)), ZERO_ADDR, mbr=MBR_LANE + MBR_BALANCE)


def test_keys_shared_by_two_tokens(token, dispenser, make, relayer):
    account, erin, k2, bob = token.account, EdKey('erin'), EdKey('erin-2'), make()
    token2 = make_token(dispenser, make, account)
    for t in (token, token2):
        run(t.alice, t, 'transfer_to_ua', [erin.id, 50], mbr=MBR_UA, boxes=[b'b' + t.alice.key, b'u' + erin.id])
    account.key_op(relayer, 'mtx_add_key', erin, [k2.record(), b''], mbr=rec_mbr(2))   # one key op, both tokens
    for t in (token, token2):
        o = t.op(erin.ua(), native(bob), 7, pay_ref=b'\x71' * 32, lane=b'\x71' * 32)
        t.mtx(relayer, 'mtx_pay', o, k2.auth(digest(o)), ZERO_ADDR)                   # k2 does not derive erin's id
        assert view(t, 'arc200_balanceOf', bob.addr) == 7
    account.key_op(relayer, 'mtx_remove_key', erin, [k2.record()], nonce=1)            # removed: on both
    for t in (token, token2):
        o = t.op(erin.ua(), native(bob), 1, pay_ref=b'\x72' * 32, lane=b'\x72' * 32)
        with no('not a key of the subject'):
            t.mtx(relayer, 'mtx_pay', o, k2.auth(digest(o)), ZERO_ADDR)


def test_rekeyed_address_signs_through_account_record(token, make, relayer):
    """S:229-230: an address rekeyed to a LogicSig or a multisig has no ed25519 key; it adds a key itself
    (`add_key_native`, sent under its authority) and signs through that record."""
    account, alice, bob = token.account, token.alice, make()
    prog = base64.b64decode(ALGOD.compile('#pragma version 10\nint 1')['result'])
    lsig = transaction.LogicSigAccount(prog)
    wait(ALGOD.send_transaction(transaction.PaymentTxn(alice.addr, sp(), alice.addr, 0, rekey_to=lsig.address())
                                .sign(alice.sk)))
    k = EdKey('alice-record')
    run(alice, account, 'add_key_native', [k.record(), b''], mbr=rec_mbr(1), boxes=[account.name(native(alice))],
        pay={'payer': relayer}, signer=LogicSigTransactionSigner(lsig), budget_by=relayer)
    o = token.op(alice, native(bob), 3, pay_ref=b'\x81' * 32, lane=b'\x81' * 32)
    with no('bad signature'):                                       # her wallet key no longer signs
        token.mtx(relayer, 'mtx_pay', o, alice.sign_op(digest(o)), ZERO_ADDR)
    token.mtx(relayer, 'mtx_pay', o, k.auth(digest(o)), ZERO_ADDR)
    assert view(token, 'arc200_balanceOf', bob.addr) == 3
    # rekeyed to a 2-of-2 multisig
    dave, carol = make(1_000_000), make(1_000_000)
    run(token.admin, token, 'mint', [dave.addr, 10], mbr=MBR_BALANCE, boxes=[b'b' + dave.key])
    msig = transaction.Multisig(1, 2, [dave.addr, carol.addr])
    wait(ALGOD.send_transaction(transaction.PaymentTxn(dave.addr, sp(), dave.addr, 0, rekey_to=msig.address())
                                .sign(dave.sk)))
    k2 = EdKey('dave-record')
    run(dave, account, 'add_key_native', [k2.record(), b''], mbr=rec_mbr(1), boxes=[account.name(native(dave))],
        pay={'payer': relayer}, signer=MultisigTransactionSigner(msig, [dave.sk, carol.sk]), budget_by=relayer)
    o = token.op(dave, native(bob), 4, pay_ref=b'\x82' * 32, lane=b'\x82' * 32)
    token.mtx(relayer, 'mtx_pay', o, k2.auth(digest(o)), ZERO_ADDR)
    assert view(token, 'arc200_balanceOf', bob.addr) == 7
    with no('no SCaaS key'):                                         # a native address without a record
        o = token.op(bob, native(dave), 1, pay_ref=b'\x83' * 32, lane=b'\x83' * 32)
        token.mtx(relayer, 'mtx_pay', o, k.auth(digest(o)), ZERO_ADDR, mbr=MBR_LANE)


def test_policy_passkey_for_value(token, make, relayer):
    """R8: POLICY_PASSKEY_FOR_VALUE (set by the set_policy key-op action) binds the token's value entries."""
    account, erin, dave, bob = token.account, EdKey('erin'), PasskeyKey('dave'), make()
    h = erin.ua()
    run(token.alice, token, 'transfer_to_ua', [erin.id, 100], mbr=MBR_UA, boxes=[b'b' + token.alice.key, b'u' + erin.id])
    account.key_op(relayer, 'mtx_add_key', erin, [dave.record(), ORIGIN.encode()], mbr=rec_mbr(2, 1))
    account.key_op(relayer, 'mtx_set_policy', erin, [POLICY_PASSKEY_FOR_VALUE], nonce=1)   # a wallet-kind key may
    assert account.record(h)['policy'] == 1

    def pay(signer, lane, amount=1, **kw):
        o = token.op(h, native(bob), amount, pay_ref=lane, lane=lane)
        return token.mtx(relayer, 'mtx_pay', o, signer.auth(digest(o)), ZERO_ADDR, **kw)
    with no('POLICY_PASSKEY_FOR_VALUE'):
        pay(erin, b'\x91' * 32)
    pay(dave, b'\x92' * 32)
    o = token.op(h, native(bob), 1, code=4, lane=b'\x93' * 32)
    with no('POLICY_PASSKEY_FOR_VALUE'):
        token.mtx(relayer, 'mtx_transfer', o, erin.auth(digest(o)))
    account.key_op(relayer, 'mtx_set_guardian', erin, [list(native(bob))], nonce=2)     # key ops: any key
    with no('unknown policy bit'):
        account.key_op(relayer, 'mtx_set_policy', erin, [2], nonce=3)
    with no('extra is not sha256 of the parameters'):            # the policy is bound by extra
        account.key_op(relayer, 'mtx_set_policy', erin, [0], nonce=3, op_kw={'extra': sha256(bytes([6, 1]))})
    with no('extra is not sha256 of the parameters'):            # a set_policy op fed to set_guardian
        o = account.op(10, h, params=bytes([6, 0]), nonce=3)
        account.call(relayer, 'mtx_set_guardian', o, erin.auth(digest(o)), NONE_HOLDER)
    account.key_op(relayer, 'mtx_set_policy', erin, [0], nonce=3)
    pay(erin, b'\x94' * 32)
    assert view(token, 'arc200_balanceOf', bob.addr) == 2
    # choice: a native address's wallet signature is its own authority (as a direct ARC-200 transfer), outside the
    # policy, which binds the keys of its record
    alice, k = token.alice, EdKey('alice-key')
    run(alice, account, 'add_key_native', [k.record(), b''], mbr=rec_mbr(1), boxes=[account.name(native(alice))])
    account.key_op(relayer, 'mtx_set_policy', alice, [POLICY_PASSKEY_FOR_VALUE])
    o = token.op(alice, native(bob), 1, pay_ref=b'\x95' * 32, lane=b'\x95' * 32)
    with no('POLICY_PASSKEY_FOR_VALUE'):
        token.mtx(relayer, 'mtx_pay', o, k.auth(digest(o)), ZERO_ADDR)
    token.mtx(relayer, 'mtx_pay', o, alice.sign_op(digest(o)), ZERO_ADDR)
    assert view(token, 'arc200_balanceOf', bob.addr) == 3


# ---------------------------------------------------------------- envelope, authority
def test_key_op_envelope_refused(account, relayer, make):
    erin, other = EdKey('erin'), make(10_000_000)
    cases = [('wrong network', {'network': sha256(b'another genesis')}), ('wrong contract', {'contract': sha256(b'x')}),
             ('expired', {'valid_until': 1}), ('relayer is not the sender', {'relayer': other.key}),
             ('extra is not sha256', {'extra': Z32}), ('key op shape', {'amount': 1}),
             ('key op shape', {'pay_ref': b'\x01' * 32}), ('key op shape', {'lane': b'\x01' * 32})]
    for msg, kw in cases:
        with no(msg):
            account.key_op(relayer, 'mtx_set_guardian', erin, [NONE_HOLDER], mbr=rec_mbr(1), op_kw=kw)
    with no('key op shape'):                                     # another op code under this entry
        o = account.op(7, erin.ua(), params=bytes([0]) + Z32)
        account.call(relayer, 'mtx_set_guardian', o, erin.auth(digest(o)), NONE_HOLDER, mbr=rec_mbr(1))
    with no('to must be the subject'):
        account.key_op(relayer, 'mtx_set_guardian', erin, [NONE_HOLDER], to=EdKey('x').ua(), mbr=rec_mbr(1))
    account.key_op(relayer, 'mtx_set_guardian', erin, [NONE_HOLDER], mbr=rec_mbr(1), op_kw={'relayer': relayer.key})
    ts = latest_ts()
    account.key_op(relayer, 'mtx_set_guardian', erin, [NONE_HOLDER], nonce=1, op_kw={'valid_until': ts})


def test_account_update_delete_optin_refused(account, dispenser, make):
    refused_actions(account, dispenser, ['update', 'delete'])        # the creator included
    refused_actions(account, make(1_000_000), ['optin', 'closeout'])
    assert ALGOD.application_info(account.id)['params']['approval-program'] == base64.b64encode(
        account.app.approval).decode()
    assert account.app.schema == {'ints': 0, 'bytes': 0}
