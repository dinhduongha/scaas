"""DEX app + trade legs on localnet (near-algorand T14; spec §4.7, §4.1; CTR-DEX-09 / -10; README §11 (no partial fill);
rulings R3, R5, R7, R11, T14 pre-flight (a)–(g); parity with the NEAR DEX of Task 8:
smartcontracts/near/integration/tests/dex.rs).

EVM shape, atomic: the relayer's group is `[MBR → dex] [dex.settle(order_a, op_a, auth_a, order_b, op_b, auth_b, mbr)]
[dex.carry(auth)]*`; settle checks each order's `relayer` (zero or the submitter, CTR-DEX-09) and the fill-or-kill pair,
then — inside the one call — pulls both legs by inner `token.mtx_trade(op, auth, order)` (leg op 1 with to = relayer =
the DEX address: the whole sell_amount moves from the seller into the DEX's balance) and pays each sell_amount straight
on to the other leg's seller (inner arc200_transfer / transfer_to_ua). Any failure fails the whole group: no order
closes, nothing moves, and the DEX holds nothing after a settle. `mbr` = the exact MBR forwarded before each of the four
inner token calls (leg a, leg b, payout at token a, payout at token b); the relayer's one payment equals their sum."""
import base64

import pytest
from algosdk import abi, encoding

from conftest import (ALGOD, DEPLOYED, FAR, MBR_BALANCE, ORIGIN, POLICY_PASSKEY_FOR_VALUE, SLOT, Z32, Deployed, EdKey,
                      MsigKey, PasskeyKey, box_mbr, deploy, digest, holder, latest_ts, make_token, native, rec_mbr,
                      refused_actions, run, sha256, sign_as, view)
from test_account import ChromeKey, arg_bytes
from test_mandate import (FEE_CREDIT, amount_box, bal, box, events, fund_ua, no, patch, send, sim_view, token_mbr,
                          u64)

ORDER = '(uint64,uint64,uint128,uint128,byte[32],uint64)'
ORDER_T = abi.ABIType.from_string(ORDER)
MBR_ORDER = box_mbr(33, 1)       # "o" ‖ sha256(kind ‖ holder ‖ lane ‖ nonce) → uint8 (1 filled, 2 cancelled)
MBR_MIN_NONCE = box_mbr(33, 8)   # "n" ‖ sha256(kind ‖ holder ‖ lane) → uint64
LANE_A, LANE_B = b'\xc0' * 32, b'\xc1' * 32
ARGS_MAX = 2048                  # app-call argument bytes (current consensus)
# Opcode budget of a settle in its minimal group (simulate, no bare budget calls: the apps raise their own budget by
# inner budget calls on the relayer's pooled fee), (consumed, inner app calls) — runs/2026-10-28-algorand-limits.txt
BUDGET_PIN = {'settle native': (7700, 13), 'settle ed25519 UA': (8900, 14), 'settle passkey UA': (13300, 20),
              'settle msig 3 passkey + passkey (carried)': (24000, 33)}

NOT_APP = "a leg is pulled only by an app, the order's DEX"
NOT_DEX = "a leg is pulled only by the order's DEX (to = relayer = caller)"
FOK_AMOUNT = 'fill-or-kill: op amount = sell_amount'
FOK_PRICE = "fill-or-kill: each side's sell_amount covers the other's min_buy"
NO_PAIR = 'orders do not pair (each buys what the other sells)'
ORDER_RELAYER = 'order relayer is not the submitter'
FILLED, CANCELLED, BELOW_MIN = 'order filled', 'order cancelled', 'order nonce below min_nonce'
MIN_CAP, MIN_UP = 'min_nonce must be below 2^63', 'min_nonce only increases'
SHAPE = 'cancel / invalidate shape (to = from; amount, pay_ref, lane and nonce zero)'
MBR = 'MBR payment must equal'


class Leg:
    """One leg as settle takes it: the order, the seller's signed op 1, its auth."""

    def __init__(self, token, order, op, auth):
        self.token, self.order, self.op, self.auth = token, order, op, auth

    @property
    def seller(self):
        return (self.op[3][0], bytes(self.op[3][1]))


def order_key(h, lane, nonce):
    return b'o' + sha256(bytes([h[0]]), bytes(h[1]), lane, u64(nonce))


def min_nonce_key(h, lane):
    return b'n' + sha256(bytes([h[0]]), bytes(h[1]), lane)


def payout_mbr(token, h):
    return 0 if box(token, amount_box(h)) else MBR_BALANCE


def app_events(g, d):
    """Events logged by app `d` itself anywhere in the group (top level or inner)."""
    out = []

    def walk(t):
        if t['txn']['txn'].get('apid') == d.id:
            out.extend(events(d.app, [base64.b64decode(x) for x in t.get('logs', [])]))
        for it in t.get('inner-txns', []):
            walk(it)
    for i in g.infos:
        walk(i)
    return out


def algo(d):
    return ALGOD.account_info(d.address)['amount']


class Dx(Deployed):
    def order(self, sell, buy, amount, min_buy, relayer=Z32, expiry=FAR):
        return [sell.id, buy.id, amount, min_buy, relayer, expiry]

    def leg(self, token, signer, order, lane=LANE_A, nonce=0, sign=None, **op_kw):
        """`signer` signs the leg op of `order` on `token`: op 1, to = relayer = this DEX, amount = sell_amount,
        extra = sha256(ARC-4(order)), pay_ref zero (fields overridden by `op_kw`)."""
        o = token.op(holder(signer), native(self.key), order[2], lane=lane, nonce=nonce, relayer=self.key, code=1,
                     extra=sha256(ORDER_T.encode(order)))
        o = patch(o, op_kw)
        return Leg(token, order, o, (sign or (lambda d: sign_as(signer, d)))(digest(o)))

    def mbr(self, la, lb):
        """The exact parts: each leg's (its order box, the DEX's balance box when new, the seller's record when it
        opens) and each payout's (the receiver's balance box when new)."""
        return [token_mbr(la.token, la.op, la.auth), token_mbr(lb.token, lb.op, lb.auth),
                payout_mbr(la.token, lb.seller), payout_mbr(lb.token, la.seller)]

    def settle(self, relayer, la, lb, mbr='auto', delta=(0, 0, 0, 0), pay=None, carry='', simulate=False, dex=None):
        """`relayer` submits [MBR → dex][settle][carry]*; `carry` 'a' / 'b' / 'ab' moves those auths into carry calls
        (settle gets an empty auth); `dex` another DEX app submits the same legs."""
        d = dex or self
        parts = [m + x for m, x in zip(self.mbr(la, lb) if mbr == 'auto' else mbr, delta)]
        total = sum(parts) if pay is None else pay
        ta, tb = la.token, lb.token
        args = [la.order, la.op, b'' if 'a' in carry else la.auth, lb.order, lb.op, b'' if 'b' in carry else lb.auth,
                parts]
        items = ([('pay', d.address, total)] if total else []) + [
            (d, 'settle', args, {'apps': [ta.id, tb.id, ta.account.id]})]
        items += [(d, 'carry', [x.auth], {}) for c, x in (('a', la), ('b', lb)) if c in carry]
        return send(relayer, d, items, *self.refs(la, lb, d), simulate)

    def refs(self, la, lb, d=None):
        """The boxes and accounts a settle of (la, lb) by DEX `d` touches."""
        d = d or self
        boxes = []
        for x, y in ((la, lb), (lb, la)):
            t, s = x.token, x.seller
            boxes += [(t, order_key(s, x.op[8], x.op[9])), (t, min_nonce_key(s, x.op[8])), (t, amount_box(s)),
                      (t, b'b' + d.key), (t, amount_box(y.seller)), (t.account, t.account.name(s))]
        return boxes, [encoding.encode_address(x.seller[1]) for x in (la, lb) if x.seller[0] == 0]

    def args_of(self, la, lb, carry=''):
        """settle's argument bytes (the carried auths travel in their own carry calls)."""
        return arg_bytes(self, 'settle', [la.order, la.op, b'' if 'a' in carry else la.auth, lb.order, lb.op,
                                          b'' if 'b' in carry else lb.auth, [0, 0, 0, 0]])


def admin(token, by, method, signer, tlane, n, mbr='auto', sign=None, **op_kw):
    """`signer` signs a cancel (op 14: target (lane, nonce)) or invalidate (op 15: (lane, min_nonce)): to = from;
    amount, pay_ref, lane and nonce zero; extra = sha256(ARC-4(params)); `by` submits with the exact MBR."""
    h = holder(signer)
    params = tlane + u64(n)
    o = patch(token.op(h, h, 0, lane=Z32, code=14 if method == 'mtx_cancel' else 15, extra=sha256(params)), op_kw)
    a = (sign or (lambda d: sign_as(signer, d)))(digest(o))
    key = order_key(h, tlane, n) if method == 'mtx_cancel' else min_nonce_key(h, tlane)
    if mbr == 'auto':
        mbr = MBR_ORDER if method == 'mtx_cancel' else (0 if box(token, key) else MBR_MIN_NONCE)
        if not (h[0] == 0 and len(a) == 64) and token.account.record(h) is None:
            v, _, fail, _ = sim_view(token.account, 'verify_mbr', [h[0], bytes(h[1]), digest(o), a])
            mbr += 0 if fail else v
    return token.mtx(by, method, o, a, tlane, n, mbr=mbr or None, extra_boxes=[key, min_nonce_key(h, tlane)],
                     fee_extra_=FEE_CREDIT)


@pytest.fixture
def relayer(make):
    return make(300_000_000)


@pytest.fixture
def dex(dispenser):
    return deploy_dex(dispenser)


def deploy_dex(dispenser):
    d = deploy(dispenser, 'Dex', [])
    x = Dx(d.app, d.id)
    DEPLOYED[x.id] = x
    return x


@pytest.fixture
def pair(token, dispenser, make, account):
    """Token A (`token`) and token B, one account app; each with its own `alice` holding 1,000,000."""
    return token, make_token(dispenser, make, account)


def setup_legs(dex, ta, tb, relayer, a_min=50, b_min=100, a_relayer=None):
    """erin (ed25519 UA, 1,000 A) sells 100 A for >= `a_min` B, bound to `relayer`; B's alice (native) sells 60 B for
    >= `b_min` A, open, on lane c1 at nonce 3 (any nonce >= min_nonce: orders are not sequential)."""
    erin = EdKey('erin')
    fund_ua(ta, erin, 1_000)
    oa = dex.order(ta, tb, 100, a_min, relayer=(a_relayer or relayer).key)
    ob = dex.order(tb, ta, 60, b_min)
    return erin, dex.leg(ta, erin, oa), dex.leg(tb, tb.alice, ob, lane=LANE_B, nonce=3)


# ---------------------------------------------------------------- plan Step 1
def test_settle_both_legs_atomic(dex, pair, relayer):
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    alice_b = tb.alice
    # one payment = the four forwarded parts, each checked exactly by its own token call (and the DEX: their sum)
    for i in range(4):
        for dx in (-1, 1):
            with no(MBR):
                dex.settle(relayer, la, lb, delta=tuple(dx if j == i else 0 for j in range(4)))
    with no(MBR):
        dex.settle(relayer, la, lb, pay=sum(dex.mbr(la, lb)) + 1)
    parts = dex.mbr(la, lb)
    assert parts == [MBR_ORDER + MBR_BALANCE + rec_mbr(1), MBR_ORDER + MBR_BALANCE, MBR_BALANCE, MBR_BALANCE]
    mb = [d.min_balance() for d in (ta, tb, ta.account, dex)]
    algo0 = algo(dex)
    r = dex.settle(relayer, la, lb)
    # measured = charged: token a grew by the order box, the DEX's box and alice's (the payout receiver) box; token b by
    # its order box, the DEX's box and erin's UA box; the account app by erin's record; the DEX not at all
    assert [d.min_balance() - m for d, m in zip((ta, tb, ta.account, dex), mb)] == [
        MBR_ORDER + 2 * MBR_BALANCE, MBR_ORDER + 2 * MBR_BALANCE, rec_mbr(1), 0]
    # each side receives the other's full sell_amount; the DEX holds nothing (token balances 0, ALGO unchanged)
    assert (bal(ta, erin.ua()), bal(tb, erin.ua()), bal(ta, native(alice_b)), bal(tb, native(alice_b))) == (
        900, 60, 100, 1_000_000 - 60)
    assert (bal(ta, native(dex.key)), bal(tb, native(dex.key)), algo(dex)) == (0, 0, algo0)
    # events on success, carrying both token ids and the settle id = sha256(digest(op_a) ‖ digest(op_b))
    da, db = digest(la.op), digest(lb.op)
    assert r.own(dex) == [('Matched', [list(sha256(da, db)), ta.id, tb.id, list(da), list(db)])]
    fa = [e for e in app_events(r, ta) if e[0] == 'OrderFilled']
    fb = [e for e in app_events(r, tb) if e[0] == 'OrderFilled']
    assert fa == [('OrderFilled', [[1, list(erin.id)], dex.address, list(LANE_A), 0, 100, list(da)])]
    assert fb == [('OrderFilled', [[0, list(alice_b.key)], dex.address, list(LANE_B), 3, 60, list(db)])]
    assert ('arc200_Transfer', [dex.address, alice_b.addr, 100]) in app_events(r, ta)
    assert ('UaTransfer', [[0, list(dex.key)], [1, list(erin.id)], 60]) in app_events(r, tb)
    # orders keyed (holder, lane, nonce), closed for good
    assert view(ta, 'filled', 1, erin.id, LANE_A, 0) is True and view(tb, 'filled', 0, alice_b.key, LANE_B, 3) is True
    assert view(ta, 'filled', 1, erin.id, LANE_A, 1) is False
    with no(FILLED):
        dex.settle(relayer, la, lb, mbr=[MBR_ORDER, MBR_ORDER, 0, 0])
    # a second pair on the same tokens: the DEX's boxes exist, so the legs need only their order boxes
    _, la2, lb2 = setup_legs(dex, ta, tb, relayer)
    la2 = dex.leg(ta, erin, la2.order, nonce=1)
    lb2 = dex.leg(tb, alice_b, lb2.order, lane=LANE_B, nonce=4)
    assert dex.mbr(la2, lb2) == [MBR_ORDER, MBR_ORDER, 0, 0]
    dex.settle(relayer, la2, lb2)
    assert (bal(ta, erin.ua()), bal(tb, erin.ua())) == (1_800, 120)


def test_one_leg_fails_group_fails(dex, pair, relayer, make):
    """Atomic (ruling R3): a failing leg or payout fails the whole settle — nothing moves, no order closes (unlike NEAR's
    async escrow, T8-I1), the DEX holds nothing; the same orders settle afterwards."""
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    alice_b = tb.alice
    poor = EdKey('poor')                                   # a seller short of its sell_amount (59 of 60)
    fund_ua(tb, poor, 59)

    def unchanged():
        assert (bal(ta, erin.ua()), bal(tb, native(alice_b)), bal(ta, native(dex.key)), bal(tb, native(dex.key))) == (
            1_000, 1_000_000 - 59, 0, 0)
        assert view(ta, 'filled', 1, erin.id, LANE_A, 0) is False
        assert view(tb, 'filled', 0, alice_b.key, LANE_B, 3) is False
    with no('bad signature'):                              # leg b signed by another key (after leg a ran)
        dex.settle(relayer, la, dex.leg(tb, alice_b, lb.order, lane=LANE_B, nonce=3,
                                        sign=lambda d: make().sign_op(d)))
    unchanged()
    with no('the key does not derive the UA id'):          # leg a signed by another key
        dex.settle(relayer, dex.leg(ta, erin, la.order, sign=lambda d: EdKey('zed').auth(d)), lb)
    unchanged()
    with no('insufficient balance'):
        dex.settle(relayer, la, dex.leg(tb, poor, lb.order, lane=LANE_B, nonce=3))
    unchanged()
    with no(MBR):                                          # the last payout's MBR short: everything before it undone
        dex.settle(relayer, la, lb, delta=(0, 0, 0, -1))
    unchanged()
    dex.settle(relayer, la, lb)
    assert (bal(ta, erin.ua()), bal(tb, erin.ua()), bal(ta, native(alice_b))) == (900, 60, 100)


def test_order_relayer_mismatch_refused(dex, pair, relayer, make):
    """CTR-DEX-09: an order with `relayer` set settles only when that address submits the settle; zero = any. The leg
    op itself is bound to the DEX (relayer = to = the DEX address), so the order's `relayer` is the submitter check."""
    ta, tb = pair
    other = make(100_000_000)
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    with no(ORDER_RELAYER):                                # order a bound to `relayer`
        dex.settle(other, la, lb)
    lb2 = dex.leg(tb, tb.alice, dex.order(tb, ta, 60, 100, relayer=relayer.key), lane=LANE_B, nonce=3)
    la2 = dex.leg(ta, erin, dex.order(ta, tb, 100, 50))
    with no(ORDER_RELAYER):                                # order b bound to `relayer`
        dex.settle(other, la2, lb2)
    with no(NOT_DEX):                                      # a leg op whose relayer is zero is not a leg of this DEX
        dex.settle(relayer, dex.leg(ta, erin, la.order, relayer=Z32), lb)
    with no(NOT_DEX):                                      # … nor one whose relayer is the submitting relayer
        dex.settle(relayer, dex.leg(ta, erin, la.order, relayer=relayer.key), lb)
    assert bal(ta, erin.ua()) == 1_000
    dex.settle(other, la2, dex.leg(tb, tb.alice, dex.order(tb, ta, 60, 100), lane=LANE_B, nonce=3))
    with no(FILLED):
        dex.settle(relayer, la, lb)


def test_leg_by_non_dex_refused(dex, pair, relayer, make, probe, dispenser):
    """A leg moves only when the order's DEX — the app whose address is the op's `to` and `relayer` — calls mtx_trade:
    not another app (the probe, a second DEX), not the address itself at the top level, and never through the token's
    open mode (mtx_pay refuses op 1)."""
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    need = token_mbr(ta, la.op, la.auth)
    with no(NOT_DEX):                                      # another app pulls a leg signed for this DEX
        run(relayer, probe, 'trade', [ta.id, la.op, la.auth, la.order, need], apps=[ta.id, ta.account.id],
            fee_extra=FEE_CREDIT)
    dex2 = deploy_dex(dispenser)
    with no(NOT_DEX):                                      # a second DEX settles legs signed for the first
        dex.settle(relayer, la, lb, dex=dex2)
    x = make(1_000_000)                                    # a leg bound to an ordinary address, sent by it
    lx = Leg(ta, la.order, patch(la.op, {'to': [0, x.key], 'relayer': x.key}), None)
    lx.auth = erin.auth(digest(lx.op))
    with no(NOT_APP):
        ta.mtx(x, 'mtx_trade', lx.op, lx.auth, lx.order, mbr=token_mbr(ta, lx.op, lx.auth), fee_extra_=FEE_CREDIT)
    lp = Leg(ta, la.order, patch(la.op, {'to': [0, probe.key], 'relayer': probe.key}), None)
    lp.auth = erin.auth(digest(lp.op))
    with no('wrong op code'):
        run(relayer, probe, 'pay', [ta.id, lp.op, lp.auth, probe.address, 0], apps=[ta.id, ta.account.id],
            fee_extra=FEE_CREDIT)
    # the leg's order must sell the token it runs on (only an app other than this DEX can mismatch them)
    other = dex.order(tb, ta, 100, 50)
    lo = Leg(ta, other, patch(lp.op, {'extra': sha256(ORDER_T.encode(other))}), None)
    lo.auth = erin.auth(digest(lo.op))
    with no('order sells another token'):
        run(relayer, probe, 'trade', [ta.id, lo.op, lo.auth, other, need], apps=[ta.id, ta.account.id],
            fee_extra=FEE_CREDIT)
    assert (bal(ta, erin.ua()), bal(ta, native(probe.key)), bal(ta, native(x.key))) == (1_000, 0, 0)
    dex.settle(relayer, la, lb)
    assert bal(tb, erin.ua()) == 60


def test_cancel_filled_refused(dex, pair, relayer, make):
    """Cancel (op 14) closes an open order for good; a filled or cancelled order, or one below min_nonce, is refused (no
    effect for a no-op, owner rule); the signed shape and the relayer binding hold; MBR exact (the order box)."""
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    dex.settle(relayer, la, lb)
    with no(FILLED):
        admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 0)
    with no(MBR):
        admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 1, mbr=MBR_ORDER - 1)
    with no(MBR):
        admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 1, mbr=MBR_ORDER + 1)
    for kw, err in (({'amount': 1}, SHAPE), ({'to': [1, b'\x01' * 32]}, SHAPE), ({'lane': LANE_A}, SHAPE),
                    ({'nonce': 1}, SHAPE), ({'pay_ref': b'\x01' * 32}, SHAPE), ({'op': 15}, SHAPE),
                    ({'extra': sha256(LANE_A + u64(2))}, 'extra is not sha256 of the parameters'),
                    ({'relayer': make().key}, 'relayer is not the sender'),
                    ({'network': sha256(b'another genesis')}, 'wrong network'),
                    ({'contract': tb.key}, 'wrong contract'), ({'valid_until': 1}, 'expired')):
        with no(err):
            admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 1, **kw)
    with no('not a key of the subject'):                  # signed by a key erin's record does not hold
        admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 1, sign=lambda d: EdKey('zed').auth(d))
    with no('bad signature'):                             # a native maker's wallet signature by another key
        admin(tb, relayer, 'mtx_cancel', tb.alice, LANE_B, 9, sign=lambda d: make().sign_op(d))
    t0 = ta.min_balance()
    r = admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 1)
    assert ta.min_balance() - t0 == MBR_ORDER
    from test_token import events as tev
    assert ('OrderCancelled', [[1, erin.id], LANE_A, 1]) in tev(ta, r)
    with no(CANCELLED):                                    # a no-op: refused
        admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 1, mbr=MBR_ORDER)
    with no(CANCELLED):                                    # the cancelled order cannot settle
        dex.settle(relayer, dex.leg(ta, erin, la.order, nonce=1), dex.leg(tb, tb.alice, lb.order, lane=LANE_B, nonce=4))
    admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, 10)
    with no(BELOW_MIN):                                    # below min_nonce: already void
        admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 9, mbr=MBR_ORDER)
    assert view(ta, 'filled', 1, erin.id, LANE_A, 1) is False and bal(ta, erin.ua()) == 900
    # a native maker cancels with its wallet signature
    admin(tb, relayer, 'mtx_cancel', tb.alice, LANE_B, 9)


def test_min_nonce_cap_refused(dex, pair, relayer):
    """CTR-DEX-10: invalidate (op 15) raises a lane's min_nonce, below 2^63 only, strictly increasing (a repeat or a
    decrease is a no-op: refused); orders below it never settle. MBR: the min_nonce box once per (holder, lane)."""
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    for n in (2**63, 2**64 - 1):
        with no(MIN_CAP):
            admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, n, mbr=MBR_MIN_NONCE + rec_mbr(1))
    with no(MIN_UP):                                       # 0 is the start: not an increase
        admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, 0, mbr=rec_mbr(1))
    for d in (-1, 1):
        with no(MBR):
            admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, 5, mbr=MBR_MIN_NONCE + rec_mbr(1) + d)
    with no(SHAPE):
        admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, 5, op=14)
    t0 = ta.min_balance()
    r = admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, 5)
    assert ta.min_balance() - t0 == MBR_MIN_NONCE
    from test_token import events as tev
    assert ('NoncesInvalidated', [[1, erin.id], LANE_A, 5]) in tev(ta, r)
    with no('not a key of the subject'):
        admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, 6, sign=lambda d: EdKey('zed').auth(d))
    for n in (5, 4):
        with no(MIN_UP):
            admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, n)
    with no(BELOW_MIN):                                    # nonce 0 < 5: void
        dex.settle(relayer, la, lb)
    t0 = ta.min_balance()
    admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_A, 2**63 - 1, mbr=None)   # the box exists: no MBR
    assert ta.min_balance() == t0 and view(ta, 'min_nonce', 1, erin.id, LANE_A) == 2**63 - 1
    assert view(ta, 'min_nonce', 1, erin.id, LANE_B) == 0      # per (holder, lane)
    dex.settle(relayer, dex.leg(ta, erin, la.order, lane=LANE_B, nonce=0), lb)
    assert bal(tb, erin.ua()) == 60


def test_no_partial_fill(dex, pair, relayer):
    """Fill-or-kill (README §11): the leg moves exactly the order's sell_amount, each order's sell_amount covers the
    other's min_buy, and each side receives the other's FULL sell_amount (no remainder kept, no second fill)."""
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer, a_min=40, b_min=90)
    for amount in (99, 101):
        with no(FOK_AMOUNT):
            dex.settle(relayer, dex.leg(ta, erin, la.order, amount=amount), lb)
    zero = dex.order(ta, tb, 0, 40, relayer=relayer.key)     # a zero sell_amount (against a zero min_buy)
    with no(FOK_AMOUNT):
        dex.settle(relayer, dex.leg(ta, erin, zero), dex.leg(tb, tb.alice, dex.order(tb, ta, 60, 0), lane=LANE_B, nonce=3))
    with no(FOK_PRICE):                                    # b's min_buy 101 > a's 100
        dex.settle(relayer, la, dex.leg(tb, tb.alice, dex.order(tb, ta, 60, 101), lane=LANE_B, nonce=3))
    with no(FOK_PRICE):                                    # a's min_buy 61 > b's 60
        dex.settle(relayer, dex.leg(ta, erin, dex.order(ta, tb, 100, 61, relayer=relayer.key)), lb)
    with no(NO_PAIR):                                      # b buys B: does not pair
        dex.settle(relayer, la, dex.leg(tb, tb.alice, dex.order(tb, tb, 60, 90), lane=LANE_B, nonce=3))
    with no(NO_PAIR):                                      # both sell A for A
        dex.settle(relayer, dex.leg(ta, erin, dex.order(ta, ta, 100, 40)),
                   dex.leg(ta, ta.alice, dex.order(ta, ta, 100, 40), lane=LANE_B))
    dex.settle(relayer, la, lb)
    # surplus goes to the counterparty: alice receives 100 A (min 90), erin 60 B (min 40); nothing stays at the DEX
    assert (bal(ta, native(tb.alice)), bal(tb, erin.ua()), bal(ta, native(dex.key)), bal(tb, native(dex.key))) == (
        100, 60, 0, 0)
    with no(FILLED):
        dex.settle(relayer, la, dex.leg(tb, tb.alice, lb.order, lane=LANE_B, nonce=4))


# ---------------------------------------------------------------- more guards
def test_replay_across_dexes_tokens_networks(dex, pair, relayer):
    """A leg op binds the network, the token (contract and the order's sell_token), the DEX (to = relayer), the order
    (extra) and expiries; each mismatch refused, nothing moves."""
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    for kw, err in (({'network': sha256(b'another genesis')}, 'wrong network'),
                    ({'contract': tb.key}, 'wrong contract'),
                    ({'valid_until': 1}, 'expired'),
                    ({'pay_ref': b'\x01' * 32}, 'a trade leg carries no pay_ref'),
                    ({'op': 0}, 'wrong op code'),
                    ({'to': [0, relayer.key]}, NOT_DEX),
                    ({'extra': sha256(ORDER_T.encode(dex.order(ta, tb, 100, 1, relayer=relayer.key)))},
                     'extra is not sha256 of the order')):
        with no(err):
            dex.settle(relayer, dex.leg(ta, erin, la.order, **kw), lb)
    now = latest_ts()
    old = dex.order(tb, ta, 60, 100, expiry=now - 1)
    with no('order expired'):
        dex.settle(relayer, la, dex.leg(tb, tb.alice, old, lane=LANE_B, nonce=3))
    assert (bal(ta, erin.ua()), bal(tb, native(tb.alice))) == (1_000, 1_000_000)
    dex.settle(relayer, la, lb)


def test_trade_leg_is_a_value_op(dex, pair, relayer):
    """T13 n2: a leg verifies through account `verify` (POLICY_PASSKEY_FOR_VALUE binds); a cancel / invalidate moves no
    value (`verify_key`, the policy does not block them)."""
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 7)      # opens erin's record
    dave = PasskeyKey('dave-trader')
    ta.account.key_op(relayer, 'mtx_add_key', erin, [dave.record(), ORIGIN.encode()], mbr=2 * SLOT)
    ta.account.key_op(relayer, 'mtx_set_policy', erin, [POLICY_PASSKEY_FOR_VALUE], nonce=1)
    with no('POLICY_PASSKEY_FOR_VALUE'):
        dex.settle(relayer, la, lb)
    admin(ta, relayer, 'mtx_cancel', erin, LANE_A, 8)
    admin(ta, relayer, 'mtx_invalidate_nonces', erin, LANE_B, 1)
    dex.settle(relayer, dex.leg(ta, erin, la.order, sign=lambda d: dave.auth(d)), lb)
    assert bal(tb, erin.ua()) == 60


def test_carried_auth_anywhere_in_group(dex, pair, relayer, probe, dispenser):
    """A carried auth is the first `carry` call to this DEX in group order (a's before b's), wherever it sits — here
    before the MBR payment, with an app call after settle (the T15 relay shape puts the router call there); a carry to
    another app is not one; an empty auth without a carry call is refused."""
    ta, tb = pair
    erin, la, lb = setup_legs(dex, ta, tb, relayer)
    dex2 = deploy_dex(dispenser)
    parts = dex.mbr(la, lb)
    args = [la.order, la.op, b'', lb.order, lb.op, b'', parts]
    apps = {'apps': [ta.id, tb.id, ta.account.id]}
    refs = dex.refs(la, lb)
    with no('a carried auth needs a carry call'):
        send(relayer, dex, [(dex, 'carry', [la.auth], {}), ('pay', dex.address, sum(parts)), (dex, 'settle', args, apps)],
             *refs)
    items = [(dex2, 'carry', [b'\x01' * 70], {}), (dex, 'carry', [la.auth], {}), (dex, 'carry', [lb.auth], {}),
             ('pay', dex.address, sum(parts)), (dex, 'settle', args, apps), (probe, 'lane_of', [Z32], {})]
    send(relayer, dex, items, *refs)
    assert (bal(tb, erin.ua()), bal(ta, native(tb.alice))) == (60, 100)


def test_dex_update_delete_optin_refused(dex, dispenser, make):
    """R11: the DEX approval refuses Update / Delete (creator included) and OptIn / CloseOut; no state at all."""
    refused_actions(dex, dispenser, ['update', 'delete'])
    refused_actions(dex, make(1_000_000), ['optin', 'closeout'])
    assert ALGOD.application_info(dex.id)['params']['approval-program'] == base64.b64encode(dex.app.approval).decode()
    s = dex.app.spec['state']['schema']
    assert s['local'] == {'ints': 0, 'bytes': 0} and s['global'] == {'ints': 0, 'bytes': 0}


def test_figures_pinned(dex, pair, relayer, make):
    """Budget of a settle per leg signer kind in the minimal group (no bare budget calls), pinned; the worst-case leg —
    a 3-member passkey msig (MSIG_MAX_MEMBERS) with Chrome-shaped assertions — against a Chrome passkey leg: its auth
    does not fit settle's 2,048 B of arguments inline, so it rides a carry call; every app call of the group (settle,
    carry, the inner mtx_trade and account.verify) stays within 2,048 B. MBR per order / min_nonce box; program size."""
    ta, tb = pair
    out, args = {}, {}

    def legs(sa, sb, n):
        """`None` = the token's native alice; else a UA key funded with 1,000."""
        for t, s in ((ta, sa), (tb, sb)):
            if s is not None:
                fund_ua(t, s, 1_000)
        return (dex.leg(ta, sa or ta.alice, dex.order(ta, tb, 100, 60), nonce=n),
                dex.leg(tb, sb or tb.alice, dex.order(tb, ta, 60, 100), lane=LANE_B, nonce=n))
    cases = (('native', None, None, ''), ('ed25519 UA', EdKey('fig-a'), EdKey('fig-b'), ''),
             ('passkey UA', ChromeKey('fig-pa'), ChromeKey('fig-pb'), ''),
             ('msig 3 passkey + passkey (carried)', MsigKey(3, [(ChromeKey('fig-m%d' % i), 1) for i in range(3)]),
              ChromeKey('fig-pc'), 'ab'))
    for n, (name, sa, sb, carry) in enumerate(cases):
        la, lb = legs(sa, sb, n)
        args[name] = (dex.args_of(la, lb), dex.args_of(la, lb, carry) if carry else None)
        used, inner, fail = dex.settle(relayer, la, lb, carry=carry, simulate=True)
        assert fail is None, (name, fail)
        out['settle ' + name] = (used, inner)
        dex.settle(relayer, la, lb, carry=carry)
        assert (bal(ta, native(dex.key)), bal(tb, native(dex.key))) == (0, 0)
    # la: the msig-3 leg just settled
    inner_args = 4 + 291 + 2 + len(la.auth) + 88                     # token.mtx_trade(op, auth, order) from the DEX
    verify_args = 4 + 1 + 32 + 32 + 2 + len(la.auth)                 # account.verify(kind, id, digest, auth)
    carry_args = 4 + 2 + len(la.auth)
    print('\nDEX settle opcode budget, minimal group (consumed, inner app calls): %s\npins %s' % (out, BUDGET_PIN))
    print('settle argument bytes (inline, carried): %s; msig-3 leg auth %d B, carry call %d B, inner mtx_trade %d B, '
          'inner account.verify %d B (limit %d)' % (args, len(la.auth), carry_args, inner_args, verify_args, ARGS_MAX))
    print('MBR (µALGO): order box %d (name 33 B, value 1 B), min_nonce box %d; per leg + the DEX balance box %d once '
          'per token, the payout receiver box %d when new; the DEX app: none' % (MBR_ORDER, MBR_MIN_NONCE, MBR_BALANCE,
                                                                                 MBR_BALANCE))
    print('program size (B): dex approval %d, clear %d; token approval %d' % (
        len(dex.app.approval), len(dex.app.clear), len(ta.app.approval)))
    inline, carried = args['msig 3 passkey + passkey (carried)']
    assert inline > ARGS_MAX >= carried and max(carry_args, inner_args, verify_args) <= ARGS_MAX
    assert args['passkey UA'][0] <= ARGS_MAX                         # two Chrome passkey legs fit inline
    for k, (used, calls) in out.items():
        assert used <= BUDGET_PIN[k][0] and calls <= BUDGET_PIN[k][1], (k, used, calls)
