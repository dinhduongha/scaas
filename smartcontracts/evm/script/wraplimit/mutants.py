# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Group 3l, plan T99 (wrap limits spec 2026-11-10-wrap-limits.md §11): every mutant alone on a clean tree, `forge test` of the
wrap-limit tests through `scripts/capped`, the file restored byte-equal (sha256 checked) after each. One line per mutant:
`mutant | red tests | rc` (rc 1 = killed). Full output in git-ignored `.log` files under `<runs>/mutants/`.

usage (from smartcontracts/evm): python3 script/wraplimit/mutants.py <runs dir> [name ...]   UNAUDITED tooling."""
import hashlib
import os
import re
import subprocess
import sys

LIB = 'src/metatx/WrappedLib.sol'
CORE = 'src/metatx/WrappedTokenCore.sol'
BITS = 'src/governance/GovernanceBits.sol'
ZCORE = 'src/zether/WrappedZetherTokenCore.sol'
RB = 'src/governance/GovernanceRouterBase.sol'
W = 'test/wrap/WrapLimits.t.sol'
K = 'test/wrap/WrapLimitsKinds.t.sol'
G = 'test/governance/GovWrapLimits.t.sol'

# (name, file, old, new, test dir, test file)
M = [
    ('list-reads-receiver', LIB, 'if (ctl & CTL_WLIST != 0) _listed(MetaTxLib.pad(from), 1);',
     'if (ctl & CTL_WLIST != 0) _listed(receiver == 0 ? MetaTxLib.pad(from) : receiver, 1);', 'test/wrap', W),
    ('list-after-pull', LIB, '''        if (ctl & CTL_WLIST != 0) _listed(MetaTxLib.pad(from), 1);
        received = _pull(L, amount, from, value);''', '''        received = _pull(L, amount, from, value);
        if (ctl & CTL_WLIST != 0) _listed(MetaTxLib.pad(from), 1);''', 'test/wrap', W),
    ('holder-msgsender', CORE, '''        bytes32 holder = _subject(); // group 3l (R14): the signer's id, never `UA_POOL`
        (out, burned) = WrappedLib.quoteUnwrap(''', '''        bytes32 holder = MetaTxLib.pad(_msgSender());
        (out, burned) = WrappedLib.quoteUnwrap(''', 'test/wrap', W),
    ('cap-gt-to-ge', LIB, 'if (nu > cap) revert IWrappedToken.WrapLimitExceeded', 'if (nu >= cap) revert IWrappedToken.WrapLimitExceeded',
     'test/wrap', W),
    ('quanta-floor', LIB, 'c.q = Math.ceilDiv(c.x, c.unit);', 'c.q = c.x / c.unit;', 'test/wrap', W),
    ('one-window-for-both', LIB, 'uint256 l = 2 * side + j;', 'uint256 l = 2 * side;', 'test/wrap', W),
    ('unwrap-counts-burned', LIB, 'if (ctl != 0) _unwrapNext(ctl, i, holder, out, L.token);',
     'if (ctl != 0) _unwrapNext(ctl, i, holder, burned, L.token);', 'test/wrap', W),
    ('total-not-written', LIB, '''        (qw, tw) = _side(cfg, _ld(ps), tw, 0, _use(x, payer, u));
        if (ts != 0) _st(ts, tw);''', '''        (qw, tw) = _side(cfg, _ld(ps), tw, 0, _use(x, payer, u));''', 'test/wrap', W),
    ('window-le-to-lt', LIB, '% _CIRCLE <= p;', '% _CIRCLE < p;', 'test/wrap', W),
    ('start-reset-every-use', LIB, '(ns, nu) = (active ? start : nowMin, base + q);', '(ns, nu) = (nowMin, base + q);', 'test/wrap', W),
    ('checked-subtraction', LIB, 'bool active = used != 0 && (nowMin + _CIRCLE - start) % _CIRCLE <= p;',
     'bool active = used != 0 && (nowMin - start) % _CIRCLE <= p;', 'test/wrap', W),
    ('credit-the-payer', LIB, 'if (receiver == 0) receiver = payer;', 'receiver = payer;', 'test/wrap', W),
    ('debit-floor', LIB, '''        uint256 q = Math.ceilDiv(x, unit);
        uint256 b = _get(qw, 160, 32);''', '''        uint256 q = x / unit;
        uint256 b = _get(qw, 160, 32);''', 'test/wrap', W),
    ('track-only-under-net', LIB, 'if (ctl & CTL_TRACK != 0) _wrapCount(i, u, MetaTxLib.pad(from), receiver, received);',
     'if (ctl & CTL_NET != 0) _wrapCount(i, u, MetaTxLib.pad(from), receiver, received);', 'test/wrap', W),
    ('clock-not-kept-off', LIB, 'if (decayDays == 0) return (b, g, 0);', 'if (decayDays == 0) return (b, 0, 0);', 'test/wrap', W),
    ('order-counts-submitter', LIB, 'if (L.ctl & CTL_TRACK != 0) _wrapCount(i, u, o.from, o.destination, o.amount);',
     'if (L.ctl & CTL_TRACK != 0) _wrapCount(i, u, MetaTxLib.pad(submitter), o.destination, o.amount);', 'test/wrap', W),
    ('unshield-envelope-from', ZCORE, 'bytes32 holder = ZetherTypes.UA.unwrap(ZetherLib.uaOf(b.yFrom));', 'bytes32 holder = _subject();',
     'test/wrap', K),
    ('eff0-tightest', LIB, '''        tight = b != 0 && (a == 0 || b < a);
        loose = a != 0 && (b == 0 || b > a);''', '''        tight = a == 0 || b < a;
        loose = a != 0 && b > a;''', 'test/wrap', W),
    ('pending-window-unchecked', LIB, 'return eta != 0 && w.pendingGeneration == gen && block.timestamp <= eta + delay;',
     'return eta != 0 && w.pendingGeneration == gen;', 'test/wrap', W),
    ('pending-generation-unchecked', LIB, 'return eta != 0 && w.pendingGeneration == gen && block.timestamp <= eta + delay;',
     'return eta != 0 && block.timestamp <= eta + delay;', 'test/wrap', W),
    ('period-direction-inverted', LIB, '(tight, loose) = (tight || b > a, loose || b < a);', '(tight, loose) = (tight || b < a, loose || b > a);',
     'test/wrap', W),
    ('unwrap-side-as-wrap-side', LIB, '(bool tight,) = _cmp(o1, w1);', '(, bool tight) = _cmp(o1, w1);', 'test/wrap', W),
    ('decay-as-wrap-side', LIB, '(bool t,) = _amt(uint16(o1 >> 232), uint16(w1 >> 232));', '(, bool t) = _amt(uint16(o1 >> 232), uint16(w1 >> 232));',
     'test/wrap', W),
    ('unit-copy-not-written', LIB, 'w1 = _part(l.unwrapShort, u, 2) | (_part(l.unwrapLong, u, 3) << 112) | tail;',
     'w1 = _part(l.unwrapShort, u, 2) | (_part(l.unwrapLong, u, 3) << 112) | (uint256(l.decayDays) << 232);', 'test/wrap', W),
    ('disable-26-unchecked', LIB, 'if (ctl & (limit ? CTL_NET : CTL_WLIST | CTL_ULIST) != 0)', 'if (ctl & (limit ? CTL_NET : 0) != 0)',
     'test/wrap', W),
    ('disable-27-unchecked', LIB, 'if (GovernanceLib.$().counts[bit].holders != 0) revert IWrappedToken.WrapControlActive(bit);',
     'GovernanceLib.$().counts[bit].holders;', 'test/wrap', W),
    ('bit25-in-normal-mask', BITS, 'uint256 internal constant NORMAL_BITS = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE) | (1 << RESCUABLE);',
     'uint256 internal constant NORMAL_BITS = (1 << PAYABLE) | (1 << MINTABLE) | (1 << BURNABLE) | (1 << RESCUABLE) | (1 << 25);',
     'test/wrap', W),
    ('one-quota-across-legs', LIB, '''        mapping(uint256 => uint256) storage m = w.quota[id];
        assembly ("memory-safe") {
            mstore(0, i)''', '''        mapping(uint256 => uint256) storage m = w.quota[id];
        i;
        assembly ("memory-safe") {
            mstore(0, 0)''', 'test/wrap', W),
    ('one-leg-ctl', LIB, '            s.legs[i].ctl = ctl;\n', '            if (i == 0) s.legs[i].ctl = ctl;\n', 'test/wrap', W),
    ('view-wrong-window', LIB, 'r.wrapShort = _userView(_ld(c), qw, 0, unit);', 'r.wrapShort = _userView(_ld(c), qw, 1, unit);', 'test/wrap', W),
    ('entitlement-round-up', LIB, '        e = b * (h - g) / h;\n', '        e = Math.ceilDiv(b * (h - g), h);\n', 'test/wrap', W),
    ('age-unclamped', LIB, '        if (g > h) g = h;\n', '', 'test/wrap', W),
    ('start-now-every-wrap', LIB, 'uint256 g2 = Math.ceilDiv(e * g, e + a);', 'uint256 g2 = 0;', 'test/wrap', W),
    ('age-rounded-down', LIB, 'uint256 g2 = Math.ceilDiv(e * g, e + a);', 'uint256 g2 = e * g / (e + a);', 'test/wrap', W),
    ('base-not-rescaled', LIB, 'if (h != 0) b2 = Math.min(b2, (e + a) * h / (h - g2));', '', 'test/wrap', W),
    ('base-clamp-missing', LIB, 'if (h != 0) b2 = Math.min(b2, (e + a) * h / (h - g2));', 'if (h != 0) b2 = (e + a) * h / (h - g2);',
     'test/wrap', W),
    ('debit-b-minus-q', LIB, 'return (_put(qw, 160, 32, q >= e ? 0 : b * (e - q) / e), excess);', 'return (_put(qw, 160, 32, q >= b ? 0 : b - q), excess);',
     'test/wrap', W),
    ('debit-guard-removed', LIB, 'return (_put(qw, 160, 32, q >= e ? 0 : b * (e - q) / e), excess);', 'return (_put(qw, 160, 32, b * (e - q) / e), excess);',
     'test/wrap', W),
    ('redeemer-no-use', LIB, '        if (excess != 0) GovernanceUse.use(GovernanceBits.REDEEMER, holder, excess);\n', '', 'test/wrap', W),
    ('redeemer-use-zero', LIB, 'if (excess != 0) GovernanceUse.use(GovernanceBits.REDEEMER, holder, excess);',
     'if (excess != 0) GovernanceUse.use(GovernanceBits.REDEEMER, holder, 0);', 'test/wrap', W),
    ('redeemer-skips-windows', LIB, '''        (qw, tw) = _side(cfg, _ld(_qslot(wl(), holder, i)), tw, 1, _use(x, holder, u));''', '''        if (GovernanceLib.hasRole(GovernanceBits.REDEEMER, holder)) qw = _ld(_qslot(wl(), holder, i));
        else (qw, tw) = _side(cfg, _ld(_qslot(wl(), holder, i)), tw, 1, _use(x, holder, u));''', 'test/wrap', W),
    ('base-unsaturated', LIB, '_put(_put(qw, 160, 32, Math.min(b2, type(uint32).max)), 192, 64', '_put(_put(qw, 160, 32, b2), 192, 64', 'test/wrap', W),
    ('hybrid-check-misses-27', LIB, 'uint256 wc = c.features & GovernanceBits.WRAP_CONTROLS;',
     'uint256 wc = c.features & ((uint256(1) << 25) | (uint256(1) << 26));', 'test/wrap', W),
    ('hybrid-check-reads-storage', LIB, 'uint256 wc = c.features & GovernanceBits.WRAP_CONTROLS;',
     'uint256 wc = GovernanceLib.$().features & GovernanceBits.WRAP_CONTROLS;', 'test/wrap', W),
    ('decay-gated-on-net', LIB, 'if ((ctl & CTL_NET != 0 || decayDays != 0) && q > e) {', 'if (ctl & CTL_NET != 0 && q > e) {', 'test/wrap', W),
    ('subject-zero-unchecked', LIB, '        if (holder == 0) revert IWrappedToken.WrapSubjectZero();\n', '', 'test/wrap', W),
    ('stale-load-one-slot', LIB, '            _st(ps, _credit(qw, a, uint16(cfg >> 232)));', '            _st(ps, _credit(_ld(ps), a, uint16(cfg >> 232)));',
     'test/wrap', W),
    ('router-limit-type-left-out', RB, '''        "WrapLegLimits(address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)"
        "WrapLimit(uint24 perUser,uint64 tokenWide,uint32 period)");
    bytes32 internal constant UA_SET_WRAP_MEMBER''', '''        "WrapLegLimits(address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)");
    bytes32 internal constant UA_SET_WRAP_MEMBER''', 'test/governance', G),
]

FORGE = os.path.expanduser('~/.foundry/bin/forge')


def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()


def run(runs, name, f, old, new, tdir, tfile):
    src = open(f).read()
    assert src.count(old) == 1, (name, f)
    h = sha(f)
    log = os.path.join(runs, 'mutants', f'{name}.log')
    try:
        open(f, 'w').write(src.replace(old, new))
        env = dict(os.environ, FOUNDRY_TEST=tdir, CAPPED_SLOTS=os.environ.get('CAPPED_SLOTS', '3'))  # owner 2026-11-10: three slots
        with open(log, 'w') as out:
            rc = subprocess.call(['../../scripts/capped', FORGE, 'test', '--match-path', tfile], stdout=out, stderr=subprocess.STDOUT,
                                 env=env)
    finally:
        open(f, 'w').write(src)
    assert sha(f) == h, f'{f} not restored byte-equal'
    text = open(log).read()
    red = sorted(set(re.findall(r'\[FAIL[^\]]*\] (\w+)\(', text)))
    if 'Compiler run failed' in text:
        red = ['(compile error)']
    return rc, red


def others_waiting():
    """Slot fairness (controller 2026-11-10): a `scripts/capped` job of another work tree waits for a slot (holds no lock
    file of `~/.cache/r3-locks`); this one yields to it."""
    here = os.path.realpath(os.path.join(os.getcwd(), '../..'))
    locks = os.path.expanduser('~/.cache/r3-locks')
    held = subprocess.run(['fuser'] + [os.path.join(locks, f) for f in os.listdir(locks)], capture_output=True,
                          text=True).stdout.split()
    out = subprocess.run(['pgrep', '-f', 'scripts/capped'], capture_output=True, text=True).stdout.split()
    for pid in out:
        if pid in held:
            continue
        try:
            cwd = os.path.realpath(os.readlink(f'/proc/{pid}/cwd'))
            args = open(f'/proc/{pid}/cmdline').read()
        except OSError:
            continue
        if args.split('\0')[1:2] and args.split('\0')[1].endswith('scripts/capped') and not cwd.startswith(here + os.sep) \
                and cwd != here:
            return True
    return False


def main():
    runs = sys.argv[1]
    os.makedirs(os.path.join(runs, 'mutants'), exist_ok=True)
    only = set(sys.argv[2:])
    out = os.path.join(runs, 'mutants.txt')
    done = {}
    if os.path.exists(out):
        for line in open(out):
            if ' | ' in line and not line.startswith('mutant'):
                done[line.split(' | ')[0]] = line
    with open(out, 'a') as o:
        if not done:
            o.write('mutant | red tests | rc\n')
        for name, f, old, new, tdir, tfile in M:
            if (only and name not in only) or name in done:
                continue
            if others_waiting():
                print('yield: another work tree waits for a capped slot; rerun to resume', flush=True)
                return
            rc, red = run(runs, name, f, old, new, tdir, tfile)
            line = f'{name} | {", ".join(red) or "-"} | {rc}\n'
            o.write(line)
            o.flush()
            print(line, end='', flush=True)


if __name__ == '__main__':
    main()
