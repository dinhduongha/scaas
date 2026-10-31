#!/usr/bin/python3 -I
"""zether-msm: prove the merged-check tests can fail. Each row removes a check or a weight from the verifier, runs the tests
named for it and expects red, then restores the source. A row that runs no test is an error, not a pass.
Run from smartcontracts/evm: python3 -I runs/2026-11-01-zether-msm-mutation.py [first] [last].

It edits the source in place, so it refuses to start unless that file matches git and takes a lock for the whole run: two runs at
once read each other's mutants as the original and restore those (seen 2026-11-01, a mutant was left in src)."""
import fcntl, re, subprocess, sys

SRC = 'src/zether/ZetherVerifier.sol'
ALONE = r'test_eachTransferEquationAloneRefused\(\)'
E3 = '''for (uint256 i; i < 3; ++i) _term(x.f, slots[i], x.w, s[i], x.r);
        x.w = mulmod(x.w, x.rho, x.r);'''
E4 = '''for (uint256 i; i < 4; ++i) _term(x.f, slots[i], x.w, s[i], x.r);
        x.w = mulmod(x.w, x.rho, x.r);'''


def drop3(off):
    return [(E3, f'''uint256 wAt = x.w; if (slots[2] == SLOT_EXT + {off}) x.w = 0;
        for (uint256 i; i < 3; ++i) _term(x.f, slots[i], x.w, s[i], x.r);
        x.w = mulmod(wAt, x.rho, x.r);''')]


def drop4(off):
    return [(E4, f'''uint256 wAt = x.w; if (slots[3] == SLOT_EXT + {off}) x.w = 0;
        for (uint256 i; i < 4; ++i) _term(x.f, slots[i], x.w, s[i], x.r);
        x.w = mulmod(wAt, x.rho, x.r);''')]


ROWS = [
    ('rho constant: every weight 1', [('x.rho = _rho(x.st, x.pr);', 'x.rho = 1;')], 'test_cancellingPairRefused'),
    ('rho skips the proof bytes', [('T.absorb(st, "fold.proof", proof)', 'T.absorb(st, "fold.proof", new bytes(proof.length & 0))')],
     'test_cancellingPairRefused'),
    ('no rho == 0 check', [('if (b.rho == 0 || rangeProofs.length', 'if (rangeProofs.length')], 'test_zeroRhoRefused'),
    ('E3-form weight does not advance', [(E3, E3.split('\n')[0])], ALONE),
    ('z canonical check removed', [('ok = v < x.r;', 'ok = true;')], 'test_nonCanonicalScalarRejected'),
    ('BP scalar canonical check removed', [('if (b.sc[i] >= b.r) return (false, st);', '')], 'test_mutatedSolidityRows'),
    ('A of each proof left out of the MSM', [('_copy(pts, b.at * b.p, b.pr, 0, 16 * b.p);', '_copy(pts, (b.at + 1) * b.p, b.pr, b.p, 15 * b.p);')],
     'test_everyTransferPointReachesTheMsm'),
    ('T2 term dropped', [('_term(b.f, b.at + 3, w, _negS(mulmod(b.x, b.x, r), r), r);', '')], 'test_pointCountPerForm'),
    ('E1 dropped from the fold', drop3(2), ALONE),
    ('E2 dropped from the fold', drop3(3), ALONE),
    ('E3 dropped from the fold', drop4(4), ALONE),
    ('E4 dropped from the fold', drop4(5), ALONE),
    ('E5 dropped from the fold', [
        ('''uint256 r = x.r;
        _term(x.f, SLOT_G, x.w, addmod(zb,''', '''uint256 r = x.r;
        uint256 wAt = x.w; x.w = 0;
        _term(x.f, SLOT_G, x.w, addmod(zb,'''),
        ('''_term(x.f, slots[4], x.w, r - 1, r);
        x.w = mulmod(x.w, x.rho, r);''', '''_term(x.f, slots[4], x.w, r - 1, r);
        x.w = mulmod(wAt, x.rho, r);''')], ALONE),
    ('E6 dropped from the fold', drop4(7), ALONE),
    ('E7 dropped from the fold', drop4(8), ALONE),
    ('E8 dropped from the fold', drop4(9), ALONE),
    ('BP-1 dropped from the fold', [
        ('''uint256 w = b.wt;
        uint256 z2 = mulmod(b.z, b.z, r);
        uint256 sumY;''', '''uint256 w = 0;
        uint256 z2 = mulmod(b.z, b.z, r);
        uint256 sumY;'''),
        ('''_term(b.f, b.at + 3, w, _negS(mulmod(b.x, b.x, r), r), r);
        b.wt = mulmod(w, b.rho, r);''', '''_term(b.f, b.at + 3, w, _negS(mulmod(b.x, b.x, r), r), r);
        b.wt = mulmod(b.wt, b.rho, r);''')], 'test_firstBpOneAloneRefused'),
    ('BP-2 dropped from the fold', [
        ('''uint256 w = b.wt;
        uint256 a = b.at;''', '''uint256 w = 0; b.wt = 0;
        uint256 a = b.at;''')], 'test_eachBpTwoAloneRefused'),
]


def run(pat):
    p = subprocess.run(['../../scripts/capped', 'forge', 'test', '--match-path', 'test/zether/*.t.sol', '--match-test', pat],
                       capture_output=True, text=True)
    out = p.stdout + p.stderr
    if 'Compiler run failed' in out:
        return 'COMPILE ERROR', False
    ran = sum(int(n) for n in re.findall(r'^Ran (\d+) tests? for', out, re.M))
    fail = sorted(set(re.findall(r'^\[FAIL[^\n]*\] (\w+)', out, re.M)))
    if ran == 0:
        return 'NO TEST RAN', False
    return (f'RED ({ran} ran): ' + ', '.join(fail)[:80], True) if fail else (f'still GREEN ({ran} ran)', False)


lock = open('/tmp/zether-msm-mutation.lock', 'w')
try:
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit('another mutation run holds the lock')
if subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--', SRC]).returncode != 0:
    sys.exit(f'{SRC} differs from HEAD: commit it first, a mutation run must start from a known source')
orig = open(SRC, encoding='utf8').read()
first, last = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) > 2 else (0, len(ROWS))
bad = 0
try:
    for name, edits, pat in ROWS[first:last]:
        s = orig
        for a, b in edits:
            assert a in s, name
            s = s.replace(a, b, 1)
        open(SRC, 'w', encoding='utf8').write(s)
        msg, ok = run(pat)
        bad += not ok
        print(f'{name:40s} {msg}', flush=True)
finally:
    open(SRC, 'w', encoding='utf8').write(orig)
print('surprises:', bad)
sys.exit(1 if bad else 0)
