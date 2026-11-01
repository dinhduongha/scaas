#!/usr/bin/python3 -I
"""zether-msm: prove the merged-check tests can fail. Each row removes a check or a weight from the verifier, runs the tests
named for it and expects red, then restores the source. A row that runs no test is an error, not a pass.
Run from smartcontracts/evm: python3 -I runs/2026-11-01-zether-msm-mutation.py [first] [last].

It edits the source in place, so it refuses to start unless that file matches git and takes a lock for the whole run: two runs at
once read each other's mutants as the original and restore those (seen 2026-11-01, a mutant was left in src)."""
import fcntl, re, subprocess, sys

SRC = 'src/zether/ZetherVerifier.sol'
ALONE = r'test_eachTransferEquationAloneRefused\(\)'
BURN = 'test_eachBurnEquationAloneRefused'
MULTI = 'test_eachMultiEquationAloneRefused'
RANGE = 'test_rangeEquationsAloneRefused'
AUD = 'test_auditorOffFieldsRefused'
LEG = 'test_auditorOffLegFieldsRefused'
RHO_RANGE = 'test_verifyRangeRhoHashesCommitmentAndProof'
CORPUS = 'test_s3TransferSigma'
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
        b.wt = mulmod(b.wt, b.rho, r);''')], RANGE),
    ('BP-2 dropped from the fold', [
        ('''uint256 w = b.wt;
        uint256 a = b.at;''', '''uint256 w = 0; b.wt = 0;
        uint256 a = b.at;''')], r'test_(eachBpTwoAloneRefused|verifyRange|rangeEquationsAloneRefused)'),
    ('second BP: BP-1 dropped', [
        ('''uint256 w = b.wt;
        uint256 z2 = mulmod(b.z, b.z, r);
        uint256 sumY;''', '''uint256 w = b.at == sigmaEnd(b) ? b.wt : 0;
        uint256 z2 = mulmod(b.z, b.z, r);
        uint256 sumY;'''),
        ('''_term(b.f, b.at + 3, w, _negS(mulmod(b.x, b.x, r), r), r);
        b.wt = mulmod(w, b.rho, r);''', '''_term(b.f, b.at + 3, w, _negS(mulmod(b.x, b.x, r), r), r);
        b.wt = mulmod(b.wt, b.rho, r);'''),
        ('''    struct BP {''', '''    function sigmaEnd(BP memory b) private pure returns (uint256) { return b.f.length - 32; }

    struct BP {''')], RANGE),
    ('no-auditor E7 dropped', drop4(8), 'test_eachTransferEquationAloneRefused_noAuditor'),
    ('burn E1 dropped', drop3(1), BURN),
    ('burn E5 dropped', drop4(2), BURN),
    ('burn E8 dropped', drop4(3), BURN),
    ('multi E3_0 dropped', drop4(7), MULTI),
    ('multi E6_0 dropped', drop4(8), MULTI),
    ('multi E6p_1 dropped', drop3(14), MULTI),
    ('multi E7_1 dropped', drop4(15), MULTI),
    ('multi E4 dropped', drop4(3), MULTI),
    ('multi E8 dropped', drop4(5), MULTI),
    ('first caller point not in the MSM', [('_copy(pts, SLOT_EXT * b.p, sigma.points, 0, sigma.points.length);',
                                            '_copy(pts, (SLOT_EXT + 1) * b.p, sigma.points, b.p, sigma.points.length - b.p);')], r'test_every(Transfer|Burn|Multi)Point'),
    ('A_Vv and A_Vb out of the MSM', [('_copy(pts, SLOT_EXT * b.p, sigma.points, 0, sigma.points.length);',
                                       '_copy(pts, SLOT_EXT * b.p, sigma.points, 0, sigma.points.length); _put(pts, SLOT_EXT + 8, new bytes(b.p), b.p); _put(pts, SLOT_EXT + 9, new bytes(b.p), b.p);')],
     'test_lowOrderPairAcrossEquationsRefused'),
    ('zero-scalar slots dropped from the MSM', [('return (_isZero(_msm(pts, b.f)), st);',
                                                 'for (uint256 i; i < b.f.length; ++i) if (b.f[i] == 0) _put(pts, i, new bytes(b.p), b.p);\n        return (_isZero(_msm(pts, b.f)), st);')],
     'test_zeroScalarSlotStillChecked'),
    ('wrong modulus in _term', [('f[slot] = addmod(f[slot], mulmod(w, s, r), r);', 'f[slot] = addmod(f[slot], mulmod(w, s, r), r - 2);')],
     'test_sharedGeneratorsAddModR'),
    # the weights: every advance of a power, and where the range proofs pick it up
    ('BP-1 and BP-2 of a proof share a weight', [('''_term(b.f, b.at + 3, w, _negS(mulmod(b.x, b.x, r), r), r);
        b.wt = mulmod(w, b.rho, r);''', '_term(b.f, b.at + 3, w, _negS(mulmod(b.x, b.x, r), r), r);')], RANGE),
    ('BP-2 of proof k, BP-1 of k+1 share one', [('''_term(b.f, a + 5 + 2 * j, w, mulmod(b.uInv[j], b.uInv[j], r), r);
        }
        b.wt = mulmod(w, b.rho, r);''', '''_term(b.f, a + 5 + 2 * j, w, mulmod(b.uInv[j], b.uInv[j], r), r);
        }''')], RANGE),
    ('E4-form weight does not advance', [(E4, E4.split('\n')[0])], ALONE),
    ('E5 weight does not advance', [('''_term(x.f, slots[4], x.w, r - 1, r);
        x.w = mulmod(x.w, x.rho, r);''', '_term(x.f, slots[4], x.w, r - 1, r);')], ALONE),
    ('range weights restart at 1', [('b.wt = sigma.weight;', 'b.wt = 1;')], RANGE),
    # auditor off: each field's own check, on rows proved for the junk they carry
    ('C_aud O check removed', [('if (!_isZero(_sp(x, 8)) || !_isZero(_pf(x, 7))) return false;', 'if (!_isZero(_pf(x, 7))) return false;')], AUD),
    ('A_aud O check removed', [('if (!_isZero(_sp(x, 8)) || !_isZero(_pf(x, 7))) return false;', 'if (!_isZero(_sp(x, 8))) return false;')], AUD),
    ('z_tj zero check removed', [('return zt == 0 && _isZero(_lp(x, j, 2))', 'return _isZero(_lp(x, j, 2))')], LEG),
    ('C_aud_j O check removed', [('_isZero(_lp(x, j, 2)) && _isZero(_lp(x, j, 3))', '_isZero(_lp(x, j, 3))')], LEG),
    ('D_aud_j O check removed', [('_isZero(_lp(x, j, 2)) && _isZero(_lp(x, j, 3))', '_isZero(_lp(x, j, 2))')], LEG),
    ('A_aud_j O check removed', [('''&& _isZero(_pf(x, 6 + 5 * j + 2))
                && _isZero(_pf(x, 6 + 5 * j + 3));''', '&& _isZero(_pf(x, 6 + 5 * j + 3));')], LEG),
    ('A_Daud_j O check removed', [('''&& _isZero(_pf(x, 6 + 5 * j + 2))
                && _isZero(_pf(x, 6 + 5 * j + 3));''', '&& _isZero(_pf(x, 6 + 5 * j + 2));')], LEG),
    # verifyRange's rho
    ('verifyRange rho misses the proof', [('_rho(st, bytes.concat(V, proof))', '_rho(st, V)')], RHO_RANGE),
    ('verifyRange rho misses V', [('_rho(st, bytes.concat(V, proof))', '_rho(st, proof)')], RHO_RANGE),
    # a refusal by revert: BadPoint on a bad point, nothing else
    ('a Panic in place of BadPoint', [('_copy(pts, SLOT_EXT * b.p, sigma.points, 0, sigma.points.length);',
                                       '_copy(pts, SLOT_EXT * b.p, sigma.points, 0, sigma.points.length); assert(_valid(_slice(sigma.points, 0, b.p)));')],
     CORPUS),
    ('BadPoint on a row of valid points', [('return (_isZero(_msm(pts, b.f)), st);',
                                            'if (!_isZero(_msm(pts, b.f))) revert G1Bls12381.BadPoint();\n        return (true, st);')], CORPUS),
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
    return (f'RED ({ran} ran): ' + ', '.join(fail), True) if fail else (f'still GREEN ({ran} ran)', False)


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
