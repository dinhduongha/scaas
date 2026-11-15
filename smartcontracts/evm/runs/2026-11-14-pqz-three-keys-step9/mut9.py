#!/usr/bin/env python3
"""Step 9 mutants (spec §14.12, Fable round review): apply one edit, run the named test(s) (they must FAIL), restore. Resumable:
done lines in mut9.txt are skipped. Covers the round's late code (registry P3-1/P3-2, the mark path P3-3, the invariants M1-M5
over the skip semantics, the ROLL_MAX pin) beside step 4's 33 (mut4.txt, all killed).
usage (from smartcontracts/evm): python3 <this> [name ...]"""
import os, subprocess, sys
OUT = os.path.join(os.path.dirname(__file__), 'mut9.txt')
LOG = os.path.join(os.path.dirname(__file__), 'mut')
C, S, A = 'src/pqz/PqzCore.sol', 'src/pqz/PqzStateLib.sol', 'src/ua/UARegistryAuxLib.sol'
INV = 'test/pqz/invariant/PqzMarkInvariants.t.sol'
TK = 'test/pqz/PqzThreeKeys.t.sol'
SK = 'test/ua/PqzScopedKeys.t.sol'
M = [
 # the skip semantics under the invariants (M1-M5): each must turn the invariant suite red
 ('inv-skip-adds', C, '            if (skipped) continue; // CTR-PQZ-41', '            // mutant', INV, ''),
 ('inv-mark-lost', S, '            a.pending[skip[j]] = x | PqzCore.SKIP;', '            a.pending[skip[j]] = x;', INV, ''),
 ('inv-mark-extra', S, '            a.pending[skip[j]] = x | PqzCore.SKIP;',
  '            a.pending[skip[j]] = x | PqzCore.SKIP; if (skip[j] + 1 < a.pendingCount) a.pending[skip[j] + 1] |= PqzCore.SKIP;', INV, ''),
 ('inv-rollseq', S, '        a.rollSeq += 1;\n', '        if (n != 0) a.rollSeq += 1;\n', INV, ''),
 ('inv-entry-mask', S, '        uint256 e = a.pending[uint64(i)] & ~PqzCore.SKIP;', '        uint256 e = a.pending[uint64(i)];', INV, ''),
 # P3-3: no second event
 ('p33-second-event', S, '            if (x & PqzCore.SKIP != 0) continue; // already marked: no second `PqzSkipped` (Fable P3-3)\n', '',
  TK, 'test_roll_secondMarkNoEvent'),
 # P3-1 / P3-2: the registry's scope reads
 ('p31-own-word', A, 'if (!ok || own != 1 || w > 1)', 'if (!ok || w > 1)', SK, 'test_class3_scopeMustOwnItsKey_longAnswerRead'),
 ('p31-short', A, 'ok := and(ok, iszero(lt(returndatasize(), add(OPENING_WORD, 32))))', 'ok := ok', SK, 'test_class3_scopeNotAnswering_refused'),
 ('p32-other-set', A, 'if (proven || scope != address(0) || key.length == PqzSet.PK)', 'if (proven || key.length == PqzSet.PK)', SK,
  'test_class3_otherSet_becomesCurrent'),
 ('p32-scope0', A, 'if (proven || scope != address(0) || key.length == PqzSet.PK)', 'if (true)', SK, 'test_class3_otherSet_becomesCurrent'),
]
done = open(OUT).read().split('\n') if os.path.exists(OUT) else []
want = sys.argv[1:]
os.makedirs(LOG, exist_ok=True)
for name, f, old, new, path, test in M:
    if want and name not in want: continue
    if any(l.startswith(name + ' |') for l in done): print('skip', name); continue
    src = open(f).read()
    if src.count(old) != 1:
        print(name, '| NOT APPLIED (pattern count %d)' % src.count(old), flush=True); continue
    open(f, 'w').write(src.replace(old, new))
    try:
        print(f'start {name}', flush=True)
        cmd = ['../../scripts/capped', os.path.expanduser('~/.foundry/bin/forge'), 'test', '-j', '1', '--match-path', path]
        if test: cmd += ['--match-test', test]
        with open(os.path.join(LOG, 'm9-' + name + '.log'), 'w') as lg:
            rc = subprocess.call(cmd, stdout=lg, stderr=subprocess.STDOUT, env=dict(os.environ, CAPPED_SLOTS=os.environ.get('CAPPED_SLOTS', '4')))
        txt = open(os.path.join(LOG, 'm9-' + name + '.log')).read()
        ran = 'Suite result' in txt
        res = 'COMPILE-ERROR' if 'Compiler run failed' in txt else ('KILLED' if rc != 0 and ran else ('SURVIVED' if ran else 'NO-RUN'))
    finally:
        open(f, 'w').write(src)
    line = f'{name} | {res} | {path} {test}'
    print(line, flush=True)
    open(OUT, 'a').write(line + '\n')
