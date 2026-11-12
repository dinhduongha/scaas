# Mutant runner (from smartcontracts/evm): python3 runs/2026-11-12-rescue-vault/mutants.py <spec.json> <out.json>. Each mutant
# (id, file, old, new, path, test) is applied, forge runs under scripts/capped, the file is restored. Killed = rc != 0.
import json, os, subprocess, sys, shutil
EVM = '.'; spec = json.load(open(sys.argv[1])); out = sys.argv[2]
env = dict(os.environ, PATH=os.path.expanduser('~/.foundry/bin') + ':' + os.environ['PATH'], CAPPED_SLOTS='3')
res = []
for m in spec:
    p = os.path.join(EVM, m['file']); orig = open(p).read()
    assert orig.count(m['old']) == 1, (m['id'], 'old not unique')
    open(p, 'w').write(orig.replace(m['old'], m['new']))
    try:
        cmd = ['../../scripts/capped', 'forge', 'test', '--match-path', m['path'], '-j', '1']
        if m.get('test'): cmd += ['--match-test', m['test']]
        r = subprocess.run(cmd, cwd=EVM, env=env, capture_output=True, text=True)
        log = r.stdout + r.stderr
        compiled = 'Compiler run failed' not in log and 'Error (' not in log
        killed = r.returncode != 0
        line = next((l for l in log.splitlines() if l.startswith('[FAIL')), '')[:160]
        res.append(dict(id=m['id'], killed=killed, compiled=compiled, first_fail=line))
        print(m['id'], 'KILLED' if killed else 'SURVIVED', '' if compiled else '(compile error)', line, flush=True)
    finally:
        open(p, 'w').write(orig)
json.dump(res, open(out, 'w'), indent=1)
print('killed', sum(r['killed'] for r in res), '/', len(res))
