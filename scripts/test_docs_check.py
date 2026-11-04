#!/usr/bin/env python3
"""Self-test for docs_check.py: a temp docs tree with one entry, one doc, one alias (plan §3.4)."""
import subprocess, sys, tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / 'docs_check.py'
ENTRY = """# Decisions

### NODE-JOB-01 — Idempotency key
- old: R91 · status: current · owner: no · date: 2026-10-06 · normative: node/job-api.md#NODE-JOB-01 · superseded-by: —

**Why.** Retries never duplicate.
"""
DOC = '# Job API\n\n<a id="NODE-JOB-01"></a>**NODE-JOB-01** — Every job carries an idempotency key.\n\nSee [NODE-JOB-01](job-api.md#NODE-JOB-01) and [decisions](../decisions.md#node-job-01--idempotency-key).\n'


def tree(doc=DOC):
    root = Path(tempfile.mkdtemp())
    (root / 'history').mkdir()
    (root / 'node').mkdir()
    (root / 'history' / 'ruling-ids.txt').write_text('R91\thistory/specs/x.md:1\n')
    (root / 'decisions.md').write_text(ENTRY)
    (root / 'node' / 'job-api.md').write_text(doc)
    run(root, '--write')
    return root


def run(root, *args):
    return subprocess.run([sys.executable, str(SCRIPT), '--docs', str(root), *args], capture_output=True, text=True)


def check(root):
    return run(root, 'check')


def main():
    r = check(tree())
    assert r.returncode == 0, r.stdout + r.stderr
    r = check(tree(DOC.replace('<a id="NODE-JOB-01"></a>', '')))
    assert r.returncode == 1 and 'C2' in r.stdout, r.stdout
    r = check(tree(DOC + '\nThe old rule R91 said so.\n'))
    assert r.returncode == 1 and 'C4' in r.stdout, r.stdout
    r = check(tree(DOC + '\nOur Odoo client does this.\n'))
    assert r.returncode == 1 and 'C9' in r.stdout, r.stdout
    r = check(tree(DOC + '\n[x](missing.md)\n'))
    assert r.returncode == 1 and 'C6' in r.stdout, r.stdout
    r = check(tree(DOC + '\n```\n┌──┐\n│ x │──►\n└──┘\n```\n'))
    assert r.returncode == 1 and 'C11' in r.stdout, r.stdout
    r = check(tree(DOC + '\n```text\n┌──┐\n│ x │──►\n└──┘\n```\n'))
    assert r.returncode == 0, r.stdout
    root = tree()
    assert 'NODE-JOB-01' in run(root, 'resolve', 'R91').stdout
    # paths: the repo is the parent of --docs; only tracked files count, legacy/ is exempt
    repo = Path(tempfile.mkdtemp())
    (repo / 'x' / 'legacy').mkdir(parents=True)
    (repo / 'docs').mkdir()
    home = '/ho' + 'me/someone/'                       # split: this file must pass the check itself
    (repo / 'ok.txt').write_text('built in <repo>/x and ~/usr/Qt\n')
    (repo / 'x' / 'legacy' / 'old.txt').write_text(home + 'w\n')
    (repo / 'untracked.txt').write_text(home + 'w\n')
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    subprocess.run(['git', '-C', str(repo), 'add', 'ok.txt', 'x/legacy/old.txt'], check=True)
    r = run(repo / 'docs', 'paths')
    assert r.returncode == 0, r.stdout
    for planted in (home + 'w/scaas/runs/a.txt', '/tm' + 'p/claude-1000/s/scratchpad', '/Use' + 'rs/someone/x'):
        (repo / 'log.txt').write_text('line one\nCompiling (' + planted + ')\n')
        subprocess.run(['git', '-C', str(repo), 'add', 'log.txt'], check=True)
        r = run(repo / 'docs', 'paths')
        assert r.returncode == 1 and 'log.txt:2: machine path' in r.stdout and 'legacy' not in r.stdout, r.stdout
    sys.path.insert(0, str(SCRIPT.parent))
    import docs_check as dc
    assert dc.expand('7.1–7.3, 9') == {'7.1', '7.2', '7.3', '9'} and dc.expand('10.0–10.x') == {'10'}
    assert dc.norm_num('3,000,000') == dc.norm_num('3 000 000') == '3000000' and dc.norm_num('2⁵⁴') == '2^54'
    print('test_docs_check: ok')


if __name__ == '__main__':
    main()
