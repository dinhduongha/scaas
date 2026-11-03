# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Which CI jobs a run needs: one output per job, "true" when a changed path starts with one of its prefixes.

A push (to main), a change to .github/, or a failed diff runs every job. Prefixes are the job's own directory plus every
directory its tests read (vectors, contracts, ua-rs for the wrappers); when in doubt a prefix is wider, never narrower.
`docs` runs on every pull request: it reads ids in code comments too.

A group is forced on, whatever the paths, by a pull-request label `ci-full-<group>` / `ci-full` (env LABELS, a JSON list)
or by a manual run (workflow_dispatch, env FULL = the chosen `ci-full-<group>` / `ci-full`); a manual run has no diff,
so it runs only that group plus `docs`.
"""
import json
import os
import subprocess

# Each on-chain family: its own directory, the shared build/test scripts and the cross-language vectors.
SC = ['smartcontracts/scripts/', 'smartcontracts/vectors/']
JOBS = {
    'contract-evm': ['smartcontracts/evm/'] + SC + ['pqz-core/params/', 'scripts/size_gate.py', 'scripts/evm_libs.sh'],
    'contract-soroban': ['smartcontracts/soroban/'] + SC,
    'contract-solana': ['smartcontracts/solana/'] + SC,
    'contract-near': ['smartcontracts/near/'] + SC,
    'contract-algorand': ['smartcontracts/algorand/'] + SC,
    # smartcontracts/move/ holds only aptos/ and sui/, nothing shared; a shared file there gets its prefix in both
    'contract-aptos': ['smartcontracts/move/aptos/'] + SC,
    'contract-sui': ['smartcontracts/move/sui/'] + SC,
    'contract-cosmos': ['smartcontracts/cosmos/'] + SC,
    'contract-ton': ['smartcontracts/ton/'] + SC,
    'node': ['scaas-node/', 'clients/ua-rs/', 'smartcontracts/'],
    'docs': [''],
    'clientkeys': ['clients/clientkeys/', 'smartcontracts/', 'scaas-node/src/'],
    'pqz': ['pqz-core/', 'smartcontracts/vectors/pqz/'],
    'zether-prover': ['clients/zether-prover/', 'smartcontracts/evm/', 'smartcontracts/vectors/'],
    'ua-rs': ['clients/ua-rs/', 'smartcontracts/'],
    'ua-cxx': ['clients/ua-cxx/', 'clients/ua-rs/', 'smartcontracts/vectors/'],
    'ua-c': ['clients/ua-c/', 'clients/ua-rs/', 'smartcontracts/vectors/'],
    'ua-qt': ['clients/ua-qt/', 'clients/ua-rs/', 'smartcontracts/vectors/', 'smartcontracts/near/', 'smartcontracts/algorand/'],
    'ua-py': ['clients/ua-py/', 'smartcontracts/vectors/'],
    'ua-go': ['clients/ua-go/', 'smartcontracts/vectors/', 'smartcontracts/evm/'],
    'ua-cs': ['clients/ua-cs/', 'smartcontracts/vectors/'],
    'ua-dart-frb': ['clients/ua-dart-frb/', 'clients/ua-rs/', 'smartcontracts/vectors/'],
    'ua-dart': ['clients/ua-dart/', 'smartcontracts/vectors/', 'smartcontracts/evm/'],
}
# ci-full-<group>: the jobs a label or a manual run forces on; ci-full: every job.
GROUPS = {
    'ci-full-contracts': [j for j in JOBS if j.startswith('contract-')],
    'ci-full-node': ['node'],
    'ci-full-clients': ['clientkeys', 'zether-prover'] + [j for j in JOBS if j.startswith('ua-')],
    'ci-full-pqz': ['pqz'],
    'ci-full': list(JOBS),
}


def changed():
    """The pull request's paths, or None: run everything."""
    if os.environ.get('EVENT') != 'pull_request' or not os.environ.get('BASE'):
        return None
    r = subprocess.run(['git', 'diff', '--name-only', os.environ['BASE'], 'HEAD'], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    paths = [p for p in r.stdout.splitlines() if p]
    return None if any(p.startswith('.github/') for p in paths) else paths


def needed(paths, forced=()):
    """paths None: every job. forced: group names (labels or the manual choice) ORed in."""
    on = {j for g in forced for j in GROUPS.get(g, ())}
    return {job: paths is None or job in on or any(p.startswith(x) for p in paths for x in prefixes)
            for job, prefixes in JOBS.items()}


def main():
    if os.environ.get('EVENT') == 'workflow_dispatch':
        out = needed([''], [os.environ.get('FULL', '')])  # no diff: only `docs` (prefix '') and the chosen group
    else:
        out = needed(changed(), json.loads(os.environ.get('LABELS') or 'null') or [])
    with open(os.environ.get('GITHUB_OUTPUT', '/dev/stdout'), 'a') as f:
        for job, run in out.items():
            f.write(f"{job.replace('-', '_')}={'true' if run else 'false'}\n")
    print(' '.join(j for j, r in out.items() if r) or 'no job')


if __name__ == '__main__':
    assert all(needed(None).values())
    assert needed(['pqz-core/pqzl/x.c']) == {j: j in ('pqz', 'docs') for j in JOBS}
    assert needed(['clients/ua-rs/src/lib.rs'])['ua-c'] and not needed(['clients/ua-py/x.py'])['pqz']
    assert needed(['smartcontracts/vectors/ua/nested.json'])['ua-py'] and needed(['smartcontracts/vectors/pqz/a'])['pqz']
    # each family: its own directory runs its job and no other family's; shared scripts and vectors run them all
    for fam, d in [('evm', 'evm'), ('soroban', 'soroban'), ('solana', 'solana'), ('near', 'near'), ('algorand', 'algorand'),
                   ('aptos', 'move/aptos'), ('sui', 'move/sui'), ('cosmos', 'cosmos'), ('ton', 'ton')]:
        r = needed([f'smartcontracts/{d}/x'])
        assert [j for j in r if j.startswith('contract-') and r[j]] == [f'contract-{fam}'], fam
    assert all(needed(['pqz-core/params/sets/a'])[j] for j in ('contract-evm', 'pqz'))
    for p in ('smartcontracts/scripts/test.sh', 'smartcontracts/vectors/metatx/paymeta.json'):
        assert all(needed([p])[j] for j in GROUPS['ci-full-contracts']), p
    # groups: a label on a docs-only pull request runs `docs` and that group, nothing else
    for g, js in GROUPS.items():
        assert needed(['docs/x.md'], [g]) == {j: j == 'docs' or j in js for j in JOBS}, g
    assert set(GROUPS['ci-full-contracts']) == {f'contract-{f}' for f in
                                                'evm soroban solana near algorand aptos sui cosmos ton'.split()}
    assert set(GROUPS['ci-full-clients']) == {'clientkeys', 'zether-prover', 'ua-rs', 'ua-cxx', 'ua-c', 'ua-qt', 'ua-py',
                                              'ua-go', 'ua-cs', 'ua-dart-frb', 'ua-dart'}
    assert all(needed(['docs/x.md'], ['ci-full']).values())
    assert needed(['docs/x.md'], ['bug', 'ci-full-node']) == needed(['docs/x.md'], ['ci-full-node'])  # other labels ignored
    assert needed([''], ['ci-full-pqz']) == {j: j in ('pqz', 'docs') for j in JOBS}  # manual run
    main()
