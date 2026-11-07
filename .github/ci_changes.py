# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Which CI jobs a run needs: one output per job, "true" when a changed path starts with one of its prefixes.

A push (to main), a change to .github/, or a failed diff runs every job. Prefixes are the job's own directory plus every
directory its tests read (vectors, contracts, ua-rs for the wrappers); when in doubt a prefix is wider, never narrower.
`docs` runs on every pull request: it reads ids in code comments too.
A path no component test reads starts no component job, only `docs`: Markdown anywhere, and everything under a `runs/`
directory (evidence logs, one-off scripts, probe data: the owner's machine runs them, CI does not). A `runs/` file a test
does read is named in RUNS_READ with the jobs that read it.

A group is forced on, whatever the paths, by a pull-request label `ci-full-<group>` / `ci-full` (env LABELS, a JSON list)
or by a manual run (workflow_dispatch, env FULL = the chosen `ci-full-<group>` / `ci-full`); a manual run has no diff,
so it runs only that group plus `docs`.
"""
import json
import os
import subprocess

# Each on-chain family: its own directory, the shared build/test scripts and the cross-language vectors.
SC = ['smartcontracts/scripts/', 'smartcontracts/vectors/']
# the root rust-toolchain.toml: the one Rust toolchain of every crate (ARCH-POS-12)
RT = ['rust-toolchain.toml']
# ua-rs and every crate it builds (ua-rs-sign T18): scaas-ct, zether-prover (the Zether facade), pqz-ffi, pqzl, pqz-stmt, Ligero
# and the parameter sets (the PQZ facade, MD-5); a job over ua-rs reads them all
UARS = ['clients/ua-rs/', 'clients/scaas-ct/', 'clients/zether-prover/', 'pqz-core/ffi/', 'pqz-core/pqzl/', 'pqz-core/stmt/',
        'pqz-core/pqzh/', 'pqz-core/params/'] + RT
JOBS = {
    'contract-evm': ['smartcontracts/evm/'] + SC + ['pqz-core/params/', 'scripts/size_gate.py', 'scripts/evm_libs.sh'],
    'contract-soroban': ['smartcontracts/soroban/'] + SC + RT,
    'contract-solana': ['smartcontracts/solana/'] + SC + RT,
    'contract-near': ['smartcontracts/near/'] + SC + RT,
    'contract-algorand': ['smartcontracts/algorand/'] + SC,
    # smartcontracts/move/ holds only aptos/ and sui/, nothing shared; a shared file there gets its prefix in both
    'contract-aptos': ['smartcontracts/move/aptos/'] + SC,
    'contract-sui': ['smartcontracts/move/sui/'] + SC,
    'contract-cosmos': ['smartcontracts/cosmos/'] + SC + RT,
    'contract-ton': ['smartcontracts/ton/'] + SC,
    'node': ['scaas-node/', 'clients/ua-rs/', 'smartcontracts/'] + RT,
    'docs': [''],
    'clientkeys': ['clients/clientkeys/', 'smartcontracts/', 'scaas-node/src/'],
    # the directories the pqz job builds and tests (pqzl, ffi, stmt, pqzh/ligero, params, fuzz); pqz-core/nethermind/ (chain
    # scripts, the C# plugin), artifact/, glic/, research/, runs/ and the top-level gate scripts are run on the owner's machine
    'pqz': ['pqz-core/pqzl/', 'pqz-core/ffi/', 'pqz-core/stmt/', 'pqz-core/pqzh/', 'pqz-core/params/', 'pqz-core/fuzz/',
            'smartcontracts/vectors/pqz/'] + RT,
    'zether-prover': ['clients/zether-prover/', 'clients/scaas-ct/', 'smartcontracts/evm/', 'smartcontracts/vectors/'] + RT,
    'ua-rs': UARS + ['smartcontracts/'],
    'ua-cxx': ['clients/ua-cxx/', 'smartcontracts/vectors/'] + UARS,
    'ua-c': ['clients/ua-c/', 'smartcontracts/vectors/'] + UARS,
    'ua-qt': ['clients/ua-qt/', 'smartcontracts/vectors/', 'smartcontracts/near/', 'smartcontracts/algorand/'] + UARS,
    # ua-py, ua-go, ua-cs load libscaas_ua_c (the wallet surface, MD-3): the job builds clients/ua-c first
    'ua-py': ['clients/ua-py/', 'clients/ua-c/', 'smartcontracts/vectors/'] + UARS,
    'ua-go': ['clients/ua-go/', 'clients/ua-c/', 'smartcontracts/vectors/', 'smartcontracts/evm/'] + UARS,
    'ua-cs': ['clients/ua-cs/', 'clients/ua-c/', 'smartcontracts/vectors/'] + UARS,
    'ua-dart-frb': ['clients/ua-dart-frb/', 'smartcontracts/vectors/'] + UARS,
    # every lockfile over ua-rs (cargo tree --locked); cargo deny and cargo audit of ua-rs, ua-c, zether-prover (clients/ua-rs/deny.toml)
    'ua-deps': ['clients/', 'pqz-core/ffi/', 'pqz-core/pqzl/', 'pqz-core/stmt/', 'pqz-core/pqzh/', 'scaas-node/Cargo.toml',
                'scaas-node/Cargo.lock'] + RT,
    'ua-dart': ['clients/ua-dart/', 'smartcontracts/vectors/', 'smartcontracts/evm/'],
    # ARCH-POS-13 (ua-rs-sign T15c2): no test feature in a production artifact; every manifest that can reach scaas-ua,
    # zether-prover or pqz-ffi
    'test-features': ['clients/', 'pqz-core/ffi/', 'scaas-node/Cargo.toml', 'scripts/check_test_features.py'] + RT,
}
# ci-full-<group>: the jobs a label or a manual run forces on; ci-full: every job.
GROUPS = {
    'ci-full-contracts': [j for j in JOBS if j.startswith('contract-')],
    'ci-full-node': ['node'],
    'ci-full-clients': ['clientkeys', 'zether-prover', 'test-features'] + [j for j in JOBS if j.startswith('ua-')],
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


# the runs/ files a CI test reads (found by grep of the tests for reads of runs/ paths, 2026-11-04), with the jobs reading them
RUNS_READ = {
    'smartcontracts/evm/runs/2026-10-27-metatx-split-node-floor.txt': ['node'],  # guard.rs erc1271_floor_covers_forge_minimum
}


def read_by_tests(p):
    """False for a path no component test reads: Markdown, or anything under a `runs/` directory not in RUNS_READ."""
    if p.endswith('.md'):
        return False
    return not ('/runs/' in f'/{p}')


def needed(paths, forced=()):
    """paths None: every job. forced: group names (labels or the manual choice) ORed in. `docs` (prefix '') sees every
    path; the other jobs only the paths a test reads."""
    on = {j for g in forced for j in GROUPS.get(g, ())}
    code = None if paths is None else [p for p in paths if read_by_tests(p)]
    read = set() if paths is None else {j for p in paths for j in RUNS_READ.get(p, ())}
    return {job: paths is None or job in on or job in read
            or any(p.startswith(x) for p in (paths if job == 'docs' else code) for x in prefixes)
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
    assert needed(['pqz-core/fuzz/run.sh']) == {j: j in ('pqz', 'docs') for j in JOBS}
    for p in ('pqz-core/ffi/src/x.rs', 'pqz-core/stmt/src/x.rs', 'pqz-core/pqzh/ligero/src/x.rs', 'pqz-core/fuzz/run.sh'):
        assert needed([p])['pqz'], p
    for p in ('pqz-core/nethermind/chain/patch-chainspec.py', 'pqz-core/nethermind/Nethermind.Pqz/X.cs', 'pqz-core/gate.sh',
              'pqz-core/artifact/results.py', 'pqz-core/glic/absence.sh'):
        assert not needed([p])['pqz'], p  # chain scripts, plugin, local gates: not read by the pqz job
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
                                              'ua-go', 'ua-cs', 'ua-dart-frb', 'ua-dart', 'test-features', 'ua-deps'}
    assert all(needed(['docs/x.md'], ['ci-full']).values())
    assert needed(['docs/x.md'], ['bug', 'ci-full-node']) == needed(['docs/x.md'], ['ci-full-node'])  # other labels ignored
    assert needed([''], ['ci-full-pqz']) == {j: j in ('pqz', 'docs') for j in JOBS}  # manual run
    # Markdown and everything under runs/ start only `docs`; code beside them still counts
    only_docs = {j: j == 'docs' for j in JOBS}
    for p in ('scaas-node/runs/2026-11-01-x.txt', 'smartcontracts/evm/runs/a/b.log', 'pqz-core/sv/runs/g.jsonl',
              'pqz-core/README.md', 'smartcontracts/evm/src/README.md', 'runs/top.txt'):
        assert needed([p]) == only_docs, p
    for p in ('smartcontracts/evm/runs/2026-11-04-gov-smoke-7622.sh', 'pqz-core/ffi/vectors/runs/probe/kat.json',
              'pqz-core/nethermind/runs/2026-11-04-mldsa87-probe.py', 'smartcontracts/evm/runs/x/Probe.t.sol'):
        assert needed([p]) == only_docs, p  # one-off scripts and probe data under runs/
    for p, js in RUNS_READ.items():  # a runs/ file a test reads starts exactly its readers (and docs)
        assert needed([p]) == {j: j == 'docs' or j in js for j in JOBS}, p
    assert {j for j, r in needed(['rust-toolchain.toml']).items() if r} == {
        'docs', 'contract-soroban', 'contract-solana', 'contract-near', 'contract-cosmos', 'node', 'pqz', 'zether-prover',
        'ua-rs', 'ua-cxx', 'ua-c', 'ua-qt', 'ua-dart-frb', 'test-features', 'ua-py', 'ua-go', 'ua-cs', 'ua-deps'}
    # ua-rs-sign T18: every job over ua-rs reads the crates ua-rs builds; the bindings over libscaas_ua_c read ua-c and ua-rs
    over = ['ua-rs', 'ua-c', 'ua-cxx', 'ua-qt', 'ua-dart-frb', 'ua-py', 'ua-go', 'ua-cs']
    for p in ('pqz-core/ffi/src/lib.rs', 'pqz-core/pqzl/rust/src/lib.rs', 'pqz-core/pqzl/x.c', 'pqz-core/stmt/src/lib.rs',
              'pqz-core/pqzh/ligero/src/x.rs', 'pqz-core/params/sets/a', 'clients/zether-prover/src/api.rs',
              'clients/scaas-ct/src/lib.rs'):
        assert all(needed([p])[j] for j in over), p
    for p in ('clients/ua-rs/src/lib.rs', 'clients/ua-c/src/lib.rs'):
        assert all(needed([p])[j] for j in ('ua-py', 'ua-go', 'ua-cs', 'ua-deps')), p
    assert not any(needed(['pqz-core/fuzz/run.sh'])[j] for j in over)  # a directory only the pqz job reads
    assert needed(['clients/scaas-ct/src/lib.rs'])['zether-prover'] and needed(['scaas-node/Cargo.lock'])['ua-deps']
    assert not needed(['scaas-node/src/main.rs'])['ua-deps'] and not needed(['clients/ua-py/x.py'])['ua-c']
    assert needed(['smartcontracts/evm/foundry.txt'])['contract-evm']  # a .txt outside runs/ counts
    assert needed(['scaas-node/runs/a.txt', 'scaas-node/src/x.rs'])['node']
    assert needed(['smartcontracts/evm/runs/a.txt'], ['ci-full-contracts'])['contract-evm']  # a label still forces
    main()
