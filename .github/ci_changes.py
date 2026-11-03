# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Which CI jobs a pull request needs: one output per job, "true" when a changed path starts with one of its prefixes.

A push (to main), a change to .github/, or a failed diff runs every job. Prefixes are the job's own directory plus every
directory its tests read (vectors, contracts, ua-rs for the wrappers); when in doubt a prefix is wider, never narrower.
`docs` runs on every pull request: it reads ids in code comments too.
"""
import os
import subprocess

JOBS = {
    'contracts': ['smartcontracts/evm/', 'smartcontracts/vectors/', 'pqz-core/params/', 'scripts/size_gate.py', 'scripts/evm_libs.sh'],
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
    'near': ['smartcontracts/near/', 'smartcontracts/scripts/', 'smartcontracts/vectors/'],
    'algorand': ['smartcontracts/algorand/', 'smartcontracts/scripts/', 'smartcontracts/vectors/'],
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


def needed(paths):
    return {job: paths is None or any(p.startswith(x) for p in paths for x in prefixes) for job, prefixes in JOBS.items()}


def main():
    out = needed(changed())
    with open(os.environ.get('GITHUB_OUTPUT', '/dev/stdout'), 'a') as f:
        for job, run in out.items():
            f.write(f"{job.replace('-', '_')}={'true' if run else 'false'}\n")
    print(' '.join(j for j, r in out.items() if r) or 'no job')


if __name__ == '__main__':
    assert all(needed(None).values())
    assert needed(['pqz-core/pqzl/x.c']) == {j: j in ('pqz', 'docs') for j in JOBS}
    assert needed(['clients/ua-rs/src/lib.rs'])['ua-c'] and not needed(['clients/ua-py/x.py'])['pqz']
    assert needed(['smartcontracts/vectors/ua/nested.json'])['ua-py'] and needed(['smartcontracts/vectors/pqz/a'])['pqz']
    main()
