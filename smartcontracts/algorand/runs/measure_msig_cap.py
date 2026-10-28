#!/usr/bin/env python3
"""MSIG_MAX_MEMBERS derivation (T12 fix 1, Ruling T12-budget): build the apps with a cap of UPTO members, tabulate every
group shape for all-passkey n-of-n msigs n = 1…UPTO (tests/test_account.py::test_msig_cap_fits_limits with
SCAAS_MSIG_MEASURE), restore contracts/account.py from memory and rebuild. Run on a live localnet under scripts/capped."""
import os
import re
import subprocess
import sys

R = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = os.path.join(R, 'contracts', 'account.py')
UPTO = int(sys.argv[1]) if len(sys.argv) > 1 else 4
BUILD = ('rm -rf out && .venv/bin/puyapy contracts --out-dir "$PWD/out" --output-bytecode --no-output-teal '
         '--no-output-source-map >/dev/null')


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, cwd=R, text=True, **kw)


src = open(A).read()
assert len(re.findall(r'^MSIG_MAX_MEMBERS = \d+$', src, re.M)) == 1
try:
    open(A, 'w').write(re.sub(r'^MSIG_MAX_MEMBERS = \d+$', 'MSIG_MAX_MEMBERS = %d' % UPTO, src, flags=re.M))
    assert sh(BUILD).returncode == 0
    r = sh('.venv/bin/python -m pytest -q -s -p no:cacheprovider -W ignore::DeprecationWarning '
           'tests/test_account.py::test_msig_cap_fits_limits', capture_output=True,
           env={**os.environ, 'SCAAS_MSIG_MEASURE': str(UPTO)})
    out = [ln for ln in r.stdout.splitlines() if ln.startswith(('msig ', 'S3_MAX'))]
    print('\n'.join(out) if out else r.stdout[-3000:])
finally:
    open(A, 'w').write(src)
    print('account.py restored; rebuilt rc=%d' % sh(BUILD).returncode)
