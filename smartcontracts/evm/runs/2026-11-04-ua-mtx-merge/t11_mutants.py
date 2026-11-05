#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T11 (plan step 5): one mutant at a time on clientkeys' src/evm.js, the vectors fixed. `t11_mutants.py <name>`
from clients/clientkeys applies one (every edit's anchor must be found exactly once); `run_t11_mutants.sh` runs
typed-ops.test.js and evm.test.js after each and restores src/evm.js with `git checkout -- src/evm.js` (clean checked first).
`--list` prints the names. The plan's five, in its order."""
import sys

EVM = 'src/evm.js'
MUT = {
    # a field order swapped in one UA<Op> string (UASetPayee: payee before token)
    'uasetpayee-field-order-swapped': [(EVM,
        "  UASetPayee: { fields: 'address token,bytes32 payee,bool allowed', on: WALLET },\n",
        "  UASetPayee: { fields: 'bytes32 payee,address token,bool allowed', on: WALLET },\n")],
    # relayer left non-zero while unbound (canonical() no longer zeroes it without mode bit 1)
    'relayer-unbound-not-zeroed': [(EVM,
        '      if (!(BigInt(m.mode) & 1n)) m.relayer = ZERO_ADDRESS;\n',
        '')],
    # the router domain used for a token row (NormalToken signed under 'SCaaS GovernanceRouter')
    'token-row-in-router-domain': [(EVM,
        "const DOMAIN_OF = { NormalToken: 'SCaaS MetaToken',",
        "const DOMAIN_OF = { NormalToken: 'SCaaS GovernanceRouter',")],
    # a wallet row signed in the token domain (MandateWallet under 'SCaaS MetaToken')
    'wallet-row-in-token-domain': [(EVM,
        "  MandateWallet: 'SCaaS MandateWallet',",
        "  MandateWallet: 'SCaaS MetaToken',")],
    # payee encoded as address in UAPayUnderMandate
    'payunder-payee-as-address': [(EVM,
        "  UAPayUnderMandate: { fields: 'address token,bytes32 payee,",
        "  UAPayUnderMandate: { fields: 'address token,address payee,")],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
