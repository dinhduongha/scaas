#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T10 (plan step 5): one mutant at a time on the T10 tree. `t10_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t10_mutants.sh` runs the deploy suites after each and
restores `script` with `git checkout -- script`. `--list` prints the names. The plan's four, in its order, then one more:
the declared public gate ignored (the testnet formula on every chain)."""
import sys

DB = 'script/DeployBase.sol'
ASK = '        uint256 asked = (regular + state) * 105 / 100;\n'
MUT = {
    # the public gate on a block's gas_used (EIP-8037: max(regular, state), accounting, not inclusion)
    'public-gate-on-gas-used': [(DB, ASK,
        '        uint256 asked = (regular > state ? regular : state) * 105 / 100;\n')],
    # x 1.05 dropped (the deploy asks --gas-estimate-multiplier 105)
    'x105-dropped': [(DB, ASK, '        uint256 asked = regular + state;\n')],
    # the regular-part check (regular x 1.05 < 2^24, EIP-7825) dropped
    'regular-check-dropped': [(DB,
        '        if (regular * 105 / 100 >= TX_REGULAR_GAS_CAP) {\n',
        '        if (false) {\n')],
    # the testnet formula changed: runtime x 1,530 without the 2^24 regular part
    'testnet-formula-changed': [(DB,
        '        return _baselineRuntime(name) * STATE_GAS_PER_BYTE + TX_REGULAR_GAS_CAP;\n',
        '        return _baselineRuntime(name) * STATE_GAS_PER_BYTE;\n')],
    # the declared public gate ignored: the testnet formula on every chain
    'public-gate-ignored': [(DB,
        '        if (!_publicGate()) return _requireReleaseGas(name);\n',
        '        return _requireReleaseGas(name);\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
