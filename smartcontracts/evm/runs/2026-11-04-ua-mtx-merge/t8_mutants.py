#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T8 (plan step 5): one mutant at a time on the T8 tree. `t8_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t8_mutants.sh` runs the Hedera suites and the other
HIP-632 readers after each and restores `src` with `git checkout -- src`. `--list` prints the names. The plan's three, in
its order; the two signature checks (`_authorizeNative` on the merged entries, `_requireSignature` on
`executeMetaTransaction`) each take the HIP-632 and the 65-byte mutant on their own row."""
import sys

LIB = 'src/metatx/MtxPipelineLib.sol'
UA_SEAT = '        if (c.hedera && auth.length == 64 && !SigCheck.isContract(a)) return HederaLib.requireValid(a, digest, auth);\n'
ADDR_SEAT = '        if (c.hedera && sig.length == 64 && !SigCheck.isContract(from)) return HederaLib.requireValid(from, digest, sig);\n'
MUT = {
    # HIP-632 accepted for an account with code (the merged entries' native branch)
    'hip632-for-code': [(LIB, UA_SEAT,
        '        if (c.hedera && auth.length == 64) return HederaLib.requireValid(a, digest, auth);\n')],
    # the same on the address path (`executeMetaTransaction`)
    'hip632-for-code-address-path': [(LIB, ADDR_SEAT,
        '        if (c.hedera && sig.length == 64) return HederaLib.requireValid(from, digest, sig);\n')],
    # the long-zero padding reversed: the account read from the id's high 20 bytes instead of its low 20
    'long-zero-padding-reversed': [(LIB,
        '        address a = address(uint160(uint256(from)));\n',
        '        address a = address(uint160(uint256(from) >> 96));\n')],
    # a 65-byte (ECDSA) signature taken down the HIP-632 branch (the merged entries)
    '65-byte-down-hip632': [(LIB, UA_SEAT,
        '        if (c.hedera && auth.length >= 64 && !SigCheck.isContract(a)) return HederaLib.requireValid(a, digest, auth);\n')],
    # the same on the address path
    '65-byte-down-hip632-address-path': [(LIB, ADDR_SEAT,
        '        if (c.hedera && sig.length >= 64 && !SigCheck.isContract(from)) return HederaLib.requireValid(from, digest, sig);\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
