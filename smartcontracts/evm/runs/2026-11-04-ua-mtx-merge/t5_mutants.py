#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T5 (plan step 6): one mutant at a time on the T5 tree. `t5_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t5_mutants.sh` runs test/merge and test/pqz after each
and restores `src` with `git checkout -- src`. `--list` prints the names. The plan's three in its order (the third on
`PqzStateLib`: `PqzWrappedLib` reads no subject, see the T5 summary), then the binding over the address `from`."""
import sys

L = 'src/pqz/PqzLayer.sol'
UA_BINDING = ('        return keccak256(abi.encode(PqzCore.TAG_UA_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch,\n'
              '            m.nonce, m.validUntil, m.mode, r, m.fee, f));\n')
MUT = {
    # the UA tag swapped for the address tag on the merged entries' binding (and so the view)
    'ua-tag-swapped-for-address-tag': [(L, UA_BINDING, UA_BINDING.replace('PqzCore.TAG_UA_ENVELOPE', 'PqzCore.TAG_ENVELOPE'))],
    # `PqzCore`'s UA tag constant changed (the tests compute the spec's string)
    'pqzcore-ua-tag-changed': [('src/pqz/PqzCore.sol', 'keccak256("SCAAS-PQZ-UA-ENVELOPE-V1")', 'keccak256("SCAAS-PQZ-UA-ENVELOPE-V2")')],
    # `msg.sender` read inside the shield library (DELEGATECALL: the token's caller) instead of the passed subject
    'msg-sender-in-pqzstatelib-shield': [('src/pqz/PqzStateLib.sol', '        PqzCore._trivial(ua, amount, from);\n',
                                          '        PqzCore._trivial(ua, amount, msg.sender);\n')],
    # the binding computed over the address `from` (the id's low 160 bits): equal for a native, wrong for a derived id
    'binding-over-address-from': [(L, UA_BINDING,
        '        return keccak256(abi.encode(PqzCore.TAG_UA_ENVELOPE, block.chainid, CHAIN_UID, address(this),\n'
        '            address(uint160(uint256(m.from))), m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f));\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
