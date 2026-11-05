#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T4 (plan step 6): one mutant at a time on the T4 tree. `t4_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t4_mutants.sh` runs test/merge and test/zether after
each and restores `src` with `git checkout -- src`. `--list` prints the names. The plan's four, in its order."""
import sys

L = 'src/zether/ZetherLayer.sol'
LIB = 'src/zether/ZetherLib.sol'
UA_BINDING = ('        return keccak256(abi.encode(ZetherLib.TAG_UA_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch,\n'
              '            m.nonce, m.validUntil, m.mode, r, m.fee, f));\n')
MUT = {
    # the UA tag swapped for the address tag on one merged entry (`mtxUnshield`; the view follows, the tests' formula not)
    'ua-tag-swapped-on-unshield': [(L, UA_BINDING,
        '        return keccak256(abi.encode(bytes4(m.data) == IZetherToken.mtxUnshield.selector ? ZetherLib.TAG_ENVELOPE\n'
        '            : ZetherLib.TAG_UA_ENVELOPE, block.chainid, CHAIN_UID, address(this), m.from, m.batch,\n'
        '            m.nonce, m.validUntil, m.mode, r, m.fee, f));\n')],
    # the binding computed over the address `from` (the id's low 160 bits): equal for a native, wrong for a derived id
    'binding-over-address-from': [(L, UA_BINDING,
        '        return keccak256(abi.encode(ZetherLib.TAG_UA_ENVELOPE, block.chainid, CHAIN_UID, address(this),\n'
        '            address(uint160(uint256(m.from))), m.batch, m.nonce, m.validUntil, m.mode, r, m.fee, f));\n')],
    # `msg.sender` read inside `ZetherLib` instead of the passed subject (the token itself inside the self-call)
    'msg-sender-in-zetherlib': [(LIB,
        '        emit IConfidentialToken.Shielded(ZetherTypes.UA.unwrap(ua), from, amount, s.acct[ua].pendingSeq);\n',
        '        emit IConfidentialToken.Shielded(ZetherTypes.UA.unwrap(ua), msg.sender, amount, s.acct[ua].pendingSeq);\n')],
    # a return-data word dropped in the DELEGATECALL into the library (`_lib`'s reply one word short)
    'return-word-dropped': [(L,
        '            mstore(r, returndatasize())\n',
        '            mstore(r, sub(returndatasize(), 32))\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
