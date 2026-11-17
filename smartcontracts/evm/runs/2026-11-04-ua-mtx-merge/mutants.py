#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T0 of the ua*/mtx* merge plan: one mutant at a time on M (ported from the spike's merge-harness/mutants.py, anchors
moved to today's code; two new: R17 and the Q2 cancel's lane). `mutants.py <name>` from smartcontracts/evm applies one;
then `FOUNDRY_TEST=test/merge forge test --match-path test/merge/MergedEntry.t.sol`; restore with `git checkout -- src`.
`mutants.py --list` prints the names. A mutant whose anchor is missing fails (it would test nothing).
"""
import sys

PIPE = 'src/metatx/MtxPipelineLib.sol'
UAB = 'src/metatx/UAMetaTxBase.sol'
CANCEL = '        MetaTxLib.UAMetaTransaction memory m = _uaMetaOf(e, abi.encodeCall(this.cancelNonce, (lane)));\n'
MUT = {
    'native-on-ua-list': (PIPE, 'if (ua && !UAKinds.inNativeSpace(e.from) && (f.len < 4 || !f.uaAllowed))',
                          'if (ua && (f.len < 4 || !f.uaAllowed))'),
    'derived-off-ua-list': (PIPE, 'if (ua && !UAKinds.inNativeSpace(e.from) && (f.len < 4 || !f.uaAllowed))',
                            'if (ua && f.len < 4)'),
    'no-signature-check': (PIPE, '        if (!SigCheck.isValid(a, digest, auth, _erc1271Gas(c, a))) revert IMetaTx.MetaTxBadSignature();\n', ''),
    'no-receiver-check': (PIPE, '        if (kind == 0) revert IUALedger.UANotRegistered(to);\n', ''),
    'registry-for-every-receiver': (PIPE, '    function _checkTo(address registry, bytes32 to) internal view {\n',
                                    '    function _checkTo(address registry, bytes32 to) internal view {\n'
                                    '        if (registry == address(0)) revert IUALedger.UALedgerOff();\n'),
    'registry-read-for-native': (PIPE, '    function _checkTo(address registry, bytes32 to) internal view {\n',
                                 '    function _checkTo(address registry, bytes32 to) internal view {\n'
                                 '        if (registry != address(0)) IUARegistry(registry).kindOf(to);\n'),
    'cancel-refuses-native': (UAB, CANCEL, '        if (UAKinds.inNativeSpace(e.from)) revert IUALedger.UAKindNotAccepted(e.from, 0);\n' + CANCEL),
    'no-ua-credit': ('src/metatx/ERC20MetaTx.sol', '        if (toUA) _ua().balance[to] += value;\n', ''),
    'r17-off': (PIPE, '        if (auth.keyData.length != 0 || auth.members.length != 0) revert IMetaTx.MetaTxBadSignature();\n', ''),
    'cancel-wrong-lane': (UAB, '_bumpNonce(e.from, lane)', '_bumpNonce(e.from, e.batch)'),
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
path, a, b = MUT[sys.argv[1]]
s = open(path).read()
assert s.count(a) == 1, (sys.argv[1], s.count(a))
open(path, 'w').write(s.replace(a, b, 1))
