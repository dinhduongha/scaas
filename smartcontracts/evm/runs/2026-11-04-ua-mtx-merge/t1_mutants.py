#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T1 (plan step 6): one mutant at a time on the T1 tree. `t1_mutants.py <name>` from smartcontracts/evm
applies one; `run_t1_mutants.sh` runs test/merge after each and restores `src` with `git checkout -- src`. `--list` prints
the names. A mutant whose anchor is not found exactly once fails (it would test nothing). The spike's eight first (anchors
moved to T1's code), then T1's own."""
import sys

PIPE = 'src/metatx/MtxPipelineLib.sol'
UAB = 'src/metatx/UAMetaTxBase.sol'
UA_LIST = 'if (ua && !UAKinds.inNativeSpace(e.from) && (f.len < 4 || !f.uaAllowed))'
CANCEL = '        MetaTxLib.UAMetaTransaction memory m = _uaMetaOf(e, abi.encodeCall(IMetaTx.cancelNonce, (lane)));\n'
CHECK_TO = '    function _checkTo(address registry, bytes32 to) internal view {\n'
MUT = {
    # the spike's eight (merge-entries.md §4)
    'native-on-ua-list': (PIPE, UA_LIST, 'if (ua && (f.len < 4 || !f.uaAllowed))'),  # also: `_uaAllowed` read for a native
    'derived-off-ua-list': (PIPE, UA_LIST, 'if (ua && f.len < 4)'),  # also: `_mtxRule` alone read for a derived
    'no-signature-check': (PIPE, '        if (!SigCheck.isValid(a, digest, auth, _erc1271Gas(c, a))) revert IMetaTx.MetaTxBadSignature();\n', ''),
    'no-receiver-check': (PIPE, '        if (kind == 0) revert IUALedger.UANotRegistered(to);\n', ''),
    'registry-for-every-receiver': (PIPE, CHECK_TO, CHECK_TO + '        if (registry == address(0)) revert IUALedger.UALedgerOff();\n'),
    'registry-read-for-native': (PIPE, CHECK_TO, CHECK_TO + '        if (registry != address(0)) IUARegistry(registry).kindOf(to);\n'),
    'cancel-refuses-native': (UAB, CANCEL, '        if (uint256(e.from) >> 160 == 0) revert IUALedger.UAKindNotAccepted(e.from, 0);\n' + CANCEL),
    'no-ua-credit': ('src/metatx/ERC20MetaTx.sol', '        if (toUA) _ua().balance[to] += value;\n', ''),
    # T1's own
    'r17-off': (PIPE, '        if (auth.keyData.length != 0 || auth.members.length != 0) revert IMetaTx.MetaTxBadSignature();\n', ''),
    'derived-ledger-off-guard-dropped': (PIPE, '            if (c.registry == address(0)) revert IUALedger.UALedgerOff();\n', ''),
    'stale-nonce-accepted': (PIPE, 'if (expected != nonce) revert', 'if (expected < nonce) revert'),  # the cancel's nonce check
    'cancel-self-calls-cancelNonce': (UAB, '        emit IUALedger.UANonceCancelled(e.from, lane, _bumpNonce(e.from, lane));\n',
                                      '        _selfCall(e.from, m.data, bytes32(0));\n'),
    'cancel-wrong-lane': (UAB, '_bumpNonce(e.from, lane)', '_bumpNonce(e.from, e.batch)'),
    'canon-binds-relayer-bit-off': (PIPE, '            _canon(e.mode, MetaTxLib.MODE_RESTRICT_RELAYER, e.relayer), e.fee,\n',
                                    '            e.relayer, e.fee,\n'),
    'native-test-from-shr160-lt-2': (PIPE, '        if (!UAKinds.inNativeSpace(from)) {\n', '        if (!(uint256(from) >> 160 < 2)) {\n'),
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
path, a, b = MUT[sys.argv[1]]
s = open(path).read()
assert s.count(a) == 1, (sys.argv[1], s.count(a))
open(path, 'w').write(s.replace(a, b, 1))
