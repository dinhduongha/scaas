#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T7 (plan step 6): one mutant at a time on the T7 tree. `t7_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t7_mutants.sh` runs test/merge, then the governance
suites and `TypedOps.t`, after each and restores `src` with `git checkout -- src`. `--list` prints the names. The plan's
four in its order."""
import sys

GRB = 'src/governance/GovernanceRouterBase.sol'
MUT = {
    # `target` left out of the signed struct (a zero word in its place)
    'target-out-of-digest': [(GRB,
        '        return bytes.concat(bytes32(uint256(uint160(target))), words);\n',
        '        return bytes.concat(bytes32(0), words);\n')],
    # the subject the target reads is the submitter, not the signer
    'subject-from-msg-sender': [(GRB,
        '        _call(e.from, target, data);\n',
        '        _call(MetaTxLib.pad(msg.sender), target, data);\n')],
    # the router's `mtxBatch` refusal dropped: the base's generic batch runs
    'generic-refusal-dropped-on-mtxBatch': [(GRB,
        '    function mtxBatch(MetaTxLib.UAMetaTransaction[] calldata, IUARegistry.UASig[] calldata)\n'
        '        public pure override returns (bool)\n'
        '    {\n'
        '        revert MtxSelectorNotAllowed(bytes4(0));\n'
        '    }\n\n', '')],
    # the cancel unordered: the lane check takes a stale nonce (the cancel shares the pipeline's one nonce check)
    'cancel-unordered': [('src/metatx/MtxPipelineLib.sol',
        'if (expected != nonce) revert IMetaTx.MetaTxBadNonce(expected, nonce);',
        'if (expected < nonce) revert IMetaTx.MetaTxBadNonce(expected, nonce);')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
