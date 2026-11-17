#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T32 (bit 22 `operatorTransfer`, the router's eight regulated controls): one mutant at a time on the T32
tree. `t32_mutants.py <name>` from smartcontracts/evm applies one (every edit's anchor must be found exactly once, and the
edit must change something); `run_t32_mutants.sh` runs the T32 suites after each and restores `src` with `git checkout`.
`--list` prints the names. The plan's step 5 rows (adapted from `moderatedTransfer` to `operatorTransfer`, CTR-GOV-20)
first, then the controller's, then this task's own. The node row (`a router row on the token domain`) is the shell's last
step: it edits `scaas-node/src/typed.rs` and runs the two node tests that read it."""
import sys

L = 'src/regulated/RegulatedLib.sol'
R = 'src/regulated/RegulatedBase.sol'
GB = 'src/governance/GovernanceBits.sol'
RB = 'src/governance/GovernanceRouterBase.sol'
GR = 'src/governance/GovernanceRouter.sol'

USE = '        GovernanceUse.use(GovernanceBits.OPERATOR_TRANSFER, subject, amount);\n'
AMT = '        if (amount == 0) revert IRegulatedToken.AmountZero();\n'
REFC = '        if (ref == 0) revert IRegulatedToken.RefRequired();\n'
CODE = '            || (UAKinds.inNativeSpace(from) && address(uint160(uint256(from))).code.length != 0))'
FROM = '        if (from == 0 || from == to || _pool(from)\n'
TO = '        if (to == 0 || _pool(to)) revert IRegulatedToken.OperatorTargetRefused(to);\n'
CHECKTO = '        MtxPipelineLib._checkTo(uaRegistry, to);\n'
EMIT = '        emit IRegulatedToken.OperatorTransfer(from, to, amount, ref);\n'
STUB = '''        RegulatedLib.operatorTransfer(from, to, amount, ref, _govSubject(), _REGISTRY);
        _uaMove(from, to, amount);
    }
'''
TS = '0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521506'  # scaas.pqz + 6: totalShielded
ZS = '0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce01'  # scaas.zether + 1: shieldScale
SIGNED = '        return bytes.concat(bytes32(uint256(uint160(target))), words);'
OPSEL = 'IRegulatedToken.operatorTransfer.selector, abi.encode(account, to, amount, ref)'
FT = '"UAForceTransfer(bytes32 from,address target,bytes32 recordId,uint256 amount,'

MUT = {
    # ------------------------------------------------------------------ plan T32 step 5, adapted (CTR-GOV-20)
    'op-on-poolmove': [(R, STUB, STUB.replace('_uaMove(from, to, amount)', '_poolMove(from, to, amount)'))],
    'from-with-code-accepted': [(L, CODE, '            )')],
    'target-out-of-digest': [(RB, SIGNED, '        target;\n        return words;')],
    # 'router-row-on-token-domain' is the node's: run_t32_mutants.sh
    # ------------------------------------------------------------------ the controller's
    'limited-window-not-enforced': [(L, USE, USE.replace('subject, amount)', 'subject, 0)'))],
    # a plain kind taking bit 22: the plain normal kinds' mask (`NORMAL_BITS`) gains it
    'plain-kind-accepts-bit22': [(GB, 'NORMAL_BITS = ', 'NORMAL_BITS = (1 << 22) | ')],
    'bit21-given-the-body': [(L, USE, USE.replace('OPERATOR_TRANSFER', 'MODERATE'))],
    'bit21-moderated-entry': [(R, STUB, STUB + '''
    function moderatedTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref) external nonReentrant {
        RegulatedLib.operatorTransfer(from, to, amount, ref, _govSubject(), _REGISTRY);
        _uaMove(from, to, amount);
    }
''')],
    # an `sstore(x, sload(x))` is removed by the optimizer (T30): the write changes the value, the read feeds a branch
    'op-writes-pqz-state': [(L, EMIT, EMIT + '        assembly { sstore(' + TS + ', add(sload(' + TS + '), 1)) }\n')],
    'op-reads-pqz-state': [(L, EMIT, EMIT + '        assembly { if eq(sload(' + TS + '), 0x5ca1ab1e) { revert(0, 0) } }\n')],
    'op-writes-zether-state': [(L, EMIT, EMIT + '        assembly { sstore(' + ZS + ', add(sload(' + ZS + '), 1)) }\n')],
    'op-reads-zether-state': [(L, EMIT, EMIT + '        assembly { if eq(sload(' + ZS + '), 0x5ca1ab1e) { revert(0, 0) } }\n')],
    # ------------------------------------------------------------------ this task's own
    'amount-zero-accepted': [(L, USE + AMT, USE)],
    'ref-zero-accepted': [(L, AMT + REFC, AMT)],
    'self-move-accepted': [(L, FROM, FROM.replace(' || from == to', ''))],
    'from-pool-accepted': [(L, FROM, FROM.replace(' || _pool(from)', ''))],
    'to-pool-accepted': [(L, TO, '')],
    'checkto-dropped': [(L, CHECKTO, '')],
    'event-dropped': [(L, EMIT, '')],
    'router-op-wrong-selector': [(GR, OPSEL, OPSEL.replace('operatorTransfer.selector', 'forceTransfer.selector'))],
    'router-typehash-fields-swapped': [(RB, FT, FT.replace('bytes32 recordId,uint256 amount', 'uint256 amount,bytes32 recordId'))],
}


def main():
    if sys.argv[1] == '--list':
        print('\n'.join(MUT))
        return
    for path, old, new in MUT[sys.argv[1]]:
        s = open(path).read()
        if s.count(old) != 1:
            sys.exit('%s: anchor found %d times in %s' % (sys.argv[1], s.count(old), path))
        if new == old:
            sys.exit('%s: the edit changes nothing in %s' % (sys.argv[1], path))
        open(path, 'w').write(s.replace(old, new))


if __name__ == '__main__':
    main()
