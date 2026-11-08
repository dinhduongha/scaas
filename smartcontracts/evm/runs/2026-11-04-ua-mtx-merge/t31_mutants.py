#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T31 (the regulated PQZ kinds 12 and 13): one mutant at a time on the T31 tree.
`t31_mutants.py <name>` from smartcontracts/evm applies one (every edit's anchor must be found exactly once, and the edit
must change something); `run_t31_mutants.sh` runs the regulated PQZ suites (test/as/confidential/Pqz*) after each and
restores `src` with `git checkout`. `--list` prints the names. The plan's step 5 rows first, then the controller's (a
check after the proof, a ciphertext touched by FORCE, a note or the account read by a regulated check), then this task's
own. PQZ only (Zether != PQZ)."""
import sys

P = 'src/pqz/PqzLayer.sol'
WP = 'src/pqz/WrappedPqzToken.sol'
R = 'src/regulated/RegulatedBase.sol'
N12 = 'src/regulated/NormalPqzRegulatedToken.sol'

CHECKS_T = '''        _regSender(t.fromUA);
        if (t.shieldIn != 0) _regPayer();
        _regName(t.beneficiaryUA);
'''
SINGLE = CHECKS_T + '''        _pullShieldIn(t.shieldIn);
        PqzCore.Paid memory f;
        (r, f) = PqzTransferLib.transfer(e, t, accHint, proof, pqzAuth);
'''
MULTI = CHECKS_T + '''        _pullShieldIn(t.shieldIn);
        PqzCore.Paid memory f;
        (r, f) = PqzTransferLib.transferMulti(e, t, accHint, proof, pqzAuth);
'''
CHECKS_B = '''        if (e.amount != 0) _regSender(b.fromUA); // a refresh (amount 0) names no sender (spec §4.2)
        if (b.shieldIn != 0) _regPayer();
        _regName(b.beneficiaryUA);
'''
BURN = CHECKS_B + '''        _pullShieldIn(b.shieldIn);
        PqzCore.Paid memory f = PqzBurnLib.unshield(e, b, accHint, proof, pqzAuth);
'''
UNSHIELD_R = '        if (amount != 0) _regReceiver(recipient);\n        if (!UAKinds.inNativeSpace(recipient))'
SHIELD = '        _regPayer();\n        PqzStateLib.shield(toUA, amount, _msgSender(), _REGISTRY);'
WRAP_SHIELD = '        _regPayer();\n        address m = _msgSender();\n        (,, uint256 minted) = WrappedLib.wrap('
FORCE = '        MtxPipelineLib._checkTo(_REGISTRY, to);\n        _poolMove(from, to, amount);'
PRE = '        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre(from, sel, mode);'
TS = '0xda865ec17214f25b93cdb133d719c79392c290a4b9089fd0bba156256c521506'  # scaas.pqz + 6: totalShielded


def after_proof(block, checks, proof_line):
    """`block` with its checks moved after the proof's line."""
    return block.replace(checks, '').replace(proof_line, proof_line + checks)


MUT = {
    # ------------------------------------------------------------------ plan T31 step 5
    'shieldin-payer-unchecked-single': [(P, SINGLE, SINGLE.replace('        if (t.shieldIn != 0) _regPayer();\n', '', 1))],
    'shieldin-payer-unchecked-burn': [(P, BURN, BURN.replace('        if (b.shieldIn != 0) _regPayer();\n', ''))],
    'check-after-pullshieldin': [(P, SINGLE, SINGLE.replace(CHECKS_T + '        _pullShieldIn(t.shieldIn);\n',
                                                            '        _pullShieldIn(t.shieldIn);\n' + CHECKS_T))],
    'refresh-refused-under-freeze': [(P, BURN, BURN.replace('if (e.amount != 0) _regSender(b.fromUA);', '_regSender(b.fromUA);'))],
    'r-on-refresh-zero-recipient': [(P, UNSHIELD_R, UNSHIELD_R.replace('if (amount != 0) _regReceiver', '_regReceiver'))],
    # ------------------------------------------------------------------ the controller's
    'check-after-proof-single': [(P, SINGLE, after_proof(SINGLE, CHECKS_T,
                                  '        (r, f) = PqzTransferLib.transfer(e, t, accHint, proof, pqzAuth);\n'))],
    'check-after-proof-multi': [(P, MULTI, after_proof(MULTI, CHECKS_T,
                                 '        (r, f) = PqzTransferLib.transferMulti(e, t, accHint, proof, pqzAuth);\n'))],
    'check-after-proof-burn': [(P, BURN, after_proof(BURN, CHECKS_B,
                                '        PqzCore.Paid memory f = PqzBurnLib.unshield(e, b, accHint, proof, pqzAuth);\n'))],
    # an `sstore(x, sload(x))` is removed by the optimizer (T30's first run): the write changes the value, the read feeds a
    # branch
    'force-writes-pqz-state': [(R, FORCE, FORCE.replace('        _poolMove(', '        assembly { sstore(' + TS + ', add(sload('
                                + TS + '), 1)) }\n        _poolMove('))],
    'force-reads-pqz-state': [(R, FORCE, FORCE.replace('        _poolMove(', '        assembly { if eq(sload(' + TS
                               + '), 0x5ca1ab1e) { revert(0, 0) } }\n        _poolMove('))],
    'leg-note-read-by-check': [(P, MULTI, '        for (uint256 j; j < t.legs.length; ++j) _regSender(t.legs[j].ua);\n' + MULTI)],
    'sender-account-read-by-check': [(P, SINGLE, '        if (PqzCore.$().acct[t.fromUA].sendCounter == type(uint64).max) revert();\n'
                                      + SINGLE)],
    # ------------------------------------------------------------------ this task's own
    'multi-sender-check-dropped': [(P, MULTI, MULTI.replace('        _regSender(t.fromUA);\n', '', 1))],
    'burn-beneficiary-unchecked': [(P, BURN, BURN.replace('        _regName(b.beneficiaryUA);\n', ''))],
    'unshield-recipient-unchecked': [(P, UNSHIELD_R, UNSHIELD_R.replace('        if (amount != 0) _regReceiver(recipient);\n', ''))],
    'shield-payer-unchecked': [(P, SHIELD, SHIELD.replace('        _regPayer();\n', ''))],
    'wrapshield-payer-unchecked': [(WP, WRAP_SHIELD, WRAP_SHIELD.replace('        _regPayer();\n', ''))],
    'k12-pre-row-on-fee-none': [(N12, PRE, '        RegulatedBase._regPre(from, sel, mode);')],
    'k12-pre-row-dropped': [(N12, PRE, '        from; sel; mode;')],
    'k12-allowlist-in-mask': [(N12, 'GovernanceBits.NORMAL_BITS | REG_BITS_CONFIDENTIAL', 'GovernanceBits.NORMAL_BITS | REG_BITS')],
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
