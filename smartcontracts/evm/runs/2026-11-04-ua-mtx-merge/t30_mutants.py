#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T30 (the regulated Zether kinds 10 and 11): one mutant at a time on the T30 tree.
`t30_mutants.py <name>` from smartcontracts/evm applies one (every edit's anchor must be found exactly once);
`run_t30_mutants.sh` runs the regulated Zether suites (test/as/confidential/Zether*) and GovDeploy after each and restores
`src` and `script` with `git checkout`. `--list` prints the names. The plan's step 5 rows first (spec §9 Confidential,
DENYLIST), then the controller's (a check after the proof, a frozen sender passing, a ring member read, a ciphertext
touched by FORCE), then this task's own."""
import sys

Z = 'src/zether/ZetherLayer.sol'
WZ = 'src/zether/WrappedZetherToken.sol'
N = 'src/regulated/NormalZetherRegulatedToken.sol'
W = 'src/regulated/WrappedZetherRegulatedToken.sol'
R = 'src/regulated/RegulatedBase.sol'
P = 'src/pqz/PqzLayer.sol'
D = 'script/DeployBase.sol'

BUNDLE = '''        _regZetherSender(t.yFrom);
        _regName(t.beneficiaryUA);
        return _multi(t.beneficiaryUA, ZetherLib.defaultMode());'''
COMPACT = '''        _regZetherSender(t.yFrom);
        _regName(t.beneficiaryUA);
        return _multi(t.beneficiaryUA, ZetherTypes.TransferMode.HASH);'''
SINGLE = '''        _regZetherSender(t.yFrom);
        _regName(t.beneficiaryUA);
        (bytes32 ref, uint256 fee) = abi.decode(
            _lib(address(ZetherLib), ZetherLib.transferSingle.selector, abi.encode(_env())), (bytes32, uint256));'''
UNSHIELD = '''        _regZetherSender(b.yFrom);
        _regName(b.beneficiaryUA);
        if (amount != 0) _regReceiver(recipient);'''
UNWRAP_TOP = '''        _regZetherSender(b.yFrom);
        _regName(b.beneficiaryUA);
        uint256 i = WrappedLib.indexOf(x.underlying);'''
UNWRAP_PROOF = '''            _lib(address(ZetherWrappedLib), ZetherWrappedLib.unshieldUnwrap.selector, abi.encode(_env())), (uint256));'''
SENDER = '        _regSender(ZetherTypes.UA.unwrap(ZetherLib.uaOf(yFrom)));'
PRE = '        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre(from, sel, mode);'
FORCE = '        MtxPipelineLib._checkTo(_REGISTRY, to);\n        _poolMove(from, to, amount);'
ZSLOT = '0xd1eef6cbeb7b383e0a92b3cb723053d5c39c76707d89da6b14ff91b83198ce04'  # scaas.zether + 4: totalShielded


def both(old, new):
    return [(N, old, new), (W, old, new)]


MUT = {
    # ------------------------------------------------------------------ plan T30 step 5
    'compact-multi-check-dropped': [(Z, COMPACT, COMPACT.replace('        _regZetherSender(t.yFrom);\n', ''))],
    'envelope-subject-as-sender': both(SENDER, '        yFrom;\n        _regSender(_subject());'),
    'check-after-proof-bundle': [(Z, BUNDLE, '''        bytes32 r = _multi(t.beneficiaryUA, ZetherLib.defaultMode());
        _regZetherSender(t.yFrom);
        _regName(t.beneficiaryUA);
        return r;''')],
    'r-on-decoy-leg': [(Z, '        if (f.decoyFee != 0) for (uint256 j; j < f.legs.length; ++j) _fromPool(f.legs[j], f.decoyFee);',
                        '''        if (f.decoyFee != 0) for (uint256 j; j < f.legs.length; ++j) {
            _regReceiver(ZetherTypes.UA.unwrap(f.legs[j]));
            _fromPool(f.legs[j], f.decoyFee);
        }''')],
    'zether-hook-in-pqz-layer': [(P, 'abstract contract PqzLayer is MetaTokenBase, IPqzToken {\n',
                                  'abstract contract PqzLayer is MetaTokenBase, IPqzToken {\n'
                                  '    function _regZetherSender(bytes32 a) internal view virtual { a; }\n')],
    # ------------------------------------------------------------------ the controller's four
    'check-after-proof-single': [(Z, SINGLE, '''        (bytes32 ref, uint256 fee) = abi.decode(
            _lib(address(ZetherLib), ZetherLib.transferSingle.selector, abi.encode(_env())), (bytes32, uint256));
        _regZetherSender(t.yFrom);
        _regName(t.beneficiaryUA);''')],
    'check-after-proof-unshield-unwrap': [(WZ, UNWRAP_TOP, UNWRAP_TOP.replace('        _regZetherSender(b.yFrom);\n', '')),
                                          (WZ, UNWRAP_PROOF, UNWRAP_PROOF + '\n        _regZetherSender(b.yFrom);')],
    'frozen-sender-passes': both(SENDER, '        yFrom;\n        _notPaused();'),
    'ring-member-read': [(Z, BUNDLE, '''        for (uint256 j; j < t.legs.length; ++j) _regSender(ZetherTypes.UA.unwrap(ZetherLib.uaOf(t.legs[j].yTo)));
''' + BUNDLE)],
    # an `sstore(x, sload(x))` is removed by the optimizer (an equivalent mutant, first run): the write changes the value,
    # the read feeds a branch
    'force-writes-zether-state': [(R, FORCE, FORCE.replace('        _poolMove(', '        assembly { sstore(' + ZSLOT + ', add(sload('
                                   + ZSLOT + '), 1)) }\n        _poolMove('))],
    'force-reads-zether-state': [(R, FORCE, FORCE.replace('        _poolMove(', '        assembly { if eq(sload(' + ZSLOT
                                  + '), 0x5ca1ab1e) { revert(0, 0) } }\n        _poolMove('))],
    # ------------------------------------------------------------------ this task's own
    'frozen-beneficiary-passes': [(Z, BUNDLE, BUNDLE.replace('        _regName(t.beneficiaryUA);\n', ''))],
    'unshield-check-dropped': [(Z, UNSHIELD, UNSHIELD.replace('        _regZetherSender(b.yFrom);\n', ''))],
    'unshield-recipient-unchecked': [(Z, UNSHIELD, UNSHIELD.replace('\n        if (amount != 0) _regReceiver(recipient);', ''))],
    'f-on-envelope-from-not-fee-bearing': both(PRE, '        RegulatedBase._regPre(from, sel, mode);'),
    'fee-bearing-pre-row-dropped': both(PRE, '        from; sel; mode;'),
    'shield-payer-unchecked': [(Z, '''        _regPayer();
        address m = _msgSender();
        ZetherLib.shield(ZetherTypes.UA.wrap(toUA), amount, _REGISTRY, m);''', '''        address m = _msgSender();
        ZetherLib.shield(ZetherTypes.UA.wrap(toUA), amount, _REGISTRY, m);''')],
    'deploy-zether-regulated-dropped': [(D, '            _deployZetherRegulated(f, reg, smartKeyAccountImpl, deps);\n', '')],
    'deploy-without-regulatedlib': [(D, '_withRegulatedLib(_zetherLibs(true))', '_zetherLibs(true)')],
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
