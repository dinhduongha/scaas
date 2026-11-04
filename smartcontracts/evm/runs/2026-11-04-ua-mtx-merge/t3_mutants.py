#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T3 (plan step 6): one mutant at a time on the T3 tree. `t3_mutants.py <name>` from smartcontracts/evm
applies one (a mutant may edit more than one file: every edit's anchor must be found exactly once); `run_t3_mutants.sh`
runs test/merge after each and restores `src` with `git checkout -- src`. `--list` prints the names. The plan's four."""
import sys

LIB = 'src/metatx/WrappedLib.sol'
TOK = 'src/metatx/ERC20MetaTx.sol'
WT = 'src/metatx/WrappedToken.sol'
IWT = 'src/metatx/IWrappedToken.sol'
MUT = {
    # C: `IUALedger` asked of every leg in `mtxWrapOrder`, a native holder's too
    'ledger-asked-of-every-leg': [(LIB,
        '        if (!UAKinds.inNativeSpace(o.from) && !ERC165Checker.supportsInterface(u, type(IUALedger).interfaceId)) {\n',
        '        if (!ERC165Checker.supportsInterface(u, type(IUALedger).interfaceId)) {\n')],
    # CTR-GOV-12: the hybrid's cap skipped on `mtxWrapOrder` (its quote, `_sigQuote`)
    'cap-skipped-on-wrap-order': [(LIB,
        '        if (L.capped) _cap(supply, minted);\n        fee = Math.mulDiv(minted, feePpm, 1_000_000, Math.Rounding.Ceil);\n',
        '        fee = Math.mulDiv(minted, feePpm, 1_000_000, Math.Rounding.Ceil);\n')],
    # `mtxUnwrapToUA` accepting a native receiver: the leg's one receiver rule for every `…ToUA` lets a native id through
    'unwrap-to-ua-native-receiver': [(TOK, '        if (UAKinds.inNativeSpace(to)) revert UANotRegistered(to);\n', '')],
    # a no-twin entry moved onto `UAEnvelope` + `UASig` (`mtxWrap`; the interface with it, so the tree compiles)
    'no-twin-wrap-on-ua-envelope': [
        (WT, '''    function mtxWrap(MetaTxLib.Envelope calldata e, uint256 amount, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(WRAP_TYPEHASH, SEL_WRAP, e, abi.encode(amount), sig);
    }
''', '''    function mtxWrap(MetaTxLib.UAEnvelope calldata e, uint256 amount, IUARegistry.UASig calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _namedUA(WRAP_TYPEHASH, SEL_WRAP, e, abi.encode(amount), sig);
    }
'''),
        (IWT, '    function mtxWrap(MetaTxLib.Envelope calldata e, uint256 amount, bytes calldata sig) external returns (bytes memory);\n',
         '    function mtxWrap(MetaTxLib.UAEnvelope calldata e, uint256 amount, IUARegistry.UASig calldata sig)\n'
         '        external returns (bytes memory);\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
