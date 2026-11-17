#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T25 (plan step 5): one mutant at a time on the T25 tree. `t25_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t25_mutants.sh` runs `test/as/RegConfig.t.sol` and the
factory suites after each and restores `src` with `git checkout -- src`. `--list` prints the names. The plan's two first
(`reg` ignored on a plain kind; `PqzWrappedLib` back on the fixed masks), then each `requireRegOfKind` call site alone, the
same fixed masks in `ZetherWrappedLib`, and the fixed kind in `ZetherLib.initNormal`."""
import sys

IF = 'src/factory/IFactoryToken.sol'
MB = 'src/metatx/MetaTokenBase.sol'
ZL = 'src/zether/ZetherLib.sol'
ZW = 'src/zether/ZetherWrappedLib.sol'
PW = 'src/pqz/PqzWrappedLib.sol'
FIXED_IMPORTS = ('import {WrappedLib} from "../metatx/WrappedLib.sol";\n',
                 'import {WrappedLib} from "../metatx/WrappedLib.sol";\nimport {GovernanceBits} from "../governance/GovernanceBits.sol";\n'
                 'import {TokenStore} from "../metatx/TokenStore.sol";\n')
MUT = {
    # `reg` ignored on a plain kind: the shared check never refuses
    'reg-ignored-on-plain': [(IF,
        '|| r.deniedFlags != 0 || r.termsHash != 0)) revert IFactoryToken.ConfigFieldForOtherKind(6);',
        '|| r.deniedFlags != 0 || r.termsHash != 0)) {}')],
    # `PqzWrappedLib` back on the fixed kind id and `WRAPPED_*` masks
    'pqz-fixed-masks': [(PW, *FIXED_IMPORTS), (PW,
        'WrappedLib.initToken(cfg, false, kind, valid, roleBits, contractOnly, registry);',
        'WrappedLib.initToken(cfg, false, TokenStore.KIND_WRAPPED_PQZ, GovernanceBits.WRAPPED_BITS,\n'
        '            GovernanceBits.WRAPPED_ROLES, GovernanceBits.WRAPPED_CONTRACT_ONLY, registry);')],
    # each call site of the check alone left out
    'reg-unchecked-metatokenbase': [(MB, '        requireRegOfKind(kind(), cfg.reg);\n', '')],
    'reg-unchecked-zether-normal': [(ZL, '        requireRegOfKind(kind, cfg.reg);\n', '')],
    'reg-unchecked-zether-wrapped': [(ZW, '        requireRegOfKind(kind, cfg.reg);\n', '')],
    'reg-unchecked-pqz-wrapped': [(PW, '        requireRegOfKind(kind, cfg.reg);\n', '')],
    # `ZetherWrappedLib` back on the fixed kind id and masks
    'zether-fixed-masks': [(ZW, *FIXED_IMPORTS), (ZW,
        'WrappedLib.initToken(cfg, false, kind, valid, roleBits, contractOnly, registry);',
        'WrappedLib.initToken(cfg, false, TokenStore.KIND_WRAPPED_ZETHER, GovernanceBits.WRAPPED_BITS,\n'
        '            GovernanceBits.WRAPPED_ROLES, GovernanceBits.WRAPPED_CONTRACT_ONLY, registry);')],
    # `ZetherLib.initNormal` writing the fixed kind 2
    'normal-zether-fixed-kind': [(ZL, '        t.kind = kind;\n', '        t.kind = TokenStore.KIND_NORMAL_ZETHER;\n')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
