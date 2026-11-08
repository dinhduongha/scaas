#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T27 (the regulated skeleton of kinds 9 and 13): one mutant at a time on the T27 tree. `t27_mutants.py <name>`
from smartcontracts/evm applies one (every edit's anchor must be found exactly once); `run_t27_mutants.sh` runs
`test/as/RegulatedSkeleton.t.sol`, `test/governance/GovDeploy.t.sol` and `test/v2/LinkClosure.t.sol` after each and restores
`src` and `script` with `git checkout`. `--list` prints the names. The plan lists no T27 mutant; these are the skeleton's
own claims, one at a time: ERC-165, the init path, each hook seat wired, the confidential pre row, each mask, a stub, a
view, the deploy path and its link closure. Row conditions inside the hooks (which check runs for which argument) are not
mutated: every check reverts the placeholder until T28 / T29, so no test can tell them apart yet."""
import sys

R = 'src/regulated/RegulatedBase.sol'
K9 = 'src/regulated/WrappedRegulatedToken.sol'
K13 = 'src/regulated/WrappedPqzRegulatedToken.sol'
D = 'script/DeployBase.sol'
MUT = {
    'supports-no-iregulated': [(R, 'return id == type(IRegulatedToken).interfaceId || super.supportsInterface(id);',
                                'return super.supportsInterface(id);')],
    'init-skips-regulatedlib': [(R, '        RegulatedLib.init(initArgs);\n        super._initRaw(initArgs);',
                                 '        super._initRaw(initArgs);')],
    'k13-pre-reads-at-fee-none': [(K13, '        if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre(from, sel, mode);',
                                   '        RegulatedBase._regPre(from, sel, mode);')],
    'k13-pre-never-reads': [(K13, 'if (mode & MetaTxLib.MODE_FEE_MASK != MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre',
                             'if (mode & MetaTxLib.MODE_FEE_MASK == MetaTxLib.MODE_FEE_NONE) RegulatedBase._regPre')],
    'k9-regpre-unwired': [(K9, '        super._regPre(from, sel, mode);', '        UAMetaTxBase._regPre(from, sel, mode);')],
    'k9-regmove-unwired': [(K9, '        super._regMove(from, to, value);', '        ERC20MetaTx._regMove(from, to, value);')],
    'k13-regmove-unwired': [(K13, '        super._regMove(from, to, value);', '        ERC20MetaTx._regMove(from, to, value);')],
    'k13-regpayer-unwired': [(K13, '        super._regPayer();', '        ERC20MetaTx._regPayer();')],
    'k13-allowlist-in-mask': [(K13, 'return GovernanceBits.WRAPPED_BITS | REG_BITS_CONFIDENTIAL;',
                               'return GovernanceBits.WRAPPED_BITS | REG_BITS;')],
    'operator-contract-only': [(R, 'uint256 internal constant REG_CONTRACT_ONLY = GovernanceBits.REGULATED_ROLES;',
                                'uint256 internal constant REG_CONTRACT_ONLY = REG_ROLES;')],
    'delayed-relax-zero': [(R, '        return GovernanceBits.ISSUER_BITS;', '        return 0;')],
    'scalar-without-operator': [(R, '''        return GovernanceBits.TOKEN_SCALAR | (1 << GovernanceBits.FORCE) | (1 << GovernanceBits.MODERATE)
            | (1 << GovernanceBits.OPERATOR_TRANSFER);''', '''        return GovernanceBits.TOKEN_SCALAR | (1 << GovernanceBits.FORCE) | (1 << GovernanceBits.MODERATE);''')],
    'k9-kind-wrapped': [(K9, 'return TokenStore.KIND_WRAPPED_REGULATED;', 'return TokenStore.KIND_WRAPPED;')],
    'stub-freeze-skips-lib': [(R, '        RegulatedLib.freeze(account, ref, recordId, _govSubject());\n', '')],
    'view-isfrozen-false': [(R, 'returns (bool) { return _frozen(account); }', 'returns (bool) { account; return false; }')],
    'deploy-regulated-ignored': [(D, '        if (deployRegulated && register) _deployRegulated(f, address(reg), smartKeyAccountImpl, isHedera);\n',
                                  '')],
    'deploy-regulated-without-lib': [(D, '''        address[] memory libs = new address[](6);
        (libs[0], libs[1], libs[2], libs[3], libs[4], libs[5]) = (address(GovernanceLib), address(HederaLib),
            address(TradeLib), address(MtxPipelineLib), address(WrappedLib), address(RegulatedLib));''', '''        address[] memory libs = new address[](5);
        (libs[0], libs[1], libs[2], libs[3], libs[4]) = (address(GovernanceLib), address(HederaLib),
            address(TradeLib), address(MtxPipelineLib), address(WrappedLib));''')],
}


def main():
    if sys.argv[1] == '--list':
        print('\n'.join(MUT))
        return
    for path, old, new in MUT[sys.argv[1]]:
        s = open(path).read()
        if s.count(old) != 1:
            sys.exit('%s: anchor found %d times in %s' % (sys.argv[1], s.count(old), path))
        open(path, 'w').write(s.replace(old, new))


if __name__ == '__main__':
    main()
