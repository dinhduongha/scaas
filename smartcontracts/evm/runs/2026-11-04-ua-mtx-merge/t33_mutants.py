#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T33 (the regulated releases 8-13, the canonical `ComplianceRegistry` deploy): one mutant at a time on the
T33 tree. `t33_mutants.py <name>` from smartcontracts/evm applies one (every edit's anchor must be found exactly once, and
the edit must change something); `run_t33_mutants.sh` runs the T33 forge suites (or, for an `e2e-*` mutant, `e2e.py
--self-test`) after each and restores `script` with `git checkout`. `--list` prints the names. The plan's step 5 rows
first, then this task's own."""
import sys

D = 'script/DeployBase.sol'
E = 'script/pqz/e2e.py'

IMPL = '        bytes memory implArgs = abi.encode(_registryCodehash());\n'
LIBS8 = ('            (address(GovernanceLib), address(HederaLib), address(TradeLib), address(MtxPipelineLib), '
         'address(RegulatedLib));\n')
NEWREG = '        ComplianceRegistry r = new ComplianceRegistry{salt: salt}(complianceAdmin);\n'

MUT = {
    # ------------------------------------------------------------------ plan T33 step 5
    'reglib-missing-from-libcodehashes': [(D, '        for (uint256 i; i < libs.length; ++i) h[i] = libs[i].codehash;\n',
        '        for (uint256 i; i < libs.length; ++i) h[i] = libs[i] == address(RegulatedLib) ? bytes32(0) : libs[i].codehash;\n')],
    'registry-hash-out-of-implargs-8-9': [(D, IMPL + '        address n = _release(f, IOpenFactory.TokenKind.NORMAL_REGULATED,',
         '        bytes memory implArgs = "";\n        address n = _release(f, IOpenFactory.TokenKind.NORMAL_REGULATED,')],
    # ------------------------------------------------------------------ this task's own
    'registry-hash-out-of-implargs-10-11': [(D, IMPL + '        f.publishEnv(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED,',
        '        bytes memory implArgs = "";\n        f.publishEnv(IOpenFactory.TokenKind.NORMAL_ZETHER_REGULATED,')],
    'reglib-dropped-from-8-env': [(D, LIBS8, LIBS8.replace('address(RegulatedLib)', 'address(WrappedLib)'))],
    'reglib-dropped-from-zether-env': [(D, '        l[libs.length] = address(RegulatedLib);\n',
                                        '        l[libs.length] = address(TradeLib);\n')],
    'registry-not-deployed': [(D, '        if (deployRegulated) _deployComplianceRegistry();\n', '')],
    'registry-on-every-deploy': [(D, '        if (deployRegulated) _deployComplianceRegistry();\n',
                                  '        _deployComplianceRegistry();\n')],
    'registry-admin-the-deployer': [(D, NEWREG, NEWREG.replace('(complianceAdmin)', '(address(this))'))],
    'registry-codehash-json-wrong': [(D, '"compliance_registry_codehash", address(r).codehash);',
                                      '"compliance_registry_codehash", bytes32(uint256(1)));')],
    'kind-8-not-enabled': [(D, '        f.setKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED, true);\n', '')],
    'e2e-impl-args-not-on-13': [(E, '    return registry_codehash() if kind >= 8 else b""\n',
                                 '    return registry_codehash() if kind == 12 else b""\n')],
    'e2e-13-not-released': [(E, '(12, "NormalPqzRegulatedToken"),\n            (13, "WrappedPqzRegulatedToken"))',
                             '(12, "NormalPqzRegulatedToken"))')],
    'e2e-registry-hash-of-initcode': [(E, 'return keccak256(bytes.fromhex(j["deployedBytecode"]["object"]',
                                       'return keccak256(bytes.fromhex(j["bytecode"]["object"]')],
}


def main():
    if sys.argv[1:] == ['--list']:
        print(' '.join(MUT))
        return
    name = sys.argv[1]
    for path, old, new in MUT[name]:
        s = open(path).read()
        if s.count(old) != 1:
            sys.exit(f'{name}: anchor in {path} found {s.count(old)} times')
        if old != new:
            open(path, 'w').write(s.replace(old, new))
    if all(old == new for _, old, new in MUT[name]):
        sys.exit(f'{name}: changes nothing')


if __name__ == '__main__':
    main()
