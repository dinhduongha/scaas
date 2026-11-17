#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T24 (plan step 5): one mutant at a time on the T24 tree. `t24_mutants.py <name>` from smartcontracts/evm
applies one (every edit's anchor must be found exactly once); `run_t24_mutants.sh` runs the governance suites and
`test/metatx/GovernanceLib.t.sol` after each and restores `src` with `git checkout -- src`. `--list` prints the names. The
plan's eight in its order, then the window and `applied` at a proposal."""
import sys

GL = 'src/governance/GovernanceLib.sol'
MUT = {
    # the proposer not compared: anyone with the same commitment confirms
    'proposer-not-compared': [(GL,
        '            if (p.proposer != caller) revert IGovernance.NotProposer(bit, account, p.proposer);\n', '')],
    # the action left out of the commitment: a grant confirms a revoke, a renounce an owner's revoke
    'action-out-of-commit': [(GL,
        'bytes32 c = keccak256(abi.encode(action, bit, account,',
        'bytes32 c = keccak256(abi.encode(bit, account,')],
    # `barred` set at the proposal of the owner's revoke
    'barred-at-propose': [(GL,
        '        if (_delayed(s, bit, delayedRelax)) {\n            IGovernance.GrantTerms memory none;\n'
        '            if (!_due(s, bit, account, caller, REVOKE, none)) return;\n',
        '        if (owner) s.grants[bit][account].barred = true;\n        if (_delayed(s, bit, delayedRelax)) {\n'
        '            IGovernance.GrantTerms memory none;\n            if (!_due(s, bit, account, caller, REVOKE, none)) return;\n')],
    # `features` cleared at the proposal of a disable
    'features-cleared-at-propose': [(GL,
        '        if (s.features & m == 0) revert IGovernance.FeatureNotSet(bit);\n        if (_delayed(s, bit, delayedRelax)) {\n',
        '        if (s.features & m == 0) revert IGovernance.FeatureNotSet(bit);\n        s.features &= ~m;\n'
        '        if (_delayed(s, bit, delayedRelax)) {\n')],
    # `ownerGeneration` not read: a pending of the previous owner's term stays live
    'generation-not-read': [(GL,
        'return p.eta != 0 && p.generation == s.ownerGeneration && block.timestamp',
        'return p.eta != 0 && block.timestamp')],
    # an `msig` accepted on `RATE_ADJUSTABLE` (any contract-only bit)
    'msig-on-rate-adjustable': [(GL,
        ': (GovernanceBits.REGULATED_ROLES & _bit(bit) == 0 || uaRegistry == address(0)',
        ': (uaRegistry == address(0)')],
    # any derived id accepted on a regulated contract-only bit (the registry's kind not read)
    'any-derived-on-bit-5': [(GL,
        '\n                || IUARegistry(uaRegistry).kindOf(account) != UAKinds.MSIG)))', ')))')],
    # `RoleConflict` (with the rest of `_check`) skipped on the leaf path
    'roleconflict-skipped-on-leaf': [(GL,
        '        _check($(), bit, holder, roleBits, contractOnly, uaRegistry);\n',
        '        if (!leaf) _check($(), bit, holder, roleBits, contractOnly, uaRegistry);\n')],
    # the window not checked: a confirm long after `eta + grantDelay` still applies
    'window-not-checked': [(GL,
        'return p.eta != 0 && p.generation == s.ownerGeneration && block.timestamp <= uint256(p.eta) + s.grantDelay;',
        'return p.eta != 0 && p.generation == s.ownerGeneration;')],
    # a disable reports `applied` at its proposal (a contract would clear its mirror then)
    'applied-at-propose': [(GL,
        '            if (!_due(s, bit, 0, caller, DISABLE, none)) return false;',
        '            if (!_due(s, bit, 0, caller, DISABLE, none)) return true;')],
}

if sys.argv[1] == '--list':
    print(' '.join(MUT))
    sys.exit(0)
for path, a, b in MUT[sys.argv[1]]:
    s = open(path).read()
    assert s.count(a) == 1, (sys.argv[1], path, s.count(a))
    open(path, 'w').write(s.replace(a, b, 1))
