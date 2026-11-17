#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T29 (ComplianceRegistry, the bounded registry call, the code pin): one mutant at a time on the T29 tree.
`t29_mutants.py <name>` from smartcontracts/evm applies one (every edit's anchor must be found exactly once);
`run_t29_mutants.sh` runs the regulated suites (test/as), GovDeploy and LinkClosure after each and restores `src` and
`script` with `git checkout`. `--list` prints the names. The plan's step 5 rows first (spec §9 ALLOWLIST, DENYLIST, the
code pin), then this task's own: the starvation check and its margin, the output length and value checks, the init
write, the receiver seats, `canReceive`, the release's `implArgs`."""
import sys

R = 'src/regulated/RegulatedBase.sol'
L = 'src/regulated/RegulatedLib.sol'
C = 'src/regulated/ComplianceRegistry.sol'
D = 'script/DeployBase.sol'
ACTIVE = '        bool active = a.validUntil >= block.timestamp && attesterEnabled(a.attesterId);'
CALL = '            ok := staticcall(REGISTRY_GAS, reg, add(cd, 0x20), mload(cd), out, len)'
FAIL = '        if (!ok || size != len) revert RegistryUnavailable(reg);'
MUT = {
    # ------------------------------------------------------------------ plan T29 step 5
    'eligible-contract-ignored': [(C, ' || a.flags & ELIGIBLE_CONTRACT != 0)))', ')))')],
    'lapsed-passes': [(C, ACTIVE, '        bool active = attesterEnabled(a.attesterId);')],
    'disabled-attester-passes': [(C, ACTIVE, '        bool active = a.validUntil >= block.timestamp;')],
    'failed-call-eligible': [(R, FAIL, '        if (!ok || size != len) out[0] = 1;')],
    'gas-cap-removed': [(R, CALL, '            ok := staticcall(gas(), reg, add(cd, 0x20), mload(cd), out, len)')],
    'eligible-contract-passes-denied': [(C, '            && !(active && a.flags & denied != 0);',
                                         '            && !(active && a.flags & denied != 0 && a.flags & ELIGIBLE_CONTRACT == 0);')],
    'codehash-check-skipped': [(L, '        if (reg != address(0) && reg.codehash != registryCodehash) {', '        if (false) {')],
    # ------------------------------------------------------------------ this task's own
    'starvation-check-dropped': [(R, '        if (left < REGISTRY_GAS * 64 / 63 + REGISTRY_GAS_MARGIN) revert RegistryGasStarved(REGISTRY_GAS, left);\n', '        left;\n')],
    'starvation-margin-zero': [(R, 'uint256 internal constant REGISTRY_GAS_MARGIN = 5_000;', 'uint256 internal constant REGISTRY_GAS_MARGIN = 0;')],
    'output-length-unchecked': [(R, FAIL, '        if (!ok) revert RegistryUnavailable(reg);')],
    'two-read-as-eligible': [(R, '        if (w > 1) revert RegistryUnavailable(reg);\n        if (w == 0)', '        if (w == 0)')],
    'not-eligible-ignored': [(R, '        if (w == 0) revert NotEligible(a, 0);\n', '')],
    'registry-not-written': [(L, '        (s.complianceRegistry, s.controls) = (reg, uint8(f >> GovernanceBits.FREEZE) & 0x3F);',
                              '        s.controls = uint8(f >> GovernanceBits.FREEZE) & 0x3F;')],
    'disabled-list-still-read': [(R, 'c & RegulatedLib.C_ALLOW != 0 ? r.requiredFlags : 0, c & RegulatedLib.C_DENY != 0 ? r.deniedFlags : 0)), 32)[0];',
                                  'r.requiredFlags, r.deniedFlags)), 32)[0];')],
    'force-beneficiary-r-dropped': [(R, '        _eligible(to);\n        MtxPipelineLib._checkTo', '        MtxPipelineLib._checkTo')],
    'fee-recipient-r-dropped': [(R, '''        if (RegulatedLib.frozen(a)) revert FeeRecipientFrozen(a);
        _eligible(a);''', '''        if (RegulatedLib.frozen(a)) revert FeeRecipientFrozen(a);''')],
    'mint-receiver-unchecked': [(R, '        if (to != 0) _eligible(to);\n', '        if (to != 0 && from != 0) _eligible(to);\n')],
    'canreceive-reasons-2-3-swapped': [(R, 'on == 0 ? 3 : !active ? 2 : 1);', 'on == 0 ? 2 : !active ? 3 : 1);')],
    'canreceive-eligible-ignored': [(R, ' || a[0] & ELIGIBLE_CONTRACT != 0)))', ')))')],
    'canreceive-lists-off-calls': [(R, '        if (c & RegulatedLib.C_LISTS == 0) return (true, 0);\n', '')],
    'zero-codehash-release': [(R, '        if (h == 0) revert RegulatedConfigInvalid();\n', '')],
    'deploy-implargs-empty': [(D, '        bytes memory implArgs = abi.encode(keccak256(type(ComplianceRegistry).runtimeCode));',
                               '        bytes memory implArgs = "";')],
    'attest-any-sender': [(C, '            if (id == 0 || !_enabled[id]) revert NotAttester();', '            id;')],
    'eligible-contract-by-attester': [(C, '(id != 0 || validUntil[i] != type(uint64).max)', '(validUntil[i] != type(uint64).max)')],
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
