#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge, owner ruling 2026-11-06 (ComplianceRegistry: only the admin overwrites or revokes an admin-written slot,
`attesterId == 0 && flags != 0`): one mutant at a time. `adminslot_mutants.py <name>` from smartcontracts/evm applies one
(every edit's anchor found exactly once, and the edit must change something); `run_adminslot_mutants.sh` runs the registry
suites after each and restores `src` with `git checkout`. `--list` prints the names. The controller's three first, then
this change's own."""
import sys

C = 'src/regulated/ComplianceRegistry.sol'
CHECK = '            if (id != 0 && s.attesterId == 0 && s.flags != 0) revert AdminWrittenSlot(accounts[i]);\n'
WRITE = '            (s.flags, s.validUntil, s.attesterId) = (flags[i], validUntil[i], id);\n'

MUT = {
    # ------------------------------------------------------------------ the controller's three
    'admin-check-removed': [(C, CHECK, '')],
    'check-on-caller-not-writer': [(C, CHECK, CHECK.replace('s.attesterId == 0 && ', ''))],
    'empty-slot-as-admin': [(C, CHECK, CHECK.replace(' && s.flags != 0', ''))],
    # ------------------------------------------------------------------ this change's own
    'writer-mismatch-locks': [(C, CHECK, CHECK.replace('id != 0 && s.attesterId == 0', 'id != s.attesterId'))],
    'admin-revoke-stays-locked': [(C, CHECK, CHECK.replace('s.flags != 0', '(s.flags != 0 || s.validUntil != 0)'))],
    'admin-locked-out-too': [(C, CHECK, CHECK.replace('id != 0 && ', ''))],
    'check-after-write': [(C, CHECK + WRITE, WRITE + CHECK)],
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
