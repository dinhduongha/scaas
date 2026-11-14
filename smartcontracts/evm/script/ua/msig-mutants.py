# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""TODO 3ze (CTR-UA-44, spec section 8): every mutant of `updateMsig` and the current-structure readers alone on a clean tree,
`forge test` of test/ua/UARegistryMsigUpdate.t.sol through `scripts/capped`, the file restored byte-equal (sha256 checked) after each.
One line per mutant: `mutant | red tests | rc` (rc 1 = killed). Resumes: a mutant already in `<runs>/mutants.txt` is skipped. Full
output in git-ignored `.log` files under `<runs>/mutants/`. The runner is script/wraplimit/mutants.py's.

usage (from smartcontracts/evm): python3 script/ua/msig-mutants.py <runs dir> [name ...]   UNAUDITED tooling."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'wraplimit'))
import mutants as runner  # noqa: E402  (the shared runner: run, others_waiting)

REG = 'src/ua/UARegistry.sol'
CORE = 'src/ua/UARegistryCoreLib.sol'
AUX = 'src/ua/UARegistryAuxLib.sol'
STORE = 'src/ua/UAStore.sol'
T = 'test/ua/UARegistryMsigUpdate.t.sol'
D = 'test/ua'

# (name, file, old, new)
M = [
    ('chain-path-no-enabled-mask', REG, 'uint256 accepted = _s.accepted[ua] & UAStore.enabledOf(d);', 'uint256 accepted = _s.accepted[ua];'),
    ('portable-path-no-enabled-mask', CORE, '_accepted(ua, sigs)) & UAStore.enabledOf(d);', '_accepted(ua, sigs));'),
    ('portable-count-mask-restored', CORE, '_accepted(ua, sigs)) & UAStore.enabledOf(d);', '_accepted(ua, sigs)) & ((1 << UAStore.u16(d, 2)) - 1);'),
    ('memberAccepted-no-enabled', REG, 'return (_s.accepted[ua] & en) >> index & 1 != 0;', 'return _s.accepted[ua] >> index & 1 != 0;'),
    ('version-gt-not-eq', AUX, 'if (version != stored + 1) revert', 'if (version <= stored) revert'),
    ('no-chain-check', AUX, 'if (chainUid_ != u.chainUid) revert IUARegistry.ChainUidMismatch(u.chainUid, chainUid_); // 1', '// 1'),
    ('no-expiry-check', AUX, 'if (block.number > validUntilBlock) revert IUARegistry.UAMsigExpired(ua); // 2', '// 2'),
    ('sigs-over-target', AUX, 'UARegistryCoreLib.msigOk.selector, u.ua, md, typed, u.stored, sigs', 'UARegistryCoreLib.msigOk.selector, u.ua, md, typed, u.t, sigs'),
    ('no-slot-changed-check', AUX, '                revert IUARegistry.UAMsigSlotChanged(uint16(i));', '                continue;'),
    ('no-duplicate-check', AUX, '                    if (m[j].id == x.id) revert IUARegistry.UAKeyData(UAKinds.MSIG);', '                    m[j].id;'),
    ('duplicate-by-kind-and-id', AUX, 'if (m[j].id == x.id) revert', 'if (m[j].id == x.id && m[j].kind == x.kind) revert'),
    ('no-self-slot-check', AUX, '(en && x.kind == UAKinds.MSIG && x.id == u.ua)', '(false)'),
    ('threshold-counts-unaccepted', AUX, 'if (en && accepted >> i & 1 != 0) weight += x.weight;', 'if (en) weight += x.weight;'),
    ('no-row-10', AUX, '        _fresh(u); // 10\n', ''),
    ('row-10-not-on-reenabled', AUX, 'if (i >= sn || (en && se >> i & 1 == 0)) u.fresh |= 1 << i;', 'if (i >= sn) u.fresh |= 1 << i;'),
    ('no-row-11', CORE, '        uint256 w = _membersWorst(t, _nativeCap(), true);\n        if (_pqEligible(t, false))',
     '        uint256 w = 0;\n        if (_pqEligible(t, false))'),
    ('bound-counts-disabled', CORE, 'return UAStore.enabledOf(d) >> i & 1 != 0\n', 'return true\n'),
    ('bound-follows-inner-msig', CORE, '&& (mode != INNER | LENIENT || UAStore.u16(d, 4 + 36 * i) != UAKinds.MSIG);', ';'),
    ('eligibility-follows-inner-msig', CORE, 'if (kind == UAKinds.MSIG && !inner && _pqEligible(', 'if (kind == UAKinds.MSIG && _pqEligible('),
    ('no-stays-pq-eligible', CORE, '        else if (_pqEligible(stored, false)) revert IUARegistry.UAPqzHolder(ua);\n', ''),
    ('no-row-13', CORE, 'if (w + MSIG_UPDATE_GAS + n * MSIG_UPDATE_SLOT_GAS > TX_GAS_CAP) revert IUARegistry.UAMsigSlots(n);', 'n;'),
    ('registration-reads-msig-keyPtr', STORE, 'SSTORE2.read(vkLength(r.kind) == 0 ? address(0) : r.keyPtr)', 'SSTORE2.read(r.keyPtr)'),
    ('accept-reads-first-structure', CORE, '        bytes memory d = UAStore.msig(ua, r.keyPtr);\n        uint16 index = memberSig.index;',
     '        bytes memory d = UAStore.keyRest(ua);\n        uint16 index = memberSig.index;'),
    ('host-reads-registrationOf', AUX, 'if (kind == UAKinds.MSIG) d = UARegistryCoreLib._msigBytes(ua);', 'if (kind == UAKinds.MSIG && !host) d = UARegistryCoreLib._msigBytes(ua);'),
    ('gen2-msigState-not-forwarded', AUX, 'if (UARegistryCoreLib._elsewhere(ua)) return IUARegistry(UARegistryCoreLib._pred()).msigStateOf(ua);', ''),
    ('registry-not-in-digest', AUX, 'UAKinds.msigUpdateDigest(ua, u.chainUid, address(this),', 'UAKinds.msigUpdateDigest(ua, u.chainUid, address(0),'),
    ('purpose-tag', 'src/ua/UAKinds.sol', 'keccak256("scaas.ua.purpose.msig-update.v1")', 'keccak256("scaas.ua.purpose.msig-update.v2")'),
]


def main():
    runs = sys.argv[1]
    os.makedirs(os.path.join(runs, 'mutants'), exist_ok=True)
    only = set(sys.argv[2:])
    out = os.path.join(runs, 'mutants.txt')
    done = set()
    if os.path.exists(out):
        done = {line.split(' | ')[0] for line in open(out) if ' | ' in line and not line.startswith('mutant')}
    with open(out, 'a') as o:
        if not done:
            o.write('mutant | red tests | rc\n')
        for i, (name, f, old, new) in enumerate(M):
            if (only and name not in only) or name in done:
                continue
            if runner.others_waiting():
                print('yield: another work tree waits for a capped slot; rerun to resume', flush=True)
                return
            print(f'start {i + 1}/{len(M)} {name}', flush=True)
            rc, red = runner.run(runs, name, f, old, new, D, T)
            line = f'{name} | {", ".join(red) or "-"} | {rc}\n'
            o.write(line)
            o.flush()
            print(line, end='', flush=True)


if __name__ == '__main__':
    main()
