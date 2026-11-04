#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T0 of the ua*/mtx* merge plan, spec §9 step 2: the regulated stand-in, on a scratch copy only (measured, never
committed): the six regulated entries as direct stubs (freeze, unfreeze, pause, unpause, forced transfer, order record:
size-options §10) on `MetaTokenBase`, and the hook of `token-core`'s hook.py 'two' (two governance reads and a refusal) in
`_update` and `_uaMove` (CTR-GOV-17: a hook only in `_update` would miss every relayed transfer). Not a design: it counts
bytes. Run from smartcontracts/evm on a lever tree; restore with `git checkout -- src/metatx/ERC20MetaTx.sol
src/metatx/MetaTokenBase.sol`.
"""
HOOK = '''
    function _hook(bytes32 from, bytes32 to, uint256 value) private view {
        if (GovernanceLib.$().features & (uint256(1) << 7) != 0 && value == type(uint256).max) revert UAPoolNotPayable();
        if (GovernanceLib.$().lockedFeatures == uint256(from) ^ uint256(to)) revert UAPoolNotPayable();
    }
'''

ENTRIES = '''
    // ------------------------------------------------------------------ T0 regulated stand-in (never committed)

    event RegStandIn(uint8 op, bytes32 a, bytes32 b, uint256 v);

    function freeze(bytes32 a) external nonReentrant {
        GovernanceUse.use(GovernanceBits.FREEZE, _govSubject(), 0);
        _regSet(a, 1);
        emit RegStandIn(1, a, 0, 0);
    }

    function unfreeze(bytes32 a) external nonReentrant {
        GovernanceUse.use(GovernanceBits.FREEZE, _govSubject(), 0);
        _regSet(a, 0);
        emit RegStandIn(2, a, 0, 0);
    }

    function pause() external nonReentrant {
        GovernanceUse.use(GovernanceBits.PAUSE, _govSubject(), 0);
        _regSet(0, 1);
        emit RegStandIn(3, 0, 0, 0);
    }

    function unpause() external nonReentrant {
        GovernanceUse.use(GovernanceBits.PAUSE, _govSubject(), 0);
        _regSet(0, 0);
        emit RegStandIn(4, 0, 0, 0);
    }

    function forcedTransfer(bytes32 from, bytes32 to, uint256 value) external nonReentrant {
        GovernanceUse.use(GovernanceBits.FORCE, _govSubject(), value);
        _poolMove(from, to, value);
        emit RegStandIn(5, from, to, value);
    }

    function recordOrder(bytes32 ref, bytes32 holder, uint256 value) external nonReentrant {
        GovernanceUse.use(GovernanceBits.RECORD, _govSubject(), value);
        _regSet(ref, value);
        emit RegStandIn(6, ref, holder, value);
    }

    function _regSet(bytes32 k, uint256 v) private {
        bytes32 slot = keccak256(abi.encode(k, uint256(0x7e9)));
        assembly ("memory-safe") { sstore(slot, v) }
    }
'''

p = 'src/metatx/ERC20MetaTx.sol'
s = open(p).read()
s = s.replace('import {IUALedger} from "./IUALedger.sol";',
              'import {IUALedger} from "./IUALedger.sol";\nimport {GovernanceLib} from "../governance/GovernanceLib.sol";', 1)
mark = '    function _uaMove(bytes32 from, bytes32 to, uint256 value) internal {\n'
assert mark in s
s = s.replace(mark, HOOK + '\n' + mark + '        _hook(from, to, value);\n', 1)
head = '    function _update(address from, address to, uint256 value) internal virtual override {\n'
assert head in s
s = s.replace(head, head + '        _hook(MetaTxLib.pad(from), MetaTxLib.pad(to), value);\n', 1)
open(p, 'w').write(s)
print(p, 'hook in _update and _uaMove')

p = 'src/metatx/MetaTokenBase.sol'
s = open(p).read()
anchor = '    // ------------------------------------------------------------------ direct path\n'
assert anchor in s
s = s.replace(anchor, ENTRIES.lstrip('\n') + '\n' + anchor, 1)
if 'GovernanceUse' not in s.split('abstract contract')[0]:
    s = s.replace('import {GovernanceBits} from "../governance/GovernanceBits.sol";',
                  'import {GovernanceBits} from "../governance/GovernanceBits.sol";\nimport {GovernanceUse} from "../governance/GovernanceBase.sol";', 1)
open(p, 'w').write(s)
print(p, 'six regulated stubs')
