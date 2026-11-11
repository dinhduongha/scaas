#!/usr/bin/env python3
"""The round's mutants: each patches one source line, runs its test file, restores the file. A mutant must make the test
fail. From smartcontracts/evm. Output: one line per mutant; logs runs/2026-11-11-review-fixes/mut-<id>.log (git-ignored)."""
import subprocess, sys
R = 'runs/2026-11-11-review-fixes'
M = [
 ('B-P2-1-restore-moves-nothing', 'src/metatx/ERC20MetaTx.sol', '        _uaMove(TradeLib.pad(o.dex), o.from, amount);\n', '', 'test/v2/DexHybrid.t.sol'),
 ('A-2-code-length', 'src/regulated/RegulatedLib.sol', 'SigCheck.isContract(address(uint160(uint256(from))))', 'address(uint160(uint256(from))).code.length != 0', 'test/as/OperatorTransfer.t.sol'),
 ('A-1-refresh-fee-unchecked', 'src/pqz/PqzLayer.sol', '        if (e.amount == 0 && f.fee != 0) _regSender(b.fromUA);', '', 'test/as/confidential/PqzRefresh.t.sol'),
 ('A-3-tax-recipient-ignored', 'src/factory/IFactoryToken.sol', ' || r.taxRecipient != 0', '', 'test/as/RegConfig.t.sol'),
 ('B-P3-4-late-fee-refusal', 'src/metatx/MtxPipelineLib.sol', '        if (fee != 0) {\n            if (feeTo == address(this)) revert IERC20MetaTx.TransferToSelf();\n', '        if (fee != 0) {\n', 'test/ua/UALedger.t.sol'),
 ('B-P3-4-late-shield-refusal', 'src/metatx/MtxPipelineLib.sol', '            if (feeTo == MetaTxLib.SHIELD_POOL) revert IUALedger.ShieldPoolNotPayable();\n        }\n        return (fee, feeTo);', '        }\n        return (fee, feeTo);', 'test/ua/UALedger.t.sol'),
 ('D-P3-1-any-owner', 'src/pqchat/PqChat.sol', '        if (ownerUA != 0 && ownerUA != IOpenFactory(FACTORY).creating()) revert PqChatOwnerNotCreator(ownerUA);\n', '', 'test/pqchat/PqChat.t.sol'),
 ('P3-9-no-floor', 'src/zether/ZetherLib.sol', '        if (g < _PROBE_GAS * 64 / 63 + _PROBE_GAS_MARGIN) revert IZetherToken.BadInit();\n', '', 'test/zether/ZetherRevertPaths.t.sol'),
 ('P3-9-no-oog-check', 'src/zether/ZetherLib.sol', '        if (!ok && g - gasleft() >= _PROBE_GAS) revert IZetherToken.BadInit();\n', '', 'test/zether/ZetherRevertPaths.t.sol'),
 ('C1-whole-no-total', 'src/governance/GovernanceLib.sol', ' || t.total != 0 || t.perWindow != 0 || t.maxUses != 0;', ' || t.perWindow != 0 || t.maxUses != 0;', 'test/governance/GovRelax.t.sol'),
 ('C1-whole-no-perWindow', 'src/governance/GovernanceLib.sol', ' || t.total != 0 || t.perWindow != 0 || t.maxUses != 0;', ' || t.total != 0 || t.maxUses != 0;', 'test/governance/GovRelax.t.sol'),
 ('C1-whole-no-min', 'src/governance/GovernanceLib.sol', 'return t.min != 0 || t.max != type(uint128).max', 'return t.max != type(uint128).max', 'test/governance/GovRelax.t.sol'),
 ('C1-whole-no-maxUses', 'src/governance/GovernanceLib.sol', ' || t.perWindow != 0 || t.maxUses != 0;', ' || t.perWindow != 0;', 'test/governance/GovRelax.t.sol'),
 ('C1-whole-no-max', 'src/governance/GovernanceLib.sol', ' || t.max != type(uint128).max ||', ' ||', 'test/governance/GovRelax.t.sol'),
 ('C1-limited-no-maxUses', 'src/governance/GovernanceLib.sol', '\n            || _lower(g.maxUses, t.maxUses) ||', '\n            ||', 'test/governance/GovRelax.t.sol'),
 ('C2-no-delegable', 'src/governance/GovernanceLib.sol', ' || (g.delegable && !t.delegable);', ';', 'test/governance/GovRelax.t.sol'),
 ('P3-10-no-executor-event', 'src/factory/OpenFactory.sol', '            emit ChainEntrySet(v, x, relayFeeExecutorCodeHash);', '', 'test/v2/FactoryDirectory.t.sol'),
]
only = sys.argv[1:]
for mid, f, old, new, test in M:
    if only and mid not in only: continue
    src = open(f).read()
    assert src.count(old) == 1, (mid, 'pattern')
    open(f, 'w').write(src.replace(old, new))
    try:
        log = f'{R}/mut-{mid}.log'
        with open(log, 'w') as out:
            rc = subprocess.call(['../../scripts/capped', 'forge', 'test', '-j', '1', '--match-path', test],
                                 stdout=out, stderr=subprocess.STDOUT, env={**__import__('os').environ, 'CAPPED_SLOTS': '3'})
        fails = sorted({l.split('] ')[-1].split('(')[0] for l in open(log) if l.startswith('[FAIL')})
        print(f'{mid} | rc {rc} | {"KILLED" if rc != 0 and fails else "SURVIVED"} | {" ".join(fails)}', flush=True)
    finally:
        open(f, 'w').write(src)
