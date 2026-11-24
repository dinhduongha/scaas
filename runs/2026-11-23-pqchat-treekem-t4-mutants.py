# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM T4 (allow-list part) mutants, node side (CTR-CHAT-27: the tree rows, `tree_lists`, `tree_shape`, the
both-ways allow-list), each killed by the `pqchat` tests of `scaas-node` (lib, through scripts/capped, on
scripts/mutant_guard.py via runs/mutants_lib.py, ARCH-POS-23):
python3 runs/2026-11-23-pqchat-treekem-t4-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

T = "scaas-node/src/typed.rs"
G = "scaas-node/src/guard.rs"
I = "smartcontracts/evm/src/pqchat/IPqChat.sol"
CMD = "cd scaas-node && ../scripts/capped cargo test --locked --lib pqchat"
BOUNDS = "pqchat_tree_bounds_are_the_contract"
AUDIT = "pqchat_rows_equal_the_contract_both_directions"
MUTANTS = [
    ("a missing bound on addPathList's ctTargets",
     [(T, '    ("addPathList", "/ctTargets", TREE_CTS_MAX),\n', "")], CMD, BOUNDS),
    ("a missing bound on commit's ctTargets",
     [(T, '    ("commit", "/ctTargets", TREE_CTS_MAX),\n', "")], CMD, BOUNDS),
    ("TREE_ADMINS_MAX one above the contract's",
     [(T, "const TREE_ADMINS_MAX: usize = 32;", "const TREE_ADMINS_MAX: usize = 33;")], CMD, BOUNDS),
    ("TREE_INFO_MAX one above the contract's",
     [(T, "const TREE_INFO_MAX: usize = 4124;", "const TREE_INFO_MAX: usize = 4125;")], CMD, BOUNDS),
    ("treeRemove's members one above",
     [(T, "        TREE_CHANGES_MAX + TREE_ADMINS_MAX,\n", "        TREE_CHANGES_MAX + TREE_ADMINS_MAX + 1,\n")], CMD, BOUNDS),
    ("the changes bound counts removes alone",
     [(T, 'if len(cv("removes")) + adds > TREE_CHANGES_MAX {', 'if len(cv("removes")) > TREE_CHANGES_MAX {')], CMD, BOUNDS),
    ("the path bounded by the cap, not depth(leaves)",
     [(T, "if ct_count >= leaves || keys > depth ||", "if ct_count >= leaves || keys > TREE_DEPTH_MAX ||")], CMD, BOUNDS),
    ("ctCount up to leaves",
     [(T, "if ct_count >= leaves || keys > depth ||", "if ct_count > leaves || keys > depth ||")], CMD, BOUNDS),
    ("an empty sealedInfo accepted",
     [(T, "if info == 0 || info > TREE_INFO_MAX {", "if info > TREE_INFO_MAX {")], CMD, BOUNDS),
    ("a commit's node keys of any size",
     [(T, "if (nk != 0 && nk != keys) || !sized(at(\"nodeKeys\"), KEM_PK) {", "if nk != 0 && nk != keys {")], CMD, BOUNDS),
    ("a path ciphertext's sealed secret of any size above 48",
     [(T, "&& t[2].as_bytes().is_some_and(|b| b.len() == SEALED_SECRET)",
       "&& t[2].as_bytes().is_some_and(|b| b.len() >= SEALED_SECRET)")], CMD, BOUNDS),
    ("addPath without firstCt",
     [(T, 'if num(at("firstCt")).saturating_add(len(at("cts")) as u64) > TREE_CTS_MAX as u64',
       'if len(at("cts")) as u64 > TREE_CTS_MAX as u64')], CMD, BOUNDS),
    ("a commit's wraps up to the changes bound",
     [(T, 'if len(at("wraps")) > adds {', 'if len(at("wraps")) > TREE_CHANGES_MAX {')], CMD, BOUNDS),
    ("the lists read after the parse only",
     [(T, "        tree_lists(row.entry, args)?;\n", "")], CMD, BOUNDS),
    ("an unsigned piece relayed with the option off",
     [(G, '(lane_pays, row.fields.iter().any(|f| f.0 == "UASig"))',
       '(lane_pays, row.fields.iter().any(|f| f.0 == "UASig") || row.entry == "addPath")')],
     CMD, "unsigned_pqchat_writes_run_paid_or_under_the_lane_policy"),
    ("a node row missing (treeLeave)",
     [(T, '    ("treeLeave", PC, "PqChatTreeLeave l,UASig sig"),\n', "")], CMD, AUDIT),
    ("a contract entry missing (treeRemove)",
     [(I, "    function treeRemove(PqChatTreeRemove calldata r, IUARegistry.UASig calldata sig) external;\n", "")],
     CMD, AUDIT),
]

if __name__ == "__main__":
    main("t4", MUTANTS, prefix="2026-11-23-pqchat-treekem")
