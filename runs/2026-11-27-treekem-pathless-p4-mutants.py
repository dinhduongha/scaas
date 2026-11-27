# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""TreeKEM path-less Adds, P4 mutants (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §12, the contract mutants):
one change at a time in the base (`PqGroupTree`), the chat's record and error mapping, each to be killed by the path-less
rows (PqChatTreePathless) or the mode and view tests beside them, through scripts/capped, on scripts/mutant_guard.py via
runs/mutants_lib.py (ARCH-POS-23).
python3 runs/2026-11-27-treekem-pathless-p4-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

G = "smartcontracts/evm/src/pqgroup/PqGroupTree.sol"
C = "smartcontracts/evm/src/pqchat/PqChat.sol"
CORE = "smartcontracts/evm/src/pqchat/PqChatCore.sol"
T = "smartcontracts/evm/src/pqchat/PqChatTree.sol"
FG = ("cd smartcontracts/evm && PATH=$HOME/.foundry/bin:$PATH FOUNDRY_TEST=test/pqchat FOUNDRY_SCRIPT=test/pqchat "
      "../../scripts/capped forge test -j 1 --match-path 'test/pqchat/PqChat{TreePathless,GroupMode,TreeViews,Types}.t.sol'")
SET = "        t.sincePath = d.pathless ? t.sincePath + uint32(d.adds.length) : 0;"
BOUND = "        if (bound != 0 && uint256(t.sincePath) + d.adds.length > bound) _treeFail(T_PATH_BOUND, t.sincePath, bound);"
MODE = "s.groupMode == 0 ? s.pathRefreshBound != 0 || s.confirmTag != 0 : s.pathRefreshBound > TREE_LEAVES_MAX - 2"
MUTANTS = [
    ("the Remove condition dropped", [(G, "bool same = d.removes.length == 0 && d.admins.length == h.length;", "bool same = d.admins.length == h.length;")], FG, "test_r2_"),
    ("the admin-equality dropped", [(G, "            same = d.admins[i] == h[i];", "            same = true;")], FG, "test_r3_"),
    ("the pathless field ignored", [(T, "c.treeHash, c.pathless);", "c.treeHash, false);")], FG, "[FAIL"),
    ("pathless with a path piece", [(G, "if (d.adds.length == 0 || d.nodeKeyHashes.length != 0 || d.ctCount != 0) _treeFail(T_SHAPE, 0, 0);", "if (d.adds.length == 0) _treeFail(T_SHAPE, 0, 0);")], FG, "test_r11_"),
    ("the bound > as >=", [(G, BOUND, BOUND.replace(" > bound)", " >= bound)"))], FG, "test_r6_"),
    ("the bound ignored when N > 0", [(G, BOUND, BOUND.replace("if (bound != 0 &&", "if (false &&"))], FG, "test_r6_"),
    ("the error's arguments swapped", [(CORE, "PqChatTreePathBound(uint32(a), uint32(b))", "PqChatTreePathBound(uint32(b), uint32(a))")], FG, "test_r6_"),
    ("sincePath + 1 per commit", [(G, SET, SET.replace("t.sincePath + uint32(d.adds.length)", "t.sincePath + 1"))], FG, "[FAIL"),
    ("no reset by a path commit", [(G, SET, SET.replace(" : 0;", " : t.sincePath;"))], FG, "[FAIL"),
    ("a reset only when nodeKeyHashes is not empty", [(G, SET, SET.replace("d.pathless ?", "d.pathless || d.nodeKeyHashes.length == 0 ?"))], FG, "test_r14_"),
    ("a reset by a path-less commit", [(G, SET, SET.replace("t.sincePath + uint32(d.adds.length)", "uint32(d.adds.length)"))], FG, "[FAIL"),
    ("a path commit's Adds counted", [(G, SET, SET.replace(" : 0;", " : uint32(d.adds.length);"))], FG, "[FAIL"),
    ("_walkPath on the path-less shape", [(G, "        if (!d.pathless) _walkPath(t, d, w);", "        _walkPath(t, d, w);")], FG, "[FAIL"),
    ("the Add's blanking stopped below the root", [(G, "            if (w.st[x] == 0) w.st[x] = 1;", "            if (w.st[x] == 0 && x != root) w.st[x] = 1;")], FG, "[FAIL"),
    ("mode 0 accepting a bound or tag", [(C, MODE, MODE.replace("s.groupMode == 0 ? s.pathRefreshBound != 0 || s.confirmTag != 0 :", "s.groupMode == 0 ? false :"))], FG, "[FAIL"),
    # the path-less review's A-3: the targets hash written for a record with no list
    ("a targets hash for ctCount 0", [(T, "        if (c.ctCount != 0) _staged(eid).targetsHash = keccak256(_pack4(w.targets));", "        _staged(eid).targetsHash = keccak256(_pack4(w.targets));")], FG, "test_r1_theTargetsHashSlot"),
    # the path-less review's A-1: the spec's two missing rows (delta §13 "Contract mutants")
    ("equality replaced by _keepsAdmins (a gone head admin dropped)", [(G, """        bool same = d.removes.length == 0 && d.admins.length == h.length;
        for (uint256 i; same && i < h.length; ++i) {
            same = d.admins[i] == h[i];
        }""", """        bool same = d.removes.length == 0;
        uint256 j;
        for (uint256 i; same && i < h.length; ++i) {
            if (j < d.admins.length && d.admins[j] == h[i]) ++j;
            else same = t.gone[h[i]].kind != 0;
        }
        same = same && j == d.admins.length;""")], FG, "test_r5_"),
    ("the counter moved at acceptance", [(T, "        Walk memory w = _treeCheck(reg, c.sessionId, _delta(m), false);\n", "        Walk memory w = _treeCheck(reg, c.sessionId, _delta(m), false);\n        if (m.pathless) _tree(c.sessionId).sincePath += uint32(m.adds.length);\n"), (G, SET, SET.replace("t.sincePath + uint32(d.adds.length)", "t.sincePath"))], FG, "[FAIL"),
    ("the cap at 511", [(C, MODE, MODE.replace("TREE_LEAVES_MAX - 2", "TREE_LEAVES_MAX - 1"))], FG, "test_r8_"),
]

if __name__ == "__main__":
    main("p4", MUTANTS, prefix="2026-11-27-treekem-pathless")
