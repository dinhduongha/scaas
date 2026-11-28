# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""F-1 of the path-less review (owner 2026-11-28): mutants per language of the rule "a device's own path-less record
with a reproduced nonce and a tag it could not have written is the compromise warning, anchored or not, with no key",
each killed by its own test, through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py (ARCH-POS-23).
The treekem-f1 review's fixes (fable-A-1 = B-1 = D-1 = E-3 = F-3, A-2, B-3) add the own test moved below the unanchored
test, the own test limited to an anchored device and the key kept, and point ua-rs at its named test.
python3 runs/2026-11-28-treekem-f1-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

UA = ("cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 "
      "--features app-core,vectors --test tree -- --exact tree_pathless_own_wrong_tag_is_the_warning")
CK = "cd clients/clientkeys && ../../scripts/capped node --test --test-name-pattern='F-1 \\(owner' test/treekem.test.js"
RS = "clients/ua-rs/src/wallet/tree.rs"
JS = "clients/clientkeys/src/treekem.js"
RS_OWN = "        if p.own {\n            return Ok(compromise());\n        }\n"
RS_UNANCHORED = '        if !ch.anchored {\n            return Ok(not("welcome may not match"));\n        }\n'
JS_OWN = '  if (p.own) return { state: "compromise" };\n'
JS_UNANCHORED = '  if (!chain.anchored) return { state: "not followed", reason: "welcome may not match" };\n'
RT = "tree_pathless_own_wrong_tag_is_the_warning"
MUTANTS = [
    ("ua-rs: the own record read as C45", [(RS, RS_OWN + RS_UNANCHORED, RS_UNANCHORED)], UA, RT),
    ("ua-rs: the own test below the unanchored test", [(RS, RS_OWN + RS_UNANCHORED, RS_UNANCHORED + RS_OWN)], UA, RT),
    ("ua-rs: the own test at an anchored device only",
     [(RS, RS_OWN + RS_UNANCHORED, RS_OWN.replace("p.own", "p.own && ch.anchored") + RS_UNANCHORED)], UA, RT),
    ("ua-rs: the key kept after the warning",
     [(RS, RS_OWN + RS_UNANCHORED,
       RS_OWN.replace("compromise()", "Opened { k: Some(sch.k), ..compromise() }") + RS_UNANCHORED)], UA, RT),
    ("clientkeys: the own record read as C45", [(JS, JS_OWN, "")], CK, "F-1"),
    ("clientkeys: the own test below the unanchored test", [(JS, JS_OWN + JS_UNANCHORED, JS_UNANCHORED + JS_OWN)], CK, "F-1"),
    ("clientkeys: the own test at an anchored device only",
     [(JS, JS_OWN, JS_OWN.replace("p.own", "p.own && chain.anchored"))], CK, "F-1"),
    ("clientkeys: the key kept after the warning",
     [(JS, JS_OWN, JS_OWN.replace('"compromise" }', '"compromise", K: sch.K }'))], CK, "F-1"),
]

if __name__ == "__main__":
    main("f1", MUTANTS, prefix="2026-11-28-treekem-f1")
