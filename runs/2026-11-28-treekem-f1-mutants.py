# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""F-1 of the path-less review (owner 2026-11-28): one mutant per language of the rule "a device's own path-less record
with a reproduced nonce and a tag it could not have written is the compromise warning", each killed by its own test,
through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py (ARCH-POS-23).
python3 runs/2026-11-28-treekem-f1-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

UA = ("cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 "
      "--features app-core,vectors --test tree -- --exact tree_secrets_every_row")
CK = "cd clients/clientkeys && ../../scripts/capped node --test --test-name-pattern='F-1 \\(owner' test/treekem.test.js"
MUTANTS = [
    ("ua-rs: the own record read as C45", [("clients/ua-rs/src/wallet/tree.rs", "        if p.own {\n            return Ok(compromise());\n        }\n        if !ch.anchored {",
                                            "        if !ch.anchored {")], UA, "tree_secrets_every_row"),
    ("clientkeys: the own record read as C45", [("clients/clientkeys/src/treekem.js", '  if (p.own) return { state: "compromise" };\n', "")], CK, "F-1"),
]

if __name__ == "__main__":
    main("f1", MUTANTS, prefix="2026-11-28-treekem-f1")
