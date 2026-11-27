# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""TreeKEM path-less Adds, P6 mutants (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §12, the client mutants of
the SDK's planner: the default form offered when the device does not hold the head, or while its own path commit is staged
(F-5), and each other condition of C46): each check dropped or moved by one, killed by
`pqchat_tree::tests::pathless_form_and_its_plan`, through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py
(ARCH-POS-23).
python3 runs/2026-11-27-treekem-pathless-p6-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/pqchat_tree.rs"
ST = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 "
      "--features pqchat-records,vectors --lib pathless_form_and_its_plan")
K = "pathless_form_and_its_plan"
B = "        if self.bound > 0 && self.since_path.saturating_add(self.adds) > self.bound {"
MUTANTS = [
    ("offered when the device does not hold the head", [(S, "        if !self.holds_head {", "        if false {")], ST, K),
    ("offered while an exit is owed", [(S, "        if self.owed > 0 {", "        if false {")], ST, K),
    ("offered with a gone head admin", [(S, "        if self.gone_admin {", "        if false {")], ST, K),
    ("offered with an admin change", [(S, "        if self.admins_changed || self.removes {", "        if self.removes {")], ST, K),
    ("offered with a Remove", [(S, "        if self.admins_changed || self.removes {", "        if self.admins_changed {")], ST, K),
    ("offered with no Add", [(S, "        if self.adds == 0 {", "        if false {")], ST, K),
    ("the bound > as >=", [(S, B, B.replace(") > self.bound {", ") >= self.bound {"))], ST, K),
    ("bound 0 forcing", [(S, B, B.replace("if self.bound > 0 &&", "if true &&"))], ST, K),
    ("offered while its own path commit is staged", [(S, "        if self.own_path_commit_staged {", "        if false {")], ST, K),
    ("offered with no try left", [(S, "        if !self.tries_left {", "        if false {")], ST, K),
]

if __name__ == "__main__":
    main("p6", MUTANTS, prefix="2026-11-27-treekem-pathless")
