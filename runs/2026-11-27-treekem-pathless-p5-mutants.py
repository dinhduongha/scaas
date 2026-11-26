# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""TreeKEM path-less Adds, P5 mutants (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §12, the node rows: one
mutant per bound): each change to `scaas-node`'s stateless shape check of `createSession` and `commit` killed by
`typed::tests::pqchat_tree_bounds_are_the_contract`, through scripts/capped, on scripts/mutant_guard.py via
runs/mutants_lib.py (ARCH-POS-23).
python3 runs/2026-11-27-treekem-pathless-p5-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

N = "scaas-node/src/typed.rs"
NT = ("cd scaas-node && CARGO_INCREMENTAL=0 ../scripts/capped cargo test --locked --offline -j 2 --lib "
      "typed::tests::pqchat_tree_bounds_are_the_contract")
PL = "                && (adds == 0 || keys != 0 || ct_count != 0 || len(cv(\"removes\")) != 0)"
M0 = "            if num(sv(\"groupMode\")) == 0 && (bound != 0 || !tag_zero) {"
CAP = "            if num(sv(\"groupMode\")) == 1 && bound > PATH_REFRESH_BOUND_MAX {"
K = "pqchat_tree_bounds_are_the_contract"
MUTANTS = [
    ("mode 0 with bound 1 accepted", [(N, M0, M0.replace("(bound != 0 || !tag_zero)", "(!tag_zero)"))], NT, K),
    ("mode 0 with a tag accepted", [(N, M0, M0.replace("(bound != 0 || !tag_zero)", "(bound != 0)"))], NT, K),
    ("mode 1 with 511 accepted", [(N, CAP, CAP.replace("bound > PATH_REFRESH_BOUND_MAX", "bound > PATH_REFRESH_BOUND_MAX + 1"))], NT, K),
    ("mode 1 with 510 refused", [(N, CAP, CAP.replace("bound > PATH_REFRESH_BOUND_MAX", "bound >= PATH_REFRESH_BOUND_MAX"))], NT, K),
    ("a path-less Remove accepted", [(N, PL, PL.replace(" || len(cv(\"removes\")) != 0", ""))], NT, K),
    ("a path-less node key accepted", [(N, PL, PL.replace("keys != 0 || ", ""))], NT, K),
    ("a path-less ctCount accepted", [(N, PL, PL.replace("ct_count != 0 || ", ""))], NT, K),
    ("a path-less commit of no Add accepted", [(N, PL, PL.replace("adds == 0 || ", ""))], NT, K),
]

if __name__ == "__main__":
    main("p5", MUTANTS, prefix="2026-11-27-treekem-pathless")
