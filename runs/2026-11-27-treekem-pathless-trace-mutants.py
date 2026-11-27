# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""TreeKEM path-less Adds, the read / write trace mutants (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §13,
ARCH-POS-13): an extra contract read on a failure the device met (a bad tag at an anchored device, any "not followed", a
sealedInfo not taken) turns `tree_scenarios::the_pathless_faults_read_as_their_control` red. One change at a time in
`ua-rs`'s replay, through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py (ARCH-POS-23).
python3 runs/2026-11-27-treekem-pathless-trace-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

U = "clients/ua-rs/src/wallet/tree.rs"
PT = ("cd clients/pqchat-core && CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=../scaas-sdk/target ../../scripts/capped cargo test "
      "--locked --offline -j 2 --features vectors --test tree_scenarios the_pathless_faults_read_as_their_control")
K = "the_pathless_faults_read_as_their_control"
EXTRA = "let _ = rd.read(View::WrapAt(n, 0))?;"
DNH = "            if state == State::AuthorDidNotHold {\n                let adds = adds_of()?;"
NT = "                    if st == State::Followed {\n                        info = Some(InfoTook::NotTaken);"
MUTANTS = [
    ("a read more on a bad tag at an anchored device (C45)", [(U, DNH, DNH.replace("{\n", "{\n                " + EXTRA + "\n", 1))], PT, K),
    ("a read more on a sealedInfo not taken", [(U, NT, NT.replace("{\n", "{\n                        " + EXTRA + "\n", 1))], PT, K),
    ("a read more on any epoch not followed", [(U, "            let adds_of = || list(&c, \"adds\", Add::from_json);", "            if matches!(state, State::NotFollowed(_)) {\n                " + EXTRA + "\n            }\n            let adds_of = || list(&c, \"adds\", Add::from_json);")], PT, K),
]

if __name__ == "__main__":
    main("trace", MUTANTS, prefix="2026-11-27-treekem-pathless")
