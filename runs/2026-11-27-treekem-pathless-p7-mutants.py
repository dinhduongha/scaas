# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""TreeKEM path-less Adds, P7 mutants (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §12, the client mutants of
`pqchat-core`'s reading of the default form: offered when the device does not hold the head, or while its own path commit is
staged, F-5): each input of `PqChat::pathless_form` dropped, killed by `tree_scenarios::the_pathless_form_from_the_state`,
through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py (ARCH-POS-23).
python3 runs/2026-11-27-treekem-pathless-p7-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

P = "clients/pqchat-core/src/tree.rs"
PT = ("cd clients/pqchat-core && CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=../scaas-sdk/target ../../scripts/capped cargo test --locked --offline -j 2 "
      "--features vectors --test tree_scenarios the_pathless_form_from_the_state")
K = "the_pathless_form_from_the_state"
CT = ("cd clients/pqchat-core && PATH=$HOME/.foundry/bin:$PATH CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=../scaas-sdk/target "
      "../../scripts/capped cargo test --locked --offline -j 2 --test chain_tree -- --ignored --exact chain_tree_session")
CK = "chain_tree_session"
MUTANTS = [
    ("offered when the device does not hold the head", [(P, "            holds_head: r.holds_head,", "            holds_head: true,")], PT, K),
    ("the owed count not parsed", [(P, "                .and_then(|x| x.parse::<u32>().ok())", "                .and_then(|_| Some(0))")], PT, K),
    ("an admin change not read", [(P, "            admins_changed: mine != head_admins,", "            admins_changed: false,")], PT, K),
    ("a Remove not read", [(P, "            removes: !c.removes.is_empty(),", "            removes: false,")], PT, K),
    ("the staged marker of another parent", [(P, "                .map(str::to_ascii_lowercase)\n                == head,", "                .map(str::to_ascii_lowercase)\n                != head,")], PT, K),
    ("the staged marker ignored", [(P, "                .map(str::to_ascii_lowercase)\n                == head,", "                .map(str::to_ascii_lowercase)\n                == None,")], PT, K),
    # the gaps closed on 2026-11-27 (controller, after the reboot): the try counter (C47), the quote's two prices and the
    # deferred cost (§6.4, §9); chain_tree on anvil
    ("no try counter (always a try left)", [(P, "            tries_left: self.next_try(st)? < pt::ADD_NONCE_TRIES,", "            tries_left: true,")], PT, K),
    ("the try counter not moved by a signed path-less Add", [(P, "let next = self.next_try(st)?.saturating_add(1);", "let next = self.next_try(st)?;")], CT, CK),
    ("the quote without the refresh price", [(P, "            split.refresh = Some(", "            let _unused = Some(")], CT, CK),
    ("the deferred cost without this commit's Adds", [(P, "            split.deferred = self.tree_deferred(s, st, shape.adds)?;", "            split.deferred = self.tree_deferred(s, st, 0)?;")], CT, CK),
]

if __name__ == "__main__":
    main("p7", MUTANTS, prefix="2026-11-27-treekem-pathless")
