# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""TreeKEM path-less Adds, P3 mutants (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §13): the `ua-rs` side of
the delta's client mutants, one change at a time, each killed by `tests/tree.rs` (the vector rows both ways, the handle
test) through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py (ARCH-POS-23).
python3 runs/2026-11-27-treekem-pathless-p3-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

U = "clients/ua-rs/src/wallet/tree.rs"
P = "clients/ua-rs/src/wallet/tree_public.rs"
UA = ("cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 "
      "--features app-core,vectors --test tree")
ROWS = "tree_secrets_every_row"
HANDLE = "tree_pathless_handle_of_another_parent"
MUTANTS = [
    ("next from K", [(U, '        next: h(&s[..], &sc.l("next"))?,', '        next: h(&h(&s[..], &sc.l("key"))?[..], &sc.l("next"))?,')], UA, ROWS),
    ("the tag under the key label", [(U, '&[&sc.l("confirm")[..], &tag_ctx].concat()', '&[&sc.l("key")[..], &tag_ctx].concat()')], UA, ROWS),
    ("epoch 0's tag over ctx_0", [(U, "    let tag_ctx = if f.epoch == 0 { f.tree_id } else { ctx };", "    let tag_ctx = ctx;")], UA, ROWS),
    ("the add-joiner without hash(adds)", [(U, '&[&sc.l("add-joiner")[..], tree_id, epoch_id, adds_hash].concat(),', '&[&sc.l("add-joiner")[..], tree_id, epoch_id].concat(),')], UA, ROWS),
    ("the add-joiner under the joiner label", [(U, '&[&sc.l("add-joiner")[..], tree_id, epoch_id, adds_hash].concat(),', '&[&sc.l("joiner")[..], tree_id, epoch_id, adds_hash].concat(),')], UA, ROWS),
    ("another nonce than addNonce", [(U, "    Ok(u64::from_be_bytes(b))", "    Ok(u64::from_be_bytes(b).wrapping_add(1))")], UA, ROWS),
    ("the own-commit test reduced to the tag", [(U, "        if p.own && !add_nonce_reproduced(sc, dev.kem, c)? {", "        if p.own && !add_nonce_reproduced(sc, dev.kem, c)? && false {")], UA, ROWS),
    ("the joiner skipping the tag", [(U, "            if sch.tag != tag {\n                return Ok(not(\"tag\"));", "            if false {\n                return Ok(not(\"tag\"));")], UA, ROWS),
    ("a member skipping the tag", [(U, "        if sch.tag == tag {\n            return Ok(taken(sc, a, &epoch_id, &sealed, sch, ch.anchored));", "        if true {\n            return Ok(taken(sc, a, &epoch_id, &sealed, sch, ch.anchored));")], UA, ROWS),
    ("C45 applied by a first-run joiner", [(U, "        if !ch.anchored {", "        if false {")], UA, ROWS),
    ("a path commit's tag skipped", [(U, '        if sch.tag != b32j(c, "confirmTag")? {', '        if false {')], UA, ROWS),
    ("epoch 0's tag skipped", [(U, '        if sch.tag != b32j(&a.s0, "confirmTag")? {', '        if false {')], UA, ROWS),
    ("the derivation picked by the shape", [(U, "            } else if pathless {", "            } else if list(&c, \"nodeKeyHashes\", b32)?.is_empty() {")], UA, ROWS),
    ("the author's path dropped on a path-less epoch", [(U, "                if !pathless {", "                if true {")], UA, ROWS),
    ("a handle of another parent accepted", [(U, "        if head.epoch_id != pr.parent_epoch_id || head.tree_hash != pr.parent_tree_hash {", "        if false {")], UA, HANDLE),
    ("next kept by a device whose range ends before the head", [(U, "            Some(ch) if last == head =>", "            Some(ch) =>")], UA, ROWS),
    ("the warning at W(N) - 1", [(U, "        (n - n.div_ceil(4)).max(1)", "        (n - n.div_ceil(4)).max(1) - 1")], UA, ROWS),
    ("the warning shown to a non-admin", [(U, "            is_admin && end_epoch.is_none() && top.since_path >= warn_at(top.path_bound);", "            end_epoch.is_none() && top.since_path >= warn_at(top.path_bound);")], UA, ROWS),
    ("the session's bound unchecked", [(U, '                    && u32j(&s0, "pathRefreshBound").ok()? <= PATH_REFRESH_BOUND_MAX\n', '')], UA, ROWS),
    ("the snapshot's sincePath unchecked", [(U, '                && u32j(t, "sincePath").ok()? == w.since_path\n', '')], UA, ROWS),
    ("the bound > as >=", [(P, "            if t.path_bound > 0 && t.since_path.saturating_add(n) > t.path_bound {", "            if t.path_bound > 0 && t.since_path.saturating_add(n) >= t.path_bound {")], UA, ROWS),
    ("sincePath + 1 per commit", [(P, "            t.since_path = t.since_path.saturating_add(n);", "            t.since_path = t.since_path.saturating_add(1);")], UA, ROWS),
    ("no reset by a path commit", [(P, "        t.since_path = 0;\n", "")], UA, ROWS),
    ("a path-less Remove or admin change accepted", [(P, "        if c.pathless && (!c.removes.is_empty() || admins != head_admins) {", "        if false {")], UA, ROWS),
    ("the path-less shape unchecked", [(P, "        if c.pathless && (c.adds.is_empty() || !node_key_hashes.is_empty()) {", "        if false {")], UA, ROWS),
]

if __name__ == "__main__":
    main("p3", MUTANTS, prefix="2026-11-27-treekem-pathless")
