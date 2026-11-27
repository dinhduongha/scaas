# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""TreeKEM path-less Adds, P9 mutants: the checks the Fable review's fix wave added (scratchpad review dir
treekem-pathless-review-20261127-1527, STATUS.md), one per check, each killed by its own test; plus F-4's mutant (the R20
reset), through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py (ARCH-POS-23).
python3 runs/2026-11-27-treekem-pathless-p9-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

AK = "clients/ua-rs/src/wallet/appkey.rs"
TR = "clients/ua-rs/src/wallet/tree.rs"
TP = "clients/ua-rs/src/wallet/tree_public.rs"
JS = "clients/clientkeys/src/treekem.js"
JT = "clients/clientkeys/src/pqchat-tree.js"
P = "clients/pqchat-core/src/tree.rs"


def ua(test):
    return ("cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 "
            f"--features app-core,vectors --test tree -- --exact {test}")


def ck(file, pattern):
    return f"cd clients/clientkeys && ../../scripts/capped node --test --test-name-pattern='{pattern}' test/{file}"


def pq(target, test):
    t = "--lib" if target == "lib" else f"--test {target}"
    return ("cd clients/pqchat-core && CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=../scaas-sdk/target ../../scripts/capped cargo test "
            f"--locked --offline -j 2 --features vectors {t} {test}")


NEXT, RESUME, BOUND, JSON, NAMES = (
    "tree_next_never_leaves",
    "tree_resume_keeps_the_leaves_under_review",
    "tree_session_bound_above_the_cap_is_a_lie",
    "tree_json_needs_its_counter",
    "tree_pathless_refusals_by_name",
)
MUTANTS = [
    # C-1 = F-3, C-6: the head's `next` never leaves
    ("next sealed", [(AK, "as `wrap_with` refuses;\n        // nor a head's `next`\n        if matches!(key.origin, Origin::Tree | Origin::TreeNext) {",
                      "as `wrap_with` refuses;\n        // nor a head's `next`\n        if matches!(key.origin, Origin::Tree) {")], ua(NEXT), NEXT),
    ("next KEM-wrapped", [(AK, "a tree session needs no flat wrap of it;\n        // nor a head's `next`\n        if matches!(key.origin, Origin::Tree | Origin::TreeNext) {",
                           "a tree session needs no flat wrap of it;\n        // nor a head's `next`\n        if matches!(key.origin, Origin::Tree) {")], ua(NEXT), NEXT),
    ("next derived from", [(AK, "            if matches!(k.origin, Origin::TreeNext) {", "            if false {")], ua(NEXT), NEXT),
    ("next MACed", [(AK, "        self.check_usage(key, KeyUsage::Derive)?;\n        if matches!(key.origin, Origin::TreeNext) {",
                     "        self.check_usage(key, KeyUsage::Derive)?;\n        if false {")], ua(NEXT), NEXT),
    # C-2 = G-1 = D-2, C-3: a resume keeps the leaves under review; F-2 = C-4: adopt drops the old head's `next`
    ("resume drops the warnings", [(TR, "            f.warnings\n                .iter()", "            f.warnings\n                .iter()\n                .take(0)")], ua(RESUME), RESUME),
    ("resume drops the suspects", [(TR, "            f.suspects\n                .iter()", "            f.suspects\n                .iter()\n                .take(0)")], ua(RESUME), RESUME),
    ("adopt keeps the old head", [(TR, "            from.head = None;\n", "")], ua(RESUME), RESUME),
    # the re-check's R-1: the warnings half in each language (run 1: the ua-rs one survived; efd338878 adds its test)
    ("JS resume drops the warnings", [(JS, "const warnings = (from?.warnings ?? [])", "const warnings = ([])")], ck("treekem.test.js", "R-1"), "R-1"),
    ("JS resume drops the suspects", [(JS, "const suspects = (from?.suspects ?? [])", "const suspects = ([])")], ck("treekem.test.js", "C-2 = G-1"), "C-2 = G-1"),
    # E-3 = C-5: a bound above 510 refused at creation
    ("a bound above 510 signed", [(TR, 'if u32j(session, "pathRefreshBound").unwrap_or(0) > PATH_REFRESH_BOUND_MAX {', "if false {")], ua(BOUND), BOUND),
    ("JS a bound above 510 signed", [(JS, '  if ((session.pathRefreshBound ?? 0) > tr.PATH_REFRESH_BOUND_MAX) refuse("PqChatShape");\n', "")], ck("treekem.test.js", "C-1: a key no signed"), "C-1: a key no signed"),
    # C-9: a missing counter is a lying read
    ("a missing sincePath read as 0", [(TP, '            since_path: u32j(j, "sincePath")?,', '            since_path: u32j(j, "sincePath").unwrap_or(0),')], ua(JSON), JSON),
    ("JS a missing counter read as 0", [(JT, "  sincePath: counter(t.sincePath),", "  sincePath: t.sincePath ?? 0,")], ck("pqchat-tree.test.js", "C-9"), "C-9"),
    # C-10: a seedless device's own path-less record
    ("JS seedless own path-less as compromise", [(JS, '  if (p.own && !dev.kemSeed) return { state: "not followed", reason: "random key" };\n', "")], ck("treekem.test.js", "C-10"), "C-10"),
    # E-4: the two path-less refusals by name
    ("PathBound named Shape", [(TP, "                return refuse(TreeError::PathBound);", "                return refuse(TreeError::Shape);")], ua(NAMES), NAMES),
    ("PathRequired named Shape", [(TP, "            return refuse(TreeError::PathRequired);", "            return refuse(TreeError::Shape);")], ua(NAMES), NAMES),
    # D-1 = G-2: a path commit over leaves under review asks first
    ("the review not asked", [(P, "        if !pathless && !st.replay.review.is_empty() && !c.review_acknowledged && !preview {",
                               "        if false {")], pq("tree_scenarios", "a_path_commit_over_leaves_under_review_asks_first"), "a_path_commit_over_leaves_under_review_asks_first"),
    # D-3: the head's admins from the walk
    ("no head admins read", [(P, "            .head_admins\n            .iter()", "            .head_admins\n            .iter()\n            .take(0)")],
     pq("tree_scenarios", "the_pathless_form_from_the_state"), "the_pathless_form_from_the_state"),
    # E-2 = D-6: a lost slot is TreeStale
    ("a lost slot not named", [(P, '        "683ad3f6",\n', "")], pq("lib", "a_lost_slot_is_named"), "a_lost_slot_is_named"),
    # D-10: a head confirmed by its id
    ("a head confirmed by number only", [(P, "head > c || (head == c && ids.last() != Some(&id))", "head > c")],
     pq("tree_scenarios", "a_head_is_confirmed_by_its_id"), "a_head_is_confirmed_by_its_id"),
    # F-4 (UNSURE in the review): the R20 reset, a chain kept over a path commit the device did not follow
    ("the chain kept over a path commit not followed", [(TR, "            chain = next_chain;\n", "            chain = next_chain.or(chain);\n")], ua("tree_secrets_every_row"), "tree_secrets_every_row"),
]

if __name__ == "__main__":
    main("p9", MUTANTS, prefix="2026-11-27-treekem-pathless")
