# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM T4 (the rest, after the merge) mutants, node side: the whole-set guard (fable-r3-6), C37's order
(codex-r3-12) and the exit that waits within the lag (D2-5), each killed by its named test of `scaas-node` (lib, through
scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py, ARCH-POS-23):
python3 runs/2026-11-26-pqchat-treekem-t4b-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

T = "scaas-node/src/tree_set.rs"
G = "scaas-node/src/guard.rs"
SET = "cd scaas-node && CARGO_INCREMENTAL=0 ../scripts/capped cargo test --locked -j 2 --lib tree_set"
EXIT = "cd scaas-node && CARGO_INCREMENTAL=0 ../scripts/capped cargo test --locked -j 2 --lib an_exit_waits_within_the_lag"
MUTANTS = [
    ("the guard checks the hashes but not the admission check",
     [(T, """        if !admissible(&pk) {
            return bad(format!("node key {k} fails the admission check"));
        }
""", "")], SET, "the_whole_set_guard"),
    ("a path ciphertext not checked against ctHashes",
     [(T, """        if hash("PathCt", ct) != b32(h) {
            return bad(format!("ciphertext {i} does not hash to ctHashes[{i}]"));
        }
""", "")], SET, "the_whole_set_guard"),
    ("a Welcome wrap not checked against wrapHashes",
     [(T, """        if hash("Wrap", w) != b32(h) {
            return bad(format!("Welcome wrap {i} does not hash to wrapHashes[{i}]"));
        }
""", "")], SET, "the_whole_set_guard"),
    ("a set with a piece missing taken (the ciphertexts' count)",
     [(T, """    if path.len() != cts {
        return bad(format!(
            "path ciphertexts: {cts} signed, {} held",
            path.len()
        ));
    }
""", "")], SET, "the_whole_set_guard"),
    ("no piece held back: the last transaction holds several pieces",
     [(T, """    if s.cts > 0 {
        Some((true, s.cts - 1))
    } else {
        (s.adds > 0).then(|| (false, s.adds - 1))
    }""", "    let _ = s;\n    None")], SET, "c37_order_to_the_end"),
    ("the node keys not final before the ciphertexts",
     [(T, """        if !fin.keys {
            return Step::Wait("the node keys are not final".into());
        }
""", "")], SET, "c37_order_to_the_end"),
    ("the held ciphertext sent before every other piece is final",
     [(T, """        Some((true, i)) if !at(&latest.cts, i) => {
            if !rest_final {""", """        Some((true, i)) if !at(&latest.cts, i) => {
            if false && !rest_final {""")], SET, "c37_order_to_the_end"),
    ("a piece on its own relayed while ciphertexts are missing",
     [(T, """    let n = have.cts.iter().filter(|x| !**x).count();
    if n > 0 {
        missing.push(format!("{n} ciphertext(s)"));
    }
""", "")], SET, "a_piece_alone"),
    ("a backlog refusal of an exit reported dead",
     [(G, 'const EXIT_WAITS: [&str; 3] = ["PqChatTreeBacklog", "PqChatIncomplete", "PqVaultIncomplete"];',
       'const EXIT_WAITS: [&str; 3] = ["PqChatTreeBacklogX", "PqChatIncomplete", "PqVaultIncomplete"];')],
     EXIT, "an_exit_waits_within_the_lag"),
    ("an exit past the lag kept waiting",
     [(G, '    (exit_op(data) && EXIT_WAITS.iter().any(|p| reason.starts_with(p)))\n',
       '    (exit_op(data) && (reason.starts_with("PqChatExitLag") || EXIT_WAITS.iter().any(|p| reason.starts_with(p))))\n')],
     EXIT, "an_exit_waits_within_the_lag"),
    # the T4-T9 review's fixes (A-4, A-5, D-12)
    ("A-4 a ciphertext before its list refused as a bad hash",
     [(T, '        "addPath" if r.cts > 0 && ct_hashes.is_empty() => {', '        "addPath" if false => {')],
     SET, "a_piece_early_a_short_key_list_and_a_wrap_of_another_member"),
    ("A-5 node keys short of the signed count waiting for ever",
     [(T, "            if held.len() != r.key_hashes.len() {\n                return bad(format!(",
       "            if false {\n                return bad(format!(")],
     SET, "a_piece_early_a_short_key_list_and_a_wrap_of_another_member"),
    ("D-12 a Welcome wrap of another member than its Add",
     [(T, "        if b32(&w[\"member\"]) != b32(&add[\"ua\"]) || num(&w[\"keyId\"]) != num(&add[\"keyId\"]) {",
       "        if false {")],
     SET, "a_piece_early_a_short_key_list_and_a_wrap_of_another_member"),
]

if __name__ == "__main__":
    main("t4b", MUTANTS, prefix="2026-11-26-pqchat-treekem")
