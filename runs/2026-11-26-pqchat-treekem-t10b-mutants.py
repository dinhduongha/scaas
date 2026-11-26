# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM T10b mutants: the fixes of Fable's re-check of the T4-T9 fixes (R2-*), one per new check, each killed by
its named test (through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py, ARCH-POS-23).
python3 runs/2026-11-26-pqchat-treekem-t10b-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

U = "clients/ua-rs/src/wallet/tree.rs"
J = "clients/clientkeys/src/treekem.js"
T = "clients/pqchat-core/src/tree.rs"
MS = "clients/pqchat-core/src/message.rs"
N = "clients/pqchat-core/src/net.rs"
S = "clients/scaas-sdk/src/pqchat_tree.rs"
G = "clients/scaas-sdk/gas/pqchat-tree.json"
SUB = "scaas-node/src/submit.rs"
CARGO = "CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2"
UA = f"cd clients/ua-rs && {CARGO} --features app-core,vectors --test tree"
JS = "cd clients/clientkeys && ../../scripts/capped node scripts/pqchat-vectors.mjs --check"
SC = f"cd clients/pqchat-core && {CARGO} --features vectors --test tree_scenarios"
SIGNED = f"cd clients/pqchat-core && {CARGO} --features vectors --test signed agreed_reads_cover_the_control_plane_only"
CHAIN = f"cd clients/pqchat-core && {CARGO} --features vectors --test chain_tree -- --ignored"
SDK = f"cd clients/scaas-sdk && {CARGO} --features pqchat-records,vectors --lib every_signer_kind_has_a_verify_row"
NODE = ("cd scaas-node && CARGO_INCREMENTAL=0 ../scripts/capped cargo test --locked --offline -j 2 --lib "
        "a_record_another_sender_landed_between_the_simulations_is_no_verdict")
MUTANTS = [
    ("R2-D-1 treeOf.owed not compared (ua-rs)",
     [(U, '                && u64j(t, "owed").ok()? == owed as u64\n', "")], UA, "R2-D-1"),
    ("R2-D-1 treeOf.owed not compared (clientkeys)",
     [(J, "    t.owed === a.exits[head].reduce((sum, x) => sum + leavesOf(w, x.ua), 0) &&\n", "")], JS, "R2-D-1"),
    ("R2-C-2 a consumed replay resumed again",
     [(U, "        if from.is_some_and(|f| f.consumed) {\n            return refuse(TreeError::Period);\n        }\n", "")],
     SC, "a consumed replay"),
    ("R2-C-2 a resume from below the store's pin",
     [(U, "        if store.is_some_and(|p| from.pin.epoch < p.epoch) {\n            return refuse(TreeError::Checkpoint);\n",
       "        if store.is_some_and(|p| from.pin.epoch < p.epoch && false) {\n            return refuse(TreeError::Checkpoint);\n")],
     SC, "a resume below the pin"),
    ("R2-D-5 / U-a the node keys moved before the pin is stored",
     [(S, "                let g = f.inner.lock().unwrap_or_else(PoisonError::into_inner);\n"
          "                sc.tree_resume_kept(&PQCHAT_TREE, &mut rd, &dev, &g, pin.as_ref(), keys_from)",
       "                let mut g = f.inner.lock().unwrap_or_else(PoisonError::into_inner);\n"
       "                sc.tree_resume(&PQCHAT_TREE, &mut rd, &dev, &mut g, keys_from)")],
     SC, "a_failed_pin_write_keeps_the_replay_resumed_from"),
    ("R2-C-1 K handles from the pin's epoch",
     [(T, "app.pqchat_tree_vectors_replay(seed, kem_seed, ua, key_id, rd, pin, from, 0)",
       "app.pqchat_tree_vectors_replay(seed, kem_seed, ua, key_id, rd, pin, from, "
       "pin.and_then(|p| p.get(\"epoch\")).and_then(Value::as_u64).unwrap_or(0))")],
     SC, "K below the pin"),
    ("R2-D-3 unconfirmed cleared once the pin reaches the head",
     [(T, "        let asked = confirmed.is_none_or(|c| head > c);",
       "        let asked = epoch_of(pin.as_ref()).or(confirmed).is_none_or(|c| head > c);")],
     SC, "majority agrees false"),
    ("R2-C-3 a tree epoch without its author",
     [(T, "                author: e.author.to_ascii_lowercase(),", "                author: String::new(),")],
     SC, "a_tree_epoch_carries_its_author_and_admins"),
    ("R2-C-6 the tree epochs' info kept past the seed lock",
     [(MS, "        self.tree_epochs\n            .lock()\n            .unwrap_or_else(std::sync::PoisonError::into_inner)\n"
           "            .clear();\n", "")],
     SC, "the info dropped at the lock"),
    ("R2-C-4 a failover's kept revert not read",
     [(S, '        }) => d.starts_with(&scaas_ua::keccak256(b"PqChatUnknown()")[..4]),',
       '        }) => d.is_empty() && false,')],
     SC, "a_record_unknown_behind_a_down_first_endpoint_is_not_landed"),
    ("R2-C-5 the later poll resumed from epoch 0",
     [(T, "            let run = self\n                .tree_run(s, &mut reads, start.unwrap_or(0), |rd| {\n"
          "                    f(&app, rd, pin.as_ref(), resume)",
       "            let run = self\n                .tree_run(s, &mut reads, start.map_or(0, |_| 0), |rd| {\n"
       "                    f(&app, rd, pin.as_ref(), resume)")],
     SC, "the later poll starts at the pin"),
    ("R2-C-5 pin_replaced never set",
     [(T, "            unconfirmed,\n            pin_replaced: replaced,", "            unconfirmed,\n            pin_replaced: false,")],
     SC, "the event shown"),
    ("R2-C-5 unconfirmed never set",
     [(T, "            unconfirmed,\n            pin_replaced: replaced,", "            unconfirmed: false,\n            pin_replaced: replaced,")],
     SC, "a_first_pin_needs_the_majority"),
    ("R2-C-5 head_confirmed always true",
     [(T, "            plan,\n            head_confirmed,\n        })", "            plan,\n            head_confirmed: true,\n        })")],
     CHAIN, "one endpoint confirms nothing"),
    ("R2-D-8 D-11's agreed read restored to IPqChat. only",
     [(N, '    (item.starts_with("IPqChat.") || item.starts_with("IPqChatTreeViews."))',
       '    item.starts_with("IPqChat.")')],
     SIGNED, "agreed_reads_cover_the_control_plane_only"),
    ("R2-D-7 a derived kind without a verify row",
     [(G, '  "frost-bn254": {', '  "frost-bn254-unmeasured": {')], SDK, "frost-bn254"),
    ("R2-D-4 a race in the record-with-list simulation is a verdict",
     [(SUB, "                                    if tree_race(&r2) {\n",
       "                                    if tree_race(&r2) && false {\n")],
     NODE, "a_record_another_sender_landed_between_the_simulations_is_no_verdict"),
]

if __name__ == "__main__":
    main("t10b", MUTANTS, prefix="2026-11-26-pqchat-treekem")
