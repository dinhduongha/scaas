# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM T6 mutants (the crate's tree mode; plan T6a's 13 and T6b's 10, then the T4-T9 review's fixes), each killed
by its named test (feature vectors, through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py,
ARCH-POS-23). The walk's checks are `scaas-ua`'s (the crate delegates them): their mutants are killed by `ua-rs`'s
`tests/tree.rs` over the vectors' lies, or by the crate's recovery gate.
python3 clients/pqchat-core/runs/2026-11-26-pqchat-treekem-t6-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "runs"))
from mutants_lib import main

T = "clients/pqchat-core/src/tree.rs"
N = "clients/pqchat-core/src/net.rs"
ST = "clients/pqchat-core/src/stores.rs"
MS = "clients/pqchat-core/src/message.rs"
U = "clients/ua-rs/src/wallet/tree.rs"
UP = "clients/ua-rs/src/wallet/tree_public.rs"
S = "clients/scaas-sdk/src/pqchat_tree.rs"
AC = "clients/scaas-sdk/src/app_core.rs"
P = "clients/scaas-rpc/src/pool.rs"
CMD = ("cd clients/pqchat-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 --features vectors "
       "--test tree_scenarios")
LIB = "cd clients/pqchat-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 --features vectors --lib "
UA = ("cd clients/ua-rs && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 "
      "--features app-core,vectors --test tree")
SDK = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 "
       "--features pqchat-records,vectors --test pqchat_keys read_app_agreed_is_the_agreed_read")
RPC = ("cd clients/scaas-rpc && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 --test pool "
       "the_named_agreement_counts_named_endpoints_only")
MUTANTS = [
    # ---- plan T6a
    ("T6a encrypting before the signature check (a commit's signature unchecked)",
     [(U, 'let version = verified(sc, &*rd, "PqChatCommit", &c, &author, served(v.get("sig"))?)?;',
       'let version = verified(sc, &*rd, "PqChatCommit", &c, &author, served(v.get("sig"))?).unwrap_or_default();')],
     UA),
    ("T6a the tree hash not recomputed",
     [(U, "            || applied.tree_hash != b32j(c, \"treeHash\")?\n", "")], UA),
    ("T6a a tree read from a replica",
     [(T, "    ) -> Result<Value, PqChatError> {\n        self.net.read(&s.chain, &s.home, item, args).await\n    }",
       "    ) -> Result<Value, PqChatError> {\n        self.net.read(&s.chain, \"0x5ca00000000000000000000000000000000000c2\", item, args).await\n    }")],
     CMD, "recovery_every_scenario_device"),
    ("T6a the checkpoint not consulted",
     [(T, "            .get::<Value>(&pin_key(&tree_id))?\n            .filter(|p| !p.is_null());\n        let app",
       "            .get::<Value>(&pin_key(&tree_id))?\n            .filter(|_| false);\n        let app")],
     CMD, "a_twin_at_the_pin_is_settled_by_the_majority"),
    ("T6a the checkpoint by epoch id only",
     [(U, "        let p = self.pin_at(sc, s.epoch)?;\n        if p.hash != s.hash {",
       "        let p = self.pin_at(sc, s.epoch)?;\n        if false {")],
     CMD, "a_twin_at_the_pin_is_settled_by_the_majority"),
    ("T6a the pin not compared when the head is higher (codex-r3-2)",
     [(U, "        let p = self.pin_at(sc, s.epoch)?;\n        if p.hash != s.hash {",
       "        let p = self.pin_at(sc, s.epoch)?;\n        if self.head == s.epoch && p.hash != s.hash {")],
     CMD, "a_twin_at_the_pin_is_settled_by_the_majority"),
    ("T6a a cached info sealed in full after a gap without the review",
     [(T, "(Some(_), None) if !c.info_reviewed => return Err(PqChatError::TreeInfoReview),", "")],
     CMD, "an_info_after_a_gap_needs_its_review"),
    ("T6a a lookup that reads only the latest version",
     [(T, "            let versions: Vec<u64> = if high <= KEM_SCAN_MAX {\n                (0..=high).collect()",
       "            let versions: Vec<u64> = if high <= KEM_SCAN_MAX {\n                vec![high]")],
     CMD, "the_add_warnings_lookup"),
    ("T6a a pin replaced on one node's word",
     [(T, "        if named < 3\n            || at(&v, \"0\")", "        if at(&v, \"0\")")],
     CMD, "a_twin_at_the_pin_is_settled_by_the_majority"),
    ("T6a the setting taken from one discovered node (sigStore a plain read)",
     [(N, '    ("IPqChat.sigStore", Trusted),', '    ("IPqChat.sigStore", Plain),')],
     LIB + "tree_reads_are_trusted", "tree_reads_are_trusted"),
    ("T6a a changed info sealed with one endpoint",
     [(T, "                Fresh::Unavailable if !changed => false,\n                _ => return Err(PqChatError::TreeInfoUnconfirmed),",
       "                _ => false,")],
     CMD, "a_changed_info_is_sealed_only_after_the_majority_read"),
    ("T6a a discovered node counted among the 3 (the SDK's named read over the whole list)",
     [(AC, "                pool.read_at_block_agreed_named(choice, purpose, call)\n",
       "                pool.read_at_block_agreed(choice, purpose, call)\n")],
     SDK, "read_app_agreed_is_the_agreed_read"),
    ("T6a a discovered node counted among the 3 (scaas-rpc's named agreement over every class)",
     [(P, "        let member = |i: usize| !only_named || self.classes[i] == Class::Named;",
       "        let member = |_: usize| true;")],
     RPC, "the_named_agreement_counts_named_endpoints_only"),
    ("T6a a receipt sent in a tree session",
     [(ST, "            && self.tree_epoch(&ep.epoch.id).is_some()\n            && prefs.receipts != Some(true)",
       "            && self.tree_epoch(&ep.epoch.id).is_some()\n            && prefs.receipts == Some(false)")],
     CMD, "a_tree_epoch_sends_no_receipt_by_default"),
    # ---- plan T6b
    ("T6b an automatic write after a failed open",
     [(T, "        let unconfirmed = asked && self.majority_tree(s, &seen).await != Fresh::Confirmed;",
       "        let unconfirmed = asked && self.majority_tree(s, &seen).await != Fresh::Confirmed;\n"
       "        if r.epochs.iter().any(|e| e.state != \"followed\") {\n"
       "            let _ = self.net.prepare(&s.chain, &s.home, \"IPqChat.commit\", json!({}), &KeyRef::Native { seed: String::new(), network: \"evm\".into(), index: 0 }).await;\n"
       "        }")],
     CMD, "a_failed_open_reads_as_a_followed_one"),
    ("T6b a held send flushed (a tree epoch's child not asked for)",
     [(MS, "                None if self.tree_epoch(&ep.epoch.id).is_some() => {\n                    return Err(PqChatError::EpochTaken)\n                }\n", "")],
     CMD, "a_tree_send_meets_its_child_and_an_exit_its_lag"),
    ("T6b a read skipped after a failed open",
     [(T, "        let asked = pinned.is_none_or(|p| head > p);",
       "        let asked = pinned.is_none_or(|p| head > p) && r.epochs.iter().all(|e| e.state == \"followed\");")],
     CMD, "a_failed_open_reads_as_a_followed_one"),
    ("T6b a dropped UA accepted without its signed leave or removal",
     [(UP, ".all(|x| x.ua == c.author || self.gone_ua.contains(&x.ua));", ".all(|_| true);")], UA),
    ("T6b replay that reads an event",
     [(T, "            let mut names = vec![format!(\"leaveCount({e})\"), format!(\"removalCount({e})\")];",
       "            let _ = self.net.read(&s.chain, &s.home, \"IPqChat.byAuthor\", json!({})).await;\n"
       "            let mut names = vec![format!(\"leaveCount({e})\"), format!(\"removalCount({e})\")];")],
     CMD, "recovery_every_scenario_device"),
    ("T6b replay that opens before the join",
     [(U, "        let first = if from.is_some() { n0 + 1 } else { join_epoch };",
       "        let first = if from.is_some() { n0 + 1 } else { join_epoch.saturating_sub(1) };")],
     CMD, "recovery_every_scenario_device"),
    ("T6b the range stopped at endEpoch (a ciphertext opened at the commit that removed the key)",
     [(U, "        let last = end_epoch.map_or(head, |e| e - 1);", "        let last = end_epoch.map_or(head, |e| e);")],
     CMD, "recovery_every_scenario_device"),
    ("T6b the join's author judged without the parent's admins",
     [(U, "let admin = n == 0 || a.admins_at(n - 1)?.contains(&author);",
       "let admin = n == 0 || a.admins_at(n)?.contains(&author);")],
     CMD, "recovery_every_scenario_device"),
    ("T6b the warning cleared by a refresh while a foreign leaf stays",
     [(U, "                    leaves_left: adds.iter().filter(|x| live(x)).map(|x| x.leaf).collect(),",
       "                    leaves_left: vec![],")],
     CMD, "recovery_every_scenario_device"),
    ("T6b a commit author not checked against the roster",
     [(UP, "Some(me) if c.leaf < t.leaves && me.ua == c.author && me.key_id == c.key_id =>",
       "Some(_) if c.leaf < t.leaves =>")], UA),
    # ---- the T4-T9 review's fixes
    ("C-1 a record stored alone taken as complete",
     [(S, "    if fin.complete {\n        return PqTreeNext::Done;\n    }\n    if plan.txs.len() == 1 && landed.record {",
       "    if fin.complete || (plan.txs.len() == 1 && landed.record) {\n        return PqTreeNext::Done;\n    }\n    if plan.txs.len() == 1 && landed.record {")],
     CMD, "a_record_landed_alone_is_not_complete"),
    ("D-14 what landed read at the final block only",
     [(T, "                self.net.read_latest(&s.chain, &s.home, item, args).await",
       "                self.net.read(&s.chain, &s.home, item, args).await")],
     CMD, "a_record_landed_not_final_is_not_sent_again"),
    ("D-2 a first pin written without the majority",
     [(T, "        if pin.is_some() || !unconfirmed {", "        if true {")],
     CMD, "a_first_pin_needs_the_majority"),
    ("D-3 the majority read compared by its head only",
     [(T, "            Ok((v, named)) if named >= 3 && v == *seen => Fresh::Confirmed,",
       "            Ok((v, named)) if named >= 3 && v[\"headEpochId\"] == seen[\"headEpochId\"] => Fresh::Confirmed,")],
     CMD, "a_changed_info_is_sealed_only_after_the_majority_read"),
    ("D-5 a changed info refused on the receiving side",
     [(T, "        let unconfirmed = asked && self.majority_tree(s, &seen).await != Fresh::Confirmed;",
       "        let unconfirmed = asked && self.majority_tree(s, &seen).await != Fresh::Confirmed;\n"
       "        if unconfirmed && r.epochs.iter().any(|e| e.info.as_deref() == Some(\"changed\")) {\n"
       "            return Err(PqChatError::TreeInfoUnconfirmed);\n        }")],
     CMD, "a_changed_info_is_taken_whatever_the_majority"),
    ("D-6 the snapshot checked only after the call",
     [(T, "            if !fresh {\n                fresh = true;", "            if false {\n                fresh = true;")],
     CMD, "a_head_that_moves_during_a_resume_keeps_every_epoch_followed"),
    ("C-8 the resume's reads from epoch 0",
     [(T, "                self.tree_prefetch(s, reads, start).await?;", "                self.tree_prefetch(s, reads, 0).await?;")],
     CMD, "a_head_that_moves_during_a_resume_keeps_every_epoch_followed"),
    ("D-10 a commit on a moved head",
     [(T, "            return Err(PqChatError::TreeStale);\n        }\n        let head_confirmed",
       "        }\n        let head_confirmed")],
     CMD, "a_commit_on_a_state_behind_the_head_is_refused"),
    ("C-10 an exit past the lag signed",
     [(T, "            .map(|i| first + i as u64)\n            .ok_or(PqChatError::ExitLag)",
       "            .map(|i| first + i as u64)\n            .or(Some(0))\n            .ok_or(PqChatError::ExitLag)")],
     CMD, "a_tree_send_meets_its_child_and_an_exit_its_lag"),
    ("C-6 a session closed by exits shown open",
     [(T, "        .chain(list(at(pin, \"exits\")).iter().map(first))\n", "")],
     LIB + "a_session_closed_by_exits", "a_session_closed_by_exits"),
    ("C-9 the forged continuation taken at another number",
     [(U, "            let changes = c.get(\"removes\")?.as_array()?.iter();\n            Some(\n                u64j(&c, \"epoch\").ok()? == n\n                    && b32j(&c, \"sessionId\").ok()? == self.sid\n                    && sc.epoch_id(",
       "            let changes = c.get(\"removes\")?.as_array()?.iter();\n            Some(\n                true\n                    && b32j(&c, \"sessionId\").ok()? == self.sid\n                    && sc.epoch_id(")],
     CMD, "hostile_reads_are_refused"),
]

if __name__ == "__main__":
    main("t6", MUTANTS, prefix="2026-11-26-pqchat-treekem")
