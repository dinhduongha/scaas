# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T3 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t3-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/scaas-rpc/src/pool.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test pool "
MUTANTS = [
    ("need = n / 2", [(P, "let need = n / 2 + 1;", "let need = n / 2;")], T + "four_two_agree_two_fail_is_no_majority"),
    ("the smallest named block", [(P, "let b = sorted[need - 1];", "let b = *sorted.last().unwrap();")],
     T + "the_block_is_the_need_th_highest_named"),
    ("answers not compared whole (any two values agree)", [(P, "(Ok(x), Ok(y)) => x == y,", "(Ok(_), Ok(_)) => true,")],
     T + "two_lie_on_different_words_is_no_majority"),
    ("skip the re-check", [(P, "            let again =\n                futures::future::join_all(todo.iter().map(|&m| probe.header(m, number, deadline)))\n                    .await;",
                            "            let again: Vec<Result<P::Hash, EndpointFailure>> = todo.iter().map(|_| Ok(hash.clone())).collect();")],
     T + "a_reorg_during_the_read_is_block_changed"),
    ("count only answering endpoints as n", [(P, "        if sorted.len() < need {\n            return Err(no(0, failures));",
                                              "        let need = sorted.len() / 2 + 1;\n        if sorted.len() < need {\n            return Err(no(0, failures));")],
     T + "four_two_agree_two_fail_is_no_majority"),
    ("await every endpoint", [(P, "        )> = vec![];\n        let same =", "        )> = vec![];\n        let mut decided = None;\n        let same ="),
                              (P, "                return Ok((v, h, members));", "                decided.get_or_insert((v, h, members));\n                continue;"),
                              (P, "        Err((\n            groups.iter().map(|g| g.2.len()).max().unwrap_or(0),\n            failures,\n        ))",
                               "        if let Some(d) = decided {\n            return Ok(d);\n        }\n        Err((\n            groups.iter().map(|g| g.2.len()).max().unwrap_or(0),\n            failures,\n        ))")],
     T + "two_fast_equal_and_one_hung_decide_before_the_timeout"),
    ("no fallback round", [(P, "let fallback = sorted.iter().copied().find(|&x| x < b && x >= floor);", "let fallback: Option<u64> = None;")],
     T + "a_far_future_liar_at_n_3_agrees_in_the_fallback_round"),
    ("no floor", [(P, "        if b < floor {\n", "        if false {\n")], T + "an_agreement_below_the_last_agreed_block_is_refused"),
    ("no read deadline", [(P, "let deadline = Some(self.deadline());", "let deadline: Option<Instant> = None;")],
     T + "a_slow_endpoint_is_bounded_by_the_read_deadline"),
    ("a later endpoint's revert ends the read", [(P, "Err(ReadError::Revert { data, reason }) if i == first =>", "Err(ReadError::Revert { data, reason }) if true =>")],
     T + "a_revert_from_a_later_endpoint_moves_on_and_keeps_its_data"),
    ("a later endpoint raises the head", [(P, "                    let n = probe.head(i, None).await?;\n",
                                           "                    let n = probe.head(i, None).await?;\n                    self.head.fetch_max(n, Relaxed);\n")],
     T + "a_later_endpoint_behind_the_head_is_skipped"),
    ("a discovered endpoint for a decryption read under failover", [(P, "                all.filter(|&i| self.classes[i] != Class::Discovered)\n                    .collect()", "                all.collect()")],
     T + "discovered_is_skipped_under_failover"),
    ("identity not checked on endpoint 0", [(P, "                self.identity_ok(probe, i, None).await?;\n", "                if i != first {\n                    self.identity_ok(probe, i, None).await?;\n                }\n")],
     T + "the_first_endpoint_is_identity_checked_too"),
]

if __name__ == "__main__":
    main("t3", MUTANTS)
