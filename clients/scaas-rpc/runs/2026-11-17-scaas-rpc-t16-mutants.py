# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T16 (Solana) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t16-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/solana.rs"
N = "scaas-node/src/adapters/solana.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test solana "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::solana::tests::"
MUTANTS = [
    # the plan's family mutants (a): the quorum helper on endpoint 0 only (the adapter's loop), no API key on Solana, the 20 s
    # timeout is the family client's (T15's mutant)
    ("a: the block produced at the slot itself", [(S, "            .and_then(|a| a.last())", "            .and_then(|a| a.first())")],
     T + "the_finalized_reads"),
    ("a: an error answer's code lost", [(N, "                code: e[\"code\"].as_i64().unwrap_or(0),", "                code: 0,")],
     NT + "an_error_answer_reaches_the_classifier_whole"),
    ("a: the identity a constant", [(S, "            Some(g) => Ok(g == self.genesis),", "            Some(_) => Ok(true),")],
     T + "the_failover_drops_another_cluster_and_skips_an_endpoint_behind"),
    ("b: tx_status through failover", [(N, "        let v = self.rpc(\"getSignatureStatuses\", json!([[sig], {\"searchTransactionHistory\": true}])).await?;",
        "        let v = self.read(\"getSignatureStatuses\", json!([[sig], {\"searchTransactionHistory\": true}])).await?;")],
     NT + "solana_tx_status_op_consumed_and_the_lane_sequence_never_fail_over"),
    ("b: op_consumed through failover", [(N, "        let next = match self.account_data(&pda, \"confirmed\").await? {", "        let next = match self.read_account(&pda, \"confirmed\").await? {")],
     NT + "solana_tx_status_op_consumed_and_the_lane_sequence_never_fail_over"),
    ("b: the lane sequence through failover", [(N, "        Ok(nonce_sequence(&self.nonce(lane).await?))", "        Ok(nonce_sequence(&self.read_nonce(lane).await?))")],
     NT + "solana_tx_status_op_consumed_and_the_lane_sequence_never_fail_over"),
    ("b: the build's simulation on endpoint 0 only", [(N, "            .read(\"simulateTransaction\", json!([b64,", "            .rpc(\"simulateTransaction\", json!([b64,")],
     NT + "solana_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: a failover refusal final (the counter not compared)", [(N, "            Err(SimError::Revert(r)) if self.failovers() != mark =>", "            Err(SimError::Revert(r)) if false =>")],
     NT + "solana_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
]

if __name__ == "__main__":
    main("t16", MUTANTS)
