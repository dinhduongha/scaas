# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T15 (Soroban) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t15-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/soroban.rs"
F = "clients/scaas-rpc/src/family.rs"
N = "scaas-node/src/adapters/soroban.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test soroban "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::soroban::tests::"
MUTANTS = [
    # the plan's family mutants (a): the quorum helper asked on endpoint 0 only; the 20 s timeout replaced by 30 s (no API key here)
    ("a: the head quorum on endpoint 0 only", [(S, "        for i in 1..self.client.len() {", "        for i in 1..1 {")],
     T + "the_ledger_reads_and_the_head_quorum"),
    ("a: the family timeout 30 s", [(F, "pub const FAMILY_TIMEOUT_MS: u64 = 20_000;", "pub const FAMILY_TIMEOUT_MS: u64 = 30_000;")],
     "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --lib family::tests::"),
    ("a: an error answer read as a result", [(F, "        if let Some(e) = v.get_mut(\"error\").filter(|e| !e.is_null()) {", "        if let Some(e) = None::<&mut Value> {")],
     T + "an_error_answer_is_kept_whole"),
    ("a: the ledger hash not lowercased", [(S, "        Ok(format!(\"0x{}\", h.to_lowercase()))", "        Ok(format!(\"0x{h}\"))")],
     T + "the_ledger_reads_and_the_head_quorum"),
    ("b: tx_status through failover", [(N, "            let r = self.rpc(\"getTransaction\", json!({\"hash\": tx_id.trim_start_matches(\"0x\")})).await?;\n            Ok(match r[\"status\"].as_str() {",
        "            let r = self.read(\"getTransaction\", json!({\"hash\": tx_id.trim_start_matches(\"0x\")})).await?;\n            Ok(match r[\"status\"].as_str() {")],
     NT + "soroban_tx_status_never_fails_over"),
    ("b: op_consumed through failover", [(N, "        match self.view_first(contract, f, args).await {\n            Err(e) if e.is::<SimRefused>() => Ok(None),",
        "        match self.view(contract, f, args).await {\n            Err(e) if e.is::<SimRefused>() => Ok(None),")],
     NT + "soroban_op_consumed_and_the_lane_sequence_never_fail_over"),
    ("b: the lane sequence through failover", [(N, "        let r = self.rpc(\"getLedgerEntries\", json!({\"keys\": [k]})).await?;\n        let x = r[\"entries\"][0][\"xdr\"]",
        "        let r = self.read(\"getLedgerEntries\", json!({\"keys\": [k]})).await?;\n        let x = r[\"entries\"][0][\"xdr\"]")],
     NT + "soroban_op_consumed_and_the_lane_sequence_never_fail_over"),
    ("b: the build's simulation on endpoint 0 only", [(N, "            .read(\"simulateTransaction\", json!({\"transaction\": b64}))", "            .rpc(\"simulateTransaction\", json!({\"transaction\": b64}))")],
     NT + "soroban_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: a failover refusal final (the counter not compared)", [(N, "            Err(SimError::Revert(r)) if self.failovers() != mark =>", "            Err(SimError::Revert(r)) if false =>")],
     NT + "soroban_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
]

if __name__ == "__main__":
    main("t15", MUTANTS)
