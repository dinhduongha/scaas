# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T19 (Aptos) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t19-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/aptos.rs"
N = "scaas-node/src/adapters/aptos.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test aptos "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::aptos::tests::"
MUTANTS = [
    # the plan's family mutants (a); the 20 s is T15's family mutant
    ("a: the quorum read on endpoint 0 only", [(S, "            for i in 1..self.client.len() {", "            for i in 1..1 {")],
     T + "the_rest_reads_the_quorum_read_and_the_indexer"),
    ("a: the indexer key dropped", [(N, "indexer_key.map(|k| scaas_rpc::EndpointAuth::Bearer(scaas_rpc::Secret::new(&k)))", "indexer_key.and(None::<scaas_rpc::EndpointAuth>)")],
     NT + "the_indexer_key_goes_to_the_indexer_only"),
    ("a: a 404 an error", [(S, "            404 => Ok(None),", "            400 => Ok(None),")],
     T + "the_rest_reads_the_quorum_read_and_the_indexer"),
    ("a: the identity a constant", [(S, "            Some(c) => Ok(c == u64::from(self.chain_id)),", "            Some(_) => Ok(true),")],
     T + "the_failover_drops_another_network_and_skips_an_endpoint_behind"),
    # (b) the carve-out (F3) first, then the failover
    ("b: every read fails over (the carve-out gone)", [("scaas-node/src/adapters/evm.rs", "    BUILDING.try_with(|_| ()).is_ok()", "    true")],
     NT + "aptos_tx_status_op_consumed_and_the_lane_sequence_never_fail_over"),
    ("b: the build's reads on endpoint 0 only", [(N, "        match BUILDING.scope((), self.build_on(job, lane)).await {", "        match self.build_on(job, lane).await {")],
     NT + "aptos_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: a failover refusal final (the counter not compared)", [(N, "            Err(SimError::Revert(r)) if self.failovers() != mark => Err(SimError::Transport(crate::adapters::evm::failover_answer(&r))),\n            r => r,\n        }\n    }\n\n    async fn sign", "            r => r,\n        }\n    }\n\n    async fn sign")],
     NT + "aptos_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: a later endpoint's refusal text reaches the classifier", [(N, "            Err(e) => Err(crate::adapters::evm::all_failed(path, &e)),", "            Err(e) => bail!(\"{path}: {e}\"),")],
     NT + "aptos_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
]

if __name__ == "__main__":
    main("t19", MUTANTS)
