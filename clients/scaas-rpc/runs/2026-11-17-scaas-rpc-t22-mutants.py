# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T22 (TON) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t22-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/ton.rs"
N = "scaas-node/src/adapters/ton.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test ton "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::ton::tests::"
MUTANTS = [
    # the plan's family mutants (a): the API key dropped; the key to every endpoint; TON has no quorum helper (one endpoint
    # read today); the 20 s is T15's family mutant
    ("a: the TON Center key dropped", [(N, "                .filter(|_| i == 0)\n", "                .filter(|_| false)\n")],
     NT + "the_ton_center_key_goes_to_the_first_endpoint"),
    ("a: each endpoint the first's credential", [("clients/scaas-rpc/src/family.rs", ".map(|(i, u)| Endpoint::new(u, crate::Class::Named, None, auth(i)))", ".map(|(_, u)| Endpoint::new(u, crate::Class::Named, None, auth(0)))")],
     T + "the_reads_the_status_class_and_the_key_to_the_first_endpoint_only"),
    ("a: a non-2xx read as an answer", [(S, "        if !(200..300).contains(&status) {", "        if status >= 500 {")],
     T + "the_reads_the_status_class_and_the_key_to_the_first_endpoint_only"),
    # (b) the carve-out (F3) first, then the failover
    ("b: every read fails over (the carve-out gone)", [("scaas-node/src/adapters/evm.rs", "    BUILDING.try_with(|_| ()).is_ok()", "    true")],
     NT + "ton_tx_status_op_consumed_and_the_lane_sequence_never_fail_over"),
    ("b: the build's reads on endpoint 0 only", [(N, "        match BUILDING.scope((), self.build_on(job, lane)).await {", "        match self.build_on(job, lane).await {")],
     NT + "ton_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: a failover refusal final (the counter not compared)", [(N, "            Err(SimError::Revert(r)) if self.api.failovers() != mark => Err(SimError::Transport(crate::adapters::evm::failover_answer(&r))),\n", "")],
     NT + "ton_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: the first endpoint's key to every endpoint", [(N, "                .filter(|_| i == 0)\n", "                .filter(|_| true)\n")],
     NT + "ton_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
]

if __name__ == "__main__":
    main("t22", MUTANTS)
