# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T5 mutants (F17, the node's wiring): python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t5-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

N = "scaas-node/src/chain.rs"
T = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib chain::tests::"
MUTANTS = [
    ("a fresh Arc instead of cfg.head", [(N, "let shared = scaas_rpc::evm::Shared { head: cfg.head.clone(),", "let shared = scaas_rpc::evm::Shared { head: Default::default(),")],
     T + "chain_reads_fail_over_on_transport_errors_never_on_a_revert"),
    ("failover_answers returning the total", [(N, "        self.pool.failover_answers()\n", "        self.pool.pool().failover_total()\n")],
     T + "chain_reads_fail_over_on_transport_errors_never_on_a_revert"),
    ("the simulation on the 30 s clients", [(N, "scaas_rpc::Policy::Failover, cfg.rpc_timeout_ms, cfg.rpc_simulate_timeout_ms,", "scaas_rpc::Policy::Failover, cfg.rpc_timeout_ms, cfg.rpc_timeout_ms,")],
     T + "a_hung_endpoint_and_the_block_gas_read_fail_over"),
    ("a lane read through the failover read", [(N, "self.pool.first_pending_nonce(self.address).await", "self.pool.pending_nonce(self.address, scaas_rpc::Purpose::Plain).await")],
     T + "the_lane_reads_stay_on_the_first_endpoint"),
]

if __name__ == "__main__":
    main("t5", MUTANTS)
