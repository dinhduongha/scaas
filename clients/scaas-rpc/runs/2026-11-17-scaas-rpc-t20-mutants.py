# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T20 (Sui) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t20-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/sui.rs"
N = "scaas-node/src/adapters/sui.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test sui "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::sui::tests::"
MUTANTS = [
    # the plan's family mutants (a): the quorum on endpoint 0 only; Sui has no key; the 20 s is T15's family mutant
    ("a: the final head's quorum on endpoint 0 only", [(N, "        for i in 1..self.net.client.len() {", "        for i in 1..1 {")],
     NT + "sui_final_head_quorum_reads_every_endpoint"),
    ("a: the identity a constant", [(S, "        Ok(self.chain_identifier(i).await? == want)", "        Ok(true)")],
     T + "the_failover_drops_another_network_and_skips_an_endpoint_behind"),
    ("a: each endpoint its own reference", [(S, "                let w = self.chain_identifier(0).await.map_err(|e| {", "                let w = self.chain_identifier(i).await.map_err(|e| {")],
     T + "the_failover_drops_another_network_and_skips_an_endpoint_behind"),
]

if __name__ == "__main__":
    main("t20", MUTANTS)
