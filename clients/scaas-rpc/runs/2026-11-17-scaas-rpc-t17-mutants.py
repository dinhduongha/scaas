# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T17 (NEAR) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t17-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/near.rs"
N = "scaas-node/src/adapters/near.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test near "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::near::tests::"
MUTANTS = [
    # the plan's family mutants (a): the quorum helper on endpoint 0 only; no API key on NEAR; the 20 s is T15's family mutant
    ("a: the quorum read on endpoint 0 only", [(S, "            for i in 1..self.client.len() {", "            for i in 1..1 {")],
     T + "the_block_reads_and_the_quorum_read"),
    ("a: an error's cause lost", [(N, "            let cause = error.pointer(\"/cause/name\").or_else(|| error.get(\"name\")).and_then(Value::as_str).unwrap_or(\"UNKNOWN\").to_string();",
        "            let cause = \"UNKNOWN\".to_string();")],
     NT),
    ("a: the identity a constant", [(S, "            Some(g) => Ok(g == self.genesis),", "            Some(_) => Ok(true),")],
     T + "the_failover_drops_another_network_and_skips_an_endpoint_behind"),
]

if __name__ == "__main__":
    main("t17", MUTANTS)
