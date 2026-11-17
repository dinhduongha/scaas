# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T18 (Algorand) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t18-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/algorand.rs"
H = "clients/scaas-rpc/src/http.rs"
N = "scaas-node/src/adapters/algorand.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test algorand "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::algorand::tests::"
MUTANTS = [
    # the plan's family mutants (a): the API key header dropped; the quorum on endpoint 0 only is the adapter's loop; the
    # 20 s is T15's family mutant
    ("a: the algod token dropped", [(N, "                    token.map(|t| scaas_rpc::EndpointAuth::Header { name: \"X-Algo-API-Token\".into(), value: scaas_rpc::Secret::new(&t) }),",
        "                    token.and(None),")],
     NT + "the_algod_token_goes_to_every_endpoint_and_a_status_is_algod_error"),
    ("a: a raw answer scanned as JSON", [(H, "                (ctype, false),", "                (ctype, true),")],
     T + "the_raw_reads_the_status_classes_and_the_token"),
    ("a: a non-2xx read as an answer", [(S, "    if (200..300).contains(&status) {", "    if status < 500 {")],
     T + "the_raw_reads_the_status_classes_and_the_token"),
    ("a: the identity a constant", [(S, "            Some(g) => Ok(g == self.genesis),", "            Some(_) => Ok(true),")],
     T + "the_failover_drops_another_network_and_skips_an_endpoint_behind"),
]

if __name__ == "__main__":
    main("t18", MUTANTS)
