# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T8 mutants (F17): python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t8-mutants.py check | run
(`connect_http` itself is no longer reachable: the verifier's alloy has no `reqwest` transport left in its reads; its mutant is
the bounded transport's cap dropped.)"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

V = "scaas-pqz-verifier/src/chain.rs"
T = "cd scaas-pqz-verifier && ../scripts/capped cargo test --locked --offline -j2 --test service "
MUTANTS = [
    ("no eth_chainId check at start", [(V, '            anyhow::ensure!(id == chain_id, "rpc_urls[{i}] answers chain {id}, the config pins {chain_id}");\n', "            let _ = id;\n")],
     T + "start_pins_chain_id"),
    ("no answer bound (connect_http reads an answer whole)", [("clients/scaas-rpc/src/evm.rs", "BoundedRpc::new(h.clone(), list.clone(), i, ANSWER_MAX, deadline)", "BoundedRpc::new(h.clone(), list.clone(), i, usize::MAX, deadline)")],
     T.replace("--test service", "--test bounds") + "an_answer_above_16_mib_is_the_nodes_failure"),
]

if __name__ == "__main__":
    main("t8", MUTANTS)
