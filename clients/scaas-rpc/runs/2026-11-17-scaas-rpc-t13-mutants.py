# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T13 mutants (one or more per review finding's new check):
python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t13-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/scaas-rpc/src/pool.rs"
E = "clients/scaas-rpc/src/evm.rs"
EP = "clients/scaas-rpc/src/endpoint.rs"
H = "clients/scaas-rpc/src/http.rs"
N = "clients/scaas-rpc/src/node.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features "
MUTANTS = [
    ("S1 no freshness", [(P, "let fresh = |i: usize| names[i].is_some_and(|x| number.saturating_add(self.max_lag) >= x);",
                          "let fresh = |i: usize| names[i].is_some();")],
     T + "--test pool one_endpoint_cannot_choose_an_old_block"),
    ("S2 one floor for every choice", [(P, "        let floor = self.agreed_floor(choice);\n",
                                        "        let floor = self.floor.lock().map(|f| f.values().copied().max().unwrap_or(0)).unwrap_or(0);\n")],
     T + "--test pool reads_of_every_block_choice_mix_on_one_pool"),
]

if __name__ == "__main__":
    main("t13", MUTANTS)
