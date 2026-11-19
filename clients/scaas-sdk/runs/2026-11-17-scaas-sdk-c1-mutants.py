# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Owner ruling C1 of 2026-11-19, scaas-rpc's PQZ verifier client: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-c1-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

N = "clients/scaas-rpc/src/node.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test node "
MUTANTS = [
    ("a verifier refusal failed over",
     [(N, "                    NodeOutcome::Refused(e) if !majority => return Err(e),\n", "")],
     T + "a_verifier_refusal_is_final_under_failover"),
    ("the majority compared with the signature",
     [(N, '        self.post(VERDICT_ROUTE, req, |v| v["pqzVerdict"].clone())', "        self.post(VERDICT_ROUTE, req, Value::clone)")],
     T + "verifier_strict_majority_compares_the_verdict"),
    ("a majority of one", [(N, "        let need = n / 2 + 1;", "        let need = 1;")],
     T + "verifier_strict_majority_compares_the_verdict"),
    ("the verifier body cap dropped", [(N, "        if body.len() > VERDICT_BODY_MAX {", "        if false {")],
     T + "a_verifier_redirect_is_not_followed_and_answers_are_bounded"),
]

if __name__ == "__main__":
    main("c1", MUTANTS)
