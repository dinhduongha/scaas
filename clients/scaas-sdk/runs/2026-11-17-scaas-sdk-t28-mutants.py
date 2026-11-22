# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T28 (node `POST /v1/ops`, `scaas-rpc` `submit_ops`) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t28-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "scaas-node/src/gateway.rs"
Q = "scaas-node/src/external_pull.rs"
N = "clients/scaas-rpc/src/node.rs"
NODE = "cd scaas-node && ../scripts/capped cargo test --locked --offline -j2 --lib "
RPC = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test node "
MUTANTS = [
    # a check skipped
    ("the token check skipped", [(G, "    if !c\n        .tokens\n        .read()\n        .map(|t| t.iter().any(|x| x == contract))",
                                  "    if false && !c\n        .tokens\n        .read()\n        .map(|t| t.iter().any(|x| x == contract))")],
     NODE + "ops_accept_checks_in_order_each_by_its_code"),
    ("the validity's upper bound dropped", [(G, "if valid_until <= now() || valid_until > now().saturating_add(max) {",
                                             "if valid_until <= now() {")],
     NODE + "ops_accept_checks_in_order_each_by_its_code"),
    ("a client digest other than the node's taken", [(G, "        if !d.eq_ignore_ascii_case(&format!(\"{digest:#x}\")) {",
                                                       "        if d.is_empty() {")],
     NODE + "a_client_digest_other_than_the_nodes_is_bad_payload"),
    # the family check dropped
    ("the family check dropped", [(G, "    if Family::parse(r.op[\"family\"].as_str().unwrap_or_default()) != Some(family) {",
                                   "    if Family::parse(r.op[\"family\"].as_str().unwrap_or_default()).is_none() {")],
     NODE + "ops_accept_checks_in_order_each_by_its_code"),
    ("TON reaches a lane", [(G, "    if family == Family::Ton {", "    if family == Family::Ton && false {")],
     NODE + "ton_is_refused_by_name"),
    # the own queue
    ("a lease by a worker without a lane", [(Q, "        let Some(label) = self.labels.get(worker) else {\n            return Ok(false);",
                                             "        let Some(label) = self.labels.values().next() else {\n            return Ok(false);")],
     NODE + "the_own_queue_hands_out_claims_and_moves_gateway_rows"),
    # the merge counting `unreachable` as accepted
    ("the merge counting unreachable as accepted", [(N, "            .filter(|(_, o)| matches!(o, NodeOutcome::Queued { .. }))",
                                                     "            .filter(|(_, o)| matches!(o, NodeOutcome::Queued { .. } | NodeOutcome::Unreachable(_)))")],
     RPC + "submit_ops_sends_the_same_bytes_and_merges"),
]

if __name__ == "__main__":
    main("t28", MUTANTS)
