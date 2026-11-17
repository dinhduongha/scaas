# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T11 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t11-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

N = "clients/scaas-rpc/src/node.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test node "
MUTANTS = [
    ("dead from the nodes heard only", [(N, "if !sent_to.is_empty() && sent_to.iter().all(|&i| matches!(of(i), Some(IntentState::Dead | IntentState::Unknown))) {",
                                         "if !sent_to.is_empty() && sent_to.iter().filter(|&&i| of(i).is_some()).all(|&i| matches!(of(i), Some(IntentState::Dead | IntentState::Unknown))) {")],
     T + "a_node_that_timed_out_on_submit_keeps_it_in_flight"),
    ("GivenUpByEveryNode read as terminal", [(N, "    /// Never: only the chain's facts end a relayed operation.\n    pub fn is_terminal(&self) -> bool {\n        false",
                                              "    /// Never: only the chain's facts end a relayed operation.\n    pub fn is_terminal(&self) -> bool {\n        matches!(self, MergedState::GivenUpByEveryNode)")],
     T + "all_dead_is_given_up_not_failed"),
    ("a refusal read as final", [(N, "    /// Never: a refusal can be a dishonest node's, a queue is no landing (CLI-RPC-09).\n    pub fn is_terminal(&self) -> bool {\n        false",
                                  "    /// Never: a refusal can be a dishonest node's, a queue is no landing (CLI-RPC-09).\n    pub fn is_terminal(&self) -> bool {\n        matches!(self, SubmitOutcome::NotQueued { .. })")],
     T + "all_refused_is_not_queued_and_not_final"),
]

if __name__ == "__main__":
    main("t11", MUTANTS)
