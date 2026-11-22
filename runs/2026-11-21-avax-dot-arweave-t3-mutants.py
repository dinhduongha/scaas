# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T3 mutants (the node's lanes on an Avalanche-like chain: the audit's held points and the two gaps built):
python3 runs/2026-11-21-avax-dot-arweave-t3-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "scaas-node/src/submit.rs"
G = "scaas-node/src/guard.rs"
B = "scaas-node/src/breaker.rs"
T = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j2 --lib "
DEAD = """                Ok(None) => {
                    if let Some(id) = self.inflight.remove(&n).and_then(|s| s.work).and_then(|w| w.job_id) {
                        _ = self.report(id, "dead", None, None, None).await;
                    }
                    continue;
                }
                Err(e) => {
                    warn!(nonce = n, "receipt: {e:#}");"""
MUTANTS = [
    (
        "`dead` on a missing receipt",
        [(S, """                Ok(None) => {}
                Err(e) => {
                    warn!(nonce = n, "receipt: {e:#}");""", DEAD)],
        T + "an_earlier_replaced_hash_that_mines_settles_the_nonce",
        "an_earlier_replaced_hash_that_mines_settles_the_nonce",
    ),
    (
        "the in-flight cap ignored",
        [(S, "        self.inflight.len() < self.cfg.max_inflight", "        self.cfg.max_inflight > 0")],
        T + "a_lane_keeps_at_most_max_inflight_in_flight",
        "a_lane_keeps_at_most_max_inflight_in_flight",
    ),
    (
        "a fixed gas padding",
        [(G, "    estimate.saturating_add(estimate / 5).max(floor).min(cap)", "    cap.max(floor).min(cap)")],
        T + "gas_floor_and_settle_sizing",
        "gas_floor_and_settle_sizing",
    ),
    (
        "the in-flight cost alert dropped",
        [(B, "        let short = balance < cost;", "        let short = balance < cost && false;")],
        T + "balance_below_the_in_flight_cost_is_alerted",
        "balance_below_the_in_flight_cost_is_alerted",
    ),
]

if __name__ == "__main__":
    main("t3", MUTANTS)
