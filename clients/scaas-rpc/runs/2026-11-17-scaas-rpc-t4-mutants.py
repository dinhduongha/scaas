# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T4 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t4-mutants.py check | run
(`connect_reqwest` itself is not compiled in: alloy's `reqwest` feature is off; its mutant is the transport's cap dropped.)"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

E = "clients/scaas-rpc/src/evm.rs"
P = "clients/scaas-rpc/src/pool.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test evm_fakes "
F = T + "chain_reads_fail_over_on_transport_errors_never_on_a_revert"
MUTANTS = [
    ("an unbounded transport (connect_reqwest reads an answer whole)",
     [(E, "BoundedRpc::new(h.clone(), list.clone(), i, ANSWER_MAX, deadline)", "BoundedRpc::new(h.clone(), list.clone(), i, usize::MAX, deadline)")],
     T + "an_evm_answer_above_the_cap_is_that_endpoints_failure"),
    ("a first_* read delegated to the failover read",
     [(E, "        self.providers[0]\n            .get_transaction_count(who)\n            .pending()\n            .await\n            .map_err(|e| first_err(&e))",
       "        self.failover_read(Purpose::Plain, |p| async move { p.get_transaction_count(who).pending().await }).await")],
     T + "the_lane_"),
    ("read_within: a revert from endpoint 1 final", [(P, "Err(ReadError::Revert { data, reason }) if i == first =>", "Err(ReadError::Revert { data, reason }) if true =>")], F),
    ("read_within: head floor removed", [(P, "                    if n < floor {\n", "                    if false {\n")], F),
    ("read_within: identity not checked", [(P, "                self.identity_ok(probe, i, None).await?;\n", "")], F),
    ("read_within: counter not raised", [(P, "                        self.failover.fetch_add(1, Relaxed);\n", "")], F),
]

if __name__ == "__main__":
    main("t4", MUTANTS)
