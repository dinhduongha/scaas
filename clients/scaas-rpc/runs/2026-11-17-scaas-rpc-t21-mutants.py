# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T21 (Cosmos) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t21-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/cosmos.rs"
N = "scaas-node/src/adapters/cosmos.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test cosmos "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::cosmos::tests::"
MUTANTS = [
    # (a): the owner's list (2026-11-18); the family's reads; Cosmos has no key; the 20 s is T15's family mutant
    ("a: params.rest read as its first entry only", [(N, "scaas_rpc::family::Client::of_urls(&rest, None)", "scaas_rpc::family::Client::of_urls(&rest[..1], None)")],
     NT + "cosmos_rest_is_a_list_of_gateways"),
    ("a: a single URL string accepted", [(N, '            Some(_) => bail!("chain {}: params.rest must be a list of REST gateway URLs", cfg.chain_key()),',
                                           '            Some(v) => vec![v.as_str().unwrap_or_default().to_string()],')],
     NT + "cosmos_rest_is_a_list_of_gateways"),
    ("a: a 5xx read as the endpoint's failure", [(S, "        .raw_any_at(i, method, path, body, \"application/json\", ANSWER_MAX)", "        .raw_at(i, method, path, body, \"application/json\", ANSWER_MAX)")],
     T + "the_cometbft_and_rest_reads"),
    ("a: a 4xx read as the endpoint's failure", [(S, "    if b.iter().all(u8::is_ascii_whitespace) {",
                                                    "    if status >= 400 {\n        return Err(FamilyError::Status { status, message: String::new() });\n    }\n    if b.iter().all(u8::is_ascii_whitespace) {")],
     T + "the_cometbft_and_rest_reads"),
    ("a: a CometBFT error lost", [(S, 'error: v.get("error").cloned().unwrap_or(v),', "error: Value::Null,")],
     T + "the_cometbft_and_rest_reads"),
    ("a: the identity a constant", [(S, "            Some(n) => Ok(n == self.chain_id),", "            Some(_) => Ok(true),")],
     T + "the_failover_drops_another_network_and_skips_an_endpoint_behind"),
    # (b) the carve-out (F3) first, then the failover over the REST gateways
    ("b: every read fails over (the carve-out gone)", [("scaas-node/src/adapters/evm.rs", "    BUILDING.try_with(|_| ()).is_ok()", "    true")],
     NT + "cosmos_tx_status_op_consumed_and_the_lane_sequence_never_fail_over"),
    ("b: the router's executor through the failover", [(N, 'self.rest_get_first(&format!("/cosmwasm/wasm/v1/contract/{router}/smart/{q}"))', 'self.rest_get(&format!("/cosmwasm/wasm/v1/contract/{router}/smart/{q}"))')],
     NT + "cosmos_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: the build's reads on endpoint 0 only", [(N, "        match BUILDING.scope((), self.build_on(job, lane)).await {", "        match self.build_on(job, lane).await {")],
     NT + "cosmos_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: a failover refusal final (the counter not compared)", [(N, "            Err(SimError::Revert(r)) if self.failovers() != mark => Err(SimError::Transport(crate::adapters::evm::failover_answer(&r))),\n", "")],
     NT + "cosmos_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
    ("b: a later gateway's refusal text kept", [(N, "            Err(e) => Err(crate::adapters::evm::all_failed(path, &e)),", "            Err(e) => bail!(\"{path}: {e}\"),")],
     NT + "cosmos_build_reads_fail_over_and_a_failover_refusal_is_no_verdict"),
]

if __name__ == "__main__":
    main("t21", MUTANTS)
