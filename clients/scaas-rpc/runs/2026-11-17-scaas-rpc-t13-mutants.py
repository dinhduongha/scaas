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
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib chain::tests::"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features "
MUTANTS = [
    ("S1 no freshness", [(P, "let fresh = |i: usize| names[i].is_some_and(|x| number.saturating_add(self.max_lag) >= x);",
                          "let fresh = |i: usize| names[i].is_some();")],
     T + "--test pool one_endpoint_cannot_choose_an_old_block"),
    ("S2 one floor for every choice", [(P, "        let floor = self.agreed_floor(choice);\n",
                                        "        let floor = self.floor.lock().map(|f| f.values().copied().max().unwrap_or(0)).unwrap_or(0);\n")],
     T + "--test pool reads_of_every_block_choice_mix_on_one_pool"),
    ("S3 first_* without identity", [(E, "    pub async fn first_pending_nonce(&self, who: Address) -> Result<u64, RpcError> {\n        self.first().await?;\n",
                                      "    pub async fn first_pending_nonce(&self, who: Address) -> Result<u64, RpcError> {\n")],
     T + "--test evm_fakes a_dropped_endpoint_is_never_asked_again"),
    ("S3 broadcast without identity", [(E, "                if let Err(failure) = self.pool.admit(self, i, None).await {\n",
                                        "                if let Err(failure) = Ok::<(), EndpointFailure>(()) {\n")],
     T + "--test evm_fakes a_dropped_endpoint_is_never_asked_again"),
    ("S3 strict fee without identity", [(E, "            self.pool.admit(self, i, deadline).await?;\n", "")],
     T + "--test evm_fakes a_dropped_endpoint_is_never_asked_again"),
    ("S16 a pruned endpoint trusted on the pin", [(E, "            (Some(p), None) if self.list.endpoints()[at].checkpoint().is_some() => p,",
                                                    "            (Some(p), None) => p,")],
     T + "--test evm_fakes chain_uid_is_block_zero_and_a_wrong_pin_is_refused"),
    ("S16 a pruned endpoint admitted without its checkpoint",
     [(E, '''                None => Err(EndpointFailure::new(
                    i,
                    FailureKind::ChainIdentityUnreadable,
                    &format!("endpoint {i} serves no block 0 and names no checkpoint"),
                )),''', "                None => Ok(true),")],
     T + "--test evm_fakes an_endpoint_without_block_0_is_refused_unless_it_names_a_checkpoint"),
    ("point 6 endpoint 0 skipped on reads", [(P, "                self.identity_ok(probe, i, None).await?;\n",
                                               "                if i != first {\n                    self.identity_ok(probe, i, None).await?;\n                }\n")],
     NT + "an_endpoint_0_of_another_chain_is_dropped"),
    ("point 6 endpoint 0 skipped on admit", [(P, "    ) -> Result<(), EndpointFailure> {\n        self.identity_ok(probe, i, deadline).await\n",
                                               "    ) -> Result<(), EndpointFailure> {\n        if i == 0 {\n            return Ok(());\n        }\n        self.identity_ok(probe, i, deadline).await\n")],
     NT + "an_endpoint_0_of_another_chain_is_dropped"),
    ("S4 a revert message kept whole", [(E, "            None if resp.message.contains(\"revert\") => {\n                SimError::Revert(endpoint_text(&resp.message))",
                                         "            None if resp.message.contains(\"revert\") => {\n                SimError::Revert(resp.message.to_string())")],
     T + "--test evm_fakes a_revert_text_is_capped_and_cleaned"),
    ("S4 a decoded reason kept whole", [(E, "Some(data) => SimError::Revert(endpoint_text(&decode(&data))),",
                                         "Some(data) => SimError::Revert(decode(&data)),")],
     T + "--test evm_fakes a_revert_text_is_capped_and_cleaned"),
    ("S4 intent_id kept whole", [(N, "intent_id: v[\"intent_id\"].as_str().map(crate::error::endpoint_text),",
                                  "intent_id: v[\"intent_id\"].as_str().map(str::to_string),")],
     T + "--test node a_gateways_intent_id_and_revert_data_are_bounded"),
    ("S4 revert_data hex unchecked", [(N, "h.bytes().all(|b| b.is_ascii_hexdigit())", "true")],
     T + "--test node a_gateways_intent_id_and_revert_data_are_bounded"),
    ("S4 revert_data uncapped", [(N, "h.len() <= 2 * REVERT_DATA_MAX", "h.len() <= 2 * ANSWER_MAX")],
     T + "--test node a_gateways_intent_id_and_revert_data_are_bounded"),
    ("S5 an entry prints its URL", [(EP, '        f.debug_struct("EntryConfig")\n', '        f.debug_struct("EntryConfig")\n            .field("url", &self.url)\n')],
     T + "--lib endpoint::tests::debug_and_display_carry_no_url_or_secret"),
    ("S5 an entry prints its key file", [(EP, '        f.debug_struct("EntryConfig")\n', '        f.debug_struct("EntryConfig")\n            .field("api_key_file", &self.api_key_file)\n')],
     T + "--lib endpoint::tests::debug_and_display_carry_no_url_or_secret"),
    ("S5 a list prints its URLs", [(EP, '.field("rpc_urls", &self.rpc_urls.as_ref().map(Vec::len))', '.field("rpc_urls", &self.rpc_urls)')],
     T + "--lib endpoint::tests::debug_and_display_carry_no_url_or_secret"),
    ("S6 no timeout check", [(EP, "if policy == Policy::StrictMajority && timeout_ms >= read_timeout_ms {", "if false {")],
     T + "--lib endpoint::tests::strict_majority_needs_a_request_timeout_below_the_read_deadline"),
    ("S6 an equal timeout passes", [(EP, "if policy == Policy::StrictMajority && timeout_ms >= read_timeout_ms {",
                                     "if policy == Policy::StrictMajority && timeout_ms > read_timeout_ms {")],
     T + "--lib endpoint::tests::strict_majority_needs_a_request_timeout_below_the_read_deadline"),
]

if __name__ == "__main__":
    main("t13", MUTANTS)
