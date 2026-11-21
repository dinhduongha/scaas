# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""rpc T24.sui-graphql: the family client's GraphQL request and `scaas-rpc`'s `SuiGraphql`:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24suigql-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

F = "clients/scaas-rpc/src/family.rs"
S = "clients/scaas-rpc/src/sui.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features sui --test sui_graphql -- --exact "
MUTANTS = [
    ("data read before errors (a partial answer read)",
     [(F, "        if let Some(e) = v\n            .get_mut(\"errors\")",
       "        if let Some(d) = v.get(\"data\").filter(|d| !d.is_null()) {\n            return Ok(d.clone());\n        }\n"
       "        if let Some(e) = v\n            .get_mut(\"errors\")")],
     T + "an_errors_answer_is_kept_whole_and_never_read_beside_data"),
    ("an empty errors list taken as errors",
     [(F, "e.as_array().is_none_or(|a| !a.is_empty())", "e.as_array().is_none_or(|_| true)")],
     T + "an_errors_answer_is_kept_whole_and_never_read_beside_data"),
    ("a 4xx without errors read as data",
     [(F, "        if !(200..300).contains(&status) {\n            return Err(FamilyError::Status {\n                status,\n"
          "                message: crate::error::endpoint_text(&v.to_string()),",
       "        if false {\n            return Err(FamilyError::Status {\n                status,\n"
       "                message: crate::error::endpoint_text(&v.to_string()),")],
     T + "an_answer_without_data_is_malformed_and_a_bare_4xx_is_its_status"),
    ("a null data read",
     [(F, "match v.get_mut(\"data\").filter(|d| !d.is_null()) {", "match v.get_mut(\"data\") {")],
     T + "an_answer_without_data_is_malformed_and_a_bare_4xx_is_its_status"),
    ("the variables left out of the request",
     [(F, "json!({\"query\": query, \"variables\": variables});", "json!({\"query\": query, \"variables\": {}});")],
     T + "a_query_sends_its_variables_and_reads_the_checkpoints"),
    ("a checkpoint of another number read",
     [(S, "        if d.pointer(\"/checkpoint/sequenceNumber\")\n            .and_then(Value::as_u64)\n            != Some(seq)\n        {",
       "        if false {")],
     T + "a_checkpoint_of_another_number_or_a_head_not_a_number_is_malformed"),
    ("a head as text read",
     [(S, "            .and_then(Value::as_u64)\n            .ok_or_else(|| bad(i, \"a checkpoint sequence number",
       "            .and_then(num)\n            .ok_or_else(|| bad(i, \"a checkpoint sequence number")],
     T + "a_checkpoint_of_another_number_or_a_head_not_a_number_is_malformed"),
    ("the GraphQL identity not checked",
     [(S, "    /// `chainIdentifier` against the configured one, else against the first endpoint's.\n"
          "    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {\n"
          "        same_as_reference(&self.first, i, |j| self.chain_identifier(j)).await",
       "    /// `chainIdentifier` against the configured one, else against the first endpoint's.\n"
       "    async fn same_chain(&self, _i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {\n"
       "        Ok(true)")],
     T + "the_failover_drops_another_network_and_skips_an_endpoint_behind"),
    ("endpoint 0 queried before its identity",
     [(S, "        crate::family::admit_first(&self.client, self, i).await?;\n        self.client.graphql_at(i, query, variables).await",
       "        self.client.graphql_at(i, query, variables).await")],
     T + "a_pinned_identity_refuses_endpoint_0_of_another_network"),
]

if __name__ == "__main__":
    main("t24suigql", MUTANTS)
