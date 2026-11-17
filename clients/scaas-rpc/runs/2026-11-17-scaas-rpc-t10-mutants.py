# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T10 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t10-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

N = "clients/scaas-rpc/src/node.rs"
H = "clients/scaas-rpc/src/http.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test node "
MUTANTS = [
    ("re-serialise op through a struct", [(N, '''        let body = format!(r#"{{"chain":{chain},"op":{}}}"#, serde_json::to_string(op).expect("a Value serialises")).into_bytes();
        self.submit_at(i, "/v1/op", body).await''', '''        #[derive(serde::Serialize)]
        struct R<'a> { op: &'a Value, chain: u64 }
        let body = serde_json::to_vec(&R { op, chain }).unwrap();
        self.submit_at(i, "/v1/op", body).await''')], T + "bodies_are_sent_byte_for_byte"),
    ("drop the body cap", [(N, "    async fn submit_at(&self, i: usize, route: &str, body: Vec<u8>) -> Result<NodeOutcome, RpcError> {\n        if body.len() > BODY_MAX {",
                            "    async fn submit_at(&self, i: usize, route: &str, body: Vec<u8>) -> Result<NodeOutcome, RpcError> {\n        if false {")],
     T + "a_body_above_64_kib_is_refused_unsent"),
    ("read detail instead of code", [(N, 'let code = v["code"].as_str().or(v["error"].as_str())', 'let code = v["detail"].as_str().or(v["error"].as_str())')],
     T + "an_error_is_read_by_code_else_by_error_string"),
    ("one shared credential for the list", [(H, "match e.auth() {", "match list.endpoints().iter().find_map(|x| x.auth()) {")],
     T + "a_second_gateway_receives_no_credential_of_the_first"),
]

if __name__ == "__main__":
    main("t10", MUTANTS)
