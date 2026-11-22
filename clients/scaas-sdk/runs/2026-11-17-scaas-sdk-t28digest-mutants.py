# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T28's digest fix (node `POST /v1/ops` keyed on the node's digest, fail closed; gateway.md step 3) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t28digest-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "scaas-node/src/adapter.rs"
G = "scaas-node/src/gateway.rs"
S = "scaas-node/src/adapters/soroban.rs"
NODE = "cd scaas-node && CARGO_INCREMENTAL=0 CAPPED_SLOTS=4 ../scripts/capped cargo test --locked --offline -j2 --lib "
MUTANTS = [
    # the refusal: the trait's default and the gateway's branch
    ("the default ops digest takes the client's", [(A, "        _job: &Job,\n    ) -> std::result::Result<Option<alloy::primitives::B256>, SimError> {\n        Ok(None)\n",
                                                    "        _job: &Job,\n    ) -> std::result::Result<Option<alloy::primitives::B256>, SimError> {\n        Ok(job_digest(_job))\n")],
     NODE + "the_default_ops_digest_refuses"),
    ("a family without a node digest keyed on the client's", [(G, "        Ok(None) => {\n            return refuse(\n                StatusCode::BAD_REQUEST,\n                \"FAMILY_NOT_SUPPORTED\",",
                                                               "        Ok(None) if crate::submit::job_digest(&job).is_some() => crate::submit::job_digest(&job).unwrap_or_default(),\n        Ok(None) => {\n            return refuse(\n                StatusCode::BAD_REQUEST,\n                \"FAMILY_NOT_SUPPORTED\",")],
     NODE + "a_family_without_a_node_digest_is_refused"),
    # the comparison and the stored key
    ("a client digest other than the node's taken", [(G, "        if !d.eq_ignore_ascii_case(&format!(\"{digest:#x}\")) {", "        if d.is_empty() {")],
     NODE + "a_client_digest_other_than_the_nodes_is_bad_payload"),
    ("the client's digest stored", [(G, "        o.remove(\"digest\");\n", "        let _ = o;\n")],
     NODE + "a_client_digest_other_than_the_nodes_is_bad_payload"),
    # Soroban's node digest
    ("Soroban's ops digest the client's", [(S, "        signed_op_digest(&self.network_id, op)\n            .map(|d| Some(d.into()))",
                                            "        signed_op_digest(&self.network_id, op)\n            .map(|_| crate::submit::job_digest(job))")],
     NODE + "a_signed_ops_digest_is_the_nodes"),
    ("Soroban's G2 key the client's", [(S, "        if matches!(job.kind.as_deref(), None | Some(\"signed_op\")) {\n            if let Some(Ok(d))",
                                        "        if false && matches!(job.kind.as_deref(), None | Some(\"signed_op\")) {\n            if let Some(Ok(d))")],
     NODE + "a_signed_ops_digest_is_the_nodes"),
    ("the preimage on another network", [(S, "        network_id: Hash(*network),\n        nonce: c.nonce,", "        network_id: Hash([0; 32]),\n        nonce: c.nonce,")],
     NODE + "a_signed_ops_digest_is_the_nodes"),
]

if __name__ == "__main__":
    main("t28digest", MUTANTS)
