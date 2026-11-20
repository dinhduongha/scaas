# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk P-T16-8 mutants (NODE-GW-08, controller call 2026-11-19): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t16e-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "scaas-node/src/gateway.rs"
A = "scaas-node/src/gwauth.rs"
R = "clients/scaas-rpc/src/node.rs"
Q = "clients/scaas-sdk/src/op/quote.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
NODE = "cd scaas-node && ../scripts/capped cargo test --locked --offline -j2 --lib "
RPC = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test node "
SDK = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} "
MUTANTS = [
    ("the job submission route without its own cap", [(G, "post(post_op).layer(DefaultBodyLimit::max(OP_BODY_MAX)),", "post(post_op),")], NODE + "op_body_cap_is_the_job_submission_cap"),
    ("the node's cap one byte larger", [(G, "pub const OP_BODY_MAX: usize = 1_310_720;", "pub const OP_BODY_MAX: usize = 1_310_721;")], NODE + "op_body_cap_is_the_job_submission_cap"),
    ("the HMAC check reads every route at 64 KiB", [(A, "crate::gateway::OP_BODY_MAX\n", "crate::gateway::BODY_MAX\n")], NODE + "hmac_reads_each_route_up_to_its_cap"),
    ("the HMAC check reads every route at the job cap", [(A, "            } else {\n                crate::gateway::BODY_MAX\n", "            } else {\n                crate::gateway::OP_BODY_MAX\n")], NODE + "hmac_reads_each_route_up_to_its_cap"),
    ("scaas-rpc sends /v1/op at 64 KiB", [(R, "    if route == \"/v1/op\" {\n        OP_BODY_MAX", "    if route == \"/v1/opx\" {\n        OP_BODY_MAX")], RPC + "each_route_refuses_a_body_above_its_cap_unsent"),
    ("the SDK keeps PQZ debits off the gateway", [(Q, "    matches!(p.t.kind, \"token\" | \"zether\" | \"pqz\")\n}", "    matches!(p.t.kind, \"token\" | \"zether\" | \"pqz\") && !p.t.name.starts_with(\"UAPqzUnshield\")\n}")], SDK + "--test confidential_pqz pqz_unshield_pairs"),
]

if __name__ == "__main__":
    main("t16e", MUTANTS)
