# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T24.sui: the derived Account<T> id (clientkeys, ua-rs), the SDK's balance reads over GraphQL and the CLI's profile file:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24sui-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/wallet/families/sui.rs"
M = "clients/scaas-sdk/src/wallet/families/mod.rs"
L = "clients/scaas-sdk/src/lib.rs"
U = "clients/ua-rs/src/families/sui.rs"
K = "clients/clientkeys/src/fam/sui.js"
C = "clients/scaas-cli/src/config.rs"
CM = "clients/scaas-cli/Cargo.toml"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features sui --test sui -- --exact "
UT = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test families_sui -- --exact "
KT = "cd clients/clientkeys && ../../scripts/capped node --test --test-reporter=tap test/fam-sui.test.js"
CT = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --bin scaas "
MUTANTS = [
    ("the Sui dispatch off",
     [(M, "        crate::Family::Sui => sui::balances(c, id).await,",
       "        crate::Family::Sui => Err(SdkError::FeatureMissing),")],
     T + "sui_balances_at_one_checkpoint"),
    ("read the second endpoint first",
     [(M, "let a = client.failover(probe, first).await?;",
       "let a = client.failover(probe, |i| first((i + 1) % client.len())).await?;")],
     T + "sui_two_endpoints_one_down"),
    ("the registry and the owner swapped in the derivation",
     [(S, "account_of(&bytes32(&t.address)?, &owner)", "account_of(&owner, &bytes32(&t.address)?)")],
     T + "sui_balances_at_one_checkpoint"),
    ("an absent Account refused, not 0",
     [(S, "        if o.is_null() {\n            out.push(\"0\".into());\n            continue;\n        }\n", "")],
     T + "sui_balances_at_one_checkpoint"),
    ("an Account of another registry read",
     [(S, "        if j.get(\"registry\").and_then(Value::as_str) != Some(registry.as_str())\n            || j.get",
       "        if false\n            || j.get")],
     T + "sui_malformed_answers_are_refused"),
    ("an Account of another owner read",
     [(S, "            || j.get(\"owner\").and_then(Value::as_str) != Some(who)\n", "")],
     T + "sui_malformed_answers_are_refused"),
    ("a set of another checkpoint read",
     [(S, "    if d.pointer(\"/checkpoint/sequenceNumber\")\n        .and_then(Value::as_u64)\n        != Some(c)\n    {",
       "    if false {")],
     T + "sui_malformed_answers_are_refused"),
    ("the holder's SUI not pinned to the checkpoint",
     [(S, "address(address: $a, atCheckpoint: $c)", "address(address: $a)")],
     T + "sui_balances_at_one_checkpoint"),
    ("the network identity not pinned to chain_uid",
     [(L, "                        Some(&uid),\n", "                        None,\n")],
     T + "sui_endpoint_of_another_network_is_dropped"),
    ("the GraphQL policy ignored",
     [(L, "list(graphql, *graphql_policy)?", "list(graphql, scaas_rpc::Policy::Failover)?")],
     T + "sui_strict_majority_agrees_at_one_checkpoint"),
    ("ua-rs: another hashing intent",
     [(U, "    h.update([0xf0]);", "    h.update([0xf1]);")],
     UT + "account_rows"),
    ("ua-rs: the key's type tag of another type argument",
     [(U, "DerivedObjectKey\\x01\\x04\";", "DerivedObjectKey\\x01\\x05\";")],
     UT + "account_rows"),
    ("clientkeys: the key's length left out",
     [(K, "  len[0] = 32;\n", "")],
     KT, "the Move test's Account<SUI> of alice is derived, and is a row"),
    ("the CLI's Sui params dropped",
     [(C, "        Fam::Sui(s) => FamilyParams::Sui {\n            graphql: eps(s.graphql),",
       "        Fam::Sui(s) => FamilyParams::Sui {\n            graphql: eps(s.graphql).into_iter().take(0).collect(),")],
     CT + "family_params_are_read_by_name"),
    ("the CLI's SDK without Sui reads",
     [(CM, '  "soroban",\n  "sui",\n', '  "soroban",\n')],
     CT + "family_profiles_open_and_read"),
]

if __name__ == "__main__":
    main("t24sui", MUTANTS)
