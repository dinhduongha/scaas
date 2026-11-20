# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T10 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t10-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

O = "clients/scaas-sdk/src/op/"
P = "clients/ua-rs/src/wallet/policy.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib op::tests::"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas"
MUTANTS = [
    # the plan's five
    ("report a terminal state on GivenUpByEveryNode",
     [(O + "follow.rs", "                        _ => OpState::InFlight {\n                            detail: tx_detail(",
       "                        _ if row.detail == \"GivenUpByEveryNode\" => OpState::Consumed,\n                        _ => OpState::InFlight {\n                            detail: tx_detail(")],
     SDK + "all_gateways_dead_is_in_flight"),
    ("send before writing the row",
     [(O + "submit.rs", "                state::put(&sdk, &row).await?;\n                let op = row.op.clone();",
       "                let (s3, r3) = (sdk.clone(), row.clone());\n                detach(&sdk, async move { send(&s3, r3).await });\n                state::put(&sdk, &row).await?;\n                let op = row.op.clone();")],
     SDK + "submit_returns_after_the_row_write"),
    ("take the fee cap from the endpoint",
     [(O + "quote.rs", "U256::from(max_fee) > cap(&l.max_fee_per_gas)?", "U256::from(max_fee) > U256::from(max_fee)")],
     SDK + "quote_shows_and_caps"),
    ("let Auto pick a gateway for a non-door-A entry",
     [(O + "quote.rs", "if gateways > 0 && door_a(&prepared) =>", "if gateways > 0 =>")],
     SDK + "submit_path_none"),
    ("re-send a sent row at restart",
     [(O + "submit.rs", "if row.state == \"signed\" && row.detail != \"SimRefused\" {", "if (row.state == \"signed\" || row.state == \"sent\") && row.detail != \"SimRefused\" {")],
     SDK + "write_ahead_then_send"),
    # each check of the task
    ("no stale check on a moved nonce", [(O + "submit.rs", "if at != *nonce {", "if false && at != *nonce {")], SDK + "prepared_stale_on_nonce_move"),
    ("the account's event for every contract", [(O + "follow.rs", "let sig: &[u8] = if kind == \"account\" {\n        b\"MetaTransactionExecuted",
       "let sig: &[u8] = if kind != \"token\" {\n        b\"MetaTransactionExecuted")], SDK + "executed_event_per_contract"),
    ("any log of the event lands it", [(O + "follow.rs", "None => l.data.get(32..64) == Some(digest.as_slice()),", "None => !l.data.is_empty(),")],
     SDK + "executed_event_per_contract"),
    ("Expired without the timestamp check", [(O + "follow.rs", "&& row.valid_until < ts =>", "&& row.valid_until > ts =>")], SDK + "all_gateways_dead_is_in_flight"),
    ("a designator not seen", [(O + "quote.rs", "code.len() == 23 && code.starts_with", "code.len() == 22 && code.starts_with")], SDK + "payer_delegated"),
    ("the chain's per-transaction cap not applied", [(O + "quote.rs", "profile.tx_gas_cap.is_some_and(|c| gas > c)", "profile.tx_gas_cap.is_some_and(|c| gas > c + 1)")],
     SDK + "gas_above_tx_cap"),
    ("an unlisted token shown as listed", [(O + "prepared.rs", "listed.map_or(\"unlisted\".to_string()", "listed.map_or(\"listed\".to_string()")],
     SDK + "review_lists_every_named_field_with_its_source"),
    ("a gateway body to the first gateway only", [(O + "submit.rs", ".submit_op(chain_id, &row.op_json, Fanout::All)", ".submit_op(chain_id, &row.op_json, Fanout::First)")],
     SDK + "gateway_path_posts_the_same_bytes"),
    ("scaas-ua: the payee's co-sign under metatx", [(P, "\"UAPayeeFee\" => \"payee-fee\",", "\"UAPayeeFee\" => \"metatx\",")], UA),
    ("scaas-ua: a UA key signs without the check", [(P, "    if check(td, &expect)? != digest {\n        return Err(Error::PolicyRefused);\n    }\n    super::uasig::ua_sig(key, None",
       "    super::uasig::ua_sig(key, None")], UA),
]

if __name__ == "__main__":
    main("t10", MUTANTS)
