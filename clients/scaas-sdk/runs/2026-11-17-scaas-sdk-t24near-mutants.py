# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T24.near, NEAR's balance reads (spec §8.7):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24near-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/scaas-sdk/src/wallet/families/mod.rs"
N = "clients/scaas-sdk/src/wallet/families/near.rs"
L = "clients/scaas-sdk/src/lib.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features near --test near -- --exact "
MUTANTS = [
    ("read the second endpoint first",
     [(M, "let a = client.failover(probe, first).await?;",
       "let a = client.failover(probe, |i| first((i + 1) % client.len())).await?;")],
     T + "near_two_endpoints_one_down"),
    ("an amount's digits not checked",
     [(M, "if s.is_empty() || s.len() > 78 || !s.bytes().all(|b| b.is_ascii_digit()) {",
       "if s.is_empty() || s.len() > 78 {")],
     T + "near_malformed_amount_is_refused"),
    ("an amount's length not checked",
     [(M, "if s.is_empty() || s.len() > 78 || !s.bytes().all(|b| b.is_ascii_digit()) {",
       "if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {")],
     T + "near_malformed_amount_is_refused"),
    ("an empty amount read as 0",
     [(M, "if s.is_empty() || s.len() > 78 || !s.bytes().all(|b| b.is_ascii_digit()) {",
       "if s.len() > 78 || !s.bytes().all(|b| b.is_ascii_digit()) {")],
     T + "near_malformed_amount_is_refused"),
    ("strict majority: no agreement asked",
     [(M, "if client.pool().policy() == Policy::StrictMajority {", "if false {")],
     T + "near_strict_majority_agrees_at_one_height"),
    ("strict majority: another endpoint's identity not checked",
     [(M, "let r = match client.pool().admit(probe, j, None).await {", "let r = match Ok::<(), EndpointFailure>(()) {")],
     T + "near_strict_majority_agrees_at_one_height"),
    ("strict majority: the others read at their own final block",
     [(N, "|j, h| async move { set_at(near, j, h, who, tokens).await },",
       "|j, _h| async move { let h = near.final_header(j).await.map_err(|e| failed(j, e))?.0; set_at(near, j, h, who, tokens).await },")],
     T + "near_strict_majority_agrees_at_one_height"),
    ("an answer at another block accepted",
     [(N, "if v.get(\"block_height\").and_then(Value::as_u64) == Some(h) {", "if v.get(\"block_height\").and_then(Value::as_u64).is_some() {")],
     T + "near_answer_at_another_height_is_refused"),
    ("a view result above 128 bytes read",
     [(N, ".filter(|r| r.len() <= VIEW_MAX)", ".filter(|r| r.len() <= 4 * VIEW_MAX)")],
     T + "near_view_result_above_128_bytes_is_refused"),
    ("a view's number read as its digits",
     [(N, "Ok(Value::String(s)) => amount(i, &s),",
       "Ok(Value::String(s)) => amount(i, &s),\n        Ok(Value::Number(n)) => amount(i, &n.to_string()),")],
     T + "near_malformed_amount_is_refused"),
    ("an unknown account not read as 0",
     [(N, "== Some(\"UNKNOWN_ACCOUNT\") =>", "== Some(\"NO_SUCH_CAUSE\") =>")],
     T + "near_unknown_account_is_zero"),
    ("a NEAR account id's case not checked",
     [(N, ".all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || sep(c))",
       ".all(|c| c.is_ascii_alphanumeric() || sep(c))")],
     T + "near_holder_and_token_forms"),
    ("a listed token's form not checked",
     [(N, "if !tokens.iter().all(|t| account_id(t)) {", "if tokens.is_empty() {")],
     T + "near_holder_and_token_forms"),
    ("the genesis as hex, not base58",
     [(L, "&bs58::encode(uid).into_string(),", "&crate::op::hex(&uid),")],
     T + "near_balances_at_the_final_block"),
]

if __name__ == "__main__":
    main("t24near", MUTANTS)
