# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T24.aptos, Aptos's balance reads (spec §8.7):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24aptos-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "clients/scaas-sdk/src/wallet/families/aptos.rs"
M = "clients/scaas-sdk/src/wallet/families/mod.rs"
G = "clients/scaas-sdk/src/config.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features aptos --test aptos -- --exact "
MUTANTS = [
    ("read the second endpoint first",
     [(M, "let a = client.failover(probe, first).await?;",
       "let a = client.failover(probe, |i| first((i + 1) % client.len())).await?;")],
     T + "aptos_two_endpoints_one_down"),
    ("the views not pinned to the version",
     [(A, "&format!(\"/view?ledger_version={version}\"),", "\"/view\","),],
     T + "aptos_strict_majority_agrees_at_one_version"),
    ("the pinned version as the failover's floor",
     [(M, "client.pool().saw_block(head);", "client.pool().saw_block(height);")],
     T + "aptos_floor_is_the_block_height"),
    ("strict majority: the others read at their own version",
     [(A, "|j, v| async move { set_at(apt, j, v, id, package, tokens).await },",
       "|j, _v| async move { let (_, v) = ledger(apt, j).await?; set_at(apt, j, v, id, package, tokens).await },")],
     T + "aptos_strict_majority_agrees_at_one_version"),
    ("the native balance read without the amount rule",
     [(A, "let native = amount(i, &native)?;", "let native = native;")],
     T + "aptos_malformed_answers_are_refused"),
    ("a view of two values read",
     [(A, "Some([Value::String(s)]) => Ok(s.clone()),", "Some([Value::String(s), ..]) => Ok(s.clone()),")],
     T + "aptos_malformed_answers_are_refused"),
    ("the account view's address not checked",
     [(A, "if !acct.starts_with(\"0x\")", "if false && !acct.starts_with(\"0x\")")],
     T + "aptos_account_that_is_no_address_is_refused"),
    ("an address's uppercase hex read",
     [(G, ".all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))", ".all(|b| b.is_ascii_hexdigit())")],
     T + "aptos_holder_and_token_forms"),
    ("params of another family accepted",
     [(G, "family == Family::Aptos && *chain_id != 0", "*chain_id != 0")],
     T + "aptos_holder_and_token_forms"),
    ("chain id 0 accepted",
     [(G, "family == Family::Aptos && *chain_id != 0", "family == Family::Aptos")],
     T + "aptos_holder_and_token_forms"),
]

if __name__ == "__main__":
    main("t24aptos", MUTANTS)
