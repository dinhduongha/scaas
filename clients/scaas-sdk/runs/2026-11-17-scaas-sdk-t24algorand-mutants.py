# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T24.algorand, Algorand's balance reads (spec §8.7):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24algorand-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "clients/scaas-sdk/src/wallet/families/algorand.rs"
M = "clients/scaas-sdk/src/wallet/families/mod.rs"
L = "clients/scaas-sdk/src/lib.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features algorand --test algorand -- --exact "
MUTANTS = [
    ("read the second endpoint first",
     [(M, "let a = client.failover(probe, first).await?;",
       "let a = client.failover(probe, |i| first((i + 1) % client.len())).await?;")],
     T + "algorand_two_endpoints_one_down"),
    ("a box value of another length read",
     [(A, ".filter(|w| w.len() == 32)", ".filter(|w| w.len() <= 32)")],
     T + "algorand_malformed_answers_are_refused"),
    ("an account amount as a string read",
     [(A, ".get(\"amount\")\n                .and_then(Value::as_u64)",
       ".get(\"amount\")\n                .and_then(|a| a.as_u64().or_else(|| a.as_str().and_then(|s| s.parse().ok())))")],
     T + "algorand_malformed_answers_are_refused"),
    ("an absent box an error",
     [(A, "            Err(FamilyError::Status {\n                status: 404,\n                message,\n",
       "            Err(FamilyError::Status {\n                status: 405,\n                message,\n")],
     T + "algorand_ua_id_reads_the_u_box"),
    ("answers at two rounds accepted",
     [(A, "if rounds.iter().all(|x| *x == r) && want.is_none_or(|w| r >= w) {",
       "if want.is_none_or(|w| r >= w) {")],
     T + "algorand_answers_at_two_rounds_are_retried_once"),
    ("no second pass",
     [(A, "for _ in 0..2 {", "for _ in 0..1 {")],
     T + "algorand_answers_at_two_rounds_are_retried_once"),
    ("strict majority: another endpoint's round not compared",
     [(A, "if rounds.iter().all(|x| *x == r) && want.is_none_or(|w| r >= w) {",
       "if rounds.iter().all(|x| *x == r) {")],
     T + "algorand_strict_majority_agrees_at_one_round"),
    ("an app id with a leading zero read",
     [(A, ".filter(|n| *n > 0 && n.to_string() == s)", ".filter(|n| *n > 0)")],
     T + "algorand_holder_and_token_forms"),
    ("app id 0 read",
     [(A, ".filter(|n| *n > 0 && n.to_string() == s)", ".filter(|n| n.to_string() == s)")],
     T + "algorand_holder_and_token_forms"),
    ("the genesis as hex, not base64",
     [(L, "&base64::engine::general_purpose::STANDARD.encode(uid),", "&crate::op::hex(&uid),")],
     T + "algorand_balances_at_one_round"),
]

if __name__ == "__main__":
    main("t24algorand", MUTANTS)
