# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T24.solana, Solana's program address (clientkeys, ua-rs), `scaas-rpc`'s batch and the SDK's balance reads
(spec §8.7): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24solana-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/wallet/families/solana.rs"
M = "clients/scaas-sdk/src/wallet/families/mod.rs"
L = "clients/scaas-sdk/src/lib.rs"
U = "clients/ua-rs/src/families/solana.rs"
K = "clients/clientkeys/src/fam/solana.js"
R = "clients/scaas-rpc/src/solana.rs"
CM = "clients/scaas-cli/Cargo.toml"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features solana --test solana -- --exact "
UT = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test families_solana -- --exact "
KT = "cd clients/clientkeys && ../../scripts/capped node --test --test-reporter=tap test/fam-solana.test.js"
RT = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features solana --test solana -- --exact "
CT = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --bin scaas "
MUTANTS = [
    ("read the second endpoint first",
     [(M, "let a = client.failover(probe, first).await?;",
       "let a = client.failover(probe, |i| first((i + 1) % client.len())).await?;")],
     T + "solana_two_endpoints_one_down"),
    ("a set at two slots accepted",
     [(S, "        (Some(lo), Some(hi)) if lo == hi => return Ok((*hi, v)),",
       "        (Some(_), Some(hi)) => return Ok((*hi, v)),")],
     T + "solana_two_slots_read_again_once"),
    ("the second pass not at the later slot",
     [(S, "            let (slots, v) = pass(sol, i, who, pda, mints, Some(hi)).await?;",
       "            let (slots, v) = pass(sol, i, who, pda, mints, None).await?;")],
     T + "solana_two_slots_read_again_once"),
    ("a token account of another mint summed",
     [(S, "                || field(\"/mint\") != Some(m.as_str())\n", "")],
     T + "solana_malformed_answers_are_refused"),
    ("a token account of another owner summed",
     [(S, "                || field(\"/owner\") != Some(pda)\n", "")],
     T + "solana_malformed_answers_are_refused"),
    ("a token account of another program summed",
     [(S, "            if !program.is_some_and(|p| TOKEN_PROGRAMS.contains(&p))\n                ||",
       "            if false\n                ||")],
     T + "solana_malformed_answers_are_refused"),
    ("the sum wraps",
     [(S, "                .checked_add(v)\n", "                .checked_add(v).or(Some(sum.wrapping_add(v)))\n")],
     T + "solana_malformed_answers_are_refused"),
    ("lamports as a string read",
     [(S, "        .and_then(Value::as_u64)\n        .ok_or_else(|| malformed(i, \"lamports that are not a u64\"))?",
       "        .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()))\n        .ok_or_else(|| malformed(i, \"lamports that are not a u64\"))?")],
     T + "solana_malformed_answers_are_refused"),
    ("the tokens read on the holder, not its Account",
     [(S, "json!([pda, {\"mint\": m}", "json!([who, {\"mint\": m}")],
     T + "solana_balances_at_one_slot"),
    ("strict majority: the others not floored at the slot",
     [(S, "            set_at(sol, j, id, pda, mints, Some(slot))", "            set_at(sol, j, id, pda, mints, None)")],
     T + "solana_strict_majority_agrees_on_the_set"),
    ("the genesis hash as hex",
     [(L, "                            &bs58::encode(uid).into_string(),\n                        )),\n                        program,",
       "                            &alloy::hex::encode(&uid),\n                        )),\n                        program,")],
     T + "solana_balances_at_one_slot"),
    ("a program of another length read",
     [(L, "                        .and_then(|v| v.try_into().ok())\n                        .ok_or(SdkError::Argument)?;\n                    let uid",
       "                        .map(|mut v: Vec<u8>| { v.resize(32, 0); let mut a = [0u8; 32]; a.copy_from_slice(&v); a })\n                        .ok_or(SdkError::Argument)?;\n                    let uid")],
     T + "solana_holder_token_and_program_forms"),
    ("ua-rs: a 16th seed beside the bump",
     [(U, "    if seeds.len() >= MAX_SEEDS ||", "    if seeds.len() > MAX_SEEDS ||")],
     UT + "refusals_beside_controls"),
    ("ua-rs: a seed of 33 bytes",
     [(U, "seeds.iter().any(|s| s.len() > MAX_SEED_LEN)", "seeds.iter().any(|s| s.len() > MAX_SEED_LEN + 1)")],
     UT + "refusals_beside_controls"),
    ("ua-rs: the bump from 0 up",
     [(U, "    (0..=255u8).rev().find_map(", "    (0..=255u8).find_map(")],
     UT + "pda_rows"),
    ("ua-rs: an on-curve hash taken",
     [(U, "        (!on_curve(&a)).then_some((a, bump))", "        Some((a, bump))")],
     UT + "pda_rows"),
    ("ua-rs: the Account's seed",
     [(U, "    find_pda(&[b\"acct\", owner], program)", "    find_pda(&[b\"acc\", owner], program)")],
     UT + "account_rows"),
    ("clientkeys: a 16th seed beside the bump",
     [(K, "  if (seeds.length > MAX_SEEDS - 1)", "  if (seeds.length > MAX_SEEDS)")],
     KT),
    ("clientkeys: the program before the bump",
     [(K, "concatBytes(...seeds, Uint8Array.of(bump), program, MARKER)", "concatBytes(...seeds, program, Uint8Array.of(bump), MARKER)")],
     KT),
    ("rpc: a batch member twice accepted",
     [(R, "            let Some((k, slot @ None)) = slot else {", "            let Some((k, slot)) = slot else {")],
     RT + "a_batch_answers_each_call_by_id"),
    ("rpc: a missing batch member accepted",
     [(R, "            .map(|r| r.ok_or_else(|| bad(i, \"a batch member missing\")))",
       "            .map(|r| Ok(r.unwrap_or(Ok(Value::Null))))")],
     RT + "a_batch_answers_each_call_by_id"),
    ("cli: the CLI's SDK without Solana reads",
     [(CM, '  "aptos",\n  "solana",\n', '  "aptos",\n')],
     CT + "family_profiles_open_and_read"),
]

if __name__ == "__main__":
    main("t24solana", MUTANTS)
