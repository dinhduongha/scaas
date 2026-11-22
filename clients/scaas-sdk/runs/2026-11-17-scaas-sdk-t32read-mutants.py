# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T32's read part (owner 2026-11-22): native DOT on Polkadot Hub's Substrate side: ua-rs's SS58 decode and System.Account
key, scaas-rpc's substrate module, the SDK's Hub balance read:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t32read-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

U = "clients/ua-rs/src/wallet/substrate.rs"
R = "clients/scaas-rpc/src/substrate.rs"
S = "clients/scaas-sdk/src/wallet/families/substrate.rs"
C = "clients/scaas-sdk/src/config.rs"
B = "clients/scaas-sdk/src/wallet/balances.rs"
TU = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test wallet_native -- --exact "
TR = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features substrate --test substrate -- --exact "
TS = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features substrate --test substrate -- --exact "
MUTANTS = [
    ("an SS58 text not re-encoded to itself (prefix and checksum unchecked)",
     [(U, "    if ss58(&pk, prefix)? != address {", "    if false {")],
     TU + "ss58_public_key_reads_every_row_and_refuses_each_change"),
    ("the storage key's hash over the prefix, not the key",
     [(U, "    let h = blake2::Blake2b::<blake2::digest::consts::U16>::digest(pk);",
       "    let h = blake2::Blake2b::<blake2::digest::consts::U16>::digest(PREFIX);")],
     TU + "system_account_key_known_answers"),
    ("the identity check skipped",
     [(R, "            Some(g) => Ok(g == self.genesis),", "            Some(_) => Ok(true),")],
     TR + "endpoint_0_of_another_genesis_is_refused"),
    ("a read at the best head, not the finalized one",
     [(R, '.rpc_at(i, "chain_getFinalizedHead", json!([]))', '.rpc_at(i, "chain_getBlockHash", json!([]))')],
     TR + "the_hub_and_the_relay_chain_read_at_the_finalized_head"),
    ("an AccountInfo of 81 bytes read",
     [(R, "        if b.len() != ACCOUNT_INFO_LEN {", "        if b.len() < ACCOUNT_INFO_LEN {")],
     TR + "malformed_and_oversized_storage_is_refused"),
    ("a storage value without 0x read",
     [(R, '            .and_then(|s| s.strip_prefix("0x"))\n            .and_then(unhex)',
       '            .map(|s| s.trim_start_matches("0x"))\n            .and_then(unhex)')],
     TR + "malformed_and_oversized_storage_is_refused"),
    ("a finalized head of any length read",
     [(R, "            .filter(|h| is_hash(h))\n            .ok_or_else(|| malformed(i, \"a finalized head",
       "            .ok_or_else(|| malformed(i, \"a finalized head")],
     TR + "a_malformed_finalized_head_or_number_is_refused"),
    ("no entry refused, not zeros",
     [(R, "        if v.is_null() {\n            return Ok(AccountInfo::default());",
       "        if v.is_null() {\n            return Err(malformed(i, \"null\"));")],
     TR + "the_hub_and_the_relay_chain_read_at_the_finalized_head"),
    ("free read at another offset",
     [(R, "            free: u128_at(16)?,", "            free: u128_at(20)?,")],
     TR + "the_hub_and_the_relay_chain_read_at_the_finalized_head"),
    ("the SS58 id read at prefix 0, not the params'",
     [(S, "ss58_public_key(id, *prefix)", "ss58_public_key(id, 0)")],
     TS + "hub_native_dot_at_the_finalized_head"),
    ("reserved shown as the native amount",
     [(S, "native: Some(info.free.to_string()),", "native: Some(info.reserved.to_string()),")],
     TS + "hub_native_dot_at_the_finalized_head"),
    ("the majority not comparing the block hash",
     [(S, "            Ok((n, (hash, info)))", "            Ok((n, (String::new(), info)))"),
      (S, "    Ok((hash, info))\n}", "    Ok((String::new(), info))\n}")],
     TS + "hub_native_strict_majority_at_one_finalized_hash"),
    ("Substrate params on any family",
     [(C, "                family == Family::Evm\n                    && is_word_hex(genesis)",
       "                is_word_hex(genesis)")],
     TS + "hub_substrate_params_are_checked_at_open"),
    ("a genesis of any form",
     [(C, "                    && is_word_hex(genesis)\n", "")],
     TS + "hub_substrate_params_are_checked_at_open"),
    ("a reserved prefix accepted",
     [(C, "                    && !matches!(ss58_prefix, 46 | 47)\n", "")],
     TS + "hub_substrate_params_are_checked_at_open"),
    ("a 0x id read on the Substrate side",
     [(B, "                let r = if !id.starts_with(\"0x\")\n                    && matches!(", "                let r = if matches!(")],
     TS + "hub_native_id_at_another_prefix_is_refused"),
]

if __name__ == "__main__":
    main("t32read", MUTANTS)
