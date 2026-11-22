# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T36's read part: scaas-rpc's bitcoin module (Esplora reads, Bitcoin Core reads, BitcoinCrossCheck):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t36read-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-rpc/src/bitcoin.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features bitcoin --test bitcoin -- --exact "
MUTANTS = [
    ("Esplora's identity check skipped",
     [(R, "            .map(|g| g == self.genesis)", "            .map(|_| true)")],
     T + "esplora_of_another_network_is_refused"),
    ("Core's identity check skipped",
     [(R, "            Some(g) => Ok(g == self.genesis),", "            Some(_) => Ok(true),")],
     T + "core_of_another_network_is_refused"),
    ("the tip cross-check skipped",
     [(R, "    if at.as_deref() != Some(hash.as_str()) {", "    if false {")],
     T + "the_cross_check_refuses_each_disagreement"),
    ("a UTXO Core reports spent still used",
     [(R, "            None => return Err(BitcoinCrossCheck::Spent { txid, vout }),", "            None => {}")],
     T + "the_cross_check_refuses_each_disagreement"),
    ("the UTXO's value not compared",
     [(R, "            Some(o) if o.value != u.value || o.script", "            Some(o) if o.script")],
     T + "the_cross_check_refuses_each_disagreement"),
    ("the UTXO's script not compared",
     [(R, " || o.script != script.to_ascii_lowercase() => {", " => {")],
     T + "the_cross_check_refuses_each_disagreement"),
    ("a value above 21 million BTC read",
     [(R, "        .filter(|s| *s <= MAX_SATS)", "        .filter(|s| *s <= MAX_SATS + 1)")],
     T + "esplora_answers_out_of_form_are_refused"),
    ("1001 UTXOs read",
     [(R, "pub const UTXO_MAX: usize = 1000;", "pub const UTXO_MAX: usize = 1001;")],
     T + "esplora_answers_out_of_form_are_refused"),
    ("a txid of 31 bytes read",
     [(R, "        .filter(|t| t.len() == 64 && t.bytes()", "        .filter(|t| t.len() >= 58 && t.bytes()")],
     T + "esplora_answers_out_of_form_are_refused"),
    ("a confirmed status without a height read as unconfirmed",
     [(R, "            .map(Some)\n            .ok_or_else(|| malformed(i, \"a confirmed status without a height\")),",
       "            .map(Some)\n            .or(Some(None))\n            .ok_or_else(|| malformed(i, \"a confirmed status without a height\")),")],
     T + "esplora_answers_out_of_form_are_refused"),
    ("an address of any form asked",
     [(R, "    let ok = (14..=90).contains(&a.len())", "    let ok = true || (14..=90).contains(&a.len())")],
     T + "esplora_answers_out_of_form_are_refused"),
    ("a text answer of 81 bytes read",
     [(R, "const TEXT_MAX: usize = 80;", "const TEXT_MAX: usize = 81;")],
     T + "esplora_answers_out_of_form_are_refused"),
    ("fee rates rounded up",
     [(R, ".map(|r| (r * 1000.0).round() as u64);", ".map(|r| (r * 1000.0).ceil() as u64);")],
     T + "esplora_reads_the_recorded_answers"),
    ("the next history page asked from the start",
     [(R, '            Some(t) => format!("/address/{a}/txs/chain/{}", txid(i, &json!(t))?),',
       '            Some(t) => format!("/address/{a}/txs?after={}", txid(i, &json!(t))?),')],
     T + "esplora_reads_the_recorded_answers"),
    ("gettxout without the mempool's spends",
     [(R, "json!([txid(i, &json!(id))?, vout, true])", "json!([txid(i, &json!(id))?, vout, false])")],
     T + "core_reads_the_recorded_answers"),
    ("Core's value in another unit",
     [(R, ".map(|b| (b * 1e8).round() as u64)", ".map(|b| (b * 1e7).round() as u64)")],
     T + "core_reads_the_recorded_answers"),
]

if __name__ == "__main__":
    main("t36read", MUTANTS)
