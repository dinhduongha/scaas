# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T24.soroban, Soroban's ledger keys (clientkeys) and the SDK's balance reads (spec §8.7):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24soroban-mutants.py check | run [name...]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/wallet/families/soroban.rs"
M = "clients/scaas-sdk/src/wallet/families/mod.rs"
L = "clients/scaas-sdk/src/lib.rs"
K = "clients/clientkeys/src/fam/soroban.js"
CM = "clients/scaas-cli/Cargo.toml"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features soroban --test soroban -- --exact "
KT = "cd clients/clientkeys && ../../scripts/capped node --test --test-reporter=tap test/fam-soroban.test.js"
CT = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --bin scaas "
MUTANTS = [
    ("the Soroban dispatch off",
     [(M, "        crate::Family::Soroban => soroban::balances(c, id).await,\n", "")],
     T + "soroban_balances_at_one_ledger"),
    ("read the second endpoint first",
     [(M, "let a = client.failover(probe, first).await?;",
       "let a = client.failover(probe, |i| first((i + 1) % client.len())).await?;")],
     T + "soroban_two_endpoints_one_down"),
    ("an archived entry read",
     [(S, "            .is_some_and(|l| l < ledger)", "            .is_some_and(|l| l < ledger && false)")],
     T + "soroban_entries_out_of_form_are_refused"),
    ("an entry listed twice read",
     [(S, "        let Some(n) = slot.filter(|n| amounts.get(*n).is_some_and(Option::is_none)) else {",
       "        let Some(n) = slot else {")],
     T + "soroban_entries_out_of_form_are_refused"),
    ("a negative I128 read",
     [(S, "    (v >= 0).then(|| v.to_string())\n}\n\n/// What a key's entry holds.",
       "    Some(v.to_string())\n}\n\n/// What a key's entry holds.")],
     T + "soroban_entries_out_of_form_are_refused"),
    ("an account entry of another account read",
     [(S, "            if x.len() > ACCOUNT_MAX || x.get(..40)? != key {", "            if x.len() > ACCOUNT_MAX {")],
     T + "soroban_entries_out_of_form_are_refused"),
    ("a byte after a token value read",
     [(S, "    let v = i128::from_be_bytes(b.try_into().ok()?);",
       "    let v = i128::from_be_bytes(b.get(..16)?.try_into().ok()?);")],
     T + "soroban_entries_out_of_form_are_refused"),
    ("a C… holder's native read as a token entry",
     [(S, "        Holder::Contract(_) => keys.push((balance_key(sac, &h), Form::Sac)),",
       "        Holder::Contract(_) => keys.push((balance_key(sac, &h), Form::Token)),")],
     T + "soroban_balances_at_one_ledger"),
    ("a UA id's key as Balance(Address)",
     [(S, "            sym(&mut v, \"UaBalance\");", "            sym(&mut v, \"Balance\");")],
     T + "soroban_balances_at_one_ledger"),
    ("the strkey checksum unchecked",
     [(S, "    if acc != 0 || crc16(body).to_le_bytes() != crc {", "    if acc != 0 {")],
     T + "soroban_holder_token_and_params_forms"),
    ("the passphrase's hash not checked",
     [(L, "                    if scaas_ua::sha256(passphrase.as_bytes()).as_slice() != uid.as_slice() {",
       "                    if false {")],
     T + "soroban_holder_token_and_params_forms"),
    ("strict majority: an endpoint behind the set counted",
     [(S, "        |j, l| async move { set_at(sor, j, keys, native, l).await.map(|(_, v)| v) },",
       "        |j, _l| async move { set_at(sor, j, keys, native, 0).await.map(|(_, v)| v) },")],
     T + "soroban_strict_majority_agrees_on_the_set"),
    ("clientkeys: a UA id's key as Balance",
     [(K, "return S.vec([S.sym(\"UaBalance\"), S.bytes(fromHex(holder))]);",
       "return S.vec([S.sym(\"Balance\"), S.bytes(fromHex(holder))]);")],
     KT),
    ("clientkeys: a temporary entry",
     [(K, "const PERSISTENT = 1;", "const PERSISTENT = 0;")],
     KT),
    ("cli: the CLI's SDK without Soroban reads",
     [(CM, '  "solana",\n  "soroban",\n', '  "solana",\n')],
     CT + "family_profiles_open_and_read"),
]

if __name__ == "__main__":
    main("t24soroban", MUTANTS)
