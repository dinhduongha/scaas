# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T24.ton: the SDK's balance reads over TON Center (pinned to one masterchain seqno) and the CLI's TON feature:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24ton-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/wallet/families/ton.rs"
M = "clients/scaas-sdk/src/wallet/families/mod.rs"
L = "clients/scaas-sdk/src/lib.rs"
CM = "clients/scaas-cli/Cargo.toml"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features ton --test ton -- --exact "
CT = "cd clients/scaas-cli && ../../scripts/capped cargo test --locked --offline -j2 --bin scaas "
MUTANTS = [
    ("the TON dispatch off",
     [(M, "        crate::Family::Ton => ton::balances(c, id).await,",
       "        crate::Family::Ton => Err(SdkError::FeatureMissing),")],
     T + "ton_balances_at_one_masterchain_block"),
    ("read the second endpoint first",
     [(M, "let a = client.failover(probe, first).await?;",
       "let a = client.failover(probe, |i| first((i + 1) % client.len())).await?;")],
     T + "ton_two_endpoints_one_down"),
    ("exit code 1 not a success",
     [(S, "    code == 0 || code == 1\n", "    code == 0\n")],
     T + "ton_malformed_answers_are_refused"),
    ("a failed get_wallet_address read",
     [(S, "    if !success(g.exit_code) {", "    if false {")],
     T + "ton_malformed_answers_are_refused"),
    ("a failed get_wallet_data read",
     [(S, "    if !success(d.exit_code) {", "    if false {")],
     T + "ton_malformed_answers_are_refused"),
    ("the master asked for its own wallet",
     [(S, "boc::address_slice(who.0, &who.1)", "boc::address_slice(master.0, &master.1)")],
     T + "ton_balances_at_one_masterchain_block"),
    ("an uninitialized wallet asked, not 0",
     [(S, "        \"uninitialized\" => return Ok(\"0\".into()),\n        \"active\" => {}",
       "        \"uninitialized\" | \"active\" => {}")],
     T + "ton_balances_at_one_masterchain_block"),
    ("a frozen wallet read",
     [(S, "        \"active\" => {}", "        \"active\" | \"frozen\" => {}")],
     T + "ton_malformed_answers_are_refused"),
    ("a wallet of another owner read",
     [(S, "    if address_of(i, d.stack.get(1), \"a wallet owner that is not an addr_std\")? != who\n        || ",
       "    if ")],
     T + "ton_malformed_answers_are_refused"),
    ("a wallet of another master read",
     [(S, "\n        || address_of(i, d.stack.get(2), \"a wallet master that is not an addr_std\")? != master", "")],
     T + "ton_malformed_answers_are_refused"),
    ("a jetton balance that is no number read as 0",
     [(S, "        None => Err(malformed(\n            i,\n            \"a jetton balance that is not a number of at most 128 bits\",\n        )),",
       "        None => Ok(\"0\".into()),")],
     T + "ton_malformed_answers_are_refused"),
    ("the native balance not bounded",
     [(S, "    let native = amount(\n        i,\n", "    let native = (|_: usize, s: &str| Ok::<String, ReadError>(s.to_string()))(\n        i,\n")],
     T + "ton_malformed_answers_are_refused"),
    ("the set read one block before the head",
     [(S, "            Ok((s, set_at(ton, i, s, who, tokens).await?))",
       "            Ok((s, set_at(ton, i, s - 1, who, tokens).await?))")],
     T + "ton_balances_at_one_masterchain_block"),
    ("the majority read at its own head",
     [(S, "        |j, s| async move { set_at(ton, j, s, who, tokens).await },",
       "        |j, _s| async move { set_at(ton, j, head(ton, j).await?, who, tokens).await },")],
     T + "ton_strict_majority_agrees_at_one_block"),
    ("endpoint 0's block not the identity reference",
     [(S, "    if i == 0 {\n        ton.saw(s, root);\n    }\n", "")],
     T + "ton_two_endpoints_one_down"),
    ("a token out of form skipped",
     [(S, "        .map(|t| raw_address(&t.address).ok_or(SdkError::Argument))\n        .collect::<Result<Vec<Addr>, SdkError>>()?;",
       "        .filter_map(|t| raw_address(&t.address))\n        .collect::<Vec<Addr>>();")],
     T + "ton_holder_and_token_forms"),
    ("the TON policy ignored",
     [(L, "                Family::Ton => Some(Arc::new(scaas_rpc::ton::Ton::new(\n                    scaas_rpc::family::Client::new(list(&p.rpc, p.rpc_policy)?)?,",
       "                Family::Ton => Some(Arc::new(scaas_rpc::ton::Ton::new(\n                    scaas_rpc::family::Client::new(list(&p.rpc, scaas_rpc::Policy::Failover)?)?,")],
     T + "ton_strict_majority_agrees_at_one_block"),
    ("the CLI's SDK without TON reads",
     [(CM, '  "sui",\n  "ton",\n', '  "sui",\n')],
     CT + "family_profiles_open_and_read"),
]

if __name__ == "__main__":
    main("t24ton", MUTANTS)
