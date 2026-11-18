# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T24 (the fixes of the families' review) mutants, one set per fix:
FIX=<k> python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t24-mutants.py check | run [name…]
writes 2026-11-17-scaas-rpc-t24-<k>-mutants.txt (every mutant of fix T24.<k>; names start with "<k>:")."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "scaas-node/src/adapters/"
C = "clients/scaas-rpc/src/"
EVM = A + "evm.rs"
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::"
MUTANTS = [
    # T24.1 (P1): no later endpoint's text reaches a classifier; the abort is endpoint 0's typed answer
    ("1: the all-failed error carries the endpoints' text",
     [(EVM, 'anyhow::anyhow!("{what}: no endpoint answered ({}); a failover endpoint\'s answer decides nothing", e.code())',
       'anyhow::anyhow!("{what}: no endpoint answered ({e}); a failover endpoint\'s answer decides nothing")')],
     NT + "aptos::tests::aptos_a_later_endpoints_forged_abort_never_kills_the_job"),
    ("1: the abort read from the error's text",
     [(A + "aptos.rs", "Err(e) if e.downcast_ref::<ViewRefused>().is_some_and(ViewRefused::is_abort) =>",
       'Err(e) if format!("{e:#}").contains("Move abort") =>')],
     NT + "aptos::tests::aptos_the_abort_is_read_from_endpoint_0s_typed_answer"),
    # T24.3: only what the family's classifier reads as the contract's answer is endpoint 0's verdict; the rest fails over
    ("3: Aptos: every status endpoint 0's verdict",
     [(A + "aptos.rs", 'Ok((s, _)) => Err(ReadError::Failure(scaas_rpc::EndpointFailure::new(i, scaas_rpc::FailureKind::Http, &format!("{path}: HTTP {s}")))),',
       'Ok((s, v)) => Err(ReadError::Revert { data: vec![], reason: format!("{s}\\n{v}") }),')],
     NT + "aptos::tests::aptos_endpoint_0_rate_limited_fails_over"),
    ("3: Cosmos: every code the first gateway's verdict",
     [(A + "cosmos.rs", 'Ok((s, v)) if matches!(v["code"].as_u64(), Some(2 | 3)) =>', "Ok((s, v)) =>")],
     NT + "cosmos::tests::cosmos_gateway_0_unavailable_fails_over"),
    ("3: Algorand: every status endpoint 0's verdict",
     [(A + "algorand.rs", "FamilyError::Status { status, message } if status == 404 || (post && status == 400) => {",
       "FamilyError::Status { status, message } => {")],
     NT + "algorand::tests::algorand_endpoint_0_rate_limited_fails_over"),
    ("3: NEAR: every error endpoint 0's verdict",
     [(A + "near.rs", ' if matches!(cause_name(&error), "CONTRACT_EXECUTION_ERROR" | "UNKNOWN_ACCOUNT") => {', " => {")],
     NT + "near::tests::near_endpoint_0_rate_limited_fails_over"),
    ("3: Sui: every error endpoint 0's verdict",
     [(A + "sui.rs", ' if error["code"] == -32602 => ReadError::Revert', " => ReadError::Revert")],
     NT + "sui::tests::sui_endpoint_0_rate_limited_fails_over"),
    ("3: TON: every status endpoint 0's verdict",
     [(A + "ton.rs", 'FamilyError::Status { status: 404, message } => ReadError::Revert { data: vec![], reason: format!("404\\n{message}") },',
       'FamilyError::Status { status, message } => ReadError::Revert { data: vec![], reason: format!("{status}\\n{message}") },')],
     NT + "ton::tests::ton_endpoint_0_rate_limited_fails_over"),
    # T24.2: every Mined status endpoint 0 read, and its polled head, raise the failover reads' floor (CLI-RPC-04)
    ("2: aptos: a mined status leaves the floor", [(A + "aptos.rs", "            self.net.client.pool().saw_block(*height);\n        }\n        st", "            let _ = height;\n        }\n        st")], NT + "aptos::tests::aptos_a_mined_status_and_the_head_raise_the_floor"),
    ("2: aptos: the polled head leaves the floor", [(A + "aptos.rs", "        self.net.client.pool().saw_block(head); // the failover reads' floor: endpoint 0's block height\n", "")], NT + "aptos::tests::aptos_a_mined_status_and_the_head_raise_the_floor"),
    ("2: sui: a mined status leaves the floor", [(A + "sui.rs", "            self.net.client.pool().saw_block(*height);\n        }\n        st", "            let _ = height;\n        }\n        st")], NT + "sui::tests::sui_a_mined_status_and_the_head_raise_the_floor"),
    ("2: sui: the polled head leaves the floor", [(A + "sui.rs", "        self.net.client.pool().saw_block(seq); // the failover reads' floor: endpoint 0's checkpoint\n", "")], NT + "sui::tests::sui_a_mined_status_and_the_head_raise_the_floor"),
    ("2: ton: a mined status leaves the floor", [(A + "ton.rs", "            self.api.saw(*height);\n        }\n        st", "            let _ = height;\n        }\n        st")], NT + "ton::tests::ton_a_mined_status_and_the_head_raise_the_floor"),
    ("2: ton: the polled head leaves the floor", [(A + "ton.rs", "        self.api.saw(height); // the failover reads' floor: endpoint 0's masterchain seqno\n", "")], NT + "ton::tests::ton_a_mined_status_and_the_head_raise_the_floor"),
    ("2: cosmos: a mined status leaves the floor", [(A + "cosmos.rs", "            self.net.rest.client.pool().saw_block(*height);\n        }\n        st", "            let _ = height;\n        }\n        st")], NT + "cosmos::tests::cosmos_a_mined_status_and_the_head_raise_the_floor"),
    ("2: cosmos: the polled head leaves the floor", [(A + "cosmos.rs", "        self.net.rest.client.pool().saw_block(height); // the failover reads' floor: the first CometBFT endpoint's height\n", "")], NT + "cosmos::tests::cosmos_a_mined_status_and_the_head_raise_the_floor"),
    ("2: algorand: a mined status leaves the floor", [(A + "algorand.rs", "            self.net.client.pool().saw_block(*height);\n        }\n        st", "            let _ = height;\n        }\n        st")], NT + "algorand::tests::algorand_a_mined_status_and_the_head_raise_the_floor"),
    ("2: algorand: the polled head leaves the floor", [(A + "algorand.rs", "        self.net.client.pool().saw_block(height); // the failover reads' floor: endpoint 0's last round\n", "")], NT + "algorand::tests::algorand_a_mined_status_and_the_head_raise_the_floor"),
    ("2: near: a mined status leaves the floor", [(A + "near.rs", "            self.net.client.pool().saw_block(*height);\n        }\n        st", "            let _ = height;\n        }\n        st")], NT + "near::tests::near_a_mined_status_and_the_head_raise_the_floor"),
    ("2: near: the polled head leaves the floor", [(A + "near.rs", "        self.net.client.pool().saw_block(height); // the failover reads' floor: endpoint 0's final height\n", "")], NT + "near::tests::near_a_mined_status_and_the_head_raise_the_floor"),
    ("2: soroban: a mined status leaves the floor", [(A + "soroban.rs", "            self.net.client.pool().saw_block(*height);\n        }\n        st", "            let _ = height;\n        }\n        st")], NT + "soroban::tests::soroban_a_mined_status_and_the_head_raise_the_floor"),
    ("2: soroban: the polled head leaves the floor", [(A + "soroban.rs", "        self.net.client.pool().saw_block(head.sequence); // the failover reads' floor (endpoint 0's polled ledger)\n", "")], NT + "soroban::tests::soroban_a_mined_status_and_the_head_raise_the_floor"),
    ("2: solana: a mined status leaves the floor", [(A + "solana.rs", "            self.net.client.pool().saw_block(*height);\n        }\n        st", "            let _ = height;\n        }\n        st")], NT + "solana::tests::solana_a_mined_status_and_the_head_raise_the_floor"),
    ("2: solana: the polled head leaves the floor", [(A + "solana.rs", "                    self.net.client.pool().saw_block(s); // the failover reads' floor: endpoint 0's slot\n", "")], NT + "solana::tests::solana_a_mined_status_and_the_head_raise_the_floor"),
    ("2: hedera: a mined status leaves the floor", [(A + "hedera.rs", "                c.saw_block(*height);\n", "                let _ = (c, height);\n")], NT + "hedera::tests::hedera_a_mined_status_raises_the_floor"),
    ("2: solana: the head read at finalized", [("clients/scaas-rpc/src/solana.rs", '.call(i, "getSlot", json!([{"commitment": "confirmed"}]))', '.call(i, "getSlot", json!([{"commitment": "finalized"}]))')],
     "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test solana the_head_is_the_confirmed_slot"),
    # T24.5: a network limit is kept from endpoint 0's answer only
    ("5: Soroban: the tx size kept from any endpoint", [(A + "soroban.rs", "                if at == 0 {\n                    *last = Some(limit);\n                }", "                *last = Some(limit);")],
     NT + "soroban::tests::soroban_the_last_good_limit_is_endpoint_0s_only"),
    ("5: Soroban: the entry size kept from any endpoint", [(A + "soroban.rs", "            Ok((limit, 0)) => *last = Some(limit),\n            Ok((limit, _)) => return Some(limit),", "            Ok((limit, _)) => *last = Some(limit),")],
     NT + "soroban::tests::soroban_the_last_good_limit_is_endpoint_0s_only"),
    # T24.7: the sends go to endpoint 0 explicitly, inside `build`'s scope too
    ("7: Algorand: the send through the failover helper", [(A + "algorand.rs", 'match self.net.post(0, "/v2/transactions", signed.raw.clone(), "application/x-binary").await.map_err(algod_error) {',
       'match self.post("/v2/transactions", signed.raw.clone(), "application/x-binary").await {')],
     NT + "algorand::tests::algorand_submit_inside_build_asks_endpoint_0_only"),
    ("7: Cosmos: the send through the failover helper", [(A + "cosmos.rs", 'let (code, v) = self.net.rest.post(0, "/cosmos/tx/v1beta1/txs", &body).await.map_err(|e| anyhow!("POST /cosmos/tx/v1beta1/txs: {e}"))?;',
       'let (code, v) = self.rest_post("/cosmos/tx/v1beta1/txs", &body).await?;')],
     NT + "cosmos::tests::cosmos_submit_inside_build_asks_gateway_0_only"),
    ("7: TON: the send through the failover helper", [(A + "ton.rs", 'self.net.post(0, "message", &body).await.map(|_| ()).map_err(|e| Self::error("message", e))',
       'self.post("message", body).await.map(|_| ())')],
     NT + "ton::tests::ton_submit_inside_build_asks_endpoint_0_only"),
    # T24.8 (CLI-RPC-03): endpoint 0 passes its identity before its own reads, in every family
    ("8: Aptos: endpoint 0 read unchecked", [(C + "aptos.rs", "crate::family::admit_first(&self.client, self, i).await?;\n        self.fetch(i, path).await", "self.fetch(i, path).await")], NT + "aptos::tests::aptos_endpoint_0_of_another_network_answers_no_read"),
    ("8: sui: endpoint 0 read unchecked", [(C + "sui.rs", "crate::family::admit_first(&self.client, self, i).await?;\n        self.client.rpc_at(i, method, params).await", "self.client.rpc_at(i, method, params).await")], NT + "sui::tests::sui_endpoint_0_of_another_network_answers_no_read"),
    ("8: near: endpoint 0 read unchecked", [(C + "near.rs", "crate::family::admit_first(&self.client, self, i).await?;\n        self.client.rpc_at(i, method, params).await", "self.client.rpc_at(i, method, params).await")], NT + "near::tests::near_endpoint_0_of_another_network_answers_no_read"),
    ("8: soroban: endpoint 0 read unchecked", [(C + "soroban.rs", "crate::family::admit_first(&self.client, self, i).await?;\n        self.client.rpc_at(i, method, params).await", "self.client.rpc_at(i, method, params).await")], NT + "soroban::tests::soroban_endpoint_0_of_another_network_answers_no_read"),
    ("8: solana: endpoint 0 read unchecked", [(C + "solana.rs", "crate::family::admit_first(&self.client, self, i).await?;\n        self.client.rpc_at(i, method, params).await", "self.client.rpc_at(i, method, params).await")], NT + "solana::tests::solana_endpoint_0_of_another_network_answers_no_read"),
    ("8: Algorand: endpoint 0 read unchecked", [(C + "algorand.rs", "crate::family::admit_first(&self.client, self, i).await?;\n        self.fetch(i, path, query).await", "self.fetch(i, path, query).await")], NT + "algorand::tests::algorand_endpoint_0_of_another_network_answers_no_read"),
    ("8: Cosmos: REST gateway 0 read unchecked", [(C + "cosmos.rs", "crate::family::admit_first(&self.client, self, i).await?;\n        json_at(&self.client, i, reqwest::Method::GET, path, None).await", "json_at(&self.client, i, reqwest::Method::GET, path, None).await")], NT + "cosmos::tests::cosmos_endpoint_0_of_another_network_answers_no_read"),
    ("8: Cosmos: CometBFT endpoint 0 read unchecked", [(C + "cosmos.rs", "crate::family::admit_first(&self.rpc, self, i).await?;\n        self.comet(i, path).await", "self.comet(i, path).await")], NT + "cosmos::tests::cosmos_endpoint_0_of_another_network_answers_no_read"),
    # T24.9: Algorand's raw JSON answers through the bounded decode (CLI-RPC-07)
    ("9: Algorand: get parsed by serde_json alone", [(A + "algorand.rs", "json_of(path, &self.get_raw(path, &[]).await?)", "Ok(serde_json::from_slice(&self.get_raw(path, &[]).await?)?)")],
     NT + "algorand::tests::algorand_a_raw_json_answer_deeper_than_64_is_refused"),
    ("9: Algorand: a box parsed by serde_json alone", [(A + "algorand.rs", 'let v = json_of("box", &b)?;', "let v: Value = serde_json::from_slice(&b)?;")],
     NT + "algorand::tests::algorand_a_raw_json_answer_deeper_than_64_is_refused"),
    # T24.12: endpoint 0's answers classified by status or code, never text
    ("12: TON: 404 read from the text", [(A + "ton.rs", "Err(e) if e.downcast_ref::<HttpStatus>().is_some_and(|s| s.status == 404) => 0,", 'Err(e) if format!("{e:#}").contains("404") => 0,')],
     NT + "ton::tests::ton_a_404_is_read_from_the_status_never_the_text"),
    ("12: Sui: not found read from the text", [(A + "sui.rs", 'Err(e) if e.downcast_ref::<FamilyError>().and_then(FamilyError::rpc_error).is_some_and(|x| x["code"] == -32602) => {', 'Err(e) if format!("{e:#}").contains("Could not find") => {')],
     NT + "sui::tests::sui_not_found_is_read_from_the_code_never_the_text"),
    # T24.14: the signing account number kept from gateway 0 only
    ("14: Cosmos: the account number kept from any gateway", [(A + "cosmos.rs", "        if !building() {\n            if let Ok(mut m) = self.account_numbers.lock() {", "        if true {\n            if let Ok(mut m) = self.account_numbers.lock() {")],
     NT + "cosmos::tests::cosmos_the_account_number_is_kept_from_gateway_0_only"),
]

if __name__ == "__main__":
    fix = os.environ.get("FIX")
    main(f"t24-{fix}" if fix else "t24", [m for m in MUTANTS if not fix or m[0].startswith(f"{fix}:")])
