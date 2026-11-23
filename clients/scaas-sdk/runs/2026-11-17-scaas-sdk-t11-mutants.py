# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T11 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t11-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

W = "clients/scaas-sdk/src/wallet/"
Q = "clients/scaas-sdk/src/op/quote.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test wallet "
U = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib op::tests::"
LATEST = ("let w = { use alloy::network::TransactionBuilder; pool.call_tx(alloy::rpc::types::TransactionRequest::default()"
          ".with_to(*t).with_input(Bytes::from(data.clone()))).await.map_err(|_| ReadError::Failure(scaas_rpc::EndpointFailure::new("
          "at.endpoint, scaas_rpc::FailureKind::Transport, \"x\")))? };")
MUTANTS = [
    # the plan's three
    ("skip the token chainUid check", [(W + "tokens.rs", "if hex(&uid) != profile.chain_uid.to_ascii_lowercase() {",
                                         "if false && hex(&uid) != profile.chain_uid.to_ascii_lowercase() {")], T + "token_chain_uid_mismatch_is_refused"),
    ("read balances at latest per token", [(W + "balances.rs", "let w = pool.call_at(&at, *t, Bytes::from(data.clone())).await?;", LATEST)],
     T + "balances_at_one_block"),
    ("show an unlisted name unmarked", [(W + "tokens.rs", "display: format!(\"[unlisted] {symbol}\"),", "display: symbol.clone(),")],
     T + "unlisted_name_is_sanitised"),
    # each check of the task
    ("an unlisted name not stripped", [(W + "tokens.rs", ".filter(|c| !crate::text::hidden(*c))", ".filter(|_| true)")], T + "unlisted_name_is_sanitised"),
    ("the gateway's chain_uid not compared", [("clients/scaas-sdk/src/wallet/families/mod.rs", ".is_some_and(|u| u.eq_ignore_ascii_case(&c.profile.chain_uid))", ".is_some()")],
     U + "gateway_chain_uid_mismatch_is_refused"),
    ("only type 4 refused", [(W + "native_evm.rs", "if req.tx_type.is_some_and(|t| t > 2) {", "if req.tx_type.is_some_and(|t| t == 4) {")], T + "native_send_types"),
    ("the index's tokens shown listed", [(W + "tokens.rs", "                listed: false,\n", "                listed: true,\n")],
     T + "factory_index_token_off_list_is_unlisted"),
]

if __name__ == "__main__":
    main("t11", MUTANTS)
