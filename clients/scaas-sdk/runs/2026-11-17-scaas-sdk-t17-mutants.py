# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T17 (`dex`) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t17-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

D = "clients/scaas-sdk/src/dex.rs"
P = "clients/scaas-sdk/src/op/prepared.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} "
E2E = f"cd clients/scaas-sdk && CAPPED_MEM=6G ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test e2e -- --ignored "
MUTANTS = [
    ("skip the DEX list check", [(D, "                listed(&sdk, &req.chain, &dex)?;\n                let sell = addr20(&req.sell_token.to_ascii_lowercase())?;\n                let receive", "                let sell = addr20(&req.sell_token.to_ascii_lowercase())?;\n                let receive")], SDK + "--test dex dex_not_on_profile_list_is_refused"),
    ("skip the wrapper list check", [(D, "if !wrappers.contains(&wrapper) {", "if wrappers.is_empty() && false {")], SDK + "--test dex cancel_and_wrap_rows_equal_the_vectors"),
    ("ignore the liquidity mark", [(D, "if !entry.liquidity {", "if entry.liquidity && false {")], SDK + "--test dex dex_not_on_profile_list_is_refused"),
    ("the order's form from the request, not the factory", [(D, "let ua = scaas_token(&pool, dex, sell).await?;\n                drop(key_opened", "let ua = true;\n                drop(key_opened")], SDK + "--test dex place_posts_the_named_order_signed_in_its_form"),
    ("another signer's order cancelled", [(D, "if ua { \"bytes32\" } else { \"address\" }).await?;\n                if unhex(&me)? != from_b {", "if ua { \"bytes32\" } else { \"address\" }).await?;\n                if unhex(&me)? == from_b && false {")], SDK + "--test dex cancel_and_wrap_rows_equal_the_vectors"),
    ("post to a gateway of another chain_uid", [(D, "            Ok(_) => {\n                mismatch = true;\n                continue;\n            }", "            Ok(_) => {}")], SDK + "--test dex place_posts_the_named_order_signed_in_its_form"),
    ("an order cancel followed by the executed event", [(P, "\"CancelUAOrder\" => Some((", "\"CancelUAOrderX\" => Some((")], E2E + "e2e_dex_cancel_order_on_anvil"),
]

if __name__ == "__main__":
    main("t17", MUTANTS)
