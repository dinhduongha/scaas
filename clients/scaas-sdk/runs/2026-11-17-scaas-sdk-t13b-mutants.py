# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk T13b mutants (closing review P1-1, P2-3, P2-5, P2-6, the P3s of submit; owner 2026-11-19 rulings A and B):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/op/submit.rs"
Q = "clients/scaas-sdk/src/op/quote.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
L = "clients/scaas-sdk/src/lib.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
U = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib "
MUTANTS = [
    ("ruling A: no write ahead before the simulation",
     [(S, "                // the write ahead: nothing signed has left the SDK yet (ruling A)\n                state::put(&sdk, &row).await?;\n", "")],
     U + "sim_refused_is_written_and_followed"),
    ("ruling A: a refused simulation is sent anyway",
     [(S, "Ok(g) if row.gas_limit.is_some_and(|l| g <= l) => {}", "_ if true => {}")],
     U + "sim_refused_is_written_and_followed"),
    ("ruling A: a refused simulation is sent at restart",
     [(S, '                        && row.detail != "SimRefused"\n', '')],
     U + "sim_refused_is_written_and_followed"),
    ("P2-5: from_block is the head", [(S, "super::final_number(&pool, &profile).await?", "super::head(&pool).await?.0")],
     U + "from_block_is_the_final_block_at_submit"),
    ("P3: a Prepared stays in the table at submit", [(S, "            t.remove(&p.id());\n", "")], U + "one_prepared_submits_once"),
    ("P3: a hand-built gateway quote skips door A", [(S, "if p.is_some_and(|p| !door_a(p)) {", "if false {")],
     U + "hand_built_gateway_quote_is_checked"),
    ("P3: a hand-built gateway quote skips the gateways' chain_uid",
     [(S, "                    check_gateways(&sdk, &prepared.chain()).await?;\n", "")], U + "hand_built_gateway_quote_is_checked"),
    ("P2-3: a new pool per call",
     [(L, "let pool = c.pool.clone().ok_or(SdkError::Argument)?;",
       "let pool = Arc::new(scaas_rpc::evm::EvmPool::connect(list(&c.profile.rpc, c.profile.rpc_policy)?, id, c.profile.chain_uid.parse().ok())?);")],
     U + "one_pool_per_chain_for_the_session"),
    ("ruling B: a relayed op without a row is estimated",
     [(Q, "    } else if relayed {\n        return Err(SdkError::GasUnquoted);", "    } else if false {\n        return Err(SdkError::GasUnquoted);")],
     U + "an_operation_without_a_gas_row_is_gas_unquoted"),
    ("ruling B: the signer kind left out of the key",
     [(G, ".filter(|v| v.signer == signer && !v.line.write);", ".filter(|v| !v.line.write);")],
     U + "an_operation_without_a_gas_row_is_gas_unquoted"),
    # removed 2026-11-20 (review T5): "ruling B: a row below its pin": the built-in gas rows and their pin test left in 64c8ed24d (gas tables are data)
]

if __name__ == "__main__":
    main("t13b", MUTANTS)
