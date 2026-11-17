# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T14 (Hedera) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t14-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

H = "clients/scaas-rpc/src/hedera.rs"
N = "scaas-node/src/adapters/hedera.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test hedera "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::hedera::tests::"
MUTANTS = [
    ("a: every transaction known", [(H, "        Ok(!tx.is_null())", "        Ok(true)")],
     T + "the_relay_receipt_is_read_raw_from_the_first_endpoint"),
    ("a: the receipt dropped", [(H, "            .raw_request(\"eth_getTransactionReceipt\".into(), (hash,))\n            .await\n            .map_err(|e| first_err(&e))\n",
                                 "            .raw_request::<_, Value>(\"eth_getTransactionReceipt\".into(), (hash,))\n            .await\n            .map_err(|e| first_err(&e))\n            .map(|_| Value::Null)\n")],
     T + "the_relay_receipt_is_read_raw_from_the_first_endpoint"),
    ("a: the adapter reads no receipt", [(N, "        if let Some(st) = decode_receipt(&pool.first_relay_receipt(id).await?) {",
                                          "        if let Some(st) = decode_receipt(&{ let _ = pool.first_relay_receipt(id).await?; Value::Null }) {")],
     NT + "contract_revert_stays_terminal"),
]

if __name__ == "__main__":
    main("t14", MUTANTS)
