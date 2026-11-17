# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T14 (Hedera) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t14-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

H = "clients/scaas-rpc/src/hedera.rs"
N = "scaas-node/src/adapters/hedera.rs"
EV = "scaas-node/src/adapters/evm.rs"
ST = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib submit::tests::"
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
    ("b: tx_status through failover", [(N, "        if let Some(st) = decode_receipt(&pool.first_relay_receipt(id).await?) {",
        "        if let Some(st) = decode_receipt(&self.inner.lane(0)?.read(|p| async move { p.raw_request::<_, Value>(\"eth_getTransactionReceipt\".into(), (id,)).await.map_err(|e| SimError::Transport(e.to_string())) }).await.map_err(|e| anyhow!(\"{e}\"))?) {")],
     NT + "hedera_tx_status_never_fails_over"),
    ("b: op_consumed through failover", [(N, "        if chain.failover_answers() != mark {\n            bail!(", "        if false {\n            bail!(")],
     NT + "hedera_op_consumed_never_rests_on_a_failover_answer"),
    ("b: the lane sequence through failover", [(EV, "        self.lane(lane)?.nonce_at().await",
        "        let c = self.lane(lane)?;\n        c.read(|p| async move { p.get_transaction_count(c.address()).latest().await.map_err(|e| SimError::Transport(e.to_string())) }).await.map_err(|e| anyhow!(\"{e}\"))")],
     NT + "hedera_the_lane_sequence_never_fails_over"),
    ("b: the build's balance on endpoint 0 only", [(N, "            .read(|p| async move { p.get_balance(addr).await.map_err(|e| SimError::Transport(e.to_string())) })\n            .await?;",
        "            .primary()\n            .get_balance(addr)\n            .await\n            .map_err(|e| SimError::Transport(e.to_string()))?;")],
     NT + "hedera_build_reads_fail_over_when_the_first_endpoint_is_down"),
    ("b: the failover counter not compared in build", [(EV, "            Err(SimError::Revert(r)) if chain.failover_answers() != mark =>", "            Err(SimError::Revert(r)) if false =>")],
     ST + "the_generic_runner_requeues_a_refusal_on_a_failover_answer"),
]

if __name__ == "__main__":
    main("t14", MUTANTS)
