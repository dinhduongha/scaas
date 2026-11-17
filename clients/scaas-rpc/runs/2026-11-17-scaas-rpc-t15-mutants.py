# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T15 (Soroban) mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t15-mutants.py check | run [name…]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-rpc/src/soroban.rs"
F = "clients/scaas-rpc/src/family.rs"
N = "scaas-node/src/adapters/soroban.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test soroban "
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::soroban::tests::"
MUTANTS = [
    # the plan's family mutants (a): the quorum helper asked on endpoint 0 only; the 20 s timeout replaced by 30 s (no API key here)
    ("a: the head quorum on endpoint 0 only", [(S, "        for i in 1..self.client.len() {", "        for i in 1..1 {")],
     T + "the_ledger_reads_and_the_head_quorum"),
    ("a: the family timeout 30 s", [(F, "pub const FAMILY_TIMEOUT_MS: u64 = 20_000;", "pub const FAMILY_TIMEOUT_MS: u64 = 30_000;")],
     "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --lib family::tests::"),
    ("a: an error answer read as a result", [(F, "        if let Some(e) = v.get_mut(\"error\").filter(|e| !e.is_null()) {", "        if let Some(e) = None::<&mut Value> {")],
     T + "an_error_answer_is_kept_whole"),
    ("a: the ledger hash not lowercased", [(S, "        Ok(format!(\"0x{}\", h.to_lowercase()))", "        Ok(format!(\"0x{h}\"))")],
     T + "the_ledger_reads_and_the_head_quorum"),
]

if __name__ == "__main__":
    main("t15", MUTANTS)
