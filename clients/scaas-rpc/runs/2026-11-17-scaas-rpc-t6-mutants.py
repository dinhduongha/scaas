# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T6 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t6-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

E = "clients/scaas-rpc/src/evm.rs"
P = "clients/scaas-rpc/src/pool.rs"
C = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features "
A = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features evm --test anvil -- --ignored "
MUTANTS = [
    ("pin by number instead of hash", [(E, "    alloy::eips::BlockId::Hash(alloy::eips::RpcBlockHash {\n        block_hash: at.hash,\n        require_canonical: Some(true),\n    })",
                                        "    alloy::eips::BlockId::number(at.number)")],
     C + "--test evm_fakes pinned_reads_name_the_block_by_hash"),
    ("skip the re-check", [(E, "            if self.header(i, number, None).await? != hash {", "            if false {")],
     C + "--test evm_fakes a_reorg_between_read_and_recheck_is_block_changed"),
    ("compare T without the block hash", [(P, "let g = match groups.iter().position(|g| g.1 == hash && same(&g.0, &v)) {",
                                           "let g = match groups.iter().position(|g| same(&g.0, &v)) {")],
     C + "--test pool a_member_whose_block_hash_differs_is_outside_the_group"),
    ("the smallest block", [(P, "let b = sorted[need - 1];", "let b = *sorted.last().unwrap();")],
     C + "--test pool the_block_is_the_need_th_highest_named"),
    ("the pending nonce from one endpoint under strict majority",
     [(E, "    pub async fn pending_nonce(&self, who: Address, purpose: Purpose) -> Result<u64, RpcError> {\n        if self.pool.policy() == crate::Policy::StrictMajority {",
       "    pub async fn pending_nonce(&self, who: Address, purpose: Purpose) -> Result<u64, RpcError> {\n        if false {")],
     A + "the_nonce_under_strict_majority_is_the_agreed_committed_nonce"),
    ("the fee from one endpoint under strict majority", [(E, "    pub async fn fees(&self, purpose: Purpose) -> Result<Fees, RpcError> {\n        if self.pool.policy() != crate::Policy::StrictMajority {",
       "    pub async fn fees(&self, purpose: Purpose) -> Result<Fees, RpcError> {\n        if true {")],
     C + "--test evm_fakes fees_under_strict_majority_are_the_need_th_highest"),
]

if __name__ == "__main__":
    main("t6", MUTANTS)
