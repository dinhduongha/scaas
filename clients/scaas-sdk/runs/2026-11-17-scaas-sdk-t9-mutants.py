# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T9 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t9-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "clients/scaas-sdk/src/account/mod.rs"
R = "clients/scaas-sdk/src/account/restore.rs"
U = "clients/ua-rs/src/wallet/derive.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin"
SDK = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test account "
MUTANTS = [
    ("reuse account 0 for the second wallet", [(A, ".map_or(0, |a| a.saturating_add(1))", ".map_or(0, |_| 0)")], SDK + "one_index_per_wallet"),
    ("gap 20 -> 0", [(R, "let (mut scanned, mut until) = (0usize, req.gap);", "let (mut scanned, mut until) = (0usize, 0);")], SDK + "restore_gap_scan"),
    ("the scan not extended past a found index", [(R, ".max(i.saturating_add(1).saturating_add(req.gap))", ".max(i.saturating_add(1))")], SDK + "restore_gap_scan"),
    ("drop the seed id from the row", [(A, "        id: id.into(),\n        seed: seed.into(),\n", "        id: id.into(),\n        seed: String::new(),\n")], SDK + "add_ua_row_names_its_seed"),
    ("every read to the first endpoint", [(R, ".get(reads % pools.len().max(1))", ".first()")], SDK + "restore_reads_spread_over_the_list"),
    ("an EIP-2333 kind at index 1 (scaas-ua's rule)", [(U, "let eip = |root: u32| {\n        if index == 0 {", "let eip = |root: u32| {\n        if index < 2 {")], SDK + "eip2333_kinds_index_0_only"),
    ("a watch row signs", [(A, "Ok(!matches!(row, AccountRow::Watch { .. }))", "Ok(!matches!(row, AccountRow::Key { .. }))")], SDK + "watch_row_signs_nothing"),
    ("no delegation mark", [(R, "i.delegated = code.len() == 23 && code.starts_with(&[0xef, 0x01, 0x00]);", "i.delegated = code.len() == 22;")], SDK + "delegated_eoa_marked"),
]

if __name__ == "__main__":
    main("t9", MUTANTS)
