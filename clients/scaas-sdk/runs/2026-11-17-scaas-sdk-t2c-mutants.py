# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T2c mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t2c-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/vault/store.rs"
M = "clients/scaas-sdk/src/vault/mod.rs"
K = "clients/scaas-sdk/src/vault/keystore.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --no-default-features --features vault,file-store --lib "
MUTANTS = [
    ("write in place instead of temp + rename", [(S, "let mut f = io(open_new(&tmp))?;", "let mut f = io(File::create(p))?;"),
                                                 (S, "io(std::fs::rename(&tmp, p))?;", "")],
     T + "filestore_writes_atomically"),
    ("skip the rev check", [(S, "if now != prev_rev {", "if false {")], T + "filestore_writes_atomically"),
    ("drop keystore.prev", [(M, "self.put(PREV, prev_rev, old.bytes.clone()).await?;", "let _ = prev_rev;")], T + "keystore_prev_kept"),
    ("drop the depth scan", [(K, "if bytes.len() > MAX_BYTES || scaas_ua::json::depth_within(bytes, MAX_DEPTH).is_err() {",
                              "if bytes.len() > MAX_BYTES {")], T + "depth_is_scanned_before_parsing"),
]

if __name__ == "__main__":
    main("t2c", MUTANTS)
