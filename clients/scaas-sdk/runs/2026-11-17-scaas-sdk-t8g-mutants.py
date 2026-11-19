# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T8g mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t8g-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/ua-rs/src/wallet/entries/mod.rs"
K = "clients/ua-rs/src/wallet/entries/router.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test entries "
MUTANTS = [
    ("swap two arguments of mtxSetFeeSplit", [(K, "uint32 relayerSharePpm,address treasury,bytes32 chainUid", "address treasury,uint32 relayerSharePpm,bytes32 chainUid")], UA + "entries_router"),
    ("a wrong selector on mtxMintToUA", [(K, '"UAMintToUA", "mtxMintToUA",', '"UAMintToUA", "mtxMintUA",')], UA + "entries_router"),
    ("drop the unsigned config of mtxCreateToken", [(K, '"E target kind version init!config:TokenConfig salt @"', '"E target kind version salt @"')], UA + "entries_router"),
    ("a creation's initHash not filled from its config", [(M, '        msg.insert("initHash".into(), h);\n', '')], UA + "entries_router"),
    ("a release approval given a job op", [(M, "let op = if r.node {", "let op = if !r.entry.is_empty() {")], UA + "entries_router"),
    ("the approval's release words flat", [(K, '"E target (contractClass,kind,version,envVersion,initSelector,interfaceId,initcodeHash,implArgsHash,chainUid,factory,adminGeneration,until) @"', '""')], UA + "entries_router"),
]

if __name__ == "__main__":
    main("t8g", MUTANTS)
