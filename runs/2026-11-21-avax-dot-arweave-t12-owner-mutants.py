# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The owner's answers of 2026-11-22 to plan T12's questions (decisions ARCH-POS-20): the pinned-reads refusal (2) and Fuji's
disabled kinds (5): python3 runs/2026-11-21-avax-dot-arweave-t12-owner-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

E = "clients/scaas-rpc/src/evm.rs"
F = "smartcontracts/evm/src/chains/avalanche-testnet/profile.json"
TR = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test evm_profiles "
TS = (
    "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features "
    "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records "
    "--test evm_profiles a_disabled_kind_is_refused_before_signing"
)
MUTANTS = [
    (
        "rpc: the pinned-reads refusal dropped",
        [(E, "        if !self.pinned_reads {", "        if false && !self.pinned_reads {")],
        TR + "a_pinned_read_is_refused_where_pinned_reads_are_not_trusted",
        "a_pinned_read_is_refused_where_pinned_reads_are_not_trusted",
    ),
    (
        "profile: Fuji's disabled kinds dropped",
        [(F, '"disabledKinds": [\n    "mldsa44",\n    "mldsa65",\n    "mldsa87",\n    "pqz"\n  ]', '"disabledKinds": []')],
        TS,
        "a_disabled_kind_is_refused_before_signing",
    ),
]

if __name__ == "__main__":
    main("t12-owner", MUTANTS)
