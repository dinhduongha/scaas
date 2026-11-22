# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk: the profile's `pinned_reads` (owner 2026-11-22, decisions ARCH-POS-20 (2)) mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-pinned-mutants.py check | run [name]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

L = "clients/scaas-sdk/src/lib.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 "
MUTANTS = [
    (
        "the profile's pinned_reads never reaches the pool",
        [(L, "\n                            .with_pinned_reads(p.pinned_reads),", ",")],
        T + "--test evm_profiles pinned_reads_follow_the_profile",
    ),
    (
        "pinned_reads false accepted on a non-EVM profile",
        [(L, "            if !p.pinned_reads && p.family != Family::Evm {", "            if false {")],
        T + "--test evm_feature an_evm_profile_needs_the_evm_feature",
    ),
]

if __name__ == "__main__":
    main("pinned", MUTANTS)
