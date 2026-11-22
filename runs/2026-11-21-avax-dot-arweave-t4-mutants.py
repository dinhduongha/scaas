# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T4 mutants (NET-EVM-18's deploy checks): python3 runs/2026-11-21-avax-dot-arweave-t4-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

F = "smartcontracts/evm/script/forkcheck.py"
T = "python3 -I smartcontracts/evm/script/test_forkcheck.py "
MUTANTS = [
    (
        "the scan as a deny-list without CLZ",
        [(F, "        if op not in allowed:", "        if op in (AMSTERDAM - allowed) - {CLZ}:")],
        T + "scan_clz_refused_for_cancun",
        "FAIL scan_clz_refused_for_cancun",
    ),
    (
        "immediates not skipped",
        [(F, "        i += 1 + immediate(op)", "        i += 1")],
        T + "push_data_1e_passes",
        "FAIL push_data_1e_passes",
    ),
    (
        "the control's result ignored",
        [(F, "    if not red:", "    if False:")],
        T + "control_green_voids_the_run",
        "FAIL control_green_voids_the_run",
    ),
    (
        "check (5) skipped",
        [(F, "(5) {check_precompiles(nodes, entries)} precompiles", "(5) {len(entries)} precompiles")],
        T + "deploy_gate_runs_every_check",
        "FAIL deploy_gate_runs_every_check",
    ),
    (
        "the size check against 65,536",
        [(F, '    if rt > profile["codeSizeLimit"]:', "    if rt > 65536:")],
        T + "sizes_against_the_profile",
        "FAIL sizes_against_the_profile",
    ),
]

if __name__ == "__main__":
    main("t4", MUTANTS)
