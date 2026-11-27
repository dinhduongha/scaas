# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM, R2-D-6 of the T4-T9 re-check: clientkeys' replay keeps the info in force across a resume; the mutant puts
back the read of the last epoch row (through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py).
python3 runs/2026-11-27-pqchat-treekem-js-resume-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

J = "clients/clientkeys/src/treekem.js"
JS = "cd clients/clientkeys && ../../scripts/capped node --test --test-name-pattern R2-D-6 test/treekem.test.js"
MUTANTS = [
    ("the info in force from the last epoch row (R2-D-6)",
     [(J, "  let inForce = from ? from.inForce : null;", "  let inForce = from ? (from.epochs.at(-1)?.inForce ?? null) : null;")],
     JS, "R2-D-6"),
]

if __name__ == "__main__":
    main("js-resume", MUTANTS, prefix="2026-11-27-pqchat-treekem")
