# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The pqchat-core plan's mutant runner: the scaas-sdk plan's `mutants_lib` with this plan's record directory and prefix.
A task's file: `from pqc_mutants import main; main("t<n>", MUTANTS)`, modes `check` and `run [name…]`."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scaas-sdk" / "runs"))
import mutants_lib as L  # noqa: E402

R = "clients/pqchat-core/runs"
L.OUT = Path(__file__).parent
L.PREFIX = "2026-11-17-pqchat-core-"
L.RUNS = R
L.NOT_CODE = [f":!{R}/*-mutants.txt", f":!{R}/2026-11-17-pqchat-core-summary.txt",
              ":!clients/scaas-sdk/runs/*-mutants.txt", ":!clients/scaas-sdk/runs/2026-11-17-scaas-sdk-summary.txt"]
main = L.main
