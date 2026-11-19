# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T20 (bindings) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t20-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "clients/scaas-sdk/ffi/src/api/mod.rs"
L = "clients/scaas-sdk/bindings/dart/lib/scaas_sdk.dart"
# the source changed, its generated files not: the drift check is red; the regenerated files are put back after
GEN = ("bash clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh --check; rc=$?; "
       "git checkout -- clients/scaas-sdk/bindings/dart/lib/src/rust clients/scaas-sdk/ffi/src/frb_generated.rs; exit $rc")
DART = "cd clients/scaas-sdk/bindings/dart && bash ./run.sh"
MUTANTS = [
    ("a stale generated file", [(A, "/// This library's feature bits (spec §3.3).", "/// This library's feature bits (spec §3.3); a stale binding.")], GEN),
    ("a binding without its load check", [(L, "if (apiVersion() != expectApi) throw", "if (apiVersion() != expectApi && false) throw")], DART),
]

if __name__ == "__main__":
    main("t20", MUTANTS)
