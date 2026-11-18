# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T24 (the fixes of the families' review) mutants, one set per fix:
FIX=<k> python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t24-mutants.py check | run [name…]
writes 2026-11-17-scaas-rpc-t24-<k>-mutants.txt (every mutant of fix T24.<k>; names start with "<k>:")."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "scaas-node/src/adapters/"
EVM = A + "evm.rs"
NT = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j1 --lib adapters::"
MUTANTS = [
    # T24.1 (P1): no later endpoint's text reaches a classifier; the abort is endpoint 0's typed answer
    ("1: the all-failed error carries the endpoints' text",
     [(EVM, 'anyhow::anyhow!("{what}: no endpoint answered ({}); a failover endpoint\'s answer decides nothing", e.code())',
       'anyhow::anyhow!("{what}: no endpoint answered ({e}); a failover endpoint\'s answer decides nothing")')],
     NT + "aptos::tests::aptos_a_later_endpoints_forged_abort_never_kills_the_job"),
    ("1: the abort read from the error's text",
     [(A + "aptos.rs", "Err(e) if e.downcast_ref::<ViewRefused>().is_some_and(ViewRefused::is_abort) =>",
       'Err(e) if format!("{e:#}").contains("Move abort") =>')],
     NT + "aptos::tests::aptos_the_abort_is_read_from_endpoint_0s_typed_answer"),
]

if __name__ == "__main__":
    fix = os.environ.get("FIX")
    main(f"t24-{fix}" if fix else "t24", [m for m in MUTANTS if not fix or m[0].startswith(f"{fix}:")])
