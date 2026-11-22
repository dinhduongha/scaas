# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T2, T11 and T12 mutants: the identity check and the not-final label in scaas-rpc (T2), the probe runner's fixes (T12):
python3 runs/2026-11-21-avax-dot-arweave-t2-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

E = "clients/scaas-rpc/src/evm.rs"
R = "clients/scaas-rpc/runs/2026-11-22-evm-probes.py"
TR = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test evm_profiles "
TP = "python3 -I clients/scaas-rpc/runs/test_evm_probes.py "
MUTANTS = [
    (
        "rpc: the identity check on the chain id only",
        [(E, "            Ok(Some(b)) => Ok(b.header.hash == want),", "            Ok(Some(_)) => Ok(true),")],
        TR + "each_profile_drops_an_endpoint_of_the_other_chain",
        "each_profile_drops_an_endpoint_of_the_other_chain",
    ),
    (
        "rpc: the not-final label dropped",
        [(E, "            is_final: fin.is_some_and(|f| to <= f),", "            is_final: fin.is_some() || true,")],
        TR + "a_log_read_above_finalized_is_not_final_and_gas_is_the_receipts",
        "a_log_read_above_finalized_is_not_final_and_gas_is_the_receipts",
    ),
    (
        "runner: --summary keeps no row of another checkout",
        [(R, "        rows += [r for r in kept if", "        rows += [r for r in [] if")],
        TP + "logs_and_summary",
        "not ok logs_and_summary",
    ),
    (
        "runner: --summary keeps a stale row of a key logged here",
        [(R, 'r and " | ".join(r.split(" | ", 2)[:2]) + " |" not in have]', "r]")],
        TP + "logs_and_summary",
        "not ok logs_and_summary",
    ),
    (
        "runner: caps asks eth_call from a named sender",
        [(R, '[{"to": ZERO, "gas": hex(gas)}, "latest"]', '[{"from": ZERO, "to": ZERO, "gas": hex(gas)}, "latest"]')],
        TP + "caps_and_pq_fit",
        "not ok caps_and_pq_fit",
    ),
    (
        "runner: a gateway's 'not served' read as the method",
        [(R, "|not supported|not served|", "|not supported|")],
        TP + "l1_fee_model",
        "not ok l1_fee_model",
    ),
]

if __name__ == "__main__":
    main("t2", MUTANTS)
