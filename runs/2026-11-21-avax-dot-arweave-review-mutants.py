# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutants of the fixes after Fable's review of the contract part (scratchpad report 20261121-fable-contract-review, one row
per new check, named by its finding): python3 runs/2026-11-21-avax-dot-arweave-review-mutants.py check | run [name…]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

F = "smartcontracts/evm/script/forkcheck.py"
D = "smartcontracts/evm/script/deploy_pqchatstore.py"
T = "python3 -I smartcontracts/evm/script/test_forkcheck.py "
TD = "python3 -I smartcontracts/evm/script/test_deploy_pqchatstore.py "
FUJI = "smartcontracts/evm/src/chains/avalanche-testnet/profile.json"
MUTANTS = [
    (
        "P1-1 a key without a profile defaults to amsterdam",
        [(F, "        if NO_PROFILE_AMSTERDAM.fullmatch(key):", "        if True:")],
        T + "profile_and_set_gate",
        "FAIL profile_and_set_gate",
    ),
    (
        "P1-1 any local- key amsterdam without a profile",
        [(F, 're.compile(r"scaas-testnet|local(-[a-z0-9-]+)?-testnet")', 're.compile(r"scaas-testnet|local-[a-z0-9-]+")')],
        T + "profile_and_set_gate",
        "FAIL profile_and_set_gate",
    ),
    (
        "P1-1 txGasCap not checked in the profile",
        [(F, "    if cap is not None and (not isinstance(cap, int)", "    if False and (not isinstance(cap, int)")],
        T + "profile_and_set_gate",
        "FAIL profile_and_set_gate",
    ),
    (
        "P1-1 the profile's txGasCap ignored by check (2)",
        [(F, "    if tx_cap is not None and gas_limit > tx_cap:", "    if False:")],
        T + "gas_against_the_live_caps",
        "FAIL gas_against_the_live_caps",
    ),
    (
        "P1-1 deploy_gate drops the profile's txGasCap",
        [(F, 'tx_cap=pr.get("txGasCap")', "tx_cap=None")],
        T + "deploy_gate_runs_every_check",
        "FAIL deploy_gate_runs_every_check",
    ),
    (
        "P1-1 the Fuji profile at amsterdam",
        [(FUJI, '"evmFork": "cancun"', '"evmFork": "amsterdam"')],
        TD + "fuji_dry_run_needs_a_profile",
        "FAIL fuji_dry_run_needs_a_profile",
    ),
    (
        "P2-2 the vote on the whole answer",
        [(F, "        keys.append(json.dumps(v, sort_keys=True))", '        keys.append(json.dumps(a["result"], sort_keys=True))')],
        T + "majority_on_the_used_fields",
        "FAIL majority_on_the_used_fields",
    ),
    (
        "P2-2 a number: the highest answer",
        [(F, "    return sorted(got, reverse=True)[len(nodes) // 2]", "    return max(got)")],
        T + "majority_on_the_used_fields",
        "FAIL majority_on_the_used_fields",
    ),
    (
        "P2-2 a malformed answer counted as a vote",
        [(F, '        if k != "malformed" and 2 * keys.count(k) > len(keys):', "        if 2 * keys.count(k) > len(keys):")],
        T + "majority_on_the_used_fields",
        "FAIL majority_on_the_used_fields",
    ),
    (
        "P2-2 the block read at latest",
        [(F, '"eth_getBlockByNumber", [hex(n), False], lambda r:', '"eth_getBlockByNumber", ["latest", False], lambda r:')],
        T + "majority_on_the_used_fields",
        "FAIL majority_on_the_used_fields",
    ),
    (
        "P2-2 a receipt field outside consensus voted on",
        [(D, '        "gasUsed": f.qty(r["gasUsed"]),', '        "gasUsed": r.get("size"),')],
        TD + "three_honest_nodes_agree",
        "FAIL three_honest_nodes_agree",
    ),
]

if __name__ == "__main__":
    main("review", MUTANTS)
