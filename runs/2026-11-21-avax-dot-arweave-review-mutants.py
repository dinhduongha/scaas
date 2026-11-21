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
U = "smartcontracts/evm/chain-uids.json"
B = "smartcontracts/evm/script/DeployBase.sol"
TB = "python3 -I smartcontracts/evm/script/test_deploybook.py"
FG = "cd smartcontracts/evm && ../../scripts/capped forge test --match-path "
GOV = FG + "test/governance/DeployBook.t.sol --match-test "
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
    (
        "P1-2 UARegistry off homeChainKinds",
        [(U, '    "PqVault",\n    "UARegistry"\n', '    "PqVault"\n')],
        TB,
        "home_chain_kinds_refused",
    ),
    (
        "P1-2 the gen-1 registry not gated",
        [(B, '        _requireKindHere("UARegistry", uid); // NET-ALL-25: UAMsigUpdate', "        // NET-ALL-25: UAMsigUpdate")],
        GOV + "test_registryRefusedOnSharedGenesis",
        "test_registryRefusedOnSharedGenesis",
    ),
    (
        "P1-2 a later registry generation not gated",
        [(B, '        _requireKindHere("UARegistry", uid); // NET-ALL-25, as', "        // NET-ALL-25, as")],
        GOV + "test_registryRefusedOnSharedGenesis",
        "test_registryRefusedOnSharedGenesis",
    ),
    (
        "P2-1 cast mktx without --chain",
        [(D, '"--gas-limit", str(tx["gas"]), "--chain", str(tx["chainId"])]', '"--gas-limit", str(tx["gas"])]')],
        TD + "cast_signs_what_was_asked",
        "FAIL cast_signs_what_was_asked",
    ),
    (
        "P2-1 the signed bytes not compared",
        [(D, "        if bad:\n", "        if False:\n")],
        TD + "cast_signs_what_was_asked",
        "FAIL cast_signs_what_was_asked",
    ),
    (
        "P2-1 the chain id from the first node",
        [(D, '    cid = _read(nodes, "eth_chainId", [], f.qty)\n    if chain_id', '    cid = f.qty(nodes[0]("eth_chainId", [])["result"])\n    if chain_id')],
        TD + "the_transaction_from_the_majority",
        "FAIL the_transaction_from_the_majority",
    ),
    (
        "P2-1 the chain id not the resolved one",
        [(D, "    if chain_id is not None and cid != chain_id:", "    if False:")],
        TD + "the_transaction_from_the_majority",
        "FAIL the_transaction_from_the_majority",
    ),
    (
        "P2-1 the nonce from the first node",
        [(D, '    nonce = _read(nodes, "eth_getTransactionCount", [sign.address(), "latest"], f.qty)',
          '    nonce = f.qty(nodes[0]("eth_getTransactionCount", [sign.address(), "latest"])["result"])')],
        TD + "the_transaction_from_the_majority",
        "FAIL the_transaction_from_the_majority",
    ),
    (
        "P2-1 the fee cap from the highest node",
        [(D, '    cap = FEE_FACTOR * _number(nodes, "eth_gasPrice", [])',
          '    cap = FEE_FACTOR * max(f.qty(n("eth_gasPrice", [])["result"]) for n in nodes)')],
        TD + "the_transaction_from_the_majority",
        "FAIL the_transaction_from_the_majority",
    ),
    (
        "P2-1 a tip above the cap signed",
        [(D, "    if tip > cap:", "    if False:")],
        TD + "the_transaction_from_the_majority",
        "FAIL the_transaction_from_the_majority",
    ),
]

if __name__ == "__main__":
    main("review", MUTANTS)
