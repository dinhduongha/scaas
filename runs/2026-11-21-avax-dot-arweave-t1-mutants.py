# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T1 mutants (NET-ALL-25: the pair, the private genesis, the homeChain kinds), in each of the three places that hold the
rule (script/deploybook.py, script/DeployBook.sol, the node's config check):
python3 runs/2026-11-21-avax-dot-arweave-t1-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "smartcontracts/evm/script/deploybook.py"
S = "smartcontracts/evm/script/DeployBook.sol"
N = "scaas-node/src/config.rs"
TP = "python3 -I smartcontracts/evm/script/test_deploybook.py"
TS = "cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/governance/DeployBook.t.sol --match-test "
TN = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j2 --lib chain_pair_and_private_genesis_at_start"
NT = "config::tests::chain_pair_and_private_genesis_at_start"
MUTANTS = [
    (
        "py: the pair compared by chainUid only",
        [(P, '        pair = (r["chainId"], r["chainUid"].lower())', '        pair = r["chainUid"].lower()')],
        TP,
        # the committed table itself: Ethereum and ETC share a genesis (the first read of the test file)
        "CHAIN_PAIR_TAKEN: etc-mainnet repeats the (chainId, chainUid) pair of ethereum-mainnet",
    ),
    (
        "py: the private-genesis check dropped",
        [(P, '        if r["private"] and r["chainUid"].lower() == uid:', "        if False:")],
        TP,
        "FAIL private_genesis_refused",
    ),
    (
        "py: the homeChain kind refusal dropped",
        [(P, '    if kind in t["homeChainKinds"]:', "    if False:")],
        TP,
        "FAIL home_chain_kinds_refused",
    ),
    (
        "sol: the pair compared by chainUid only",
        [(S, 'if (sameUid && vm.parseJsonUint(j, string.concat(p, ".chainId")) == block.chainid) {', "if (sameUid) {")],
        TS + "test_avalancheRowsResolve",
        "test_avalancheRowsResolve",
    ),
    (
        "sol: the private-genesis check dropped",
        [(S, 'if (sameUid && vm.parseJsonBool(j, string.concat(p, ".private"))) priv = k;', "")],
        TS + "test_privateGenesisRefused",
        "test_privateGenesisRefused",
    ),
    (
        "sol: the homeChain kind refusal dropped",
        [(S, "        if (!home) return;", "        if (!home || true) return;")],
        TS + "test_homeChainKindsRefused",
        "test_homeChainKindsRefused",
    ),
    (
        "node: the pair compared by chain_uid only",
        [(N, "pairs.insert((c.evm_chain_number, uid), key.clone())", "pairs.insert((0, uid), key.clone())")],
        TN,
        NT,
    ),
    (
        "node: the private-genesis check dropped",
        [(N, "*u == uid && *id != c.evm_chain_number)", "*u == uid && *id != c.evm_chain_number && false)")],
        TN,
        NT,
    ),
]

if __name__ == "__main__":
    main("t1", MUTANTS)
