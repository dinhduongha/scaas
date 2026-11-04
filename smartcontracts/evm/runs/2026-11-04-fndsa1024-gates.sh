#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# fndsa1024: the closing gates of kind 0x0135 on branch mldsa87 at one commit (spec 2026-11-04-fndsa1024, plan of the same date).
# A sibling of 2026-11-04-mldsa87-gates.sh: the same steps without nethermind (owner Q5: no Nethermind change); it sets the step
# list, log prefix, its own steps and test names, then runs 2026-10-27-metatx-split-gates.sh (step contract, commands, resume, summary).
#   2026-11-04-fndsa1024-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-11-04-fndsa1024-<s>.log (git-ignored); the `summary` step writes the committed -summary.txt.
# First line "# <s> at commit <sha>", last line "rc=<n>". A step is skipped when its log ends rc=0 at the current commit and the tree is clean.
# A fresh worktree needs the git-ignored inputs as real directories: smartcontracts/evm/lib, clients/clientkeys/node_modules.
# Not here: the scaas-node suite (6 GB alone, the coordinator runs it); node-kinds builds the node and runs the kind tests only.
P=2026-11-04-fndsa1024
LOGEXT=log # step logs are git-ignored (*.log); only <P>-summary.txt is committed (owner 2026-11-02)
STEPS="forge-n2304-kmax4096 atset-n2048-kmax1024 atset-n2560-kmax16384 atset-n2816-kmax65536 forge-isolate sizes docs vectors-check clientkeys ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt cargo-zether-prover soroban-registry near-common node-kinds named-tests summary"
FAMILIES="ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt soroban-registry near-common node-kinds"

extra_step() { # this kind's own steps (the base runner calls it for a step it does not know)
  case $1 in
    # owner 2026-11-04: Falcon-1024 runs as ML-DSA-87 did: the full forge suite at the default set (forge-n2304-kmax4096), at the
    # other three sets only the paths the kind touches (it reaches PQZ through the registry's holder rules); at-set.sh restores PqzSet.sol
    atset-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#atset-}" test --match-path 'test/{ua,pqz}/*' ;;
    soroban-registry) CARGO_BUILD_JOBS=2 scripts/capped sh -c 'cd smartcontracts/soroban && cargo test -j2 -p scaas-ua-registry' ;;
    near-common) CARGO_BUILD_JOBS=2 scripts/capped sh -c 'cd smartcontracts/near && cargo test -j2 -p scaas-near-common' ;;
    node-kinds) cd scaas-node && ../scripts/capped sh -c 'cargo build -j2 && cargo test -j2 --lib chain_kind' ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

# "<step>|<form>|<name>": the tests this kind adds (forms: see the base runner); filled in as the tasks land
NEW_TESTS=$(cat <<'NAMES'
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
