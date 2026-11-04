#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# mldsa87: the closing gates of branch mldsa87 at one commit (kind 0x0134, spec 2026-11-04-mldsa87, plan of the same date). Not a copy:
# it sets the step list, log prefix, its own steps and test names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract,
# commands, resume and summary).
#   2026-11-04-mldsa87-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-11-04-mldsa87-<s>.log (git-ignored); the `summary` step writes the committed -summary.txt.
# First line "# <s> at commit <sha>", last line "rc=<n>". A step is skipped when its log ends rc=0 at the current commit and the tree is clean.
# A fresh worktree needs the git-ignored inputs as real directories: smartcontracts/evm/lib, clients/clientkeys/node_modules; the
# nethermind step needs pqz-core/nethermind/ref, bin/corpus.jsonl, bin/test-hooks and pqz-core/ffi/target/release/libpqz_ffi.so
# (pqz-core/nethermind/README.md "Build and test").
# Not here: the scaas-node suite (6 GB alone, the coordinator runs it); node-kinds builds the node and runs the kind tests only.
P=2026-11-04-mldsa87
LOGEXT=log # step logs are git-ignored (*.log); only <P>-summary.txt is committed (owner 2026-11-02)
STEPS="forge-n2304-kmax4096 atset-n2048-kmax1024 atset-n2560-kmax16384 atset-n2816-kmax65536 forge-isolate sizes docs vectors-check clientkeys ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt cargo-zether-prover soroban-registry near-common node-kinds nethermind named-tests summary"
FAMILIES="ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt soroban-registry near-common node-kinds nethermind"

extra_step() { # this branch's own steps (the base runner calls it for a step it does not know)
  case $1 in
    # controller 2026-11-04: the full forge suite at the default set (forge-n2304-kmax4096); at the other three sets only the
    # paths the kind touches (it reaches PQZ through the registry's holder rules only); at-set.sh restores PqzSet.sol
    atset-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#atset-}" test --match-path 'test/{ua,pqz}/*' ;;
    soroban-registry) CARGO_BUILD_JOBS=2 scripts/capped sh -c 'cd smartcontracts/soroban && cargo test -j2 -p scaas-ua-registry' ;;
    near-common) CARGO_BUILD_JOBS=2 scripts/capped sh -c 'cd smartcontracts/near && cargo test -j2 -p scaas-near-common' ;;
    node-kinds) cd scaas-node && ../scripts/capped sh -c 'cargo build -j2 && cargo test -j2 --lib chain_kind' ;;
    nethermind) # in the pinned SDK image (OpenSSL 3.5: the host's 3.0 has no ML-DSA); run-tests.sh writes runs/<date>-test.txt
      local o=pqz-core/nethermind/runs/$(date +%F)-test.txt t
      scripts/capped pqz-core/nethermind/run-tests.sh > /dev/null
      t=$(cat "$o" 2>/dev/null); rm -f "$o"; echo "$t"
      grep -qx 'rc=0' <<< "$t" ;; # the test command's own rc, printed inside the container
    *) echo "unknown step $1"; return 2 ;;
  esac
}

# "<step>|<form>|<name>": the tests this branch adds (forms: see the base runner)
NEW_TESTS=$(cat <<'NAMES'
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
