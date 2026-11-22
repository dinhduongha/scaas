#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plan T42 (CLI-SDK-33 (31)): ua-rs built with no family, each fam-<row> alone and all on (`wallet` always, no zether / pqz), in
# release; prints `build | bytes | delta to none` of the size probe examples/fam_size.rs. From clients/ua-rs:
#   bash runs/fam-sizes.sh [build…]   (builds: none, fam-<row>, all; default every one; each cargo build through
#   ../../scripts/capped, CAP='' runs it bare, as CI does)
set -euo pipefail
cd "$(dirname "$0")/.."
CAP=${CAP-../../scripts/capped}
FAMS=(fam-evm fam-hedera fam-near fam-algorand fam-cosmos fam-aptos fam-solana fam-soroban fam-sui fam-ton fam-dot fam-btc fam-arweave)
all=$(
    IFS=,
    echo "${FAMS[*]}"
)
size() {
    $CAP cargo build --locked -q --release --example fam_size --no-default-features --features "wallet$1" >&2
    stat -c %s target/release/examples/fam_size
}
none=$(size "")
echo "none | $none | 0"
want=("$@")
((${#want[@]})) || want=("${FAMS[@]}" all)
for f in "${want[@]}"; do
    [[ $f == none ]] && continue
    [[ $f == all ]] && s=$(size ",$all") || s=$(size ",$f")
    echo "$f | $s | $((s - none))"
done
