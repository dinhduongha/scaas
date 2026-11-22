#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plan T42 (CLI-SDK-33 (31)): the SDK's release size with and without its EVM part (`account`, `wallet`: alloy's providers,
# network and rpc-types, `scaas-ua/fam-evm`), native and wasm32. The SDK is a library, so the figure is the sum of the release
# rlibs its build links (every artifact cargo reports for the build, the SDK's own included). From the worktree root:
#   bash clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t42-evm-size.sh [native|wasm32]…   (each build through scripts/capped)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/clients/scaas-sdk"
CAP=${CAP-../../scripts/capped}
sum() { # $1 target args, $2 features: the bytes of the rlibs the build reports
    $CAP cargo build --locked -q --release --lib $1 --no-default-features --features "$2" --message-format=json |
        python3 -c 'import json,os,sys
seen=set()
for l in sys.stdin:
    m=json.loads(l)
    for f in m.get("filenames") or []:
        if f.endswith(".rlib"): seen.add(f)
print(sum(os.path.getsize(f) for f in seen))'
}
(($#)) || set -- native wasm32
for t in "$@"; do
    a=""
    [[ $t == wasm32 ]] && a="--target wasm32-unknown-unknown"
    without=$(sum "$a" "vault,file-store")
    with=$(sum "$a" "vault,account,wallet,file-store")
    echo "$t | without EVM $without | with EVM $with | $((with - without)) | $(((with - without) * 100 / with)) %"
done
