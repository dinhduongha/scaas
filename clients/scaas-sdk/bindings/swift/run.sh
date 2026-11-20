#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# scaas-sdk plan T20f: the Swift binding's smoke test on Linux (gate `bind-swift`, CI job `scaas-sdk-swift`), from this
# directory: builds the reference library with the async API (../lib.sh uniffi), compiles generated/ (both crates' Swift and
# their C module maps) with main.swift by swiftc (SWIFTC, else `swiftc` on PATH; the pin 6.4.2, Swift 5 language mode as the
# generated code is written for it), links the library and runs it over the keystore rows (../rows.py). Build output in
# git-ignored build/.
set -euo pipefail
cd "$(dirname "$0")"
W=$(git rev-parse --show-toplevel)
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
LIB="$W/clients/scaas-sdk/ffi/target/lib-uniffi"
bash ../lib.sh uniffi
mkdir -p build
echo "[swift] start: swiftc"
"${cap[@]}" "${SWIFTC:-swiftc}" -swift-version 5 -suppress-warnings -I generated \
    -Xcc -fmodule-map-file=generated/scaas_sdkFFI.modulemap -Xcc -fmodule-map-file=generated/scaas_sdk_ffiFFI.modulemap \
    -L "$LIB" -lscaas_sdk_ffi -Xlinker -rpath -Xlinker "$LIB" -o build/smoke main.swift generated/*.swift
echo "[swift] ok: swiftc"
python3 -I ../rows.py "$W/smartcontracts/vectors/keystore/keystore.json" build/rows.tsv
"${cap[@]}" build/smoke build/rows.tsv
