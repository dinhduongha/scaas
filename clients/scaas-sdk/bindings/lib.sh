#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Builds the reference library (clients/scaas-sdk/ffi) with one UniFFI surface and copies it to ffi/target/lib-<surface>/, the
# path every UniFFI binding's generator and smoke test reads (plan T20b-T20h; spec §16.1):
#   bindings/lib.sh uniffi      the async API (Python, Kotlin, Swift, and C#, Java, Go where their generator carries async)
#   bindings/lib.sh sync-api    the sync surface (C++, and C#, Java, Go where it does not)
# One target directory for both: cargo keeps each feature set's artifacts apart, the copy keeps the two libraries apart. Through
# scripts/capped, in the foreground (on CI, which sets `CI`, directly).
set -euo pipefail
case "${1:-}" in uniffi | sync-api) ;; *) echo "usage: $0 uniffi|sync-api" >&2 && exit 2 ;; esac
W=$(git rev-parse --show-toplevel)
F="$W/clients/scaas-sdk/ffi"
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
(cd "$F" && "${cap[@]}" cargo build --locked ${J:--j2} --features "$1")
mkdir -p "$F/target/lib-$1"
cp "$F/target/debug/libscaas_sdk_ffi.so" "$F/target/lib-$1/"
echo "[lib] ok: ffi/target/lib-$1/libscaas_sdk_ffi.so"
