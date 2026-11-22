#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# scaas-sdk plan T20h: the Go binding's smoke test (gate `bind-go`, CI cell `scaas-sdk-bindings` [go]), from this directory: builds the
# reference library with the async API (../lib.sh uniffi), then `go vet` of the hand-written packages and `go test` of smoke/
# with cgo linked to that library (the generated packages under generated/, module `scaas`). Through scripts/capped, in the
# foreground (on CI, which sets `CI`, directly).
set -euo pipefail
cd "$(dirname "$0")"
W=$(git rev-parse --show-toplevel)
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
LIB="$W/clients/scaas-sdk/ffi/target/lib-uniffi"
bash ../lib.sh uniffi
export CGO_ENABLED=1 CGO_LDFLAGS="-L$LIB -lscaas_sdk_ffi -Wl,-rpath,$LIB"
go vet ./copycall ./smoke
"${cap[@]}" go test -count=1 ./smoke
