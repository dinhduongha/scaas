#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Regenerates every generated binding of scaas-sdk (plan T20; spec §16.1), from the worktree root:
#   clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh            regenerate in place
#   clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh --check    regenerate, fail if a generated file differs from HEAD's (the
#                                                                 drift test, as ua-c's header test), then put the working
#                                                                 tree's generated files back as they were
# Today the one generated binding is the FRB Dart surface (flutter_rust_bridge_codegen 2.13.0, the pin of the ffi crate's
# flutter_rust_bridge): bindings/dart/lib/src/rust/ (the freezed classes of the data-carrying enums by build_runner, which the
# codegen runs) and ffi/src/frb_generated.rs, from ffi/src/api and the scaas-sdk crate itself (`rust_input`). The old Dart
# output is removed first, so a file the surface no longer produces cannot stay behind. The UniFFI targets (T20b-T20h) add
# their generators here. The codegen runs through scripts/capped, in the foreground (on CI, which sets `CI`, directly: the
# runner is the job's own machine; pub resolves offline locally only).
set -euo pipefail
W=$(git rev-parse --show-toplevel)
D="$W/clients/scaas-sdk"
GEN=(bindings/dart/lib/src/rust ffi/src/frb_generated.rs)
want=2.13.0
have=$(flutter_rust_bridge_codegen --version | awk '{print $2}')
if [ "$have" != "$want" ]; then
    echo "[gen] FAIL flutter_rust_bridge_codegen $have, the pin is $want" >&2
    exit 2
fi
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
off=(--offline)
[ -n "${CI:-}" ] && off=()
if [ "${1:-}" = --check ]; then
    # the check leaves the working tree as it found it: the generated files (committed or not) are copied first and put back
    # on exit; the regenerated ones are compared with HEAD, never with the index
    keep=$(mktemp -d)
    (cd "$D" && cp -a --parents "${GEN[@]}" "$keep/")
    trap 'cd "$D" && rm -rf "${GEN[@]}" && cp -a "$keep/." "$D/" && rm -rf "$keep"' EXIT
fi
echo "[gen] start: FRB Dart"
(cd "$D/bindings/dart" && "${cap[@]}" dart pub get "${off[@]}" --enforce-lockfile >/dev/null &&
    rm -rf lib/src/rust && "${cap[@]}" flutter_rust_bridge_codegen generate >/dev/null)
echo "[gen] ok: FRB Dart"
if [ "${1:-}" = --check ]; then
    cd "$D"
    if ! git diff --exit-code --stat HEAD -- "${GEN[@]}" || [ -n "$(git status --porcelain --untracked-files=all -- "${GEN[@]}" | grep '^??')" ]; then
        echo "[gen] FAIL a generated file differs from the committed one (run this script without --check and commit)" >&2
        exit 1
    fi
    echo "[gen] ok: no drift"
fi
