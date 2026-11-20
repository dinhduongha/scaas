#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Regenerates every generated binding of scaas-sdk (plan T20, T20b-T20h; spec §16.1), from the worktree root:
#   clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh            regenerate in place
#   clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh --check    regenerate, then fail if a generated file differs from the
#                                                                 committed one (the drift test, as ua-c's header test)
#   SCAAS_GEN=<part>[,<part>…] limits it to those parts (a CI job with one generator); default every part:
#   dart  the FRB Dart surface (flutter_rust_bridge_codegen 2.13.0, the pin of the ffi crate's flutter_rust_bridge):
#         bindings/dart/lib/src/rust/ (the freezed classes of the data-carrying enums by build_runner, which the codegen runs)
#         and ffi/src/frb_generated.rs, from ffi/src/api and the scaas-sdk crate itself (`rust_input`)
#   cpp   the sync C++ surface (uniffi-bindgen-cpp v0.10.0+v0.31.0) over the reference library with `sync-api`
#         (bindings/lib.sh): bindings/cpp/generated/ (compared as sorted lines: the generator's type order varies by run)
#   cs    the C# binding (uniffi-bindgen-cs v0.11.1+v0.31.0, its renames in bindings/cs/uniffi.toml) over the reference library
#         with the async API (`uniffi`): bindings/cs/generated/
# A UniFFI generator is the pin when `cargo install` recorded that version in the root it runs from (locally
# `cargo install --locked --root <main checkout>/scratchpad/tools/uniffi`, on PATH). Each part's old output is removed first,
# so a file the surface no longer produces cannot stay behind. The codegen runs through scripts/capped, in the foreground (on
# CI, which sets `CI`, directly: the runner is the job's own machine; pub resolves offline locally only).
set -euo pipefail
W=$(git rev-parse --show-toplevel)
D="$W/clients/scaas-sdk"
PARTS=",${SCAAS_GEN:-dart,cpp,cs},"
GEN=()
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
off=(--offline)
[ -n "${CI:-}" ] && off=()
pin() { # <tool> <version>: the generator on PATH is the pin, as cargo install recorded it in its root
    local t
    t=$(command -v "$1") || { echo "[gen] FAIL $1 not on PATH (pin $2)" >&2 && exit 2; }
    cargo install --list --root "$(dirname "$(dirname "$t")")" | grep -qF "$1 v$2 " ||
        { echo "[gen] FAIL $1 is not the pin $2" >&2 && exit 2; }
}
lib() { echo "$D/ffi/target/lib-$1/libscaas_sdk_ffi.so"; }
if [[ $PARTS == *,dart,* ]]; then
    GEN+=(bindings/dart/lib/src/rust ffi/src/frb_generated.rs)
    want=2.13.0
    have=$(flutter_rust_bridge_codegen --version | awk '{print $2}')
    if [ "$have" != "$want" ]; then
        echo "[gen] FAIL flutter_rust_bridge_codegen $have, the pin is $want" >&2
        exit 2
    fi
    echo "[gen] start: FRB Dart"
    (cd "$D/bindings/dart" && "${cap[@]}" dart pub get "${off[@]}" --enforce-lockfile >/dev/null &&
        rm -rf lib/src/rust && "${cap[@]}" flutter_rust_bridge_codegen generate >/dev/null)
    echo "[gen] ok: FRB Dart"
fi
if [[ $PARTS == *,cpp,* ]]; then
    GEN+=(bindings/cpp/generated)
    echo "[gen] start: C++ (sync-api)"
    pin uniffi-bindgen-cpp "0.10.0+v0.31.0"
    bash "$D/bindings/lib.sh" sync-api >/dev/null
    rm -rf "$D/bindings/cpp/generated"
    # the generator reads `cargo metadata` of the library's crate
    (cd "$D/ffi" && uniffi-bindgen-cpp --library "$(lib sync-api)" --out-dir "$D/bindings/cpp/generated" >/dev/null)
    # the generator orders type definitions by a hash map's walk: the same lines in another order between runs. A file with
    # the committed file's lines in another order keeps the committed one (an order the compiler took); any other change shows.
    for f in "$D"/bindings/cpp/generated/*; do
        c=clients/scaas-sdk/bindings/cpp/generated/${f##*/}
        if git -C "$W" cat-file -e "HEAD:$c" 2>/dev/null &&
            cmp -s <(sort "$f") <(git -C "$W" show "HEAD:$c" | sort); then
            git -C "$W" show "HEAD:$c" >"$f"
        fi
    done
    echo "[gen] ok: C++"
fi
if [[ $PARTS == *,cs,* ]]; then
    GEN+=(bindings/cs/generated)
    echo "[gen] start: C# (uniffi)"
    pin uniffi-bindgen-cs "0.11.1+v0.31.0"
    bash "$D/bindings/lib.sh" uniffi >/dev/null
    rm -rf "$D/bindings/cs/generated"
    # the generator's own output: CSharpier is not run (it warns that it is not installed)
    out=$(cd "$D/ffi" && uniffi-bindgen-cs --library "$(lib uniffi)" --config "$D/bindings/cs/uniffi.toml" \
        --out-dir "$D/bindings/cs/generated" 2>&1) || { echo "$out" >&2 && exit 1; }
    echo "[gen] ok: C#"
fi
[ ${#GEN[@]} -gt 0 ] || { echo "[gen] FAIL no part in SCAAS_GEN=${SCAAS_GEN:-}" >&2 && exit 2; }
if [ "${1:-}" = --check ]; then
    cd "$D"
    if ! git diff --exit-code --stat -- "${GEN[@]}" || [ -n "$(git status --porcelain -- "${GEN[@]}")" ]; then
        echo "[gen] FAIL a generated file differs from the committed one (run this script without --check and commit)" >&2
        exit 1
    fi
    echo "[gen] ok: no drift"
fi
