#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Regenerates every generated binding of scaas-sdk (plan T20, T20b-T20h; spec §16.1), from the worktree root:
#   clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh            regenerate in place
#   clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh --check    regenerate, fail if a generated file differs from HEAD's (the
#                                                                 drift test, as ua-c's header test), then put the working
#                                                                 tree's generated files back as they were
#   SCAAS_GEN=<part>[,<part>…] limits it to those parts (a CI job with one generator); default every part:
#   dart  the FRB Dart surface (flutter_rust_bridge_codegen 2.13.0, the pin of the ffi crate's flutter_rust_bridge):
#         bindings/dart/lib/src/rust/ (the freezed classes of the data-carrying enums by build_runner, which the codegen runs)
#         and ffi/src/frb_generated.rs, from ffi/src/api and the scaas-sdk crate itself (`rust_input`)
#   cpp   the sync C++ surface (uniffi-bindgen-cpp v0.10.0+v0.31.0) over the reference library with `sync-api`
#         (bindings/lib.sh): bindings/cpp/generated/ (compared as sorted lines: the generator's type order varies by run)
#   cs    the C# binding (uniffi-bindgen-cs v0.11.1+v0.31.0, its renames in bindings/cs/uniffi.toml) over the reference library
#         with the async API (`uniffi`): bindings/cs/generated/
#   python  the Python binding (official UniFFI's uniffi-bindgen 0.31.0) over the same library: bindings/python/generated/
#   kotlin  the Kotlin binding (the same generator, ktlint not run) over the same library: bindings/kotlin/generated/
#   swift   the Swift binding (the same generator, swiftformat not run) over the same library: bindings/swift/generated/
# A UniFFI generator is the pin when `cargo install` recorded that version in the root it runs from (locally
# `cargo install --locked --root <main checkout>/scratchpad/tools/uniffi`, on PATH). Each part's old output is removed first,
# so a file the surface no longer produces cannot stay behind. The codegen runs through scripts/capped, in the foreground (on
# CI, which sets `CI`, directly: the runner is the job's own machine; pub resolves offline locally only).
set -euo pipefail
W=$(git rev-parse --show-toplevel)
D="$W/clients/scaas-sdk"
PARTS=",${SCAAS_GEN:-dart,cpp,cs,python,kotlin,swift},"
GEN=()
if [[ $PARTS == *,dart,* ]]; then GEN+=(bindings/dart/lib/src/rust ffi/src/frb_generated.rs); fi
for p in cpp cs python kotlin swift; do
    if [[ $PARTS == *,$p,* ]]; then GEN+=("bindings/$p/generated"); fi
done
[ ${#GEN[@]} -gt 0 ] || { echo "[gen] FAIL no part in SCAAS_GEN=${SCAAS_GEN:-}" >&2 && exit 2; }
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
off=(--offline)
[ -n "${CI:-}" ] && off=()
pin() { # <tool> <version> [<package>]: the generator on PATH is the pin, as cargo install recorded its package in its root
    local t p=${3:-$1}
    t=$(command -v "$1") || { echo "[gen] FAIL $1 not on PATH (pin $2)" >&2 && exit 2; }
    cargo install --list --root "$(dirname "$(dirname "$t")")" | grep -qF -e "$p v$2 " -e "$p v$2:" ||
        { echo "[gen] FAIL $1 is not the pin $2" >&2 && exit 2; }
}
lib() { echo "$D/ffi/target/lib-$1/libscaas_sdk_ffi.so"; }
if [ "${1:-}" = --check ]; then
    # the check leaves the working tree as it found it: the generated files (committed or not) are copied first and put back
    # on exit; the regenerated ones are compared with HEAD, never with the index
    keep=$(mktemp -d)
    (cd "$D" && for g in "${GEN[@]}"; do [ ! -e "$g" ] || cp -a --parents "$g" "$keep/"; done)
    trap 'cd "$D" && rm -rf "${GEN[@]}" && cp -a "$keep/." "$D/" && rm -rf "$keep"' EXIT
fi
if [[ $PARTS == *,dart,* ]]; then
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
    echo "[gen] start: C# (uniffi)"
    pin uniffi-bindgen-cs "0.11.1+v0.31.0"
    bash "$D/bindings/lib.sh" uniffi >/dev/null
    rm -rf "$D/bindings/cs/generated"
    # the generator's own output: CSharpier is not run (it warns that it is not installed)
    out=$(cd "$D/ffi" && uniffi-bindgen-cs --library "$(lib uniffi)" --config "$D/bindings/cs/uniffi.toml" \
        --out-dir "$D/bindings/cs/generated" 2>&1) || { echo "$out" >&2 && exit 1; }
    echo "[gen] ok: C#"
fi
if [[ $PARTS == *,python,* ]]; then
    echo "[gen] start: Python (uniffi)"
    pin uniffi-bindgen "0.31.0" uniffi
    bash "$D/bindings/lib.sh" uniffi >/dev/null
    rm -rf "$D/bindings/python/generated"
    (cd "$D/ffi" && uniffi-bindgen generate --library "$(lib uniffi)" --language python \
        --out-dir "$D/bindings/python/generated" >/dev/null)
    echo "[gen] ok: Python"
fi
if [[ $PARTS == *,kotlin,* ]]; then
    echo "[gen] start: Kotlin (uniffi)"
    pin uniffi-bindgen "0.31.0" uniffi
    bash "$D/bindings/lib.sh" uniffi >/dev/null
    rm -rf "$D/bindings/kotlin/generated"
    (cd "$D/ffi" && uniffi-bindgen generate --library "$(lib uniffi)" --language kotlin --no-format \
        --out-dir "$D/bindings/kotlin/generated" >/dev/null)
    echo "[gen] ok: Kotlin"
fi
if [[ $PARTS == *,swift,* ]]; then
    echo "[gen] start: Swift (uniffi)"
    pin uniffi-bindgen "0.31.0" uniffi
    bash "$D/bindings/lib.sh" uniffi >/dev/null
    rm -rf "$D/bindings/swift/generated"
    (cd "$D/ffi" && uniffi-bindgen generate --library "$(lib uniffi)" --language swift --no-format \
        --out-dir "$D/bindings/swift/generated" >/dev/null)
    echo "[gen] ok: Swift"
fi
if [ "${1:-}" = --check ]; then
    cd "$D"
    if ! git diff --exit-code --stat HEAD -- "${GEN[@]}" || [ -n "$(git status --porcelain --untracked-files=all -- "${GEN[@]}" | grep '^??')" ]; then
        echo "[gen] FAIL a generated file differs from the committed one (run this script without --check and commit)" >&2
        exit 1
    fi
    echo "[gen] ok: no drift"
fi
