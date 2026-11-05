#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T0 cross-builds (ua-rs-sign): compile only (an rlib: nothing links, nothing runs, no timing) of the spike crate per target and
# cell. Cells: `full` (default: scaas-ua `pq` with the PQClean Falcon C build), `no-pq` (--no-default-features: pure Rust) and
# `no-pq-check` (the same as `cargo check`: no linker, so the cdylib crates pqz-ffi / zether-prover need no NDK or Xcode).
# Each cargo run goes through scripts/capped, foreground. Logs: clients/ua-rs/target/t0-xbuild/<target>-<cell>.log (git-ignored).
# Usage: xbuild.sh <target>... ; prints "target | cell | rc | first error".
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
logs="$here/../../target/t0-xbuild"; mkdir -p "$logs"
export CARGO_TARGET_DIR="$here/../../target/t0-spike"
for t in "$@"; do
  for cell in full no-pq no-pq-check; do
    cmd=build; args=(); [[ $cell == no-pq* ]] && args=(--no-default-features); [[ $cell == *-check ]] && cmd=check
    log="$logs/$t-$cell.log"
    (cd "$here/spike" && "$root/scripts/capped" cargo "$cmd" --locked -j2 --target "$t" "${args[@]}") > "$log" 2>&1
    rc=$?
    err=$(grep -m1 -E '^error|error:|warning: .*(failed|error)' "$log" | cut -c1-160 | sed "s#$root/##g; s#$HOME#~#g")
    echo "$t | $cell | $rc | ${err:--}"
  done
done
