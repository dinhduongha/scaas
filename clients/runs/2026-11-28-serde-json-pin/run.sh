#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# CLI-UAL-67: differ.rs built against serde_json =1.0.145 and =1.0.154, each without and with preserve_order, in a temp dir;
# prints each output's sha256 and whether 1.0.154's equals 1.0.145's, as written and with `e+` read as `e`.
# Usage (from the repository root): scripts/capped bash clients/runs/2026-11-28-serde-json-pin/run.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
for v in 145 154; do for po in no yes; do
    d="$T/v$v-$po"
    mkdir -p "$d/src"
    cp "$here/differ.rs" "$d/src/main.rs"
    feat=
    [ "$po" = yes ] && feat=', features = ["preserve_order"]'
    printf '[package]\nname = "sj%s%s"\nversion = "0.0.0"\nedition = "2021"\n[dependencies]\nserde_json = { version = "=1.0.%s"%s }\n[workspace]\n' "$v" "$po" "$v" "$feat" >"$d/Cargo.toml"
    echo "build 1.0.$v preserve_order=$po"
    cargo build --release -q --manifest-path "$d/Cargo.toml" --target-dir "$T/target"
    "$T/target/release/sj$v$po" >"$T/$v-$po.out"
done; done
cd "$T"
sha256sum ./*.out
for po in no yes; do
    if cmp -s "145-$po.out" "154-$po.out"; then echo "preserve_order=$po: identical"; else
        echo "preserve_order=$po: differ; lines with e+: 1.0.145 $(grep -c 'e+' "145-$po.out" || true), 1.0.154 $(grep -c 'e+' "154-$po.out")"
        sed 's/e+/e/g' "154-$po.out" | cmp -s "145-$po.out" - && echo "preserve_order=$po: identical once e+ is read as e"
    fi
done
