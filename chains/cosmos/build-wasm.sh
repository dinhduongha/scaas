#!/bin/sh
# Build the three contracts for wasmd into artifacts/. Rust >= 1.87 emits bulk-memory/sign-ext/
# nontrapping-fptoint which wasmvm 3 rejects ("bulk memory support is not enabled"): binaryen lowers them
# back to MVP and the result is validated with MVP features only. Needs `wasm-opt` (binaryen) in PATH.
set -e
cd "$(dirname "$0")"
mkdir -p artifacts
for c in token mandate dex; do
  cargo build --release --lib --target wasm32-unknown-unknown -p "bamboo-$c"
  wasm-opt -Os --enable-bulk-memory --enable-sign-ext --enable-mutable-globals --enable-nontrapping-float-to-int \
    --enable-reference-types --enable-multivalue \
    --llvm-memory-copy-fill-lowering --signext-lowering --llvm-nontrapping-fptoint-lowering \
    --strip-target-features --strip-debug \
    "target/wasm32-unknown-unknown/release/bamboo_$c.wasm" -o "artifacts/bamboo_$c.wasm"
  wasm-opt --mvp-features --enable-mutable-globals "artifacts/bamboo_$c.wasm" -o /dev/null
done
sha256sum artifacts/*.wasm
