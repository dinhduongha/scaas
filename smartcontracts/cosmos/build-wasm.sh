#!/bin/sh
# Build the five contracts for wasmd into artifacts/. Rust >= 1.87 emits bulk-memory/sign-ext/
# nontrapping-fptoint which wasmvm 3 rejects ("bulk memory support is not enabled"): binaryen lowers them
# back to MVP and the result is validated with MVP features only. Needs `wasm-opt` (binaryen) in PATH.
set -e
cd "$(dirname "$0")"
# cosmwasm-std 3.0.10 declares its host imports without `wasm_import_module = "env"`, and newer rustc no longer
# passes --allow-undefined to rust-lld: without this flag the link fails on every import (`undefined symbol`).
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=--allow-undefined"
mkdir -p artifacts
for c in token mandate dex relayfee relayexec; do
  cargo build -j2 --release --lib --target wasm32-unknown-unknown -p "scaas-$c"
  wasm-opt -Os --enable-bulk-memory --enable-sign-ext --enable-mutable-globals --enable-nontrapping-float-to-int \
    --enable-reference-types --enable-multivalue \
    --llvm-memory-copy-fill-lowering --signext-lowering --llvm-nontrapping-fptoint-lowering \
    --strip-target-features --strip-debug \
    "target/wasm32-unknown-unknown/release/scaas_$c.wasm" -o "artifacts/scaas_$c.wasm"
  wasm-opt --mvp-features --enable-mutable-globals "artifacts/scaas_$c.wasm" -o /dev/null
done
# --allow-undefined turns ANY missing symbol into an import: fail unless every import is a cosmwasm-std 3.0.10 host
# function in `env` (src/exports/imports.rs). `cosmwasm-check` when installed, else this stdlib parser.
if command -v cosmwasm-check >/dev/null; then
  cosmwasm-check artifacts/*.wasm
else
  python3 -I - artifacts/*.wasm <<'EOF'
import sys
ALLOWED = set("""abort db_read db_write db_remove db_scan db_next db_next_key db_next_value addr_validate addr_canonicalize
addr_humanize bls12_381_aggregate_g1 bls12_381_aggregate_g2 bls12_381_pairing_equality bls12_381_hash_to_g1
bls12_381_hash_to_g2 secp256k1_verify secp256k1_recover_pubkey secp256r1_verify secp256r1_recover_pubkey
ed25519_verify ed25519_batch_verify debug query_chain""".split())
def leb(b, i):
    n = s = 0
    while True:
        x = b[i]; i += 1; n |= (x & 0x7f) << s; s += 7
        if x < 0x80: return n, i
def name(b, i):
    n, i = leb(b, i); return b[i:i + n].decode(), i + n
bad = []
for path in sys.argv[1:]:
    b = open(path, "rb").read()
    assert b[:4] == b"\0asm", path
    i = 8
    while i < len(b):
        sid = b[i]; size, i = leb(b, i + 1); end = i + size
        if sid == 2:
            count, i = leb(b, i)
            for _ in range(count):
                mod, i = name(b, i); field, i = name(b, i); kind = b[i]; i += 1
                if kind != 0 or mod != "env" or field not in ALLOWED:
                    bad.append(f"{path}: import {mod}.{field} (kind {kind})")
                if kind == 0: _, i = leb(b, i)
                elif kind == 1: i += 1; f = b[i]; _, i = leb(b, i + 1); i = leb(b, i)[1] if f & 1 else i
                elif kind == 2: f = b[i]; _, i = leb(b, i + 1); i = leb(b, i)[1] if f & 1 else i
                elif kind == 3: i += 2
        i = end
if bad:
    sys.exit("unexpected wasm imports (a missing symbol?):\n" + "\n".join(bad))
print(f"imports ok: {len(sys.argv) - 1} contracts, only cosmwasm-std env host functions")
EOF
fi
sha256sum artifacts/*.wasm
