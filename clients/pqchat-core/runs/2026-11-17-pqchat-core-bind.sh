#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# pqchat-core plan T12, the bindings check (gate `bind`, after the SDK's own drift check), from the worktree root:
#   bash clients/pqchat-core/runs/2026-11-17-pqchat-core-bind.sh
# The SDK's generator (flutter_rust_bridge_codegen 2.13.0, the pin of the SDK's script) runs over the reference library
# clients/pqchat-core/ffi with `pqchat-core` linked (`rust_input: crate::api,pqchat-core`); its output is written at check
# time only (git-ignored, removed on exit) and read: no handle type of the SDK (`AppKey`) and no byte accessor of a secret
# (`SecretBytes`) in the generated surface; `attach_matrix`, `detach_matrix`, the storage interface, the chain port and the
# Matrix transport absent; decrypted content only as the SDK's opaque `SecretBytes`, whose bytes move through the SDK's two
# C copy calls; then the library is built and neither its exported symbols nor its enabled features hold a vectors-build
# entry (K30). Heavy steps through scripts/capped, in the foreground. The first failure by name; rc 1.
set -uo pipefail
W=$(git rev-parse --show-toplevel)
F="$W/clients/pqchat-core/ffi"
cap="$W/scripts/capped"
want=2.13.0
have=$(flutter_rust_bridge_codegen --version | awk '{print $2}')
[ "$have" = "$want" ] || {
    echo "[bind] FAIL flutter_rust_bridge_codegen $have, the pin is $want" >&2
    exit 2
}
cleanup() { rm -rf "$F/dart/lib/src/rust" "$F/src/frb_generated.rs"; }
trap cleanup EXIT
fail() {
    echo "[bind] FAIL $1" >&2
    exit 1
}
echo "[bind] start: FRB over pqchat-core"
(cd "$F/dart" && "$cap" dart pub get --offline --enforce-lockfile >/dev/null &&
    rm -rf lib/src/rust && "$cap" flutter_rust_bridge_codegen generate >/dev/null) || fail "the generator"
G=("$F/dart/lib/src/rust" "$F/src/frb_generated.rs")
[ -s "$F/src/frb_generated.rs" ] || fail "no glue generated"
n=$(grep -rhoE "class [A-Za-z]+" "$F/dart/lib/src/rust" | sort -u | wc -l)
echo "[bind] ok: generated, $n Dart classes"
# the surface holds the crate's object
grep -rqE "class PqChat\b|abstract class PqChat\b" "$F/dart/lib/src/rust" || fail "PqChat not in the surface (positive control)"
# no handle type of the SDK; no byte accessor of a secret
if grep -rlE "\bAppKey\b" "${G[@]}"; then fail "a key handle (AppKey) in the generated surface"; fi
if grep -rnE "SecretBytes[^\n]*(Uint8List|List<int>)|(Uint8List|List<int>)[^\n]*SecretBytes" "$F/dart/lib/src/rust"; then
    fail "a byte accessor of SecretBytes"
fi
# Rust-only: the Matrix client, the storage interface, the chain port
for x in attachMatrix detachMatrix attach_matrix detach_matrix PqChatStore MemoryStore MatrixTransport SdkNet withNet with_net; do
    # (the generator's own comment listing the items it ignored is not the surface)
    if grep -rnw "$x" "${G[@]}" | grep -vE '^[^:]+:[0-9]+:\s*//'; then fail "$x in the generated surface"; fi
done
# decrypted content only as the SDK's `SecretBytes` through its copy calls: no call of the surface carries a content's
# value (its text) through the codec, and no record holds a secret type other than the SDK's handle
for x in pqchat_core__content__Content_value pqchat_core__content__Content_parse; do
    if grep -q "wire__${x}_impl" "$F/src/frb_generated.rs"; then
        fail "decrypted content through the codec (${x#pqchat_core__content__})"
    fi
done
if grep -q "RustAutoOpaqueInner<SecretBytes>" "$F/src/frb_generated.rs"; then
    fail "decrypted content as an opaque of the surface, not the SDK's SecretBytes handle with its copy calls"
fi
echo "[bind] ok: no handle, no secret bytes, no Rust-only item, decrypted content only through the SDK's copy calls"
if grep -rlE "vectors_|_vectors" "${G[@]}"; then fail "a test-only entry (feature vectors) generated"; fi
(cd "$F" && "$cap" cargo build --offline -j2 >/dev/null 2>&1) || fail "the library build"
lib="$F/target/debug/libpqchat_core_ffi.so"
[ -f "$lib" ] || fail "no library"
syms=$(nm -D --defined-only "$lib" | grep -c frbgen_)
[ "$syms" -gt 0 ] || fail "no generated symbol exported (positive control)"
if nm -D --defined-only "$lib" | grep -iE "vector"; then fail "a vectors-build symbol exported"; fi
feats=$(cd "$F" && "$cap" cargo tree --offline -e features -f '{p} {f}' 2>/dev/null)
echo "$feats" | grep -qE "^.*scaas-sdk .*app-core" || fail "the features not read (positive control)"
if echo "$feats" | grep -E "(scaas-sdk|scaas-ua|pqchat-core) .*\bvectors\b"; then fail "a vectors feature enabled"; fi
echo "[bind] ok: $syms generated symbols, no vectors entry in the symbols or features"
