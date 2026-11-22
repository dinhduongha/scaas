#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# pqchat-core plan T12, the bindings check (gate `bind`, after the SDK's own drift check), from the worktree root:
#   bash clients/pqchat-core/runs/2026-11-17-pqchat-core-bind.sh
# The SDK's generator (flutter_rust_bridge_codegen 2.13.0, the pin of the SDK's script) runs over the reference library
# clients/pqchat-core/ffi with `pqchat-core` linked (`rust_input: crate::api,pqchat-core`); its output is written at check
# time only (git-ignored, removed on exit) and read: no handle type of the SDK (`AppKey`) and no byte accessor of a secret
# (`SecretBytes`) in the generated surface; `attach_matrix`, `detach_matrix`, the storage interface, the chain port and the
# Matrix transport absent; decrypted content and `sealedInfo` plaintext only as the SDK's `SecretBytes` handle, whose bytes
# move through the SDK's C copy calls (owner 2026-11-22: runs/bind_surface.py holds every type carrying them to its members);
# then the library is built, exports the three copy calls, and neither its exported symbols nor its enabled features hold a
# vectors-build entry (K30). Heavy steps through scripts/capped, in the foreground. The first failure by name, as a TAP
# `not ok` line; rc 1.
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
fail() { # a TAP line, as the mutant runner reads a failure
    echo "not ok - $1"
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
# every type holding a decrypted content or `sealedInfo` plaintext, member by member (owner 2026-11-22, "Handle SecretBytes")
python3 -I "$W/clients/pqchat-core/runs/bind_surface.py" "$F/dart/lib/src/rust" || fail "a decrypted content not only as the handle"
# the handle's id for the copy calls in the surface (the calls themselves are the library's C exports, checked below)
grep -rqE "BigInt secretId\(\{required ArcSecretBytes s\}\)" "$F/dart/lib/src/rust" || fail "no secretId of the handle in the surface"
echo "[bind] ok: no handle, no secret bytes, no Rust-only item, decrypted content only through the SDK's copy calls"
if grep -rlE "vectors_|_vectors" "${G[@]}"; then fail "a test-only entry (feature vectors) generated"; fi
mkdir -p "$F/target"
(cd "$F" && "$cap" cargo build --offline -j2 >"$F/target/bind-build.log" 2>&1) || fail "the library build (ffi/target/bind-build.log)"
lib="$F/target/debug/libpqchat_core_ffi.so"
[ -f "$lib" ] || fail "no library"
exports=$(nm -D --defined-only "$lib")
syms=$(grep -c frbgen_ <<<"$exports")
[ "$syms" -gt 0 ] || fail "no generated symbol exported (positive control)"
if grep -iE "vector" <<<"$exports"; then fail "a vectors-build symbol exported"; fi
for c in scaas_sdk_secret_write scaas_sdk_secret_read scaas_sdk_secret_dispose; do
    grep -qw "$c" <<<"$exports" || fail "the SDK's copy call $c not exported"
done
feats=$(cd "$F" && "$cap" cargo tree --offline -e features -f '{p} {f}' 2>/dev/null)
# (here-strings: `grep -q` stops reading early, and a pipe's writer would then fail the pipeline)
grep -qE "scaas-sdk .*app-core" <<<"$feats" || fail "the features not read (positive control)"
if grep -E "(scaas-sdk|scaas-ua|pqchat-core) .*\bvectors\b" <<<"$feats"; then fail "a vectors feature enabled"; fi
echo "[bind] ok: $syms generated symbols, the three copy calls exported, no vectors entry in the symbols or features"
