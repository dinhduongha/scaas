#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# scaas-sdk plan T20e2: the Java binding's smoke test (gate `bind-java`, CI cell `scaas-sdk-bindings` [java]), from this directory: builds
# the reference library with the async API (../lib.sh uniffi), writes the keystore rows (../rows.py), compiles generated/ and
# Smoke.java with the JDK of JAVA_HOME (else `javac` / `java` on PATH; 22 or later: the generated code is Java's FFM API, the
# pin 25) and runs it with native access. No jar beyond the JDK. Build output in git-ignored build/.
set -euo pipefail
cd "$(dirname "$0")"
W=$(git rev-parse --show-toplevel)
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
bin=${JAVA_HOME:+$JAVA_HOME/bin/}
LIB="$W/clients/scaas-sdk/ffi/target/lib-uniffi"
bash ../lib.sh uniffi
rm -rf build && mkdir -p build
python3 -I ../rows.py "$W/smartcontracts/vectors/keystore/keystore.json" build/rows.tsv
find generated -name '*.java' >build/sources
printf 'CopyCall.java\nSmoke.java\n' >>build/sources
echo "[java] start: javac"
"${cap[@]}" "${bin}javac" -nowarn -d build/classes @build/sources
echo "[java] ok: javac"
"${cap[@]}" "${bin}java" --enable-native-access=ALL-UNNAMED -Djava.library.path="$LIB" \
    -Dscaas.lib="$LIB/libscaas_sdk_ffi.so" -cp build/classes Smoke build/rows.tsv
