#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# scaas-sdk plan T20e: the Kotlin binding's smoke test (gate `bind-kotlin`, CI job `scaas-sdk-kotlin`), from this directory:
# builds the reference library with the async API (../lib.sh uniffi), writes the keystore rows (../rows.py), compiles generated/
# and Smoke.kt with kotlinc (KOTLINC, else `kotlinc` on PATH; the pin 2.4.21) against the two pinned jars (JNA 5.12 or later:
# the generated code uses its Cleaner), and runs it on the JVM. The jars sit in git-ignored lib/: copied from the main
# checkout's scratchpad/tools/jars or the local Maven or Gradle cache, else fetched from Maven Central (CI); any file without
# the pinned sha256 is refused. Build output in git-ignored build/.
set -euo pipefail
cd "$(dirname "$0")"
W=$(git rev-parse --show-toplevel)
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
JARS=(
    "net/java/dev/jna/jna/5.17.0/jna-5.17.0.jar b3a9408e7c51e08ef0e3bfcc08f443f6ec0f6191ba8cd7c18d53d2b22e5bdbc0"
    "org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.10.2/kotlinx-coroutines-core-jvm-1.10.2.jar 5ca175b38df331fd64155b35cd8cae1251fa9ee369709b36d42e0a288ccce3fd"
)
mkdir -p lib build
cp=()
for j in "${JARS[@]}"; do
    read -r path sum <<<"$j"
    f=lib/${path##*/}
    if [ ! -f "$f" ]; then
        tools="$(cd "$(git rev-parse --git-common-dir)/.." && pwd)/scratchpad/tools/jars"
        local_copy=$(find "$tools" "$HOME/.m2/repository/${path%/*}" "$HOME/.gradle/caches/modules-2/files-2.1" -name "${path##*/}" \
            2>/dev/null | head -1 || true)
        if [ -n "$local_copy" ]; then cp "$local_copy" "$f"; else curl -fsSL -o "$f" "https://repo1.maven.org/maven2/$path"; fi
    fi
    echo "$sum  $f" | sha256sum -c --quiet - || { echo "[kotlin] FAIL $f is not the pinned jar" >&2 && rm -f "$f" && exit 1; }
    cp+=("$f")
done
CP=$(
    IFS=:
    echo "${cp[*]}"
)
bash ../lib.sh uniffi
python3 -I ../rows.py "$W/smartcontracts/vectors/keystore/keystore.json" build/rows.tsv
echo "[kotlin] start: kotlinc"
"${cap[@]}" "${KOTLINC:-kotlinc}" -nowarn -cp "$CP" -include-runtime -d build/smoke.jar \
    $(find generated -name '*.kt') Smoke.kt
echo "[kotlin] ok: kotlinc"
"${cap[@]}" java -Djna.library.path="$W/clients/scaas-sdk/ffi/target/lib-uniffi" -cp "build/smoke.jar:$CP" SmokeKt build/rows.tsv
