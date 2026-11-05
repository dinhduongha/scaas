#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T0 Q1 (ua-rs-sign): does PQClean's crypto_sign_keypair, its randombytes() fed the 48-byte seed xi, give the same Falcon
# key pair as @noble/post-quantum 0.7.1's keygen(xi) (clientkeys)? PQClean sources: pqcrypto-falcon 0.4.1 from the local cargo
# registry. Binaries in clients/ua-rs/target/t0-q1 (git-ignored). Usage: q1.sh [extra seeds, default 16]. Exit 0 iff all equal.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../../target/t0-q1"; mkdir -p "$out"
pqc=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/pqcrypto-falcon-0.4.1 | head -1)/pqclean
# variant dir | PQClean symbol prefix | pk bytes | sk bytes | kind
variants=(
  "falcon-512/clean PQCLEAN_FALCON512_CLEAN 897 1281 fndsa512"
  "falcon-512/avx2 PQCLEAN_FALCON512_AVX2 897 1281 fndsa512"
  "falcon-padded-512/clean PQCLEAN_FALCONPADDED512_CLEAN 897 1281 fndsa512"
  "falcon-1024/clean PQCLEAN_FALCON1024_CLEAN 1793 2305 fndsa1024"
  "falcon-1024/avx2 PQCLEAN_FALCON1024_AVX2 1793 2305 fndsa1024"
  "falcon-padded-1024/clean PQCLEAN_FALCONPADDED1024_CLEAN 1793 2305 fndsa1024"
)
for v in "${variants[@]}"; do
  read -r dir sym pkb skb _ <<<"$v"
  flags=(); [[ $dir == */avx2 ]] && flags=(-mavx2 -mbmi2 -mpopcnt)
  cc -O2 "${flags[@]}" -I"$pqc/common" -I"$pqc/crypto_sign/$dir" -DKEYPAIR="${sym}_crypto_sign_keypair" -DPKB="$pkb" -DSKB="$skb" \
    "$here/falcon_seeded.c" "$pqc"/crypto_sign/"$dir"/*.c "$pqc/common/fips202.c" -o "$out/${dir//\//-}"
done
node "$here/noble_keys.mjs" "${1:-16}" > "$out/noble.jsonl"
fail=0; total=0
while IFS= read -r row; do
  kind=$(jq -r .kind <<<"$row"); src=$(jq -r .source <<<"$row"); xi=$(jq -r .xi <<<"$row")
  npk=$(jq -r .pk <<<"$row"); nsk=$(jq -r .sk <<<"$row")
  for v in "${variants[@]}"; do
    read -r dir _ _ _ vk <<<"$v"; [[ $vk == "$kind" ]] || continue
    read -r ppk psk < <("$out/${dir//\//-}" "$xi")
    total=$((total + 1))
    if [[ $ppk == "$npk" && $psk == "$nsk" ]]; then r=equal; else r=DIFFER; fail=$((fail + 1)); fi
    echo "$kind | $src | $dir | pk ${ppk:0:16}… | $r"
  done
done < "$out/noble.jsonl"
echo "q1: $total comparisons, $fail differ"
# Negative control: the comparison must be able to fail. Each kind's pq_kat seed with its last byte flipped must differ.
neg=0
while IFS= read -r row; do
  [[ $(jq -r .source <<<"$row") == pq_kat ]] || continue
  kind=$(jq -r .kind <<<"$row"); xi=$(jq -r .xi <<<"$row"); npk=$(jq -r .pk <<<"$row")
  bad=${xi:0:94}$(printf '%02x' $(( 0x${xi:94:2} ^ 1 )))
  bin=falcon-512-clean; [[ $kind == fndsa1024 ]] && bin=falcon-1024-clean
  read -r ppk _ < <("$out/$bin" "$bad")
  if [[ $ppk != "$npk" ]]; then echo "$kind | negative control (xi last byte ^ 1) | differs as expected"; else echo "$kind | negative control | EQUAL: harness cannot fail"; neg=1; fi
done < "$out/noble.jsonl"
[[ $fail == 0 && $neg == 0 ]]
