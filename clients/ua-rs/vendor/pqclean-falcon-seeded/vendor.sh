#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Re-creates the PQClean files of this directory (ua-rs-sign T3b, MD-8) from the crates.io archives the crate used before:
# pqcrypto-falcon 0.4.1 (PQClean `falcon-padded-512/clean`, `falcon-padded-1024/clean`, MIT, Falcon Project) and
# pqcrypto-internals 0.2.11 (PQClean `common/fips202.{c,h}`, public domain), each checked against its Cargo.lock sha256.
# Every file is copied as shipped but for one mechanical rename, so this build links beside another PQClean copy (a
# dependent's pqcrypto-falcon) without a duplicate symbol:
#   PQCLEAN_FALCONPADDED512_CLEAN_  -> SCAAS_UA_FNDSA512_
#   PQCLEAN_FALCONPADDED1024_CLEAN_ -> SCAAS_UA_FNDSA1024_
#   shake128* shake256* sha3_256* sha3_384* sha3_512* (fips202's API) -> scaas_ua_shake128* ...
# `pqclean.c` (the NIST API wrapper, which draws its randomness through `randombytes`) is not taken: `seeded.c` is that
# wrapper with the randomness passed in (the 48-byte keygen seed; the 40-byte nonce and 48-byte sampler seed of a
# signature). Run from this directory: `sh vendor.sh`; a re-run leaves `git status` clean.
set -eu
FALCON_SHA=01a0e72acca23e8bc9886f26396adbc1a2c71fc0b841723415ee245cdc5b395c
INTERNALS_SHA=b4a326caf27cbf2ac291ca7fd56300497ba9e76a8cc6a7d95b7a18b57f22b61d
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch() { # name version sha256
    f="$tmp/$1-$2.crate"
    c=$(ls "${CARGO_HOME:-$HOME/.cargo}"/registry/cache/*/"$1-$2.crate" 2>/dev/null | head -n 1 || true)
    if [ -n "$c" ]; then cp "$c" "$f"; else curl -sSfL -o "$f" "https://static.crates.io/crates/$1/$1-$2.crate"; fi
    echo "$3  $f" | sha256sum -c --quiet
    tar -xzf "$f" -C "$tmp"
}
fetch pqcrypto-falcon 0.4.1 "$FALCON_SHA"
fetch pqcrypto-internals 0.2.11 "$INTERNALS_SHA"

rename() {
    sed -e 's/PQCLEAN_FALCONPADDED512_CLEAN_/SCAAS_UA_FNDSA512_/g' \
        -e 's/PQCLEAN_FALCONPADDED1024_CLEAN_/SCAAS_UA_FNDSA1024_/g' \
        -e 's/\b\(shake128\|shake256\|sha3_256\|sha3_384\|sha3_512\)/scaas_ua_\1/g' "$1" > "$2"
}
for n in 512 1024; do
    src="$tmp/pqcrypto-falcon-0.4.1/pqclean/crypto_sign/falcon-padded-$n/clean"
    mkdir -p "falcon-padded-$n"
    for f in api.h inner.h fpr.h codec.c common.c fft.c fpr.c keygen.c rng.c sign.c vrfy.c; do
        rename "$src/$f" "falcon-padded-$n/$f"
    done
done
cp "$tmp/pqcrypto-falcon-0.4.1/pqclean/crypto_sign/falcon-padded-512/clean/LICENSE" LICENSE
rename "$tmp/pqcrypto-internals-0.2.11/cfiles/fips202.c" fips202.c
rename "$tmp/pqcrypto-internals-0.2.11/include/fips202.h" fips202.h
