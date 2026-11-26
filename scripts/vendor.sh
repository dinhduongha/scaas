#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# vendor/: the third-party sources the repository builds, git-ignored, each fetched as an exact published package and
# checked against its pins (owner 2026-11-26, ARCH-POS-24; vendor/README.md).
#   scripts/vendor.sh install [group...]   fetch every package of the groups (default core) whose directory is missing or
#                                          fails its check; the archive's sha256 is checked before it is unpacked
#   scripts/vendor.sh check [group...]     each installed directory against its pinned git tree id; exit 1 on a mismatch
#                                          or a missing directory
# The pin of a directory is its git tree id (`git write-tree` over every file under it, ignore rules off): what `git
# rev-parse <commit>:<dir>` names for a committed tree, so a pin reproduces from the package alone.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
V="$root/vendor"

# group | directory | kind | package | version | sha256 of the archive | git tree id of the directory
PINS='
core|falcon-rs-0.3.1|crate|falcon-rs|0.3.1|97afa6b3e692aa0c332b883f18e3f999e99df06331ac93196b60805950b0f65f|315fb462132276c5cdf64dca2ee094f9652c5f85
core|pqclean-falcon-seeded|pqclean|-|-|-|ae0932f272cdf58f2eefa9188b121e86abf32547
'
# falcon-rs-0.3.1 as the Fable audit read it (docs/audit/audited/vendor-falcon-rs.md): the package's tree plus the
# VENDORED.md of 5120ac3c5 (blob c0866a60), which then sat inside the directory
AUDIT_TREE=57a1aa39f980835a94100cf0b0d81bf8b221752e
AUDIT_VENDORED_BLOB=c0866a60d826f57b50928e65231c55b57d47910e
# pqclean-falcon-seeded is built from two crates (their Cargo.lock sha256 when ua-rs used them; vendor/README.md)
PQC_FALCON_SHA=01a0e72acca23e8bc9886f26396adbc1a2c71fc0b841723415ee245cdc5b395c
PQC_INTERNALS_SHA=b4a326caf27cbf2ac291ca7fd56300497ba9e76a8cc6a7d95b7a18b57f22b61d

say() { echo "vendor: $*"; }
die() {
    echo "vendor: $*" >&2
    exit 1
}

# git tree id of every file under $1, as git would store it (no ignore rules, no global attributes); with $2, the tree
# that also holds the blob $2 as VENDORED.md (the object itself not needed)
treeid() {
    g=$(mktemp -d)
    git init -q --bare "$g"
    GIT_INDEX_FILE="$g/index" git -c core.autocrlf=false -c core.attributesFile=/dev/null -c core.excludesFile=/dev/null \
        --git-dir="$g" --work-tree="$1" add -A -f . &&
        if [ -n "${2:-}" ]; then
            GIT_INDEX_FILE="$g/index" git --git-dir="$g" update-index --add --cacheinfo "100644,$2,VENDORED.md"
        fi &&
        GIT_INDEX_FILE="$g/index" git --git-dir="$g" write-tree --missing-ok
    rm -rf "$g"
}

sha256() { # GNU coreutils, else macOS (the ua-rs-targets cell)
    if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

# crate name version sha256 dest-dir: the .crate from the cargo cache, else crates.io; sha256 checked, unpacked into dest
crate() {
    f="$4/$1-$2.crate"
    c=$(ls "${CARGO_HOME:-$HOME/.cargo}"/registry/cache/*/"$1-$2.crate" 2>/dev/null | head -n 1 || true)
    if [ -n "$c" ]; then
        say "$1 $2: from the cargo cache"
        cp "$c" "$f"
    else
        say "$1 $2: from static.crates.io"
        curl -sSfL -o "$f" "https://static.crates.io/crates/$1/$1-$2.crate" || die "CRATE_FETCH_FAILED: $1 $2"
    fi
    got=$(sha256 "$f")
    [ "$got" = "$3" ] || die "CRATE_SHA256_MISMATCH: $1 $2: $got, pin $3"
    tar -xzf "$f" -C "$4"
    rm -f "$f"
}

# PQClean Falcon-padded-512 / -1024 (clean, MIT) from pqcrypto-falcon 0.4.1 and common/fips202.{c,h} (public domain) from
# pqcrypto-internals 0.2.11, copied as shipped but for one mechanical rename, so this build links beside another PQClean
# copy (a dependent's pqcrypto-falcon) without a duplicate symbol:
#   PQCLEAN_FALCONPADDED512_CLEAN_  -> SCAAS_UA_FNDSA512_
#   PQCLEAN_FALCONPADDED1024_CLEAN_ -> SCAAS_UA_FNDSA1024_
#   shake128* shake256* sha3_256* sha3_384* sha3_512* (fips202's API) -> scaas_ua_shake128* ...
# `pqclean.c` (the NIST API wrapper, which draws its randomness through `randombytes`) is not taken: ua-rs builds
# vendor/pqclean-falcon-seeded.local/seeded.c, that wrapper with the randomness passed in (ua-rs-sign T3b, MD-8).
pqclean() { # tmp out
    crate pqcrypto-falcon 0.4.1 "$PQC_FALCON_SHA" "$1"
    crate pqcrypto-internals 0.2.11 "$PQC_INTERNALS_SHA" "$1"
    for n in 512 1024; do
        src="$1/pqcrypto-falcon-0.4.1/pqclean/crypto_sign/falcon-padded-$n/clean"
        mkdir -p "$2/falcon-padded-$n"
        for f in api.h inner.h fpr.h codec.c common.c fft.c fpr.c keygen.c rng.c sign.c vrfy.c; do
            rename "$src/$f" "$2/falcon-padded-$n/$f"
        done
    done
    cp "$1/pqcrypto-falcon-0.4.1/pqclean/crypto_sign/falcon-padded-512/clean/LICENSE" "$2/LICENSE"
    rename "$1/pqcrypto-internals-0.2.11/cfiles/fips202.c" "$2/fips202.c"
    rename "$1/pqcrypto-internals-0.2.11/include/fips202.h" "$2/fips202.h"
}
rename() {
    sed -E -e 's/PQCLEAN_FALCONPADDED512_CLEAN_/SCAAS_UA_FNDSA512_/g' \
        -e 's/PQCLEAN_FALCONPADDED1024_CLEAN_/SCAAS_UA_FNDSA1024_/g' \
        -e 's/(^|[^[:alnum:]_])(shake128|shake256|sha3_256|sha3_384|sha3_512)/\1scaas_ua_\2/g' "$1" >"$2"
}

# check one row: 0 when the directory's tree equals the pin
check_one() { # dir tree
    [ -d "$V/$1" ] || {
        echo "vendor: $1 MISSING (scripts/vendor.sh install)" >&2
        return 1
    }
    got=$(treeid "$V/$1")
    if [ "$got" != "$2" ]; then
        echo "vendor: $1 MISMATCH: tree $got, pin $2" >&2
        return 1
    fi
    say "$1 OK (tree $got)"
    if [ "$1" = falcon-rs-0.3.1 ]; then
        a=$(treeid "$V/$1" "$AUDIT_VENDORED_BLOB")
        [ "$a" = "$AUDIT_TREE" ] || {
            echo "vendor: $1: with the audited VENDORED.md, tree $a, not the audit's $AUDIT_TREE" >&2
            return 1
        }
        say "$1 = the audited tree $AUDIT_TREE without its VENDORED.md (blob $AUDIT_VENDORED_BLOB)"
    fi
}

rows() { # groups... -> the PINS rows of those groups
    for grp in "$@"; do echo "$PINS" | grep "^$grp|"; done
}

cmd=${1:-}
[ $# -gt 0 ] && shift
[ $# -gt 0 ] || set -- core
for grp in "$@"; do
    echo "$PINS" | grep -q "^$grp|" || die "UNKNOWN_GROUP: $grp (core)"
done
t=
trap 'rm -rf "$t"' EXIT
case "$cmd" in
    install)
        for r in $(rows "$@"); do
            IFS='|' read -r _ dir kind pkg ver sha tree <<ROW
$r
ROW
            if [ -e "$V/$dir" ] || [ -L "$V/$dir" ]; then
                if check_one "$dir" "$tree" 2>/dev/null; then continue; fi
                [ -L "$V/$dir" ] && die "SYMLINK_FAILS_CHECK: vendor/$dir is a symlink whose tree is not the pin; remove it"
                say "$dir: not the pin, re-installing"
            fi
            t=$(mktemp -d)
            mkdir "$t/out"
            case "$kind" in
                crate)
                    crate "$pkg" "$ver" "$sha" "$t"
                    rm -f "$t/$pkg-$ver/.cargo-ok" "$t/$pkg-$ver/.cargo_vcs_info.json"
                    rmdir "$t/out"
                    mv "$t/$pkg-$ver" "$t/out"
                    ;;
                pqclean) pqclean "$t" "$t/out" ;;
                *) die "UNKNOWN_KIND: $kind" ;;
            esac
            got=$(treeid "$t/out")
            [ "$got" = "$tree" ] || {
                rm -rf "$t"
                die "TREE_MISMATCH: $dir as installed: $got, pin $tree"
            }
            rm -rf "${V:?}/$dir"
            mv "$t/out" "$V/$dir"
            rm -rf "$t"
            say "$dir installed (tree $got)"
        done
        ;;
    check)
        bad=0
        for r in $(rows "$@"); do
            IFS='|' read -r _ dir _ _ _ _ tree <<ROW
$r
ROW
            check_one "$dir" "$tree" || bad=1
        done
        exit "$bad"
        ;;
    *)
        echo "usage: $0 install|check [group...] (groups: core, the default)" >&2
        exit 2
        ;;
esac
