#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# vendor/: the third-party sources the repository builds, git-ignored, each fetched as an exact published package and
# checked against its pins (owner 2026-11-26, ARCH-POS-24; vendor/README.md).
#   scripts/vendor.sh install [group...]   fetch every package of the groups (default core) whose directory is missing or
#                                          fails its check; the archive's sha256 is checked before it is unpacked
#   scripts/vendor.sh check [group...]     each installed directory against its pinned git tree id; exit 1 on a mismatch
#                                          or a missing directory
#   scripts/vendor.sh link <main checkout> [group...]   in a worktree: each package whose copy in <main checkout>/vendor
#                                          passes this checkout's pin becomes a link to it (no second copy); a package
#                                          whose pin differs (a branch that moves it) is installed here as a real copy.
#                                          check reads through a link exactly as through a directory; install never
#                                          writes through one (SYMLINK_FAILS_CHECK when the linked copy is not the pin)
# Groups: core (what CI builds: ua-rs's Falcon sources, the forge libraries of smartcontracts/evm), kat (upstream LaZer
# for the pqz-core KAT and cross-check scripts), research (the lattice estimators of pqz-core/pqzl/params).
# The pin of a directory is its git tree id (`git write-tree` over every file under it, ignore rules off): what `git
# rev-parse <commit>:<dir>` names for a committed tree, so a pin reproduces from the package alone.
# A git package (kind git) is fetched by its full commit id alone (`git fetch --depth 1`, which checks every object id) and
# keeps that one-commit `.git`, so a script can still ask `git -C <dir> rev-parse HEAD` or clone it; the tree id leaves
# `.git` out (git never adds it). Its sha256 is over `sha256sum` of every other file, sorted by path, so the content is
# also pinned by SHA-256; install and check require the commit, the sha256 and the tree id.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
V="$root/vendor"

# group | directory | kind | package | version | sha256 of the archive | git tree id of the directory
PINS='
core|falcon-rs-0.3.1|crate|falcon-rs|0.3.1|97afa6b3e692aa0c332b883f18e3f999e99df06331ac93196b60805950b0f65f|315fb462132276c5cdf64dca2ee094f9652c5f85
core|pqclean-falcon-seeded|pqclean|-|-|-|ae0932f272cdf58f2eefa9188b121e86abf32547
core|openzeppelin-contracts-fda6b85f|git|https://github.com/OpenZeppelin/openzeppelin-contracts|fda6b85f2c65d146b86d513a604554d15abd6679|95afdb2052758a3a3ca153d07a328747f732af516651b231f6154322b775085c|ca37933ccdf02f8d8d549e86deac97239ec7516f
core|forge-std-88c8a288|git|https://github.com/foundry-rs/forge-std|88c8a2886f6f64c846ae57533a36361acb81683a|8401226cdbba19d3640f90d1868c68fc1b9f91b0c79c598bdd7ad60903c62a35|92bb6f3538c130f4874f478d05d1c90b28e41997
kat|lazer-3330e48|git|https://github.com/lazer-crypto/lazer|3330e487228f633eceb322807b13a596b516770f|d84efa27e9da25602dc844e561582c37e79c8c25405350fc3842e8a5dff02d4a|930143bfdf00172100a2c6ca8a0df4f6e7e7d2d2
research|leaky-LWE-Estimator-0a9caf8|git|https://github.com/lducas/leaky-LWE-Estimator|0a9caf8bf0f80097724e0c6147194c52c6b90f86|200aa5fd0f441e120cf31cd6926789b2ac4b9ff03136709048259f8512fafcf0|ff8f143c948362d60c6c49f8b3be7bc9dfb62bee
research|lattice-estimator-53da598|git|https://github.com/malb/lattice-estimator|53da5982597709ba0fdf94ea37a84d822310fd84|6e44b984b1d0470f73087ed62da650ad12d8f867871cce61feb5aa61fe263fd9|7cb765baf3bb401580c08f678dcee8c6f35e66d1
'
# Links into vendor/ (path from the root | the vendor directory): forge reads smartcontracts/evm/lib/<name> as before, so its
# remappings, every source unit name (lib/openzeppelin-contracts/...) and the metadata stay as they were (TODO 8b-9
# (4b)). install writes each link of its groups (relative, inside this tree) and replaces an old
# link; a real directory there is refused (LINK_IS_A_DIRECTORY: the copy the old evm_libs.sh installed; remove it).
LINKS='
smartcontracts/evm/lib/openzeppelin-contracts|openzeppelin-contracts-fda6b85f
smartcontracts/evm/lib/forge-std|forge-std-88c8a288
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

# sha256 over `sha256sum` of every file of a git package but its .git, sorted by path (C locale)
filesum() {
    if command -v sha256sum >/dev/null; then set -- "$1" sha256sum; else set -- "$1" shasum -a 256; fi
    d=$1
    shift
    (cd "$d" && find . -path ./.git -prune -o -type f -print0 | LC_ALL=C sort -z | xargs -0 "$@") | "$@" | cut -d' ' -f1
}

# url commit dest: that one commit, fetched by its id (git checks every object id against it), checked out in dest
gitpkg() {
    git init -q "$3"
    git -C "$3" fetch -q --depth 1 "$1" "$2" || die "GIT_FETCH_FAILED: $1 $2"
    git -C "$3" -c advice.detachedHead=false checkout -q FETCH_HEAD
    [ "$(git -C "$3" rev-parse HEAD)" = "$2" ] || die "GIT_COMMIT_MISMATCH: $1: $(git -C "$3" rev-parse HEAD), pin $2"
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

# check one row: 0 when the directory's tree equals the pin (a git package: its commit and sha256 too)
check_one() { # dir tree [kind commit sha256]
    [ -d "$V/$1" ] || {
        echo "vendor: $1 MISSING (scripts/vendor.sh install)" >&2
        return 1
    }
    got=$(treeid "$V/$1")
    if [ "$got" != "$2" ]; then
        echo "vendor: $1 MISMATCH: tree $got, pin $2" >&2
        return 1
    fi
    if [ "${3:-}" = git ]; then
        c=$(git -C "$V/$1" rev-parse -q --verify HEAD 2>/dev/null || echo none)
        [ "$c" = "$4" ] || {
            echo "vendor: $1 MISMATCH: commit $c, pin $4" >&2
            return 1
        }
        f=$(filesum "$V/$1")
        [ "$f" = "$5" ] || {
            echo "vendor: $1 MISMATCH: sha256 $f, pin $5" >&2
            return 1
        }
        say "$1 OK (commit $c, sha256 $f, tree $got)"
        return 0
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

# the link a path should hold: ../ per directory level of the path, then vendor/<dir>
linkto() { # path dir
    echo "$(dirname "$1" | sed -E 's#[^/]+#..#g')/vendor/$2"
}
links() { # groups... -> the LINKS rows whose directory is in those groups
    for r in $LINKS; do
        rows "$@" | cut -d'|' -f2 | grep -qx "${r#*|}" && echo "$r"
    done
    return 0
}
check_link() { # path dir
    if [ -L "$root/$1" ] && [ "$(readlink "$root/$1")" = "$(linkto "$1" "$2")" ]; then
        say "$1 -> vendor/$2 OK"
        return 0
    fi
    if [ -L "$root/$1" ]; then
        echo "vendor: $1 LINK_MISMATCH: -> $(readlink "$root/$1"), want $(linkto "$1" "$2") (scripts/vendor.sh install)" >&2
    elif [ -e "$root/$1" ]; then
        echo "vendor: $1 LINK_IS_A_DIRECTORY: not a link to vendor/$2; remove it, then scripts/vendor.sh install" >&2
    else
        echo "vendor: $1 LINK_MISSING (scripts/vendor.sh install)" >&2
    fi
    return 1
}

rows() { # groups... -> the PINS rows of those groups
    for grp in "$@"; do echo "$PINS" | grep "^$grp|"; done
}

# install one PINS row into vendor/ (nothing to do when it already passes its check); never through a link
install_row() { # row
    IFS='|' read -r _ dir kind pkg ver sha tree <<ROW
$1
ROW
    if [ -L "$V/$dir" ]; then
        check_one "$dir" "$tree" "$kind" "$ver" "$sha" >/dev/null 2>&1 && {
            say "$dir: a link that passes its check, left as it is"
            return 0
        }
        die "SYMLINK_FAILS_CHECK: vendor/$dir is a link whose content is not the pin; install never writes through a link: run scripts/vendor.sh link, or remove the link"
    fi
    if [ -e "$V/$dir" ]; then
        if check_one "$dir" "$tree" "$kind" "$ver" "$sha" 2>/dev/null; then return 0; fi
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
        git)
            gitpkg "$pkg" "$ver" "$t/out"
            f=$(filesum "$t/out")
            [ "$f" = "$sha" ] || die "SHA256_MISMATCH: $dir as fetched: $f, pin $sha"
            ;;
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
}

# the LINKS rows of the groups (smartcontracts/evm/lib/<name> -> vendor/<dir>, relative)
write_links() { # groups...
    for r in $(links "$@"); do
        p=${r%%|*} dir=${r#*|}
        if [ -e "$root/$p" ] && [ ! -L "$root/$p" ]; then check_link "$p" "$dir" || exit 1; fi
        mkdir -p "$(dirname "$root/$p")"
        ln -sfn "$(linkto "$p" "$dir")" "$root/$p"
        check_link "$p" "$dir" >/dev/null || exit 1
        say "$p -> vendor/$dir"
    done
}

cmd=${1:-}
[ $# -gt 0 ] && shift
M=
if [ "$cmd" = link ]; then
    M=${1:-}
    [ -n "$M" ] || die "usage: $0 link <main checkout> [group...]"
    shift
    [ -d "$M/vendor" ] || die "LINK_SOURCE_MISSING: $M/vendor is not a directory"
    MV=$(cd "$M/vendor" && pwd -P)
    [ "$MV" != "$(cd "$V" && pwd -P)" ] || die "LINK_TO_SELF: $M is this checkout"
fi
[ $# -gt 0 ] || set -- core
for grp in "$@"; do
    echo "$PINS" | grep -q "^$grp|" || die "UNKNOWN_GROUP: $grp (core, kat, research)"
done
t=
trap 'rm -rf "$t"' EXIT
case "$cmd" in
    install)
        for r in $(rows "$@"); do install_row "$r"; done
        write_links "$@"
        ;;
    link)
        # each package whose copy in the main checkout passes this checkout's pin (commit, sha256, tree id, as check
        # computes them) becomes a link to it; any other is installed here as a real copy, and the line says which
        for r in $(rows "$@"); do
            IFS='|' read -r _ dir kind _ ver sha tree <<ROW
$r
ROW
            VV=$V
            V=$MV
            same=1
            if check_one "$dir" "$tree" "$kind" "$ver" "$sha" >/dev/null 2>&1; then same=0; fi
            V=$VV
            if [ $same = 0 ]; then
                [ -L "$V/$dir" ] || rm -rf "${V:?}/$dir"
                ln -sfn "$MV/$dir" "$V/$dir"
                check_one "$dir" "$tree" "$kind" "$ver" "$sha" >/dev/null || exit 1
                say "$dir: LINKED -> $MV/$dir (the same pin)"
            else
                [ ! -L "$V/$dir" ] || rm -f "$V/$dir"
                say "$dir: COPY: the main checkout's vendor/$dir is missing or not this pin; installing a real copy here"
                install_row "$r"
            fi
        done
        write_links "$@"
        ;;
    check)
        bad=0
        for r in $(rows "$@"); do
            IFS='|' read -r _ dir kind _ ver sha tree <<ROW
$r
ROW
            check_one "$dir" "$tree" "$kind" "$ver" "$sha" || bad=1
        done
        for r in $(links "$@"); do
            check_link "${r%%|*}" "${r#*|}" || bad=1
        done
        exit "$bad"
        ;;
    *)
        echo "usage: $0 install|check [group...] | link <main checkout> [group...] (groups: core, the default; kat; research)" >&2
        exit 2
        ;;
esac
