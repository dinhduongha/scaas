#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-rs-sign T20: the closing gates of branch ua-rs-sign at one commit (plan 2026-11-05-ua-rs-sign T20), with the mechanical gates of
# the ARCH-POS-13 rework (T15i, T15l: "never a decryption oracle"; spec no-decryption-oracle §4.8, §5). Not a copy: it sets the step
# list, the log prefix, its own steps and test names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract, resume,
# named-tests and summary), as 2026-11-04-mldsa87-gates.sh. From the worktree root, foreground, one step per call:
#   smartcontracts/evm/runs/2026-11-07-ua-rs-sign-gates.sh [--only <step>]      GATES_FRESH=1 re-runs a step that passed
# Step <s> writes runs/2026-11-08-ua-rs-sign-<s>.log (git-ignored); `summary` writes the committed 2026-11-08-ua-rs-sign-summary.txt.
# First line "# <s> at commit <sha>", last line "rc=<n>"; a step is skipped when its log ends rc=0 at the current commit and the tree
# is clean apart from runs/. Every step that writes a tracked file (vectors-check, wallet-rows, test-features' positive control, a
# mutant) ends with `git diff --exit-code` (runs/ aside). Heavy commands through scripts/capped, -j2, --locked --offline. UNAUDITED.
# Inputs: smartcontracts/evm/lib and clients/clientkeys/node_modules as real directories; Foundry (forge, cast, anvil) in
# ~/.foundry/bin or on PATH; PQ_DOWNLOADS (vectors-check): a directory holding the pinned downloads of pq-external.mjs and
# ua-wallet-vectors.mjs (each read only when its sha256 is the pinned one); QT (ua-qt, ua-sizes); ANDROID_NDK_HOME (ua-sizes).
# The T15i / T15l mutant runs (mutant-<n>, l-mutant-<n>, then rebuild) are not closing steps: mutant-logs checks their records and
# harnesses. One re-runs as `STEPS=mutant-3 smartcontracts/evm/runs/2026-11-07-ua-rs-sign-gates.sh --only mutant-3`.
# GATES_P names another round's re-run (its own logs and summary; T15o: GATES_P=2026-11-08-ua-rs-sign-t15o; T20b's first sync with
# ua-mtx-merge: GATES_P=2026-11-08-ua-rs-sign-t20b1, the second: 2026-11-08-ua-rs-sign-t20b2), T20's stay.
P=${GATES_P:-2026-11-08-ua-rs-sign}
LOGEXT=log # step logs are git-ignored (*.log); only <P>-summary.txt is committed (owner 2026-11-02)
STEPS=${STEPS-"docs clientkeys vectors-check forge-ua ua-rs-nodefault ua-rs-wallet ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-rs-vectors ua-rs-zether ua-rs-pqz ua-rs-pqz-n2048 ua-deny ua-fuzz ua-sizes ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs ua-dart cargo-zether-prover wasm-zether-prover scaas-ct no-oracle no-oracle-n2048 no-oracle-ua-py wallet-rows test-features mutant-logs pqz-read read-balance named-tests summary"}
# the base runner's steps this round runs as its CI cells (.github/workflows/ci.yml, T18)
OWN_STEPS="vectors-check ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-c ua-dart-frb ua-py ua-go ua-cs cargo-zether-prover wasm-zether-prover"
# named-tests: no log of these may show a test binary with 0 passed or a skipped suite
FAMILIES="clientkeys ua-rs-nodefault ua-rs-wallet ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-rs-vectors ua-rs-zether ua-rs-pqz ua-rs-pqz-n2048 ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs ua-dart cargo-zether-prover scaas-ct no-oracle no-oracle-n2048 no-oracle-ua-py pqz-read read-balance"
export PATH=$HOME/.foundry/bin:$PATH CAPPED_MEM=${CAPPED_MEM:-4G} # 4G: capped's own default (the base sets 3G)
C="--locked --offline -j2"
T15I=smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15i-mutants.py
T15L=smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15l-mutants.py
N2048="--no-default-features --features wallet,zether,pqz,pqz-set-n2048-kmax1024,mlock"

cap() { "$W/scripts/capped" "$@"; }
uars() { # one ua-rs cell as CI runs it: clippy over every target, then the tests. Args: <features> [-- <test selection>]
  local f=(); while [ $# -gt 0 ] && [ "$1" != -- ]; do f+=("$1"); shift; done; [ $# -gt 0 ] && shift
  cd clients/ua-rs && cap cargo clippy $C --all-targets "${f[@]}" -- -D warnings && cap cargo test $C "${f[@]}" "$@"
}
release_ua_c() { cap cargo build --release $C --manifest-path clients/ua-c/Cargo.toml; } # what ua-py, ua-go, ua-cs load
clean() { git diff --exit-code --stat -- . ":(exclude)$R"; } # no tracked file moved (runs/: this runner's own files)

extra_step() { # this branch's own steps (the base runner calls it for a step it does not know, and for OWN_STEPS)
  case $1 in
    # each generator twice (clientkeys first, MD-7; then the both-ways fixtures of ua-rs: rs_signatures.json, rs_vault.json, each
    # keeping a row that still verifies / opens); the committed files must not move
    vectors-check) : "${PQ_DOWNLOADS:?PQ_DOWNLOADS: the pinned downloads (see the header)}"
      local i
      for i in 1 2; do
        (cd clients/clientkeys && UA_WALLET_DOWNLOADS=$PQ_DOWNLOADS cap node scripts/ua-wallet-vectors.mjs &&
           cap node scripts/pq-external.mjs "$PQ_DOWNLOADS") || return 1
        (cd clients/ua-rs && cap cargo test $C --features vectors --test wallet_pq --test wallet_vault -- --ignored regenerate) || return 1
        clean || return 1
      done ;;
    # the contracts' UA suites read the shared vector files (lib/ at its pins, a real directory: scripts/evm_libs.sh install)
    forge-ua) scripts/evm_libs.sh check && cd smartcontracts/evm && cap forge test --match-path 'test/ua/*' ;;
    # the ua-rs cells of CI (MD-5, T18); pqz_read against anvil is step pqz-read, the wallet_state.json generator wallet-rows
    ua-rs-nodefault) uars --no-default-features ;;
    ua-rs-wallet) uars --no-default-features --features wallet,mlock ;;
    ua-rs) uars ;;
    ua-rs-pq) uars --no-default-features --features pq -- --test pq --test ua8 ;;
    ua-rs-signers) uars --no-default-features --features signers -- --test groups ;;
    ua-rs-json) uars --no-default-features --features json -- --test json ;;
    ua-rs-vectors) uars --features vectors ;;
    ua-rs-zether) uars --no-default-features --features wallet,zether,mlock -- --lib --test facade_zether ;;
    # PQZ without Zether at the committed set (the zether-only cell's counterpart; no_oracle needs both facades)
    ua-rs-pqz) uars --no-default-features --features wallet,pqz,pqz-set-n2304-kmax4096,mlock -- --lib --bin pqz-read --test pqz_read \
                 --test facade_pqz_state --test facade_pqz --test pqz_backup --test pqz_wallet_rows ;;
    ua-rs-pqz-n2048) (uars $N2048 -- --lib --bin pqz-read --test pqz_read --test facade_pqz_state --test facade_pqz --test pqz_backup \
                        --test no_oracle) && uars $N2048,vectors -- --test facade_pqz_state --test facade_pqz --test pqz_backup --test no_oracle ;;
    # every lockfile over ua-rs resolves as committed; cargo deny by ua-rs/deny.toml; cargo audit with deny.toml's ignores (CI ua-deps)
    ua-deny) local m d ig
      for m in clients/ua-rs clients/ua-c clients/ua-cxx clients/ua-qt clients/ua-dart-frb/rust clients/ua-rs/fuzz clients/zether-prover scaas-node; do
        cap cargo tree --locked --offline -e normal --manifest-path "$m/Cargo.toml" > /dev/null || { echo "cargo tree --locked failed: $m"; return 1; }
      done
      (cd clients/ua-rs && cap cargo deny --all-features check) && (cd clients/ua-c && cap cargo deny --all-features --config ../ua-rs/deny.toml check) &&
        (cd clients/zether-prover && cap cargo deny --all-features --config ../ua-rs/deny.toml check) || return 1
      ig=$(python3 -I -c 'import tomllib; print(" ".join("--ignore " + a["id"] for a in tomllib.load(open("clients/ua-rs/deny.toml", "rb"))["advisories"]["ignore"]))')
      for d in clients/ua-rs clients/ua-c clients/zether-prover; do (cd "$d" && cap cargo audit $ig) || return 1; done ;;
    # T11's libFuzzer binary, then every target a short run over its seeds and regress/ inputs: no finding, no crash
    ua-fuzz) local t o bad=0
      cap clients/ua-rs/fuzz/build.sh || return 1
      for t in typed_data expect tx vault manifest container sealed kem_pk mnemonic container_expect members accepted uasig zether_cmd pqz_cmd; do
        o=$(cap clients/ua-rs/fuzz/run.sh "$t" "${UA_FUZZ_SECONDS:-20}" "$P"); echo "== $t"; echo "$o"
        grep -qx '\[fuzz rc=0\]' <<< "$o" && ! grep -qE 'ua-fuzz FINDING|deadly signal|^SUMMARY|^==[0-9]+==ERROR' <<< "$o" || bad=1
      done; [ $bad = 0 ] ;;
    # MD-12's ratchet (T17): every row this host builds (measure resumes per row), check, and every baseline cell measured
    ua-sizes) local m=clients/ua-c/target/ua-sizes-$(git rev-parse --short HEAD).json
      python3 -I clients/ua-c/sizes.py selftest > /dev/null || { echo "sizes.py selftest failed"; return 1; }
      ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-$HOME/usr/Android/sdk/ndk/29.0.13113456} LLVM_STRIP=${LLVM_STRIP:-llvm-strip-18} \
        LLVM_NM=${LLVM_NM:-llvm-nm-18} QMAKE=$QT/bin/qmake6 LD_LIBRARY_PATH=$QT/lib python3 -I clients/ua-c/sizes.py measure "$m" &&
        python3 -I clients/ua-c/sizes.py check "$m" || return 1
      python3 -I -c 'import json, sys; m, b = (json.load(open(f))["sizes"] for f in sys.argv[1:]); miss = sorted(set(b) - set(m))
print("baseline cells not measured:", miss or "none"); sys.exit(1 if miss else 0)' "$m" clients/ua-c/size-baseline.json ;;
    ua-c) (cd clients/ua-c && cap sh -c "cargo clippy $C --all-targets -- -D warnings && cargo build $C && cargo test $C &&
          cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/smoke.c target/debug/libscaas_ua_c.a -lpthread -ldl -lm -o target/smoke &&
          target/smoke && c++ -fsyntax-only -x c++ include/scaas_ua.h" && python3 -m unittest -v tests.test_vectors &&
          cap tests/asan-smoke.sh) ;;
    # the binding's own Rust tests too (T13c: secrets never cross the codec), which CI's ua-dart-frb job does not run; dart -j 1:
    # with two test files at once the expanded reporter leaves out a test that starts and ends between two of its lines (named-tests)
    ua-dart-frb) cd clients/ua-dart-frb && cap sh -c "dart pub get --enforce-lockfile && cargo build $C --manifest-path rust/Cargo.toml &&
        cargo test $C --manifest-path rust/Cargo.toml && dart test -r expanded -j 1" ;;
    ua-py) release_ua_c && cd clients/ua-py && python3 -m unittest -v tests.test_vectors tests.test_wallet ;;
    ua-go) release_ua_c && cd clients/ua-go && cap sh -c 'go vet ./... && go test -v ./...' ;;
    ua-cs) release_ua_c || return 1
      cd clients/ua-cs && cap dotnet test Scaas.Ua.Tests --logger 'console;verbosity=normal'; local rc=$?
      dotnet build-server shutdown > /dev/null 2>&1; return $rc ;; # VBCSCompiler would keep the capped slot
    cargo-zether-prover) cd clients/zether-prover && cap sh -c "cargo clippy $C --all-targets -- -D warnings &&
        cargo clippy $C --all-targets --features hazmat -- -D warnings && cargo test $C && cargo test $C --features hazmat" ;;
    # the shipped wasm refuses the raw commands; with hazmat (test-only) the prover runs in wasm
    wasm-zether-prover) cd clients/zether-prover && cap ./wasm-smoke.sh && cap env ZETHER_HAZMAT=1 ./wasm-smoke.sh ;;
    # secret_mul's own tests (T3c; the vectors feature exposes the ladder trace), which no CI job runs: ua-rs only builds the crate
    scaas-ct) cd clients/scaas-ct && cap sh -c "cargo clippy $C --all-targets --features vectors -- -D warnings && cargo test $C &&
        cargo test $C --features vectors" ;;
    # the oracle harness and the wallet rows at the default set (release cell, then vectors: the positive control)
    no-oracle) (cd clients/ua-rs && cap cargo test $C --test no_oracle --test pqz_wallet_rows &&
                cap cargo test $C --features vectors --test no_oracle --test pqz_wallet_rows) ;;
    no-oracle-n2048) (cd clients/ua-rs && cap cargo test $C $N2048 --test no_oracle && cap cargo test $C $N2048,vectors --test no_oracle) ;;
    # the same harness through the C ABI (the release library, which every binding but ua-cxx / ua-dart-frb / ua-qt loads)
    no-oracle-ua-py) release_ua_c && (cd clients/ua-py && python3 -m unittest -v tests.test_wallet.Pqz.test_no_oracle) ;;
    # the rows' generator twice: the same bytes as committed
    wallet-rows) local f=smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json a b
                 smartcontracts/vectors/pqz/gen_wallet_state.sh && a=$(sha256sum < $f) &&
                 smartcontracts/vectors/pqz/gen_wallet_state.sh && b=$(sha256sum < $f) &&
                 echo "sha256 $a / $b" && [ "$a" = "$b" ] && git diff --exit-code -- $f ;;
    # no test feature in a production artifact: the manifests and `cargo tree -e features` of ua-c (libscaas_ua_c: ua-py,
    # ua-go, ua-cs), ua-cxx, ua-qt, ua-dart-frb's crate and zether-prover (zether-read-balance); positive control: ua-c with
    # scaas-ua/vectors forced fails the check (both the manifest and the graph check); restored, tree clean
    test-features) local m=clients/ua-c/Cargo.toml r
                   CARGO_NET_OFFLINE=true python3 -I scripts/check_test_features.py || return 1
                   sed -i 's/features = \["json", "wallet"\] }/features = ["json", "wallet", "vectors"] }/' $m
                   CARGO_NET_OFFLINE=true python3 -I scripts/check_test_features.py; r=$?
                   git checkout -q -- $m
                   echo "positive control (scaas-ua/vectors forced in $m): rc=$r (must be 1)"
                   [ $r = 1 ] && clean ;;
    # the mutant records of the round: each ends with no survivor, and every harness still applies at this commit (`check`:
    # each replacement string found once, no run), so a later change cannot leave a record that no longer tests anything.
    # T1a-T3d: `check` mode added at T20 (their stale strings brought to HEAD and re-run, each record's dated T20 section)
    mutant-logs) local t bad=0
                 for t in 2026-11-05-ua-rs-sign-t1a 2026-11-05-ua-rs-sign-t1b 2026-11-05-ua-rs-sign-t1c 2026-11-05-ua-rs-sign-t2 \
                          2026-11-05-ua-rs-sign-t3a 2026-11-05-ua-rs-sign-t3b 2026-11-05-ua-rs-sign-t3c 2026-11-05-ua-rs-sign-t3d \
                          2026-11-05-ua-rs-sign-t4 2026-11-05-ua-rs-sign-t5 2026-11-05-ua-rs-sign-t6 2026-11-05-ua-rs-sign-t7 \
                          2026-11-06-ua-rs-sign-t8 2026-11-06-ua-rs-sign-t9 2026-11-06-ua-rs-sign-t10 2026-11-06-ua-rs-sign-t11 \
                          2026-11-06-ua-rs-sign-parity 2026-11-06-ua-rs-sign-t12 2026-11-06-ua-rs-sign-t12fu 2026-11-06-ua-rs-sign-t13a \
                          2026-11-06-ua-rs-sign-t13b 2026-11-06-ua-rs-sign-t13c 2026-11-06-ua-rs-sign-t13c-secrets 2026-11-06-ua-rs-sign-t13d \
                          2026-11-06-ua-rs-sign-t13e 2026-11-06-ua-rs-sign-t13f 2026-11-06-ua-rs-sign-t14 2026-11-06-ua-rs-sign-t15 \
                          2026-11-06-ua-rs-sign-t16 2026-11-06-ua-rs-sign-t16a 2026-11-06-ua-rs-sign-t16b \
                          2026-11-06-ua-rs-sign-t15b 2026-11-06-ua-rs-sign-t15c 2026-11-07-ua-rs-sign-t15c2 2026-11-07-ua-rs-sign-t15e \
                          2026-11-07-ua-rs-sign-t14b 2026-11-07-ua-rs-sign-t15g 2026-11-07-ua-rs-sign-t15k 2026-11-07-ua-rs-sign-t15i \
                          2026-11-07-ua-rs-sign-t15l 2026-11-07-ua-rs-sign-t15m 2026-11-07-ua-rs-sign-t15n \
                          2026-11-07-ua-rs-sign-t15n2 2026-11-08-ua-rs-sign-t15o 2026-11-08-ua-rs-sign-t20b1 \
                          2026-11-08-ua-rs-sign-t20b2 ${MUTANT_LOGS_EXTRA:-}; do
                   l=$(tail -n 1 smartcontracts/evm/runs/$t-mutants.txt); echo "$t: $l"
                   grep -Eq '(survived or not loaded: 0|0 survived, 0 not loaded)$|0 survived, 0 not loaded \(' <<< "$l" || bad=1
                   echo "$t check: $(python3 -I smartcontracts/evm/runs/$t-mutants.py check 2>&1 | tail -n 1)"
                   python3 -I smartcontracts/evm/runs/$t-mutants.py check > /dev/null 2>&1 || bad=1
                 done; [ $bad = 0 ] ;;
    # the PQZ and Zether reading layers (R1-R7) against a local anvil each test starts and stops (CI: the default cell, zether-prover)
    pqz-read) cd clients/ua-rs && cap cargo test $C --test pqz_read --bin pqz-read -- --include-ignored ;;
    read-balance) cd clients/zether-prover && cap sh -c "cargo test $C --test read_balance --bin zether-read-balance -- --include-ignored &&
        cargo test $C --features hazmat --test read_balance --bin zether-read-balance -- --include-ignored" ;;
    l-mutant-*) local n=${1#l-mutant-}; python3 -I "$T15L" "$n" "$n"; local r=$?; clean && return $r ;;
    mutant-*) local n=${1#mutant-}; python3 -I "$T15I" "$n" "$n"; local r=$?; clean && return $r ;;
    # the libraries the binding mutants rebuilt, from the clean tree
    rebuild) cap cargo build --release $C --manifest-path clients/ua-c/Cargo.toml &&
             cap cargo build $C --manifest-path clients/ua-c/Cargo.toml &&
             cap sh -c 'cmake --build clients/ua-cxx/build -j2' &&
             cap cargo build $C --manifest-path clients/ua-dart-frb/rust/Cargo.toml && clean ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

# "<step>|<form>|<name>": the tests this branch adds (forms: see the base runner). Written at T20 from the test definitions the
# diff merge-base(origin/main)..HEAD adds (Rust #[test] fns, node test(), unittest, Go, xUnit, QML, Dart test(), ua-cxx's ctest
# names), each under the first step whose log shows it passed: 618 definitions, 611 rows (a name two test files of one step
# share is one row; the two `regenerate` writers by their module).
NEW_TESTS=$(cat <<'NAMES'
clientkeys|node|kem.json keys: the KEM key of every holder × version {0, 1}, other account / index / version, the 12-word wallet
clientkeys|node|kem.json refusals: a non-holder kind and an msig have no KEM key (KemHolder), version ≥ 2^64 (Argument)
clientkeys|node|kem.json encaps: fixed m and e give mlkemCt, E and ss; the holder decapsulates the same ss
clientkeys|node|kem.json encaps refusals: modulus, length, scheme 2, all-zero ss_X (KemCheck)
clientkeys|node|kem.json decaps: lengths and small-order E refused, a flipped mlkemCt byte gives another ss (implicit rejection)
clientkeys|node|KEM key only through the UA key: kemKey of the UA key equals kemKeyOf; another seed gives another key
clientkeys|node|pq_external.json: every T1c section names its source URL and a sha256
clientkeys|node|ACVP ML-KEM-1024 keyGen: KeyGen_internal(d, z) = (ek, dk)
clientkeys|node|ACVP ML-KEM-1024 encapDecap: encapsulation (m → c, K), decapsulation (valid and modified c), key checks
clientkeys|node|RFC 7748 X25519: §5.2 scalar multiplications and the iterated function (1, 1,000), §6.1 Diffie-Hellman
clientkeys|node|ACVP sigGen: the ML-DSA and SLH-DSA signers reproduce deterministic and hedged signatures over M' (internal and pure external)
clientkeys|node|pinned sources: a download is read only at its sha256; one flipped byte is refused
clientkeys|node|seal.json seal rows: fixed m and e per purpose (backup, link to an ephemeral key, empty pt and aad) reproduce and open
clientkeys|node|seal.json refusals: purpose, aad, version, scheme, a flipped byte in each field, another key; argument refusals
clientkeys|node|seal.json containers: backup, link and msig senders reproduce byte for byte and open with the expected sender
clientkeys|node|container builder: an msig sender signs only in the minimal form (UAPoP), a single key only as a UA key
clientkeys|node|seal.json acceptance: each refusal from an otherwise valid container (C-03), before decapsulation where it says ContainerSender
clientkeys|node|msig sender acceptance (CTR-UA-37): only a true answer accepts, a single key needs no lookup
clientkeys|node|seal.json replay and rollback (C-11): link window and one use, backup generation
clientkeys|node|12-word wallet round trip (C-10): mnemonic, signing key and KEM key equal before and after, through the vault and a sealed backup
clientkeys|node|rs_vault.json backups: a ua-rs backup restores here
clientkeys|node|SLIP-10 nist256p1: test vector 1, derivation retry, seed retry (published, slip-0010.md)
clientkeys|node|native index and coin type in [0, 2^31); solana m/44'/501'/i'/0' base58 address
clientkeys|node|mnemonics: entropy, seed, the 12-word row (16-byte entropy) and the non-ASCII BIP-39 passphrase row
clientkeys|node|normalization rows: NFKD of the words and of the passphrase
clientkeys|node|keys.json rows equal deriveUAKey for every kind × account {0,1} × index {0,1}
clientkeys|node|UA tree paths: m/22776'/0'/<account>'/<kindNo>'/<i>', the EIP-2333 UA paths, never a native path
clientkeys|node|index 1 refused for every EIP-2333 kind and musig2-bn254 at m/254/0/<account>/274
clientkeys|node|account 2^31 refused (and every keys.json refusal row)
clientkeys|node|native keys per NETWORKS, solana at m/44'/501'/i'/0'
clientkeys|node|0x0101 and 0x0108 sign ua_msg (no prehash for 0x0108, sha256 for 0x0101)
clientkeys|node|sign.json ua rows: deterministic rows byte-equal, randomized rows verify, the role follows the purpose
clientkeys|node|two release signatures differ for every randomized kind; deterministic kinds repeat
clientkeys|node|a purpose not in PURPOSES is refused; a UA key has no raw-digest call
clientkeys|node|member rows: sign_member signs uaMessage(kind, member, memberDigest(structure, structure ua_msg))
clientkeys|node|BLS ordinary and PoP rows, right message under the wrong DST refused
clientkeys|node|nonce map is the 512-bit map
clientkeys|node|unbound relayer / feeRecipient hashed as zero in every mode struct
clientkeys|node|unrelated Order(mode, relayer, feeRecipient, amount) through Any equals hashTypedData of the supplied values
clientkeys|node|typed rows with arrays and a negative int; missing field is zero, unknown field refused
clientkeys|node|policy rows: accepted and refused, from the check* functions
clientkeys|node|tx type 4 cannot be built
clientkeys|node|tx chainId < 2^64 (ua-rs ChainId, EIP-2294): 2^64 and 2^64 + 1 refused, 2^64 - 1 signed
clientkeys|node|EIP-155 published row
clientkeys|node|tx rows per type 0-3 from the seed's EVM key: unsigned, sighash, signature, raw
clientkeys|node|WebAuthn assertion: accepted rows, refusals (wrong challenge, reordered JSON, crossOrigin: true, r = 0, s = n)
clientkeys|node|WebAuthn clientDataJSON that is not UTF-8 is refused by the builder, accepted by the chains' byte rule (ua-rs parity)
clientkeys|node|msig rows: minimal sets signed at both levels, non-minimal and unsorted sets refused
clientkeys|node|chain separation (owner 2026-11-05): one message and one key on 7622 and 22776, other digests and signatures, no cross-chain verify
clientkeys|node|sign.json external (T1c): RFC 6979 A.2.5 P-256 / SHA-256 and the named secp256k1 RFC 6979 set, with source and sha256
clientkeys|node|rs_signatures.json: ua-rs signatures (Falcon, hedged ML-DSA, randomized SLH-DSA, OS-aux BIP-340 and scaas Schnorr) verify here
clientkeys|node|vault.json: seed vaults at N = 2^15, 2^16, 2^17, 12 words, NFC sealed / NFD opened (NFKC), PRF; each opens to its entropy
clientkeys|node|vault.json refusals: wrong passphrase, altered AAD label, N = 2^31 / 3, r = 16, p = 2, v 2 and its tombstone, 31 and 64-byte payloads, label
clientkeys|node|rs_vault.json: ua-rs vaults (24 and 12 words, PRF envelope, rewrapped pin) open here
clientkeys|node|zether.json: cache boxes open under the conf key, refusals do not
scaas-ct|cargo|blind_is_k_plus_rho_r
scaas-ct|cargo|blinded_and_plain_products_equal
scaas-ct|cargo|ladder_is_384_bits_wide
scaas-ct|cargo|masked_swap_swaps_exactly_when_asked
scaas-ct|cargo|every_call_blinds_with_a_new_integer
ua-c|cargo|abi_version_is_6
ua-c|cargo|features_bits_match_the_build
ua-c|cargo|handles_wipe_on_free
ua-c|cargo|a_panic_is_internal_never_an_unwind
ua-c|cargo|kem_key_takes_no_wallet
ua-c|cargo|header_states_its_rules
ua-c|cargo|every_export_is_guarded
ua-c|cargo|export_pqz_leaf_raw_is_warned
ua-c|unittest|test_abi_version_is_6
ua-c|unittest|test_features_bits
ua-c|unittest|test_status_codes_appended
ua-c|unittest|test_free_null_is_a_noop
ua-c|unittest|test_external_key_new_is_KIND_UNAVAILABLE
ua-c|unittest|test_null_handles_and_arguments
ua-c|unittest|test_keys_json_ua_rows
ua-c|unittest|test_keys_json_native_rows
ua-c|unittest|test_keys_json_refusals
ua-c|unittest|test_sign_json_ua_rows
ua-c|unittest|test_sign_json_member_rows
ua-c|unittest|test_sign_json_policy_rows
ua-c|unittest|test_sign_json_typed_any
ua-c|unittest|test_sign_json_tx_rows
ua-c|unittest|test_sign_json_webauthn
ua-c|unittest|test_sign_json_msig_rows_through_uasig
ua-c|unittest|test_uasig_single_key_is_sign_ua
ua-c|unittest|test_sign_digest_raw_on_a_ua_key_is_RawDigestRefused
ua-c|unittest|test_sign_key_proof
ua-c|unittest|test_kem_json_keys
ua-c|unittest|test_kem_json_refusals
ua-c|unittest|test_kem_json_encaps_refusals_and_round_trip
ua-c|unittest|test_kem_json_decaps
ua-c|unittest|test_kem_ephemeral
ua-c|unittest|test_seal_json_seal_rows
ua-c|unittest|test_seal_json_refusals
ua-c|unittest|test_seal_json_argument_refusals
ua-c|unittest|test_seal_json_containers
ua-c|unittest|test_seal_json_acceptance
ua-c|unittest|test_open_container_msig_without_accepted_json_is_ContainerSender
ua-c|unittest|test_container_json_inputs_are_bounded
ua-c|unittest|test_seal_json_replay_backup_rows_and_the_none_flag
ua-c|unittest|test_backup_seal_restores_a_wallet
ua-c|unittest|test_link_session_is_consumed
ua-c|unittest|test_link_seal_round_trip
ua-c|unittest|test_vault_json_vaults
ua-c|unittest|test_vault_json_refusals
ua-c|unittest|test_exactly_one_unlock_secret
ua-c|unittest|test_seal_vault_rewrap_enable_prf
ua-c|unittest|test_lock_revokes_and_unlock_does_not_revive
ua-c|unittest|test_imported_key_after_unlock
ua-c|unittest|test_unlock_with_another_wallets_vault_is_WalletMismatch
ua-c|unittest|test_child_handle_after_wallet_free_is_KEY_REVOKED
ua-c|unittest|test_memory_protection
ua-c|unittest|test_seed_backup_sequence
ua-c|unittest|test_import_manifest_discover
ua-c|unittest|test_error_strings_never_contain_an_input
ua-c|unittest|test_aead_hkdf_hmac
ua-c|unittest|test_zether_feature_in_the_default_build
ua-c|unittest|test_r33_keys
ua-c|unittest|test_pop_and_check_balance
ua-c|unittest|test_pick_decoys
ua-c|unittest|test_words_commands_on_the_forge_rows
ua-c|unittest|test_a_key_field_in_command_json_is_refused
ua-c|unittest|test_cache_box_rows
ua-c|unittest|test_zether_handle_after_lock_and_free_is_KEY_REVOKED
ua-c|unittest|test_out_max_holds_a_proof_twice
ua-c|unittest|test_pqz_and_one_set_in_the_default_build
ua-c|unittest|test_leaf_is_the_ua_pq_rule
ua-c|unittest|test_register_set_mismatch_and_key_field
ua-c|unittest|test_enc_dec_and_cache_box
ua-c|unittest|test_pqz_handle_after_lock_and_free_is_KEY_REVOKED
ua-c|unittest|test_two_of_three_rebuild_through_the_abi
ua-c|unittest|test_rebuilt_key_after_lock_and_unlock
ua-c|unittest|test_k_and_recipients_checked
ua-cs|cs|LoadRefusesWrongAbiOrFeatures
ua-cs|cs|AbiVersionIs6AndFeatures
ua-cs|cs|HandleFreedExactlyOnce
ua-cs|cs|UseAfterDisposeNeverReachesTheLibrary
ua-cs|cs|SecretBufferWipedAfterCall
ua-cs|cs|FixedSizeAndShortSecretsAreRefused
ua-cs|cs|KeysJson
ua-cs|cs|SignJsonUAAndMember
ua-cs|cs|SignJsonPolicyTypedTx
ua-cs|cs|SignJsonWebAuthn
ua-cs|cs|SignJsonMsigThroughUASig
ua-cs|cs|KemJson
ua-cs|cs|SealJsonRowsAndRefusals
ua-cs|cs|SealJsonContainersAndAcceptance
ua-cs|cs|SealJsonReplayBackupRows
ua-cs|cs|BackupSealRestoresAWallet
ua-cs|cs|LinkSessionAndLinkSeal
ua-cs|cs|VaultJson
ua-cs|cs|Custody
ua-cs|cs|ChildHandleAfterWalletFreeIsKeyRevoked
ua-cs|cs|SeedBackupSequence
ua-cs|cs|ErrorStringsNeverContainAnInput
ua-cs|cs|AeadHkdfHmac
ua-cs|cs|Zether
ua-cs|cs|ZetherWordsOnTheForgeRows
ua-cs|cs|PqzWordsOnTheForgeRows
ua-cs|cs|Pqz
ua-cxx|ctest|wallet_load_refuses_wrong_abi_or_features
ua-cxx|ctest|wallet_secret_buffer_wiped_after_call
ua-cxx|ctest|wallet_handle_freed_once
ua-cxx|ctest|wallet_keys_json
ua-cxx|ctest|wallet_sign_json
ua-cxx|ctest|wallet_rs_signatures_json
ua-cxx|ctest|wallet_kem_json
ua-cxx|ctest|wallet_seal_json
ua-cxx|ctest|wallet_backup_link_restore
ua-cxx|ctest|wallet_vault_json
ua-cxx|ctest|wallet_rs_vault_json
ua-cxx|ctest|wallet_custody
ua-cxx|ctest|wallet_seed_backup_sequence
ua-cxx|ctest|wallet_error_strings_never_contain_an_input
ua-cxx|ctest|wallet_aead_hkdf_hmac
ua-cxx|ctest|wallet_zether_facade
ua-cxx|ctest|wallet_pqz_facade
ua-cxx|ctest|wallet_zether_words
ua-cxx|ctest|wallet_pqz_words
ua-dart-frb|cargo|secret_fixed_locked_and_zeroed_on_drop
ua-dart-frb|cargo|secret_sizes_and_outputs
ua-dart-frb|cargo|secrets_never_cross_the_codec
ua-dart-frb|dart|load_refuses_wrong_abi_or_features
ua-dart-frb|dart|secret_bytes_take_and_dispose
ua-dart-frb|dart|handle_freed_once
ua-dart-frb|dart|keys_json
ua-dart-frb|dart|sign_json
ua-dart-frb|dart|rs_signatures_json
ua-dart-frb|dart|kem_json
ua-dart-frb|dart|seal_json
ua-dart-frb|dart|backup_link_restore
ua-dart-frb|dart|vault_json and rs_vault_json
ua-dart-frb|dart|custody
ua-dart-frb|dart|seed_backup_sequence
ua-dart-frb|dart|aead_hkdf_hmac
ua-dart-frb|dart|zether_facade
ua-dart-frb|dart|zether_words
ua-dart-frb|dart|pqz_words
ua-dart-frb|dart|pqz_facade
ua-go|go|TestLoadRefusesWrongAbiOrFeatures
ua-go|go|TestAbiVersionIs6AndFeatures
ua-go|go|TestHandleFreedExactlyOnce
ua-go|go|TestCloseWaitsForACallInFlight
ua-go|go|TestUseAfterCloseNeverReachesTheLibrary
ua-go|go|TestSecretBufferWipedAfterCall
ua-go|go|TestFixedSizeAndShortSecretsAreRefused
ua-go|go|TestKeysJSON
ua-go|go|TestSignJSONUAAndMember
ua-go|go|TestSignJSONPolicyTypedTx
ua-go|go|TestSignJSONWebAuthn
ua-go|go|TestSignJSONMsigThroughUASig
ua-go|go|TestKemJSON
ua-go|go|TestSealJSONRowsAndRefusals
ua-go|go|TestSealJSONContainersAndAcceptance
ua-go|go|TestSealJSONReplayBackupRows
ua-go|go|TestBackupSealRestoresAWallet
ua-go|go|TestLinkSessionAndLinkSeal
ua-go|go|TestVaultJSON
ua-go|go|TestCustody
ua-go|go|TestChildHandleAfterWalletFreeIsKeyRevoked
ua-go|go|TestSeedBackupSequence
ua-go|go|TestErrorStringsNeverContainAnInput
ua-go|go|TestAeadHkdfHmac
ua-go|go|TestZether
ua-go|go|TestZetherWordsOnTheForgeRows
ua-go|go|TestPqzWordsOnTheForgeRows
ua-go|go|TestPqz
ua-py|unittest|test_load_refuses_wrong_abi_or_features
ua-py|unittest|test_abi_version_is_6_and_features_bits
ua-py|unittest|test_handle_freed_exactly_once
ua-py|unittest|test_use_after_close_never_reaches_the_library
ua-py|unittest|test_close_waits_for_a_call_in_flight
ua-py|unittest|test_secret_buffer_wiped_after_call
ua-py|unittest|test_a_str_secret_is_refused
ua-py|unittest|test_keys_json_ua_rows
ua-py|unittest|test_keys_json_native_rows
ua-py|unittest|test_keys_json_refusals
ua-py|unittest|test_sign_json_ua_rows
ua-py|unittest|test_sign_json_member_rows
ua-py|unittest|test_sign_json_policy_rows
ua-py|unittest|test_sign_json_typed_any
ua-py|unittest|test_sign_json_tx_rows
ua-py|unittest|test_sign_json_webauthn
ua-py|unittest|test_sign_json_msig_rows_through_uasig
ua-py|unittest|test_uasig_single_key_is_sign_ua
ua-py|unittest|test_raw_digest_and_key_proof
ua-py|unittest|test_kem_json_keys
ua-py|unittest|test_kem_json_refusals
ua-py|unittest|test_kem_json_encaps_refusals_and_round_trip
ua-py|unittest|test_kem_json_decaps
ua-py|unittest|test_kem_ephemeral
ua-py|unittest|test_seal_json_seal_rows
ua-py|unittest|test_seal_json_refusals
ua-py|unittest|test_seal_json_argument_refusals
ua-py|unittest|test_seal_json_containers
ua-py|unittest|test_seal_json_acceptance
ua-py|unittest|test_open_container_msig_without_accepted_json_is_ContainerSender
ua-py|unittest|test_seal_json_replay_backup_rows
ua-py|unittest|test_backup_seal_restores_a_wallet
ua-py|unittest|test_link_session_is_consumed
ua-py|unittest|test_link_seal_round_trip
ua-py|unittest|test_vault_json_vaults
ua-py|unittest|test_vault_json_refusals
ua-py|unittest|test_exactly_one_unlock_secret
ua-py|unittest|test_seal_vault_rewrap_enable_prf
ua-py|unittest|test_lock_revokes_and_unlock_does_not_revive
ua-py|unittest|test_imported_key_after_unlock
ua-py|unittest|test_unlock_with_another_wallets_vault_is_WalletMismatch
ua-py|unittest|test_child_handle_after_wallet_free_is_KEY_REVOKED
ua-py|unittest|test_memory_protection
ua-py|unittest|test_seed_backup_sequence
ua-py|unittest|test_import_manifest_discover
ua-py|unittest|test_error_strings_never_contain_an_input
ua-py|unittest|test_aead_hkdf_hmac
ua-py|unittest|test_r33_keys
ua-py|unittest|test_pop_prove_and_key_field
ua-py|unittest|test_words_commands_on_the_forge_rows
ua-py|unittest|test_cache_box_rows
ua-py|unittest|test_zether_handle_after_lock_is_KEY_REVOKED
ua-py|unittest|test_set_and_check_set
ua-py|unittest|test_leaf_is_the_ua_pq_rule
ua-py|unittest|test_register_set_mismatch_and_key_field
ua-py|unittest|test_enc_dec_and_cache_box
ua-py|unittest|test_no_oracle
ua-py|unittest|test_pqz_handle_after_lock_is_KEY_REVOKED
ua-qt|qt|test_load_refuses_wrong_abi_or_features
ua-qt|qt|test_secret_buffer_wiped_after_call
ua-qt|qt|test_no_decaps_no_raw_export_no_handle
ua-qt|qt|test_public_fields_by_id
ua-qt|qt|test_sign_by_handle_id
ua-qt|qt|test_uasig_msig_by_handle_ids
ua-qt|qt|test_seal_to_a_public_key
ua-qt|qt|test_revoked_after_lock_public_data_readable
ua-qt|qt|test_a_handle_released_once
ua-rs|cargo|helpers
ua-rs|cargo|uniform_no_duplicates_exclusions_honoured
ua-rs|cargo|weighted
ua-rs|cargo|legs_recipient_position_uniform
ua-rs|cargo|shuffle_uniform
ua-rs|cargo|rejection_sampling
ua-rs|cargo|refusals
ua-rs|cargo|pqz_key_is_the_ua_pq_rule
ua-rs|cargo|two_proofs_differ
ua-rs|cargo|set_mismatch_refused
ua-rs|cargo|pqz_handle_KeyRevoked_after_lock
ua-rs-vectors|cargo|unlock_does_not_revive_a_pqz_handle
ua-rs|cargo|release_has_no_raw_decrypt
ua-rs|cargo|raw_requests_compile_only_under_vectors
ua-rs|cargo|disclose_sender_compares_in_constant_time
ua-rs|cargo|open_memo_compares_in_constant_time
ua-rs|cargo|a_key_field_in_command_json_is_refused
ua-rs|cargo|command_json_is_bounded_and_typed
ua-rs-vectors|cargo|transfer_and_disclosures_verify
ua-rs-vectors|cargo|burn_and_refresh_verify
ua-rs-vectors|cargo|transfer_multi_memo_and_sender_disclosure
ua-rs-vectors|cargo|multi_bundle_memo_hash_is_zero
ua-rs-vectors|cargo|multi_hash_memo_hash_matches_contract
ua-rs-vectors|cargo|multi_without_mode_refused
ua-rs|cargo|key_record_register_verifies
ua-rs|cargo|cache_box_key_and_label
ua-rs-vectors|cargo|keygen_rows_through_the_facade
ua-rs-vectors|cargo|memo_open_rows_through_the_facade
ua-rs-vectors|cargo|multi_rows_per_mode
ua-rs-vectors|cargo|proof_rows_through_the_facade
ua-rs|cargo|pick_decoys
ua-rs|cargo|stored_form_is_the_contracts
ua-rs|cargo|layout_is_the_pin
ua-rs-vectors|cargo|state_rows_reproduce_the_contract
ua-rs|cargo|balances_and_debits_over_rebuilt_words
ua-rs|cargo|disclosures_audit_reads_and_memo_over_rebuilt_words
ua-rs|cargo|requests_carry_words_only
ua-rs|cargo|word_negatives_refused_before_the_key
ua-rs|cargo|entry_and_role_negatives_refused_before_the_key
ua-rs|cargo|sender_disclosure_over_rebuilt_words
ua-rs|cargo|sender_disclosure_negatives
ua-rs|cargo|open_memo_binds_the_entry
ua-rs|cargo|memo_hash_is_the_contracts
ua-rs|cargo|op1_memo_per_mode
ua-rs|cargo|burn_and_refresh_memo_hash_is_zero
ua-rs|cargo|forge_rows_on_another_handle_are_refused_before_the_key
ua-rs|cargo|conf_and_viewing_keys_are_r33_keys
ua-rs|cargo|key_use_other_than_conf_or_viewing_is_refused
ua-rs|cargo|zether_handle_KeyRevoked_after_lock
ua-rs-vectors|cargo|unlock_does_not_revive_a_zether_handle
ua-rs|cargo|fields_outside_the_allow_list_are_refused
ua-rs|cargo|numbers_other_than_u64_are_refused
ua-rs|cargo|command_json_is_bounded_by_length_and_depth
ua-rs|cargo|pop_and_check_balance_through_the_facade
ua-rs|cargo|cache_box_equals_clientkeys
ua-rs-vectors|cargo|zether_prover_vectors_through_the_facade
ua-rs|cargo|the_parser_is_the_pin_of_the_rows
ua-rs|cargo|balances_from_the_words
ua-rs|cargo|openings_for_the_receiver_and_the_auditor_verify
ua-rs|cargo|debits_over_the_words_verify
ua-rs|cargo|location_word_and_role_negatives_are_refused_with_the_key_unused
ua-rs|cargo|residual_control_consistent_fabricated_words_are_decrypted
ua-rs-vectors|cargo|json_inputs_deeper_than_their_cap_are_refused_unparsed
ua-rs-vectors|cargo|json_inputs_longer_than_their_cap_are_refused_unparsed
ua-rs-vectors|cargo|sealed_short_of_its_tag_is_refused
ua-rs-vectors|cargo|sealed_past_its_plaintext_cap_does_not_open
ua-rs-vectors|cargo|kem_pk_of_another_scheme_or_length_is_refused
ua-rs-vectors|cargo|mnemonic_past_1_kib_or_24_words_is_refused
ua-rs-vectors|cargo|container_json_inputs_read_the_vector_rows
ua-rs-vectors|cargo|zether_inputs_past_their_caps_are_refused_unparsed
ua-rs-vectors|cargo|pqz_inputs_past_their_caps_are_refused_unparsed
ua-rs-vectors|cargo|positive_control_raw_dec_recovers_s
ua-rs|cargo|production_refuses_every_crafted_query_before_the_key
ua-rs|cargo|a_crafted_query_beside_real_words_is_refused
ua-rs|cargo|residual_control_fabricated_words_are_decrypted
ua-rs|cargo|zether_refuses_a_bare_ciphertext
ua-rs|cargo|k_shares_rebuild_a_key_matching_pqzKeyHash
ua-rs|cargo|k_minus_1_shares_refused
ua-rs|cargo|a_share_for_another_msig_key_or_version_refused
ua-rs|cargo|shares_never_carry_wallet_entropy
ua-rs|cargo|recipients_and_k_checked
ua-rs|cargo|a_missing_backup_warns_and_never_refuses
ua-rs|cargo|reseal_takes_share_containers_only
ua-rs-vectors|cargo|field_and_split_known_answers
ua-rs-vectors|cargo|a_backup_record_past_its_caps_is_refused_unparsed
ua-rs|cargo|a_rebuilt_key_survives_lock_and_unlock_through_its_vault
ua-rs|cargo|the_rebuilders_backup_carries_the_key
ua-rs-vectors|cargo|a_held_vault_is_checked_against_its_key_hash
ua-rs|cargo|the_holders_configuration_is_required
pqz-read|cargo|reading_layer_against_anvil
ua-rs|cargo|decoy_arguments
pqz-read|cargo|decoys_against_anvil
wallet-rows|cargo|write_wallet_rows
ua-rs|cargo|wallet_rows_decrypt
ua-rs-vectors|cargo|key_handles_need_the_test_only_marker
ua-rs|cargo|lock_keeps_manifest_drops_secrets
ua-rs|cargo|unlock_reopens_the_vault
ua-rs|cargo|unlock_refuses_a_vault_of_another_wallet
ua-rs|cargo|unlock_with_an_empty_manifest_has_nothing_to_compare
ua-rs|cargo|derive_lock_then_sign_decaps_open_prove_are_KeyRevoked
ua-rs|cargo|unlock_does_not_revive_old_handles
ua-rs|cargo|ua_key_on_locked_wallet_is_WalletLocked
ua-rs|cargo|wallet_dropped_with_children_retained
ua-rs|cargo|concurrent_lock_and_sign
ua-rs-vectors|cargo|lock_returns_only_after_operations_in_flight
ua-rs-vectors|cargo|sign_json_rows_through_an_external_key_equal_the_internal_ones
ua-rs-vectors|cargo|native_rows_through_an_external_key
ua-rs-vectors|cargo|webauthn_rows_through_an_external_passkey
ua-rs-vectors|cargo|a_bad_external_signature_is_ExternalSignature
ua-rs-vectors|cargo|high_s_from_device_normalised
ua-rs|cargo|kem_json_keys
ua-rs|cargo|kem_json_refusals
ua-rs|cargo|kem_json_decaps
ua-rs|cargo|release_encaps_round_trip
ua-rs|cargo|kem_json_encaps_refusals_release
ua-rs|cargo|ephemeral_round_trip
ua-rs|cargo|kem_key_of_wallet_a_handle_is_a_derivation_while_wallet_b_unlocked
ua-rs|cargo|kem_handles_revoked_by_lock
ua-rs-vectors|cargo|kem_json_encaps
ua-rs-vectors|cargo|kem_json_encaps_refusals
ua-rs-vectors|cargo|ek_modulus_check
ua-rs-vectors|cargo|acvp_mlkem_keygen
ua-rs-vectors|cargo|acvp_mlkem_encap_decap
ua-rs-vectors|cargo|rfc7748
ua-rs-vectors|cargo|self_test_runs_once_per_store
ua-rs-vectors|cargo|kem_secret_in_arena
ua-rs|cargo|keys_json_ua_rows
ua-rs|cargo|keys_json_native_rows
ua-rs|cargo|keys_json_refusals_are_argument
ua-rs|cargo|index_1_refused_for_eip2333_kinds
ua-rs|cargo|normalization_rows_nfkd
ua-rs|cargo|mnemonic_refusals_name_no_input
ua-rs|cargo|bounded_json_refuses_depth_9
ua-rs|cargo|lock_revokes_every_handle_and_keeps_the_wallet_locked
ua-rs|cargo|wallet_send_sync
ua-rs|cargo|generate_is_24_words_and_the_backup_forgets
ua-rs-vectors|cargo|keys_json_mnemonic_rows_entropy_and_seed
ua-rs-vectors|cargo|twelve_word_entropy_kept_at_16_bytes
ua-rs-vectors|cargo|mnemonic_is_not_cloned_and_dropped_after_from_mnemonic
ua-rs-vectors|cargo|handle_holds_no_secret_bytes
ua-rs-vectors|cargo|lock_wipes_and_revokes_unlock_never_revives
ua-rs-vectors|cargo|lock_waits_for_an_operation_in_flight
ua-rs-vectors|cargo|bip32_published_vector_1
ua-rs-vectors|cargo|slip10_published_vectors
ua-rs-vectors|cargo|eip2333_published_vectors
ua-rs-vectors|cargo|eip2333_equals_zether_prover_on_the_zether_path
ua-rs-vectors|cargo|hkdf_pq_seed_is_the_ml_dsa_key
ua-rs|cargo|link_seal_then_from_link_installs
ua-rs|cargo|link_seal_with_a_wrong_short_code_is_refused
ua-rs|cargo|link_seal_takes_a_container_key_of_this_wallet
ua-rs|cargo|members_json_holds_64_mldsa87_members_and_no_more
ua-rs-vectors|cargo|link_seal_outside_the_window_is_ContainerReplay
ua-rs-vectors|cargo|link_seal_equals_clientkeys_link_row
ua-rs|cargo|memory_protection_reports_the_arena
ua-rs-vectors|cargo|arena_chunks_locked_and_no_dump
ua-rs|cargo|mlock_refused_never_fails_the_wallet
ua-rs|cargo|sign_json_pairing_rows
ua-rs|cargo|bls_wrong_dst_refusal_rows
ua-rs|cargo|right_message_wrong_dst_refused
ua-rs|cargo|release_randomness_per_kind
ua-rs|cargo|locked_wallet_pairing_handles_sign_nothing
ua-rs|cargo|second_sign_on_a_session_errors
ua-rs|cargo|frost_session_nonce_signs_once
ua-rs-vectors|cargo|sign_json_fixed_aux_rows
ua-rs-vectors|cargo|nonce_map_rows
ua-rs-vectors|cargo|bls_pop_and_sig_through_the_trait
ua-rs-vectors|cargo|fixed_randomness_shapes
ua-rs-vectors|cargo|structural_keygen_g1
ua-rs-vectors|cargo|structural_keygen_g2
ua-rs-vectors|cargo|structural_nonce_point
ua-rs-vectors|cargo|structural_bls_sign
ua-rs-vectors|cargo|structural_musig2_bn254
ua-rs-vectors|cargo|structural_frost_bn254
ua-rs|cargo|pq_kat_keys
ua-rs|cargo|sign_json_pq_rows
ua-rs|cargo|two_release_signatures_differ
ua-rs|cargo|signed_bytes_per_scheme
ua-rs|cargo|locked_wallet_pq_handles_sign_nothing
ua-rs|cargo|rs_signatures_json_rows
ua-rs-vectors|cargo|sign_json_pq_bytes_rows
ua-rs-vectors|cargo|pq_kat_signatures
ua-rs-vectors|cargo|acvp_siggen_rows
ua-rs-vectors|cargo|falcon_fixed_randomness
ua-rs-vectors|cargo|arena_keeps_the_encoded_keys
vectors-check|cargo|vectors::regenerate
vectors-check|cargo|regen::regenerate
ua-rs|cargo|nist_gcm_aes256
ua-rs|cargo|rfc8452_aes256_gcm_siv
ua-rs|cargo|aead_open_refusals
ua-rs|cargo|rfc5869_hkdf_sha256
ua-rs|cargo|rfc4231_hmac_sha256
ua-rs|cargo|seal_json_open
ua-rs|cargo|seal_json_refusals
ua-rs|cargo|seal_json_argument_refusals
ua-rs|cargo|empty_pt_ok
ua-rs|cargo|pt_over_1_MiB_refused
ua-rs|cargo|release_seal_round_trip
ua-rs|cargo|seal_json_containers_open
ua-rs|cargo|seal_json_acceptance
ua-rs|cargo|msig_member_msig_with_own_sig_refused
ua-rs|cargo|msig_sender_without_accepted_refused
ua-rs|cargo|single_key_sender_never_asks_accepted
ua-rs|cargo|approved_set_bounded
ua-rs|cargo|container_json_bounds
ua-rs|cargo|seal_purpose_only_from_the_container_builder
ua-rs|cargo|msig_recipient_refused
ua-rs|cargo|release_link_round_trip
ua-rs-vectors|cargo|seal_json_seal_rows
ua-rs-vectors|cargo|seal_json_containers_rebuilt
ua-rs-vectors|cargo|seal_json_acceptance_link
ua-rs-vectors|cargo|seal_json_replay_link
ua-rs-vectors|cargo|link_session_key_wiped_after_install
ua-rs|cargo|sign_json_ua_rows
ua-rs|cargo|sign_json_member_rows
ua-rs|cargo|chain_separation_rows
ua-rs|cargo|keys_json_native_addresses
ua-rs|cargo|evm_address_is_checksummed
ua-rs|cargo|native_key_proof_and_raw_digest
ua-rs|cargo|purpose_not_in_purposes_refused
ua-rs|cargo|other_kinds_not_signed_here
ua-rs|cargo|bip340_release_aux_is_random
ua-rs|cargo|locked_wallet_handles_sign_nothing
ua-rs|cargo|signer_trait_key_ref
ua-rs-vectors|cargo|role_follows_the_registry_rule
ua-rs-vectors|cargo|kind_no_of_another_kind_refused
ua-rs-vectors|cargo|rfc6979_a25_p256
ua-rs-vectors|cargo|rfc6979_secp256k1_set
ua-rs-vectors|cargo|signatures_json_native_ecdsa
ua-rs-vectors|cargo|sign_raw_refusals
ua-rs|cargo|sign_json_tx_rows_per_type
ua-rs|cargo|eip155_published_row
ua-rs|cargo|sign_json_tx_refusals
ua-rs|cargo|legacy_without_chain_id_refused
ua-rs|cargo|blob_tx_without_hashes_refused_when_built
ua-rs|cargo|chain_separation_tx_rows
ua-rs|cargo|ed25519_native_key_refused
ua-rs|cargo|tx_json_capped_at_16_kib
ua-rs|cargo|typed_ops_json_rows
ua-rs|cargo|portable_json_typed_rows
ua-rs|cargo|sign_json_typed_rows
ua-rs|cargo|unknown_field_refused
ua-rs|cargo|cyclic_types_refused
ua-rs|cargo|negative_int_two_complement
ua-rs|cargo|typed_data_bounds
ua-rs|cargo|eip712_domain_order
ua-rs|cargo|sign_json_canon_rows
ua-rs|cargo|nested_metatransfer_zeroed
ua-rs|cargo|sign_json_policy_rows
ua-rs|cargo|checked_path_refuses_nonzero_unbound_relayer_and_fee_recipient
ua-rs|cargo|unrelated_order_through_any_is_signed_as_supplied
ua-rs|cargo|expect_bounds_and_forms
ua-rs|cargo|chain_separation_typed_digests
ua-rs|cargo|payment_lane_nonce_and_deadline
ua-rs|cargo|op_requires_the_whole_message
ua-rs|cargo|sign_json_msig_rows
ua-rs|cargo|non_minimal_set_refused_at_level_2
ua-rs|cargo|slots_sorted
ua-rs|cargo|portable_json_msig_rows
ua-rs|cargo|nested_json_msig_rows
ua-rs|cargo|pq_signatures_json_treasury
ua-rs|cargo|single_key_uasig_forms
ua-rs|cargo|native_ua_sig_r17
ua-rs|cargo|native_slot_needs_its_typed_data
ua-rs|cargo|slot_must_match_its_member
ua-rs|cargo|vault_json_vaults_open
ua-rs|cargo|vault_json_refusals
ua-rs|cargo|seed_payload_of_31_bytes_refused
ua-rs|cargo|vault_seal_open_round_trip
ua-rs|cargo|rs_vault_json_rows_open
ua-rs|cargo|rewrap_pin_keeps_the_dek
ua-rs|cargo|prf_envelope
ua-rs|cargo|passphrase_policy
ua-rs|cargo|bip39_passphrase_absent_from_every_payload
ua-rs|cargo|imported_key_refused_for_another_family
ua-rs|cargo|label_vaults_import_and_manifest
ua-rs|cargo|manifest_records_first_use_and_survives_lock
ua-rs|cargo|discover_candidates_gap
ua-rs|cargo|seed_backup_shown_once_and_confirmed
ua-rs-vectors|cargo|backup_payload_json
ua-rs|cargo|seal_json_restore_rows
ua-rs|cargo|backup_restores_manifest_and_secrets
ua-rs|cargo|twelve_word_wallet_round_trips_vault_and_backup
ua-rs|cargo|older_backup_over_newer_refused_with_allow_rollback_accepted_equal_is_a_no_op
ua-rs|cargo|backup_signed_by_another_registered_ua_refused
ua-rs|cargo|backup_whose_entropy_does_not_derive_sender_refused
ua-rs-vectors|cargo|link_installs_manifest_and_secrets
ua-rs|cargo|webauthn_challenge_is_ua_msg
ua-rs|cargo|sign_json_accepted_rows
ua-rs|cargo|sign_json_refusals
ua-rs|cargo|challenge_from_the_json_is_never_the_reference
ua-rs|cargo|signatures_json_rows
ua-rs|cargo|portable_json_pop_row
ua-rs|cargo|wrong_type_refused
ua-rs|cargo|non_utf8_client_data_refused
ua-rs|cargo|high_s_normalised
ua-rs|cargo|s_out_of_range_refused_before_normalisation
ua-rs|cargo|assertion_for_another_key_refused
ua-rs|cargo|passkey_signs_through_the_uasig_builder
cargo-zether-prover|cargo|b64url_decodes
cargo-zether-prover|cargo|a_given_key_proves_the_same_bytes_as_the_json_key
cargo-zether-prover|cargo|release_has_no_raw_decrypt
cargo-zether-prover|cargo|hazmat_is_off_by_default
cargo-zether-prover|cargo|hazmat_helpers_are_not_pub
cargo-zether-prover|cargo|a_given_key_refuses_key_reveal_and_witness_fields
cargo-zether-prover|cargo|open_disclosure_gives_the_receiver_and_auditor_openings
cargo-zether-prover|cargo|ct_only_with_hazmat_and_rpc_only_as_a_reading_layer
cargo-zether-prover|cargo|the_holders_cache_box
read-balance|cargo|rpc_reading_layer_against_anvil
cargo-zether-prover|cargo|decoy_arguments
read-balance|cargo|decoys_against_anvil
cargo-zether-prover|cargo|every_x_multiplication_on_a_supplied_point_is_secret_mul
cargo-zether-prover|cargo|layout_is_the_pin_of_the_rows
cargo-zether-prover|cargo|accounts_rebuild_and_decrypt
cargo-zether-prover|cargo|entries_rebuild_and_open_for_the_receiver_and_the_auditor
cargo-zether-prover|cargo|debits_over_rebuilt_words_verify
cargo-zether-prover|cargo|word_location_and_role_negatives_are_refused_before_the_key
cargo-zether-prover|cargo|the_sender_recovers_its_own_entries_from_words
clientkeys|node|pqzKeyVersions: two holders, versions 1 and 2, every set; digests by hand; a member signature over the record; the args
clientkeys|node|verifyPqzKeyVersionRecord accepts every row and refuses a flipped byte, version 0, the other version's consent
clientkeys|node|pqzKeyVersionNegatives: every row by its table, the signature cases by the verifier, the state cases by the builder
clientkeys|node|C8: version 0 keeps the info without a suffix, version v >= 1 appends be64(v); the rows by hand
clientkeys|node|the builder refuses a version-0 replacement, a gap, no version 0, a repeated key; the control passes
clientkeys|node|KV-7: a pending version is the latest of this set's length, not eligible; the decoy filter drops only those
clientkeys|node|F-14: a vault or backup key names (ua, version, pqzKeyHash): two keys at one number stay apart
ua-rs-pq|cargo|pqz_key_version_vectors
ua-rs|cargo|pqz_key_versions_are_the_pq_kat_rows
ua-rs|cargo|key_versions_stale_rule_migration_and_additive_recovery
ua-c|unittest|test_pqz_key_versions_are_the_pq_kat_rows
ua-py|unittest|test_pqz_key_versions
ua-py|unittest|test_pqz_key_versions_are_the_pq_kat_rows
ua-go|go|TestPqzKeyVersions
ua-cs|cs|PqzKeyVersionVectors
ua-cs|cs|PqzKeyVersionsAreThePqKatRows
ua-cxx|ctest|wallet_pqz_key_versions
ua-dart-frb|dart|pqz_key_versions
ua-dart|dart|pqz key versions
ua-rs|cargo|pqz_rollover_is_its_own_op
ua-rs|cargo|trade_order_takes_the_ua_struct
ua-rs|cargo|pay_meta_v2_body_rules
ua-rs|cargo|registry_slots_are_the_layout_pin
ua-rs|cargo|create3_kat_rows
ua-rs|cargo|ua_envelope_through_the_facade
ua-rs|cargo|factory_record_is_the_layout_pin
cargo-zether-prover|cargo|factory_record_is_the_layout_pin
cargo-zether-prover|cargo|registry_slots_are_the_layout_pin
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
