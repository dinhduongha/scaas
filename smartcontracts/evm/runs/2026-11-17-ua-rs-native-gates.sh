#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-rs-native: the gates of branch ua-rs-native (plan 2026-11-17-ua-rs-native T1; Bitcoin P2WPKH / P2TR, NEAR, Polkadot sr25519
# and raw-message signing in ua-rs, the native vectors). Not a copy: it sets the step list, the log prefix, its own steps and test
# names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract, resume, named-tests and summary), as
# 2026-11-07-ua-rs-sign-gates.sh. From the worktree root, foreground, one step per call:
#   smartcontracts/evm/runs/2026-11-17-ua-rs-native-gates.sh [--only <step>]      GATES_FRESH=1 re-runs a step that passed
# Step <s> writes runs/2026-11-17-ua-rs-native-<s>.log (git-ignored); `summary` writes the committed
# 2026-11-17-ua-rs-native-summary.txt. First line "# <s> at commit <sha>", last line "rc=<n>"; a step is skipped when its log ends
# rc=0 at the current commit and the tree is clean apart from runs/. Every step that writes a tracked file (vectors-check,
# test-features' positive control) ends with `git diff --exit-code` (runs/ aside). Heavy commands through scripts/capped, -j2,
# --locked --offline. The round touches wallet/mod.rs and the store, which every facade opens through: every ua-rs cell and every
# binding runs (AGENTS.md: full gates on shared changes). No forge step: no contract and no smartcontracts/vectors/ua change.
# Inputs: clients/clientkeys/node_modules as a real directory; NATIVE_DOWNLOADS (vectors-check): a directory holding the pinned
# downloads of native-vectors.mjs (each read only when its sha256 is the pinned one; the list: runs/2026-11-17-ua-rs-native-t0.md);
# QT (ua-qt, ua-sizes); ANDROID_NDK_HOME (ua-sizes). UNAUDITED.
P=${GATES_P:-2026-11-17-ua-rs-native}
LOGEXT=log # step logs are git-ignored (*.log); only <P>-summary.txt is committed (owner 2026-11-02)
STEPS=${STEPS-"docs clientkeys vectors-check ua-rs-nodefault ua-rs-wallet ua-rs ua-rs-vectors ua-rs-zether ua-rs-pqz no-oracle ua-deny ua-fuzz ua-sizes ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs test-features mutant-logs named-tests summary"}
# the base runner's steps this round runs its own way (the CI cells)
OWN_STEPS="vectors-check ua-rs ua-c ua-dart-frb ua-py ua-go ua-cs"
# named-tests: no log of these may show a test binary with 0 passed or a skipped suite
FAMILIES="clientkeys ua-rs-nodefault ua-rs-wallet ua-rs ua-rs-vectors ua-rs-zether ua-rs-pqz no-oracle ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs"
# the mutant records of this round (one per task that has mutants; extended per task)
MUTANT_RECORDS=${MUTANT_RECORDS-"2026-11-17-ua-rs-native-t2 2026-11-17-ua-rs-native-t3 2026-11-17-ua-rs-native-t4 2026-11-17-ua-rs-native-t5 2026-11-17-ua-rs-native-t6 2026-11-17-ua-rs-native-t6a 2026-11-17-ua-rs-native-t6b 2026-11-17-ua-rs-native-t7 2026-11-17-ua-rs-native-t8a 2026-11-17-ua-rs-native-t8b 2026-11-17-ua-rs-native-t9 2026-11-17-ua-rs-native-t10 2026-11-17-ua-rs-native-t11d 2026-11-17-ua-rs-native-t11e 2026-11-17-ua-rs-native-t11f 2026-11-17-ua-rs-native-t11a 2026-11-17-ua-rs-native-t11b 2026-11-17-ua-rs-native-t11c 2026-11-17-ua-rs-native-t13-c1 2026-11-17-ua-rs-native-t13-c2"}
export CAPPED_MEM=${CAPPED_MEM:-4G} # 4G: capped's own default (the base sets 3G)
C="--locked --offline -j2"

cap() { "$W/scripts/capped" "$@"; }
uars() { # one ua-rs cell as CI runs it: clippy over every target, then the tests. Args: <features> [-- <test selection>]
  local f=(); while [ $# -gt 0 ] && [ "$1" != -- ]; do f+=("$1"); shift; done; [ $# -gt 0 ] && shift
  cd clients/ua-rs && cap cargo clippy $C --all-targets "${f[@]}" -- -D warnings && cap cargo test $C "${f[@]}" "$@"
}
release_ua_c() { cap cargo build --release $C --manifest-path clients/ua-c/Cargo.toml; } # what ua-py, ua-go, ua-cs load
clean() { git diff --exit-code --stat -- . ":(exclude)$R"; } # no tracked file moved (runs/: this runner's own files)

extra_step() { # this branch's own steps (the base runner calls it for a step it does not know, and for OWN_STEPS)
  case $1 in
    # each generator twice (clientkeys first, CLI-UAL-01; then ua-rs's both-ways file rs_native.json); the committed files must not
    # move, and smartcontracts/vectors/ua never moves in this round (spec §12.1)
    vectors-check) : "${NATIVE_DOWNLOADS:?NATIVE_DOWNLOADS: the pinned downloads (see the header)}"
      [ -f clients/clientkeys/scripts/native-vectors.mjs ] || { echo "vectors-check: not yet (native-vectors.mjs, plan T4)"; return 1; }
      local i
      for i in 1 2; do
        (cd clients/clientkeys && NATIVE_DOWNLOADS=$NATIVE_DOWNLOADS cap node scripts/native-vectors.mjs) || return 1
        (cd clients/ua-rs && cap cargo test $C --features vectors --test wallet_native -- --ignored regenerate) || return 1
        clean || return 1
      done
      git diff --exit-code --stat -- smartcontracts/vectors/ua ;;
    # the ua-rs cells of CI (MD-5, T18)
    ua-rs-nodefault) uars --no-default-features ;;
    ua-rs-wallet) uars --no-default-features --features wallet,mlock ;;
    ua-rs) uars ;;
    ua-rs-vectors) uars --features vectors ;;
    ua-rs-zether) uars --no-default-features --features wallet,zether,mlock -- --lib --test facade_zether ;;
    # PQZ without Zether at the committed set (the store's open runs under every facade)
    ua-rs-pqz) uars --no-default-features --features wallet,pqz,pqz-set-n2304-kmax4096,mlock -- --lib --bin pqz-read --test pqz_read \
                 --test facade_pqz_state --test facade_pqz --test facade_pqz_proof --test pqz_backup --test pqz_wallet_rows ;;
    # the oracle harness and the wallet rows at the default set (release cell, then vectors: the positive control)
    no-oracle) (cd clients/ua-rs && cap cargo test $C --test no_oracle --test pqz_wallet_rows &&
                cap cargo test $C --features vectors --test no_oracle --test pqz_wallet_rows) ;;
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
    # (polkadot_path: plan T8b)
    ua-fuzz) local t o bad=0
      cap clients/ua-rs/fuzz/build.sh || return 1
      for t in typed_data expect tx vault manifest container sealed kem_pk mnemonic container_expect members accepted uasig zether_cmd pqz_cmd polkadot_path; do
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
    # the binding's own Rust tests too, which CI's ua-dart-frb job does not run; dart -j 1 (named-tests)
    ua-dart-frb) cd clients/ua-dart-frb && cap sh -c "dart pub get --enforce-lockfile && cargo build $C --manifest-path rust/Cargo.toml &&
        cargo test $C --manifest-path rust/Cargo.toml && dart test -r expanded -j 1" ;;
    ua-py) release_ua_c && cd clients/ua-py && python3 -m unittest -v tests.test_vectors tests.test_wallet ;;
    # -count=1: Go's test cache does not recheck a file outside the module (the shared vectors)
    ua-go) release_ua_c && cd clients/ua-go &&
      cap sh -c 'go vet ./... && LD_LIBRARY_PATH=$PWD/../ua-c/target/release go test -count=1 -v ./...' ;;
    ua-cs) release_ua_c || return 1
      cd clients/ua-cs && cap dotnet test Scaas.Ua.Tests --logger 'console;verbosity=normal'; local rc=$?
      dotnet build-server shutdown > /dev/null 2>&1; return $rc ;; # VBCSCompiler would keep the capped slot
    # no test feature in a production artifact; positive control: ua-c with scaas-ua/vectors forced fails the check
    test-features) local m=clients/ua-c/Cargo.toml r
                   CARGO_NET_OFFLINE=true python3 -I scripts/check_test_features.py || return 1
                   sed -i 's/features = \["json", "wallet"\] }/features = ["json", "wallet", "vectors"] }/' $m
                   CARGO_NET_OFFLINE=true python3 -I scripts/check_test_features.py; r=$?
                   git checkout -q -- $m
                   echo "positive control (scaas-ua/vectors forced in $m): rc=$r (must be 1)"
                   [ $r = 1 ] && clean ;;
    # the round's mutant records: each ends with no survivor, and every harness still applies at this commit (`check`)
    mutant-logs) local t l bad=0
                 for t in $MUTANT_RECORDS; do
                   l=$(tail -n 1 smartcontracts/evm/runs/$t-mutants.txt); echo "$t: $l"
                   grep -Eq ' 0 survived, 0 not loaded$' <<< "$l" || bad=1
                   echo "$t check: $(python3 -I smartcontracts/evm/runs/$t-mutants.py check 2>&1 | tail -n 1)"
                   python3 -I smartcontracts/evm/runs/$t-mutants.py check > /dev/null 2>&1 || bad=1
                 done; [ $bad = 0 ] ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

# "<step>|<form>|<name>": the tests this branch adds (forms: see the base runner), written at T12 from the test definitions the
# diff 87a9608ea..HEAD adds, each under the step whose log shows it passed
NEW_TESTS=$(cat <<'NAMES'
clientkeys|node|NETWORKS stays the nine; NATIVE_NETWORKS is the four, exported by seed-signer too
clientkeys|node|BIP-84 receive and change addresses of abandon ×11 about
clientkeys|node|BIP-86 receive and change addresses, internal key, tweak and output key
clientkeys|node|BIP-341 scriptPubKey[0] (null scriptTree): taprootTweak gives tweak, output key and address
clientkeys|node|Bitcoin coin type: 1 gives tb1…, 0 is the default, 2 refused; change 2 refused; change off Bitcoin refused
clientkeys|node|NEAR: m/44'/397'/i', implicit account id, ed25519:base58 text; no coin-type override
clientkeys|node|polkadot is not derived by deriveKey (it needs the entropy and the passphrase)
clientkeys|node|BIP-143 native P2WPKH: signDigest is RFC 6979 with no extra data, r ‖ s ‖ v
clientkeys|node|BIP-341 keyPathSpending input 0: signDigest on a P2TR key (negate, tweak, BIP-340, aux zero) and verify under x(Q)
clientkeys|node|P2TR keys of the mnemonic sign under their own output key, both y parities of P
clientkeys|node|Bitcoin and NEAR keys: no key proof, no EIP-712, no EVM transaction (Argument); evm and solana keep theirs
clientkeys|node|no import and no imported UA of the four networks (Argument); evm accepted
clientkeys|node|substrate.js loads
clientkeys|node|substrate-bip39 VECTORS: the mini-secret is the first half of PBKDF2(entropy, "mnemonic" ‖ "Substrate")
clientkeys|node|the subkey answers and the junction rows of T0 (hard and soft, 31 / 32 / 63 / 64-byte junctions)
clientkeys|node|the passphrase as given: NFC and NFD give one BIP-39 seed and two Polkadot keys; the mini-secret is not the seed
clientkeys|node|path refusals, each beside its accepted neighbour (Argument)
clientkeys|node|SS58 prefixes: 0, 2, 42, 64 (two-byte form), 16383; 46, 47, 16384 refused
clientkeys|node|Polkadot: no index, no coin type through deriveKey; no key proof, EIP-712 or EVM transaction (Argument)
clientkeys|node|signMessage on the ed25519 networks (1 B to 131,072 B): RFC 8032, deterministic
clientkeys|node|signMessage and signDigest on Polkadot keys verify under @scure/sr25519; fixed randomness is test-only; T0 polkadot.js signature verifies
clientkeys|node|signMessage refusals (Argument), each beside the call accepted
clientkeys|node|native.json is tracked (not git-ignored) and lists the thirteen networks in ua-rs's order
clientkeys|node|native.json addresses: every row re-derived (Bitcoin both chains and coins, NEAR, the bare Polkadot key)
clientkeys|node|native.json polkadotPaths: chain codes and keys of every path
clientkeys|node|native.json signatures: deterministic and fixed-randomness rows byte-equal, verify-only rows verify
clientkeys|node|native.json refusals: each refused (Argument), its accepted neighbour accepted
clientkeys|node|native.json external: BIP-84 / BIP-86 / BIP-143 / BIP-340 / BIP-341 / BIP-350 / substrate-bip39 / subkey / polkadot.js rows
clientkeys|node|signMessage has no first-byte rule: 0x05 and 0x19 0x01 sign on Ed25519 and sr25519 keys (T13 C1)
clientkeys|node|envelope calls: NEAR sha256, Sui intent + blake2b-256, Stellar network id + ENVELOPE_TYPE_TX, Hedera body bytes
clientkeys|node|native.json envelopes rows byte-equal; the appended refusal rows of spec §8.1 are present
clientkeys|node|rs_native.json: every ua-rs Taproot and sr25519 row is of its mnemonic's key and verifies here
ua-rs|cargo|native_json_ed25519_message_rows_byte_equal
ua-rs|cargo|sign_message_bounds_and_envelopes_beside_their_accepted_neighbours
ua-rs|cargo|native_json_sign_message_refusal_rows_of_the_nine
ua-rs|cargo|sign_message_by_a_ua_key_is_refused_a_native_key_accepted
ua-rs|cargo|schemes_and_scheme_kinds_of_the_nine
ua-rs|cargo|errors_name_no_input
ua-rs-vectors|cargo|external_raw_message_answers_are_verified
ua-rs|cargo|native_json_near_addresses_and_signatures
ua-rs|cargo|near_refusals_beside_their_accepted_neighbours
ua-rs|cargo|near_scheme_and_no_scheme_kind
ua-rs|cargo|sign_message_has_no_evm_prefix_rule
ua-rs|cargo|native_json_envelopes_rows_byte_equal
ua-rs|cargo|native_json_envelope_refusal_rows
ua-rs|cargo|native_json_bitcoin_addresses_both_chains_and_coins
ua-rs|cargo|native_json_p2wpkh_signatures_byte_equal_and_bip143
ua-rs|cargo|p2tr_release_signatures_verify_under_the_output_key_and_differ
ua-rs|cargo|bitcoin_refusals_beside_their_accepted_neighbours
ua-rs|cargo|bitcoin_keys_sign_no_evm_record
ua-rs|cargo|manifest_change_written_only_when_one
ua-rs|cargo|native_json_polkadot_bare_addresses_and_ss58
ua-rs-vectors|cargo|native_json_polkadot_mini_secrets
ua-rs|cargo|substrate_known_answers_and_the_passphrase_as_given
ua-rs|cargo|polkadot_refusals_beside_their_accepted_neighbours
ua-rs|cargo|polkadot_signatures_verify_and_differ_the_polkadot_js_row_verifies
ua-rs|cargo|polkadot_handle_after_lock_is_key_revoked
ua-rs|cargo|native_json_polkadot_paths_rows
ua-rs|cargo|native_json_polkadot_key_refusal_rows
ua-rs|cargo|soft_keys_sign_and_verify
ua-rs|cargo|manifest_polkadot_paths_written_only_when_not_empty_bounded_on_read
ua-rs|cargo|a_65th_path_is_refused
ua-rs|cargo|junction_handle_after_lock_is_key_revoked
ua-rs|cargo|network_list_is_native_json_networks
ua-rs-vectors|cargo|native_json_p2tr_fixed_aux_rows_byte_equal
ua-rs-vectors|cargo|bip341_key_path_spending_null_merkle_root
ua-rs-vectors|cargo|taproot_self_check_refuses_a_fault_beside_the_right_key
ua-rs-vectors|cargo|bip340_csv_signing_rows_through_sign_raw
ua-rs-vectors|cargo|native_json_sr25519_fixed_rows_byte_equal_one_read_each
ua-rs-vectors|cargo|a_failing_os_rng_is_error_rng_never_a_panic
ua-rs-vectors|cargo|sr25519_self_verify_refuses_a_wrong_public_key_beside_the_right_one
ua-rs-vectors|cargo|polkadot_slot_in_the_arena
ua-rs-vectors|cargo|polkadot_path_past_512_bytes_is_refused
ua-rs|cargo|one_shot_yields_once
ua-c|unittest|test_networks_and_feature_bit
ua-c|unittest|test_addresses_witness_programs_ss58
ua-c|unittest|test_polkadot_paths
ua-c|unittest|test_deterministic_signature_and_envelope_rows
ua-c|unittest|test_refusal_rows_of_the_c_surface
ua-py|unittest|test_networks_and_load_needs_bit_native_networks
ua-py|unittest|test_addresses_witness_programs_ss58
ua-py|unittest|test_polkadot_paths
ua-py|unittest|test_deterministic_rows
ua-py|unittest|test_refusal_rows
ua-py|unittest|test_ua_key_has_no_raw_message_or_envelope_call
ua-go|go|TestNativeNetworksAndAddresses
ua-go|go|TestNativeDeterministicRowsAndRefusals
ua-cs|cs|NativeNetworksAddressesAndPaths
ua-cs|cs|NativeDeterministicRowsAndRefusals
ua-cxx|ctest|wallet_native_json
ua-qt|qt|test_native_addresses_witness_programs_ss58
ua-dart-frb|dart|native.json: networks, addresses, witness programs, SS58, polkadotPaths
ua-dart-frb|dart|native.json: deterministic rows, refusals, a UA key refused
clientkeys|node|signDigest refuses anything but 32 bytes on every scheme, beside 32 bytes accepted (T13 C2)
ua-rs|cargo|native_json_sign_digest_rows_are_32_bytes_by_type
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
