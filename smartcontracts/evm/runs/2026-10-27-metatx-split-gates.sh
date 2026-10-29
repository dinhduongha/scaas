#!/bin/bash
# metatx-split Task 20: the closing gates over every family, one resumable step per log (owner 2026-10-27:
# affected steps only, no full pqz-core gate). Modelled on 2026-10-27-review2-gates.sh.
#   2026-10-27-metatx-split-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-27-metatx-split-<s>.txt: first line "# <s> at commit <sha>", last line "rc=<n>".
# A step is skipped when its log ends rc=0 at the current commit (git rev-parse --short HEAD) and the tree is clean.
# "Clean" ignores smartcontracts/evm/runs/ (the logs this script writes); every other change, untracked files included, counts.
# Stops at the first failure. After a run, commit the logs (HEAD changes) and do not re-run.
# named-tests reads the step logs from NAMED_TESTS_LOG_DIR (default runs/; the guard self-check points it at a scratch copy).
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W" || exit 2
R=smartcontracts/evm/runs
P=2026-10-27-metatx-split
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 sizes gen-set docs cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node clientkeys ua-rs ua-qt ua-py ua-go ua-cs ua-c ua-cxx ua-dart soroban solana cosmos sui aptos ton near algorand e2e-near e2e-algorand named-tests"
FAMILIES="soroban solana cosmos sui aptos ton near algorand e2e-near e2e-algorand"
QT=/home/ha/usr/Qt/6.12.0/gcc_64
export CAPPED_SLOTS=${CAPPED_SLOTS:-2} CAPPED_MEM=${CAPPED_MEM:-3G}

run_step() { # the command of one step (runs in a subshell, rc = the step's rc)
  case $1 in
    forge-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#forge-}" test ;;
    sizes) cd smartcontracts/evm || return 1
      j=$(mktemp) && ../../scripts/capped forge build src --sizes --json > "$j" &&
        python3 -I ../../scripts/size_gate.py "$j" size-baseline.json; rc=$?; rm -f "$j"; return $rc ;;
    gen-set) python3 -I pqz-core/params/sets/gen_set.py --all --check ;;
    docs) python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check &&
      { python3 scripts/docs_check.py facts check | tail -n 12; true; } ;; # facts: logged only (as review2)
    cargo-zether-prover) cd clients/zether-prover && ../../scripts/capped cargo test -j2 ;;
    wasm-zether-prover) cd clients/zether-prover && ../../scripts/capped cargo build -j2 --release --bin zether-cli &&
      ../../scripts/capped cargo build -j2 --release --lib --target wasm32-unknown-unknown &&
      ~/.cargo/bin/wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/release/zether_prover.wasm &&
      node smoke/smoke.cjs ;;
    zether-cross) # the CLI-vs-contract cross-check; a skipped test (no CLI / no --ffi) must FAIL the step
      (cd clients/zether-prover && ../../scripts/capped cargo build -j2 --release --bin zether-cli) || return 1
      cd smartcontracts/evm || return 1
      o=$(mktemp); ZETHER_CLI="$W/clients/zether-prover/target/release/zether-cli" ../../scripts/capped forge test --ffi \
        --match-path test/zether/ZetherProverCross.t.sol 2>&1 | tee "$o"; rc=${PIPESTATUS[0]}
      [ $rc -eq 0 ] && grep -q "6 passed; 0 failed; 0 skipped" "$o" || { echo "zether-cross: not 6 passed / 0 skipped"; rc=1; }
      rm -f "$o"; return $rc ;;
    cargo-scaas-node) cd scaas-node && ../scripts/capped cargo test -j2 ;;
    clientkeys) cd clients/clientkeys && ../../scripts/capped npm test ;;
    ua-rs) cd clients/ua-rs && ../../scripts/capped cargo test -j2 ;;
    ua-qt) # as Task 18; build/ is git-ignored; ctest -V prints QtQuickTest's per-function PASS lines for named-tests
      QMAKE=$QT/bin/qmake6 LD_LIBRARY_PATH=$QT/lib QT_QPA_PLATFORM=offscreen scripts/capped sh -c \
        "cmake -S clients/ua-qt -B clients/ua-qt/build -DCMAKE_PREFIX_PATH=$QT && cmake --build clients/ua-qt/build -j2 &&
         cd clients/ua-qt/build && ctest -V --output-on-failure" ;;
    # near-algorand T22: the UA reproducers of Task 2 (commands: the ci.yml header), NEAR / Algorand, their node e2e
    ua-py) cd clients/ua-py && python3 -m unittest -v tests.test_vectors ;;
    ua-go) cd clients/ua-go && ../../scripts/capped sh -c 'go vet ./... && go test ./...' ;;
    ua-cs) cd clients/ua-cs && ../../scripts/capped dotnet test Scaas.Ua.Tests; rc=$?
      dotnet build-server shutdown >/dev/null 2>&1; return $rc ;; # VBCSCompiler would keep the capped slot
    ua-c) cd clients/ua-c && ../../scripts/capped sh -c 'cargo clippy -j2 --locked --all-targets -- -D warnings &&
        cargo build -j2 --locked && cargo test -j2 --locked &&
        cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/smoke.c target/debug/libscaas_ua_c.a -lpthread -ldl -lm -o target/smoke &&
        target/smoke && c++ -fsyntax-only -x c++ include/scaas_ua.h' && python3 -m unittest -v tests.test_vectors ;;
    ua-cxx) cd clients/ua-cxx && ../../scripts/capped sh -c 'cargo clippy -j2 --locked --all-targets -- -D warnings &&
        cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DSCAAS_UA_CARGO_TARGET_DIR=$PWD/target &&
        cmake --build build -j2 && ctest --test-dir build --output-on-failure' ;;
    ua-dart) cd clients/ua-dart && ../../scripts/capped sh -c 'dart pub get && dart analyze && dart test && dart test -p node &&
        dart run test/vectors_test.dart' ;;
    soroban|solana|cosmos|sui|aptos|ton|near) CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh "$1" ;;
    # -rA: pytest's summary lists every "PASSED tests/<file>::<test>" for named-tests (the suite runs -q -s)
    algorand) PYTEST_ADDOPTS=-rA scripts/capped smartcontracts/scripts/test.sh algorand ;;
    # starts near-sandbox itself (the binary near-workspaces fetched for the near step) and stops it with the test
    e2e-near) cd scaas-node && ../scripts/capped cargo test -j2 --test e2e_near -- --ignored ;;
    e2e-algorand) smartcontracts/algorand/scripts/e2e.sh ;; # a fresh localnet up (capped), e2e, down on any exit
    named-tests) named_tests ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

# The new tests of the plan (Tasks 1-18), "<step>|<form>|<name>", and the pass line each must show in that step's log:
#   forge  "[PASS] <name>(" in at least one forge-* log
#   cargo  "test [<path>::]<name> ... ok"; a "::" in <name> may span module path segments
#   move   "[ PASS    ] <addr>::<module>::<name>"
#   jest   "✓ <name>"     node "✔ <name>"     qt "PASS   : <TestCase>::<name>()"
#   pytest "PASSED tests/<file>::<name>[<id>]" (-rA summary)   unittest "<name> (<class>) ... ok"
# (the plan's test names, as the tasks built them: git diff of the test functions, merge-base..T19;
#  near-algorand T22: the same for merge-base..T21, plus the existing tests its briefs name; final fix wave: its new
#  tests; node-ua-jobs (EVM `ua_metatx` jobs, 2026-10-30) and its fix 1: their unit tests, last block)
NEW_TESTS=$(cat <<'EOF'
forge|forge|test_parity
forge|forge|test_isValid_7702_ctrUa24
forge|forge|test_isValid_7702_badDelegates
forge|forge|test_ruleTableParity
forge|forge|test_preCall_orderAddressPath
forge|forge|test_preCall_orderUaPath
forge|forge|test_preCall_writesOnlyTheNonceSlot
forge|forge|test_preTransfer_matchesTodayOrder
forge|forge|test_directCallReverts
forge|forge|test_addressPath_refusesDerivedFrom
forge|forge|test_digestsEqualMetaTxLib
forge|forge|test_ctxEqualsTokenViews
forge|forge|test_digestViewsEqualKats
forge|forge|test_relayedCall_writesRecordedSlots
forge|forge|test_minGas_smartKeyAccountMtxExecute
forge|forge|test_minGas_mldsa65UaExecute
forge|forge|test_hedera_hip632CallerIsToken
forge|forge|test_libraryErrorsAreInTheTokenAbi
forge|forge|test_splitOverhead_dataSizeBound
forge|forge|test_envLibsEqualLinkClosure
forge|forge|test_libraryOpcodes
forge|forge|test_payMeta_settlesLikeMtxPay
forge|forge|test_uaPayMeta_settlesLikeUaPay
forge|forge|test_payMeta_mismatchAndReplayRefused
forge|forge|test_payMeta_requiresPayable
forge|forge|test_payMetaVectors
forge|forge|test_relayRef_formula
forge|forge|test_relayRefVectors
forge|forge|test_relay_boundToCall
forge|forge|test_routerBoundPayment_refusedOutsideRouter
forge|forge|test_relay_callDataIsAnotherRouterPayment
forge|forge|test_relay_innerRevertBubbles
forge|forge|test_relay_payOnce
forge|forge|test_relay_openModePaysCaller
forge|forge|test_relay_boundPayee
forge|forge|test_uaRelay_mldsa65Payer
forge|forge|test_relay_reentryRefused
forge|forge|test_relay_shapeRefused
forge|forge|test_relay_targetNoCode_counterfactual
forge|forge|test_relay_payeeExecutorRefused
forge|forge|test_relay_paymentFailureRollsBackCall
forge|forge|test_executor_onlyRouter
forge|forge|test_router_holdsNothingAfterOpenMode
forge|forge|test_relay_targetEnvelopeBoundToExecutor
forge|forge|test_relayGas_ecdsaAndMldsa65
forge|forge|test_deployBase_relayFee
soroban|cargo|pay_meta_vectors_match
soroban|cargo|pay_meta_settles_and_emits_meta_first
soroban|cargo|soroban_pay_meta_mismatch_and_replay
soroban|cargo|pay_ref_is_per_payer_nobody_can_pre_burn_it
soroban|cargo|relay_open_mode_pays_relayer
soroban|cargo|relay_bound_payee
soroban|cargo|relay_same_call_with_different_salts_and_replay
soroban|cargo|relay_attacker_cannot_pre_burn_the_ref
soroban|cargo|relay_target_failure_reverts_all
soroban|cargo|relay_refuses_target_without_contract
soroban|cargo|soroban_router_bound_pay_refused_direct
soroban|cargo|relay_ref_vectors
soroban|cargo|relay_g_account_payer_real_signed_entries
solana|cargo|pay_meta_vectors_match
solana|cargo|pay_meta_emits_meta_then_settled
solana|cargo|solana_pay_meta_mismatch_and_replay
solana|cargo|pay_meta_id_is_per_payer
solana|cargo|relay_pay_pdas_are_checked_in_the_body
solana|cargo|relay_ref_vectors
solana|cargo|relay_fee_open_mode_pays_lane
solana|cargo|relay_fee_bound_payee
solana|cargo|relay_fee_target_failure_reverts
solana|cargo|relay_fee_self_target_refused
solana|cargo|relay_fee_indirect_reentry_refused
solana|cargo|relay_fee_target_must_be_executable
solana|cargo|relay_fee_shape_refused
solana|cargo|solana_router_bound_pay_refused_direct
solana|cargo|relay_fee_ref_is_per_payer
solana|cargo|relay_fee_relayer_must_sign
solana|cargo|adapter_ix_data_vectors
solana|cargo|relay_fee_target_signer_refused
solana|cargo|wrapper_settles_and_pays
solana|cargo|wrapper_bound_payee
solana|cargo|wrapper_inner_failure_leaves_no_payment
solana|cargo|wrapper_payment_failure_rolls_back_the_call
solana|cargo|wrapper_router_bound_pay_refused_direct
solana|cargo|wrapper_ref_vectors
solana|cargo|wrapper_noop_refused_payer_not_charged
solana|cargo|guardian_recovery_waits_and_can_be_cancelled
solana|cargo|recovery_refuses_a_present_key
solana|cargo|recovery_refuses_a_full_set
solana|cargo|wrapper_any_lane_may_submit
solana|cargo|wrapper_other_instance_refused
cosmos|cargo|pay_meta_vectors_match
cosmos|cargo|pay_meta_emits_meta_then_settled
cosmos|cargo|cosmos_pay_meta_mismatch_and_replay
cosmos|cargo|relay_fee_open_mode_pays_sender
cosmos|cargo|relay_fee_bound_payee
cosmos|cargo|relay_fee_target_failure_reverts_all
cosmos|cargo|relay_fee_target_sees_executor
cosmos|cargo|relayexec_only_router
cosmos|cargo|cosmos_router_bound_pay_refused_direct
cosmos|cargo|relay_ref_vectors
cosmos|cargo|relay_fee_target_must_be_contract
cosmos|cargo|relay_fee_shape_refusals
cosmos|cargo|relay_fee_attacker_cannot_pre_burn_ref
cosmos|cargo|relay_fee_reentry_refused
cosmos|cargo|relay_fee_router_with_admin_refused
cosmos|cargo|relay_fee_target_is_router_refused
cosmos|cargo|relay_fee_passkey_payer
sui|move|meta_tests::pay_meta_vectors_match
sui|move|meta_tests::pay_meta_salt_is_32_bytes
sui|move|meta_tests::pay_meta_emits_meta_then_settled
sui|move|meta_tests::pay_meta_and_plain_pay_share_one_lane
sui|move|meta_tests::sui_pay_meta_mismatch_and_replay
sui|move|meta_tests::sui_pay_meta_mismatch_salt
sui|move|meta_tests::sui_pay_meta_replay
sui|move|meta_tests::pay_meta_once_set_is_per_payer
sui|move|relayfee_tests::relay_ref_vectors
sui|move|relayfee_tests::marker_is_the_relay_fee_object
sui|move|relayfee_tests::relay_open_mode_pays_sender
sui|move|relayfee_tests::relay_revoke_pays_bound_payee
sui|move|relayfee_tests::relay_cancel_succeeds
sui|move|relayfee_tests::relay_invalidate_nonces_succeeds
sui|move|relayfee_tests::relay_target_abort_aborts_all
sui|move|relayfee_tests::relay_revoke_target_abort_aborts_all
sui|move|relayfee_tests::relay_cancel_target_refused_aborts_all
sui|move|relayfee_tests::relay_nonces_target_abort_aborts_all
sui|move|relayfee_tests::relay_payment_abort_aborts_manage
sui|move|relayfee_tests::relay_payment_abort_aborts_revoke
sui|move|relayfee_tests::relay_payment_abort_aborts_cancel
sui|move|relayfee_tests::relay_payment_abort_aborts_nonces
sui|move|relayfee_tests::sui_router_bound_pay_refused_direct
sui|move|relayfee_tests::sui_router_bound_pay_meta_refused_direct
sui|move|relayfee_tests::relay_payment_does_not_cross_wrappers
sui|move|relayfee_tests::relay_same_ref_pays_once
aptos|move|meta_tests::pay_meta_vectors_match
aptos|move|meta_tests::pay_meta_settles_with_its_event
aptos|move|meta_tests::pay_meta_check_matches_relay_pay_meta
aptos|move|meta_tests::pay_meta_check_refuses_another_meta
aptos|move|meta_tests::aptos_pay_meta_mismatch_and_replay
aptos|move|meta_tests::aptos_pay_meta_mismatch_salt
aptos|move|meta_tests::aptos_pay_meta_replay
aptos|move|meta_tests::aptos_pay_meta_then_plain_pay_refused
aptos|move|meta_tests::pay_meta_salt_is_32_bytes
aptos|move|meta_tests::pay_meta_once_set_is_per_payer
aptos|move|meta_tests::aptos_router_bound_pay_meta_refused_direct
aptos|move|relayfee_tests::relay_ref_vectors
aptos|move|relayfee_tests::relay_ref_binds_the_chain
aptos|move|relayfee_tests::marker_is_the_derived_address
aptos|move|relayfee_tests::relay_open_mode_pays_lane
aptos|move|relayfee_tests::relay_mandate_open_succeeds
aptos|move|relayfee_tests::relay_revoke_pays_bound_payee
aptos|move|relayfee_tests::relay_cancel_succeeds
aptos|move|relayfee_tests::relay_invalidate_nonces_succeeds
aptos|move|relayfee_tests::relay_paid_by_another_payer
aptos|move|relayfee_tests::relay_target_abort_aborts_all
aptos|move|relayfee_tests::relay_open_target_abort_aborts_all
aptos|move|relayfee_tests::relay_revoke_target_abort_aborts_all
aptos|move|relayfee_tests::relay_cancel_target_refused_aborts_all
aptos|move|relayfee_tests::relay_nonces_target_abort_aborts_all
aptos|move|relayfee_tests::relay_payment_abort_aborts_manage
aptos|move|relayfee_tests::relay_payment_abort_aborts_open
aptos|move|relayfee_tests::relay_payment_abort_aborts_revoke
aptos|move|relayfee_tests::relay_payment_abort_aborts_cancel
aptos|move|relayfee_tests::relay_payment_abort_aborts_nonces
aptos|move|relayfee_tests::aptos_router_bound_pay_refused_direct
aptos|move|relayfee_tests::relay_payment_does_not_cross_wrappers
aptos|move|relayfee_tests::relay_payment_does_not_cross_instances
aptos|move|relayfee_tests::relay_same_ref_pays_once
aptos|move|relayfee_tests::relay_preburn_by_another_payer_does_not_block
ton|jest|a signed revoke runs once in either form: a resend is refused and sends no cancel (NET-TON-18, T16 fix 2)
ton|jest|pay with params emits PaymentMeta then PaymentSettled
ton|jest|ton pay meta mismatch and replay
ton|jest|an attacker's minimal pre-burn of the victim's payId does not block the victim (per payer)
ton|jest|pay without params unchanged
ton|jest|meta size limit: measured through a W5R1 lane
ton|jest|release on the served entry's acknowledgment, before the probe's bounce
ton|jest|the Mandate's owner revoke is the other served entry: released on its ack
ton|jest|a revoke of an order already sent: its forward TON is in the call's floor, its late cancel excess goes to the relayer
ton|jest|a revoke replayed after it ran is refused: the escrow is refunded, no second cancel (T16 fix 2)
ton|jest|a copied RelayCall after the release names its own relayer in the refund event (node attribution)
ton|jest|refund on call bounce: payer refunded, nothing to the relayer
ton|jest|refund when the target does not exist: a served code at an address with no account bounces (rule 5)
ton|jest|executor: an action-phase failure sends no ack and is refunded; an ack is released; the start-value edge
ton|jest|refund by RelayRefund after deadline, refused before or below the settle TON; permissionless
ton|jest|release and refund are exclusive
ton|jest|a settlement transfer that bounces restores the escrow; RelayRefund sends it again (important 3)
ton|jest|second RelayCall for a pending (payer, ref) refused; another payer on the same target is not blocked
ton|jest|an attacker cannot pre-burn the victim's ref: the call names the victim's executor (per payer)
ton|jest|payment bounce clears pending
ton|jest|ton router bound pay refused direct
ton|jest|call that is a SignedOp naming the router refused
ton|jest|notification from a foreign jetton wallet ignored; a stray payment is handed back
ton|jest|target, shape, deadline and value refusals (exact exit codes)
ton|jest|relay ref vectors: every ref of the call is hashed, and the salt and target
ton|jest|metaPayId and payLane of every paymeta.json row
cargo-scaas-node|cargo|adapter::one_kind_rule_and_one_payee_rule
cargo-scaas-node|cargo|aptos::aptos_indexer_joins_pay_meta_and_relay_fee
cargo-scaas-node|cargo|aptos::aptos_pay_meta_payload_bytes
cargo-scaas-node|cargo|aptos::aptos_relay_fee_job_checks_ref
cargo-scaas-node|cargo|aptos::plain_pay_to_the_marker_is_refused
cargo-scaas-node|cargo|aptos::unknown_job_kind_is_refused
cargo-scaas-node|cargo|aptos::relay_fee_config_must_parse
cargo-scaas-node|cargo|aptos::relay_fee_and_pay_meta_jobs_never_panic
cargo-scaas-node|cargo|cosmos::cosmos_indexer_joins_pay_meta_and_relay_fee
cargo-scaas-node|cargo|cosmos::cosmos_pay_meta_job_builds_msg
cargo-scaas-node|cargo|cosmos::cosmos_relay_fee_job_checks_ref
cargo-scaas-node|cargo|cosmos::cosmos_kind_rule_and_never_pay_router_or_executor
cargo-scaas-node|cargo|cosmos::cosmos_executor_is_lazy_and_never_stalls_plain_pays
cargo-scaas-node|cargo|cosmos::cosmos_relay_fee_policy_config
cargo-scaas-node|cargo|cosmos::cosmos_jobs_never_panic
cargo-scaas-node|cargo|hedera::the_hedera_lane_keeps_the_job_kind_rule
cargo-scaas-node|cargo|solana::relay_fee_router_config_must_parse
cargo-scaas-node|cargo|solana::solana_relay_fee_covers_first_use_rent
cargo-scaas-node|cargo|solana::solana_indexer_joins_pay_meta_and_relay_fee
cargo-scaas-node|cargo|solana::solana_pay_meta_job_builds_ix
cargo-scaas-node|cargo|solana::solana_relay_fee_job_checks_ref
cargo-scaas-node|cargo|solana::solana_relay_fee_wrapper_job_builds_ix
cargo-scaas-node|cargo|solana::wrapper_jobs_never_panic
cargo-scaas-node|cargo|solana::jobs_never_panic_on_untrusted_input
cargo-scaas-node|cargo|soroban::soroban_indexer_joins_pay_meta_and_relay_fee
cargo-scaas-node|cargo|soroban::soroban_pay_meta_job_builds_pay_meta
cargo-scaas-node|cargo|soroban::soroban_kind_router_and_payee_rules
cargo-scaas-node|cargo|soroban::soroban_relay_fee_job_checks_ref
cargo-scaas-node|cargo|soroban::relay_fee_job_survives_non_utf8_symbol
cargo-scaas-node|cargo|soroban::jobs_never_panic_on_untrusted_input
cargo-scaas-node|cargo|sui::sui_pay_meta_job_builds_ptb
cargo-scaas-node|cargo|sui::sui_relay_fee_job_checks_ref
cargo-scaas-node|cargo|sui::plain_pay_to_the_marker_is_refused
cargo-scaas-node|cargo|sui::unknown_job_kind_is_refused
cargo-scaas-node|cargo|sui::malformed_token_is_a_startup_error
cargo-scaas-node|cargo|sui::sui_indexer_joins_pay_meta_and_relay_fee
cargo-scaas-node|cargo|sui::relay_fee_config_must_parse
cargo-scaas-node|cargo|sui::relay_fee_and_pay_meta_jobs_never_panic
cargo-scaas-node|cargo|ton::ton_indexer_joins_payment_meta_by_payer
cargo-scaas-node|cargo|ton::ton_pay_meta_job_builds_params
cargo-scaas-node|cargo|ton::ton_relay_fee_vectors
cargo-scaas-node|cargo|ton::ton_relay_fee_job_checks_ref
cargo-scaas-node|cargo|ton::ton_plain_pay_to_router_refused
cargo-scaas-node|cargo|ton::ton_relay_fee_policy_config
cargo-scaas-node|cargo|ton::ton_relay_fee_event_vectors
cargo-scaas-node|cargo|ton::ton_relay_fee_job_tracks_escrow
cargo-scaas-node|cargo|ton::ton_relay_fee_refunds_after_deadline
cargo-scaas-node|cargo|ton::ton_relay_fee_refuses_failing_call_before_send
cargo-scaas-node|cargo|ton::ton_relay_fee_refuses_failing_payment_before_send
cargo-scaas-node|cargo|venue::a_7702_maker_signs_with_its_key_or_its_delegate
cargo-scaas-node|cargo|ton::pay_meta_job_never_panics
cargo-scaas-node|cargo|ton::relay_fee_job_never_panics
cargo-scaas-node|cargo|config::relay_params_default_and_refuse_invalid_values
cargo-scaas-node|cargo|config::the_ton_meta_journal_lives_in_the_store_dir
cargo-scaas-node|cargo|guard::erc1271_floor_covers_forge_minimum
cargo-scaas-node|cargo|indexer::indexer_joins_payment_meta
cargo-scaas-node|cargo|submit::pay_meta_job_checks_commitment_lane_nonce
cargo-scaas-node|cargo|submit::pay_meta_cap_refused
cargo-scaas-node|cargo|submit::relay_fee_row_requires_router_and_registered_token
cargo-scaas-node|cargo|submit::relay_fee_submits_only_when_fee_covers_gas
clientkeys|node|paymeta vectors
clientkeys|node|decodeMeta refuses a non-canonical envelope or an unknown schema
clientkeys|node|refuses a payId that does not commit to meta
clientkeys|node|mtxPayMeta: the payment is mtxPay with payId = metaPayId(salt, meta), lane payLane, nonce 0
clientkeys|node|uaPayMeta: UAMetaTransfer between ids, uaPayMeta / uaPay calldata
clientkeys|node|checkPayMeta: server typed data for the committed payId passes and returns the decoded meta
clientkeys|node|relayRef matches the contract vector
clientkeys|node|buildRelayFee: open mode by default, one prompt with both intents, the router-bound payment
clientkeys|node|buildRelayFee: an open inner envelope stays open; a bound payee; the UA path
clientkeys|node|mtxExecuteCalldata: the signed call the payment commits to
clientkeys|node|buildRelayFee refuses to pay the executor, an inner envelope bound elsewhere or on another contract
clientkeys|node|buildRelayFee refuses an inner call on another chain or outliving its payment, a zero or token payee
ua-rs|cargo|meta_pay_id_vectors
ua-rs|cargo|relay_ref_matches_vector
ua-qt|qt|test_meta_pay_id_vectors
ua-qt|qt|test_relay_ref_matches_vector
clientkeys|node|algorand vectors
clientkeys|node|algorand addresses and app addresses
clientkeys|node|algorand relay refs, lanes and router call
clientkeys|node|algorand passkey assertion
clientkeys|node|refuses pay-meta mismatch
clientkeys|node|relay fee prompt carries both intents
clientkeys|node|pay-meta and relay-fee payments need nonce 0
clientkeys|node|passkeyAssertion refuses a wrong challenge
clientkeys|node|refuses native send to a UA id
clientkeys|node|near vectors
clientkeys|node|near relay refs, lanes and call forms
clientkeys|node|near native ids
clientkeys|node|near passkey assertion: low-s normalised, challenge = digest
clientkeys|node|near key op fans out to every held token, each at its own nonce
clientkeys|node|passkeyAssertion refuses a wrong challenge, type or invalid UTF-8
clientkeys|node|passkeyAssertion output verifies as P-256 over authenticatorData || sha256(clientDataJSON)
ua-qt|qt|test_near_digest_and_relay_ref
ua-qt|qt|test_algorand_digest_and_relay_ref
ua-rs|cargo|near_vectors
ua-rs|cargo|algorand_vectors
cargo-scaas-node|cargo|algorand::algorand_metaop_decode_vectors
cargo-scaas-node|cargo|algorand::algorand_pay_meta_job_checks_commitment
cargo-scaas-node|cargo|algorand::algorand_relay_fee_job_checks_ref
cargo-scaas-node|cargo|algorand::relay_fee_target_app_missing_or_clearstate_refused
cargo-scaas-node|cargo|algorand::group_has_exact_mbr_payment_and_budget_calls
cargo-scaas-node|cargo|algorand::discovery_simulate_has_the_budget_the_group_can_gain
cargo-scaas-node|cargo|algorand::budget_calls_added_as_simulate_reports
cargo-scaas-node|cargo|algorand::lane_below_min_balance_is_retried
cargo-scaas-node|cargo|algorand::executor_address_matches_contract
cargo-scaas-node|cargo|algorand::start_check_approval_hash_mismatch_halts
cargo-scaas-node|cargo|algorand::start_check_genesis_mismatch_errors
cargo-scaas-node|cargo|algorand::start_check_lane_below_min_balance_errors
cargo-scaas-node|cargo|algorand::algorand_last_valid_within_valid_until
cargo-scaas-node|cargo|algorand::unknown_job_kind_is_refused
cargo-scaas-node|cargo|algorand::tx_matches_algosdk
cargo-scaas-node|cargo|algorand::relay_fee_config_must_parse
cargo-scaas-node|cargo|algorand::quote_covers_fees_and_mbr
cargo-scaas-node|cargo|algorand::relay_fee_target_static_checks
cargo-scaas-node|cargo|algorand::deep_inner_block_decodes_at_protocol_depth
cargo-scaas-node|cargo|algorand::msgpack_depth_bound
cargo-scaas-node|cargo|algorand::origin_parity_vectors
cargo-scaas-node|cargo|algorand::no_measured_round_time_refuses
cargo-scaas-node|cargo|algorand::spent_entries_end_with_the_group
cargo-scaas-node|cargo|algorand::same_box_is_paid_once
cargo-scaas-node|cargo|algorand::target_mbr_per_entry
cargo-scaas-node|cargo|algorand::sponsored_bound_payee_is_built_unpriced
cargo-scaas-node|cargo|algorand::algorand_events_book_configured_only_and_join
cargo-scaas-node|cargo|algorand::events_scan_blocks_and_pruned_rounds_error
cargo-scaas-node|cargo|algorand::submit_and_status_are_classified
cargo-scaas-node|cargo|algorand::op_consumed_reads_the_lane_box
cargo-scaas-node|cargo|algorand::algorand_jobs_never_panic
cargo-scaas-node|cargo|near::near_metaop_decode_vectors
cargo-scaas-node|cargo|near::tx_matches_near_primitives
cargo-scaas-node|cargo|near::near_pay_meta_job_checks_commitment
cargo-scaas-node|cargo|near::near_relay_fee_job_checks_ref
cargo-scaas-node|cargo|near::relay_fee_target_router_or_executor_refused
cargo-scaas-node|cargo|near::unknown_job_kind_is_refused
cargo-scaas-node|cargo|near::signature_budgets
cargo-scaas-node|cargo|near::relay_fee_config_must_parse
cargo-scaas-node|cargo|near::relay_fee_target_without_code_refused
cargo-scaas-node|cargo|near::quote_covers_gas_and_storage_needed
cargo-scaas-node|cargo|near::action_fees_and_timeout_are_priced
cargo-scaas-node|cargo|near::deposit_equals_storage_needed_plus_nep_yocto
cargo-scaas-node|cargo|near::near_amount_above_2_pow_53_round_trips
cargo-scaas-node|cargo|near::start_check_genesis_mismatch_errors
cargo-scaas-node|cargo|near::start_check_access_key_present_halts
cargo-scaas-node|cargo|near::start_check_lane_unregistered_errors
cargo-scaas-node|cargo|near::escrow_tracking_times_out_after_deadline
cargo-scaas-node|cargo|near::submit_errors_are_classified
cargo-scaas-node|cargo|near::action_fees_read_from_the_rpc
cargo-scaas-node|cargo|near::quote_is_prepaid_fees_and_resend
cargo-scaas-node|cargo|near::implicit_transfer_pin_checked
cargo-scaas-node|cargo|near::submit_waits_until_included
cargo-scaas-node|cargo|near::escrow_in_flight_times_out_after_deadline
cargo-scaas-node|cargo|near::near_events_success_only_configured
cargo-scaas-node|cargo|near::near_events_join_meta_relay_fee_and_mandate
cargo-scaas-node|cargo|near::near_events_trades_from_transfers
cargo-scaas-node|cargo|near::events_scan_blocks
cargo-scaas-node|cargo|near::key_sets_per_token
cargo-scaas-node|cargo|near::refunded_router_job_is_not_consumed
cargo-scaas-node|cargo|near::router_target_bound_to_fail_refused
cargo-scaas-node|cargo|near::pruned_heights_error
cargo-scaas-node|cargo|near::escrow_foreign_entry_not_followed
cargo-scaas-node|cargo|near::stuck_settle_checks_relay_held
cargo-scaas-node|cargo|near::wrapper_conflicts_refused
cargo-scaas-node|cargo|near::key_sets_shown_for_key_op_jobs
cargo-scaas-node|cargo|near::view_over_gas_cap_is_transport
cargo-scaas-node|cargo|near::same_token_value_target_needs_balance
cargo-scaas-node|cargo|near::dex_pair_and_index_replicated
cargo-scaas-node|cargo|near::expiry_margin_refused
cargo-scaas-node|cargo|near::third_party_methods_listed
cargo-scaas-node|cargo|near::dex_deposit_floor_covers_the_larger_leg_twice
cargo-scaas-node|cargo|near::unopened_subject_origins
cargo-scaas-node|cargo|near::mandate_terms_expiry_margin
cargo-scaas-node|cargo|near::node_target_figures_are_priced
cargo-scaas-node|cargo|near::plain_pay_expiry_margin
cargo-scaas-node|cargo|near::origin_of_parity_vectors
cargo-scaas-node|cargo|near::passkey_origin_shapes_as_on_chain
cargo-scaas-node|cargo|near::router_job_gas_on_node_figures
cargo-scaas-node|cargo|near::near_jobs_never_panic
cargo-scaas-node|cargo|near::never_pay_any_carried_payee
cargo-scaas-node|cargo|near::dex_lane_bound_order_via_router
cargo-scaas-node|cargo|near::start_check_dex_executor_mismatch_errors
cargo-scaas-node|cargo|addresses::near_account_ids
cargo-scaas-node|cargo|addresses::algorand_addresses_and_app_ids
cargo-scaas-node|cargo|keys::lane_path_near
cargo-scaas-node|cargo|keys::lane_path_algorand
e2e-algorand|cargo|deploy_gate_fails_on_hash_mismatch
e2e-algorand|cargo|deploy_resumes_after_an_interruption
e2e-algorand|cargo|algorand_pay_relay_finalize
e2e-algorand|cargo|algorand_pay_meta_job
e2e-algorand|cargo|algorand_relay_fee_job
e2e-algorand|cargo|algorand_router_mandate
e2e-algorand|cargo|algorand_router_dex_settle
e2e-algorand|cargo|algorand_events_ingested
e2e-near|cargo|deploy_gate_fails_with_a_key_left
e2e-near|cargo|deploy_resumes_after_an_interruption
e2e-near|cargo|near_pay_relay_finalize
e2e-near|cargo|near_pay_meta_job
e2e-near|cargo|near_relay_fee_wrapper_job
e2e-near|cargo|near_router_release
e2e-near|cargo|near_router_refund
e2e-near|cargo|near_router_timeout
e2e-near|cargo|near_events_include_native_ft_transfer
e2e-near|cargo|near_lanes_do_not_block_each_other
e2e-near|cargo|near_router_token_target
e2e-near|cargo|near_router_listed_target_ok
algorand|unittest|test_recorded_create_decodes_its_parameters
algorand|unittest|test_found_among_the_funders_created_apps
algorand|unittest|test_not_on_chain
algorand|unittest|test_two_matches_refused
algorand|unittest|test_txn_counter_read
algorand|unittest|test_txn_counter_missing_fails_hard
algorand|pytest|test_account.py::test_ua_opened_lazily_relayer_pays_mbr
algorand|pytest|test_account.py::test_each_kind_accepted
algorand|pytest|test_account.py::test_high_s_refused
algorand|pytest|test_account.py::test_ninth_key_refused
algorand|pytest|test_account.py::test_add_key_native_sender_is_the_address
algorand|pytest|test_account.py::test_origin_and_rp_checked
algorand|pytest|test_account.py::test_origin_cap
algorand|pytest|test_account.py::test_recovery_after_delay_only
algorand|pytest|test_account.py::test_recovery_of_a_passkey_with_its_origin
algorand|pytest|test_account.py::test_cancel_recovery_and_guardian_ops
algorand|pytest|test_account.py::test_msig_native_member_by_current_authority
algorand|pytest|test_account.py::test_msig_one_key_counts_once
algorand|pytest|test_account.py::test_msig_rules
algorand|pytest|test_account.py::test_msig_cap_fits_limits
algorand|pytest|test_account.py::test_budget_per_kind_pinned
algorand|pytest|test_account.py::test_inner_budget_calls_fee_pooled_no_residue
algorand|pytest|test_account.py::test_token_ua_pay_via_account_verify
algorand|pytest|test_account.py::test_token_takes_only_a_true_verify
algorand|pytest|test_account.py::test_token_msig_with_address_member
algorand|pytest|test_account.py::test_keys_shared_by_two_tokens
algorand|pytest|test_account.py::test_rekeyed_address_signs_through_account_record
algorand|pytest|test_account.py::test_policy_passkey_for_value
algorand|pytest|test_account.py::test_key_op_envelope_refused
algorand|pytest|test_account.py::test_account_update_delete_optin_refused
algorand|pytest|test_dex.py::test_settle_both_legs_atomic
algorand|pytest|test_dex.py::test_one_leg_fails_group_fails
algorand|pytest|test_dex.py::test_order_relayer_mismatch_refused
algorand|pytest|test_dex.py::test_leg_by_non_dex_refused
algorand|pytest|test_dex.py::test_cancel_filled_refused
algorand|pytest|test_dex.py::test_min_nonce_cap_refused
algorand|pytest|test_dex.py::test_no_partial_fill
algorand|pytest|test_dex.py::test_replay_across_dexes_tokens_networks
algorand|pytest|test_dex.py::test_trade_leg_is_a_value_op
algorand|pytest|test_dex.py::test_carried_auth_after_the_settle
algorand|pytest|test_dex.py::test_dex_update_delete_optin_refused
algorand|pytest|test_dex.py::test_figures_pinned
algorand|pytest|test_mandate.py::test_mandate_pay_within_limits
algorand|pytest|test_mandate.py::test_open_terms_bound_by_the_funding_op
algorand|pytest|test_mandate.py::test_funding_only_through_the_open
algorand|pytest|test_mandate.py::test_limits_exceeded_refused
algorand|pytest|test_mandate.py::test_wrong_payee_refused
algorand|pytest|test_mandate.py::test_expired_refused
algorand|pytest|test_mandate.py::test_delegate_policy_passkey_for_value
algorand|pytest|test_mandate.py::test_revoked_refused_then_funds_back
algorand|pytest|test_mandate.py::test_pay_ref_once
algorand|pytest|test_mandate.py::test_no_pay_meta_entry
algorand|pytest|test_mandate.py::test_native_owner_ua_payee
algorand|pytest|test_mandate.py::test_msig_delegate
algorand|pytest|test_mandate.py::test_replay_across_tokens_networks_apps
algorand|pytest|test_mandate.py::test_fake_token_cannot_touch_other_funds
algorand|pytest|test_mandate.py::test_mandate_update_delete_optin_refused
algorand|pytest|test_mandate.py::test_figures_pinned
algorand|pytest|test_relayfee.py::test_relay_open_mode_pays_lane
algorand|pytest|test_relayfee.py::test_relay_bound_payee
algorand|pytest|test_relayfee.py::test_target_failure_rejects_group
algorand|pytest|test_relayfee.py::test_algorand_router_bound_pay_refused_direct
algorand|pytest|test_relayfee.py::test_target_not_by_executor_refused
algorand|pytest|test_relayfee.py::test_clearstate_target_refused
algorand|pytest|test_relayfee.py::test_missing_app_refused
algorand|pytest|test_relayfee.py::test_target_relayfee_refused
algorand|pytest|test_relayfee.py::test_payee_executor_refused
algorand|pytest|test_relayfee.py::test_add_key_native_target_refused
algorand|pytest|test_relayfee.py::test_payment_shape_refused
algorand|pytest|test_relayfee.py::test_executor_rejects_rekey_close_fee
algorand|pytest|test_relayfee.py::test_executor_without_relay_next_rejected
algorand|pytest|test_relayfee.py::test_target_pay_naming_router_fails
algorand|pytest|test_relayfee.py::test_lane_transfer_as_target_refused
algorand|pytest|test_relayfee.py::test_executor_transfer_moves_nothing
algorand|pytest|test_relayfee.py::test_executor_address_matches_offchain_derivation
algorand|pytest|test_relayfee.py::test_router_salt_below_128
algorand|pytest|test_relayfee.py::test_relay_ref_vectors
algorand|pytest|test_relayfee.py::test_router_holds_nothing_after_relay
algorand|pytest|test_relayfee.py::test_router_mbr_forward_exact
algorand|pytest|test_relayfee.py::test_relayed_noop_refused
algorand|pytest|test_relayfee.py::test_relay_every_target_kind
algorand|pytest|test_relayfee.py::test_dex_bound_order_via_router
algorand|pytest|test_relayfee.py::test_router_update_delete_optin_refused
algorand|pytest|test_relayfee.py::test_inner_txns_never_rekey_or_close
algorand|pytest|test_relayfee.py::test_figures_pinned
algorand|pytest|test_token.py::test_arc200_getters
algorand|pytest|test_token.py::test_mint_admin_only
algorand|pytest|test_token.py::test_arc200_transfer_new_receiver_needs_exact_mbr
algorand|pytest|test_token.py::test_mbr_payment_exact
algorand|pytest|test_token.py::test_pay_meta_emits_meta_then_settled
algorand|pytest|test_token.py::test_algorand_pay_meta_mismatch_and_replay
algorand|pytest|test_token.py::test_pay_meta_cap_measured
algorand|pytest|test_token.py::test_rekeyed_address_signs_with_auth_addr
algorand|pytest|test_token.py::test_rekeyed_to_logicsig_refused_natively
algorand|pytest|test_token.py::test_wrong_network_refused
algorand|pytest|test_token.py::test_valid_until_seconds
algorand|pytest|test_token.py::test_relayer_bound_to_sender
algorand|pytest|test_token.py::test_ua_signer_goes_through_the_account_app
algorand|pytest|test_token.py::test_pay_to_token_app_refused
algorand|pytest|test_token.py::test_transfer_and_execute_transfer
algorand|pytest|test_token.py::test_transfer_to_ua_and_ua_balance_of
algorand|pytest|test_token.py::test_open_payee_only_in_open_mode
algorand|pytest|test_token.py::test_approve_only_app_to_app
algorand|pytest|test_token.py::test_amount_u128_max_and_supply_cap
algorand|pytest|test_token.py::test_box_prefixes_disjoint
algorand|pytest|test_token.py::test_update_and_delete_refused
algorand|pytest|test_token.py::test_optin_refused
algorand|pytest|test_token.py::test_figures_pinned
algorand|pytest|test_vectors.py::test_metaop_vectors
algorand|pytest|test_vectors.py::test_sign_bytes_vectors
algorand|pytest|test_vectors.py::test_pay_meta_vectors
algorand|pytest|test_vectors.py::test_native_ids_are_the_address_keys
algorand|pytest|test_vectors.py::test_key_op_vectors
algorand|pytest|test_vectors.py::test_mandate_vectors
algorand|pytest|test_vectors.py::test_dex_vectors
algorand|pytest|test_vectors.py::test_origin_parity_vectors
forge|forge|test_nearAlgorandNatives
near|cargo|borsh_and_display_match_the_vectors
near|cargo|metaop_vectors_match
near|cargo|nep413_vectors_match
near|cargo|ua_of_matches_kinds_json_valid_rows
near|cargo|native_id_forms
near|cargo|webauthn_grammar_net_all_04
near|cargo|origin_of_parity_vectors
near|cargo|pay_meta_vectors_match
near|cargo|relay_ref_vectors_match
near|cargo|settle_vectors_match
near|cargo|late_on_legs_pays_nothing
near|cargo|on_refund_after_on_legs_pays_nothing
near|cargo|passkey_field_cap
near|cargo|leg_gas_by_auth
near|cargo|refund_only_own_leg
near|cargo|ua_opened_lazily_relayer_pays_storage
near|cargo|ed25519_secp256k1_passkey_each_accepted
near|cargo|secp256k1_high_s_refused
near|cargo|ninth_key_refused
near|cargo|origin_and_rp_checked
near|cargo|recovery_after_delay_only
near|cargo|cancel_recovery_by_key
near|cargo|msig_native_member_only_as_predecessor
near|cargo|access_key_signature_never_accepted
near|cargo|wrong_network_or_contract_refused
near|cargo|set_policy_by_key_op
near|cargo|settle_pays_both_legs
near|cargo|leg_settle_view_tracks_the_index
near|cargo|one_leg_fails_other_refunded
near|cargo|order_relayer_mismatch_refused
near|cargo|leg_called_by_non_dex_refused
near|cargo|settle_leg_shape_refused
near|cargo|settle_deposit_short_refused
near|cargo|refund_expired_after_lost_callback
near|cargo|refund_before_expiry_refused
near|cargo|cancel_filled_order_refused
near|cargo|min_nonce_cap_refused
near|cargo|no_partial_fill
near|cargo|settle_short_gas_refused
near|cargo|settle_gas_pin
near|cargo|settle_msig_leg_gas_limit
near|cargo|settle_passkey_field_cap_refused
near|cargo|mandate_pay_within_limits
near|cargo|open_funding_equals_op_amount
near|cargo|per_payment_and_per_period_exceeded_refused
near|cargo|wrong_payee_refused
near|cargo|expired_refused
near|cargo|delegate_policy_passkey_for_value
near|cargo|revoked_refused_then_funds_back
near|cargo|pay_ref_once_per_mandate
near|cargo|mandate_has_no_pay_meta_entry
near|cargo|pay_meta_emits_meta_then_settled
near|cargo|near_pay_meta_mismatch_and_replay
near|cargo|pay_once_per_lane
near|cargo|relayer_bound_to_predecessor
near|cargo|near_wrapper_bound_pay_refused_direct
near|cargo|pay_to_token_itself_refused
near|cargo|transfer_to_unregistered_native_registers_from_deposit
near|cargo|near_valid_until_is_seconds
near|cargo|near_check_storage_needed_is_exact
near|cargo|batch_of_actions_atomic
near|cargo|policy_passkey_for_value
near|cargo|pay_meta_size_bound_measured
near|cargo|implicit_relayer_refund_within_job_gas
near|cargo|node_tx_vector
near|cargo|webauthn_vector_accepted
near|cargo|p256_two_passkey_relay_fee_fits_300_tgas
near|cargo|relay_fee_add_key_ok
near|cargo|relay_fee_remove_key_ok
near|cargo|relay_fee_add_origin_ok
near|cargo|relay_fee_remove_origin_ok
near|cargo|relay_fee_set_guardian_ok
near|cargo|relay_fee_set_policy_ok
near|cargo|relay_fee_start_recovery_ok
near|cargo|relay_fee_cancel_recovery_ok
near|cargo|relay_fee_finish_recovery_ok
near|cargo|relay_fee_mandate_open_ok
near|cargo|relay_fee_revoke_ok
near|cargo|relay_fee_cancel_ok
near|cargo|relay_fee_invalidate_nonces_ok
near|cargo|wrapper_open_mode_pays_predecessor
near|cargo|wrapper_bound_payee_paid_directly
near|cargo|refused_entry_pays_nothing
near|cargo|pay_op_shape_enforced
near|cargo|wrapper_payment_policy_passkey_for_value
near|cargo|near_relay_fee_two_passkey_within_300_tgas
near|cargo|relay_fee_msig_cap_fits_300_tgas
near|cargo|release_on_success
near|cargo|refund_on_target_panic
near|cargo|refund_on_missing_code
near|cargo|target_success_with_failing_child_releases
near|cargo|hold_failure_clears_pending
near|cargo|short_deposit_refused
near|cargo|timeout_refund_refused_before_deadline
near|cargo|timeout_refunds_after_deadline
near|cargo|release_and_refund_exclusive
near|cargo|pending_empty_and_router_balance_unchanged_after_each_branch
near|cargo|executor_holds_only_its_stake_after_each_branch
near|cargo|target_deposit_forwarded_and_returned_on_failure
near|cargo|short_prepaid_gas_refused
near|cargo|near_router_bound_pay_refused_direct
near|cargo|target_router_or_executor_refused
near|cargo|payee_executor_refused
near|cargo|relay_shape_and_salt_refused
near|cargo|forwarded_call_cannot_spend_router_bound_payment
near|cargo|near_router_release_to_unregistered_payee
near|cargo|gas_pins_hold
near|cargo|ft_transfer_registered_needs_one_yocto
near|cargo|ft_transfer_unregistered_auto_registers
near|cargo|storage_bounds_min_equals_max_equals_measured
near|cargo|storage_withdraw_positive_panics
near|cargo|storage_unregister_registered_panics_force_included
near|cargo|ft_transfer_call_resolves_as_nep141
near|cargo|transfer_to_ua_credits_ua_ledger
near|cargo|mint_admin_only
near|cargo|token_refuses_transfer_to_self
near|cargo|check_no_authority_finds_forbidden_api
near|cargo|admin_view_is_the_mint_admin
near|cargo|relay_ref_vectors
near|cargo|late_callbacks_pay_nothing
near|cargo|stale_callback_leaves_a_newer_entry_alone
near|cargo|hold_refused_returns_deposits
near|cargo|failed_settle_kept_for_the_timeout
near|cargo|timeout_during_hold_returns_target_deposit
near|cargo|mandate_vectors_match
near|cargo|pay_at_expiry_second_allowed
near|cargo|routed_plan_shape_payee_and_policy
near|cargo|dex_vectors_match
near|cargo|settle_worst_case_leg_storage_pin
near|cargo|settle_near_expiry_refused
near|cargo|lane_bound_order_settles_through_router
near|cargo|add_origin_present_refused
forge|forge|test_kindTable
ua-rs|cargo|table_groups_purposes_constants
ua-rs|cargo|natives_native_space_canonical_ids
cargo-scaas-node|cargo|adapters::example_config_builds_every_family
cargo-scaas-node|cargo|metatx::ua_digests_match_the_metatx3_vectors
cargo-scaas-node|cargo|metatx::ua_wire_needs_bytes32_ids_and_normalizes
cargo-scaas-node|cargo|metatx::ua_pay_meta_calldata_checks_the_payment
cargo-scaas-node|cargo|submit::ua_metatx_jobs_build_the_ua_entry_points
cargo-scaas-node|cargo|submit::ua_metatx_job_relays_and_a_spent_ua_nonce_is_consumed
cargo-scaas-node|cargo|submit::ua_relay_fee_needs_a_price_and_covers_the_quote
cargo-scaas-node|cargo|submit::min_wei_value_is_parsed_or_refused
cargo-scaas-node|cargo|indexer::ua_payments_are_payment_rows_and_join_their_meta_and_relay_fee
cargo-scaas-node|cargo|submit::priced_relay_fee_replacements_stay_under_the_job_ceiling
cargo-scaas-node|cargo|submit::a_tracked_priced_relay_job_is_rechecked_after_a_restart
cargo-scaas-node|cargo|submit::a_relay_fee_job_holds_its_payer
cargo-scaas-node|cargo|submit::op_stack_l1_fee_is_in_the_quote
cargo-scaas-node|cargo|chain::a_native_ua_subject_is_classified_on_both_paths
EOF
)

named_tests() { # every new test passed; no family log with 0 passed, a skipped suite, or a new test ignored
  local D=${NAMED_TESTS_LOG_DIR:-$R} miss=0 step form name re f n
  norm() { sed -E 's/^[[:space:]]*([0-9]+: )?[[:space:]]*//; s/ \([0-9.]+ ?m?s\)$//' "$1"; }
  # cargo --nocapture --test-threads=1 (the near step) prints "test <t> ... " + the test's output + "ok" on its own line:
  # rejoin each result to its "test <t> ... " line
  cnorm() { awk '/^test [^ ]+ \.\.\. / { i = index($0, " ... "); h = substr($0, 1, i + 4); r = substr($0, i + 5)
      if (r ~ /^(ok|FAILED|ignored)/) print; else p = h; next }
    p != "" && /^(ok|FAILED|ignored)/ { print p $0; p = "" }' "$1"; }
  while IFS='|' read -r step form name; do
    case $form in
      forge) cat "$D/$P"-forge-*.txt 2>/dev/null | grep -qF "[PASS] $name(" ;;
      cargo) re="^test ([^ ]+::)?${name//::/::([^ ]+::)?}"
        f=$(cnorm "$D/$P-$step.txt" 2>/dev/null)
        ! grep -qE "$re \.\.\. ignored(, .*)?$" <<< "$f" && grep -qE "$re \.\.\. ok$" <<< "$f" ;;
      move) grep -qE "\[ PASS +\] [^ ]*::${name}\$" "$D/$P-$step.txt" 2>/dev/null ;;
      jest) norm "$D/$P-$step.txt" 2>/dev/null | grep -qxF "✓ $name" ;;
      node) norm "$D/$P-$step.txt" 2>/dev/null | grep -qxF "✔ $name" ;;
      qt) grep -qE "PASS +: ([A-Za-z_]+::)+${name}\(\)" "$D/$P-$step.txt" 2>/dev/null ;;
      pytest) grep -qE "^PASSED tests/${name}(\[[^ ]*\])?\$" "$D/$P-$step.txt" 2>/dev/null ;;
      unittest) grep -qE "^${name} \(.*\) \.\.\. ok\$" "$D/$P-$step.txt" 2>/dev/null ;;
    esac || { echo "named-tests: not passed in $step: $name"; miss=$((miss + 1)); }
  done <<< "$NEW_TESTS"
  for s in $FAMILIES; do
    f=$D/$P-$s.txt
    [ -f "$f" ] || { echo "named-tests: no log for $s"; miss=$((miss + 1)); continue; }
    # cargo: a crate's doc-test or a test-less binary prints "0 passed"; only those lines are allowed
    n=$(awk '/^ *Doc-tests /{d=1} /^ *Running /{d=0} /^running 0 tests$/{z=1}
             / 0 passed/{ if (!d && !z) c++; z=0 } END{print c+0}' "$f")
    [ "$n" -eq 0 ] || { echo "named-tests: $s reports 0 passed ($n)"; miss=$((miss + 1)); }
    grep -qE 'Test Suites:.* skipped|Total tests: 0;|passed: 0;|^(=+ )?([0-9]+ [a-z]+, )*[0-9]+ (skipped|deselected|xfailed)' "$f" && { echo "named-tests: $s has a skipped / empty suite"; miss=$((miss + 1)); }
  done
  echo "named-tests: $(grep -c . <<< "$NEW_TESTS") names, $miss problem(s)"
  [ $miss -eq 0 ]
}

done_at_head() { # log ends rc=0, first line names HEAD, tree clean apart from the logs
  L=$R/$P-$1.txt
  [ -f "$L" ] && [ "$(tail -n1 "$L")" = "rc=0" ] && [ "$(head -n1 "$L")" = "# $1 at commit $(git rev-parse --short HEAD)" ] &&
    [ -z "$(git status --porcelain -- . ":(exclude)$R")" ]
}

only=
[ "$1" = "--only" ] && only=$2
[ -z "$only" ] || case " $STEPS " in *" $only "*) ;; *) echo "unknown step $only" >&2; exit 2 ;; esac
if [ -n "$NAMED_TESTS_LOG_DIR" ]; then # the guard self-check: report only, never write runs/
  [ "$only" = named-tests ] || { echo "NAMED_TESTS_LOG_DIR only with --only named-tests" >&2; exit 2; }
  named_tests; exit $?
fi
fail=0
for s in $STEPS; do
  [ -z "$only" ] || [ "$s" = "$only" ] || continue
  if [ -z "$GATES_FRESH" ] && done_at_head "$s"; then echo "skip $s (rc=0 at $(git rev-parse --short HEAD))"; continue; fi
  L=$R/$P-$s.txt
  echo "run  $s"
  { echo "# $s at commit $(git rev-parse --short HEAD)"; (run_step "$s") 2>&1; echo "rc=$?"; } > "$L.tmp" 2>&1
  mv "$L.tmp" "$L"   # named-tests reads $R; the step's own log appears only when the step is done
  tail -n1 "$L" | grep -qx 'rc=0' || { echo "FAIL $s ($L)"; fail=1; break; }
done
exit $fail
