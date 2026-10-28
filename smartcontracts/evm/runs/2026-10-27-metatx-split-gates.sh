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
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 sizes gen-set docs cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node clientkeys ua-rs ua-qt soroban solana cosmos sui aptos ton named-tests"
FAMILIES="soroban solana cosmos sui aptos ton"
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
    soroban|solana|cosmos|sui|aptos|ton) CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh "$1" ;;
    named-tests) named_tests ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

# The new tests of the plan (Tasks 1-18), "<step>|<form>|<name>", and the pass line each must show in that step's log:
#   forge  "[PASS] <name>(" in at least one forge-* log
#   cargo  "test [<path>::]<name> ... ok"; a "::" in <name> may span module path segments
#   move   "[ PASS    ] <addr>::<module>::<name>"
#   jest   "✓ <name>"     node "✔ <name>"     qt "PASS   : <TestCase>::<name>()"
# (the plan's test names, as the tasks built them: git diff of the test functions, merge-base..T19)
NEW_TESTS=$(cat <<'EOF'
forge|forge|test_parity
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
EOF
)

named_tests() { # every new test passed; no family log with 0 passed, a skipped suite, or a new test ignored
  local D=${NAMED_TESTS_LOG_DIR:-$R} miss=0 step form name re f n
  norm() { sed -E 's/^[[:space:]]*([0-9]+: )?[[:space:]]*//; s/ \([0-9.]+ ?m?s\)$//' "$1"; }
  while IFS='|' read -r step form name; do
    case $form in
      forge) cat "$D/$P"-forge-*.txt 2>/dev/null | grep -qF "[PASS] $name(" ;;
      cargo) re="^test ([^ ]+::)?${name//::/::([^ ]+::)?}"
        f=$D/$P-$step.txt
        ! grep -qE "$re \.\.\. ignored$" "$f" 2>/dev/null && grep -qE "$re \.\.\. ok$" "$f" 2>/dev/null ;;
      move) grep -qE "\[ PASS +\] [^ ]*::${name}\$" "$D/$P-$step.txt" 2>/dev/null ;;
      jest) norm "$D/$P-$step.txt" 2>/dev/null | grep -qxF "✓ $name" ;;
      node) norm "$D/$P-$step.txt" 2>/dev/null | grep -qxF "✔ $name" ;;
      qt) grep -qE "PASS +: ([A-Za-z_]+::)+${name}\(\)" "$D/$P-$step.txt" 2>/dev/null ;;
    esac || { echo "named-tests: not passed in $step: $name"; miss=$((miss + 1)); }
  done <<< "$NEW_TESTS"
  for s in $FAMILIES; do
    f=$D/$P-$s.txt
    [ -f "$f" ] || { echo "named-tests: no log for $s"; miss=$((miss + 1)); continue; }
    # cargo: a crate's doc-test or a test-less binary prints "0 passed"; only those lines are allowed
    n=$(awk '/^ *Doc-tests /{d=1} /^ *Running /{d=0} /^running 0 tests$/{z=1}
             / 0 passed/{ if (!d && !z) c++; z=0 } END{print c+0}' "$f")
    [ "$n" -eq 0 ] || { echo "named-tests: $s reports 0 passed ($n)"; miss=$((miss + 1)); }
    grep -qE 'Test Suites:.* skipped|Total tests: 0;|passed: 0;' "$f" && { echo "named-tests: $s has a skipped / empty suite"; miss=$((miss + 1)); }
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
