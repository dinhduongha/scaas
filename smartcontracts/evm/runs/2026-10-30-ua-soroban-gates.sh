#!/bin/bash
# UA-Soroban Task T12: the closing gates of branch ua-soroban (docs, Soroban contracts, clientkeys, node, the T0 spike and
# the local Protocol 30 e2e). Not a copy: it sets the step list, log prefix and test names, then runs
# 2026-10-27-metatx-split-gates.sh (the same step contract, commands, resume and guard).
#   2026-10-30-ua-soroban-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-30-ua-soroban-<s>.txt; resume = skip a step whose log ends rc=0 at this commit, tree clean.
# named-tests reads NAMED_TESTS_LOG_DIR (default runs/); the guard self-check points it at a scratch copy of the logs.
# cargo-scaas-node needs smartcontracts/algorand/out (git-ignored): ALGORAND_ARTIFACTS_CHECK=1 scripts/capped smartcontracts/scripts/build.sh algorand once per checkout.
# soroban-spike-local and e2e-soroban-local start the quickstart container `scaas-stellar` (removed on exit; they stop
# with exit 3 when one already exists). Owner rule 2026-10-23: when a docker job is running (docker ps), run with CAPPED_SLOTS=1.
P=2026-10-30-ua-soroban
STEPS="docs soroban clientkeys cargo-scaas-node soroban-spike-local e2e-soroban-local named-tests"
FAMILIES="soroban soroban-spike-local e2e-soroban-local"
# "<step>|<form>|<name>": every test added by Tasks T0-T10 (T2b, T6b included; the names as in the code now, from the
# tasks' commits), in its tool's pass form (forms: see the base runner); then main's router-fix test kept at the merge
# and the two node tests of the carried router-fix review fixes; then the final fix wave's tests (2026-10-31).
NEW_TESTS=$(cat <<'NAMES'
soroban-spike-local|cargo|spike_ua_pay_passkey_model_budget
soroban-spike-local|cargo|spike_bls_add_mul_fr_budget
soroban-spike-local|cargo|spike_bls_g1_msm_budget
soroban-spike-local|cargo|spike_bls_g2_msm_budget
soroban-spike-local|cargo|spike_bls_pairing_budget
soroban-spike-local|cargo|spike_mldsa44_verify_budget
soroban-spike-local|cargo|spike_mldsa65_verify_budget
soroban-spike-local|cargo|spike_msig3_mldsa65_model_budget
soroban-spike-local|cargo|spike_register_mldsa65_model_budget
soroban-spike-local|cargo|spike_require_authorized_passkey_budget
soroban-spike-local|cargo|spike_zether_transfer_model_budget
soroban|cargo|dex_native_orders_bind_relayer
soroban|cargo|dex_ua_cancel_sets_filled
soroban|cargo|dex_ua_destination_receives_proceeds
soroban|cargo|dex_ua_maker_native_taker_settles
soroban|cargo|native_leg_with_auth_is_refused
soroban|cargo|ua_ops_vectors_ua_trade_rows
soroban|cargo|ua_trade_dex_only_partial_fill_no_resign
soroban|cargo|mandate_epoch_increments
soroban|cargo|mandate_instance_ttl_on_every_entry
soroban|cargo|mandate_native_owner_unchanged_semantics
soroban|cargo|mandate_pay_ref_once
soroban|cargo|mandate_pay_stale_epoch_refused
soroban|cargo|mandate_revoke_stale_epoch_refused
soroban|cargo|mandate_ua_owner_delegate_payee
soroban|cargo|mandate_ua_owner_lane_replay_refused
soroban|cargo|mandate_ua_owner_needs_registry
soroban|cargo|mandate_withdraw_to_ua
soroban|cargo|ua_ops_vectors_mandate_rows
soroban|cargo|constructor_refuses_a_foreign_executor
soroban|cargo|executor_exec_refuses_all_but_router
soroban|cargo|relay_fee_paid_holder_fields
soroban|cargo|relay_payee_never_router_or_executor
soroban|cargo|relay_victim_ua_pay_as_target_refused
soroban|cargo|ua_ops_vectors_ua_relay_row
soroban|cargo|ua_relay_bound_ua_payee
soroban|cargo|ua_relay_open_mode_pays_submitter
soroban|cargo|ua_relay_ref_commits_to_call
soroban|cargo|ua_relay_router_only
soroban|cargo|ua_relay_victim_ua_pay_as_target_refused
soroban|cargo|env_default_protocol_30
soroban|cargo|mint_to_ua_admin_only
soroban|cargo|pay_to_ua_ref_once_per_payer
soroban|cargo|pool_address_not_payable
soroban|cargo|relayer_bound_needs_auth
soroban|cargo|sep41_events_match_balance_with_ua_moves
soroban|cargo|transfer_to_ua_then_ua_transfer
soroban|cargo|ua_burn_and_cancel_nonce
soroban|cargo|ua_entries_extend_ttl
soroban|cargo|ua_entry_archived_nonce_restored_not_reset
soroban|cargo|ua_expired_refused
soroban|cargo|ua_ledger_off_refused
soroban|cargo|ua_ops_vectors_token_rows
soroban|cargo|ua_pay_meta_emits_meta_first
soroban|cargo|ua_pay_once_per_ref
soroban|cargo|ua_receiver_not_registered_or_not_receivable
soroban|cargo|ua_trade_dex_must_be_contract
soroban|cargo|ua_trade_only_named_dex
soroban|cargo|ua_trade_over_pull_one_call_refused
soroban|cargo|ua_trade_pulled_total_bounded
soroban|cargo|ua_transfer_replay_refused
soroban|cargo|entries_extend_ttl
soroban|cargo|id_in_native_space_refused
soroban|cargo|key_data_invalid_rows_refused
soroban|cargo|key_hash_unique
soroban|cargo|kind_msig_negatives_fail
soroban|cargo|kind_msig_vectors_verify
soroban|cargo|member_large_pop_same_budget
soroban|cargo|msig_evm_eoa_member_portable_only
soroban|cargo|msig_member_unknown_refused
soroban|cargo|msig_soroban_native_member_host_auth
soroban|cargo|msig_unsignable_not_receivable
soroban|cargo|stellar_account_round_trip
soroban|cargo|register_any_submitter
soroban|cargo|register_attrs_refused_4b
soroban|cargo|register_disabled_kind_refused
soroban|cargo|register_front_run_identical
soroban|cargo|register_portable_pop_from_portable_json
soroban|cargo|register_unverifiable_part_refused_4b
soroban|cargo|registration_of_returns_register_args
soroban|cargo|relayers_from_constructor
soroban|cargo|require_authorized_each_kind_and_purpose
soroban|cargo|require_authorized_not_registered
soroban|cargo|require_authorized_refuses_portable_purposes
soroban|cargo|ua_lists_per_kind
soroban|cargo|ed25519_key_check_matches_kinds_json
soroban|cargo|evm_eoa_member_personal_sign_recovers
soroban|cargo|kind_ed25519_negatives_fail
soroban|cargo|kind_ed25519_rfc8032_vectors
soroban|cargo|kind_ed25519_vectors_verify
soroban|cargo|kind_mldsa44_negatives_fail
soroban|cargo|kind_mldsa44_vectors_verify
soroban|cargo|kind_mldsa65_negatives_fail
soroban|cargo|kind_mldsa65_vectors_verify
soroban|cargo|kind_p256_negatives_fail
soroban|cargo|kind_p256_vectors_verify
soroban|cargo|kind_secp256k1_negatives_fail
soroban|cargo|kind_secp256k1_vectors_verify
soroban|cargo|kind_webauthn_p256_negatives_fail
soroban|cargo|kind_webauthn_p256_vectors_verify
soroban|cargo|member_sigs_abi_canonical_only
soroban|cargo|op_digest_matches_token_cross_vector
soroban|cargo|pay_ids_match_paymeta_json
soroban|cargo|portable_digests_match_portable_json
soroban|cargo|purpose_tags_match_kinds_json
soroban|cargo|tags_match_kinds_json
soroban|cargo|ua_message_matches_kinds_json
soroban|cargo|webauthn_blob_canonical_only
soroban|cargo|webauthn_cross_origin_refused
soroban|cargo|webauthn_origin_not_compared
clientkeys|node|soroban URN: derived ids never as strkey; a native send to a URN is refused
clientkeys|node|soroban op digest: the token cross vector reproduced
clientkeys|node|soroban ua-ops.json reproduced byte for byte
clientkeys|node|soroban ua-ops: every auth verifies under its kind
cargo-scaas-node|cargo|auto_restore_within_deposit_cap
cargo-scaas-node|cargo|decode_relay_fee_paid_holder
cargo-scaas-node|cargo|decode_ua_events
cargo-scaas-node|cargo|executor_is_read_once
cargo-scaas-node|cargo|op_consumed_ua_lane
cargo-scaas-node|cargo|op_consumed_ua_pay_ref
cargo-scaas-node|cargo|pays_router_covers_ua_pay
cargo-scaas-node|cargo|relay_jobs_refuse_the_executor_as_payee
cargo-scaas-node|cargo|restore_preamble_still_reverts
cargo-scaas-node|cargo|soroban_unknown_job_kind_refused
cargo-scaas-node|cargo|stale_epoch_names_the_current_epoch
cargo-scaas-node|cargo|ua_metatx_allowlist
cargo-scaas-node|cargo|ua_metatx_digest_matches_ua_ops_vectors
cargo-scaas-node|cargo|ua_metatx_job_never_panics
cargo-scaas-node|cargo|ua_metatx_refuses_extra_source_account_auth
cargo-scaas-node|cargo|ua_metatx_relayer_must_be_lane
e2e-soroban-local|cargo|e2e_soroban_ua_dex_leg
e2e-soroban-local|cargo|e2e_soroban_ua_lane_authority_not_lent
e2e-soroban-local|cargo|e2e_soroban_ua_mandate_pays_ua_payee
e2e-soroban-local|cargo|e2e_soroban_ua_register_passkey_and_mldsa65
e2e-soroban-local|cargo|e2e_soroban_ua_relay_fee
e2e-soroban-local|cargo|e2e_soroban_ua_transfer_to_ua_and_ua_pay_relayed
soroban|cargo|relay_victim_pay_as_target_then_drain_refused
cargo-scaas-node|cargo|node_refuses_approvals_to_router_or_executor
cargo-scaas-node|cargo|missing_executor_is_a_config_error
soroban|cargo|msig_soroban_contract_member_refused
soroban|cargo|msig_member_equal_to_token_refused
clientkeys|node|soroban URN: any-case urn:scaas:ua: prefix is a UA form, never a strkey (NET-SOR-17)
clientkeys|node|soroban msig: a soroban-contract (C…) member is refused when building (S10, owner ruling 2026-10-31)
cargo-scaas-node|cargo|ua_metatx_lane_entry_root_only_no_member_auth
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
