#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua8-soroban Task B9: the closing gates of branch ua8-soroban at one commit (the Soroban round, the typed-signing merge it
# carries, the node's Soroban jobs and spend stop). Not a copy: it sets the step list, log prefix and test names, then runs
# 2026-10-27-metatx-split-gates.sh (the same step contract, commands, resume and guard).
#   2026-10-31-ua8-soroban-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-31-ua8-soroban-<s>.log (git-ignored); the `summary` step writes the committed -summary.txt.
# (was) <s>.txt: first line "# <s> at commit <sha>", last line "rc=<n>".
# A step is skipped when its log ends rc=0 at the current commit and the tree is clean (see the base runner).
# A fresh worktree needs the git-ignored inputs as real directories (a symlink named lib / node_modules / out is not ignored):
# smartcontracts/evm/lib, clients/clientkeys/node_modules, smartcontracts/algorand/out (remove out after the run).
# cargo-scaas-node needs CAPPED_MEM=6G (the one allowed exception; only with nothing else heavy on the machine).
# e2e-ua8-1..3 are the three filtered runs of e2e-ua8-local.sh (a full run is 688 s, over the 600 s command limit);
# e2e-ua8-union checks that the three ran each of the 10 tests once. They start the quickstart container `scaas-stellar`
# (3 GB, removed on exit) and two anvils: at least 6 GB available, one step at a time.
P=2026-10-31-ua8-soroban
LOGEXT=log # step logs are git-ignored (*.log); only <P>-summary.txt is committed (owner 2026-11-02)
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes docs soroban clientkeys vectors-check ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt cargo-scaas-node node-e2e-anvil soroban-spike-local e2e-soroban-local soroban-roundtrip-check e2e-ua8-1 e2e-ua8-2 e2e-ua8-3 e2e-ua8-union named-tests summary"
FAMILIES="ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt soroban soroban-spike-local e2e-soroban-local e2e-ua8-1 e2e-ua8-2 e2e-ua8-3"
# "<step>|<form>|<name>": every test added from bdde1d66 (the typed-signing merge) to HEAD in the contracts, spike, node and
# ua-rs (test functions found in the diff: Tasks M2, M3, G1, B0-B7c, V1, B9a, N2, MA-S), clientkeys' new titles, in the tool's pass
# form (forms: see the base runner). e2e_ua8 tests sit in the e2e-ua8-N step that runs them.
NEW_TESTS=$(cat <<'NAMES'
forge|forge|test_gen1KindGate_refusesMissingZether
forge|forge|test_gen1KindGate_refusesMissingSchnorrBls
forge|forge|test_gen1KindGate_noBlsPasses
forge|forge|test_gen1KindGate_hederaExempts0141
forge|forge|test_gen1KindGate_deployPathRunsIt
forge|forge|test_msigPopNotMinimalRefused
forge|forge|test_msigKemSigNotMinimalRefused
forge|forge|test_msigPqzKeySigNotMinimalRefused
forge|forge|test_msigRequireAuthorizedKeepsRule
forge|forge|test_msigFrontRunSlotDropRefused
soroban|cargo|ua8_relayer_checked_ua_authorises_nothing
soroban|cargo|register_attrs_accepted
soroban|cargo|msig_pop_not_minimal_refused
soroban|cargo|msig_g_member_redundant_slot_refused
soroban|cargo|msig_require_authorized_keeps_rule
soroban|cargo|msig_classical_dominant_empty_pop
soroban|cargo|msig_classical_dominant_matches_evm_bytes
soroban|cargo|ua8_register_attrs_rows
soroban|cargo|ua8_register_kem_commit
soroban|cargo|ua8_pqz_bytes_in_state
soroban|cargo|ua8_pqz_attrs_stored_unproven
soroban|cargo|ua8_register_without_pqz_pop
soroban|cargo|ua8_registration_of_reassembles
soroban|cargo|ua8_negatives_from_portable_json
soroban|cargo|ua8_pop_purpose_and_record_separated
soroban|cargo|ua8_ua_of_typed
soroban|cargo|ua8_register_webauthn_typed
soroban|cargo|ua8_classical_msig_with_kem
soroban|cargo|ua8_kem_scheme_above_a_byte_refused
soroban|cargo|ua8_checked_of_shape
soroban|cargo|ua8_events_fit_and_hash
soroban|cargo|ua8_entries_extend_ttl
soroban|cargo|ua8_attrs_error_unused
soroban|cargo|ua8_register_msig_typed
soroban|cargo|ua8_require_authorized_uasig_fields
soroban|cargo|ua8_kind_name_table
soroban|cargo|ua8_kem_any_order_write_once
soroban|cargo|ua8_kem_from_vectors
soroban|cargo|ua8_kem_commit_filled_once
soroban|cargo|ua8_kem_rules
soroban|cargo|ua8_kem_by_third_party
soroban|cargo|msig_kem_sig_not_minimal_refused
soroban|cargo|ua8_portable_sig_fields
soroban|cargo|ua8_set_pqz_key_from_vectors
soroban|cargo|ua8_set_pqz_key_write_once
soroban|cargo|ua8_set_pqz_key_negatives
soroban|cargo|ua8_set_pqz_key_single_key
soroban|cargo|ua8_set_pqz_key_rules
soroban|cargo|ua8_store_pqz_pop_hash_checked
soroban|cargo|ua8_store_pqz_pop_idempotent
soroban|cargo|ua8_store_pqz_pop_negatives
soroban|cargo|ua8_set_events_hash_only
soroban|cargo|ua8_views_of_register
soroban|cargo|ua8_register_slot_fields_pop
soroban|cargo|ua8_set_pqz_key_msig_largest_fits
soroban|cargo|ua8_set_pqz_key_msig_over_limit_n2816
soroban|cargo|ua8_set_pqz_key_msig_over_limit_n2048
soroban|cargo|ua8_relayer_unlisted_refused
soroban|cargo|ua8_relayer_must_authorise
soroban|cargo|ua8_relayer_checked_every_offchain_kind
soroban|cargo|ua8_relayer_kind_without_relayer_not_verifiable
soroban|cargo|ua8_relayer_mode_still_verifies_chain_parts
soroban|cargo|ua8_relayer_msig_mixed_members
soroban|cargo|ua8_relayer_msig_signable_counts_chain_members
soroban|cargo|ua8_relayer_msig_member_rules
soroban|cargo|ua8_relayer_evm_contract_slot
soroban|cargo|ua8_relayer_fndsa512_kem_and_pqz
soroban|cargo|ua8_relayer_register_parts_take_pop_checked
soroban|cargo|ua8_relayer_bad_record_takes_slot_marked
soroban|cargo|ua8_relayer_list_immutable
soroban|cargo|ua8_relayer_classical_msig_row
soroban|cargo|ua8_relayer_group_kinds_typed
soroban|cargo|ua8_relayer_group_typed_rules
soroban|cargo|ua8_relayer_key_data_layout
soroban|cargo|ua8_relayer_key_hash_groups
soroban|cargo|ua8_relayer_marked_record_blocks_no_chain_kind
soroban|cargo|ua8_relayer_kind_refused_over_chain_key
soroban|cargo|ua8_set_pqz_key_relayer_slots_largest_fit
soroban|cargo|ua8_set_pqz_key_relayer_slots_over_limit_n2816
soroban|cargo|ua8_set_pqz_key_relayer_slots_over_limit_n2048
soroban|cargo|ua8_register_relayer_slots_largest_fit
soroban|cargo|ua8_register_relayer_slots_over_limit
soroban|cargo|ua8_record_bytes_round_trip
soroban|cargo|ua8_attest_binds_register
soroban|cargo|ua8_attest_binds_register_msig
soroban|cargo|ua8_attest_binds_group_keys
soroban|cargo|ua8_attest_binds_set_kem_key
soroban|cargo|ua8_attest_binds_set_pqz_key
soroban|cargo|ua8_attest_hash_of_another_entry_refused
soroban|cargo|ua8_attest_needs_the_named_relayer
soroban|cargo|ua8_attest_digest_vector
soroban|cargo|ua8_event_key_data_limit
soroban|cargo|ua8_event_is_evm_key_data_below_the_limit
soroban|cargo|ua8_event_frost_sizes
soroban|cargo|kem_record_digests_match_portable_json
soroban|cargo|pqz_key_record_digests_match_portable_json
soroban|cargo|portable_digests_with_attrs_match
soroban|cargo|kem_record_of_no_key_is_the_zero_record
cargo-scaas-node|cargo|a_landed_failure_counts_against_the_budget_once
cargo-scaas-node|cargo|an_unread_fee_reports_the_job_and_is_counted
cargo-scaas-node|cargo|a_refused_send_ends_the_job
cargo-scaas-node|cargo|the_call_share_stops_only_soroban
cargo-scaas-node|cargo|a_job_put_back_is_a_retry
cargo-scaas-node|cargo|tx_fee_reads_the_fee_or_fails
cargo-scaas-node|cargo|tx_fee_reads_the_burn_or_fails
cargo-scaas-node|cargo|named_payload_rebuilds_the_signed_bytes
cargo-scaas-node|cargo|wrong_contract_and_bad_signatures_are_refused
cargo-scaas-node|cargo|soroban_job_explicit_args_build_xdr
cargo-scaas-node|cargo|soroban_hex_args_refused
cargo-scaas-node|cargo|soroban_job_bad_fields_refused
cargo-scaas-node|cargo|typed_values_against_their_xdr
cargo-scaas-node|cargo|deep_xdr_is_refused_not_a_stack_overflow
cargo-scaas-node|cargo|a_nested_job_stops_at_the_depth_bound
cargo-scaas-node|cargo|signed_op_allow_list
cargo-scaas-node|cargo|a_plain_signed_op_stops_at_the_call_share
cargo-scaas-node|cargo|a_token_payment_runs_to_the_budget
cargo-scaas-node|cargo|a_job_whose_root_and_built_call_differ_is_refused
cargo-scaas-node|cargo|restart_takes_a_ua_metatx_deadline_from_the_built_call
cargo-scaas-node|cargo|recorded_auth_own_means_the_lanes_own
cargo-scaas-node|cargo|soroban_call_job_registry_only
cargo-scaas-node|cargo|soroban_call_job_function_allowlist
cargo-scaas-node|cargo|soroban_call_job_builds_the_contract_shapes
cargo-scaas-node|cargo|soroban_call_job_has_no_job_auth_entries
cargo-scaas-node|cargo|attest_digest_vector
cargo-scaas-node|cargo|relayer_arg_is_the_lane
cargo-scaas-node|cargo|ua_registry_param_required_for_call
cargo-scaas-node|cargo|msig_row_converts_to_the_stored_bytes
cargo-scaas-node|cargo|relayer_mode_prechecks_off_chain
cargo-scaas-node|cargo|relayer_mode_refuses_failing_record
cargo-scaas-node|cargo|relayer_mode_checks_a_marked_msig_slot
cargo-scaas-node|cargo|archived_record_restores_within_the_cap
cargo-scaas-node|cargo|archived_record_job_does_not_hold_the_queue
cargo-scaas-node|cargo|oversized_job_does_not_hold_the_queue
cargo-scaas-node|cargo|transaction_of_exactly_the_limit_passes
cargo-scaas-node|cargo|oversized_ua_metatx_refused_at_build
cargo-scaas-node|cargo|failed_limit_read_uses_the_last_answer
cargo-scaas-node|cargo|unread_limit_is_transport
cargo-scaas-node|cargo|relayer_mode_refuses_evm_contract_slot
cargo-scaas-node|cargo|g_member_msig_is_checked_only_for_a_marked_slot
cargo-scaas-node|cargo|msig_member_list_is_bounded_before_any_read
cargo-scaas-node|cargo|call_job_valid_until_is_bounded
cargo-scaas-node|cargo|chain_parts_are_not_prechecked
cargo-scaas-node|cargo|relayer_mode_refused_on_unlisted_lane
cargo-scaas-node|cargo|failed_relayers_read_stops_only_relayer_mode
cargo-scaas-node|cargo|call_job_refuses_recorded_authority
cargo-scaas-node|cargo|members_read_as_the_contract_reads_them
cargo-scaas-node|cargo|ua8_check_never_panics
cargo-scaas-node|cargo|mutated_payload_never_panics
cargo-scaas-node|cargo|tx_fee_is_the_fee_charged
cargo-scaas-node|cargo|lane_balance_is_the_account_that_pays
cargo-scaas-node|cargo|an_empty_fee_account_opens_the_floor_behind_a_funded_lane
cargo-scaas-node|cargo|soroban_invalid_ends_the_head_job_and_the_next_runs
cargo-scaas-node|cargo|only_soroban_invalid_is_for_good
cargo-scaas-node|cargo|rejected_send_backs_off
cargo-scaas-node|cargo|failing_jobs_open_the_budget_and_later_jobs_do_not_send
cargo-scaas-node|cargo|balance_floor_stops_the_lane_before_it_sends
cargo-scaas-node|cargo|entry_over_the_limit_is_refused_at_build
cargo-scaas-node|cargo|entry_check_never_stops_a_job_on_what_it_cannot_read
cargo-scaas-node|cargo|a_payment_runs_while_relayers_read_fails
cargo-scaas-node|cargo|call_jobs_stop_at_their_share_and_payments_run_to_the_budget
cargo-scaas-node|cargo|the_call_share_is_configured
cargo-scaas-node|cargo|stopped_calls_at_the_head_do_not_hide_a_payment
cargo-scaas-node|cargo|a_backlog_over_the_read_hides_a_payment_on_the_pull_path
cargo-scaas-node|cargo|soroban_lanes_need_both_spend_limits
ua-rs-pq|cargo|pq_kat_verifies
ua-rs-pq|cargo|pq_external_verifies
ua-rs-pq|cargo|pq_signatures_verify
ua-rs-pq|cargo|pq_other_kinds_refused
ua-rs|cargo|msig_slots_minimal_cases
ua-rs|cargo|portable_msig_rows_minimal
ua-rs-pq|cargo|check_registration_vectors
ua-rs-pq|cargo|check_kem_record_vectors
ua-rs-pq|cargo|check_pqz_key_record_vectors
ua-rs-pq|cargo|check_refuses_negatives
ua-rs-pq|cargo|check_fails_closed
ua-rs|cargo|check_without_pq_refuses_pq_kinds
ua-rs-pq|cargo|check_refuses_invalid_keys
ua-rs-pq|cargo|check_group_kinds
e2e-soroban-local|cargo|e2e_soroban_native_relay_fee
e2e-soroban-local|cargo|e2e_soroban_dex_both_native
e2e-ua8-1|cargo|e2e_ua8_copy_evm_soroban_evm
e2e-ua8-1|cargo|e2e_ua8_simulation_auth_mode
e2e-ua8-1|cargo|e2e_ua8_unused_source_account_entry
e2e-ua8-3|cargo|e2e_ua8_network_fit
e2e-ua8-1|cargo|e2e_ua8_tx_size_limit
e2e-ua8-1|cargo|e2e_ua8_spend_stop
e2e-ua8-3|cargo|e2e_ua8_relayer_table
e2e-ua8-3|cargo|e2e_ua8_attestation_binds
e2e-ua8-2|cargo|e2e_ua8_frost_every_size
e2e-ua8-2|cargo|e2e_ua8_relayer_checked_msig_slot
clientkeys|node|msigSlotsMinimal: 2-of-(1,1) both slots minimal; 2-of-(1,2) both slots not; one slot of weight 2 minimal; below threshold not
clientkeys|node|vector builders refuse a non-minimal portable set
clientkeys|node|portable.json msig rows are minimal
clientkeys|node|verifyRegistration accepts every row and refuses every negative
clientkeys|node|verifyKemRecord accepts every row and refuses a flipped byte
clientkeys|node|verifyPqzKeyRecord accepts every row and refuses a flipped byte
clientkeys|node|verify* fail closed: each case one field off a row that passes (ua-rs check_fails_closed)
clientkeys|node|verifyRegistration refuses every kinds.json invalid key by its error; valid[] reaches the signature (ua-rs check_refuses_invalid_keys)
clientkeys|node|the group kinds have no verifier here: refused, never accepted (C14; ua-rs checks them)
soroban|cargo|ua_ops_msig_authorizes_nothing_until_accepted
soroban|cargo|ua_ops_msig_trade_and_cancel_refused_until_accepted
soroban|cargo|ua_ops_msig_mandate_owner_refused_until_accepted
soroban|cargo|ua_ops_msig_relay_refused_until_accepted
soroban|cargo|rows_digests_rebuild
soroban|cargo|rows_accept_unchanged
soroban|cargo|a_row_with_a_changed_byte_refused
soroban|cargo|native_and_registered_members_accept
soroban|cargo|g_member_accepts_by_a_signed_entry
soroban|cargo|nothing_until_the_accepted_weight_reaches_the_threshold
soroban|cargo|records_count_accepted_slots_only
soroban|cargo|a_relayer_checked_slot
soroban|cargo|the_attestation_binds
soroban|cargo|an_evm_contract_slot_needs_a_relayer
soroban|cargo|a_c_member_has_no_slot
soroban|cargo|wrong_acceptances_refused
soroban|cargo|an_acceptance_is_no_authorization
soroban|cargo|accepting_twice_is_a_no_op
soroban|cargo|top_slot
soroban|cargo|a_pop_marks_its_attested_slots
soroban|cargo|ttl_and_size_of_the_entry
soroban|cargo|rows_cover_chain_and_relayer_kinds
cargo-scaas-node|cargo|accept_job_runs_on_the_registry_alone
cargo-scaas-node|cargo|accept_job_attests_one_word
cargo-scaas-node|cargo|accept_job_prechecks_a_marked_slot
cargo-scaas-node|cargo|accept_job_on_an_accepted_slot_is_refused_unsent
cargo-scaas-node|cargo|accept_job_a_marked_slot_beside_a_g_member_fails_closed
cargo-scaas-node|cargo|accept_job_refuses_an_evm_contract_slot
cargo-scaas-node|cargo|accept_job_needs_a_g_members_entry
cargo-scaas-node|cargo|accept_job_is_in_the_call_share
e2e-soroban-local|cargo|e2e_soroban_ua_member_accepts_then_counts
e2e-soroban-local|cargo|e2e_soroban_ua_membership_rows_and_a_g_member
ua-rs|cargo|membership_rows
ua-rs-pq|cargo|check_membership_rows
clientkeys|node|accept_membership (CTR-UA-37): the op a node takes, a row unchanged, the G member's entry
clientkeys|node|acceptance (CTR-UA-37): every row by hand, the wallet JSON, the native signer, the purpose apart from the records
clientkeys|node|verifyMembership accepts every row and refuses a flipped byte (ua-rs check_membership_rows)
forge|forge|test_msigPopLightestInMiddleRefused
forge|forge|test_typedViewsMatchTheRows
soroban|cargo|msig_pop_lightest_slot_in_the_middle_refused
soroban|cargo|ua8_instance_ttl
soroban|cargo|ua8_relayer_register_kem_event_names_it
soroban|cargo|a_high_s_evm_eoa_slot_is_refused
soroban|cargo|a_listed_relayers_junk_acceptance_is_write_once
soroban|cargo|ua8_typed_views_match_the_rows
cargo-scaas-node|cargo|a_signed_op_deadline_is_bounded
cargo-scaas-node|cargo|a_past_deadline_ends_on_one_claim
cargo-scaas-node|cargo|a_lost_transaction_holds_the_lane_for_the_bound_at_most
cargo-scaas-node|cargo|a_view_the_host_refuses_is_unknown
cargo-scaas-node|cargo|a_failed_view_read_is_not_unknown
cargo-scaas-node|cargo|a_failed_sequence_read_puts_the_claimed_job_back
cargo-scaas-node|cargo|a_ua_metatx_missing_a_native_signer_is_refused_unsent
cargo-scaas-node|cargo|a_ua_metatx_runs_only_a_listed_mandate_wasm
cargo-scaas-node|cargo|an_unlisted_mandate_never_reports_consumed
cargo-scaas-node|cargo|a_mandate_job_names_a_registered_token
cargo-scaas-node|cargo|mandate_wasm_hashes_are_a_list_of_hashes
cargo-scaas-node|cargo|a_job_over_the_resource_fee_cap_is_refused_unsent
cargo-scaas-node|cargo|a_token_registered_after_the_start_is_served
cargo-scaas-node|cargo|a_kem_version_may_be_a_decimal_string
cargo-scaas-node|cargo|store_pqz_pop_over_a_stored_proof_is_refused_unsent
cargo-scaas-node|cargo|a_re_run_acceptance_is_consumed
cargo-scaas-node|cargo|a_record_over_the_read_bound_is_the_jobs_answer
cargo-scaas-node|cargo|deep_xdr_from_an_rpc_is_refused_not_a_stack_overflow
cargo-scaas-node|cargo|a_rejected_send_past_its_deadline_is_dead
cargo-scaas-node|cargo|a_failed_sign_puts_the_claimed_job_back
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
