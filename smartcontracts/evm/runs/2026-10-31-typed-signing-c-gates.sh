#!/bin/bash
# typed-signing Task CG: the closing gates of Parts C, N and R2 at one commit. Not a copy: it sets the step list, log prefix and
# test names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract, commands, resume and guard).
#   2026-10-31-typed-signing-c-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-31-typed-signing-c-<s>.txt: "# <s> at commit <sha>" first, "rc=<n>" last; skipped when done at the
# same commit with a clean tree. The P step list + gen-set + pqz-kat (per set) + the clients ua-cs / ua-dart / ua-dart-frb that C7
# did not run + zether-cross with the real zether-cli (10 tests since C7) + vectors-check (now with typed_ops.json: the base's
# typed-ops-vectors.mjs, typed-ops-cast-check.mjs and the typed/ diff). No full pqz-core gate: no core change happened.
# A fresh worktree needs the git-ignored inputs as real directories (no symlink): smartcontracts/evm/lib,
# clients/clientkeys/node_modules, smartcontracts/algorand/out (copy; remove after). cargo-scaas-node needs CAPPED_MEM=6G.
P=2026-10-31-typed-signing-c
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes gen-set docs pqz-kat-n2048-kmax1024 pqz-kat-n2304-kmax4096 pqz-kat-n2560-kmax16384 pqz-kat-n2816-kmax65536 cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node node-e2e-anvil clientkeys ua-rs ua-rs-signers ua-rs-json ua-qt ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb soroban vectors-check gas-n2048-kmax1024 gas-n2304-kmax4096 gas-n2560-kmax16384 gas-n2816-kmax65536 named-tests"
FAMILIES="soroban ua-rs ua-rs-signers ua-rs-json ua-qt ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb"
export ZETHER_CROSS_N=10
# pqz-kat-<set>: pqz-vectors --check (regenerate and compare byte for byte) + pqz_kat.py --check, as vectors/run.sh's check steps
extra_step() {
  case $1 in
    pqz-kat-*) local S=${1#pqz-kat-} BF=
      [ "$S" = n2304-kmax4096 ] || BF="--no-default-features --features pqzl-rust,set-$S"
      cd pqz-core/ffi || return 1
      export PQZ_SET=$S CARGO_TARGET_DIR=$PWD/target/$S
      ../../scripts/capped cargo build --release --offline $BF --features prove --bin pqz-vectors &&
        ../../scripts/capped "$CARGO_TARGET_DIR/release/pqz-vectors" --check &&
        ../../scripts/capped python3 -I ../../smartcontracts/vectors/pqz/pqz_kat.py --check ;;
    # the PQZ gas table per set (as the R2 gates): the debit_min_gas figure is its "pqzl-ua | burn 1 to an address, fresh ref" regular gas
    gas-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#gas-}" test --match-path test/pqz/PqzStateGas.t.sol --match-contract PqzStatePinGasTest --match-test test_gasTable -vv ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}
# "<step>|<form>|<name>": the names of 2026-10-31-typed-signing-p-gates.sh that are still tests at HEAD, then every test of C0-C8,
# R2, N1 (runs/2026-10-31-typed-signing-c-newtests.py over 006c6dfe..HEAD; a name removed later is not listed)
NEW_TESTS=$(cat <<'NAMES'
forge|forge|test_noKemRecordIsZeroRecord
forge|forge|test_portableDomainSeparatorPinned
forge|forge|test_portableRecordDigestVectors
forge|forge|test_portableTypehashesPinned
forge|forge|test_registerTypedKeysSameId
forge|forge|test_kemCommitFormRefused
forge|forge|test_kemHashCommitThenFill
forge|forge|test_kemKeyAssembledBytes
forge|forge|test_kindNameEveryKind
forge|forge|test_kindNameUnknownReverts
forge|forge|test_msigContractMember1271OverTypedDigest
forge|forge|test_msigNativeMemberPersonalSignRefused
forge|forge|test_msigNativeMemberTypedDigest
forge|forge|test_msigOfRoundTrip
forge|forge|test_registerMsigTypedMembersSameId
forge|forge|test_registrationArgsFromVectors
forge|forge|test_registrationOfUnchangedBytes
forge|forge|test_setKemKeyNeverOverwrites
forge|forge|test_setKemKeyV0WithoutCommitReverts
forge|forge|test_setKemKeyV0WrongKeyReverts
forge|forge|test_storePqzPopGen2HostKindFromGen1
forge|forge|test_requireAuthorizedUASigEveryKind
forge|forge|test_r1_kemHashCommitFits
forge|forge|test_x0_calldata
forge|forge|test_x0_reassemblesPayload
soroban|cargo|msig_evm_eoa_member_typed_digest
soroban|cargo|msig_evm_eoa_personal_sign_refused
soroban|cargo|register_rows_from_portable_json
soroban|cargo|domain_separator_pinned
soroban|cargo|evm_eoa_member_typed_recovers
soroban|cargo|portable_typehashes_pinned
cargo-zether-prover|cargo|zether_registration_digest_pinned
cargo-zether-prover|cargo|pop_over_typed_registration
ua-rs|cargo|domain_separator_pinned
ua-rs|cargo|native_member_typed_digest
ua-rs|cargo|portable_rows_typed
ua-rs|cargo|portable_typehashes_pinned
ua-rs|cargo|registration_args_typed
ua-rs|cargo|registration_args_typed_keys
ua-rs|cargo|registration_hash_commit_when_over_limit
ua-rs-signers|cargo|portable_pop_rows
ua-rs-json|cargo|refusals
ua-rs-json|cargo|registration_args_rows
ua-rs-json|cargo|set_key_args_rows
clientkeys|node|UA-6 / UA-8: a holder registers its PQZ key in the same call: pop over the typed UARegistration{record(ua, kind, h, no KEM), pqzPopHash}
clientkeys|node|digests: portable pop (UA-8, no chain context; typed records), UAAuth, member
clientkeys|node|native EOA member signs the typed digest (ECDSA recovers the member)
clientkeys|node|no-KEM record is {ua,0,0,0}
clientkeys|node|personal_sign of md is refused by the reference verifier
clientkeys|node|portable domain separator is 0x9a2c…4ca1 (name + version only)
clientkeys|node|portable typehashes pinned
clientkeys|node|register args typed
clientkeys|node|register args typed keys (registerWebAuthn / registerMuSig2 / registerFrost)
clientkeys|node|register hash-commit only when the full call does not fit (X0: PQZH n2560-kmax16384, PQZ key + KEM key)
clientkeys|node|TS-D4 scope: a code-less native msig member signs the typed digest of the portable records only
clientkeys|node|typed digest equals hashTypedData(portableTypedData(…)) for every row
clientkeys|node|zether PoP message (0x0141, no PQZ, no KEM)
clientkeys|node|the Zether PoP is portable (UA-8 P1): no chain field, over the typed UARegistration{record(UA, 0x0141, 0, no KEM), 0}
ua-qt|qt|test_portablePurposes
ua-qt|qt|test_registration_args
ua-qt|qt|test_set_key_args
ua-py|unittest|test_native_member_typed_digest
ua-py|unittest|test_portable_typed
ua-py|unittest|test_registration_args_typed
ua-py|unittest|test_registration_args_typed_keys
ua-py|unittest|test_registration_hash_commit_when_over_limit
ua-go|go|TestNativeMemberTypedDigest
ua-go|go|TestPortableTyped
ua-go|go|TestRegistrationArgsTyped
ua-go|go|TestRegistrationArgsTypedKeys
ua-go|go|TestRegistrationHashCommitWhenOverLimit
ua-cs|cs|NativeMemberTypedDigest
ua-cs|cs|PortableTyped
ua-cs|cs|RegistrationArgsTyped
ua-cs|cs|RegistrationArgsTypedKeys
ua-cs|cs|RegistrationHashCommitWhenOverLimit
ua-c|unittest|test_portable_purposes
ua-c|unittest|test_registration_args
ua-c|unittest|test_set_key_args
ua-cxx|ctest|portable_purposes
ua-cxx|ctest|registration_args
ua-cxx|ctest|set_key_args
ua-dart|dart|native member typed digest
ua-dart|dart|portable typed
ua-dart|dart|registration args typed
ua-dart|dart|registration args typed keys
ua-dart|dart|registration hash commit when over limit
ua-dart-frb|dart|portable purposes
ua-dart-frb|dart|registration args
ua-dart-frb|dart|set key args
forge|forge|test_storePqzPopAfterKemHashCommit
forge|forge|test_storePqzPopAfterKemHashCommitGen2Host
clientkeys|node|a malformed KEM key is refused before a form is chosen
clientkeys|node|kem repair after a front-run hash commit (PRV M1)
ua-rs|cargo|registration_refuses_malformed_kem
ua-rs|cargo|kem_repair_fills_a_front_run_commit
ua-py|unittest|test_malformed_kem_refused
ua-go|go|TestMalformedKemRefused
ua-cs|cs|MalformedKemRefused
ua-dart|dart|malformed kem refused
cargo-scaas-node|cargo|submit::ua8_registry_writes_are_call_jobs
cargo-scaas-node|cargo|submit::ua8_relayed_pq_register_over_the_cap_is_split
clientkeys|node|kind field equals the row's kind
forge|forge|test_badPointInTheAbi
forge|forge|test_pqzExplicitSignaturesPinned
forge|forge|test_zetherExplicitSignaturesPinned
forge|forge|test_relayFeeDirectCallRefused
forge|forge|test_relayFeeExecutorPayeeRefused
forge|forge|test_relayFeeFieldsBound
forge|forge|test_relayFeeRows
forge|forge|test_relayFeeTyped
forge|forge|test_c0_gasNamedVsGeneric
forge|forge|test_c0_namedEntryNotAllowlisted
forge|forge|test_c0_setMandateTyped
forge|forge|test_c0_shieldTyped
forge|forge|test_c0_unwrapTyped
forge|forge|test_c1_setMandateRow
forge|forge|test_c1_shieldRow
forge|forge|test_c1_uaShieldRow
forge|forge|test_c1_unwrapRow
forge|forge|test_c6EntriesNotAllowlisted
forge|forge|test_typedOpsVectors_CancelDexOrderRow
forge|forge|test_typedOpsVectors_CancelOrderRow
forge|forge|test_typedOpsVectors_CancelUAOrderRow
forge|forge|test_typedOpsVectors_CancelUAWrapOrderRow
forge|forge|test_typedOpsVectors_CancelWrapOrderRow
forge|forge|test_typedOpsVectors_ReceiverFeeRow
forge|forge|test_typedOpsVectors_RelayFeeRow
forge|forge|test_typedOpsVectors_UACancelNonceRow
forge|forge|test_typedOpsVectors_UAReceiverFeeRow
forge|forge|test_typedOpsVectors_UARelayFeeRow
forge|forge|test_typedOpsVectors_UAWrapOrderRow
forge|forge|test_typedOpsVectors_WrapOrderRow
forge|forge|test_flatUaUnwrapGone
forge|forge|test_genericEntriesKept
forge|forge|test_iMetaTxIdPinned
forge|forge|test_namedCancelNonceFromAccount
forge|forge|test_namedCancelNonceOwnLane
forge|forge|test_namedEntryEnvelopeTamper
forge|forge|test_namedEntryFeeClass
forge|forge|test_namedEntryOtherOpDigestRefused
forge|forge|test_namedEntryOtherToken
forge|forge|test_namedEntryReplayRefused
forge|forge|test_namedUADerivedSigner
forge|forge|test_namedUADerivedUnwrap
forge|forge|test_namedUADerivedUnwrapToUA
forge|forge|test_namedUAEmptySignatureRefused
forge|forge|test_namedUAMsig
forge|forge|test_relayFeeRouterRunsNamedEntry
forge|forge|test_removedAliasesGone
forge|forge|test_typedOpsVectors_AddKey
forge|forge|test_typedOpsVectors_AddReserve
forge|forge|test_typedOpsVectors_Burn
forge|forge|test_typedOpsVectors_BurnRow
forge|forge|test_typedOpsVectors_CancelNonce
forge|forge|test_typedOpsVectors_CancelNonceRow
forge|forge|test_typedOpsVectors_CancelRecovery
forge|forge|test_typedOpsVectors_DelegateRevoke
forge|forge|test_typedOpsVectors_ExecuteAccount
forge|forge|test_typedOpsVectors_ExecuteWallet
forge|forge|test_typedOpsVectors_HederaWallet
forge|forge|test_typedOpsVectors_PayUnderMandate
forge|forge|test_typedOpsVectors_RemoveKey
forge|forge|test_typedOpsVectors_RevokeMandate
forge|forge|test_typedOpsVectors_RotateKey
forge|forge|test_typedOpsVectors_SetGuardian
forge|forge|test_typedOpsVectors_SetMandate
forge|forge|test_typedOpsVectors_SetPayee
forge|forge|test_typedOpsVectors_UABurn
forge|forge|test_typedOpsVectors_UABurnRow
forge|forge|test_typedOpsVectors_UAUnwrap
forge|forge|test_typedOpsVectors_UAUnwrapLeg
forge|forge|test_typedOpsVectors_UAUnwrapToUA
forge|forge|test_typedOpsVectors_Unwrap
forge|forge|test_typedOpsVectors_UnwrapLeg
forge|forge|test_typedOpsVectors_UnwrapToUA
forge|forge|test_typedOpsVectors_Wrap
forge|forge|test_typedOpsVectors_WrapLeg
forge|forge|test_typedOpsVectors_WrapLegRow
forge|forge|test_typedOpsVectors_WrapToUA
forge|forge|test_uaBaseAddressPathUsesCtx
forge|forge|test_uaBaseAllowlist
forge|forge|test_uaBaseBatch
forge|forge|test_uaBaseCancelNonce
forge|forge|test_uaBaseModesAsAddressPath
forge|forge|test_uaBaseOffWithoutRegistry
forge|forge|test_uaBaseRefusesFee
forge|forge|test_C0_13_emptySinglePartsAreBadPayload
forge|forge|test_multi_emptyPartsAreBadPayload
forge|forge|test_multi_partLengths
forge|forge|test_pqzhN2048FitsBothPaths
forge|forge|test_partLengths_burn
forge|forge|test_partLengths_op1
forge|forge|test_partLengths_op7
forge|forge|test_pqzAuthDigestIsNotTheOldDigest
forge|forge|test_pqzAuthDigestVectors
forge|forge|test_pqzAuthTypehashPinned
forge|forge|test_pqzAuthWalletDigest
forge|forge|test_pqzExplicitStatementBytes_burn
forge|forge|test_pqzExplicitStatementBytes_compact
forge|forge|test_pqzExplicitStatementBytes_op7
forge|forge|test_pqzExplicitStatementBytes_single
forge|forge|test_pqzExplicitStatementBytes_singleCompact
forge|forge|test_pqzExplicitStatementBytes_transfer
forge|forge|test_pqzExplicitStatementBytes_unshieldUnwrap
forge|forge|test_pqzNamedEntryNotAllowlisted
forge|forge|test_pqzNamedFeePaid
forge|forge|test_pqzNamedFeePaidUA
forge|forge|test_pqzNamedPrepareAcc
forge|forge|test_pqzNamedPrepareAccUA
forge|forge|test_pqzNamedRollOver
forge|forge|test_pqzNamedRollOverUA
forge|forge|test_pqzNamedTransfer
forge|forge|test_pqzNamedTransferCompact
forge|forge|test_pqzNamedTransferCompactUA
forge|forge|test_pqzNamedTransferSingle
forge|forge|test_pqzNamedTransferSingleCompact
forge|forge|test_pqzNamedTransferSingleCompactUA
forge|forge|test_pqzNamedTransferSingleUA
forge|forge|test_pqzNamedTransferUA
forge|forge|test_pqzNamedUnshield
forge|forge|test_pqzNamedUnshieldUA
forge|forge|test_pqzNamedUnshieldUnwrap
forge|forge|test_pqzNamedUnshieldUnwrapUA
forge|forge|test_pqzNamedWrapShield
forge|forge|test_pqzStoredCiphertextUnchanged
forge|forge|test_rawCalldata_pAndSaltOutOfType
forge|forge|test_typedOpsVectors_PqzAuth
forge|forge|test_typedOpsVectors_PqzTransfer
forge|forge|test_typedOpsVectors_PqzTransferSingle
forge|forge|test_typedOpsVectors_PqzUnshield
forge|forge|test_typedOpsVectors_PqzUnshieldUnwrap
forge|forge|test_typedOpsVectors_PrepareAcc
forge|forge|test_typedOpsVectors_RollOver
forge|forge|test_typedOpsVectors_UAPqzTransfer
forge|forge|test_typedOpsVectors_UAPqzTransferSingle
forge|forge|test_typedOpsVectors_UAPqzUnshield
forge|forge|test_typedOpsVectors_UAPqzUnshieldUnwrap
forge|forge|test_typedOpsVectors_UAPrepareAcc
forge|forge|test_typedOpsVectors_UARollOver
forge|forge|test_typedOpsVectors_WrapShield
forge|forge|test_registryDeployGate
forge|forge|test_uaCancelNonceTyped
forge|forge|test_uaReceiverFeeNested
forge|forge|test_1271MemberSeesTheRegistry
forge|forge|test_abiUnchanged
forge|forge|test_callerCannotSupplyTheWords
forge|forge|test_constructorRefusesAMissingLibrary
forge|forge|test_deployGas
forge|forge|test_diff
forge|forge|test_gasHotPath
forge|forge|test_gen2SharesTheLibrary
forge|forge|test_libraryDirectCallRefused
forge|forge|test_msigPopAtTheBudget
forge|forge|test_nestedOffsetReadsAWordAsItsOwnArgument
forge|forge|test_reentryFromAVerifierRefused
forge|forge|test_starvedMemberThroughTheSelfCall
forge|forge|test_storageLayoutUnchanged
forge|forge|test_split_portableRowsSame
forge|forge|test_split_storePqzPopWithAVerify
forge|forge|test_cancelUAOrderNested
forge|forge|test_cancelUAWrapOrderNested
forge|forge|test_cancelDexOrderNested
forge|forge|test_registryClosure
forge|forge|test_mtxWrapOrderRenamed
forge|forge|test_mtxWrapOrder_anOutsideLegHasNoMtxTrade
forge|forge|test_mtxWrapOrder_deliveredLessOrMoreThanSignedIsRefused
forge|forge|test_mtxWrapOrder_disabledLegIsRefused
forge|forge|test_mtxWrapOrder_escrowFlagIsRefusedByTheUnderlying
forge|forge|test_mtxWrapOrder_feeIsRoundedUp
forge|forge|test_mtxWrapOrder_isNotAllowlisted
forge|forge|test_mtxWrapOrder_mintsAtTheRate_feeToTheSubmitter
forge|forge|test_mtxWrapOrder_nativeLegIsNotGasless
forge|forge|test_mtxWrapOrder_pausedDuringARateChange
forge|forge|test_mtxWrapOrder_refusals
forge|forge|test_mtxWrapOrder_relayerBinding
forge|forge|test_mtxWrapOrder_reserveShortfallIsRefused
forge|forge|test_mtxWrapOrder_signedMinimumIsThePrice
forge|forge|test_mtxWrapOrder_throughMtxExecuteIsNotAllowlisted
forge|forge|test_mtxWrapOrder_toDestination
forge|forge|test_mtxWrapOrder_tooSmallToMint
forge|forge|test_mtxWrapOrder_walletJson
forge|forge|test_receiverFeeNested
forge|forge|test_cancelOrderNested
forge|forge|test_cancelWrapOrderNested
forge|forge|test_tradeOrderStillTradeOrder
forge|forge|test_wrapOrderTyped
forge|forge|test_accountSigMalformedLayout
forge|forge|test_accountSigRefusals
forge|forge|test_addKeyKindRefused
forge|forge|test_addKeyTyped
forge|forge|test_delegateRevokeTyped
forge|forge|test_ed25519DelegateNamedEntries
forge|forge|test_ed25519OwnerNamedEntries
forge|forge|test_executeTyped
forge|forge|test_executeTypedAndGenericShareTheLane
forge|forge|test_executeTypedEmitsExecuted
forge|forge|test_executeTypedFailureAndReentry
forge|forge|test_executeTypedReplayAndEnvelope
forge|forge|test_mandateEpochBound
forge|forge|test_mandateLanesFloatRefAndEpochGuard
forge|forge|test_namedEntriesNotAllowlisted
forge|forge|test_namedFeeModeRefused
forge|forge|test_namedModesAndSelfSender
forge|forge|test_payUnderMandateTyped
forge|forge|test_removeKeyTyped
forge|forge|test_revokeMandateTyped
forge|forge|test_rotateKeyToPasskeyTyped
forge|forge|test_rotateKeyTyped
forge|forge|test_setGuardianAndCancelRecoveryTyped
forge|forge|test_setPayeeTyped
forge|forge|test_skaMerkleBatchLeafIsTypedDigest
forge|forge|test_skaPasskeyChallengeTypedDigest
forge|forge|test_named_multi_relayed
forge|forge|test_named_single_relayed
forge|forge|test_named_unshield_relayed
forge|forge|test_statementDifferential
forge|forge|test_typedOpsVectors_RollOverBatch
forge|forge|test_typedOpsVectors_RollOverSigned
forge|forge|test_typedOpsVectors_SetRollOverMode
forge|forge|test_typedOpsVectors_UARollOverBatch
forge|forge|test_typedOpsVectors_UARollOverSigned
forge|forge|test_typedOpsVectors_UASetRollOverMode
forge|forge|test_typedOpsVectors_UAZetherTransfer
forge|forge|test_typedOpsVectors_UAZetherTransferSingle
forge|forge|test_typedOpsVectors_UAZetherUnshield
forge|forge|test_typedOpsVectors_UAZetherUnshieldUnwrap
forge|forge|test_typedOpsVectors_ZetherRollOver
forge|forge|test_typedOpsVectors_ZetherSetRollOverMode
forge|forge|test_typedOpsVectors_ZetherTransfer
forge|forge|test_typedOpsVectors_ZetherTransferSingle
forge|forge|test_typedOpsVectors_ZetherUnshield
forge|forge|test_typedOpsVectors_ZetherUnshieldUnwrap
forge|forge|test_zetherEntrySelectorPins
forge|forge|test_zetherEnvelopeBindingNamed
forge|forge|test_zetherNamedFeeClass
forge|forge|test_zetherNamedRollOver
forge|forge|test_zetherNamedRollOverBatch
forge|forge|test_zetherNamedRollOverSigned
forge|forge|test_zetherNamedSetRollOverMode
forge|forge|test_zetherNamedShield
forge|forge|test_zetherNamedUnshieldUnwrap
forge|forge|test_zetherNamedWrapShield
forge|forge|test_zetherOwnerRollOverTyped
forge|forge|test_zetherSetRollOverModeTyped
forge|forge|test_zetherTransferExplicitStatementBytes
forge|forge|test_zetherTransferStoredBytesUnchanged
forge|forge|test_zetherTransferTyped_bundle
forge|forge|test_zetherTransferTyped_bundleUA
forge|forge|test_zetherTransferTyped_compact
forge|forge|test_zetherTransferTyped_compactUA
forge|forge|test_zetherTransferTyped_single
forge|forge|test_zetherTransferTyped_singleUA
forge|forge|test_zetherTypedTamperRefused
forge|forge|test_zetherUARollOverSigned
forge|forge|test_zetherUAUnshieldUnwrap
forge|forge|test_zetherUnshieldBoundsKept
forge|forge|test_zetherUnshieldExplicit
forge|forge|test_zetherUnshieldUnwrapExplicit
cargo-zether-prover|cargo|every_zether_row_digest_equals_the_vector
cargo-zether-prover|cargo|named_call_equals_the_vector_calldata
cargo-zether-prover|cargo|typed_digest_refuses_unknown_op_missing_and_extra_field
cargo-scaas-node|cargo|the_hedera_lane_skips_bytes_already_in_flight
cargo-scaas-node|cargo|a_cancel_needs_the_token_kind_and_keeps_the_book_without_it
cargo-scaas-node|cargo|door_a_takes_registered_tokens_only
cargo-scaas-node|cargo|hex_data_is_refused_at_the_gateway
cargo-scaas-node|cargo|the_gateway_checks_the_typed_signature_before_the_simulation
cargo-scaas-node|cargo|ua_entries_stay_off_the_gateway_door
cargo-scaas-node|cargo|a_signature_that_is_not_65_bytes_is_the_contracts
cargo-scaas-node|cargo|fill_digest_keeps_the_key_and_what_the_chain_emits_apart
cargo-scaas-node|cargo|guard_allows_every_named_entry_only
cargo-scaas-node|cargo|the_plain_rows_are_pinned
cargo-scaas-node|cargo|work_without_a_row_is_refused_before_any_chain_read
cargo-scaas-node|cargo|dedup_by_typed_digest
cargo-scaas-node|cargo|evm_call_key_follows_the_bytes
cargo-scaas-node|cargo|hex_data_refused
cargo-scaas-node|cargo|job_api_explicit_json_roundtrip
cargo-scaas-node|cargo|a_job_deadline_never_outlives_the_signed_one
cargo-scaas-node|cargo|a_receiver_fee_is_recognised_by_its_payment_digest
cargo-scaas-node|cargo|an_op_is_exact
cargo-scaas-node|cargo|call_op_round_trips_a_plain_entry
cargo-scaas-node|cargo|digest_and_calldata_cannot_diverge
cargo-scaas-node|cargo|hex_fields_are_refused_by_name_and_a_declared_bytes_field_is_not
cargo-scaas-node|cargo|invalidate_digests_match_the_vectors
cargo-scaas-node|cargo|mandate_ops_run_on_their_own_lane_at_nonce_zero
cargo-scaas-node|cargo|relay_fee_call_object
cargo-scaas-node|cargo|the_flat_wallet_builders_stay_beside_the_named_entries
cargo-scaas-node|cargo|the_signer_is_found_where_the_row_keeps_it
cargo-scaas-node|cargo|typed_ops_kat_every_entry
cargo-scaas-node|cargo|unbound_fields_stay_out_of_the_digest_and_off_the_wire
node-e2e-anvil|cargo|plain_rows_match_the_forge_abi
clientkeys|node|cancel: only the order the user holds or the lane the user chose, from the account, in the order's domain
clientkeys|node|checkCancel: the UA invalidation resolves its builder
clientkeys|node|owner call: the client signs only AddKey(the key it just made) as its own account, on its chain
clientkeys|node|receiver-pays, address path: the payee co-signs ReceiverFee nesting only the payment it expects, within its own bounds
clientkeys|node|a named entry as the relayed call: fee 0, relayer bound to the executor; the payment commits to its calldata
clientkeys|node|Appendix X.4: every confidential type string and its UA twin, exactly; referenced types sorted
clientkeys|node|EIP-712 by the MetaMask v4 rules: bytes16 right-padded, arrays element by element, nested structs hashed
clientkeys|node|a bool is true or false: 'false' is no truth, in the builder, the hash or the calldata
clientkeys|node|abiEncode: nested dynamic tuples, arrays of tuples, bytes16, bool (abi.encode by hand)
clientkeys|node|after C6 a wrap is only a WrapOrder: checkTradeOrder and checkCancel refuse the TradeOrder form
clientkeys|node|an omitted expectation is no "expect zero": every own field is the client's, in full
clientkeys|node|calldata decodes to the message: selector of the full signature, every parameter in place
clientkeys|node|calldata refuses what the entry cannot verify: the missing signature, an encoded account blob; a shared op names its domain
clientkeys|node|canonical zero for an unbound relayer / fee recipient: envelope and nested MetaTransfer
clientkeys|node|checkOp keeps a relayer or fee recipient the client named: refused when the mode bit would drop it
clientkeys|node|checkOp refuses a wrap order: its rules cannot be bypassed; the cancel of one still goes through checkCancel
clientkeys|node|checkOp refuses every changed field; the server supplies only the envelope
clientkeys|node|checkOp: the deadline, the fee policy, the contract, the chain, the operation
clientkeys|node|checkWrapOrder: CLI-SGN-35 / -36 on the real WrapOrder; the server supplies only the nonce and an in-window deadline
clientkeys|node|every typehash pinned: the plan's truncated value, keccak256(typeString), table = vector
clientkeys|node|hashTypedData(td) == row.digest; the builder rebuilds the wallet's JSON; the row signs natively
clientkeys|node|kept unchanged: the type strings the plan freezes
clientkeys|node|the builder refuses a field off the struct, a value out of range, a domain the op does not live in
clientkeys|node|the overloads: selectors from the full signature, the C0 shapes
clientkeys|node|the table covers every allowlisted entry of every contract, and only them
clientkeys|node|typed-ops-cast-check: a swapped parameter is refused against the message, not passed as a round trip
clientkeys|node|UAReceiverFee nests the row's payment: the payee checks it on ids, the payment digest is the payer's
clientkeys|node|CancelUAOrder nests the order as signed; checkCancel takes it only from the holder of that order
clientkeys|node|G1: the 128 encoded bytes word by word, abi.encode(G1) = the packed point
clientkeys|node|owner op: UASig{signature: Schnorr over uaMessage(kind, zether-owner, digest)}
clientkeys|node|typed owner ops: ZetherRollOver / ZetherSetRollOverMode digests, ownerSig as UASig.signature, the direct calldata
forge|forge|test_msigPopNotMinimalRefused
forge|forge|test_msigKemSigNotMinimalRefused
forge|forge|test_msigPqzKeySigNotMinimalRefused
forge|forge|test_msigRequireAuthorizedKeepsRule
forge|forge|test_msigFrontRunSlotDropRefused
forge|forge|test_membershipDigestByHand
forge|forge|test_membershipNativeAccepts
forge|forge|test_membershipRegisteredAccepts
forge|forge|test_membershipContractAccepts
forge|forge|test_membershipPopSignersAccepted
forge|forge|test_membershipEmptyPopWritesNothing
forge|forge|test_membershipPopExempt
forge|forge|test_membershipRefusedUntilEnoughWeight
forge|forge|test_membershipUnacceptedRefusedRequireAuthorized
forge|forge|test_membershipUnacceptedRefusedErc1271
forge|forge|test_membershipUnacceptedRefusedSetKemKey
forge|forge|test_membershipUnacceptedRefusedSetPqzKey
forge|forge|test_membershipWrongMemberRefused
forge|forge|test_membershipWrongUaRefused
forge|forge|test_membershipIndexOutOfRangeRefused
forge|forge|test_membershipRecordSigIsNoAcceptance
forge|forge|test_membershipNativePopIsNoAcceptance
forge|forge|test_membershipAcceptanceIsNoRecordSig
forge|forge|test_membershipKeyDataRefused
forge|forge|test_membershipNotAnMsigRefused
forge|forge|test_membershipIdempotent
forge|forge|test_membershipTopSlot
forge|forge|test_membershipPortable
forge|forge|test_membershipGen2HoldsNoGen1Acceptance
forge|forge|test_membershipGen2HostReadsGen1Bits
forge|forge|test_membershipGen2HostStarvedIsVerifyGas
forge|forge|test_membershipStarvedMemberIsVerifyGas
forge|forge|test_membershipVerifyReadsOneSlot
forge|forge|test_membershipVectors
forge|forge|test_namedUAMsigUnacceptedRefused
clientkeys|node|acceptance (CTR-UA-37): every row by hand, the wallet JSON, the native signer, the purpose apart from the records
ua-rs|cargo|membership_rows
ua-qt|qt|test_membershipRows
ua-py|unittest|test_membership_rows
ua-go|go|TestMembershipRows
ua-cs|cs|MembershipRows
ua-c|unittest|test_membership_rows
ua-cxx|ctest|membership_rows
ua-dart|dart|membership rows
ua-dart-frb|dart|membership rows
cargo-scaas-node|cargo|accept_membership_job_decodes
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
