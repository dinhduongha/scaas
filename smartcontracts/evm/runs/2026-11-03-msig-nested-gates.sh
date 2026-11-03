#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# msig-nested: the closing gates of branch msig-nested at one commit (nested `msig`, EVM first, spec 2026-11-02-msig-nested). Not a copy: it sets
# the step list, log prefix and test names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract, commands, resume and guard).
#   2026-11-03-msig-nested-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-11-03-msig-nested-<s>.log (git-ignored); the `summary` step writes the committed -summary.txt.
# First line "# <s> at commit <sha>", last line "rc=<n>". A step is skipped when its log ends rc=0 at the current commit and the tree is clean.
# A fresh worktree needs the git-ignored inputs as real directories: smartcontracts/evm/lib, clients/clientkeys/node_modules, and for
# cargo-scaas-node's Algorand adapter tests smartcontracts/algorand/out (20 of them fail without it; remove out after the run).
# cargo-scaas-node needs CAPPED_MEM=6G, the one allowed exception, with nothing else heavy on the machine. No Soroban e2e here: Soroban did not move.
P=2026-11-03-msig-nested
LOGEXT=log # step logs are git-ignored (*.log); only <P>-summary.txt is committed (owner 2026-11-02)
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes docs vectors-check clientkeys ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt soroban cargo-scaas-node node-e2e-anvil named-tests summary"
FAMILIES="ua-rs ua-rs-pq ua-rs-signers ua-rs-json ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb ua-qt soroban"
# "<step>|<form>|<name>": every test added from origin/main (73494fe9) to HEAD in the contracts, node and ua-rs (test functions found in the diff), clientkeys'
# new titles, in the tool's pass form (forms: see the base runner). The ua-py ... ua-dart-frb rows are the client round's own.
NEW_TESTS=$(cat <<'NAMES'
forge|forge|test_authorize_registryWithoutCodeRefuses
forge|forge|test_authorize_lowLevelAnswersAsTheTypedCall
forge|forge|test_groupKindIsAnMsigMember
forge|forge|test_libMsig_popRows
forge|forge|test_libMsig_stopsAtTheThreshold
forge|forge|test_libMsig_sameMemberTwice
forge|forge|test_libMsig_indexPastTheMembers
forge|forge|test_genericAuthIsTheTypedCall
forge|forge|test_genericAuthMalformed
forge|forge|test_twoLevelsOnly
forge|forge|test_hederaNativeInInner
forge|forge|test_memberRegisteredFirst
forge|forge|test_nestedAuthorizes
forge|forge|test_nestedNegatives
forge|forge|test_innerStopsAtThreshold
forge|forge|test_unacceptedAtEitherLevel
forge|forge|test_digestChainBindsOuterAndInner
forge|forge|test_acceptanceAtBothLevels
forge|forge|test_innerHeldByGen1
forge|forge|test_portablePopNested
forge|forge|test_popInnerSlotNeedsItsOwnAcceptance
forge|forge|test_pqEligibleCountsInnerByItsOwnRule
forge|forge|test_setKemKeyNested
forge|forge|test_flatEncodingUnchanged
forge|forge|test_thirdLevelThroughGen1
forge|forge|test_selfMemberHasNoForm
forge|forge|test_n5OneSignatureTwoSlots
forge|forge|test_minimalAtTheInnerLevel
forge|forge|test_spliceOffsets
forge|forge|test_spliceAliasedElement
forge|forge|test_cloneCapPortableOnGen2
forge|forge|test_newGen2OverOldGen1
forge|forge|test_copyReplaysTheStoredAcceptance
forge|forge|test_memberSigHashOf
forge|forge|test_popMemberSigHashes
forge|forge|test_acceptanceCostRows
forge|forge|test_gen1InnerBitsReadOnGen2
forge|forge|test_gen1InnerNativeCapAtTheBound
forge|forge|test_nested_mldsa65
forge|forge|test_nested_mldsa44
forge|forge|test_nested_fndsa512
forge|forge|test_nested_slhdsa128s
forge|forge|test_nested_mldsa65Precompile
forge|forge|test_nested_mostSignatures
forge|forge|test_edges_oneMoreIsRefused
forge|forge|test_edges_fitTheBudget
forge|forge|test_nested_gen2
forge|forge|test_pqzHolderFits2p24WithItsCalldata
forge|forge|test_pqzHolderCalldataFloor
forge|forge|test_registrationCostRows
forge|forge|test_nestedVectors_registrations
forge|forge|test_nestedVectors_typedPopIsTheBlob
forge|forge|test_nestedVectors_records
forge|forge|test_nestedVectors_memberships
forge|forge|test_nestedVectors_copyReplaysTheAcceptance
forge|forge|test_nestedVectors_authorizations
forge|forge|test_nestedVectors_negatives
forge|forge|test_nestedVectors_structures
forge|forge|test_nestedVectors_eligibility
ua-rs|cargo|nested_eligibility_rows
ua-rs|cargo|nested_rows_encode_and_digests
ua-rs|cargo|nested_flat_bytes_unchanged_and_decode_bounded
ua-rs|cargo|nested_minimal_at_both_levels
ua-rs|cargo|nested_replay_rows
ua-rs|cargo|nested_member_kind
ua-rs|cargo|nested_decode_offsets_checked
ua-rs-pq|cargo|verdicts::nested_check_rows
ua-rs-pq|cargo|verdicts::nested_check_negatives
ua-rs-pq|cargo|verdicts::nested_check_records_and_acceptances
ua-rs-pq|cargo|verdicts::nested_n5_one_signature_two_slots
ua-rs-pq|cargo|verdicts::nested_check_inner_acceptance
ua-rs-pq|cargo|verdicts::nested_check_authorizations
ua-rs-json|cargo|registration_args_nested_rows
cargo-scaas-node|cargo|typed::tests::member_sig_json_is_two_levels
cargo-scaas-node|cargo|typed::tests::member_sig_lists_are_bounded
cargo-scaas-node|cargo|typed::tests::nested_sig_bytes_are_the_stored_form
clientkeys|node|nested.json is what the generator writes
clientkeys|node|eligibility: an msig member by its own rule, read from its record
clientkeys|node|registrations: every row verifies, typed list and stored bytes agree, md_I rebuilds
clientkeys|node|N5: one native signature serves both slots of msig-nested-twice, that record only
clientkeys|node|negatives: each row refused with the error of the registry, the same record with its own pop passes
clientkeys|node|structures: a third level, an unregistered inner are refused from the records
clientkeys|node|the minimal rule at both levels
clientkeys|node|records and acceptances: every row verifies, a flipped leaf byte is refused
clientkeys|node|authorizations: a leaf one level down signs md_I, a native leaf UAAuth in the registry domain
clientkeys|node|CTR-UA-37: the stored acceptance replays with no new signature, an msig slot by its list
clientkeys|node|Q4: the minimal rule, every weight vector of up to 4 slots of weight 1-4, every threshold, every subset
clientkeys|node|flat bytes did not change: the empty list encodes as the empty keyData did
clientkeys|node|decodeMemberSigs: canonical, 16 at each level, an index in a u16
clientkeys|node|Soroban stays flat until its round: an msig member and a nested list are refused
clientkeys|node|inner acceptance: accepted(id, index) read at the inner level always, unchecked without it, a pop accepting its own record only
clientkeys|node|replayedMemberSig: truncated or out-of-range bytes are UAUnauthorized, never another throw
clientkeys|node|authorizations: every row as requireAuthorized checks it, valid or UAUnauthorized, unchecked without the accepted bits
ua-py|unittest|test_nested_eligibility
ua-py|unittest|test_nested_registrations
ua-py|unittest|test_nested_memberships
ua-go|go|TestNestedEligibility
ua-go|go|TestNestedRegistrations
ua-go|go|TestNestedMemberships
ua-cs|cs|NestedEligibility
ua-cs|cs|NestedRegistrations
ua-cs|cs|NestedMemberships
ua-dart|dart|nested eligibility
ua-dart|dart|nested registrations
ua-dart|dart|nested memberships
ua-qt|qt|test_nested_rows
ua-c|unittest|test_nested_rows
ua-cxx|ctest|nested_rows
ua-dart-frb|dart|nested rows
ua-rs-json|cargo|inner_json_bounded_and_replay_rows
ua-c|unittest|test_nested_inner
ua-cxx|ctest|nested_inner
ua-qt|qt|test_nested_inner
ua-dart-frb|dart|nested inner
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
