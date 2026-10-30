#!/bin/bash
# DEX round Task T17: the gates of the branch `dex-round`. Not a copy: it sets the step list, log prefix and test names,
# then runs 2026-10-27-metatx-split-gates.sh (the same step contract, commands, resume and named-tests guard), as
# 2026-10-30-token-rename-gates.sh does. Own prefix, so the other rounds' logs in the tree stay as they are.
#   2026-10-30-dex-round-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-30-dex-round-<s>.txt; resume = skip a step whose log ends rc=0 at this commit.
# cargo-scaas-node needs smartcontracts/algorand/out (git-ignored): scripts/capped smartcontracts/scripts/build.sh algorand
# once per checkout. clientkeys needs clients/clientkeys/node_modules (npm ci, or a symlink to another checkout's).
# Owner rule 2026-10-23: when a docker job is running (docker ps), run with CAPPED_SLOTS=1.
P=2026-10-30-dex-round
STEPS="forge-n2304-kmax4096 sizes docs cargo-scaas-node node-e2e-anvil clientkeys named-tests"
FAMILIES=""
# "<step>|<form>|<name>": the tests T1-T14 built (git diff of the test functions, merge-base..T16), in their pass form,
# plus the existing tests the tasks rewrote (test_dexKat T9, test_pathB_dexChecksTheMatchedPart T1,
# guard::the_call_table_is_pinned T12, dex::limits_and_the_settlement_mirror_... T11, the clientkeys trade-order test T14).
# Not listed: the invariant_* of T8 (forge prints an invariant "[PASS] <name>" without "(", which the forge form does not
# match; their PASS lines are in the forge log, DexInvariantTest) and the opt-in Uniswap fork tests of T10 (skipped
# without the fork RPC, PD8; run log runs/2026-10-30-dex-round-fork.txt).
NEW_TESTS=$(cat <<'NAMES'
forge|forge|test_uaTrade_belowHalfSettles
forge|forge|test_ua_minFill_remainderClosesBelowMinFill
forge|forge|test_settle_makerAtTenPercent_settles
forge|forge|test_settle_minFill_remainderClosesBelowMinFill
forge|forge|test_settle_pathAOrderFilledInFiveSettlements
forge|forge|test_pathB_signedMinFill_isEnforced
forge|forge|test_batch_secondPlanFails_othersSettle
forge|forge|test_batch_allFail_nothingSettled
forge|forge|test_batch_lengthMismatch
forge|forge|test_batch_exchangeOneFromOutside_notSelf
forge|forge|test_batch_restorePulledInteraction_forbidden
forge|forge|test_batch_relayerBindingAndFeeShare_followTheCaller
forge|forge|test_batch_laterPlanSeesEarlierPulled
forge|forge|test_batch_realSigCheckGasStarved_revertsWhole
forge|forge|test_batch_realUAVerifyGas_revertsWhole
forge|forge|test_batch_forgedStarvationFromTarget_onlyThatPlan
forge|forge|test_batch_returnbombTarget_onlyThatPlan
forge|forge|test_batch_gasBurningTarget_laterPlansFailEmpty
forge|forge|test_exchange_forbiddenSelector_restorePulled
forge|forge|test_exchange_failingTarget_wrappedAsInteractionFailed
forge|forge|test_exchange_targetForgingStarvation_isInteractionFailed
forge|forge|test_exchange_returnbombTarget_boundedCopy
forge|forge|test_exchange_successReturnDataNotCopied
forge|forge|test_GAS_hybrid_1x1_oneHop
forge|forge|test_GAS_hybrid_1x2_oneHop
forge|forge|test_GAS_batch_overheadPerPlan
forge|forge|test_GAS_settle_1x1_unchanged
forge|forge|test_hybrid_makersAtTheirPrice_takerGetsAllAboveTheFloor
forge|forge|test_hybrid_events_makerLegSettled_takerExchangeLegSettled
forge|forge|test_hybrid_fees_makersOnReceive_takerOnceOnFloor_surplusFeeFree
forge|forge|test_hybrid_outputBelowFloor_insufficientOutput
forge|forge|test_hybrid_fillMismatch
forge|forge|test_hybrid_marketNotListed
forge|forge|test_hybrid_selfTrade_takerIsMaker
forge|forge|test_hybrid_twoMakersOneSigner_settle
forge|forge|test_hybrid_duplicateOrder
forge|forge|test_hybrid_makerWrongRelayer
forge|forge|test_hybrid_listedPools_takerFlag_makerFlagIgnored
forge|forge|test_hybrid_zeroMakers
forge|forge|test_hybrid_zeroOutsideSell
forge|forge|test_hybrid_takerIoc_closedAtThePull
forge|forge|test_hybrid_takerFok
forge|forge|test_hybrid_takerPathB_refundsTheRest
forge|forge|test_hybrid_makerPathB
forge|forge|test_hybrid_uaMaker_and_outsideMaker
forge|forge|test_hybrid_staleMaker_revertsWholePlan
forge|forge|test_hybrid_reentry_refused
forge|forge|test_hybrid_gasBurningTarget
forge|forge|test_hybrid_designatorSubmitterAndRelayer_open
forge|forge|test_hybridVia_executorPaysShort_insufficientOutput
forge|forge|test_hybridVia_executorPaysMore_toTaker
forge|forge|test_hybridVia_executorNotListed
forge|forge|test_hybrid_refund_soldAboveMinFill_settlesAndRefunds
forge|forge|test_hybrid_refund_noFeeOnRefund
forge|forge|test_hybrid_refund_makersNeverGetTheRemainder
forge|forge|test_hybrid_refund_soldBelowMinFill_reverts
forge|forge|test_hybrid_refund_fokTaker_reverts
forge|forge|test_hybrid_refund_soldZero_zeroFill
forge|forge|test_hybrid_refund_worsePrice_priceLimit
forge|forge|test_hybrid_refund_leftoverAboveOutsideSell_conservationBroken
forge|forge|test_hybrid_refund_pathBTaker_refundIsLeftoverPlusRemainder
forge|forge|test_hybrid_refund_iocTaker_staysClosed
forge|forge|test_hybrid_refund_viaExecutor
forge|forge|test_hybrid_refund_gtcTakerPulledIsTheSoldPart
forge|forge|test_hybrid_refund_restoresCapacity_gtcRefillsLater
forge|forge|test_hybrid_refund_outsideTaker_restoredOnTheDex
forge|forge|test_restorePulled_onlyOrderDex
forge|forge|test_restorePulled_boundedByThisTxPull
forge|forge|test_restorePulled_noCarryAcrossTx
forge|forge|test_restorePulled_noOpCancelClearsTheCounter
forge|forge|test_restorePulled_uaOrder
forge|forge|test_hybrid_forbiddenSelector_restorePulled
forge|forge|test_hybrid_routeOverspendsA_conservationBroken
forge|forge|test_hybrid_interactionMovesAOut_conservationBroken
forge|forge|test_hybrid_floorBelowTakerLimit_priceLimit
forge|forge|test_hybrid_extraTokensHop
forge|forge|test_hybrid_uaTaker
forge|forge|test_hybrid_feeOnTransferSellToken_conservationBroken
forge|forge|test_dexKat_newEntriesRoundTrip
forge|forge|test_mode3_exchangePlan_takerAndTwoMakers_viaMockV2
forge|forge|test_mode3_exchangePlan_viaMockV3Router
forge|forge|test_mode3_exchangePlan_takerIocAndFok
forge|forge|test_mode3_exchangePlan_uaMaker_outsideMaker
forge|forge|test_mode3_exchangePlan_staleMaker_revertsWithItsHash
forge|forge|test_mode3_exchangePlan_excessAToMakersProRata
forge|forge|test_mode4_partialCow_netThroughAmm_bothFilled
forge|forge|test_mode4_clearingPrice_ammMarginal
forge|forge|test_mode4_clearingPrice_midpointWithoutPool
forge|forge|test_mode4_ring3_noInteractions_remainderToLastReceiver
forge|forge|test_mode4_ring_intermediateLeftover_conservationBroken
forge|forge|test_mode4_legAtMinFillBelowHalf
forge|forge|test_mode4_twoCowPlansInOneBatch
forge|forge|test_outsideLeg_belowHalfSettles
forge|forge|test_minFill_signerMinimum_andFillOrKill
forge|forge|test_minFill_belowHalfSettles
forge|forge|test_minFill_zeroAcceptsAnyFill
forge|forge|test_minFill_remainderClosesBelowMinFill
forge|forge|test_minFill_belowSignedMinFill_reverts
forge|forge|test_executor_onlyDex
forge|forge|test_executor_v3Callback_nonPool_refused
forge|forge|test_executor_v4Callback_notPoolManager_refused
forge|forge|test_executor_v3_twoHops_wholeBalance
forge|forge|test_executor_v4_hop
forge|forge|test_executor_v4_nativeCurrency_refused
forge|forge|test_executor_leftover_refused
forge|forge|test_executor_strayBalance_becomesSurplus
forge|forge|test_executor_hopKindOff
forge|forge|test_executor_constructor_dependenciesMustBeContracts
forge|forge|test_executor_viaDex_mtxExchangeVia_endToEnd
forge|forge|test_executor_viaDex_mtxHybridVia_withRefund
forge|forge|test_dexKat
forge|forge|test_pathB_dexChecksTheMatchedPart
cargo-scaas-node|cargo|dex::min_fill_is_the_signed_min_fill
cargo-scaas-node|cargo|dex::matcher_fills_a_maker_below_half
cargo-scaas-node|cargo|dex::leg_below_min_base_amount_skipped_unless_closing
cargo-scaas-node|cargo|dex::depth_keeps_large_min_fill_in_its_own_bucket
cargo-scaas-node|cargo|dex::depth_bucket_edge_is_min_in_base_equal_to_min_base_amount
cargo-scaas-node|cargo|dex::limits_and_the_settlement_mirror_the_contract_including_rounding
cargo-scaas-node|cargo|dex::venue::ticker_ignores_the_min_fill_bucket
cargo-scaas-node|cargo|dex::venue::a_wrapped_empty_interaction_revert_is_out_of_gas
cargo-scaas-node|cargo|guard::hybrid_and_batch_calldata_round_trip_the_kat
cargo-scaas-node|cargo|guard::hybrid_and_batch_only_to_a_listed_dex
cargo-scaas-node|cargo|guard::a_wrapped_empty_interaction_revert_is_out_of_gas
cargo-scaas-node|cargo|guard::the_call_table_is_pinned
node-e2e-anvil|cargo|dex_fill_below_half_settles_on_anvil
clientkeys|node|trade order: exactly the order the client built, on a pinned DEX or wrapper (CLI-SGN-35, CLI-SGN-36)
clientkeys|node|a bid's minFill from a base minimum and back (CLI-SGN-35)
clientkeys|node|a base minimum that needs more than the bid's amount is refused
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
