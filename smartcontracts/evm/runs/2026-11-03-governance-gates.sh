#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# governance: the gates of branch governance at one commit (spec 2026-11-02-governance, plan 2026-11-03-governance). Not a copy: it sets the
# step list, log prefix and test names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract, resume and guard).
#   2026-11-03-governance-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-11-03-governance-<s>.log (git-ignored); the `summary` step writes the committed -summary.txt.
# First line "# <s> at commit <sha>", last line "rc=<n>". A step is skipped when its log ends rc=0 at the current commit and the tree is clean.
# forge runs per test directory, so a failing part reruns alone; forge-rest is every directory the five others leave out.
# at-set-<set>: the whole forge suite at another PQZ set (script/pqz/at-set.sh); only by --only at-set-<set>, when a task asks. A plain run
# and its summary leave them out; `--only summary` lists every at-set step that has a log.
# A fresh worktree needs smartcontracts/evm/lib and clients/clientkeys/node_modules as real directories.
P=2026-11-03-governance
LOGEXT=log # step logs are git-ignored (*.log); only <P>-summary.txt is committed (owner 2026-11-02)
CAPPED_MEM=${CAPPED_MEM:-4G} # capped's own default; the base would lower it to 3G
ZETHER_CROSS_N=10 # test/zether/ZetherProverCross.t.sol: 10 tests, none skipped
FORGE_DIRS="ua zether pqz governance v2"
SETS="n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536"
STEPS="build forge-ua forge-zether forge-pqz forge-governance forge-v2 forge-rest forge-isolate sizes zether-cross clientkeys vectors-check cargo-zether-prover docs named-tests summary"
if [ "$1" = "--only" ]; then
  case $2 in
    at-set-*|summary) for s in $SETS; do
        [ "$2" = "at-set-$s" ] || [ -f "$(dirname "$0")/$P-at-set-$s.$LOGEXT" ] && STEPS="${STEPS% summary} at-set-$s summary"
      done ;;
  esac
fi
FAMILIES=""
extra_step() {
  case $1 in
    build) cd smartcontracts/evm && ../../scripts/capped forge build ;;
    forge-rest) cd smartcontracts/evm && ../../scripts/capped forge test --no-match-path "test/{${FORGE_DIRS// /,}}/**" ;;
    forge-*) cd smartcontracts/evm && ../../scripts/capped forge test --match-path "test/${1#forge-}/**" ;;
    at-set-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#at-set-}" test ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}
# "<step>|<form>|<name>": every test function added from main (b25796b6) to HEAD in smartcontracts/evm/test, a test_attack_* fixed by a task
# under its test_fixed_* name (forms: see the base runner).
NEW_TESTS=$(cat <<'NAMES'
forge|forge|test_createAboveSixtyFourKiBDeploys
forge|forge|test_releaseAboveTheChainLimitIsRefusedByName
forge|forge|test_chainCodeLimitDefaultsToEip7954
forge|forge|test_fixed_setGrantMakesAnUnboundedHolderInOneCall
forge|forge|test_fixed_delegableHolderAddsAHolderWithNoOwnerCall
forge|forge|test_fixed_aReservedKindDecodes
forge|forge|test_stated_aSecondFactorysTokenIsOutsideToTheFirst
forge|forge|test_fixed_revokedGrantorStripsAnOwnerGrantedHolder
forge|forge|test_fixed_parentGrantsBackALeafTheOwnerRevoked
forge|forge|test_fixed_createdWithoutOwnerKeepsAnUnlockedMinter
forge|forge|test_fixed_deadLeavesBlockTheRenounce
forge|forge|test_fixed_afterRenounceALockedBitsHolderAddsHolders
forge|forge|test_fixed_noScalarMeansNoTotalAndNoWindow
forge|forge|test_fixed_aFloorBricksAPowerWithNoScalar
forge|forge|test_fixed_aScopeOnABuiltPowerBindsNothing
forge|forge|test_fixed_leafKeepsAScopeItsParentLost
forge|forge|test_fixed_endingDelegationLeavesTheLeaves
forge|forge|test_fixed_changingTheWindowRefreshesTheBudget
forge|forge|test_attack_dexTransferLeavesThePowersBehind
forge|forge|test_refuted_relayerAltersTheTarget
forge|forge|test_fixed_isTokenTrustsAnUnregisteredLeg
forge|forge|test_attack_revokedRateAdminsProposalOutlivesIt
forge|forge|test_fixed_aLeafsWindowIsNotNarrowed
forge|forge|test_fixed_narrowingBelowSpentPanicsTheLeafPath
forge|forge|test_fixed_wholeThenLimitedRevivesLeaves
forge|forge|test_fixed_aPoolCanBeOwner
forge|forge|test_refuted_reGrantThroughAnotherParentRefreshes
forge|forge|test_refuted_holderWidensItself
forge|forge|test_refuted_lockBypass
forge|forge|test_transfer
forge|forge|test_mtxTransfer
forge|forge|test_mintWholeShape
forge|forge|test_createToken
forge|forge|test_coldSload
forge|forge|test_wholeShapeHasNoRecord
forge|forge|test_bandOnTheScalar
forge|forge|test_total
forge|forge|test_windowOnTheGrid
forge|forge|test_maxUsesAndExpiry
forge|forge|test_mintToUABoundToo
forge|forge|test_editNeverRefreshesABudget
forge|forge|test_leafDebitsItsParent
forge|forge|test_leafMustNarrow
forge|forge|test_onlyDelegableGrants_andOnlyItsOwnLeaves
forge|forge|test_revokingTheParentKillsLeaves_andAGrantBackDoesNotRevive
forge|forge|test_grantorRevokesItsLeaf_noOneElse
forge|forge|test_holderCount_idempotent_andRenounce
forge|forge|test_renounceRefusedWhileAnUnlockedBitHasHolders
forge|forge|test_renounceWithALockedBitsHolderSurvives
forge|forge|test_renounceWithADisabledBitsHolder
forge|forge|test_refusals
forge|forge|test_wrappedPowerIsBound
forge|forge|test_dexPowerIsBound
forge|forge|test_limitedUseIsOneDelegatecall
forge|forge|test_dexInitHoldsBothBitsThroughInitHolder
forge|forge|test_dexAnswersIGovernance
forge|forge|test_dexPowerRefusedInsideASettlement
forge|forge|test_gas_setGrant_fresh
forge|forge|test_gas_mintLimited_everyBound
forge|forge|test_gas_mintLeaf
forge|forge|test_regulatedBitsRefusedOnPlainKinds
forge|forge|test_validBitsHoldsNoRegulatedBit
forge|forge|test_complianceWordIsBitTen
forge|forge|test_regulatedKindPublishesOnTheSameFactory
forge|forge|test_normalKindHasNoRateRole
forge|forge|test_regulatedBitsInvalidOnConfidentialKinds
forge|forge|test_plusZero_transfer_normal
forge|forge|test_plusZero_transfer_wrapped
forge|forge|test_plusZero_mtxTransfer_normal
forge|forge|test_plusZero_mtxTransfer_wrapped
forge|forge|test_plusZero_transferToUA_normal
forge|forge|test_plusZero_transferToUA_wrapped
forge|forge|test_plusZero_uaExecuteTransfer_normal
forge|forge|test_plusZero_uaExecuteTransfer_wrapped
forge|forge|test_plusZero_transfer_normalZether
forge|forge|test_plusZero_transfer_wrappedZether
forge|forge|test_plusZero_mtxTransfer_normalZether
forge|forge|test_plusZero_mtxTransfer_wrappedZether
forge|forge|test_plusZero_transferToUA_normalZether
forge|forge|test_plusZero_transferToUA_wrappedZether
forge|forge|test_plusZero_uaExecuteTransfer_normalZether
forge|forge|test_plusZero_uaExecuteTransfer_wrappedZether
forge|forge|test_plusZero_transfer_normalPqz
forge|forge|test_plusZero_transfer_wrappedPqz
forge|forge|test_plusZero_mtxTransfer_normalPqz
forge|forge|test_plusZero_mtxTransfer_wrappedPqz
forge|forge|test_plusZero_transferToUA_normalPqz
forge|forge|test_plusZero_transferToUA_wrappedPqz
forge|forge|test_plusZero_uaExecuteTransfer_normalPqz
forge|forge|test_plusZero_uaExecuteTransfer_wrappedPqz
forge|forge|test_everyKindIdDecodes
forge|forge|test_retiredKindsRefusedAtDeployImplementation
forge|forge|test_regulatedKindsOffUntilPublished
forge|forge|test_unregisteredRefusesEveryKindFromTwo
forge|forge|test_namespaceRootsAndOffsetsArePinned
forge|forge|test_eachWordRefusedOnAScalarlessBit
forge|forge|test_windowWithoutPerWindowRefused
forge|forge|test_newHolderEmitsRoleGranted
forge|forge|test_lockedMinterSurvivesNoOwner
forge|forge|test_counts_row1
forge|forge|test_counts_row2
forge|forge|test_counts_row3
forge|forge|test_counts_row4
forge|forge|test_counts_row5
forge|forge|test_counts_row6
forge|forge|test_counts_row7
forge|forge|test_counts_row8
forge|forge|test_counts_row9
forge|forge|test_counts_row10
forge|forge|test_counts_row11
forge|forge|test_ownerReadmitsABarredAccount
forge|forge|test_hasRoleMeansListed
forge|forge|test_leafThatRenouncesFirstIsBarred
forge|forge|test_expiredParentAddsNobody
forge|forge|test_exhaustedParentAddsNobody
forge|forge|test_leafMaxUsesByWhatRemains
forge|forge|test_windowChangeIntoASpentPeriodRefused
forge|forge|test_windowChangeAfterBothGridsPassed
forge|forge|test_wholeHolderStaleWindowRefusesNothing
forge|forge|test_expiredRootCountsUntilRevoked
forge|forge|test_newHolderTakesTwoCalls
forge|forge|test_eachWidenedWordTakesTwoCalls
forge|forge|test_eachNarrowedWordRunsAtOnce
forge|forge|test_finiteOnEachUnboundedWordRunsAtOnce
forge|forge|test_windowWithItsLimitRunsAtOnce
forge|forge|test_finiteToUnboundedTakesTwoCalls
forge|forge|test_leafMadeARootTakesTwoCalls
forge|forge|test_grantRoleOnLimitedTakesTwoCalls
forge|forge|test_confirmWithOtherTermsReverts
forge|forge|test_confirmBeforeEtaReverts
forge|forge|test_afterTheWindowThePendingIsDead
forge|forge|test_afterRenounceNobodyConfirms
forge|forge|test_afterTransferTheNewOwnerProposesAgain
forge|forge|test_aToBToAKillsThePending
forge|forge|test_cancelledTransferKillsNothing
forge|forge|test_delayZeroIsOneCall
forge|forge|test_revokeDeletesThePending
forge|forge|test_grantorRevokeKeepsThePending
forge|forge|test_renounceDeletesThePending
forge|forge|test_narrowingDeletesThePending
forge|forge|test_cancelGrantLiveAndDead
forge|forge|test_pendingGrantSaysLive
forge|forge|test_delayAboveThirtyDaysRefused
forge|forge|test_dexInitHoldsBothBitsWithADelay
forge|forge|test_holderCountCountsInitOnceAndNeverAPending
forge|forge|test_lastProposedAtMoves
forge|forge|test_configFieldsFailClosedUntilBuilt
forge|forge|test_loanApprovalInABand
forge|forge|test_loanLeafDebitsItsManager
forge|forge|test_subtreeAddAndRemove
forge|forge|test_subtreeOutsideTheScopeRefused
forge|forge|test_subtreeHeadWithNoBudgetRefused
forge|forge|test_moveWithinAGroup
forge|forge|test_moveOutOfTheGroupRefused
forge|forge|test_bitsAbove127AreApplicationBits
forge|forge|test_bits64To127AreScaasBits
forge|forge|test_registeredForceLegRefused
forge|forge|test_registeredModerateLegRefused
forge|forge|test_unregisteredLegIsOutside
forge|forge|test_secondFactoryLegIsOutside
forge|forge|test_registeredPlainLegAccepted
forge|forge|test_pauseAndFreezeLegsStayAllowed
forge|forge|test_legCheckRunsOnEveryWrappedKind
forge|forge|test_capHolds_wrap
forge|forge|test_capHolds_wrapToUA
forge|forge|test_capHolds_mtxWrapShieldZether
forge|forge|test_capHolds_mtxWrapShieldPqz
forge|forge|test_capHolds_mtxWrapOrder
forge|forge|test_capHolds_uaWrapOrder
forge|forge|test_capHolds_mint
forge|forge|test_capHolds_mintToUA
forge|forge|test_unwrapToEmptyThenInsufficientReserve
forge|forge|test_unitsTransferAfterTheReserveIsEmpty
forge|forge|test_executeRateOnAHybridShortOfSupply
forge|forge|test_rateFallOnAHybridNeedsNoAddReserve
forge|forge|test_rateFallWithDisabledLegStillRefusedOnAHybrid
forge|forge|test_executeRateNonHybridStillChecksSupply
forge|forge|test_disableMintableLeavesAHybrid
forge|forge|test_mintToTheCapStopsWraps
forge|forge|test_addReserveRefusedOnADisabledLegOfAHybrid
forge|forge|test_unshieldUnwrapShortReserveRevertsBeforeTheProofZether
forge|forge|test_unshieldUnwrapShortReserveRevertsBeforeTheProofPqz
forge|forge|test_mintableWithoutMaxSupplyRefused
forge|forge|test_maxSupplyWithoutMintableRefused
forge|forge|test_limitedMinterBindsOnAWrappedKind
forge|forge|test_nonHybridWrapReadsNoNewSlot
forge|forge|test_minterNeverMintsIntoAShieldedBalance
forge|forge|test_rescueForeignToken
forge|forge|test_rescueNativeLessReserve
forge|forge|test_rescueLegSurplusOnly
forge|forge|test_rescueAliasOfALegRefused
forge|forge|test_rescuePastAShortLeg
forge|forge|test_rescueReentrantAssetRefused
forge|forge|test_rescueOwnTokenRefused
forge|forge|test_rescueToDesignatorRefusedNative
forge|forge|test_rescueOffWithoutTheBit
forge|forge|test_rescueOnNormalTakesAll
forge|forge|test_rescueNativeOnNormal
forge|forge|test_rescueLegShortfallNamesItsError
forge|forge|test_rescueToThisOrAPoolRefusedAtInit
forge|forge|test_tokenAnswersIRescuableOnlyWithTheBit
forge|forge|test_pullerRescueWholeBalance
forge|forge|test_pullerRescueOff
forge|forge|test_pullerRescueCannotSpendAllowances
forge|forge|test_interfaceIdIsOneOnDexAndToken
forge|forge|test_rescueOnTheZetherKinds
forge|forge|test_rescueOnThePqzKinds
forge|forge|test_govRouterIsTheReleases
forge|forge|test_derivedUAOwnsAndGrantsThroughTheRouter
forge|forge|test_derivedUAMintsThroughTheRouter
forge|forge|test_dexOwnedByADerivedUA
forge|forge|test_nativeCallerIsItsPaddedAddress
forge|forge|test_routerSubjectReadOnlyFromTheRouter
forge|forge|test_routerSubjectZeroRefused
forge|forge|test_contractOnlyBitToADerivedUARefused
forge|forge|test_poolsAndZeroRefusedAsOwnerAndHolder
forge|forge|test_eachOpByMtx
forge|forge|test_eachOpByUa
forge|forge|test_pqMsigOwnsGrantsMintsAndHandsOver
forge|forge|test_nestedTermsRoundTrip
forge|forge|test_wrongSubjectRefusedNonceUnspent
forge|forge|test_wrongSignerRefused
forge|forge|test_starvedRelayerUAVerifyGasNonceUnspent
forge|forge|test_msigBelowThresholdRefused
forge|forge|test_msigSlotNotAcceptedIsInert
forge|forge|test_refuted_targetReentersTheRouter
forge|forge|test_refuted_formerOwnersEnvelope
forge|forge|test_targetWithoutCodeRefused
forge|forge|test_refuted_replayAcrossRoutersAndChains
forge|forge|test_feeModeIsNone
forge|forge|test_fixed_theRoutersOpIsNotReachableAsABytesBlob
forge|forge|test_cancelNonceStays
forge|forge|test_subjectOnlyToTheLiveTarget
forge|forge|test_subjectClearedInTheSameTransaction
forge|forge|test_noReceive
forge|forge|test_domain
forge|forge|test_grantTermsTypehashIsPinned
forge|forge|test_grantRoleTypehashIsPinned
forge|forge|test_uaGrantRoleTypehashIsPinned
forge|forge|test_revokeRoleTypehashIsPinned
forge|forge|test_uaRevokeRoleTypehashIsPinned
forge|forge|test_setGrantTypehashIsPinned
forge|forge|test_uaSetGrantTypehashIsPinned
forge|forge|test_cancelGrantTypehashIsPinned
forge|forge|test_uaCancelGrantTypehashIsPinned
forge|forge|test_disableFeatureTypehashIsPinned
forge|forge|test_uaDisableFeatureTypehashIsPinned
forge|forge|test_transferOwnershipTypehashIsPinned
forge|forge|test_uaTransferOwnershipTypehashIsPinned
forge|forge|test_acceptOwnershipTypehashIsPinned
forge|forge|test_uaAcceptOwnershipTypehashIsPinned
forge|forge|test_renounceOwnershipTypehashIsPinned
forge|forge|test_uaRenounceOwnershipTypehashIsPinned
forge|forge|test_renounceRoleTypehashIsPinned
forge|forge|test_uaRenounceRoleTypehashIsPinned
forge|forge|test_mintTypehashIsPinned
forge|forge|test_uaMintTypehashIsPinned
forge|forge|test_mintToUATypehashIsPinned
forge|forge|test_uaMintToUATypehashIsPinned
forge|forge|test_disableWrapTypehashIsPinned
forge|forge|test_uaDisableWrapTypehashIsPinned
forge|forge|test_proposeRateTypehashIsPinned
forge|forge|test_uaProposeRateTypehashIsPinned
forge|forge|test_cancelRateTypehashIsPinned
forge|forge|test_uaCancelRateTypehashIsPinned
forge|forge|test_executeRateTypehashIsPinned
forge|forge|test_uaExecuteRateTypehashIsPinned
forge|forge|test_setMarketTypehashIsPinned
forge|forge|test_uaSetMarketTypehashIsPinned
forge|forge|test_setExchangeTargetTypehashIsPinned
forge|forge|test_uaSetExchangeTargetTypehashIsPinned
forge|forge|test_setListedOnlyTypehashIsPinned
forge|forge|test_uaSetListedOnlyTypehashIsPinned
forge|forge|test_setFeeSplitTypehashIsPinned
forge|forge|test_uaSetFeeSplitTypehashIsPinned
forge|forge|test_govRouterBeforeTheReleases
forge|forge|test_routerRow_GrantRole
forge|forge|test_routerRow_RevokeRole
forge|forge|test_routerRow_SetGrant
forge|forge|test_routerRow_CancelGrant
forge|forge|test_routerRow_DisableFeature
forge|forge|test_routerRow_TransferOwnership
forge|forge|test_routerRow_AcceptOwnership
forge|forge|test_routerRow_RenounceOwnership
forge|forge|test_routerRow_RenounceRole
forge|forge|test_routerRow_Mint
forge|forge|test_routerRow_MintToUA
forge|forge|test_routerRow_DisableWrap
forge|forge|test_routerRow_ProposeRate
forge|forge|test_routerRow_CancelRate
forge|forge|test_routerRow_ExecuteRate
forge|forge|test_routerRow_SetMarket
forge|forge|test_routerRow_SetExchangeTarget
forge|forge|test_routerRow_SetListedOnly
forge|forge|test_routerRow_SetFeeSplit
forge|forge|test_routerRow_CancelNonce
forge|forge|test_routerRow_UACancelNonce
clientkeys|node|GovernanceRouter: 38 rows equal GovRouterTypehash.t.sol, target the first op word, fee mode NONE, the router domain only
clientkeys|node|a router row refuses a field off GrantTerms, a value out of range, a string bool, another domain; target is signed
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
