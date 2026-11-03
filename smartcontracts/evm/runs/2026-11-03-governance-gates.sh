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
STEPS="build forge-ua forge-zether forge-pqz forge-governance forge-v2 forge-rest forge-isolate sizes zether-cross clientkeys docs named-tests summary"
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
forge|forge|test_attack_setGrantMakesAnUnboundedHolderInOneCall
forge|forge|test_fixed_delegableHolderAddsAHolderWithNoOwnerCall
forge|forge|test_fixed_aReservedKindDecodes
forge|forge|test_stated_aSecondFactorysTokenIsOutsideToTheFirst
forge|forge|test_attack_revokedGrantorStripsAnOwnerGrantedHolder
forge|forge|test_attack_parentGrantsBackALeafTheOwnerRevoked
forge|forge|test_fixed_createdWithoutOwnerKeepsAnUnlockedMinter
forge|forge|test_attack_deadLeavesBlockTheRenounce
forge|forge|test_attack_afterRenounceALockedBitsHolderAddsHolders
forge|forge|test_fixed_noScalarMeansNoTotalAndNoWindow
forge|forge|test_fixed_aFloorBricksAPowerWithNoScalar
forge|forge|test_fixed_aScopeOnABuiltPowerBindsNothing
forge|forge|test_attack_leafKeepsAScopeItsParentLost
forge|forge|test_attack_endingDelegationLeavesTheLeaves
forge|forge|test_attack_changingTheWindowRefreshesTheBudget
forge|forge|test_attack_dexTransferLeavesThePowersBehind
forge|forge|test_attack_theHoldersOpIsReachableAsABytesBlob
forge|forge|test_refuted_replayAcrossHolders
forge|forge|test_refuted_relayerAltersTheTarget
forge|forge|test_refuted_replacedOperatorsEnvelope
forge|forge|test_refuted_targetReentersTheHolder
forge|forge|test_attack_isTokenTrustsAnUnregisteredLeg
forge|forge|test_attack_revokedRateAdminsProposalOutlivesIt
forge|forge|test_attack_aLeafsWindowIsNotNarrowed
forge|forge|test_attack_narrowingBelowSpentPanicsTheLeafPath
forge|forge|test_attack_wholeThenLimitedRevivesLeaves
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
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
