#!/bin/bash
# Token-family rename (owner 2026-10-29 / 30, option (a)): the gates of the branch `token-rename`. Not a copy: it sets the
# step list, log prefix and test names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract, commands, resume
# and guard), as 2026-10-30-ua8-gates.sh does. Own prefix, so the ua8 / no7702 logs in the tree stay as they are.
#   2026-10-30-token-rename-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-30-token-rename-<s>.txt; resume = skip a step whose log ends rc=0 at this commit.
# cargo-scaas-node needs smartcontracts/algorand/out (git-ignored): ALGORAND_ARTIFACTS_CHECK=1 scripts/capped smartcontracts/scripts/build.sh algorand once per checkout.
# Owner rule 2026-10-23: when a docker job is running (docker ps), run with CAPPED_SLOTS=1.
P=2026-10-30-token-rename
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes cargo-scaas-node clientkeys docs named-tests"
FAMILIES=""
# "<step>|<form>|<name>": the test functions the rename renamed (forge pass form), plus the renamed parity / KAT readers
NEW_TESTS=$(cat <<'NAMES'
forge|forge|test_allowlistPinned_wrappedZether
forge|forge|test_allowlistRefusals_wrappedZether
forge|forge|test_everyListedSelectorRuns_wrappedZether
forge|forge|test_uaAllowlist_wrappedZether
forge|forge|test_wrappedZether_flagsValidatedForItsKind
forge|forge|test_validFlags_wrappedKind
forge|forge|test_disclosureOnTheWrappedKind
forge|forge|test_wrapped_classAndBasisMatchTheRule
forge|forge|test_createToken_wrapped_indexesEveryLeg_includingNative
forge|forge|invariant_T_V3_2_wrapped
forge|forge|test_normal_allowlistPinned
forge|forge|test_normal_everyListedSelectorRuns
forge|forge|test_normal_classAndBasisMatchTheRule
forge|forge|test_normalZether_burnUnderUA
forge|forge|test_createToken_normal_emitsOneEventWithProvenance
forge|forge|test_allowlists_normalKind
forge|forge|invariant_T_V3_2_normal
forge|forge|test_parity
forge|forge|test_ruleTableParity
forge|forge|test_dexKat
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
