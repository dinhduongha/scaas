#!/bin/bash
# UA-8 Task A13: the closing gates of the portable-registrations branch (contracts, docs, clients). Not a copy: it sets the
# step list, log prefix and test names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract, commands, resume and guard).
#   2026-10-30-ua8-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-30-ua8-<s>.txt; resume = skip a step whose log ends rc=0 at this commit (see the base runner).
# Every client step builds before it tests, so a client that stops building fails its step (rc != 0), never skips.
# named-tests reads NAMED_TESTS_LOG_DIR (default runs/); the guard self-check points it at a scratch copy of the logs.
# cargo-scaas-node needs smartcontracts/algorand/out (git-ignored): ALGORAND_ARTIFACTS_CHECK=1 scripts/capped smartcontracts/scripts/build.sh algorand once per checkout.
# Owner rule 2026-10-23: when a docker job is running (docker ps), run with CAPPED_SLOTS=1.
P=2026-10-30-ua8
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes docs cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node clientkeys ua-rs ua-rs-signers ua-qt ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb named-tests"
FAMILIES=""
# "<step>|<form>|<name>": every test name added by Tasks A1-A11, in its tool's pass form (forms: see the base runner)
NEW_TESTS=$(cat <<'NAMES'
forge|forge|test_T_GAS_register_ua8PerKind
forge|forge|test_T_GAS_setKemKey
forge|forge|test_T_GAS_storePqzPop
forge|forge|test_UA6_gen2GrieferRefused
forge|forge|test_checkedCodePoints
forge|forge|test_kemRecordDigestVectors
forge|forge|test_portablePopDigestVectors
forge|forge|test_pqzKeyRecordDigestVectors
forge|forge|test_purposeTagsV2
forge|forge|test_registrationDigestVectors
forge|forge|test_ua8_attrsShapeRefused
forge|forge|test_ua8_blobChunksRoundTrip
forge|forge|test_ua8_checkedIsChain
forge|forge|test_ua8_copyBetweenRegistries
forge|forge|test_ua8_copyFromState
forge|forge|test_ua8_disabledKindReverts
forge|forge|test_ua8_everyKindFromVectors
forge|forge|test_ua8_frontRunnerDropsPqzPop
forge|forge|test_ua8_frontRunnerGetsIdenticalRecord
forge|forge|test_ua8_gen2ForwardsReads
forge|forge|test_ua8_gen2PqzKeyWhenGen1HasNone
forge|forge|test_ua8_gen2ProvesGen1RegisterKey
forge|forge|test_ua8_gen2RefusesWhenGen1HasPqz
forge|forge|test_ua8_gen2RefusesWritesForGen1
forge|forge|test_ua8_gen2SetPqzKeyForGen1Record
forge|forge|test_ua8_kemBadSigRefused
forge|forge|test_ua8_kemCopyBetweenRegistries
forge|forge|test_ua8_kemEvent
forge|forge|test_ua8_kemGen2RecordElsewhereRefused
forge|forge|test_ua8_kemInitialVersionFromRegister
forge|forge|test_ua8_kemLengthRefused
forge|forge|test_ua8_kemLowerVersionAfterHigher
forge|forge|test_ua8_kemMsigMofN
forge|forge|test_ua8_kemNoOwnerCheck
forge|forge|test_ua8_kemNonHolderRefused
forge|forge|test_ua8_kemRepeatedVersionRefused
forge|forge|test_ua8_kemVersionZeroRefused
forge|forge|test_ua8_largestMsigPopStored
forge|forge|test_ua8_msigNativeMember7702Portable
forge|forge|test_ua8_msigNativeMemberPersonalSignPortable
forge|forge|test_ua8_msigNativeMemberWithCode1271
forge|forge|test_ua8_msigPqEligibleCopy
forge|forge|test_ua8_nonHolderAttrsRefused
forge|forge|test_ua8_popCoversAttrs
forge|forge|test_ua8_pqzPopInRegisterProven
forge|forge|test_ua8_pqzProveLaterOnVerifierChain
forge|forge|test_ua8_pqzTokenAcceptsAfterStorePqzPop
forge|forge|test_ua8_pqzTokenRefusesUnproven
forge|forge|test_ua8_pqzTokenSetPqzKeyThenProve
forge|forge|test_ua8_pqzUnprovenWithoutVerifier
forge|forge|test_ua8_provenKeyStillUnique
forge|forge|test_ua8_setKemKeyByThirdParty
forge|forge|test_ua8_setPqzKeyCopyFromState
forge|forge|test_ua8_setPqzKeyFromVectors
forge|forge|test_ua8_setPqzKeyRefused
forge|forge|test_ua8_sigOkPortablePurposesOnly
forge|forge|test_ua8_storePqzPopBadProofReverts
forge|forge|test_ua8_storePqzPopIdempotent
forge|forge|test_ua8_storePqzPopNoKemExactMessage
forge|forge|test_ua8_storePqzPopWrongBytesRefused
forge|forge|test_ua8_storesEveryField
forge|forge|test_ua8_unprovenListingDoesNotBlockOwner
forge|forge|test_ua8_writeSelectorsPinned
ua-rs|cargo|tags
ua-rs|cargo|portable_vectors
ua-rs|cargo|kem_record_vectors
ua-rs|cargo|pqz_key_record_vectors
ua-rs|cargo|negatives_refused
ua-rs|cargo|native_member_personal_sign
ua-rs|cargo|malformed_msig_key_data
cargo-scaas-node|cargo|submit::ua8_registry_writes_are_call_jobs
clientkeys|node|keys and ids: pq_kat.json's keys, ids from the kind table, the portable PoP (UA-8) on contexts A and B
clientkeys|node|UA-6 / UA-8: a holder registers its PQZ key in the same call: pop over registrationDigest(portablePopDigest(ua, h, 0), pqzPopHash)
clientkeys|node|derived kinds: key data, ids, portable PoP messages, every signature verifies
clientkeys|node|digests: portable pop (UA-8, no chain context), UAAuth, member
clientkeys|node|purposes: every purpose at v1, pop also at v2 (UA-8), kem
clientkeys|node|portable.json reproduced byte for byte
clientkeys|node|portable PoP has no chain context
clientkeys|node|registration digest covers the proof hash
clientkeys|node|kem record digest matches the hand-built words
clientkeys|node|holder refusals
clientkeys|node|pqz key record: signed, portable, write-once, only for a registration without a PQZ key (setPqzKey)
clientkeys|node|C7 scope: personal_sign only for the portable records of code-less native msig members
clientkeys|node|every portable pop verifies
clientkeys|node|the Zether PoP is portable (UA-8 P1): no chain field, over registrationDigest(portablePopDigest(UA, 0, 0), 0)
ua-qt|qt|test_portable
ua-qt|qt|test_pqzKeyRecord
ua-qt|qt|test_kemRecord
ua-py|unittest|test_portable
ua-py|unittest|test_kem_record
ua-py|unittest|test_pqz_key_record
ua-py|unittest|test_personal_sign_portable_purposes
ua-py|unittest|test_holder_refusals
ua-c|unittest|test_portable
ua-c|unittest|test_kem_record
ua-c|unittest|test_pqz_key_record
ua-c|unittest|test_personal_sign_portable_purposes
ua-c|unittest|test_holder_refusals
ua-go|go|TestPortable
ua-go|go|TestKemRecord
ua-go|go|TestPqzKeyRecord
ua-go|go|TestPersonalSignPortablePurposes
ua-go|go|TestHolderRefusals
ua-cs|cs|PortableVectors
ua-cs|cs|KemRecordVectors
ua-cs|cs|PqzKeyRecordVectors
ua-cs|cs|PersonalSignPortablePurposes
ua-cs|cs|HolderRefusals
ua-cxx|ctest|portable
ua-cxx|ctest|kem_record
ua-cxx|ctest|pqz_key_record
ua-cxx|ctest|personal_sign_portable_purposes
ua-cxx|ctest|holder_refusals
ua-dart|dart|portable
ua-dart|dart|kem record
ua-dart|dart|pqz key record
ua-dart|dart|personal_sign of the portable purposes
ua-dart|dart|holder refusals
ua-dart-frb|dart|portable
ua-dart-frb|dart|kem record
ua-dart-frb|dart|pqz key record
ua-dart-frb|dart|personal_sign of the portable purposes
ua-dart-frb|dart|holder refusals
NAMES
)
export P STEPS FAMILIES NEW_TESTS
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
