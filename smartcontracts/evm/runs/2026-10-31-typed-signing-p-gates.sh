#!/bin/bash
# typed-signing Task PG: the closing gates of Parts P and R (portable typed records + kindName, registry explicit ABI). Not a
# copy: it sets the step list, log prefix and test names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract,
# commands, resume and guard; its ua-rs-json and vectors-check steps are this round's).
#   2026-10-31-typed-signing-p-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-31-typed-signing-p-<s>.txt; resume = skip a step whose log ends rc=0 at this commit (see the base runner).
# A fresh worktree needs the git-ignored inputs as real directories (a symlink named lib / node_modules / out is not ignored,
# the tree would be dirty): smartcontracts/evm/lib, clients/clientkeys/node_modules, smartcontracts/algorand/out.
# cargo-scaas-node needs CAPPED_MEM=6G.
P=2026-10-31-typed-signing-p
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes docs cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node node-e2e-anvil clientkeys ua-rs ua-rs-signers ua-rs-json ua-qt ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb soroban vectors-check named-tests"
# the skipped / empty-suite check (base runner): the one chain family this round touches + the client steps, as UA-8;
# clientkeys keeps its 2 environmental skips, so it is checked by its named tests only
FAMILIES="soroban ua-rs ua-rs-signers ua-rs-json ua-qt ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb"
# "<step>|<form>|<name>": every test name added by P1-P8, P1b, X0, R1, R1b, R1c, R2, R2c (test functions, merge-base 9f88f43b..HEAD;
# renamed tests by their new names), in its tool's pass form (forms: see the base runner). Last block: the node's UA-8 write
# tests, which keep their names over the new call table and sizes (R1, R1b, P1b).
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
clientkeys|node|kind field equals the row's kind
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
cargo-scaas-node|cargo|submit::ua8_registry_writes_are_call_jobs
cargo-scaas-node|cargo|submit::ua8_relayed_pq_register_over_the_cap_is_split
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
