# UA-8 portable UA registrations (steps 1–2: EVM, Soroban) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** a UA registered on one chain can be registered on any other chain, by anyone, from the same record bytes: the
portable proof of possession, every `register` field in contract state, the optional PQZ proof with a `proven` flag,
the KEM (chat) key records, relayable writes without a fee, and the `checked` field — on EVM (`UARegistry`, Part A)
and on Soroban (the `SmartKeyAccount` factory's registry entries, Part B).

**Architecture:** Part A on branch `ua8` (worktree `.claude/worktrees/ua8`) from `main` at the plan's commit, in
parallel with the token-family rename in its own worktree (TODO "Now (order)" step 2; the only shared file is
`src/pqz/PqzCore.sol`, where Part A changes one function, `_keyPtr`). Order: the JS reference and the vectors first
(A1–A3: every PoP in the vector files moves to the portable digest), then Solidity (A4–A8), the other reproducers
(A9–A10), scripts and node (A11), docs (A12), gates (A13). Part B starts only when the 4b Soroban spec exists and its UA
base has landed on `main` (TODO step 4, "4b Soroban (UA base) + UA-8 step 2 in one round"); it branches `ua8-soroban`
from `main` after both Part A and the 4b round's UA base are merged. Code and tests on a local Protocol 30 network; the
Stellar testnet e2e (B10) only after 2026-11-03, as the last step of the round.

**Tech Stack:** Solidity / Foundry v1.8.5 (`evm_version = "amsterdam"`), SSTORE2; Node `node --test` with
`@noble/curves` 2.4.0 + `@noble/post-quantum` 0.7.1 (`clients/clientkeys`, the vector generators); Rust `scaas-ua`
(`clients/ua-rs`), `zether-prover`, cxx-qt (`clients/ua-qt`, Qt 6.12), .NET (`ua-cs`), Python / Go / C / C++ / Dart
reproducers; Part B: Rust `soroban-sdk` at the Protocol 30 release (Task B0), `stellar/quickstart` at Protocol 30
(docker, pinned digest), `scaas-node` Soroban adapter.

**Spec:** `docs/superpowers/specs/2026-10-25-ua8-portable-registrations.md` (P1–P11, §3 work items 1–7, the family
order and "steps 1–2 only"). Background: `docs/research/pq-signatures-per-family.md` (CAP-0087
`verify_sig_ml_dsa_{44,65,87}`, Protocol 30); `docs/contracts/accounts.md` §1.4 (CTR-UA-06/-07), §1.8 (registry),
§1.15, §1.16; TODO.md "Now (order)" (owner 2026-10-29) steps 2 and 4 and "Details of the registration items".

## Global Constraints

Binding rules of the design (quoted or restated without change):

- P1: "`portablePopDigest = keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)`" — no chain id, no registry
  address; the `R_REG` proof over `uaMessage(0x0142, POP_V2, portablePopDigest)`; the signer's `pop` over
  `uaMessage(kind, POP_V2, keccak256(portablePopDigest ‖ pqzPopHash))`; "`register` accepts only this form (one rule;
  all chains are test-only, so the registries are redeployed with no migration)".
- P2: one `register(kind, keyData, UAAttrs attrs, pop, pqzPop)`, permissionless, the submitter pays gas; "UA-8 stores
  every `register` field in contract state" (`pop`, `pqzPop`, the KEM record and its signature, SSTORE2); the event
  carries them as well; `keyData` alone defines the UA id.
- P3: the kind must be enabled in the target registry (else it reverts like any registration of a disabled kind).
- P4 / P5: the PQZ (balance) key is immutable; only the KEM key changes; a KEM record `(ua, version, pk)` is signed over
  a chain-independent digest, stored by anyone, in any order, each `(ua, version)` once; **no revocation**; version v
  names the same key on every chain.
- P6 unchanged: UA ids, key data, `keyHash` / `_keyOwner` uniqueness per chain (signer keys and **proven** PQZ keys),
  generations and kind caps, chain-bound write authorization (`uaAuthDomainSeparator`), ML-DSA expanded-key caches.
- P7: "One scheme only: ML-KEM-1024 + X25519", the contract "accepts only 1,600-byte keys"; only the U3 holders
  (`mldsa44` / `mldsa65` / `fndsa512`, PQ-eligible `msig`; not `slhdsa128s`) hold a KEM key; **no one-owner check** for
  KEM keys; storage keyed `(ua, keyId)` with `keyId = version`; views `kemKeyOf`, `kemKeyAt`, `popOf`, `pqzPopOf`;
  event `UAKemKeySet(ua, version, keyHash, kemPk, sig)` (built form: it carries the written bytes).
- P8: `pop` always required and checked; only PQ holders attach a PQZ key or a KEM record; a PQZ key always comes with
  `attrs.pqzPopHash ≠ 0`; the proof bytes optional in `register`, else `storePqzPop`; `proven = true` only where the PQZ
  verifier checked them; PQZ tokens accept only proven keys; one UA per PQZ key only among proven keys.
- P9: `setKemKey` (signed) and `storePqzPop` (no signature, hash check, no-op when stored) are relayable by anyone,
  "without a chain and without a fee"; **no `mtx*` fee forms**.
- P10: the record has "the same bytes on every family"; one vector file under `smartcontracts/vectors/ua/` run by
  every family's tests; a family accepts only the kinds it verifies; PQZ unproven where there is no verifier; anyone
  may submit (the family's storage rule); `keyHash` uniqueness per family.
- P11: relayer-checked mode rules 1–6 (the relayer checks off chain before it submits; only listed relayers write in
  this mode, the list given at deployment; `checked = chain | relayer(<id>) | none` per part, stored and in the event;
  everything needed to re-check is stored and clients always re-verify; a relayer-checked record never authorises
  anything on that chain; the residual of a bad record taking a write-once slot is accepted). EVM is status (a):
  everything on chain, `checked = chain`.

Owner rulings that bind every task:

- Decisions are recorded in full in `docs/decisions.md` (content, who: "owner <date>" or "controller call, owner may
  override", status, commit); no bare labels (`UA8-D7` always comes with its content).
- No zero-gas assumption: no gas price 0 and no block-limit assumption of our chains (the precompile and these
  contracts may ship to customer chains); a full PQ registration that does not fit one block uses `storePqzPop`.
- Parameter sets are named only `n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`, `n2816-kmax65536`.
- Code size: the only ceiling is 65,536 B (EIP-7954); the size gate's ratchet baseline records the new numbers; no size
  work.
- Heavy commands (forge, cargo, npm, dotnet, cmake, dart, docker) only through `scripts/capped`, never inside
  `timeout`; cargo `-j2`; every container gets `--memory`; `dotnet build-server shutdown` after a capped `dotnet`.
- Every multi-step gate logs per step (`# <step> at commit <sha>` first line, `rc=<n>` last line) and skips steps done
  at the same commit with a clean tree (resume, never restart).
- No full pqz-core gate: no core code and no set parameter changes (pqz-core is not touched, UA8-D14); the affected
  steps only.
- Superseded built code goes to a legacy area, never deleted (UA8-D13). All chains are test-only: no migration.
- One rule for every chain kind (no L1 / L2 split). Every state-changing write here is relayable.
- Commit per task on the task's branch, message `ua8 A<n>: …` / `ua8 B<n>: …` ending
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; no merge, no push (owner's go only).
- The SCaaS testnet (7622) is not touched here: its registry is redeployed once in fs3 Task 13, so Part A lands before
  fs3 Task 13.

## Plan decisions (controller calls, owner may override; recorded in decisions.md by Tasks A12 / B8)

- **UA8-D1 Encoding.** Every UA-8 digest is `keccak256` of 32-byte words in `abi.encode` order:
  `portablePopDigest = keccak256(abi.encode(PURPOSE_POP_V2, ua, pqzKeyHash, kemRecordHash))`,
  `registrationDigest = keccak256(abi.encode(portablePopDigest, pqzPopHash))`,
  `kemRecordDigest = keccak256(abi.encode(KEM_RECORD_TAG, ua, uint256(version), keccak256(kemPk)))` (the version as a
  big-endian 32-byte word). For 32-byte fields `abi.encode` equals the concatenation `‖`, so every family computes the
  same bytes with its keccak256. Tags: `PURPOSE_POP_V2 = keccak256("scaas.ua.purpose.pop.v2")`,
  `PURPOSE_KEM = keccak256("scaas.ua.purpose.kem.v1")`, `KEM_RECORD_TAG = keccak256("scaas.ua.kem-record.v1")`.
- **UA8-D2 One signed digest for every kind.** The signer's `pop` — and each member of a PQ-eligible `msig` (members
  under `member`, as today) — signs `uaMessage(kind, PURPOSE_POP_V2, registrationDigest)`; P3's "members sign
  `uaMessage(MSIG, POP_V2, portablePopDigest)`" is read as this digest, so one signature covers the UA, both attribute
  hashes and the proof hash for every kind. Zether (`0x0141`) and the group kinds keep their schemes; only the message
  changes. A non-PQ-eligible `msig` keeps the empty `pop`.
- **UA8-D3 KEM versions start at 1.** `attrs.kemVersion = 0` and an empty `kemPk` mean "no KEM record" (P2 "0 =
  absent"); `kemRecordHash = kemRecordDigest(ua, kemVersion, kemPk)`, 0 without a record. `setKemKey` refuses version
  0.
- **UA8-D4 The initial KEM record travels with `register`.** It is stored as version `attrs.kemVersion` with an empty
  `sig`: its consent is the registration `pop`, which covers `kemRecordHash`. `kemKeyAt(ua, v)` returns `sig = ""` for
  that version; it reaches another chain only through that chain's `register` (which must carry the same record, or
  the `pop` fails).
- **UA8-D5 A KEM signature has the `pop` format.** `setKemKey(ua, version, kemPk, sig)`: `sig` is the kind's raw
  signature for a single key, `abi.encode(MemberSig[])` for an `msig` (members under `member`), over
  `uaMessage(kind, PURPOSE_KEM, kemRecordDigest(ua, version, kemPk))`, verified against the stored key data. The same
  bytes on every family (P10); a family that decodes `msig` signatures parses this ABI layout.
- **UA8-D6 Native `msig` members stay chain-bound.** A native member signs the registry's EIP-712 `uaAuthDigest`
  (CTR-UA-24 unchanged: an EOA never signs a raw digest), so a `pop` or KEM signature whose signing set has a native
  member is valid only on its own registry; copying it needs fresh native signatures. Derived members are portable.
- **UA8-D7 Every field in state, chunked.** `register` stores `abi.encode(keyData, pop)`, `pqzPop` and each KEM
  version's `pk ‖ sig` as SSTORE2 chunks of at most `BLOB_CHUNK = 32,768` B (the largest `msig` PoP the gas bound admits
  on a chain with a larger `verifyBudget` exceeds one 64 KiB code blob). `registrationOf(ua)` returns exactly the
  `register` arguments. The PQZ key keeps its own single pointer (`PqzCore` checks its code length).
- **UA8-D8 An unproven PQZ key claims nothing.** No `keyOwner` entry and no `0x0142` list entry until proven; the
  `keyOwner` check (`UAKeyInUse`) and the list append happen when the key becomes proven (`register` with a checked
  proof, or `storePqzPop` on a registry with the verifier). On a registry without the PQZ verifier (`0x0142` slot
  empty) a PQZ key is accepted unproven (formerly `UAKindDisabled(0x0142)`).
- **UA8-D9 PQZ tokens read `proven`.** New view `pqzKeyOf(ua) → (address ptr, bytes32 pqzPopHash, bool proven)`;
  `PqzCore._keyPtr` refuses an unproven key with the existing `AccountNotRegistered(ua)` (no new token error);
  `recordOf` keeps its shape and returns the pointer for unproven keys too (directory).
- **UA8-D10 `checked` on EVM is derived, not stored.** Every part the EVM registry stores is verified on chain, except
  an unproven PQZ proof. Code points shared by every family (in `portable.json`): `NONE = 0`, `CHAIN = 1`,
  `RELAYER = 2` (+ the relayer id). EVM view `checkedOf(ua) → (uint8 pop, uint8 pqzPop)` = `(CHAIN, proven ? CHAIN :
  NONE)` (`NONE` for the proof of a UA without a PQZ key); KEM records on EVM are always `CHAIN`; the events carry
  `proven`.
- **UA8-D11 Generations.** Gen 2 forwards the new views (`registrationOf`, `popOf`, `pqzPopOf`, `pqzKeyOf`, `checkedOf`,
  `kemKeyOf`, `kemKeyAt`) to gen 1 for records it does not hold; `setKemKey` / `storePqzPop` for such a UA revert
  `UAUnauthorized(ua)` (they go to the generation that holds the record).
- **UA8-D12 KEM holder set.** The U3 kinds plus a PQ-eligible `msig`; the `msig` PQZ debit gas bound (CTR-PQZ-12,
  `TX_GAS_CAP`) applies to the PQZ key only. Other kinds revert `UAKemHolder(ua)`.
- **UA8-D13 Legacy.** The pre-UA-8 `UARegistry.sol`, `UAKinds.sol`, `IUARegistry.sol` are copied to
  `smartcontracts/evm/legacy/ua8/` (not built), with the tests that only exercise the chain-bound PoP; clientkeys'
  chain-bound `popDigest` / `holderPopMessage` / `pqzRegMessage` / Zether PoP go to `clients/clientkeys/legacy/ua8/`;
  the other reproducers replace their functions in place; a local tag `ref/pre-ua8` marks the start (not pushed).
- **UA8-D14 pqz-core untouched.** The `R_REG` relation, statement and precompile do not change, only the 32-byte
  message's pre-image; the `pqz-core/stmt/src/lib.rs` doc comment naming `popDigest` is updated with the next core
  change (TODO entry, A12), so no full pqz-core gate runs.
- **UA8-D15 KEM vector keys.** The vector KEM keys are real `ML-KEM-1024 ek ‖ X25519 pk` (1,568 + 32 B, X-Wing order)
  from fixed seeds; the contracts check the length only (the scheme is UA-7's).
- **UA8-D16 EVM relaying.** The three writes are ordinary node `call` jobs (`kind = "call"`, `call.target`,
  `call.calldata`): no new job kind, no fee.
- **UA8-D17 Proof vectors are not proofs.** `pqzPop` in `portable.json` is deterministic filler of a real proof's
  length per set (forge mocks the PQZ precompile per exact bytes, non-EVM families store it unchecked); the real
  `R_REG` path stays in `script/pqz/e2e.py` (fs3 Task 13).

Part B decisions (Soroban) are UA8-D18–D24 in Part B's header.

## Review Focus

1. A copied registration must be byte-identical on two registries with different chain ids, `chainUid`s and
   addresses, and `registrationOf` must return exactly the `register` arguments — `test_ua8_copyFromState` (A5),
   `ua8_record_bytes_round_trip` (B7).
2. The `pop` must bind every attribute: stripping or swapping `pqzKey`, `pqzPopHash`, `kemVersion` or `kemPk` must be
   `UAPoP` — `test_ua8_popCoversAttrs` (A5).
3. An unproven PQZ listing must never block the real owner, and a PQZ token must never accept an unproven key —
   `test_ua8_unprovenListingDoesNotBlockOwner` (A6), `test_ua8_pqzTokenRefusesUnproven` (A6).
4. KEM records: any order, each version once (even with the same bytes), only 1,600-byte keys, only PQ holders —
   `test_ua8_kemLowerVersionAfterHigher`, `test_ua8_kemRepeatedVersionRefused` (A7).
5. A relayer-checked record must never authorise anything on Soroban, and an unlisted relayer must not write in that
   mode — `ua8_relayer_checked_ua_authorises_nothing`, `ua8_relayer_unlisted_refused` (B4).

---

## File Structure

| Path | Responsibility |
|---|---|
| `smartcontracts/evm/src/ua/UAKinds.sol` | tags, `portablePopDigest`, `registrationDigest`, `kemRecordDigest`, `KEM_PK_LENGTH`, `CHECKED_*` |
| `smartcontracts/evm/src/ua/IUARegistry.sol`, `UARegistry.sol` | `UAAttrs`, `register`, `storePqzPop`, `setKemKey`, the views, events, errors |
| `smartcontracts/evm/src/common/SSTORE2.sol` | `writeChunks` / `readChunks` |
| `smartcontracts/evm/src/pqz/PqzCore.sol` | `_keyPtr` via `pqzKeyOf` (proven only) |
| `smartcontracts/evm/legacy/ua8/` | pre-UA-8 registry, kinds, interface, chain-bound PoP tests (not built) |
| `smartcontracts/evm/test/ua/UARegistryUA8.t.sol` (new), `UAKinds.t.sol`, `UARegistry*.t.sol`, `UARegistryBase.sol`, `UAGas.t.sol`, `test/pqz/helpers/PqzRegistryBase.sol`, `test/pqz/PqzUA8.t.sol` (new), `test/zether/**` | tests |
| `smartcontracts/vectors/ua/portable.json` (new), `structures.json`, `kinds.json`, `signatures.json`, `pq_signatures.json`, `metatx3.json`, `uatrade_kat.json`, `groups.json`; `smartcontracts/evm/test/vectors/zether/s3/r33_keys.json` | vectors |
| `clients/clientkeys/src/{ua.js,zether.js}`, `scripts/{ua-portable-vectors.mjs,ua-vectors.mjs,ua-sig-vectors.mjs}`, `legacy/ua8/`, `test/ua8.test.js` (new) | JS reference + generators |
| `clients/ua-rs/src/{lib.rs,ua8.rs}`, `tests/{vectors.rs,groups.rs,signatures.rs,ua8.rs}`; Part B `src/pq.rs` (feature `pq`) | Rust reference; Part B off-chain verifier |
| `clients/zether-prover/src/{schnorr.rs,api.rs}`, tests | Zether PoP |
| `clients/{ua-cs,ua-qt,ua-py,ua-go,ua-c,ua-cxx,ua-dart,ua-dart-frb}` | reproducers |
| `smartcontracts/evm/script/pqz/e2e.py`, `scripts/e2e-zether.sh`, `scaas-node/src/submit.rs` (test) | scripts, EVM node |
| `docs/contracts/{accounts.md,pq-zero-knowledge.md,zether.md}`, `docs/{decisions.md,architecture.md,integration.md}`, `docs/networks/README.md`, `docs/node/gateway.md`, the spec, `TODO.md` | docs |
| `smartcontracts/evm/runs/2026-10-30-ua8-gates.sh` + logs, `.github/workflows/ci.yml` | gates |
| Part B: the 4b factory crate under `smartcontracts/soroban/contracts/` (its `ua8` module), `smartcontracts/soroban/{vectors/ua8-roundtrip.json,runs/}`, `scaas-node/src/adapters/soroban.rs`, `scaas-node/tests/e2e_ua8.rs`, `smartcontracts/scripts/devnet.sh`, `docs/networks/soroban.md` | Soroban step |

## Setup (before Task A1)

- [ ] `git -C /home/ha/work/ainative/scaas worktree add .claude/worktrees/ua8 -b ua8 main && git tag ref/pre-ua8 main`
  (local tag, never pushed). Copy the three pre-UA-8 Solidity files to `smartcontracts/evm/legacy/ua8/` with a
  `README.md` line (as `legacy/ua6/`); commit `ua8 setup: legacy copies of the pre-UA-8 registry`.

---

# Part A — EVM `UARegistry` (UA-8 step 1)

### Task A1: JS reference, `portable.json`, the PoPs of every JS-generated vector file (P1, P7, P10; UA8-D1–D5, D15, D17)

**Files:**
- Create: `clients/clientkeys/scripts/ua-portable-vectors.mjs` → `smartcontracts/vectors/ua/portable.json`,
  `clients/clientkeys/test/ua8.test.js`, `clients/clientkeys/legacy/ua8/ua-pop-v1.js` (the chain-bound functions)
- Modify: `clients/clientkeys/src/ua.js`, `clients/clientkeys/src/zether.js` (Zether PoP), `clients/clientkeys/scripts/{ua-vectors.mjs,ua-sig-vectors.mjs}`,
  `clients/clientkeys/package.json` (`test` runs `ua8.test.js`), the regenerated `structures.json` (version 2: `pop`,
  `pqzReg`, `pqzMsig` rows context-free), `kinds.json` (`purposes` + `pop` v2, `kem`), `signatures.json`,
  `pq_signatures.json`, `metatx3.json`, `uatrade_kat.json`, `clients/clientkeys/test/{ua.test.js,ua-sig.test.js,pq-sig.test.js,zether.test.js}`

**Interfaces:**
- Produces (`ua.js`): `purposeTag(p, version = 1)`, `PURPOSES` + `kem`; `POP_V2_TAG`, `KEM_TAG` (purpose),
  `KEM_RECORD_TAG`, `KEM_PK_LENGTH = 1600`, `CHECKED = { none: 0, chain: 1, relayer: 2 }`;
  `portablePopDigest({ ua, pqzKeyHash, kemRecordHash })`, `registrationDigest(portable, pqzPopHash)`,
  `kemRecordDigest({ ua, version, kemPk })`, `holderPopMessage(kind, { ua, pqzKey, pqzPop, kemVersion, kemPk })` →
  `{ pqzKeyHash, pqzPopHash, kemRecordHash, portablePopDigest, registrationDigest, message }` (refuses a non-holder with
  attributes: `UAPqzHolder` / `UAKemHolder`), `pqzRegMessage({ ua, pqzKey, kemVersion, kemPk })`,
  `kemRecordMessage(kind, { ua, version, kemPk })`; `zether.js` `zetherPop({ x })` without chain fields. Removed from
  `ua.js` (moved to `legacy/ua8/`): `popDigest`, the chain-bound `holderPopMessage` / `pqzRegMessage`.
- Produces `portable.json` (read by Tasks A2–A11 and B1–B7): `{ note, version: 1, tags, checked, registrations[],
  kemRecords[], negatives[] }`. `registrations[]` rows: `name, kind, kindName, keyData, ua, attrs { pqzKey, pqzPopHash,
  kemVersion, kemPk }, pqzKeyHash, kemRecordHash, portablePopDigest, registrationDigest, popMessage, pop, pqzPop,
  pqzRegMessage` (+ `members` for `msig`) for every kind clientkeys signs: `webauthn-p256`, `p256`, `ed25519`,
  `bip340`, `secp256k1`, `schnorr-bn254`, `schnorr-bls12381`, `bls12381-minsig`, `bls-bn254-minsig`,
  `zether-bls12381`, `mldsa44`, `mldsa65` (with PQZ key, `pqzPop` for `n2304-kmax4096` and KEM v1), `fndsa512` (KEM
  v1, no PQZ), `slhdsa128s`, a classical `msig` (empty `pop`), a PQ-eligible `msig` of two `mldsa65` members (PQZ +
  KEM). `kemRecords[]`: versions 1, 2, 3 for the `mldsa65`, `fndsa512` and PQ-eligible `msig` rows (`ua, kind,
  version, kemPk, digest, message, sig`). `negatives[]`: `{ name, entry, mutation, error }` (swapped `pqzKey`,
  stripped `kemPk`, wrong `pqzPopHash`, 1,599-byte `kemPk`, version 0, non-holder with KEM, `storePqzPop` other bytes).
  Keys: the fixed seeds of `signatures.json` / `pq_kat.json` (account 0, index 0; `mldsa65` indexes 1 and 2 for the
  `msig`); KEM keys per UA8-D15; `pqzPop` per UA8-D17.

- [ ] **Step 1: Failing tests** (`ua8.test.js`): `portable.json reproduced byte for byte` (generator in memory vs file);
  `portable PoP has no chain context` (`portablePopDigest` takes no chain field; one row recomputed by hand with
  `keccak_256(concat(...))` of the four words); `registration digest covers the proof hash`;
  `kem record digest matches the hand-built words`; `holder refusals` (`secp256k1` with a KEM record → `UAKemHolder`,
  `slhdsa128s` with a PQZ key → `UAPqzHolder`); `every portable pop verifies` (each row's `pop` under its kind's
  verifier in `ua.js` / `pq.js`, msig per member); in `ua.test.js`: `the generator reproduces kinds.json and
  structures.json byte for byte` (existing test, new content).
- [ ] **Step 2:** `cd clients/clientkeys && ../../scripts/capped npm test` — FAIL (no file, no functions).
- [ ] **Step 3: Implement** the functions (UA8-D1 words, `keccak_256` from `@noble/hashes`), move the chain-bound
  ones to `legacy/ua8/`, write the generator; switch `ua-vectors.mjs` / `ua-sig-vectors.mjs` to
  `holderPopMessage` (every PoP in `signatures.json`, `pq_signatures.json`, `metatx3.json`, `uatrade_kat.json` is now
  the portable one; the per-context fields keep their names, their PoPs become equal across contexts; the `uaAuth` /
  domain rows stay chain-bound). Regenerate: `node scripts/ua-vectors.mjs && node scripts/ua-sig-vectors.mjs && node scripts/ua-portable-vectors.mjs`.
- [ ] **Step 4:** Step 2's command — PASS.
- [ ] **Step 5: Commit** `ua8 A1: portable PoP + KEM record digests (clientkeys), portable.json, JS vector PoPs regenerated`.

### Task A2: `ua-rs` portable digests, `groups.json` regenerated (P1, P10; UA8-D1, D2)

**Files:**
- Create: `clients/ua-rs/src/ua8.rs`, `clients/ua-rs/tests/ua8.rs`
- Modify: `clients/ua-rs/src/lib.rs` (`pub mod ua8`; `pop_digest`, `holder_pop_message`, `pqz_reg_message` replaced),
  `clients/ua-rs/tests/{vectors.rs,signatures.rs,groups.rs,groups_verify.rs}`, `smartcontracts/vectors/ua/groups.json`
  (regenerated by `tests/groups.rs` with `--features signers`)

**Interfaces:**
- Produces: `scaas_ua::ua8::{portable_pop_digest(ua: &[u8;32], pqz_key_hash: &[u8;32], kem_record_hash: &[u8;32]) -> [u8;32],
  registration_digest(portable: &[u8;32], pqz_pop_hash: &[u8;32]) -> [u8;32], kem_record_digest(ua: &[u8;32], version: u64, kem_pk: &[u8]) -> [u8;32],
  KEM_PK_LENGTH: usize = 1600, Checked { None, Chain, Relayer([u8;32]) }}`; `scaas_ua::holder_pop_message(kind, ua,
  pqz_key: Option<&[u8]>, pqz_pop: Option<&[u8]>, kem: Option<(u64, &[u8])>) -> Result<[u8;32]>`,
  `scaas_ua::pqz_reg_message(ua, pqz_key, kem: Option<(u64, &[u8])>) -> Result<[u8;32]>`.

- [ ] **Step 1: Failing tests:** `ua8::portable_vectors` (every `registrations[]` digest field), `ua8::kem_record_vectors`,
  `ua8::negatives_refused` (holder refusals as errors); the existing `vectors.rs` / `signatures.rs` / `groups_verify.rs`
  tests against the regenerated files (the `pop` rows now portable).
- [ ] **Step 2:** `cd clients/ua-rs && ../../scripts/capped cargo test -j2` — FAIL.
- [ ] **Step 3: Implement**; regenerate `groups.json`: `../../scripts/capped cargo test -j2 --features signers --test groups -- --ignored write_groups_json`
  (the existing regeneration entry of `tests/groups.rs`).
- [ ] **Step 4:** `../../scripts/capped cargo test -j2 && ../../scripts/capped cargo test -j2 --features signers && ../../scripts/capped cargo clippy -j2 --all-targets -- -D warnings` — PASS.
- [ ] **Step 5: Commit** `ua8 A2: ua-rs portable digests, groups.json PoPs regenerated`.

### Task A3: `zether-prover` portable Zether PoP (P1; UA8-D2)

**Files:**
- Modify: `clients/zether-prover/src/{schnorr.rs,api.rs}` (`zether_pop` / API `pop` without `chain_id`, `chain_uid`,
  `registry`), `clients/zether-prover/src/vectors.rs`, `clients/zether-prover/tests/{r33_keys.rs,vectors.rs}`,
  `smartcontracts/evm/test/vectors/zether/s3/r33_keys.json` (regenerated: the PoP context dropped)

**Interfaces:**
- Produces: `schnorr::zether_pop(key: &ZetherKey) -> Signature` over `ua_message(0x0141, POP_V2,
  registration_digest(portable_pop_digest(ua, 0, 0), 0))`; wasm API `pop(x)`.

- [ ] **Step 1: Failing tests:** `r33_keys::pop_matches_structures` (the `structures.json` portable `pop` row of the
  Zether kind), `vectors::r33_keys_reproduced`.
- [ ] **Step 2:** `cd clients/zether-prover && ../../scripts/capped cargo test -j2` — FAIL.
- [ ] **Step 3: Implement**; regenerate with the crate's existing generator (`zether-cli vectors <dir>`, the
  `src/vectors.rs` header; `tests/vectors.rs` fails on drift) and copy `r33_keys.json` to the forge vector path.
- [ ] **Step 4:** Step 2's command and the wasm smoke (`./wasm-smoke.sh` under `scripts/capped`) — PASS.
- [ ] **Step 5: Commit** `ua8 A3: zether-prover portable PoP, r33_keys.json regenerated`.

### Task A4: Solidity `UAKinds` + `IUARegistry` surface (P1, P7, P11; UA8-D1, D10)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UAKinds.sol`, `smartcontracts/evm/src/ua/IUARegistry.sol`,
  `smartcontracts/evm/test/ua/UAKinds.t.sol`

**Interfaces:**
- Produces (`UAKinds`): `PURPOSE_POP_V2`, `PURPOSE_KEM`, `KEM_RECORD_TAG`, `KEM_PK_LENGTH = 1600`,
  `CHECKED_NONE = 0`, `CHECKED_CHAIN = 1`, `CHECKED_RELAYER = 2`;
  `portablePopDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 kemRecordHash)`,
  `registrationDigest(bytes32 portable, bytes32 pqzPopHash)`, `kemRecordDigest(bytes32 ua, uint64 version, bytes memory kemPk)`
  (all `internal pure`, UA8-D1). `popDigest` (chain-bound) removed (in `legacy/ua8/`); `PURPOSE_POP` (v1) kept.
- Produces (`IUARegistry`):

```solidity
struct UAAttrs { bytes pqzKey; bytes32 pqzPopHash; uint64 kemVersion; bytes kemPk; }   // empty / 0 = absent

event UARegistered(bytes32 indexed ua, uint16 indexed kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop,
    uint8 checkedPop, uint8 checkedPqzPop, uint8 checkedKem);              // built form (ruling C8: `checked` values, not `proven`)
event UAPqzPopStored(bytes32 indexed ua, uint8 checkedPqzPop, bytes pqzPop);   // built form (C8, ruling A6-m: the written bytes)
event UAPqzKeyAdded(bytes32 indexed ua, bytes32 pqzKeyHash, bytes32 pqzPopHash, bytes pqzKey, bytes sig);   // built (setPqzKey)
event UAKemKeySet(bytes32 indexed ua, uint64 indexed version, bytes32 keyHash, bytes kemPk, bytes sig);   // keyHash = keccak256(kemPk); built form (A7)

error UAKemHolder(bytes32 ua);                 // kind / structure may not hold a KEM key (UA8-D12)
error UAKemVersion(bytes32 ua, uint64 version); // 0, or already stored
error UAKemKeyLength(uint256 length);           // ≠ 1,600
error UAPqzPopHash(bytes32 ua);                 // keccak256(pqzPop) ≠ the stored pqzPopHash (or no PQZ key)

function register(uint16 kind, bytes calldata keyData, UAAttrs calldata attrs, bytes calldata pop,
    bytes calldata pqzPop) external returns (bytes32 ua);
function storePqzPop(bytes32 ua, bytes calldata pqzPop) external;
function setKemKey(bytes32 ua, uint64 version, bytes calldata kemPk, bytes calldata sig) external;
function portablePopDigest(bytes32 ua, bytes32 pqzKeyHash, bytes32 kemRecordHash) external pure returns (bytes32);
function registrationDigest(bytes32 portable, bytes32 pqzPopHash) external pure returns (bytes32);
function kemRecordDigest(bytes32 ua, uint64 version, bytes calldata kemPk) external pure returns (bytes32);
function registrationOf(bytes32 ua) external view returns (uint16 kind, bytes memory keyData, UAAttrs memory attrs,
    bytes memory pop, bytes memory pqzPop);
function popOf(bytes32 ua) external view returns (bytes memory);
function pqzPopOf(bytes32 ua) external view returns (bytes memory);
function pqzKeyOf(bytes32 ua) external view returns (address ptr, bytes32 pqzPopHash, bool proven);
function checkedOf(bytes32 ua) external view returns (uint8 pop, uint8 pqzPop);
function kemKeyOf(bytes32 ua) external view returns (uint64 version, bytes memory pk, bytes memory sig); // highest
function kemKeyAt(bytes32 ua, uint64 version) external view returns (bytes memory pk, bytes memory sig);
```

  `popDigest(bytes32,bytes32)` and the old `register(uint16,bytes,bytes,bytes,bytes)` removed; `recordOf` unchanged
  (UA8-D9).

- [ ] **Step 1: Failing tests** (`UAKinds.t.sol`, reading `portable.json`): `test_portablePopDigestVectors`,
  `test_registrationDigestVectors`, `test_kemRecordDigestVectors`, `test_purposeTagsV2` (`kinds.json` purposes),
  `test_portableDigestHasNoChainContext` (the same inputs under `vm.chainId(31337)` and `vm.chainId(7622)` give the
  same digest), `test_checkedCodePoints` (`portable.json` `checked`).
- [ ] **Step 2:** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/ua/UAKinds.t.sol` — FAIL.
- [ ] **Step 3: Implement** `UAKinds` and the interface (the registry compiles again in A5; until then this task's
  command runs with `--skip 'test/ua/UARegistry*' --skip 'src/ua/UARegistry.sol'` only if the build needs it).
- [ ] **Step 4:** Step 2's command — PASS.
- [ ] **Step 5: Commit** `ua8 A4: UAKinds portable digests + IUARegistry UA-8 surface`.

### Task A5: `register` on the portable digest, every field stored (P1–P3, P6; UA8-D2, D4–D7, D10, D11; work item 1)

**Files:**
- Create: `smartcontracts/evm/test/ua/UARegistryUA8.t.sol`
- Modify: `smartcontracts/evm/src/ua/UARegistry.sol`, `smartcontracts/evm/src/common/SSTORE2.sol`,
  `smartcontracts/evm/test/ua/UARegistryBase.sol` (one `_register(reg, kind, keyData, attrs, pop, pqzPop)` helper and
  the portable `_pop`), every forge call site of `register` / `popDigest` (`test/ua/*.t.sol`, `test/pqz/**`,
  `test/zether/**`, `test/ua/verifiers/*.t.sol`, `test/ua/GroupFixtures.sol`), `test/ua/UARegistry.t.sol`
  (`test_T_CHAIN` inverted: the PoP of `rC` now registers on `rB`, the native `uaAuth` stays refused;
  `test_vectorsContextA` / `_assertVectors` on the portable rows; `test_T_REG_3b_pqzKey` per UA8-D8), the chain-bound
  PoP tests moved to `smartcontracts/evm/legacy/ua8/`

**Interfaces:**
- Consumes: A1 `portable.json` and the regenerated vector files; A4 surface.
- Produces: `register` steps (accounts.md §1.8 as revised in A12): 1–4 `_identify` as today; 5 `_attrs` (shape:
  `pqzKey` empty ⇔ `pqzPopHash == 0`, `pqzPop` only with a key, else `UAPoP`; `kemVersion == 0` ⇔ `kemPk` empty, else
  `UAKemVersion`; `kemPk.length == 1600` else `UAKemKeyLength`; holders: `UAPqzHolder` / `UAKemHolder`; the `msig`
  PQZ debit bound as today); 6 `_sigOk(kind, d, ua, PURPOSE_POP_V2, registrationDigest(...), pop)` else `UAPoP` (the
  generalised `_popOk`, also used by A7); 7 the PQZ key (A6); 8 the record, `keyPtr`, `keyOwner`, the kind's list, the
  KEM version (UA8-D4), the registration blob (UA8-D7), `UARegistered`. `SSTORE2.writeChunks(bytes memory) returns
  (address[] memory)`, `SSTORE2.readChunks(address[] storage) returns (bytes memory)`, `BLOB_CHUNK = 32_768`. Storage:
  `mapping(bytes32 ua => address[]) _reg` (`abi.encode(keyData, pop)`), `mapping(bytes32 ua => PqzAttr) _pqz`
  (`struct PqzAttr { bytes32 popHash; bool proven; }`), `mapping(bytes32 ua => address[]) _pqzPop`,
  `mapping(bytes32 ua => mapping(uint64 version => address[])) _kem` (`pk ‖ sig`), `mapping(bytes32 ua => uint64) _kemMax`.

- [ ] **Step 1: Failing tests** (`UARegistryUA8.t.sol`): `test_ua8_copyBetweenRegistries` (registries at
  `vm.chainId(31337)` / `vm.chainId(7622)`, different `chainUid`s and addresses: the same arguments register on both),
  `test_ua8_copyFromState` (register on A; `registrationOf` from A submitted to B by a third party; equal records and
  `registrationOf` bytes), `test_ua8_everyKindFromVectors` (every `portable.json` row; `msig` members first),
  `test_ua8_disabledKindReverts` (`UAKindDisabled` where the kind's slot is empty), `test_ua8_msigPqEligibleCopy`,
  `test_ua8_msigNativeMemberPopChainBound` (UA8-D6), `test_ua8_popCoversAttrs` (each `negatives[]` swap / strip →
  `UAPoP`), `test_ua8_frontRunnerGetsIdenticalRecord`, `test_ua8_storesEveryField` (`popOf`, `registrationOf`,
  `kemKeyAt(ua, v)` with empty `sig`, `vm.expectEmit` of `UARegistered`), `test_ua8_attrsShapeRefused`,
  `test_ua8_nonHolderAttrsRefused`, `test_ua8_checkedIsChain`, `test_ua8_gen2ForwardsReads`,
  `test_ua8_blobChunksRoundTrip` (0, 1, 32,768, 32,769 and 100,000 B), `test_ua8_largestMsigPopStored` (the
  `UAGas.t.sol` 8 × `slhdsa128s` + clone `msig` at `verifyBudget`, and a 12-member one on a registry with a larger
  budget: stored and read back).
- [ ] **Step 2:** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/ua/UARegistry*.t.sol'` — FAIL.
- [ ] **Step 3: Implement** in `UARegistry.sol` (no state from `msg.sender`; every write permissionless); migrate the
  call sites through the base helper.
- [ ] **Step 4:** `../../scripts/capped forge test` (the default set `n2304-kmax4096`) — PASS, the whole suite.
- [ ] **Step 5: Commit** `ua8 A5: register on the portable PoP, UAAttrs, every field stored (SSTORE2 chunks)`.

### Task A6: optional `pqzPop`, `proven`, `storePqzPop`; PQZ tokens read `proven` (P8, P9; UA8-D8, D9; work items 2, 4)

**Files:**
- Create: `smartcontracts/evm/test/pqz/PqzUA8.t.sol`
- Modify: `smartcontracts/evm/src/ua/UARegistry.sol` (`_pqzRegister` → `_pqzAttach` / `_prove`, `storePqzPop`,
  `pqzKeyOf`), `smartcontracts/evm/src/pqz/PqzCore.sol` (`_keyPtr` only), `smartcontracts/evm/test/ua/UARegistryUA8.t.sol`,
  `smartcontracts/evm/test/pqz/helpers/PqzRegistryBase.sol` (the `R_REG` mock keyed by the portable message)

**Interfaces:**
- Produces: in `register`, a PQZ key is stored with `pqzPopHash`; with `pqzPop` given: `keccak256(pqzPop) ==
  pqzPopHash` (`UAPqzPopHash`), bytes stored, and where slot `0x0142` is set the proof checked over
  `uaMessage(0x0142, PURPOSE_POP_V2, portablePopDigest)` (`UAPoP` on failure), then `keyOwner(h)` free (`UAKeyInUse`),
  `keyOwner[h] = ua`, list `0x0142`, `proven = true`. `storePqzPop(ua, pqzPop)`: anyone; `UAPqzPopHash` unless the
  hash matches; no-op (no event) when the bytes are stored; else store, prove as above where the verifier exists,
  `UAPqzPopStored(ua, proven)`. `PqzCore._keyPtr`: `(ptr, , proven) = pqzKeyOf(ua)`; `!proven` or a wrong code length
  → `AccountNotRegistered(ua)`.

- [ ] **Step 1: Failing tests:** `test_ua8_pqzUnprovenWithoutVerifier` (slot `0x0142` empty: key and proof stored,
  `proven = false`, no `keyOwner`, not listed), `test_ua8_pqzProveLaterOnVerifierChain` (copied without `pqzPop`, then
  `storePqzPop` by a third party → proven, owner set, listed), `test_ua8_pqzPopInRegisterProven`,
  `test_ua8_storePqzPopWrongBytesRefused`, `test_ua8_storePqzPopIdempotent`, `test_ua8_storePqzPopBadProofReverts`
  (hash matches, the mocked verifier returns 0), `test_ua8_unprovenListingDoesNotBlockOwner` (an attacker UA lists the
  victim's PQZ key unproven; the victim registers proven; the attacker's `storePqzPop` cannot prove),
  `test_ua8_provenKeyStillUnique`; `PqzUA8.t.sol`: `test_ua8_pqzTokenRefusesUnproven` (shield / credit to an unproven
  holder → `AccountNotRegistered`), `test_ua8_pqzTokenAcceptsAfterStorePqzPop`.
- [ ] **Step 2:** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/{ua/UARegistryUA8,pqz/PqzUA8}.t.sol'` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `../../scripts/capped forge test` — PASS.
- [ ] **Step 5: Commit** `ua8 A6: optional pqzPop, proven flag, storePqzPop; PQZ tokens accept proven keys only`.

### Task A7: KEM key records `setKemKey` / `kemKeyOf` / `kemKeyAt` (P4, P5, P7, P9; UA8-D3–D5, D11, D12; work items 3, 4)

**Files:**
- Modify: `smartcontracts/evm/src/ua/UARegistry.sol`, `smartcontracts/evm/test/ua/UARegistryUA8.t.sol`

**Interfaces:**
- Produces: `setKemKey(ua, version, kemPk, sig)`: anyone; `UAUnauthorized(ua)` if this generation does not hold the
  record; `UAKemHolder(ua)` for a non-holder (kind from the record, `msig` eligibility from the stored key data);
  `UAKemVersion` for 0 or a stored version; `UAKemKeyLength`; `_sigOk(kind, d, ua, PURPOSE_KEM, kemRecordDigest(ua,
  version, kemPk), sig)` else `UAUnauthorized(ua)`; store `pk ‖ sig`, `_kemMax = max`, `UAKemKeySet(ua, version,
  keccak256(kemPk), kemPk, sig)` (built form, A7). `kemKeyOf` = the highest stored version (`(0, "", "")` without one); `kemKeyAt` = `("", "")` for
  a version not stored.

- [ ] **Step 1: Failing tests:** `test_ua8_setKemKeyByThirdParty`, `test_ua8_kemCopyBetweenRegistries` (every
  `kemRecords[]` row on two registries), `test_ua8_kemLowerVersionAfterHigher` (3, then 1, then 2: all stored,
  `kemKeyOf` = 3), `test_ua8_kemRepeatedVersionRefused` (same bytes and other bytes), `test_ua8_kemVersionZeroRefused`,
  `test_ua8_kemLengthRefused` (1,599 and 1,601), `test_ua8_kemNonHolderRefused` (`secp256k1`, `slhdsa128s`, a classical
  `msig`), `test_ua8_kemMsigMofN`, `test_ua8_kemBadSigRefused`, `test_ua8_kemNoOwnerCheck` (two UAs list one `pk`),
  `test_ua8_kemEvent`, `test_ua8_kemGen2RecordElsewhereRefused`, `test_ua8_kemInitialVersionFromRegister` (UA8-D4: a
  `setKemKey` of the registered version is `UAKemVersion`).
- [ ] **Step 2:** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/ua/UARegistryUA8.t.sol` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `../../scripts/capped forge test` — PASS.
- [ ] **Step 5: Commit** `ua8 A7: KEM key records (setKemKey, kemKeyOf, kemKeyAt; write-once, any order)`.

### Task A8: gas figures and the size gate (no zero-gas assumption; code-size rule)

**Files:**
- Modify: `smartcontracts/evm/test/ua/UAGas.t.sol`, `smartcontracts/evm/size-baseline.json` (`_comment` entry + new
  ceilings), `smartcontracts/evm/runs/2026-10-30-ua8-gas.txt` (new log)

**Interfaces:**
- Produces: measured gas (forge, deterministic) per kind for `register` with the stored blobs, `storePqzPop` at each of
  the four sets (`R_REG` lengths 28,080–35,420 B), `setKemKey` for `mldsa65` / `fndsa512` / the PQ-eligible `msig`;
  the `msig`-at-budget tests (`test_T_GAS_msigAtBudget`, `test_T_GAS_msigPqAtBudget`) on the new `register`.

- [ ] **Step 1: Failing tests:** `test_T_GAS_register_ua8PerKind`, `test_T_GAS_storePqzPop`,
  `test_T_GAS_setKemKey` (each figure ≤ its pinned constant / 1.0, pinned from the first measured run and logged); the
  existing `UAGas.t.sol` bounds on the new call.
- [ ] **Step 2:** `cd smartcontracts/evm && ../../scripts/capped forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'` — FAIL (constants unset).
- [ ] **Step 3:** Pin the figures; write the log (one row per kind / set, regular and state gas as forge reports them);
  no figure assumes a block limit: the log states which full registrations exceed a 60 M block (P2) and therefore use
  `storePqzPop`.
- [ ] **Step 4:** Step 2's command at each set (`scripts/capped smartcontracts/evm/script/pqz/at-set.sh <set> test --isolate --match-path 'test/ua/UAGas.t.sol'`, one run at a time)
  — PASS; size gate: `cd smartcontracts/evm && j=$(mktemp) && ../../scripts/capped forge build src --sizes --json > "$j" && python3 -I ../../scripts/size_gate.py "$j" size-baseline.json; rm -f "$j"`
  — 0 errors after the ratchet entry (`UARegistry` and the PQZ kinds to their measured sizes, all < 65,536 B).
- [ ] **Step 5: Commit** `ua8 A8: UA-8 gas figures, size baseline ratchet`.

### Task A9: `ua-cs` and `ua-qt` (work item 5)

**Files:**
- Modify: `clients/ua-cs/Scaas.Ua/Ua.cs` (`PortablePopDigest`, `RegistrationDigest`, `KemRecordDigest`,
  `HolderPopMessage`, `PqzRegMessage` on the portable form; `PopDigest` removed), `clients/ua-cs/Scaas.Ua.Tests/VectorTests.cs`;
  `clients/ua-qt/src/ua_kinds.rs` (invokables `portablePopDigest(ua, pqzKeyHash, kemRecordHash)`,
  `registrationDigest(portable, pqzPopHash)`, `kemRecordDigest(ua, version, kemPk)`, `holderPopMessage(kind, ua,
  pqzKey, pqzPop, kemVersion, kemPk)`, `pqzRegMessage(ua, pqzKey, kemVersion, kemPk)`; `popDigest` removed; hex strings,
  over `scaas_ua`), `clients/ua-qt/tests/tst_ua.qml`

- [ ] **Step 1: Failing tests:** ua-cs `PortableVectors`, `KemRecordVectors`, `HolderRefusals` (and the existing
  `VectorTests` on the regenerated files); `tst_ua.qml` `test_portable`, `test_kemRecord`.
- [ ] **Step 2:** `cd clients/ua-cs && ../../scripts/capped dotnet test Scaas.Ua.Tests; dotnet build-server shutdown`;
  ua-qt: `QMAKE=/home/ha/usr/Qt/6.12.0/gcc_64/bin/qmake6 LD_LIBRARY_PATH=/home/ha/usr/Qt/6.12.0/gcc_64/lib QT_QPA_PLATFORM=offscreen scripts/capped sh -c "cmake -S clients/ua-qt -B clients/ua-qt/build -DCMAKE_PREFIX_PATH=/home/ha/usr/Qt/6.12.0/gcc_64 && cmake --build clients/ua-qt/build -j2 && cd clients/ua-qt/build && ctest -V --output-on-failure"` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Step 2's commands — PASS.
- [ ] **Step 5: Commit** `ua8 A9: ua-cs and ua-qt on the portable PoP and KEM record digests`.

### Task A10: the other reproducers (they read the regenerated `structures.json` and expose the PoP functions)

**Files:**
- Modify: `clients/ua-py/scaas_ua/__init__.py`, `clients/ua-py/tests/test_vectors.py`; `clients/ua-go/{ua.go,ua_test.go}`;
  `clients/ua-c/{src/lib.rs,include/scaas_ua.h,tests/test_vectors.py}`; `clients/ua-cxx/{src/lib.rs,src/scaas_ua.cpp,tests/vectors_test.cpp}`;
  `clients/ua-dart/{lib/src/ua.dart,test/vectors_test.dart}`; `clients/ua-dart-frb/{rust/src/api/ua.rs,lib/src/rust/**,test/vectors_test.dart}` (regenerated bindings)

**Interfaces:**
- Produces in each: `portable_pop_digest` / `registration_digest` / `kem_record_digest` / portable
  `holder_pop_message` / `pqz_reg_message` in the language's naming (Python / Go / C / C++ / Dart), the chain-bound
  `pop_digest` removed; each reads `portable.json` `registrations[]` digest fields and `kemRecords[]` digests.

- [ ] **Step 1: Failing tests:** in each: `test_portable` / `TestPortable` / `portable` (the digest fields of every row),
  `test_kem_record`; the existing structures tests on the new rows.
- [ ] **Step 2:** the commands of the gate runner's steps `ua-py ua-go ua-c ua-cxx ua-dart` (A13) and
  `cd clients/ua-dart-frb && ../../scripts/capped sh -c 'dart pub get --enforce-lockfile && cargo build -j2 --locked --manifest-path rust/Cargo.toml && dart test'` — FAIL.
- [ ] **Step 3: Implement** (no new dependency; keccak from each package's existing one).
- [ ] **Step 4:** Step 2's commands — PASS.
- [ ] **Step 5: Commit** `ua8 A10: ua-py, ua-go, ua-c, ua-cxx, ua-dart, ua-dart-frb on the portable digests`.

### Task A11: scripts and the EVM node (work item 5; UA8-D16)

**Files:**
- Modify: `smartcontracts/evm/script/pqz/e2e.py` (the portable message for `pop` and `R_REG`; `register` with
  `UAAttrs`; a KEM v1 for the PQZ holder; a `storePqzPop` path), `scripts/e2e-zether.sh` (`register(uint16,bytes,(bytes,bytes32,uint64,bytes),bytes,bytes)`,
  the portable Zether PoP from clientkeys), `scaas-node/src/submit.rs` (test only)

- [ ] **Step 1: Failing test:** `submit::tests::ua8_registry_writes_are_call_jobs` (a `call` job carrying
  `register`, `setKemKey` and `storePqzPop` calldata builds `Work` with that target and data, no fee field, and an
  unknown kind is still refused).
- [ ] **Step 2:** `cd scaas-node && ../scripts/capped cargo test -j2 ua8_registry_writes_are_call_jobs` — FAIL (no
  test); `python3 -I -m py_compile smartcontracts/evm/script/pqz/e2e.py && bash -n scripts/e2e-zether.sh`.
- [ ] **Step 3: Implement** the test (the path exists) and the script changes. The scripts run against a chain in fs3
  Task 13 (7622 redeploy), not here.
- [ ] **Step 4:** Step 2's commands — PASS.
- [ ] **Step 5: Commit** `ua8 A11: e2e scripts on the UA-8 register, node call-job test for the registry writes`.

### Task A12: docs, decisions, TODO (work item 5)

**Files:**
- Modify: `docs/contracts/accounts.md` — CTR-UA-07 rewritten (the portable PoP, UA8-D1/D2, the registration flow
  diagram with the copy to a second chain), §1.8 registry (the new `register` steps, `storePqzPop`, `setKemKey`, the
  views, events, errors, generations UA8-D11), new **CTR-UA-31** (a registration is portable: same record bytes on every
  chain, anyone copies it, every field in state, `checked`, UA8-D6/D7/D10) and **CTR-UA-32** (KEM key records: scheme,
  1,600 B, holders, write-once any order, no revocation, no one-owner check, UA8-D3–D5/D12/D15), CTR-UA-16 (PQZ key
  optional proof, `proven`, UA8-D8/D9), §1.12 touchpoints (zether-prover row), §1.15 gas (the A8 figures, no
  `[estimate]` for a measured one), §1.16 vectors (`portable.json`); `docs/contracts/pq-zero-knowledge.md` (`R_REG`
  message pre-image, `proven`), `docs/contracts/zether.md` (Zether PoP), `docs/architecture.md`, `docs/integration.md`,
  `docs/networks/README.md`, `docs/node/gateway.md` (every `popDigest` mention); `docs/decisions.md` (**CTR-UA-31**,
  **CTR-UA-32** with the owner rulings of the design P1–P9 by date, and UA8-D1–D17 each in full, "controller call,
  owner may override", status, commit); the spec's status line ("step 1 built on `ua8` …"); `TODO.md` (UA-8 step 1
  done on the branch, the 7622 registry redeploy in fs3 Task 13, the `pqz-core/stmt` comment for the next core change
  UA8-D14, UA-7 can use `kemKeyOf`)

- [ ] **Step 1:** Write every change.
- [ ] **Step 2:** `python3 scripts/test_docs_check.py && python3 -I scripts/docs_check.py check` — 0 errors.
- [ ] **Step 3: Commit** `ua8 A12: docs (accounts CTR-UA-07/-16/-31/-32, PQZ, Zether, decisions, TODO)`.

### Task A13: gate steps in a UA-8 runner + CI

**Files:**
- Create: `smartcontracts/evm/runs/2026-10-30-ua8-gates.sh` (a copy of `2026-10-27-metatx-split-gates.sh` with
  `P=2026-10-30-ua8`, the same step contract and `named_tests`)
- Modify: `.github/workflows/ci.yml` (the header comment: `portable.json` readers; no new job)

**Interfaces:**
- Produces: `STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes docs cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node clientkeys ua-rs ua-rs-signers ua-qt ua-py ua-go ua-cs ua-c ua-cxx ua-dart ua-dart-frb named-tests"`,
  `FAMILIES=""`; new step commands `forge-isolate` (`cd smartcontracts/evm && ../../scripts/capped forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'`),
  `ua-rs-signers` (`cd clients/ua-rs && ../../scripts/capped cargo test -j2 --features signers`), `ua-dart-frb`
  (A10's command); the other commands as in the metatx-split runner; `NEW_TESTS` = every test name of Tasks A1–A11 in
  its tool's pass form.

- [ ] **Step 1:** Write the runner and the names.
- [ ] **Step 2: Self-check the guard:** `NAMED_TESTS_LOG_DIR=<scratch copy with one forge name removed> smartcontracts/evm/runs/2026-10-30-ua8-gates.sh --only named-tests` exits non-zero.
- [ ] **Step 3: Run** `smartcontracts/evm/runs/2026-10-30-ua8-gates.sh`. Expected: every step `rc=0`. On a failure: fix in
  the owning task's files, commit, re-run (finished steps are skipped only at the same commit, so a fix re-runs them).
- [ ] **Step 4: Commit** the runner, CI and logs: `ua8 A13: UA-8 gate runner, logs`.
- [ ] **Step 5:** Report to the controller: commits, A8 figures, the size ratchet, the overlap with the token-family
  rename (`PqzCore._keyPtr`); ask for the owner's go to merge / push.

---

# Part B — Soroban registry (UA-8 step 2)

**Starts only when** (a) the 4b Soroban spec exists (TODO step 2 "Specs") and (b) its UA base (UA ids, the
`SmartKeyAccount` factory with the `UA(ua)` / `KEY(keyHash)` persistent entries, the classical kinds it verifies, the
UA ledger) has landed on `main` (TODO step 4, one round with this part), and (c) Part A is merged. Names below follow
the accounts.md "Where the records live" row; where the 4b spec names a type, entry or crate differently, the 4b name
wins and the tests here are renamed, not re-scoped (controller call).

**Part B decisions (controller calls, owner may override; recorded by Task B8):**

- **UA8-D18 Relayer argument.** `register` and `set_kem_key` take `relayer: Option<Address>`; it is consulted only for
  a part the chain cannot verify, which then needs `relayer` ∈ the list and `relayer.require_auth()` (the submitting
  lane is the transaction source, so its auth is implicit); parts the chain verifies are always verified on chain,
  `checked = Chain`, and stay open to anyone (P11.2).
- **UA8-D19 The relayer list.** Given to the factory's constructor (the node's lane addresses at deploy, from the node's
  key derivation), immutable, no admin (the CTR-UA-15 pattern); "the operator delists such a relayer" (P11.6) means a
  new factory deployment — records of the old one stay readable.
- **UA8-D20 Who checks what on Soroban.** Signature parts (`pop`, KEM `sig`): `Chain` for the classical kinds the 4b
  base verifies and for `mldsa44` / `mldsa65` (CAP-0087 host functions, empty context, `M = ua_msg`); `Relayer(id)` for
  `fndsa512`, `slhdsa128s` and any kind 4b does not verify; an `msig` part is `Chain` when every signature of its signing
  set is chain-verifiable, else `Relayer(id)`. The PQZ proof: always `None` (no verifier on Soroban and none in the node;
  `proven = false`, `store_pqz_pop` open to anyone, hash-checked).
- **UA8-D21 PQZ bytes on Soroban.** Stored in full (P2, so a copy back to EVM works from Soroban state) when B0's
  measured limits allow: the PQZ key (16–22 KB) and `pqz_pop` (28–35 KB) each in its own persistent entry; `pqz_pop`
  through `store_pqz_pop` when one transaction cannot carry both (P9); if the key alone exceeds an entry or a
  transaction, only `pqzKeyHash` / `pqzPopHash` are stored (P10's literal form) and the round-trip test takes the key
  from `portable.json`. B0 records which case holds.
- **UA8-D22 TTL.** Like the other persistent state of these contracts: each write and read of an entry extends it
  (`extend_ttl(30 days, 60 days)`, as `dex` / `mandate`); an archived entry is restored by its next access (Protocol 23+
  automatic restore); no node TTL job.
- **UA8-D23 Node `call` jobs on Soroban.** New `op.kind = "call"` (added to the adapter's known kinds): `op.extra.call`
  = `InvokeContractArgs` XDR, no subject auth entries, target = the configured factory contract only, function ∈
  {`register`, `set_kem_key`, `store_pqz_pop`} only (the lane is the source account, so any other unauthenticated call
  could spend the lane's own authority); a `relayer` argument must equal the submitting lane.
- **UA8-D24 Off-chain verifier.** `scaas-ua` feature `pq` with exact-pinned crates (`ml-dsa` for ML-DSA-44/65,
  `slh-dsa` for SLH-DSA-SHA2-128s, `pqcrypto-falcon` `falcon-padded-512` for the 666-byte padded Falcon-512 of
  EIP-8052), accepted only if every `pq_kat.json` / `pq_external.json` / `pq_signatures.json` entry agrees; the node and
  the client re-check use it; clientkeys re-checks with its existing noble verifiers.

### Task B0: preconditions and the Soroban budget spike — HARD GATE (§3 item 7)

**Files:**
- Create: `smartcontracts/soroban/runs/<date>-ua8-b0.txt`; the spike as a test of the 4b factory crate
  (`tests/ua8_spike.rs`, kept)
- Modify: `smartcontracts/soroban/Cargo.toml` / `Cargo.lock` (only if 4b did not already pin the Protocol 30 SDK),
  `smartcontracts/scripts/devnet.sh` (`soroban`: the pinned quickstart command)

**Interfaces:**
- Produces: the pinned `soroban-sdk` release that carries `Crypto::ml_dsa_44_verify` / `ml_dsa_65_verify` (rs-soroban-sdk
  PR #2138, merged 2026-10-19; a published release preferred, else a pinned git revision replaced by the release before
  B10) and its exact signatures; `Env::default()` at protocol 30 in unit tests; `stellar/quickstart@sha256:<digest>`
  with Stellar Core v30 run as `scripts/capped docker run -d --rm --memory 3g --name scaas-stellar -p 127.0.0.1:31980:8000 <image> --local --protocol-version 30 --enable core,rpc,horizon`;
  the network limits read from the local network (`stellar network settings`: transaction size, write bytes, entry
  size, CPU instructions and memory per transaction).

- [ ] **Step 1: Failing test:** `ua8_spike_register_mldsa65_full_fits` — the factory's `register` of the
  `portable.json` `mldsa65` row with PQZ key, `pqz_pop` and KEM v1 (or the split of UA8-D21), plus one `set_kem_key`,
  simulated on the local network: CPU instructions and memory within the per-transaction limits, sizes within the
  entry / write limits; prints the figures.
- [ ] **Step 2:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — FAIL (no entry points).
- [ ] **Step 3:** Pin the SDK and the image, record the limits and the 4b merge commit in the run log; a minimal
  `register` for the spike.
- [ ] **Step 4: Gate:** PASS ⇒ continue, with UA8-D21's case written into the log. FAIL (no SDK carrying the wrappers,
  no Protocol 30 image, or the full `mldsa65` registration over a limit even split per UA8-D21) ⇒ **STOP**: commit the
  spike and log, report to the owner, start no further Part B task until the owner rules.
- [ ] **Step 5: Commit** `ua8 B0: Soroban P30 SDK + quickstart pinned, budget spike`.

### Task B1: portable digests in the factory crate (P10; UA8-D1)

**Files:**
- Create: `<factory crate>/src/ua8.rs`, `<factory crate>/src/test_ua8.rs`

**Interfaces:**
- Produces: `ua8::{portable_pop_digest(env, ua: &BytesN<32>, pqz_key_hash: &BytesN<32>, kem_record_hash: &BytesN<32>) -> BytesN<32>,
  registration_digest(env, portable, pqz_pop_hash) -> BytesN<32>, kem_record_digest(env, ua, version: u64, kem_pk: &Bytes) -> BytesN<32>,
  ua_message(env, kind: u32, purpose: &BytesN<32>, digest: &BytesN<32>) -> BytesN<32>}` (`env.crypto().keccak256`), the
  tags as constants.

- [ ] **Step 1: Failing test:** `ua8_portable_digests_match_vectors` (every `registrations[]` / `kemRecords[]` digest and
  message of `portable.json`, read with `include_str!`).
- [ ] **Step 2:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Step 2's command — PASS.
- [ ] **Step 5: Commit** `ua8 B1: Soroban portable digests (keccak256 host function) vs portable.json`.

### Task B2: registry entries and `register` (P2, P3, P8, P10; UA8-D20–D22)

**Files:**
- Modify: `<factory crate>/src/lib.rs` (entries, `register`, views), `<factory crate>/src/test_ua8.rs`

**Interfaces:**
- Produces:

```rust
#[contracttype] pub enum Checked { None, Chain, Relayer(Address) }
#[contracttype] pub struct UaAttrs { pub pqz_key: Bytes, pub pqz_pop_hash: BytesN<32>, pub kem_version: u64, pub kem_pk: Bytes }
#[contracttype] pub struct Registration { pub kind: u32, pub key_data: Bytes, pub attrs: UaAttrs, pub pop: Bytes,
    pub pop_checked: Checked, pub pqz_pop_checked: Checked, pub proven: bool, pub ledger: u32 }
// persistent keys: UA(ua) -> Registration (attrs.kem_pk empty; the initial KEM version is a KEM entry),
// KEY(keyHash) -> ua, PQZK(ua) -> Bytes, PQZP(ua) -> Bytes, KEM(ua, version) -> (Bytes pk, Bytes sig, Checked), KEMMAX(ua) -> u64
fn register(env: Env, kind: u32, key_data: Bytes, attrs: UaAttrs, pop: Bytes, pqz_pop: Bytes, relayer: Option<Address>) -> BytesN<32>;
fn registration_of(env: Env, ua: BytesN<32>) -> Option<(u32, Bytes, UaAttrs, Bytes, Bytes)>; // the register arguments
fn pop_of(env: Env, ua: BytesN<32>) -> Bytes;
fn pqz_pop_of(env: Env, ua: BytesN<32>) -> Bytes;
fn checked_of(env: Env, ua: BytesN<32>) -> (Checked, Checked);
```

  Errors (contracterror): `KindDisabled`, `KeyData`, `IdInNativeSpace`, `AlreadyRegistered`, `KeyInUse`, `PqzHolder`,
  `KemHolder`, `KemVersion`, `KemKeyLength`, `Pop`, `PqzPopHash`, `NotVerifiable` (a part the chain cannot verify and
  no listed relayer), `RelayerNotListed`; events `UaRegistered(ua, kind)` with the record as data, `UaPqzPopStored(ua)`.
  The `msig` `pop` is decoded from its ABI `MemberSig[]` layout (UA8-D5).

- [ ] **Step 1: Failing tests:** `ua8_register_every_chain_kind_from_vectors` (each `portable.json` row of a kind
  UA8-D20 marks `Chain`, `registration_of` equal to the row), `ua8_mldsa44_mldsa65_pop_via_host_function` (valid and a
  flipped byte), `ua8_unverifiable_kind_refused_without_relayer` (`fndsa512`, `slhdsa128s` → `NotVerifiable`),
  `ua8_disabled_kind_refused`, `ua8_pqz_attrs_stored_unproven` (`proven = false`, `pqz_pop_checked = None`, no `KEY`
  entry for the PQZ key), `ua8_key_hash_unique`, `ua8_pop_covers_attrs` (the `negatives[]` swaps → `Pop`),
  `ua8_any_submitter` (a third-party source account), `ua8_entries_extend_ttl` (UA8-D22).
- [ ] **Step 2:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — FAIL.
- [ ] **Step 3: Implement** (verification through the 4b base's verifiers for the classical kinds and
  `env.crypto().ml_dsa_{44,65}_verify` for the PQ ones).
- [ ] **Step 4:** Step 2's command — PASS.
- [ ] **Step 5: Commit** `ua8 B2: Soroban registry entries + register (portable PoP, ML-DSA via CAP-0087)`.

### Task B3: `set_kem_key`, `store_pqz_pop`, KEM views (P4, P5, P7, P9)

**Files:**
- Modify: `<factory crate>/src/lib.rs`, `<factory crate>/src/test_ua8.rs`

**Interfaces:**
- Produces: `set_kem_key(env, ua, version: u64, kem_pk: Bytes, sig: Bytes, relayer: Option<Address>)` (rules of A7;
  `sig` in the UA8-D5 format; `Checked` per UA8-D20), `store_pqz_pop(env, ua, pqz_pop: Bytes)` (hash check, no-op when
  stored, `proven` stays false), `kem_key_of(env, ua) -> Option<(u64, Bytes, Bytes, Checked)>`,
  `kem_key_at(env, ua, version: u64) -> Option<(Bytes, Bytes, Checked)>`; event `UaKemKeySet(ua, version, key_hash, checked)`.

- [ ] **Step 1: Failing tests:** `ua8_kem_any_order_write_once` (3, 1, 2; a repeated version refused), `ua8_kem_from_vectors`
  (every `kemRecords[]` row of an `mldsa65` UA), `ua8_kem_length_and_holder_refused`, `ua8_kem_by_third_party`,
  `ua8_store_pqz_pop_hash_checked`, `ua8_store_pqz_pop_idempotent`.
- [ ] **Step 2:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Step 2's command — PASS.
- [ ] **Step 5: Commit** `ua8 B3: Soroban set_kem_key, store_pqz_pop, KEM views`.

### Task B4: relayer-checked mode (P11; UA8-D18–D20)

**Files:**
- Modify: `<factory crate>/src/lib.rs` (constructor `relayers: Vec<Address>`, `relayers()` view), `<factory crate>/src/test_ua8.rs`

- [ ] **Step 1: Failing tests:** `ua8_relayer_unlisted_refused` (`RelayerNotListed`), `ua8_relayer_must_authorise`
  (a listed address without its auth → host auth error), `ua8_relayer_checked_fndsa512_marked` (`pop_checked =
  Relayer(id)`, KEM records likewise, event carries it), `ua8_relayer_mode_still_verifies_chain_parts` (an `mldsa65`
  `pop` with a bad signature submitted with a listed relayer → `Pop`), `ua8_relayer_msig_mixed_members` (an `msig` with
  an `fndsa512` member → `Relayer`; all `mldsa65` → `Chain`), `ua8_relayer_bad_record_takes_slot_marked` (P11.6: a
  listed relayer's bad `fndsa512` KEM record occupies `(ua, v)`, marked with its id), `ua8_relayer_checked_ua_authorises_nothing`
  (P11.5: the 4b base refuses any signature of a UA whose kind it cannot verify), `ua8_relayer_list_immutable` (no entry
  changes it).
- [ ] **Step 2:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Step 2's command — PASS.
- [ ] **Step 5: Commit** `ua8 B4: Soroban relayer-checked mode (listed relayers, checked per part)`.

### Task B5: off-chain verifier and client re-check (P11.1, P11.4; UA8-D24)

**Files:**
- Create: `clients/ua-rs/src/pq.rs` (feature `pq`), `clients/ua-rs/tests/pq.rs`
- Modify: `clients/ua-rs/Cargo.toml` (feature `pq`, exact pins), `clients/ua-rs/src/{ua8.rs,verify.rs}` (PQ kinds
  behind the feature), `clients/clientkeys/src/ua.js` (`verifyRegistration`, `verifyKemRecord`),
  `clients/clientkeys/test/ua8.test.js`

**Interfaces:**
- Produces: `scaas_ua::ua8::{check_registration(kind: u16, key_data: &[u8], attrs: &Attrs, pop: &[u8], pqz_pop: &[u8]) -> Result<()>,
  check_kem_record(kind: u16, key_data: &[u8], ua: &[u8;32], version: u64, kem_pk: &[u8], sig: &[u8]) -> Result<()>}`
  (UA id from key data, holder and shape rules, every signature incl. `msig` members, `keccak256(pqz_pop) ==
  pqz_pop_hash`; the PQZ proof itself is not checked, UA8-D20); clientkeys `verifyRegistration(row)` /
  `verifyKemRecord(row)` with the same rules (what a client runs before it uses a KEM or PQZ key read from a chain where
  a part is not `Chain`).

- [ ] **Step 1: Failing tests:** ua-rs `pq::pq_kat_verifies`, `pq::pq_external_verifies`, `pq::pq_signatures_verify`,
  `ua8::check_registration_vectors`, `ua8::check_kem_record_vectors`, `ua8::check_refuses_negatives`; clientkeys
  `verifyRegistration accepts every row and refuses every negative`, `verifyKemRecord accepts every row and refuses a
  flipped byte`.
- [ ] **Step 2:** `cd clients/ua-rs && ../../scripts/capped cargo test -j2 --features pq`; `cd clients/clientkeys && ../../scripts/capped npm test` — FAIL.
- [ ] **Step 3: Implement.** A crate that disagrees with any KAT entry is not used (the step reports which, and the
  kind stays unverifiable off chain, so no node submits it in relayer mode).
- [ ] **Step 4:** Step 2's commands and `../../scripts/capped cargo clippy -j2 --all-targets --features pq -- -D warnings` — PASS.
- [ ] **Step 5: Commit** `ua8 B5: ua-rs pq feature + UA-8 record checks; clientkeys re-check`.

### Task B6: node — Soroban `call` jobs and the relayer pre-check (P11.1; UA8-D23)

**Files:**
- Modify: `scaas-node/Cargo.toml` (`scaas-ua` path dependency, feature `pq`), `scaas-node/src/adapters/soroban.rs`
  (`job_call`: `"call"`; `ua8_call_job`), `scaas-node/src/adapter.rs` (the kinds list of the Soroban adapter),
  `scaas-node/node.example.toml` (`params.ua_registry` of the Soroban chain)

**Interfaces:**
- Produces: `pub fn ua8_call_job(network: &[u8; 32], op: &Value, lane: &ScAddress, registry: &ScAddress) -> Result<InvokeContractArgs>`
  (target / function allow-list, no auth entries, `relayer` = `lane` when present; for a write with a part UA8-D20
  marks `Relayer`, the decoded arguments pass `scaas_ua::ua8::check_*` before simulation, else the job fails without a
  submit).

- [ ] **Step 1: Failing tests:** `soroban_call_job_registry_only`, `soroban_call_job_function_allowlist`,
  `soroban_call_job_has_no_auth_entries`, `relayer_arg_is_the_lane`, `relayer_mode_prechecks_off_chain` (a valid
  `fndsa512` row passes), `relayer_mode_refuses_failing_record` (a flipped `pop` byte: refused, never simulated),
  `unknown_job_kind_is_refused` (still).
- [ ] **Step 2:** `cd scaas-node && ../scripts/capped cargo test -j2 adapters::soroban` — FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** `../scripts/capped cargo test -j2 && ../scripts/capped cargo clippy -j2 --all-targets -- -D warnings` — PASS.
- [ ] **Step 5: Commit** `ua8 B6: scaas-node Soroban call jobs for the registry writes, relayer pre-check`.

### Task B7: the copy EVM → Soroban → EVM (P10 work item 6)

**Files:**
- Create: `smartcontracts/soroban/vectors/ua8-roundtrip.json` (written by the Soroban test, `--check` mode in the gate),
  `scaas-node/tests/e2e_ua8.rs` (`#[ignore]`)
- Modify: `<factory crate>/src/test_ua8.rs`, `smartcontracts/evm/test/ua/UARegistryUA8.t.sol`

- [ ] **Step 1: Failing tests:** Soroban `ua8_record_bytes_round_trip` (every `portable.json` row and KEM record
  registered, read back with `registration_of` / `kem_key_at`, byte-equal to the row; writes the read-back bytes to
  `ua8-roundtrip.json` when `UA8_WRITE=1`, else compares); forge `test_ua8_sorobanRoundTripRegisters` (every
  `ua8-roundtrip.json` record registers on an EVM registry and `registrationOf` equals it); e2e
  `e2e_ua8_copy_evm_soroban_evm`: anvil (as `tests/e2e.rs`) + the local Protocol 30 quickstart (B0's command): register
  on EVM registry A, the node reads `registrationOf` and relays it as a Soroban `call` job, reads `registration_of` back,
  relays it as an EVM `call` job to registry B on a second anvil chain id; plus one `fndsa512` UA through the relayer
  mode and its KEM records 3 then 1.
- [ ] **Step 2:** `CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban`;
  `cd smartcontracts/evm && ../../scripts/capped forge test --match-test test_ua8_sorobanRoundTripRegisters`; the
  quickstart up, then `cd scaas-node && ../scripts/capped cargo test -j2 --test e2e_ua8 -- --ignored` — FAIL.
- [ ] **Step 3: Implement**; the quickstart is stopped on every exit (`docker stop scaas-stellar`).
- [ ] **Step 4:** Step 2's commands — PASS; log `smartcontracts/soroban/runs/<date>-ua8-e2e-local.txt`.
- [ ] **Step 5: Commit** `ua8 B7: copy EVM -> Soroban -> EVM (vector round trip + local P30 e2e)`.

### Task B8: docs, decisions, TODO

**Files:**
- Modify: `docs/networks/soroban.md` (new NET-SOR rule: the registry entries, `register` / `set_kem_key` /
  `store_pqz_pop`, the per-part `checked` table UA8-D20, the relayer list UA8-D19, TTL UA8-D22, the B0 limits and
  figures with the run log), `docs/contracts/accounts.md` (CTR-UA-31 family table: Soroban built; "Where the records
  live" row), `docs/node/job-api.md` (Soroban `op.kind = "call"`), `docs/decisions.md` (**CTR-UA-33** relayer-checked
  mode on Soroban with the owner rulings of P10 / P11 of 2026-10-29, and UA8-D18–D24 in full), the spec's status line,
  `TODO.md` (UA-8 step 2 done; next UA-8 plan = NEAR)

- [ ] **Step 1:** Write every change (no `[estimate]` for a measured figure).
- [ ] **Step 2:** `python3 scripts/test_docs_check.py && python3 -I scripts/docs_check.py check` — 0 errors.
- [ ] **Step 3: Commit** `ua8 B8: docs (soroban NET-SOR, accounts CTR-UA-31, decisions CTR-UA-33, TODO)`.

### Task B9: gate steps (local)

**Files:**
- Modify: `smartcontracts/evm/runs/2026-10-30-ua8-gates.sh` (Part B steps; for a new commit on `ua8-soroban` the
  runner re-runs only what is not done at that commit)

**Interfaces:**
- Produces: steps `soroban` (`CARGO_BUILD_JOBS=2 scripts/capped smartcontracts/scripts/test.sh soroban`), `ua-rs-pq`
  (B5's command), `soroban-roundtrip-check` (the Soroban test without `UA8_WRITE` and the forge round-trip test),
  `e2e-ua8-local` (quickstart up with `--memory`, B7's e2e, down on any exit); `FAMILIES="soroban"`; `NEW_TESTS` + every
  test of B0–B7. The Part A steps stay (the forge and client steps re-run at the new commit).

- [ ] **Step 1:** Add the steps and names.
- [ ] **Step 2: Self-check the guard** as A13 Step 2 with a `soroban` cargo name.
- [ ] **Step 3: Run** the runner — every step `rc=0`.
- [ ] **Step 4: Commit** `ua8 B9: Soroban gate steps, logs`.

### Task B10: Stellar testnet e2e — only after 2026-11-03 (last step of the round)

**Files:**
- Create: `smartcontracts/soroban/runs/<date>-ua8-e2e-testnet.txt`

- [ ] **Step 1: Precondition:** the date is 2026-11-03 or later and the testnet RPC's `getNetwork` /
  `getLatestLedger` reports protocol 30 (read, never assumed); the SDK pin is a published release (B0). Otherwise
  stop here and leave B10 open in TODO.
- [ ] **Step 2:** Deploy the factory to the testnet (lanes funded by friendbot, relayer list = the lanes), then
  `STELLAR_URL=<testnet rpc> STELLAR_NETWORK=testnet ../scripts/capped cargo test -j2 --test e2e_ua8 -- --ignored`
  (EVM side on local anvil).
- [ ] **Step 3:** PASS; log the run (ledger numbers, contract ids, CPU / fee figures) and update `docs/networks/soroban.md`
  with the measured testnet figures.
- [ ] **Step 4: Commit** `ua8 B10: Stellar testnet e2e (Protocol 30)`.
- [ ] **Step 5:** Report to the controller: commits, B0 limits and UA8-D21's case, the figures; ask for the owner's go
  to merge / push.

---

**Open questions:** none blocks a task. The plan decides UA8-D1–D24 above (each recorded in `docs/decisions.md` as a
controller call the owner may override); Part B's only external dependency is the 4b Soroban spec and UA base, a
precondition, not a question.
