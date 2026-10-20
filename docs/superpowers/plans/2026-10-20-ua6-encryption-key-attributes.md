# UA-6: encryption keys as attributes, `authRef` removed: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (one implementer and one reviewer per task). Steps use checkbox (`- [ ]`) syntax.

**Status:** plan (designer for UA-6, 2026-10-20), **waiting for the owner's review of the spec** (Task 0). Nothing here is built.

**Base:** `main` at `c173de37` (5g-Z2 merged). UA-6 runs **before** plan Task 5h (CTR-UA-30); the 5h plan is being
updated in parallel and is this plan's dependency only for the chain-7622 roll-out (plan fs3 Task 13).

**Goal.** Build the owner rulings of 2026-10-20 (decisions CTR-UA-30 and its two Change lines, CTR-ZTH-32 Change):
1. a UA is the actor that signs a write; the PQZ public key is an attribute of a PQ signing UA (`mldsa44`, `mldsa65`,
   `fndsa512`, or a PQ-dominant `msig`), supplied in `register`, immutable, one UA per key, `msig` included;
2. the `pqz-mlwe` kind 0x0142 goes (0x0142 stays as the PQZ scheme id); `R_REG` is bound to chain, registry and the
   signer's UA id;
3. the classical Zether key is the UA ("self" mode): spends by proof, other writes by Schnorr with `x`; `authRef` is
   removed entirely, with `authPop`, purpose `authref`, `UAAuthRef`, `requireZetherAuthorized`;
4. classical Zether on BLS12-381 only: `zether-bn254` 0x0140 and its Schnorr verifier to `legacy/`.

**Spec:** [`docs/superpowers/specs/2026-10-20-ua6-encryption-key-attributes.md`](../specs/2026-10-20-ua6-encryption-key-attributes.md)
(U1–U20, owner question Q1). Normative text after Task 1: `docs/contracts/accounts.md` §1.4–§1.8, `zether.md` §13 and
CTR-ZTH-51, `pq-zero-knowledge.md` §6, §7.2, §7.10, `docs/node/gateway.md` NODE-GW-03.

## Global constraints

- Heavy jobs under `scripts/capped` (forge, cargo, npm, dotnet, dart / flutter), **never wrapped in `timeout`** (it
  kills a job still queued for a slot); from `smartcontracts/evm`: `../../scripts/capped forge …`. After a capped
  `dotnet` run: `dotnet build-server shutdown`. Never poll; stop every background shell before reporting.
- No merge, no push by implementers; the controller merges after the owner's approval.
- Backup, not delete: everything removed goes to `smartcontracts/evm/legacy/ua6/` (and the clients' legacy folders).
- Decisions into `docs/decisions.md` in full (content + status + commit), "controller proposal, owner may override"
  for U1–U20.
- No size optimisation (owner: wait for Glamsterdam); `scripts/size_gate.py` with the ratcheting baseline for every
  contract whose bytecode changes. Forge gas tests are fine; no timing runs without the owner's go-ahead.
- All chains are test-only: no compatibility path, no record migration.
- Every commit ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Decisions (controller proposals; the owner may override)

| # | Decision | Proposal | Why |
|---|---|---|---|
| U1 | Record | `Record` unchanged (one slot); `_authRef` removed; new `_pqzKey[ua]` = SSTORE2 pointer (0 = none); the PQZ key claims `keyOwner[keccak256(GROUP("pqz-mlwe") ‖ key)]` (msig too); no length in the registry (the verifier checks `PqzCt.PK`). | One extra cold SLOAD only on PQZ paths; 5h's 20,608-byte keys need no registry change. |
| U2 | `register` | `register(kind, keyData, pop, pqzKey, pqzPop)`, the pair empty except for holders. | One selector for every kind; reuses the removed pair's slots. |
| U3 | Holder set | `mldsa44`, `mldsa65`, `fndsa512` (where enabled); `msig` with non-PQ weight (kinds outside 0x0130–0x0133) < threshold. `slhdsa128s` not a direct holder; everything else `UAPqzHolder`. | The owner's list; `slhdsa128s` keeps counting as PQ inside an `msig` as built. |
| U4 | PoP digest | `popDigest(ua, pqzKeyHash)` (the `authRef` word renamed; 0 without a key); signer PoP and `R_REG` over the same digest. | No strip / swap by a front-runner; classical PoP bytes unchanged. |
| U5 | `msig` PoP | A PQ-eligible `msig` always registers with an m-of-n `MemberSig[]` over `uaMessage(MSIG, POP, popDigest(ua, h))`; a classical `msig` keeps `pop` empty. | Stops squatting an `msig` id without (or with a foreign) PQZ key. |
| U6 | Interface | `recordOf → (Record, address pqzKey)`; `UARegistered(ua, kind, keyData, address pqzKey)`; `UAPqzHolder(bytes32)` new; `UAAuthRef` and `requireZetherAuthorized` gone; slot 0x0142 = PQZ key verifier + cap, one generation per chain. | The token copies the key by pointer; no 16 KB event. |
| U7 | PQZ token lookup | `_registered` / `_keyPtr` from `recordOf(ua).pqzKey`; `_check` calls `requireAuthorized(from, PURPOSE_ZETHER_AUTH, authDigest, authSig)`. Statements, relations and statement vectors unchanged. | The signer is the account; the registry's one-to-one map binds `(ua, pk)`. |
| U8 | Zether kind sets | `zether-bls12381` joins SIGNING (every purpose through `requireAuthorized`, UA-ledger receiver), not MEMBER, not a PQZ holder. **Q1.** | Its public balance shares the id and must be spendable by its key. |
| U9 | Zether spends | Proof alone: `kindOf(from)` check; `authSig` and the `SCAAS-ZETHER-AUTH-V1` digest removed from every proof-covered entry point and the prover. Owner ops through `requireAuthorized(ua, PURPOSE_ZETHER_OWNER, digest, abi.encode("", schnorrSig))`. | A dead argument is an ABI break either way; one registry path. |
| U10 | bn254 | UA-6 moves the whole bn254 Zether line (kind, Schnorr verifier, token verifier instances, `proofSystemId`, deploy steps, fixtures, KATs) to `legacy/`; 5h drops its bn254 step. | The kind cannot leave while bn254 suites register bn254 accounts; UA-6 lands first. |
| U11 | Index | Each UA in its kind's list; a holder also in the `0x0142` "PQZ-capable" list (`uaCount/uaAt/uaPage(0x0142)`), no reverse index. The CTR-UA-29 decoy rule loses its `authRef` clause. | One anonymity set per chain for PQZ decoys; ≈ +27 k gas per holder. |
| U12 | Public balances | PQZ public balance, fees, shield source under the signing UA id; Zether public balance under the Zether UA id. | CTR-UA-30 (2), (3); CTR-PQZ-06 Change 2026-10-20. |
| U13 | `R_REG` | Message `uaMessage(0x0142, POP, popDigest(signerUA, h))`; no own `proofSystemId`; reaches 7622 with the 16k id in fs3 Task 13. | The message is opaque to the relation; the verifier probe is unchanged. |
| U14 | Clients | 9 libraries + clientkeys + zether-prover per spec §10 table; 0x0142 in a `SCHEMES` table. | `tag(0x0142)` and the keyHash group must survive. |
| U15 | Node | Gateway route `{chain, kind, keyData, pop, pqzKey?, pqzPop?}`, its body limit 160 KiB; record cache on the new `recordOf`. No node source change expected. | A PQZL holder registration is ≈ 100–108 KB as hex. |
| U16–U19 | Vectors, size, gas, tests | Spec §10. | — |
| U20 | Migration | Redeploy; 7622 in fs3 Task 13. | Test chains only. |

## Review Focus (inputs most likely to bite)

1. **Front-running a holder registration** (U4): a relayed `register` with `pqzKey` stripped, swapped, or with `pqzPop`
   from another id must fail `UAPoP`; one test per variant, and one for an ML-DSA PoP signed over `h = 0` submitted with
   a key.
2. **`msig` squatting** (U5): a PQ-eligible `msig` without `pop`, with `pop` over another `h`, or with fewer weight than
   the threshold ⇒ `UAPoP`; a classical `msig` with `pop` non-empty ⇒ `UAPoP` (unchanged).
3. **Uniqueness across kinds** (CTR-UA-30 (4)): the same PQZ key on an ML-DSA UA and then on an `msig` (and the reverse)
   ⇒ `UAKeyInUse`; across generations: 0x0142 refused in gen 2 when gen 1 enables it (`UAConfig(0x0142)`).
4. **Zether in SIGNING but not MEMBER** (U8): `isSigning(0x0141)` true, `isMember(0x0141)` false; an `msig` naming a
   Zether member ⇒ `UAKeyData(MSIG)`/`UAMemberUnknown` as for any non-member kind.
5. **`requireAuthorized` on a Zether UA** must take `auth.keyData` empty (stored kind) and verify on `Y` from `keyPtr`;
   a non-empty `keyData` fails, as for every stored kind.
6. **The PQZ token never trusts the caller's key**: `_keyPtr` reads only `recordOf(ua).pqzKey`; a UA with a record but
   no key ⇒ `AccountNotRegistered`; the pointer's code length is checked against `PqzCt.PK + 1`.
7. **Classical vectors unchanged**: `kinds.json` / `signatures.json` PoP bytes for every non-holder row must be
   byte-identical before and after (`h = 0`).

## Tasks

### Task 0: Owner review and rulings
- [ ] The owner reads the spec and answers **Q1** (Zether UA signs every write: U8, or only its three writes).
- [ ] Worktree `ua6` from main; record the ruling in the branch's first commit (Task 1).

### Task 1: Fold the spec into the component docs and decisions
**Files:** `docs/contracts/accounts.md` (CTR-UA-06 / -07 popDigest word, -10 purpose table without `authref`, -14 and
-27 kind sets with Zether in SIGNING, -16 rewritten as "Zether key is the UA; PQZ key is an attribute", -17 stored keys
and `recordOf`, -29 list `0x0142` and the decoy rule, §1.6 kind table (0x0140 out, 0x0142 to a scheme table), §1.7 Zether
table and `authSig` paragraph, §1.8 interface / steps / storage / generations, threat S30, CTR-UA-22 note),
`docs/contracts/zether.md` (§13 rewritten without `authRef`, the `authRef` table removed, CTR-ZTH-32 bn254 to legacy,
CTR-ZTH-50, CTR-ZTH-51 public side under the Zether id, entry-point signatures without `authSig`),
`docs/contracts/pq-zero-knowledge.md` (§6 CTR-PQZ-12 / -13 as the attribute rule, record storage, §7.2 register steps,
§7.10 authorization, the threat list rows on `authRef`, the gas row of `register`), `docs/node/gateway.md` (route body,
limit, record cache), `docs/clients/signers-clientkeys.md` (register flow with the PQZ key), `docs/decisions.md`
(Change lines under CTR-UA-30, -16, -14, -17, -29, -10, CTR-PQZ-12, -13, CTR-ZTH-32, -51 carrying U1–U20 and Q1),
`README.md` §6 if it lists the kind sets.
- [ ] Rewrite each section to the post-UA-6 state (no history in component docs; history goes to decisions).
- [ ] Verify: `python3 -I scripts/docs_check.py check` → 0 errors; `grep -rn "authRef\|requireZetherAuthorized\|survivesEncKeyLeak\|PURPOSE_AUTHREF" docs/contracts docs/node docs/clients` → only "removed in UA-6" mentions. Commit.

### Task 2: Registry (U1–U6, U8 sets, U11)
**Files:** `smartcontracts/evm/src/ua/UAKinds.sol` (0x0140 out; `isZether = 0x0141`; `isSigning` + 0x0141;
`PURPOSE_AUTHREF` out; `tag` / `groupName` keep 0x0142 as a scheme; `popDigest` parameter rename),
`IUARegistry.sol`, `UARegistry.sol` (`register`, `_pqzAttr` holder rule from `keyData`, `_msig` PoP, `_pqzKey`,
`recordOf`, the `0x0142` list, `_authorized` without the Zether refusal; remove `_checkAuthRef`, `_checkPqzAuthRef`,
`_coSign`, `_authRef`, `requireZetherAuthorized` and its helpers; slot 12 out of `_cfg` / `_slot`; `_vkLength` without
0x0140 / 0x0142); tests `test/ua/UARegistry.t.sol`, `UARegistryPq.t.sol`, `UARegistryZether.t.sol`, `UARegistryBase.sol`,
`UAKinds.t.sol`, `UADeploy.t.sol`, `UAGas.t.sol`, new `test/ua/UARegistryUA6.t.sol`; `test/pqz/helpers/PqzRegistryBase.sol`.
- [ ] Write the failing `test_UA6_*` tests of spec U19 for the registry (Review Focus 1–5) first.
- [ ] Implement; move the replaced suites' `authRef` cases to `legacy/ua6/test/`.
- [ ] Verify (from `smartcontracts/evm`): `../../scripts/capped forge test --isolate --match-path 'test/ua/**'` green;
  `../../scripts/capped forge test --match-path 'test/pqz/**'` green. Commit.

### Task 3: Verifiers and deployment
**Files:** `src/ua/verifiers/PairingVerifiers.sol` (`ZetherSchnorrBn254Verifier` → `legacy/ua6/src/`),
`src/pqz/UAPqzVerifier.sol` (NatSpec: the PQZ key PoK verifier of slot 0x0142; bytecode unchanged),
`script/DeployBase.sol` (no 0x0140 step; `KindConfig(0x0142, …)` only where the PQZ gate allows),
`script/UAPrecompileProbe.sol` if it lists 0x0140, `script/pqz/e2e.py` (kinds list, one-call holder registration),
`pqz-core/nethermind/chain/e2e.py`.
- [ ] Verify: `../../scripts/capped forge test --match-path 'test/ua/UADeploy.t.sol'`;
  `../../scripts/capped forge test --match-path 'test/pqz/UAPqzVerifier.t.sol'`; `python3 -I -m py_compile script/pqz/e2e.py`. Commit.

### Task 4: Zether (U8–U10)
**Files:** `src/zether/ZetherLib.sol` (`_check` without the registry auth; `rollOverSigned` / `setRollOverMode` through
`requireAuthorized`; `AUTH_TAG` out), `ZetherLayer.sol`, `IZetherToken.sol`, `UnderlyingZetherToken.sol`,
`ZetherStatements.sol` (entry points without `authSig`), `ZetherTypes.sol` (BLS12-381 only), the bn254 token verifier
instances and `proofSystemId` (to legacy per U10); tests `test/zether/**` (fixtures `useBls = true` only;
`ZetherAuthRef.t.sol` and the bn254 KAT / prover-cross suites to `legacy/ua6/test/`), `test/ua/UAReceivers.t.sol`,
`UALedger.t.sol`, `UAWrap.t.sol` (a Zether UA as receiver and signer); `script/ZetherE2E.s.sol`, `scripts/e2e-zether.sh`.
- [ ] Tests: Zether spend without `authSig`; owner ops via `requireAuthorized`; a Zether UA signs a
  `UAMetaTransaction` and `uaExecute(zetherShield)`; receives by `transferToUA`; refused as an `msig` member.
- [ ] Verify: `../../scripts/capped forge test --match-path 'test/zether/**'` and `--match-path 'test/ua/**'` green. Commit.

### Task 5: PQZ key lookup (U7, U12)
**Files:** `src/pqz/PqzLib.sol` (`_registered`, `_keyPtr`, `_check`; the NatSpec of the auth path), `PqzLayer.sol`
(NatSpec), `test/pqz/**` (holders registered with the key in one call; a leg / auditor without a key).
- [ ] Coordinate with 5h's library split if it has landed (`PqzCore` holds `_keyPtr` / `_check` then).
- [ ] Verify: `../../scripts/capped forge test --match-path 'test/pqz/**'`; statement views byte-identical
  (`test_transferStatementMatchesVector`). Commit.

### Task 6: Clients (U14)
**Files:** `clients/ua-rs` (`src/lib.rs`, `src/keydata.rs`, tests), `ua-c` (`src/lib.rs`, `include/scaas_ua.h`),
`ua-cxx` (`src/lib.rs`, `src/scaas_ua.cpp`, `include/scaas_ua.hpp`), `ua-qt` (`src/ua_kinds.rs`, `tests/tst_ua.qml`),
`ua-dart-frb` (`rust/src/api/ua.rs`, regenerated bindings), `ua-dart` (`lib/src/table.dart`, `ua.dart`, `keydata.dart`),
`ua-py` (`scaas_ua/__init__.py`), `ua-go` (`ua.go`, `keydata.go`), `ua-cs` (`Scaas.Ua/Ua.cs`, `KeyData.cs`),
`clients/clientkeys` (`src/ua.js`, `src/zether.js`, tests), `clients/zether-prover` (`src/api.rs`, `src/zether.rs`,
`src/envelope.rs`, `src/schnorr.rs`, bn254 builds off).
- [ ] Verify each: `../scripts/capped cargo test --locked` (ua-rs, ua-c with the header test, ua-cxx, ua-qt where Qt is
  installed, zether-prover); `flutter_rust_bridge_codegen generate && git diff --exit-code` then `../scripts/capped dart test`
  (ua-dart-frb); `../scripts/capped dart test && ../scripts/capped dart test -p node` (ua-dart);
  `../scripts/capped python3 -m unittest -v tests.test_vectors` (ua-py); `../scripts/capped go test ./...` (ua-go);
  `../scripts/capped dotnet test Scaas.Ua.Tests` then `dotnet build-server shutdown` (ua-cs);
  `../scripts/capped npm test` (clientkeys). Commit per library group.

### Task 7: Node (U15)
**Files:** `docs/node/gateway.md` (done in Task 1); `scaas-node/src` only if a selector or ABI string of
`register(uint16,bytes,bytes,bytes32,bytes)`, `recordOf` or `requireZetherAuthorized` appears.
- [ ] `grep -rn "register(uint16\|recordOf\|requireZetherAuthorized\|authRef" scaas-node/src scaas-node/tests` → none, or fixed.
- [ ] Verify: `cd scaas-node && ../scripts/capped cargo test --locked` (unit); the UA e2e
  (`../scripts/capped cargo test --test e2e -- --ignored`) on a dev chain if Task 4 changed a selector it relays. Commit.

### Task 8: Vectors (U16)
**Files:** `clients/clientkeys/scripts/ua-vectors.mjs`, `scripts/ua-sig-vectors.mjs`; `smartcontracts/vectors/ua/kinds.json`,
`structures.json`, `signatures.json`, `pq_signatures.json`, `groups.json`, `metatx3.json`; bn254 Zether rows
(`r33_keys.json` copies) to legacy; `smartcontracts/vectors/pqz/` unchanged.
- [ ] Regenerate: `cd clients/clientkeys && ../../scripts/capped node scripts/ua-vectors.mjs && ../../scripts/capped node scripts/ua-sig-vectors.mjs`.
- [ ] Check Review Focus 7 (non-holder PoP bytes identical): a `git diff --word-diff` of `signatures.json` shows only
  removed `authRef` fields, removed bn254 rows and new rows.
- [ ] Every library of Task 6 and the forge vector suites (`UARegistryVectors.t.sol`, `UAMetaTx3Vectors.t.sol`) pass the
  new files; `scripts/capped python3 -I smartcontracts/vectors/pqz/pqz_kat.py --check` (repo root) passes with no PQZ vector changed. Commit.

### Task 9: Gates (U17, U18)
- [ ] Full forge suite: `../../scripts/capped forge test` green (count recorded).
- [ ] Sizes: `../../scripts/capped forge build --sizes --json > /tmp/ua6-sizes.json 2>/dev/null; python3 -I ../../scripts/size_gate.py /tmp/ua6-sizes.json size-baseline.json`; ratchet the baseline down where code shrank; log `runs/<date>-ua6-sizes.txt`.
- [ ] Gas: the U18 rows by `../../scripts/capped forge test --isolate --match-path 'test/ua/{UAGas,UARegistryUA6}.t.sol' -vv`
  and the Zether / PQZ gas tests; log `smartcontracts/evm/runs/<date>-ua6-gas.txt` with before / after.
- [ ] `python3 -I scripts/docs_check.py check` 0 errors; the docs' gas rows updated from the log. Commit.

### Task 10: Review
- [ ] Reviewer (Claude sub-agent; Codex only on the owner's request): spec conformance, Review Focus 1–7, the legacy
  backups, the gas and size logs. Fixes; findings and dispositions recorded under CTR-UA-30 in decisions.md.

### Task 11: Merge
- [ ] After the owner's approval the controller merges `ua6` into main (and pushes on the owner's word). The 7622
  redeploy is **not** here: it happens in plan fs3 Task 13 with the 16k `proofSystemId` (spec §9, U20), using Task 3's
  `e2e.py`. Until then 7622 keeps today's registry.

## Out of scope
Mainnet 22776. The 5h state layout, the K_MAX = 16,384 parameter set and its `proofSystemId` (plan 5h). Wallet decoy
selection code (P6h). The node's UA routes and record cache as code (UA F5). An EIP-191 `secp256k1` variant (CTR-UA-29
W-J). Threshold decryption for `msig` PQZ keys.

## Critical files
- `smartcontracts/evm/src/ua/UARegistry.sol` (`register` 330, `_claim` 355, `_checkAuthRef` 375, `_checkPqzAuthRef` 390,
  `_keyPtr` 411, `_popOk` 416, `_authorized` 486, `_derived` 502, `_zetherAuthorized` 541, `_cfg` 685, `_slot` 699,
  `_vkLength` 712), `IUARegistry.sol`, `UAKinds.sol` (sets 84–107, `groupName` 159, `popDigest` 212)
- `smartcontracts/evm/src/pqz/PqzLib.sol` (`_check` 807, `_registered` 871, `_keyPtr` 876), `UAPqzVerifier.sol`
- `smartcontracts/evm/src/zether/ZetherLib.sol` (`rollOverSigned` 335, `setRollOverMode` 357, `registeredOn` 597,
  `_check` 604), `ZetherLayer.sol`, `ZetherTypes.sol`; `src/ua/verifiers/PairingVerifiers.sol` 112–140
- `smartcontracts/evm/src/metatx/ERC20MetaTx.sol` (`_checkTo` 426)
- `smartcontracts/evm/test/zether/helpers/ZetherFixture.sol` (`_deploy` 80, registry kinds 109–114),
  `test/pqz/helpers/PqzRegistryBase.sol`
- `clients/ua-rs/src/lib.rs` (`KINDS` 100–105, `PURPOSES` 113, sets 150–161, `pop_digest` 245)
- `docs/contracts/accounts.md` §1.7–§1.8, `zether.md` §13, `pq-zero-knowledge.md` §6, §7.2
