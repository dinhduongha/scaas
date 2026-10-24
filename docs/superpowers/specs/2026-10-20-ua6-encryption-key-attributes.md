# UA-6: encryption keys as attributes, `authRef` removed: design

**Status:** design for the owner's review (designer for UA-6, 2026-10-20). Nothing is built; the decisions below
(U1–U20) are controller proposals inside the owner's rulings and stand until the owner overrides them. Implementation
plan: [`2026-10-20-ua6-encryption-key-attributes.md`](../plans/2026-10-20-ua6-encryption-key-attributes.md).

**Inputs.** Owner rulings in [decisions.md](../../decisions.md): **CTR-UA-30** and its two Change lines of 2026-10-20
(UA = the actor that signs and answers for a write; the PQZ key is an attribute of a PQ signer, supplied in `register`,
immutable, one UA per key; the Zether key is the UA, "self" mode; `authRef` removed entirely, Zether included);
**CTR-ZTH-32** Change 2026-10-20 (classical Zether on BLS12-381 only; the bn254 line to `legacy/`); CTR-UA-29 (per-kind
index), CTR-UA-10 / -14 / -16 / -17, CTR-PQZ-06 Change lines of 2026-10-20 (fees to the public UA-ledger balance; the
four transfer flows; proof-free shield), CTR-PQZ-12 / -13. Research: [`ua-identity.md`](../../research/ua-identity.md)
(§6 minimal design, §7 migration list; §8 superseded by §9), [`shield-and-key-reuse.md`](../../research/shield-and-key-reuse.md)
§1 (leaked `x` = full loss, accepted). Normative text today: [accounts.md](../../contracts/accounts.md) §1.6–§1.8,
[zether.md](../../contracts/zether.md) §13, CTR-ZTH-51, [pq-zero-knowledge.md](../../contracts/pq-zero-knowledge.md) §6,
§7.2, §7.10.

**Dependency.** Plan Task 5h ([spec](2026-10-20-pqz-state-redesign.md), [plan](../plans/2026-10-20-pqz-state-redesign.md);
being updated in parallel for the `K_MAX = 16,384` ruling and the proof-free shield). CTR-UA-30 orders UA-6 **before**
5h; the `R_REG` message change of UA-6 reaches SCaaS testnet together with 5h's `proofSystemId` bump (the "16k" id, which
also carries the B-1 transcript fix) in the roll-out of plan fs3 Task 13 (§9).

**Code read** (main `c173de37`): `smartcontracts/evm/src/ua/UARegistry.sol` (`register` 330–352, `_checkAuthRef` 375,
`_checkPqzAuthRef` 390, `_authorized` 486, `_zetherAuthorized` 541), `IUARegistry.sol`, `UAKinds.sol`,
`src/pqz/UAPqzVerifier.sol`, `src/pqz/PqzLib.sol` (`_check` 807, `_registered` 871, `_keyPtr` 876),
`src/zether/ZetherLib.sol` (`rollOverSigned` 335, `setRollOverMode` 357, `_check` 604, `registeredOn` 597),
`src/zether/ZetherTypes.sol`, `src/ua/verifiers/PairingVerifiers.sol` (`ZetherSchnorrBn254Verifier` 116),
`src/metatx/ERC20MetaTx.sol` (`_checkTo` 426), `clients/ua-rs/src/lib.rs`, `smartcontracts/vectors/ua/`,
`smartcontracts/vectors/pqz/statement_register.json`, `pqz-core/stmt/src/lib.rs`, `docs/node/gateway.md` NODE-GW-03.

## 1. Summary

| Before (built) | After UA-6 |
|---|---|
| `pqz-mlwe` 0x0142 is a UA kind; its id = `keccak256(TAG ‖ pk)`; an immutable `authRef` (a PQ signer) co-signs | 0x0142 is a **scheme id**, not a kind; the PQZ key is an attribute of a PQ signing UA (`mldsa44`, `mldsa65`, `fndsa512`, or a PQ-dominant `msig`), given in that UA's `register` |
| PQZ account, fees and public balance under two ids (the PQZ UA and its `authRef`) | one id: the signing UA |
| Zether UAs: `authRef` (0 = self, or a co-signer), `requireZetherAuthorized`, never a signer through `requireAuthorized` | the Zether key **is** the UA: spends by proof alone, every other write by Schnorr with `x` through `requireAuthorized`; no `authRef`, no `requireZetherAuthorized` |
| `zether-bn254` 0x0140 and `zether-bls12381` 0x0141 | 0x0141 only; 0x0140 and its Schnorr verifier in `legacy/` |
| `register(kind, keyData, pop, authRef, authPop)`; `popDigest(ua, authRef)` | `register(kind, keyData, pop, pqzKey, pqzPop)`; `popDigest(ua, pqzKeyHash)` — the same bytes for every UA without a PQZ key |
| `R_REG` message `uaMessage(0x0142, POP, popDigest(pqzUA, authRef))` | `uaMessage(0x0142, POP, popDigest(signerUA, pqzKeyHash))`; relation, statement layout, verifier and vectors unchanged |
| per-kind list holds `pqz-mlwe` UAs | each UA in its kind's list; a PQZ holder also in the list `0x0142` (the "PQZ-capable" list for decoys) |
| purpose `authref`, error `UAAuthRef`, `survivesEncKeyLeak` | gone |

Net: the registry loses a mapping, two check functions, one co-sign path and one external function, and gains one
mapping and one optional argument pair.

## 2. Record and storage (U1)

```
mapping(bytes32 ua      => Record)     _records;   // unchanged: kind (16) | registeredAt (40) | keyPtr (160) | index (40) = one slot
mapping(bytes32 ua      => address)    _pqzKey;    // NEW: SSTORE2 pointer of the PQZ public key; 0 = none. Written once.
mapping(bytes32 keyHash => bytes32)    _keyOwner;  // unchanged; also claims keccak256(GROUP("pqz-mlwe") ‖ pqzKey) for every holder, msig included
mapping(bytes32 ua      => address[2]) _ekPtr;     // unchanged (ML-DSA expanded-key cache)
mapping(uint16 kind => …) _uaCount / _uaAt;        // unchanged; key 0x0142 = the PQZ-capable list (§7)
removed: mapping(bytes32 ua => bytes32) _authRef
```

- **Fields removed:** `authRef` (the `_authRef` mapping, the `recordOf` second return value, the `UARegistered` field),
  `authPop` (the `register` argument). The `Record` struct keeps its one slot: the PQZ pointer does not fit, and a
  separate mapping costs one cold SLOAD only on the PQZ paths that need it.
- **PQZ key storage:** SSTORE2 of the key bytes, as `keyPtr` today (16,384 B now; 20,608 B after the 16k parameter set,
  still under EIP-170 for the data contract). The registry does **not** hard-code the length: `UAPqzVerifier.verifyPop`
  already refuses any key that is not exactly `PqzCt.PK` bytes with every coefficient `< q` (CTR-PQZ-13 change
  2026-10-16), so the registry stays unchanged when 5h changes `PK`.
- **Uniqueness (CTR-UA-30 (4)):** the PQZ key claims `keyHash = keccak256(GROUP("pqz-mlwe") ‖ pqzKey)` in the existing
  `_keyOwner` map, read through the predecessor as today; a second registration with the same key reverts
  `UAKeyInUse(keyHash, owner)` whichever kind (single key or `msig`) tries it. The group name `pqz-mlwe` and its tag stay,
  so the keyHash bytes are those of today.
- **Immutability:** `_pqzKey[ua]` is written only inside `register`. Ids keep their derivation (CTR-UA-30 (1)), so the
  PQZ key is **not** in the id: a PQ signer registered without a PQZ key can never get one (a new signing key is a new
  UA, CTR-UA-13). Wallets register the PQZ key with the signer from the start.

## 3. `register` per kind (U2–U5)

```solidity
function register(uint16 kind, bytes calldata keyData, bytes calldata pop, bytes calldata pqzKey, bytes calldata pqzPop)
    external returns (bytes32 ua);   // pqzPop empty iff pqzKey empty
```

| Kind | `keyData` | `pop` | `pqzKey` | `pqzPop` |
|---|---|---|---|---|
| native ids | no registration (CTR-UA-06) | — | — | — |
| classical single key 0x0100–0x0108, group 0x0110–0x0113 | as today | as today, over `uaMessage(kind, POP, popDigest(ua, 0))` (bytes unchanged) | empty (`UAPqzHolder` otherwise) | empty |
| `zether-bls12381` 0x0141 | `Y` (128 B) | Zether Schnorr by `x` over `uaMessage(0x0141, POP, popDigest(ua, 0))` | empty | empty |
| `slhdsa128s` 0x0133 | `pk` (32 B) | as today | empty (U3) | empty |
| `mldsa44` 0x0130, `mldsa65` 0x0131, `fndsa512` 0x0132 | `pk` | the kind's signature over `uaMessage(kind, POP, popDigest(ua, h))` | the PQZ public key, or empty | `R_REG` proof over `uaMessage(0x0142, POP, popDigest(ua, h))` |
| `msig` 0x0120, classical-dominant (non-PQ weight ≥ threshold) | the structure | empty (today) | empty | empty |
| `msig` 0x0120, PQ-eligible (non-PQ weight < threshold) | the structure | **required** (U5): `abi.encode(MemberSig[])` reaching the threshold over `uaMessage(0x0120, POP, popDigest(ua, h))` | the PQZ key, or empty | `R_REG` as above |

`h = keccak256(GROUP("pqz-mlwe") ‖ pqzKey)` (the PQZ keyHash) when `pqzKey` is given, else `0`.

**U2 — one function, optional pair.** One `register` with a trailing `(pqzKey, pqzPop)` pair, empty for everyone but PQ
holders: the same selector for every kind (node gateway, clients), and the argument slots of the removed
`(authRef, authPop)` pair are reused. A separate `registerWithPqzKey` was rejected: two entry points for one record.

**U3 — the holder set** (CTR-UA-30 (3), CTR-PQZ-12): single-key holders are `mldsa44`, `mldsa65` and `fndsa512` (the
owner's list; `fndsa512` registers only where the chain enables its verifier, so "later" needs no registry change);
`slhdsa128s` is **not** a direct holder (not in the owner's list; a 7,856-byte signature and a ≈ 1.4 M gas cap on every
spend) but counts as PQ weight inside an `msig`, as built (`_isPq` = 0x0130–0x0133). An `msig` holds a PQZ key iff the
summed weight of its members whose kind is not 0x0130–0x0133 is below its threshold (today's `_checkPqzAuthRef`, now
read from `keyData` directly instead of `authPop`). Every other kind, Zether included, reverts `UAPqzHolder(ua)`.

**U4 — one digest for both proofs.** `popDigest(ua, h) = keccak256(abi.encode(POP_TAG, chainKeyHash, chainUid, registry,
ua, h))` — the built function with its last word renamed from `authRef` to `pqzKeyHash`. The signer's PoP and the
`R_REG` proof are over the same digest under different kind tags (`TAG(kind)` vs `TAG(0x0142)` in `uaMessage`), so:
a relayer or front-runner can neither strip the PQZ key (the signer's PoP over `h ≠ 0` fails with `h = 0`) nor swap it
(another key changes `h`); `R_REG` is bound to chain, registry and **the signer's id**, so a proof made for another UA
fails; a UA without a PQZ key keeps today's PoP bytes (`h = 0` = the old `authRef = 0`), so every classical vector and
client PoP stays valid.

**U5 — a PQ-eligible `msig` signs its registration.** Today an `msig` registers with no signature (a pure function of its
members). With an optional attribute that is a squatting hole: anyone who learns the structure could register it first
without a PQZ key (or, if `pop` stayed empty, with their own key and their own `R_REG` over the victim's id), and the id
could never get the members' key. So a PQ-eligible `msig` always registers with the m-of-n `MemberSig[]` over
`uaMessage(MSIG, POP, popDigest(ua, h))` — the built `_msig` check with purpose `pop`; members sign
`memberDigest(ua, that message)` under `member` as for any `msig` authorization — **with or without** a PQZ key. A
classical-dominant `msig` can never hold a PQZ key, so squatting gains nothing there and its `pop` stays empty (no
change). The registration bound of step 4 already covers the cost of that check (it is the authorization worst case).

### 3.1 Steps (cheap first)

1. `kindEnabled(kind)` — `UAKindDisabled(kind)`.
2. Key data canonical — `UAKeyData(kind)`.
3. `ua = uaOf(kind, keyData)`; not native-space, not registered here or in the predecessor.
4. Single key: `keyHash` free; `msig`: members and the gas bound (unchanged).
5. **PQZ attribute** (only if `pqzKey` non-empty): `kindEnabled(0x0142)` — `UAKindDisabled(0x0142)`; holder rule (U3) —
   `UAPqzHolder(ua)`; `h = keyHashOf(0x0142, pqzKey)` free here and in the predecessor — `UAKeyInUse`. `pqzPop`
   non-empty without `pqzKey`, or empty with it — `UAPoP`.
6. PoP: single key over `popDigest(ua, h)` (ML-DSA: cached path as today); classical `msig`: `pop` empty; PQ-eligible
   `msig`: `_msig(ua, PURPOSE_POP, popDigest(ua, h), keyData, pop)` — `UAPoP`.
7. `R_REG` (only with `pqzKey`): `UAPqzVerifier.verifyPop(pqzKey, uaMessage(0x0142, POP, popDigest(ua, h)), pqzPop)`
   through `_capped` at `verifyCap(0x0142)` with the hold — `UAPoP` (the verifier's length / coefficient refusal included).
8. Store `Record`, `keyPtr` (stored kinds), `_pqzKey[ua] = SSTORE2.write(pqzKey)`, `_keyOwner[keyHash] = ua`,
   `_keyOwner[h] = ua`, append to the kind's list and (holder) to the `0x0142` list; emit
   `UARegistered(ua, kind, keyData, pqzKeyPtr)`.

```mermaid
sequenceDiagram
    participant W as Wallet (PQ signer + PQZ key)
    participant R as Relayer / node
    participant G as UARegistry
    participant V as UAPqzVerifier (0x0142)
    W->>W: h = keccak256(GROUP(pqz-mlwe) ‖ pqzKey); d = popDigest(ua, h)
    W->>W: pop = ML-DSA sig over uaMessage(kind, POP, d)
    W->>W: pqzPop = R_REG proof over uaMessage(0x0142, POP, d)
    W->>R: register(kind, pk, pop, pqzKey, pqzPop)
    R->>G: register(…)
    G->>G: steps 1–5: kind, key data, id, keyOwner[pk group], holder rule, keyOwner[h] free
    G->>G: step 6: signer PoP over d
    G->>V: step 7: verifyPop(pqzKey, uaMessage(0x0142, POP, d), pqzPop) (capped)
    G->>G: step 8: record, _pqzKey[ua], keyOwner ×2, lists (kind, 0x0142)
```

### 3.2 Interface after UA-6 (U6)

```solidity
event UARegistered(bytes32 indexed ua, uint16 indexed kind, bytes keyData, address pqzKey);   // pointer, not 16 KB of log
error UAPqzHolder(bytes32 ua);          // NEW: this UA's kind / structure may not hold a PQZ key (U3)
// removed: error UAAuthRef(bytes32); requireZetherAuthorized(...)
function popDigest(bytes32 ua, bytes32 pqzKeyHash) external view returns (bytes32);
function register(uint16 kind, bytes calldata keyData, bytes calldata pop, bytes calldata pqzKey,
    bytes calldata pqzPop) external returns (bytes32 ua);
function recordOf(bytes32 ua) external view returns (Record memory r, address pqzKey);   // pqzKey 0 = none; gen 2 forwards
function kindEnabled(uint16 kind) external view returns (bool);   // kindEnabled(0x0142): this generation accepts PQZ keys
function verifyCap(uint16 kind) external view returns (uint64);   // verifyCap(0x0142): the R_REG verify cap
```

`recordOf` returns the pointer (as `Record.keyPtr`): the token copies the key straight into its statement buffer with
`EXTCODECOPY`, and returning 16–20 KB of `bytes` through a call would copy it twice. Wallets read the key with
`eth_getCode(pqzKey)` minus the leading `STOP` byte (as the SSTORE2 convention of `keyOf`). The event carries the pointer
(20 B) instead of today's 16 KB `pk` (≈ 0.13 M gas of log data saved); the bytes are in state (CTR-PQZ-07's rule).
`keyOf(ua)` keeps returning the signer's own stored key (ML-DSA `pk`, Zether `Y`, …). No `pqzKeyOf(bytes)` view: one
pointer read serves every reader.

**Kind table.** The registry's slot 12 (`zether-bn254`) goes; slot 18 (today `pqz-mlwe`) stays, now meaning "PQZ key
verifier and its cap" (`KindConfig(0x0142, UAPqzVerifier, cap)` at deploy). The generation rule keeps 0x0142 in at most
one generation per chain (its keyHash group `pqz-mlwe`, `_groupInPredecessor`), because gen 1 cannot see a key claimed
in gen 2. On every chain but the SCaaS testnet slot 18 is 0: a `pqzKey` reverts `UAKindDisabled(0x0142)` (CTR-PQZ-01).

## 4. How PQZ tokens find the key (U7)

| Today (`PqzLib`) | After |
|---|---|
| `_registered(r, ua)`: `kindOf(ua) == PQZ_MLWE` | `recordOf(ua).pqzKey != 0` |
| `_keyPtr(r, ua)`: `recordOf(ua)`, `kind == PQZ_MLWE`, `keyPtr.code.length == PK + 1` | `recordOf(ua).pqzKey`, `code.length == PK + 1`, else `AccountNotRegistered(ua)` |
| `_check`: `requireZetherAuthorized(from, authDigest, authSig, true)` (the registry dispatched to the `authRef`) | `requireAuthorized(from, PURPOSE_ZETHER_AUTH, authDigest, authSig)` on the signing UA itself; `UAVerifyGas` re-raised, anything else `AuthRejected` as today |

- Every UA id in a PQZ statement (`fromUA`, `toUA`, every leg of op 7, `auditorUA`) is now a signing UA id holding a PQZ
  key; `pk_f`, `pk_t`, `pk_a` are still loaded by the contract from the registry, never from the caller. Because
  `ua ↔ pqzKey` is one-to-one and immutable (U1), "the key of `fromUA`" in `R_TX` row 1 stays unique: **`R_TX`, `R_TX0`,
  `R_TXM`, `R_BURN`, the disclosure relations and the statement layout do not change** (ua-identity.md §4.5); only the
  values of the id words do, and the PQZ statement vectors take ids as input words, so they stay byte-identical.
- The `authDigest` covers the header ids, so the signer's ML-DSA / `msig` signature binds `fromUA`, the recipients and
  their keys (unchanged argument). Purpose `zether-auth` keeps its bytes (no vector churn).
- The auditor (`auditorUA`) must be a holder (it gets a signing UA it may never use); every credited leg must be a holder
  (`AccountNotRegistered`). Fees go to the beneficiary's **public UA-ledger balance** (CTR-PQZ-06 change 2026-10-20), so
  the beneficiary is any UA-ledger receiver (5h builds that); it needs no PQZ key.
- `pqzShield` (proof-free per the latest CTR-PQZ-06 change) burns the signer's public balance and credits a holder's
  accumulator; shielding to another account requires that account to be a holder.
- A leaked PQZ secret is a read-only breach (spends need the signer's signature); for an `msig` holder the PQZ secret is
  one view / prove key held by an operator, every spend needs the m-of-n (CTR-UA-30 (3)). This replaces the
  `survivesEncKeyLeak` wording for PQZ.

## 5. Zether "self" mode without `authRef` (U8, U9)

| Write | Today | After UA-6 |
|---|---|---|
| `zetherTransfer*`, `zetherUnshield*` (proof-covered) | `requireZetherAuthorized(from, authDigest, authSig, zkCovered = true)`: self ⇒ `authSig` empty; else the `authRef` signs | **the proof alone**: the token checks `kindOf(from) == ZETHER_BLS12381` (`AccountNotRegistered`) and verifies the proof; the `authSig` argument and the `SCAAS-ZETHER-AUTH-V1` digest are removed (U9) |
| `zetherRollOverSigned`, `zetherSetRollOverMode` | `requireZetherAuthorized(ua, digest, sig, false)`: self ⇒ Schnorr by `x` under `zether-owner`, `Y` from `keyPtr` | `requireAuthorized(ua, PURPOSE_ZETHER_OWNER, digest, sig)`; `sig = abi.encode(bytes(""), schnorrSig)` — the same bytes a self owner op carries today; the registry verifies on `Y` from `keyPtr` like any stored kind |
| `register` PoP | Schnorr by `x` over `popDigest(ua, authRef)` | over `popDigest(ua, 0)` (bytes as today's self accounts) |
| UA-ledger writes of the Zether UA's public balance (`ua*`, `uaExecute(zetherShield)`, trade) | impossible (Zether never signs through `requireAuthorized`, never a UA-ledger receiver) | Schnorr by `x` through `requireAuthorized` under the write's purpose; the Zether UA receives on the UA ledger (U8) |

**U8 — the Zether kind joins SIGNING, not MEMBER.** CTR-UA-30 (2) puts the Zether account's public balance and its
confidential account under one id; spending that public balance is a UA-ledger write the Zether UA must sign, and by the
owner's definition a key that signs a write is a UA. So `zether-bls12381` joins the SIGNING set: `requireAuthorized`
accepts it for every purpose (the verifier is `ZetherSchnorrBls12381Verifier`, `auth.keyData` empty as a stored kind),
`_checkTo` accepts it as a UA-ledger receiver, and parity (CTR-UA-27) applies. It stays **out of MEMBER** (a hot key the
wallet holds in software for every balance read, shield-and-key-reuse.md §1 risk 2; keeping it out of `msig`s is the
smaller change) and out of the PQZ holder set. Domain separation is unchanged: Schnorr hashes
`"SCAAS-ZETHER-SCHNORR-V1" ‖ R ‖ Y ‖ uaMessage(kind, purpose, digest)`; proofs have their own transcripts. **Owner
question Q1** (§11) confirms the scope.

**U9 — `authSig` leaves the Zether entry points.** With `authRef` gone the argument can only be empty; a dead argument in
every proof-covered entry point (`zetherTransfer`, `…Compact`, `…NoBundle`, `…Single`, `zetherUnshield`,
`zetherUnshieldUnwrap` and the specified `…ToUA` forms) and in the prover API is an ABI break either way, so it is removed with the `requireZetherAuthorized`
call (the `_authRef` read and the `authSig` calldata saved per spend; `kindOf(from)` replaces the call; U18 measures it). Kept rejected alternative: keep the argument and require it
empty.

**Removed** (CTR-UA-30 Change 2026-10-20): the `authRef` field and `authPop`; purpose `authref`
(`PURPOSE_AUTHREF`, the tag `scaas.ua.purpose.authref.v1`, the `_coSign` step); error `UAAuthRef`;
`requireZetherAuthorized`, `_zetherAuthorized`, `_zetherOwner`, `_zetherViaPredecessor`; `_checkAuthRef`,
`_checkPqzAuthRef` (rewritten as the U3 holder rule); the "BLS UA on the curve of `Y`" refusal (it constrained the
`authRef` choice; the self-inflicted variant — one secret `x` used both as a Zether key and a `bls12381-minsig` key —
becomes a wallet derivation rule, already true for the separate derivation trees); the doc term `survivesEncKeyLeak`
(a leaked Zether `x` is a full loss, accepted; a leaked PQZ key is read-only, §4). `UAKinds.isZether` becomes
`kind == ZETHER_BLS12381`.

## 6. `zether-bn254` to `legacy/` (U10)

Per CTR-ZTH-32 (2026-10-20): `UAKinds.ZETHER_BN254`, its name / tag / group rows, `ZetherSchnorrBn254Verifier`
(`PairingVerifiers.sol` 116), registry slot 12, `ZetherTypes.KIND_ZETHER_BN254` / `TAG_ZETHER_BN254` and the length
switch in `toUA` / `kindOf`, `DeployBase` steps, the bn254 rows of `kinds.json` / `signatures.json`, the bn254 Zether
key vectors (`r33_keys.json` rows) and the client kind rows move to `smartcontracts/evm/legacy/ua6/` and the clients'
legacy folders (backup, not delete). The `bn254-g1` group stays (`schnorr-bn254`, `musig2-bn254`, `frost-bn254`).

**Split with 5h.** CTR-ZTH-32 says "built with UA-6 (kind) and plan Task 5h (tokens)". The Zether fixture registers
bn254 accounts (`ZetherFixture._deploy(useBls = false)`, used by most Zether suites), so the kind cannot leave while the bn254 token line
still runs. Proposal: **UA-6 moves the whole bn254 Zether line** (kind, Schnorr verifier, the bn254 token verifier
instances and `proofSystemId`, deploy steps, fixtures switched to `useBls = true`, bn254 KATs and prover-cross tests to
`legacy/`, the prover built and tested on BLS12-381 only) since UA-6 lands first; plan 5h then has no Zether bn254 step.
If the parallel 5h update keeps it, whichever branch lands second drops its copy (controller's call at merge).

## 7. Per-kind index and decoys (U11)

Each UA stays in its kind's list (`uaCount(kind)`, CTR-UA-29), `msig` included. A holder is **also** appended to the list
of key `0x0142` — the "PQZ-capable" list — read with the same `uaCount(0x0142)`, `uaAt(0x0142, i)`,
`uaPage(0x0142, …)`. Reason: PQZ decoy legs need recipients with a PQZ key; the `mldsa65` list mixes holders and
non-holders and the `msig` list is mostly classical, so a wallet would otherwise filter by one `recordOf` per candidate,
and a per-kind filter leaks which kind the real recipient is. One list across kinds gives one anonymity set per chain.
`Record.index` keeps the kind-list position (`uaIndex`); the PQZ list has no reverse index (no reader needs one). Cost
≈ +27 k gas per holder registration (one more append, as measured for CTR-UA-29). Generations: the `0x0142` list lives
in the generation that enables 0x0142 (one per chain, §3.2). Classical Zether decoys keep using the `0x0141` list.

The decoy rule of CTR-UA-29's 2026-10-19 Change ("at most a fixed share per `authRef` group", threat S30) loses its
`authRef` clause: with one key per UA there is no on-chain grouping left to cap; the rule keeps "active in the token
within the look-back window, weighted by recency, never registered after the wallet's sync point". S30's text records
that a sybil decoy set now costs one PQ registration per decoy (≈ 5 M gas, free on the SCaaS testnet: bounded by node sponsorship
quotas, CTR-UA-25).

## 8. UA ledger and public balances (U12)

- **PQZ:** the public balance, the fees of CTR-PQZ-06 (2026-10-20), the source of `pqzShield` and the target of an
  unshield to oneself all live under the signing UA's id in the token's UA ledger, spent by that UA's ML-DSA / `msig`
  signature like any UA-ledger balance. No second id, no `authRef` hop.
- **Zether:** the public balance of a Zether account sits under its Zether UA id (U8), spendable by Schnorr with `x`;
  `uaExecute(zetherShield)` signed by the Zether UA shields its own public units. CTR-ZTH-51's "a PQ UA holder needs no
  classical key to use a Zether token" still holds for the public side (a PQ UA may pay a shield into any Zether
  account); the confidential side of classical Zether is classical by nature.
- `_checkTo` (`ERC20MetaTx` 426) needs no code change beyond `UAKinds.isSigning`; CTR-UA-14 / -27's "a Zether kind never
  receives" is deleted.

## 9. `R_REG`, `proofSystemId` and the 5h dependency (U13)

`R_REG` absorbs a 32-byte `message` (statement offset 64): the relation, the 16,480-byte statement (20,576 under the 16k
parameters), `UAPqzVerifier`, the precompile and `statement_register.json` (which takes the message as an input word)
do not change. Only the **pre-image** of the message changes (signer id instead of the PQZ id, keyHash instead of
`authRef`), which is registry and client code. Consequences:

- No `proofSystemId` of its own: the change "rides the 16k bump" (CTR-UA-30) in the sense that the SCaaS testnet gets the new
  registry when fs3 Task 13 resets it with the K_MAX = 16,384 / B-1 id; until then the SCaaS testnet keeps today's registry.
- The constructor probe of `UAPqzVerifier` (the pinned self-test vector with its fixed message) is untouched.
- 5h changes `PqzCt.PK` (20,608 B); the registry follows automatically (U1: no length in the registry).

## 10. Clients, node, vectors, size, gas (U14–U19)

**U14 — client libraries** (`clients/ua-rs`, `ua-c`, `ua-cxx`, `ua-qt`, `ua-dart-frb`, `ua-dart`, `ua-py`, `ua-go`,
`ua-cs`, clientkeys `src/ua.js`; the wrappers `ua-c` / `ua-cxx` / `ua-qt` / `ua-dart-frb` follow `ua-rs`):

| Item | Change |
|---|---|
| kind table | rows 0x0140 and 0x0142 out of `KINDS`; 0x0142 kept in a `SCHEMES` table (name `pqz-mlwe`, tag, group) so `tag(0x0142)`, `ua_msg(0x0142, …)` and `key_hash(0x0142, …)` still work, while `ua_of` / `validate_key_data` refuse it as a kind (`KindNotDerived`) |
| sets | `is_zether(k) = k == 0x0141`; `is_signing` adds 0x0141; `is_member` unchanged; new `is_pqz_holder(kind)` (0x0130–0x0132) and `msig_pqz_eligible(keyData)` |
| purposes | `authref` removed from `PURPOSES` |
| digests | `pop_digest(…, pqz_key_hash)` (parameter rename, same bytes); new `pqz_reg_message(chain, uid, registry, ua, pqz_key) = ua_msg(0x0142, pop, pop_digest(ua, key_hash(0x0142, pqz_key)))` |
| C ABI / C++ / Qt / FRB | regenerated: `scaas_ua.h` (header test), `scaas_ua.hpp`, the QML object, `flutter_rust_bridge_codegen generate` (drift check) |
| clientkeys | `ua.js` as `ua-rs`; the register flow builds `(pqzKey, pqzPop)` from the sealed PQZ leaf (`openPqKey`) and signs `pop` with the same `h`; `zether.js`: the bn254 path to legacy, Schnorr signing for UA-ledger purposes |
| `clients/zether-prover` | `authSig` / `authDigest` out of `api.rs` / `zether.rs` / `envelope.rs`; bn254 builds off (U10) |
| `pqz-core` | no code change (ids and the message are opaque); `smartcontracts/evm/script/pqz/e2e.py` and `pqz-core/nethermind/chain/e2e.py` register ML-DSA + PQZ key in one call |

**U15 — node.** No `scaas-node` source reads the registry today (`/v1/ua/register` and the UA record cache are
SPECIFIED, not built). Spec changes in `docs/node/gateway.md`: the route body becomes `{chain, kind, keyData, pop,
pqzKey?, pqzPop?}` (the node recomputes `h` and checks the PoP for cheap kinds over `popDigest(ua, h)`; it never
verifies `R_REG` locally — simulation does); the route's body limit rises from the gateway's 64 KiB to **160 KiB** (a
PQZL holder registration is ≈ 49 KB binary — 1,952 + 3,309 + 16,384 (20,608) + 28,091 — ≈ 100–108 KB as hex; PQZH proofs
of ≈ 187 KB register directly, not through the gateway); the record cache reads `recordOf → (Record, address pqzKey)`.
The node e2e suites (`tests/e2e.rs`) get a grep for the old selectors and are rerun where they touch UA flows.

**U16 — vectors.** `vectors/ua/kinds.json` (0x0140 out, 0x0142 to `schemes`, `authref` out of purposes, new holder /
`pqz_reg_message` rows), `structures.json` (PQ-eligible `msig` rows with the `pop` message), `signatures.json` /
`pq_signatures.json` / `groups.json` (`authRef` fields dropped — every one is zero today, so PoP bytes do not move; new
holder PoP rows over `h ≠ 0`; bn254 Zether rows to legacy), `metatx3.json` (a Zether-UA `UAMetaTransaction` row). PQZ
statement vectors unchanged (§4, §9); `pqz_kat.py` reruns as the check. Generators: clientkeys
`scripts/ua-vectors.mjs`, `scripts/ua-sig-vectors.mjs`; every library passes the same files.

**U17 — size gate.** `scripts/size_gate.py` on `UARegistry` (over EIP-170 since CTR-UA-29, 25,602 B; allowed on the test
chains' 64 KiB) and the Zether / PQZ token implementations and libraries; expected to shrink (`requireZetherAuthorized`,
the co-sign and the authRef checks go; the holder rule and one mapping come). No size work (owner: wait for
Glamsterdam); the baseline ratchets down where it shrinks.

**U18 — gas to measure** (forge, `--isolate`, logged in `smartcontracts/evm/runs/<date>-ua6-gas.txt`):

| Path | Expected |
|---|---|
| `register` `mldsa65`, no PQZ key | ≈ today (one empty-bytes decode) |
| `register` `mldsa65` + PQZ key vs today's `mldsa65` + `pqz-mlwe` registrations | lower: one transaction, no second record slot, no `_authRef` slot, no `authPop` ML-DSA verify, a pointer instead of a 16 KB event; plus the `0x0142` append |
| `register` PQ-eligible `msig` (2-of-3 ML-DSA) with and without PQZ key | new cost: the m-of-n PoP |
| `register` `zether-bls12381` | ≈ today |
| `requireAuthorized` on a Zether UA (Schnorr BLS12-381) | new path; one SSTORE2 read + the verifier |
| `zetherRollOverSigned`, `zetherSetRollOverMode` | ≈ today |
| `zetherTransfer` (M = 1, 4), `zetherUnshield` | lower: no registry auth call, `authSig` calldata gone |
| `pqzTransferSingle`, op 7 M = 4, `pqzUnshield` (mocked precompile) | slightly lower: `requireAuthorized` directly instead of `requireZetherAuthorized` → `_authorized(authRef)` |

**U19 — tests** (new or rewritten, names `test_UA6_*`): holder registration with and without key; strip / swap of the PQZ
key by a front-runner (`UAPoP`); `R_REG` over another UA's digest (`UAPoP`); the same PQZ key on two UAs, an `msig` and an
ML-DSA UA (`UAKeyInUse`); non-holders (`secp256k1`, `slhdsa128s`, Zether, classical-dominant `msig`) with a key
(`UAPqzHolder`); PQ-eligible `msig` without `pop` (`UAPoP`) and its squatting attempt; `pqzKey` where 0x0142 is
disabled (`UAKindDisabled`); gen-2 forwarding of `recordOf`'s pointer; `uaCount(0x0142)` order; Zether UA signs a
`UAMetaTransaction`, receives by `transferToUA`, is refused as an `msig` member; Zether spends with no `authSig`; owner
ops through `requireAuthorized`; PQZ transfer from an ML-DSA holder and an `msig` holder; a leg or auditor without a key
(`AccountNotRegistered`). The `authRef` suites (`ZetherAuthRef.t.sol`, the `authRef` parts of
`UARegistryZether.t.sol` / `UARegistryPq.t.sol`) go to `legacy/ua6/`.

**U20 — migration** (all chains test-only, owner; mainnet 22776 not launched): no compatibility path. The registry ABI,
the Zether entry points and every client change at once. SCaaS testnet: the new gen-1 registry (with `UAPqzVerifier` in
slot 0x0142 on the 16k id), the PQZ and Zether tokens and the e2e accounts are redeployed by
`smartcontracts/evm/script/pqz/e2e.py` in plan fs3 **Task 13** (back up, reset, deploy; controller may do this on the SCaaS testnet,
owner 2026-10-15). Other dev chains: `DeployBase` redeploys on their next reset. No record is carried over.

## 11. Owner questions (blocking only)

**Q1 — may a Zether UA sign every write?** CTR-UA-30 (2) and its Change line name three Schnorr-signed writes
(`zetherRollOverSigned`, `zetherSetRollOverMode`, `pop`) and put the public balance under the Zether id. Spending that
balance (and parity: trade, mandates, receiver fees) needs the Zether key to sign through `requireAuthorized` under every
purpose, which U8 proposes (SIGNING, not MEMBER). The alternative — Zether keys sign only the three writes, the public
side of a Zether account cannot be spent by it (unshield always to another UA) — keeps the key's use narrower but
contradicts "one identity for public and confidential balances". The registry code, `_checkTo`, the vectors and the
client sets depend on the answer. **Proposal: U8.**

No other question blocks the design: U3 (holder set), U5 (`msig` PoP), U9 (`authSig` removal), U10 (bn254 split) and
U15 (route limit) are controller proposals the owner may override after the fact.

## 12. Risks

- **Holder lock-out.** A PQ signer registered without its PQZ key can never get one (ids unchanged, record immutable):
  wallets must register both together; clientkeys refuses a holder-kind registration without a key unless asked.
- **Registration size.** A holder registration carries ≈ 49 KB (PQZL) to ≈ 210 KB (PQZH) of calldata in one
  transaction: fine on the SCaaS testnet (64 KiB code, 2^24 gas); the gateway limit (U15) and the PQZH path need care.
- **Hot Zether key now signs public writes** (U8): a leaked `x` already lost the confidential balance; the public
  balance under the same id goes with it. Accepted by CTR-UA-30's Change line; wallets show it.
- **Sybil decoys** (§7): without `authRef` groups nothing on chain ties decoys to one owner; the wallet rule and the
  node's registration quotas bound it.
