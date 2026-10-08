# EVM token tree: one base, kinds by code, features by flags

**Status:** DRAFT; owner decisions recorded (T1–T15). Provisional ids `TT-n`; real ids are allocated in
`docs/decisions.md` on acceptance.
**Date:** 2026-10-08. **Scope:** every EVM token contract, the factory, `OrderBookDex` deployment, the Zether token
layer, the account contracts' base. Replaces the **structural** part of stream MT-1 and re-orders streams MT-1…MT-9
(§9). Builds on the accepted meta-tx v3 design (`contracts/metatx.md`, `token-wrappers.md`, `dex.md`, `zether.md`);
every v3 rule not changed here stays. Non-EVM families: out of scope. Nothing is deployed, so the design changes in
place (no compatibility, no migration).

## 1. Why

The code still carries three generations side by side: the v1 line (`ERC20MetaTx` mixin, `MetaToken`,
`HederaMetaToken`, v1 `OpenFactory`, `MetaTxDex`), the v2 line (`MetaTxCore` → `MetaTokenBase` → No/Single/Multi +
three Hedera children) and `ZetherMetaTx` → `ZetherToken`. The v3 design exists only in the docs.

- **Three copies of the meta-tx base.** Nonce lanes, `nonReentrant`, `cancelMetaNonce`, the 9-step pipeline,
  `approve`/`transferFrom`, `_isContract` and the signature check are near-identical in `ERC20MetaTx`, `MetaTxCore`
  and `ZetherMetaTx`; init/provenance exists three times; the HIP-632 override four times; three more signature checks
  live in `OrderBookDex`, `MandateWallet`, `SubjectAccount`; `SigLib` has no importer.
- **No room.** Runtime sizes against EIP-170 (24,576 B): `ZetherToken` 28,939 (over), `HederaMultiUnderlyingToken`
  23,885, `MultiUnderlyingToken` 22,561, `SingleUnderlyingToken` 21,637. Streams MT-2…MT-5 and the regulated
  children (`*_REG`) still have to land in these contracts.
- **Duplicated product logic.** `ZetherToken` holds its own 1:1 underlying, wrap/unwrap and escrow check, i.e. a second
  tier 2. Single is Multi with one leg (Multi already inherits Single).
- **Features fixed by class.** A creator cannot pick "single underlying, payable off, confidential": every feature is
  either in the class or not.

## 2. Owner decisions (2026-10-08)

| # | Decision |
|---|---|
| T1 | Two axes. **Kind** = code (one implementation per large combination); **features** = flags chosen at creation. Heavy logic lives in external libraries linked at deploy |
| T2 | Every token can trade (`TradeOrder`, in the base). Pay (`IERC20Payment`: `mtxPay`, `payWithFee`, `payLane`, `PaymentSettled`) is gated by the flag `PAYABLE`, chosen at creation, **default off**, immutable; its code is `PayLib`. `MetaTransfer` is never gated |
| T3 | Hedera is a per-chain variant, not a creator's choice |
| T4 | Confidentiality is a layer over the public ERC-20 balance. Public balances stay normal. Ways in: from the public balance, or from the underlying straight into the shielded balance; ways out: to the public balance, or straight to the underlying. Zether keeps no underlying of its own; the reserve invariant counts the shielded supply |
| T5 | A minter never mints into a shielded balance |
| T6 | Explicit names with the layer prefix `zether…` / `pqz…` (§6.2). No registration function on any token: a UA registers once in the registry and is usable by every token of its curve |
| T7 | Implement v3. Delete the v1 line; the v2 code is material, not a design; no "v2" name survives |
| T8 | One common set of administration flags (§5), chosen at creation; per flag the creator chooses **locked** (exists forever) or **disableable** (the owner may clear it once, never set it again). One `owner` per token (0 = no administration) grants and revokes the roles, disables disableable flags, transfers or renounces ownership; role holders keep their roles after the owner renounces |
| T9 | Confidentiality per token: none / Zether (bn254 or BLS12-381, chosen at creation) / PQZ. Zether + PQZ on one token: room in the design (kind ids reserved), not built |
| T10 | Tree `MetaTxBase` → `ERC20MetaTx` → `MetaTokenBase` (trade, pay behind `PAYABLE`, flags, init) → kinds (§3) |
| T11 | The factory refuses `FREEZE`, `FORCE`, `PAUSE`, `ALLOWLIST` on a confidential kind (as today: confidential tokens are not regulated) |
| T12 | `OpenFactory` creates tokens **and** DEX instances and keeps a DEX registry (`isDex`). Tokens do **not** require a factory-made DEX ([CTR-DEX-19](../../contracts/dex.md#CTR-DEX-19) unchanged): that would give the factory admin too much power; `isDex` serves clients and the node |
| T13 | Single and Multi merge into one `UnderlyingToken` (1–8 legs); Hedera becomes an implementation constructor parameter (no Hedera child contracts) |
| T14 | The prover-only views move to a stateless `ZetherStatements` contract (pairs with `ZetherDisclosure`) |
| T15 | `SubjectAccount` is renamed **`SmartKeyAccount`** (and its factory): "smart" marks a contract account, "key" its many keys. Every chain family at once, in phase P4 |

## 3. Tree

```text
MetaTxBase (abstract)        MetaTransaction, nonce lanes, signature check (SigCheck), transient sender + ticket,
 │                           selector allowlist, mtxExecute / mtxBatch / cancelNonce — any SCaaS contract
 │                           (MandateWallet, SmartKeyAccount, third parties)
 └─ ERC20MetaTx (abstract)   ERC-20, MetaTransfer (entryRef), fee, receiver-pays, approve only by contracts, UA ledger
     └─ MetaTokenBase (abstract)
         │                   trade (TradeLib), pay behind PAYABLE (PayLib), features + roles (AdminLib),
         │                   init/provenance (factory, implementation, kind, version, IS_HEDERA)
         ├─ NoUnderlyingToken            kind NONE
         ├─ UnderlyingToken              kind UNDERLYING, 1–8 legs (UnderlyingLib)
         ├─ NoUnderlyingZetherToken      kind NONE_ZETHER        + ZetherLayer (ZetherLib)
         └─ UnderlyingZetherToken        kind UNDERLYING_ZETHER  + ZetherLayer, wrap-shield / unshield-unwrap
            reserved, not built: NONE_PQZ, UNDERLYING_PQZ, NONE_ZETHER_PQZ, UNDERLYING_ZETHER_PQZ (+ PqzLayer, PqzLib)
```

Outside the tokens, unchanged in role: the Zether verifiers (one per curve), `UniversalAccountRegistry`,
`ZetherDisclosure`, `ZetherStatements` (new, T14), `OpenFactory` (one factory), `OrderBookDex` (now a clone, §7).

- **Single + Multi (T13).** `UnderlyingToken` takes 1–8 legs at creation. The single-asset convenience ABI
  (`wrap(amount)`, `unwrap(amount, recipient[, minOut])`) works only when the token has exactly one leg
  (`UnderlyingRequired` otherwise); the per-leg ABI works for every count. The kind labels `META_SINGLE`/`META_MULTI`
  disappear: the leg count says it.
- **Hedera (T3, T13).** Each implementation is deployed with an immutable `IS_HEDERA`. When set, the signature check
  takes the HIP-632 path and `UnderlyingLib` associates HTS underlyings fail-closed (`HederaLib`). The Hedera children
  and their four copies of the override go; every implementation carries the ≈ 0.5–1 KB of Hedera branches.
- **Accounts.** `MandateWallet` and `SmartKeyAccount` sit on `MetaTxBase` (v3 CTR-ACC-06/07/10, stream P4).

## 4. Hot paths and libraries

Libraries are **external**, linked at deploy, called by `DELEGATECALL` (≈ 2.6 k gas on the first call of a
transaction, 100 after). Each library ≤ 24,576 B.

| Library | Content | Kinds |
|---|---|---|
| `TradeLib` | `TradeOrder` checks, `mtxTrade`, `mtxCancelOrder`, `mtxInvalidateNonces`, the token side of fills | all |
| `PayLib` | `mtxPay`, `payWithFee`, `payLane`, `PaymentSettled` | all (behind `PAYABLE`) |
| `AdminLib` | creation-time flag validation, roles, `disableFeature`, freeze / force / pause / allowlist functions | all |
| `UnderlyingLib` | legs; the core of wrap and unwrap **without a destination** (pull, rate, reserve; pay out); rate changes with timelock; `disableWrap`; the reserve invariant | `UNDERLYING*` |
| `ZetherLib` | statements, verifier calls, account updates, roll-over, shield / unshield, disclosure entries | `*_ZETHER` |
| `HederaLib` | HIP-632 signature path, HTS associate | all (branch on `IS_HEDERA`) |

Inline in the token, never behind a library: ERC-20 `transfer`/`transferFrom`, the core of a `MetaTransfer`, and the
per-transfer administration check (a bit test plus a mapping read — cheaper than a `DELEGATECALL`).

**Signature check.** One internal library `SigCheck` (ECDSA low-s, ERC-1271 with the gas cap rule, the HIP-632 hook)
is used by `MetaTxBase`, `OrderBookDex`, `MandateWallet`, `SmartKeyAccount`. `SigLib` is deleted.

**Storage.** Every module keeps its state in its own ERC-7201 namespace: `scaas.metatx`, `scaas.token` (features,
roles, kind, version), `scaas.trade`, `scaas.pay`, `scaas.admin`, `scaas.underlying`, `scaas.zether`. A library gets
its storage pointer from the fixed slot, so libraries never overlap.

**Size budget.** Each token implementation ≤ 20,480 B (≈ 4 KB left for later streams); CI fails the build when a
contract exceeds its budget (`forge build --sizes`).

## 5. Features

`features` and `lockedFeatures` are two immutable words written by `initialize`; `lockedFeatures ⊆ features`.

| Bit | Flag | Role | Valid kinds | Meaning |
|---|---|---|---|---|
| 0 | `PAYABLE` | — | all | `IERC20Payment` works; default off; immutable (no role) |
| 1 | `MINTABLE` | `minter` | `NONE*` | `mint` to a public balance (T5) |
| 2 | `BURNABLE` | — (holder) | `NONE*` | holder `burn` of its public balance |
| 3 | `RATE_ADJUSTABLE` | `rateAdmin` (contract) | `UNDERLYING*` | rate change with timelock; off ⇒ rates fixed at creation |
| 4 | `WRAP_DISABLEABLE` | `guardian` | `UNDERLYING*` | disable wrap per leg, one-way |
| 5 | `FREEZE` | `issuer` (contract) | non-confidential | as [CTR-AS-05](../../contracts/asset-suite.md) |
| 6 | `FORCE` | `issuer` + `compliance` | non-confidential | forced transfer on a recorded order (CTR-AS-04) |
| 7 | `PAUSE` | `issuer` | non-confidential | as CTR-AS-06 |
| 8 | `ALLOWLIST` | `compliance` | non-confidential | receivers checked against a `ComplianceRegistry` (CTR-AS-07) |

- **Administration: one `owner`.** Each token has one `owner` (0 at creation = no administration ever). Candidate
  implementation, decided in P1: OpenZeppelin `AccessControlDefaultAdminRules` (owner = default admin, delayed two-step
  transfer, renounce). The owner can: `grantRole(bit, account)` / `revokeRole(bit, account)` for the role of a flag set
  in `features` (a role may have several holders; the contract-only roles stay contract-only); `disableFeature(bit)`,
  one-way, only for a flag not in `lockedFeatures` (reverts `FeatureLocked(bit)`; `FeatureNotSet(bit)` when already
  clear); two-step `transferOwnership`; `renounceOwnership()`, after which the owner is 0 forever. After
  `renounceOwnership()` the existing role holders **keep** their roles; to make a token unchangeable the owner revokes
  every role, then renounces. A role holder performs the flag's actions (mint, rate change, freeze, …) and may
  `renounceRole(bit)` itself. The owner only administers: it acts on a flag only if it grants itself the role.
  `PAYABLE` and `BURNABLE` have no role and are therefore immutable. Events: `RoleGranted`/`RoleRevoked`,
  `FeatureDisabled(bit, by)`, the ownership events.
- **Validation in the token**, in `initialize` through `AdminLib` (the factory only forwards; `createTokenUnregistered`
  lets anyone bring an implementation, so the token is the one authority): each flag valid for the kind
  (`FeatureInvalidForKind(bit)`); `lockedFeatures ⊆ features` (`LockedNotSubset()`); a role holder in `roles` only for a
  set flag (`RoleWithoutFeature(bit)`); contract-only roles are contracts. Roles may also be granted later by the owner.
- **Views:** `features()`, `lockedFeatures()`, `owner()`, `hasRole(bit, account)`, `kind()`, `version()`. `supportsInterface(IERC20Payment)` is
  true iff `PAYABLE` is set.
- **Regulated kinds 5–7 are superseded.** The four controls of `RegulatedControls` become flags 5–8 on the ordinary
  kinds; their rules (caps, cooldowns, orders, receiver-only allowlist, the shape-step plus `_update` check) are
  unchanged and move to `AdminLib`. A token with none of the flags is fully permissionless.

## 6. Confidential layer

### 6.1 Structure

`ZetherLayer` (abstract, in the token) holds the ERC-7201 `scaas.zether` storage (per-UA `acc`/`pending`, counters,
`totalShielded`, disclosure entries) and the external stubs of §6.2; the logic is `ZetherLib`. The verifier (curve) and
the auditor key are chosen at creation and immutable; the registry address is an implementation immutable; the
dev-chain gate `ZetherSafety` stays. `ZetherStatements` (stateless) serves the prover views
(`transferStatement*`, `unshieldStatement`) from the token's `accountState`; `ZetherDisclosure` stays as built (Z13).
All rules of the multi-recipient draft (Z1–Z13) carry over unchanged except the names below.

### 6.2 Entry points

`shieldScale` = public units per shielded unit (shielded amounts are bounded by `2^54`).

| Function | Effect |
|---|---|
| `zetherShield(ua, amount)` | `_burn(sender, amount·shieldScale)` from the public balance; `pending[ua] += [amount]G` |
| `zetherWrapShield(u, amountIn, ua)` | `UnderlyingLib` pulls `amountIn` of leg `u` and computes the public-equivalent `minted` at the leg's rate **without minting**; `minted % shieldScale ≠ 0` ⇒ `AmountNotScaled` (the client sends an exact amount); `pending[ua] += [minted / shieldScale]G` |
| `zetherTransfer` (HASH), `zetherTransferBundle`, `zetherTransferNoBundle`, `zetherTransferSingle` | as `transferConfidential*` of the multi-recipient draft |
| `zetherUnshield(payload, proof, authSig, beneficiary, to, amount)` | proof as today's `burn`; `_mint(to, amount·shieldScale)` |
| `zetherUnshieldUnwrap(payload, proof, authSig, beneficiary, u, recipient, amount, minOut)` | the same proof; `UnderlyingLib` pays leg `u` for `amount·shieldScale` public-equivalent units, bounded by `minOut`, nothing minted |
| `zetherRollOver`, `zetherRollOverBatch`, `zetherSetRollOverMode`, `zetherRollOverSigned` | as today's roll-over functions |

`NONE_ZETHER` has `zetherShield` / `zetherUnshield` only. Events follow the names (`ZetherShielded`,
`ZetherUnshielded`, `ZetherTransfer`, `ZetherTransferMulti`, …). PQZ mirrors the table with `pqz…` names when built.
There is no `zetherRegister` / `pqzRegister` (T6): the registry's `register` must be relayable, which the accepted
registry design already provides (PoP over `popDigest(ua, authRef)`, anyone submits; [accounts.md](../../contracts/accounts.md));
the confidential kinds depend on that registry for gasless onboarding.

### 6.3 Invariants and fees

- `UNDERLYING_ZETHER`: `Σ_i ⌊reserve_i·num_i/den_i⌋ ≥ totalSupply() + totalShielded·shieldScale`, checked after every
  operation that moves value out. `totalSupply()` counts public balances only (ERC-20 meaning); `totalShielded()` is a
  separate view.
- The inner confidential fee (fixed per token, credited to the beneficiary UA) stays in `ZetherLib`. Relaying goes
  through the base: Zether entry points are allowlisted self-calls of `mtxExecute` (v3, MT-6); `ZetherMetaTx` and the
  `_executeOp` / `relayed*` envelope go.
- Flags valid on confidential kinds: `PAYABLE`; `MINTABLE`/`BURNABLE` (`NONE_ZETHER`); `RATE_ADJUSTABLE`/
  `WRAP_DISABLEABLE` (`UNDERLYING_ZETHER`). Flags 5–8 are refused (T11).

### 6.4 Removed from today's `ZetherToken`

Its own underlying and `wrap`/`unwrap`/`fund`, `_checkEscrow`, `ZetherMetaTx` and the envelope, the v1
`IFactoryToken` init, the name `burn`, the prover views (to `ZetherStatements`).

## 7. Factory and DEX

```solidity
function createToken(TokenKind kind, uint64 version, TokenConfig calldata cfg, bytes32 salt) external returns (address);
function createTokenUnregistered(TokenKind kind, address implementation, TokenConfig calldata cfg, bytes32 salt) external returns (address);
function createDex(uint64 version, DexConfig calldata cfg, bytes32 salt) external returns (address);

struct TokenConfig {
    string name; string symbol; uint8 decimals;
    uint256 features; uint256 lockedFeatures;
    address owner;                             // 0 = no administration ever
    Roles roles;                               // initial holders (optional, each only for a set flag): minter, rateAdmin, guardian, issuer, compliance
    uint256 initialSupply; address initialHolder;   // NONE* only
    Leg[] legs;                                // underlying, num, den — UNDERLYING* only, 1..8
    RateConfig rate;                           // with RATE_ADJUSTABLE
    ConfidentialConfig conf;                   // verifier, auditorKey (empty = no auditor), shieldScale — *_ZETHER only
}
struct DexConfig { address admin; uint32 relayerSharePpm; address treasury; bool listedOnly; }
```

- **Creation (unchanged pattern).** `CREATE2` of an EIP-1167 clone, then `initialize(cfg)` **in the same call** (no
  front-run of `initialize`, no deployed-but-uninitialized state); the implementation locks its own `initialize` in
  its constructor. The address is predictable from `(factory, salt, implementation)`.
- **Kinds** (fresh enum, nothing deployed): `NONE`, `UNDERLYING`, `NONE_ZETHER`, `UNDERLYING_ZETHER`; reserved
  `NONE_PQZ`, `UNDERLYING_PQZ`, `NONE_ZETHER_PQZ`, `UNDERLYING_ZETHER_PQZ`. The implementation registry keeps
  versions per kind (register, deprecate) as today.
- **One event per creation:** `TokenCreated(token, creator, kind, version, implementation, features, lockedFeatures,
  owner, underlyings)`; `DexCreated(dex, creator, version, implementation, admin)`.
- **DEX as a clone.** `OrderBookDex` moves `admin` from an immutable to storage written once by `initialize` (same
  behaviour: no setter); its `DexPuller` is deployed by `initialize`; the EIP-712 `verifyingContract` is the clone.
- **Registry views:** `isToken(addr)`, `isDex(addr)`, `versionOf(addr)`. `isDex` is advisory (T12): clients and the
  node use it, together with the implementation version, to warn about or refuse an unlisted `dex`; tokens do not
  consult it.
- `IFactoryToken`, `IFactoryTokenV2`, `IOpenFactory`, `IOpenFactoryV2` are replaced by one `IOpenFactory` and one
  `IFactoryToken`.

## 8. Deleted

`ERC20MetaTx` (v1 mixin), `MetaToken`, `HederaMetaToken`, v1 `OpenFactory`, `MetaTxDex`, `MetaTxCore` (absorbed into
`MetaTxBase`/`ERC20MetaTx`), `ZetherMetaTx`, `ZetherToken` (replaced by the two `*_ZETHER` kinds),
`SingleUnderlyingToken` and `MultiUnderlyingToken` (merged), `HederaNo/Single/MultiUnderlyingToken`, `SigLib`, the
revert-only overrides of Multi, the hand-decoded `mtxUnwrapWithFee` fallback (gasless unwrap is `mtxExecute(unwrap)`,
v3 CTR-MTX-12), `OpenFactoryV2.createMetaToken`, the regulated children (`Regulated*`, `HederaRegulated*`, kinds 5–7),
`MAX_LEGS` duplicates (one constant in `UnderlyingLib`).

## 9. Phases

| Phase | Content | Streams |
|---|---|---|
| P0 | This spec; fold into `metatx.md`, `token-wrappers.md`, `asset-suite.md` (regulated as flags), `dex.md` (factory, DEX registry), `zether.md` (layer, names), the factory section, `decisions.md` | — |
| P1 | The complete base (`MetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`; both structs, allowlist, ticket; approve rule; `salt = chain_uid`; CREATE2 deployer); kinds `NONE`, `UNDERLYING` with `AdminLib`, `PayLib`, `UnderlyingLib`, `HederaLib`, `SigCheck`; factory `createToken`; delete §8 items of the v1/v2 lines | MT-1, MT-2, MT-3, MT-4 |
| P2 | `TradeLib`; `OrderBookDex` as a clone; `createDex`, DEX registry | MT-5 |
| P3 | `*_ZETHER` kinds: `ZetherLayer`, `ZetherLib`, `ZetherStatements`, shield / unshield paths; delete `ZetherToken` | MT-6 |
| P4 | `MandateWallet`, `SmartKeyAccount` (rename, every family) on `MetaTxBase` | MT-7 (+ rename in NM-*) |
| P5 | Node, clientkeys, encoders for the new ABI | MT-8, MT-9 |

MT-2 and MT-4 join P1 because the base is rewritten anyway; landing them later would rewrite it twice. Every phase
ends with the size gate of §4 and the full forge suite.

## 10. Testing

Per kind × flag set: creation validation (every invalid combination of §5 reverts with its error), `disableFeature`
(locked, disableable; owner grant/revoke, holder renounce, renounceOwnership keeps holders' roles), pay on/off, mint/burn on/off, rate fixed vs adjustable, guardian, the four
regulated flags (existing asset-suite cases moved onto the ordinary kinds), Hedera branch under `IS_HEDERA`, the reserve
invariant with shielded supply (fuzz: wrap, wrap-shield, unshield, unshield-unwrap never break it), library storage
isolation (a write through one library never changes another namespace), the size gate, and the cross-language
vectors of the meta-tx and Zether formats regenerated per phase.

## 11. Revision history

| Rev | Date | What |
|---|---|---|
| 1 | 2026-10-08 | First draft from the owner's chat decisions T1–T15 |
| 2 | 2026-10-08 | T8: one owner grants/revokes roles, disables disableable flags, renounces ownership; role holders keep roles after renounce |
