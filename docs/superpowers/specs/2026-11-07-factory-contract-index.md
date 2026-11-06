# `OpenFactory`: an on-chain index of every contract it creates (draft for the owner)

**Status:** DRAFT, SPECIFIED, not approved. Nothing is built; the plan tasks T67–T69 of
[`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md) are **not started until the owner approves this spec**.
**Place (owner 2026-11-07):** after 3g (T51–T57), before 3f: work order 3e → 3g → factory index → 3f → 3h → 3c. Branch
`ua-mtx-merge`.

**Owner, 2026-11-07:** an owner or creator must be able to list the contracts they made (for example the owner creates many
gift-card tokens and needs their list) from contract **state**, not from events ("không lọc event, vì mất": logs and history
expire); every contract the factory creates, not only tokens, with a class a caller can filter on; who created it and when.

## 1. What the factory creates today (read at `HEAD`, `src/factory/OpenFactory.sol`)

| Path | What | Recorded today |
|---|---|---|
| `createToken` / `createTokenUnregistered` → `_create` | EIP-1167 clone of a `TokenKind` release (0–5, 8–13; version 0 for unregistered) | `_info[token] = {creator, kind, version, exists}`; per leg `_wrappers[creator][underlying]`, `_byUnderlying[underlying]` |
| `createDex` | EIP-1167 clone of a DEX release | `_dexVersion[dex]` |
| `deployImplementation` / `deployDexImplementation` → `_deploy` | the releases, by the registrar | the catalogue `_releases[kind][version]`, `_dexReleases[version]` (already state, enumerable by version) |

Nothing lists the tokens or DEXes of an owner or a creator: `TokenCreated` / `DexCreated` carry `owner` (`bytes32` UA id) and
`creator`, and a log is all there is.

**Out of scope:** contracts the factory does not create — `UARegistry`, `GovernanceRouter`, `MtxRelayFee` and its executor,
`SmartKeyAccountFactory` and its accounts, the deterministic deployer — and contracts a clone creates itself (the
`DexPuller` deployed by the DEX's `initialize`, reachable as `puller()` on the DEX). The releases stay in the catalogue (§6 Q3).

## 2. The rule (proposed CTR-TOK-27; `docs_check.py` confirms the id is next-free)

`OpenFactory` keeps, in its own state, one record per contract it clones and three append-only lists per **class**: all,
by owner UA at creation, by creator. The index is written in the creating call, never changed, never deleted. One rule on
every chain: a factory of another family carries the same index when it is built (no family has a factory today).

### 2.1 Record

```solidity
uint8 public constant CLASS_TOKEN = 1;   // kind = TokenKind
uint8 public constant CLASS_DEX = 2;     // kind = 0
// 0 = not made here; 3..255 for the classes a later factory version creates (a new catalogue entry, never an upgrade)

struct Created {
    address addr;          // the clone
    address creator;       // msg.sender of the creating call
    bytes32 ownerUA;       // owner() of the clone right after initialize (a UA id; 0 = no administration ever)
    uint8 contractClass;   // CLASS_TOKEN, CLASS_DEX
    uint8 kind;            // TokenKind for a token, 0 for a DEX: the class-specific id
    uint64 version;        // the release version (0 = createTokenUnregistered)
    uint64 createdBlock;   // block.number
    uint64 createdAt;      // block.timestamp
}
```

Stored as three slots per address (`addr` is the key): `creator ‖ contractClass ‖ kind ‖ version`, `ownerUA`,
`createdBlock ‖ createdAt`. The record **replaces** `_info` and `_dexVersion` (one source); the existing views keep their
answers exactly (`isToken`, `isRegisteredToken`, `creatorOf`, `versionOf` for class TOKEN only, so `creatorOf(dex)` stays 0;
`isDex`, `dexVersionOf` for class DEX), and `SaltAlreadyUsed` checks `contractClass != 0`. `_wrappers` and `_byUnderlying`
are unchanged.

`ownerUA` is the value the creating call already reads for `TokenCreated` / `DexCreated` (one `owner()` call, used twice).
`createdBlock` is whatever the chain returns (no assumption about block time or Hedera's record numbering); `createdAt` is the
reference time.

### 2.2 Lists and views

```solidity
mapping(uint8 => address[]) _all;                                   // per class
mapping(bytes32 => mapping(uint8 => address[])) _byOwner;           // ownerUA at creation, per class; never for ownerUA 0
mapping(address => mapping(uint8 => address[])) _byCreator;         // per class

uint256 public constant MAX_PAGE = 100;
function infoOf(address c) external view returns (Created memory);                     // contractClass 0: not made here
function contractsPage(uint8 contractClass, uint256 from, uint256 n)
    external view returns (Created[] memory page, uint256 total);
function contractsOfOwner(bytes32 ownerUA, uint8 contractClass, uint256 from, uint256 n)
    external view returns (Created[] memory page, uint256 total);
function contractsOfCreator(address creator, uint8 contractClass, uint256 from, uint256 n)
    external view returns (Created[] memory page, uint256 total);
error ClassUnknown(uint8 contractClass);   // 0 or a class this factory does not create
error PageTooLarge(uint256 n);             // n > MAX_PAGE
```

- **Order:** creation order, oldest first; the newest page is `from = total − n`. `from ≥ total` returns an empty page and
  `total`; `n = 0` returns only `total` (this is `contractCount`: no separate count or `contractAt` view).
- **Filter by class** is the list key: a caller lists one class per call; "all classes" is one call per class (two today).
  Filtering by kind (gift cards of `NORMAL` only, say) is the caller's, on the returned `kind`.
- **Write order** in `_create` / `createDex`: as today the clone and `initialize`, then the record and the three pushes, then
  the event. A creation nested inside an unregistered implementation's `initialize` is appended first; nothing assumes
  otherwise.

### 2.3 What the lists mean

- **By creator** is authenticated: `msg.sender` made it. A creation submitted by a relayer, a backend or a smart account is
  listed under that sender, not under the customer.
- **By owner** is a claim, not consent: any creator may name any UA as `owner` in `TokenConfig` / `DexConfig`, and an
  unregistered implementation's `owner()` returns what its code likes. Anyone can therefore append to a UA's owner list
  (spam, look-alike gift cards). It costs the victim nothing (reads are paged) and every entry carries `creator` and
  `version`: a wallet shows `version ≠ 0` (registered) entries, and the creator, by default.
- **Owner at creation, not now:** ownership moves (`transferOwnership` / `acceptOwnership`, CTR-GOV). The index keeps the owner
  at creation; the current owner is each contract's own `owner()`. A client lists by owner at creation and checks `owner()` per
  entry. A contract handed to a UA later is not in that UA's list. Listing by **current** owner on-chain needs a hook from every
  governed contract's ownership change into the factory: code in the twelve kinds and the DEX, a cross-contract call on that
  path, a new trust edge (the factory trusting a clone's call). **Recommendation: not now** (§6 Q2).

## 3. Gas, on paper (EIP-8037, ≈97,920 state gas per new slot = 64 B × 1,530)

Per creation, against today:

| Slots | Steady state | First of the class for that owner and creator |
|---|---|---|
| record: 3 instead of 1 (`_info` or `_dexVersion`) | +2 | +2 |
| element of `_all`, `_byOwner`, `_byCreator` | +3 | +3 |
| length of `_byOwner[ua][class]`, `_byCreator[addr][class]` (new key) | 0 | +2 |
| **new slots** | **+5 → ≈ +489,600 state gas** | **+7 → ≈ +685,440** |

`ownerUA = 0` skips the owner push (−1 element, −1 length). The first creation of a class on a factory adds one `_all` length
slot once. Regular gas: about +25–40 k (the SSTOREs' regular share, three cold list lengths); no added external call. Measured
in T67 by `GovGas`'s `createToken` row and a new `createDex` row, old → new. The creating transaction stays far below any block
limit (inclusion is regular + state, EIP-8037).

## 4. Size, layout, formats

- **Size:** `OpenFactory` runtime 15,821 B in the current local build; the record and three paged struct views add an
  estimated 2.5–4 KB, far below the 64 KiB ceiling (EIP-7954, Glamsterdam mandatory on every chain that runs these
  contracts) and the repo's 64,512 B stop line. T67 records old → new in the size-gate ratchet (`size-baseline.json`),
  adding an `OpenFactory` row if it is not tracked.
- **Layout pins:** none. `test/v2/layout/` pins the ERC-7201 namespaces of clones; the factory is not a proxy, is never
  upgraded and is never a DELEGATECALL target, so its sequential layout protects nothing. Its slot use is pinned by T67's
  slot-count test instead.
- **Formats:** `TokenCreated`, `DexCreated`, `TokenConfig`, `DexConfig`, every typehash and selector of a token or the DEX
  unchanged. No vector, `clientkeys` or `ua-*` change. A new factory init code moves the factory's deterministic address in the
  deploy JSONs (`DeployBase`, Hedera, `script/pqz/e2e.py`), regenerated at the SCaaS testnet reset; T68 checks that no KAT holds
  it.
- **Nothing deployed is upgraded:** a new `OpenFactory` build for the reset chain (all chains are test-only). After mainnet a
  further class is a new factory version.
- **Relayable:** the creation entries have no signature and no `mtx*` form; anyone submits them, a relayer included. The index
  adds no entry that changes state.

## 5. Node

The state is authoritative. The indexer may mirror the index (reading `TokenCreated` / `DexCreated` and backfilling with the
paged views after history expiry); a mirror is a cache, never the source. Nothing is built in the node by this spec
(`indexer-feeds.md` gains one PLANNED line, T69). The node's uses of the factory (`isRegisteredToken`, `isDex`, `config.rs`'s
`factory`) are unchanged.

## 6. Questions for the owner (each with a recommendation)

1. **The owner list is a claim** (§2.3): anyone may name any UA as owner. **Recommend:** accept; wallets show registered
   entries and the creator by default. A consent step (the owner UA signing the creation) is a separate signed creation path,
   only if spam proves real.
2. **Current owner on-chain** (a hook on every ownership change). **Recommend:** not now; owner at creation plus `owner()` per
   entry.
3. **Releases in the index** (the implementations `deployImplementation` creates). **Recommend:** no; the catalogue already
   holds them in state, enumerable by kind and version `1..latestVersion`.
4. **`ownerUA = 0`** (no administration ever): **Recommend:** recorded, not pushed to an owner list (it would be everyone's).
5. **Lists per class only**, no unfiltered owner or creator list: **Recommend:** yes; saves two slots (≈195,840 state gas) per
   creation; "all" is one call per class.
6. **Unregistered tokens (version 0)** in the index: **Recommend:** yes, the factory made them; one rule, flagged by `version`.

## 7. Tests (T67, T68)

- **Every class and kind:** a token of each kind (0–5 and the regulated 8–13 built in T24–T36, each release published and the kind enabled), a
  `createTokenUnregistered` token (version 0), a DEX; `infoOf` returns every field; the old views give their old answers.
- **Creator ≠ owner:** created by a relayer EOA and by a contract caller naming a derived UA (non-native id) as owner: the
  owner list holds it, the creator list holds it under the relayer, `infoOf.creator` is the relayer.
- **Paging bounds:** `n = 0`, `n = MAX_PAGE`, `MAX_PAGE + 1` (`PageTooLarge`), the last partial page, `from = total`,
  `from > total`, class 0 and 3 (`ClassUnknown`), a page across both classes for one owner returning only the class asked.
- **Negatives:** `SaltAlreadyUsed` on the record; `ownerUA = 0` not listed; owner moved after creation: the index keeps the
  creation owner, `owner()` the new one; an unregistered implementation claiming a victim's UA is listed with `version 0` and
  its creator; a nested creation from `initialize` appends in order without corrupting either record; `owner()` reverting
  reverts the creation (as today).
- **Slot count:** `vm.record` / `vm.accesses` over a creation: +5 new slots steady, +7 first, as §3.
- **Mutants (T68):** the owner push dropped; the creator push keyed by `tx.origin`; `ownerUA` read before `initialize`; class
  swapped; `from` / `n` off by one; the zero-owner skip removed; the record written before the salt check; `creatorOf(dex)`
  answering non-zero.
