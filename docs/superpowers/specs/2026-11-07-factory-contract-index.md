# `OpenFactory`: an on-chain index of every contract it creates 

**Status:** **Built (T19, 2026-11-10):** the index (§1–§7, T67 `658f684f`) and the extensible catalogue (§8, T70) are BUILT on branch `ua-mtx-merge`, UNAUDITED; rules CTR-TOK-27, CTR-TOK-28. SPECIFIED, **revised 2026-11-07**. The index (§1–§7) is **approved by the owner 2026-11-07** (the six questions
of §6 answered as recommended). The **extension** (§8, an extensible catalogue: generic classes and kinds, `createInstance`,
`PqChat` as class 3) is **approved by the owner 2026-11-07** (direction first, then Q7–Q12 of §8.11 answered as
recommended, among them the one change to the approved index: Q12, class and kind ids `uint16`, written into §2 below).
Nothing is built yet; the plan tasks T67–T70 of [`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md) start after 3g (T57).
**Place (owner 2026-11-07):** after 3g (T51–T57), before 3f: work order 3e → 3g → factory index + chain-neutral → 3f → 3h → T66b → 3c. Branch
`ua-mtx-merge`.
**Same addresses on every chain (owner decisions A and B, 2026-11-07):** CREATE3 on every creation path, chain-neutral
releases, the chain values written into each instance by the factory: spec
[`2026-11-07-chain-neutral-releases.md`](2026-11-07-chain-neutral-releases.md) (approved by the owner 2026-11-07, option I:
each instance's `ChainEnv` appended to its clone code, read by `EXTCODECOPY`; Fable review applied). It changes this spec's creation salt and `predictAddress` (§8.4 step 3) and the release constructor (§8.2,
§8.8); those details live there. **S3 answered "the signing UA" (owner 2026-11-07):** the creator is a `bytes32 creatorId`
(chain-neutral spec §4.4), written into §2.1, §2.2, §2.3 and §8.4 below; the record stays three slots.

**Owner, 2026-11-07:** an owner or creator must be able to list the contracts they made (for example the owner creates many
gift-card tokens and needs their list) from contract **state**, not from events ("không lọc event, vì mất": logs and history
expire); every contract the factory creates, not only tokens, with a class a caller can filter on; who created it and when.

## 1. What the factory creates today (read at `HEAD`, `src/factory/OpenFactory.sol`)

| Path | What | Recorded today |
|---|---|---|
| `createToken` / `createTokenUnregistered` → `_create` | EIP-1167 clone of a `TokenKind` release (0–5, 8–13; version 0 for unregistered) | `_info[token] = {creator, kind, version, exists}`; per leg `_wrappers[creator][underlying]`, `_byUnderlying[underlying]` |
| `createDex` | EIP-1167 clone of a DEX release | `_dexVersion[dex]` |
| `deployTokenImplementation` / `deployDexImplementation` → `_deploy` | the releases, by the registrar | the catalogue `_releases[kind][version]`, `_dexReleases[version]` (already state, enumerable by version) |

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
uint16 public constant CLASS_TOKEN = 1;  // kind = TokenKind
uint16 public constant CLASS_DEX = 2;    // kind = 0
// 0 = not made here; 3..65535 are generic classes, registered by the registrar without a factory change (§8);
// 3 = PqChat (§8.8)

struct Created {
    address addr;          // the clone
    bytes32 creatorId;     // the creator's UA id (S3, chain-neutral spec §4.4): pad(msg.sender) on a direct call,
                           // the router's verified subject() on a signed creation
    bytes32 ownerUA;       // owner() of the clone right after initialize (a generic class: factoryInfo().ownerUA, §8.4)
                           // (a UA id; 0 = no administration ever)
    uint16 contractClass;  // CLASS_TOKEN, CLASS_DEX, a generic class (revision Q12: was uint8)
    uint16 kind;           // TokenKind for a token, 0 for a DEX, the class's own id for a generic class (was uint8)
    uint64 version;        // the release version (0 = createTokenUnregistered)
    uint64 createdBlock;   // block.number
    uint64 createdAt;      // block.timestamp
}
```

Stored as three slots per address (`addr` is the key): `creatorId`, `ownerUA`,
`contractClass ‖ kind ‖ version ‖ createdBlock ‖ createdAt` (2 + 2 + 8 + 8 + 8 = 28 B, one slot with the `uint16` ids). The record **replaces** `_info` and `_dexVersion` (one source); the existing views keep their
answers exactly (`isToken`, `isRegisteredToken`, `creatorOf` (the address for a native `creatorId`, 0 for a derived one),
`versionOf` for class TOKEN only, so `creatorOf(dex)` stays 0;
`isDex`, `dexVersionOf` for class DEX), and `SaltAlreadyUsed` checks `contractClass != 0`. `_wrappers` and `_byUnderlying`
are keyed by `bytes32 creatorId` (S3).

`ownerUA` is the value the creating call already reads for `TokenCreated` / `DexCreated` (one `owner()` call, used twice).
`createdBlock` is whatever the chain returns (no assumption about block time or Hedera's record numbering); `createdAt` is the
reference time.

### 2.2 Lists and views

```solidity
mapping(uint16 => address[]) _all;                                  // per class
mapping(bytes32 => mapping(uint16 => address[])) _byOwner;          // ownerUA at creation, per class; never for ownerUA 0
mapping(bytes32 => mapping(uint16 => address[])) _byCreator;        // creatorId, per class (S3)

uint256 public constant MAX_PAGE = 100;
function infoOf(address c) external view returns (Created memory);                     // contractClass 0: not made here
function contractsPage(uint16 contractClass, uint256 from, uint256 n)
    external view returns (Created[] memory page, uint256 total);
function contractsOfOwner(bytes32 ownerUA, uint16 contractClass, uint256 from, uint256 n)
    external view returns (Created[] memory page, uint256 total);
function contractsOfCreator(bytes32 creatorId, uint16 contractClass, uint256 from, uint256 n)
    external view returns (Created[] memory page, uint256 total);
error ClassUnknown(uint16 contractClass);  // 0, or a generic class with no release yet (§8.2)
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

- **By creator** is authenticated: `pad(msg.sender)` on a direct call, or the UA that signed a creation the chain's
  `GovernanceRouter` verified (`mtxCreateToken` / `mtxCreateDex` / `mtxCreateInstance`, S3, chain-neutral spec §4.4, T76). A
  direct creation submitted by a relayer, a backend or a smart account is listed under that sender; a signed one under the
  customer's UA.
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
- **Formats:** the index itself moves no format of a token or the DEX (`TokenCreated`, `DexCreated`, `TokenConfig`,
  `DexConfig`, typehashes, selectors); the chain-neutral spec's S3 and CREATE3 changes move some, listed there. No vector, `clientkeys` or `ua-*` change. A new factory init code moves the factory's deterministic address in the
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

**Owner 2026-11-07: all six answered as recommended:** (1) the owner list stays a claim, wallets filter on `version ≠ 0`
and show the creator; (2) no list by current owner now; (3) releases are not indexed; (4) `ownerUA = 0` stays out of the
owner lists; (5) lists per class only; (6) unregistered contracts are indexed, flagged by `version`.

1. **The owner list is a claim** (§2.3): anyone may name any UA as owner. **Recommend:** accept; wallets show registered
   entries and the creator by default. A consent step (the owner UA signing the creation) is a separate signed creation path,
   only if spam proves real.
2. **Current owner on-chain** (a hook on every ownership change). **Recommend:** not now; owner at creation plus `owner()` per
   entry.
3. **Releases in the index** (the implementations `deployTokenImplementation` creates). **Recommend:** no; the catalogue already
   holds them in state, enumerable by kind and version `1..latestVersion`.
4. **`ownerUA = 0`** (no administration ever): **Recommend:** recorded, not pushed to an owner list (it would be everyone's).
5. **Lists per class only**, no unfiltered owner or creator list: **Recommend:** yes; saves two slots (≈195,840 state gas) per
   creation; "all" is one call per class.
6. **Unregistered tokens (version 0)** in the index: **Recommend:** yes, the factory made them; one rule, flagged by `version`.

## 7. Tests (T67, T68)

- **Every class and kind:** a token of each kind (0–5 and the regulated 8–13 built in T24–T36, each release published and the kind enabled), a
  `createTokenUnregistered` token (version 0), a DEX; `infoOf` returns every field; the old views give their old answers.
- **Creator ≠ owner:** created by a relayer EOA and by a contract caller naming a derived UA (non-native id) as owner: the
  owner list holds it, the creator list holds it under the relayer, `infoOf.creatorId` is `pad(relayer)`; a signed router creation (T76) lists under the signing UA.
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

## 8. Extension: an extensible catalogue (direction approved by the owner 2026-11-07)

**Owner, 2026-11-07:** "OpenFactory must be built so that later the admin can easily add another kind / implementation."
Same day: `PqChat` becomes a factory-made contract (anyone creates instances, as tokens and DEXes; EIP-1167 clones of
catalogued releases). **Direction approved by the owner 2026-11-07:** a generic class / kind catalogue registered by the
registrar under the existing notice period; one generic creation entry calling the release's catalogued, typed initializer
and reading back `factoryInfo()`; the token and DEX entries kept; `PqChat` the first generic class (id 3); the acceptance
test adds a kind end to end without changing factory code. Proposed rule **CTR-TOK-28** (`docs_check.py resolve` reports the
id unknown, so it is free; it lands with T69).

**What it means.** Adding a kind or a whole class = the registrar publishes an env, deploys a release from init code, and
enables the kind after the notice period. No factory code, no factory version, no upgrade: the factory is deployed once per
chain and stays immutable ([CTR-GEN-02](../../contracts/README.md#CTR-GEN-02)); what grows is its append-only catalogue, as
token versions grow today. One rule on every chain: class and kind ids are the same on every family; a factory of another
family, when one is built, carries the same catalogue.

### 8.1 Ids

| Class | Name | Kinds | Creation entry |
|---|---|---|---|
| 0 | not made here | | |
| 1 | `TOKEN` | `TokenKind` 0–5, 8–13 (compiled enum, CTR-TOK-25) | `createToken`, `createTokenUnregistered` (unchanged) |
| 2 | `DEX` | 0 | `createDex` (unchanged) |
| 3 | `PQCHAT` | 0 = `PqChat` | `createInstance` (§8.4) |
| 4–65535 | assigned by the registrar, next free | 0–65535, per class | `createInstance` |

Classes 1 and 2 keep their typed paths and are refused on the generic entries (`ClassReserved`). For a generic class the
chain is the authority: `classes()` and `kindsOf(class)` list what has a release, in order of first release; the names live in
the CTR-TOK-28 table in `docs/contracts/token-wrappers.md`. A generic class exists once its first release is deployed: until
then the index views answer `ClassUnknown` for it (§2.2). The factory holds no constant for class 3 or later.

### 8.2 Catalogue (registrar only, `onlyRegistrar` as today: `NotRegistrar`, `CallerDelegated`)

```solidity
struct ReleaseId { uint16 contractClass; uint16 kind; uint64 version; }   // version from 1
struct ClassRelease {
    address implementation;
    uint16 envVersion;
    bytes32 envHash;
    uint64 usableFrom;      // deployment + noticePeriod, as Release
    bool deprecated;        // immediate, never undone, as Release
    bytes4 initSelector;    // the only call createInstance makes on a fresh clone
    bytes4 interfaceId;     // the class's ERC-165 interface id the implementation answers true
}
/// What every generic release and each of its clones answers (§8.5). Seven static words, 224 B.
struct FactoryInfo {
    address factory; bytes32 chainUid; uint16 contractClass; uint16 kind; uint64 version;
    bytes32 ownerUA;        // the clone's owner UA after initialize; 0 on the implementation
    bool initialized;       // true on the implementation (locked by its constructor) and on a clone after initialize
}

function publishClassEnv(uint16 contractClass, uint16 kind, uint16 envVersion, IFactoryToken.Env calldata env) external;
function deployImplementation(ReleaseId calldata id, uint16 envVersion, bytes4 initSelector, bytes4 interfaceId,
    bytes calldata initcode, bytes calldata implArgs) external returns (address implementation);
function deprecateRelease(ReleaseId calldata id, string calldata reason) external;
function setClassKindEnabled(uint16 contractClass, uint16 kind, bool on) external;

function classEnvOf(uint16 contractClass, uint16 kind, uint16 envVersion) external view returns (IFactoryToken.Env memory);
function latestClassEnvVersion(uint16 contractClass, uint16 kind) external view returns (uint16);
function classReleaseOf(ReleaseId calldata id) external view returns (ClassRelease memory);
function latestClassVersion(uint16 contractClass, uint16 kind) external view returns (uint64);  // may be deprecated
function classKindEnabled(uint16 contractClass, uint16 kind) external view returns (bool);
function classes() external view returns (uint16[] memory);                     // generic classes, first-release order
function kindsOf(uint16 contractClass) external view returns (uint16[] memory);  // kinds with a release, same order

event ClassEnvPublished(uint16 indexed contractClass, uint16 indexed kind, uint16 indexed envVersion, bytes32 envHash);
event ReleaseDeployed(uint16 indexed contractClass, uint16 indexed kind, uint64 indexed version, address implementation,
    uint16 envVersion, bytes32 envHash, bytes32 initcodeHash, bytes32 codeHash, bytes4 initSelector, bytes4 interfaceId,
    uint64 usableFrom);
event ReleaseDeprecated(uint16 indexed contractClass, uint16 indexed kind, uint64 indexed version, string reason);
event ClassKindEnabled(uint16 indexed contractClass, uint16 indexed kind, bool enabled);
```

- **Env.** The same `IFactoryToken.Env` and the same `_publish` checks (append-only, version 0 refused, `factory` /
  `chainUid` this factory's, library pins non-empty). Internally the env and release maps are keyed by a `uint32` domain
  `class << 16 | kind` (≥ `3 << 16`, so never equal to a token kind 0–13 or `DEX_DOMAIN` 255); the token and DEX maps,
  entries, views and events stay as they are.
- **`deployImplementation`.** Refuses class 0–2 (`ClassReserved`), version 0 and a taken version (`ReleaseUnknown`,
  `ReleaseAlreadyRegistered`), `initSelector == 0` (`InitSelectorZero`), an unknown env (`EnvUnknown`). The shared `_deploy`
  checks the library code hashes and `CREATE2`s (salt `keccak256(abi.encode("release", id))`)
  `initcode ‖ abi.encode(id, envVersion, env, implArgs)`: the constructor receives its own `ReleaseId`, so class, kind and
  version are immutables of the code. Then, each by `staticcall`: `SigCheck.isContract`; `factoryInfo()` exactly 224 B with
  `factory == this`, `chainUid`, class, kind, version equal to `id`, `ownerUA == 0`, `initialized == true`
  (`ReleaseInfoMismatch`); `supportsInterface(0x01ffc9a7)` and `supportsInterface(interfaceId)` true,
  `supportsInterface(0xffffffff)` false (`InterfaceNotSupported`). The first release of a class pushes it to `classes()`,
  the first of a kind to `kindsOf`.
- **Enabled.** A new `(class, kind)` starts **off** (Q7); the registrar turns it on after reading the notice period's
  feedback. Off is reversible and stops creation of every version of the kind at once (the emergency stop); deprecation is
  per version and permanent. Neither touches existing instances.

### 8.3 Why one typed init call (explicit parameters)

`createInstance` takes `initCall`: one ABI-encoded call to the implementation's own typed initializer, selector first,
for `PqChat` `abi.encodeCall(IPqChat.initialize, (ownerUA))`. Weighed against the rule "named, typed parameters, no packed
`bytes` holding several fields":

- A per-class typed entry (`createPqChat(uint64 version, bytes32 ownerUA, bytes32 salt)`) is the most explicit form, but it
  is factory code per class: every new class would be a new factory build, which is what the owner ruled out.
- An opaque `initArgs` blob (today's `createToken`) is a bundle the factory never types.
- The init call is neither: its parameters are named and typed in the implementation's ABI, published with the release
  (`interfaceId`, the class's spec); the factory pins which function it is (`initSelector`, refused otherwise:
  `InitSelectorMismatch`), and the implementation decodes its own typed arguments (a malformed call reverts in its ABI
  decoder). It is the one form that keeps the factory generic and the parameters typed. The factory never forwards it to
  anything but the fresh clone, and never as a `DELEGATECALL`.

### 8.4 `createInstance`

```solidity
function createInstance(ReleaseId calldata id, bytes32 salt, bytes calldata initCall) external returns (address instance);
function creating() external view returns (bytes32 creatorId); // the creator of the creation in progress, 0 outside one
event InstanceCreated(address indexed instance, bytes32 indexed creatorId, uint16 indexed contractClass, uint16 kind,
    uint64 version, address implementation, bytes32 owner);
```

In order, in one call (as `createDex`):

1. The release `id` exists, is not deprecated, is usable (`ReleaseUnknown`, `ReleaseDeprecated`, `ReleaseNotYetUsable`), its
   `(class, kind)` is on (`ClassKindDisabled`); class 0–2 cannot have a release.
2. `initCall.length ≥ 4` and `bytes4(initCall) == initSelector` (`InitSelectorMismatch(expected, got)`).
3. Salt scoped by the creator; the predicted address has no code and no record (`SaltAlreadyUsed`). The salt and
   `predictAddress` are the chain-neutral spec's (§4.1–§4.2: CREATE3, `s` over `creatorId`, class, kind and salt).
4. The clone; the transient creator saved, set to `creatorId` (EIP-1153), `instance.call(initCall)` with
   value 0 (a revert bubbled as the constructor's is), the previous creator restored (a nested creation inside an `initialize`
   sees its own creator, then the outer one again). `creating()` reads it (Q8).
5. `factoryInfo()` read from the clone by `staticcall`: exactly 224 B, `factory`, `chainUid`, class, kind, version equal to the
   release, `initialized == true` (`InstanceInfoMismatch`). `ownerUA` is the value the index records.
6. The record and the three list pushes of §2, then `InstanceCreated`. The record is class `id.contractClass`, kind
   `id.kind`, version `id.version`; never version 0 (no unregistered generic path, Q9).

**Relayable.** A direct call has no signature; anyone submits it, a relayer included, and the submitter is the creator. A
creation in a customer's name is the router's signed `mtxCreateInstance` (S3, chain-neutral spec §4.4, T76), relayable at
fee 0. `createInstance` is not a node job (§8.6, Q11).

**Existing kinds stay on their typed paths** (Q10): the token path carries kind-specific safety the generic path does not
know (`underlyings()`, `_wrappers`, `_byUnderlying`, `MAX_LEGS`, `createTokenUnregistered` for plain kinds, the
`TokenCreated` fields `features` / `lockedFeatures`, the `TokenKind` ABI the node and clients use), and the DEX path is
built and pinned. Moving them buys nothing now and would change formats on every client. Revisit only with a reason.

### 8.5 Safety: what the factory enforces, what it cannot know

| The factory enforces, for every generic kind | How |
|---|---|
| Registered code only | a release the registrar deployed from init code, under a published env; no `createInstance` from a caller's address |
| The public's window | `usableFrom = deployment + noticePeriod` (≤ `MAX_NOTICE_PERIOD`); the kind off until enabled (Q7) |
| The release is what it says | implementation's `factoryInfo()` names this factory, `chainUid`, its own `ReleaseId`; `initialized` (locked by its constructor); ERC-165 for `interfaceId` |
| Only the catalogued initializer is called | `initSelector` match; one `CALL`, value 0, to the fresh clone only |
| Initialized in the creating call | clone and init in one call; `factoryInfo().initialized == true` after it, else the whole creation reverts |
| An owner is reported | `factoryInfo().ownerUA`, recorded in the index (a claim, as §2.3) |
| One record per address | salt check before the clone, record after init; the index is append-only |
| No `DELEGATECALL` by the factory | the factory never delegatecalls; a clone's `DELEGATECALL` goes only to its implementation (EIP-1167) |

| The factory cannot know (the kind's spec, implementation and release review) | |
|---|---|
| The kind's own rules and what its init arguments mean | the class's spec; the implementation validates its arguments |
| A second `initialize` refused, and any caller but the factory | the implementation's rule (`msg.sender == FACTORY`, a stored lock), its tests |
| No `SELFDESTRUCT` (EIP-6780: a clone could delete itself in its creating transaction), no `DELEGATECALL` or `CALLCODE` to an address a caller supplies | release review; the registrar's deploy script disassembles the runtime and refuses those opcodes before `deployImplementation` (an on-chain scan cannot tell code from `PUSH` data cheaply) |
| Storage layout, gas, code size | the kind's layout pin (`test/v2/layout/`), gas pins and `size-baseline.json` row in its own task; a runtime over the chain's ceiling (CTR-GOV-19) fails `CREATE2` (`DeployFailed`) |
| Whether the owner UA exists or consents | as §2.3: a claim; wallets filter |

The registrar's key stays the trust root for code, now for every class (a multisig / UA msig before mainnet, as today).
Reentrancy: an `initialize` may call the factory: a nested creation is allowed and appended first (§2.2); the registrar's
entries refuse it; the factory holds no value and writes nothing between the clone and the post-init check that a nested
call could corrupt (`creating()` is restored, step 4).

### 8.6 Node, clients, vectors

- **NODE-JOB-01 unchanged:** the factory is never a `call` target, so `createInstance` is not a job; creators submit it
  themselves (Q11).
- **The instance check is generic.** A new guard rule `factory_class(class)` (`guard.rs`): the target's `infoOf(target)` has
  `contractClass == class` and `version != 0` on the chain's `token_factory`. The index never changes, so the answer is
  cacheable forever. The node learns new **instances** from state, with no config.
- **A kind's entries are per-kind rows.** Each entry of a new kind is a call-table row built from named fields
  (`typed.rs`), as for every contract today; the rows equal the implementation's state-changing entries both directions
  through its `selector_audit.json` artifact. A catalogued kind with no node rows is refused by the node (fail closed) until a
  node release adds them; a direct submission still works. A generic row built from an on-chain signature is not specified:
  the chain holds no parameter names, and named JSON fields need them.
- **Clients and vectors:** no signed byte format changes (no typehash, no `mtx*`); token and DEX formats unchanged; the
  deploy JSONs move with the factory's init code (§4). A client builds `createInstance` calldata and reads `infoOf`,
  `classes`, `kindsOf` in the round that first uses a generic class (`PqChat`'s `ua-rs` task). No vector rows in T67–T70.

### 8.7 Gas and size, on paper

- **`createInstance`** against `createDex`: the same clone (account and 45 B of code, ≈ 0.25 M state gas) and the index's
  +5 / +7 slots (§3, ≈ 0.49–0.69 M state gas); added regular gas: the `factoryInfo()` `staticcall` (warm clone and
  implementation, ≈ 3–5 k), four transient accesses (≈ 0.4 k), the selector compare; minus `owner()`. No loop. The kind's own
  `initialize` is the creator's. Measured by a `GovGas` `createInstance` row with the test kind of §8.9.
- **`deployImplementation`:** `deployTokenImplementation` plus four `staticcall`s and, the first time, one or two list pushes;
  registrar-only, once per release.
- **Size:** the generic block (four registrar entries, seven views, two structs, the checks) ≈ +3–5 KB runtime on top of the
  index's +2.5–4 KB: `OpenFactory` ≈ 22–25 KB against 15,821 B today, far below 64 KiB. T70 records old → new in
  `size-baseline.json`. A new kind's implementation is its own artifact with its own size row.

### 8.8 `PqChat`: the first generic class (class 3, kind 0)

The `PqChat` specs ([`2026-10-25-ua7-pq-e2e-sessions.md`](2026-10-25-ua7-pq-e2e-sessions.md) §2.1 P32,
`2026-11-07-pqchat-public-topics.md` §10–§11, branch `ua7-research`) need instances with an owner UA, release immutables
(registry, `chain_uid`, factory, code-size limit), a notice period, deprecation, the index, and a node check that a target is
a registered instance. Every one of them is the generic path; the factory gets no `PqChat` code.

**What `PqChat` implements** (the first generic initializer):

```solidity
// constructor(IOpenFactory.ReleaseId id, address factory_, bytes implArgs)   (chain-neutral spec §2.1)
//   immutables: FACTORY = factory_, CLASS = id.contractClass (3), KIND = id.kind (0), VERSION = id.version;
//   chain values (chain_uid, the registry, the code-size limit as params[0], P11) read from the clone's appended ChainEnv;
//   the initializer locked on the implementation
function initialize(bytes32 ownerUA) external;  // msg.sender == FACTORY, once; ownerUA 0 allowed, fixed, no transfer
function factoryInfo() external view returns (IOpenFactory.FactoryInfo memory);
function supportsInterface(bytes4 id) external view returns (bool);   // ERC-165 and type(IPqChat).interfaceId
function owner() external view returns (bytes32);                      // P32: names the instance, no power
```

`creator` and `version` are not arguments: the version is an immutable of the release, and the creator is in the index
(`infoOf(this).creatorId`) and, during `initialize`, `IOpenFactory(FACTORY).creating()`.

**Registration and creation** (deploy script and anyone):

```solidity
factory.publishClassEnv(3, 0, 1, env);   // env.registry, env.params[0] = the code-size limit; the factory adds chain_uid
factory.deployImplementation(ReleaseId(3, 0, 1), 1, IPqChat.initialize.selector, type(IPqChat).interfaceId, initcode, implArgs);
factory.setClassKindEnabled(3, 0, true);  // after the notice period
factory.createInstance(ReleaseId(3, 0, v), salt, abi.encodeCall(IPqChat.initialize, (ownerUA)));
```

**What the `PqChat` spec must change** (its §11 proposes `PqChat`-specific factory code; map each item):

| `pqchat-public-topics.md` §11 / §10 | Becomes |
|---|---|
| §11.1 `uint8 CLASS_PQCHAT = 3`, `ClassUnknown` for 0 and 4–255 | class id 3 assigned in the CTR-TOK-28 table, no factory constant; ids `uint16`; `ClassUnknown` for 0 and any generic class with no release; `ownerUA` from `factoryInfo()` |
| §11.2 `PQCHAT_DOMAIN = 254`, `publishPqChatEnv`, `pqChatEnvOf`, `latestPqChatEnvVersion` | `publishClassEnv(3, 0, …)`, `classEnvOf`, `latestClassEnvVersion` |
| §11.3 `deployPqChatImplementation`, `pqChatReleaseOf`, `pqChatImplementationOf`, `deprecatePqChat`, `isPqChatDeprecated`, `latestPqChatVersion`, `PqChat*` events and errors | `deployImplementation(ReleaseId(3, 0, v), …)`, `classReleaseOf`, `deprecateRelease`, `latestClassVersion`, `ReleaseDeployed` / `ReleaseDeprecated`, the generic errors; checks by `factoryInfo()` instead of `factory()` / `chainUid()` |
| §11.4 `createPqChat(uint64 version, bytes32 ownerUA, bytes32 salt)`, `initialize(msg.sender, version, ownerUA)`, `PqChatCreated`, `isPqChat` | `createInstance(ReleaseId(3, 0, v), salt, abi.encodeCall(IPqChat.initialize, (ownerUA)))`; `initialize(bytes32 ownerUA)`; `InstanceCreated`; `infoOf(a).contractClass == 3 && version != 0` (node: `factory_class(3)`) |
| §11.5 gas, a `GovGas` `createPqChat` row | a `createInstance` row with the `PqChat` release (`PqChatGas`, PT4); the factory side measured once in T70 with the test kind |
| §11.6 size +2–3 KB on `OpenFactory` | none for `PqChat`: the generic block is T70's |
| §11.7 tests (release usable after notice, deprecated, wrong factory / `chainUid`, relayer creator, `isPqChat`, slot count) | the generic ones are T70's; `PqChat`'s own: `initialize` once and only by the factory, `factoryInfo()` fields, ERC-165, two instances independent, `contractsPage(3, …)` after a creation; its mutants: `initialize` without the factory check, `factoryInfo()` with a wrong class |
| §11.8 formats | unchanged: no factory format moves for `PqChat` |
| §10 PF1 (factory `PQCHAT` class, 1–1.5) | **dropped**: T70 builds the generic path before 3c; `PqChat`'s registration is three deploy-script calls in PC0 |
| §10 PC0 `initialize(creator, version, ownerUA)` | `initialize(bytes32 ownerUA)`, `factoryInfo()`, `supportsInterface`, constructor `(ReleaseId, uint16, Env, bytes)`; `DeployBase` publishes the class env, deploys release 1, enables `(3, 0)`, creates one instance |
| §10 PT6 node instance check `isPqChat` | the generic `factory_class(3)` guard rule (built with PT6's rows) |

### 8.9 Tests and mutants (T70; mutants in T68)

**The acceptance test** (`test/v2/FactoryGenericKind.t.sol`): on a factory deployed before the kinds exist, with
`OpenFactory`'s runtime code hash asserted unchanged before and after, two test-only implementations under `test/v2/mocks/`
(no `src/` file): `NoteKind` (class 4, kind 0, `initialize(bytes32 ownerUA, string note)`) and `RosterKind` (class 5, kind 1,
`initialize(bytes32 ownerUA, uint64 start, address[] members)`, a dynamic argument). For each: `publishClassEnv` →
`deployImplementation` → before the notice period `ReleaseNotYetUsable` → after it, off: `ClassKindDisabled` → enable →
`createInstance` by an EOA and by a relayer naming another owner UA → `infoOf` every field, `contractsPage`,
`contractsOfOwner`, `contractsOfCreator` under the class, `classes() == [4, 5]`, `kindsOf(5) == [1]`, `creating()` seen inside
`initialize` and 0 after → version 2 deployed, version 1 deprecated: the old instance still answers, creation of v1 refused,
v2 created; a second kind added to class 4.

**Negatives**, each with its positive control: class 0, 1, 2 on every generic entry (`ClassReserved`); version 0 and a taken
version; `initSelector` 0; env unknown; a release whose `factoryInfo()` names another factory, another `chainUid`, another
class, kind or version, `initialized == false`, `ownerUA ≠ 0`, a 192 B or 256 B answer, no answer; ERC-165 false for
`interfaceId`, true for `0xffffffff`; an `initCall` of 0–3 bytes and one with another selector; an initializer that leaves
`initialized` false or reports another class after init; an initializer that reverts (bubbled); `SaltAlreadyUsed`; a nested
`createInstance` from `initialize` (order and both creators right); non-registrar and delegated registrar refused; a disabled
kind stops every version and enabling restores it; the token and DEX tests of T67 unchanged. **Slot count:** +5 / +7 as §3.

**Mutants** (T68, one at a time, each must turn a T70 test red): the selector check dropped; the post-init `factoryInfo()`
check dropped; class compared with kind; the version not compared; `initialized` not checked (at registration, after init);
the enabled check dropped; the `usableFrom` check dropped; `ClassReserved` accepting 2; the transient creator not restored;
`ownerUA` read before `initialize`; the 224 B length check relaxed; `classes()` pushed on every release instead of the first.

### 8.10 Tasks (plan [`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md))

| # | Task | Change | Size (agent-days) |
|---|---|---|---|
| T67 | the record, per-class lists, paged views | ids `uint16` (Q12); otherwise as approved | 2 (unchanged) |
| T70 | **new:** generic catalogue and `createInstance` (§8.2–§8.5), the acceptance test (§8.9), `GovGas` `createInstance` row, size row | after T67 | 2 |
| T68 | mutants, deploy dry run, factory address | + the generic mutants of §8.9; the dry run also registers `NoteKind` and creates one | 0.5 → 1 |
| T69 | docs share | + CTR-TOK-28 (class table, the generic path, §8.5's two lists), a PLANNED `factory_class` guard line in `docs/node/job-api.md` | 0.5 → 1 |
| | **Total** | | **3 → 6** |

Order T67 → T70 → T68; T69 beside, lands in T19; T44 (3f) now depends on T69 after T70. `PqChat`'s own release is 3c
(PC0); its PF1 is dropped (§8.8).

### 8.11 Questions for the owner (each with a recommendation)

**Owner 2026-11-07: Q7–Q12 answered as recommended:** (7) a new `(class, kind)` starts off: yes; (8) `creating()`: yes;
(9) no unregistered generic path: yes, none; (10) token and DEX kinds onto the generic path: not now; (11) the node relaying
`createInstance`: not now; (12) class and kind ids `uint16`: yes.

7. **A new `(class, kind)` starts off.** **Recommend:** yes. Fail closed: the registrar enables it as an explicit second step
   after the notice period, and the same switch is the reversible stop for every version of a kind.
8. **`creating()`, the transient creator view.** **Recommend:** yes. About 0.4 k gas per creation and a few lines; without it a
   later kind that needs its creator inside `initialize` needs a new factory build, the thing the extension avoids. `PqChat`
   does not need it.
9. **No unregistered generic path** (no `createInstance` from a caller's own implementation). **Recommend:** yes, none.
   `createTokenUnregistered` stays for the plain token kinds only; every generic instance has `version ≠ 0`.
10. **Existing token and DEX kinds onto the generic path.** **Recommend:** not now (§8.4): their kind-specific index and
    events stay in the typed entries; no gain, formats would move on every client.
11. **The node relaying `createInstance`.** **Recommend:** not now; NODE-JOB-01 unchanged. A creation is a one-off the creator
    submits and pays; a lane paying for unsigned creations is a spam vector. A signed, fee-paid creation is a later entry if
    a consumer needs it.
12. **Class and kind ids `uint16`** (the one change to the approved index, §2): **Recommend:** yes. Open-ended ids without a
    compiled enum; the record stays three slots (`creator ‖ class ‖ kind ‖ version` is 32 B); no other format moves.
