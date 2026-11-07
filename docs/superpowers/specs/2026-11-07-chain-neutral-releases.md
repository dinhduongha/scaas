# Chain-neutral releases: the same factory, release and instance addresses on every chain

**Status:** SPECIFIED, **approved by the owner 2026-11-07, pending the Fable review** (decisions A and B, then the eight
questions of §10.3 answered as recommended; the Fable review's fixes come next). Nothing is built. Companion of the factory
index spec [`2026-11-07-factory-contract-index.md`](2026-11-07-factory-contract-index.md) (index §1–§7 and extension §8
approved; S3's `creatorId` written into it): this spec changes its creation paths (§2.1 `creator`, §8.4 step 3, `predictAddress`) and every
factory-made kind. Branch `ua-mtx-merge`. Proposed rule **CTR-TOK-29** (`docs_check.py resolve` reports it unknown; CTR-TOK-28
is §8's) and a change of [NET-ALL-22](../../networks/README.md#NET-ALL-22) (draft in §9). **Everything cryptographic here is
UNAUDITED.**

**Owner, 2026-11-07:**

- **A.** Same addresses on every chain via CREATE3, on **all** creation paths: `createToken`, `createTokenUnregistered`,
  `createDex` and the generic `createInstance` (index spec §8). An instance address depends only on the factory address, the
  creator, the class, the kind and the salt (class and kind folded into the salt: owner yes), not on the implementation. The
  `predict…` views follow.
- **B.** Implementations are chain-neutral bytecode, deployable at the same address on every chain: "the implementation should
  have an initialization function called by OpenFactory that initializes those values". The chain-specific values that are
  constructor immutables today leave the constructor and are written by the factory into each instance at creation. The factory
  itself is at the same address on every chain, so its own `chainUid` (and anything else chain-specific) becomes a one-time value
  set by the registrar after a deterministic deploy.

**Rules this spec applies, not reopens:** nothing deployed is upgraded ([CTR-GEN-02](../../contracts/README.md#CTR-GEN-02)); one
rule on every chain; explicit parameters; every state-changing `mtx*` relayable at fee 0; `salt = chain_uid` in every domain
([CTR-GEN-05](../../contracts/README.md#CTR-GEN-05)); size and gas pins move only with old → new.

## 1. Where chain-specific values live today (read at `HEAD`)

`OpenFactory._deploy` `CREATE2`s `initcode ‖ abi.encode(envVersion, Env, implArgs)`, so every `IFactoryToken.Env` field is a
constructor argument and the implementation's address and code hash differ per chain. Clones (`Clones.cloneDeterministic`, salt
`keccak256(abi.encode(msg.sender, salt))`) inherit the difference: their address is a function of the implementation address.

| Value | Today | Chain-specific? | Read by (runtime) |
|---|---|---|---|
| `chainUid` | `SaltedEIP712.CHAIN_UID` immutable; `OpenFactory.chainUid` immutable | **yes** (genesis hash) | every signature check (domain `salt`), confidential digests, `chainUid()`, `eip712Domain()` |
| `factory` | `MetaTokenBase.FACTORY`, `SCaaSDex.FACTORY` immutable | no once A holds (one address everywhere) | `initialize`'s `msg.sender` check, `WrappedLib` / `RegulatedLib` reads of `IOpenFactory` |
| `registry` | `UAMetaTxBase._REGISTRY` immutable | **yes** (`UARegistry`'s constructor takes `chain_uid`) | UA path of every `mtx*` (`requireAuthorized`), registry `chainUid()` check at `initialize` |
| `govRouter` | `GovernanceBase.GOV_ROUTER` immutable | **yes** (its constructor takes `chain_uid`) | every governance entry through the router |
| `smartKeyAccountImpl` | `MetaTokenBase.SMART_KEY_ACCOUNT_IMPL`, `UAMetaTxBase._SMART_KEY_CLONE_CODEHASH`, DEX same | **yes** (`SmartKeyAccount`'s constructor takes `chain_uid`) | the ERC-1271 gas budget of a smart-key clone |
| `hedera` | `UAMetaTxBase.IS_HEDERA` immutable | **yes** | the HIP-632 branch of every signature check |
| `deps` | `ZetherLayer` `TRANSFER_VERIFIER`, `BURN_VERIFIER`, `_DISCLOSURE`; `PqzLayer.PQZ_VERIFIER` | per release (see §4.3) | Zether / PQZ proof entries |
| `libs`, `libCodeHashes` | linked addresses in the bytecode; hashes checked by the factory at release deploy | no (§5) | every linked call |
| `implArgs` | `RegulatedBase.REGISTRY_CODEHASH` (the canonical `ComplianceRegistry` runtime hash) | no: `ComplianceRegistry` keeps `admin` in storage and has no immutable, so its runtime is the same everywhere | `initialize` |
| `noticePeriod` | `OpenFactory` immutable | **yes** (7622: minutes; a mainnet: ≥ 3 days, `DeployBase._checkedNotice`) | `deployImplementation`, `deployRelease` |

Unchanged and out of scope (not factory-made; their constructors keep `chain_uid` as an immutable, so they keep a per-chain
address, NET-ALL-22 as today): `UARegistry`, `GovernanceRouter`, `SmartKeyAccountFactory` and accounts, `MandateWallet`,
`MtxRelayFee` (stateless, no `chain_uid`), the verifiers. Their addresses are **values** an instance stores (§2), not code, so
they do not break A or B. Making them chain-neutral too is Q6.

## 2. The instance's chain environment (decision B)

### 2.1 What leaves the constructor, and where it goes

```solidity
/// Written once by the factory into each instance, in the creating call (CTR-TOK-29). Explicit fields; unused = 0.
struct ChainEnv {
    bytes32 chainUid;            // the factory's own (§3), never the creator's
    address registry;            // this chain's UARegistry (0 = no UA path)
    address govRouter;           // this chain's GovernanceRouter (0 = none)
    address smartKeyAccountImpl; // 0 = none
    bool hedera;
    address[4] deps;             // by documented position, as Env.deps today (ENV_ZETHER_*, ENV_PQZ_VERIFIER)
    bytes32[2] params;           // chain values of a generic class by documented position (PqChat: [0] = code-size limit)
}
/// On every factory-made implementation (and so every clone):
function initEnv(ChainEnv calldata env) external;   // msg.sender == FACTORY, once; locked on the implementation
function chainEnv() external view returns (ChainEnv memory);
function validateEnv(ChainEnv calldata env) external view;  // the constructor checks of today; reverts BadInit
```

- **Storage.** An ERC-7201 namespace `scaas.chainenv` in the clone's own storage (an EIP-1167 clone runs the implementation's
  code by `DELEGATECALL` and never sees the implementation's storage, so the values must be written into each clone). Layout:
  slot 0 `chainUid`; slot 1 `registry ‖ hedera ‖ lock`; slot 2 `govRouter`; slot 3 `smartKeyAccountImpl`; slots 4–7 `deps`;
  slots 8–9 `params`. A zero field is never written, so it creates no slot and costs no state gas. Pinned in `test/v2/layout/`.
- **`FACTORY` stays an immutable**, now from a chain-neutral constructor argument `factory_` (the factory is at one address on
  every chain, decision A, so the value and the code hash are the same everywhere). It is not in `ChainEnv`: `initEnv` itself is
  gated by it, and keeping it in code keeps `initialize`'s `NotFactory` check free. `createTokenUnregistered` keeps working: an
  unregistered implementation also names the factory in its constructor, and the factory still checks `factory() == this`.
- **Constructor after B:** `constructor(address factory_, bytes implArgs)` for the token kinds and the DEX; `constructor(ReleaseId
  id, address factory_, bytes implArgs)` for a generic class (index spec §8.2 without `envVersion` and `Env`). `implArgs` holds
  only values that are the same on every chain (today: `REGISTRY_CODEHASH`); a chain value goes into `ChainEnv`. The
  constructor sets the lock bit of slot 1 and `TokenStore.initialized` (or the class's own lock), so the implementation can be
  neither `initEnv`ed nor `initialize`d.
- **The constructor checks of today move to `validateEnv`** (`ZetherLayer`: four deps, one proof system, roles not swapped, not
  Hedera, registry has code; `PqzLayer`: one dep, not Hedera; `NormalPqzToken`: registry has code). The factory calls it by
  `staticcall` once per release and chain, when the release is deployed or bound to an env (§3.3), so a creation does not pay
  for it. Its body goes in the kind's existing linked library (`ZetherLib`, `PqzStateLib`) where the kind is near the size
  ceiling (§7).
- **`initEnv`** (factory only, once): stores the non-zero fields; with `registry ≠ 0` requires `IUARegistry(registry).chainUid()
  == env.chainUid` (moved from today's `MetaTokenBase.initialize`, `UARegistryChainUid`); `SMART_KEY_CLONE_CODEHASH` is no longer
  stored but recomputed from `smartKeyAccountImpl` when used (a 45 B `keccak256`, ≈ 50 gas, only on the ERC-1271 path).

### 2.2 How each kind reads them

`SaltedEIP712` gets one internal hook, `_chainUid()`: the storage read for factory-made contracts, the immutable for the others
(the registry, the router, accounts, wallets keep their constructor). `UAMetaTxBase._mtxCtx()` (the one place that builds
`MtxPipelineLib.Ctx`) reads slots 0 and 1 and leaves `smartKeyAccountImpl` to the ERC-1271 branch; `GovernanceBase`'s router
check reads slot 2; `ZetherLayer` / `PqzLayer` read their deps from slots 4–7 (`ZetherLib` already copies the transfer verifier
into its own storage at `init`; it reads the `ChainEnv` slot instead and the copy is dropped). Every view that answers an
immutable today (`chainUid()`, `eip712Domain()`, `verifier()`, `burnVerifier()`, `IS_HEDERA`, `GOV_ROUTER`, `FACTORY`) keeps its
selector and answer on a clone. On the implementation, `chainUid()` answers 0: it is never a signing target, and the node's
guard ([NODE-GW-07](../../node/gateway.md#NODE-GW-07)) refuses a target whose `chainUid()` is not the chain's.

### 2.3 Storage, factory read, or a shared env contract: compared

| | **S: in the instance (recommended)** | F: read from the factory at run time | P: one SSTORE2 env contract per env, pointer in the instance |
|---|---|---|---|
| Per signature check | +2 cold `SLOAD` (slots 0, 1) ≈ **+4.2 k** | cold `CALL` to the factory (2.6 k) + its `SLOAD`s + ABI ≈ +7–9 k | 1 `SLOAD` + cold `EXTCODECOPY` ≈ +4.8 k |
| Per creation (new slots) | 3–7 (plain 4, DEX 3, PQZ 5, Zether 7–8) | 0–1 (the env version) | 1 |
| Trust | self-contained, written once | a live edge to the factory on every call; an env change would reach existing instances unless keyed by version | as S (the data contract is immutable) |
| Code | typed fields, one getter each | an `IOpenFactory` call per value | a typed decode of the blob per read |

**Recommend S**: the owner's wording (values written into each instance), the cheapest hot path, no cross-contract call on a
signature path, and an instance whose state alone says what it is. P halves the creation cost of the confidential kinds at
+0.6 k per call; it is the owner's choice only if creation cost of many confidential tokens matters more (Q5).

### 2.4 The domain separator: no cache

Today a clone already rebuilds the separator on every call: `SaltedEIP712` caches it for `_cachedThis`, the implementation's
address, which a clone never equals. After B the rebuild reads `chainUid` from slot 0 (one cold `SLOAD`, 2,100) and hashes
six words (≈ 100 gas). Caching the separator in the instance would add a slot at creation (≈ 97,920 state gas), cost the same
cold `SLOAD` per call, and still need `chainUid` for `eip712Domain()`, the confidential digests and a chain-id fork check.
**No cache.** Name and version stay immutables (constants per kind, the same on every chain).

## 3. Replay protection: who sets `chainUid`, what stops a wrong value

### 3.1 The factory (registrar, once)

```solidity
constructor(address registrar_);   // the only constructor argument; the same on every chain (§3.4)
function configureChain(bytes32 chainUid_, uint64 noticePeriod_, address govRouter_) external;  // onlyRegistrar, once
function chainUid() external view returns (bytes32);       // 0 until configured
function noticePeriod() external view returns (uint64);
function govRouter() external view returns (address);      // S3, §4.4; 0 = none
error ChainNotConfigured();       // every creation, publish and deploy entry before configureChain
error ChainAlreadyConfigured();
error ChainUidNotGenesis(bytes32 given, bytes32 provable);
```

`configureChain` refuses `chainUid_ == 0` (`ChainUidZero`), `noticePeriod_ > MAX_NOTICE_PERIOD`, a second call, and a value the
EVM can still prove wrong: `blockhash(0)` when `block.number ≤ 256`, else the EIP-2935 history contract's answer for block 0
when it still serves it (8,191 blocks); both are 0 / no answer on an older chain, and then nothing is compared. One rule on every
chain: "if the chain can prove its genesis hash, the value must equal it". A fresh chain (22776 at launch, a customer chain)
configured within its first 256 blocks is therefore proven on-chain.

### 3.2 Each instance (factory, once)

The factory passes its own `chainUid` in `ChainEnv` (the registrar's published env carries no `chainUid` and no `factory`; the
factory fills them), then after `initialize` / `initCall` requires `chainUid()` (tokens, DEX) or `factoryInfo().chainUid`
(generic) of the clone to equal its own, else the whole creation reverts (`ChainUidMismatch`). An unregistered implementation's
code is unvetted as today; the post-check still guarantees that what it reports as its domain salt is the factory's.

### 3.3 The trust, stated

- **Same as today in substance.** Today the deploy script reads the genesis hash from the RPC and passes it as a constructor
  argument; the deploy gate and the node check every `chainUid()` against the RPC and the chain profile
  ([NET-EVM-05](../../networks/evm.md#NET-EVM-05), [NODE-GW-07](../../node/gateway.md#NODE-GW-07)). After B the registrar's
  transaction carries the same value, the same gate and node checks apply, plus the on-chain proof when the chain is young.
- **What is worse.** A wrong value is permanent for the canonical factory address **on that chain**: today a mistaken
  constructor argument means a new factory at a new address; after A the canonical address is taken by the misconfigured factory
  and cannot be redeployed (CREATE2 collision). The deploy gate therefore dry-runs `configureChain` by `eth_call`, compares with
  ≥ the profile's RPC quorum and `chain-uids.json`, and only then sends it. Accepted or not by the owner: Q4.
- **What a wrong value does** (unchanged from NET-ALL-22): correct signatures fail; it is unsafe only if it equals another
  chain's `chain_uid`, which the gate's cross-profile check excludes.
- **Front-running.** Anyone can deploy the factory's init code through the deterministic deployer on any chain; that is the same
  contract with the same registrar, so it is harmless. Only the registrar can `configureChain`; until it does, the factory
  refuses everything.
- **Why it is still one rule on every chain:** every factory-made contract on every chain takes `chain_uid` from its factory;
  every factory takes it from its registrar once, checked against the chain's own provable genesis when there is one. No chain
  kind is special-cased.

### 3.4 The registrar's address

The registrar is the factory's only constructor argument, so it must be the same address on every chain, under the same
control. An EOA is that by construction. A contract registrar (the multisig / UA `msig` planned before mainnet) must itself be
deployed deterministically with its owners in its init code, before the factory is configured on that chain; otherwise its
address on another chain may belong to someone else (the 2022 Wintermute / Optimism loss: a Safe address deployed on L1 and not
on L2 was taken there), and that person would configure the canonical factory there. The deploy gate checks the registrar's code
hash per chain against the release list. Q3.

## 4. CREATE3 (decision A)

### 4.1 Construction

An internal library `Create3` (≈ 30 lines in `src/common/`; no new dependency; Solady's and 0xSequence's layout):

1. `proxy = CREATE2(factory, s, PROXY_INITCODE)` with the fixed 16-byte init code `67363d3d37363d34f03d5260086018f3`, which
   deposits the 8-byte runtime `363d3d37363d34f0` ("`CREATE` with my calldata as init code").
2. The factory calls `proxy` with the EIP-1167 init code of the release's implementation (OpenZeppelin's 55-byte clone init
   code); the proxy `CREATE`s it at nonce 1.
3. `instance = address(keccak256(rlp([proxy, 1]))[12:])`: a function of the factory address and `s` only.

`s = keccak256(abi.encode(creatorId, contractClass, kind, salt))`, with `contractClass` 1 / `kind` the `TokenKind` for
`createToken` and `createTokenUnregistered`, 2 / 0 for `createDex`, the release's class and kind for `createInstance`. Neither the
implementation nor the version is in it. The proxy stays (no `SELFDESTRUCT`, index spec §8.5), so a used `s` cannot be reused:
`CREATE2` of the proxy fails; the factory checks the record first and reverts `SaltAlreadyUsed(predicted)` as today.

### 4.2 `predict…`

```solidity
function predictAddress(bytes32 creatorId, uint16 contractClass, uint16 kind, bytes32 salt) external view returns (address);
```

One view for every path; today's `predictAddress(implementation, creator, salt)` is removed with the factory it belongs to (the
old factory moves to `legacy/`; it would return an address no path creates any more). Clients compute the same address from the
vector rows of §6.4.

### 4.3 Same address is not same content

The address fixes the factory, the creator, class and kind, never the version, the implementation, the env or the
`TokenConfig`. On two chains the same address may be version 1 on one and version 3 on the other, with other verifiers, another
owner, another name, or a registered token on one and an unregistered one (version 0, same class and kind) on the other; or
exist on one chain only. A wallet or a node never infers anything from the address: it reads `infoOf(addr)` (class, kind,
version, creator), `releaseOf` (implementation, code hash, env hash) and the instance's own views **per chain**. Docs and client
copy say so wherever the shared address is shown.

### 4.4 Creator identity (owner question S3): the signing UA

**Owner 2026-11-07: the UA that signed** (as recommended; T76 is in). `creatorId` is a `bytes32` UA id ([CTR-UA-03](../../contracts/accounts.md#CTR-UA-03)): a
native caller is `pad(msg.sender)`; a derived UA (a PQ key, an `msig`) is its registered id. The factory learns it two ways only:

1. **Direct call:** `creatorId = bytes32(uint256(uint160(msg.sender)))`.
2. **Signed, relayed:** the chain's `GovernanceRouter` gains three typed ops, `mtxCreateToken`, `mtxCreateDex`,
   `mtxCreateInstance` (`UAEnvelope`, then the creation's named parameters, `initHash = keccak256(initArgs or initCall)`, the
   `UASig`), verified as every router op today (`MtxPipelineLib.preNamedUA`: a native id by its own key, a derived id through
   `requireAuthorized(PURPOSE_METATX)`, lane nonce, `validUntil`, fee mode `NONE`, relayable at fee 0). The router calls the
   factory with the transient `subject()` set; the factory, seeing `msg.sender == govRouter()` (its one-time value, §3.1), takes
   `creatorId = IGovernanceRouter(govRouter).subject()` and refuses 0. The factory holds no signature code, no domain and no
   nonce. A native id through the router gets `pad(addr)`, the same `creatorId` as a direct call, so the same address.

Why not the submitter: a relayer, a backend or a smart account would own the customer's address on every chain and could take it
first on a chain the customer has not used yet. Why the UA id is right for A: a native EOA and a derived UA are bound to keys, and
the UA id is chain-independent ([CTR-UA-07](../../contracts/accounts.md#CTR-UA-07)), so the same signer gets the same address
everywhere. **Limit:** a contract creator (a smart account, a multisig) calling directly is `pad(contract)`; that address may
belong to someone else on another chain (§3.4), who can then create at "its" addresses there. Stated, not prevented: refusing
contract creators would break smart accounts.

**What it changes in the approved index (Q1):** `Created.creator` (address) becomes `creatorId` (`bytes32`); the record stays three
slots (`creatorId`; `ownerUA`; `contractClass ‖ kind ‖ version ‖ createdBlock ‖ createdAt` = 28 B); `_byCreator`,
`contractsOfCreator`, `_wrappers`, `getWrapper*` and `creating()` are keyed by `bytes32`; `creatorOf(token)` keeps answering the
address for a native id and 0 for a derived one; `infoOf` returns `creatorId`. Tokens' and the DEX's `initialize(creator, …)` take
`bytes32 creatorId` (`TokenStore.creator` widens: a layout pin moves).

### 4.5 Squatting

- **By a third party:** impossible on any path: `creatorId` is in `s` and authenticated (`msg.sender` or the router's verified
  subject). A signed creation is chain-bound (the router's domain carries `chain_uid`), so a relayer cannot replay it on another
  chain.
- **By the creator against itself:** a creator may put another kind or an unregistered token at its own address on another chain
  (§4.3).
- **Contract creators:** §4.4 limit.

## 5. Libraries: chain-neutral by default (coordinator, owner's question 2026-11-07)

**Default:** every linked library is chain-neutral bytecode deployed at the same address on every chain through the
deterministic deployer (`0x4e59b44847b379578588920cA78FbF26c0B4956C`, salt `create2_library_salt`, as `DeployBase` already
does through forge). Implementations keep `Lib.f()` linking unchanged: **zero gas, zero code change.**

Checked at `HEAD` (artifacts' `linkReferences`, sources): Solidity allows no state variable and no constructor in a library, so
no library holds an immutable or a constructor argument; a library's runtime embeds only its own address (call protection) and
the addresses of the libraries it links, which are chain-neutral recursively. `HederaLib`'s `HTS = 0x167` is a constant, read
only behind the `hedera` flag.

| Library | Links | Linked by |
|---|---|---|
| `GovernanceLib`, `HederaLib`, `TradeLib`, `ZetherLib`, `PqzBurnLib`, `PqzTransferLib`, `PqzStateLib`, `PqzViewLib`, `UARegistryLib` | none (deploy first) | tokens, DEX (`GovernanceLib`, `TradeLib`); the registry (`UARegistryLib`) |
| `MtxPipelineLib` | `HederaLib` | every token |
| `WrappedLib`, `RegulatedLib` | `GovernanceLib` | wrapped and regulated kinds |
| `ZetherWrappedLib` | `WrappedLib`, `ZetherLib` | `WRAPPED_ZETHER*` |
| `PqzWrappedLib` | `PqzStateLib`, `WrappedLib` | `WRAPPED_PQZ*` |

(Linked sets per kind, e.g. kind 13: `GovernanceLib`, `MtxPipelineLib`, `PqzBurnLib`, `PqzStateLib`, `PqzTransferLib`,
`PqzViewLib`, `PqzWrappedLib`, `RegulatedLib`, `TradeLib`, `WrappedLib`; the DEX: `GovernanceLib`, `TradeLib`; `OpenFactory`
none.) Deploy order: the leaves, then `MtxPipelineLib`, `WrappedLib`, `RegulatedLib`, then `ZetherWrappedLib`, `PqzWrappedLib`.
The factory keeps `Env.libs` / `libCodeHashes` as a per-chain check at release deployment (an empty address would make a
library call fail on that chain); they are never written into an instance.

**Fallback, only for a library that cannot be made chain-neutral:** its address becomes a `ChainEnv` value and the kind calls it
by an explicit `DELEGATECALL` through an interface. Costs: a cold `SLOAD` per call (≈ +2.1 k), ABI encoding instead of the
linker's direct call, every call site rewritten. Risk: a `DELEGATECALL` to a storage-held address is arbitrary code over the
token's storage; only the factory may write it, once, from the registrar's published env, and the release review must accept it.
No library needs it today.

## 6. What changes, per component

### 6.1 Contracts

| Component | Change |
|---|---|
| `OpenFactory` | constructor `(registrar)`; `configureChain` (§3.1); `chainUid`, `noticePeriod` from storage; `Create3` on `_create`, `createDex`, `createInstance`; `creatorId` (§4.4) incl. the router path; `predictAddress` (§4.2); `_deploy` appends `abi.encode(address(this), implArgs)` (or `(id, address(this), implArgs)`), so the release's address is `CREATE2(factory, keccak256(kind, version), initcode ‖ args)`, the same on every chain for the same code; `_checkImplementation` checks `kind()`, `factory()` and `validateEnv(env)`, no longer `chainUid()`; `Env` loses `factory` and `chainUid` (the factory fills them) and gets `address[4] deps`, `bytes32[2] params`; creation: clone → `initEnv(ChainEnv)` → `initialize` / `initCall` → `chainUid()` post-check → index |
| `IFactoryToken`, `IOpenFactory` | `ChainEnv`, `initEnv`, `chainEnv`, `validateEnv`; `initialize(bytes32 creatorId, uint64, bytes)`; new errors |
| `SaltedEIP712` | `_chainUid()` hook (storage for factory-made, immutable for the rest) |
| `UAMetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`, `GovernanceBase` | immutables `_REGISTRY`, `IS_HEDERA`, `_SMART_KEY_CLONE_CODEHASH`, `SMART_KEY_ACCOUNT_IMPL`, `GOV_ROUTER` → `ChainEnv` getters; constructor `(factory_, implArgs)` |
| 12 token kinds (0–5, 8–13) | constructors per above; `ZetherLayer`, `PqzLayer` deps → slots; constructor checks → `validateEnv` (in `ZetherLib` / `PqzStateLib`); `RegulatedBase.REGISTRY_CODEHASH` stays an immutable (chain-neutral) |
| `SCaaSDex` | same as a kind (chain env, `validateEnv`, `initEnv`); `DexPuller` is `CREATE`d by the DEX at nonce 1, so it follows the DEX's address unchanged |
| `PqChat` (class 3, 3c) | constructor `(ReleaseId, factory_, implArgs)`; `chainUid`, registry and the code-size limit (`params[0]`, a chain value: 131,072 on 7622, 65,536 under EIP-7954) from `ChainEnv`; the `PqChat` spec's PC0 row in index §8.8 follows |
| Generic classes (index §8) | `factoryInfo().chainUid` from `ChainEnv`; `deployRelease` calls `validateEnv`; acceptance mocks `NoteKind`, `RosterKind` get `initEnv` |
| Storage layout pins | `scaas.chainenv` added; `TokenStore.creator` widened; every kind's pin regenerated |
| Typehashes, selectors of `mtx*` | unchanged (no domain field moves; only its source) |

### 6.2 Deploy scripts

`DeployBase`, `script/hedera/`, `script/pqz/e2e.py`: the libraries by `0x4e59` (as today), the factory by `0x4e59` with
`(registrar)` only, then `configureChain` after the dry run of §3.3, the registry and router as today (per-chain addresses), envs
published with the chain's values, releases from chain-neutral init code. The deploy gate adds: factory address = the canonical
one; each release's address and code hash = the release list's (equal on every chain); `chainUid()` of the factory and of one
test instance = the RPC's genesis hash; the registrar's code hash (§3.4).

### 6.3 Node

Allow-lists unchanged (no `mtx*` selector of a kind moves). The guard's `chainUid()` call on a target is unchanged and now reads
storage; an implementation answers 0 and is refused. `config.rs`'s `token_factory` becomes one address on every chain. If S3
lands, the router's three create ops get `typed.rs` rows only when the owner answers index §8.11 Q11 for relaying creations
(today: not now; anyone submits them, fee 0).

### 6.4 Vectors and clients

- **Digests:** no typehash or domain format changes, and the vectors' fixed `chain_uid` constants (e.g. the SCaaS testnet's
  earlier `0x24e4…c464`) keep their values. What moves is any KAT whose `verifyingContract` is a factory-made address computed
  in a test from the CREATE2 clone formula (candidates at `HEAD`: `test/vectors/dex_order_kat.json`,
  `vectors/governance/regulated_kat.json`, `test/vectors/plus_zero_gas.json`; the task greps every KAT for a factory-predicted
  address): regenerated by their generators, and every language reads the new rows.
- **New:** `smartcontracts/vectors/factory/create3_kat.json` — rows `(factory, creatorId, contractClass, kind, salt) → (s,
  proxy, instance)`, including a native and a derived `creatorId`, class 1/2/3, a non-zero salt; read by the Solidity test,
  `clientkeys` and `ua-rs` (the signer, which predicts a creation's address). Other `ua-*` clients read `predictAddress` over RPC.
- **Domains:** clients already read the domain from the instance (`eip712Domain()`, ERC-5267); nothing changes there. A client
  that cached a domain per implementation must read it per instance.

## 7. Size and gas, on paper

### 7.1 Size (old → new is the task's to measure)

- **Init code shrinks** for every kind (no `Env` decode, no constructor checks): about −1 to −2 KB [estimate].
- **Runtime grows** per kind by `initEnv` (a struct decode and up to ten `SSTORE`s), `chainEnv()`, `validateEnv` (moved
  constructor checks), and storage getters instead of `PUSH32` immutables (one shared getter per field): about **+0.5 to +1.5
  KB** [estimate; plain kinds at the low end, the Zether and PQZ kinds at the high end unless `validateEnv`'s body sits in their
  library].
- **Kind 13** (`WrappedPqzRegulatedToken`) is 64,522 B in `size-baseline.json` at `HEAD` (64,969 B in the local build of 3g in
  progress, uncommitted), already over the 64,512 B stop line: it lands at ≈ 65.0–66.5 KB, likely over 65,536 B. It deploys on
  the SCaaS testnet (131,072 B, CTR-GOV-19) and stays inside the size window: pinned in `_above64KiB` ("owner 2026-11-07, removed
  by T66b"); T66b's target includes this growth. The other kinds stay under 65,536 B on paper (kind 11 59,678 B → ≈ 61 KB).
- **`OpenFactory`:** `configureChain`, `Create3`, `creatorId`, the router path ≈ +1–1.5 KB on top of the index spec's ≈ 22–25
  KB.

### 7.2 Gas (EIP-8037: ≈ 97,920 state gas per new slot; [estimate] until the tasks' `GovGas` / `UAGas` rows give old → new)

| Operation | Today | After | Δ |
|---|---|---|---|
| Any `mtx*` with a signature check (native or UA), DEX order | immutables (≈ 3 gas each) | cold `SLOAD` of slots 0 and 1 | **≈ +4.2 k regular** |
| + governance entry via the router | `GOV_ROUTER` immutable | + slot 2 | +2.1 k |
| + ERC-1271 smart-key signer | immutable code hash | + slot 3, a 45 B hash | +2.2 k |
| Zether / PQZ proof entry | dep immutables | + 1–2 dep slots | +2.1–4.2 k (against ≥ millions of gas for the proof) |
| `createToken`, plain kind | CREATE2 clone (≈ 0.25 M state) | + CREATE3 proxy (account and 8 B: ≈ 0.19 M state, ≈ +40–50 k regular) + `ChainEnv` 4 slots (391,680 state) + the `initEnv` call (≈ +10 k regular) | **≈ +0.58 M state, ≈ +55 k regular** |
| `createToken`, PQZ kinds (5 slots) / Zether kinds (8 slots) | as above | as above | ≈ +0.68 M / ≈ +0.97 M state |
| `createDex` (3 slots) / `createInstance` `PqChat` (3 slots) | as above | as above | ≈ +0.49 M state |
| `deployImplementation` / `deployRelease` | init code + ≈ 1 KB env | init code + 64 B; + `validateEnv` staticcall | smaller calldata, ≈ +5–20 k regular |
| `configureChain` | (constructor) | once per chain, 3 slots | ≈ +0.29 M state, once |

The CREATE3 proxy's 0.19 M is §8.7's clone figure (≈ 0.25 M for an account and 45 B) less 45 B × 1,530, plus 8 B × 1,530.
A creation stays far below any block limit (inclusion is regular + state, EIP-8037). The per-signature +4.2 k is the trade-off
the owner accepts with B (Q2).

## 8. Tests and mutants

**Two chains** (`test/v2/ChainNeutral.t.sol` with forge forks, and a script test on two `anvil`s, which carry `0x4e59…956c`
by default): chain A id 31901, chain B id 31902 with another genesis timestamp (different genesis hash), and chain C with id
31901 and a third genesis (the NET-ALL-22 case: one chain id, two chains). On each: the libraries, the factory, `configureChain`
with that chain's genesis, the registry and router, envs, releases of every kind and the DEX, and one instance per path.

- **Same address:** the factory, every library, every release (address and `extcodehash` equal across A, B, C); one instance per
  path at the same address on A, B, C for the same `(creatorId, class, kind, salt)`; `predictAddress` equals the created address
  on every path; a different creator, class or kind gives another address; the version and the implementation do not change it
  (v1 on A, v2 on B: same address).
- **Signatures bound to their chain:** a signed `mtx*` built for the instance on A is refused on B and C (B: chain id and salt
  differ; C: only the salt differs), and accepted on A; the same for a UA signature, a DEX order and a router op;
  `eip712Domain()` differs exactly in `chainId` and `salt`.
- **Negatives, each with its positive control:** a creation, publish or deploy before `configureChain` (`ChainNotConfigured`); a
  second `configureChain`; by a non-registrar or a delegated registrar; `chainUid_ = 0`; a value ≠ `blockhash(0)` on a young
  chain (`ChainUidNotGenesis`); `initEnv` by another caller, twice, on the implementation; an instance whose `chainUid()` after
  init differs from the factory's (a mock implementation that stores another value: `ChainUidMismatch`); an env failing
  `validateEnv` (Zether deps swapped, a duplicated pair, Hedera with a confidential kind) refused at release deploy; the same
  `s` twice (`SaltAlreadyUsed`), also across `createToken` and `createTokenUnregistered`; the router path with `subject() = 0`;
  a router call from a non-router address claiming a subject; `chainUid()` of an implementation is 0 and the node's guard
  refuses it.
- **Hedera:** CREATE3 depends on `CREATE` addresses from a contract's nonce (HIP-729) and on `0x4e59…956c` being present; checked
  on the Hedera local node in the task, and if either fails the owner is told before anything else (Q7).
- **Gas and size:** `GovGas` / `UAGas` rows old → new (§7.2); `size-baseline.json` old → new with the reason; the four PQZ sets
  (`at-set.sh`); layout pins regenerated.
- **Mutants** (one at a time, each must turn a test red): `initEnv` without the `FACTORY` check; without the once-lock; the
  implementation not locked; `chainUid` read from slot 1; the factory passing the creator's value instead of its own; the
  post-init `chainUid()` check dropped; `configureChain` without `onlyRegistrar` or callable twice; the genesis comparison
  inverted; `s` without `creatorId`, without `kind`, with the implementation; the proxy init code changed by one byte;
  `predictAddress` off the creation formula; `creatorId` from `tx.origin`; the router subject accepted from any caller;
  `validateEnv` skipped at release deploy; `eip712Domain()` reporting the immutable while the digest uses storage.

## 9. NET-ALL-22: draft of the new text (owner rule; lands with the docs task)

Written for `docs/networks/README.md`; links are left out of the draft and restored when it lands.

> **NET-ALL-22** — **A chain is identified by `(chain_key, chain_uid)`, never by its chain id alone, and `chain_uid` is the
> `salt` of every SCaaS signing domain.** `chain_uid` (`bytes32`, `≠ 0`) is the chain's genesis block hash as its RPC reports
> it (EVM, Hedera). On EVM and Hedera every SCaaS contract that checks a signature or binds a digest to a chain exposes it as
> `chainUid()`, from one of two sources, the same on every chain:
>
> - **Factory-made contracts and the factory** are chain-neutral bytecode at the same address on every chain
>   (CTR-TOK-29). The factory's `chain_uid` is written once by its registrar after
>   the deterministic deploy and must equal the genesis hash whenever the EVM can still prove it (`BLOCKHASH(0)`, EIP-2935);
>   every token, DEX and generic instance receives the factory's value once, in its creating call, in its own storage, and the
>   factory refuses an instance that reports another. An implementation holds none (`chainUid()` = 0) and is never a signing
>   target.
> - **Every other SCaaS contract** (the Universal Account registry, the governance router, the subject account factory and its
>   accounts, mandate wallets) takes it as a constructor immutable, and so has a different address on each chain.
>
> It is the `salt` of every SCaaS EIP-712 domain `(name, version, chainId, verifyingContract, salt = chain_uid)`, ERC-5267 fields
> `0x1f`, and is bound into the `metatx-cancel` digest and the confidential token's non-EIP-712 digests beside `chainId`. The
> EVM cannot read its genesis hash after block 256 (8,191 with EIP-2935), so a contract cannot always *prove* `chain_uid`: the
> deploy script reads it from the RPC quorum and `chain-uids.json`, and the deploy gate and the node require every `chainUid()`
> = the RPC's genesis hash = the chain profile (NODE-GW-07, NET-EVM-05).
> A wrong value makes correct signatures fail; it is unsafe only if it equals another chain's `chain_uid`, which that comparison
> excludes; on the factory it is permanent for the canonical address on that chain, so the gate dry-runs it first.
>
> **Addresses.** An instance's address depends only on the factory, the creator's UA id, the class, the kind and the salt
> (CREATE3), so a creator has the same token, DEX or instance address on every chain; the address says nothing about the version,
> the code or the configuration on a given chain, which are read per chain. Safety does not rest on the address: the salt is in
> every digest. Limit: a genesis hash does not separate the two branches of a fork (NET-ALL-25). Non-EVM families
> unchanged (…, as today). Why: chain ids are a registry convention, not unique (…, as today).

Also changed in the docs task: [NET-EVM-05](../../networks/evm.md#NET-EVM-05) (the factory, libraries and releases at the same
address everywhere; contracts with a `chain_uid` constructor per chain), [CTR-TOK-03](../../contracts/token-wrappers.md#CTR-TOK-03)
(constructor, `configureChain`), [CTR-TOK-25](../../contracts/token-wrappers.md#CTR-TOK-25) (creation order, `initEnv`, CREATE3,
`predictAddress`), [CTR-GEN-05](../../contracts/README.md#CTR-GEN-05) (the separator's source), the new CTR-TOK-29 (this spec
§2–§5), `decisions.md` entries for NET-ALL-22 (Change, owner yes 2026-11-07) and CTR-TOK-29, and the integration guides' lines
that say the factory's constructor takes `chain_uid`.

## 10. Order, tasks, questions

### 10.1 Place

**Recommend: with the factory index group, after 3g, before 3f.** Both rewrite the same creation paths (`_create`, `createDex`,
`createInstance`, the record's creator field), so building CREATE3 and `creatorId` before T70 avoids writing the generic path
twice; and 3f (T44–T50) adds code to `PqzCore` / `PqzLayer` / the PQZ kinds that would otherwise be written against immutables
and moved again. Kind 13's growth falls inside the size window that T66b closes. Order: T67 → **T71** → T70 → **T72** → **T73**
→ **T74** → T68 (mutants, with this spec's), **T75** beside (docs, lands with T19), **T76** after T71, before T68 (S3 answered
"signing UA", so T76 is in). **Owner 2026-11-07:** approved as recommended.

### 10.2 Tasks (plan [`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md); T71–T76 are free)

| # | Task | Size (agent-days) |
|---|---|---|
| T71 | `OpenFactory`: constructor `(registrar)`, `configureChain` with the genesis check, `Create3`, `s` with class and kind, `creatorId` in the record and lists (Q1), `predictAddress`, `Env` without `factory` / `chainUid`, `validateEnv` at release deploy; factory tests | 1.5 |
| T72 | `ChainEnv` in every token kind: `SaltedEIP712` hook, `UAMetaTxBase` / `MetaTokenBase` / `GovernanceBase` / `ZetherLayer` / `PqzLayer` getters, `initEnv`, `validateEnv` in the kinds' libraries, constructors `(factory_, implArgs)`, layout pins, the whole suite and the four PQZ sets, gas pins old → new, size old → new | 3 |
| T73 | DEX and the generic surface (`initEnv` in `NoteKind` / `RosterKind`, `PqChat`'s PC0 note); deploy scripts (`DeployBase`, Hedera, `e2e.py`): factory by `0x4e59`, `configureChain` dry run, release list, the gate's new checks | 1.5 |
| T74 | the two-chain tests (§8) on forks and two `anvil`s, the Hedera local-node check, `create3_kat.json` and its readers in Solidity, `clientkeys`, `ua-rs`; KATs with factory-predicted addresses regenerated | 2 |
| T76 | (S3) the router's `mtxCreateToken` / `mtxCreateDex` / `mtxCreateInstance`, the factory's router path, typed vectors rows; tests: native and derived creators, replay on another chain refused | 1.5 |
| T68 | + this spec's mutants (§8) | +0.5 |
| T75 | docs: NET-ALL-22 (§9), NET-EVM-05, CTR-TOK-03 / -25 / -29, CTR-GEN-05, `decisions.md`, integration guides | 1 |
| | **Total** | **11** |

### 10.3 Questions for the owner (each with a recommendation)

**Owner 2026-11-07: all eight answered as recommended:** (1) S3: the signing UA is the creator, `creatorId` `bytes32` in the
index, T76 in; (2) the cost of B accepted; (3) the registrar at the same address on every chain, an EOA or a deterministically
deployed contract, the gate checks its code hash; (4) the wrong-`chainUid` risk accepted, with the gate's dry run and quorum
check and the genesis check; (5) `ChainEnv` in instance storage (S); (6) the registry, router, subject account factory and
verifiers keep per-chain addresses this round; (7) Hedera checked in T74, the owner rules on any exception before T72 ends;
(8) `ChainEnv.params` for a generic class's chain values, first user `PqChat`'s code-size limit.

1. **S3, the creator identity:** the signing UA (via the router, §4.4) or the submitter. **Recommend the signing UA**; it also
   changes the approved index's `creator` to a `bytes32 creatorId` (three slots kept) and `initialize`'s creator argument.
2. **The cost of B:** ≈ +4.2 k regular gas per signed transaction (two cold `SLOAD`s), +2.1 k per further field touched, and
   ≈ +0.49–0.97 M state gas per creation (CREATE3 proxy and `ChainEnv` slots). **Recommend: accept**; it is the price of one
   bytecode and one address on every chain.
3. **The registrar's address is the same on every chain** (the factory's only constructor argument): an EOA, or a contract
   deployed deterministically with its owners in its init code before the factory is configured there. **Recommend yes**, with the
   gate's code-hash check (§3.4).
4. **A misconfigured `chainUid` burns the canonical factory address on that chain** (no redeploy at the same address).
   **Recommend: accept**, with the gate's dry run and quorum check and the on-chain genesis proof on young chains (§3.3).
5. **Storage (S) or a shared env contract (P)** for `ChainEnv` (§2.3). **Recommend S**: cheaper per call, no extra pattern; P only
   if mass creation of confidential tokens dominates.
6. **The registry, router, subject account factory and verifiers stay per-chain addresses** (constructors with `chain_uid`).
   **Recommend: yes for this round**; they are values in `ChainEnv`, not code, so A and B hold without them. Making them
   chain-neutral too (same registry and subject account addresses everywhere) is its own spec if wanted.
7. **Hedera** joins only if its `CREATE` address derivation and `0x4e59…956c` are confirmed (T74). **Recommend:** if either fails,
   Hedera keeps the per-chain addresses for its instances and the owner rules on the exception before T72 ends (a split by chain
   is otherwise refused by the rules).
8. **`ChainEnv.params`** (two `bytes32` chain values by documented position for a generic class, first user `PqChat`'s
   code-size limit). **Recommend yes**: without a slot for a chain value, a new class with one needs a factory change, the thing
   index §8 rules out.
