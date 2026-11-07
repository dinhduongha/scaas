# Chain-neutral releases: the same factory, release and instance addresses on every chain

**Status:** SPECIFIED, **approved by the owner 2026-11-07 (option I); Fable review applied** (decisions A and B; the eight
questions of §10.3 answered as recommended, then question 5 overridden by option I: `ChainEnv` appended to each clone's code,
§2; the Fable review's findings, no P0, applied as listed in §11). Nothing is built. Companion of the factory index spec
[`2026-11-07-factory-contract-index.md`](2026-11-07-factory-contract-index.md) (index §1–§7 and extension §8 approved; S3's
`creatorId` written into it): this spec changes its creation paths (§8.4 step 3, `predictAddress`) and every factory-made kind.
Branch `ua-mtx-merge`. Proposed rule **CTR-TOK-29** (`docs_check.py resolve` reports it unknown; CTR-TOK-28 is §8's) and a
change of [NET-ALL-22](../../networks/README.md#NET-ALL-22) (draft in §9). **Everything cryptographic here is UNAUDITED.**

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
- **Option I** (same day, after §2.3's comparison): the factory writes the instance's chain values by **appending them to the
  clone's runtime code** (an EIP-1167 clone with immutable arguments, Solady `LibClone` layout); the implementation reads them with
  `EXTCODECOPY(address(this))`. No `initEnv`, no storage slot, no lock, no re-initialization window, no layout pin: immutable by
  construction. The clone's code hash differs per chain (allowed).

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
| `deps` | `ZetherLayer` `TRANSFER_VERIFIER`, `BURN_VERIFIER`, `_DISCLOSURE`; `PqzLayer.PQZ_VERIFIER` | per release and chain | Zether / PQZ proof entries |
| `libs`, `libCodeHashes` | linked addresses in the bytecode; hashes checked by the factory at release deploy | no (§5) | every linked call |
| `implArgs` | `RegulatedBase.REGISTRY_CODEHASH` (the canonical `ComplianceRegistry` runtime hash) | no: `ComplianceRegistry` keeps `admin` in storage and has no immutable, so its runtime is the same everywhere | `initialize` |
| `noticePeriod` | `OpenFactory` immutable | **yes** (7622: minutes; a mainnet: ≥ 3 days, `DeployBase._checkedNotice`) | `deployImplementation`, `deployRelease` |

Unchanged and out of scope (not factory-made; their constructors keep `chain_uid` as an immutable, so they keep a per-chain
address, NET-ALL-22 as today): `UARegistry`, `GovernanceRouter`, `SmartKeyAccountFactory` and accounts, `MandateWallet`,
`MtxRelayFee` (stateless, no `chain_uid`), the verifiers. Their addresses are **values** an instance carries (§2), not code, so
they do not break A or B (§10.3 Q6).

## 2. The instance's chain environment (decision B, option I)

### 2.1 What leaves the constructor, and where it goes

```solidity
/// The chain values of one instance (CTR-TOK-29). The factory composes it and appends it to the clone's runtime code;
/// it is never a parameter of an entry a caller reaches.
struct ChainEnv {
    bytes32 chainUid;            // the factory's own (§3), never the creator's or the registrar's
    address registry;            // this chain's UARegistry (0 = no UA path)
    address govRouter;           // this chain's GovernanceRouter: the factory's one-time value (§3.1), 0 = none
    address smartKeyAccountImpl; // 0 = none
    bool hedera;
    address[] deps;              // 0..4, by documented position, as Env.deps today (ENV_ZETHER_*, ENV_PQZ_VERIFIER)
    bytes32[] params;            // 0..2, chain values of a generic class by documented position (PqChat: [0] = code-size limit)
}
/// On every factory-made implementation (and so every clone):
function chainEnv() external view returns (ChainEnv memory);  // decoded from the clone's code; all zero on the implementation
function validateEnv(ChainEnv calldata env) external view;    // the constructor checks of today; reverts BadInit
```

**The clone.** The runtime code of every factory-made instance is the 45-byte EIP-1167 proxy followed by the encoded `ChainEnv`
(Solady `LibClone`'s "ERC-1167 with immutable arguments" layout; an in-repo internal library, no new dependency):

```
363d3d373d3d3d363d73 ‖ implementation (20 B) ‖ 5af43d82803e903d91602b57fd5bf3   // 45 B, never reaches the bytes below
‖ chainUid (32) ‖ registry (20) ‖ govRouter (20) ‖ smartKeyAccountImpl (20) ‖ hedera (1)   // head, 93 B, fixed offsets
‖ nDeps (1) ‖ deps (20 × nDeps) ‖ nParams (1) ‖ params (32 × nParams)                       // counted tails
```

The proxy forwards calldata unchanged; the trailing bytes are data, never executed (the proxy's only jump targets `0x2b`).
The layout is one fixed format, pinned byte for byte in `create3_kat.json` (§6.4) and decoded by one internal library,
`ChainEnvCode` (constants for each offset, one decoder). Explicit parameters: the format is the contract's own immutable data,
written only by the factory and exposed typed (`chainEnv()`); no entry takes it as a blob. Sizes: 95 B for a plain token kind
and the DEX, 115 B for the PQZ kinds (one dep), 175 B for the Zether kinds (four deps), 127 B for `PqChat` (one param).

**Reading.** `EXTCODECOPY(address(this), 0x2d + offset, n)`: under the clone's `DELEGATECALL`, `address(this)` is the clone, the
account the transaction called, so it is warm; a copy costs 100 gas + 3 per word + memory (≈ 0.1 k for the 93 B head, read once
per call where a call needs more than `chainUid`). On the implementation itself (`address(this) == _SELF`, an immutable every kind
already has) the reader returns an all-zero `ChainEnv` without reading: the implementation's own bytes after offset 45 are code,
not an env.

- **`FACTORY` stays an immutable**, from a chain-neutral constructor argument `factory_` (the factory is at one address on every
  chain, decision A, so the value and the code hash are the same everywhere). `createTokenUnregistered` keeps working: an
  unregistered implementation also names the factory, and the factory still checks `factory() == this`.
- **Constructor after B:** `constructor(address factory_, bytes implArgs)` for the token kinds and the DEX; `constructor(ReleaseId
  id, address factory_, bytes implArgs)` for a generic class (index spec §8.2 without `envVersion` and `Env`). `implArgs` holds
  only values that are the same on every chain (today: `REGISTRY_CODEHASH`); a chain value goes into `ChainEnv`. The constructor
  keeps `TokenStore.initialized = true` (or the class's own lock), so the implementation cannot be `initialize`d.
- **`initialize` requires its env** (Fable P3-4): it refuses unless `address(this) != _SELF`, `extcodesize(address(this))` equals
  45 + the length the encoded counts give (at most 4 deps, 2 params) and `chainUid ≠ 0` (`EnvMissing`); `msg.sender == FACTORY`
  and the `initialized` lock stay. A clone someone makes outside the factory (with or without forged trailing bytes) cannot be
  initialized, is in no index and is refused by the node (`isRegisteredToken`).
- **The constructor checks of today move to `validateEnv`** (`ZetherLayer`: four deps, one proof system, roles not swapped, not
  Hedera, registry has code; `PqzLayer`: one dep, not Hedera; `NormalPqzToken`: registry has code). The factory calls it by
  `staticcall` once per release and chain, at release deployment, so a creation does not pay for it. Kinds 10–13 put this block
  and the env reader in their linked libraries (`ZetherLib`, `PqzStateLib`, `RegulatedLib`) to hold their size (§7.1).
- **The registry and router checks move to the factory** (Fable P3-1): `publishEnv` refuses a `registry ≠ 0` whose `chainUid()`
  is not the factory's (today's per-creation `UARegistryChainUid` in `MetaTokenBase.initialize`, now once per env), and
  `configureChain` refuses a `govRouter ≠ 0` whose `chainUid()` differs. The published `Env` carries neither `govRouter` nor
  `chainUid` nor `factory`: the factory fills all three.

### 2.2 How each kind reads them

`SaltedEIP712` gets one internal hook, `_chainUid()`: the code read for factory-made contracts, the immutable for the others (the
registry, the router, accounts, wallets keep their constructor). For factory-made contracts `_chainUid()` **reverts
`ChainUidZero` when the value is 0** (Fable P2-1), so the implementation, which reads an all-zero env, can never verify a
signature or build a domain: `mtxExecute` and every signed entry on it revert. `UAMetaTxBase._mtxCtx()` (the one place that
builds `MtxPipelineLib.Ctx`) reads the head once; `GovernanceBase`'s router check reads `govRouter`; `ZetherLayer` / `PqzLayer`
read their deps (`ZetherLib`'s copy of the transfer verifier into its own storage at `init` is dropped: it reads the code).
`_SMART_KEY_CLONE_CODEHASH` is recomputed from `smartKeyAccountImpl` when used (a 45 B `keccak256`, ≈ 50 gas, only on the
ERC-1271 path). Every view that answers an immutable today (`chainUid()`, `eip712Domain()`, `verifier()`, `burnVerifier()`,
`IS_HEDERA`, `GOV_ROUTER`, `FACTORY`) keeps its selector and answer on a clone. On the implementation `chainUid()` answers 0 (a
view, no revert); the node's guard ([NODE-GW-07](../../node/gateway.md#NODE-GW-07)) refuses a target whose `chainUid()` is not the
chain's.

### 2.3 Four placements, compared (I chosen by the owner; S, F, P rejected)

| | **I: appended to the clone's code (owner)** | S: instance storage | F: read from the factory at run time | P: one SSTORE2 env contract per env, pointer in the instance |
|---|---|---|---|---|
| Per signed call | warm `EXTCODECOPY` ≈ **+0.1–0.2 k** | 2 cold `SLOAD` ≈ +4.2 k | cold `CALL` to the factory + its `SLOAD`s ≈ +7–9 k | 1 `SLOAD` + cold `EXTCODECOPY` ≈ +4.8 k |
| Per creation | 95–175 B of code × 1,530 ≈ **0.15–0.27 M state** | 3–8 slots ≈ 0.29–0.78 M state, plus an `initEnv` call | 0–1 slot | 1 slot |
| Written | in the creating `CREATE`, by construction | `initEnv`, once, behind a lock | never | `initEnv`, once |
| Re-initialization window, lock, layout pin | none | lock, a namespace pin | none | lock |
| Trust | self-contained, immutable | self-contained, written once | a live edge to the factory on every call | as S |

I is the cheapest on both axes and has nothing to protect after creation. Its one visible difference: an instance's code hash is
`keccak256(proxy ‖ ChainEnv)`, so it differs per chain and per env; nothing in the system keys on a clone's code hash (the node
and the factory key on `infoOf`), and any check written against the plain 45-byte form must take the appended env (T74 greps).

### 2.4 The domain separator: no cache

Today a clone already rebuilds the separator on every call: `SaltedEIP712` caches it for `_cachedThis`, the implementation's
address, which a clone never equals. After B the rebuild reads `chainUid` from the clone's code (≈ 0.1 k) and hashes six words
(≈ 0.1 k). A cache would need storage (a slot, ≈ 97,920 state gas, and a cold `SLOAD` dearer than the read it saves). **No
cache.** Name and version stay immutables (constants per kind, the same on every chain).

## 3. Replay protection: who sets `chainUid`, what stops a wrong value

### 3.1 The factory (registrar, once)

```solidity
constructor(address registrar_);   // the only constructor argument; the same on every chain (§3.4)
function configureChain(bytes32 chainUid_, uint64 noticePeriod_, address govRouter_, uint256 refBlock, bytes32 refHash)
    external;                                                // onlyRegistrar, once
function chainUid() external view returns (bytes32);       // 0 until configured
function noticePeriod() external view returns (uint64);
function govRouter() external view returns (address);      // the S3 path (§4.4) and every instance's ChainEnv; 0 = none
error ChainNotConfigured();       // every creation, publish and deploy entry before configureChain
error ChainAlreadyConfigured();
error ChainUidNotGenesis(bytes32 given, bytes32 provable);
error RefBlockMismatch(uint256 refBlock, bytes32 given, bytes32 actual);   // actual 0: the chain cannot answer
```

`configureChain` refuses `chainUid_ == 0` (`ChainUidZero`), `noticePeriod_ > MAX_NOTICE_PERIOD`, a second call, a `govRouter_`
whose `chainUid()` differs, and:

- **Genesis, when provable.** `blockhash(0)` when `block.number ≤ 256`; else the EIP-2935 history contract queried with the raw
  32-byte block number 0 (Fable P3-2: a revert or a return that is not 32 bytes means "nothing to compare", never a failure).
  When either answers, the value must equal it. One rule on every chain: "if the chain can prove its genesis hash, the value must
  equal it". A chain configured within 256 blocks of genesis (22776 at launch, a fresh customer chain) is proven on-chain; the
  EIP-2935 window is 8,191 blocks, about 4.5 h at 2 s blocks and 11.4 h at the SCaaS testnet's 5 s, which a multisig registrar
  must plan its signatures around.
- **The transaction belongs to this chain** (Fable P1-1). `refBlock ≠ 0` requires the hash of `refBlock` on this chain, read by
  `BLOCKHASH`, else by EIP-2935, to equal `refHash`; no answer counts as a mismatch (a supplied reference must match). The
  deploy script sets `refBlock` to a recent block of the target chain read from its RPC quorum. A chain whose `BLOCKHASH` is not
  its own chain's block hash (Arbitrum's pseudo-blockhash, any chain that documents it so) supplies `refBlock = 0` and relies on
  the gate order below. One rule: a supplied reference must match.

### 3.2 Each instance (factory, by construction)

The factory composes `ChainEnv` from its own `chainUid` and `govRouter` and the release's published env, encodes it into the
clone's code in the creating call, then after `initialize` / `initCall` requires `chainUid()` (tokens, DEX) or
`factoryInfo().chainUid` (generic) of the clone to equal its own, else the whole creation reverts (`ChainUidMismatch`). For this
repository's kinds the post-check is redundant with the code read; it stays for unregistered implementations, whose code is
unvetted as today: what they report as their domain salt is the factory's.

### 3.3 The trust, stated

- **Same as today in substance.** Today the deploy script reads the genesis hash from the RPC and passes it as a constructor
  argument; the deploy gate and the node check every `chainUid()` against the RPC and the chain profile
  ([NET-EVM-05](../../networks/evm.md#NET-EVM-05), [NODE-GW-07](../../node/gateway.md#NODE-GW-07)). After B the registrar's
  transaction carries the same value, the same gate and node checks apply, plus the on-chain proofs of §3.1.
- **Replay between two chains with one chain id** (Fable P1-1). EIP-155 binds a transaction to a chain id, not to a chain: the
  registrar's `configureChain` on chain X is a valid transaction on a sibling Y with the same chain id (7622-style collisions,
  ETH/ETC-style forks) if the registrar's nonce matches there. Replayed, it binds Y's canonical factory permanently to X's
  `chain_uid`; then every instance on Y carries X's salt at the **same address** (decision A) under the same chain id, so every
  signature for an instance on X is valid on its twin on Y and back: full replay between the two chains. The reference block
  stops it (Y's block hash differs). Where the reference is unavailable, the gate's order stops it: **on a chain id shared by
  several live chains, the gate configures the factory on every one of them, each with its own reference, before any other
  registrar transaction on any of them**; a later replay then meets `ChainAlreadyConfigured`, and a replayed `publishEnv` names a
  registry whose `chainUid()` is not that factory's (§2.1) and is refused. `chain-uids.json` lists the siblings.
- **A wrong value is permanent** for the canonical factory address on that chain: today a mistaken constructor argument means a
  new factory at a new address; after A the canonical address is taken and cannot be redeployed (CREATE2 collision). The gate
  dry-runs `configureChain` by `eth_call`, compares with ≥ the profile's RPC quorum and `chain-uids.json`, and only then sends it.
- **What a wrong value does** (unchanged from NET-ALL-22): correct signatures fail; it is unsafe only if it equals another
  chain's `chain_uid` (the replay case above), which the gate's cross-profile check and the reference block exclude.
- **Front-running.** Anyone can deploy the factory's init code through the deterministic deployer on any chain; that is the same
  contract with the same registrar, so it is harmless. Only the registrar can `configureChain`; until it does, the factory
  refuses everything.
- **Why it is still one rule on every chain:** every factory-made contract takes `chain_uid` from its factory; every factory
  takes it from its registrar once, checked against the chain's provable genesis and a supplied reference block whenever the
  chain can answer. No chain kind is special-cased; a chain that cannot answer simply supplies nothing to compare.

### 3.4 The registrar's address

The registrar is the factory's only constructor argument, so it must be the same address on every chain, under the same
control. An EOA is that by construction. A contract registrar (the multisig / UA `msig` planned before mainnet) must itself be
deployed deterministically with its owners in its init code, before the factory is configured on that chain; otherwise its
address on another chain may belong to someone else (the 2022 Wintermute / Optimism loss: a Safe address deployed on L1 and not
on L2 was taken there), and that person would configure the canonical factory there. The deploy gate checks the registrar's code
hash per chain against the release list (§6.2).

## 4. CREATE3 (decision A)

### 4.1 Construction

An internal library `Create3` (Solady's and 0xSequence's layout; no new dependency):

1. `proxy = CREATE2(factory, s, PROXY_INITCODE)` with the fixed 16-byte init code `67363d3d37363d34f03d5260086018f3`, which
   deposits the 8-byte runtime `363d3d37363d34f0` ("`CREATE` with my calldata as init code").
2. The factory calls `proxy` with the init code of the clone **with its appended `ChainEnv`** (the `LibClone` init-code prefix,
   then the 45 B proxy and the env bytes of §2.1); the proxy `CREATE`s it at nonce 1.
3. `instance = address(keccak256(rlp([proxy, 1]))[12:])`: a function of the factory address and `s` only. The appended env changes
   the instance's code, never its address.
4. The factory requires `instance.code.length != 0` after the proxy call (`InstanceNotCreated`, Fable P2-5): a `CREATE` that
   fails inside the proxy returns address 0 there without reverting the outer call.

`s = keccak256(abi.encode(creatorId, contractClass, kind, salt))`, with `contractClass` 1 / `kind` the `TokenKind` for
`createToken` and `createTokenUnregistered`, 2 / 0 for `createDex`, the release's class and kind for `createInstance`. Neither the
implementation, the version nor the env is in it. The proxy stays (no `SELFDESTRUCT`, index spec §8.5). **Salt used** is checked
first on the proxy: `proxy.code.length != 0` → `SaltAlreadyUsed(predicted)` (the proxy exists exactly when `s` was used), with the
index record checked as well.

### 4.2 `predict…`

```solidity
function predictAddress(bytes32 creatorId, uint16 contractClass, uint16 kind, bytes32 salt) external view returns (address);
```

One view for every path, unaffected by option I (the env is code, not address). Today's `predictAddress(implementation,
creator, salt)` is removed with the factory it belongs to (the old factory moves to `legacy/`; it would return an address no
path creates any more). Clients compute the same address from the vector rows of §6.4.

### 4.3 Same address is not same content

The address fixes the factory, the creator, class and kind, never the version, the implementation, the env or the
`TokenConfig`. On two chains the same address may be version 1 on one and version 3 on the other, with other verifiers, another
owner, another name, or a registered token on one and an unregistered one (version 0, same class and kind) on the other; or
exist on one chain only. A wallet or a node never infers anything from the address: it reads `infoOf(addr)` (class, kind,
version, creator), `releaseOf` (implementation, code hash, env hash) and the instance's own views **per chain**. Docs and client
copy say so wherever the shared address is shown.

### 4.4 Creator identity (S3): the signing UA

**Owner 2026-11-07: the UA that signed** (as recommended; T76 is in). `creatorId` is a `bytes32` UA id
([CTR-UA-03](../../contracts/accounts.md#CTR-UA-03)): a native caller is `pad(msg.sender)`; a derived UA (a PQ key, an `msig`) is
its registered id. The factory learns it two ways only:

1. **Direct call:** `creatorId = bytes32(uint256(uint160(msg.sender)))`.
2. **Signed, relayed:** the chain's `GovernanceRouter` gains three typed ops, `mtxCreateToken`, `mtxCreateDex`,
   `mtxCreateInstance` (`UAEnvelope`, then the creation's named parameters, `initHash = keccak256(initArgs or initCall)`, the
   `UASig`), verified as every router op today (`MtxPipelineLib.preNamedUA`: a native id by its own key, a derived id through
   `requireAuthorized(PURPOSE_METATX)`, lane nonce, `validUntil`, fee mode `NONE`, relayable at fee 0). The router calls the
   factory with the transient `subject()` set; the factory, seeing `msg.sender == govRouter()` (its one-time value, §3.1), reads
   `creatorId = IGovernanceRouter(govRouter).subject()` **once, at entry**, refuses 0, and uses that value for `s`, the record
   and `creating()`. The factory holds no signature code, no domain and no nonce. A native id through the router gets
   `pad(addr)`, the same `creatorId` as a direct call, so the same address.

A creation nested inside an `initialize` is called by the instance, not the router, so its creator is `pad(instance)` (the router
names its subject only to its live target, the factory, and the factory does not ask for a nested call).

Why not the submitter: a relayer, a backend or a smart account would own the customer's address on every chain and could take it
first on a chain the customer has not used yet. Why the UA id is right for A: a native EOA and a derived UA are bound to keys, and
the UA id is chain-independent ([CTR-UA-07](../../contracts/accounts.md#CTR-UA-07)), so the same signer gets the same address
everywhere. **Limit:** a contract creator (a smart account, a multisig) calling directly is `pad(contract)`; that address may
belong to someone else on another chain (§3.4), who can then create at "its" addresses there. Stated, not prevented: refusing
contract creators would break smart accounts.

**In the index and the kinds:** `Created.creatorId` (`bytes32`), the record still three slots; `_byCreator`, `contractsOfCreator`,
`_wrappers`, `getWrapper*` and `creating()` keyed by `bytes32`; `creatorOf(token)` answers the address for a native id and 0 for a
derived one. Tokens' and the DEX's `initialize` take `bytes32 creatorId`; **`TokenStore.creator` stays an `address`** (Fable
P2-3): the native id's address, or 0 for a derived creator, whose id lives in the factory's record. No slot is added and the
token's layout pin does not move for it.

### 4.5 Squatting

- **By a third party:** impossible on any path: `creatorId` is in `s` and authenticated (`msg.sender` or the router's verified
  subject). A signed creation is chain-bound (the router's domain carries `chain_uid`), so a relayer cannot replay it on another
  chain.
- **By the creator against itself:** a creator may put another kind or an unregistered token at its own address on another chain
  (§4.3).
- **Contract creators:** §4.4 limit.

## 5. Libraries: chain-neutral by default

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
library call fail on that chain); they are never part of an instance's env.

**Fallback, only for a library that cannot be made chain-neutral:** its address becomes a `ChainEnv` value and the kind calls it
by an explicit `DELEGATECALL` through an interface. Costs: a read per call (≈ +0.1 k from the clone's code), ABI encoding
instead of the linker's direct call, every call site rewritten. Risk: a `DELEGATECALL` to an address taken from data is arbitrary
code over the token's storage; only the factory writes it, from the registrar's published env, and the release review must
accept it. No library needs it today.

## 6. What changes, per component

### 6.1 Contracts

| Component | Change |
|---|---|
| `OpenFactory` | constructor `(registrar)`; `configureChain` (§3.1); `chainUid`, `noticePeriod`, `govRouter` from storage; `Create3` with the clone-with-env init code on `_create`, `createDex`, `createInstance`; `InstanceNotCreated`; `creatorId` incl. the router path; `predictAddress` (§4.2); `_deploy` appends `abi.encode(address(this), implArgs)` (or `(id, address(this), implArgs)`), so a release's address is `CREATE2(factory, keccak256(kind, version), initcode ‖ args)`, the same on every chain for the same code; `_checkImplementation` checks `kind()`, `factory()` and `validateEnv(env)`, no longer `chainUid()`; the published `Env` loses `factory`, `chainUid`, `govRouter` (the factory fills them), `deps` at most 4, `params` at most 2; `publishEnv` checks `registry.chainUid()`; creation: CREATE3 → `initialize` / `initCall` → `chainUid()` post-check → index |
| `IFactoryToken`, `IOpenFactory` | `ChainEnv`, `chainEnv`, `validateEnv`; `initialize(bytes32 creatorId, uint64, bytes)`; the ABI changes of §6.3 |
| `SaltedEIP712` | `_chainUid()` hook (code read for factory-made, reverting on 0; immutable for the rest) |
| `UAMetaTxBase`, `ERC20MetaTx`, `MetaTokenBase`, `GovernanceBase` | immutables `_REGISTRY`, `IS_HEDERA`, `_SMART_KEY_CLONE_CODEHASH`, `SMART_KEY_ACCOUNT_IMPL`, `GOV_ROUTER` → `ChainEnvCode` reads; constructor `(factory_, implArgs)`; `initialize` requires its env (§2.1) |
| 12 token kinds (0–5, 8–13) | constructors per above; `ZetherLayer`, `PqzLayer` deps → code reads; constructor checks → `validateEnv`; kinds 10–13: reader and `validateEnv` body in their linked libraries; `RegulatedBase.REGISTRY_CODEHASH` stays an immutable (chain-neutral) |
| `SCaaSDex` | the same as a kind; `DexPuller` is `CREATE`d by the DEX at nonce 1, so it follows the DEX's address unchanged |
| `PqChat` (class 3, 3c) | constructor `(ReleaseId, factory_, implArgs)`; `chainUid`, registry and the code-size limit (`params[0]`, a chain value: 131,072 on 7622, 65,536 under EIP-7954) from the clone's code; index §8.8's PC0 row follows |
| Generic classes (index §8) | `factoryInfo().chainUid` from the code; `deployRelease` calls `validateEnv`; the acceptance mocks `NoteKind`, `RosterKind` read their env from code |
| Storage layout pins | **none move for the env** (option I); `TokenStore` unchanged (§4.4) |
| Typehashes, selectors of `mtx*` | unchanged (no domain field moves; only its source) |

### 6.2 Deploy scripts and the release list

`DeployBase`, `script/hedera/DeployHedera.s.sol`, `script/pqz/e2e.py`: the libraries by `0x4e59` (as today), the factory by
`0x4e59` with `(registrar)` only, then `configureChain` with a reference block after the dry run of §3.3 (on a shared chain id,
every sibling first), the registry and router as today (per-chain addresses), envs published with the chain's values, releases
from chain-neutral init code.

**The deterministic deployer is a chain requirement** (Fable P2-4): every chain that runs SCaaS must carry
`0x4e59…956c` (genesis alloc, its keyless transaction, or EIP-7997 once a chain has it). For 22776 the genesis alloc is no longer
optional: without it the canonical addresses cannot exist there (the owner's launch decision, now a precondition). Hedera:
`DeployHedera.s.sol` runs `_setup()`, which requires the deployer's code, before anything else; the only recorded run
(`runs/2026-11-01-typed-signing-c8-deploy-hedera-dry.txt`) was a local dry run on chain 31337, so its presence on a Hedera
network is unconfirmed (T74, Q7).

**The release list** (Fable P3-5): `smartcontracts/evm/releases.json`, one row per release `(class, kind, version, address,
runtime code hash, initcode hash, implArgs hash, library addresses and code hashes)` plus the factory's address and init-code
hash and the registrar's code hash. **Generator:** `DeployBase` writes it (`vm.writeJson`) from the first chain's deployment;
**reader:** the deploy gate on every later chain refuses a release, library, factory or registrar whose address or code hash
differs from the file; committed (no secrets, no machine paths), reviewed like a pin.

The deploy gate adds: factory address = the canonical one; `configureChain` with a matching reference; each release's address and
code hash = the release list's; `chainUid()` of the factory and of one test instance = the RPC's genesis hash; the registrar's
code hash (§3.4).

### 6.3 ABI changes (Fable P1-2) and the node

`creatorId` (`bytes32`) and the new factory entries change event and view ABIs that consumers decode:

| Item | Old | New |
|---|---|---|
| `TokenCreated`, `DexCreated` | `address indexed creator` | `bytes32 indexed creatorId` (for a native creator the 32-byte topic is the same padded word; the decoder type changes) |
| `creatorOf(address)` | `address` | `address` (native id; 0 for a derived creator, read `infoOf`) |
| `getWrapper`, `getWrapperCount`, `getWrapperAt` | `(address creator, …)` | `(bytes32 creatorId, …)`: new selectors |
| `predictAddress` | `(address implementation, address creator, bytes32 salt)` | `(bytes32 creatorId, uint16 contractClass, uint16 kind, bytes32 salt)` |
| token / DEX `initialize` | `(address creator, uint64, bytes)` | `(bytes32 creatorId, uint64, bytes)` (factory → kind only) |
| token `creator()` | `address` | `address`, unchanged (0 for a derived creator) |
| new | | `configureChain`, `govRouter()`, `chainEnv()`, `validateEnv(ChainEnv)`; the router's `mtxCreateToken` / `mtxCreateDex` / `mtxCreateInstance` (T76) |

- **`selector_audit.json`:** new rows for `configureChain`, `chainEnv`, `validateEnv`, the new `predictAddress`,
  `getWrapper*`, `initialize`, and the router's three create ops; the removed rows moved to legacy.
- **Node:** allow-lists (`typed.rs` `TYPED` / `PLAIN`, `guard.rs`) unchanged for the kinds (no `mtx*` selector of a kind moves);
  the guard's `chainUid()` call is unchanged and now reads code (an implementation answers 0 and is refused); `config.rs`'s
  `token_factory` is one address on every chain; `abi.rs` and the indexer decode `TokenCreated` / `DexCreated` with
  `bytes32 creatorId`. The router's create ops get `typed.rs` rows only when relaying creations is decided (index §8.11 Q11:
  not now; anyone submits them, fee 0).
- **Operator note** (AGENTS.md: job shape changes need one): any feed, job field or export that carries a factory creator changes
  from a 20-byte address to a 32-byte UA id in canonical form (a native id still written in its 20-byte form, CTR-UA-03); a
  consumer on the old shape sees derived creators as missing.

### 6.4 Vectors and clients

- **Digests:** no typehash or domain format changes, and the vectors' fixed `chain_uid` constants keep their values. What moves is
  any KAT whose `verifyingContract` or whose content is a factory-made or factory-derived address (Fable P3-3, candidates at
  `HEAD`): `test/vectors/dex_order_kat.json`, `vectors/governance/regulated_kat.json`, `test/vectors/metatx_kat.json`,
  `test/vectors/metatransfer_kat.json`, `test/vectors/hedera_kat.json`, `test/vectors/mandate_kat.json`,
  `test/vectors/smart_key_account_kat.json`, `vectors/metatx/paytax.json`, `test/vectors/smart_key_account_create2.json`
  (`test/vectors/plus_zero_gas.json` is not one). Each is checked; the ones that move are regenerated by their generators and every language reads the new rows.
- **New:** `smartcontracts/vectors/factory/create3_kat.json` (Fable P2-5) pins the CREATE3 proxy init code, the clone-with-env
  init code prefix, the `ChainEnv` code layout (a plain, a PQZ, a Zether and a `PqChat` env, byte for byte) and the derivation:
  rows `(factory, creatorId, contractClass, kind, salt) → (s, proxy, instance)` with a native and a derived `creatorId`, classes
  1/2/3, a non-zero salt. Read by the Solidity test, `clientkeys` and `ua-rs` (the signer, which predicts a creation's address).
- **Bindings:** `clientkeys` and every `ua-*` binding that carries the factory ABI (`ua-rs`, `ua-c`, `ua-cxx`, `ua-qt`, `ua-cs`,
  `ua-py`, `ua-go`, `ua-dart`, `ua-dart-frb`) take the §6.3 changes in one round; other `ua-*` read `predictAddress` over RPC.
- **Domains:** clients already read the domain from the instance (`eip712Domain()`, ERC-5267); nothing changes there.

## 7. Size and gas, on paper

### 7.1 Size (old → new is the task's to measure)

- **Init code shrinks** for every kind (no `Env` decode, no constructor checks): about −1 to −2 KB [estimate].
- **Runtime grows** per kind by `chainEnv()`, `validateEnv` (the moved constructor checks) and the code reader instead of
  `PUSH32` immutables; no `initEnv`, no `SSTORE`s: about **+0.2 to +0.8 KB** [estimate].
- **Kinds 10–13** (Fable P2-6) put the reader and `validateEnv`'s body in their linked libraries. **Kind 13**
  (`WrappedPqzRegulatedToken`) is 64,522 B in `size-baseline.json` at `HEAD` (64,969 B in the local build of 3g in progress),
  already over the 64,512 B stop line: with the library placement it lands at ≈ 64.7–65.5 KB [estimate]. It deploys on the SCaaS
  testnet (131,072 B, CTR-GOV-19) and stays inside the size window, pinned in `_above64KiB` ("owner 2026-11-07, removed by
  T66b"); T66b's target includes this growth. **A chain at EIP-7954's 65,536 B cannot take kind 13 until T66b.**
- **`OpenFactory`:** `configureChain`, `Create3`, the clone-with-env encoder, `creatorId`, the router path ≈ +1.5–2 KB on top of the
  index spec's ≈ 22–25 KB.

### 7.2 Gas (EIP-8037: 1,530 state gas per byte of code, ≈ 97,920 per new slot; [estimate] until the `GovGas` / `UAGas` rows)

| Operation | Today | After (option I) | Δ |
|---|---|---|---|
| Any `mtx*` with a signature check (native or UA), DEX order | immutables (≈ 3 gas each) | one warm `EXTCODECOPY` of the 93 B head | **≈ +0.1–0.2 k regular** |
| + governance entry via the router, ERC-1271 smart-key signer, Zether / PQZ dep | immutables | from the same copy, or one more copy | ≈ +0–0.1 k (the smart-key path + ≈ 50 for its hash) |
| `createToken`, plain kind | CREATE2 clone (≈ 0.25 M state) | + CREATE3 proxy (account and 8 B: ≈ 0.19 M state, ≈ +40–50 k regular) + 95 B env code (145,350 state) | **≈ +0.34 M state, ≈ +45 k regular** |
| `createToken`, PQZ kinds (115 B) / Zether kinds (175 B) | as above | as above | ≈ +0.37 M / ≈ +0.46 M state |
| `createDex` (95 B) / `createInstance` `PqChat` (127 B) | as above | as above | ≈ +0.34 M / ≈ +0.39 M state |
| `deployImplementation` / `deployRelease` | init code + ≈ 1 KB env | init code + 64 B; + `validateEnv` staticcall | smaller calldata, ≈ +5–20 k regular |
| `configureChain` | (constructor) | once per chain, 3 slots, ≤ 3 hash look-ups | ≈ +0.29 M state, once |

The CREATE3 proxy's 0.19 M is index §8.7's clone figure (≈ 0.25 M for an account and 45 B) less 45 B × 1,530, plus 8 B × 1,530.
Against the storage placement S (§2.3) option I saves ≈ 4 k per signed call and 0.24–0.51 M state gas per creation. A creation
stays far below any block limit (inclusion is regular + state, EIP-8037).

## 8. Tests and mutants

**Two chains** (`test/v2/ChainNeutral.t.sol` with forge forks, and a script test on two `anvil`s, which carry `0x4e59…956c`
by default): chain A id 31901, chain B id 31902 with another genesis timestamp (different genesis hash), and chain C with id
31901 and a third genesis (the NET-ALL-22 case: one chain id, two chains). On each: the libraries, the factory, `configureChain`
with that chain's genesis and a reference block, the registry and router, envs, releases of every kind and the DEX, and one
instance per path.

- **Same address:** the factory, every library, every release (address and `extcodehash` equal across A, B, C); one instance per
  path at the same address on A, B, C for the same `(creatorId, class, kind, salt)`; `predictAddress` equals the created address
  on every path; a different creator, class or kind gives another address; the version, the implementation and the env do not
  change it (v1 on A, v2 on B: same address); the instance's code hash differs between A and B and equals `keccak256(proxy ‖
  env)` from `create3_kat.json`; `chainEnv()` decodes to the factory's composition.
- **Signatures bound to their chain:** a signed `mtx*` built for the instance on A is refused on B and C (B: chain id and salt
  differ; C: only the salt differs), and accepted on A; the same for a UA signature, a DEX order and a router op;
  `eip712Domain()` differs exactly in `chainId` and `salt`.
- **Replayed `configureChain`** (Fable P3-6): the registrar's signed transaction for A sent raw to C (same chain id, same nonce):
  with a reference block it reverts `RefBlockMismatch`; with `refBlock = 0` it binds C to A's uid, and the test then shows the full
  replay (a signature for A's instance accepted on C's twin) — the evidence for the gate's order, which a script test asserts
  (siblings configured before any other registrar transaction).
- **Negatives, each with its positive control:** a creation, publish or deploy before `configureChain` (`ChainNotConfigured`); a
  second `configureChain`; by a non-registrar or a delegated registrar; `chainUid_ = 0`; a value ≠ `blockhash(0)` on a young
  chain (`ChainUidNotGenesis`); an EIP-2935 answer that reverts or is short treated as nothing to compare; a `govRouter_` or env
  `registry` naming another `chainUid()`; on the implementation: `initialize` refused, `mtxExecute` and every signed entry
  revert `ChainUidZero`, `chainUid()` answers 0 and the node's guard refuses it; a clone made outside the factory (no env, a
  truncated env, a forged env) cannot be initialized (`EnvMissing`, `NotFactory`); an env with 5 deps or 3 params refused by the
  factory; a second `initialize` refused; an instance whose `chainUid()` after init differs from the factory's (a mock
  implementation reporting another value: `ChainUidMismatch`); an env failing `validateEnv` (Zether deps swapped, a duplicated
  pair, Hedera with a confidential kind) refused at release deploy; the same `s` twice (`SaltAlreadyUsed` on the proxy), also
  across `createToken` and `createTokenUnregistered`; a clone init code that fails inside the proxy (`InstanceNotCreated`); the
  router path with `subject() = 0`; a router call from a non-router address claiming a subject.
- **Reentrancy under S3** (Fable P3-6): a test kind whose `initialize` calls `createToken`, inside a router-signed creation: the
  nested record's creator is `pad(instance)`, the outer one the signing UA (`subject()` read once at entry), `creating()` right
  in both and restored.
- **Hedera:** CREATE3 depends on `CREATE` addresses from a contract's nonce (HIP-729), on `EXTCODECOPY` of the executing account,
  and on `0x4e59…956c` being present; checked on the Hedera local node in T74, and if any fails the owner is told before T72 ends
  (Q7).
- **Gas and size:** `GovGas` / `UAGas` rows old → new (§7.2); `size-baseline.json` old → new with the reason; the four PQZ sets
  (`at-set.sh`); layout pins regenerated where `creatorId` moved a factory-side struct (none in the kinds).
- **Mutants** (one at a time, each must turn a test red): `_chainUid()` returning 0 instead of reverting (Fable P2-1); the
  `_SELF` guard of the reader dropped (the implementation reads its own code as an env); `initialize` without the env-presence
  check, without the `FACTORY` check, without the `initialized` lock (Fable P3-4); the reader at a wrong offset (head shifted by
  one byte); the deps count not bounded; the factory encoding the creator's or the registrar's value instead of its own
  `chainUid`; the post-init `chainUid()` check dropped; `InstanceNotCreated` dropped; the salt check on the record only (the
  proxy check dropped); `configureChain` without `onlyRegistrar`, callable twice, without the reference check, with the genesis
  comparison inverted, treating an EIP-2935 revert as a failure; `s` without `creatorId`, without `kind`, with the
  implementation or the env; the proxy init code changed by one byte; `predictAddress` off the creation formula; `creatorId` from
  `tx.origin`; the router subject accepted from any caller or read after `initialize`; `validateEnv` skipped at release deploy;
  `eip712Domain()` reporting another salt than the digest uses; `publishEnv` without the registry `chainUid()` check.

## 9. NET-ALL-22: draft of the new text (owner rule; lands with the docs task)

Written for `docs/networks/README.md`; links are left out of the draft and restored when it lands.

> **NET-ALL-22** — **A chain is identified by `(chain_key, chain_uid)`, never by its chain id alone, and `chain_uid` is the
> `salt` of every SCaaS signing domain.** `chain_uid` (`bytes32`, `≠ 0`) is the chain's genesis block hash as its RPC reports
> it (EVM, Hedera). On EVM and Hedera every SCaaS contract that checks a signature or binds a digest to a chain exposes it as
> `chainUid()`, from one of two sources, the same on every chain:
>
> - **Factory-made contracts and the factory** are chain-neutral bytecode at the same address on every chain (CTR-TOK-29). The
>   factory's `chain_uid` is written once by its registrar after the deterministic deploy and must equal the genesis hash
>   whenever the EVM can still prove it (`BLOCKHASH(0)`, EIP-2935), in a transaction tied to this chain by a reference block
>   hash whenever the chain can answer for it; every token, DEX and generic instance carries the factory's value in its own
>   code, appended by the factory when it is created, and the factory refuses an instance that reports another. An
>   implementation carries none (`chainUid()` = 0) and cannot sign.
> - **Every other SCaaS contract** (the Universal Account registry, the governance router, the subject account factory and its
>   accounts, mandate wallets) takes it as a constructor immutable, and so has a different address on each chain.
>
> It is the `salt` of every SCaaS EIP-712 domain `(name, version, chainId, verifyingContract, salt = chain_uid)`, ERC-5267 fields
> `0x1f`, and is bound into the `metatx-cancel` digest and the confidential token's non-EIP-712 digests beside `chainId`. The
> EVM cannot read its genesis hash after block 256 (8,191 with EIP-2935), so a contract cannot always *prove* `chain_uid`: the
> deploy script reads it from the RPC quorum and `chain-uids.json`, and the deploy gate and the node require every `chainUid()`
> = the RPC's genesis hash = the chain profile (NODE-GW-07, NET-EVM-05). On a chain id shared by several live chains the factory
> is configured on each of them before any other registrar transaction there, so a replayed configuration cannot bind one to the
> other's `chain_uid`. A wrong value makes correct signatures fail; it is unsafe only if it equals another chain's `chain_uid`,
> which those checks exclude; on the factory it is permanent for the canonical address on that chain, so the gate dry-runs it
> first.
>
> **Addresses.** An instance's address depends only on the factory, the creator's UA id, the class, the kind and the salt
> (CREATE3), so a creator has the same token, DEX or instance address on every chain; the address says nothing about the version,
> the code or the configuration on a given chain, which are read per chain. Safety does not rest on the address: the salt is in
> every digest. Limit: a genesis hash does not separate the two branches of a fork (NET-ALL-25). Non-EVM families unchanged (…,
> as today). Why: chain ids are a registry convention, not unique (…, as today).

Also changed in the docs task: [NET-EVM-05](../../networks/evm.md#NET-EVM-05) (the deterministic deployer a requirement of every
chain, 22776's genesis alloc included; the factory, libraries and releases at the same address everywhere; contracts with a
`chain_uid` constructor per chain; the release list and the gate's checks), [CTR-TOK-03](../../contracts/token-wrappers.md#CTR-TOK-03)
(constructor, `configureChain`), [CTR-TOK-25](../../contracts/token-wrappers.md#CTR-TOK-25) (creation order, the env in the clone's
code, CREATE3, `predictAddress`), [CTR-GEN-05](../../contracts/README.md#CTR-GEN-05) (the separator's source), the new CTR-TOK-29
(this spec §2–§5), `decisions.md` entries for NET-ALL-22 (Change, owner yes 2026-11-07) and CTR-TOK-29, and the integration
guides' lines that say the factory's constructor takes `chain_uid`.

## 10. Order, tasks, questions

### 10.1 Place

**With the factory index group, after 3g, before 3f** (owner 2026-11-07, approved as recommended). Both rewrite the same
creation paths (`_create`, `createDex`, `createInstance`, the record's creator field), and 3f (T44–T50) adds code to `PqzCore` /
`PqzLayer` / the PQZ kinds that would otherwise be written against immutables and moved again. Kind 13's growth falls inside the
size window that T66b closes. **T71 and T72 land as one segment** (Fable): no other task between them, and the gates run at T72's
end, since T71 alone leaves every kind on the old constructor. Order: T67 → **T71 + T72** → T70 → **T73** → **T74** → **T76** →
T68 (mutants, with this spec's), **T75** beside (docs, lands with T19).

### 10.2 Tasks (plan [`2026-11-04-ua-mtx-merge.md`](../plans/2026-11-04-ua-mtx-merge.md))

| # | Task | Size (agent-days) |
|---|---|---|
| T71 | `OpenFactory`: constructor `(registrar)`, `configureChain` with the genesis and reference-block checks (BLOCKHASH, EIP-2935), `govRouter`, `Create3` with the clone-with-env init code, `InstanceNotCreated`, the proxy salt check, `s` with class and kind, `creatorId`, `predictAddress`, `Env` without `factory` / `chainUid` / `govRouter`, `publishEnv`'s registry check, `validateEnv` at release deploy; factory tests | 2 |
| T72 | the env in every token kind: `ChainEnvCode` reader, `SaltedEIP712` hook (revert on 0), `UAMetaTxBase` / `MetaTokenBase` / `GovernanceBase` / `ZetherLayer` / `PqzLayer` reads, `initialize`'s env check, `validateEnv` (kinds 10–13 in their libraries), constructors `(factory_, implArgs)`, `initialize(bytes32 creatorId, …)`; the whole suite and the four PQZ sets, gas pins old → new, size old → new | 3.5 |
| T73 | DEX and the generic surface (`NoteKind` / `RosterKind` env reads, `PqChat`'s PC0 note); deploy scripts (`DeployBase`, Hedera, `e2e.py`): factory by `0x4e59`, `configureChain` dry run and reference, sibling order, `releases.json` generator and gate reader, the gate's new checks | 2 |
| T74 | the two-chain tests (§8) on forks and two `anvil`s, the replay test, the Hedera local-node check; `create3_kat.json` and its readers in Solidity, `clientkeys`, `ua-rs`; the §6.3 ABI in `clientkeys` and every `ua-*` binding, the node's `abi.rs` and indexer, `selector_audit.json` rows; the nine KATs checked and the moved ones regenerated; the operator note | 3 |
| T76 | (S3) the router's `mtxCreateToken` / `mtxCreateDex` / `mtxCreateInstance`, the factory's router path (`subject()` once at entry), typed vector rows; tests: native and derived creators, replay on another chain refused, the reentrant `initialize` | 1.5 |
| T68 | + this spec's mutants (§8) | +0.5 |
| T75 | docs: NET-ALL-22 (§9), NET-EVM-05, CTR-TOK-03 / -25 / -29, CTR-GEN-05, `decisions.md`, integration guides | 1 |
| | **Total** | **13.5** |

Against the storage design's 11 days: option I drops `initEnv`, its lock and the layout pin (−0.5 in T72), and the Fable
findings add the reference block and sibling order (T71, T73), the ABI round in every binding and the node (T74), the release
list (T73), and more negatives (+3).

### 10.3 Questions for the owner (each with a recommendation)

**Owner 2026-11-07: all eight answered as recommended:** (1) S3: the signing UA is the creator, `creatorId` `bytes32` in the
index, T76 in; (2) the cost of B accepted; (3) the registrar at the same address on every chain, an EOA or a deterministically
deployed contract, the gate checks its code hash; (4) the wrong-`chainUid` risk accepted, with the gate's dry run and quorum
check and the genesis check; (5) `ChainEnv` in instance storage (S) — **superseded the same day by option I** (appended to the
clone's code); (6) the registry, router, subject account factory and verifiers keep per-chain addresses this round; (7) Hedera
checked in T74, the owner rules on any exception before T72 ends; (8) `ChainEnv.params` for a generic class's chain values,
first user `PqChat`'s code-size limit.

1. **S3, the creator identity:** the signing UA (via the router, §4.4) or the submitter. **Recommend the signing UA**; the index
   record's creator becomes a `bytes32 creatorId` (three slots kept); `TokenStore.creator` stays an address (§4.4).
2. **The cost of B** under option I: ≈ +0.1–0.2 k regular gas per signed transaction and ≈ +0.34–0.46 M state gas per creation
   (CREATE3 proxy and the env's code bytes). **Recommend: accept.**
3. **The registrar's address is the same on every chain** (the factory's only constructor argument). **Recommend yes**, with the
   gate's code-hash check (§3.4).
4. **A misconfigured `chainUid` burns the canonical factory address on that chain**, and a replayed configuration on a sibling
   with the same chain id would make the two chains replay each other's signatures (§3.3). **Recommend: accept**, with the gate's
   dry run and quorum check, the on-chain genesis proof on young chains, the reference block, and the sibling order.
5. **Placement of `ChainEnv`:** option I (owner), §2.3.
6. **The registry, router, subject account factory and verifiers stay per-chain addresses.** **Recommend: yes for this round.**
7. **Hedera** joins only if its `CREATE` address derivation, `EXTCODECOPY` of the executing account and `0x4e59…956c` are
   confirmed (T74). **Recommend:** if any fails, the owner rules on the exception before T72 ends.
8. **`ChainEnv.params`.** **Recommend yes.**

Still open for the owner after the Fable review: nothing new is a decision; the sibling-order rule of §3.3 and the deterministic
deployer as a requirement for 22776 (§6.2) are consequences of A and B the owner should see before T73.

## 11. Fable review: findings and outcomes (no P0)

| Finding | Outcome |
|---|---|
| P1-1 replayed `configureChain` on a same-chain-id sibling → full replay | `refBlock` / `refHash` (§3.1), the sibling order and the consequence (§3.3), Q4, replay test (§8) |
| P1-2 `creatorId` changes event and view ABIs | §6.3 table, `selector_audit.json` rows, the node's `abi.rs` and indexer, every binding, operator note; T74 |
| P2-1 `_chainUid()` 0 on the implementation | reverts `ChainUidZero` (§2.2); mutant |
| P2-3 `TokenStore.creator` widening | stays `address` (§4.4); no slot |
| P2-4 the deterministic deployer | a chain requirement, 22776's alloc not optional; Hedera's evidence is a local dry run only (§6.2) |
| P2-5 CREATE3 failure and salt checks | `InstanceNotCreated`, the proxy-existence check, `create3_kat.json` pins (§4.1, §6.4) |
| P2-6 size of kinds 10–13 | reader and `validateEnv` in their libraries; kind 13 not on 65,536 B chains until T66b (§7.1) |
| P3-1 `govRouter` in the published env | filled by the factory from `configureChain`; router and registry `chainUid()` checked once (§2.1, §3.1) |
| P3-2 EIP-2935 details | raw 32-byte input; revert or short return = nothing to compare; the window per block time (§3.1) |
| P3-3 KAT candidates | the nine files of §6.4 |
| P3-4 `initialize` without env, double init | `EnvMissing`, lock kept, mutants (§2.1, §8) |
| P3-5 the release list | `smartcontracts/evm/releases.json`, generator and reader (§6.2, T73) |
| P3-6 missing tests | reentrant `initialize` under S3, replayed `configureChain` with and without reference, the implementation's `mtxExecute` (§8) |
| Size of T72 / T74; T71 + T72 one segment | T72 3.5 (option I's −0.5 against Fable's 4), T74 3; one segment (§10.1); total 13.5 |
