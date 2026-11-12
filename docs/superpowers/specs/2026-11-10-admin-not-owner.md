# Admin, not owner: the factory's record, UA admins, one name on every contract (round 3r) — design

**Status:** SPECIFIED, nothing built, **UNAUDITED**. Written 2026-11-10 for three owner rulings of the same day (§1); **the
owner answered Q1–Q6 and ruled the directory the same day (§10, §13)**, recorded in `decisions.md` as CTR-GOV-23 and its
Changes (§11). **Fable review 2026-11-10: approve with fixes, no P0**; every finding is applied below, each checked against the
code first, and tagged (Fable P1-1 …). **The owner's final ruling on P1-2 the same day: the admin
approves one release by hash, and anyone deploys it straight to the factory; a native admin's own deploy is its own approval
(§5.6).** The owner also ruled P2-5 (no usage restriction) and made the relay pair a write-once entry (§13). **Owner ruling, the same day,
added to the rename map: in `ComplianceRegistry` the "attester" becomes the "KYC provider"** (§4.1, §5.3.1), the party the
registry admin enables to write compliance rows; it is a UA `bytes32` as Q5 says. **And (owner, same day):** the contract keeps
its name `ComplianceRegistry` and stays a full deploy pinned by code hash (no factory clone class); `REGISTRY_CODEHASH` becomes
`COMPLIANCE_REGISTRY_CODEHASH`, the new error is `ComplianceRegistryRouterMismatch`, and the bare "registry" names of the
regulated code that would read as `UARegistry` take `ComplianceRegistry` (§4.1).

## 1. The rulings (owner, 2026-11-10, in chat)

- **R1. `OpenFactory` keeps no owner information.** An owner can transfer or renounce, so a recorded owner goes stale. The
  record, its views and the creation events lose the owner; the immutable facts stay (`creatorId`, `contractsOfCreator`, class,
  kind, version, block, time). The current admin is read from the contract, its history from the contract's own events.
- **R2. The address admins become UA admins:** `OpenFactory.registrar` (an `address immutable`, usually an EOA) and
  `ComplianceRegistry.admin` (an `address`, written once). Reason (owner): an admin should be any UA, an `msig` or a PQ-signing
  UA included, which is more secure and more flexible. Same pattern as `GovernanceBase`; every admin op relayable through the
  router at fee 0 too.
- **R3. `owner` becomes `admin`** on every governed contract (the 12 token kinds and the DEX: `GovernanceBase`,
  `GovernanceLib`, `SCaaSDexAdmin`) and on the PqChat topic record (`PqTopic.owner`). Exactly one admin per contract; the
  two-step transfer, the renounce, the role bits, the delays and every rule stay; only names and the ABI move. **Not renamed
  (owner):** the PqChat instance's `owner` (`bytes32`), `MandateWallet` and `SmartKeyAccount` `owner` (the holder of the assets).

**Also not renamed** (another meaning of the word): the registry's own single `admin` (it stays `admin`), and its
`AdminWrittenSlot` (the registry admin's row, `providerId == 0`); the UA registry's `keyOwner`; the owner of a PQZ leg
(`src/pqz/PqzCore.sol:725-781`); Zether's account owner (purpose `zether-owner`, `ownerSig`, the owner statements of TS-D19);
ERC-20 `allowance(owner, spender)`; `"owner 2026-…"` in comments (the person).

**Rules applied, not reopened:** [CTR-GOV-01](../../decisions.md#ctr-gov-01--governancebase-on-every-token-kind-and-the-dex)
and its 2026-11-04 Change (every identity a UA id, `_govSubject()`), CTR-GOV-07 (the non-EVM `set_admin` / `renounce_admin`
semantics), CTR-GOV-15's router Change, [CTR-TOK-27](../../contracts/token-wrappers.md#CTR-TOK-27),
[CTR-TOK-29](../../contracts/token-wrappers.md#CTR-TOK-29), [CTR-AS-07](../../contracts/asset-suite.md#CTR-AS-07),
[NET-EVM-05](../../networks/evm.md#NET-EVM-05), [NET-EVM-11](../../networks/evm.md#NET-EVM-11), D2 (no EIP-7702 designator as a
direct authority, `decisions.md:2167`), explicit parameters, every state-changing `mtx*` relayable at fee 0, nothing deployed is
upgraded, all chains test-only.

## 2. What is there today

| Item | Where | Today |
|---|---|---|
| Record | `src/factory/OpenFactory.sol:31-40`, `src/factory/IOpenFactory.sol:47-63` | `Rec {creatorId, ownerUA, class, kind, version, block, time}`, three slots; `Created` the same plus `addr` |
| Owner reads | `OpenFactory.sol:330` (`IGovernance(dex).owner()`), `:756-757` (`t.owner()`), `:484-488` (`fi.ownerUA`) | read once after `initialize`, written to the record, the owner list and the event |
| Owner list | `OpenFactory.sol:71` (`_byOwner`, slot 12), `:508-512` (`contractsOfOwner`), `:665` (push) | never for 0 |
| Events | `IOpenFactory.sol:77-79` (`TokenCreated … bytes32 owner …`), `:84` (`DexCreated`), `:307-308` (`InstanceCreated`) | the owner at creation |
| `FactoryInfo` | `IOpenFactory.sol:287-299`, read `OpenFactory.sol:712-717` (224 B), `:704` (release owner 0) | seven words, `ownerUA` the sixth |
| Registrar | `OpenFactory.sol:53` (`address public immutable registrar`), `:90-98` (`onlyRegistrar`: `msg.sender`, `requireNotDelegated`) | the factory's only constructor argument; trust root for code (`docs/contracts/token-wrappers.md:738`, `:892`) |
| Registry admin | `src/regulated/ComplianceRegistry.sol:23-35`, `:51` | `address admin`, constructor only, must be a contract (`AdminNotContract`); no immutables so one runtime, one code hash (F-11, `:8-11`) |
| Governance owner | `src/governance/GovernanceLib.sol:70-73` (`owner` +2, `pendingOwner` +3, `ownerGeneration` +4), `:382-408`, `:595-598` | two-step transfer, renounce refused while a live root (`OwnerHasHolders`, `:512`) |
| The pattern | `src/governance/GovernanceBase.sol:46-50` (`governed`), `:61-65` (`_govSubject()`) | `msg.sender == router` ⇒ `subject()`, else `pad(_caller())`; the DEX's `_caller()` runs `requireNotDelegated` (`src/dex/SCaaSDexAdmin.sol:29-32`) |
| Router owner ops | `src/governance/GovernanceRouterBase.sol:33-38`, `:190-205` | `UATransferOwnership(… bytes32 newOwner …)`, `UAAcceptOwnership`, `UARenounceOwnership` |
| Topic owner | `src/pqchat/IPqChat.sol:83-91`, `:167`, `:200`, `:302`; `src/pqchat/PqChatTypes.sol:30-31`, `:142-144`; `src/pqchat/PqChatCore.sol:35`, `:78`; `src/pqchat/PqChatTopics.sol:34-43`, `:243-256` | `PqTopic.owner`, `topicsByOwner`, `PqTopicNotOwner`, `_ownerAuth` |

Why the registrar was immutable: the chain-neutral spec §3.4 (`docs/superpowers/specs/2026-11-07-chain-neutral-releases.md:222-229`)
needs the factory's constructor argument to be the same account under the same control on every chain (an EOA by construction;
a contract registrar deployed deterministically, the Wintermute lesson), and the registrar's key is the trust root for code. No
document argues against a transfer as such; immutability was the simplest way to keep the factory's address and its control
equal everywhere.

## 3. R1: the factory keeps no owner information

- **Record.** `Rec {creatorId, contractClass, kind, version, createdBlock, createdAt}`: two slots (the packed word moves from
  `+2` to `+1`). `Created {addr, creatorId, contractClass, kind, version, createdBlock, createdAt}`. `_rec` stays at slot 8.
- **Views.** `infoOf`, `contractsPage`, `contractsOfCreator` stay; `contractsOfOwner` and `_byOwner` go (the later sequential
  slots move down by one; only slot 8 is pinned, by `test/zether/ZetherStateVectors.t.sol:34`, `:222-228`).
- **Reads.** The factory reads no owner or admin of anything it creates: `_create` drops `t.owner()` (`:756-757`), `createDex`
  drops `IGovernance(dex).owner()` (`:330`), `_recordInstance` stops using `fi.ownerUA` (`:488-489`).
- **Events.** `TokenCreated(token, creatorId, kind, version, implementation, features, lockedFeatures, underlyings)`,
  `DexCreated(dex, creatorId, version, implementation)`, `InstanceCreated(instance, creatorId, contractClass, kind, version,
  implementation)`; topic0 of each moves (§4.3).
- **`FactoryInfo`** loses `ownerUA` (owner, Q4): six words, 192 B; `_factoryInfo` checks 192 (`:715`); `_checkRelease` drops "owner 0"
  (`:704`); `PqChat.factoryInfo()` (`src/pqchat/PqChat.sol:67-70`) answers six fields; PqChat's own `owner()` stays.
- **The admin's history** is the contract's own: `GovernanceLib.init` already emits the creation-time transfer from 0
  (`GovernanceLib.sol:128-132`), renamed `AdminTransferred(0, admin)` (§4), in the creating transaction.
- **Node.** It decodes no `TokenCreated` / `DexCreated` / `InstanceCreated` (`docs/node/indexer-feeds.md:228-229`); it reads
  `infoOf(target)` for `(contractClass, version)` only (`scaas-node/src/guard.rs:1013-1024`). `abi.rs:597-605`'s `Created` loses
  `ownerUA`, the test mock at `guard.rs:2465-2466` likewise; no job shape moves.

## 4. R3: `owner` becomes `admin`

### 4.1 Rename map (EVM)

| Area | Old | New |
|---|---|---|
| Views | `owner()`, `pendingOwner()` | `admin()`, `pendingAdmin()` |
| Entries | `transferOwnership(bytes32 newOwner)`, `acceptOwnership()`, `renounceOwnership()` | `transferAdmin(bytes32 newAdmin)`, `acceptAdmin()`, `renounceAdmin()` |
| Events | `OwnershipTransferStarted(previousOwner, newOwner)`, `OwnershipTransferred(previousOwner, newOwner)` | `AdminTransferStarted(previousAdmin, newAdmin)`, `AdminTransferred(previousAdmin, newAdmin)` (both `bytes32 indexed`) |
| Errors | `NotOwner(bytes32)`, `NotPendingOwner(bytes32)`, `OwnerAccountPool(bytes32)`, `OwnerHasHolders(uint8)` | `NotAdmin(bytes32)`, `NotPendingAdmin(bytes32)`, `AdminAccountPool(bytes32)`, `AdminHasHolders(uint8)` |
| Storage `scaas.governance` | `owner` +2, `pendingOwner` +3, `ownerGeneration` (+4, packed) | `admin`, `pendingAdmin`, `adminGeneration`: **same slots and offsets** |
| Bodies | `_ownerBody`, `_pendingOwnerBody`, `_transfer/_accept/_renounceOwnershipBody` (`GovernanceBase.sol:92-93`, `:134-138`); `GovernanceLib.transfer/accept/renounceOwnership`, `_onlyOwner` | `_adminBody`, …, `GovernanceLib.transferAdmin`, …, `_onlyAdmin` |
| Readers | `WrappedLib.sol:831`, `:855`, `:1006`; `PqzStateLib.sol:132`, `:185`, `:196` | `g.admin`, `g.adminGeneration` |
| Init config | `TokenConfig.owner` (`src/factory/IFactoryToken.sol:128`), `DexConfig.owner` (`src/dex/ISCaaSDex.sol:18`), `GovernanceLib.init(…, bytes32 owner, …)` (`:98`), `ZetherLib.initNormal` (`:293-306`) | `admin`; the ABI encoding of `initArgs` is unchanged (names are not encoded) |
| DEX stubs | `SCaaSDex.sol:809-810`, `:832-834`; `SCaaSDexAdmin.sol:73-74`, `:107-109` | the new names |
| Token faces | generated (`src/metatx/NormalToken.sol:4`) from `script/modules/entries.json` (72 lines name `Ownership`); `face_abi.json` (from `d142b57c`) declares the old events and errors | `entries.json` renamed, `gen_faces.py` run; `legacy_artifacts.py faceabi` takes the rename map, so the faces declare the new names |
| Selector audit | class `OWNER` (`test/governance/SelectorAudit.t.sol:37`, `:151`, `:172`; `scaas-node/src/guard.rs:1718`) | `ADMIN` (`HOLDER_OWN` stays: `acceptAdmin` is the pending's own) |
| Router | `UATransferOwnership(…,bytes32 newOwner,…)`, `UAAcceptOwnership`, `UARenounceOwnership`; `mtx…Ownership` | `UATransferAdmin(…,bytes32 newAdmin,…)`, `UAAcceptAdmin`, `UARenounceAdmin`; `mtxTransferAdmin`, `mtxAcceptAdmin`, `mtxRenounceAdmin` |
| Topic | `PqTopic.owner`; `PqTopicCreated(topicId, owner)`; `PqTopicNotOwner(bytes32 owner)`; `topicsByOwner(owner_, start, count)`; storage `Topic.owner`, `S.topicsByOwner`; `_ownerAuth` | `admin`; `PqTopicCreated(topicId, admin)`; `PqTopicNotAdmin(bytes32 admin)`; `topicsByAdmin(admin_, …)`; `Topic.admin`, `S.topicsByAdmin` (same slots); `_adminAuth` |
| Disclosure | `governance_bits.json` sentences "The owner may …" (bits 25, 26), from `test/governance/GovBitsVector.t.sol:327`, `:339` | "The admin may …", regenerated (`WRITE_BITS=true`) |
| Registry: the party (owner 2026-11-10) | `setAttester(address attester, bool)`; `attesterId(address)` (mapping); `attesterEnabled(uint32)`; `AttesterSet(address indexed attester, uint32 indexed attesterId, bool)`; `NotAttester()`; the draft's `AttesterZero` | `setKycProvider(bytes32 provider, bool enabled)`; `kycProviderId(bytes32)`; `kycProviderEnabled(uint32)`; `KycProviderSet(bytes32 indexed provider, uint32 indexed providerId, bool enabled)`; `NotKycProvider()`; `KycProviderZero()` |
| Registry: the row (named after what it writes) | `attest(bytes32[] accounts, uint64[] flags, uint64[] validUntil)`; `Attested(bytes32 indexed account, uint64 flags, uint64 validUntil, uint32 indexed attesterId)`; `attestationOf(bytes32) returns (flags, validUntil, attesterId)`; struct `Attestation {flags, validUntil, attesterId}` | `setCompliance(bytes32[] accounts, uint64[] flags, uint64[] until)`; `ComplianceSet(bytes32 indexed account, uint64 flags, uint64 validUntil, uint32 indexed providerId)`; `complianceOf(bytes32) returns (flags, validUntil, providerId)`; struct `ComplianceRow {flags, validUntil, providerId}` (one slot, same packing) |
| Registry: router ops | the draft's `UASetAttester(…,bytes32 attester,bool enabled,…)` / `mtxSetAttester` and `UAAttest(…,bytes32[] accounts,uint64[] flags,uint64[] until,…)` / `mtxAttest` (never built) | `UASetKycProvider(…,bytes32 provider,bool enabled,…)` / `mtxSetKycProvider`; `UASetCompliance(…,bytes32[] accounts,uint64[] flags,uint64[] until,…)` / `mtxSetCompliance` |
| Registry: readers | `RegulatedBase` (`attestationOf`, `attesterEnabled`, `canReceive` reason 3 "attester disabled"), `IRegulatedToken`, `IComplianceRegistry`, the node's `abi.rs` / `dex/venue.rs`, clientkeys `regulated.js` (`attesterEnabled`), `regulated_kat.json` | `complianceOf`, `kycProviderEnabled`, reason 3 "KYC provider disabled", the same names everywhere; `hasFlags`, `LengthMismatch`, `EligibleContractAdminOnly`, `AdminWrittenSlot`, `admin` unchanged |
| Compliance registry names in the regulated code (owner 2026-11-10: unambiguous next to `UARegistry`) | `RegulatedBase.REGISTRY_CODEHASH` (public immutable, in the faces' `entries.json` and `ITokenModule`); `RegulatedImplArgs.registryCodehash`; `RegulatedLib.init(…, bytes32 registryCodehash, address uaRegistry)`; `IRegulatedToken.RegistryCodeMismatch(address registry, bytes32 codehash)`, `RegistryUnavailable(address registry)`, `RegistryGasStarved(uint256 cap, uint256 left)`; `RegulatedBase.REGISTRY_GAS`, `REGISTRY_GAS_MARGIN`; `DeployBase._registryCodehash()`; the draft's `RegistryRouterMismatch` | `COMPLIANCE_REGISTRY_CODEHASH`; `complianceRegistryCodehash`; `init(…, bytes32 complianceRegistryCodehash, address uaRegistry)`; `ComplianceRegistryCodeMismatch(address complianceRegistry, bytes32 codehash)`, `ComplianceRegistryUnavailable(address complianceRegistry)`, `ComplianceRegistryGasStarved(uint256 cap, uint256 left)`; `COMPLIANCE_REGISTRY_GAS`, `COMPLIANCE_REGISTRY_GAS_MARGIN`; `_complianceRegistryCodehash()`; `ComplianceRegistryRouterMismatch(address complianceRegistry, address got)`. The contract keeps its name `ComplianceRegistry` (a full deploy pinned by code hash, no factory clone class). Not renamed: `complianceRegistry` (already explicit), `IComplianceRegistry`, `RegulatedBase._registry()` and `uaRegistry` (they are the UA registry), `_requireRegistryGas` in `DeployBase` (the UA registry's verify budget), short locals (`reg`, `_regCall`), the test file and contract names of `test/as/Registry.t.sol`, and the node's `compliance_registry_codehash` (already explicit) |
| The factory's token member of each token / DEX / class triple (owner 2026-11-11: "UADeprecateToken chứ?"; the two others the controller's, for consistency) | `publishEnv`, `deprecate`, `setKindEnabled`; the views `envOf`, `latestEnvVersion`, `isDeprecated`, `kindEnabled`; the events `ImplementationDeprecated`, `KindEnabled`; the router's `UAPublishEnv` / `mtxPublishEnv`, `UADeprecate` / `mtxDeprecate`, `UASetKindEnabled` / `mtxSetKindEnabled` (§5.4, never built) | `publishTokenEnv`, `deprecateToken`, `setTokenKindEnabled`; `tokenEnvOf`, `latestTokenEnvVersion`, `isTokenDeprecated`, `tokenKindEnabled`; `TokenImplementationDeprecated`, `TokenKindEnabled`; `UAPublishTokenEnv` / `mtxPublishTokenEnv`, `UADeprecateToken` / `mtxDeprecateToken`, `UASetTokenKindEnabled` / `mtxSetTokenKindEnabled`. Renamed only where the DEX or class sibling carries `Dex` / `Class` (`dexEnvOf`, `classKindEnabled`, `isDexDeprecated`, `DexImplementationDeprecated`, `ClassKindEnabled`, …). Not renamed: `EnvPublished` (the token kinds' and the DEX's, by domain), `deployTokenImplementation`, `approveTokenRelease` (already `Token`), and the rest of the token side (`releaseOf`, `implementationOf`, `latestVersion`, `ImplementationDeployed`, the errors `KindDisabled`, `VersionDeprecated`, …) |

One shared interface, `IAdmin` (`src/governance/IAdmin.sol`): `admin()`, `pendingAdmin()`, `transferAdmin(bytes32)`,
`acceptAdmin()`, the two events, `NotAdmin(bytes32)`, `NotPendingAdmin(bytes32)`. `IGovernance is IAdmin` and adds
`renounceAdmin()`; `IOpenFactory` and `IComplianceRegistry` use it (§5), so every admin has one selector set and one error
shape. The topic id derivation keeps its value: `topicId(admin, nonce) = keccak256(abi.encode(TAG_TOPIC, admin, nonce))`, the
nonce scope likewise; only the field name and `TOPIC_TYPEHASH` change.

### 4.2 Selectors (keccak256 of each signature, recomputed with `cast sig` / `cast keccak` on 2026-11-10: every row of §4.2 and §4.3 equal; the old values equal `typed_ops.json` and the typehash pins)

| Old | Selector | New | Selector |
|---|---|---|---|
| `owner()` | `0x8da5cb5b` | `admin()` | `0xf851a440` |
| `pendingOwner()` | `0xe30c3978` | `pendingAdmin()` | `0x26782247` |
| `transferOwnership(bytes32)` | `0xf807e3da` | `transferAdmin(bytes32)` | `0xe923bc3d` |
| `acceptOwnership()` | `0x79ba5097` | `acceptAdmin()` | `0x0e18b681` |
| `renounceOwnership()` | `0x715018a6` | `renounceAdmin()` | `0x8bad0c0a` |
| `registrar()` (factory) | `0x2b20e397` | `admin()` | `0xf851a440` |
| `NotOwner(bytes32)` | `0xa6922f00` | `NotAdmin(bytes32)` | `0xba963c12` |
| `NotPendingOwner(bytes32)` | `0xda5bcbae` | `NotPendingAdmin(bytes32)` | `0x16600d0b` |
| `OwnerAccountPool(bytes32)` | `0x631254fc` | `AdminAccountPool(bytes32)` | `0x0c4bfe3f` |
| `OwnerHasHolders(uint8)` | `0xb164ad5e` | `AdminHasHolders(uint8)` | `0xc77bc55f` |
| `NotRegistrar()` (factory) | `0x2ad95351` | `NotAdmin(bytes32)` | `0xba963c12` |
| `NotAdmin()` (registry) | `0x7bfa4b9f` | `NotAdmin(bytes32)` | `0xba963c12` |
| `topicsByOwner(bytes32,uint256,uint256)` | `0x944640bd` | `topicsByAdmin(bytes32,uint256,uint256)` | `0xa448972c` |
| `PqTopicNotOwner(bytes32)` | `0xbbd4dd0b` | `PqTopicNotAdmin(bytes32)` | `0x8bb56219` |
| `contractsOfOwner(bytes32,uint16,uint256,uint256)` | `0x9fbde75c` | removed | |
| `mtxTransferOwnership` | `0xc3efbc3a` | `mtxTransferAdmin` | `0xa682ea50` |
| `mtxAcceptOwnership` | `0x9c682cce` | `mtxAcceptAdmin` | `0x321b86a3` |
| `mtxRenounceOwnership` | `0x71364d1a` | `mtxRenounceAdmin` | `0xfeedac3d` |
| `setAttester(address,bool)` | `0x5c0204d9` | `setKycProvider(bytes32,bool)` | `0x105b99c7` |
| `attesterId(address)` | `0xf146f55a` | `kycProviderId(bytes32)` | `0x2d4138d7` |
| `attesterEnabled(uint32)` | `0xf358d481` | `kycProviderEnabled(uint32)` | `0xbbc8fe54` |
| `attest(bytes32[],uint64[],uint64[])` | `0xfff67e1b` | `setCompliance(bytes32[],uint64[],uint64[])` | `0x7fa569a5` |
| `attestationOf(bytes32)` | `0xb174a9c4` | `complianceOf(bytes32)` | `0x996ee3f2` |
| `NotAttester()` | `0xcab98054` | `NotKycProvider()` | `0x3f153a68` |
| `AttesterZero()` (draft, never built) | | `KycProviderZero()` | `0x42a1ea7f` |
| `mtxSetAttester` (draft, never built) | `0xa0224cf5` | `mtxSetKycProvider` | `0xd4733492` |
| `mtxAttest` (draft, never built) | `0x3957a8be` | `mtxSetCompliance` | `0x37a68821` |
| `REGISTRY_CODEHASH()` | `0xbeb598de` | `COMPLIANCE_REGISTRY_CODEHASH()` | `0xd10351b4` |
| `RegistryCodeMismatch(address,bytes32)` | `0x84dfcab7` | `ComplianceRegistryCodeMismatch(address,bytes32)` | `0xd4cff8d4` |
| `RegistryUnavailable(address)` | `0x2466be0b` | `ComplianceRegistryUnavailable(address)` | `0x4c06f1f3` |
| `RegistryGasStarved(uint256,uint256)` | `0xaf0824dc` | `ComplianceRegistryGasStarved(uint256,uint256)` | `0x966a8ed1` |
| `RegistryRouterMismatch(address,address)` (draft, never built) | `0x8b4535bc` | `ComplianceRegistryRouterMismatch(address,address)` | `0x6c36f6ee` |
| `publishEnv(uint8,uint16,Env)` | `0x79f23f46` | `publishTokenEnv(uint8,uint16,Env)` | `0x15735a6c` |
| `deprecate(uint8,uint64,string)` | `0xcd26d6c9` | `deprecateToken(uint8,uint64,string)` | `0xb7fdb2fa` |
| `setKindEnabled(uint8,bool)` | `0x3941ae68` | `setTokenKindEnabled(uint8,bool)` | `0xbb4aac3a` |
| `envOf(uint8,uint16)` | `0xbb072443` | `tokenEnvOf(uint8,uint16)` | `0x4ae0f85a` |
| `latestEnvVersion(uint8)` | `0xfeb1775e` | `latestTokenEnvVersion(uint8)` | `0xcaf571af` |
| `isDeprecated(uint8,uint64)` | `0x5fdcad9a` | `isTokenDeprecated(uint8,uint64)` | `0x40d34668` |
| `kindEnabled(uint8)` | `0xcb196d20` | `tokenKindEnabled(uint8)` | `0xffb1d907` |

The `mtx*` selectors are over `(UAEnvelope, address target[, bytes32], UASig)` as `typed_ops.json:8016` pins the old one.

### 4.3 Event topics and typehashes

| Old | topic0 / typehash | New | topic0 / typehash |
|---|---|---|---|
| `OwnershipTransferStarted(bytes32,bytes32)` | `0x77586e9b…` | `AdminTransferStarted(bytes32,bytes32)` | `0xc022cde7…` |
| `OwnershipTransferred(bytes32,bytes32)` | `0xcbbb77f6…` | `AdminTransferred(bytes32,bytes32)` | `0x72ecac40…` |
| `TokenCreated(…,uint256,uint256,bytes32,address[])` | `0x6328d132…` | `TokenCreated(…,uint256,uint256,address[])` | `0x0ed41946…` |
| `DexCreated(address,bytes32,uint64,address,bytes32)` | `0xe7ef47f6…` | `DexCreated(address,bytes32,uint64,address)` | `0x7333afd9…` |
| `InstanceCreated(…,uint64,address,bytes32)` | `0x45e2860e…` | `InstanceCreated(…,uint64,address)` | `0xdb1952a9…` |
| `PqTopicCreated(bytes32,bytes32)` | `0x5b2fb9b3…` | unchanged (a parameter name only) | |
| `AttesterSet(address,uint32,bool)` | `0x52573ee7…` | `KycProviderSet(bytes32,uint32,bool)` | `0xa2ead380…` |
| `Attested(bytes32,uint64,uint64,uint32)` | `0x7a80112d…` | `ComplianceSet(bytes32,uint64,uint64,uint32)` | `0xe6da38c5…` |
| `UATransferOwnership` | `0xa468e58d…` (pinned, `GovRouterTypehash.t.sol:50-53`) | `UATransferAdmin(bytes32 from,address target,bytes32 newAdmin,E)` | `0x36dbad09…` |
| `UAAcceptOwnership` | `0x2ce67927…` | `UAAcceptAdmin(bytes32 from,address target,E)` | `0x996ac68d…` |
| `UARenounceOwnership` | `0x0397c70e…` | `UARenounceAdmin(bytes32 from,address target,E)` | `0x4be88ff9…` |
| `PqTopic(bytes32 owner,…)` | `0x75bed97b…` | `PqTopic(bytes32 admin,uint64 nonce,bytes32 homeChain,address homeChatContract,string name,bytes about,bool openReplies)` | `0x66954727…` |
| `UASetAttester` (draft, never built) | `0xbd91b79a…` | `UASetKycProvider(bytes32 from,address target,bytes32 provider,bool enabled,E)` | `0x297e6c85…` |
| `UAAttest` (draft, never built) | `0x1e48485c…` | `UASetCompliance(bytes32 from,address target,bytes32[] accounts,uint64[] flags,uint64[] until,E)` | `0x0c697df1…` |
| `KindEnabled(uint8,bool)` | `0x437ef05e…` | `TokenKindEnabled(uint8,bool)` | `0x5c5afa9d…` |
| `ImplementationDeprecated(uint8,uint64,string)` | `0x78f6ee1e…` | `TokenImplementationDeprecated(uint8,uint64,string)` | `0x70d98086…` |

`E` is the seven envelope words (`uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address
feeRecipient`). The registry rows of §4.2 and §4.3 were recomputed with `cast sig` / `cast keccak` on 2026-11-10 (the KYC
provider and compliance-registry rulings); the draft rows were never built. No other typehash names `owner` (`src/` scan); the old four stay pinned as legacy pins. Every chain test-only: no
alias, no old selector kept.

### 4.4 Layout pins

The slots do not move; the labels do: `test/v2/layout/namespaces.json` (`owner`, `pendingOwner`, `ownerGeneration`),
`test/v2/Layout.t.sol:48-51`, `:201-204`; PqChat's `Topic.admin` and `S.topicsByAdmin`; `ComplianceRegistry` has no layout pin (its sequential slots, `kycProviderId`,
`_enabled`, the rows, are its own and move with §5.3's `UAAdmin` namespace) (the namespace pin
`test/pqchat/PqChatLayout.t.sol:37` names the instance's `ownerUA`, unchanged). The test still asserts the same offsets: a label
edit that moved a slot fails it.

### 4.5 One rule on every chain

The non-EVM token and DEX already say admin: `smartcontracts/soroban/contracts/token/src/lib.rs:204`,
`smartcontracts/soroban/contracts/dex/src/lib.rs:120`, `smartcontracts/near/token/src/lib.rs:187`, and CTR-GOV-07's
`set_admin` / `renounce_admin` for every family. 3r aligns the EVM; the mandate's `owner` stays on every family, as on EVM.

## 5. R2: UA admins for `OpenFactory` and `ComplianceRegistry`

### 5.1 The pattern, one definition

`abstract contract UAAdmin is IAdmin` (`src/governance/UAAdmin.sol`), storage in ERC-7201 namespace `scaas.admin` (no sequential
slot moves: the factory's slot 8 and the registry's slots stay):

```solidity
struct AdminStorage { bytes32 admin; bytes32 pendingAdmin; uint32 adminGeneration; }
function _adminRouter() internal view virtual returns (address);          // factory: govRouter; registry: its own
function _adminSubject() internal view returns (bytes32) {               // GovernanceBase._govSubject, :61-65
    address r = _adminRouter();
    if (r != address(0) && msg.sender == r) return IGovernanceRouter(r).subject();
    SigCheck.requireNotDelegated(msg.sender);                             // D2, as onlyRegistrar (:96)
    return MetaTxLib.pad(msg.sender);
}
modifier onlyAdmin() { bytes32 c = _adminSubject(); if (c == 0 || c != $().admin) revert NotAdmin(c); _; }
// transferAdmin(next) onlyAdmin: pending = next (0 cancels), AdminTransferStarted(admin, next)
// acceptAdmin(): c = _adminSubject(); c != 0 && c == pending, else NotPendingAdmin(c); AdminTransferred(admin, c);
//   admin = c; pending = 0; ++adminGeneration
// _renounceAdmin() onlyAdmin: AdminTransferred(admin, 0); admin = pending = 0; ++adminGeneration  (the factory only: Q1, Q2)
```

The semantics are `GovernanceLib`'s (`:382-408`) and CTR-GOV-07's: two steps with acceptance, a renounce clears the pending and
is one-way. No pool check (the factory and the registry hold no pool). `adminGeneration` moves at every accept and renounce, as
`GovernanceLib`'s `ownerGeneration` does, so an approval dies with the admin's term (§5.6). The pending has
no expiry, as in `GovernanceLib`: a forgotten pending can accept years later; the admin cancels it with `transferAdmin(0)`
(Fable P3).

### 5.2 `OpenFactory`

- `constructor(bytes32 admin_)`: `admin_` must be a native id (`≠ 0`, high 96 bits 0), else `AdminNotNative(admin_)`; emits
  `AdminTransferred(0, admin_)`. The factory's address stays chain-neutral: the first admin is the same native id on every chain.
- `onlyRegistrar` → `onlyAdmin` on `configureChain`, `publishEnv`, `publishDexEnv`, `publishClassEnv`, `deprecate`,
  `deprecateDex`, `deprecateRelease`, `setKindEnabled`, `setClassKindEnabled` (`OpenFactory.sol:113-416`); the three release
  deploys: open to anyone against an approval, and a native admin's own call is its own approval (§5.6).
  `_adminRouter()` is `govRouter`; the router's subject read shares `_creatorId()`'s source (`:631-636`).
- **`configureChain` is direct only, by construction:** before it `govRouter` is 0, so the router path does not exist; the factory
  cannot trust a router it has not been told of (a contract that names itself the router could answer any `subject()`). Hence a
  native first admin, and the transfer after `configureChain` (§6).
- `transferAdmin`, `acceptAdmin`, `renounceAdmin` (owner, Q1); `admin()`, `pendingAdmin()` replace `registrar()`. `transferAdmin`
  and `renounceAdmin` carry `configured` (Fable P2-4): a slip, or a sibling's replayed direct transaction, cannot end an
  unconfigured factory, whose address is the same on every chain. `renounceAdmin(chainUid_)` also names the factory's word
  after the admin check (fix2 2026-11-12, Fable recheck-2 P3-1): void on a configured sibling too. `admin()` shares its selector with the proxy admins of
  ERC-1967 tooling; an explorer may label it so, harmlessly (Fable P3).
- **Renounce ends every admin op for good, deprecation included:** no env, no release, no deprecation, no kind switch on that
  chain's factory; a release found bad after a renounce can no longer be stopped there (owner, Q1: stated consequence).
- **The first admin's key stays the root on every chain not yet configured** (Fable P2-4): `pad(deployer)` is in the factory's
  init code, so after a transfer on one chain that key is still the sole authority over the same factory address wherever
  `configureChain` has not run. It is kept offline and used only for a new chain's `configureChain`, its first writes and its
  `transferAdmin` (the custody line of NET-EVM-05's Change); "an `msig` is safer" holds per configured chain.
- `configureChain` with a router also requires `router.registry()` to be non-zero with code (Fable P3), the router's code hash and
  the `SmartKeyAccount` binding (§13.3, §13.4).
- The chain's directory (owner, §13): the write-once `setChainEntries`.

### 5.3 `ComplianceRegistry`

- `constructor(bytes32 admin_, address govRouter_)`, both written once to storage (no immutable: F-11's one runtime holds; the
  regulated releases' `COMPLIANCE_REGISTRY_CODEHASH` changes once, with the new runtime). `admin_ ≠ 0` (`AdminZero`); `AdminNotContract`
  goes: any UA, an EOA, a contract, an `msig` or a PQ UA (CTR-AS-07 Change, §11). `govRouter_` 0 = no router path, so a derived
  `admin_` with `govRouter_` 0 is refused (`AdminUnreachable(admin_)`), and a `govRouter_` without code too
  (`RouterNotContract(govRouter_)`): no registry is born with an admin nobody can act as (Fable P2-3). `govRouter()` is a view.
  The registry's address now differs per chain (the router is per chain); every book names it per chain already.
- **A canonical-code registry behind another router** (Fable P1-1): the code hash pins the code, not the `govRouter` word, so
  `ComplianceRegistry(admin_ = a regulator's UA, govRouter_ = Evil)` passes every regulated release's `COMPLIANCE_REGISTRY_CODEHASH` check
  (`src/regulated/RegulatedLib.sol:114-116`) while `Evil` answers `subject() = admin`: `admin()` shows one UA and another party
  writes. Hence `RegulatedLib.init` also requires `registry.govRouter()` to be 0 or the token's own `ChainEnv.govRouter`
  (`ComplianceRegistryRouterMismatch(complianceRegistry, got)`), and a client checks the same before it trusts `admin()`.
- `setKycProvider(bytes32 provider, bool enabled)`: `onlyAdmin`; provider 0 refused (`KycProviderZero`: 0 is what a router read
  outside a live call answers, Fable P3). `setCompliance`: `c = _adminSubject()`; `c == admin` ⇒ id 0, else
  `id = kycProviderId[c]`, enabled, else `NotKycProvider` (§5.3.1). D2 applies to every direct caller, a KYC provider's too (the
  registry is authority there; it had no check because its admin had to be a contract).
- `transferAdmin`, `acceptAdmin`; **no renounce** (owner, Q2): only the admin disables a compromised KYC provider or writes an
  `ELIGIBLE_CONTRACT` row, so the registry always has one.

#### 5.3.1 The KYC provider is a UA too (owner, Q5; the name, owner 2026-11-10)

**Name (owner ruling 2026-11-10):** the party the registry admin enables to write compliance rows is the **KYC provider**, not
the "attester"; the row it writes is a **compliance row**, and the op is named after it (`setCompliance`). The rename rows are in
§4.1-§4.3. The registry's own `admin` stays `admin`; `AdminWrittenSlot` keeps its name (the admin's row, `providerId == 0`);
nothing in PQZ changes (3f's verifier is `pqzVerifierUA`, the last item of this section).

The KYC provider writes the registry's own state: it is the subject of its call, like a governance holder, so it takes the
`governed` / `UAAdmin` pattern, not a signer's. (A signer, like 3f's verifier UA, signs a record that rides inside someone
else's transaction and never sends one: `PqzVerdict` is the last parameter of the user's proof-carrying entry, CTR-PQZ-29. A
KYC provider sends its own `setCompliance`.) Hence:

- `kycProviderId` is keyed by the provider's UA id: `mapping(bytes32 provider => uint32)`; `setKycProvider(bytes32, bool)`,
  `kycProviderId(bytes32)`, `KycProviderSet(bytes32 indexed provider, uint32 indexed providerId, bool enabled)`. The id rules
  stay: assigned at the first enabling, never reused, 0 is the admin, an unknown id is not enabled (`kycProviderEnabled(uint32)`).
- `setCompliance` takes the subject from `_adminSubject()`: a native provider calls directly (`pad(addr)`, D2), a derived one
  (`msig`, PQ) through the router's `mtxSetCompliance`, the same op the admin uses; the router's domain, `target` and nonce give
  replay protection, so the registry needs no domain, nonce or record of its own.
- `setCompliance` takes at most 256 rows per call (`TooManyRows(n)`), the node's decode bound (§5.4, Fable P3).
- Every row rule stays: `ComplianceRow {flags, validUntil, providerId}` in one slot; `ELIGIBLE_CONTRACT` only by the admin with
  `validUntil = type(uint64).max` (CTR-AS-16); an admin row (`providerId 0`, `flags ≠ 0`) is the admin's alone
  (`AdminWrittenSlot`, owner 2026-11-06); disabling a KYC provider voids its rows at once; `hasFlags` keeps its selector;
  `RegulatedBase`'s two bounded reads move to `complianceOf` and `kycProviderEnabled` (the same words, the same bounds).
- **3f is untouched.** The PQZ verifier UA stays a signer: `pqzVerifyMode`, `pqzVerifierUA`, its admitted kinds and frozen shape,
  fixed or transferable with the factory's notice, immediate revocation, the epoch in every verdict, `PqzVerdict` under
  `PURPOSE_PQZ_VERDICT`, the OFFCHAIN key rule (CTR-PQZ-27 to CTR-PQZ-30). Only the word changes where they say "the owner"
  (`PqzStateLib.sol:185`: the admin proposes). The registry's compliance rows and 3f's attested verification stay two things.

### 5.4 Router ops

In `GovernanceRouterBase` (every `IAdmin` contract): the three renamed ops, which reach the factory and the registry too, as
their selectors equal `IGovernance`'s. In `GovernanceRouter`, next to the creations
(`src/governance/GovernanceRouter.sol:215-241`), fifteen new ops (the four of §5.6, `UASetChainEntries` from §13), each
`mtx<Op>(UAEnvelope e, address target, <params>, UASig auth)` over `UA<Op>(bytes32 from,address target,<words>,E)`, fee mode
`NONE`, relayable at fee 0 (the token members named `Token`, owner 2026-11-11, §4.1):

| Op | Signed words after `target` | Calls |
|---|---|---|
| `UAPublishTokenEnv` | `uint8 kind,uint16 envVersion,Env env` | `publishTokenEnv` |
| `UAPublishDexEnv` | `uint16 envVersion,Env env` | `publishDexEnv` |
| `UAPublishClassEnv` | `uint16 contractClass,uint16 kind,uint16 envVersion,Env env` | `publishClassEnv` |
| `UAApproveTokenRelease` | `uint8 kind,uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until` | `approveTokenRelease` (§5.6) |
| `UAApproveDexRelease` | `uint64 version,uint16 envVersion,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until` | `approveDexRelease` |
| `UAApproveRelease` | `uint16 contractClass,uint16 kind,uint64 version,uint16 envVersion,bytes4 initSelector,bytes4 interfaceId,bytes32 initcodeHash,bytes32 implArgsHash,bytes32 chainUid,address factory,uint32 adminGeneration,uint64 until` | `approveRelease` |
| `UARevokeApproval` | `bytes32 key` | `revokeApproval` |
| `UADeprecateToken` | `uint8 kind,uint64 version,bytes32 chainUid,string reason` | `deprecateToken` |
| `UADeprecateDex` | `uint64 version,bytes32 chainUid,string reason` | `deprecateDex` |
| `UADeprecateRelease` | `uint16 contractClass,uint16 kind,uint64 version,bytes32 chainUid,string reason` | `deprecateRelease` |
| `UASetTokenKindEnabled` | `uint8 kind,bool on,bytes32 chainUid` | `setTokenKindEnabled` |
| `UASetClassKindEnabled` | `uint16 contractClass,uint16 kind,bool on,bytes32 chainUid` | `setClassKindEnabled` |
| `UASetKycProvider` | `bytes32 provider,bool enabled` | `ComplianceRegistry.setKycProvider` |
| `UASetCompliance` | `bytes32[] accounts,uint64[] flags,uint64[] until` | `ComplianceRegistry.setCompliance` (the admin or a KYC provider, §5.3.1) |
| `UASetChainEntries` | `address relayFeeRouter,bytes32 relayFeeRouterCodeHash,bytes32 relayFeeExecutorCodeHash,address complianceRegistry,bytes32 complianceRegistryCodeHash,address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,address zetherStatements,bytes32 zetherStatementsCodeHash` | `OpenFactory.setChainEntries` (§13.3) |

- `Env(address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[]
  libCodeHashes)` is appended to the three publish types and hashed as EIP-712 does (each array `keccak256` of its 32-byte
  words), so every field of the env is signed by name.
- The five deprecations and kind switches sign the factory's `chainUid` as their direct entries take it (fix2 2026-11-12,
  Fable D P3-2): a native admin's direct call is void on a sibling with the same chain id.
- `renounceAdmin(bytes32 chainUid_)` on the factory, every token kind and the DEX, and the three deploys with a last
  `chainUid_` (fix2 2026-11-12, owner: Fable recheck-2 P3-1 option (a)): the router's `UARenounceAdmin(bytes32 from,address
  target,bytes32 chainUid,E)` (`0x3284850e…`, was `0x4be88ff9…` of §4.3) signs the target's word and forwards it; the
  selectors `renounceAdmin(bytes32)` `0x4fa3ed14` (was `renounceAdmin()` `0x8bad0c0a` of §4.2), `mtxRenounceAdmin`
  `0xfcdfdb9a` (was `0xfeedac3d`). Not changed, stopped for the owner: `transferAdmin(bytes32)` (shared `IAdmin`;
  `ComplianceRegistry` has no chain word) and `setChainEntries` / `UASetChainEntries` (a 13th router parameter is too deep
  for the ABI decoder) ([token-wrappers.md](../../contracts/token-wrappers.md#factory)).
- No release deploy is a router op (§5.6); the approvals sign the release's hashes as `UACreateToken` signs `initHash` (S3). A
  `string reason` is signed as `keccak256(bytes(reason))`, as EIP-712 hashes a string (Fable P1-3). The ids flat, as
  `UACreateInstance` (`:234-241`). `UASetCompliance` names its third array `until` because `validUntil` is an envelope word (the
  precedent: `UAOperatorTransfer`'s `account`, `GovernanceRouter.sol:105`).
- No `mtxConfigureChain` (§5.2) and no deploy op. The router's entries go from 38 to 53.
- **Release management is not a node job** (owner 2026-11-10; Q3 as updated, §5.6): neither the four approval ops nor the three
  deploys are node rows; all seven are in `NOT_ROWS` with the reason "release management is not a node job (owner 2026-11-10)"
  (§7). The gateway's limit is irrelevant. Every other admin op is a router op and a node row.
- **Node decode bounds** (Fable P3): `Env.deps` ≤ 4 and `Env.params` ≤ 2 (the factory's `ChainEnvCode.MAX_DEPS`, `MAX_PARAMS`);
  `libs` and `libCodeHashes` of one length ≤ 32, with a new factory bound `MAX_LIBS` (`EnvInvalid`) so the node and the contract
  refuse the same (today's largest env measured in T7); `UASetCompliance`'s three arrays of one length ≤ 256 (§5.3.1); every array
  flat, depth 1.

### 5.5 Threat notes

- **A stolen admin key.** Factory: the thief publishes envs, deploys releases (usable after `noticePeriod`, at least 3 days on a
  mainnet; existing contracts are clones of old code and do not move), deprecates or disables (a denial of creation), and can
  move the admin to itself. Registry: the thief enables KYC providers and writes rows (a receiver check passes for its accounts) or
  disables honest KYC providers (their rows void at once). Today's immutable registrar is the same exposure with no way to rotate
  first; a k-of-n `msig` or a PQ UA admin needs more than one key, and a transfer lets an honest admin rotate before a loss.
  The release list (`releases.json`) and `isRegisteredToken` stay what clients trust; a thief's release is not in the list.
- **The router down.** It has no owner, no pause and no state: it cannot be stopped, only refused by relayers, and then the
  admin's own account submits the signed call (any submitter). A router bug blocks a derived admin, which has no direct path; a
  native admin (an EOA or a contract) keeps it. The factory's `govRouter` is fixed by `configureChain`: a later router needs a
  new factory. Mitigation: the router passes the matrix run on the chain before the transfer to a derived admin.
- **Replay across chains or factories.** The router's domain is `("SCaaS GovernanceRouter", "1", chainId, router, chain_uid)`
  and `target` is a signed word: a signature for one chain's factory is refused by another chain (another `chain_uid` and
  router) and by another factory or registry on the same chain. The native admin's direct transactions keep NET-EVM-05's sibling
  rule (configure every sibling first); once the admin is derived, every admin op goes through the router and that class closes.
- **Another chain's control of the admin id.** A derived UA id is a pure function of its key data or policy, the same on every
  chain (`docs/contracts/accounts.md:70-73`), so nobody else holds it elsewhere: §3.4's deterministic-deployment requirement
  holds only for a native contract admin. Each chain's transfer is its own; the pending must be registered on that chain's UA
  registry before it can accept.
- **Delegated callers.** `requireNotDelegated` stays on every direct path (`_adminSubject`); through the router a native EOA is
  verified by its own key only (CTR-UA-24), the delegate never asked; the router is the caller, a contract.
- **A fake router.** Only `msg.sender == govRouter` (the factory's, written once) or the registry's constructor router is asked
  for a subject; any other caller is its own native id. A regulated token refuses a registry that names another router (§5.3,
  Fable P1-1).
- **The router and the UA registry join the trust root for code** (Fable P2-5). Today a flaw there forges a creator id at worst;
  after 3r any flaw that makes `subject()` answer the admin's id (the pipeline, a kind's verifier, `msig` aggregation) publishes
  envs and moves the admin, and nothing detaches the router (written once); a flaw in the registry's check of the admin's
  signature also approves releases (§5.6). Both are UNAUDITED. Stated as information only:
  derived admins may be used on every chain at once, with no audit gate (owner 2026-11-10, on P2-5). The notice period gives
  watchers time to see a release before it is creatable; it does not stop one, as a deprecation needs the admin. Tests (§8): a
  7702-delegated native admin through the router is verified by its own key, never by the delegate's ERC-1271 (D1, CTR-UA-24); a
  nested router op is refused by the router's guard (`src/metatx/MetaTxBase.sol:285`).

### 5.6 Release deploys: approve, then an open deploy (owner ruling 2026-11-10, final)

**Ruling (owner, final).** It replaces two drafts of the same day (an approval split with node rows; then "option (A)": signed
deploy entries on the factory under a 50 M per-release rule). Status: decided, SPECIFIED. **Why** (Fable P1-2): through the router
a release would pay one more call frame, the copy and `keccak256` of its init code and the admin's check, and a derived admin has
no other path; split, the signed part is small and the large transaction verifies nothing.

1. **Approve.** The factory admin, any UA kind, through the `governed` pattern (directly as its native id, or the router's
   `subject()`), approves **one release by hash**:
   - `approveTokenRelease(TokenKind kind, uint64 version, uint16 envVersion, bytes32 initcodeHash, bytes32 implArgsHash, bytes32
     chainUid, address factory, uint32 adminGeneration, uint64 until)`;
   - `approveDexRelease(uint64 version, uint16 envVersion, bytes32 initcodeHash, bytes32 implArgsHash, bytes32 chainUid, address
     factory, uint32 adminGeneration, uint64 until)`;
   - `approveRelease(ReleaseId id, uint16 envVersion, bytes4 initSelector, bytes4 interfaceId, bytes32 initcodeHash, bytes32
     implArgsHash, bytes32 chainUid, address factory, uint32 adminGeneration, uint64 until)` (what `deployImplementation` binds).

   Each is `onlyAdmin configured`; `chainUid`, `factory` and `adminGeneration` must be the factory's own
   (`ApprovalFieldMismatch(field)`); `until` must be in the future and at most **30 days** ahead (`ApprovalTooLong(until)`, the
   factory's `MAX_NOTICE_PERIOD`, `OpenFactory.sol:49`; Fable re-check P3). It stores `approvals[key] = {LIVE, adminGeneration,
   until}` and emits `ReleaseApproved(key, …)`; `approvalOf(key)` answers it. **The key binds every caller-supplied field the
   deploy stores** (Fable re-check N1), one tag per domain, fixed-width `abi.encode`:

   | Deploy | Key fields after `tag, chainUid, factory` | What the deploy stores from the caller |
   |---|---|---|
   | `deployTokenImplementation` (`"scaas.factory.release.token"`) | `kind, version, envVersion, initcodeHash, implArgsHash` | the release `[kind][version]`: its implementation (from `initcode`, `implArgs`), `envVersion` (and the env hash it names), the latest version (`OpenFactory.sol:157-177`) |
   | `deployDexImplementation` (`.dex`) | `version, envVersion, initcodeHash, implArgsHash` | the DEX release `[version]` likewise (`:284-302`) |
   | `deployImplementation` (`.class`) | `contractClass, kind, version, envVersion, initSelector, interfaceId, initcodeHash, implArgsHash` | the class release: implementation, `envVersion`, **`initSelector`** and **`interfaceId`** (`:362-371`, `:391-403`), the class and kind lists; `createInstance` admits only `initCall`s of that selector (`:456-458`) |

   **Live** means: state `LIVE`, the current `adminGeneration`, and `block.timestamp ≤ until` (Fable re-check N2). `approve*` refuses
   a live entry for the same key (`ApprovalLive(key)`) and overwrites one that is not live (expired, of an earlier admin term, or
   revoked), so a release can always be approved again. Through the router these are `UAApproveTokenRelease`,
   `UAApproveDexRelease`, `UAApproveRelease` (§5.4): relayable, anyone sends them, fee 0 too, and small, so an `msig` of several
   PQ signatures fits (its check is bounded by the registry's per-call budget, `UA_VERIFY_BUDGET` 12 M,
   `script/DeployBase.sol:128-130`, far under NET-EVM-11's 60 M). The approval's expiry is named `until`, not `validUntil`,
   because the router's envelope already has `validUntil`, the signature's deadline (the precedent of `UASetCompliance`).
2. **Revoke.** `revokeApproval(bytes32 key)`, `onlyAdmin configured`, deletes any stored entry not consumed, live or not
   (`ApprovalNotRevocable(key)` for an unknown or consumed one), and emits `ReleaseApprovalRevoked(key)`; through the router
   `UARevokeApproval`.
3. **Deploy.** `deployTokenImplementation`, `deployDexImplementation`, `deployImplementation` keep their names (their ABI gains a
   last `bytes32 chainUid_`, checked first: fix2 2026-11-12, Fable recheck-2 P3-1), carry no
   signature and go **straight to the factory, open to anyone**. The factory rebuilds `key` from the call (the table above: every
   stored caller field, the hashes of `initcode` and `implArgs` computed from the bytes) and accepts the deploy only against a
   live approval of it (else `ReleaseNotApproved(key)`, checked before the version); it marks the approval consumed (each is used
   once), then runs today's body. `configured` stays: a deploy before `configureChain` is refused. **The shortcut, in the owner's
   words** (2026-11-10):

   | The factory admin | Who sends `deploy*` | Approval |
   |---|---|---|
   | a native id | that same account (`msg.sender == admin`) | **none**: one transaction, as today |
   | a native EOA | another account | **needed**: the EOA signs the approval (its direct `approve*` call or its signed router op), and anyone deploys |
   | a derived UA (`msig`, ML-DSA, passkey, …) | anyone | **always**: it cannot send a transaction itself |

   The shortcut checks only `msg.sender` (`pad(msg.sender) == admin`), never a signature, and reads no router subject. Once the
   admin moves to an `msig` or a PQ UA, the original deployer EOA has no shortcut. Two edges (Fable re-check P3): a native
   admin's own deploy **also consumes a live approval of the same key**, so none is left dangling; and an admin EOA that is an
   EIP-7702 designator never takes the shortcut (D2): its deploy falls to the approval path, which works for any sender, and is
   refused only if no live approval matches.
   **A deploy's result does not depend on the sender's gas** (Fable re-check N3): every probe in the deploy path fails closed or
   is absent. At `74262fa0` the factory's checks revert on a failed call (`_word`, `_factoryInfo`, `_validateEnv`,
   `_checkModules`) but one: `_checkRelease`'s "not `0xffffffff`" leg (`OpenFactory.sol:707`) runs `_supports` at 30,000 gas
   (`:720-724`) and counts a failed call as a pass, so a sender short of gas could pass it. Fix: `_supports` requires `gasleft()`
   above `30,000 × 64 / 63` plus a margin before each probe (`ProbeGasLow`), so each probe gets its full EIP-165 stipend and its
   answer is the release's, not the sender's. The release constructors (the 12 kinds, the DEX, PqChat) check their modules by
   ordinary calls, which revert on failure (`src/dex/SCaaSDex.sol:111-125`, `src/pqchat/PqChat.sol:45-51`), and store no probe;
   T5 reviews every one of them again.
4. **No node involvement** (owner): the four approval ops and the three deploys are not node rows; all seven are in `NOT_ROWS`
   with the reason "release management is not a node job (owner 2026-11-10)".

**Gas.** A deploy transaction verifies no signature, so the release gas is exactly today's direct deploy, plus the approval
lookup when another account sends it (one cold `SLOAD` and one `SSTORE`, a few thousand gas [inference]). NET-EVM-11's 60 M
per-transaction bound stays as today: every release of the SCaaS testnet reset 2 fits it (the largest, `SCaaSDex`, 55,820,670
asked [measured, `smartcontracts/evm/runs/2026-11-10-scaas-testnet-reset2/summary.txt`]). An approval costs about one new slot
(about 98 k state gas) plus the admin's check.

**Threats.**
- **Front-running the open deploy** is harmless: the same bytes land at the same `CREATE2` address with the same result (the
  result does not depend on the sender's gas, item 3), and the slower sender reverts; the deploy plan takes "already deployed
  with the approved code hash" as done (T10).
- **An approval for a wrong hash:** the admin revokes it; it wins only if it lands before a deploy (anyone holding the bytes may
  send them once the approval is public); after a deploy the remedy is `deprecate*`, and the release is not creatable before
  `noticePeriod`.
- **Replay across chains or factories:** blocked by the bound `chainUid` and factory (checked fields, in the key, and in the
  router's domain and `target`).
- **A stale approval after an admin change:** dead by `adminGeneration` (a transfer or a renounce moves it, so Q1's "renounce =
  no release ever" holds and a thief's approvals die at recovery); an expired one is dead at `until`.
- **A deploy before `configureChain`:** refused.
- **State:** an approval is about one new slot (about 98 k state gas).
## 6. Deploy order (NET-EVM-05, NET-EVM-11)

```mermaid
sequenceDiagram
    participant D as deployer EOA (first admin)
    participant R as UA registry + GovernanceRouter
    participant F as OpenFactory(pad(D))
    participant M as msig / PQ UA
    D->>R: CREATE2 relay pair (constant salt, reused if there), SmartKeyAccountFactory, registry, libraries, router
    Note over D,R: with DEPLOY_REGULATED, CREATE2 ComplianceRegistry(adminUA, router)
    D->>F: CREATE2 OpenFactory(bytes32 admin = pad(D)): same address on every chain
    D->>F: configureChain(chainUid, noticePeriod, router, routerCodeHash, ref): direct only
    D->>F: setChainEntries, publishEnv, deploy releases, setKindEnabled
    D->>F: transferAdmin(M) (optional FACTORY_ADMIN_NEXT)
    M->>R: mtxAcceptAdmin(target F), any submitter, fee 0
    Note over F,M: from here every admin op is a typed op M signs, sent through R
```

- `DeployBase._deployTokenFactory` (`script/DeployBase.sol:353-369`) moves the factory after the account factory, the registry and
  the router (the ruling's order). `SmartKeyAccountFactory` comes first: its `IMPLEMENTATION` is a constructor argument of the
  registry and the router (`script/Deploy.s.sol:38-40`, `script/DeployBase.sol:365-366`, `:522`, `:777`; Fable P2-1). The
  factory's address depends on none of them. `new OpenFactory{salt}(MetaTxLib.pad(deployer))` (`:364`).
- `releases.json`: the row `registrar` (`:600`) becomes `admin`, the factory's constructor argument (the first admin); the
  factory row hashes `abi.encode(bytes32 admin)` (`:598-599`). The chain's book gains `factory_admin` (current) and the gate
  reads `admin()` and `pendingAdmin()` against it.
- `FACTORY_ADMIN_NEXT` (optional `bytes32`): the run's last transaction is `transferAdmin(next)`; the accept is `next`'s signed
  `mtxAcceptAdmin`, a separate step; until then the deployer stays admin and the gate reports the pending.
- `COMPLIANCE_ADMIN` becomes a `bytes32` UA id, required with `DEPLOY_REGULATED` (no default).
- NET-EVM-11 and the release deploys: §5.6 (no signature in a deploy transaction: today's gas plus the approval lookup; the 60 M
  bound as today).
- With the directory (§13.10): the relay pair, always under the constant salt and reused when its code is there, comes before
  the factory; `setChainEntries` writes it with the other entries after `configureChain`.

## 7. ABI consumers

| Consumer | Change |
|---|---|
| Contracts | §3–§5; `entries.json` → `gen_faces.py`; `face_abi.json` through the rename map |
| `scaas-node/src/typed.rs` | `:121` `PqTopic(bytes32 admin,…)`; `:207-209` the three renamed rows; eleven new `GR` rows (§5.4) |
| `scaas-node/src/guard.rs` | the router count `36` → `47` (`:1726`); `NOT_ROWS` (`:1649-1663`) + the four approval ops and the three deploys, reason "release management is not a node job (owner 2026-11-10)": the approval ops join the creations' exclusion, and `AUDIT_KINDS` gains `OpenFactory` as `factory`, whose three deploys (class `APPROVED(release)`) the test requires in `NOT_ROWS`; the decode bounds of §5.4; class `ADMIN` (`:1718`); the `infoOf` mock (`:2465-2466`) |
| `scaas-node/src/abi.rs` | `Created` without `ownerUA` (`:597-605`) |
| `test/vectors/selector_audit.json` | class `ADMIN`; the router's 15 new `SIGNED` rows; `OpenFactory` added (its `ADMIN` entries, the creations, the three deploys `APPROVED(release)`); the old names gone (both directions, `SelectorAudit.t.sol`) |
| `clients/clientkeys` | `src/evm.js:360-362` renamed + 15 router rows (the four approval ops among them); the approval keys (the `Env` type, the arrays); `src/pqchat.js:49`; the governance-bits sentence table; `scripts/typed-ops-vectors.mjs`, `scripts/pqchat-vectors.mjs` |
| `clients/ua-rs` | a router-op table for the 18 ops and the approval keys (the pattern of `src/regulated.rs`, `src/wraplimit.rs`), so a PQ or `msig` admin signs them (ua-rs signs every kind); tested against `typed_ops.json` |
| `clients/zether-prover/tests/typed_ops.rs` | `:22-23` the names |
| `src/regulated/RegulatedLib.sol` | `init` takes the token's `ChainEnv.govRouter` and checks the registry's (§5.3, Fable P1-1); every regulated kind's call site |
| `RegulatedBase`, `IRegulatedToken`, `IComplianceRegistry`; node `abi.rs`, `dex/venue.rs`; clientkeys `regulated.js` | the KYC provider names of §4.1 (`complianceOf`, `kycProviderEnabled`, `providerId`, reason 3) |
| Verification (NET-EVM-12) | `script/onchain/verify.sh`, `vcheck.py`: the new constructor arguments (`bytes32`; `(bytes32, address)`) and the directory's entries in the completeness check (Fable P3) |
| Other `ua-*` | no router or topic row; they read `governance_bits.json` (text only) |
| Vectors (generators only) | `typed/typed_ops.json`, `pqchat/topics.json` (topic ids unchanged, digests move), `governance/governance_bits.json` (`GovBitsVector.t.sol`), `governance/regulated_kat.json` (`RegulatedKat.t.sol`, the registry's code hash), `zether/state.json` (`ZetherStateVectors.t.sol`, `record` two words) |
| Matrix | `script/onchain/{Tokens,Dex,Gov,Misc,PqChat,Liquidity,WrapLimits,ZetherMore}.s.sol` (e.g. `Tokens.s.sol:276-278`, `:639-666`; `Dex.s.sol:477-488`; `Gov.s.sol:209-221`, `:289-299`, `:792`; `Misc.s.sol:318`; `PqChat.s.sol:530`; `PqChat.s.sol:187` is the instance and stays); new steps: misc's factory admin moved to an `msig` UA and every factory op through the router, gov's registry likewise; `coverage.py gen`, `notrun.json` reasons; `matrix.sh:227` `COMPLIANCE_ADMIN` becomes a UA id |
| Docs | every current doc naming the old identifiers (15 files, 114 hits today, mostly `token-wrappers.md`, `pqchat.md`, `contracts/README.md`, `networks/evm.md`, `dex.md`, `asset-suite.md`, `node/job-api.md`, `node/indexer-feeds.md`); `decisions.md` keeps its history and gains §11 |

## 8. Tests (red first) and mutants

Red first, each before its code: (1) `test/governance/AdminNames.t.sol`: on each of the 12 kinds and the DEX the new five answer
and the old five selectors revert with no data; (2) the four new typehash pins and the old four as legacy pins; (3)
`FactoryIndex.t.sol`: `Created` without the owner, no `contractsOfOwner`, a release whose `admin()` reverts is still created
(today `test_index_ownerRevertRevertsCreation`), the slot counts `test_index_slotCount_*` one record slot and one list push
fewer; (4) `test/v2/FactoryAdmin.t.sol`; (5) `test/as/RegistryAdmin.t.sol`; (6) the router ops in `GovRouter.t.sol`.

`FactoryAdmin.t.sol` and `RegistryAdmin.t.sol` cover: the constructor (factory: 0 and a derived id refused); a direct native
admin passes every op; a stranger `NotAdmin(pad(stranger))`; an EIP-7702 designator admin `CallerDelegated`; `configureChain`
direct only; after `transferAdmin` + router `acceptAdmin` by a derived UA (secp256k1, ML-DSA, `msig`), every op through the
router at fee 0 by a stranger relayer; another signer through the router `NotAdmin(signer)`; a contract answering
`subject() = admin` that is not the router refused; the same signature on a second factory or registry (same admin) refused,
and on a second chain (another `chain_uid`, router) refused; `acceptAdmin` by a non-pending `NotPendingAdmin`; renounce: admin 0,
pending 0, every op refused, including through a mock router answering 0. The registry's runtime code hash is equal across two
deployments with different admins and routers (F-11 positive control); the registry has no `renounceAdmin` (its selector
reverts with no data). KYC providers (§5.3.1): a native provider directly and a derived provider (`msig`, ML-DSA) through the
router each write rows under their own id; a derived provider's id called directly (`pad(msg.sender)` is not it) refused
`NotKycProvider`; a disabled provider's rows read inactive at once; a provider over an admin row `AdminWrittenSlot`; a provider's
`ELIGIBLE_CONTRACT` `EligibleContractAdminOnly`; an EIP-7702 designator provider `CallerDelegated`; provider 0
`KycProviderZero`; 257 rows `TooManyRows`; the old selectors (`setAttester`, `attest`, `attestationOf`, `attesterEnabled`,
`attesterId`) revert with no data; the `RegulatedKat` rows regenerated and equal.

**Field binding of every new signed op** (Fable P1-3): for each op (`UAPublishTokenEnv`, `UAPublishDexEnv`, `UAPublishClassEnv`,
`UADeprecateToken`, `UADeprecateDex`, `UADeprecateRelease`, `UASetTokenKindEnabled`, `UASetClassKindEnabled`, `UASetKycProvider`, `UASetCompliance`,
`UASetChainEntries`, `UAApproveTokenRelease`, `UAApproveDexRelease`, `UAApproveRelease`, `UARevokeApproval`), a
matrix test that changes one signed word at a time against the signature (each scalar; for each array one element, the length
and the order; the bytes of `reason`) and expects the router's refusal, with a positive control (the untouched call passes); one
mutant per op that drops a word from its hash (B1–B15); the digests reproduced by `clientkeys` and `ua-rs` from the same
`typed_ops.json` rows, one of them with a non-zero unbound `relayer` and `feeRecipient` (the zeroing of `MetaTxLib`'s canonical
form; AGENTS, Cryptography).

**Further** (Fable P1-1, P1-2, P2-3 to P2-5, P2-8): a regulated token refuses a canonical-code registry whose `govRouter()` is
another router (`ComplianceRegistryRouterMismatch`) and takes one with 0 or its own; the registry constructor refuses a derived admin
without a router and a router without code; `transferAdmin` and `renounceAdmin` before `configureChain` refuse
(`ChainNotConfigured`); a derived pending on a router-less factory cannot accept and the admin stays; a renounce clears the
pending (a renounced factory never comes back through it); a 7702-delegated native admin through the router is checked by its own
key only (a delegate whose ERC-1271 says yes changes nothing); a nested router op refused; the gas rows of §5.6.

**The deploy ruling** (§5.6). Passing: the shortcut's three rows, one test each: (1) the native admin sends `deploy*` itself,
one transaction, no approval, at today's gas; (2) a native EOA admin approves (directly, and in a second test through the
router) and another account deploys; (3) a derived admin (`mldsa65`, an `msig` of three ML-DSA-65 at 2-of-3, `webauthn-p256`)
approves through the router, sent by a stranger, and another account deploys. Refused (`ReleaseNotApproved` unless named): a
deploy without approval by a non-admin sender; one whose `initcode`, `implArgs`, `envVersion` or id differs from the approval's
by one byte or one field (among them the two class fields: a deploy with another `initSelector`, one with another
`interfaceId`); an approval used twice; a revoked approval; an expired one (`until`); one of a previous admin term (after a
transfer, after a renounce); after the admin moves to an `msig`, the original deployer EOA's own deploy without approval; an
approval naming another `chainUid` or factory (`ApprovalFieldMismatch`), or one made on another chain or factory, opening
nothing here; a deploy before `configureChain` (`ChainNotConfigured`); revoking a consumed approval (`ApprovalNotRevocable`); an
`until` more than 30 days ahead (`ApprovalTooLong`). Re-approval passes after expiry, after a transfer of the admin and after a
revoke (Fable re-check N2). A native admin's own deploy with a live approval of the same key consumes it. An admin EOA that is a
7702 designator deploys only through an approval. A deploy at the lowest gas that succeeds gives the same code hash and the same
release record as one at ample gas, and `_supports` below its floor refuses (`ProbeGasLow`) (Fable re-check N3). The approval
structs' field binding is the per-word matrix above (B12–B15) with its mutants; their digests are reproduced in `clientkeys` and
`ua-rs`.

Mutants (each must turn a named test red; the round's mutant log records it):

| # | Mutant | Caught by |
|---|---|---|
| M1 | `_adminSubject` asks any caller for `subject()` | the fake-router test |
| M2 | the router branch returns `pad(msg.sender)` | the derived-admin tests |
| M3 | `onlyAdmin` drops `c != 0` | renounce + mock router answering 0 |
| M4 | the direct path drops `requireNotDelegated` | the designator test |
| M5 | `entries.json` keeps an `owner()` alias | `AdminNames.t.sol`, `SelectorAudit.t.sol` |
| M6 | `_create` still reads `admin()` | the reverting-`admin()` creation |
| M7 | `UATransferAdmin` keeps `newOwner` | the typehash pin, the clientkeys vector |
| M8 | `TOPIC_TYPEHASH` keeps `owner` | `PqChatTypes.t.sol`, `topics.json` |
| M9 | `acceptAdmin` leaves the pending | a second accept |
| M10 | the factory constructor takes a derived id | the constructor test |
| M11 | `setCompliance` from the router takes a non-admin subject as the admin | `RegistryAdmin.t.sol` |
| M12 | a node row keeps `mtxTransferOwnership` | `allow_lists_equal_the_selector_audit_both_directions` |
| M13 | `setCompliance` looks the KYC provider up by `msg.sender`, not the subject | the derived-provider test |
| M14 | the registry keeps a `renounceAdmin` | the no-renounce test, `SelectorAudit.t.sol` |
| M15 | a node row for a release deploy | the guard test (`NOT_ROWS`, `APPROVED`) |
| M16 | `RegulatedLib.init` drops the registry-router check | the `ComplianceRegistryRouterMismatch` test |
| M17 | `_renounceAdmin` leaves the pending | the renounce-clears-pending test |
| M18 | `transferAdmin` writes the admin in one step | the two-step tests |
| M19 | `acceptAdmin` drops `c != 0` | a mock router answering 0 with no pending |
| M20 | the registry's `_adminRouter()` answers 0 or another address | the derived registry-admin tests |
| M21 | the registry constructor takes a derived admin with router 0, or a router without code | the constructor tests |
| M22 | `transferAdmin` / `renounceAdmin` without `configured` | the unconfigured tests |
| M23 | the shortcut accepts a sender that is not the admin (or reads the router's `subject()`) | the non-admin-sender and through-the-router tests |
| M24 | the deploy skips the approval lookup, or takes the hashes from somewhere but the call's bytes | the no-approval and one-byte tests |
| M25 | the key leaves out `chainUid`, the factory, `envVersion`, `initSelector`, `interfaceId` or the tag | the cross-chain, cross-factory, `envVersion`, `initSelector`, `interfaceId` and cross-domain tests |
| M26 | `adminGeneration` or `until` not checked at the deploy | the stale-generation and expired tests |
| M27 | the deploy does not mark the approval consumed | the used-twice test (the approval check runs before the version check) |
| M28 | `revokeApproval` without `onlyAdmin`, or on a consumed key | the revoke tests |
| M29 | an approval that ignores its `chainUid`, `factory` or `adminGeneration` field | the `ApprovalFieldMismatch` tests |
| M30 | `approve*` refuses an entry that is no longer live (expired, older term, revoked) | the three re-approval tests |
| M31 | `_supports` counts a failed probe as a pass without the gas floor | the low-gas deploy test |
| B1–B15 | one per new signed struct: a word dropped from its hash | that struct's binding matrix |

Gates: every `forge` directory and the node e2e (the change is shared), `script/pqz/at-set.sh <set> test` at the four sets,
the size gate, layout, ABI and gas pins, `cargo test` + `clippy -D warnings`, clientkeys and ua-rs tests, the local matrix run.

## 9. Gas and size

- **Renames:** zero bytes of logic; selector values move, so each dispatcher's order does: a few gas per entry either way
  [inference]; the pinned gas figures move only with old → new in the commit.
- **Creation:** one record slot, two list writes (`_byOwner` length and element) and one `STATICCALL` fewer per creation, so
  `createToken`, `createDex`, `createInstance` fall from their last pins (2,183,102 / 4,383,367 / 1,826,732 [measured,
  CTR-TOK-27]); new pins measured.
- **Admin ops:** a cold `SLOAD` of the admin instead of an immutable read (+2,100 [inference]); through the router, the router's
  verification on top (a native ECDSA in the tens of thousands, a PQ or `msig` more). A release deploy verifies no signature:
  today's gas, plus the approval lookup when another account sends it; an approval is about one new slot (about 98 k state
  gas) and the admin's check (§5.6).
- **Size:** `OpenFactory` 29,238 B [measured, `size-baseline.json`] gains `UAAdmin` and loses the owner index (net about +0.5 to
  +1 KB [estimate]); `GovernanceRouter` (not in the baseline) gains 15 entries with the `Env` and array hashing (several KB
  [estimate]); the registry about +1 KB. Measured in T12; a baseline row moves only with its reason.

## 10. Owner rulings on the questions (2026-11-10)

Each answer is the owner's, in chat, relayed by the controller; status: decided, SPECIFIED, nothing built.

- **Q1. The factory admin: a two-step transfer and a renounce, as in `GovernanceBase`.** The first admin is a native id (the
  constructor refuses a derived one) and `configureChain` is its direct call. **Consequence: a renounce also ends deprecation**,
  with every other admin op (env, release, kind switch): a release found bad after it can no longer be deprecated on that
  factory. Why (spec): "immutable but UA-typed" cannot serve a derived admin, whose only path is the router, which the factory
  may trust only after `configureChain` names it; a router in the constructor would give the factory another address per chain.
- **Q2. The `ComplianceRegistry` admin: a two-step transfer, no renounce.** Why: a derived UA's keys never change
  (`accounts.md:70-72`), so the transfer is how an `msig` or PQ admin rotates; with no admin nobody could void a bad KYC provider's
  rows or write an `ELIGIBLE_CONTRACT` row.
- **Q3. Option (i), updated by the final P1-2 ruling the same day: release management is not a node job.** Neither the approval
  ops nor the deploys are node rows; all are in `NOT_ROWS` with the reason "release management is not a node job (owner
  2026-11-10)"; the gateway's limit is irrelevant; every other admin op is a node row (§5.4, §5.6, §7).
- **Q4. `FactoryInfo.ownerUA` is dropped** (six words, 192 B). The PqChat instance keeps `owner()` (`bytes32`).
- **Q5. Yes: the attester becomes a UA too, inside 3r**, in the `governed` / `UAAdmin` pattern (§5.3.1): an attester is the
  subject of its own call, not a signer riding in another's; every 3f rule (CTR-PQZ-27 to CTR-PQZ-30) and every row rule stays.
  **Then (owner, same day) its name: the KYC provider** (`setKycProvider`, `kycProviderId`, `providerId`, `NotKycProvider`,
  `KycProviderSet`, `UASetKycProvider`), and the row op `setCompliance` / `UASetCompliance` (§4.1, §5.3.1).
- **Q6. The names as proposed** (§4.1): `admin()`, `pendingAdmin()`, `transferAdmin(bytes32)`, `acceptAdmin()`,
  `renounceAdmin()`, `AdminTransferStarted` / `AdminTransferred(previousAdmin, newAdmin)`, `NotAdmin(bytes32)`,
  `NotPendingAdmin(bytes32)`, `AdminAccountPool`, `AdminHasHolders`, `adminGeneration`, config field `admin`, selector-audit
  class `ADMIN`, `UATransferAdmin(…,bytes32 newAdmin,…)`, `UAAcceptAdmin`, `UARenounceAdmin`, `topicsByAdmin`,
  `PqTopicNotAdmin`, the factory's `AdminNotNative`, the registry's `AdminZero`.
- **Directory: option (a)**, write-once, one address per name, no versions (§13); **then (owner, same day) no constants: the relay
  pair is a write-once entry too**, under its constant salt.
- **The release deploys (owner, final, on Fable P1-2): approve, then an open deploy.** The admin approves one release by hash
  (`approve*`, relayable, fee 0 too; `revokeApproval` for an unused one; dead at an admin change or at `until`); the deploys keep
  their names, are open to anyone, carry no signature and go straight to the factory, each approval consumed once; the native
  admin's own deploy is its own approval (the three-row table of §5.6). No 50 M rule: NET-EVM-11's 60 M stays as today.
- **P2-5 (owner): no restriction.** Derived admins may be used everywhere at once; the trust-root note stays as information (§5.5).

## 11. `decisions.md`

Recorded on this branch: [CTR-GOV-23](../../decisions.md#ctr-gov-23--one-admin-per-contract-a-ua-named-admin-on-every-contract)
(owner: yes; status SPECIFIED) with the rulings R1–R3, Q1–Q6 and the directory, and Change lines on CTR-TOK-27 (R1, Q4),
CTR-TOK-29 (the constructor, Q1, the directory), CTR-AS-07 (Q2, Q5, the registry-router check), CTR-GOV-01 (the names) and
NET-EVM-05 (the deploy order, the first admin's custody) and NET-EVM-11 (a deploy carries no signature check); the deploy
ruling is in CTR-GOV-23.
The component docs (`token-wrappers.md`, `asset-suite.md`, `pqchat.md`, `networks/evm.md`, the node's) move with the build
(T14), when the code exists.

## 12. Tasks

| Task | Content | Estimate |
|---|---|---|
| T1 | Red tests: `AdminNames.t.sol`, typehash pins, `FactoryIndex` changes, `FactoryAdmin.t.sol`, `RegistryAdmin.t.sol` skeletons | 0.5 d |
| T2 | R3 in the governed contracts: `IAdmin`, `IGovernance`, `GovernanceLib`, `GovernanceBase`, `SCaaSDexAdmin`, `SCaaSDex`, `WrappedLib`, `PqzStateLib`, `ZetherLib`, the config fields, `entries.json` + `gen_faces.py`, `face_abi.json` map, layout labels, `GovBitsVector` sentences | 1 d |
| T3 | R3 on the topic: `IPqChat`, `PqChatTypes`, `PqChatCore`, `PqChatTopics`, `PqChat`; `topics.json`; node `typed.rs:121`; clientkeys `pqchat.js` | 0.5 d |
| T4 | R1: record, views, events, `FactoryInfo`, reads; `ZetherStateVectors` + `state.json`; node `abi.rs`, guard mock | 1 d |
| T5 | `UAAdmin`; `OpenFactory` admin (constructor, `onlyAdmin`, transfer and renounce under `configured`), the approvals (the key per deploy kind, live, the 30-day cap), the revoke, the open deploys and the native admin's shortcut, the gas-independence review of every release constructor and `_supports`'s floor (§5.6); `FactoryAdmin.t.sol` green | 2 d |
| T6 | `ComplianceRegistry` admin, router, constructor refusals, transfer without renounce, KYC providers by UA (§5.3.1), the row bound; `RegulatedLib`'s registry-router check; `RegistryAdmin.t.sol`; `regulated_kat.json`; `Gov.s.sol`'s `setAttester` | 2 d |
| T7 | Router: the 3 renamed and the 15 new ops, the binding matrix per signed struct and its mutants (B1–B15), `Env` and array hashing, the view `smartKeyCloneHash()`, pins, `GovRouter.t.sol` | 2 d |
| T8 | Clients and vectors: clientkeys rows + `typed_ops.json`, ua-rs router-op table + test, zether-prover list | 1 d |
| T9 | Node: rows, `NOT_ROWS`, counts, class `ADMIN`; `cargo test`, `clippy` | 0.5 d |
| T10 | Deploy: `DeployBase` order (§6, §13.10), the relay pair under the constant salt, `FACTORY_ADMIN_NEXT`, `COMPLIANCE_ADMIN` as UA, release rows, the gate; `DeploySend.s.sol` takes a release already deployed with the approved code hash as done, so a front-runner cannot fail the plan step by step (Fable re-check P3); every release on a 60 M anvil (§5.6, NET-EVM-11) | 1 d |
| T11 | Matrix: scripts renamed, the router steps for the factory and the registry, coverage, local run | 1 d |
| T12 | Gates and pins: every forge dir, the four PQZ sets, size, layout, ABI, gas old → new | 0.5 d |
| T13 | Mutants M1–M31, B1–B15, D1–D14, log | 1 d |
| T14 | Docs: component docs (`decisions.md` done, §11), `docs_check` | 0.5 d |
| T15 | The directory (§13): the relay pair under the constant salt and its reuse, every entry write-once, `setChainEntries`, `configureChain`'s checks, the registry and `SmartKeyAccount` bindings, `directory()`; `FactoryDirectory.t.sol`, mutants D1–D14; `DeployBase` and `e2e.py` order | 1.5 d |
|  | **Total** | **≈ 16 d** |

## 13. `OpenFactory` as the chain's directory (owner ruling 2026-11-10, option (a))

**Ruling (owner).** From the factory anyone finds the chain's fixed shared contracts: `UARegistry`, `GovernanceRouter`,
`RelayFeeRouter`, `RelayFeeExecutor`, `ComplianceRegistry`, `SmartKeyAccountFactory`, and the shared Zether contracts that stand
apart. Option (a): write-once, one address per name, no versions; constants could be used, and then (owner, same day) none
are: the relay pair is write-once too (§13.2). Excluded: libraries and body modules
(they are in the env and the releases), and per-DEX children (`DexPuller` through `dex.puller()`, `mtxLiquidityPull` a token
entry, the position readers listed by the DEX). Status: decided, SPECIFIED, nothing built.

### 13.1 The entries, from the deploy scripts at `74262fa0`

| Name | Chain-neutral? | Constant or write-once | Source of the address |
|---|---|---|---|
| `UARegistry` | no: constructor `chain_uid` (`script/DeployBase.sol:777`) | neither: not stored | the router's `registry()`; every env bound to it (§13.4) |
| `GovernanceRouter` | no: `(chain_uid, registry, smartKeyAccountImpl, hedera)` (`:522`) | write-once, `configureChain` (today's `govRouter`) | `configureChain`'s `govRouter_`, code hash the admin's argument |
| `RelayFeeRouter` | yes: no argument (`:511`), under the constant salt (§13.2) | write-once, `setChainEntries` (owner) | the admin's write; code hash the admin's argument |
| `RelayFeeExecutor` | yes: `CREATE` by the relay router's constructor, nonce 1 (`src/metatx/RelayFeeRouter.sol:59`) | not stored: read through the written relay router | `relayFeeRouter().EXECUTOR()`; its code hash checked at the router's write |
| `ComplianceRegistry` (the SCaaS deploy's) | no in 3r: `(bytes32 admin, address govRouter)` (§5.3); today `(admin)` (`:496`) | write-once, `setChainEntries` | the admin's write; code hash the admin's argument |
| `SmartKeyAccountFactory` | no: `(chain_uid)` (`script/Deploy.s.sol:38`) | write-once, `setChainEntries` | the admin's write; code hash the admin's argument |
| `ZetherStatements` | yes: no argument (`:852`); optional (no Zether on Hedera or without EIP-2537) | write-once, `setChainEntries` | the admin's write; code hash the admin's argument |

Not entries, each found where it lives: the libraries and body modules (`envOf(…).libs`, `modules()`), the releases (the
catalogue), Zether's `ZetherDisclosure` and the transfer, burn and inner-product verifiers and the PQZ verifiers (an env's `deps`,
`:861-862`), the `SmartKeyAccount` implementation (`smartKeyAccountFactory().IMPLEMENTATION()` and `Env.smartKeyAccountImpl`),
`DexPuller` (`dex.puller()`), the position readers (the DEX), PqChat instances (the index). The Zether registry is the UA
registry (`:869`), so it stands apart from nothing. **The `ComplianceRegistry` entry** is the registry the SCaaS deploy itself
makes (`COMPLIANCE_ADMIN`), one issuer policy among many (CTR-AS-07: one per issuer policy, deployed by anyone); naming it
confers nothing: a regulated token names its own registry in its config and checks its code and its router (§5.3) (Fable P3).

### 13.2 No constants (owner ruling 2026-11-10)

- **Every entry is write-once; the factory holds no other contract's address or code hash.** Its address on every chain depends
  only on its own code and its first admin. Why (Fable P2-7, checked at `74262fa0`): `foundry.toml` sets no `bytecode_hash` (its
  line 5 already guards the metadata against stray sources), so the CBOR metadata, which carries the `keccak256` of every source
  file in a compilation, is in each init code and runtime. A constant would tie the factory's address, and every release's (each
  names its factory), to every byte of that singleton's source closure, comments included: for the relay pair,
  `src/metatx/RelayFeeRouter.sol` and its imports (`src/common/MetaTxLib.sol`, `src/common/FeePolicy.sol`,
  `src/common/SigCheck.sol`, `src/metatx/IERC20MetaTx.sol`, `src/ua/IUARegistry.sol`, OpenZeppelin's `IERC20`, `SafeERC20`,
  `ReentrancyGuardTransient`; `MetaTxLib.sol` alone changed in five commits since 2026-11-01); for `ZetherStatements`, its
  `ZetherLib.sol` closure; for the registry, its own.
- **The relay pair keeps its constant salt** (Fable P2-2): `script/onchain/matrix.sh:227` deploys each target under its own
  `DEPLOY_SALT`, and `_deployRelayFeeRouter` uses that salt today (`script/DeployBase.sol:511`). The pair always goes under
  `RELAY_SALT = keccak256("scaas.deploy.v1")`, so it has one address on every chain and every stack, and is reused when its code
  is already there (no second `CREATE2`, which would revert); `DEPLOY_SALT` moves only the rest.

### 13.3 Write-once entries

- **The router:** `configureChain(chainUid_, noticePeriod_, govRouter_, govRouterCodeHash, refBlock, refHash)`:
  `govRouter_.codehash` must equal `govRouterCodeHash` (not 0, not `keccak256("")`), beside today's `chainUid()` check, and its
  `registry()` must be non-zero with code (Fable P3); `govRouter_` 0 with hash 0 is no router. The router's runtime carries
  `chain_uid` and the registry as immutables, so its hash is per chain and comes from the deploy's build.
- **`setChainEntries(address relayFeeRouter, bytes32 relayFeeRouterCodeHash, bytes32 relayFeeExecutorCodeHash, address
  complianceRegistry, bytes32 complianceRegistryCodeHash, address smartKeyAccountFactory, bytes32 smartKeyAccountFactoryCodeHash,
  address zetherStatements, bytes32 zetherStatementsCodeHash)`**, `onlyAdmin configured`: each non-zero address is written once,
  into its zero slot, else `EntryAlreadySet(bytes4 view)`; 0 leaves the entry open for a later call (a chain may add the
  regulated kinds or Zether later). Each code hash must be its argument (not 0, not `keccak256("")`). The relay router's
  `EXECUTOR()` must have the executor's code hash and answer `ROUTER()` with the relay router; the registry's `govRouter()` must
  be the factory's; the account factory's `chainUid()` must be the factory's and its implementation's clone hash the router's
  (§13.4). Event `ChainEntrySet(bytes4 indexed view, address at, bytes32 codeHash)`. Relayable: `mtxSetChainEntries` (§5.4), a
  node row.
- Storage: four slots appended after `_classes` (slot 8 untouched).

### 13.4 One source for the registry and the `SmartKeyAccount` implementation

- **The registry.** `uaRegistry()` stores nothing. Its value is the router's `registry()` (`src/metatx/UAMetaTxBase.sol:365`),
  an immutable of the router's runtime, so the router's code-hash check at `configureChain` pins it too; and every `publishEnv`,
  `publishDexEnv`, `publishClassEnv` refuses an `env.registry` other than 0 or that value (`EnvRegistryMismatch(expected,
  got)`). The env each clone carries, the router that authenticates its governance and the directory name one registry. Without
  a router `uaRegistry()` is 0 and the envs are free, as today. A stack with its own registry has its own router and its own
  factory (`script/pqz/e2e.py:1295-1315`), so one registry per factory holds.
- **The `SmartKeyAccount` implementation, bound from the router** (Fable P2-6). The router holds it as `_SMART_KEY_CLONE_CODEHASH`
  (the EIP-1167 clone code hash of the implementation, `src/metatx/UAMetaTxBase.sol:38-48`), and so does the UA registry
  (`smartKeyCloneHash()`, `src/ua/UARegistry.sol:378`). The router gains the view `smartKeyCloneHash()`. `configureChain` requires
  the router's to equal its registry's; every env publish requires `env.smartKeyAccountImpl` to be 0 or an implementation of that
  clone hash (`EnvSmartKeyAccountMismatch`); `setChainEntries` requires the account factory's `IMPLEMENTATION()` to be one.
  Sound: equal clone hashes mean equal implementations (the 45-byte clone embeds the address), and no env can precede the
  binding, since every publish carries `configured` (`OpenFactory.sol:133-141`, `:344-346`). Without a router there is no
  binding, as today.

### 13.5 Cycles

None. The factory holds no other contract's address or code in its init code (§13.2), so no singleton can depend on it through
a constant; and no constructor of the seven at `74262fa0` takes the factory (`UARegistry` `src/ua/UARegistry.sol:164-172`; the
router `(chain_uid, registry, smartKeyAccountImpl, hedera)`; `RelayFeeRouter` none, its executor none, `ROUTER = msg.sender`;
`SmartKeyAccountFactory` `(chain_uid)`; `ComplianceRegistry` `(admin)`, in 3r `(admin, govRouter)`; `ZetherStatements` none). A
later entry whose init code needs the factory is a write-once entry like the rest. (Had the registry been a constant, finding
its router through the factory would have closed a cycle; the router is its constructor argument, §5.3.)

### 13.6 ABI

```solidity
struct Directory {
    address uaRegistry;
    address govRouter;
    address relayFeeRouter;
    address relayFeeExecutor;
    address complianceRegistry;
    address smartKeyAccountFactory;
    address zetherStatements;
}
function directory() external view returns (Directory memory);
function uaRegistry() external view returns (address);             // the router's registry(); 0 without a router
function govRouter() external view returns (address);              // exists (CTR-TOK-29): one name, no second one
function relayFeeRouter() external view returns (address);         // 0 until written
function relayFeeExecutor() external view returns (address);       // relayFeeRouter().EXECUTOR(); 0 until written
function complianceRegistry() external view returns (address);     // 0 until written
function smartKeyAccountFactory() external view returns (address); // 0 until written
function zetherStatements() external view returns (address);       // 0 until written
```

No generic key map: a new entry comes with a new factory release, under (a).

### 13.7 Threats

- **A wrong address written once** is refused at the write unless its code is the expected code (no code and empty code fail).
  Once written, nothing but a new factory fixes it, and a new factory is a new address on every chain. So the deploy flow checks
  before writing: `DeployBase` takes every expected hash from its own build and the chain's book, dry-runs the call (as
  `configureChain`'s dry run, NET-EVM-05) and writes after the gate; the gate then compares `directory()` with the book.
- **What the code hash does not prove.** It pins code, not state (a canonical-code registry whose admin is a thief passes it:
  hence the `govRouter` checks, here and in every regulated token, §5.3), and an admin-supplied hash proves only that the admin
  wrote what it claimed (a typo is caught, a malicious admin is not). The directory is discovery: no contract reads it for
  authority, and clients verify every entry's code hash against the pinned list (`releases.json` for the chain-neutral ones, the
  chain's `deployments/<key>.json` for the chain-specific ones) before use.
- **A stolen admin key** fills an open entry once with code of the hash it supplies; it changes no entry already written (stated
  as ruled; the open entries stay a target until written).

### 13.8 Size and gas [estimate]

- Views: a write-once entry one cold `SLOAD` (2,100 [inference]); `relayFeeExecutor()` one `SLOAD` and one `STATICCALL`;
  `uaRegistry()` one `STATICCALL` to the router; `directory()` all of them, about 10 k gas, an `eth_call`.
- Writes, once per chain: `setChainEntries` four new slots, an `EXTCODEHASH` per contract and five view calls; `configureChain`
  one `EXTCODEHASH` and three view calls more; every env publish one `STATICCALL` more (two with a `SmartKeyAccount`
  implementation).
- `OpenFactory` about +0.8 to +1.3 KB (eight views, the struct, the setter and its checks; no literals); the router one op and one
  view more.

### 13.9 Tests and mutants

`test/v2/FactoryDirectory.t.sol`, red first: `configureChain` refuses a router of another code hash, one whose `registry()` is 0
or has no code, one whose clone hash differs from its registry's; `setChainEntries` writes each of the four entries once and
refuses a wrong code hash, no code, a second write of each (`EntryAlreadySet`), a stranger (`NotAdmin`); for the relay pair it
refuses a router whose `EXECUTOR()` has another code hash or whose executor's `ROUTER()` is another address, and
`relayFeeExecutor()` answers 0 until the router is written and then its `EXECUTOR()`; it refuses a registry naming another
router, an account factory of another `chainUid` or another implementation; 0 leaves an entry open and a later call fills it; a
derived admin writes through `mtxSetChainEntries`; every view answers 0 until written; `directory()` equals the named views; each
of the three publish entries refuses an env naming another registry (`EnvRegistryMismatch`) or another implementation
(`EnvSmartKeyAccountMismatch`) and passes 0 and the router's; two chains (`ChainNeutralFactory.t.sol`): one factory address, each
chain its own entries; a stack under another `DEPLOY_SALT` reuses the shared relay pair (same address, no second `CREATE2`) and
writes it.

| # | Mutant | Caught by |
|---|---|---|
| D1 | `setChainEntries` overwrites a written entry (one mutant per entry, four) | that entry's second-write test |
| D2 | no code-hash compare at the write | the wrong-hash tests |
| D3 | 0 or `keccak256("")` taken as a code hash | the no-code tests |
| D4 | an env publish without the registry agreement (one mutant per publish entry) | that entry's `EnvRegistryMismatch` test |
| D5 | `directory()` reads another source than the views | the equality test |
| D6 | `configureChain` skips the router's code hash | its test |
| D7 | `setChainEntries` drops the registry's `govRouter` check | the other-router test |
| D8 | `setChainEntries` drops the account factory's `chainUid` check | the other-`chainUid` test |
| D9 | `configureChain` drops the router-registry clone-hash check | its test |
| D10 | an env publish drops the implementation binding (one mutant per publish entry) | that entry's `EnvSmartKeyAccountMismatch` test |
| D11 | `setChainEntries` drops the implementation binding | the other-implementation test |
| D12 | `configureChain` takes a router whose `registry()` is 0 or has no code | its test |
| D13 | `setChainEntries` drops the executor's code-hash or `ROUTER()` check | the executor tests |
| D14 | `relayFeeExecutor()` answers anything but the written router's `EXECUTOR()` | the executor view test |

### 13.10 Deploy order with the directory

The CREATE2 deployer → `RelayFeeRouter` under `RELAY_SALT` (its executor in the same transaction; reused if there) →
`SmartKeyAccountFactory` (its `IMPLEMENTATION` is an argument of the next two) → the UA registry → the router →
`ComplianceRegistry(admin, router)` with `DEPLOY_REGULATED` → `ZetherStatements` with `DEPLOY_ZETHER` → `OpenFactory(pad(deployer))`
→ `configureChain(…, router, routerCodeHash, …)` → `setChainEntries(the relay pair, the registry, the account factory,
`ZetherStatements`, their hashes)` → envs and releases → `transferAdmin`. Today `DeployBase` deploys the account factory first
(`script/Deploy.s.sol:38`), the relay pair after the factory under `DEPLOY_SALT` (`script/DeployBase.sol:364-367`, `:511`), and
`ZetherStatements` inside `_deployZether` after `configureChain` (`:852`). `script/pqz/e2e.py` deploys its factory after its
registry and router (`:1295-1315`), reuses the shared relay pair and writes it with `setChainEntries`.
