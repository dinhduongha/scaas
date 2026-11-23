# PqChat: the signature-storage setting per home instance: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task by task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-23):** S1–S5 BUILT on branch `pqchat-sigs` (made from `origin/ua-rs-sign` at `5c64f15ba`); the code started
at once (auto-run mandate); gate rows in `smartcontracts/evm/runs/2026-11-23-pqchat-sigs-summary.txt`. **UNAUDITED.**

**Owner ruling (2026-11-23, owner: yes):** "Theo cách 2 với mặc định là SSTORE2, kèm (d - option)": the pqchat-core spec §13 O11 is
settled by (b) in this form, replacing "(b) asked for the next `PqChat` release":

1. Every `PqChat` home instance has an **immutable signature-storage setting**, fixed when it is created, with the modes `none` and
   `sstore2`; **the default is `sstore2`**. In `sstore2` every accepted control-plane record keeps its signature bytes in contract
   state; the setting and each record's signature are read by views; `none` is today's behaviour (`sigHash` only). No log mode
   (state-only recovery). The pattern is PQZ's proof-storage token setting. A setting per session was rejected (a lying endpoint
   could report it off: a downgrade).
2. `pqchat-core` gets the option `require_signed_records`: on, a home whose setting is `none` is refused (read under trusted
   reads); on an `sstore2` home the author's `UASig` over the rebuilt EIP-712 digest of every control-plane record it uses
   (`sealedInfo` included) is verified before the record is trusted. The default is a controller call.
3. (d) as an option: the SDK and `pqchat-core` expose strict majority (CLI-RPC-05/06) for PqChat's control-plane reads; never
   forced.

**Goal:** the contract change, the factory and catalogue path, the node's rows, the vectors and every reader, in one round.

## 1. Design

### 1.1 ABI (`IPqChat`)

| Item | Form |
|---|---|
| modes | `SIG_STORE_NONE = 0`, `SIG_STORE_SSTORE2 = 2`: PQZ's numbering (`NONE` 0, `LOG` 1, `SSTORE2` 2), so one vocabulary; 1 (log) is never valid here |
| initializer | `initialize(bytes32 ownerUA, uint8 sigStore)` (was `initialize(bytes32)`); `sigStore` neither 0 nor 2: `PqChatSigStore(uint8 sigStore)` |
| setting | `sigStore() returns (uint8)` |
| signatures | `sessionSig(bytes32 sessionId)`, `epochSig(bytes32 epochId)`, `removalSig(bytes32 epochId, uint256 index)`, `messageSig(bytes32 sessionId, uint256 index)`, `leaveSig(bytes32 epochId, uint256 index)`, each `returns (IUARegistry.UASig memory sig)`; on a `none` home `PqChatSigNotStored()`; unknown ids as the record views (`PqChatUnknown`, an index past the end the array-bounds panic). As built: each view returns the stored signature's tail as its ABI output directly (the compiler's memory decoder of a `UASig` runs out of stack in the legacy pipeline) |
| leave records | `leaveCount(bytes32 epochId) returns (uint256)`, `leaveAt(bytes32 epochId, uint256 index) returns (PqChatLeave memory l, bytes32 sigHash)`: kept on an `sstore2` home only (a `none` home keeps today's flag alone, so `leaveCount` is 0) |

The record views (`sessionOf`, `epochOf`, `removalAt`, `messageAt`) are unchanged. One entry per operation and per record kind; the
signature is returned as the named `UASig` struct, never as bytes. `interfaceId` moves (new views); the release's catalogued
`initSelector` moves with the initializer.

**Which records.** Session, epoch, leave and removal (the control plane) and `postMessage`'s message: a message read with
`messageAt` is a record whose authorship a client must check (the spec's K12 is the same gap), so it is kept too. Topic records are
out: they are public, choose no key or epoch, and live in the body module; an owner question (§4).

### 1.2 Where the setting is passed

- **Creation:** `OpenFactory.createInstance(ReleaseId(3, 0, v), salt, abi.encodeCall(IPqChat.initialize, (ownerUA, sigStore)))`,
  and the router's `mtxCreateInstance` with the same `initCall`. The setting is fixed for the instance's life: no setter.
- **Catalogue:** the factory binds each release's initializer selector at `deployImplementation`; the release now catalogues
  `initialize(bytes32,uint8)`. The factory itself does not change and keeps no per-instance setting: a client reads `sigStore()` at
  the instance (a trusted read) and pins it per instance (§1.5).
- **Default `sstore2`:** every tool that creates an instance passes 2 unless told otherwise: the deploy scripts, clientkeys'
  `instanceInitCall`, the node's named config (`args.config.sigStore`, absent = 2), the tests' helpers.

### 1.3 Storage (CTR-CHAT-05)

- The setting: `uint8 sigStore` packed after `initialized` in the namespace's slot +1 (byte 1). Every signed write reads it (one
  cold `SLOAD`, both modes).
- As built, the blob is assembled byte for byte from `abi.encode(record)` and `abi.encode(sig)` (`PqChat._blob`; the tuple
  encoder of a calldata record and signature runs out of stack), and the shared `PqGroupBase._noneRemoved` reads the author
  through a hook (`_authorOf`) that `PqChat` overrides to follow the record's offset word (the author moves one word in the
  three-word head; a test caught it: `test_removedAuthorsStagedChildCannotComplete`).
- **In the record's own blob** (chosen over a sibling blob): on an `sstore2` home a record is stored as
  `abi.encode(record, sigHash, sig)` (`sigHash = keccak256(abi.encode(sig))` kept, so replicas still compare record and
  `sigHash`); on a `none` home as today, `abi.encode(record, sigHash)`. The existing decoders read the first two head words and are
  unchanged. A sibling blob costs a new account and a slot per record (about 0.28 M state gas more than the same bytes inside the
  record's blob); the record's blob is read by every later write of its epoch (`_lists`), which pays about 1 k regular gas more per
  copied 4 KiB.
- Leaves: `mapping(bytes32 => address[]) leaves` appended to the namespace (+22), one blob per accepted leave, `sstore2` only.
- `postMessage`'s one-blob rule counts the stored blob, signature included: on an `sstore2` home a large `msig` signature leaves less
  room for the ciphertext.

### 1.4 Signature sizes and bounds

`abi.encode(UASig)` of a single key (no `keyData`, no members) is `192 + ⌈len / 32⌉ × 32` B; stored at 1,530 state gas per byte
(EIP-8037 code bytes).

| Kind | Signature | Encoded | State gas per record |
|---|---:|---:|---:|
| FN-DSA-512 | 666 | 864 | 1,321,920 |
| ML-DSA-44 | 2,420 | 2,624 | 4,014,720 |
| ML-DSA-65 | 3,309 | 3,520 | 5,385,600 |
| ML-DSA-87 | 4,627 | 4,832 | 7,392,960 |
| SLH-DSA-128s | 7,856 | 8,064 | 12,337,920 |

An `msig` carries its quorum's signatures (minimal form, two levels, at most 16 enabled slots per level): `k` ML-DSA-87 members add
about `k × 4.8` KiB, `k × 7.4` M state gas. Records are chained across blobs (no size bound of their own); the bound is the
transaction: EIP-8037 puts regular + state under the block limit, so at 60 M a 2-member `createSession` with both wraps
(about 7.7 M state) leaves room for at most 7 ML-DSA-87 signatures in `sstore2`, while the regular cost of their verification
(about 0.2 M each by an EIP-8355 precompile, about 5.8 M each in software) binds first on a chain without the precompile (the 2^24
cap). Owner question (§4).

### 1.5 Readers

| Reader | Change |
|---|---|
| clientkeys `src/pqchat.js` | `recordBlob(name, s, sig, sigStore)` (the `sstore2` form), `SIG_STORE`; `src/factory.js` `instanceInitCall` for class 3 takes `{owner, sigStore}` (absent: 2), class 4 unchanged |
| vectors `smartcontracts/vectors/pqchat/records.json` | `sigStore` modes; every session, epoch, leave, remove and message row gains `uaSig`, `sigHash`, `blob` (`none`) and `blobSigned` (`sstore2`); `vectors/factory/create_config.json` `instance` gains `config.sigStore` and its `initCall` |
| `ua-rs` `wallet::pqchat::verify` | unchanged code; a test verifies every row's `uaSig` and refuses each with one field changed (`sealedInfo` included) |
| `scaas-rpc` | `EvmPool::read_at_block_agreed`: the agreed read (CLI-RPC-05) on request, whatever the list's policy; one endpoint: `Argument` |
| `scaas-sdk` | `AppCore::read_app_agreed` (new file `app_core/agreed.rs`): `read_app` under strict majority, the read's own option |
| `pqchat-core` | `PqChatConfig.require_signed_records`, `PqChatConfig.agreed_reads`; the setting pinned per instance; signatures verified on `sstore2` homes (session, epoch, the parent's leaves and removals, posted messages); a `none` home refused when required; `abi.json` regenerated |
| node `typed.rs` | `INSTANCE_CONFIGS` `PqChat initialize(bytes32 owner,uint8 sigStore)`, `args.config.sigStore` (absent 2; else 0 or 2); the `TYPED` / `PLAIN` rows are unchanged (no write's arguments change) |
| `selector_audit.json` | `initialize(bytes32,uint8)` FACTORY (one row's signature moves; the class stays) |
| deploy | `script/DeployBase.sol`, `script/onchain/PqChat.s.sol`: `sstore2` |

**Default of `require_signed_records` (controller call):** `false`, meaning "verify wherever the home keeps signatures": on an
`sstore2` home every control-plane record is verified with no switch to turn it off, and a `none` home is read as today (the
contract's check through trusted reads). `true` also refuses a `none` home. The setting is immutable, so the client pins the first
answer per instance in its store; a later different answer is a forged one (dropped as `control`), which closes the downgrade an
endpoint could try by reporting `none` for an `sstore2` home.

**What the check buys.** A single-key author's UA id is the hash of its key (`is_record_of`), so a record whose signature verifies
was signed by that UA even when the same endpoint lies about the registry; with an `sstore2` home and the check on, a substituted
`sealedInfo` (a store list the endpoint runs) or a forged chain of epochs is caught. An `msig` author's structure is a registry
read: strict majority over several named endpoints (option d) is the defence there.

## 2. Gas rows to add (`test/pqchat/PqChatSigGas.t.sol`)

`createSession` (2 members, both wraps) and plain `rekey` (2 members), each at `none` and `sstore2`, with an ML-DSA-65 signature
(3,309 B) and an FN-DSA-512 signature (666 B) through a verifier stand-in that accepts every signature (the verifier's own gas
excluded, as in `PqChatGas.t.sol`); `leave`, `remove` and `postMessage` at both modes with ML-DSA-65. Regular ±500, state exact.

## 3. Tasks

| # | Task | Gates |
|---|---|---|
| S1 | Contract: red tests first (`PqChatSigs.t.sol`: a `none` home stores no signature and its views refuse; an `sstore2` home returns exactly the signed bytes; a forged or mismatched signature still refused at write; mode 1 and 3 refused at `initialize`), then the code; layout, `interfaceId`, gas pins and size moved with old → new figures; typehashes do not move (the signature is no signed field) | every forge directory at the default set; `at-set.sh others sensitive`; `at-set.sh others modules`; size gate; mutants |
| S2 | Factory and catalogue path: deploy scripts, `selector_audit.json`, the node's named config (red first) | `cargo test` / clippy in `scaas-node`; `GovDeploy`, `CreateConfigKat`, `SelectorAudit` |
| S3 | Vectors: clientkeys first (red), regenerate `smartcontracts/vectors/pqchat/` and the `create_config.json` row; forge reads the new rows | `npm test`; `ck-vectors` (regenerated tree equal); `PqChatTypes.t.sol` |
| S4 | Readers: `ua-rs` vector test, `scaas-rpc` agreed read, SDK `read_app_agreed`, `pqchat-core` options (red first, mutants) | `ua-test`, `rpc` tests, `sdk-test`, `pqc-test`, `pqc-clippy`, `pqc-reads`, `pqc-chain`; mutants |
| S5 | Docs: CTR-CHAT-05 and CTR-CHAT-23; CLI-PQC-07 / -13 and CLI-PQC-15 / -16; spec O11 decided and the threat row; decisions entries | `docs_check.py check` at 0 errors |

## 4. Owner questions

- Topic records (`PqTopic`, updates, writers, entries, edits, votes) keep `sigHash` (entries and edits also carry the signature in
  their events). Keep them out of the setting, or add them in the module?
- An `msig` author on an `sstore2` home: at a 60 M block, at most about 7 ML-DSA-87 quorum signatures fit a 2-member
  `createSession` with both wraps (§1.4). Accept, or bound the quorum the client offers on `sstore2` homes?
