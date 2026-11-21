# PqVault

`PqVault` keeps post-quantum encrypted notes and passwords in contract state: a vault is a key group with PqChat's
epochs and KEM wraps (one member or more), and its items keep every version, ordered by the contract. The chain holds the
ciphertexts, the group's keys wrapped to each member, the signed group records and the order of versions; clients
encrypt, decrypt, verify and merge. Every record is signed by its author and checked by the contract; a relayer only
carries it.

Status: **SPECIFIED, nothing built, UNAUDITED.** Design, parts and order: the spec
[`2026-11-17-pqvault.md`](../superpowers/specs/2026-11-17-pqvault.md) and its plan
[`2026-11-17-pqvault.md`](../superpowers/plans/2026-11-17-pqvault.md). The registry's open portable app namespace
([CTR-UA-45](accounts.md#CTR-UA-45)) and the base shared with PqChat come before the EVM freeze (Part R); the contract may
come after (Part V). Clients: [ua-libraries.md](../clients/ua-libraries.md#pqvault-clients).
Other families: **PLANNED**, each in its own `pqvault-<family>` round.

**Contents**

1. [Overview](#1-overview)
2. [The release on the factory](#2-the-release-on-the-factory)
3. [Records and typed signing](#3-records-and-typed-signing)
4. [Storage](#4-storage)
5. [Vaults, epochs and wraps](#5-vaults-epochs-and-wraps)
6. [Items and versions](#6-items-and-versions)
7. [Recovery from state alone](#7-recovery-from-state-alone)
8. [Relaying](#8-relaying)
9. [The base shared with PqChat](#9-the-base-shared-with-pqchat)
10. [The two modes](#10-the-two-modes)

## 1. Overview

Status: **SPECIFIED**.

<a id="CTR-PQV-01"></a>**CTR-PQV-01** — **PqVault is PqChat's group rules with at least one member plus an item model taken
from PqChat topics: every version of every item in contract state, an edit the next version number, the latest version
readable from state, nothing removed** (owner 2026-11-17, V1, V4, V5, V7, V12 as recommended; every decision in full in
its [register entry](../decisions.md#ctr-pqv-01--pqvault-pqchats-group-rules-with-at-least-one-member-plus-a-topics-style-item-model)).

- A factory kind of its own ([CTR-PQV-02](#CTR-PQV-02)), separate from chat: vault traffic never shows in `PqChat`'s
  `sessionsOf`.
- Every member of the current epoch writes ([CTR-PQV-07](#CTR-PQV-07)); read access is cryptographic, write rights are the
  contract's.
- Revocation is a rekey only: old versions stay under their epochs and a removed member keeps what it could read; nothing
  is re-encrypted (V5).
- Small secrets live in items, on chain; files stay off chain with their key and hashes inside an item (V7).
- The contract checks signatures, shapes, membership, the epoch rules, versions and nonces; it runs no KEM, KDF or cipher
  and never reads a ciphertext or `sealedInfo`.
- The registry's app namespace and the shared base land before the freeze; the contract may follow it (V12, N1).
- A vault is portable or chain-bound from its creation ([CTR-PQV-16](#CTR-PQV-16)).

## 2. The release on the factory

Status: **SPECIFIED**.

<a id="CTR-PQV-02"></a>**CTR-PQV-02** — **`PqVault` is a generic factory class of its own on `OpenFactory`'s generic path,
not class 3; each instance reads its chain values from its own `ChainEnv`, is initialised once by the factory, keeps its
state in the ERC-7201 namespace `scaas.pqvault`, and its owner UA has no power** (owner 2026-11-17, V10). The class id is
[CTR-PQV-13](#CTR-PQV-13)'s.

The registration, constructor, `initialize`, `validateEnv`, `chainEnv`, `factoryInfo`, `supportsInterface` and `rescue`
are those of [CTR-CHAT-02](pqchat.md#CTR-CHAT-02) with `PqVault*` errors. Namespace root
`0x5bab91edb5f7201959ccc400acb38a4632e4bb30c3ed3cf98f817b8f10b48800`, no plain slot, layout pinned in
`test/v2/layout/PqVault.json`. A client and the node take as a `PqVault` only an address the chain's factory lists under
PqVault's class with version ≠ 0. Class 3 stays `PqChat`.

## 3. Records and typed signing

Status: **SPECIFIED** (registry entry: BUILT, Part R `09000f2af`, [CTR-UA-46](accounts.md#CTR-UA-46); records: Part V).

<a id="CTR-PQV-03"></a>**CTR-PQV-03** — **Every record is a typed EIP-712 struct in its vault's domain, signed as a `UASig`
over `uaMessage(kind, P_V, typed(record))` with `P_V = appPurpose(keccak256("scaas.pqvault.v1"))`, PqVault's purpose in the
registry's open app namespace, and checked by `requirePortableApp` (a portable vault) or `requireAuthorized` (a
chain-bound vault); the vault and epoch records carry the passphrase flag `passKdf` and its `passSalt`, nothing else about
a passphrase** (owner 2026-11-17, N1, which replaced V2's `PURPOSE_PQVAULT` the same day; P2 for the flag). The domains
and the choice between them are [CTR-PQV-17](#CTR-PQV-17)'s.

- The type strings are the spec's
  [§5.2](../superpowers/specs/2026-11-17-pqvault.md#52-domains-purpose-and-records-n1-vc20-vc21-vc22): `MemberKey`, `Wrap` (PqChat's),
  `PqVaultCreate`, `PqVaultEpoch`, `PqVaultLeave`, `PqVaultRemove`, `PqVaultItem`, `PqVaultEdit`, `PqVaultBatch`; pinned by
  `*TypehashIsPinned` against `smartcontracts/vectors/pqvault/`.
- No fee, deadline or submitter in any record; no write reads `msg.sender` except `initialize`.
- `passKdf` 0 means no passphrase and then `passSalt` is 0; otherwise `passSalt ≠ 0` (`PqVaultShape`). The contract knows no
  parameter set; clients refuse an id they do not know.
- `P_V` is never a SCaaS purpose and the reverse ([CTR-UA-46](accounts.md#CTR-UA-46)); a `PURPOSE_PQCHAT` signature is no
  `PqVault` signature and the reverse.

<a id="CTR-PQV-04"></a>**CTR-PQV-04** — **Ids hash the signer and its nonce under `scaas/pqvault/v1/…` tags, `vaultId` also
the vault's `mode`, `homeChain` and `homeVaultContract`; nonces are per-scope bitmaps checked after the signature: a vault
`(creator)`, an epoch `(vaultId, author)` for rekeys, leaves and removals, an item `(vaultId, author)` for items, edits
and batches** (controller call, owner may override). A client draws a creation nonce as 64 random bits. The ids and
scopes are the spec's [§5.3](../superpowers/specs/2026-11-17-pqvault.md#53-ids-and-nonce-scopes); epoch 0's id is the
vault id; a used nonce is `PqVaultNonceUsed(scope, nonce)`.

## 4. Storage

Status: **SPECIFIED**.

<a id="CTR-PQV-05"></a>**CTR-PQV-05** — **Every accepted record is kept in full in contract state, in SSTORE2 blobs no larger
than the chain's code-size limit (chained beyond it); vault, epoch and remove records keep their full `UASig`, items their
`sigHash`; slots hold only pointers and indexes; an event only notifies, the item, edit and batch events carry the item
signature, and no event carries a ciphertext** (the never-lose-ciphertext rule as PqChat applies it,
[CTR-CHAT-05](pqchat.md#CTR-CHAT-05); the blob forms and the full `UASig` are controller calls, owner may override).

Group records `abi.encode(record, sig)`, so a client verifies the signature chain from state; a version-1 item
`abi.encode(item, sigHash, batchId)` (`batchId` 0 for a single create), an edit `abi.encode(edit, sigHash)`, a batch header
`abi.encode(vaultId, epochId, author, nonce, itemIds, sigHash)`; wraps packed as PqChat's. A ciphertext is never a hash in
a slot with its bytes in calldata or a log.

## 5. Vaults, epochs and wraps

Status: **SPECIFIED**.

<a id="CTR-PQV-06"></a>**CTR-PQV-06** — **A vault is epoch 0 with at least one member; a personal vault is a one-member
vault whose random epoch key is wrapped once to its own UA KEM key, by the same path as a shared vault, and no
seed-derived vault key exists; epochs, wraps in chunks, the home-instance slot, admins, leave and remove follow PqChat**
(owner 2026-11-17, V1 and ruling "(a)").

- `createVault(PqVaultCreate, Wrap[], UASig)`, `rekeyVault(PqVaultEpoch, Wrap[], UASig)`, `addVaultWraps(epochId, first,
  Wrap[])` (unsigned), `leaveVault(PqVaultLeave, UASig)`, `removeVaultMembers(PqVaultRemove, UASig)`: the checks of
  [CTR-CHAT-06](pqchat.md#CTR-CHAT-06) to [CTR-CHAT-10](pqchat.md#CTR-CHAT-10) and [CTR-CHAT-20](pqchat.md#CTR-CHAT-20),
  with at least 1 member at creation, `homeVaultContract` for the home address and `PqVault*` errors, and who may rekey
  as [CTR-PQV-13](#CTR-PQV-13) states.
- Sharing a vault is a `rekeyVault` to the new members with a wrap per member.

<a id="CTR-PQV-13"></a>**CTR-PQV-13** — **`PqVault` is class 4, kind 0; its write names differ from PqChat's so no write
selector is shared; every `rekeyVault` is authored by an admin of the parent epoch who was not removed from it** (controller
calls, owner may override).

- A rekey by any other member is `PqVaultNotAdmin`: a vault has no reason for member-authored rekeys, and a member could
  otherwise take the home slot with wraps or a `sealedInfo` the others cannot open. A change of `(passKdf, passSalt)` is
  therefore always an admin's signed record.
- Dropping a member that left is an admin's rekey; with no admin left, membership and keys are frozen (items stay
  writable under the last epoch). An admin that left an epoch or was removed from it rekeys and removes no more
  (`PqVaultNotAdmin`), and a child whose author was removed from the parent no longer completes
  (`PqVaultRemovedKept(parent, author)`), the same rule as PqChat's in the shared base (controller call 2026-11-21, the
  Fable code review F1, F2, F7). An admin that is no member (an `msig`) is removable (F3). The admin model itself is the
  owner's (2026-11-21: several admins, only admins rekey).
- Views such as `versionAt(bytes32,uint32)` share PqChat's selectors; the node keeps rows for writes only.

## 6. Items and versions

Status: **SPECIFIED**.

<a id="CTR-PQV-07"></a>**CTR-PQV-07** — **An item write names an epoch of the item's vault that is complete here and, at
home, has no complete child; its author is a member of that epoch** (owner 2026-11-17, V4: every member of the current
epoch writes). Refusals: `PqVaultUnknown`, `PqVaultIncomplete`, `PqVaultEpochTaken`, `PqVaultNotMember`; the further limits
are [CTR-PQV-14](#CTR-PQV-14)'s.

<a id="CTR-PQV-08"></a>**CTR-PQV-08** — **`createItem` stores a member's version 1; `editItem` by any member stores version
`count + 1` only (the first edit 2), else `PqVaultVersion(expected, got)`; every version stays and the latest is read from
state; the refusal is the conflict signal** (owner 2026-11-17, V1, V4). A delete is a tombstone version the contract does
not tell apart. An edit's epoch must belong to the item's vault (`PqVaultUnknown`).

<a id="CTR-PQV-09"></a>**CTR-PQV-09** — **`createItems(PqVaultBatch, UASig)` creates one or more items of one vault, epoch
and author under one signature over the whole list; each item's nonce and the batch's are used in the item scope; the
client sizes a batch to its chain's limits** (owner 2026-11-17, V6). Every item's `vaultId`, `epochId` and `author` equal
the batch's (`PqVaultShape`); no protocol bound on the count: `(regular + state) × 1.05` within the chain's block gas
limit (EIP-8037) and regular under 2^24 where EIP-7825 applies.

<a id="CTR-PQV-14"></a>**CTR-PQV-14** — **A member removed from an epoch writes no item under it; every ciphertext is 32 to
16,416 bytes; items and versions are read at the home instance, and a replica's version counts only when the home holds the
same record and `sigHash` at the same `(itemId, version)`** (controller calls, owner may override; the replica rule as
PqChat's, [CTR-CHAT-14](pqchat.md#CTR-CHAT-14)). Refusals `PqVaultNotMember`, `PqVaultShape`. The upper bound (the 16,384 B
padding bucket plus salt and tag) makes `latestRange`'s page bound hold on every chain. A replica takes writes under any
complete epoch it holds, in its own order; it orders nothing. A member that left an epoch writes no item under it either
(owner 2026-11-17, the spec's O3 (b); `PqVaultNotMember`). A chain-bound vault has no replica
([CTR-PQV-17](#CTR-PQV-17)). A vault's or an epoch's `sealedInfo` is 1,052 to 16,412 bytes (a nonce, a padded bucket of
1,024 to 16,384 B, a tag; `PqVaultShape`), so no write reads an unbounded record (controller call 2026-11-21, the Fable code
review F8, F12). `removalAt` past the end is `PqVaultUnknown(epochId)` (F15).

## 7. Recovery from state alone

Status: **SPECIFIED**.

<a id="CTR-PQV-10"></a>**CTR-PQV-10** — **A client keeps no vault list and reads no event: `vaultsOf(ua)`, `vaultOf`,
`epochsOf`, `latestEpoch`, `epochOf`, `wrapAt`, `itemsOf(vaultId)`, `itemOf`, `versionAt`, `latestRange(vaultId)` and
`batchOf` answer everything; pages never revert and are clamped (128 ids, 16 latest versions)** (owner 2026-11-17, V1:
recovery from state alone). The views and bounds are the spec's
[§5.9](../superpowers/specs/2026-11-17-pqvault.md#59-reads-for-recovery-from-state-alone); `vaultOf`, `epochOf` and
`removalAt` return the record with its `UASig`.

## 8. Relaying

Status: **SPECIFIED** (the node's rows in Part V; [job-api.md](../node/job-api.md#pqchat-calls) gains a `pqvault` kind).

<a id="CTR-PQV-11"></a>**CTR-PQV-11** — **Every write is relayable by anyone with a fee of 0 too; the seven signed writes
carry the record and its `UASig`; whether a relayer pays for the unsigned `addVaultWraps` is the node's policy** (the rule
that every state-changing write is relayable; PqChat's precedent [CTR-CHAT-19](pqchat.md#CTR-CHAT-19)).

## 9. The base shared with PqChat

Status: **BUILT** (Part R `fcdd83a7e`: `src/pqgroup/PqGroupBase.sol`, PqChat on it, its proof as
CTR-PQV-15 lists it held; `PqVault` on it: Part V). UNAUDITED.

<a id="CTR-PQV-12"></a>**CTR-PQV-12** — **The group code PqChat and PqVault share moves into one abstract base without state
of its own, PqChat's storage-layout and gas pins proving PqChat unchanged; if that proof fails, PqVault copies the code
instead and PqChat stays untouched** (owner 2026-11-17, V3, V12). What counts as the proof is [CTR-PQV-15](#CTR-PQV-15).

<a id="CTR-PQV-15"></a>**CTR-PQV-15** — **PqChat's behaviour counts as unchanged when, with no test, pin or vector edited, its
layout pin, typehash pins and vectors, ABI and `interfaceId`, every per-operation gas row, every PqChat test, the node's
PqChat allow-list test and all 55 of its mutants hold; only the release-size pins move, with old → new figures** (controller
call, owner may override). The mutant script is the one instrument allowed to change, with an old line → new line table per
mutant. PqChat's bytecode moves, so it is redeployed and verified at the next reset and its diff is in the audit scope. The
boundary is the spec's [§4.2](../superpowers/specs/2026-11-17-pqvault.md#42-r-b-the-base-shared-with-pqchat-v3).

## 10. The two modes

Status: **SPECIFIED** (Part V).

<a id="CTR-PQV-16"></a>**CTR-PQV-16** — **PqVault supports both paths an app has: a vault is portable (path A, the
registry's open app namespace, replicas allowed) or chain-bound (path B, the registry's `requireAuthorized`, one instance,
no replica), chosen at its creation** (owner 2026-11-17, N1: "support both A and B";
[CTR-UA-45](accounts.md#CTR-UA-45)). Everything else is shared: ids, scopes, storage, epochs, wraps, roles, items,
versions, batches, views, events, errors and the key schedule.

<a id="CTR-PQV-17"></a>**CTR-PQV-17** — **The mode is the field `uint8 mode` of `PqVaultCreate` (0 portable, 1
chain-bound), fixed by the creator's signature and kept in state as `modes[vaultId] = 1` for a chain-bound vault; every
later record of the vault is checked in that mode's domain by one internal check, which takes the vault from the stored
epoch the record names (for an edit, the item) and requires the record's `vaultId` to equal it: mode 0 in `DS_V` ("SCaaS PqVault", "1",
`salt = keccak256("scaas.pqvault.v1")`, no chain, no address) through `requirePortableApp`, mode 1 in `DS_B` ("SCaaS
PqVault", "1", `chainId`, `verifyingContract` = the instance) through `requireAuthorized`; a mode-1 vault names this
instance as its home, else `PqVaultShape`, so no replica of it can exist; clients create mode 0 unless the user chooses
mode 1** (controller calls, owner may override). A mode other than 0 or 1
is `PqVaultShape`. The design and its costs are the spec's
[§5.15](../superpowers/specs/2026-11-17-pqvault.md#515-the-two-modes-n1-vc22-vc23).
