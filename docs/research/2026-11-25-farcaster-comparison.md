> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Farcaster and SCaaS: on-chain identity, off-chain data, and what the ledger service can learn

Research of 2026-11-25 for the owner, who noted that SCaaS, like Farcaster, keeps identities and keys in an on-chain
registry, and asked to study Farcaster further. Nothing here is built, specified or ruled; every lesson in §8 is a
**proposal**. Any SCaaS cryptographic design it names is **UNAUDITED** ([ARCH-POS-14](../decisions.md#ARCH-POS-14)).

It is read beside two notes of the same week: the off-chain ledger direction
[`2026-11-24-offchain-ledger-backends.md`](2026-11-24-offchain-ledger-backends.md) ("ledger note §n"; the owner's direction of
2026-11-24 is its §11) and [`2026-11-25-treekem-beyond-256.md`](2026-11-25-treekem-beyond-256.md) ("TreeKEM note"; its last
sections hold the owner's answers on `groupMode = 2` and `groupMode = 3` and the three anchoring levels).

Tags: **[F]** a fact read on 2026-11-25 in a primary source (Farcaster's docs, the `farcasterxyz` GitHub repositories, a FIP
thread, the Snapchain source or its own docs) or, for SCaaS, a repository rule id; **[S]** a secondary source (press, a third
party's docs), not confirmed in a primary one; **[U]** could not be confirmed at all; **[B]** background from a published standard, cited from
memory; **[I]** our inference; **[E]** an estimate, paper arithmetic, no run. A FIP is a Farcaster Improvement Proposal, a GitHub discussion in `farcasterxyz/protocol`; its stage
(Idea, Draft, Review, Finalized) is the one shown on 2026-11-25.

**Contents**

0. [Summary](#0-summary)
1. [Farcaster in late 2026: timeline and who runs it](#1-farcaster-in-late-2026-timeline-and-who-runs-it)
2. [The on-chain part](#2-the-on-chain-part)
3. [The off-chain part: from hubs to Snapchain](#3-the-off-chain-part-from-hubs-to-snapchain)
4. [Messaging, groups and channels](#4-messaging-groups-and-channels)
5. [Spam, payment, apps and recovery](#5-spam-payment-apps-and-recovery)
6. [Mapping, component by component](#6-mapping-component-by-component)
7. [Where SCaaS differs on purpose](#7-where-scaas-differs-on-purpose)
8. [Lessons for the ledger service and groupMode 2 / 3 (proposals, ranked)](#8-lessons-for-the-ledger-service-and-groupmode-2--3-proposals-ranked)
9. [Open questions for the owner](#9-open-questions-for-the-owner)
10. [Sources, and what could not be confirmed](#10-sources-and-what-could-not-be-confirmed)

## 0. Summary

- **Same split, different weight.** Farcaster puts only what needs global consistency on chain (account id and its owner
  address, app keys, paid storage) on OP Mainnet, and everything social (posts, reactions, follows, profiles) on Snapchain, its
  own ordered network [F, docs "Architecture"]. SCaaS keeps far more on chain today: the UA registry, the KEM key directory, and
  for PqChat the whole control plane and every wrap in contract state ([CTR-CHAT-01](../contracts/pqchat.md#CTR-CHAT-01),
  [CTR-CHAT-05](../contracts/pqchat.md#CTR-CHAT-05)). The ledger direction (ledger note §11) moves SCaaS towards Farcaster's
  split, per deployment.
- **Farcaster tried "no order" and gave it up.** Its hubs ran an eventually consistent CRDT set with gossip and diff sync; at
  thousands of nodes they drifted, per-node rate limits diverged, and pruning made sync hard, so it moved to **Snapchain**: a
  Malachite (Tendermint-family) BFT chain, sharded by account, blocks of signed user messages, no smart contracts [F, Snapchain
  FIP #207, Snapchain docs]. Mainnet in spring 2025 [S: The Block, 2025-03-21; others give April 2025].
- **Its decentralisation is thin.** The live validator set is **7 keys, 5 of them Neynar's**; a block commits with 5 of 7; the
  set comes from an owner-controlled config contract on Ethereum L1 [F, `validators.toml`, Snapchain docs "Mainnet
  Validators", FIP #277]. Ownership changed twice in 2026 (Neynar in January, Network School announced 2026-10-15) [S].
- **Keys moved off chain in 2026.** FIP #266 (Finalized 2026-05-12) lets the custody address add an app key by a signed
  Snapchain message instead of an OP transaction, **with scopes (allowed message types) and a sliding TTL** (at most 90 days in
  the draft text); on-chain keys keep full, unscoped power [F]. FIP #238 (Finalized 2025-07-10) made a key's removal
  **forward-only**: past messages are no longer deleted [F].
- **Storage is rented, expires and is pruned.** Units cost USD-priced ETH (USD 0.20 after the 2025 redenomination), last a year,
  carry per-type message caps and a daily rate limit, and the oldest message is pruned when a cap is hit; Farcaster has changed
  unit sizes and expiry three times (legacy, 2024, 2025 cohorts; +1 year to every cohort in June 2026) [F, FIP #229, FIP #271].
- **No encryption anywhere in the protocol.** All Farcaster data is public plaintext; direct casts and group chats are a
  service of the official client, off protocol; an E2E design (FIP #99, X3DH plus a ratchet) has stayed an Idea since 2023 [F].
  So Farcaster has no answer to SCaaS's hardest off-chain problems: a substituted KEM key and ciphertext availability.
- **Top lessons (§8):** scoped, expiring delegated app keys signed by the UA; total order by a small BFT committee of ledger
  nodes whose block signatures double as a data-availability attestation for `groupMode = 3`; an on-chain record of the
  ledger's node set and endpoints (but immutable, not owner-edited); registry reads pinned to a final block and named in each
  accepted record; quota units as rate limit and payment, **never** as a reason to prune ciphertext; forward-only revocation.
  Explicitly rejected: pruning, client timestamps as order, Ed25519-only and 160-bit hashes, off-protocol private messaging,
  owner-only admin keys over the registry or the node set.

## 1. Farcaster in late 2026: timeline and who runs it

| When | What | Tag |
|---|---|---|
| 2023-11 | Protocol spec v2023.11.15: hubs (Hubble), CRDT stores, gossipsub, Merkle-trie diff sync; contracts on OP Mainnet | [F] spec |
| 2024-08-29 | "2024" storage units start (legacy units before) | [F] FIP #271 |
| 2025 (spring) | Snapchain mainnet replaces hubs | [S] The Block 2025-03-21; others April 2025 |
| 2025-07-16 | Storage redenomination: USD 0.20 a unit, about 8x smaller units, lower rate limits | [F] FIP #229 |
| 2025-10 | Snapchain 0.10.0: signer revocation no longer deletes past messages (FIP #238) | [F] CHANGELOG, PR #714 |
| 2026-01 | Neynar acquires Farcaster (protocol contracts, codebase, client) from Merkle Manufactory; about USD 180 M returned to investors | [S] The Block 2026-01-21 |
| 2026-05-12 | FIP #266 "Snapchain Signers" Finalized: gasless, scoped, TTL app keys | [F] |
| 2026-06-22 | FIP #271: every pre-existing storage cohort gets one more year (engine V18) | [F] |
| 2026-07 / 08 | Channels on Snapchain: FIP #276 Draft (2026-07-09); code in 0.14.1 (2026-08-06) | [F] FIP, CHANGELOG |
| 2026-10-15 | Network School (Balaji Srinivasan) announces it takes over the app, protocol repositories and products from Neynar; users asked to sign a "social smart contract" and get an access NFT; a rename to "Network State Protocol" reported | [S] several outlets; terms and completion not confirmed |
| 2026-11-16 | Snapchain 0.17.0 (latest release seen) | [F] CHANGELOG |

The protocol code is open source and the identity contracts are on a public chain, so the network outlived two changes of
owner [I]. But every party that matters for liveness (most validators, the config registry owner, the fname server, the main
client) has sat with one company at a time [F for the validators and the registry owner, §3.3; I for the rest].

## 2. The on-chain part

### 2.1 Chains and contracts

[F, `farcasterxyz/contracts` `docs/docs.md`; Snapchain `src/connectors/onchain_events`]:

| Contract | Chain | Role |
|---|---|---|
| `IdRegistry` + `IdGateway` | OP Mainnet (10) | the account id (`fid`) and its custody and recovery addresses |
| `KeyRegistry` + `KeyGateway` | OP Mainnet | app keys per fid |
| `StorageRegistry` | OP Mainnet | storage units per fid |
| `Bundler` | OP Mainnet | register + rent + add key in one transaction |
| `SignedKeyRequestValidator` | OP Mainnet | checks the app's signed request inside a key's metadata |
| `RecoveryProxy` | OP Mainnet | the official client's default recovery address (a 2-of-3 multisig owner) |
| `TierRegistry` | Base (8453) | paid "Pro" tier (long casts, more embeds), price per day |
| Fname resolver | Ethereum L1 | ENSIP-10 off-chain resolution of fnames |
| `SnapchainConfigRegistry` | Ethereum L1 (Sepolia for testnet) | validator sets and bootstrap peers (§3.3) |
| channel registrar (Basenames-style ERC-721) | Base by default (open in FIP #276) | channel ownership |

### 2.2 IdRegistry: a stable id above a transferable owner

[F, docs "IdRegistry", contracts `docs.md`]:

- A `fid` is a `uint256` counter. Each fid maps 1:1 to a **custody address** (an Ethereum address); an address holds at most
  one fid.
- The custody address names one **recovery address**, which may move the fid to a new custody address (`recover`,
  `recoverFor`); the recovery address can be changed by custody (`changeRecoveryAddress[For]`).
- `transfer` moves the fid to a new address that must sign a `Transfer` (EIP-712, nonce, deadline);
  `transferAndChangeRecovery` also resets recovery and is advised for an fid received from an untrusted party.
- Every write has a `...For` form taking EIP-712 signatures, so a third party can pay the gas [F].
- `register` only through `IdGateway`; in its "untrusted" mode a registration must rent one storage unit.
- **Admin:** the owner can **pause** registration, transfer and recovery; it bulk-populated state before `migrate()`. The
  official client's accounts default to the `RecoveryProxy`, recoverable by e-mail through the client [F, docs "Accounts"].

### 2.3 KeyRegistry: app keys under the custody address

[F, docs "KeyRegistry", contracts `docs.md`, protocol spec]:

- Key type 1 is an EdDSA (Ed25519) key; metadata type 1 is a **SignedKeyRequest**: the requesting app's fid and its
  signature, so every key names the app that asked for it.
- States `added` and `removed`; `add` only through `KeyGateway`; `remove` by the fid's custody, `removeFor` with its EIP-712
  signature. At most **1,000** keys per fid.
- Only the custody address adds or removes keys; an app key cannot add another key [F, spec; FIP #266].
- Until 2025 a removal also deleted every message the key had signed; since FIP #238 it only refuses new ones (§3.6).

### 2.4 StorageRegistry: rent with expiry

[F, docs "StorageRegistry", contracts `docs.md`, FIP #229, FIP #271]:

- `rent(fid, units)` and `batchRent`; price fixed in USD, paid in ETH through a Chainlink ETH/USD feed; an `operator` role may
  **credit** units with no payment; a `treasurer` moves funds; an `owner` changes parameters and pauses; the contract has a
  deprecation timestamp.
- **Price:** USD 0.20 a unit for units rented after 2025-07-16 (from USD 2), "the only fee a user needs to pay" [F, FIP #229].
- **Per-unit caps** (FIP #229, before → after the redenomination): casts 2,000 → 100, reactions 1,000 → 200, links 1,000 → 200,
  user data 50 → 25, verifications 25 → 5, username proofs 5 → 2. **Rate limit:** 200 messages a day per new unit, 2,000 per
  legacy unit. Older units keep their old caps.
- **Expiry:** one year for a new unit; after FIP #271 (mainnet 2026-06-22) legacy units last 4 years, 2024 units 3, 2025 units
  2. When all units expire the account cannot post, and after a 30-day grace its messages are pruned [F, spec, docs
  "Messages"].
- **Storage lending:** Snapchain added `LendStorage` messages in 2025 (0.8.0, 2025-09-16): one fid lends units to another, with
  pruning when the lender revokes [F, CHANGELOG, `storage_lend_store.rs`]; the economic rules were not read for this note [U].

Farcaster's docs still show older caps (5,000 casts, 2,500 reactions) on the "Messages" page [F], so its own documentation lags the
FIPs; the FIP figures above are the current ones [I].

### 2.5 Names

Fnames are **off-chain** ENS names issued by Farcaster's name server (`fnames.farcaster.xyz`), EIP-712 signed by the custody
address and countersigned by the server's key; one change per 28 days; "Farcaster can revoke them at any time". A `.eth` name
needs an on-chain ENS record plus a verification; validators check those against Ethereum L1 [F, spec, docs "Usernames",
Snapchain docs "node types"].

### 2.6 Who pays gas

Every registry write has a signed `...For` form and the `Bundler` does all three steps at once, so an app (the official client,
a mini-app) pays the OP gas and the user signs [F for the forms; I for who pays in practice]. FIP #266's motivation is exactly
that cost: "each key currently needs an Optimism transaction" [F]. The OP gas per write was not measured for this note.

## 3. The off-chain part: from hubs to Snapchain

### 3.1 A message

[F, protocol spec; Snapchain `proto/`]: `Message {data, hash, hash_scheme, signature, signature_scheme, signer}`; `data` is
`MessageData {type, fid, timestamp, network, body}`; the hash is **BLAKE3 truncated to 160 bits** over the data bytes; the
signature is **Ed25519 by the app key** over the hash (some types, such as verifications, carry an EIP-712 signature by an
Ethereum address in the body). The timestamp is the author's, in seconds since 2021-01-01, at most 600 s in the future. No
nonce: order comes from timestamps (CRDT era) and now from blocks.

### 3.2 Validation against the registries

A message is accepted only if its fid is registered, its signer is an active key of that fid, and the fid has storage left
[F, spec]. On Snapchain each node subscribes to the OP contracts through its own RPC URL and feeds the events (`ID_REGISTER`,
`SIGNER`, `STORAGE_RENT`, tier and channel events) into the mempool, so on-chain events are ordered into blocks like user
messages; the source carries `TODO: Wait for 1 confirmation before "committing" an onchain event` and reads the `latest` block
[F, `src/connectors/onchain_events/mod.rs` at `main`, 2026-11-25]. A reorg rule was "TBD" in the whitepaper [F]. Messages that
need Ethereum L1 (ENS proofs, ERC-1271 verifications) are re-checked by each validator before it proposes them, fail closed on
RPC errors, rate limited per fid [F, Snapchain docs "node types"].

### 3.3 Snapchain: order by a small committee

[F, Snapchain whitepaper (FIP #207 and `site/docs/pages/whitepaper.mdx`), docs "node types" and "Mainnet Validators",
`validators.toml`, FIP #277]:

- **Why it was built.** CRDT hubs were eventually consistent; a node noticed missed gossip only by comparing everything with
  every peer ("4000 nodes x 150 million messages"); rate limits could only be per node, so one hub accepted what another
  refused; pruning rewrote old state and made sync slow; partial order per user or per app was considered and rejected because
  pruning and global rate limits stay unsolved; forking an existing chain was rejected because pruning is hard to bolt on.
- **Shape.** Transactions are single-account and not Turing complete. Accounts are sharded: a message goes to message shard
  `SHA-256(fid)[0..4] mod n + 1`; **mainnet has shards 1 and 2**, and **shard 0** (the "block shard") orders the shards' chunks
  and holds what every shard depends on: signer `KEY_ADD` / `KEY_REMOVE`, storage lends, channel messages.
- **Consensus.** Malachite BFT per shard; a block commits with votes of more than two thirds of the set's weight; it tolerates
  under one third faulty. Throughput target over 9,000-10,000 transactions a second (a goal, not a measurement).
- **The set.** `validators.toml` lists **7 keys: 5 operated by Neynar, and since registry config version 18 two named
  "moria" and "isengard"** (replacing "Uno" and "Degen"; the docs table still lists the old two). 5 of 7 commit a block, so
  Neynar alone has a quorum [F, I]. The whitepaper's plan (15 voters electing 11 validators every six months) is not what runs
  [F for the plan, I that it is not in force].
- **Config registry.** Validators pull their validator sets and peers from `SnapchainConfigRegistry` on Ethereum L1 at every
  boot, watch `configVersion()` every 300 s and restart one at a time; it is `Ownable2Step`, owned by **one EOA** today, a
  multisig "expected" [F, FIP #277]. Read nodes take the set from `validators.toml` instead.
- **Read nodes** (anyone): never vote, fetch decided blocks, verify commit certificates against the set, apply them, serve the
  HTTP / gRPC API, relay submitted messages by gossip without a mempool of their own ("if that gossip is lost, the message is
  gone") [F]. Requirements: 16 GB RAM, 4 cores, about 1.5 TB disk [F, README].
- **Snapshots.** Daily global-state snapshots on a file server; a new node downloads one and streams blocks [F, whitepaper].

### 3.4 Merge rules and pruning

[F, spec; whitepaper]: each store is a CRDT with last-write-wins by `(timestamp, hash)`, some with remove-wins (a `CastRemove`
is a tombstone: a removed cast cannot be re-added; a reaction add loses to a remove at the same timestamp). Over a cap, the
lowest `(timestamp, hash)` message of that type is pruned (oldest first), even if it is a tombstone. Block pruning: the
whitepaper allows non-epoch blocks to be pruned after a week ("permanently removes deleted posts and likes which is desirable");
in the code **validators never prune blocks**, read nodes may (`pruning.block_retention`) [F, docs "node types"]. Epoch blocks
are kept forever. The whitepaper's **erasure coding of a shard's state across other shards** was not found in the source tree
(no file or module by that name) [U, likely not built].

### 3.5 What a node can and cannot do

| Actor | Can | Cannot |
|---|---|---|
| a read node | refuse, delay or drop a submission (gossip only); serve stale or partial reads | forge or alter a message (Ed25519 by the app key), forge a block (commit certificates) |
| a shard leader | leave a message out of its block; leaders rotate | forge a message |
| over 2/3 of a shard's validators | censor a user; re-issue a shard before finality | forge a message; change state silently (replayers detect a wrong transition) |
| over 2/3 of the block shard and of one shard | fork the network | forge a message |
| the config registry owner | name the validator set validators load at boot | sign as a validator ("the node's signing key never leaves the operator") |
| the fname server | refuse, revoke or reassign an fname | touch an on-chain ENS name |

[F, whitepaper "Failure handling", FIP #277; I for the read-node row]. Order is not discussed beyond "blocks give a global
order" [F]; a leader chooses order inside its block [I].

### 3.6 App keys on Snapchain (FIP #266) and forward-only revocation (FIP #238)

[F, FIP #266 and #238, `key_add_store.rs`]:

- `KEY_ADD` (type 16) carries the Ed25519 key, the custody address's EIP-712 signature (domain "Farcaster KeyAdd", version 1)
  over `fid, key, keyType, scopes, ttl, nonce, deadline`, the app's SignedKeyRequest, **scopes** (the message types the key may
  sign; no "all" shortcut) and a **TTL**: the key lives while `last_used_at + ttl >= block time`, updates throttled to one per 5
  minutes, at most 90 days in the body (the finalisation comment says TTL > 0; the body's "0 = no expiry" conflicts, [U] which
  text won). No refresh tokens.
- `KEY_REMOVE` (type 17) is signed by custody (EIP-712) or by the key itself (self-revocation, always allowed). Revocation is
  immediate. One `KEY_ADD` per fid per minute (pending); 1,000 active keys per fid across both paths; on-chain keys keep
  "implicit full authority, no scope check, and no TTL".
- **FIP #238:** removing a key now only refuses its future messages; what it signed while active stays. A malicious key's posts
  are deleted with another valid key, or hidden by clients that watch revoke events. No purge mechanism, on purpose.

### 3.7 Data availability

Every validator keeps full state of its shards, read nodes keep full state, snapshots are public, and nothing is encrypted, so
availability rests on replication by a handful of operators plus anyone who runs a read node [F, I]. But **data is not meant
to last**: caps prune old messages, expired storage prunes everything after 30 days, and read nodes may prune blocks. Farcaster's
model is "available while paid for", the opposite of SCaaS's "never lose ciphertext" [I].

## 4. Messaging, groups and channels

- **Direct casts are not part of the protocol** ("Direct casts are currently not part of the protocol. There are plans to add
  direct casts to the protocol later this year.", undated) [F, docs "Direct Casts"]. The official client runs them and offers
  an API key to developers.
- **Encryption:** no primary source says direct casts are end-to-end encrypted, and none says they are not [U]. The client's
  "Group Direct Casts" page reportedly says groups hold **up to 100 members** and are kept on the client's servers [S: search
  snippet of a Notion page that did not render for us].
- **FIP #99 "Direct Casts"** (2023-06-20, Idea, last activity 2023-07-06): X3DH-style keys (identity key signed by the
  wallet or signer key, signed pre-key, one-time pre-keys, an inbox key), an asynchronous "Triple Ratchet" with a DKG for
  groups, padded envelopes, ring signatures over mutual follows to hide the sender, and a key store capped at 200 per user. Not
  adopted; no MLS proposal was found [F for the FIP, U for "no MLS plan"].
- **Channels** were a feature of one operator's database; FIP #276 (Draft, 2026-07-09) puts ownership in an ERC-721 name
  registry on chain (Base proposed) and configuration, members, moderators (at most 10), bans and pins as signed messages in
  shard 0; Snapchain 0.14.1 (2026-08-06) already ingests channel registrations and merges channel messages [F]. Posting rules
  are "advisory; clients and backends enforce it".

So for private groups Farcaster has nothing comparable to PqChat; the comparison is useful for identity, keys, order, payment
and availability, not for encryption [I].

## 5. Spam, payment, apps and recovery

- **Spam and abuse.** The protocol's levers are economic and quantitative: paid units, per-type caps, a daily rate limit per
  unit enforced in consensus (Snapchain's reason 2), the per-fid L1-check rate limit, per-shard mempool caps (0.17.0) [F]. Labels,
  ranking and moderation are client-side; the Network School takeover reportedly adds proof-of-personhood and AI moderation in
  its client [S].
- **Payment.** One-off: storage rent (USD 0.20 a unit a year) and OP gas, usually paid by the app; no per-message fee;
  operators credit units for free (`operator` role) and users lend units to each other [F]. Validators are not paid by the
  protocol [I; a 2026 IMC paper reportedly finds most node operators unprofitable, S, not read].
- **Apps.** A "wallet app" holds the custody key and can do anything; a "connected app" holds only an app key and "cannot take
  control of your account"; the wallet app can undo its actions [F, docs "Apps"].
- **Recovery.** A lost app key: custody removes it and adds another. A lost custody key: the recovery address moves the fid to a
  new address; the fid, its keys and its data stay (the keys are under the fid, not the address) [F]. Recovery by e-mail is the
  client's `RecoveryProxy`, so the client can recover, and therefore take, such accounts [I].

## 6. Mapping, component by component

| Farcaster | SCaaS counterpart | Note |
|---|---|---|
| `fid` (counter) + custody address | **UA** = `keccak256(keccak256(kind_tag) ‖ key_data)`, the same on every chain ([CTR-UA-02](../contracts/accounts.md#CTR-UA-02)) | a fid is assigned and stable across custody changes; a UA *is* its key: new key data, new UA |
| custody transfer, recovery address | none inside a UA; `SmartKeyAccount` gives a stable address with guardian recovery ([CTR-ACC-09](../contracts/accounts.md#CTR-ACC-09)); an `msig` UA | SCaaS's registry is monotonic: no transfer, no recovery, no pause |
| `KeyRegistry` app keys (Ed25519, add/remove, 1,000) | KEM key versions per UA, write-once, never revoked ([CTR-UA-32](../contracts/accounts.md#CTR-UA-32)); PqChat device keys as extra KEM versions, at most 8 per UA per epoch ([CTR-CHAT-24](../contracts/pqchat.md#CTR-CHAT-24)) | SCaaS has **no delegated signing key**: every write is signed by the UA's own key |
| SignedKeyRequest (the app that asked) | app ids on the portable namespace ([CTR-UA-45](../contracts/accounts.md#CTR-UA-45), [CTR-UA-46](../contracts/accounts.md#CTR-UA-46)) | an app purpose separates signatures; it does not name a delegate |
| registry contracts on one L2 | one admin-free registry per chain, generations walking back ([CTR-UA-73](../contracts/accounts.md#CTR-UA-73)), portable registrations ([CTR-UA-31](../contracts/accounts.md#CTR-UA-31)) | multi-family; nothing to pause |
| `StorageRegistry` units, rent, expiry | fee 0, sponsorship budgets, per-request or per-byte prices (ledger note §1.4); Arweave payer credits ([NODE-SPN-05](../node/sponsorship.md#NODE-SPN-05)) | no expiry and no pruning in SCaaS |
| Storage lending | sponsor policy rows with budgets ([NODE-SPN-01](../node/sponsorship.md#NODE-SPN-01)) | similar intent |
| Snapchain validators (order) | the chain today; the **ledger service** tomorrow (ledger note §11.2), its order one service plus witnesses and anchors | the open question of the TreeKEM note: who orders commits in `groupMode = 2` |
| Snapchain read nodes | `scaas-node` (open relayer and indexer), a ledger replica | a read node relays and serves; so does `scaas-node` |
| validation against OP registries | the ledger service checking UA signatures against the registry read from a list of nodes ([ARCH-POS-15](../decisions.md#ARCH-POS-15)) | §8, lesson 4 |
| `SnapchainConfigRegistry` on L1 | the ledger's `info` (witness list, quorum, rule set) and the anchor contract (ledger note §6.4, §11.2) | §8, lesson 3 |
| shard 0 for shared state | the UA registry and the KEM directory as the shared state every app reads | §8, lesson 7 |
| daily snapshots, commit certificates | C2SP checkpoints and tiles, cosigned (ledger note §11.2) | similar |
| fnames (off-chain, revocable by the server) | no name layer in SCaaS | out of scope here |
| direct casts (client server, off protocol) | PqChat: E2E, PQ hybrid KEM, control plane in state, messages in listed stores | SCaaS is far ahead here |
| channels (shard 0 messages + ERC-721 ownership) | PqChat public topics, admins and rights in the session | similar shape |

## 7. Where SCaaS differs on purpose

1. **Post-quantum and sizes.** Farcaster signs with Ed25519 (32 B key, 64 B signature) and hashes to 160 bits [F]. A SCaaS PQ
   UA signs with ML-DSA-65 (1,952 B key, 3,309 B signature, FIPS 204) or FN-DSA-512 (897 B key, about 666 B signature) [B,
   standards], and a KEM key is 1,601 B ([CTR-UA-32](../contracts/accounts.md#CTR-UA-32)). Per message a PQ signature is 10 to 50
   times Farcaster's; a delegated small key (lesson 1) would recover part of that only by giving up PQ for that key [I].
2. **KEM keys in the registry.** Farcaster stores no encryption keys at all. SCaaS's key directory is a confidentiality root: an
   operator who shows Bob a substituted KEM key reads Bob's messages (ledger note §5.3, §11.4). Anything Farcaster does off chain
   with keys (FIP #266) is safe for *signing* keys because a forged key add needs the custody signature; it would be unsafe for
   *KEM* keys only through **withholding** (a stale key served), which signing does not prevent [I].
3. **Contracts verify records.** Snapchain validators re-execute fixed social rules; SCaaS contracts verify every typed record
   (signature, nonce, rights, shapes, the TreeKEM tree hash) and keep it in state ([CTR-CHAT-05](../contracts/pqchat.md#CTR-CHAT-05)).
4. **Multi-chain and families.** One Farcaster network, one L2 for identity. SCaaS has one rule on every chain and family, the
   same UA everywhere ([CTR-UA-04](../contracts/accounts.md#CTR-UA-04)).
5. **Never lose ciphertext; state-only recovery.** Farcaster prunes by design. SCaaS keeps every ciphertext in contract state
   and lets a client rebuild from state alone.
6. **No decryption oracle** ([ARCH-POS-13](../decisions.md#ARCH-POS-13)). Not a Farcaster concern (no encryption).
7. **Explicit typed records.** Farcaster messages are typed protobufs with named fields too [F]; the difference is the signature
   domain: SCaaS signs EIP-712 typed data under a kind and purpose tag ([CTR-UA-10](../contracts/accounts.md#CTR-UA-10)).
8. **No admin key.** Farcaster's registries can be paused, its storage owner sets prices and credits units, and its node set is
   an EOA's choice [F]. SCaaS contracts are immutable; versions live in the factory catalogue.
9. **No rotation inside an identity.** Farcaster's strongest user feature (keep your fid, lose your keys) has no UA equivalent;
   SCaaS answers it with `SmartKeyAccount` or a new UA plus a move.

## 8. Lessons for the ledger service and groupMode 2 / 3 (proposals, ranked)

Each lesson is a **proposal for the owner**, not a ruling. "Adopt" means the controller would write it into the ledger
service's spec; "consider" means worth a decision; "reject" means stated so that nobody adds it later by analogy.

**L1 (adopt). Scoped, expiring delegated app keys, signed by the UA.** FIP #266's shape fits the ledger service: a UA signs a
typed `LedgerKeyAdd {ua, appId, key, keyKind, scopes (typehashes the key may sign), ttl, nonce, deadline}` under its app purpose;
the ledger accepts a record signed by that key only within its scopes and TTL; `LedgerKeyRemove` by the UA or by the key
itself; revocation immediate and forward-only. Why: a device or app need not hold the UA's root key; a PQ UA (3,309 B per
ML-DSA-65 signature) can delegate per-message signing to a smaller key on high-volume records. Limits: the delegate key's
kind must be one of the kind table's (a small classical key gives up PQ authenticity for those records, a choice per scope, to
be stated to the user); scopes never include a value write, a KEM key record, a membership change or a key add; on chain nothing
changes (the contracts keep checking the UA's own signature). [I]

**L2 (adopt for groupMode 2, consider for 3). Order by a small BFT committee, and let its signatures attest availability.**
Farcaster's history is the evidence that unordered replication with per-node rules does not hold at scale, and that a total
order makes rate limits and sync simple. For `groupMode = 2` the commit slot needs one order; the ledger spec could allow either
one sequencer plus witnesses (ledger note §11.2) or a committee of n ledger nodes running a BFT protocol, a commit accepted when
more than two thirds sign a block that **contains the blobs**. For `groupMode = 3` that same certificate answers the TreeKEM
note's open risk: the contract would accept an epoch only with a committee certificate over the hashes it stores, the committee
members having signed only blobs they hold (the validium data-availability committee pattern). Farcaster's caution applies too:
its committee is 7 keys and one operator holds a quorum, so a committee is only as independent as its operators; the spec should
state the operator distinct-count it requires, as ARCH-POS-15's majority option does for reads. [I]

**L3 (adopt, with a difference). Publish the ledger's node set on chain, but not as an owner's mutable record.** The
`SnapchainConfigRegistry` lets every validator and client find the current set from one chain read. SCaaS's level-2 session
anchor (TreeKEM note) and the ledger's `info` could live in an on-chain record of the ledger (its id, witness or committee keys,
quorum, rule-set hash, endpoints), discovered through ARCH-POS-15. Difference: no `Ownable2Step` EOA; a set change is a new
record signed by the outgoing quorum (and optionally the deployment's governance), appended, never overwritten, so a client can
check the chain of sets. [I]

**L4 (adopt). Pin registry reads to a final block and name it in the accepted record.** Snapchain reads OP at `latest` and has
a TODO for one confirmation [F]. The ledger, when it checks a UA signature or a KEM key against a chain registry, should read at
the chain's final (or safe) block from a list of RPC nodes, and write the chain key, block number and registry generation into
the accepted entry, so a replayer reproduces the same check and a reorg cannot silently change history. [I]

**L5 (consider). Quota units as rate limit and payment, never as pruning.** Farcaster's unit gives a rate limit and a byte or
count cap per type, and its expiry prunes data; it had to change units three times and extend every cohort once (FIP #229,
#271). For the ledger: a unit bounds writes a day and bytes stored, credited by payment, sponsorship or lending; when it runs out,
the UA's writes are refused (fail closed) and **nothing stored is deleted**: "never lose ciphertext" holds off chain as on chain.
Storage cost then grows without bound and must be priced up front (per stored byte, permanent, as Arweave does) rather than as
rent; a deployment that wants retention limits would need an owner ruling for that deployment. [I]

**L6 (adopt). Forward-only revocation, with an explicit compromise marker.** FIP #238 chose not to delete a removed key's past
messages; SCaaS's KEM keys are already never revoked. For L1's delegated keys: a removal refuses future records; a separate
`compromisedSince(time or log index)` field, signed by the UA, lets clients flag (never delete) records signed after that point.
[I]

**L7 (consider). Shard by account, with a shared shard for cross-cutting state.** Snapchain routes by `hash(fid)` and keeps keys,
storage and channels in shard 0. A ledger at 100,000-member groups could shard by `sessionId`, with the UA keys, delegated keys
(L1) and quota (L5) in a shared shard every session reads. Only when one ledger outgrows a node. [I]

**L8 (consider). A stable identity above rotating keys belongs above the UA, not in it.** The fid plus recovery address is why
Farcaster users survive key loss. SCaaS keeps UAs immutable ([CTR-UA-02](../contracts/accounts.md#CTR-UA-02)); for chat and social
uses a ledger-level "profile" record could name the UA set a person uses over time, each change signed by the previous UA or by a
guardian, like `SmartKeyAccount` but off chain. Only if PqChat users need a handle that survives key changes. [I]

**L9 (reject). Things not to copy.**

- **Pruning** of messages or ciphertext, by cap, expiry or block retention (conflicts with "never lose ciphertext").
- **Author timestamps as order** (LWW by client timestamp up to 600 s ahead): the ledger orders by log index only; a timestamp
  is data.
- **Ed25519-only keys and a 160-bit message hash**: the kind table and 256-bit hashes stay.
- **Private messaging off protocol on one company's servers**, and group size set by a product (100).
- **Owner-only admin powers** over the registry (pause), prices and free credits, or the node set (one EOA).
- **Read nodes that drop a submission silently** ("if that gossip is lost, the message is gone"): the ledger's `accepted`
  answer is a signed promise (ledger note §11.2), and the client keeps resubmitting the same signed bytes to its list of
  endpoints until included.

**Ranked:** L1, L2, L3, L4, L5, L6 are the ones worth writing into the ledger service's spec (L2 and L3 are also the concrete
answer to the TreeKEM note's open questions for `groupMode = 2` / `3`); L7 and L8 wait for a need; L9 stands as stated.

## 9. Open questions for the owner

1. **Delegated keys (L1):** may the ledger service accept records signed by a key the UA delegated, with scopes and a TTL? If
   yes: may a delegate be a classical kind (smaller, not PQ) for some scopes, or must it be PQ like its UA?
2. **Ordering for `groupMode = 2` (L2):** one sequencer plus witnesses and anchors, or a BFT committee of ledger nodes, or both
   as a deployment choice? What minimum count of distinct operators?
3. **Availability for `groupMode = 3` (L2):** is a committee certificate ("more than two thirds hold these blobs") an acceptable
   completion condition for an epoch whose KEM bytes are off chain?
4. **The ledger's node set on chain (L3):** an on-chain record per ledger, appended and signed by the outgoing quorum, or is the
   anchor contract of ledger note §6.4 enough?
5. **Quota without pruning (L5):** confirm that off-chain stores never delete accepted records whatever the payment state, and
   that a deployment's retention limit would need its own ruling.
6. **A stable profile above UAs (L8):** wanted for PqChat, or out of scope?

## 10. Sources, and what could not be confirmed

Primary, read 2026-11-25:

- Farcaster docs: Architecture <https://docs.farcaster.xyz/learn/architecture/overview>; Accounts
  <https://docs.farcaster.xyz/learn/what-is-farcaster/accounts>; Messages <https://docs.farcaster.xyz/learn/what-is-farcaster/messages>;
  Apps <https://docs.farcaster.xyz/learn/what-is-farcaster/apps>; Usernames <https://docs.farcaster.xyz/learn/what-is-farcaster/usernames>;
  Direct Casts <https://docs.farcaster.xyz/reference/farcaster/direct-casts>; IdRegistry
  <https://docs.farcaster.xyz/reference/contracts/reference/id-registry>; KeyRegistry
  <https://docs.farcaster.xyz/reference/contracts/reference/key-registry>; StorageRegistry
  <https://docs.farcaster.xyz/reference/contracts/reference/storage-registry>.
- Contracts: <https://github.com/farcasterxyz/contracts/blob/main/docs/docs.md>.
- Protocol spec v2023.11.15: <https://github.com/farcasterxyz/protocol/blob/main/docs/SPECIFICATION.md>.
- FIPs: Snapchain #207 <https://github.com/farcasterxyz/protocol/discussions/207>; Storage Redenomination #229
  <https://github.com/farcasterxyz/protocol/discussions/229>; Signer revokes only impact future messages #238
  <https://github.com/farcasterxyz/protocol/discussions/238>; Functional Signers #262 (Draft, page timed out, not read)
  <https://github.com/farcasterxyz/protocol/discussions/262>; Snapchain Signers #266
  <https://github.com/farcasterxyz/protocol/discussions/266>; Extending Storage Expiry (2026) #271
  <https://github.com/farcasterxyz/protocol/discussions/271>; Channels on Snapchain #276
  <https://github.com/farcasterxyz/protocol/discussions/276>; Onchain Config Registry for Snapchain #277
  <https://github.com/farcasterxyz/protocol/discussions/277>; Direct Casts #99 <https://github.com/farcasterxyz/protocol/discussions/99>.
- Snapchain repository <https://github.com/farcasterxyz/snapchain> at `main`: `README.md`, `CHANGELOG.md` (0.17.0, 2026-11-16),
  `validators.toml`, `site/docs/pages/{whitepaper,validators,node-types}.mdx`, `src/connectors/onchain_events/mod.rs`,
  `src/storage/store/account/{key_add_store,storage_lend_store}.rs`, `src/jobs/block_pruning.rs`; PR #714
  <https://github.com/farcasterxyz/snapchain/pull/714>.

Secondary (not confirmed in a primary source): The Block on the Snapchain mainnet (2025-03-21)
<https://www.theblock.co/post/347606/decentralized-social-media-protocol-farcaster-launches-blockchain-like-data-layer-snapchain>, on
Neynar's acquisition (2026-01-21)
<https://www.theblock.co/news/deals/2026-01-21-haun-backed-neynar-acquires-farcaster-after-founders-pivot-to-wallet-app-386549> and on
Network School's (2026-10-15)
<https://www.theblock.co/news/ecosystems/2026-10-15-network-school-acquires-farcaster-from-neynar-418720> (both articles did not load;
search summaries and other outlets only, e.g. <https://cryptobriefing.com/network-school-acquires-farcaster-network-state-protocol/>);
Neynar's Snapchain docs <https://docs.neynar.com/snapchain/whitepaper>, <https://docs.neynar.com/snapchain/httpapi/storagelimits>.

**Could not be confirmed [U]:** whether direct casts are end-to-end encrypted; the 100-member group limit (Notion page did not
render); any MLS plan; the exact Snapchain mainnet date; whether the erasure coding of the whitepaper is built; the final TTL
wording of FIP #266 (90-day cap, "0 = no expiry"); the operators behind the validator keys "moria" and "isengard"; the terms and
completion of the Network School deal and the "social smart contract"; the IMC 2026 paper's figures on node economics; OP gas per
registry write; the rules of storage lending.

**Correction (owner, 2026-11-25): "Tôi chưa hề đề cập build ledger service".** No off-chain "ledger service" is decided
or scheduled; the name was the controller's label for the owner's research direction of 2026-11-24 (an API between SCaaS
and a backend such as immudb, Supabase, S3 or Arweave). Read every "ledger service", "after the freeze, with the ledger
service's spec" and "the ledger" in this note as "a possible off-chain deployment, if one is ever decided". `groupMode = 2`
and `3` are only reserved values; the questions here wait until such a build is decided.
