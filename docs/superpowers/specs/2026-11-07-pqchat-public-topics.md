# PqChat public topics: communities, posts, threaded replies and votes in contract state

**Status:** SPECIFIED (2026-11-07). The owner ruled the design's choices the same day (D18–D22, §9; a Change on
[CTR-CHAT-01](../../decisions.md#CTR-CHAT-01)); two small questions remain (§9, Q1–Q2), each with a recommendation.
Nothing is built. Builds into `PqChat` in group 3c on branch `ua-mtx-merge` (TODO item 3c); the tasks are §10, the
factory changes §11. UNAUDITED.

**Parent spec:** [`2026-10-25-ua7-pq-e2e-sessions.md`](2026-10-25-ua7-pq-e2e-sessions.md) version 2 (P1–P32, D1–D17,
D22). This file continues its numbering (P33–P46) and reuses its domain, purpose tag, signature check, nonce bitmaps,
SSTORE2 blobs and cost basis. `PqChat` is a factory kind with many instances per chain (D22, parent §2.1 P32); every
topic lives in one instance. **Why a sibling file:** the parent is accepted and long; public topics share no cryptography
with sessions (no KEM, no epochs, no sealing, nothing encrypted), only the contract and the signing path, so they read
better on their own.

**Owner, 2026-11-07:** a UA can own public topics and post in them; content is public **Markdown** (`text/markdown`);
Lemmy-style: a topic is a community, posts in it, **threaded replies** on posts and on replies; **who may post: the topic
owner plus writers the owner grants and revokes**; content must not depend on event logs (logs and history expire): posts,
replies and every index live in contract **state**, listed by paged views (topics by owner, posts by topic, replies by
parent, entries by author). Then D18–D22 (§9): nothing hidden, replies open by default, bodies in full on chain with an
optional link to an entry on another chain, up and down votes, `PqChat` instances from the factory. On cost: "if storing
on chain is cheap, fine".

## 1. Model

```mermaid
flowchart TD
  F["OpenFactory: createPqChat (D22)"] --> I["PqChat instance (owner UA): sessions + topics"]
  I --> T["Topic (owner UA, writers, openReplies)"]
  T --> P1["Post: entry, parentId = 0, depth 0"]
  T --> P2["Post"]
  P1 --> R1["Reply: entry, parentId = post, depth 1"]
  R1 --> R2["Reply to a reply: depth 2"]
  P1 -.-> V["Versions of the post: edits 2, 3, … (nothing removed)"]
  P1 -.-> S["Score: up / down counts, one vote per UA"]
  R1 -.-> X["Optional reference: (chainUid, instance, entryId, contentHash) on another chain, not verified"]
```

**P33 — One entry record.** A post and a reply are the same record, `PqTopicEntry`, with a `parentId`: zero for a post
(depth 0), otherwise the id of the entry it answers, a post or a reply, in the same topic of the same instance (depth =
the parent's depth + 1, no bound; the contract never walks a thread). Edits are versions of an entry (P38). Nothing is
removed or hidden (D18, backup-not-delete).

**P34 — Public by nature.** Topics, entries, authors, writers, votes and times are public forever. Nothing is sealed;
there is no `sealedInfo` and no store list. The unlinkable mode of the parent (§13, `docs/research/pqchat-unlinkability.md`)
does not apply and cannot: a public post or vote is linked to its author's UA by its signature, and to its topic and parent
by its fields. A UA that posts or votes in public topics and is also a session member links both; a client says so and
offers a separate UA for public use.

## 2. Records

**P35 — Domain, purpose, signature.** As the parent's P7: typed EIP-712 structs in the portable domain `DS_C` ("SCaaS
PqChat", "1", no chain id, no address), the author signs `uaMessage(kind, PURPOSE_PQCHAT, typed(s))` as a `UASig`
(single key or `msig` by quorum), the contract verifies through the registry's `requirePortable` (parent §14 O1). The type
strings below differ from every session struct, so a session signature is never a topic record. No record carries a fee;
a payer pays a relayer through `MtxRelayFee` (CTR-MTX-27). Every write is relayable by anyone, fee 0 too.

| Struct | Type string | Signed by |
|---|---|---|
| `PqTopic` | `PqTopic(bytes32 owner,uint64 nonce,bytes32 homeChain,address homeContract,string name,bytes about,bool openReplies)` | `owner` |
| `PqTopicUpdate` | `PqTopicUpdate(bytes32 topicId,uint64 seq,string name,bytes about,bool openReplies)` | the topic's owner |
| `PqTopicWriter` | `PqTopicWriter(bytes32 topicId,bytes32 writer,bool granted,uint64 seq)` | the topic's owner |
| `PqTopicEntry` | `PqTopicEntry(bytes32 topicId,bytes32 author,uint64 nonce,bytes32 parentId,EntryRef ref,string mediaType,bytes body)EntryRef(bytes32 chainUid,address pqchat,bytes32 entryId,bytes32 contentHash)` | `author` |
| `PqTopicEdit` | `PqTopicEdit(bytes32 entryId,bytes32 author,uint64 nonce,uint32 version,string mediaType,bytes body)` | the entry's author |
| `PqTopicVote` | `PqTopicVote(bytes32 entryId,bytes32 voter,int8 value,uint64 seq)` | `voter` |

**Fields.**

- `homeChain`, `homeContract` — the instance whose state readers treat as the topic's reference (as a session's home,
  parent P32); no contract rule reads them beyond "not zero". The same records may land in other instances as mirrors
  (P43).
- `name` — UTF-8, 1–128 B; not unique (ids are hashes; no global name to squat). `about` — the topic's description,
  Markdown bytes.
- `openReplies` — who may reply (P37); clients create topics with `true` (D19).
- `mediaType` — 1–64 B. Clients write `text/markdown` (RFC 7763, CommonMark); the contract checks only the length, so a
  later type needs no new release.
- `body` — the full text, non-empty, **always in state** (D20; no off-chain form). Bounded only by the transaction (P39).
- `ref` — an optional **reference to an entry in another instance**, usually on another chain (D20): all four fields zero
  for none; otherwise `chainUid`, `pqchat` (the instance's address there) and `entryId` non-zero (`PqTopicRef`), and
  `contentHash` either zero (not pinned) or `typed(...)` of the exact referenced version (its `PqTopicEntry` or
  `PqTopicEdit` record under `DS_C`). **The contract stores the reference as given and never checks it**: no bridge, no
  message across chains, no proof; the target may not exist. A reader resolves it by reading that chain's state (an RPC
  there), checks that its factory lists `pqchat` as a `PqChat` instance, and compares `contentHash` when set; until then
  the client shows the link as unverified. Edits keep the original's reference.
- `value` — `+1` up, `-1` down, `0` withdrawn (`PqTopicVoteValue` otherwise).

**P36 — Ids and nonces.** As the parent's §4.3:

```text
topicId = keccak256(abi.encode(keccak256("scaas/pqchat/v1/topic"), owner, nonce))
entryId = keccak256(abi.encode(keccak256("scaas/pqchat/v1/entry"), topicId, author, nonce))   edits use the same scope
```

Nonce bitmaps per instance, any order, checked after the signature and then marked used (a forged record cannot burn a
nonce): a topic `(owner, nonce)` under its own tag, apart from the session scope; an entry or an edit `(topicId, author,
nonce)`. Records that replace a value carry `seq` and are accepted only at **`seq == stored + 1`** (`PqTopicSeq`): a topic
update per `topicId`, a writer grant or revoke per `(topicId, writer)`, a vote per `(entryId, voter)`. A `seq` far ahead
could lock a value forever; `+1` cannot.

## 3. Rights

**P37 — Who writes what.**

| Operation | Who may sign |
|---|---|
| create a topic | any UA the registry verifies |
| update a topic, grant or revoke a writer | the topic's owner (fixed for the topic's life; an `msig` owner gives shared ownership) |
| post (`parentId` zero) | the owner or a granted writer (`PqTopicNotWriter`) |
| reply (`parentId` set) | `openReplies` true (the default, D19): any UA the registry verifies; false: the owner or a writer |
| edit | the entry's author only, the topic owner included in that rule (`PqTopicNotAuthor`) |
| vote | any UA the registry verifies, once per entry, changeable (P40) |

A revoked writer's entries stay; its new posts are refused. The **instance** owner (D22) has no right here at all. Rights
are read from **this instance's state at submission**; a record copied to a mirror before the matching grant or revoke
lands there may be accepted or refused differently, which is why readers follow the topic's home (P43). No moderators,
no hide flag, no ban list (D18); a client may filter entries locally on its own, outside the contract.

## 4. State

**P38 — Edits are versions.** `editEntry` stores a new version of an existing entry: `entryId` names the original (the
first version), `version` must equal the stored version count + 1 (`PqTopicVersion`; the first edit is version 2), the
author must be the original's author. Versions append to the original's list; `entryOf` returns the latest, `versionAt`
any. An edit keeps the original's topic, parent, reference, votes and place in every list; replies attach to the original
id. Two edits racing for the same version: the first to land wins, the other is refused and re-signed (as the parent's P9).

**P39 — Storage.** Each record's bytes, `abi.encode(<struct fields>, sigHash)`, go into SSTORE2 blobs of at most the
release's declared code-size limit (parent P11), split across as many blobs as needed. As the parent's D11, the
signature's hash is in the blob and its bytes in the event: the contract checked the signature on the way in; a mirror
copying the record elsewhere needs the bytes from the author, the event or an indexer. Content never depends on a log.
**The only bound on a body is the transaction** (EIP-8037: regular + state gas within the chain's block limit, about
38 KB at a 60 M block and 1,530 gas per byte); the contract assumes no block limit. A longer text is posted as an entry
and follow-up replies by the same author (Q1).

| State (per instance, ERC-7201) | Slots | Written by |
|---|---|---|
| `topic[topicId]` | owner; blob pointer + `seq` + `openReplies` | create; pointer, `seq`, flag on update |
| `writer[topicId][ua]` | `granted` + `seq` | grant / revoke |
| `entry[entryId]` | blob pointer + `depth` + version count; one more per extra blob | post, reply; count on edit |
| `versions[entryId]` | one blob pointer per edit | edit |
| `vote[entryId][ua]` | `value` + `seq` | vote |
| `score[entryId]` | `up` (uint128) + `down` (uint128) | vote |
| lists (`bytes32[]`, append-only) | `topics`, `topicsByOwner[owner]`, `writersOf[topicId]` (first grant only), `posts[topicId]`, `replies[parentId]`, `byAuthor[author]` (originals, every topic) | create, grant, post, reply |

Layout pinned under `test/v2/layout/` with the rest of `PqChat` (a clone's namespaced storage).

**P40 — Votes and double voting.** `voteEntry` (D21): the entry must exist in this instance (`PqTopicUnknown`); the vote
attaches to the original id. The contract keeps **one slot per (entry, voter UA)** holding the current value and `seq`; a
new vote replaces it and moves the counts (the old value's count − 1, the new one's + 1), so one UA counts at most once
per entry. A replay is refused by `seq`; the signature binds the voter UA, so nobody votes as another. What it does
**not** prevent: one person with many UAs; each UA costs its registration, and a client may weigh or filter voters on its
own. Counts are public `up` and `down`, never a combined score in state.

## 5. Entries, views, events

**P41 — Entries.** One entry per operation, named typed parameters:

| Entry | Checks |
|---|---|
| `createTopic(PqTopic t, UASig sig)` | sig; nonce; `homeChain`, `homeContract` not zero; lengths |
| `updateTopic(PqTopicUpdate u, UASig sig)` | sig by the topic owner (`PqTopicNotOwner`); `seq == stored + 1`; lengths |
| `setTopicWriter(PqTopicWriter w, UASig sig)` | sig by the topic owner; `seq == stored + 1`; `writer` not the owner |
| `postEntry(PqTopicEntry e, UASig sig)` | sig; nonce; topic exists; P37 rights; parent exists in the same topic (`PqTopicParent`); `ref` shape; lengths |
| `editEntry(PqTopicEdit e, UASig sig)` | sig; nonce in the original's topic scope; original exists; author equals the original's; `version`; lengths |
| `voteEntry(PqTopicVote v, UASig sig)` | sig; entry exists; `value` in −1..1; `seq == stored + 1` |

**P42 — Views, paged; events as notifications.** `(start, count)` returns at most `count` ids from `start`, fewer at
the end, empty past it; every list has a count view. `topicOf(topicId)`, `entryOf(entryId)` (topicId, author, parentId,
depth, ref, mediaType, body, sigHash, versionCount, of the latest version), `versionAt(entryId, i)`, `writerOf(topicId,
ua)`, `scoreOf(entryId)` (up, down), `voteOf(entryId, ua)` (value, seq); lists `topics`, `topicsByOwner`, `writersOf`,
`posts`, `replies`, `byAuthor`; `topicNonceUsed`, `entryNonceUsed`. Events: `PqTopicCreated(topicId, owner)`,
`PqTopicUpdated(topicId, seq)`, `PqTopicWriterSet(topicId, writer, granted, seq)`, `PqTopicEntryPosted(topicId, entryId,
parentId, author, sig)`, `PqTopicEntryEdited(entryId, version, sig)`, `PqTopicVoted(entryId, voter, value, seq)`. No view
reads a log, and no reader needs one. Errors named per check: `PqTopicSeq`, `PqTopicNotOwner`, `PqTopicNotWriter`,
`PqTopicNotAuthor`, `PqTopicParent`, `PqTopicVersion`, `PqTopicRef`, `PqTopicVoteValue`, `PqTopicShape`,
`PqTopicUnknown`, plus the parent's `PqChatNonceUsed`.

**P43 — Several instances and chains.** One rule in every instance on every chain: the same records, ids and checks.
Copying a topic elsewhere is copying its records, parents before replies, originals before edits, grants before the
writer's posts; out of order, a record is refused there until what it needs has landed. Readers display the topic's home
instance; others are mirrors. A cross-chain **reference** (P35 `ref`) is different: it points, it copies nothing.

## 6. Anti-spam and cost

**P44 — What limits writes.** Posts only by the owner and writers; replies and votes by any registered UA (D19, D21),
each signed, each nonce or `seq` used once (a replay guard, not a rate limit); gas paid by the submitter; the node relays
a write only when paid through `MtxRelayFee` or under the operator's lane policy (parent P17). No on-chain rate limit: one
keyed on time adds a slot write per entry and does not stop many UAs. With no hide (D18), whatever a topic accepts stays
in state; an owner who wants a quiet topic sets `openReplies` false, and a client may filter locally.

**Gas on paper** (parent §11 basis: EIP-8037 1,530 gas per state byte, new slot 97,920, new account 183,600; ETH
$2,261.87; about $0.70 per M gas at 0.31 gwei, $11.3 at 5 gwei, $0.011 on a layer 2 at 0.005 gwei). Signature
verification is regular gas: FN-DSA-512 2.3 M, ML-DSA-65 on the cached key 5.8 M, a precompile ≈ 0.2 M.

| Write | Blob | State gas | Total, FN-DSA-512 / ML-DSA-65 cached / precompile | 0.31 gwei | 0.005 gwei |
|---|---|---|---|---|---|
| **each further KiB of body** | 1,024 B | **≈ 1.57 M** | — | **$1.10** | **$0.018** |
| post, 1 KiB Markdown | 1,473 B | ≈ 2.7 M (blob 2.25 M, account 0.18 M, 3 slots 0.29 M; +0.1 M per new list or nonce word) | ≈ 5.2 / 8.7 / 3.1 M | $3.6 / 6.1 / 2.2 | $0.06 / 0.10 / 0.03 |
| reply, 256 B | 705 B | ≈ 1.6 M | ≈ 4.0 / 7.5 / 1.9 M | $2.8 / 5.3 / 1.3 | $0.05 / 0.08 / 0.02 |
| edit, 1 KiB | 1,345 B | ≈ 2.4 M (blob, account, version slot) | ≈ 4.9 / 8.4 / 2.8 M | $3.4 / 5.9 / 2.0 | $0.05 / 0.09 / 0.03 |
| vote, first on an entry by this UA | — | ≈ 0.1–0.2 M (vote slot; score slot on an entry's first vote) | ≈ 2.5 / 6.0 / 0.4 M | $1.8 / 4.2 / 0.3 | $0.03 / 0.07 / 0.004 |
| vote changed | — | 0 (slots exist) | ≈ 2.3 / 5.8 / 0.2 M | $1.6 / 4.1 / 0.2 | $0.03 / 0.06 / 0.003 |
| create topic, 256-B `about` | 609 B | ≈ 1.6 M (blob, account, 2 topic slots, 2 list slots, nonce word) | ≈ 4.0 / 7.5 / 1.9 M | $2.8 / 5.3 / 1.3 | $0.05 / 0.08 / 0.02 |
| grant a writer | — | ≈ 0.2 M | ≈ 2.6 / 6.1 / 0.5 M | $1.8 / 4.3 / 0.4 | $0.03 / 0.07 / 0.006 |

**Cheap where gas is cheap.** Storage dominates: about 1.57 M state gas per KiB of body, which is about 2 cents a KiB on a
layer 2 pricing state at 0.005 gwei and less on a chain with a lower gas price; the signature costs more than a short
reply's text. On Ethereum today the same KiB is about $1.10 (at 5 gwei, $18). On the SCaaS testnet it costs the test
token. To be measured in PT4; a transaction fits only if regular + state gas fits the block limit (EIP-8037).

**Contract size.** Six entries, ≈ 18 views, the typehashes and checks: an estimate of +8–12 KB runtime on the `PqChat`
release. Measured in PT4 against the size gate; if the release then passes 64 KiB, the owner decides between the
`_above64KiB` pin and moving topics into a second release kind, with the figures.

## 7. Node and indexer

**P45 — Node.** Six new `call` rows (`createTopic`, `updateTopic`, `setTopicWriter`, `postEntry`, `editEntry`,
`voteEntry`), equal to the release's entries both directions, named JSON fields per job, old hex forms refused
(`HEX_ARGS_REFUSED`); the call target must be an instance the chain's factory lists as `PqChat` (parent P17, P32). The
rule and the rows go in `docs/node/job-api.md` for every consumer (PLANNED). The node's indexer **may** mirror topics for
full-text search and feeds, reading the views (events only as a hint of what to read) and the factory index for the
instances; the chain's state is the answer, and every mirrored item names its `(chain_uid, instance, list, index)` so a
client can re-read it.

**P46 — Clients.** `ua-rs` signs the six structs as typed portable records (the `ua-rs` signing round, TODO 3d), and every
client reads the vectors (`smartcontracts/vectors/pqchat/topics.json`). A client renders `text/markdown` as CommonMark with
raw HTML off, links marked as external, and no remote image loaded without the reader's consent (a public post is
untrusted input); it resolves a cross-chain `ref` as P35 says before showing it as verified. The app's topic UI is out of
scope here.

## 8. Tests and mutants

Tests (red first, each refusal with its positive control, one change at a time):

1. Create a topic; owner posts; a granted writer posts; a stranger's post refused (`PqTopicNotWriter`); a revoked writer's
   new post refused and its old post still listed.
2. Writer records: `seq` 1 then 2 accepted, a repeated or skipped `seq` refused (`PqTopicSeq`), a non-owner signer refused
   (`PqTopicNotOwner`), revoke then re-grant; the instance owner is no topic owner.
3. Replies: an open topic accepts a stranger's reply; after `updateTopic(openReplies = false)` the stranger is refused and
   a writer accepted; a reply to a reply has depth 2; a parent in another topic, unknown, or in another instance refused
   (`PqTopicParent`).
4. Edits: version 2 then 3 by the author accepted, `entryOf` returns version 3, `versionAt` returns 1–3; another UA's edit
   refused, the topic owner's included (`PqTopicNotAuthor`); version 2 twice refused (`PqTopicVersion`); replies and votes
   stay on the original id.
5. Votes: +1, then −1 by the same UA moves one count from `up` to `down`; 0 withdraws; the same `seq` twice refused; a
   value of 2 refused (`PqTopicVoteValue`); two UAs count twice, one UA never; a vote on an unknown entry refused.
6. Bodies: a body over one blob splits and reads back byte-exact; an empty body, an over-length `mediaType` or `name`
   refused; a `ref` with `chainUid` set and `entryId` zero refused (`PqTopicRef`); a well-formed `ref` to nothing stored
   accepted (no cross-chain check) and returned as given.
7. Nonces: a replay refused; nonces in any order accepted; a forged record does not burn a nonce.
8. Paged views at the edges (`start` past the end, `count` clipped), `byAuthor` across two topics, `topicsByOwner`, all
   topics; every assertion through views with logs ignored.
9. Two instances from the factory: a topic in A is absent in B; its records copied into B in order land with the same
   ids; a reply before its parent refused there, then accepted.
10. An `msig` topic owner grants by quorum; a session record's signature refused as a topic record (type separation).
11. Typehashes pinned against the vectors (`*TypehashIsPinned`); layout pin; gas rows (PT4).

Mutants, each killed by a test above: the writer check, the `openReplies` check, the parent-topic equality, depth + 1,
the edit-author check, the version + 1 check, the `seq` + 1 check, the vote's old-count decrement, the vote value range,
the `ref` shape check, the nonce scope's `topicId` dimension, the list key (parent vs topic), `byAuthor` written for edits.

## 9. Owner decisions and questions

**Decisions of 2026-11-07** (owner, relayed by the coordinator; a Change on CTR-CHAT-01):

- **D18 — Nothing hidden, no on-chain moderation.** Neither the topic owner, a moderator nor anyone else may hide an
  entry; the contract has no hide flag, no moderator role and no ban list. Every accepted entry stays listed for good. A
  client may filter locally on its own.
- **D19 — Replies.** Each topic has an `openReplies` flag: true lets any registered UA reply; **the default is open**;
  the topic owner may change it (`updateTopic`). Posting stays the owner's and the writers'.
- **D20 — Bodies in full on chain; references across chains.** A body is stored in full in state; there is no off-chain
  body (hash + URI). An entry may carry a named reference to an entry in another instance, usually on another chain:
  `chainUid`, instance address, entry id and an optional content hash; no bridging and no verification across chains.
- **D21 — Votes.** Minimal up and down counts per entry, in state; one vote per UA per entry, changeable.
- **D22 — `PqChat` is a factory kind** (parent §2.1 P32): many instances per chain, each with its own owner UA, sessions
  and public topics; the factory index gets a `PQCHAT` class (§11).
- **Cost:** the owner accepts the on-chain cost ("if storing on chain is cheap, fine"); §6 gives it per KiB.

**Q1 — Text longer than one transaction.** A body is bounded by the chain's block limit (≈ 38 KB at 60 M).
**Recommendation:** no contract feature; the client posts the rest as replies by the same author, marked as a
continuation in the Markdown. A signed body hash with unsigned `appendBody` parts (as `addWraps`) is the way if long
documents become common; it adds an entry and a check, not needed for posts and comments.

**Q2 — Powers of an instance's owner UA.** **Recommendation: none** over sessions, topics, entries or votes; the owner UA
names the instance in the factory index and `owner()`, fixed at creation, with no transfer (there is nothing to govern).
A later release could add an owner-set name or a topic-creation allow-list if a service needs one.

## 10. Tasks for 3c (branch `ua-mtx-merge`)

To be numbered into the merge plan; sizes in agent-days. The factory index tasks T67–T69 come before 3c in the work order
(3e → 3g → factory index → 3f → 3h → 3c), so PF1 extends a built index.

| # | Task | Files | Size |
|---|---|---|---|
| PF1 | Factory `PQCHAT` class (§11) | `src/factory/OpenFactory.sol`, `IOpenFactory.sol`, `test/factory/*`, `GovGas` row | 1–1.5 |
| PC0 | `PqChat` as a release (parent P32): `initialize(creator, version, ownerUA)` once, by the factory only; `owner()`; ERC-7201 storage; immutables registry, `chain_uid`, factory, code-size limit; `homeContract` in `PqChatSession` and the home-instance check of P9; store-list `contract`; changes to UA-7 plan T5, T6, T8 (T8 becomes the release deploy in `DeployBase` plus one instance) | `src/pqchat/*`, `script/DeployBase.s.sol`, `test/pqchat/*` | +0.5–1 over T5–T8 |
| PT1 | Vectors: six topic typehashes, `EntryRef`, ids, a record and blob per struct, the new `PqChatSession` typehash, non-zero values in every field | `clients/clientkeys` `src/pqchat.js`, `scripts/pqchat-vectors.mjs`, `smartcontracts/vectors/pqchat/topics.json` | 0.5–1 |
| PT2 | Topics: structs, five entries (no votes), rights, edits, multi-blob bodies, `ref`, lists, views, events, errors; tests 1–4, 6–10 | `src/pqchat/PqChat.sol`, `PqChatTypes.sol`, `IPqChat.sol`, `test/pqchat/PqTopics.t.sol` | 2–3 |
| PT3 | Votes: `voteEntry`, vote and score slots, views; test 5 | same | 0.5–1 |
| PT4 | Gas rows of §6 (`--isolate`, new pins with figures), size-gate row, layout pin | `test/pqchat/PqChatGas.t.sol`, `size-baseline.json`, `test/v2/layout/` | 0.5 |
| PT5 | Mutants of §8 and their summary in the gate runner | `runs/<date>-ua7-pqchat-gates.sh` summary | 0.5–1 |
| PT6 | Node: six topic rows, the instance check on every `PqChat` row (`isPqChat`), job shapes, allow-list both directions | `scaas-node` call table, `docs/node/job-api.md` | 0.5–1 |
| PT7 | `ua-rs`: build and sign the six records, read the views, resolve a `ref`, vectors row by row | `clients/ua-rs` `pqchat` module | 1 |
| PT8 | Docs: `docs/contracts/pqchat.md` sections for instances and public topics (SPECIFIED, then BUILT); `docs/contracts/` factory doc row for class 3 | docs | 0.5 |
| | **Total** | | **7.5–11** |

## 11. Changes the factory index needs (spec `2026-11-07-factory-contract-index.md`, branch `ua-mtx-merge`)

Not edited here; for PF1. The index spec is approved with classes TOKEN = 1, DEX = 2 and 3–255 reserved for later classes.

1. **Class.** `uint8 public constant CLASS_PQCHAT = 3;` in the index's §2.1; `kind = 0`, `version` = the release version,
   `ownerUA` = the instance's `owner()` after `initialize`. `ClassUnknown` stays for 0 and 4–255.
2. **Environment domain.** `uint8 public constant PQCHAT_DOMAIN = 254` beside `DEX_DOMAIN = 255`, with `publishPqChatEnv`,
   `pqChatEnvOf`, `latestPqChatEnvVersion`, as the DEX's (the env carries the factory and `chain_uid`; `implArgs` carries
   the registry address and the declared code-size limit).
3. **Catalogue.** `deployPqChatImplementation(uint64 version, uint16 envVersion, bytes initcode, bytes implArgs)`
   (registrar only; `CREATE2` salt `keccak256(abi.encode("pqchat", version))`; checks `factory()` and `chainUid()` as for
   a DEX release; the notice period applies), `pqChatReleaseOf`, `pqChatImplementationOf`, `deprecatePqChat`,
   `isPqChatDeprecated`, `latestPqChatVersion`; events `PqChatImplementationDeployed`, `PqChatImplementationDeprecated`;
   errors `PqChatVersionUnknown`, `PqChatVersionAlreadyRegistered`, `PqChatVersionDeprecated`, `PqChatVersionNotYetUsable`.
4. **Creation.** `createPqChat(uint64 version, bytes32 ownerUA, bytes32 salt) returns (address pqchat)`: named parameters,
   no `initArgs` bundle; clone by `CREATE2` with the creator-scoped salt, `initialize(msg.sender, version, ownerUA)`, the
   index record (class 3) and its three list pushes, then `PqChatCreated(pqchat, creator, version, implementation,
   ownerUA)`. `ownerUA` zero is accepted and kept out of the owner list (index Q4). `isPqChat(address)` reads
   `contractClass == CLASS_PQCHAT` (for the node, as `isDex`).
5. **Gas.** A creation: the clone's account and 45 B of code (≈ 0.25 M state), `initialize`'s owner slot (≈ 0.1 M), the
   index (+5 slots steady, +7 first: ≈ 0.49–0.69 M): **≈ 0.85–1.05 M state gas**, plus ≈ 0.1 M regular. Measured in a
   new `GovGas` `createPqChat` row.
6. **Size.** The DEX block's pattern again: an estimated +2–3 KB on `OpenFactory` (15,821 B today, +2.5–4 KB from the
   index), far below 64 KiB; the size-gate row moves old → new.
7. **Tests.** The index tests of T67 that use class 3 as unknown move to class 4. New: a release deployed, usable after
   the notice period, deprecated and then refused; a release whose `factory()` or `chainUid()` differs refused; a creation
   by a relayer naming an owner UA lists under both; two instances by one creator, independent; `initialize` callable once
   and only by the factory; `contractsPage(3, …)` and `contractsOfOwner(ua, 3, …)`; `isPqChat` true only for class 3;
   the slot count (+5 / +7). Mutants: the class constant, the env domain, `initialize` before the salt check, `isPqChat`
   answering for a DEX.
8. **Formats.** A new `OpenFactory` build for the reset chain (all chains test-only); the deploy JSONs move with its init
   code, as the index spec says. No token, DEX or `mtx*` typehash or selector changes.
