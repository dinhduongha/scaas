# `pqchat-core`: the PqChat client core

`pqchat-core` is the Rust crate that holds PqChat's client logic: sessions, epochs, wraps, the sender chains, the envelope,
the checks of every record it reads, dedupe and conversation order, recovery from contract state, public topics and the store
adapters. It is an **app core above `scaas-sdk`**: every key operation, signature and chain read goes through the SDK, and its
Matrix store is the app's own Matrix client. The protocol it implements is normative elsewhere: the contract
[pqchat.md](../contracts/pqchat.md) (CTR-CHAT-01 to CTR-CHAT-21) and the UA-7 spec
[`2026-10-25-ua7-pq-e2e-sessions.md`](../superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md) (P1–P49) with the topics spec
[`2026-11-07-pqchat-public-topics.md`](../superpowers/specs/2026-11-07-pqchat-public-topics.md) (P33–P46); this page holds what
the crate adds. Status: **SPECIFIED**, nothing built (spec
[`2026-11-17-pqchat-core.md`](../superpowers/specs/2026-11-17-pqchat-core.md), plan
[`2026-11-17-pqchat-core.md`](../superpowers/plans/2026-11-17-pqchat-core.md), branch `pqchat-core`). Path when built:
`clients/pqchat-core`. UNAUDITED.

**Contents**

1. [Place and scope](#1-place-and-scope)
2. [Secrets and signing](#2-secrets-and-signing)
3. [The Matrix store](#3-the-matrix-store)
4. [Protocol duties](#4-protocol-duties)
5. [Vectors and tests](#5-vectors-and-tests)

## 1. Place and scope

Status: **SPECIFIED**.

<a id="CLI-PQC-01"></a>**CLI-PQC-01** — **`pqchat-core` is an app core above `scaas-sdk`: it depends on the SDK and on the app's
Matrix client, and the SDK names no chat** (owner 2026-11-17, "OK, reverse pqchat-core too"; SPECIFIED). It depends on
`scaas-sdk` with the SDK's app-core feature (the generic surface of the SDK spec's App cores section,
[`2026-11-17-scaas-sdk.md`](../superpowers/specs/2026-11-17-scaas-sdk.md), as rewritten on branch `scaas-sdk`), and on nothing else
that touches a key or a node: no `scaas-ua`, no `scaas-rpc` and no Matrix SDK of its own (a `cargo tree` test). It reaches the app's
live Matrix client (scaas-app's `app-matrix`) through a small transport trait it defines and the app's Matrix crate implements, so
the dependency points from the app to `pqchat-core`, never into the app's repository. It holds no cryptography: no KEM, KDF, MAC, AEAD, signature, and no hash or
decoder of a signed byte format (typed digests, ids, `sigHash`, wrap hashes, the envelope's inner ABI bytes); those are `ua-rs`'s,
reached through the SDK ([CLI-UAL-01](ua-libraries.md#CLI-UAL-01)). It owns the state machine: what to build, when, from which
reads, and what to show. In scaas-app it is the Cargo feature `pqchat` of the one library `app-core-rust` (implying `scaas`), so the
SDK, `app-matrix`, `pqchat-core` and `ua-rs` share one process, one tokio runtime and one Matrix login
([CLI-SDK-12](scaas-sdk.md#CLI-SDK-12)'s one library per app).

<a id="CLI-PQC-02"></a>**CLI-PQC-02** — **This round's scope: 1:1 sessions first, groups correct; Matrix and chain stores; public
topics; no calls, no attachments, no HCS, Waku or libp2p** (owner 2026-11-10: the 2-person chat is the main case; controller call
for the cut, owner may override; SPECIFIED). In: sessions, epochs and rekeys, wraps in chunks, `leave`, `remove`, the home rule and
replicas, `msig` expansion, the sender chains, padding, the envelope, `postMessage` and `storeMessage`, dedupe and order, recovery
from state, pending until accepted, the content types `text`, `edit`, `redact`, `react`, `receipt` and `typing` (UA-7 §6.4.1), and
public topics. Out, PLANNED in later tasks of the UA-7 plan: calls and their content types (`callMember`, `callOffer`,
`callAnswer`, `callCandidates`, `callKey`), `file` attachments, the HCS, Waku and libp2p adapters, device linking and the epoch-key
export (UA-7 P6, §14 O5). A content of a type out of scope is shown as unsupported and never acted on (UA-7 P49).

## 2. Secrets and signing

Status: **SPECIFIED** (the SDK surface it needs: the SDK spec's App cores section, SPECIFIED on branch `scaas-sdk`).

<a id="CLI-PQC-03"></a>**CLI-PQC-03** — **Secrets stay below the SDK: `pqchat-core` holds key handles only, and only decrypted
plaintext leaves** (coordinator condition 1, 2026-11-17; SPECIFIED). The epoch key `K`, each wrap's shared secret and KEK, the
chain keys `ck_i`, the message keys `mk_i` and nonces `n_i`, `k_env` and the `sealedInfo` key are `ua-rs` handles: the KEM
encapsulation and decapsulation with the FIPS 203 checks of UA-7 P14, HKDF, the HMAC steps of the sender chain and every AES-256-GCM
or AES-256-GCM-SIV operation run in `ua-rs` on those handles. The only bytes that leave are plaintexts decrypted for the user: a
message content and an epoch's `sealedInfo` (the store list, the room id, the Matrix user ids, the session's name and topic), as
`SecretBytes`. Every key-derivation label PqChat uses starts with `scaas/pqchat/v1/`, the one label prefix the crate declares to
the SDK, so it cannot use the user's KEM key to open another app's keys; the KEM scheme's own combiner label `scaas.kem.1` is the
scheme's (CTR-UA-32), not an app label. Handles die at the seed's lock ([CLI-UAL-09](ua-libraries.md#CLI-UAL-09)); the crate
re-derives them from contract state after an unlock and persists no secret (CLI-PQC-09). A handle, a key byte or a ciphertext never
appears in an error, an event, a log line or `Debug` output ([CLI-UAL-04](ua-libraries.md#CLI-UAL-04),
[CLI-SDK-02](scaas-sdk.md#CLI-SDK-02)).

<a id="CLI-PQC-04"></a>**CLI-PQC-04** — **No blind signing: PqChat records are signed only through the SDK's named, typed PqChat
entries, under `PURPOSE_PQCHAT` in `DS_C`, built from named fields; never a digest, never the generic app signing call**
(coordinator ruling 2026-11-17, correcting condition 2; the owner may override; SPECIFIED). `PqChat` is a SCaaS contract, so the SDK
keeps one signing entry per record struct the contract checks, as it does for every SCaaS contract's operations
([CLI-SDK-08](scaas-sdk.md#CLI-SDK-08)): `PqChatSession`, `PqChatEpoch` (each computing `wrapHashes` from the named `Wrap` fields it
is given), `PqChatLeave`, `PqChatRemove`, `PqChatMessage`, `PqTopic`, `PqTopicUpdate`, `PqTopicWriter`, `PqTopicEntry`,
`PqTopicEdit`, `PqTopicVote` ([CTR-CHAT-03](../contracts/pqchat.md#CTR-CHAT-03)). `ua-rs` builds the typed data, hashes it and signs
`uaMessage(kind, PURPOSE_PQCHAT, typed(record))`; the review shows every field before the signature. `pqchat-core` passes named
fields and receives the `UASig`, the typed digest and the record's id; it never passes a digest. The SDK's generic app signing
call stays closed to every SCaaS purpose and domain, `PURPOSE_PQCHAT` and `DS_C` included. So the SDK knows PqChat's record
formats and none of its logic. Messages and leaves are signed by a leaf UA, never by an `msig` (UA-7 P13); an `msig` admin signs
epoch and removal records by its quorum.

## 3. The Matrix store

Status: **SPECIFIED** (scaas-app's contract, its section 11, is the app side).

<a id="CLI-PQC-05"></a>**CLI-PQC-05** — **The Matrix store is the app's live Matrix client: one stack, one client, one login; a
PqChat session is never a Matrix room to the user** (owner 2026-11-17, chat "(b)"; SPECIFIED). `pqchat-core` attaches to the app's
`app-matrix` client after the app's Matrix login and detaches before the app's Matrix logout; it opens no Matrix client, login or
sync loop of its own and links no second Matrix SDK. It sends each envelope as one `net.scaas.pqchat.v1` event `{v, hint, env}`
(UA-7 P15) in the room its session's `sealedInfo` lists, and receives every such event of a room an accepted session lists; an
event of any other room is ignored. It creates the room for a session it creates, puts the room id only in `sealedInfo` (never on
chain in the clear, D10), invites and removes Matrix ids only as an epoch's members and `sealedInfo` say, and grants no PqChat
right from a Matrix power level. The app never shows a PqChat room as an ordinary Matrix room, never upgrades a Matrix room into a
PqChat session in place, and never joins a PqChat room before its session is accepted (CLI-PQC-08). Matrix's own Olm / Megolm
layer may stay on as an outer layer; it adds nothing PqChat relies on. Without an attached client a session that lists Matrix
cannot send (`MatrixDetached`) and its chain stores still serve reads.

## 4. Protocol duties

Status: **SPECIFIED**.

<a id="CLI-PQC-06"></a>**CLI-PQC-06** — **Every message goes to every listed message store; a session with a store the crate does
not implement cannot send** (UA-7 P27; the refusal a controller call, the owner may override; SPECIFIED). A send builds one signed
record and one envelope and delivers the same bytes to each store the epoch's `sealedInfo` lists: the Matrix room, and each chain
store by `storeMessage` (an instance the factory lists as class 3, version ≠ 0). When the list names a message store kind this
build does not implement (HCS or Waku in this round), the send is refused before anything is signed (`StoreUnsupported`) and the
session stays readable from the stores it does implement. `postMessage` happens only by the user's choice (D2), above the 1,024-B
bucket only after the user confirms the cost (UA-7 §6.5). The crate creates sessions only with stores it implements, at least one
message store.

<a id="CLI-PQC-07"></a>**CLI-PQC-07** — **Every record read is checked before it is shown; a record that fails is dropped silently,
and nothing sent depends on whether anything opened or checked** (UA-7 P25, P49, P12; [ARCH-POS-13](../decisions.md#ARCH-POS-13) as
amended on 2026-11-13; SPECIFIED). A message, from any store, counts only when its envelope opens, its record decodes within bounds,
its portable signature verifies against the sender's registry record, the sender is a member of a complete epoch as the home
instance orders it, its counter is fresh in its scope `(epochId, sender, device)`, and its `messageId` is new (P19); an epoch or a
session record read from a replica counts only when it equals the home's record and `sigHash` under the same id (P32). A failure is
no error, no receipt, no retry and no write; it is counted on the device only. Every read whose bytes enter a decryption (wraps,
`sealedInfo`, stored and posted messages) is a decryption-feeding read ([CLI-RPC-06](scaas-rpc.md#CLI-RPC-06)), so one unknown node
cannot put a ciphertext of its choice into one. The hybrid KEM's decapsulation and its one-shot AEAD are outside ARCH-POS-13 by its
Change of 2026-11-13; this rule keeps PqChat's own no-reaction rule for them anyway.

<a id="CLI-PQC-08"></a>**CLI-PQC-08** — **A session is pending until its user accepts it: before that, no network call and no write
derived from its wraps or `sealedInfo`** (UA-7 P12, Fable P2-4; SPECIFIED). A pending session may be read from contract state and
its own wrap and `sealedInfo` opened locally to show the creator, the members, the name and the cost of accepting; nothing else: no
store read or joined, no Matrix invite answered, no subscription, no receipt, no `leave`, no rekey. Acceptance is the user's act on
this device; declining writes nothing. A session whose `epochCount` is 0 is never shown (CTR-CHAT-14).

<a id="CLI-PQC-09"></a>**CLI-PQC-09** — **Recovery from contract state alone; the local store is a cache with no secret and no
source of truth** (owner 2026-11-10, [CTR-CHAT-14](../contracts/pqchat.md#CTR-CHAT-14); the store's content a controller call;
SPECIFIED). A new or reinstalled device finds its sessions by paging the factory index for class 3 on each chain it serves and
reading `sessionCount` / `sessionsOf` on each listed instance, de-duplicating entries; follows each session's epochs at its home
(`epochsOf`, `latestEpoch`, `childOf`, after finality); opens its own wraps; and reads the latest messages from the session's chain
stores (`storedRange`) and its Matrix room's history. It reads no event. The local store keeps only public or rebuildable data: the
device id, each own sender chain's next counter, the counters seen per scope, accepted and declined session ids, envelopes not yet
processed, and read positions. Losing it loses nothing but a new device id: a device whose store is lost or restored always makes a
new device id ([CTR-CHAT-12](../contracts/pqchat.md#CTR-CHAT-12)), so a counter is never used twice.

<a id="CLI-PQC-10"></a>**CLI-PQC-10** — **An envelope that arrives while the seed is locked is kept and processed at unlock: never
dropped, never answered** (the SDK review's finding F27, moved with the chat module to `pqchat-core`, 2026-11-17; SPECIFIED). The
Matrix sync loop runs while the seed is locked; `pqchat-core` keeps each `net.scaas.pqchat.v1` event of an accepted session's room
in its store, up to a bound per session, and past the bound keeps the room's read position instead, so the rest is read again from
the room's history; it processes them in order after the next unlock. Nothing the sender can see depends on the lock.

## 5. Vectors and tests

Status: **SPECIFIED**.

<a id="CLI-PQC-11"></a>**CLI-PQC-11** — **The crate reproduces clientkeys' PqChat rows: the bytes that cross the SDK boundary in
`pqchat-core`'s tests, the secrets between in `ua-rs`'s** (owner, byte formats change everywhere at once; SPECIFIED). `pqchat-core`'s
tests read `smartcontracts/vectors/pqchat/` (`records.json`, `topics.json`, `keys.json`, `messages.json`) and check every output
that leaves the SDK: typed digests, ids, scopes, `sigHash`, record blobs, wrap bytes and `wrapHashes`, the P14 refusals, message
ciphertexts, padding, envelopes, payloads, the Matrix event, `sealedInfo` and hints, through the SDK's test-only vectors build (fixed
randomness and key import, refused in any release build). The intermediate secrets of those rows (`ss`, `kek`, `ck_i`, `mk_i`, `n_i`,
`k_env`) are checked in `ua-rs`'s own tests, since `pqchat-core` never sees them. Every unbound field is non-zero in some row
(`via`, `device`, `parents`, `ref`). The call-key rows wait for the call tasks (CLI-PQC-02).

<a id="CLI-PQC-12"></a>**CLI-PQC-12** — **A real-crypto end-to-end run is a gate of the crate** (owner 2026-11-17, "OK, put the e2e
into the pqchat-core plan"; SPECIFIED, PLANNED). On a local chain and a local Matrix homeserver, through `pqchat-core` over the SDK
with no stand-in wrap: a 1:1 session wrapped by the hybrid KEM to registered KEM keys; a message sent by one member and decrypted by
the other, equal byte for byte; an epoch rekey after which a removed member cannot read; a fresh device recovering its sessions and
the latest messages from state alone; a replica read checked against the home; a public topic; and at least one mutant per
decryption or verification check, each killed. The same run on the SCaaS testnet follows at its next reset, on the owner's word.
