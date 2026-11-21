# `pqchat-core`: the PqChat client core

`pqchat-core` is the Rust crate that holds PqChat's client logic: sessions, epochs, wraps, the sender chains' state, the
checks of every record it reads, dedupe and conversation order, recovery from contract state, public topics and the store
adapters. It is an **app core above `scaas-sdk`**: every key operation, signature and chain read goes through the SDK, and its
Matrix store is the app's own Matrix client. The protocol it implements is normative elsewhere: the contract
[pqchat.md](../contracts/pqchat.md) (CTR-CHAT-01 to CTR-CHAT-21) and the UA-7 spec
[`2026-10-25-ua7-pq-e2e-sessions.md`](../superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md) (P1–P49) with the topics spec
[`2026-11-07-pqchat-public-topics.md`](../superpowers/specs/2026-11-07-pqchat-public-topics.md) (P33–P46); this page holds what
the crate adds. Status: **SPECIFIED**, nothing built (spec
[`2026-11-17-pqchat-core.md`](../superpowers/specs/2026-11-17-pqchat-core.md), plan
[`2026-11-17-pqchat-core.md`](../superpowers/plans/2026-11-17-pqchat-core.md), branch `pqchat-core`; Fable's review of
2026-11-17 applied, the spec's §14). Path when built: `clients/pqchat-core`. UNAUDITED.

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
`scaas-sdk` with the SDK's app-core feature and the feature that carries the SDK's `PqChat` record entries (the SDK spec's App
cores section, [`2026-11-17-scaas-sdk.md`](../superpowers/specs/2026-11-17-scaas-sdk.md), as rewritten on branch `scaas-sdk`,
names them `app-core` and `pqchat-records`), and on nothing else that touches a key or a node: no `scaas-ua`, no `scaas-rpc` and no
Matrix SDK of its own (a `cargo tree` test). It reaches the app's live Matrix client (scaas-app's `app-matrix`) through a small
transport trait it defines and the app's Matrix crate implements, so the dependency points from the app to `pqchat-core`, never
into the app's repository. It holds no cryptography: no KEM, KDF, MAC, AEAD, signature, and no writer, hash or decoder of a
signed or encrypted byte format (typed digests, ids, `sigHash`, wrap hashes, the envelope's inner ABI bytes, padding, the canonical
JSON of a content or of `sealedInfo`); those are `ua-rs`'s, reached through the SDK ([CLI-UAL-01](ua-libraries.md#CLI-UAL-01)).
It owns the state machine: what to build, when, from which reads, and what to show. In scaas-app it is the Cargo feature `pqchat`
of the one library `app-core-rust` (implying `scaas`), so the SDK, `app-matrix`, `pqchat-core` and `ua-rs` share one process, one
tokio runtime and one Matrix login ([CLI-SDK-12](scaas-sdk.md#CLI-SDK-12)'s one library per app).

<a id="CLI-PQC-02"></a>**CLI-PQC-02** — **This round's scope: 1:1 sessions first, groups correct; Matrix and chain stores; public
topics; attachments (owner 2026-11-21); no calls, no HCS, Waku or libp2p, no `msig` author** (owner 2026-11-10: the 2-person chat is the main case;
controller call for the cut, owner may override; SPECIFIED). In: sessions, epochs and rekeys, wraps in chunks, `leave`, `remove`,
the home rule and replicas, `msig` expansion of members, the sender chains, the envelope, `postMessage` and `storeMessage`, dedupe
and order, recovery from state, pending until accepted, the content types `text`, `edit`, `redact`, `react`, `receipt` and
`typing` (UA-7 §6.4.1), and public topics. Out, PLANNED in later tasks of the UA-7 plan: calls and their content types
(`callMember`, `callOffer`, `callAnswer`, `callCandidates`, `callKey`), the HCS, Waku and libp2p adapters,
device linking and the epoch-key export (UA-7 P6, §14 O5), and records authored by an `msig` (an `msig` admin's epoch or removal,
an `msig` topic owner), whose co-signers need the full record on other devices (`MsigAuthorPlanned`). A content of a type out of
scope is shown as unsupported and never acted on (UA-7 P49).

## 2. Secrets and signing

Status: **SPECIFIED** (the SDK surface it needs: the SDK spec's App cores section, SPECIFIED on branch `scaas-sdk`).

**Attachments are in this round** (owner 2026-11-21, "Đưa vào" after "images, files and data embedded in a message or a vault item may be encrypted and pushed to Arweave"; O9 (b)): the `file` content (UA-7 `file`, P28) is sent and read; the file is sealed under a fresh file key by an SDK call so no key byte leaves `ua-rs`, its ciphertext stored on Arweave (`url` = `ar://<id>`), `ctSha256` checked before it is opened, its size padded to buckets. SPECIFIED; the Arweave format, reader and upload path follow the research of TODO 8i, and the attachment task (plan T10b) waits for it.

<a id="CLI-PQC-03"></a>**CLI-PQC-03** — **Secrets stay below the SDK: `pqchat-core` holds key handles only, and only decrypted
plaintext leaves** (coordinator condition 1, 2026-11-17; SPECIFIED). The epoch key `K` and the sender chains' positions are `ua-rs`
handles; each wrap's shared secret and KEK, the message keys and nonces, `k_env` and the `sealedInfo` key never leave the `ua-rs`
call that uses them. The KEM encapsulation and decapsulation with the FIPS 203 checks of UA-7 P14, HKDF, the HMAC steps of the
sender chain, padding, canonical JSON and every AES-256-GCM or AES-256-GCM-SIV operation run in `ua-rs`. The only bytes that leave
are plaintexts decrypted for the user: a message content and an epoch's `sealedInfo` (the store list, the room id, the Matrix
user ids, the session's name and topic), as `SecretBytes`, plus one public 8-byte value derived from `K`, the epoch hint.
Every key-derivation label PqChat uses starts with `scaas/pqchat/v1/`, the one label prefix the crate declares to the SDK, so
it cannot use the user's KEM key to open another app's keys; the KEM scheme's own combiner label `scaas.kem.1` is the scheme's
(CTR-UA-32), not an app label. A handle's usage tag never changes the bytes UA-7 pins: separation comes from UA-7's labels and
HMAC inputs, and the SDK enforces a usage on the handle without mixing it into a derivation. Handles die at the seed's lock
([CLI-UAL-09](ua-libraries.md#CLI-UAL-09)); the crate derives them again lazily, when a session is opened or a message arrives,
and persists no secret (CLI-PQC-09). A handle, a key byte or a ciphertext never appears in an error, an event, a log line or
`Debug` output ([CLI-UAL-04](ua-libraries.md#CLI-UAL-04), [CLI-SDK-02](scaas-sdk.md#CLI-SDK-02)).

<a id="CLI-PQC-04"></a>**CLI-PQC-04** — **No blind signing: PqChat records are signed only through the SDK's named, typed PqChat
entries, under `PURPOSE_PQCHAT` in `DS_C`, built from named fields; never a digest, never the generic app signing call**
(coordinator ruling 2026-11-17, correcting condition 2; the owner may override; SPECIFIED). `PqChat` is a SCaaS contract, so the SDK
keeps one signing entry per record struct the contract checks, as it does for every SCaaS contract's operations
([CLI-SDK-08](scaas-sdk.md#CLI-SDK-08)): `PqChatSession`, `PqChatEpoch`, `PqChatLeave`, `PqChatRemove`, `PqChatMessage`, `PqTopic`,
`PqTopicUpdate`, `PqTopicWriter`, `PqTopicEntry`, `PqTopicEdit`, `PqTopicVote` ([CTR-CHAT-03](../contracts/pqchat.md#CTR-CHAT-03)).
`ua-rs` builds the typed data, hashes it and signs `uaMessage(kind, PURPOSE_PQCHAT, typed(record))`. **No byte string the app core
makes is signed:** the session and epoch entries take `sealedInfo`'s named fields and the `K` handle and seal it inside (the review
shows the store list and the Matrix ids as request fields), and compute `wrapHashes` from the wraps the SDK made; the message
entry takes the content and the sender chain's position, and pads, encrypts and signs in one `ua-rs` call, so what is signed is
always a ciphertext `ua-rs` made under this session's key. Every entry except the message entry shows its review before it signs;
the message entry signs each message the user sends without a per-message prompt, because a prompt per chat message is not usable
and its ciphertext can only be the user's content under the session's key. `pqchat-core` passes named fields and receives the
`UASig`, the typed digest and the record's id; it never passes a digest. The SDK's generic app signing call stays closed to every
SCaaS purpose and domain, `PURPOSE_PQCHAT` and `DS_C` included. So the SDK knows PqChat's record formats and none of its logic.
Messages and leaves are signed by a leaf UA, never by an `msig` (UA-7 P13).

## 3. The Matrix store

Status: **SPECIFIED** (scaas-app's contract, its section 11, is the app side; the trait conformance test of CLI-PQC-05 is what makes
the app's side hold).

<a id="CLI-PQC-05"></a>**CLI-PQC-05** — **The Matrix store is the app's live Matrix client: one stack, one client, one login; a
PqChat session is never a Matrix room to the user; a room and a Matrix id count only when bound** (owner 2026-11-17, chat "(b)";
the binding rules a controller call after Fable's review, owner may override; SPECIFIED). `pqchat-core` attaches to the app's
`app-matrix` client after the app's Matrix login and detaches before the app's Matrix logout; it opens no Matrix client, login or
sync loop of its own and links no second Matrix SDK. It sends each envelope as one `net.scaas.pqchat.v1` event `{v, hint, env}`
(UA-7 P15; `hint` and `env` in RFC 4648 §4 base64 with padding, the `matrixEvent` row's form, and only that form read back).
**Binding.** A room counts for a session only if this client created it for that session, or joined it through that session's
acceptance; never a room the account had joined before; one room serves one session, the first accepted keeps it. A Matrix id counts
for a UA only when that UA asserted it: its signed contact card (UA-7 §14 O7), or an envelope signed by that UA and received from
that Matrix sender; invites and removals go only to ids bound so, and only as an epoch's members and `sealedInfo` say. The room id
goes only in `sealedInfo` (never on chain in the clear, D10); no PqChat right comes from a Matrix power level. **In a bound room the
transport sends no Matrix read receipt, read marker, typing notice or presence update, and joins only on `pqchat-core`'s call**
(UA-7 P15: never Matrix's plaintext ephemeral events, D10); the trait states it and the crate's conformance test holds every
implementation to it. **PqChat rooms carry their events without Matrix's own encryption**, so a fresh device with the seed alone
reads the room's history (UA-7 P15 makes Megolm optional; the homeserver then sees the event type and the hint, as UA-7 P20 lists);
the app's rule that ordinary conversations are encrypted from their first event does not apply to them. The app never shows a
PqChat room as an ordinary Matrix room, never upgrades a Matrix room into a PqChat session in place, and never joins a PqChat room
before its session is accepted (CLI-PQC-08). Without an attached client a session that lists Matrix cannot send (`MatrixDetached`)
and its chain stores still serve reads.

## 4. Protocol duties

Status: **SPECIFIED**.

<a id="CLI-PQC-06"></a>**CLI-PQC-06** — **Every message goes to every listed message store its type may use; a session with a store
the crate does not implement cannot send; chain-store gas is spent only under the user's consent; a new store is used only after the
user confirms it** (UA-7 P27, P49; the refusal, the consent and the confirmation controller calls, the owner may override;
SPECIFIED). A send builds one signed record and one envelope and delivers the same bytes to each store the epoch's `sealedInfo` lists
that the content type may use (UA-7 P49): every type in scope to the Matrix room and to each chain store by `storeMessage` (an
instance the factory lists as class 3, version ≠ 0), except `typing`, which goes only to the Matrix room and is not sent when no
Matrix room is listed. When the list names a message store kind this build does not implement (HCS or Waku in this round), the send
is refused before anything is signed (`StoreUnsupported`) and the session stays readable from the stores it does implement. **Chain
stores cost gas on every message:** the user gives a per-session consent to that spend, shown with the figure per message, at
creation or acceptance (`ChainCostUnconfirmed` otherwise); `receipt` is off by default while a chain store is listed.
`postMessage` happens only by the user's choice (D2), above the 1,024-B bucket only after the user confirms the cost (UA-7 §6.5).
**A store list changed by a rekey** (any member may author one, UA-7 P10): a store the user has not seen is neither joined nor read
until the user confirms it, the session stays readable from the stores already confirmed, the change shows its author, and a change
by a non-admin is flagged. The crate creates sessions only with stores it implements, at least one message store.

<a id="CLI-PQC-07"></a>**CLI-PQC-07** — **Every record read is checked before it is shown or used; a record that fails is dropped
silently, and nothing sent depends on whether anything opened or checked** (UA-7 P25, P49, P12; [ARCH-POS-13](../decisions.md#ARCH-POS-13)
as amended on 2026-11-13; SPECIFIED).

- **A message from a store** counts only when its envelope opens, its record decodes within bounds, its portable signature verifies
  against the sender's registry record, the sender is a member of a complete epoch as the home instance orders it, its counter is
  fresh in its scope `(epochId, sender, device)`, its `messageId` is new (P19), and its content unpads and is canonical (re-serialised
  and compared byte for byte, in `ua-rs`).
- **A posted message read from state** (`messageAt`; its signature bytes are not in state, CTR-CHAT-05) counts on the contract's
  check: only from a listed instance, read under CLI-PQC-13's trust, with the sender's membership checked again at the home.
- **Control-plane records** (session, epoch, leave, removal) read at the home are checked as far as state allows: each wrap's
  `hashStruct` equals the signed record's `wrapHashes[i]` **before** it enters a decapsulation; the epoch number is the verified
  parent's plus one; the author's rights hold against the parent; members and admins are strictly sorted and the creator is in
  both. Their signature bytes are not in state either, so their authorship rests on the contract's check and CLI-PQC-13's trusted
  reads (the spec's open point O11). A replica's record counts only when it equals the home's record and `sigHash` under the same id
  (P32).
- **A failure** is no error, no receipt, no retry and no write; it is counted on the device only, per reason (`envelope`, `decode`,
  `signature`, `member`, `counter`, `duplicate`, `replica`, `unlisted`, `wrap-hash`, `content`, `too-far`).
- **No automatic reaction** to a result that depends on an opening or an epoch: an own wrap of the winning epoch that does not open
  is shown, never answered by a rekey, a leave or a message; a member's higher KEM version raises an event and the rekey is a write
  the user confirms; between the first sight of a complete child and its finality the client sends under neither epoch and holds the
  sends, then sends under the child once it is final.

Every read whose bytes enter a decryption is a trusted read (CLI-PQC-13). The hybrid KEM's decapsulation and its one-shot AEAD are
outside ARCH-POS-13 by its Change of 2026-11-13; this rule keeps PqChat's own no-reaction rule for them anyway.

<a id="CLI-PQC-08"></a>**CLI-PQC-08** — **A session is pending until its user accepts it: before that, no network call and no write
derived from its wraps or `sealedInfo`** (UA-7 P12, Fable P2-4; SPECIFIED). A pending session may be read from contract state and,
when the user looks at it, its own wrap and `sealedInfo` opened locally to show the creator, the members, the name and the cost of
accepting; nothing else: no store read or joined, no Matrix invite answered, no subscription, no receipt, no `leave`, no rekey. The
transport holds an invite to a room a pending session's `sealedInfo` names, unanswered. Acceptance is the user's act on this device;
declining writes nothing. A session found in any instance is shown only when its home instance is listed and reachable, holds the
equal record and has `epochCount > 0` (CTR-CHAT-14).

<a id="CLI-PQC-09"></a>**CLI-PQC-09** — **Recovery from contract state alone; the local store is a cache with no secret and no
source of truth, encrypted at rest by the app, and bound to the device** (owner 2026-11-10,
[CTR-CHAT-14](../contracts/pqchat.md#CTR-CHAT-14); the store's content a controller call; SPECIFIED). A new or reinstalled device
finds its sessions by paging the factory index for class 3 on each chain it serves and reading `sessionCount` / `sessionsOf` on each
listed instance (batched), de-duplicating entries; follows each session's epochs at its home (`epochsOf`, `latestEpoch`, `childOf`,
after finality); opens its own wraps; and, after acceptance, reads the latest messages from the session's chain stores
(`storedRange`) and its Matrix room's history. It reads no event. The local store keeps only public or rebuildable data, in items
keyed apart, each with its own revision: the device id and its anchor check, each own sender chain's next counter, the counters seen
per scope, the highest KEM version seen per UA, accepted and declined session ids, envelopes not yet processed, and read positions.
It still links sessions to rooms and hints, which the chain does not show, so the app's storage keeps it encrypted at rest under the
app's own store key (the one its Matrix store uses) and excludes it from backups. **Device binding:** the app keeps a random anchor
for the store in the platform's non-backed-up secret storage; at start a missing or different anchor (a restore, a copied data
directory, a cloned phone) makes a new device id, and so does a lost store
([CTR-CHAT-12](../contracts/pqchat.md#CTR-CHAT-12)); a counter is never used twice.

<a id="CLI-PQC-10"></a>**CLI-PQC-10** — **An envelope that arrives while the seed is locked is kept and processed at unlock: never
dropped, never answered** (the SDK review's finding F27, moved with the chat module to `pqchat-core`, 2026-11-17; SPECIFIED). The
Matrix sync loop runs while the seed is locked; `pqchat-core` keeps every `net.scaas.pqchat.v1` event it is handed in its store, up to
a bound per room, and past the bound keeps the room's read position instead, so the rest is read again from the room's history; it
processes them in order after the next unlock, dropping then those of rooms no accepted session binds. Nothing the sender can see
depends on the lock.

<a id="CLI-PQC-13"></a>**CLI-PQC-13** — **Every read that chooses an encryption key, a recipient or an epoch, or feeds a decryption,
is a trusted read** (coordinator call K1 after Fable's review, 2026-11-17; the owner may override; SPECIFIED). The reads of
`kemKeyOf`, `kemKeyAt`, `checkedOf`, `memberAccepted`, `latestEpoch`, `epochsOf`, `childOf`, `removedIn`, the factory listing, the
signer's registry record for a signature check, and the reads of wraps, `sealedInfo`, `messageAt` and `storedRange` are all made
under `scaas-rpc`'s decryption-feeding mark, `Purpose::FeedsDecryption` ([CLI-RPC-06](scaas-rpc.md#CLI-RPC-06)): never a discovered
endpoint alone; under strict majority the agreeing group holds a named or default endpoint. The recipient key inside the SDK's KEM
wrap is read the same way. So one endpoint the app did not name cannot choose a key the client encrypts to, an epoch it sends under,
or a ciphertext it decrypts. The highest KEM version seen per UA is kept in the store (CLI-PQC-09), so a lower version served later
is refused.

<a id="CLI-PQC-14"></a>**CLI-PQC-14** — **No skipped message key is kept; a verified message is read at any counter up to 2^20
steps past the nearest held chain position** (coordinator call K2 after Fable's review, 2026-11-17, a client rule within UA-7 §6.3's
bound; the owner may override; SPECIFIED). UA-7 §6.3 bounds the skipped message keys a receiver keeps at 2,000 per chain; this
client keeps none: every message key is derived again from `K` when its message arrives, through one `ua-rs` call that advances a
chain position by `n` steps. A chain walk runs only for a record that has passed the signature and membership checks of CLI-PQC-07,
so its work is charged to a signed member record; it advances at most 2^20 steps from the nearest position held for that chain (a
message beyond is shown as unreadable on the device, reason `too-far`). Positions are a cache: at most a bounded number of chains per
session are held, the least recently used dropped, and every position is derived again after a lock. So a fresh device reads the
latest messages of a long epoch without the earlier ones, and no member can fill the shared `ua-rs` arena by opening chains under new
device ids. This needs no change to UA-7.

## 5. Vectors and tests

Status: **SPECIFIED**.

<a id="CLI-PQC-11"></a>**CLI-PQC-11** — **The crate reproduces clientkeys' PqChat rows: the bytes that cross the SDK boundary in
`pqchat-core`'s tests, the secrets between in `ua-rs`'s** (owner, byte formats change everywhere at once; SPECIFIED). `pqchat-core`'s
tests read `smartcontracts/vectors/pqchat/` (`records.json`, `topics.json`, `keys.json`, `messages.json`) and check every output
that leaves the SDK: typed digests, ids, scopes, `sigHash`, record blobs, wrap bytes and `wrapHashes`, the P14 refusals, message
ciphertexts, envelopes, payloads, the Matrix event, `sealedInfo` and hints, through the SDK's test-only vectors build (fixed
randomness and key import). That build is refused in any release build by the SDK's load check, and the app library's symbols and
features are tested to hold none of it. The intermediate secrets of those rows (`ss`, `kek`, `ck_i`, `mk_i`, `n_i`, `k_env`) and the
padding and canonical JSON rows are checked in `ua-rs`'s own tests, since `pqchat-core` never sees them. clientkeys writes new rows
first where a rule has none: keys whose order differs in UTF-16 and UTF-8, a control character, an integer at `2^53 − 1`, `unpad`
refusals, and a chain read far past its first counter. Every unbound field is non-zero in some row (`via`, `device`, `parents`,
`ref`). The call-key rows wait for the call tasks (CLI-PQC-02).

<a id="CLI-PQC-12"></a>**CLI-PQC-12** — **A real-crypto end-to-end run is a gate of the crate** (owner 2026-11-17, "OK, put the e2e
into the pqchat-core plan"; SPECIFIED, PLANNED). On a local chain that enforces EIP-7825's per-transaction cap and a local Matrix
homeserver, through `pqchat-core` over the SDK with no stand-in wrap: a 1:1 session wrapped by the hybrid KEM to registered KEM keys;
a message sent by one member and decrypted by the other, equal byte for byte; an epoch rekey after which a removed member cannot
read; a fresh device recovering its sessions and the latest messages from state alone, after an explicit acceptance; a replica read
checked against the home; a public topic; and at least one mutant per decryption or verification check, each guarding a check its
own fixture reaches and killed by that check's failure reason. Writes an honest client refuses go through a named hostile harness on
the SDK's vectors build, never through `pqchat-core`. The same run on the SCaaS testnet follows at its next reset, on the owner's word.
