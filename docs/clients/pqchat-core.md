# `pqchat-core`: the PqChat client core

`pqchat-core` is the Rust crate that holds PqChat's client logic: sessions, epochs, wraps, the sender chains' state, the
checks of every record it reads, dedupe and conversation order, recovery from contract state, public topics and the store
adapters. It is an **app core above `scaas-sdk`**: every key operation, signature and chain read goes through the SDK, and its
Matrix store is the app's own Matrix client. The protocol it implements is normative elsewhere: the contract
[pqchat.md](../contracts/pqchat.md) (CTR-CHAT-01 to CTR-CHAT-21) and the UA-7 spec
[`2026-10-25-ua7-pq-e2e-sessions.md`](../superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md) (P1–P49) with the topics spec
[`2026-11-07-pqchat-public-topics.md`](../superpowers/specs/2026-11-07-pqchat-public-topics.md) (P33–P46); this page holds what
the crate adds. Status: **BUILT** in `clients/pqchat-core` (plan T0 to T12, T10b and the review rounds; gate rows
`clients/pqchat-core/runs/2026-11-17-pqchat-core-summary.txt`), except the tree mode
([CLI-PQC-17](#CLI-PQC-17)), **SPECIFIED**, and the sealed local history ([CLI-PQC-09](#CLI-PQC-09)), **PLANNED** (spec
[`2026-11-17-pqchat-core.md`](../superpowers/specs/2026-11-17-pqchat-core.md), plan
[`2026-11-17-pqchat-core.md`](../superpowers/plans/2026-11-17-pqchat-core.md); Fable's review of 2026-11-17 applied, the spec's
§14). UNAUDITED.

**Contents**

1. [Place and scope](#1-place-and-scope)
2. [Secrets and signing](#2-secrets-and-signing)
3. [The Matrix store](#3-the-matrix-store)
4. [Protocol duties](#4-protocol-duties)
5. [Vectors and tests](#5-vectors-and-tests)

## 1. Place and scope

Status: **BUILT** (`tests/deps.rs`: the `cargo tree` check; the content types in `src/content.rs`, out-of-scope types shown
unsupported; `MsigAuthorPlanned` in `src/session.rs`, `src/topics.rs`; tests `tests/session.rs`, `tests/topics.rs`,
`tests/message.rs`, `tests/stores.rs`).

<a id="CLI-PQC-01"></a>**CLI-PQC-01** — **`pqchat-core` is an app core above `scaas-sdk`: it depends on the SDK and on the app's
Matrix client, and the SDK names no chat** (owner 2026-11-17, "OK, reverse pqchat-core too"; BUILT). It depends on
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
controller call for the cut, owner may override; BUILT). In: sessions, epochs and rekeys, wraps in chunks, `leave`, `remove`,
the home rule and replicas, `msig` expansion of members, the sender chains, the envelope, `postMessage` and `storeMessage`, dedupe
and order, recovery from state, pending until accepted, the content types `text`, `edit`, `redact`, `react`, `receipt`,
`typing` and `file` (UA-7 §6.4.1), and public topics. Out, PLANNED in later tasks of the UA-7 plan: calls and their content types
(`callMember`, `callOffer`, `callAnswer`, `callCandidates`, `callKey`), the HCS, Waku and libp2p adapters,
device linking and the epoch-key export (UA-7 P6, §14 O5), and records authored by an `msig` (an `msig` admin's epoch or removal,
an `msig` topic owner), whose co-signers need the full record on other devices (`MsigAuthorPlanned`). A content of a type out of
scope is shown as unsupported and never acted on (UA-7 P49).

## 2. Secrets and signing

Status: **BUILT** (the SDK's `app_core` surface and its `pqchat_*` entries; the crate's handles in `src/lib.rs`,
`src/message.rs`; tests `tests/message.rs`, `tests/vectors.rs`, `tests/e2e.rs`, the bindings check `runs/bind_surface.py`).

**Attachments are in this round** (owner 2026-11-21, "put it in" after "images, files and data embedded in a message or a vault item may be encrypted and pushed to Arweave"; O9 (b); owner 2026-11-22: two new calls and an app id for PqChat): the `file` content (UA-7 §6.4.1 with its 2026-11-21 Change, P28) is sent and read; the file is sealed under a fresh file key by the SDK's `seal_for_arweave` under PqChat's app id (`keccak256("scaas.pqchat.v1")`), framed to its power-of-two bucket inside the AEAD, its key entered into the content inside `ua-rs` by `pqchat_seal_file_message`, so no key byte reaches the crate; the signed item is returned for the app to post to Arweave (`url` = `ar://<id>`) and keep, the crate posts nothing; a reader opens the object by `pqchat_open_file`, which checks its length and `ctSha256` before any decryption and reads the key from the opened content inside `ua-rs`; a failed file is shown on the device only. BUILT (plan T10b, `src/file.rs`: `send_file`, `file_info`, `open_file`; tests `tests/stores.rs`; the form and the controller calls in CLI-PQC-02's Change of 2026-11-23 in [decisions](../decisions.md)), UNAUDITED; a `file` without an `ar://` url is not built or read in this round.

<a id="CLI-PQC-03"></a>**CLI-PQC-03** — **Secrets stay below the SDK: `pqchat-core` holds key handles only, and only decrypted
plaintext leaves** (coordinator condition 1, 2026-11-17; BUILT). The epoch key `K` and the sender chains' positions are `ua-rs`
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
(coordinator ruling 2026-11-17, correcting condition 2; the owner may override; BUILT). `PqChat` is a SCaaS contract, so the SDK
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
SCaaS purpose and domain, `PURPOSE_PQCHAT`, `DS_C` and PqChat's app id and its `appPurpose` included (owner 2026-11-23;
BUILT, UNAUDITED), while PqChat's own paths (the record entries, the card, the file seal) sign. So the SDK knows PqChat's record formats and none of its logic.
Messages and leaves are signed by a leaf UA, never by an `msig` (UA-7 P13).

## 3. The Matrix store

Status: **BUILT** on the crate's side (`src/matrix.rs`, the conformance test `tests/matrix_conformance.rs`, the fake
`tests/matrix_fake.rs`, the e2e over a local Synapse); scaas-app's contract, its section 11, is the app side, in its own
repository, held to the trait by the same conformance test.

<a id="CLI-PQC-05"></a>**CLI-PQC-05** — **The Matrix store is the app's live Matrix client: one stack, one client, one login; a
PqChat session is never a Matrix room to the user; a room and a Matrix id count only when bound** (owner 2026-11-17, chat "(b)";
the binding rules a controller call after Fable's review, owner may override; BUILT). `pqchat-core` attaches to the app's
`app-matrix` client after the app's Matrix login and detaches before the app's Matrix logout; it opens no Matrix client, login or
sync loop of its own and links no second Matrix SDK. It sends each envelope as one `net.scaas.pqchat.v1` event `{v, hint, env}`
(UA-7 P15; `hint` and `env` in RFC 4648 §4 base64 with padding, the `matrixEvent` row's form, and only that form read back).
**Binding.** A room counts for a session only if this client created it for that session, or joined it through that session's
acceptance; a room the account had joined before only once its members check against the epoch (every Matrix id it holds, joined
or invited, is the account's own or one the epoch's `sealedInfo` maps to a member of that epoch: a fresh device's state-only
recovery, controller call 2026-11-22), else not used; one room serves one session, the first accepted keeps it. A Matrix id counts
for a UA only when that UA asserted it: its signed contact card (UA-7 §14 O7; `add_card`, checked through the SDK's
`verify_pqchat_card`), or an envelope signed by that UA and received from that Matrix sender; invites and removals go only to ids bound so, and only as an epoch's members and `sealedInfo` say. The room id
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

Status: **BUILT** for CLI-PQC-06 to CLI-PQC-10 and CLI-PQC-13 to CLI-PQC-16 (`src/stores.rs`, `consent.rs`, `check.rs`,
`drops.rs`, `session.rs`, `recovery.rs`, `reads.rs`, `message.rs`, `signed.rs`; tests `tests/stores.rs`, `check.rs`, `session.rs`,
`recovery.rs`, `reads.rs`, `message.rs`, `signed.rs`, `chain_*.rs`; the reads check `runs/check_reads.py`),
but the sealed local history of CLI-PQC-09, **PLANNED**; the tree mode, CLI-PQC-17, **SPECIFIED**.

<a id="CLI-PQC-06"></a>**CLI-PQC-06** — **Every message goes to every listed message store its type may use; a session with a store
the crate does not implement cannot send; chain-store gas is spent only under the user's consent; a new store is used only after the
user confirms it** (UA-7 P27, P49; the refusal, the consent and the confirmation controller calls, the owner may override;
BUILT). A send builds one signed record and one envelope and delivers the same bytes to each store the epoch's `sealedInfo` lists
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
as amended on 2026-11-13; BUILT).

- **A message from a store** counts only when its envelope opens, its record decodes within bounds, its portable signature verifies
  against the sender's registry record, the sender is a member of a complete epoch as the home instance orders it, its counter is
  fresh in its scope `(epochId, sender, device)`, its `messageId` is new (P19), and its content unpads and is canonical (re-serialised
  and compared byte for byte, in `ua-rs`).
- **A posted message read from state** (`messageAt`) counts only from a listed instance, read under CLI-PQC-13's trust, with the
  sender's membership checked again at the home; on an `sstore2` instance its kept signature must verify first
  ([CLI-PQC-15](#CLI-PQC-15)); on a `none` one it counts on the contract's check.
- **Control-plane records** (session, epoch, leave, removal) read at the home are checked: each wrap's `hashStruct` equals the
  signed record's `wrapHashes[i]` **before** it enters a decapsulation; the epoch number is the verified parent's plus one; the
  author's rights hold against the parent; members and admins are strictly sorted and the creator is in both. On an `sstore2` home
  each record's kept signature verifies over its rebuilt typed digest, `sealedInfo` included, before any of this
  ([CLI-PQC-15](#CLI-PQC-15)); on a `none` home their authorship rests on the contract's check and CLI-PQC-13's trusted reads. A
  replica's record counts only when it equals the home's record and `sigHash` under the same id (P32).
- **A failure** is no error, no receipt, no retry and no write; it is counted on the device only, per reason (`envelope`, `decode`,
  `signature`, `member`, `counter`, `duplicate`, `replica`, `unlisted`, `wrap-hash`, `content`, `too-far`, and `control` for a
  control-plane record that breaks the epoch rule, the rights or the shapes, which only a forged answer shows; an own wrap that
  passed its hash check and does not open counts as `envelope`; controller call 2026-11-22; `signature` also for a control-plane
  record or posted message whose kept signature fails, and `unsigned` for a record of a `none` home under
  `require_signed_records`, CLI-PQC-15).
- **No automatic reaction** to a result that depends on an opening or an epoch: an own wrap of the winning epoch that does not open
  is shown, never answered by a rekey, a leave or a message; a member's higher KEM version raises an event and the rekey is a write
  the user confirms; between the first sight of a complete child and its finality the client sends under neither epoch and holds the
  sends, then sends under the child once it is final.

Every read whose bytes enter a decryption is a trusted read (CLI-PQC-13). The hybrid KEM's decapsulation and its one-shot AEAD are
outside ARCH-POS-13 by its Change of 2026-11-13; this rule keeps PqChat's own no-reaction rule for them anyway.

<a id="CLI-PQC-08"></a>**CLI-PQC-08** — **A session is pending until its user accepts it: before that, no network call and no write
derived from its wraps or `sealedInfo`** (UA-7 P12, Fable P2-4; BUILT). A pending session may be read from contract state and,
when the user looks at it, its own wrap and `sealedInfo` opened locally to show the creator, the members, the name and the cost of
accepting; nothing else: no store read or joined, no Matrix invite answered, no subscription, no receipt, no `leave`, no rekey. The
transport holds an invite to a room a pending session's `sealedInfo` names, unanswered. Acceptance is the user's act on this device;
declining writes nothing. A session found in any instance is shown only when its home instance is listed and reachable, holds the
equal record and has `epochCount > 0` (CTR-CHAT-14).

<a id="CLI-PQC-09"></a>**CLI-PQC-09** — **Recovery from contract state alone; the local store is a cache with no secret and no
source of truth, encrypted at rest by the app, and bound to the device** (owner 2026-11-10,
[CTR-CHAT-14](../contracts/pqchat.md#CTR-CHAT-14); the store's content a controller call; BUILT). A new or reinstalled device
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
([CTR-CHAT-12](../contracts/pqchat.md#CTR-CHAT-12)); a counter is never used twice. **No plaintext** is stored until the
sealed local history lands (spec §13 O7 (b), owner 2026-11-23: under an app-scoped storage key the SDK derives, a handle never
exported; built with scaas-app after the pre-freeze tag; PLANNED).

<a id="CLI-PQC-10"></a>**CLI-PQC-10** — **An envelope that arrives while the seed is locked is kept and processed at unlock: never
dropped, never answered** (the SDK review's finding F27, moved with the chat module to `pqchat-core`, 2026-11-17; BUILT). The
Matrix sync loop runs while the seed is locked; `pqchat-core` keeps every `net.scaas.pqchat.v1` event it is handed in its store, up to
a bound per room, and past the bound keeps the room's read position instead, so the rest is read again from the room's history; it
processes them in order after the next unlock, dropping then those of rooms no accepted session binds. Nothing the sender can see
depends on the lock.

<a id="CLI-PQC-13"></a>**CLI-PQC-13** — **Every read that chooses an encryption key, a recipient or an epoch, or feeds a decryption,
is a trusted read** (coordinator call K1 after Fable's review, 2026-11-17; the owner may override; BUILT). The reads of
`kemKeyOf`, `kemKeyAt`, `checkedOf`, `memberAccepted`, `latestEpoch`, `epochsOf`, `childOf`, `removedIn`, the factory listing, the
signer's registry record for a signature check, an instance's `sigStore`, the kept signatures and leave records (`sessionSig`,
`epochSig`, `leaveCount`, `leaveAt`, `leaveSig`, `removalSig`, `messageSig`; CLI-PQC-15), and the reads of wraps, `sealedInfo`,
`messageAt` and `storedRange` are all made
under `scaas-rpc`'s decryption-feeding mark, `Purpose::FeedsDecryption` ([CLI-RPC-06](scaas-rpc.md#CLI-RPC-06)): never a discovered
endpoint alone; under strict majority the agreeing group holds a named or default endpoint. The recipient key inside the SDK's KEM
wrap is read the same way. So one endpoint the app did not name cannot choose a key the client encrypts to, an epoch it sends under,
or a ciphertext it decrypts. The highest KEM version seen per UA is kept in the store (CLI-PQC-09), so a lower version served later
is refused.

<a id="CLI-PQC-14"></a>**CLI-PQC-14** — **No skipped message key is kept; a verified message is read at any counter up to 2^20
steps past the nearest held chain position** (coordinator call K2 after Fable's review, 2026-11-17, a client rule within UA-7 §6.3's
bound; the owner may override; BUILT). UA-7 §6.3 bounds the skipped message keys a receiver keeps at 2,000 per chain; this
client keeps none: every message key is derived again from `K` when its message arrives, through one `ua-rs` call that advances a
chain position by `n` steps. A chain walk runs only for a record that has passed the signature and membership checks of CLI-PQC-07,
so its work is charged to a signed member record; it advances at most 2^20 steps from the nearest position held for that chain (a
message beyond is shown as unreadable on the device, reason `too-far`). Positions are a cache: at most a bounded number of chains per
session are held, the least recently used dropped, and every position is derived again after a lock. So a fresh device reads the
latest messages of a long epoch without the earlier ones, and no member can fill the shared `ua-rs` arena by opening chains under new
device ids. This needs no change to UA-7.

<a id="CLI-PQC-15"></a>**CLI-PQC-15** — **On an `sstore2` home every control-plane record the crate uses counts only with its
author's kept signature; the option `require_signed_records` also refuses a `none` home** (owner 2026-11-23, the spec's O11 settled
by [CTR-CHAT-23](../contracts/pqchat.md#CTR-CHAT-23); the default off a controller call, the owner may override; BUILT on branch
`pqchat-sigs`, `src/signed.rs`, `tests/signed.rs`, UNAUDITED).

- **The setting.** The crate reads an instance's `sigStore()` under CLI-PQC-13's trust and pins its first answer per instance in
  its store; a later different answer, or a value neither 0 nor 2, is a forged one (`control`). So an endpoint cannot report
  `none` for an `sstore2` instance this device has seen.
- **On an `sstore2` instance** the session and epoch records (`sessionSig`, `epochSig`), the parent's leaves and removals (from
  the kept `leaveAt` / `removalAt` records, each with its signer's signature, kept under the parent and naming it or,
  at home since the change of 2026-11-24 to [CTR-CHAT-20](../contracts/pqchat.md#CTR-CHAT-20) and
  [CTR-CHAT-10](../contracts/pqchat.md#CTR-CHAT-10) (SPECIFIED), an ancestor of it on the home's chain at most
  `EXIT_LAG_MAX` = 16 epochs above; each is judged order-free among the exits kept under the parent, exactly as the
  contract could have accepted it there (a remover in the parent's admins, whose own leave or removal
  kept under the same parent does not void it, in either order; the UAs it names members or admins of the parent; a
  leaver a member of the parent), so no chain the home took
  is refused; the `leftIn` and `removedIn`
  flags are not read there) and a posted message (`messageSig`) each count only when their signer's `UASig` verifies over the
  typed digest the SDK rebuilds from the record's fields (V1, the signer's registry record a trusted read along F2's registry
  line: `holderOf` on the bound registry names the generation whose record is read, every call of it by one endpoint at one
  block; the SDK's `tests/pqchat_keys.rs` `v1_follows_the_registry_line`, TODO 8b-8 (4)), `sealedInfo` included;
  else `signature`. A single-key author's UA id is the hash of its key, so a forged record fails even when the same endpoint lies
  about the registry; an `msig` author's structure is a registry read, for which the agreed reads of CLI-PQC-16 are the defence.
- **`require_signed_records`** (`PqChatConfig`, default `false`): `true` also refuses a `none` home: its records are dropped
  `unsigned` and a session created there refused `HomeUnsigned`. `false` reads a `none` home as before, on the contract's check;
  an `sstore2` home is verified either way, with no switch that turns it off. **Why off by default** (controller call): new homes
  are `sstore2` by default, so the check runs wherever a signature is kept; a `none` home is its creator's explicit choice, and
  refusing it by default would leave its sessions unreadable to every default client, while the pin above already stops the
  downgrade the owner named.

<a id="CLI-PQC-16"></a>**CLI-PQC-16** — **Strict majority for the control-plane reads is an explicit option, never forced** (owner
2026-11-23, option (d); BUILT on branch `pqchat-sigs`, UNAUDITED). `PqChatConfig.agreed_reads` (default `false`): every trusted
`IPqChat` read (the control plane at an instance) goes through the SDK's `read_app_agreed`, the agreed read of
[CLI-RPC-05](scaas-rpc.md#CLI-RPC-05) and [CLI-RPC-06](scaas-rpc.md#CLI-RPC-06) whatever the chain's list policy (scaas-rpc
`read_at_block_agreed`); a list of one endpoint or without a pinned `chain_uid` is the SDK's `Argument`. The other reads keep the
list's policy.

<a id="CLI-PQC-17"></a>**CLI-PQC-17** — **In a tree session (`groupMode = 1`) the crate obtains each epoch key by replaying the
commits since its Welcome; every tree secret stays in `ua-rs`; a committer's path secrets derive from its KEM seed; a device
that cannot follow an epoch shows it and sends nothing by itself** (owner 2026-11-23: our own TreeKEM in `ua-rs` after RFC
9420's algorithms, no MLS library; seed-derived committer secrets, no self-wrap; spec
[`2026-11-23-pqchat-treekem.md`](../superpowers/specs/2026-11-23-pqchat-treekem.md), revision 3, §5, §8, §10, §11, §15; the contract
side is [CTR-CHAT-26](../contracts/pqchat.md#CTR-CHAT-26)). Status: **SPECIFIED**, nothing built, UNAUDITED. The bullets below
other than the owner's rulings are controller calls, the owner may override. **Owner rulings of 2026-11-23 on the second
review:** the joiner without RFC 9420's `init` chain and its cost; the compromise warning; no automatic receipts in a tree
session; freshness before a changed session info; no return, the way back being a new UA. **After the third review:** the
warning before an Add of a key registered to another UA. **Codex's third review (controller calls):** the two ranges of
replay, the comparison at the pin, the warning's roster and empty path, the prepared creation, the lookup behind the Add
warning, an admin's new info after a gap, the order of a commit's pieces, the closed session.

- **One branch.** Both modes end in an epoch key `K` per epoch id; sender chains, `sealedInfo`, messages, stores and consent sit
  above `K` and do not change. Until the mode is built the crate refuses `groupMode ≠ 0` by name. A tree session's state,
  consent and pins are keyed by `treeId = hashStruct(PqChatSession)`, which binds the home and the genesis record.
- **Secrets.** KEM, AEAD, HKDF and every path, node and epoch secret are `ua-rs`'s, behind handles
  ([CLI-UAL-01](ua-libraries.md#CLI-UAL-01)); the crate holds the public tree, the records and handles, no key byte.
- **The committer.** `ps[0]` is an HKDF of the KEM seed of the author's leaf key over `treeId`, the parent epoch and its tree
  hash, the membership change and the target list, so a device restored from the seed opens its own commits and a commit
  rebuilt on another tree, session or home never repeats a secret. The nonce is random, stored before a piece leaves the device
  and never reused. A random device key recovers its commits on that device only.
- **Signing.** One typed `ua-rs` operation builds the path, the pieces and `PqChatCommit` inside the signing boundary, shows the
  review and signs ([CLI-PQC-04](#CLI-PQC-04)); no digest from outside is signed.
- **Before it encrypts** the crate refuses a head below its checkpoint (which holds the hash of the verified head record, not
  only its id; a mismatch at a pinned number is settled by a strict-majority read over at least 3 nodes, else the session
  shows "conflicting head" and nothing is built on it; **before it extends its state above a pin it compares the record
  that won at the pinned number with the pin**, because a child binds its parent's id and tree hash and not its
  `sealedInfo` or `admins`, and on a mismatch the epoch is replayed from the majority's record with its metadata), reads every page of a tree snapshot at one block, at an epoch-0 head rebuilds the tree from the signed member list and builds on it, **builds only on the tree it reached by
  walking every record forward from that cold tree or from its own verified tree at its pin** (each record's signature for
  the signer's kind, its parent's id and the walk's tree hash, the author's live leaf, not gone, and its right on that tree,
  the tree after it against its signed `treeHash`, after the bounds of the tree checked before anything is allocated, and
  every other acceptance check of the contract whose inputs are the record and the walk's state; a record that fails is a
  lying read, never followed, pinned or built on; the served snapshot is only compared; the pin keeps the verified tree
  **and the exits verified up to it**, so a restart cannot follow a removed UA's next epoch; a device with no verified tree
  writes its first pin only from a strict-majority read over at least 3 named endpoints, else it shows the head as
  "unconfirmed"; Change 2026-11-24, the code review's E-1, C-1, B-1, F-1, C-3, and the spec check), compares each target key with its hash in the tree, and has `ua-rs` verify against the
  registry record every key no signed tree hash covers yet (an added key, a member at creation), in every tree session; reads
  follow [CLI-PQC-13](#CLI-PQC-13). What a candidate seals counts as disclosed to every key of the tree it was built on.
- **Session info.** A commit seals the full info only when the device holds the one in force at the parent; otherwise the
  marker "unchanged" (empty content). A device that did not follow an epoch has no info in force from that epoch on: it
  seals the marker until a commit it follows carries a full info, taken under the joiner rule and never sealed while
  flagged. A changed info is taken only from an admin's commit. **After a gap an admin may establish the info anew:**
  a full info the user enters or confirms in the signing review, treated as a changed info; the value cached before the
  gap is at most a draft marked "not in force" and is never sealed automatically. **Freshness (owner):** a commit that
  seals a changed info (room and store lists) is built only after the head and the roster were read at a final block under
  the strict majority over at least 3 named endpoints ([ARCH-POS-15](../decisions.md#ARCH-POS-15)); with fewer the crate
  refuses the change by name.
- **No return (owner).** The crate leaves and removes by `PqChatTreeLeave` and `PqChatTreeRemove`, whose review says the UA
  cannot come back. A user comes back as a **new UA** with a fresh KEM key, added by an admin: the crate shows it as a new
  member, never links it to the old UA on its own, and gives it no history before its join. No "rejoin" call exists. The
  removal of a UA's only key is worded as an exclusion for good; replacing it is one commit that removes and adds.
  **Before an Add (owner):** the admin's client checks whether the added key's `kemHash` is registered to another UA in
  the registry and warns "this key is also held by UA …". It is a client warning only: the contract's two-level key sets
  ([CTR-CHAT-26](../contracts/pqchat.md#CTR-CHAT-26)) do not depend on it, and a lookup that finds nothing proves nothing.
  **The lookup.** The registry has no index by `kemHash` and its versions are sparse and stored in any order
  ([accounts.md](../contracts/accounts.md)). Candidates `(ua, version)` are: every UA of the session (live, admin, and
  the gone ones replay showed) and of the device's contacts, at each version from 0 to that UA's highest when the highest
  is at most `KEM_SCAN_MAX` = 64, else at version 0, the highest and the versions the session's leaves name; and any
  pair an index offers, as a hint. A positive is verified: `kemKeyAt(ua, version)` hashes to the `kemHash`; a hint that
  does not verify is dropped. The result is "also held by UA … (version …)" or "not found among the N UAs checked" with
  what was not covered, never "held by nobody".
- **Creation.** The wraps of epoch 0 cannot be built a second time (the record signs their hashes; `joiner_0` and every
  encapsulation are random). The crate keeps the signed record and every wrap from before the first send until epoch 0
  completes and finishes from that store after a restart. A device restored without them reads the session as
  incomplete, shows "creation incomplete, cannot be finished", sends nothing and offers a new session.
- **The order of a commit's pieces.** The record; then the list and the node keys, each final before anything else
  leaves the device; then ciphertexts and Welcome wraps; one ciphertext is held back and sent alone last, because the
  last piece pays the completion and an indivisible piece may not fit with it. The quote names the completion with the
  held ciphertext and the dearest piece that would be last if the order were broken; a commit whose order was broken
  and cannot complete is reported by name and rebuilt with a new nonce.
- **A closed session.** A session whose every live leaf belongs to a UA that left or was removed has no author and takes
  no member: it is shown as closed, and the review of the leave that closes it says so.
- **Replay** needs state only ([CLI-PQC-09](#CLI-PQC-09)). Its reads are fixed by public data, the same whether a ciphertext
  opens or not, and each fetched record, list, ciphertext, wrap and key is compared with its signed hash before use: the
  Welcome wrap and the joiner's path ciphertext, then one path ciphertext per later commit (the target that covers the device's
  leaf), each derived node key compared with the signed hash, `sealedInfo` opened as the confirmation. **Two ranges:** the
  commit records are read from the session record (or from the device's own verified tree at its pin) to the head, a
  commit joiner's included, also after the key was taken out; ciphertexts are opened only while the key was in the tree, from the join to the epoch before the commit that
  removed it, and nothing at that commit. A genesis key joins by the signed `members` and its wrap. The roster of each epoch
  is the forward walk's tree, never a snapshot with later commits undone; a non-admin's drop of another UA, and its drop of
  a gone admin from `admins` (plain, as the contract judges it), needs that UA's signed leave or removal, kept under the
  epoch `h` it was applied at and read for every epoch from the fixed lists (`leaveCount` / `removalCount` and their
  records); it counts when the contract could have accepted it at `h`, judged order-free among the exits kept under `h`
  (the remover in `h`'s `admins` and not gone before `h`, a removal of its own signer or of a keyless admin included; the
  epoch it names at most 16 below `h`), so no chain the home accepted is a lying read; every tree record's signature is verified for the signer's kind, an `msig` or WebAuthn admin's
  included (Change 2026-11-24, E-3, F-2, F-3); a key has one period per UA in a session (`goneOwnKeyOf`, then `goneKeyOf`);
  which epoch won is the home's state.
- **Not followed.** A missing or wrong ciphertext leaves that epoch unreadable on the device: it is shown, the reads go on
  unchanged, and nothing is sent automatically ([CLI-PQC-07](#CLI-PQC-07)). The device follows again at the next commit that
  reaches its leaf or a node it holds, its own commit on the user's request included (it seals the marker).
- **A compromise warning (owner).** One UA signature lets its holder build the next epoch (accepted, as mode 0's `rekey`). A
  completed commit from the device's own `(ua, keyId)` that its seed does not reproduce is shown as a compromise warning, a
  state of its own, never as "not followed". To reproduce is both tests: the derived node keys equal the signed hashes
  and `sealedInfo` opens under the derived key; with an empty path (the last live leaf) `sealedInfo` alone decides, and
  bytes that fail the signature at the read boundary are "read corrupted", not this state. It names two cases: one
  foreign signature, where the warning shows what that commit changed (leaves added and removed, the admin list, the
  info) and stays until the roster is reconciled, because a refresh keeps every leaf the foreign commit added; a stolen
  UA signing key, which it does not end: an admin removes the UA and the user returns as a new UA, the old
  UA being lost everywhere (no key rotation inside a UA, [CTR-UA-13](../contracts/accounts.md#CTR-UA-13)).
- **What shows that a device followed (owner).** The claim "the same whether a ciphertext opens or not" holds for the replay
  reads and for contract writes. A tree session sends **no automatic receipt**; a send held while a child was not final goes
  back to the user. The store read by the epoch hint stays and is the one inherited signal (one bit per epoch to a watcher of
  the store; scheme 1 is outside [ARCH-POS-13](../decisions.md#ARCH-POS-13) by the owner's change of 2026-11-13).
- **The home's setting** comes from pinned deployment data or a majority read and is pinned; the mode is pinned with `treeId`.
- **The size hint.** The crate proposes the tree mode from about 7 keys where several members commit; it enforces nothing.

## 5. Vectors and tests

Status: **BUILT** (`tests/vectors.rs` over `smartcontracts/vectors/pqchat/`; the local real-crypto e2e `tests/e2e.rs`, gate
`pqc-e2e`, with its mutants under `runs/`); the same run on the SCaaS testnet, **PLANNED**.

<a id="CLI-PQC-11"></a>**CLI-PQC-11** — **The crate reproduces clientkeys' PqChat rows: the bytes that cross the SDK boundary in
`pqchat-core`'s tests, the secrets between in `ua-rs`'s** (owner, byte formats change everywhere at once; BUILT). `pqchat-core`'s
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
into the pqchat-core plan"; BUILT locally, UNAUDITED; the SCaaS testnet run PLANNED). On a local chain that enforces EIP-7825's per-transaction cap and a local Matrix
homeserver, through `pqchat-core` over the SDK with no stand-in wrap: a 1:1 session wrapped by the hybrid KEM to registered KEM keys;
a message sent by one member and decrypted by the other, equal byte for byte; an epoch rekey after which a removed member cannot
read; a fresh device recovering its sessions and the latest messages from state alone, after an explicit acceptance; a replica read
checked against the home; a public topic; and at least one mutant per decryption or verification check, each guarding a check its
own fixture reaches and killed by that check's failure reason. Writes an honest client refuses go through a named hostile harness on
the SDK's vectors build, never through `pqchat-core`. The same run on the SCaaS testnet follows at its next reset, on the owner's word.
