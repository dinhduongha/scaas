# UA-7: PqChat — post-quantum chat sessions (version 2)

**Status:** version 2, **accepted by the owner 2026-11-04** (revised the same day; the open items O1–O7 and the round name
answered the same day, §14). Version 1 (controller, 2026-10-25, with the
owner's answers of that day) is in this file's git history. Nothing is built. Version 2 applies the owner's thirteen
decisions of 2026-11-04 (D1–D13, §15, register entry
[CTR-CHAT-01](../../decisions.md#CTR-CHAT-01)) and the corrections of the architecture study
(`docs/research/pqchat-architecture.md` §9; the two-page summary is `docs/research/pqchat-overview.md`). The build plan
is [`2026-11-04-ua7-pqchat.md`](../plans/2026-11-04-ua7-pqchat.md). Queued after plan 5h and UA-8 (owner 2026-10-25).
UNAUDITED: every cryptographic construction below is a design, not a reviewed protocol.

**Request (owner 2026-10-25).** A smart contract for chat sessions, as an application: a UA creates a session; the
session's AES key goes **on chain**, encrypted with post-quantum cryptography for each member; one KEM key per UA first;
every write is a signed record that anyone may submit, without fees; sessions and messages unique on a chain,
identical on every chain, never locked; the key is then used to chat over **Matrix** (or any other channel).
**Request (owner 2026-11-04).** Make the design clear as a decentralised or semi-decentralised application; say what
is missing, extra and needed for sessions, metadata, chat features, security, and voice and video calls.

**Contents**

1. [What changed from version 1](#1-what-changed-from-version-1)
2. [Architecture](#2-architecture)
3. [Members, KEM keys, devices](#3-members-kem-keys-devices)
4. [Records](#4-records)
5. [Control plane: sessions, epochs, roles](#5-control-plane-sessions-epochs-roles)
6. [Key schedule](#6-key-schedule)
7. [Transports](#7-transports)
8. [Ordering](#8-ordering)
9. [Metadata](#9-metadata)
10. [Voice and video calls](#10-voice-and-video-calls)
11. [Cost](#11-cost)
12. [Libraries and vectors](#12-libraries-and-vectors)
13. [What stays research](#13-what-stays-research)
14. [Open items for the owner](#14-open-items-for-the-owner)
15. [Owner answers and decisions](#15-owner-answers-and-decisions)
16. [Work](#16-work)

## 1. What changed from version 1

| Version 1 | Version 2 | Why |
|---|---|---|
| C1 `createSession(record, sig)` etc., ids `keccak256(TAG ‖ record)`, a raw digest | typed EIP-712 structs with named fields in a portable domain; one named entry per operation (§4) | explicit parameters (CTR-MTX-28, CTR-MTX-29), typed portable records (CTR-UA-07) |
| C3 `wrap = ct ‖ AES-GCM(...)`, one blob | `Wrap {member, keyId, mlkemCt, x25519Eph, sealedKey}` (§4.2) | one crypto object per `bytes` (CTR-MTX-29), the registry's `KemKey` shape |
| C3 / C6b any UA may be a member; a secp256k1 signer column | only KEM holders are members: PQ kinds and a PQ-eligible `msig` (P3) | CTR-UA-32 holders |
| C4 any member rekeys; current epoch = highest number, then smallest id | `epoch = parent + 1`, one child per parent, the first complete child on the session's home chain wins; admins change membership; plain rekeys and leaving open to all (§5) | D3, D4: the v1 rule let a removed member undo its removal |
| C5 "fits one transaction and one block on every chain we target" | wraps in chunks over several transactions; no block-limit assumption (P11) | no assumptions about a chain; EIP-8037 inclusion |
| C6 one `k_send` per sender per epoch, random nonce | a per-sender, per-device hash ratchet; counter-derived nonces (§6.3) | D6, D9 |
| C6b the signature stored in state | its hash in state, its bytes in the event; ciphertext and header in state (§7.2) | D11 |
| C7 Matrix event content in the clear, no signature | the signed record inside an envelope; one event type `net.scaas.pqchat.v1` (§7.1) | D7, D10 |
| C7 the room id "may be stored in the session as a public field" | never in the clear on chain: inside `sealedInfo` (§4.2) | D10 |
| C8 "no forward secrecy beyond C4" | FS and PCS bounded by the KEM key version; rotation is the UA owner's choice, PqChat may suggest it (P5); a per-sender ratchet and epoch rekeys | D6 (changed 2026-11-04) |
| — | `msig` expansion (P13), devices (P6), calls (§10), ordering per transport (§8), metadata hygiene (§9), FIPS 203 §7.2 check (P14) | D5, D8–D10, D12, D13 |
| C10 unlinkable mode | unchanged: research (§13) | D10 |

## 2. Architecture

```mermaid
flowchart LR
  subgraph CHAIN["chain: identity, keys, control plane"]
    REG["UARegistry: UA, signing key, KEM key versions"]
    PQC["PqChat: sessions, admins, epochs, wraps; home chain orders epochs"]
    FB["PqChat messages: fallback, by the user's choice"]
  end
  subgraph MX["Matrix: data plane"]
    ROOM["room: net.scaas.pqchat.v1 events (signed record inside an envelope)"]
    MEDIA["media repository: encrypted attachments"]
    RTC["MatrixRTC: call membership and signalling"]
  end
  SFU["LiveKit SFU / TURN: SFrame media only"]
  NODE["scaas-node: relays PqChat writes only"]
  CL["clients: ua-rs reference, ua-qt on libQuotient, JS wallet"]
  CL --> REG
  CL --> NODE --> PQC
  CL --> ROOM
  CL -.->|"user chooses: store on chain"| FB
  CL --> RTC
  CL --> SFU
```

**P1 — Four layers** (D1). **Identity**: the UA and its signing key in `UARegistry`, the same id on every chain
(CTR-UA-03, CTR-UA-07). **Key directory**: the UA's KEM key versions (CTR-UA-32). **Control plane**: `PqChat` — sessions,
admins, members, epochs, wraps of the epoch key `K` — always on chain (D2). **Data plane**: messages, attachments,
receipts, calls — on Matrix; a message goes on chain only when the user chooses (D2).

**P2 — Transports** (D1, D12). Primary: Matrix. Fallback: the same signed message record posted to `PqChat` (§7.2). Peer to
peer: 1:1 calls only (§10). `scaas-node`: relays `PqChat` writes as `call` jobs (§7.3); it stores, gossips or pushes no
chat traffic and is no TURN or SFU.

## 3. Members, KEM keys, devices

**P3 — Who can be a member.** A member is a UA that holds a KEM key in this chain's registry (CTR-UA-32 holders):
`mldsa44` (0x0130), `mldsa65` (0x0131), `fndsa512` (0x0132), or a PQ-eligible `msig`, which joins by expansion (P13); on
branch `mldsa87`, being built: `mldsa87` (0x0134) and `fndsa1024` (0x0135). Native ids and classical kinds (secp256k1,
ed25519, passkeys …) hold no KEM key and cannot be members; `slhdsa128s` is not a holder. Signature cost on chain:
FN-DSA-512 2.3 M gas; ML-DSA-44 / -65 only on the registry's cached expanded key (4.1 / 5.8 M) or an EIP-8355 precompile,
never on the FIPS 204 key (18.9 M for ML-DSA-65 is above the EIP-7825 regular cap of 2^24); `mldsa87` only by precompile
(accounts.md §1.6).

**P4 — Using a member's KEM key.** A client reads `kemKeyOf(ua)` / `kemKeyAt(ua, version)` and:

1. wraps only to the **highest version it has seen on any source it reads** (any chain, the node, a contact card); a member
   whose highest version rises is a reason for a plain rekey (P10);
2. skips a UA whose `checkedOf(ua).kem` is `NONE` (the hash-commit form not yet repaired) and says so;
3. on a family where a relayer checked the KEM record (CTR-UA-34), re-verifies the record's signature before using it;
4. shows a fingerprint of each member's `kemPkHash`, and warns when two UAs list the same KEM key (no proof of possession
   of the KEM secret exists, by CTR-UA-32);
5. checks the key before every encapsulation (P14).

**P5 — KEM key rotation: the UA owner's choice** (D6 as changed by the owner 2026-11-04). The KEM key is the UA's general
key in `UARegistry` (CTR-UA-32), used for more than chat, so PqChat sets **no rotation schedule** and requires none. A new
version is registered (`setKemKey`) when, and only when, the UA's owner chooses. A PqChat client always wraps to each
member's **highest stored version** (P4 item 1), rekeys when a member's highest version rises (P10), and **may suggest** a
rotation (for example after a device loss), never require one. Whether an old secret is deleted is also the owner's choice;
a deletion means something only if the secret cannot be regenerated (not derived from a seed the owner keeps).

**What it costs, plainly.** A leaked KEM secret opens every wrap ever made to that version: the epoch keys, and so the
history, of every session that used that version, for as long as the version was used, from the chain, forever. The per-sender
ratchet (§6.3) and epoch rekeys do not protect against that leak, because the wraps stay on chain and re-serve the epoch keys
to whoever holds the secret; they protect against the loss of a device's message and chain keys after deletion. Forward
secrecy and post-compromise security are therefore bounded by how long the owner keeps a version, which PqChat does not
control. History is kept on the device and, opt-in, in an epoch-key backup (§14 O5).
An MLS group or an off-chain ratchet for 1:1 is the later step (D6),
not in this version.

**P6 — Devices** (D9). One KEM key and one signing key per UA, shared by its devices; every device has a **device id**
(`uint32`, random, unique within the UA, assigned by an existing device at linking) that enters every sender derivation,
counter and nonce scope (§6.3, §4.3). **Linking** is off chain: the new device shows a fresh ephemeral ML-KEM-1024 + X25519
key and a short code (QR); the existing device checks the code, encapsulates to that key and sends the UA's secrets, the
device id and the current epoch keys over Matrix or a local channel. Per-device KEM keys (`keyId` per device, CTR-UA-32
"later") come later and change no layout.

## 4. Records

**P7 — Domain, purpose, signature.** Every record is a typed EIP-712 struct in the portable domain
`DS_C = keccak256(abi.encode(keccak256("EIP712Domain(string name,string version)"), keccak256("SCaaS PqChat"), keccak256("1")))`
— no chain id, no contract address, so a record is the same on every chain (owner answer 4) — and `typed(s) =
keccak256(0x1901 ‖ DS_C ‖ hashStruct(s))`. The author signs `uaMessage(kind, PURPOSE_PQCHAT, typed(s))` with
`PURPOSE_PQCHAT = keccak256("scaas.ua.purpose.pqchat.v1")`, as a `UASig` (single key: `signature`; `msig`: `members`,
minimal form, CTR-UA-07). The contract verifies it through the registry's portable check (§14 O1). No record carries a fee
(owner answer 4); a payer pays a relayer through `MtxRelayFee` (CTR-MTX-27) if it wants to.

### 4.1 Structs

| Struct | Type string |
|---|---|
| `MemberKey` | `MemberKey(bytes32 ua,uint64 keyId,bytes32 via)` |
| `Wrap` | `Wrap(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)` |
| `PqChatSession` | `PqChatSession(bytes32 creator,uint64 nonce,bytes32 homeChain,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)` |
| `PqChatEpoch` | `PqChatEpoch(bytes32 sessionId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)` |
| `PqChatLeave` | `PqChatLeave(bytes32 sessionId,bytes32 epochId,bytes32 member,uint64 nonce)` |
| `PqChatMessage` | `PqChatMessage(bytes32 sessionId,bytes32 epochId,bytes32 sender,uint32 device,uint64 counter,bytes32[] parents,bytes ciphertext)` |

### 4.2 Fields

- `members` strictly sorted by `ua`; `keyId` = the KEM version wrapped to; `via` = the `msig` seat it came from, or zero
  (display only, P13). `admins` strictly sorted, any registered UA (P10).
- `wrapHashes[i] = hashStruct(Wrap_i)` for `members[i]`, in the same order: the record signs every wrap without carrying
  it, so wraps may arrive in chunks (P11).
- `Wrap.mlkemCt` 1,568 B, `x25519Eph` the X25519 ephemeral public key, `sealedKey` 48 B (`K` under the KEK, with its tag).
- `homeChain` = the `chain_uid` of the chain that orders this session's epochs (the family-neutral id the factory already
  uses); fixed for the session's life.
- `sealedInfo` = AES-256-GCM-SIV under `HKDF(K, "scaas/pqchat/v1/info" ‖ sessionId ‖ epochId)`, a random 96-bit nonce
  prepended, over the padded (§6.5) canonical JSON `{"room": <Matrix room id>, "name", "topic", "matrix": {<ua>: <Matrix
  user id>}}`. **The room id and Matrix user ids never appear on chain in the clear** (D10).
- `parents` = the ids of the conversation heads the sender has seen, at most 8, sorted (P19).
- `ciphertext` = §6.4.

### 4.3 Ids and nonces

```text
sessionId = keccak256(abi.encode(keccak256("scaas/pqchat/v1/session"), creator, nonce))            epoch 0's id too
epochId   = keccak256(abi.encode(keccak256("scaas/pqchat/v1/epoch"), sessionId, author, nonce))    epochs >= 1
leaveId   = typed(PqChatLeave);  messageId = typed(PqChatMessage)
```

Ids are computable before the wraps exist (the KEK binds them, §6.2). Scoped nonces, checked after the signature and
then marked used (owner answer 7; bitmaps, any order, never locked): a session `(creator, nonce)`; an epoch or a leave
`(sessionId, author, nonce)`; a message `(epochId, sender, device)` over `counter`. A message's scope still has the session
as a dimension (the epoch belongs to one session); the device is new (D9).

### 4.4 Entries, views, events

| Entry | Who | What the contract checks |
|---|---|---|
| `createSession(PqChatSession s, Wrap[] wraps, UASig sig)` | anyone submits; `s.creator` signs | sig; nonce; shapes (P8); every member holds `keyId` here; each given wrap matches its hash; stores |
| `rekey(PqChatEpoch e, Wrap[] wraps, UASig sig)` | anyone submits; `e.author` signs | P9 |
| `addWraps(bytes32 epochId, uint32 first, Wrap[] wraps)` | anyone, no signature | `wraps[j]` hashes to `wrapHashes[first + j]`; not stored yet; the epoch may still complete (P9) |
| `leave(PqChatLeave l, UASig sig)` | anyone submits; `l.member` signs | sig; nonce; `member` in `epochId` |
| `postMessage(PqChatMessage m, UASig sig)` | anyone submits; `m.sender` signs | sig; nonce scope `(epochId, sender, device)`; sender in the complete epoch `epochId`; size bound of §6.5 |

Views: `sessionOf`, `epochOf`, `epochComplete(epochId)`, `childOf(parentEpochId)` (the winning child on the home chain, zero
elsewhere), `wrapAt(epochId, i)`, `leftIn(epochId, member)`, `nonceUsed(scope, nonce)`, `messageCount(sessionId)`,
`messageAt(sessionId, index)`. Events: `PqChatSessionCreated(sessionId, creator, homeChain)`, `PqChatEpochAdded(sessionId,
epochId, parentEpochId, epoch, author)`, `PqChatWraps(epochId, first, count)`, `PqChatEpochComplete(epochId)`,
`PqChatLeft(sessionId, epochId, member)`, `PqChatMessagePosted(sessionId, messageId, sender, index, sig)` with the
signature's bytes (§7.2). Errors are named per check (`PqChatEpochNumber`, `PqChatEpochTaken`, `PqChatNotAdmin`,
`PqChatNotMember`, `PqChatWrapHash`, `PqChatNonceUsed`, `PqChatKemKey`, `PqChatShape`, …). Every stored record keeps its
full bytes in state (SSTORE2 blobs; never only an event).

## 5. Control plane: sessions, epochs, roles

```mermaid
sequenceDiagram
  participant A as creator client
  participant R as relayer (node) or own account
  participant H as PqChat on the home chain
  participant B as member client
  A->>A: K random; per member: check key (FIPS 203 7.2), encapsulate, seal K
  A->>A: sign PqChatSession (wrapHashes, sealedInfo with room id)
  A->>R: createSession(s, wraps[0..k], sig)
  R->>H: transaction(s); more wraps by addWraps if needed
  H-->>B: PqChatEpochComplete(sessionId)
  B->>H: wrapAt(sessionId, i), sealedInfo
  B->>B: decapsulate, open K, read room id, join the Matrix room
```

**P8 — Session.** The creator lists itself as a member and an admin (the creator is always the first admin),
draws `K` for epoch 0 and signs the session record. `admins ⊆` registered UAs; members strictly sorted, at least 2.
Anyone may create a session with any UA (owner answer 2); consent is in clients (P12).

**P9 — Epochs** (D3). `rekey` is accepted when: the signature is the author's; the parent epoch is stored and **complete**;
`e.epoch == parent.epoch + 1` (`PqChatEpochNumber`); the author's rights hold (P10); every member holds `keyId` here. A
child is **complete** when every wrap has landed. **On the home chain** (`chain_uid == homeChain`), the first child of a
parent to become complete takes the parent's child slot; any other child of that parent is refused or can no longer
complete (`PqChatEpochTaken`). An incomplete child never takes the slot, so nobody can lock a session by starting an
epoch and never finishing it; anyone may finish it with `addWraps` (the signed hashes fix the bytes). **On every other
chain** records are replicas: each complete child is stored, `childOf` reads zero, and clients follow the home chain's
`childOf`. A new `K` is always fresh randomness, never derived from the old one, so a removed member cannot read the next
epoch.

```mermaid
sequenceDiagram
  participant AD as admin client
  participant M as removed member
  participant H as PqChat, home chain
  participant Y as PqChat, other chain
  AD->>H: rekey(parent e5, epoch 6, members without M), complete
  M->>H: rekey(parent e5, epoch 6, members with M)
  H-->>M: refused: PqChatEpochTaken (or PqChatNotAdmin)
  M->>H: rekey(parent e5, epoch 1000)
  H-->>M: refused: PqChatEpochNumber
  AD->>Y: copy of the admin's epoch 6
  Note over H,Y: clients follow childOf(e5) on the home chain
```

**P10 — Roles** (D4). Each epoch record carries the admin set. **A membership change** (any member added or removed, any
admin added or removed) needs an author who is an admin of the parent epoch (`PqChatNotAdmin`). **A plain rekey** — the
same members and admins, minus those who left the parent epoch (P12), with any `keyId` changes — may be authored by any
member of the parent. An admin that is an `msig` signs its epoch records by its quorum (`UASig.members`). An admin needs a
KEM key only if it is also a member.

**P11 — Chunks** (no block-limit assumption). The contract assumes no block or code-size limit: wraps are stored in SSTORE2
blobs of at most the chain's code-size limit, declared at deployment (a constructor argument; the EVM has no opcode for it) (one wrap is 1,680 B with its member id;
14 per blob under 24,576 B, 39 under 64 KiB); a client puts as many wraps per transaction as fit its chain's limits
(EIP-8037: regular + state gas ≤ block limit) and sends the rest by `addWraps`. Group size has no protocol bound; cost grows
by ≈ 2.6 M gas per member per epoch (§11).

**P12 — Leaving and consent** (D5). A member leaves by `leave`; the next epoch drops it (a plain rekey may). Consent is
client-side now: a client shows a session from an unknown creator only after its user accepts; a member that never accepts
can leave. The on-chain link between a creator and the UAs it lists stays public until the unlinkable mode (§13).

**P13 — `msig` members: expansion** (D8). An `msig` is a **seat**, never a KEM recipient: the author's client expands it,
at every epoch, into its accepted members (`memberAccepted`, CTR-UA-37), two levels (CTR-UA-38), keeps the leaves that hold
a KEM key (warning on the others) and lists each leaf with `via = <the seat's msig id>`. The contract does not read `via`;
clients re-check it against the registry. Leaving the `msig` (or losing acceptance) removes the leaf at the next epoch.
Messages and leaves are always signed by a leaf UA, never by the `msig`; an "on behalf of" field may go inside the
plaintext.

## 6. Key schedule

**P14 — KEM key check before encapsulation** (FIPS 203 §7.2). Scheme 1 only (`kemPk[0] == 0x01`, 1,601 B,
CTR-UA-32); anything else is refused. Before every `Encaps` the client runs the **type check** (`ek` is 1,568 B) and the
**modulus check** (`ByteEncode12(ByteDecode12(ek[0:1536])) == ek[0:1536]`), and refuses an all-zero X25519 shared secret.
A receiver runs the FIPS 203 §7.3 decapsulation-key check on its own key once, at generation.

### 6.1 The hybrid KEM (scheme 1)

```text
(ct_M, ss_M) = ML-KEM-1024.Encaps(ek)                         ek = kemPk[1:1569]
(e, E)       = X25519 key pair, fresh;  ss_X = X25519(e, pk_X) pk_X = kemPk[1569:1601]
ss           = SHA3-256(ss_M || ss_X || E || pk_X || "scaas.kem.1")    X-Wing-style combiner, own label
```

### 6.2 Wrap

```text
kek       = HKDF-SHA-256(ikm = ss, salt = empty,
                         info = "scaas/pqchat/v1/wrap" || sessionId || epochId || member || keyId || 0x01 || kemPkHash)
sealedKey = AES-256-GCM(kek, nonce = 0^96, K, aad = sessionId || epochId || member || keyId)     48 B
Wrap      = {member, keyId, mlkemCt = ct_M, x25519Eph = E, sealedKey}                             1,680 B in calldata with ids
```

`nonce = 0` is safe because each KEK encrypts once. The KEK binds the scheme byte and the key hash, so a wrap cannot be
read as one for another key.

### 6.3 Sender chains (per-sender, per-device ratchet)

```text
ck_0      = HKDF-SHA-256(K, info = "scaas/pqchat/v1/chain" || sessionId || epochId || sender || device)
mk_i      = HMAC-SHA-256(ck_i, 0x01);   n_i = HMAC-SHA-256(ck_i, 0x03)[0:12];   ck_{i+1} = HMAC-SHA-256(ck_i, 0x02)
counter   = i, from 0 in each epoch, per (sender, device)
```

A sender deletes `ck_i` and `mk_i` once used; a receiver deletes `mk_i` after decryption and keeps skipped message keys
for at most 2,000 messages per chain (O6). `K` stays recoverable from the chain while the KEM secret exists; the
bound on forward secrecy is the lifetime of the KEM version, the UA owner's choice (P5). A sender stops using an epoch once the home chain shows a complete
child of it.

### 6.4 Message encryption

```text
pt         = pad(canonical JSON content, §6.5)        content: {"type": "text" | "edit" | "redact" | "react" | "receipt" |
                                                                "typing" | "file" | "callKey" | ..., fields per type}
aad        = abi.encode(sessionId, epochId, sender, device, counter, keccak256(abi.encode(parents)))
ciphertext = AES-256-GCM-SIV(mk_i, n_i, pt, aad)
```

GCM-SIV stays (v1 C6): a device id reused by mistake does not turn into a nonce reuse. The record `PqChatMessage`
(header + ciphertext) is then signed by the sender (D7, §4); the signature authenticates the author to every member.
There is no deniability: a signature proves authorship of a ciphertext for good.

### 6.5 Padding

Plaintexts are padded (length prefix, then zeros) to 256, 1,024, 4,096 or 16,384 B, then multiples of 16,384 B (D10).
A message posted on chain is at most one 1,024-B bucket unless the user confirms the cost; attachments never go on chain
(1 MiB ≈ 1.6 G state gas).

## 7. Transports

### 7.1 Matrix (primary)

```mermaid
sequenceDiagram
  participant A as sender client
  participant HA as sender's homeserver
  participant HB as member's homeserver
  participant B as member client
  A->>A: content -> pad -> ratchet -> ciphertext; sign PqChatMessage
  A->>A: envelope = AES-256-GCM-SIV(k_env, abi.encode(message, sig))
  A->>HA: event net.scaas.pqchat.v1 {v, hint, env} (inside Megolm when on)
  HA->>HB: federation
  HB->>B: /sync
  B->>B: open envelope, verify the UA signature, decrypt, order by parents
```

**P15 — Event.** Type **`net.scaas.pqchat.v1`**, content `{"v": 1, "hint": base64(HMAC(K, "scaas/pqchat/v1/hint")[0:8]),
"env": base64(nonce ‖ AES-256-GCM-SIV(k_env, nonce, abi.encode(PqChatMessage, UASig)))}` with `k_env =
HKDF(K, "scaas/pqchat/v1/env" ‖ sessionId ‖ epochId)`. The envelope holds **the same bytes** a `postMessage` call takes,
so the fallback (§7.2) reposts them unchanged and both copies have one `messageId`. Servers see an opaque blob and an
8-byte epoch hint. Megolm may stay on as an outer layer (it hides even the event type). One room per session; its id
travels in `sealedInfo` only. Matrix room membership follows `PqChat` membership (the client invites and kicks the
Matrix ids from `sealedInfo`); a Matrix member without the epoch key sees ciphertext only. Receipts, typing, edits,
redactions, reactions and call keys are content types inside the envelope, never Matrix's plaintext ephemeral events
(D10). Attachments: the file encrypted with a random AES-256-GCM key, uploaded to the Matrix media repository; `{mxc,
key, sha256, size bucket}` in a `file` content. Qt client: `clients/ua-qt` on libQuotient (owner answer 5) registers the
event type; push uses the Matrix push gateway (event ids only).

### 7.2 Chain (fallback)

**P16 — On-chain messages** (D2, D11). `postMessage` stores the header and the ciphertext in contract state (one SSTORE2
blob per message, an append list per session: never only a hash or an event) and **the signature's hash** in that blob;
the signature's bytes go in `PqChatMessagePosted`. A client posts on chain only when its user chooses (per message or per
session setting), never silently: it costs gas and is public forever. Edits and deletes are new messages; nothing stored
can be removed, and the UI says so.

```mermaid
sequenceDiagram
  participant A as sender client
  participant N as scaas-node (call job)
  participant C as PqChat (any chain)
  participant B as member client
  A->>N: postMessage(PqChatMessage, UASig), named fields
  N->>C: transaction (lane gas; payment via MtxRelayFee if any)
  C->>C: verify sig (portable), member of complete epoch, mark (epochId, sender, device) counter
  C-->>B: PqChatMessagePosted(sessionId, messageId, sender, index, sig)
  B->>C: messageAt(sessionId, index)
  B->>B: verify sig against the event bytes and the stored hash, decrypt
```

### 7.3 The node

**P17 — Relay only** (D1). `scaas-node` relays `createSession`, `rekey`, `addWraps`, `leave` and `postMessage` as `call`
jobs: five rows in its call table, kept equal to the contract's entries (NODE-JOB-01), named JSON fields per job
(NODE-JOB-20 style), no fee form (owner answer 4). The rule and the rows go in the node's own spec (`docs/node/job-api.md`
call table), for every consumer. The node stores no chat traffic, runs no chat gossip, sends no push and is no TURN or SFU
(D12).

## 8. Ordering

**P18 — Order per transport.**

| Transport | Order it gives | What the client does |
|---|---|---|
| Chain, one chain | `(block, transaction index, log index)`; an append index per session; final after the finality gate | uses it for nothing but the epoch slot on the home chain |
| Chain, across chains | none: records are copied in any order | — |
| Home chain, epochs | one child per parent, first complete wins (P9) | follows `childOf` on the home chain, after finality |
| Matrix | per-room DAG, linearised per server | ignores it for display |
| Peer to peer (calls) | FIFO per link | — |

**P19 — Conversation order** (every transport the same). Every message names `(epochId, sender, device, counter)` and
`parents` (≤ 8 heads it saw). Display order: topological by `parents`, ties by the sender's timestamp inside the
plaintext, then `messageId`. Counters may have gaps (nonce 5 may land before 4); a message for an unknown epoch is buffered
until its epoch record arrives; a message in a child that lost the home-chain slot is shown as such if its `K` is held.
The same `messageId` on Matrix and on chain is one message.

## 9. Metadata

**P20 — What is public, and the hygiene rules** (D10).

| Observer | Sees |
|---|---|
| Anyone, forever, from the chain | sessions, creators, admins, member UAs and their KEM versions, epoch authors and times; for on-chain messages the session, sender, device, counter, size and time; the submitter's account |
| Homeservers | room membership (Matrix ids), sender Matrix id, time, envelope size (bucketed), the 8-byte hint |
| RPC providers, relayers | the IP of who reads or submits |

Rules: no room id or Matrix id on chain in the clear (`sealedInfo` only); padding buckets (§6.5); records submitted through
a relayer rather than the author's own account; receipts and typing inside the envelope; Megolm as an outer layer where
the client supports it. Hiding the member set and the sender on chain is the unlinkable mode (§13).

## 10. Voice and video calls

```mermaid
sequenceDiagram
  participant A as caller
  participant HS as Matrix room
  participant P as participant
  participant S as LiveKit SFU
  A->>HS: m.rtc.member (MatrixRTC, MSC4143), slot and SFU
  A->>A: callSecret random; per participant: Wrap (KEM) off chain
  A->>HS: net.scaas.pqchat.v1 envelope, content callKey {callId, callEpoch, wraps}
  P->>P: open wrap: callSecret; derive SFrame keys
  A->>S: SFrame media (DTLS-SRTP hop to the SFU)
  S->>P: forwards SFrame packets, cannot decrypt
  Note over A,P: join or leave: callEpoch+1, new callSecret to the remaining participants
```

**P21 — Transport** (D12). 1:1: WebRTC peer to peer (ICE, STUN, TURN when NAT requires), signalling in the session's
Matrix room. Groups: MatrixRTC (MSC4143, merged 2026-10-21) for membership (`m.rtc.member`) and transport discovery, with
a LiveKit SFU (MSC4195). Any operator's TURN or LiveKit server; the node is neither.

**P22 — Media keys** (D13). Media is encrypted end to end with **SFrame** (RFC 9605), cipher suite `AES_256_GCM_SHA512_128`,
through WebRTC Encoded Transform; DTLS-SRTP stays as the hop layer only (it ends at the SFU and is classical unless a hybrid
group is negotiated). MatrixRTC's own `m.rtc.encryption_key` (Olm, classical) is not used.

```text
group:  callSecret        = 32 random bytes per call epoch, sent as a Wrap per participant (§6.2 with the call ids)
        callBase          = HKDF-SHA-256(K || callSecret, "scaas/pqchat/v1/call" || sessionId || epochId || callId || callEpoch)
1:1:    callBase          = HKDF-SHA-256(K, "scaas/pqchat/v1/call" || sessionId || epochId || callId || callEpoch)
both:   base_key(sender)  = HKDF-SHA-256(callBase, "scaas/pqchat/v1/sframe" || sender || device)   one sender per base_key
        KID               = (context << (S + E)) + (participantIndex << E) + (callEpoch mod 2^E),  E = 4 (RFC 9605 P9 layout)
```

A join or a leave starts `callEpoch + 1` with a fresh `callSecret` wrapped to the remaining participants (no chain write);
new keys are installed for decryption first and used for encryption about 5 s later (as MSC4143). A change of the session's
epoch ends every call key of the old epoch. A session member outside the call cannot derive a group call's keys (no
`callSecret`); in a 1:1 call both parties hold `K` already.

**P23 — What a call leaks.** The SFU: participants' IPs, join and leave times, streams, packet sizes and rates, the SFrame
header (participant index, epoch bits, counter); not the media. TURN: IPs and volume. The homeserver: `m.rtc.member`
events (who joined, when, which SFU). Hygiene: constant-bitrate Opus for voice; the RTP audio-level header extension off;
no call record on chain. SFrame does not authenticate a sender inside the group (RFC 9605 §6.1.1); a participant could
forge another's media.

## 11. Cost

Estimates (architecture study §8): EIP-8037 1,530 gas per state byte, new slot 97,920, new account 183,600; ETH $2,261.87 and
0.31 gwei (both 2026-11-03); a layer 2 at 0.005 gwei pricing state the same way. To be measured in the plan.

| Item | Gas | Ethereum, 0.31 gwei | at 5 gwei | layer 2 |
|---|---|---|---|---|
| one wrap | ≈ 2.6 M | ≈ $1.8 | ≈ $30 | < $0.03 |
| session or epoch, 2 members (FN-DSA-512 author) | ≈ 8.1 M | $5.7 | $91 | $0.09 |
| session or epoch, 20 members | ≈ 55–58 M | $38–41 | $620–660 | $0.6 |
| message 1 KiB on chain, signature hash in state (FN-DSA-512 / ML-DSA-65 cached / precompile) | 4.6 / 8.1 / 2.5 M | $3.2 / 5.7 / 1.7 | $52 / 92 / 28 | $0.03–0.09 |
| new KEM version (`setKemKey`) | ≈ 6–14 M | $4–10 | $70–155 | < $0.15 |
| message, call key, attachment over Matrix | 0 gas | hosting | | |

## 12. Libraries and vectors

KEM, HKDF, HMAC, AES-GCM(-SIV) and SFrame run in clients (the contract checks signatures, shapes, membership, epoch rules
and nonces only): .NET 10 `System.Security.Cryptography.MLKem`; OpenSSL ≥ 3.5 (Qt client); Rust `ml-kem`, `x25519-dalek`,
`aes-gcm-siv`, `sframe`; JS `@noble/post-quantum`, `@noble/curves`, `@noble/ciphers`. Every combiner, KDF label, struct
hash and envelope is fixed by vectors under `smartcontracts/vectors/pqchat/` (keys, the §7.2 check's refusals, wraps,
records and typehashes, chains, messages, envelopes, call keys), read by every client.

## 13. What stays research

The unlinkable mode (v1 C10: key-private wraps with view tags, one contract-wide queue with rotating tags, sender inside the
ciphertext; `docs/research/pqchat-unlinkability.md`): later, for on-chain traffic (D10). MLS groups and an off-chain ratchet
for 1:1 (D6): later. Per-device KEM keys (D9): later.

## 14. Open items: the owner's answers

Version 2 left seven items and the round name to the owner, each with a proposal.
**Owner 2026-11-04: all as proposed**, except O6's KEM rotation, withdrawn the same day
(recorded in a Change on [CTR-CHAT-01](../../decisions.md#CTR-CHAT-01)):

1. **O1 — Portable signature check.** `requireAuthorized` verifies the chain-bound `UAAuth` digest; `PqChat` records are
   portable, and the registry verifies portable signatures (`pop`, `kem`, `pqz-key`) only internally. **Answer:** the
   registry gains the view `requirePortable(ua, purposeTag, typedDigest, UASig)` (reverts unless `auth` is the UA's portable
   signature over `uaMessage(kind, purposeTag, typedDigest)`: a single key, or an `msig` in minimal form over two levels,
   native members over the typed digest) **in the same registry generation as `mldsa87` / `fndsa1024`** (branch `mldsa87`,
   not merged on 2026-11-04), so the registry changes once; if that branch has merged before the build reaches this task,
   in the next registry generation. `PqChat` deploys only on a registry that has it.
2. **O2 — The child slot taken by a plain rekey.** Any member may author a plain rekey (D4), so a member can take a parent's
   slot before an admin's membership change. **Answer: accepted.** A plain rekey may take the child slot first; the griefer
   pays its gas (≈ 2.6 M per member each time); the admin rekeys again from the new epoch. No precedence rule for admins.
3. **O3 — Home chain lost.** **Answer:** if the home chain stops, the members start a new session on another chain (a client
   action; history stays readable from the old records); there is no in-protocol move of a session's home chain.
4. **O4 — The last admin leaves.** **Answer:** membership is then frozen (no admin can change it); plain rekeys and messages
   continue.
5. **O5 — History backup.** **Answer:** an opt-in export of epoch keys, encrypted to a backup key the user holds; it re-opens
   forward secrecy for what it holds, and the client says so when the user turns it on.
6. **O6 — Numbers.** **Answer, as proposed**, except the KEM rotation: at most 2,000 skipped message keys per chain
   (§6.3); at most 8 `parents` (P19); padding buckets 256, 1,024, 4,096 and 16,384 B, then multiples of 16,384 B (§6.5);
   SFrame `E = 4` (P22). **Change (owner 2026-11-04): no forced KEM rotation.** O6 as first answered also set a KEM
   rotation every 30 days with a 7-day grace before deleting the old secret. The owner withdrew it: the KEM key is the UA's
   general key, used for other things than chat, and a PqChat schedule would affect those uses. Rotation is the UA owner's
   choice; clients wrap to the highest stored version and may suggest a rotation, never require one (P5). The cost is in
   P5: a leaked KEM secret opens the history of every session that used that version, for as long as it was used.
7. **O7 — First contact.** **Answer:** a signed contact card — UA id, Matrix user id, current KEM version — exchanged out of
   band (QR code, link); no on-chain field.
8. **Round name.** **Answer:** every family after EVM takes `PqChat` in its own round, named `pqchat-<family>`.

## 15. Owner answers and decisions

**Answers of 2026-10-25** (version 1 §4), and what version 2 does with them:

1. Scheme ML-KEM-1024 + X25519, the only one — **kept** (scheme byte 1, CTR-UA-32).
2. Anyone may create a session with any UA; clients hide sessions from unknown UAs — **kept**; consent in clients (D5).
3. One KEM key per UA first, several later — **kept**; devices share it with a device id (D9).
4. Every write signed, relayable by anyone, chain-independent, no fee; never locked — **kept**; now as typed records in a
   portable domain (§4); "never locked" holds for epochs too (P9: an incomplete child never takes the slot); epoch order
   now comes from the session's home chain (**changed by D3**).
5. Qt client on libQuotient — **kept** (§7.1).
6. Messages may be stored on chain — **kept**, as the fallback and by the user's choice (**refined by D1, D2**); the
   signature's bytes now in the event, its hash in state (**changed by D11**).
7. Nonce: signature first, then the scoped nonce; message nonce scoped by its session — **kept**; the scope adds the epoch
   and the device (**refined by D9**).

**Decisions of 2026-11-04** (owner, all as the study recommended; [CTR-CHAT-01](../../decisions.md#CTR-CHAT-01)):
D1 Matrix primary, chain fallback, P2P for 1:1 calls, the node relays only; D2 control plane always on chain, messages on
chain by choice; D3 `epoch = parent + 1`, one child per parent, first landed on the home chain wins; D4 admins change
membership, self-leave and plain rekeys open to all; D5 consent in clients now, the public link stays until C10; D6 a
per-sender ratchet and epoch rekeys now, KEM rotation the UA owner's choice (changed 2026-11-04: first "KEM rotation with
secret deletion"), MLS or an off-chain ratchet later for 1:1; D7 a PQ signature inside every message; D8 an `msig` expands into its accepted members, two levels, messages written by a member UA; D9 a
shared key with a device id plus device linking now, per-device keys later; D10 metadata hygiene now (no Matrix room id on
chain, padding buckets, relayer submission, encrypted receipts), C10 later; D11 an on-chain message's signature as a hash in
state with the bytes in the event, the ciphertext in state; D12 WebRTC 1:1 and MatrixRTC on a LiveKit SFU for groups, the
node no TURN or SFU; D13 group call keys from `K ‖ callSecret` wrapped per participant and rotated on join or leave, 1:1 from
`K`.

**Answers of 2026-11-04 to the open items** (owner, all as proposed; §14): O1 `requirePortable(ua, purposeTag, typedDigest,
UASig)` in the registry generation of branch `mldsa87` (or the next one if that has merged); O2 a plain rekey may take the
child slot first, the griefer pays, the admin rekeys again; O3 a lost home chain means a new session on another chain, no
in-protocol move; O4 the last admin leaving freezes membership, rekeys and messages continue; O5 an opt-in export of epoch
keys encrypted to a user-held backup key; O6 2,000 skipped keys, at most 8 parents, the padding buckets, SFrame `E = 4`,
and **no forced KEM rotation** (changed the same day: the 30-day rotation with a 7-day grace was withdrawn; rotation is the
UA owner's choice, P5); O7 a signed contact card exchanged out of band, no on-chain field; family rounds named
`pqchat-<family>`.

## 16. Work

For the plan (`docs/superpowers/plans/2026-11-04-ua7-pqchat.md`); EVM first, other families in their own rounds.

1. Registry: the portable check view `requirePortable` (O1), on the registry generation of branch `mldsa87` (the next
   generation if that branch has merged first).
2. Vectors (§12) from `clientkeys`, before any contract code.
3. `PqChat.sol` (§4–§5, §7.2): structs and typehashes, entries, chunks, home-chain slot, roles, leave, messages with the
   signature hash; forge tests (red first): records in any order, a copied record on a second chain, the P9 removal
   attack refused, an incomplete child never blocks, `addWraps` by a stranger, a racing nonce, a forged signature, an
   `msig` admin; gas per wrap, epoch and message measured.
4. Node: five call-table rows and the job shapes in `docs/node/job-api.md`.
5. `clients/ua-rs` reference: keys, P14 check, wraps, records, chains, envelope, ordering, call keys; then `clients/ua-qt`
   on libQuotient (event type, room, chat screen, SFrame through Qt WebEngine or LiveKit's SDK), then the JS wallet.
6. Docs: a `docs/contracts/` component section for `PqChat` (SPECIFIED, then BUILT), `docs/clients/`, the node call table.
7. Not in this work: the unlinkable mode, MLS, per-device KEM keys, non-EVM families (each a `pqchat-<family>` round).
