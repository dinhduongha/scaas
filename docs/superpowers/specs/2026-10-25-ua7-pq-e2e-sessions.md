# UA-7: PQ chat sessions — an application contract that holds ML-KEM keys and per-session AES keys on chain

**Status:** short design for the owner's review (controller, 2026-10-25; revised the same day after the owner's
answer). Nothing is built. Queued **after plan 5h** (owner 2026-10-25: "viết spec ngắn, xếp sau 5h"). The choices
below (C1–C9) are controller proposals inside the owner's request, with the owner's answers in §4.

**Request (owner 2026-10-25).** A smart contract for chat sessions, as an application: a UA creates a session; the
session's AES key goes **on chain**, encrypted with post-quantum cryptography for each member; a UA may register
**several ML-KEM keys** (owner, later the same day: **one key per UA first**); one AES key per session; every write may
go through **mtx**, so another party (a relayer) pays the transaction fee; the AES key is then used to chat over **Matrix** (or any other
channel).

**What it is called.** On-chain **key distribution** (a key-encapsulation directory and a session-key store); the
chat itself is end-to-end encrypted with the session key. Nothing secret is exchanged in clear: the chain holds only
public KEM keys and KEM-wrapped session keys.

## 1. Why a new key, not the keys a UA already has

- **ML-DSA / FN-DSA / SLH-DSA keys sign; they cannot encrypt.**
- **The PQZ (MLWE) key must not be reused.** It is CPA-only and deliberately malleable (additive), 16.5–22.6 KB per
  ciphertext, and its secret also opens the UA's confidential balance; one purpose per key.

## 2. Design

**C1 — One application contract, `PqChat`.** Standalone (not part of `UARegistry`, no change to it): it reads
`UARegistry` only for `requireAuthorized(ua, …)`. **Every write is an `mtx*` entry point** (owner 2026-10-25: key
registration, session creation, rekey — all of them): the UA signs the envelope, a relayer submits the transaction and
pays its gas, and the UA pays the relayer a fee (which may be 0) the same way as the other `mtx*` writes (CTR-MTX-20,
the `MetaTokenBase` pattern). Upgrades by a new release, as for the other application contracts.

**C2 — The KEM key: one per UA first.** `mtxSetKemKey(ua, pk)` under `requireAuthorized(ua, purpose "kem")` sets or
replaces the UA's key (`keyId` = a version counter, + 1 on every change); `mtxSetKemKey(ua, "")` revokes it. **One
scheme only: ML-KEM-1024 + X25519** (owner 2026-10-25: the default and the only one): the X-Wing combiner with
ML-KEM-1024 (FIPS 203, NIST level 5) in place of ML-KEM-768, the QSF construction of the CFRG hybrid-KEM draft; pk
1,600 B, ciphertext 1,600 B, shared secret 32 B; secure while either part holds. The contract accepts only 1,600-byte
keys. A replaced or revoked
key gets no new session keys; it stays readable for history. **Several keys per UA (one per device) later** (owner
2026-10-25: one key first): the storage is keyed by `(ua, keyId)` from the start, so adding `mtxAddKemKey` later
changes no layout; until then the devices of one UA share its key. The key is post-quantum authenticated only if the UA's signer is a PQ
kind (`mldsa44` / `mldsa65` / `fndsa512` or a PQ-dominant `msig`); clients show the others as "not PQ-authenticated".

**C3 — Sessions.** `mtxCreateSession(creator, members[], wraps[]) → sessionId`; **anyone** may create a session with
any UA (owner 2026-10-25; the creator, or its relayer, pays the gas; clients hide sessions from unknown UAs). The
creator's client draws a random 32-byte session key `K` for epoch 0 and, for **the current KEM key of every member**
(the creator's own included), writes one wrap:

```
(ct, ss) ← KEM.Encaps(pk)
kek      = HKDF-SHA-256(ss, "scaas/pqchat/v1/wrap" ‖ chainId ‖ PqChat ‖ sessionId ‖ epoch ‖ member ‖ keyId)
wrap     = ct ‖ AES-256-GCM(kek, nonce = 0^96, K, aad = sessionId ‖ epoch ‖ member ‖ keyId)   // 1,648 B
```

A member reads its wrap from the contract, decapsulates with the matching secret key and gets `K`. Two-person chat and
group chat are the same thing (a group has more members).

**C4 — Epochs (new AES key).** `mtxRekey(member, sessionId, members[], wraps[])` by any member writes epoch + 1 with a new `K`.
Used to add a member, remove one (the removed member gets no wrap of the new key), after a key change, or on a
schedule (proposal: the client rekeys every 1,000 messages or 7 days). Old epochs stay readable so history can be
decrypted. Only members can rekey; the member list is public.

**C5 — Storage: on chain, in state.** Each epoch's wraps are stored as one SSTORE2 blob per epoch (the full bytes stay
in contract state, readable by `eth_call`; not only in events, which nodes may drop under history expiry), plus the
member list and the epoch counter. Cost [estimate, to be measured in the plan]: ≈ 1,530 state gas per stored byte
under EIP-8037, so ≈ 2.5 M state gas per wrap; a two-person session ≈ 5.0 M state gas plus calldata (paid by the relayer under mtx),
which fits one transaction and one block on every chain we target.

**C6 — Messages (off chain, for example Matrix, or on chain by C6b).** Each sender uses its own subkey so that
several senders never share a nonce: `k_send = HKDF(K, "scaas/pqchat/v1/msg" ‖ sessionId ‖ epoch ‖ senderUA ‖ keyId)`,
nonce = the sender's 96-bit message counter, AES-256-GCM with aad = `sessionId ‖ epoch ‖ senderUA ‖ keyId ‖ counter`.
A sender stops at 2^32 messages per epoch (in practice C4 rekeys long before). One counter sequence per sender and
epoch covers both channels (Matrix and C6b), so a nonce is never used twice whichever way a message travels.

**C6b — Messages stored on chain (owner 2026-10-25: "not only offline").** `mtxPostMessage(sender, sessionId, epoch,
counter, ciphertext)`, through mtx like every other write (a relayer may pay): the sender must be a member of that
epoch; `(sessionId, epoch, sender, counter)` must be new (the contract refuses a repeat, so the chain itself enforces
nonce uniqueness for what it stores); `ciphertext` is the C6 AES-256-GCM output (text + 16-byte tag). Storage: the
full ciphertext in contract state (one SSTORE2 blob per message, append-only list per session), never only a hash or
an event; event `PqChatMessage(sessionId, index, sender, epoch, counter)` lets clients sync; views `messageCount`,
`messageAt(sessionId, index)`. Nobody can edit or delete a stored message. Cost [estimate, measured in the plan]:
≈ 1,530 state gas per stored byte plus a fixed cost per blob, so a 200-character message ≈ 0.35 M state gas plus that
fixed cost; a client may store a whole conversation, only chosen messages (a record, a contract term, a key), or
nothing.

**Why store on chain (owner 2026-10-25).** No intermediate server: no Matrix homeserver to run, trust or lose; the
messages live as long as the chain, and any node (one's own included) serves them — fully decentralised delivery and
storage. `PqChat` is plain EVM code, so it can be deployed on a **cheap layer 2** (any EVM rollup) where storage costs a
small fraction of layer 1; the chain only needs `UARegistry` (C1 reads `requireAuthorized`) and an mtx relayer, both
deployable there too. What on chain does not hide: the member list and who posts when are public on chain (on Matrix
only the homeserver sees them); an L2 sequencer can delay a transaction (the rollup's forced inclusion through L1 is the
fallback); an L2's gas rules differ from EIP-8037, so the cost estimates above are layer-1 figures.

**C7 — Matrix.** Yes, the AES key works over Matrix: Matrix is only the transport. Each message is a Matrix event of a
custom type (proposal `vn.scaas.pqchat.v1`, content: `sessionId`, `epoch`, `sender`, `keyId`, `counter`, ciphertext in
base64) in a Matrix room tied to the session (the room id may be stored in the session as a public field). Matrix's own
end-to-end encryption (Megolm) may stay on as an outer layer; ours is the PQ layer inside. Limits: the Matrix server
still sees metadata (who talks, when, message sizes) and standard clients such as Element cannot read the custom
events — our clients (`clients/ua-qt`, the JS wallet) or a widget / bot decrypt them.
**Qt client (owner 2026-10-25):** `clients/ua-qt` (Qt 6.12) gains a chat screen built on **libQuotient** (the C++/Qt
Matrix library behind NeoChat and Quaternion, Qt 6; it registers custom event types, so `vn.scaas.pqchat.v1` is a
first-class event): libQuotient handles login, rooms and sync; ua-qt's existing code signs the `mtx*` envelopes and
reads `PqChat`; OpenSSL ≥ 3.5 does ML-KEM-1024, X25519 (combined per C2, a few dozen lines) and AES-GCM. No
fork of NeoChat / Quaternion / Nheko.

**C8 — What the on-chain key store does not give.** Everything on chain is public forever. Whoever obtains a member's
KEM secret key later — or breaks ML-KEM-1024 and X25519 one day — can open every session key wrapped to that key, and
with the stored (C6b) or captured Matrix ciphertexts the chat history of those epochs ("harvest now, decrypt later"). There is no forward secrecy beyond what
C4 provides. Mitigations in this design: the hybrid ML-KEM-1024 + X25519, frequent rekeys, revoking and replacing device keys
(C2), deleting old secret keys on the devices. A chat that needs full forward secrecy should add an off-chain ratchet
on top (later, not in this design).

**C9 — Libraries (no precompile, no crypto in the contract).** The contract only stores and checks shapes / sizes /
membership; KEM and AES run in the clients: .NET 10 `System.Security.Cryptography.MLKem`, OpenSSL ≥ 3.5 (Qt client),
Rust `ml-kem` + `x25519-dalek`, JS `@noble/post-quantum` + `@noble/curves`; the combiner in each client (C2). Vectors under
`smartcontracts/vectors/pqchat/` (keys, wraps, messages) shared by all clients.

## 3. Work (for the plan after 5h)

1. `PqChat.sol` (C1–C5, C6b): KEM key, sessions, epochs, SSTORE2 wraps, stored messages, events, views; forge tests,
   gas per wrap and per stored message.
2. Byte layouts (C3, C6, C7) in `docs/contracts/`; vectors.
3. One reference client (`clients/ua-rs`: create / join / rekey / encrypt / decrypt) against the vectors, then the
   `clients/ua-qt` chat screen on libQuotient (C7).

## 4. Owner answers (2026-10-25)

1. Scheme: **ML-KEM-1024 + X25519, the default and the only one** (owner 2026-10-25; X-Wing with ML-KEM-768 and
   ML-KEM-768 alone dropped).
2. Who may create a session with a UA: **anyone** (the creator pays the gas; clients hide sessions from unknown UAs).
3. KEM keys per UA: **one first**; several (one per device) later (C2).
4. Every write through **mtx** (a relayer pays the transaction fee): key registration, session creation, rekey (C1).
5. Qt client: `clients/ua-qt` on **libQuotient** (C7).
6. Encrypted messages may also be stored on chain (C6b), not only sent off chain.
