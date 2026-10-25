# UA-7: PQ chat sessions — an application contract that holds ML-KEM keys and per-session AES keys on chain

**Status:** short design for the owner's review (controller, 2026-10-25; revised the same day after the owner's
answer). Nothing is built. Queued **after plan 5h and UA-8** (owner 2026-10-25: "viết spec ngắn, xếp sau 5h"). The choices
below (C1–C9) are controller proposals inside the owner's request, with the owner's answers in §4.

**Request (owner 2026-10-25).** A smart contract for chat sessions, as an application: a UA creates a session; the
session's AES key goes **on chain**, encrypted with post-quantum cryptography for each member; a UA may register
**several ML-KEM keys** (owner, later the same day: **one key per UA first**); one AES key per session; every write is
a signed record that anyone may submit, so another party may pay the gas (owner, later: **no fees** — these writes have
nothing to do with a token); sessions and messages unique on a chain, identical on every chain, never locked; the AES key is then used to chat over **Matrix** (or any other
channel).

**What it is called.** On-chain **key distribution** (a key-encapsulation directory and a session-key store); the
chat itself is end-to-end encrypted with the session key. Nothing secret is exchanged in clear: the chain holds only
public KEM keys and KEM-wrapped session keys.

## 1. Why a new key, not the keys a UA already has

- **ML-DSA / FN-DSA / SLH-DSA keys sign; they cannot encrypt.**
- **The PQZ (MLWE) key must not be reused.** It is CPA-only and deliberately malleable (additive), 16.5–22.6 KB per
  ciphertext, and its secret also opens the UA's confidential balance; one purpose per key.

## 2. Design

**C1 — One application contract, `PqChat`; every write is a signed record, no fees.** Standalone: it reads
`UARegistry` for the members' signing keys and KEM keys (C2). Every write (session, epoch, message) is a **record signed
by its author** over a chain-independent digest (no chain id, no contract address — as UA-8 P1 / P4), checked **by the
contract** with the author's key in `UARegistry`, and **submitted by anyone**: the author or a relayer pays the gas.
These are **mtx-style writes — signed by the author, relayable by anyone — but not bound to a chain and without any
fee** (owner 2026-10-25: a session and its messages are the same on every chain and can be moved to another; these
writes are not token operations, so there is no fee and no token to take one from; a relayer that wants payment
arranges it off chain). No session and no message can be locked. One rule on every chain (owner 2026-10-25: every
chain is the same infrastructure). Upgrades by a new release, as for the other application contracts.

**Record ids and nonces (owner 2026-10-25: unique on a chain, the same on every chain, never locked).**
- Every record carries its author's **nonce** in a scope: a session `(creator, nonce)`; an epoch `(sessionId, author,
  nonce)`; a message `(sessionId, sender, nonce)` — the session id is the second dimension of a message nonce, so
  sessions never interfere. Its id is `keccak256(TAG ‖ record)` (the record without the signature).
- **The contract checks the signature first, then marks the scoped nonce used and refuses a used one** — unique on
  the chain. It keeps the set of used nonces (a bitmap per scope), **not** a "next nonce": records may arrive in any
  order (nonce 5 before 4), so a missing or late record never blocks a later one, and copying to another chain works in
  any order — never locked. Because the signature is checked before the nonce is marked, nobody can take someone
  else's nonce.
- The same signed bytes give the same id on every chain. Clients read the used set to pick their next nonce; two
  devices of one UA that race on the same nonce: the second transaction reverts (`NonceUsed`) and the device retries
  with the next one — never a silent duplicate.

**C2 — The KEM key comes from `UARegistry` (UA-8 P7).** Each member's chat key is its KEM key registered in the
registry (owner 2026-10-25: KEM key registration is part of UA-8): one scheme, ML-KEM-1024 + X25519, one key per UA
first, a signed version that is the same on every chain, no revocation. `PqChat` reads `kemKeyAt(ua, version)`; `keyId` below = that version (any stored
version; `kemKeyOf(ua)` gives the highest).

**C3 — Sessions.** `createSession(record, sig)`, `record = (creator, nonce, members[], wraps[])`; **anyone** may
create a session with any UA (owner 2026-10-25; the submitter pays the gas; clients hide sessions from unknown UAs);
`sessionId = keccak256("scaas/pqchat/v1/session" ‖ creator ‖ nonce)` (C1). The creator's client draws a random 32-byte
session key `K` for epoch 0 and, for **one KEM key of every member** (the creator's own included; normally the highest
version it sees), writes one wrap — with no chain id or contract address in it, so the session can be copied:

```
(ct, ss) ← KEM.Encaps(pk)
kek      = HKDF-SHA-256(ss, "scaas/pqchat/v1/wrap" ‖ sessionId ‖ epochId ‖ member ‖ keyId)
wrap     = ct ‖ AES-256-GCM(kek, nonce = 0^96, K, aad = sessionId ‖ epochId ‖ member ‖ keyId)   // 1,648 B
```

The contract requires one wrap per member, naming a `keyId` (version) stored for that member in this chain's registry
(any stored version, C2). A member reads its wrap, decapsulates with the matching secret key and gets `K`. Two-person
chat and group chat are the same thing (a group has more members).

**C4 — Epochs (new AES key).** `rekey(record, sig)`, `record = (sessionId, author, nonce, epoch, parentEpochId,
members[], wraps[])`, by any member of the parent epoch; `epochId = keccak256(TAG ‖ sessionId ‖ author ‖ nonce)`.
Used to add a member, remove one (the removed member gets no wrap of the new key), after a key change, or on a
schedule (proposal: every 1,000 messages or 7 days). Two members may rekey at the same time (on one chain or on two):
both records are stored (different scoped nonces); clients pick the current epoch by a fixed rule — the highest
`epoch` number, then the smallest `epochId` — so every client converges and nothing is locked. Old epochs stay readable
so history can be decrypted. The member list is public (C10 for an unlinkable mode).

**C5 — Storage: on chain, in state.** Each epoch's wraps are stored as one SSTORE2 blob per epoch (the full bytes stay
in contract state, readable by `eth_call`; not only in events, which nodes may drop under history expiry), plus the
member list and the epoch counter. Cost [estimate, to be measured in the plan]: ≈ 1,530 state gas per stored byte
under EIP-8037, so ≈ 2.5 M state gas per wrap; a two-person session ≈ 5.0 M state gas plus calldata (paid by the submitter),
which fits one transaction and one block on every chain we target.

**C6 — Message encryption (off chain, for example Matrix, or on chain by C6b).** AES-256-**GCM-SIV** with
`k_send = HKDF(K, "scaas/pqchat/v1/msg" ‖ sessionId ‖ epochId ‖ sender)` and a random 96-bit nonce per message
(GCM-SIV stays safe if a nonce ever repeats — the devices of one UA share its KEM key and could otherwise collide);
aad = `sessionId ‖ epochId ‖ sender ‖ msgNonce`.

**C6b — Messages stored on chain (owner 2026-10-25: "not only offline").** `postMessage(record, sig)`,
`record = (sessionId, epochId, sender, msgNonce, lastSeen, ciphertext)`: `msgNonce` is the sender's nonce **scoped by
the session** (the second dimension, owner 2026-10-25), `lastSeen` the id of the last message the sender saw from the
others (causal order without a global sequence), `ciphertext` the C6 output. The contract checks the sender's
signature over the whole record and that the sender is a member of that epoch, marks `(sessionId, sender, msgNonce)`
used and refuses a used one (C1: unique per chain, any order, never locked). The same text sent twice has two nonces,
so two records. Storage: the full record and its signature in contract state (one SSTORE2 blob per message, an
append-only list per session), never only a hash or an event; event `PqChatMessage(sessionId, messageId, sender)`;
views `messageCount`, `messageAt(sessionId, index)`. Nobody can edit or delete a stored message. Cost: the stored
signature adds 2,420 B (ML-DSA-44) / 3,309 B (ML-DSA-65) / ≈ 666 B (FN-DSA-512) ≈ +3.7 / +5.1 / +1.0 M state gas per
message, plus the contract's signature check (ML-DSA in Solidity ≈ 6–19 M gas, accounts.md §1.6) — one rule on every
chain.

**Why store on chain (owner 2026-10-25).** No intermediate server: no Matrix homeserver to run, trust or lose; the
messages live as long as the chain, and any node (one's own included) serves them — fully decentralised delivery and
storage. `PqChat` is plain EVM code, so it can be deployed on a **cheap layer 2** (any EVM rollup) where storage costs a
small fraction of layer 1; the chain only needs `UARegistry` (C1; registrations and KEM keys copied from another chain, UA-8) and someone
to submit the records. **A layer 2 is treated like layer 1** (owner
2026-10-25: both are infrastructure services; rollup internals such as the sequencer are not a design concern). What
on chain does not hide: the member list and who posts when are public on chain (on Matrix only the homeserver sees
them).

**Fee of one stored message, 1 KB of text [estimate, 2026-10-25; measured in the plan].** Layer 1 under the
Glamsterdam rules of `pqz-core/params/sets/README.md`:

| Part | Signer secp256k1 | Signer ML-DSA-65 |
|---|---|---|
| calldata: ciphertext 1,040 B + header + signature | ≈ 1.5 KB | ≈ 4.8 KB (signature 3,309 B) |
| regular gas = max(intrinsic 15,000 + calldata + execution, floor 15,000 + 64 / byte) | ≈ 0.14 M | ≈ 0.4 M |
| state gas, SSTORE2 blob 1,041 B × 1,530 | ≈ 1.59 M | ≈ 1.59 M |
| state gas, blob account + two new slots (counter uniqueness, list pointer) | ≈ 0.37 M | ≈ 0.37 M |
| **total** | **≈ 2.1 M gas** | **≈ 2.4 M gas** |

In money (example ETH = $3,000): Ethereum at 1 gwei ≈ 0.0022 ETH ≈ **$6–7** per message (≈ $2 at 0.3 gwei); an EVM
layer 2 (≈ 0.35 M L2 gas under the pre-Glamsterdam code-deposit price of 200 gas / byte, ≈ 0.005 gwei, plus its layer-1
data fee) ≈ **$0.005–0.02** per message, so 1,000 messages ≈ $5–20. Storing is what costs. These figures predate C6b's stored
signature and on-chain signature check (add those); the submitter pays, there is no fee.

**C7 — Matrix.** Yes, the AES key works over Matrix: Matrix is only the transport. Each message is a Matrix event of a
custom type (proposal `vn.scaas.pqchat.v1`, content: `sessionId`, `epoch`, `sender`, `keyId`, `counter`, ciphertext in
base64) in a Matrix room tied to the session (the room id may be stored in the session as a public field). Matrix's own
end-to-end encryption (Megolm) may stay on as an outer layer; ours is the PQ layer inside. Limits: the Matrix server
still sees metadata (who talks, when, message sizes) and standard clients such as Element cannot read the custom
events — our clients (`clients/ua-qt`, the JS wallet) or a widget / bot decrypt them.
**Qt client (owner 2026-10-25):** `clients/ua-qt` (Qt 6.12) gains a chat screen built on **libQuotient** (the C++/Qt
Matrix library behind NeoChat and Quaternion, Qt 6; it registers custom event types, so `vn.scaas.pqchat.v1` is a
first-class event): libQuotient handles login, rooms and sync; ua-qt's existing code signs the records and
reads `PqChat`; OpenSSL ≥ 3.5 does ML-KEM-1024, X25519 (combined per C2, a few dozen lines) and AES-GCM. No
fork of NeoChat / Quaternion / Nheko.

**C8 — What the on-chain key store does not give.** Everything on chain is public forever. Whoever obtains a member's
KEM secret key later — or breaks ML-KEM-1024 and X25519 one day — can open every session key wrapped to that key, and
with the stored (C6b) or captured Matrix ciphertexts the chat history of those epochs ("harvest now, decrypt later"). There is no forward secrecy beyond what
C4 provides. Mitigations in this design: the hybrid ML-KEM-1024 + X25519, frequent rekeys, replacing the KEM key
(C2; it does not withdraw the old one), deleting old secret keys on the devices. A chat that needs full forward secrecy should add an off-chain ratchet
on top (later, not in this design).

**C9 — Libraries (no precompile; the contract checks only signatures, shapes, membership and nonces).** KEM and
AES run in the clients: .NET 10 `System.Security.Cryptography.MLKem`, OpenSSL ≥ 3.5 (Qt client),
Rust `ml-kem` + `x25519-dalek`, JS `@noble/post-quantum` + `@noble/curves`; the combiner in each client (C2). Vectors under
`smartcontracts/vectors/pqchat/` (keys, wraps, messages) shared by all clients.

**C10 — Hiding who talks to whom (research, optional mode).** Today the member list, the session of each message and
its sender are public. An unlinkable mode — wraps without a member list (key-private KEM ciphertexts with view tags),
messages in one contract-wide append-only queue (a Merkle tree, not per session) with rotating tags, the sender inside
the ciphertext — is studied in [`docs/research/pqchat-unlinkability.md`](../../research/pqchat-unlinkability.md); not
part of this design until the owner decides.

## 3. Work (for the plan after 5h)

1. `PqChat.sol` (C1–C6b): signed records (session, epoch, message), scoped nonce bitmaps, SSTORE2 wraps and
   messages, events, views; forge tests (records in any order, a copied record on a second chain, a racing nonce
   reverts, a forged signature refused), gas per wrap and per stored message.
2. Byte layouts (C3, C6, C7) in `docs/contracts/`; vectors.
3. One reference client (`clients/ua-rs`: create / join / rekey / encrypt / decrypt) against the vectors, then the
   `clients/ua-qt` chat screen on libQuotient (C7).

## 4. Owner answers (2026-10-25)

1. Scheme: **ML-KEM-1024 + X25519, the default and the only one** (owner 2026-10-25; X-Wing with ML-KEM-768 and
   ML-KEM-768 alone dropped).
2. Who may create a session with a UA: **anyone** (the creator pays the gas; clients hide sessions from unknown UAs).
3. KEM keys per UA: **one first**; several (one per device) later (C2).
4. Every write is mtx-style — signed, relayable by anyone (a relayer may pay the gas) — **but chain-independent and
   without fees** (owner 2026-10-25: not token operations); sessions and messages are the same on every chain and can
   be moved; nothing can be locked; the KEM key is registered in `UARegistry` by UA-8.
5. Qt client: `clients/ua-qt` on **libQuotient** (C7).
6. Encrypted messages may also be stored on chain (C6b), not only sent off chain.
7. Session and message nonces: the contract checks the signature, then marks the scoped nonce used (any order, never
   locked); a message nonce is scoped by its session (C1, C6b).
