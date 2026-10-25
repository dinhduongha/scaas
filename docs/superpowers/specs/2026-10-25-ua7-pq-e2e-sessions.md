# UA-7: PQ chat sessions — an application contract that holds ML-KEM keys and per-session AES keys on chain

**Status:** short design for the owner's review (controller, 2026-10-25; revised the same day after the owner's
answer). Nothing is built. Queued **after plan 5h** (owner 2026-10-25: "viết spec ngắn, xếp sau 5h"). The choices
below (C1–C9) are controller proposals inside the owner's request; the owner may override any of them.

**Request (owner 2026-10-25).** A smart contract for chat sessions, as an application: a UA creates a session; the
session's AES key goes **on chain**, encrypted with post-quantum cryptography for each member; a UA may register
**several ML-KEM keys**; one AES key per session; the AES key is then used to chat over **Matrix** (or any other
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
`UARegistry` only for `requireAuthorized(ua, …)`. Every write is relayable like every state-changing `mtx*` write
(fee may be 0). Upgrades by a new release, as for the other application contracts.

**C2 — KEM keys, several per UA.** `addKemKey(ua, scheme, pk, label) → keyId` and `revokeKemKey(ua, keyId)`, both
under `requireAuthorized(ua, purpose "kem")`. Schemes: **ML-KEM-768** (FIPS 203; pk 1,184 B, ciphertext 1,088 B) and
**X-Wing** (X25519 + ML-KEM-768; pk 1,216 B, ciphertext 1,120 B; secure while either part holds). A UA keeps any
number of keys (one per device, for example); `label` is a short public name ("phone", "laptop"). A revoked key gets no
new session keys; it stays readable for history. The key is post-quantum authenticated only if the UA's signer is a PQ
kind (`mldsa44` / `mldsa65` / `fndsa512` or a PQ-dominant `msig`); clients show the others as "not PQ-authenticated".

**C3 — Sessions.** `createSession(creator, members[], wraps[]) → sessionId`. The creator's client draws a random
32-byte session key `K` for epoch 0 and, for **every active KEM key of every member** (the creator's own keys
included, so the creator's other devices can read it), writes one wrap:

```
(ct, ss) ← KEM.Encaps(pk)
kek      = HKDF-SHA-256(ss, "scaas/pqchat/v1/wrap" ‖ chainId ‖ PqChat ‖ sessionId ‖ epoch ‖ member ‖ keyId)
wrap     = ct ‖ AES-256-GCM(kek, nonce = 0^96, K, aad = sessionId ‖ epoch ‖ member ‖ keyId)   // ≈ 1,136 B (ML-KEM-768)
```

A member reads its wrap from the contract, decapsulates with the matching secret key and gets `K`. Two-person chat and
group chat are the same thing (a group has more members).

**C4 — Epochs (new AES key).** `rekey(sessionId, members[], wraps[])` by any member writes epoch + 1 with a new `K`.
Used to add a member, remove one (the removed member gets no wrap of the new key), after a device loss, or on a
schedule (proposal: the client rekeys every 1,000 messages or 7 days). Old epochs stay readable so history can be
decrypted. Only members can rekey; the member list is public.

**C5 — Storage: on chain, in state.** Each epoch's wraps are stored as one SSTORE2 blob per epoch (the full bytes stay
in contract state, readable by `eth_call`; not only in events, which nodes may drop under history expiry), plus the
member list and the epoch counter. Cost [estimate, to be measured in the plan]: ≈ 1,530 state gas per stored byte
under EIP-8037, so ≈ 1.7 M state gas per wrap; a two-person session with one key each ≈ 3.5 M state gas plus calldata,
which fits one transaction and one block on every chain we target.

**C6 — Messages (off chain, for example Matrix).** Messages never go on chain. Each sender uses its own subkey so that
several senders never share a nonce: `k_send = HKDF(K, "scaas/pqchat/v1/msg" ‖ sessionId ‖ epoch ‖ senderUA ‖ keyId)`,
nonce = the sender's 96-bit message counter, AES-256-GCM with aad = `sessionId ‖ epoch ‖ senderUA ‖ keyId ‖ counter`.
A sender stops at 2^32 messages per epoch (in practice C4 rekeys long before).

**C7 — Matrix.** Yes, the AES key works over Matrix: Matrix is only the transport. Each message is a Matrix event of a
custom type (proposal `vn.scaas.pqchat.v1`, content: `sessionId`, `epoch`, `sender`, `keyId`, `counter`, ciphertext in
base64) in a Matrix room tied to the session (the room id may be stored in the session as a public field). Matrix's own
end-to-end encryption (Megolm) may stay on as an outer layer; ours is the PQ layer inside. Limits: the Matrix server
still sees metadata (who talks, when, message sizes) and standard clients such as Element cannot read the custom
events — our clients (`clients/ua-qt`, the JS wallet) or a widget / bot decrypt them.

**C8 — What the on-chain key store does not give.** Everything on chain is public forever. Whoever obtains a member's
KEM secret key later — or breaks ML-KEM one day — can open every session key wrapped to that key, and with the Matrix
ciphertexts the chat history of those epochs ("harvest now, decrypt later"). There is no forward secrecy beyond what
C4 provides. Mitigations in this design: X-Wing (the hybrid), frequent rekeys, revoking and replacing device keys
(C2), deleting old secret keys on the devices. A chat that needs full forward secrecy should add an off-chain ratchet
on top (later, not in this design).

**C9 — Libraries (no precompile, no crypto in the contract).** The contract only stores and checks shapes / sizes /
membership; KEM and AES run in the clients: .NET 10 `System.Security.Cryptography.MLKem`, OpenSSL ≥ 3.5 (Qt client),
Rust `ml-kem`, JS `@noble/post-quantum`; X-Wing where the library has it. Vectors under
`smartcontracts/vectors/pqchat/` (keys, wraps, messages) shared by all clients.

## 3. Work (for the plan after 5h)

1. `PqChat.sol` (C1–C5): KEM keys, sessions, epochs, SSTORE2 wraps, events, views; forge tests and gas per wrap.
2. Byte layouts (C3, C6, C7) in `docs/contracts/`; vectors.
3. One reference client (`clients/ua-rs`: create / join / rekey / encrypt / decrypt), then a Matrix demo
   (a small bot or the Qt client sending `vn.scaas.pqchat.v1` events).

## 4. Owner answers (2026-10-25)

1. Default scheme: **X-Wing** (ML-KEM-768 alone stays accepted for clients without X25519).
2. Who may create a session with a UA: **anyone** (the creator pays the gas; clients hide sessions from unknown UAs).
