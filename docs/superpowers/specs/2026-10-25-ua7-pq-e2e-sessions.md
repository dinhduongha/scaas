# UA-7: post-quantum end-to-end encryption between UAs — KEM key in the registry, one AES key per session

**Status:** short design for the owner's review (controller, 2026-10-25). Nothing is built. Queued **after plan 5h**
(owner 2026-10-25: "viết spec ngắn, xếp sau 5h"). The choices below (E1–E9) are controller proposals; the owner may
override any of them.

**Request (owner 2026-10-25).** UA A sends a text or an AES key to UA B with post-quantum cryptography, with many
sessions at once and **one AES key per chat session**.

**What it is called.** Not "on-chain key exchange": the chain only **publishes and authenticates each UA's KEM public
key** (a key directory). The key exchange itself — a KEM handshake that sets up a session key — runs **off chain**
between the two clients. The whole feature is post-quantum **end-to-end encryption (E2EE)** with an on-chain key
directory.

## 1. Why not the keys a UA already has

- **ML-DSA / FN-DSA / SLH-DSA keys sign; they cannot encrypt.**
- **The PQZ (MLWE) key must not be reused.** It can carry 256 bits per ciphertext (16 coefficients × 16 bits), but the
  scheme is CPA-only and deliberately malleable (additive), its ciphertext is 16.5–22.6 KB per set, and its secret also
  opens the UA's confidential balance: a client that ever acts on a decryption result becomes a decryption oracle for
  the balance key. One purpose per key.

## 2. Design

**E1 — Key kind.** A UA publishes one **KEM public key**: **ML-KEM-768** (FIPS 203; pk 1,184 B, ciphertext 1,088 B,
shared secret 32 B), or the hybrid **X-Wing** (X25519 + ML-KEM-768; pk 1,216 B, ciphertext 1,120 B) — secure as long
as either part holds. Both are new **scheme ids** in `UAKinds.sol` (numbers at plan time), like `pqz-mlwe` 0x0142
since UA-6: attributes of a UA, not UA kinds; never a signer.

**E2 — Registry attribute.** `UARegistry` gains `_kemKey[ua] = (scheme, version, SSTORE2 pointer)`, set by
`setKemKey(ua, scheme, pk)` under `requireAuthorized(ua, purpose "kem")` (relayable like every state-changing
`mtx*` write, fee may be 0), cleared by `setKemKey(ua, 0, "")`. **Rotatable** (unlike the PQZ key): `version` + 1 on
every change, event `UAKemKeySet(ua, scheme, version, keyHash)`. One owner per key through the existing `_keyOwner`
(group `kem`), so nobody can register someone else's KEM key under their UA. The full key stays in contract state
(SSTORE2), readable by `eth_call`, not only in an event (events may be pruned by history expiry).

**E3 — Authentication of the key.** The binding "this KEM key belongs to UA B" is the registry write itself, authorized
by B's signer. The key is post-quantum authenticated only if B's signer is a PQ kind (`mldsa44` / `mldsa65` / `fndsa512`
or a PQ-dominant `msig`); clients show a UA with a classical signer as "not PQ-authenticated".

**E4 — Session handshake (one AES key per session).** Each session is an independent handshake, the KEM-based AKE of
CRYSTALS-Kyber (Bos et al., EuroS&P 2018, §5: two static encapsulations and one ephemeral):

```
A: sid ← 16 random bytes; (pk_e, sk_e) ← KEM.KeyGen()           // ephemeral, this session only
A: (ct_B, ss_B) ← KEM.Encaps(pk_B)                               // B's registry key, version vB
A → B: m1 = sid ‖ UA_A ‖ UA_B ‖ vA ‖ vB ‖ pk_e ‖ ct_B               // ≈ 2.3 KB with ML-KEM-768
B: ss_B ← Decaps(sk_B, ct_B); (ct_A, ss_A) ← Encaps(pk_A); (ct_e, ss_e) ← Encaps(pk_e)
B → A: m2 = sid ‖ ct_A ‖ ct_e ‖ confirm_B                           // ≈ 2.2 KB
A: ss_A ← Decaps(sk_A, ct_A); ss_e ← Decaps(sk_e, ct_e); checks confirm_B; erases sk_e
K = HKDF-SHA-256(ikm = ss_B ‖ ss_A ‖ ss_e,
                 info = "scaas/ua7/v1" ‖ chainId ‖ registry ‖ H(m1 ‖ ct_A ‖ ct_e))
(k_AB, k_BA, k_confirm) = expand(K)                               // one AES-256 key per direction
confirm_B = HMAC(k_confirm, "B" ‖ H(m1 ‖ ct_A ‖ ct_e)); A's first message carries confirm_A likewise
```

- Only B can open `ct_B` and only A can open `ct_A`, so each side knows it talks to the registered UA (implicit mutual
  authentication; no signature in the handshake). `ss_e` gives **forward secrecy**: a later theft of A's or B's
  long-term KEM key does not open past sessions, because `sk_e` was erased.
- **Many sessions:** every handshake has its own `sid` and its own fresh randomness, so every session has its own key.
  Sessions are independent: closing or losing one does not affect the others.

**E5 — Messages.** AES-256-GCM with `k_AB` (A → B) or `k_BA` (B → A); nonce = 96-bit message counter per direction
(never reused; the session ends before 2^32 messages); AAD = `sid ‖ direction ‖ counter`. To "send an AES key", A
sends those 32 bytes as one message.

**E6 — Rekey inside a long session.** Either side sends a new ephemeral `pk_e'`; the other answers with
`Encaps(pk_e')`; `K' = HKDF(K ‖ ss_e', "rekey" ‖ …)`. Proposal: rekey every 1,000 messages or 24 h. (A full double
ratchet as in Signal is out of scope; it can come later on top of the same keys.)

**E7 — Transport: off chain.** m1, m2 and messages travel over any channel (the node mesh bus, an HTTPS relay, a
mailbox service): the format does not depend on it. **Not on chain by default**: calldata and events are public
forever, so they would be stored for an attacker who breaks ML-KEM later ("harvest now, decrypt later"), and they cost
gas. The chain is used only for E2 (publishing / rotating the key).

**E8 — Rotation and loss.** A new KEM key (E2) affects only new handshakes; open sessions keep their keys until they
rekey or end. A lost KEM secret: publish a new key; sessions protected by `ss_e` stay closed to the thief.

**E9 — Libraries (no precompile, no contract crypto).** .NET 10 `System.Security.Cryptography.MLKem` (same family as
the `MLDsa` the Nethermind plugin uses), OpenSSL ≥ 3.5 (Qt client), Rust `ml-kem`, JS `@noble/post-quantum`; X-Wing
where the library has it. Clients: `clients/ua-rs`, `ua-cs`, `ua-qt`, the JS wallet. Test vectors under
`smartcontracts/vectors/ua7/` (handshake transcripts, keys, messages) shared by all clients.

## 3. Work (for the plan after 5h)

1. Registry: E2 (attribute, `setKemKey`, `_keyOwner` group, event, views), `UAKinds` scheme ids, forge tests, gas;
   accounts.md section; decisions entry.
2. Protocol spec text (E4–E6, byte layout of m1 / m2 / messages) in `docs/contracts/` and the vectors.
3. One reference client (`ua-rs`), then the others against the vectors.

## 4. Open for the owner

1. ML-KEM-768 alone, or X-Wing by default (my proposal: **X-Wing**, the hybrid hedge, +64 B per key and ciphertext).
2. Several KEM keys per UA (one per device) now, or one per UA first (my proposal: **one per UA first**; devices share
   it or each device gets its own UA under an `msig`).
3. Group chats (one key for several UAs): out of scope here; later a sender key sent through pairwise sessions, or MLS.
