> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PqChat: hiding who talks to whom (research, 2026-10-25)

**Status:** research note (owner request 2026-10-25: "study how to hide the link between session, recipients and
sender, e.g. with a Merkle tree"). Not a decision; UA-7 ([spec](../superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md)
C10) points here. All claims are [inference] unless marked.

## 1. What the UA-7 design shows today

| Public on chain | From |
|---|---|
| the members of a session, and which KEM key version each wrap is for | the session / epoch record (C3, C4) |
| the session of every stored message | `postMessage` record (`sessionId`) |
| the sender of every stored message | the record and the contract's signature check (C6b) |
| who submits, when, how large | the transaction (submitter address, block time, calldata / blob size) |

Contents stay private (KEM-wrapped `K`, AES-256-GCM-SIV messages). The goal of an **unlinkable mode** is that an
outsider learns neither the members of a session, nor which messages belong together, nor who sent them — while
records stay unique on a chain, identical on every chain and impossible to lock (UA-7 C1).

## 2. Building blocks

1. **Recipient privacy of the wraps.** A session record carries the wraps without a member list. A KEM ciphertext must
   not reveal its recipient (key privacy / anonymity). ML-KEM is analysed as anonymous (ANO-CCA) under its MLWE
   assumptions (Grubbs, Maram, Paterson, Eurocrypt 2022, "Anonymous, Robust Post-Quantum Public Key Encryption"
   [external, to be re-read before use]); the X25519 half uses a fresh ephemeral key, independent of the recipient.
   Each wrap gets a **view tag** — 1–2 bytes of `H(ss)` — so a member decapsulates only the wraps whose tag matches
   (cost: one tag compare per wrap, one ML-KEM-1024 + X25519 decapsulation per match, tens of microseconds).
2. **Message unlinkability: rotating tags instead of `sessionId` / `sender`.** A stored message carries a tag
   `t = HMAC(k_tag, epochId ‖ seq)` instead of `(sessionId, sender, msgNonce)`; only members can compute the next tags,
   so an outsider cannot group messages. The tag doubles as the scoped nonce: **the contract refuses a repeated tag**
   (unique per chain), the same record gives the same tag on every chain, and nobody without `k_tag` can predict — so
   squat — a future tag (no lock by outsiders).
3. **One contract-wide queue, a Merkle tree.** All unlinkable records (sessions, epochs, messages) go into one
   append-only list, committed to by an incremental Merkle tree (depth 32; the contract keeps the frontier and a short
   root history). There is no per-session list to read; clients scan the queue for their tags. The root lets a light
   client prove that a record is in the queue, and a client copying records to another chain can show the source
   root.
4. **Sender inside the ciphertext.** The sender's UA and its signature over the message move inside the AEAD
   plaintext; members verify them. The contract no longer sees the sender, so it cannot check a signature: it enforces
   only tag uniqueness and sizes.
5. **Metadata hygiene.** Submit through relayers or fresh accounts; pad records to fixed buckets (for example 1 KB);
   optional batching and delay.

## 3. What remains and what it costs

- **Insider squatting.** All members know `K`; if `k_tag` comes from `K`, a member can compute another member's next
  tags and post garbage under them first (a lock inside the group). Fix: a per-sender tag key that only that sender and
  the readers can check but not produce — e.g. each sender commits to a hash chain `t_n = H(t_{n+1})` in the session
  record and reveals tags backwards (an outsider and an insider can verify but not predict), or a per-sender secret
  delivered in the wraps. To be designed.
- **Spam.** The contract cannot tell members from outsiders; spam is limited only by its gas cost (paid by the
  spammer) and filtered by clients (no tag match, AEAD failure).
- **Scanning cost.** Each client checks every new record against its expected tags (cheap hashes) and decapsulates only
  view-tag matches; a large queue means more download.
- **Anonymity set** = everyone using the unlinkable mode on that contract; small at first.
- **Gas.** Per record: one Merkle insert (≈ 32 hashes and a few frontier slot updates) plus the stored bytes; no
  signature check (cheaper than C6b's).
- **Not hidden:** that a UA uses the contract at all when it submits itself; timing; the total volume.

## 4. Not needed

Membership proofs in zero knowledge (Semaphore style: "I am in the member tree" without saying who) would let the
contract keep authorising writes while hiding the sender, but they need a zero-knowledge proof per write on chain. The
tag design above gets the same unlinkability without them, because the contract does not need to authorise writes —
uniqueness by tag already prevents locks.

## 5. Open questions

1. The insider-squatting fix (§3).
2. Whether unlinkable sessions and public sessions share the contract (one larger anonymity set) or not.
3. The exact view-tag length (false-positive rate vs leakage).
4. Re-reading the ML-KEM anonymity results for the hybrid with X25519 and the CFRG combiner.
