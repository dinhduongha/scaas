> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

> Vietnamese version: [pqz-leg-proof-option.vi.md](pqz-leg-proof-option.vi.md). This English file is the reference
> version.

# PQZ `legProof`: a self-verifying proof for every ciphertext in state (2026-11)

Written 2026-11-06 at the owner's request. **PQZ only**; classical Zether is a separate system and is touched only in
§11.4. Research only: nothing here is a rule, nothing in pqz-core, the contracts, the node or the clients changed, and
everything cryptographic is **UNAUDITED**. Nothing was measured: the numbers are paper arithmetic over figures the
repository already records ([`pqz-leg-proof-option/`](pqz-leg-proof-option/), script and output). No gas or timing run
was made (that needs the owner's word).

**Status (2026-11-09):** the contract side is specified in the proof-path spec and BUILT on branch `ua-mtx-merge` (T58–T65;
normative text [pq-zero-knowledge.md §7.12](../contracts/pq-zero-knowledge.md#pqz-proof-path)); SSTORE2 for proofs was dropped by
the owner (2026-11-07); the client side lives in the no-oracle spec.

**The idea (owner, 2026-11-06).** An immutable per-token option chosen at creation, `legProof ∈ {NONE, CALLDATA}` (no
STATE variant: a proof verifies itself, so any untrusted source can serve it). Under `CALLDATA` every credit (recipient
leg, auditor copy, op 7 legs) comes with a proof that the contract verified, so every credit in state has one. A
holder's library (`ua-rs`) or an MPC quorum member then decrypts only sums of at most `K_MAX` proven parts, fetched from
any source, after checking each proof itself; a result still goes only to the key holder.

**Inputs taken as given:** [ARCH-POS-13](../decisions.md#ARCH-POS-13) (owner: never a decryption oracle); the 8·K
rounding oracle and the open in-quorum oracle of [pqz-threshold-decrypt-prove.md](pqz-threshold-decrypt-prove.md)
§12.1, §12.5, §12.6; the no-oracle fix spec (`docs/superpowers/specs/2026-11-06-no-decryption-oracle.md` on branch
`ua-rs-sign`), which chose option (A) "proven state, checked where the chain is read" with reading-layer duties R1 to R6
and rejected option (B), certificates, as not buildable; the owner decision on an MPC quorum's fallback (§9.2).

**Evidence tags:** [repo] read from this repository; [paper] peer-reviewed; [inference] our reasoning; [estimate] our
paper arithmetic.

## 1. At a glance

| Question | Answer |
|---|---|
| Q1 Does a valid proof per part plus `≤ K_MAX` parts remove the §12.1 oracle? | **Yes, for the key** [inference]: every proven part decrypts to the digits its prover chose, whatever `s` is, so an answer is a function of the ciphertext, never of `s`. The proof must bind the digit range `[0, 16)`; without it the relation says nothing. It does **not** make a composition authentic: a source can still omit or add parts, which is a balance-privacy matter, not a key one (§3.3). |
| Q2 The holder's own `v_f` and a rolled `acc`? | The re-encryption check with CTR-PQZ-19's derived randomness works for op 1 / op 7 debits and leaks nothing about `s`, but **fails for burn and refresh** (fresh randomness) and needs the seed (not available to a quorum). The holder's own debit proof covers every debit, once its `T` is published (§4). `acc` is rebuilt from its proven parts, never decrypted as given. |
| Finding: the debit proof is already the aggregate leg proof | `R_TX` / `R_TXM` / `R_BURN` rows 2, 3, 4, 5 prove every ciphertext a debit writes (each leg, each auditor copy, `v_f`). What option (B) lacked was only the sender's `T`. If the token **logs the 640-byte header and `T`** of every debit (≈ 0.15–0.20 M gas), anyone can rebuild the statement and verify the proof from history: **no new relation, no new `proofSystemId`, no precompile change** (§5). We call it *debit-T*. |
| Q3 The in-quorum MPC oracle of §12.5? | **Closed for the key** if each member verifies every part's proof itself and sums the parts itself before it contributes a partial [inference]. Left: which sums the quorum agrees to open (a policy and privacy matter) and the fallback when proofs are lost (§9.2, owner decision). |
| Q4 Sizes and gas at the four sets | A standalone leg proof ≈ `R_DS` + 0.5 KB (29.5 / 31.3 / 33.5 / 36.5 KB); one per leg costs ≈ 4.2–4.5 M gas each, so op 1 with the auditor, op 7 M ≥ 2 with the auditor and op 7 M ≥ 4 without no longer fit 2^24. One aggregated proof per transaction fits every form but op 7 M = 8 (with the auditor never; without it only at the low estimate). debit-T fits every form that fits today (§6). PQZH cannot carry any extra proof (calldata cap); debit-T needs none. |
| Q5 Aggregation, batch verification | One proof per transaction (`R_LEGS`, rows 2, 3, 5 of `R_TXM`) is possible but is what the debit proof already is; batch verification in the wallet is parallel verification, no algebraic batching is known for LNP22 proofs [inference]. |
| Q6 Wallet cost | `n2304-kmax4096`, 4,096 credits: standalone ≈ 204 MB to fetch, debit-T ≈ 0.42–0.72 GB; verify ≈ 90 s (standalone) or 185–211 s (debit-T) single-threaded, p99 proxy [estimate]. A fresh restore needs only the parts since the last debit; where their proofs come from after a reinstall is §15. |
| Q7 What changes | debit-T: one log per debit, an immutable flag in a new catalogue version, a proof path in `ua-rs`, vectors for the log layout. A standalone relation: a new `proofSystemId`, a precompile op, vectors in every client, the full gate at four sets, and an op 7 cut. Zether: not needed for the key (§11.4). |
| Verdict | **Build `legProof = CALLDATA` as debit-T**; do not add a standalone leg relation. It gives a holder a second, proof-based decrypt path, gives an MPC quorum a key-safe path, and keeps (A) as the single holder's fallback (§12). |
| Added 2026-11-06: `T` from state (§14) | If the contract stops deleting pending slots and writes one record slot per debit, every historical `T` is a function of state (≈ 0.10 M gas per debit, flat across sets, instead of the 0.15–0.20 M log of `T`). It removes only `T`'s history dependence: the debit proof is calldata, and keeping it in state costs ≈ 65–131 M gas per PQZL debit, which does not fit. The §9 fallback stays. **Owner decisions (2026-11-06):** keep every pending slot (accepted); the wallet keeping `P`,
SCaaS nodes archiving debits and the sender handing `P` over are rejected as keepers (§14). |
| Added 2026-11-06: after a reinstall (§15) | A holder restored from its seed, offline for years, decrypts key-safely without a trusted reader if (1) every own debit carries a seed-keyed tag over its `v_f` (or burn and refresh derive their randomness as op 1 does), so it needs no own `P`, and (2) the debits of its pending credits are still served by the chain's own history. Settling (holder action) is out; a compact certificate in state does not fit. Residual: a credit older than the chain's history window → (A) with the holder's own node or a verifying light client, else refuse. |

## 2. What the option rests on

**Why chain state is safe today** [repo]. Every ciphertext enters PQZ state with a proof of exact norms; the noise of a sum
of `K_MAX` units is at most `K_MAX · B_FRESH` (worst case over proven norms), below `Δ/2`, and the decryption is unique
([pq-zero-knowledge.md §4.3](../contracts/pq-zero-knowledge.md#noise), [CTR-PQZ-03](../contracts/pq-zero-knowledge.md#CTR-PQZ-03)):
"an accepted state never decrypts wrongly or fails". The §12.1 oracle needs ciphertexts outside that set: `u` a unit
polynomial and `v_i = ⌈Δ/2⌉ + off`, so that the rounding of `−s_j[16w + i] + off` near `Δ/2` reveals one coefficient
per query; 8·K queries recover `s` (288 at `n2304-kmax4096`).

**Why (B) was rejected** (no-oracle spec §3) [repo]: a credit's only proof is the sender's debit proof, whose statement
contains the sender's `T` at that block, which is not in state; proofs live in calldata (history expiry); an op 4
`SENDER_S` proof would certify a credit without `T` but needs the sender; a keeper's rollover of an uncertified credit
would strand the account; and a forged but well-formed composition still leaks the balance through the holder's later
actions. The owner's option answers the first three (a proof per credit, verified by the contract, from history); §5
shows the first is answered more cheaply by publishing `T`; §3.3 shows the last stays and what it costs.

## 3. Q1: what a proven part guarantees

### 3.1 The argument

Let a part be a ciphertext `(u, v)` with a valid proof of

```
u = Aᵀ·r + e1,  v[i] = (pkᵀ·r)[16w + i] + e2[i] + Δ·d_i  (i < 16),  d_i ∈ [0, 16),
‖r‖ ≤ β_s, ‖e1‖ ≤ β_e, ‖e2‖ ≤ β_2  (each bound its own equation, exact)
```

for the holder's registered `pk = A·s + e` (`R_REG`-proven norms). Then `v − (uᵀ s)[window] = Δ·d + (eᵀ r − e1ᵀ s + e2)`,
noise at most `B_FRESH`. For a sum of at most `K_MAX` units built by the library itself (proven parts, `Trivial` terms
of noise 0), the noise stays below `K_MAX · B_FRESH < Δ/2` and the rounding returns `Σ d` exactly, for every key that
satisfies the registered norms [repo, §4.3]. So [inference]:

1. **No rounding near `Δ/2`, no failure.** The answer is the digit sum the provers chose, a function of the ciphertexts
   and not of `s`. A §12.1 query (`u` a unit polynomial) has no short `(r, e1)` with `Aᵀr + e1 = u` (that would be an
   MSIS / MLWE break), so it has no proof.
2. **What a querier learns.** For a part it proved itself, the answer is its own witness (knowledge soundness: an
   extractor recovers `d`). For a real part of someone else (copied from the chain with its proof), it learns that
   honest ciphertext's plaintext: a known-plaintext pair on a fresh MLWE sample, which says nothing about `s`, but is
   the other party's private amount. Sums mix the two.
3. **Formal status.** This is the classical "encrypt, then prove knowledge of the plaintext" route to chosen-ciphertext
   security (Naor–Yung 1990; Sahai 1999; Shoup–Gennaro 1998 for ElGamal with a Fiat–Shamir proof) [paper]. A full proof
   for PQZ needs simulation-sound extractability of the Fiat–Shamir proof under adaptive queries; PQZL absorbs the
   statement digest first (strong Fiat–Shamir, CTR-PQZ-19 `hash0`) [repo], the property whose absence broke weak
   Fiat–Shamir uses (Bernhard–Pereira–Warinschi 2012) [paper]. No such proof exists for LNP22 / LaZer in our reading:
   **an audit item, not a claim**.

### 3.2 What the proof must bind

| Item | Why | Under debit-T (§5) |
|---|---|---|
| `u`, `v` (64-bit lanes, every coefficient `< q`), the exact bytes the library then decrypts | the proof is about these bytes; the library compares byte for byte | the leg's offsets inside `out`, `u_{g(j)}`, `v_j` or `v_{a,j}` |
| `pk`, supplied by the **verifier** (its own key), never by the source | a proof under another key certifies nothing for this key | statement word `pk_t` (or `pk_a`, or `pk_f` for `v_f`) compared with the handle's key |
| the window `w` of an auditor copy | the copy sits at `(pk_aᵀ r)[16w + i]` | row 5, `w = j mod s_aud` |
| digits `d_i ∈ [0, 16)` | **essential**: `Δ` is invertible mod `q`, so with `d ∈ Z_q` every `v` has a witness and the proof is empty | binary digit rows of `R_TX` / `R_TXM` |
| per-block exact norms | the noise budget assumes each bound (the v1 sum-only check allowed 3.7 × `B_FRESH`) | as today (v2 and later) |
| `proofSystemId` (the set, transcript and norms) and `opTag` | the budget is per set; domain separation from other relations | header words 0 and 32 |
| location (chain, token, entry, leg) | not needed for the key; useful to tie a proof to its place | header words, `entryRef` from the sender's counter |

**Trivial entries** (a shield's `Trivial(digits(amount))`, the `shieldIn` term, a hybrid token's public units shielded)
are never taken as bytes: the library rebuilds them from the public amount (`< 2^64`), one unit, noise 0. A wrong
amount from a source gives a wrong balance, never a key leak.

### 3.3 What a proof does not give: the composition

A proof certifies one ciphertext, not that it is in the account, nor that the account has no other parts. A source can
omit a real credit, add a proven part of its own or replay an old one. Decrypting that composition is key-safe, but the
result is wrong, and any **outward action that depends on it** (a debit the wallet attempts or not, which the chain then
refuses because the contract's `T` differs) gives the source one bit about the real balance. That is the last (B)
objection, and it stays [inference]. Consequences:

- **Viewing** (the result goes only to the holder, nothing goes out): any source.
- **A debit**: the account words that fix the composition (`pendingCount`, `rolled`, `floor`, `sendCounter`, `accUnits`,
  `accBlob`, the last debit's `entryRef`) come from the reading layer under R1 (a source the holder trusts). The
  ciphertexts and their proofs may still come from anywhere. This narrows R1 from "every word" to a few account words.

## 4. Q2: the holder's own `v_f` and a rolled `acc`

Every debit writes the holder's new balance `v_f` under `u_0` (op 1, op 7 group 0) or `u′` (burn, refresh). No credit
proof covers it.

| Way | Works for | Key-safe? | Notes |
|---|---|---|---|
| (i) **Re-encryption check**: re-derive `r, e1, e2_f` from `pqzKeySeed`, the counter and the published salt (CTR-PQZ-19); require `u_0 = Aᵀr + e1` byte-exact and `v_f − pkᵀr − e2_f ∈ Δ·[0, 16)^16`; read `d′` from it | op 1, op 7 | yes: `s` is never used; the reject depends on a PRF equality the source cannot guess and on the digits | **fails for burn and refresh**: their randomness is fresh CSPRNG output, not derived (CTR-PQZ-19, owner 2026-10-13). A source that keeps the real `u_0` and adds `Δ·k` to one `v_f` coefficient is accepted or refused depending on the holder's digit (a balance bit, not a key bit). A quorum has no seed, so it would need the HKDF inside MPC. |
| (ii) **The holder's own debit proof** (`R_TX` / `R_TXM` / `R_BURN`, rows 2 and 4) | every debit | yes; only someone with `s_f` can make a proof whose statement has `pk_f` = the holder's key (row 1) | needs that debit's `T`, as for credits: §5 |
| (iii) A standalone proof for `v_f` on every debit | every debit | yes | one more proof per debit (≈ 4.2 M gas, §6) |

This is not Fujisaki–Okamoto in the CCA sense (FO derives randomness from the message, Fujisaki–Okamoto 1999,
Hofheinz–Hövelmanns–Kiltz 2017 [paper]); it is a MAC-like check of the holder's own ciphertexts, the same kind as the
`SENDER_S` disclosure path of the no-oracle spec §4.6 [repo].

**A rolled or materialised `acc`** is the last debit's `v_f` plus the entries rolled since, by addition mod `q`
(CTR-PQZ-08) [repo]. The library never decrypts the materialised words as given: it rebuilds `acc` from the parts
(`v_f` checked as above, each credit proven, each TRIVIAL entry rebuilt) and may compare the bytes, or the `accHash`,
with what a source supplies. For display it can decrypt each part alone (one unit each, so `K_MAX` never binds); a debit's
`T` has `unitsOf(T) ≤ K_MAX` by the contract's own rule.

**Recommendation:** (ii) for everyone. (i) is a cheaper shortcut for a single holder on op 1 / op 7 only; it does not
cover burns and refreshes, so it cannot be the only way. After a reinstall the holder's own `P` is in history only;
§15.3 makes every own debit checkable without it.

## 5. Finding: publish the debit's `T`, and the existing proof is the leg proof (debit-T)

The debit statement is `header (640 B) ‖ pk_f ‖ [pk_t] ‖ [pk_a] ‖ T ‖ out` (op 7: the keys of every leg)
([§7.7](../contracts/pq-zero-knowledge.md#statement)) [repo]. `out` and the proof are in the transaction's calldata; the
keys are registry state, immutable; the header words are in calldata and the receipt except `envelopeBinding` (derived
from the outer envelope), and `T` exists only in the state of that block. If the token, on a `CALLDATA` token, **emits
one log `DebitStatement(entryRef, header ‖ T)` per debit** (op 1, op 7, burn, refresh, unwrap), every piece of the
statement is in history, and:

- each credit leg is certified by rows 2, 3 (and the auditor copy by row 5) of a proof the contract already verified;
- the holder's own `v_f` by rows 2 and 4, for every debit kind;
- `T` reveals nothing new: anyone can compute it from public state at that block (`acc`, the window, `shieldIn`)
  [inference];
- the source can be untrusted for every input but the verifier's own key: a forged `T`, header or `pk_f` only makes the
  verification fail, or certifies a part the forger made itself (its own plaintext).

Cost: LOG data 8 gas per byte, `8 · (640 + CT)` plus the log's base and topics and some execution (10,000 assumed) ≈
0.15 / 0.16 / 0.18 / 0.20 M gas per debit [estimate]; no
calldata, so the EIP-7976 floor and the PQZH debits are not affected. A zero-change variant exists: rebuild `T` from an
archive node's historical state (the statement view at the transaction's position); fragile, since most nodes prune old
state, so not recommended.

| | Standalone leg relation (owner's sketch) | debit-T |
|---|---|---|
| New relation, `proofSystemId`, precompile op, full gate | yes | no |
| On-chain cost | +1 proof per leg (or per tx, aggregated) | one log |
| Fits 2^24 | op 7 cut (§6) | every form that fits today |
| PQZH tokens | does not fit (a PQZH disclosure-size proof is 190–234 KB) | fits |
| Covers `v_f` of burn / refresh | no, needs (iii) or a protocol change | yes |
| Wallet bytes per credit | ≈ 46–59 KB | ≈ 93–186 KB |
| Wallet verify per credit (p99 proxy) | ≈ 22 ms | ≈ 45–51 ms |

## 6. Q4 and Q5: sizes and gas at the four sets

**How the numbers are made** ([`leg_proof_cost.py`](pqz-leg-proof-option/leg_proof_cost.py),
[`.out`](pqz-leg-proof-option/leg_proof_cost.out)) [estimate]:

- **Standalone leg proof `R_LEG`** = `R_DS` (the sender disclosure: the same rows with the amount public) plus the
  per-leg increment of `R_TXM` without the auditor from M = 1 to 2 (16 hidden digits, one `e2`, one row): 29,469 /
  31,320 / 33,485 / 36,458 B. Verify price = the provisional PQZL `R_DS` row, 3,381,000 gas (equal at every set:
  provisional, not calibrated per set). Statement build ≈ 0.37 / 0.42 / 0.48 / 0.53 M, taken from the measured
  `verifyTransferAmount` row minus intrinsic, calldata and precompile.
- **Aggregated `R_LEGS(M, A)`** (rows 2, 3, 5 of `R_TXM`): size between `R_TXM(M, A) − (R_TX − R_DS)` and `R_TXM(M, A)`,
  price between the `R_DS` row and the `R_TXM(M, A)` row.
- **Regular gas** = max(today's measured form + the additions, 15,000 + 64 × calldata); fit = ≤ 2^24 and calldata
  ≤ 261,909 B. State gas does not change in any variant (proofs are not stored).

Regular gas in M at `n2304-kmax4096` (all four sets in the output; the verdicts are the same at every set):

| Form | Today | (a) one `R_LEG` per leg | (b) one `R_LEGS` per tx | (c) debit-T |
|---|---|---|---|---|
| op 1, auditor (2 legs) | 9.17 | 17.79 ✗ | 13.48–15.06 | 9.33 |
| op 1, no auditor | 8.88 | 13.19 | 13.18–15.19 | 9.04 |
| op 7 M = 1, auditor / none | 6.87 / 7.25 | 15.49 / 11.56 | 11.18–12.76 / 11.55–13.56 | 7.03 / 7.41 |
| op 7 M = 2, auditor / none | 7.08 / 7.17 | 24.32 ✗ / 15.79 | 11.40–13.10 / 11.48–13.33 | 7.24 / 7.33 |
| op 7 M = 4, auditor / none | 8.70 / 7.52 | 43.18 ✗ (calldata) / 24.76 ✗ | 13.29–15.52 / 11.85–13.88 | 8.86 / 7.68 |
| op 7 M = 8, auditor / none | 12.73 / 10.57 | 81.69 ✗ / 45.05 ✗ | 17.59–22.49 ✗ / 15.18–18.99 (✗ at the high end) | 12.89 / 10.73 |
| burn / refresh | 6.85 | — | — | 7.01 |

- **Proof sizes, all sets:** `R_LEG` 29.5 / 31.3 / 33.5 / 36.5 KB; `R_LEGS` at op 7 M = 8 with the auditor 71–85 /
  64–80 / 55–73 / 60–79 KB.
- **PQZH:** a disclosure-size Ligero proof is 207,688 B at `n2304-kmax4096` (bound) [repo]; PQZH debits are already
  floor-bound near 2^24, so (a) and (b) cannot be carried at any set; (c) adds no calldata.
- **Tx-size caps:** the 2^24 floor allows 261,909 B of calldata; Nethermind's `MaxTxSize` 2 MiB is headroom, not a limit
  that binds first [repo].
- **USD**, as a formula: `USD = gas × price_gwei × 10⁻⁹ × ETH_USD`. With 1 gwei and 3,000 USD/ETH (assumptions, not a
  forecast): debit-T 0.17 M ≈ 0.51 USD per debit; one `R_LEG` ≈ 4.2 M ≈ 12.60 USD per leg.

**Q5, aggregation.** One proof for all legs of one transaction is `R_LEGS`; its size grows like `R_TXM` with `M`
(one `u_g` row per group, one `v` row and 64 digit bits per leg and copy). The debit proof already has these rows, so the
aggregate is free under debit-T. **Batch verification in the wallet** is running the verifier on many proofs in
parallel; we know of no algebraic batching of LNP22 verifications (unlike Bulletproofs' MSM batching) [inference], so
the cost is linear in the number of proofs and parallel across cores.

## 7. Q6: wallet cost and availability

| Set (`K_MAX`) | Standalone, per credit / all | debit-T, per credit / all |
|---|---|---|
| `n2048-kmax1024` | 46.0 KB / 47 MB | 93–186 KB / 95–191 MB |
| `n2304-kmax4096` | 49.9 KB / 204 MB | 103–175 KB / 422–718 MB |
| `n2560-kmax16384` | 54.1 KB / 886 MB | 113–158 KB / 1.9–2.6 GB |
| `n2816-kmax65536` | 59.1 KB / 3.9 GB | 124–172 KB / 8.1–11.3 GB |

(debit-T counts the sender's key every time; a cache of senders' keys lowers it.) **Verify time** [estimate]: the
provisional row ÷ 1.3 (the provisional factor) ÷ 0.12 M gas per ms of p99 verify (the calibration ratio of
[§9](../contracts/pq-zero-knowledge.md#gas)) gives ≈ 22 ms for `R_DS`, 45 ms for `R_TX`, 51 ms for `R_TXM` M = 8 with the
auditor, p99 on the chain host: 4,096 credits ≈ 90 s or 185–211 s on one core, divided by the cores used. A wasm wallet
is slower. Not measured.

**What a wallet really verifies.** Only the parts of the current balance: the last debit and the entries since its
`p`. Each part may be cached by the wallet, but nothing relies on that cache (owner 2026-11-06, §14): the bulk cost above is what a
reinstalled wallet pays (§15). The pending queue is unbounded (CTR-PQZ-06), so a decoy flood makes a fresh restore verify more proofs;
each decoy costs its sender a debit and pays the victim `decoyFee`, as today.

**History expiry** (EIP-4444): proofs, payloads and logs are in block bodies and receipts, which expire; state does not.
A part whose proof material is no longer served anywhere can no longer be checked by the proof path; §9 covers the
fallback, §15.2 what expires where.

## 8. Two decrypt paths in `ua-rs`, two commands

Explicit parameters: one command per operation, no mode flag. Both take named location fields and return
`{value, ...}` to the caller only; every refusal before the key is used is the one status `Argument` with no detail (as
the no-oracle spec §4.3).

**Path (A), every token** (no-oracle spec §4.3 to §4.5, unchanged): `balance {chainUid, token, ua, block, words}` and the
debit commands with `words`; the reading layer bears R1 to R6 for every word.

**Proof path, only for a token created with `legProof = CALLDATA`** (debit-T form):

```
balanceProven {
  chainUid, token, ua, proofSystemId,
  lastDebit: { entryRef, header, t, out, proof, pkFrom } | null,        // null: never debited, acc = Trivial(0)
  credits:   [ { index, entryRef, leg, header, t, out, proof, pkFrom, pkOthers[] } ],
  trivials:  [ { index, amount } ]
}
```

Checks, all before the key: the token's set equals the handle's `proofSystemId`; each statement is rebuilt by the
library (`header ‖ keys ‖ t ‖ out`, the holder's own key inserted where the statement names it; `pkOthers` are the
other legs' and the auditor's keys) and verified with the library's own verifier; the credit's `(u, v)` are read from
`out` at the leg's offsets; `lastDebit`'s statement names the holder as sender; indexes contiguous from the last debit's
`p`; every coefficient `< q`. Output: `{value, parts}`. The debit commands of the proof path (`proveTransferProven` and
so on) take the same lists plus the account words of §3.3 (`pendingCount`, `rolled`, `floor`, `sendCounter`,
`accUnits`, `accBlob`), which the reading layer supplies under R1. A refusal after the key is used exists only for a
debit (balance below amount + fee) and goes to the caller.

**Who uses which** [inference]. A single holder may use either for a `CALLDATA` token: (A) when it has a trusted source,
the proof path when it does not or wants fewer trusted words. An MPC quorum member uses **only** the proof path; it never
decrypts through (A) (that is §12.5 again).

**Downgrade.** `legProof` is immutable, so nobody switches a token. Under `CALLDATA` the contract itself emits the log
on every debit after verifying its proof (a sender cannot omit or alter it), so every ciphertext a debit writes is
certified; every other write is a TRIVIAL entry or a sum of existing parts. A
forge invariant must check this on every write path (op 1, op 7, burn, refresh, unwrap, shield, rollover, un-roll,
migration). An attacker who withholds proof material can push a holder toward (A): for a single holder (A) under R1 to R6
is safe, and without a trusted source the holder simply cannot view (liveness, not key). The path chosen depends on
availability, never on a decryption, so the choice itself is not an oracle bit.

## 9. When proof material is lost

### 9.1 A single holder: fall back to (A) (controller recommendation, 2026-11-06)

When the proof material of a needed part is gone from every source, the holder uses path (A). Safe under R1 to R6 (the
no-oracle spec's chosen construction): the words come from a source the holder trusts and nothing goes back. Without
such a source the wallet refuses (one status) rather than decrypt.

### 9.2 An MPC quorum: no (A); rebuild the seed and rotate (owner decision, 2026-11-06)

Falling back to (A) would bring back §12.5: a member supplying "state" to the others is the in-quorum oracle. **Owner
decision (2026-11-06):** when leg proofs are lost, `k` members rebuild `seed32` from the k-of-n backup (T16a / T16b,
built on `ua-rs-sign`), one member becomes the operator of option (A), and the operator rotates the account to a new key
version (spec 3g, `docs/superpowers/specs/2026-11-06-pqz-key-versions.md`, migration KV-9). It fits the dealer model of
the research note: each key version comes with fresh (A) shares of its `seed32`.

- **Cost:** from reconstruction to rotation the operator holds the whole key (the threshold protects nothing in that
  window); the old version's shares are kept, never deleted; the migration is a debit, so the operator decrypts the old
  balance once, as a single holder under R1 to R6.
- **What the operator never does:** decrypt a ciphertext a member supplies (§12.6, (A)'s rule): it reads the chain itself.

### 9.3 Making the fallback rare

| Measure | Status |
|---|---|
| The wallet keeps the proof material of every part it verified on arrival | **rejected as the keeper** (owner 2026-11-06): a wallet can be wiped and reinstalled. A local cache is a convenience nothing relies on |
| Each quorum member keeps every proof it verified | the same reasoning: a convenience, not a keeper (a member's device can be lost too) [inference] |
| An archive in `scaas-node`'s indexer, serving debit material by `entryRef` | **rejected** (owner 2026-11-06): not related to the node's job |
| The sender hands `P` to the recipient | **rejected** (owner 2026-11-06, §14.7) |
| What is left | §15: own debits made self-checkable, third parties' debits from the chain's own history, (A) beyond it |

**Withholding as an attack** [inference]. For a single holder: it gains nothing about `s`; at most it forces (A) or a
refusal. For a quorum: it can push toward §9.2, a period with one operator holding the key. Any full node or history mirror of
the chain that still serves the debit defeats it, and reconstruction needs `k` members, so an outsider cannot trigger it
alone; members should declare the material lost only after the chain's history was tried from several sources.

## 10. Q3: the in-quorum oracle of §12.5

With the proof path, a member contributes a partial decryption only to a sum it built itself from parts it verified
itself (each a proven credit to the quorum's key, the account's own `v_f` with its debit proof, or a TRIVIAL entry from
its public amount), at most `K_MAX` units. Then the opened `M` is a digit sum fixed by the parts' provers, and the C1
rounding opens only a uniform mask and `M` (§12.1) [repo]; so a member cannot recover `s` [inference]. Earlier the owner
chose neither "read state yourself" nor "check a well-formedness proof" (§12.5), when no such proof existed for a
credit; debit-T gives the second one substance. What is left:

- **Policy, not key:** a member can ask to open a single real credit, learning its amount. Which sums the quorum opens,
  and to whom, is the quorum's access rule (every opening approved by the members).
- **Composition** (§3.3): members agree on the account words for a debit; a wrong composition makes the debit fail on
  chain; within the quorum that reveals nothing members do not already see.
- **Availability**: §9.2.
- **Malicious security of C3, the dealer (C2), the proof of §3.1**: unchanged open items; the quorum is not built.

## 11. Q7: what it changes

### 11.1 debit-T (recommended)

- **Contracts:** one immutable `legProof` set at `initialize`, a new catalogue version (nothing deployed is upgraded);
  the log in the shared debit step (`PqzCore`, called from `PqzTransferLib` and `PqzBurnLib`). Code size: small; this
  worktree's `size-baseline.json` gives `WrappedPqzToken` 56,721 B, `WrappedPqzRegulatedToken` 62,285 B (the tightest
  under 64 KiB) and `PqzTransferLib` 17,697 B; the change belongs in the libraries [repo] [estimate]. Layout and typehash
  pins unchanged (no storage).
- **pqz-core:** none: no relation, transcript, `proofSystemId` or precompile change, so no full gate.
- **Vectors:** the log layout and "statement rebuilt from history equals the contract's" at the default set and one other,
  read by `ua-rs` and by the C ABI (`ua-c`) the bindings call.
- **`ua-rs`:** the proof-path commands of §8, the verifier on the device (it is already linked through `pqz-ffi`).
- **Node:** at most, the indexer normalises the new event. No archive rule (rejected by the owner, 2026-11-06, §14).

### 11.2 A standalone relation (not recommended)

A new relation is a new `proofSystemId`, new vectors in every client, a new precompile op in pqz-ffi and the Nethermind
plugin (a new chainspec schedule, also on customer chains), the full gate at four sets (hours each), PQZL only (PQZH does
not fit), an op 7 cut (§6), and burn and refresh still need debit-T or (iii) for `v_f`.

### 11.3 PQZH

debit-T applies unchanged: the wallet verifies the Ligero proof (≈ 250 KB per debit to fetch) [repo, sizes].

### 11.4 Zether

Zether's lifted ElGamal has no key-recovery oracle (ARCH-POS-13) [repo]; its transfer proof also contains the sender's
balance ciphertext (Σ row `A_bal` over `D_acc`, [zether.md §8.1](../contracts/zether.md)) [repo], so a "proof per leg"
would have the same shape problem. The rule's privacy side is met by (A). **Not needed for Zether**; Zether ≠ PQZ, so
nothing here applies to it.

## 12. Verdict and roadmap

**Verdict.** The owner's option is sound for the key [inference, UNAUDITED]: a proven part plus the library's own sum
and `K_MAX` count removes the §12.1 oracle, for a holder, an auditor desk and a quorum member alike. Its cheapest form is
**debit-T**: the existing debit proof, made checkable from history by logging `header ‖ T`. It does not remove the need
for a trusted source of the account words before an outward action (§3.3), and it depends on history (§9).

| Step | Work | Agent-days [estimate] |
|---|---|---|
| R1 | Fable + Codex review of this note (crypto spec rule), then decisions entry | 1–2 |
| R2 | Contracts: `legProof` immutable, `DebitStatement` log on every debit form, forge tests (log equals the verified statement; refuse-path; invariant of §8), size gate at four sets | 3–4 |
| R3 | Vectors: log layout and statement rebuild, default set + one other; `ua-c` reader | 1–2 |
| R4 | `ua-rs` proof path: `balanceProven` and the debit commands, one status, negative tests (forged `T`, wrong key, swapped leg, count above `K_MAX`, non-canonical coefficient), mutants, the 8·K harness as a negative test | 5–7 |
| R5 | ~~Node: archive rule~~, dropped (owner 2026-11-06: not the node's job) | 0 |
| R6 | Docs: `pq-zero-knowledge.md` (option, log, proof path), `ua-libraries.md` (proof path; a cache is optional, nothing relies on it), §12.5 status, Vietnamese copies | 1–2 |
| | **Total** | **11–17** |

The quorum service itself stays C3 (not scheduled). A standalone relation would be ≈ 30–45 agent-days plus four full
gates and does not cover burn and refresh.

## 13. Open questions for the owner

1. **Build `legProof = CALLDATA` as debit-T** (the token logs `header ‖ T`; the debit proof certifies every ciphertext)
   rather than a new standalone leg relation? *Recommendation:* yes: no new relation or precompile op, fits every form
   and PQZH, covers `v_f` of every debit.
2. **§12.5 for account keys:** record the proof path (each member verifies and sums the parts itself; the §9.2 fallback)
   as the resolution, status "resolved on paper, UNAUDITED", pending the review of R1? *Recommendation:* yes; the
   quorum stays unbuilt until C3 is scheduled.
3. **Archive in the node:** add a PLANNED rule that `scaas-node`'s indexer stores and serves the debit material of
   `CALLDATA` tokens by `entryRef`? **Decided (owner 2026-11-06): no**, it is not related to the node's job. Where the
   material comes from instead: §15.

## 14. debit-T from state: keep T's parts and store references (2026-11-06)

**Question (owner, 2026-11-06, direction 2).** Logging `header ‖ T` (§5) depends on history (EIP-4444), and storing `T`
whole costs ≈ 21 M (SSTORE2) or ≈ 41 M (fresh slots) at `n2304-kmax4096`, which was rejected. Can the contract instead keep
the parts `T` is made of, which are already in state, and store a short reference per debit, so that every historical `T`
rebuilds from state alone? Read against `PqzCore.sol` and `PqzStateLib.sol` on branch `ua-mtx-merge` (line numbers below);
arithmetic in [`debit_t_state.py`](pqz-leg-proof-option/debit_t_state.py) and
[`.out`](pqz-leg-proof-option/debit_t_state.out). Nothing was measured.

**Owner decisions (2026-11-06)** on this section:

1. **Accepted: keep every pending slot for good** (+32 B per credit and per debit), so that every `T` is a function of
   state (§14.2). This reverses the deletion rule of [pq-zero-knowledge.md §7.4](../contracts/pq-zero-knowledge.md#transfer)
   and the state spec's §5.5; a `decisions.md` entry is needed when it is built.
2. **Rejected: "the wallet keeps `P` when the credit arrives"** as the keeper of the proof: a wallet can be wiped and
   reinstalled.
3. **Rejected: "SCaaS nodes archive debit transactions"**: it is not related to the node's job.
4. **Rejected earlier the same day:** the sender handing `P` to the recipient (§14.7).
5. **Remark on settling:** a cold wallet cannot settle pending credits regularly, so no design may need the holder to act
   periodically (§15.4).

Where the debit material comes from instead, for a holder offline for years who reinstalls: §15.

### 14.1 What `T` is made of, and what is lost today

`_total` (`PqzCore.sol` 748–767) [repo]: `T = reduce(acc ± Σ pending[window) + Trivial(digits(shieldIn)))`, with the window
`[rolled, p)` when `p ≥ rolled` and `[p, rolled)` (subtracted) when `p < rolled`, `|p − rolled| ≤ INLINE_MAX` (10 for a PQZH
op 7).

| Part of `T` | Where it lives | Written or changed | Lost today [repo] |
|---|---|---|---|
| `acc` as a reference `(accBlob, accU, accV)`: the previous debit's `(u_0, v_f)` (burn, refresh: `(u′, v_f)`) | the previous debit's op blob (SSTORE2, never deleted) and three account fields | `_debit` 861 | the blob stays; the account fields are overwritten by the next debit (861), and that debit's `p` survives only until the next rollover moves `rolled` / `floor` (862; `PqzStateLib` 100–108) |
| `acc` materialised: `accWords` (339 / 417 / 504 / 598 slots) and `accHash`, or the calldata hint whose keccak equals `accHash` | slots | every rollover rewrites every word in place (`PqzStateLib` 92–96, 99); a debit clears `MAT` (861) | overwritten at every rollover; a cache: it equals the previous `v_f` plus the rolled entries, mod `q` |
| a credit: `pending[i] = blob ‖ uOff ‖ vOff ‖ block` | one slot pointing into the sender's blob | `_credit` 334–340 | the slot is deleted by the next debit for `[cleared, p)` (863) and by a rollover for `[cleared, rolled − INLINE_MAX)` (`PqzStateLib` 106); the ciphertext stays in the sender's blob |
| a TRIVIAL entry `(amount, block)` | the slot only | `_trivial` 348–364 (merged into the tail only while it is still pending, same block) | deleted with its slot; the amount survives only in the `Shielded` event |
| `Trivial(digits(shieldIn))` | header word 480 (calldata) | — | never in state |

The events (`Debited(ua, p, p, blob)`, `Credited`, `Shielded`, `RolledOver`) carry all of it, but they are history.

**An identity** [inference from the code]. Let `p_k` be the `p` of the holder's debit with counter `k` and `B_k` its op
blob (`B_{−1}` = `Trivial(0)`, `p_{−1}` = 0). For every path (a referenced or materialised `acc`, with or without the
hint, a window up or down, any rollovers in between):

```
T_k = reduce( (u, v_f) of B_{k−1}  +  Σ_{i ∈ [p_{k−1}, p_k)} entry_i  +  Trivial(digits(shieldIn_k)) )
```

After debit `k − 1`, `acc = B_{k−1}` and `rolled = floor = p_{k−1}` (861–862); a rollover adds entries in order
(`PqzStateLib` 86–88); a down window subtracts as `+ (q − y)` (`PqzCt.addBlob`, `neg`); every lane is reduced mod `q`
at the end, so the result is the canonical residue and the sums telescope to `[p_{k−1}, p_k)`, a range that exists since
`p ≥ floor ≥ p_{k−1}` (752). The units rule (762–766) gives `unitsOf(T_k) = (p_k − p_{k−1}) + 2 ≤ K_MAX`, so
`Δp_k ≤ K_MAX − 2` (the first debit: `p ≤ K_MAX − 1`). A consumed entry never changes: a TRIVIAL merge touches only the
tail at an index `≥ max(floor, rolled)` (354–355). **So the materialised `acc`, `accHash`, the hint and the rollovers are
caches: none of them is needed to rebuild `T`.** What is needed: the previous debit's blob, `p_{k−1}`, `p_k`, the entries
in between, and `shieldIn_k`.

**How the proof binds `T`** [repo]. `T` sits verbatim in the statement after the keys (op 1: 271, op 7: 481, burn and
refresh: 604); the signed `PqzAuth` covers it through `bodyHash = keccak256(statement[640:])` (`authDigest`, 839–851); the
precompile verifies the proof over the whole statement (PQZL absorbs the statement digest first, CTR-PQZ-19). No hash of
`T` is stored or logged today, and none is needed: a wrongly rebuilt `T` makes the verification fail, as in §5.

### 14.2 The minimal change

1. **Stop the two deletions** (`PqzCore.sol` 863, `PqzStateLib.sol` 106). `cleared` and `floor` keep their updates, so
   `floor` still bounds an un-roll to `INLINE_MAX` and `cleared` only marks where the contract stops reading. No existing
   slot moves.
2. **One record per debit**, written in `_debit`, keyed by the debit's `entryRef` (the CTR-PQZ-23 id; a burn computes it in
   `_sent` and today discards it, 555): `debitRec[entryRef] = { blob(160) ‖ p(64), shieldIn }`, the second word written
   only when `shieldIn ≠ 0`. `uOff` / `vOff` are not stored: `v_f` is at `blobLength − VP`, and `u` at 0 for a burn or
   refresh blob (length exactly `CTP`) and at 16 for a transfer blob (always longer). A one-word variant `blob ‖ Δp(32) ‖
   shieldIn(64)` exists (`Δp < 2^16` at every set, `shieldIn ≤ 2^62`), but a reader then sums `Δp` over every earlier
   debit; we take the two-word form. One view, named fields: `pqzDebitRecord(ua, counter) → (blob, p, shieldIn)`.
3. **Log the header only** (optional, §14.6): `DebitHeader(entryRef, header)`, 640 B.

**Rebuild** (a wallet, or any untrusted server whose answer the proof then checks), for the debit of `from` with counter
`k`:

1. read `rec_k` and `rec_{k−1}` (none for `k = 0`: `Trivial(0)`, `p = 0`);
2. `(u, v_f)` from `blob_{k−1}` (`eth_getCode`, packed coefficients expanded to 64-bit lanes);
3. for `i` in `[p_{k−1}, p_k)`: `pending[from][i]` (`pqzPending`, or `pendingCt`): a credit's `(u, v)` from its blob, a
   TRIVIAL entry as `Trivial(digits(amount))`;
4. add in 64-bit lanes, add `Trivial(digits(shieldIn_k))`, reduce mod `q`: that is `T_k`;
5. build the statement (`out` from `blob_k` too: `u_g`, `v_j`, `v_{a,j}`, `v_f`; keys from the registry; the header words
   of §14.6) and verify the proof.

### 14.3 Cost on paper, all four sets

The record is one slot whatever the set, so the figures are the same at every set except the rollover column
[estimate]:

| Item | State gas (EIP-8037) | Regular gas |
|---|---|---|
| record, every debit (op 1, op 7, burn, refresh, unwrap) | +97,920; +97,920 more when `shieldIn ≠ 0` | ≈ +5,000 |
| deletions skipped by a debit (0 to `2·INLINE_MAX` = 32 slots) | 0: clearing a slot that existed before the transaction gives no state gas back (EIP-8037) | −12,100 gross per slot (EIP-8038 2,100 + 10,000): up to −0.39 M. The payer also forgoes the clear refund (4,800 per slot at Osaka; the Amsterdam figure is not in the repo) |
| rollover (deletions skipped, up to `ROLL_MAX`) | 0 | up to −1.16 / −0.97 / −0.77 / −0.39 M gross |
| `mtxPrepareAcc` | 0 | 0 |
| header-only log (optional) | 0 | ≈ +0.01 M |

Net per debit, as the payer sees it: +0.10 M with no deletion skipped, down to ≈ −0.13 M with 32 skipped. Compare: a log of
`header ‖ T` costs 0.15 / 0.16 / 0.18 / 0.20 M (it grows with `CT`); `T` whole costs 16.8 / 20.6 / 24.8 / 29.4 M in SSTORE2
or 33.2 / 40.8 / 49.4 / 58.6 M in fresh slots. Direction 2 with the header log costs ≈ 0.11 M at most, flat across sets:
about a third less than the log, and about 200 times less than storing `T`.

**Fit.** Regular gas moves by at most +5,000 and usually falls, so no form gets closer to 2^24 (EIP-7825). `tx.gas` grows
by ≈ 0.1 M of state gas. A debit already carries 17.6–70.5 M of state gas, so this adds at most 0.6 %; it changes no
verdict of EIP-8037 inclusion. `PQZ_DEBIT_MIN_GAS` and the gas pins move only after a measurement, which needs the
owner's word.

### 14.4 State growth and the limits it touches

- **Per credit:** +32 B, kept for good. Its 97,920 state gas was paid when the credit was written, and clearing never
  gave it back. **Per debit:** +32 B, or +64 B with `shieldIn`. Today's op 1 blob with the auditor is 11,052 / 13,572 /
  16,348 / 19,380 B (CTR-PQZ-07), so the growth per debit is under 0.6 %. Per account the growth is `32 · (credits +
  debits)` B: 32 MB for 10^6 credits [estimate].
- **The unbounded queue** (CTR-PQZ-06): every decoy now leaves 32 B for good. As today, each decoy costs its sender a debit
  and pays the victim `decoyFee`. This reverses the reason given in [pq-zero-knowledge.md §7.4](../contracts/pq-zero-knowledge.md#transfer)
  ("keeps state from growing by 32 B per credit forever") and in the state spec (§5.5), so it is a rule change and needs a
  decisions entry.
- **`ROLL_MAX`, `mtxPrepareAcc`, `K_MAX`:** the rules do not change. A rollover gets cheaper because it no longer deletes,
  so the pinned rollover figures (`PqzStatePinGasTest`) can only fall, and the tight `n2560-kmax16384` margin (6,032 gas)
  cannot get worse. Raising `ROLL_MAX` would need a rollscan, and a rollscan needs the owner's word. `Δp ≤ K_MAX − 2`
  already follows from today's units check.
- **Code size:** two loops go; one store, the view and the optional event come in, which is a few hundred bytes in
  `PqzTransferLib` (17,697 B), `PqzBurnLib` (10,074 B) and `PqzStateLib`, plus the view's selector on the tokens. The
  largest PQZ token row, `WrappedPqzRegulatedToken`, is 62,285 B, far under the 131,072 B ceiling (CTR-GOV-19)
  [estimate].
- **A wallet without a server:** to rebuild a third party's `T` itself, a wallet fetches the `Δp` entries. Usually that is
  1 to 16 (13–213 KB at `n2304-kmax4096`). The worst case is `K_MAX − 1` entries: 11 MB / 55 MB / 264 MB / 1.25 GB, against
  18.5 KB for `T` in a log. Any indexer can compute `T` once and serve it, and the proof checks it, so only a wallet with
  no server at all pays the worst case.

### 14.5 Against the rules

- **Never lose ciphertext:** strengthened. Ciphertexts already stay, since blobs are never deleted. What is lost today is
  the composition: which ciphertexts made up `T`, and the TRIVIAL amounts. Direction 2 keeps it, so every `T` a debit
  proved over is a function of state.
- **Explicit parameters:** no new entry point or argument. The record is internal storage; the view returns named fields.
- **Layout pins:** `scaas.pqz` (`PqzStorage`) is not in `test/v2/layout/namespaces.json` today [repo]. Appending a mapping
  moves no slot; pinning `scaas.pqz` in the same change is advised. Typehashes, `PqzAuth`, statements and `proofSystemId`
  do not change, so no relation vectors and no full gate. New vectors are needed only for the record and the rebuild.
- **Immutability:** a new catalogue version of the PQZ kinds and libraries; nothing deployed changes. All chains are
  test-only, so no migration.
- **One rule on every chain:** PQZ tokens exist only on EVM. Soroban has none (NET-SOR-26), and the other families' trees
  hold no PQZ token [repo]. If one is ever built, the same rule applies there (keep the entries, one record per debit),
  but holding state costs differently [inference]: Soroban's persistent entries need TTL extension (archived entries can
  be restored), NEAR locks balance per stored byte (deleting would release it), and Algorand boxes raise the minimum
  balance.

### 14.6 Does it remove the history dependence? No, only `T`'s part

The proof is calldata. A `T` rebuilt from state is public, since anyone can compute it. What certifies a credit is the
proof `P` verified over the statement, so a state-only `T` without `P` certifies nothing. [inference]

- **Still needed from history:** the debit transaction itself. It carries `P` and the header words that are not in
  state: `beneficiary`, `fee` (op 7: `txFee + M·decoyFee`), `amount` and `recipient` (burn; they also tell a burn's
  `opTag` from a refresh's), `validUntilBlock`, and `envelopeBinding` (the relay envelope and the mode). Every other
  statement input is in state under direction 2: the header's identity words, `to` or `recipientsHash`, `auditorOn` and
  `salt` from the blob, `memoHash` from `memos`, `p` and `shieldIn` from the record, the keys from the registry, `out`
  from the blob and `T` from §14.2.
- **Keeping `P` in state as well** [estimate]: op 1 with the auditor needs +65.8 / 71.8 / 77.6 / 84.5 M of state gas, a
  burn +64.5–83.2 M, op 7 M = 8 with the auditor +111.9–131.0 M, and a PQZH debit ≈ +385 M at `n2304-kmax4096`. An op 1
  would then need `tx.gas` ≈ 92–125 M. That is over a 60 M block (the C0-10 reference) and over the SCaaS testnet node's
  64 M `max_gas_per_tx`, and under "no block limit of ours" it cannot be relied on anywhere. It also needs 2 to 4 code
  chunks at the public 24,576 B limit, and the state per debit grows to 2.8–3.9 times today's blob. **Not viable.** Storing
  the missing header words (about six words) would be pointless without `P`.
- **Conclusion:** direction 2 removes the history dependence of `T` only. The §9 fallback stays: (A) for a single holder,
  and for a quorum, rebuild the seed and rotate. What a holder must still fetch from history shrinks to the debit
  transaction (its calldata), with no receipt; where it comes from is §15 (the node archive is rejected). The `header ‖ T` log is no longer needed; a header-only log is a
  convenience that spares every client from rebuilding `envelopeBinding` out of the outer transaction.
- **What it does give:** (1) the cost per debit falls from 0.15–0.20 M to ≈ 0.10–0.11 M, flat across sets; (2) `T` depends
  neither on receipts nor on archive state nodes (the zero-change variant of §5); (3) the composition of every past debit
  is in state, so §3.3's account words for a past debit can be checked against state; (4) any server can serve `T`, and
  the proof checks it.

### 14.7 Retention: who keeps the proof (owner remark and decisions, 2026-11-06)

The owner's remark: "outside parties won't store the proofs", and the decisions of 2026-11-06 at the head of §14. Taking
them as given [inference unless tagged]:

1. **What a holder needs.** Only the debit material (the debit transaction with `P`, plus `T` or its record) of the
   credits since its own last debit, together with its own last debit. A debit consumes at most `K_MAX − 2` entries; the
   queue is unbounded, so decoys beyond that belong to a later debit. Nothing older is needed: a past composition only
   matters for an audit.
   - **Its own last debit:** for op 1 and op 7, `v_f` is checked by the re-encryption check of §4 (i). That needs the
     seed, the counter and the salt from the blob, all in state, and no `P`. For a **burn or refresh** it is not: their
     randomness is fresh (CTR-PQZ-19), so today the only proof-based check is the holder's own `P`, which after a
     reinstall exists only in history [repo, §4]. §15.3 removes that need.
   - **An MPC quorum** has no seed, so it needs `P` for its own last debit of every kind (§4).
2. **Who could keep it, and the owner's rulings.**
   - The recipient's wallet, keeping the material on arrival: **rejected as the keeper** (owner 2026-11-06). A wallet can
     be wiped and reinstalled; a local cache is a convenience nothing relies on.
   - The sender handing `P` to the recipient over a memo-like channel: **rejected by the owner (2026-11-06)** as not done
     and not reasonable. No such channel exists today either [repo]: the sealed memo is 41 B on chain (CTR-PQZ-23).
   - Nodes SCaaS runs (`scaas-node`, an archive of debit transactions): **rejected by the owner (2026-11-06)**, not related
     to the node's job.
   - The chain itself: its full nodes keep block bodies for as long as the chain's configuration says. For chains SCaaS
     runs (22776, the SCaaS testnet) this is a chain setting, owner-only for 22776; customer chains choose for themselves
     (§15.2).
3. **What is lost when the material is gone:** only the proof path. Funds stay spendable through the fallbacks: (A) for a
   single holder, and for an MPC quorum, rebuild `seed32` k-of-n, then an operator, then a key rotation (owner decision,
   §9.2).
4. **The residual case:** a pending credit whose debit transaction no full node or history mirror of that chain still
   serves (the chain expires history and the holder was away longer). That case does not change between the two forms.
   Direction 2 rebuilds `T` from state, but `P` and the header words are gone just the same, so both forms end in the
   same fallback.

**What this means for direction 2 against logging `T`.** The availability gain of direction 2 is small: in both forms
the proof comes from the chain's own history (§15). What remains is cost (≈ 0.10–0.11 M against 0.15–0.20 M per debit),
no dependence on receipts, the composition of every debit in state, and an indexer that can serve `T` without having
watched the logs. Set against that are the permanent +32 B per credit and per debit and the reversal of a recorded rule,
which the owner accepted (2026-11-06).

### 14.8 Verdict, effort, owner questions

**Verdict** [inference, UNAUDITED]. Direction 2 is sound and cheap. Every debit's `T` becomes a function of state if the
contract stops deleting pending slots and writes one record per debit; the materialised `acc` and the rollovers are not
needed for the rebuild. It replaces the `T` half of the debit-T log at about two thirds of its cost, flat across sets. It
does **not** remove the dependence on history: the proof and six header words stay in calldata, and the proof does not
fit in state. In both forms the proof comes from the chain's own history (§15; the wallet and node keepers are
rejected, §14.7), and the residual case falls back to (A) or the §9.2 rotation in both. The choice therefore rests on
cost and on the composition being in state, not on availability. Form of debit-T: **`T` from state plus a header-only
log**, in place of logging `header ‖ T`; the owner accepted keeping every pending slot (2026-11-06), which this form needs.

| Step | Work | Agent-days [estimate] |
|---|---|---|
| D2-1 | Contracts: drop the two deletions, add the record, the view and the header log. Forge tests: `T` rebuilt from state equals the statement's `T` after random runs of credits, shields (same-block merges included), rollovers, un-rolls, op 1, op 7, burn, refresh and unwrap. Pin `scaas.pqz`; size gate at four sets; gas pins old → new after measurement (the owner's word) | 3–4 (in place of §12 R2) |
| D2-2 | Vectors: the record word and one rebuild row, at the default set and one other; the rebuild in `ua-rs` and `ua-c` | +1–2 |
| D2-3 | ~~Node: the indexer serves `T` and archives the debit transaction~~, dropped (owner 2026-11-06: no node archive); any client or server rebuilds `T` from state | 0 |
| D2-4 | Docs: `pq-zero-knowledge.md` §7.1, §7.4, CTR-PQZ-07; a decisions entry reversing the deletion; the Vietnamese copies | +1 |
| | **debit-T in this form, in all** | **≈ 13–20** (§12 without R5, R2 replaced by D2-1, plus D2-2 and D2-4); §15's own-debit tag adds 2–4 |

**Owner questions**

1. **Keep every pending slot for good** (+32 B per credit and per debit), so that every `T` is a function of state? This
   reverses the state spec's §5.5. **Decided (owner 2026-11-06): yes**; a decisions entry is written when it is built.
2. **Header:** log the 640-byte header (≈ 0.01 M), or let every client rebuild it from the transaction's calldata,
   including the relay envelope's binding? *Recommendation:* log it.
3. **Proof availability:** accept that the debit proof stays in history (in state it costs ≈ 65–131 M per PQZL debit and
   does not fit), so that the §9 fallback stays and the proof comes from the chain's own history (§15)? The wallet and
   node keepers are rejected (owner 2026-11-06). *Recommendation:* yes; §15's questions refine it.

## 15. Where the debit proof comes from after a reinstall (2026-11-06)

**Question (owner, 2026-11-06).** A holder whose wallet was wiped and restored from its seed, or a cold wallet that was
offline for years, must decrypt its balance key-safely. The wallet does not keep `P`, the sender does not hand it over,
SCaaS nodes do not archive it, and the holder cannot be asked to act periodically (§14, owner decisions). Where can the
debit material come from, or how can the need for it be avoided, without trusting the state reader of path (A)?

**The trade-off** [inference]. A decrypt is key-safe when every part is a proven ciphertext (§3.1). Either the reader
vouches that the parts are chain state, which the contract proved (path (A), [ARCH-POS-13](../decisions.md#ARCH-POS-13)),
or the holder checks the evidence itself. Evidence the holder can check alone is of two kinds only: a proof, or a value
keyed by the holder's own secret. Anything else (a flag, a hash or a counter in state) is again trust in whoever read the
state. Every option below is one of the three.

Tags as above, plus **[web]**: a client's documentation or an announcement read on 2026-11-06, not peer-reviewed.

### 15.1 What a reinstalled holder needs

With `T` from state (§14, accepted), the balance is the last own debit's `v_f` plus the entries `[p_last, pendingCount)`.
TRIVIAL entries are rebuilt from their amount in state. Two needs remain [repo, §14.1, §14.6]:

- **N1, its own last debit.** For op 1 and op 7 the re-encryption check of §4 (i) already works from the seed and state.
  For a burn or refresh, only the holder's own `P` certifies `v_f` today, and after a reinstall `P` is in history only.
- **N2, third parties' debits.** For each pending credit, the sender's debit transaction: `P` and about six header words.
  The pending slot keeps the block number (`blob ‖ uOff ‖ vOff ‖ block`), so the client knows which block to fetch; it
  finds the debit among that block's transactions by rebuilding the candidate statements.

For a cold wallet, N2 covers every credit since its last own debit, possibly years of them, decoys included.

### 15.2 (a) The chain's own history

**What is fetched** [estimate, §7]. One block body per pending credit; at `n2304-kmax4096` ≈ 93–186 KB per credit (the
sender's key included), verify ≈ 45–51 ms each (p99 proxy, one core); a PQZH debit ≈ 250 KB. Any full node, public
endpoint or mirror of the chain can serve it: forged calldata only makes the verification fail (liveness, never key).

**Who expires history** [web]:

- **Ethereum mainnet and Sepolia:** partial history expiry (EIP-4444) has been supported by every execution client since
  July 2025. It drops pre-Merge block bodies and receipts only. Geth: opt-in from v1.16.0 (`geth prune-history`;
  `--history.chain postmerge` for a new node). Nethermind: on by default from 1.32.2 for newly synced nodes, through the
  ancient barriers (`Sync.AncientBodiesBarrier`, `Sync.AncientReceiptsBarrier`). Pruning applies to mainnet and Sepolia
  only. The expired history stays available from mirrors and torrents (eth-clients history endpoints), with fewer peers
  serving it.
- **Rolling expiry** (keep only a recent window): the July 2025 announcement says the work is ongoing. As of 2026-11-06 we
  found no source saying it is deployed or scheduled network-wide. Nethermind already offers it: `History.Pruning` has the
  modes `Disabled` (the default, docs for 2.2.0), `UseAncientBarriers` and `Rolling`. `Rolling` keeps
  `History.RetentionEpochs`, at least the chainspec's `minHistoryRetentionEpochs`; the 1.33 release gives 82,125 epochs
  (≈ 1 year on mainnet) as the default and the minimum. Only bodies and receipts are pruned, never state. A node
  announces the range it serves under eth/69 (EIP-7642).
- **Chains with PQZ:** PQZ tokens exist only where the PQZ precompile ships: the SCaaS testnet, 22776 and customer chains
  [repo]; Ethereum mainnet has none. What matters there is what the chain's own nodes are configured to keep. Nethermind
  keeps every body and receipt unless an operator turns `History.Pruning` on, and the ancient barriers do not apply to
  such chains [web, inference].
- **The SCaaS testnet:** the `rpc` node runs archive for state ([NET-EVM-10](../networks/evm.md#NET-EVM-10)) [repo]. The
  node configs of the stack (outside this repository) set no `History` section, so Nethermind's default keeps every block
  body and receipt [inference]. That is a default, not a stated rule: a config change or a reset of the testnet ends it.
  **22776** is the owner's alone. **Customer chains** choose for themselves. In all three cases, keeping block bodies is a
  setting of that chain's nodes. It is neither a `scaas-node` rule nor a node guarantee.

**Verdict (a)** [inference]. History covers N2 for as long as one full node or mirror of that chain serves the block. A
cold wallet away for years needs **full** retention; a one-year rolling window does not cover it. History does not help
N1 any better than N2: a cold wallet's own last debit is just as old.

### 15.3 (b) Every own debit self-checkable

**(b) as asked: derive burn and refresh randomness as op 1 does.** Burn and refresh use fresh randomness today because
their header salt is 0, so a counter-derived seed would repeat `r` and `e2_f` across two builds at one `sendCounter`
for different balances (CTR-PQZ-19, owner 2026-10-13) [repo]. With a fresh 16-byte salt per build in the salt word
(`16 zero bytes ‖ salt`, as for transfers) and in the blob, the collision argument goes away: two builds differ in the
salt. The derivation is `seed_enc` with a label of its own for these forms (controller naming). After a reinstall the
holder derives `r, e1, e2_f` from the seed, the counter and the salt, requires `u′ = Aᵀr + e1` byte for byte, computes
`z = v_f − pkᵀr − e2_f mod q`, and requires every coefficient of `z` to be exactly `Δ·d`, `d ∈ [0, 16)`. There is no
noise in `z`, since `e2_f` is known.

- **Sound for the key** [inference, UNAUDITED]. `s` is never used, so acceptance, refusal and `d′` are functions of
  seed-derived values and the bytes, never of `s`. This is not Fujisaki–Okamoto: FO derives `r` from the message and
  re-encrypts after decrypting [paper]. Here `r` comes from a PRF of public inputs and nothing is decrypted: it is a
  deterministic re-encryption check of the holder's own ciphertext, like §4 (i).
- **What it leaves:** the `Δ·k` malleability of §4. A source that adds `Δ·k` to one `v_f` coefficient is accepted or
  refused depending on that digit: a balance bit (§3.3's class), not a key bit.
- **Relation or prover?** The relation proves that short `r, e1, e2_f` exist within the norm bounds; how the client
  draws them is not part of it [repo, §3.1]. The drawing is the client's `Enc`, done before the prover receives the
  witness, so `pqzl`, the transcript and the norms do not change. The derived values must come from the same sampler and
  bounds as op 1's, which already works this way.
- **What changes anyway:** `pqz-stmt` lists the salt word of a burn and a refresh as a zero word (`zero_words`,
  `pqz-core/stmt/src/lib.rs`) [repo]. Allowing a salt changes the set of statements the precompile accepts, so the plugin
  is rebuilt on every chain that ships it. `pqz-stmt` is on the full-gate list, so a full gate is run at four sets. The
  burn and refresh vectors are regenerated in every client, and CTR-PQZ-19 is rewritten with a decisions entry (it
  reverses the owner's 2026-10-13 rule). `PqzAuth` already signs the salt word. A new `proofSystemId` is not forced, since
  the rule asks for one only when a transcript or relation changes. The owner may still want one, because old verifiers
  refuse the new statements; all chains are test-only.

**(b′) A seed-keyed own tag, the smaller form** [inference, UNAUDITED]. Every debit (op 1, op 7, burn, refresh, unwrap)
carries `ownTag = MAC_K(chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖ keccak256(P(u) ‖ P(v_f)))`. Here
`K = HKDF(pqzKeySeed, a label of its own)`, independent of `s`; `P(·)` is the stored packed form; `u` is `u_0` or `u′`.
The tag is a named payload field and is appended to the op blob (32 B). It is bound by the signed `memoHash` word:
op 1 and op 7 hash it with the memo, and a burn or refresh sets `memoHash = keccak256(ownTag)`. `memoHash` is not a zero
word on any form [repo, `pqz-stmt`], so a relayer cannot alter the tag. After a reinstall the holder checks the tag over
the bytes, read from any source, then decrypts `v_f`, a fresh ciphertext of its own.

- The refusal depends only on `K` and the bytes, never on `s` or the balance. It also closes (b)'s balance-bit
  malleability, and it treats every debit kind the same way.
- It needs no `pqz-core` change, no full gate and no new `proofSystemId`. It changes a new catalogue version of the
  contracts (the `memoHash` input and the blob layout, which also changes §14.2's length rule), the clients that build
  `memoHash` and the vectors with `memoHash` rows. Cost: 32 B in SSTORE2 ≈ +0.05 M state gas per debit at ≈ 1,539 state
  gas per byte ([`debit_t_state.out`](pqz-leg-proof-option/debit_t_state.out)) [estimate].
- It needs no holder action beyond its own debits.

**For both:** an MPC quorum has no seed, so it would need the PRF or MAC inside MPC (not designed), or its own `P` from
history. **Result:** N1 is gone for a single holder; what remains is N2.

### 15.4 (c) Settling the pending window

**Rejected as a holder action** (owner remark, 2026-11-06): a cold wallet cannot settle pending credits regularly. The
same remark rules out a holder-side attestation (a seed-keyed MAC over credits the holder verified, written on chain):
it is a periodic holder action too. What remains is a settle step that needs no holder action, no decrypt and no trusted
party [inference]:

- **`mtxRollOver`** (permissionless) adds ciphertexts mod `q`. A rolled `acc` is still the sum of the same parts, and each
  part needs its proof (§4). It certifies nothing.
- **A refresh** proves that `v_f` encrypts the decryption of `T` minus the fee. It needs `s` or the plaintext: only the
  holder.
- **Re-randomising** `T + Enc(0)` with a proof of the zero encryption: anyone can do it, but it certifies the result only
  relative to `T`, whose parts are still unproven, and it resets no noise.
- **Anyone else proving something about the plaintext** needs `s`.
- **Whatever the contract writes** (a "verified" flag, a count, a hash) is believed only through state: path (A).

**So no such settle step exists**, except a self-verifying certificate that anyone builds from the credits' proofs while
history still serves them. That is (d).

### 15.5 (d) A compact certificate in state

**What it would prove:** for each credit, or for a whole queue or token, either "this ciphertext is well-formed" (the
`R_LEG` rows) or "a valid PQZL proof exists for a statement that contains it" (recursive verification of LNP22). The
sender or any permissionless prover would build it. That needs no holder action and no trust, but it must sit in
**state**, since anything in calldata expires like `P`.

**Sizes, 2024–2026:**

| Scheme | Proof size | Verifier | Status |
|---|---|---|---|
| LaBRADOR (lattice) [paper] | 58 KB for an R1CS of 2^20 constraints | linear in the statement | research code, AVX-512 only |
| Greyhound (lattice PCS) [paper] | ≈ 53 KB evaluation proof, degree up to 2^30; polylog with LaBRADOR | `O(√N)` | research |
| LatticeFold / LatticeFold+ (lattice folding) [paper] | folding; the final proof still needs a compression SNARK | — | research, no deployable size published that we found |
| WHIR-based zkVM, hash-based (leanVM / leanMultisig, XMSS aggregation) [web] | ≈ 127–229 KiB at rate 1/4 (conjectured vs proven soundness); ≈ 190–200 KiB after 2→1 recursion | fast | prototypes, parameters not final |
| our standalone `R_LEG` (LNP22) [repo, §6] | 29.5–36.5 KB | — | not built |

**State cost** at ≈ 1,539 state gas per byte [estimate]: `R_LEG` per credit ≈ 45–56 M; a 53–58 KB lattice proof ≈ 82–89
M; a 127–229 KiB hash-based proof ≈ 200–361 M. One certificate per queue, overwritten in place: 229 KiB is 7,328 slots, at
5,000 gas per rewrite (the pre-Amsterdam figure; the Amsterdam figure is not in the repo) ≈ 37 M of regular gas, over
2^24. Submitting it costs ≈ 15 M at the 64 gas per byte calldata floor (EIP-7976).

**Circuit:** PQZ's arithmetic mod `q` over polynomials of degree `n` is non-native in every SNARK field we know of, and we
know of no implementation that verifies LNP22 proofs recursively [inference].

**Verdict (d):** it does not fit and is not mature. It would need a new proof system, a new `proofSystemId`, a precompile
op and full gates. A watch item only.

### 15.6 (e) Other ways

- **The contract re-encrypts or re-randomises credits into the holder's key space.** A contract holds no secret (all
  state is public), and any randomness it uses is public. Its output is a public function of public inputs: it proves
  nothing the holder can check without trusting state. Proxy re-encryption needs a re-encryption key derived from the
  holder's secret (a holder action), and lattice re-encryption adds noise and needs proofs of its own. **Rejected.**
- **A threshold re-encryption committee, a TEE, or a certifying service:** a trusted party. **Rejected.**
- **The sender stores a per-leg proof in state:** (d)'s figures, ≈ 45–56 M of state gas per leg. **Rejected on cost.**
- **A key rotation at reinstall:** the migration is a debit, so it decrypts the old balance and has the same need.
- **The holder's own full node, or a verifying light client:** that is path (A) with R1's allowed sources (no-oracle spec,
  Q1, owner 2026-11-06). Trust moves from a reader to the chain's rules or its sealing keys; on a Clique chain the sealing
  key is the operator's. A full node needs no block history to read current state (snap sync) [inference]. This is the
  residual path below, not a new one.

### 15.7 Verdict for a holder offline for years

**The combination** [inference, UNAUDITED]: direction 2 (`T` from state, accepted), plus (b′) or (b) on every debit,
plus (a) the chain's own full block history for third parties' debits. A holder restored from its seed alone:

1. reads state from any source;
2. checks its own last debit by its tag, or by re-encryption, with no `P`;
3. fetches each pending credit's debit transaction from any full node or history mirror of that chain;
4. rebuilds each statement with `T` from state and verifies each `P` itself;
5. decrypts.

That needs no trusted reader, no SCaaS or wallet archive, no sender hand-over and no periodic holder action.

**Cost** [estimate]: on chain ≈ +0.05 M state gas per debit for (b′), on top of direction 2's ≈ 0.10 M. On the device ≈
93–186 KB and 45–51 ms per pending credit at `n2304-kmax4096`, times the pending count. The count is unbounded with
decoys, and each decoy costs its sender a debit and `decoyFee`.

**Residual:**

1. A pending credit whose debit transaction no full node or mirror of that chain still serves. This happens on a chain
   with rolling expiry (≈ 1 year where configured as Nethermind's default window) when the holder was away longer. The
   holder then uses (A) with its own node or a verifying light client, or the wallet refuses. On chains whose nodes keep
   full block history, this residual is zero for as long as they do. For chains SCaaS runs, that is a chain setting.
2. An MPC quorum needs `P` for its own debits too, since it has no seed (§15.3).
3. The composition (§3.3) and the open audit items (§3.1) do not change. Everything here is UNAUDITED.

**Effort** [estimate]: (b′) contracts 1–2, clients and vectors 1–2, docs 0.5: **≈ 2–4 agent-days**. (b) instead: about
the same work, plus a `pqz-stmt` change and a full gate at four sets (hours each).

**Owner questions**

1. **Own debits after a reinstall:** (b′), a seed-keyed `ownTag` bound by `memoHash` (no `pqz-core` change, closes the
   balance-bit malleability), or (b), derived randomness for burn and refresh (a `pqz-stmt` change and a full gate; it
   reverses the 2026-10-13 rule)? *Recommendation:* (b′).
2. **Chains SCaaS runs keep full block history:** write it as a stated chain setting in `docs/networks/evm.md`
   (`History.Pruning` off on the SCaaS testnet's nodes; 22776 by the owner's word), and note for customer chains that the
   proof path reaches back only as far as their history? *Recommendation:* yes. It is a chain configuration, not a
   `scaas-node` rule.
3. **The residual:** a credit older than its chain's history goes through (A) with the holder's own node or a verifying
   light client, otherwise the wallet refuses? *Recommendation:* yes.
4. **(d):** a watch item, no work now? *Recommendation:* yes.

## 15A. Agreed design (owner 2026-11-06)

The owner agreed the following as the design direction ("thống nhất vậy"). It is research until a spec and plan exist;
a `decisions.md` entry follows with the spec. Estimates on paper at `n2304-kmax4096`, UNAUDITED; USD only as
`gas × gwei × 1e-9 × ETH-USD` with 1 gwei and 3,000 USD/ETH as assumptions.

**Always stored, every token with the proof path** (≈ +0.15 M gas per debit, ≈ 0.45 USD):
- every pending slot is kept for good (§14; reverses the deletion rule of `pq-zero-knowledge.md` §7.4), plus one record
  slot per debit (previous blob pointer and queue position; a second slot only when `shieldIn ≠ 0`): ≈ 0.10 M;
- a seed-keyed `ownTag` (32 B) in each own debit's blob, bound by `memoHash`, on every own debit: op 1, op 7, burn,
  refresh (§15, (b′)): ≈ 0.05 M. A rollover writes no own ciphertext and needs no tag: `acc` is a cache, `T` is rebuilt
  from its parts.

**`T` is not stored**: it is rebuilt from state (§14); the proof binds `T` verbatim in its statement, so a wrongly rebuilt
`T` fails verification.

**Where the debit proof P and its header (≈ 640 B: `beneficiary`, `fee`, `amount`, `recipient`, `validUntilBlock`,
`envelopeBinding`) live is a token setting**, chosen at creation and **changeable** later (owner 2026-11-06) by the
token's governance; a change applies to later debits only, earlier debits keep where they were stored, and each debit's
record slot notes its mode so a wallet knows where to fetch that P. The header always follows P:

| Setting | P + header | Extra gas per debit | ≈ USD | For |
|---|---|---|---|---|
| none | calldata only; the wallet fetches the transaction by the credit's transaction hash and parses the envelope | 0 | 0 | default; works for direct calls and SCaaS envelopes; a call made through another contract needs a trace, which many RPCs do not serve, else path (A) |
| log | an event from the token itself | +0.38–0.65 M | +1.1–2.0 | active wallets: robust for every call shape; short-term, lost when the chain expires history (same lifetime as calldata), loss accepted |
| SSTORE2 | state | +73–125 M | +220–375 | no history dependence, an MPC quorum included; needs a large block (op 1 ≈ 102 M, op 7 M = 8 with the auditor ≈ 194 M): document it for token creators |

**Who may change it (owner 2026-11-06, proposed name):** a new governance bit `PQZ_PROOF` in the SCaaS band, on PQZ
kinds only; bit 23 is planned for `TAX` (spec 3e), so the first free bit after it, 24, is the candidate — the spec fixes
the number, the holder kinds and whether a relaxation is delayed. **Zether needs no such bit:** ElGamal decryption has no
key-recovery oracle (§11.4), so Zether keeps path (A) only and has no proof-storage setting.

**Sealing.** An own debit or a refresh seals every earlier credit into the holder's own `v_f`, which carries `ownTag`;
after that no P of those credits is ever needed. A rollover seals nothing. The wallet knows from state whether credits are
unsealed (pending slots after its last debit record) and may advise one refresh before going cold (≈ 27.7 M gas, about
the cost of a burn). No design may rely on periodic holder action (cold wallets).

**After a reinstall:**

| Case | Action |
|---|---|
| no credit since the last own debit | `ownTag` only; nothing from history |
| new credits, P still available (calldata, log or state) | verify P, decrypt, optionally refresh to seal |
| new credits, P lost, a source the holder trusts (own node, verifying light client; R1–R6) | path (A): decrypt, then refresh to seal |
| new credits, P lost, no trusted source | the wallet refuses; funds stay, waiting for a trusted source |

An MPC quorum never uses path (A); with P lost it rebuilds `seed32` from k-of-n, one member becomes the operator, who
seals by refresh under (A) with a trusted source and rotates the key version (owner, §9.2). Rejected by the owner: the
wallet keeping P, SCaaS nodes archiving debits, the sender handing P over, periodic settling, a chain-history setting as a
rule (not related). A succinct certificate in state (§15 (d)) stays a watch item.

## 16. Sources

- Naor, Yung, "Public-key cryptosystems provably secure against chosen ciphertext attacks", STOC 1990 [paper].
- Sahai, "Non-malleable non-interactive zero knowledge and adaptive chosen-ciphertext security", FOCS 1999 [paper].
- Shoup, Gennaro, "Securing threshold cryptosystems against chosen ciphertext attack", EUROCRYPT 1998 [paper].
- Bernhard, Pereira, Warinschi, "How not to prove yourself: pitfalls of the Fiat–Shamir heuristic and applications to
  Helios", ASIACRYPT 2012 [paper].
- Fujisaki, Okamoto, "Secure integration of asymmetric and symmetric encryption schemes", CRYPTO 1999 [paper];
  Hofheinz, Hövelmanns, Kiltz, "A modular analysis of the Fujisaki–Okamoto transformation", TCC 2017 [paper].
- [EIP-4444](https://eips.ethereum.org/EIPS/eip-4444) (history expiry), [EIP-7825](https://eips.ethereum.org/EIPS/eip-7825),
  [EIP-7976](https://eips.ethereum.org/EIPS/eip-7976), [EIP-8037](https://eips.ethereum.org/EIPS/eip-8037).
- Beullens, Seiler, "LaBRADOR: compact proofs for R1CS from Module-SIS", CRYPTO 2023 [paper]; Nguyen, Seiler,
  "Greyhound: fast polynomial commitments from lattices", CRYPTO 2024, [ePrint 2024/1293](https://eprint.iacr.org/2024/1293)
  [paper]; Boneh, Chen, "LatticeFold" (2024) and "LatticeFold+" (2025) [paper]; [lattice-dogs/labrador](https://github.com/lattice-dogs/labrador)
  (implementation).
- History expiry, read 2026-11-06 [web]: [partial history expiry announcement](https://blog.ethereum.org/2025/07/08/partial-history-exp)
  (Ethereum Foundation, 2025-07-08); [Nethermind history pruning](https://docs.nethermind.io/fundamentals/history-pruning)
  (docs for 2.2.0); [Nethermind 1.33 release](https://www.nethermind.io/blog/nethermind-client-v1-33-smaller-faster-and-real-time-ui)
  (82,125 epochs); [history endpoints](https://eth-clients.github.io/history-endpoints); [EIP-7642](https://eips.ethereum.org/EIPS/eip-7642) (eth/69).
- Hash-based aggregation sizes [web]: [leanEthereum/leanMultisig](https://github.com/leanEthereum/leanMultisig) README
  benchmarks (WHIR, XMSS aggregation).
- Repository: [pq-zero-knowledge.md](../contracts/pq-zero-knowledge.md) §4.3, §7, §9.3;
  `pqz-core/params/sets/README.md`; `pqz-core/nethermind/chain/engine-pqz-provisional-n*.json`;
  [pqz-threshold-decrypt-prove.md](pqz-threshold-decrypt-prove.md) §12; the no-oracle spec and the ua-rs-sign plan
  (T16a, T16b) on branch `ua-rs-sign`; `docs/superpowers/specs/2026-11-06-pqz-key-versions.md`.
