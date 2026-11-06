> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

> Vietnamese version: [pqz-leg-proof-option.vi.md](pqz-leg-proof-option.vi.md). This English file is the reference
> version.

# PQZ `legProof`: a self-verifying proof for every ciphertext in state (2026-11)

Written 2026-11-06 at the owner's request. **PQZ only**; classical Zether is a separate system and is touched only in
§11.4. Research only: nothing here is a rule, nothing in pqz-core, the contracts, the node or the clients changed, and
everything cryptographic is **UNAUDITED**. Nothing was measured: the numbers are paper arithmetic over figures the
repository already records ([`pqz-leg-proof-option/`](pqz-leg-proof-option/), script and output). No gas or timing run
was made (that needs the owner's word).

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
| Q6 Wallet cost | `n2304-kmax4096`, 4,096 credits: standalone ≈ 204 MB to fetch, debit-T ≈ 0.42–0.72 GB; verify ≈ 90 s (standalone) or 185–211 s (debit-T) single-threaded, p99 proxy [estimate]. Verify once on arrival and keep the proof; a fresh restore needs only the parts since the last debit. |
| Q7 What changes | debit-T: one log per debit, an immutable flag in a new catalogue version, a proof path in `ua-rs`, vectors for the log layout. A standalone relation: a new `proofSystemId`, a precompile op, vectors in every client, the full gate at four sets, and an op 7 cut. Zether: not needed for the key (§11.4). |
| Verdict | **Build `legProof = CALLDATA` as debit-T**; do not add a standalone leg relation. It gives a holder a second, proof-based decrypt path, gives an MPC quorum a key-safe path, and keeps (A) as the single holder's fallback (§12). |
| Added 2026-11-06: `T` from state (§14) | If the contract stops deleting pending slots and writes one record slot per debit, every historical `T` is a function of state (≈ 0.10 M gas per debit, flat across sets, instead of the 0.15–0.20 M log of `T`). It removes only `T`'s history dependence: the debit proof is calldata, and keeping it in state costs ≈ 65–131 M gas per PQZL debit, which does not fit. The §9 fallback and the archive rule stay. Outside parties will not store proofs, so availability
rests on the recipient's wallet keeping the material in both forms. The case for direction 2 is cost and having the
composition in state, a mild preference (§14.7, §14.8). |

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
cover burns and refreshes, so it cannot be the only way.

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
`p`. Each part is verified once, on arrival, and the proof material kept: the bulk cost above is a fresh restore of a
full account. The pending queue is unbounded (CTR-PQZ-06), so a decoy flood makes a fresh restore verify more proofs;
each decoy costs its sender a debit and pays the victim `decoyFee`, as today.

**History expiry** (EIP-4444): proofs, payloads and logs are in block bodies and receipts, which expire; state does not.
A part whose proof material is no longer served anywhere can no longer be checked by the proof path; §9 covers the
fallback.

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

| Measure | Where it belongs |
|---|---|
| The wallet keeps the proof material of every part it verified on arrival (a local cache); history loss then matters only for a fresh restore | the client rules (`ua-libraries.md`, the wallet layer); the library takes the material as input and keeps no I/O |
| Each quorum member keeps every proof it verified; any one member's cache can serve all the others, since the material verifies itself | the quorum service's spec (C3, not scheduled) |
| An archive: `scaas-node`'s indexer, or any untrusted indexer, stores and serves the debit log, payload and proof by `entryRef` | **the node spec** (`docs/node/store.md`, `gateway.md`), as PLANNED: a node guarantee belongs in the node, and it needs no trust; the node still never decrypts (NODE-GEN-01) |

**Withholding as an attack** [inference]. For a single holder: it gains nothing about `s`; at most it forces (A) or a
refusal. For a quorum: it can push toward §9.2, a period with one operator holding the key. One honest member's cache or
any archive defeats it, and reconstruction needs `k` members, so an outsider cannot trigger it alone; members should
declare the material lost only after every member's cache and the archives were tried.

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
- **Node:** the PLANNED archive rule (§9.3); the indexer normalises the new event.

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
| R5 | Node: PLANNED archive rule, indexer storage and gateway read by `entryRef` | 2–4 |
| R6 | Docs: `pq-zero-knowledge.md` (option, log, proof path), `ua-libraries.md` (client cache), §12.5 status, Vietnamese copies | 1–2 |
| | **Total** | **13–21** |

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
   `CALLDATA` tokens by `entryRef`? *Recommendation:* yes; it is self-verifying, so it adds no trust in the node.

## 14. debit-T from state: keep T's parts and store references (2026-11-06)

**Question (owner, 2026-11-06, direction 2).** Logging `header ‖ T` (§5) depends on history (EIP-4444), and storing `T`
whole costs ≈ 21 M (SSTORE2) or ≈ 41 M (fresh slots) at `n2304-kmax4096`, which was rejected. Can the contract instead keep
the parts `T` is made of, which are already in state, and store a short reference per debit, so that every historical `T`
rebuilds from state alone? Read against `PqzCore.sol` and `PqzStateLib.sol` on branch `ua-mtx-merge` (line numbers below);
arithmetic in [`debit_t_state.py`](pqz-leg-proof-option/debit_t_state.py) and
[`.out`](pqz-leg-proof-option/debit_t_state.out). Nothing was measured.

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
  and for a quorum, rebuild the seed and rotate. The archive rule of §9.3 stays too, but what it must keep shrinks to the
  debit transaction (its calldata), with no receipt. The `header ‖ T` log is no longer needed; a header-only log is a
  convenience that spares every client from rebuilding `envelopeBinding` out of the outer transaction.
- **What it does give:** (1) the cost per debit falls from 0.15–0.20 M to ≈ 0.10–0.11 M, flat across sets; (2) `T` depends
  neither on receipts nor on archive state nodes (the zero-change variant of §5); (3) the composition of every past debit
  is in state, so §3.3's account words for a past debit can be checked against state; (4) any server can serve `T`, and
  the proof checks it.

### 14.7 Retention: who keeps the proof (owner remark, 2026-11-06)

The owner's remark: "outside parties won't store the proofs". Taking that as given [inference unless tagged]:

1. **What a holder needs.** Only the debit material (the debit transaction with `P`, plus `T` or its record) of the
   credits since its own last debit, together with its own last debit. A debit consumes at most `K_MAX − 2` entries; the
   queue is unbounded, so decoys beyond that belong to a later debit. Nothing older is needed: a past composition only
   matters for an audit.
   - **Its own last debit:** for op 1 and op 7, `v_f` is checked by the re-encryption check of §4 (i). That needs the
     seed, the counter and the salt from the blob, all in state, and no `P`. For a **burn or refresh** it is not: their
     randomness is fresh (CTR-PQZ-19), so the only proof-based check is the holder's own proof `P`. The wallet made `P`
     and can keep it. After a fresh restore from the seed, if the last debit was a burn or refresh, the holder needs that
     `P` from history or falls back to (A) [repo, §4].
   - **An MPC quorum** has no seed, so it needs `P` for its own last debit of every kind (§4).
2. **Who has an interest in keeping it.**
   - The recipient's wallet: it fetches and verifies on arrival and keeps the material (§9.3). This is the main copy, and it
     costs nothing on chain.
   - The sender handing `P` to the recipient over a memo-like channel: **rejected by the owner (2026-11-06)** as not done
     and not reasonable. No such channel exists today either [repo]: the sealed memo is 41 B on chain (CTR-PQZ-23).
   - Nodes SCaaS runs: a PLANNED node-spec rule (§9.3). The node is open, so this is a guarantee of `scaas-node` itself,
     not of a consumer.
   - Chains SCaaS runs (22776, the SCaaS testnet): they can be configured to keep history. The SCaaS testnet's `rpc` node
     runs archive for state (NET-EVM-10) [repo]; keeping block bodies and receipts would need its own stated setting,
     owner-only for 22776. Customer chains choose for themselves.
3. **What is lost when the material is gone:** only the proof path. Funds stay spendable through the fallbacks: (A) for a
   single holder, and for an MPC quorum, rebuild `seed32` k-of-n, then an operator, then a key rotation (owner decision,
   §9.2).
4. **The residual case:** a wallet that stays offline longer than a foreign chain's history window, with no archive
   serving the transaction (no SCaaS-run node watched that chain, and the chain itself expires history). That case does not change between the two forms. Direction 2 rebuilds
   `T` from state, but `P` and the header words are gone just the same, so both forms end in the same fallback.

**What this means for direction 2 against logging `T`.** The availability gain of direction 2 is small. For the case that
matters, the material is either kept on arrival by the recipient, or the proof itself is missing. What remains is cost
(≈ 0.10–0.11 M against 0.15–0.20 M per debit), no dependence on receipts, the composition of every debit in state, and an
indexer that can serve `T` without having watched the logs. Set against that are the permanent +32 B per credit and per
debit and the reversal of a recorded rule.

### 14.8 Verdict, effort, owner questions

**Verdict** [inference, UNAUDITED]. Direction 2 is sound and cheap. Every debit's `T` becomes a function of state if the
contract stops deleting pending slots and writes one record per debit; the materialised `acc` and the rollovers are not
needed for the rebuild. It replaces the `T` half of the debit-T log at about two thirds of its cost, flat across sets. It
does **not** remove the dependence on history: the proof and six header words stay in calldata, and the proof does not
fit in state. Since outside parties will not store proofs (§14.7), availability rests on the recipient keeping the
material on arrival in both forms, and the residual case falls back to (A) or the §9.2 rotation in both. The choice
therefore rests on cost and on the composition being in state, not on availability. It is a mild preference, not a
decisive one. Recommended form of debit-T: **`T` from state plus a header-only log**, in place of logging `header ‖ T`.
Logging `header ‖ T` with no state growth remains a reasonable choice if the owner prefers to keep the deletion rule.

| Step | Work | Agent-days [estimate] |
|---|---|---|
| D2-1 | Contracts: drop the two deletions, add the record, the view and the header log. Forge tests: `T` rebuilt from state equals the statement's `T` after random runs of credits, shields (same-block merges included), rollovers, un-rolls, op 1, op 7, burn, refresh and unwrap. Pin `scaas.pqz`; size gate at four sets; gas pins old → new after measurement (the owner's word) | 3–4 (in place of §12 R2) |
| D2-2 | Vectors: the record word and one rebuild row, at the default set and one other; the rebuild in `ua-rs` and `ua-c` | +1–2 |
| D2-3 | Node: the indexer computes `T` and serves it by `entryRef`; the archive item is the debit transaction | +1 |
| D2-4 | Docs: `pq-zero-knowledge.md` §7.1, §7.4, CTR-PQZ-07; a decisions entry reversing the deletion; the Vietnamese copies | +1 |
| | **debit-T in this form, in all** | **≈ 16–25** (against 13–21 in §12) |

**Owner questions**

1. **Keep every pending slot for good** (+32 B per credit and per debit), so that every `T` is a function of state? This
   reverses the state spec's §5.5. *Recommendation:* yes. It costs no state gas (clearing never returned any under
   EIP-8037) and lowers regular gas; it needs a decisions entry.
2. **Header:** log the 640-byte header (≈ 0.01 M), or let every client rebuild it from the transaction's calldata,
   including the relay envelope's binding? *Recommendation:* log it.
3. **Proof availability:** accept that the debit proof stays in history (in state it costs ≈ 65–131 M per PQZL debit and
   does not fit), so that the §9 fallback and the archive rule stay, with the archive item narrowed to debit
   transactions? *Recommendation:* yes.

## 15. Sources

- Naor, Yung, "Public-key cryptosystems provably secure against chosen ciphertext attacks", STOC 1990 [paper].
- Sahai, "Non-malleable non-interactive zero knowledge and adaptive chosen-ciphertext security", FOCS 1999 [paper].
- Shoup, Gennaro, "Securing threshold cryptosystems against chosen ciphertext attack", EUROCRYPT 1998 [paper].
- Bernhard, Pereira, Warinschi, "How not to prove yourself: pitfalls of the Fiat–Shamir heuristic and applications to
  Helios", ASIACRYPT 2012 [paper].
- Fujisaki, Okamoto, "Secure integration of asymmetric and symmetric encryption schemes", CRYPTO 1999 [paper];
  Hofheinz, Hövelmanns, Kiltz, "A modular analysis of the Fujisaki–Okamoto transformation", TCC 2017 [paper].
- [EIP-4444](https://eips.ethereum.org/EIPS/eip-4444) (history expiry), [EIP-7825](https://eips.ethereum.org/EIPS/eip-7825),
  [EIP-7976](https://eips.ethereum.org/EIPS/eip-7976), [EIP-8037](https://eips.ethereum.org/EIPS/eip-8037).
- Repository: [pq-zero-knowledge.md](../contracts/pq-zero-knowledge.md) §4.3, §7, §9.3;
  `pqz-core/params/sets/README.md`; `pqz-core/nethermind/chain/engine-pqz-provisional-n*.json`;
  [pqz-threshold-decrypt-prove.md](pqz-threshold-decrypt-prove.md) §12; the no-oracle spec and the ua-rs-sign plan
  (T16a, T16b) on branch `ua-rs-sign`; `docs/superpowers/specs/2026-11-06-pqz-key-versions.md`.
