> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZ with hidden identities: what sender / receiver anonymity would cost (estimate, no code)

Written 2026-10-14 at the owner's request ("PQZL hides only the amount; what if identities are hidden too — estimate,
no code"). PQZ today hides amounts and balances; sender, receiver and auditor accounts are public (pq-zero-knowledge.md, ring
size 2, no linkable tags). This note estimates two ways to hide identities. **No decision is recorded here and nothing
was measured**: every number below is an estimate scaled from the measured PQZL figures (`pqz-core/STATUS.md`,
`pqz-relations-burn-disclose.md` §1) and from published figures of others. Tags: [measured] our runs, [paper] a
published figure, [estimate] / [inference] this note.

**Update 2026-10-14 (second version, P6-ANON planning).** Owner decisions of that day, in order: build identity
hiding as an optional, prepared feature that is OFF by default; **the sender may stay visible, only the receiver must
be hidden** ("Chấp nhận lộ người gửi nhưng không biết người nhận"); and, as the final scope, **build only mode 2A′, the
receiver-only ring, for both proof systems (PQZL and PQZH), "prepared to show it works, with concrete measurements,
ready for others; SCaaS itself does not use it"** — stealth (2B), sender ring (1) and both sides (3) are not built and
stay here as described alternatives. The controller then recorded that mode 2A′ **is the multi-recipient transfer the
owner decided for classical Zether on 2026-10-08** (Z1–Z13, CTR-ZTH-37 … 43), so it is planned as the PQZ
multi-recipient transfer `R_TXM`; the owner accepted that design (sender visible, one proof per transfer, verified by
the one PQZ precompile for PQZL and PQZH, live on the SCaaS testnet with P6f) and corrected the earlier "prepared, unused":
**the multi-recipient transfer is used by SCaaS as the normal PQZ transfer**; decoys are a client choice. This version keeps the original §1–§4 (the §2 table marked as the 2026-10-13
sender + receiver estimate) and adds:

- §5 what Lether (ePrint 2026/076, ACM CCS 2026) actually does, read in full;
- §6 what changed since the first estimate (limits, PQZH, scope, corrections);
- §7 how balances change in each mode (baseline, 1, 2A′, 2B, 3) and a summary table;
- §8 mode 2A′ as the multi-recipient transfer `R_TXM`: relation, hint budget, the size / time / calldata / gas table
  for M = 1, 2, 4, 8, 16, PQZL and PQZH (Ligero), sized with LaZer's codegen, one M-leg transfer against M separate
  transfers, decoy noise and griefing, auditor and disclosure, where PQZ differs from the classical decisions;
- §9 mode 2B, one-time (stealth) receiver accounts, worked out but not built;
- §10 2A′ against 2B; §11 what leaks anyway; §12 status.

The plan built on this note is `docs/superpowers/plans/2026-10-14-p6-anon.md`. Sizing inputs and outputs:
`pqz-core/pqzl/params/anon/` (codegen sketches, generated headers, `codegen-anon.txt`, `anon_sizes.py`, `usvp.py`).

## 1. Two options

| | A. Ring anonymity (Anonymous Zether paradigm) | B. One-time receiver accounts (stealth) |
|---|---|---|
| Hides | sender and receiver among N accounts | receiver only (unlinkable receive accounts) |
| Sender visible | no (needs a relayer: `msg.sender` / fee payer leak otherwise) | yes |
| New machinery | one-of-N relation, linkable tag per epoch / event, epoch roll-over | key re-randomisation from an ML-KEM shared secret, a key-registration rule without `R_REG` by the owner |
| Prior art | Lether (ePrint 2026/076, ACM CCS 2026): account model, LNP22 through LaZer, ≈ 68 KB per transaction of which ≈ 51 KB proof, prove and verify "a fraction of a second" [paper; ring size not checked, the PDF was not readable here — **now read: N = 16, §5**] | stealth addresses (classical: ERC-5564); lattice re-randomised keys need their own noise analysis (**done in §8**) |

Option C, hiding in the whole set of notes (Zcash style), needs a note / UTXO model with nullifiers and a membership
proof (SMILE: ≈ 30 KB for a 2-in / 2-out transaction with 2^15 anonymity [paper], `pqz-proof-alternatives.md` §3). That
is a different token model, not an extension of PQZ, and is not estimated here.

## 2. Option A — ring of N accounts (2026-10-13 sender + receiver estimate, kept for the record)

*This section is the first estimate, made for the owner's question of 2026-10-13 (sender and receiver hidden). It is
superseded for the current scope by §7 (receiver only); §6 lists what it got wrong.*

**Mechanism.** The sender picks N accounts including itself and the receiver. Every member gets an update
ciphertext: −amount for the sender, +amount for the receiver, 0 for the others, indistinguishable from outside. The
proof adds: the sender knows the secret key of one member, that member's balance ≥ amount (without saying which),
exactly one debit and one credit. A deterministic linkable tag lets each account spend once per epoch (or per event,
as Lether's "event-oriented linkable tag"), so two proofs against the same balance cannot both land; balances are
frozen inside an epoch and pending credits roll over at the next one.

**What is cheap and what is not.**
- Cheap: the shared randomness of CTR-PQZ-04 (`out = u ‖ v_t ‖ v_f ‖ v_a`) extends to N recipients, so each extra
  member costs one `v` part (≈ 128 B) in the transfer output [inference from the 16,512 B ciphertext = 16,384 B `u` +
  128 B `v`].
- Expensive: the statement needs all N current balances `acc` (16,512 B each) and all N public keys (16,384 B each),
  because the proof may not reveal which one is the sender's. The balances come in calldata (CTR-PQZ-07) and both go
  into the precompile input.

**Estimate for an anonymous `R_TX`** (2026-10-13, sender + receiver ring) [estimate; the proof growth is anchored on
Lether's ≈ 51 KB vs our measured 42.7 KB, the rest scales the measured PQZL figures linearly in N; limits of that day:
`MAX_INPUT` 262,144 B, verify kill 50 ms]:

| | today (amount hidden) | N = 4 | N = 8 | N = 16 |
|---|---|---|---|---|
| Proof | 42,770 B [measured] | ≈ 48–52 KB | ≈ 50–56 KB | ≈ 55–65 KB |
| Transaction bytes | ≈ 77 KB (pq-zero-knowledge.md cost line) | ≈ 120 KB | ≈ 185 KB | ≈ 320 KB |
| Precompile input (N × (key + acc)) | < 262,144 B | ≈ 130 KB | ≈ 263 KB, at `MAX_INPUT` | over `MAX_INPUT` |
| Prove native / wasm32 | 1.0 / 1.6 s [measured] | ≈ 1.5–2.5 / 2.5–4 s | ≈ 2–4 / 3–6 s | ≈ 4–8 / 6–12 s |
| Specialised verify | ≈ 8 ms p50 [measured] | ≈ 12–20 ms | ≈ 20–40 ms | ≈ 50–80 ms, over the 50 ms budget |
| Gas (EIP-7623 calldata floor + precompile at ≈ 0.12 M gas / ms) | ≈ 4 M | ≈ 7–8 M | ≈ 10–12 M | ≈ 19–23 M, over the EIP-7825 cap 16,777,216 |

- **Practical ring size ≈ 8** under the current limits. Packing keys and ciphertexts at 42 bits per coefficient
  instead of 8 bytes cuts the input by ≈ 35 % and allows N ≈ 11–12 [estimate]. Chains we run (SCaaS testnet, 22776) could raise
  `MAX_INPUT` and the gas cap.
- An anonymity set of 8–12 is small next to Zcash's whole note set; ring choice must avoid patterns that single the
  sender out (decoy selection is a wallet problem).

**Other effects.**
- UX: one spend per account per epoch; a proof goes stale if any ring member's balance changes mid-epoch (the epoch
  freeze exists for this); wallets need decoy selection and an epoch clock.
- Network: without a relayer the transaction sender and fee payer reveal the spender; the relayer path exists
  (root README §10).
- Compliance: the auditor still decrypts amounts; a new disclosure kind could also encrypt the sender / receiver
  identity to the auditor, so identities are hidden from the public but not from the regulator.
- Soundness: new relation (one-of-N selection, products of selector bits with the secret key, tag correctness), new
  MSIS / MLWE sizing, a new `proofSystemId`, a larger audit scope.
- Licence / patents: the anonymity extension and linkable tags were not in the G-LIC preliminary search; they would
  have to be added to the lawyer's scope.

**Effort** [estimate]: spec 2–3 weeks (relation, epochs, tags, contract state and events); `pqz-core` 3–5 weeks
(relation, codegen parameters, MSIS estimate, specialised verifier, differential tests); then audit.

## 3. Option B — one-time receiver accounts (2026-10-13 sketch; worked out in §9)

The receiver publishes a scan key (ML-KEM-768, 1,184 B). The sender derives a shared secret and from it a
re-randomised MLWE key `pk′ = pk + A·δ + e′` whose secret `s + δ` only the receiver can compute; the transfer credits a
fresh account under `pk′`. No ring, no epoch.

- Cost: a new account per receive, ≈ 3.3 M gas to store the 16 KB key with SSTORE2 (pq-zero-knowledge.md record storage), on
  top of the transfer [estimate]. (§8: carrying `pk′` in calldata instead costs ≈ 0.52 M.)
- Open: the extra noise `e′` against the noise budget (B_FRESH, T5); key uniqueness today rests on `R_REG` proved by the
  key owner (§4.3), and here the sender creates the key, so the registration rule needs a new argument. (§9 answers
  both.)
- The sender stays visible.

## 4. Status / next (2026-10-13)

Estimates only. Before any decision: read the Lether paper in full (ring size behind the 68 KB, tag construction,
refresh cost, how stale balances are handled), then size the anonymous `R_TX` with the codegen (as `params/e_s1_proof.sage`
did for `R_TX`) to replace the proof-size guesses above. (Both done 2026-10-14: §5, §8.)

## 5. Lether, read in full (ePrint 2026/076, ACM CCS 2026)

Wang, Esgin, Steinfeld, Yiu, *Lether: Practical Post-Quantum Account-Based Private Blockchain Payments*. Read from the
copy archived by the Wayback Machine (25 pages; eprint itself is behind Cloudflare); the eprint listing says the
current version is a major revision of 2026-07-27, accepted at CCS 2026 — whether the archived copy is that revision
was not checked. Artifact: `github.com/LetherSub/Lether-artifact` (MIT, a LaZer fork, last push 2026-01-08).
Section numbers below are the paper's.

**What it builds.** Anonymous Zether (Bünz et al., Zether, FC 2020; Diamond, *Many-out-of-many proofs and
applications to Anonymous Zether*, IEEE S&P 2021) from lattices (§1.1): the spender picks N public keys including its
own and the receiver's, multi-encrypts `−amt` / `+amt` / `0` to them, proves its post-transfer balance non-negative
by verifiable decryption of its own account, and authorises with an epoch-scoped linkable ring signature. Three
building blocks (§1.3, §3):

- **Ref-AH mmPKE** (§2, Construction 3.2, Algorithm 1): mmCipher-style multi-recipient MLWE encryption, one shared
  `c = A r + e_u` and per-recipient `c_i = ⟨b_i, r⟩ + y_i + ⌊q/(2T+2)⌉·m̂_i` — the same shape as PQZ's CTR-PQZ-04
  (shared `u`, per-recipient `v`). Amounts are 32-bit (k = 32, §1.3; 64-bit "by composing two"), encoded as a binary
  polynomial; coefficients may grow to `{−T … T+1}`, so a fresh account takes T = 60 homomorphic additions, then its
  owner runs a **verifiable refresh** (decrypt, re-encrypt fresh, prove both; Construction 3.9) — PQZ's `REFRESH` with
  `K_MAX` plays the same role. Errors `y_i` are wide Gaussians (σ1 = 30,560) bounded only by approximate range proofs
  (ARP, relaxation ψ = 189), not exact norms.
- **One-of-N** (§2 end, §4 Eq. 4.2, App. A.2): two indicator vectors `b(s), b(r) ∈ {0,1}^N` with `Σ = 1` each; the
  messages are `m̂_i = (b(r)_i − b(s)_i)·m̂` (a **quadratic** relation in the witness), the spender's key is tied by
  `Σ b(s)_i b_i = Aᵀ s + e`, and the spender's new balance is the decryption of `Σ b(s)_i (u_i + c, v_i + c_i)`
  (quadratic again: selector × secret key). Integer-ness of the 2N indicator entries is aggregated into M = 3 integer
  proofs (App. A.2). The ring is in the statement; the paper fixes **N = 16** (Monero's setting) and plots N = 2…64.
- **Event-oriented linkable tag** (§2, Construction 3.12, §3.2): `tag = ⌊A_H · s mod q̂⌉_p̂` with
  `A_H = H("Lether" ‖ epoch)`, an MLWR PRF of the account secret; `q̂ ≈ 2^11`, `p̂ ≈ 2^10` (`q̂/p̂ = 2`, so the rounding
  error is one bit), `n′ = 2`, tag 0.16 KB; proven "plug-and-play" by batching the rounding relation into the
  encryption's ARP (Eq. 2.10). Linkability and non-frameability from MSIS (Lemmas 3.13, 3.15), multi-tag anonymity
  from MLWR (Lemma 3.14); the paper claims "more than 2^128" tags per key, citing Esgin et al. (Crypto 2023).

**Epochs, front-running, double spends.** Time is cut into epochs `H = ⌊block / E⌋` (App. D, Def. D.1). The spender
may spend once per epoch (the tag; balance Case 4, App. D.1). Front-running is handled only by inheritance: footnote 4
recalls Anonymous Zether's rule that accounts are updated at the end of the epoch so in-flight proofs stay valid, and
footnote 5 assumes a proof is verified in the epoch it was made for; the formal model makes every transaction take
effect immediately (footnote 11). There is no pending / roll-over mechanism in the paper beyond `RollOver` = add the
ciphertexts (Def. D.1).

**Sizes and timings** [paper; Intel i7-11850H, single thread, C, averages of 100 runs]:

| Item (N = 16, T = 60) | Value |
|---|---|
| Public key `b_i` / `c` / each `c_i` / multi-recipient `ct` | 9.34 / 10.78 / 0.36 / 16.53 KB (§4.2) |
| Transaction proof Π / transaction `|tx| = Π + ct + tag` | **51.1 KB / 67.8 KB** — the N keys and N accounts are **not** in `tx`; they are chain state |
| Prove / verify | 0.53 s / 0.34 s (Table 1) |
| Registration (`R_pk`, binary key) | 37.2 KB (27.5 KB proof), 0.12 / 0.08 s (Table 5) |
| Refresh | 54.9 KB (43.8 KB proof), 0.42 / 0.32 s; amortised 1.3 % / 1.5 % of a transaction (abstract) |
| Parameters | q ≈ 2^46, d = 64, m = 30, n = 26, binary keys (ν = 1), σ0 = 15.9, σ1 = 30,560 (§4.1, App. A.1) |

Figure 1 / Figure 2, read off the plots (±1 KB / ±0.02 s): N = 2: tx ≈ 53.5 KB, Π ≈ 42.5 KB, prove ≈ 0.32 s, verify
≈ 0.24 s; N = 4: 55.5 / 43.5 KB, 0.36 / 0.26 s; N = 8: 59.5 / 45.5 KB, 0.42 / 0.28 s; N = 16: 67.8 / 51.1 KB,
0.53 / 0.34 s; N = 32: ≈ 82.5 / 60.5 KB, 0.85 / 0.60 s; N = 64: ≈ 113 / 80 KB, 1.42 / 1.05 s. The proof grows ≈ 3 KB
from N = 2 to N = 8 and ≈ 0.6 KB per member up to N = 16.

**Security assumptions** (§3, §4.1, App. C–E): MLWE, MLWR, MSIS and Matrix Hint-MLWE (for the shared randomness under
corrupted recipients, Lemma 3.4), LNP22's knowledge soundness and simulatability (Fiat–Shamir in the ROM), all at 128
bits by the lattice estimator. The balance game (Def. D.5) **assumes every account in the anonymity set is honestly
generated and maintained** (stated as a modelling assumption, as in Zether); anonymity holds against non-recipients
and recipients among uncorrupted ring members (Defs. D.2, D.3).

**Implementation** (§4.2, App. A.2): LaZer's LNP22 was restructured (> 3,000 lines): the relation modulus used as the
proof modulus (as PQZ's `q`), batched proofs, aggregated integer proofs, and **quadratic relations over Z_q and R_q**,
which upstream LaZer's tbox front end does not offer. [inference, not checked] The artifact forks LaZer before the
three tbox / verifier findings of 2026-10-13 (lazer#24–#26), so it likely carries them; nothing from it can be reused
without our fixes.

**What carries over to PQZ** [inference]. The multi-recipient shape is already PQZ's (CTR-PQZ-04). With the sender
public, the one-of-N machinery is not needed at all: a receiver-only ring is a transfer with M legs of which all but
the real one carry 0 (§8) — no indicator vectors, no quadratic relation. Tags and epochs exist only to hide the
**sender**; with the owner's scope they are not needed: the public `sendCounter` already prevents double spends and the
existing pending / `p` mechanism (CTR-PQZ-08) already removes front-running. Lether's measured growth of the proof
with N (≈ 3 KB from 2 to 8) is the only number that transfers, as a plausibility check for §8.3.

## 6. What changed since the 2026-10-13 estimate

- **Scope** (owner 2026-10-14): receiver privacy only; sender public, authorised by its ML-DSA `authRef` and debited
  as today. No sender ring, no tags, no epochs. Final: build only mode 2A′, for both proof systems, as the normal PQZ
  transfer (used by SCaaS).
- **Reframing**: mode 2A′ = the multi-recipient transfer of classical Zether (Z1–Z13, CTR-ZTH-37 … 43); §8.
- **Limits**: `MAX_INPUT` 262,144 → **393,216 B** (P6e D5), per-id `MAX_PROOF` PQZL 98,304 / PQZH 262,144 B; verify
  kill 50 → **60 ms** p99 (CTR-PQZ-09, also bounding wasm32); tx cap 16,777,216 (EIP-7825) and the EIP-7623 floor
  unchanged.
- **PQZH (Ligero)** exists as the second `proofSystemId`: `R_TX` 230,392 B, verify p99 10.5 ms native, 18.7 ms wasm32
  after P6e B1 (`pqzh-ligero.md`).
- **Corrections to §2.** Lether's 51 KB is at N = 16 and its 68 KB excludes the N keys and accounts (they are state in
  Lether, calldata here). The public keys do not come from calldata: they are read from SSTORE2 (CTR-PQZ-07,
  ≈ 5 k gas each), so only the balances and the transfer output are calldata. §2's verify growth (≈ 50–80 ms at
  N = 16) was too pessimistic for a specialised verifier (§8.3).
- **New finding (§8.2)**: sharing one `(r, e1)` among M recipients multiplies the malicious-key hints of CTR-PQZ-04
  by M; that, not the input size, limits one shared randomness to 4 legs.

## 7. How balances change in each mode

Notation as pq-zero-knowledge.md: an account has `acc` (one ciphertext, its hash in storage, its bytes in calldata when used),
a pending list of proven credits (hashes), a public `plainPending`, `sendCounter`; anyone rolls pending credits into
`acc` by homomorphic addition (`pqzRollOver`, ≈ 0.55 M gas per credit); a debit proves over
`T = acc + Σ inline + plain` and **replaces** `acc` by a fresh encryption of the new balance (CTR-PQZ-05). `Enc(x)`
below is a credit under the shared randomness of the transfer.

- **Baseline (today).** Sender: `acc_f ← Enc(b′)` fresh (no homomorphic subtraction), `sendCounter++`. Receiver:
  pending `+= Enc(+x)`, rolled later (`acc += Enc(x)`, noise and digits grow until a refresh; `K_MAX` units).
  Race-free because the receiver's list only grows and the sender's `T` is rebuilt from `p` (CTR-PQZ-08).
- **Mode 1, sender ring** (Lether / Anonymous Zether; §2, §5). The sender hides among N accounts, so no account may be
  replaced by a fresh ciphertext (that would show which one spent): every member gets a homomorphic update — the
  sender `Enc(−x − fee)`, the receiver `Enc(+x)`, decoys `Enc(0)` — and the sender proves, without saying which, that
  its own `acc` decrypts to ≥ x + fee. Because the spender's balance is used inside the proof, the N balances must be
  frozen while proofs are in flight (epochs: updates land in pending and roll at the epoch change), and because the
  spender is hidden, `sendCounter` cannot stop a double spend: a **linkable tag** per account and epoch does.
- **Mode 2A′, receiver ring = the multi-recipient transfer** (§8, the mode to build). The sender is public and debited
  exactly as today (`acc_f ← Enc(b′)`, `sendCounter++`); every listed recipient gets a pending credit, the real one(s)
  `Enc(+x_j)`, the decoys `Enc(0)`. Nobody's balance is read by the proof except the sender's, credits only append to
  pending lists, and the sender's counter stops double spends: **no epoch, no tag**. The receiver does not scan: the
  transfer names it (`PqzCredit(ua indexed, …)` per leg, as today); it filters the logs for its own UA and decrypts its
  leg (microseconds); a zero means it was a decoy.
- **Mode 2B, stealth** (§9, described, not built). The sender is public; the credit goes to a brand-new one-time
  account `pk′` derived from the receiver's meta key (ML-KEM-768 + MLWE re-randomisation). Nobody but the receiver
  knows the account is its own, so the receiver must **scan** every stealth announcement (decapsulate, view tag
  first, Monero-style); each receipt creates an account whose 16 KB key costs calldata (≈ 0.52 M per use) or SSTORE2
  (≈ 3.3 M once); spending several stealth accounts into one place links them (consolidation).
- **Mode 3, both sides** (§2's table). Mode 1's machinery (epochs, tags, homomorphic −x, the quadratic selector ×
  secret-key relation, a relayer for the fee) with the receiver among the same N members.

| Mode | Hides | Epoch / tag | Receiver scans? | Cost grows with |
|---|---|---|---|---|
| Baseline | amounts, balances | no | no | — |
| 1 sender ring | sender among N (and amounts) | yes / yes | no | N balances (16.5 KB each) + N keys in the precompile input; N credits to roll |
| **2A′ receiver ring = multi-recipient** | receiver among M listed recipients | **no / no** | **no** (filters its UA, decrypts its leg) | M · 128 B calldata (+256 B with the auditor), M keys in the input, +16 KB per 4 legs (hint budget), M credits to roll |
| 2B stealth | receiver among all stealth-capable receivers | no / no | **yes** (one decapsulation per announcement) | 16 KB `pk′` + 1,089 B per transfer; one account per receipt |
| 3 both sides | sender and receiver among N | yes / yes | no | as mode 1 |

## 8. Mode 2A′ — the PQZ multi-recipient transfer `R_TXM` (accepted; the normal PQZ transfer)

**Reframing (controller, 2026-10-14).** A receiver-only ring is not a new design: it is the multi-recipient transfer
the owner already decided for classical Zether on 2026-10-08 (`docs/history/specs/2026-10-08-zether-multi-recipient-design.md`,
Z1–Z13, folded into zether.md CTR-ZTH-37 … 43, measured on the merged spike): one transfer, `M ≥ 1` recipients, one
proof, decoys receive an encryption of 0 (Z1), no sender ring (Z2). pq-zero-knowledge.md left multi-recipient transfers
unruled for PQZ (CTR-PQZ-22 *Open*). So mode 2A′ is planned as **the PQZ multi-recipient transfer `R_TXM`**, following
the Z-decisions where they carry over; §8.6 lists where PQZ differs. The owner's scope (2026-10-14): build only this
mode, for PQZL and PQZH, measured, verified by the precompile on the SCaaS testnet, and used by SCaaS as the normal transfer; **both
paths stay**, as classical Z7 + Z8: one proof for M ≥ 1 recipients (`R_TXM`, op 7), and the single-recipient
`R_TX` / `R_TX0` (op 1) unchanged — many separate transfers, each with its own proof and nonce, as before. `R_TXM` with
M = 1 is the same relation as `R_TX` (the codegen gives the identical 44,638 B; the body bytes coincide), so it reuses
`R_TX`'s parameters.

### 8.1 Relation

`R_TXM` = `R_TX` with M legs instead of one receiver (witness: `R_TX`'s, with per-leg digits `d_j` and noise `e2_j`,
per-group `(r_g, e1_g)`):

| # | Relation | Note |
|---|---|---|
| 1, 4, 6 | as `R_TX` (sender key, sender's fresh `v_f`, `T` decrypts to digits `M_i`) | unchanged |
| 2 | `u_g = Aᵀ r_g + e1_g` for each randomness group `g < G` | G = ⌈M / s⌉, s = `s_aud` with the auditor, 4 without (§8.2) |
| 3 | `v_j[i] = (pk_jᵀ r_{g(j)})[i] + e2_j[i] + Δ·d_{j,i}`, `j < M` | one row per leg |
| 5 | `v_{a,j}[i] = (pk_aᵀ r_{g(j)})[16·(j mod s) + i] + e2_{a,j}[i] + Δ·d_{j,i}` (auditor on) | one auditor copy per leg, as classical `C_aud_j`, each at its own coefficient window (R0 review fix R0-1, 2026-10-25; before it every copy of a group sat at coefficients 0..15) |
| 7 | over Z: `M_i + c_{i−1} = d′_i + Σ_j d_{j,i} + f_i + 16·c_i`, `c_{−1} = c_15 = 0` | `Σ M_i 16^i = b′ + Σ_j a_j + fee`; honest carries in `[−(15M + 31)/16, 1093]` ⊂ the proven `[−64, 1984)` for M ≤ 64 |
| norms | `R_TX`'s; `d_{j,i} ∈ [0, 16)` (64 bits per leg); one exact-ℓ2 block over all `e2_j` with bound `64·√M`, one over all `e2_{a,j}` | binary part 917 − 64 + 64·M bits |

A decoy is simply a leg with `a_j = 0`; the relation does not know which legs are decoys — there is no selector at all
(simpler than a one-hot candidate selector, which an earlier draft of this note used). Soundness as classical CTR-ZTH-18 / pq-zero-knowledge.md §7.4:
every term of row 7 is `< 2^15`, so the identity holds over the integers and `b′ ≥ 0` (a digit property) gives
`Σ a_j + fee ≤ balance`. Per-credit noise: `≤ 2·36·164 + 64·√M ≤ 12,064` for M ≤ 16, `K_MAX · 12,064 = 12.35 M < 2^24`
(§4.3 holds with `K_MAX` unchanged; mint margin 4.07× instead of 4.14×).

Statement (auditor on): §7.7 header (word 192 `recipientsHash = keccak256(UA_1 ‖ … ‖ UA_M)`, word 320 `M`) ‖ `pk_f ‖
pk_1 … pk_M ‖ pk_a ‖ T ‖ u_0 … u_{G−1} ‖ v_1 … v_M ‖ v_f ‖ v_{a,1} … v_{a,M}` = **50,048 + 16,640·M + 16,384·G B**
(auditor off: 33,664 + 16,512·M + 16,384·G); M = 1, G = 1 gives `R_TX`'s 83,072 / 66,560. The M + 2 keys come from
SSTORE2; calldata carries `acc` (+ inline), the `u_g`, the `v`s, the proof, `authSig` and the M recipient UAs.

### 8.2 Hint budget: at most 4 legs per shared randomness

CTR-PQZ-04 assumes MLWE on `(r, e1)` stays hard given ≤ 32 adversarial perfect hints (receiver + auditor, 16 each).
In an M-leg transfer every recipient key yields 16 hints on the same `(r, e1)`, and a sender cannot know which
registered keys were crafted (§4.5's examples pass `R_REG`): up to `16·M + 16` hints as first counted (the M auditor
copies under one key were taken to repeat the same 16 linear forms). **Corrected by the R0 review (2026-10-25,
finding R0-1):** copies that repeat the same forms are worse than hints — two auditor copies of one group at the same
coefficients cancel the mask outright (`v_{a,j} − v_{a,k} = Δ·(d_j − d_k) + noise`). Since the fix every leg's auditor
copy sits at its own window `[16·(j mod s), +16)` of `pk_aᵀ r_g`, so a group of `s` legs gives `16·s` recipient forms
and `16·s` distinct auditor forms: **`32·s` hints with the auditor, `16·s` without**; groups are `s = s_aud` = 2 / 3 /
4 / 4 legs with the auditor at `n2048-kmax1024` / `n2304-kmax4096` / `n2560-kmax16384` / `n2816-kmax65536` and 4
without (owner 2026-10-25; `pqz-core/research/code-review-2026-10-25/R0-1-auditor-shared-randomness.md`, hint study
`pqz-core/pqzl/params/anon/hints-s.txt`). Recovering `(r, e1)` opens `v_f` (the sender's new balance) and every
leg. Same approximation as §4.5 (one dimension per hint, ADPS16 primal uSVP; `pqz-core/pqzl/params/anon/usvp.py` reproduces
406 / 476 / 466) [estimate]:

| Hints on one `(r, e1)` | 32 (M = 1) | 48 (M = 2) | 80 (M = 4) | 144 (M = 8) | 272 (M = 16) |
|---|---|---|---|---|---|
| β (core-SVP classical) | 466 (136) | 461 (134.6) | **451 (131.7)** | 432 (126.1) | 392 (114.5, below Kyber-512's 406) |

So **one randomness serves at most 4 legs** (with the auditor) at the β ≥ 450 target: larger transfers split the legs
into groups of 4, each with its own `(r_g, e1_g, u_g)` (+16,384 B of statement and calldata, +2 big witness vectors),
with `v_f` in group 0 — CTR-PQZ-04's own split-randomness fallback, extended per group. DDGR's leaky-LWE estimator must
confirm 80 hints before any freeze. (Classical Z3 accepted that one shared `s` opens every leg *when handed over*;
here nothing is handed over, but malicious keys can extract — a lattice-specific limit with no classical analogue.)

**DDGR20 run (P6-ANON S1, 2026-10-14) — corrects the table above.** `pqz-core/pqzl/params/anon/hints.sage` runs the
leaky-LWE-Estimator (DDGR20, `lducas/leaky-LWE-Estimator` `0a9caf8`, `DBDD_predict_diag` with its q-vector
optimisation) next to lattice-estimator `53da598` in the pinned Sage image (`run_hints.sh` → `hints-anon.txt`,
74 min). Calibration: Kyber-512 405.5 (estimator 406), PQZ `(u, v_f)` without hints 475.8 (476); the closed-form
update for a general perfect hint matches the tool's full-covariance `DBDD_predict` to 0 on a small instance.
[measured]

| Hints on one `(r, e1)` | 16 | 32 | 48 | 64 | 80 | 96 | 144 | 272 |
|---|---|---|---|---|---|---|---|---|
| unit hints on `r` | 470.8 | 465.8 | 460.8 | 455.8 | 450.9 | 445.9 | 431.0 | 391.8 |
| unit hints on `e1` | 470.6 | 465.3 | 460.0 | 454.8 | 449.5 | 444.3 | 428.6 | 387.3 |
| **orthogonal maximal-norm mixed forms (worst case)** | 469.8 | 463.9 | 457.9 | **451.9** | **446.0** | 440.0 | 422.3 | 375.6 |
| estimator `primal_usvp`, n − h (the approximation above) | 471 | 466 | 461 | 456 | 451 | 446 | 432 | 392 |

The approximation matched the unit-hint case, but a malicious key chooses mixed forms (`e^T r − s^T e1`, `‖e‖ ≤ 164`,
`‖s‖ ≤ 36`): at 80 hints (4 legs + the auditor copy) the worst case is **446.0**, below the self-imposed 450 margin
and above Kyber-512's 406. The **owner accepted β 446 for `R_TXM` on 2026-10-15** (pq-zero-knowledge.md CTR-PQZ-03, the one
exception), so groups stay at **4 legs per `(r_g, e1_g)` with or without the auditor** (`G = ⌈M/4⌉`, plan D4); an
interim proposal of 3 legs with the auditor (64 hints, β 451.9) is withdrawn. *Superseded 2026-10-25 (R0 review fix):*
with the windows above the count is `32·s`, and the owner's `s_aud` 2 / 3 / 4 / 4 keeps DDGR20 ≥ 450 at every set and
dual_hybrid − offset ≥ 450 at every set but `n2048-kmax1024` (443.92 / 444.92 at 64 hints: the widened exception;
`n2304-kmax4096` passes by 3 β on that heuristic). `R_TX` (32 hints) keeps 463.9, as
`e_s0.py`'s 464. The shortcut used for mixed hints (a perfect hint's volume `½ ln(w^T Σ w)` put on an `r` coordinate)
is checked against the tool's full-covariance `DBDD_predict` after its q-vector step in `hints_q.sage` (section 5 of
`hints-anon.txt`; n = m = 256, real mixed hints with a dense e1 part, one e1 coordinate, or an r part only, at 10 and
80 hints): the shortcut's β is never above the full model's (e.g. 80 hints, one e1 coordinate: 36.3 vs 36.6), so it is
conservative [measured].

### 8.2a What β means and why 450

- **β** is the BKZ block size the best known lattice attack (primal uSVP, here with the hints folded in) needs. Its
  cost model is core-SVP: about 2^(0.292β) operations classically, 2^(0.265β) on a quantum computer.

| β | instance | classical | quantum |
|---|---|---|---|
| 406 | Kyber-512 (NIST level 1, the floor) | 2^118.6 | 2^107.6 |
| 446 | `R_TXM`: one `(r_g, e1_g)` with 80 adversarial hints (owner-accepted) | 2^130.2 | 2^118.2 |
| 450 | PQZ's self-imposed margin (CTR-PQZ-03) | 2^131.4 | 2^119.3 |
| 476 | PQZ encryption without hints | 2^139.0 | 2^126.1 |

- **Why 450.** CTR-PQZ-03's floor is "every attack costs at least Kyber-512's" (β 406); 450 is the margin PQZ set on
  top of it in block-size terms. 446 keeps the floor with ≈ 40 block sizes to spare instead of ≈ 44 — the reason the
  owner accepted it for this one case (2026-10-15); every other instance keeps β ≥ 450.
- **Hints.** Each recipient's key turns its ciphertext into 16 integer linear equations on the shared randomness
  `(r, e1)` (`h_i = (e^T r − s^T e1)[i] + e2[i]`, CTR-PQZ-04); a malicious key picks their directions. Every equation
  removes about one dimension from the attack lattice and, in the worst direction, adds volume, so β falls with the
  number of hints on one `(r, e1)`: 16 per leg plus 16 for the auditor's copies.
- **Both systems.** PQZL and PQZH share the encryption (keys, `u`, `v`), so the grouping and β 446 apply to both. PQZL
  additionally has its proof's own MSIS / MLWE instances (MSIS β 452–464, MLWE 470, `sizing-anon.txt`); PQZH's Ligero
  proof is measured in soundness bits instead, not in β.

### 8.3 Size, time, calldata and gas (M = 1, 2, 4, 8, 16)

**Measured (2026-10-17):** the built shapes were measured end to end — proof sizes, prove and verify times native and
wasm32 (the package's `--multi-bench` in Docker, `pqz-core/artifact/README.md`), the precompile path (`pqz-core/README.md`
§5.3) and the calibrated precompile gas `G_7` on the SCaaS testnet (3.63–6.18 M PQZL, 3.86–4.94 M PQZH,
[pq-zero-knowledge.md §9.3](../contracts/pq-zero-knowledge.md#gas)). The estimates below predate them and are kept as
the record of the sizing.

*The tables below use groups of 4 legs, the grouping the owner kept on 2026-10-15 (β 446 accepted, §8.2); the "hints →
β" column is the one-dimension-per-hint approximation — the DDGR20 worst case is in §8.2 (80 hints: 446.0).*

PQZL proof sizes: LaZer's codegen on the sketch specs `pqz-core/pqzl/params/anon/txm*_params.sage` (`R_TX`'s witness with
M legs and G randomness groups, auditor on), sized against the pinned lattice-estimator `53da598` (ADPS16) by
`run_sizing.sh` → `sizing-anon.txt` [measured: codegen and estimator runs, 2026-10-14]: every spec reaches MSIS β 453–464
and MLWE uSVP β 470 (≥ 450) with LaZer's root-Hermite target unchanged; codegen proof bytes `txm1` 44,638 (= `R_TX`'s),
`txm2` 45,166, `txm4` 46,222, `txm8` 49,858, `txm16` 54,306, `txm8g2` 62,002, `txm16g4` 90,938 — scaled below by
`R_TX`'s measured / codegen ratio (42,799 / 44,638). PQZH: `R_TX`'s measured 230,392 B plus 726 B per added Ligero row
(t = 121 columns × 6 B; ≈ 400 slots per extra leg, 695 per row; +60 rows per extra randomness group) [estimate]. Gas
per pq-zero-knowledge.md §9.3 (EIP-7623 floor, 25.2 tokens per `be8` coefficient, 3.99 per random byte, precompile 0.12 M gas
per p99 ms); every case is floor-bound. Auditor on. "fits" checks bytes and gas only; the last column is the hint
budget of §8.2. Output of `anon_sizes.py`:

| system | M | groups | statement B | proof B | input B | calldata | gas (floor-bound) | fits | hints → β |
|---|---|---|---|---|---|---|---|---|---|
| PQZL | 1 | 1 | 83,072 | 42,799 | 125,876 | 79.4 KB | 2.93 M | yes | 32 → 466 |
| PQZL | 2 | 1 | 99,712 | 43,305 | 143,022 | 80.2 KB | 3.01 M | yes | 48 → 461 |
| PQZL | 4 | 1 | 132,992 | 44,318 | 177,315 | 81.8 KB | 3.19 M | yes | 80 → 451 |
| PQZL | 8 | 1 | 199,552 | 47,804 | 247,361 | 86.4 KB | 3.64 M | yes | 144 → 432 |
| PQZL | 16 | 1 | 332,672 | 52,069 | 384,746 | 93.0 KB | 4.55 M | yes | 272 → 392 |
| PQZL | 8 | 2 | 215,936 | 59,448 | 275,389 | 114.5 KB | 4.62 M | yes | 80 → 451 |
| PQZL | 16 | 4 | 381,824 | 87,192 | 469,021 | 177.3 KB | 7.81 M | no: input | 80 → 451 |
| PQZH | 1 | 1 | 83,072 | 230,392 | 313,469 | 267.0 KB | 10.41 M | yes | 32 → 466 |
| PQZH | 2 | 1 | 99,712 | 231,118 | 330,835 | 268.0 KB | 10.45 M | yes | 48 → 461 |
| PQZH | 4 | 1 | 132,992 | 231,844 | 364,841 | 269.3 KB | 10.50 M | yes | 80 → 451 |
| PQZH | 8 | 1 | 199,552 | 234,022 | 433,579 | 272.7 KB | 10.62 M | no: input | 144 → 432 |
| PQZH | 16 | 1 | 332,672 | 236,926 | 569,603 | 277.9 KB | 10.81 M | no: input | 272 → 392 |
| PQZH | 8 | 2 | 215,936 | 277,582 | 493,523 | 332.6 KB | 12.87 M | no: input, MAX_PROOF | 80 → 451 |
| PQZH | 16 | 4 | 381,824 | 367,606 | 749,435 | 457.7 KB | 17.57 M | no: input, MAX_PROOF, gas cap | 80 → 451 |

- **Largest M that fits** `MAX_INPUT` 393,216, `MAX_PROOF`, the 16,777,216 gas cap and the hint budget: **PQZL M = 8 with two randomness groups** (M = 8 or 16 with one shared randomness fit the bytes but not the hint
  budget; M = 16 with four groups is over `MAX_INPUT` and would need it at ≥ 491,520 B); **PQZH M = 4** (M = 8 is over
  `MAX_INPUT` with one group, and with two also over `MAX_PROOF`: it would need `MAX_INPUT` ≥ 524,288 and PQZH
  `MAX_PROOF` ≥ 294,912; M = 16 is over the 16,777,216 cap). A client pads with decoys to a built size.
- Times [estimate, from `R_TX`'s measurements: PQZL prove 0.86–1.06 s native / 1.2–1.4 s wasm32, SV verify p99
  11.1 ms native / 16 ms wasm32; PQZH prove 0.67 s, verify p99 10.5 / 18.7 ms]: PQZL prove +5–15 % per doubling of M
  within one group and +30–40 % per extra group; SV p99 12–17 ms native (≤ 30 ms wasm32); PQZH prove 0.7–0.8 s, verify
  p99 11–15 ms native, 20–28 ms wasm32. All under 60 ms. Plan tasks L3 / H2 measure every cell.

**One M-leg transfer against M separate transfers** (both hide the real receiver equally if the decoy transfers carry
0; gas now, auditor on; both create the same M credits to roll later, ≈ 0.55 M each):

| system | M | one transfer: proofs / debits / gas | M transfers: proofs / debits / gas | saved |
|---|---|---|---|---|
| PQZL | 2 | 1 / 1 / 3.01 M | 2 / 2 / 5.85 M | 49 % |
| PQZL | 4 | 1 / 1 / 3.19 M | 4 / 4 / 11.70 M | 73 % |
| PQZL | 8 | 1 / 1 / 4.62 M | 8 / 8 / 23.40 M | 80 % |
| PQZL | 16 | 1 / 1 / 7.81 M | 16 / 16 / 46.80 M | 83 % |
| PQZH | 2 | 1 / 1 / 10.45 M | 2 / 2 / 20.82 M | 50 % |
| PQZH | 4 | 1 / 1 / 10.50 M | 4 / 4 / 41.64 M | 75 % |
| PQZH | 8 | 1 / 1 / 12.87 M | 8 / 8 / 83.28 M | 85 % |
| PQZH | 16 | 1 / 1 / 17.57 M | 16 / 16 / 166.56 M | 89 % |

Beyond gas: M separate transfers need M proofs and M debits, each changing `acc_f` and `sendCounter`, so they are
proven and mined **one after another** (each proof is over the `acc` the previous one wrote); they publish M fresh
`v_f`, M entries, and M sender → recipient edges with their order and timing, which separates the real payment from
decoy payments by timing patterns; one M-leg transfer is atomic, one proof, one debit, one `entryRef`, and every leg
is indistinguishable inside it. Shared randomness is the price: ≤ 4 legs per `u` (§8.2).

### 8.4 Decoy credits: noise, cap, roll-over, griefing

*Summary; the full analysis, the rule options and the proposed rule (decoy consent: an account must opt in to
receive multi-recipient credits — rejected once multi became the normal transfer) are in the plan, §5.1–§5.2.*

- **Noise.** Every leg, decoy or not, is a proven encryption with the norms of §8.1: it adds at most one unit of
  ≤ 12,064 noise to the recipient. The credit cap (CTR-PQZ-06) counts **units**, not amounts: a credit beyond
  `accUnits + (pendingCount − rolled) + 2 > K_MAX` reverts `RefreshRequired`. So no sequence of decoy credits can push
  an account past the noise budget — the cap stops credits first, and `K_MAX · 12,064 < 2^24` keeps decryption and the
  mint argument intact.
- **Roll-over.** A decoy credit is a pending entry like any other: rolled by anyone (≈ 0.55 M, batched by 16), needed
  before the owner's next debit only beyond `INLINE_MAX = 16` unrolled credits, and to free cap. Zero credits are
  indistinguishable from real ones until the owner decrypts them.
- **Griefing bound.** Naming a victim as a decoy is a proven transfer leg; recipients are pairwise distinct (Z1), so
  one transfer gives a victim at most one unit. Filling the victim's 1,022 free slots takes 1,022 transfers
  (≈ 1,022 × 3.0–3.5 M ≈ 3.1–3.6 G gas PQZL, ≈ 10.7 G PQZH) — exactly threat T7's price today; recovery is the same
  (roll ≈ 0.57 G + refresh ≈ 2.6 M). What decoys add is amplification: each griefing transfer also fills M − 1 other
  victims, so the attacker's cost per victim falls to ≈ T7 / (M_max) (≈ 0.4–0.9 G per victim at M_max = 4–8),
  about the victim's own recovery cost. Nothing in the relation can tell a griefing leg from a real one, and with
  multi as the normal transfer an opt-in would block real payments; the plan keeps T7's controls (permissioned
  submitters, node rate limits; gas is capacity on the SCaaS testnet), an optional per-leg fee and a wallet policy that
  spreads decoy load.

### 8.5 State, receiver, auditor, disclosure

*Summary; the per-leg disclosure, storage / memo layouts and the auditor leg are worked out in the plan, §5.3–§5.5,
and the contract / node specification in its §6–§7.*

- **No switch**: every PQZ token offers M ∈ {1} ∪ the built sizes; whether a payment carries decoys is the
  client's choice (plan §7).
- **Contract** (P6g, spec only): `pqzTransfer(payload, acc, inline, recipients[M], out, proof, authSig)` (+ the
  CTR-PQZ-23 variants `…Compact`, `…NoBundle`; today's single signature kept as `pqzTransferSingle`, Z7 / Z8); the sender's checks and effects exactly as `pqzTransfer`; recipients
  pairwise distinct, none equal to the sender, all registered and under their cap (`DuplicateRecipient`,
  `SelfTransfer`, `NotRegistered`, `RefreshRequired`, as classical Z1); `pending[recipient_j] ← (u_{g(j)}, v_j)`; one
  `PqzTransfer` with the recipient list and `PqzCredit(ua indexed, index, entryRef)` per leg; one `entryRef`, leg `j`
  addressed as `(entryRef, j)` (classical); one fee to the beneficiary.
- **Receiver.** No scanning: it filters `PqzCredit` by its own UA (as today), decrypts its leg; a zero is a decoy
  credit it still rolls.
- **CTR-PQZ-23** (bundle, memo): the bundle becomes `salt ‖ u_0 … u_{G−1} ‖ (toUA_j ‖ v_j ‖ v_{a,j})_j`; COMPACT stores
  its hash (classical Z4 measured hash-only as the cheapest at large M), BUNDLE stores it with SSTORE2 (≈ 3.4 M + 0.06 M
  per leg); the sender memo becomes `salt ‖ ((flags ‖ (be8(a_j) ‖ toUA_j)_j) XOR ks)`, so the sender recovers every leg
  from storage alone.
- **CTR-PQZ-24** (auditor): FULL — one auditor copy per leg (classical `C_aud_j`): the auditor reads every leg's amount,
  so it sees which legs are decoys and who the real recipients are; OPTIONAL — the sender may leave the auditor out of
  a transfer (no `v_{a,j}`, publicly visible, as Z12); NONE — no copies.
- **CTR-PQZ-14** (disclosure): unchanged relations, per leg: `SENDER_S` (the sender's zero-knowledge `R_DS` over
  `(pk_j, u_{g(j)}, v_j)`), `RECEIVER_X` (`R_DR` by recipient j), `AUDITOR` (over `v_{a,j}`); the opening names `j`; a
  disclosure reveals the leg's recipient and amount to its verifier, by consent.

### 8.6 Where PQZ follows the classical Z-decisions and where it differs

| Classical (2026-10-08) | PQZ `R_TXM` |
|---|---|
| Z1 one transfer, M ≥ 1, one proof, decoys `Enc(0)` | same; `MAX_RECIPIENTS` = the largest M that fits per proof system (§8.3) instead of 16 |
| Z2 no sender ring | same (owner 2026-10-14 again) |
| Z3 one shared `s` opens every leg when handed over | PQZ never reveals `r` (CTR-PQZ-14); instead malicious keys extract hints, so ≤ 4 legs per randomness group (§8.2) |
| Z4 three storage modes (hash default) | CTR-PQZ-23's BUNDLE / COMPACT and `…NoBundle`, per leg |
| Z7 / Z8 multi is the default `zetherTransfer`, single kept as `…Single` | **carries over**: `pqzTransfer` takes M ≥ 1 recipients (always op 7), today's single-recipient transfer stays unchanged as `pqzTransferSingle` (op 1) |
| Z9 no attestation | already PQZ (CTR-PQZ-14) |
| Z10 `SENDER_CP` per-leg sender opening | not needed: PQZ's `SENDER_S` is already a per-leg zero-knowledge proof |
| Z11 threshold auditor key (off chain) | not carried: an MLWE auditor key could be shared for threshold decryption, but not planned |
| Z12 per-transfer auditor opt-out | CTR-PQZ-24 OPTIONAL |
| Z13 stateless disclosure contract | a P6g layout question for PQZ, not part of this mode |
| own proof system id for the multi format | PQZ: same `proofSystemId`s; a new op and `opTag` name the relation (P6e D4: an added statement form) |
| range proof per `v_j` (Bulletproof) | 16 digits of 4 bits per leg in the same proof |

## 9. Mode 2B — one-time receiver (stealth) accounts (described alternative, not built)

*Worked out on 2026-10-14 before the owner's final scope; kept as the record of the alternative. Nothing here is
planned.*

### 9.1 Mechanism

- **Meta key.** A stealth-capable receiver has a registered `pqz-mlwe` UA `UA_R` with key `pk_R = A s + e` (ordinary
  `R_REG`, ordinary `authRef`) and an ML-KEM-768 (FIPS 203) key pair `(ek_R, dk_R)` (1,184 / 2,400 B), both derived in
  the key worker from the BIP-39 seed (CTR-PQZ-13 rule, own `info` tags). The meta-address `(UA_R, ek_R)` is handed
  out off chain (payment request / invoice); an on-chain directory is not needed for the feature.
- **Sender.** `(c_kem, K) = ML-KEM.Encaps(ek_R)` (1,088 B ciphertext, 32-byte K); `seed = HKDF-SHA256(K,
  "SCAAS-PQZ-STEALTH-V1", chainUid ‖ token ‖ keccak256(c_kem))`; from `SHAKE256(seed)`: `δ_s` sparse ternary of weight
  512, `δ_e ← CBD(10)^2048`; **`pk′ = pk_R + A·δ_s + δ_e`**; view tag = first byte of `SHAKE256("…-TAG-V1" ‖ K)`. The
  transfer is an ordinary `R_TX` with `pk_t = pk′`; `c_kem`, the view tag and `pk′` travel in calldata and in an
  announcement event.
- **Receiver.** For every announcement: decapsulate (tens of µs), compare the view tag (255 / 256 skipped), derive
  `δ`, check `pk′`, and hold `s′ = s + δ_s`, `e′ = e + δ_e`. Prior art: Mikić, Srbakoski, Praška, *Post-Quantum Stealth
  Address Protocols* (ePrint 2025/112): the same Kyber-based shape (`p = k + XOF(S)`), ≈ 141 ms to scan 5,000
  announcements with Kyber-768 and a one-byte tag (their §6.3) [paper].
- **The account.** A stealth account is **not** a UA and is never registered: the token keeps a record keyed by
  `sid = keccak256("SCAAS-PQZ-STEALTH-ID-V1" ‖ pk′)` with `keyHash` and the usual per-account slots (§7.1 of
  pq-zero-knowledge.md); `pk′` is carried in calldata whenever it enters a statement (≈ 0.52 M, against ≈ 3.3 M for SSTORE2).
  It spends with ordinary `R_TX` / `R_BURN`; **its spend authority is the proof alone** (no `authRef` exists — a
  deviation from CTR-PQZ-12 for these accounts).

### 9.2 Noise, key uniqueness, mint

- **Norms without a new relation.** If the base key is generated with half the norm budget — `s` sparse ternary of
  weight 512 (‖s‖ = 22.6), `e ← CBD(10)` — and `δ` the same, then `e′ = e + δ_e` is distributed exactly as a fresh
  CBD(20) error (`‖e′‖ > 164` exactly as often as KeyGen resamples, ≈ 2^-70), and `‖s′‖² = 1024 + 2⟨s, δ_s⟩` with
  `⟨s, δ_s⟩` a sum of 2048 terms in {−1, 0, 1} of variance 1/16 each: `‖s′‖ > 36` needs `⟨s, δ_s⟩ > 136`,
  probability ≤ 2^-75 (Bernstein) [estimate]. So `pk′` has
  a short key within the existing bounds (36 / 164): **every existing relation (`R_TX`, `R_TX0`, `R_BURN`, `R_DR`)
  serves stealth accounts unchanged**, B_FRESH and `K_MAX` are unchanged, and the receiver's resample-free derivation
  fails with negligible probability (the sender cannot resample: it does not know `s`).
- **Security of the halved key** [estimate, `usvp.py`, primal ADPS16 only]: MLWE with a weight-512 ternary secret and
  CBD(10) errors, n = 2048, q = 2^42 − 215: **β ≈ 461** (core-SVP 134.6), above the 450 target, below the standard
  key's 476; the same instance protects unlinkability (`pk′ − pk_R = Aδ_s + δ_e` against uniform, one fresh `δ` per
  account). Weight 256 / CBD(5) would give 446 (below target). The pinned lattice-estimator (incl. hybrid attacks on
  the sparse secret) must confirm before any freeze; if it misses, the fallback is relaxed-norm variants of the debit
  relations (`‖s_f‖ ≤ 72`, `‖e_f‖ ≤ 328`) with a stealth cap `K_MAX_S = 512`.
- **No `R_REG`, still no mint.** Soundness of a debit needs the spender's key short and unique and the credits' noise
  bounded. Row 1 of the stealth account's first debit proves `pk′ = A s′ + e′` with the standard bounds, and the
  kernel argument of §4.3 makes that preimage unique for all but a negligible fraction of `A` — whoever created the
  account. Every credit to `pk′` came with a sender proof of `r, e1, e2` norms, so the noise under the unique short key
  is ≤ B_FRESH per unit, and §4.3's uniqueness of the decryption holds. A `pk′` with no short preimage (a sender who
  did not follow the derivation) only makes the credit unspendable: the sender burned its own money.
- **Hints (CTR-PQZ-04).** The receiver of a stealth credit knows `(s′, e′)` within the standard norms: 16 hints, as
  today. The sender knows `r` anyway.
- **Squatting.** Anyone who sees `pk′` (from the mempool) can credit it first; credits only add. Filling its cap is
  threat T7 at the same price.

### 9.3 Costs

| 2B, auditor on [estimate, first version of `anon_sizes.py`] | statement | proof | input | calldata | gas |
|---|---|---|---|---|---|
| PQZL | today (`R_TX`) | 83,072 | 42,799 | 125,876 | 79.4 KB | 2.92 M |
| PQZL | to a stealth account | 83,072 | 42,799 | 125,876 | 96.9 KB | 3.48 M |
| PQZH | today (`R_TX`) | 83,072 | 230,392 | 313,469 | 267.0 KB | 10.41 M |
| PQZH | to a stealth account | 83,072 | 230,392 | 313,469 | 284.5 KB | 10.97 M |

A transfer to a stealth account costs ≈ +0.55 M (`pk′` 16 KB + ML-KEM ciphertext 1,089 B in calldata, the
announcement log); the stealth account's own later spend costs ≈ +0.52 M (`pk_f` from calldata). No new relation,
no new op, no precompile change, no new `proofSystemId`; the statement layout of op 1 is unchanged (`toUA` = `sid`).

### 9.4 Auditor and disclosure

The auditor still decrypts the amount (`v_a`) and sees the stealth `sid` but not the receiver's UA: the link
`pk′ ↔ pk_R` cannot be proven on chain without proving ML-KEM and HKDF in zero knowledge. Off chain, either party
(both know `δ`) can prove the link with an **`R_REG` proof over `pk′ − pk_R`** (witness `(δ_s, δ_e)`, bounds 36 / 164
cover them): no new relation. `RECEIVER_X` disclosures work unchanged with `pk = pk′`.

## 10. Mode 2A′ against 2B, and the owner's choice

| | 2A′ multi-recipient (decoy legs) | 2B stealth |
|---|---|---|
| Hides | which of the M listed registered accounts got a non-zero amount | that a receive account belongs to anyone in particular (set: every stealth-capable receiver) |
| Anonymity set | M ≤ the largest size that fits (§8.3) | unbounded; linkage reappears on consolidation |
| Sender cost | ≈ today + proof growth (+0.52 M per extra group of 4 legs) | ≈ today + 0.55 M |
| Deferred cost | M credits to roll (≈ 0.55 M each) and M cap units, borne by the recipients | +0.52 M at the stealth account's spend |
| Receiver UX | nothing new: filter its UA, decrypt its leg, roll zero credits | scan every announcement, one account per receipt, sweep |
| Authorisation | unchanged (sender ML-DSA, every account a UA) | stealth spends authorised by the proof alone |
| Crypto work | new relation `R_TXM` (PQZL tbox spec + builder + SV; Ligero constraints), new op, randomness groups | none in the relations; halved-norm base KeyGen, ML-KEM-768 in clients |
| Auditor | per-leg copies: amounts and real recipients on chain | amount and `sid`; the link is an off-chain `R_REG` proof over `pk′ − pk_R` |

The first version of this note recommended building both, stealth first. **Owner 2026-10-14: build only 2A′**, for
both proof systems, as the normal PQZ transfer (used by SCaaS, verified by the precompile on the SCaaS testnet); 2B, 1 and 3 stay
described here.

## 11. What leaks anyway

- **Sender**: public by the owner's scope (UA, authorisation, counter, timing).
- **The recipient list**: all M recipients are public; the leak is reduced to "one (or more) of these M got a
  non-zero amount". M itself is public.
- **Fee payer / relayer**: `msg.sender` is public (the sender is public anyway in 2A′; in 2B a stealth account would
  need a relayer paid from its confidential balance).
- **Timing and amount correlation**: shields and burns are public; a receive followed by a burn of a similar amount,
  or the real recipient's next activity, can single it out among the M.
- **Decoy selection**: lists of fresh, inactive or always-the-same accounts single the receiver out; repeated payments
  to one receiver with varying decoys intersect (the real one is in every list). A wallet problem (P6h).
- **Colluding recipients**: each decoy controlled by an observer removes itself from the set; beyond 4 legs per
  randomness the hints of §8.2 would put the randomness at risk, hence the groups.
- **Amounts** stay hidden (as today); a FULL auditor sees every leg, so it knows the real recipients.
- **Network**: IP-level observation of submission is outside the protocol.

## 12. Status / next

Design and sizing only; nothing built or measured beyond the codegen sizing runs and the estimate scripts. Next: the
plan `2026-10-14-p6-anon.md` (after P6e's `pqz-stmt` and `pqz-ffi` merge): estimator evidence (80 hints), `R_TXM` in
PQZL and Ligero for M = 2, 4, 8, 16, measured, the fitting sizes in P6e's frozen set and the P6-PUB package, op 7 live
in the SCaaS testnet precompile. Contracts (P6g), wallet decoy policy (P6h), keeper roll-overs (P6i) follow from the specification the plan
writes.
