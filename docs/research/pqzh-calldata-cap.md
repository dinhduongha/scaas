> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# PQZH calldata against the per-transaction gas cap (plan 5h Task 8d part 2b, item 1)

Plan 5h Task 8d part 2b, 2026-10-26, branch `pqz-8d2b`. Measurement and options only: **no option is implemented; the
owner decides.** Measured with forge 1.8.5 (Amsterdam profile) through the real token and registry at each parameter
set; logs `smartcontracts/evm/runs/2026-10-26-t8d2b-gas-<set>.txt`, test `PqzStatePinGasTest.test_gasTable_pqzh`
(`smartcontracts/evm/test/pqz/PqzStateGas.t.sol`), table script `runs/2026-10-26-t8d2b-gas-table.py pqzh`. No
wall-clock timing anywhere: the precompile is priced at its provisional testnet rows
(`pqz-core/nethermind/chain/engine-pqz-provisional-<n>.json`, Task 9 replaces them).

## 1. The limit, in both regimes

A transaction's regular gas is capped at 2^24 = 16,777,216 by **EIP-7825** (Transaction Gas Limit Cap). The
calldata floor puts a minimum on that regular gas:

| regime | EIPs | intrinsic | calldata floor | largest calldata under 2^24 (floor alone, all bytes non-zero) |
|---|---|---|---|---|
| Prague / Osaka | **EIP-7623** (Increase calldata cost) | 21,000 | 21,000 + 10 per token, tokens = zero bytes + 4 × non-zero bytes: 40 gas per non-zero byte, 10 per zero byte | (2^24 − 21,000) / 40 = **418,905 B** |
| Amsterdam (Glamsterdam) | EIP-7623 + **EIP-7976** (Increase calldata floor cost) + **EIP-2780** (intrinsic) | 15,000 (12,000 + 3,000 for a call to another account) | 15,000 + 64 gas per calldata byte, zero bytes too (the repository's model since Task 7b; on the SCaaS testnet `eth_call` and the pool refuse exactly above it: `pqz-core/nethermind/runs/2026-10-21-glamsterdam-gas-impact.md`) | (2^24 − 15,000) / 64 = **261,909 B** |

Under EIP-7623 alone the ≈ 418,900 B estimate holds (418,905 B for an all-non-zero call; the PQZ calls are ≈ 95 %
non-zero bytes, so slightly more). **The ≈ 261,909 B limit comes from EIP-7976's 64 gas per byte, not from EIP-7623.**

**The SCaaS testnet's chainspec** (`/home/dockers/mba-chain-nethermind/genesis.json`, Nethermind 2.2.0) activates
`eip7623TransitionTimestamp` 0, `eip7825TransitionTimestamp` 0 and, from timestamp 1, `eip7976TransitionTimestamp`,
`eip2780TransitionTimestamp`, `eip8037TransitionTimestamp`, `eip8038TransitionTimestamp`: the **Amsterdam regime**.

**Which regime decides.** The precompile may ship to customer chains, and one rule applies to every chain kind (owner
2026-10-21, 2026-10-25). Ethereum's next fork carries EIP-7976 and the contracts' build profile is Amsterdam for every
chain (NET-EVM-06), so a form is "built" only if it fits the **stricter** regime, EIP-7976. A chain that runs EIP-7623
alone would accept more, but no rule may depend on that.

## 2. Measurements per set (PQZH proof at its bound)

Every PQZH form the token builds (op 7 M ∈ {1, 2, 4}; M = 8 is not offered), as the relayed full transaction
(`mtxExecute`, outer fee 7; the other relay path, `uaExecute`, below the tables), plus the registration (`UARegistry.register` with the PQZ key) and the disclosure view
(`verifyTransferAmount`, an `eth_call`: Nethermind applies the same intrinsic / floor check to `eth_call`). Calldata =
the whole transaction's data (envelope + payload + proof + ML-DSA auth [+ hint]); the precompile input is built in
memory by the contract, so the statement itself is not calldata. The proof is the crate's bound `max_proof_len` (the
worst case a client can be handed; the vector proofs are 3–4 KB smaller). Gas in millions: standard calldata (4 / 16),
the precompile (provisional row + 3 per input word, CTR-PQZ-11), execution (everything else, ML-DSA-65 at 68,006
[estimate] included), the EIP-7976 floor, the transaction's regular gas as forge measures it (= max(15,000 + standard +
precompile + execution, floor)), and the EIP-7623-only floor of the same bytes. State gas (EIP-8037) is apart and does
not count against 2^24 (it is in the logs). **[measured]** for every column but the EIP-7623 floor, which is computed
from the measured bytes; the full regular gas under pre-Amsterdam pricing (no EIP-8037 / EIP-8038: state costs priced
differently) is **not** measured here.

`n2048-kmax1024`

| PQZH form | calldata B | standard | precompile | execution | EIP-7976 floor | regular (forge) | fits 2^24 | EIP-7623-only floor | fits by that floor |
|---|---|---|---|---|---|---|---|---|---|
| op 1, auditor, fresh ref | 256,772 | 3.97 | 5.52 | 2.34 | 16.45 | 16.45 | yes | 9.95 | yes |
| op 1, no auditor, fresh ref | 255,908 | 3.96 | 5.26 | 2.29 | 16.39 | 16.39 | yes | 9.92 | yes |
| op 1, auditor, materialised acc, no hint | 256,772 | 3.97 | 5.52 | 3.28 | 16.45 | 16.45 | yes | 9.95 | yes |
| op 1, auditor, materialised acc, hint | 267,620 | 4.14 | 5.52 | 2.64 | 17.14 | 17.14 | **no** | 10.38 | yes |
| op 7 M = 1, auditor | 256,836 | 3.97 | 5.05 | 2.36 | 16.45 | 16.45 | yes | 9.95 | yes |
| op 7 M = 1, no auditor | 255,972 | 3.96 | 5.64 | 2.30 | 16.40 | 16.40 | yes | 9.92 | yes |
| op 7 M = 2, auditor | 257,124 | 3.97 | 5.23 | 2.44 | 16.47 | 16.47 | yes | 9.96 | yes |
| op 7 M = 2, no auditor | 256,868 | 3.97 | 5.77 | 2.39 | 16.45 | 16.45 | yes | 9.95 | yes |
| op 7 M = 4, auditor (G = 2) | 318,372 | 4.88 | 6.46 | 3.53 | 20.39 | 20.39 | **no** | 12.21 | yes |
| op 7 M = 4, no auditor | 257,188 | 3.98 | 6.39 | 2.55 | 16.48 | 16.48 | yes | 9.96 | yes |
| burn 1 to an address | 255,780 | 3.96 | 4.89 | 2.21 | 16.38 | 16.38 | yes | 9.91 | yes |
| refresh | 255,780 | 3.96 | 4.89 | 2.20 | 16.38 | 16.38 | yes | 9.91 | yes |
| register (`UARegistry.register`) | 212,420 | 3.13 | 4.34 | 0.96 | 13.61 | 13.61 | yes | 7.84 | yes |
| disclosure sender / receiver / auditor, op 1 entry | 190,660 | 3.04 | 4.29 / 3.77 / 3.77 | 0.75–0.76 | 12.22 | 12.22 | yes | 7.62 | yes |
| disclosure receiver / auditor, op 7 M = 8 entry | 190,660 | 3.04 | 3.77 | 0.82–0.83 | 12.22 | 12.22 | yes | 7.62 | yes |

`n2304-kmax4096` (the default set)

| PQZH form | calldata B | standard | precompile | execution | EIP-7976 floor | regular (forge) | fits 2^24 | EIP-7623-only floor | fits by that floor |
|---|---|---|---|---|---|---|---|---|---|
| op 1, auditor, fresh ref | 274,948 | 4.25 | 5.52 | 2.61 | 17.61 | 17.61 | **no** | 10.65 | yes |
| op 1, no auditor, fresh ref | 274,820 | 4.25 | 5.26 | 2.55 | 17.60 | 17.60 | **no** | 10.65 | yes |
| op 1, auditor, materialised acc, no hint | 274,948 | 4.25 | 5.52 | 3.72 | 17.61 | 17.61 | **no** | 10.65 | yes |
| op 1, auditor, materialised acc, hint | 288,292 | 4.47 | 5.52 | 2.93 | 18.47 | 18.47 | **no** | 11.18 | yes |
| op 7 M = 1, auditor | 275,012 | 4.25 | 5.06 | 2.62 | 17.62 | 17.62 | **no** | 10.65 | yes |
| op 7 M = 1, no auditor | 274,884 | 4.25 | 5.64 | 2.57 | 17.61 | 17.61 | **no** | 10.65 | yes |
| op 7 M = 2, auditor | 276,036 | 4.27 | 5.24 | 2.72 | 17.68 | 17.68 | **no** | 10.69 | yes |
| op 7 M = 2, no auditor | 275,044 | 4.25 | 5.77 | 2.65 | 17.62 | 17.62 | **no** | 10.65 | yes |
| op 7 M = 4, auditor (G = 2) | 338,948 | 5.19 | 6.46 | 3.93 | 21.71 | 21.71 | **no** | 12.99 | yes |
| op 7 M = 4, no auditor | 276,100 | 4.27 | 6.40 | 2.84 | 17.69 | 17.69 | **no** | 10.69 | yes |
| burn 1 to an address | 274,692 | 4.25 | 4.89 | 2.47 | 17.60 | 17.60 | **no** | 10.64 | yes |
| refresh | 274,692 | 4.25 | 4.89 | 2.46 | 17.60 | 17.60 | **no** | 10.64 | yes |
| register (`UARegistry.register`) | 231,716 | 3.41 | 4.34 | 1.08 | 14.84 | 14.84 | yes | 8.55 | yes |
| disclosure sender / receiver / auditor, op 1 entry | 207,908 | 3.32 | 4.29 / 3.77 / 3.77 | 0.87 | 13.32 | 13.32 | yes | 8.31 | yes |
| disclosure receiver / auditor, op 7 M = 8 entry | 207,908 | 3.32 | 3.77 | 0.93 | 13.32 | 13.32 | yes | 8.31 | yes |

`n2560-kmax16384`

| PQZH form | calldata B | standard | precompile | execution | EIP-7976 floor | regular (forge) | fits 2^24 | EIP-7623-only floor | fits by that floor |
|---|---|---|---|---|---|---|---|---|---|
| op 1, auditor, fresh ref | 329,668 | 5.12 | 5.53 | 3.31 | 21.11 | 21.11 | **no** | 12.81 | yes |
| op 1, no auditor, fresh ref | 329,540 | 5.11 | 5.26 | 3.24 | 21.11 | 21.11 | **no** | 12.81 | yes |
| op 1, auditor, materialised acc, no hint | 329,668 | 5.12 | 5.53 | 4.61 | 21.11 | 21.11 | **no** | 12.81 | yes |
| op 1, auditor, materialised acc, hint | 345,796 | 5.37 | 5.53 | 3.68 | 22.15 | 22.15 | **no** | 13.45 | yes |
| op 7 M = 1, auditor | 329,732 | 5.12 | 5.06 | 3.32 | 21.12 | 21.12 | **no** | 12.81 | yes |
| op 7 M = 1, no auditor | 329,604 | 5.11 | 5.64 | 3.26 | 21.11 | 21.11 | **no** | 12.81 | yes |
| op 7 M = 2, auditor | 330,020 | 5.12 | 5.24 | 3.43 | 21.14 | 21.14 | **no** | 12.82 | yes |
| op 7 M = 2, no auditor | 329,764 | 5.12 | 5.78 | 3.35 | 21.12 | 21.12 | **no** | 12.81 | yes |
| op 7 M = 4, auditor (G = 1) | 331,428 | 5.14 | 6.46 | 3.65 | 21.23 | 21.23 | **no** | 12.87 | yes |
| op 7 M = 4, no auditor | 330,084 | 5.12 | 6.40 | 3.55 | 21.14 | 21.14 | **no** | 12.82 | yes |
| burn 1 to an address | 328,548 | 5.10 | 4.89 | 3.14 | 21.04 | 21.04 | **no** | 12.77 | yes |
| refresh | 328,548 | 5.10 | 4.89 | 3.13 | 21.04 | 21.04 | **no** | 12.77 | yes |
| register (`UARegistry.register`) | 260,292 | 3.84 | 4.34 | 1.26 | 16.67 | 16.67 | yes (0.11 M left) | 9.63 | yes |
| disclosure sender / receiver / auditor, op 1 entry | 234,436 | 3.74 | 4.29 / 3.77 / 3.77 | 1.03 | 15.02 | 15.02 | yes | 9.37 | yes |
| disclosure receiver / auditor, op 7 M = 8 entry | 234,436 | 3.74 | 3.77 | 1.07 | 15.02 | 15.02 | yes | 9.37 | yes |

**The other relay path, `uaExecute`** (review fix round of 2026-10-26, logs `runs/2026-10-26-t8d2b-fix-gas-<set>.txt`,
test `PqzStatePinGasTest.test_gasTable_pqzh_ua`, table script `runs/2026-10-26-t8d2b-gas-table.py pqzh
2026-10-26-t8d2b-fix-gas`). Every state-changing `mtx*` is relayable on both paths (owner rule), so a form is "built"
only if it fits on the costlier one. The `mldsa65` fee UA's envelope (a 3,309-byte ML-DSA-65 signature instead of
ECDSA's 65) adds **3,360 B** of calldata to every debit, so +215,040 gas under the floor (the e2e on the SCaaS testnet,
`runs/2026-10-26-t8d2b-e2e-7622.txt` section 5, shows 73,348 − 70,020 = 3,328 B for a pair of op 1 calls whose proofs
differ by 40 B: ≈ 3,368 B of envelope, the payloads not identical). Every debit is floor-bound on both paths, so the verdicts above stay.

**Accepted fee-UA kinds on `uaExecute` (C0-2 option (2), "a stated fee-UA list"; `runs/2026-10-27-review2-t2-holder-gas-<set>.txt`).** The fee UA's signature is part of the envelope, so its size is calldata under the floor. At PQZH `n2048-kmax1024`, burn 1 with an `mldsa65` holder: an `mldsa65` fee UA (precompile) fits (the table below), an `fndsa512` fee UA fits (16,429,976, a 666-byte signature), an `slhdsa128s` fee UA does **not** (16,890,776, over 2^24 by 113,560; a 7,856-byte signature). So `slhdsa128s` is the one excluded fee-UA kind, on `uaExecute` at PQZH `n2048-kmax1024`; via `mtxExecute` there is no fee UA (an ECDSA envelope). At the PQZL sets every fee-UA kind fits (op 7 M = 8 with the auditor and an `fndsa512` fee UA: 14.5–15.4 M).

At `n2048-kmax1024`, with an `mldsa65` fee UA:

| PQZH form at `n2048-kmax1024` | calldata B `mtxExecute` / `uaExecute` | regular gas `mtxExecute` / `uaExecute` | headroom to 2^24 `mtxExecute` / `uaExecute` |
|---|---|---|---|
| op 1, auditor, fresh ref (also materialised, no hint) | 256,772 / 260,132 | 16,448,408 / 16,663,448 | 328,808 (5,137 B) / 113,768 (1,777 B) |
| op 1, no auditor | 255,908 / 259,268 | 16,393,112 / 16,608,152 | 384,104 (6,001 B) / 169,064 (2,641 B) |
| op 7 M = 1, auditor / no auditor | 256,836 / 260,196; 255,972 / 259,332 | 16,452,504 / 16,667,544; 16,397,208 / 16,612,248 | 324,712 / 109,672; 380,008 / 164,968 |
| op 7 M = 2, auditor / no auditor | 257,124 / 260,484; 256,868 / 260,228 | 16,470,936 / 16,685,976; 16,454,552 / 16,669,592 | 306,280 / 91,240; 322,664 / 107,624 |
| op 7 M = 4, no auditor (the largest that fits) | 257,188 / 260,548 | 16,475,032 / 16,690,072 | 302,184 (4,721 B) / **87,144 (1,361 B)** |
| burn / refresh | 255,780 / 259,140 | 16,384,920 / 16,599,960 | 392,296 (6,129 B) / 177,256 (2,769 B) |
| op 1, materialised, hint; op 7 M = 4, auditor | 267,620 / 270,980; 318,372 / 321,732 | 17.14 / 17.36 M; 20.39 / 20.61 M | do not fit |

So on the post-quantum relay path the margin of every fitting n2048 debit is 0.09–0.18 M, one to two ML-DSA signatures'
worth of bytes: any envelope growth (for example the planned metatx split / `MtxRelayFee`) must re-check it.

`n2816-kmax65536` has no PQZH (owner 2026-10-24).

**Largest PQZH form that fits 2^24 under EIP-7976:**

- `n2048-kmax1024`: every built debit form **except op 7 M = 4 with the auditor** (G = 2 since the R0 fix), and only
  **without the `acc` hint** (the hint's 10,848 B push the materialised op 1 to 17.14 M). Largest that fits: op 7
  M = 4 without the auditor, 257,188 B, 16.48 M (302,184 gas ≈ 4,721 B left via `mtxExecute`; 87,144 gas ≈ 1,361 B via
  `uaExecute`). Every debit there is floor-bound with 0.30–0.39 M of headroom via `mtxExecute` and 0.09–0.18 M via
  `uaExecute`; the vector proofs (3–4 KB under the bounds) do not change the verdicts.
- `n2304-kmax4096`: **no debit form** (op 1, op 7, burn, refresh all ≥ 17.60 M; even the honest vector proofs, e.g.
  R_TX 248,120 B → ≈ 271,460 B of calldata, stay above 261,909). Only registration (14.84 M) and the disclosure view
  (13.32 M) fit.
- `n2560-kmax16384`: **no debit form** (≥ 21.04 M). Registration (16.67 M) and the disclosure view (15.02 M) fit.

Under EIP-7623 alone every form at every set fits by the floor (the largest, n2304's op 7 M = 4 with the auditor,
needs a floor of 12.99 M), and a debit's standard path (15,000 + standard + precompile + execution) at Amsterdam prices
is 11.1–15.6 M; its regular gas under Osaka pricing was not measured here.

What a debit proof would have to shrink to (EIP-7976, the bound, the measured per-form overhead = calldata − proof):

The overheads are `mtxExecute`'s; `uaExecute` adds 3,360 B, so every "bound needed" is 3,360 B lower on that path (at
`n2048-kmax1024` op 1 / burn / op 7 M ≤ 2: ≤ 237,247, still above today's 235,470). The op 1 / burn / op 7 M ≤ 2 bound
column gives op 1's bound; op 7 M = 2 with the auditor has 252,328 at `n2304-kmax4096` (−5.5 % needed).

| set | op 1 / burn / op 7 M ≤ 2 overhead → proof bound needed | today's bound | op 7 M = 4 auditor overhead → bound needed | today's bound |
|---|---|---|---|---|
| `n2048-kmax1024` | 21,302 B → ≤ 240,607 | 235,470 (fits) | 38,616 B → ≤ 223,293 | 279,756 (−20 %) |
| `n2304-kmax4096` | 23,340 B → ≤ 238,569 | 251,608 (−5.2 %) | 42,700 B → ≤ 219,209 | 296,248 (−26 %) |
| `n2560-kmax16384` | 25,402 B → ≤ 236,507 | 304,266 (−22 %) | 26,308 B → ≤ 235,601 | 305,120 (−23 %) |

## 3. Options

The rules every option is checked against: customer chains (no gas price 0, no own block limit; Ethereum-like limits,
so the EIP-7976 regime), one rule for every chain kind, ciphertexts never leave contract state, every state-changing
`mtx*` relayable.

### (A) Build only what fits (D20)

PQZH offers on chain only the forms under the cap, per set: at `n2048-kmax1024` every built form except op 7 M = 4
with the auditor (and clients send no hint for PQZH); at `n2304-kmax4096` and `n2560-kmax16384` registration and
disclosures only — **no PQZH debit at the default set**. Cost: no protocol or core change; documents (PQZH.md, the
sets README, spec §12 item 4, CTR-PQZ-11 / D20), the client's PQZH form list per set, optionally a deploy-time rule that
no PQZH token release (env with a PQZH `UAPqzVerifier`) is published at a set whose debits do not fit (a token whose
holders can never debit would trap funds). Optionally the token could refuse op 7 M = 4 with the auditor for PQZH at
n2048 (one line next to the existing M = 8 refusal), but the chain refuses that transaction anyway.
Rules: customer chains ✓ (judged in the stricter regime), one rule ✓, ciphertexts ✓ (unchanged), relayable ✓.
What it gives up: PQZH as a working **backup** proof system for value transfers at n2304 / n2560 — if PQZL had to be
switched off, PQZH tokens at those sets could register and disclose but not move value. It stays the backup only in
the sense "proofs exist and verify; a chain with a higher per-transaction cap could use them".

### (B) Proof upload in chunks across transactions

The proof goes into contract state in pieces (the EVM can read data only from calldata, state or code), then the
debit transaction verifies from state. Cost [estimate from Task 7b's ≈ 1,530 state gas per SSTORE2 byte]: a
251,608 B proof is ≈ 385 M of EIP-8037 state gas, permanently (code cannot be deleted since EIP-6780; storage slots
cost about twice as much per byte). One 64 KiB code chunk (EIP-7954's limit) is ≈ 100 M state gas, over a 60 M
mainnet block in the state dimension, so ≈ 7 chunk transactions of ≤ 39 KB each per debit, plus the debit itself
(≈ 23 KB of calldata, the precompile reading ≈ 250 KB with EXTCODECOPY: fits 2^24). ≈ 0.4 ETH of state gas per debit
at 1 gwei. A hash-chained calldata variant (store only a running keccak) does not help: the precompile needs the bytes
in memory in the final call, so they would be calldata again. Ligero does not split into independently verifiable
pieces either (`pqzh-starkex-verifier.md`: every piece needs the ≈ 418 KB of shared vectors again).
Rules: customer chains ✓ technically, but the cost is prohibitive; one rule ✓; ciphertexts ✓; relayable ✓ (chunk
uploads can be content-addressed `mtx*` writes). State bloat of ≈ 250 KB per debit for data that never needs to persist
(unlike ciphertexts). Contract work: a chunk store, an op form that reads the proof from it, gas pins; no core change.

### (C) PQZH parameter changes (Ligero rate / t), reopens the `pqz-core` dev-freeze

The bounds would have to drop by 5.2 % (n2304 op 1 / op 7 M ≤ 2 / burn), 20–26 % (op 7 M = 4 with the auditor) and
22–23 % (every n2560 debit) (table above). The presets are already the result of a size-minimising search at the
soundness floor (`ligero_params.py`; spike B: t = 119 is the minimum for 128 query bits, ≈ 0.94 bits per column, each
column ≈ m + 12 field elements plus Merkle digests). Lowering t by the ≈ 10 columns n2304's op 1 needs would cost
≈ 9 bits of query soundness (below the 128-bit target); a different rate or k trades the fixed part (O(k)
extension-field values) against the column size and was searched already. [inference] A 20 %+ cut is not reachable
inside Ligero at the proven soundness; a different PQZH backend (WHIR / FRI, `pqzh-zk-whir.md`,
`pqzh-backend-comparison.md`) has larger proofs. Cost: new presets / ids for three sets, vectors, the four gates,
Nethermind corpus, re-review of the transcript and parameters — days to weeks, with an uncertain result for n2304 op 1
and a negative one for the rest.
Rules: ✓ on all four if it worked; it does not keep the current 127+ bit soundness.

### (D) Blob data (EIP-4844) — does not help

A contract sees a blob only through `BLOBHASH` (its versioned hash) and the point-evaluation precompile (one KZG opening
per call, 50,000 gas per 31-byte element): reading a 250 KB proof would cost ≈ 400 M gas. The execution client does not
hold blob contents at execution time (they travel as consensus-layer sidecars and are pruned after ≈ 18 days), so a
precompile cannot read them without a consensus change, and KZG is not post-quantum. Ruled out.

### (E) Other options found

- **A chain profile without EIP-7976** (EIP-7623 only: 418,905 B): every form fits by the floor, but it breaks "one
  rule for every chain kind" and the Ethereum-like rule for customer chains (Ethereum's next fork has EIP-7976). Ruled
  out under the current rules; recorded because a customer chain on Osaka rules would in fact accept PQZH debits.
- **Two-phase verification** (verify a first sub-proof in transaction 1, record a fact keyed by the statement hash,
  verify the rest and apply the debit in transaction 2; T is stable between the two by D4 / D6): needs a PQZH relation
  that splits into independently sound pieces — new cryptography in `pqz-core`, not explored.
- **No hint for PQZH** (a client rule, part of A): at n2048 the hint alone moves the materialised op 1 over the cap.
  Generally, under EIP-7976 the hint saves gas only when the transaction is not floor-bound (PQZL: 0.5–0.9 M saved;
  PQZH: 0.7–1.0 M more).
- **Recursion / aggregation** (one outer proof per batch, `pqzh-starkex-verifier.md`): a prover service, out of scope
  for a per-transaction backup.

## 4. Controller proposal (owner decides)

**(A), recorded as a ruling:** PQZH stays the backup proof system and offers on chain exactly what fits one 2^24
transaction under EIP-7976 on both relay paths — at `n2048-kmax1024` every built form but op 7 M = 4 with the auditor,
without the hint (on `uaExecute` with only 1.3–2.8 KB to spare, so any envelope change re-checks it); at
`n2304-kmax4096` and `n2560-kmax16384` registration and disclosure only — with a deploy-time rule that no PQZH token
release is published at a set whose debits do not fit. No core change, the dev-freeze holds. (B) is possible but costs
≈ 385 M state gas per debit and permanent state, (C) cannot reach the needed sizes at the proven soundness, (D) cannot
work. If the owner wants PQZH to move value at the default set, the realistic paths are a chain that accepts larger
transactions (outside the current one-rule policy) or a different backend — both a new decision.

**Owner ruling 2026-10-27: (A).** Open, from the contracts review of 2026-10-26 ([C0-2](../../pqz-core/research/code-review-2026-10-26/README.md), P1): "fits" was measured for a single-key `mldsa65` holder and fee UA; a PQ-eligible `msig` holder (one ML-DSA-65 signature, 3,309 B, per signing member) exceeds the `n2048-kmax1024` headroom, and [C2-1](../../pqz-core/research/code-review-2026-10-26/README.md) (P1): `PqzStateLib.init` does not yet refuse a PQZH token at a set without a fitting debit. Owner 2026-10-27: at `n2048-kmax1024` only single-key `mldsa44` / `mldsa65` / `fndsa512` holders; `init` refuses PQZH at the other two sets (built in the review fix round).
