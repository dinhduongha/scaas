# Parameter set `n2560-kmax16384` (16k)

The 16k set of plan 5h Task 7 (research record [`pqz-core/pqzl/params/p16k/`](../../../pqzl/params/p16k/results-16k.md)),
approved as the Task 8 set on 2026-10-20 (owner ruling Q1) and superseded as the default by
[set (a)](../n2304-kmax4096/SET.md) on 2026-10-21; the owner keeps it as a **shippable** set (2026-10-21: a customer
chain may choose it): full vectors, its own gate, this file. Input: [`set.toml`](set.toml); every other file here is
derived (see [`../README.md`](../README.md)).

| Item | Value |
|---|---|
| ring | n = 2560 = k·d, k = 40, d = 64 |
| q | 2^50 − 42,310,535 = 1,125,899,864,532,089 (prime, q ≡ 9 mod 16; q − 1 divisible by 2^3·19·43·431, PQZH's radices) |
| Δ | ⌊q / 2^20⌋ = 1,073,741,783 (odd) |
| `K_MAX` | 16,384; digit sums `M_i` 18 bits, carries 15 bits, `e_T` / `e'` + 2^28 in 29 bits |
| norm bounds | β_s 40, β_e 182, β_2 64; B_FRESH 14,624; mint margin 3.36 |
| proof MLWE rank (`kmlwe_min`) | 39 (`e-s1.txt`) |
| encryption, no hints | uSVP β 508; 2^145.7 classical / 2^132.7 quantum (dual_hybrid β 499 / 500) (`p16k/results-16k.md` §2) |
| encryption, 80 hints | DDGR20 worst case β 482.43; dual_hybrid on the hinted instance 474.43 / 476.43 [estimate: n − 80 model minus the measured offset] (n-study §3.3) |
| e_s0 | `e-s0.txt` |
| proofSystemId | the v3 label until the plan 5h Task 8d bump (owner ruling 2026-10-21); the 16k label of spec §6.4 (`mlwe-d64k40-q50l4`) is superseded |
| owner approval | 2026-10-20 (Q1, the Task 8 set), 2026-10-21 (superseded as default by set (a); kept shippable) |
| stored-blob packing width (P46 ruling) | ⌈log2 q⌉ = 50 bits (P50); `PqzSet.sol` `PACK_BITS`; built in 8d |
| PQZH | q is PQZH-compatible; not built for this set until plan 5h Task 8c (pqz-ffi / pqz-vectors / the gate skip it) |

## Conditions for this set to work on a chain

Measured where marked; the rest [estimate]. Gas figures are Task 7b's under Ethereum's Amsterdam rules at the 16k sizes
(Foundry 1.8.5 = Nethermind 2.2.0 on the same transactions; `p16k/results-16k.md` §8), with the precompile priced at
today's PQZL v3 rows × 1.25 [estimate].

1. **Contracts built for this set.** Today's contracts (`PqzCt`, `PqzCore`, …) carry the v3 constants; a chain runs
   this set only after plan 5h Task 8d wires them to `PqzSet.sol` and the build selects this set
   (`make.sh n2560-kmax16384 sol`). Until then: not deployable.
2. **Per-transaction regular gas ≤ 2^24** (Ethereum-like cap; no zero-gas or own-block-limit assumption, owner
   2026-10-21): relayed op 1 (auditor) 8.93 M fresh / 10.53 M with a materialised `acc` [measured, precompile
   estimate]; op 7 M = 1 / 2 / 4 6.72 / 6.92 / 7.68 M; `mtxPrepareAcc` halves 4.02 M each; `mtxRollOver` at `ROLL_MAX`
   80: 12.36 M (≤ 0.75·2^24, the rollover rule) [measured]. op 7 M = 8 (G = 2): 7.22 M with the precompile mocked
   [measured], whether M = 8 is allowed on chain is decided in 8d.
3. **Calldata ≤ the EIP-7976 floor's 261,909 B per transaction:** the largest relayed PQZL calldata is 83,524 B (op 7
   M = 4, auditor) [measured]; the precompile input (≤ 222,967 B at M = 4) is built in memory by the token, bounded by
   `MAX_INPUT`, not by calldata.
4. **Block gas limit for the state dimension (EIP-8037):** every debit stores its op blob in state (SSTORE2; "Không
   được mất ciphertext": ciphertexts are never only in calldata / events): ≈ 32.8–34.8 M state gas per op 1 / op 7
   M ≤ 4 and 31.8 M per prepare half [measured], ≈ 68.7 M for op 7 M = 8 [measured, precompile mocked]; so one debit
   needs a block gas limit ≥ ≈ 43 M (regular + state), op 7 M = 8 ≥ ≈ 76 M. The P50 packing of 8d (stored data only,
   ⌈log2 q⌉ = 50 bits) lowers the blob's state gas by about 22 % (50 of 64 bits per
   stored coefficient) [estimate; the P46 spike measured −8.10 M per op 1 at set (a)]. Ethereum mainnet's 60 M block holds one 16k debit; Glamsterdam's expected 200 M holds about
   four. The real cost (state gas is paid) applies on a customer chain.
5. **`ROLL_MAX` 80** (largest multiple of 16 with the relayed rollover ≤ 0.75·2^24 regular gas) [measured, Task 7b].
6. **PQZH:** a backup only — its debit inputs (406–469 KB) exceed one transaction's calldata; `R_REG` fits
   [Task 7b]. Built for this set in 8c.
7. **Security margins:** encryption β 508; ≤ 80 worst-case hints on one `(r_g, e1_g)` (op 7 group of 4 legs + auditor)
   β 482.4 (above 450, no exception needed); proof MSIS / MLWE β ≥ 450 per spec (`e-s1.txt`); exactness and
   Fiat–Shamir rounds MET (`e-s0.txt`); mint margin 3.36.
8. **Verify time** (≤ 60 ms p99 wasm32, the precompile's budget): not re-measured for this set (owner rule: no timing
   runs during this task); the proof sizes are ≈ 12 % above set (a)'s.

Proof sizes: see `smartcontracts/vectors/pqz/n2560-kmax16384/proof_pqzl.json` (filled in by this set's vectors run).
