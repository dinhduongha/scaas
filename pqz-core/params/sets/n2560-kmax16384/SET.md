# Parameter set `n2560-kmax16384` (shippable)

The `K_MAX` 16,384 set of plan 5h Task 7 (research record [`pqz-core/pqzl/params/p16k/`](../../../pqzl/params/p16k/results-16k.md)),
approved as the Task 8 set on 2026-10-20 (owner ruling Q1) and superseded as the default by
[`n2304-kmax4096`](../n2304-kmax4096/SET.md) on 2026-10-21; the owner keeps it as a **shippable** set (2026-10-21: a customer
chain may choose it): full vectors, its own gate, this file. Input: [`set.toml`](set.toml); every other file here is
derived (see [`../README.md`](../README.md)).

| Item | Value |
|---|---|
| ring | n = 2560 = k·d, k = 40, d = 64 |
| q | 2^50 − 42,310,535 = 1,125,899,864,532,089 (prime, q ≡ 9 mod 16; q − 1 divisible by 2^3·19·43·431, PQZH's radices) |
| Δ | ⌊q / 2^20⌋ = 1,073,741,783 (odd) |
| `K_MAX` | 16,384; digit sums `M_i` 18 bits, carries 15 bits, `e_T` / `e'` + 2^28 in 29 bits |
| norm bounds | β_s 40 (CBD(1)), β_e 182 (CBD(20)), β_2 64; B_FRESH 14,624; worst case 16,383 · B_FRESH = 239,584,992 < E = 2^28 (margin 1.12), mint margin 3.36 (`worstcase_noise.json`) |
| proof MLWE rank (`kmlwe_min`) | 39 (`e-s1.txt`: every one of the 14 specs meets MSIS β 455–468, hiding MLWE uSVP 470–475, dual_hybrid 462 / 463 at `pqz_delta` 1.00366; the codegen default rank 38 gives dual_hybrid 446 / 447) |
| encryption, no hints | uSVP β 508; 2^145.7 classical / 2^132.7 quantum (dual_hybrid β 499 / 500) (`p16k/results-16k.md` §2) |
| encryption with hints (op 7 groups) | since the R0 review fix (R0-1, `s_aud` = 4: 32·4 = 128 worst-case hints with the auditor): DDGR20 β 467.60, dual_hybrid − offset 458.60 / 460.60 [estimate] (`pqzl/params/anon/hints-s.txt`); 64 hints without the auditor; was 482.43 / 474.43 at 80 |
| e_s0 | budget, exactness of every norm proof (14 relations) and Fiat–Shamir rounds (λ = 4 read from the headers: 200.00 bits; the final challenge from the η-filtered set the cores sample since the R0 review fix, R0-C3: P = 0.9143, 2/\|C\| = 2^-129.67): MET (`e-s0.txt`) |
| proofSystemId | PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k40-q50l4/v5")` = `0xeacf34a3…276882` (R0 review fix 2026-10-25; v4 `0xa3db21fc…70262d` retired); PQZH `keccak256("scaas/pqz/pqzh/ligero-fq50-n32756k817t122-keccak256-zk-proven/v3")` = `0xc93f3bdd…3f3662` (R0 review fix; v2 `0xe83ad1da…109851` retired) (set.toml `pqzl_id` / `pqzh_id`; plan 5h Task 8d, the one bump of Task 8: controller proposal, decisions CTR-PQZ-09) |
| owner approval | 2026-10-20 (Q1, the Task 8 set), 2026-10-21 (superseded as default by `n2304-kmax4096`; kept shippable) |
| stored-blob packing width (P46 ruling) | ⌈log2 q⌉ = 50 bits; `PqzSet.sol` `PACK_BITS`; built in 8d part 2: stored `ct` 16,100 B (64-bit lanes 20,608), `acc` 504 slots |
| PQZH | built (plan 5h Task 8c part 2): THE preset's radices and n / k (n 32,756, k 817) with t = 122 (owner 2026-10-23), `pqzh_set.rs` generated from `set.toml` `[pqzh_preset]`; debit bounds 303,412–305,120 B exceed 262,144 → **owner 2026-10-23: `MAX_PROOF_PQZH` = 327,680 B (320 KiB) for this set only** (decisions CTR-PQZ-10), in `pqz-stmt` with `MAX_INPUT` 524,288; in pqz-ffi, the vectors and the gate; conditions: [PQZH.md](PQZH.md) |
| LaZer codegen headers | byte-identical to the p16k record's (`pqzl/params/p16k/`, the 12 relations it has) |
| upstream KAT | `lazer-3330e48-kat.json`: pqz-core = upstream LaZer 3330e48 (+ HEXL), 19/19 |

## Conditions for this set to work on a chain

Measured where marked; the rest [estimate]. Gas figures are Task 7b's under Ethereum's Amsterdam rules at this set's sizes
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
   stored coefficient) [estimate; the P46 spike measured −8.10 M per op 1 at `n2304-kmax4096`]. Ethereum mainnet's 60 M block holds one debit of this set; Glamsterdam's expected 200 M holds about
   four. The real cost (state gas is paid) applies on a customer chain.
5. **`ROLL_MAX` 80** (largest multiple of 16 with the relayed rollover ≤ 0.75·2^24 regular gas) [measured, Task 7b].
6. **PQZH:** a backup only — its debit proofs (bounds 303,412–305,120 B [crate]) need this set's `MAX_PROOF_PQZH` of
   327,680 B (owner 2026-10-23, built in 8c part 2), and its debit inputs (largest 493,445 B at the limit, 470,885 B at
   the bound ≤ `MAX_INPUT` 524,288, which the node takes from the library since 8d part 1) exceed one transaction's calldata; `R_REG`
   fits. [PQZH.md](PQZH.md).
7. **Security margins:** encryption β 508; ≤ 80 worst-case hints on one `(r_g, e1_g)` (op 7 group of 4 legs + auditor)
   β 482.4 (above 450, no exception needed); proof MSIS / MLWE β ≥ 450 per spec (`e-s1.txt`); exactness and
   Fiat–Shamir rounds MET (`e-s0.txt`); mint margin 3.36.
8. **Verify time** (≤ 60 ms p99 wasm32, the precompile's budget): not re-measured for this set (owner rule: no timing
   runs during this task); the proof sizes are 6–8 % above `n2304-kmax4096`'s (below).

Proof sizes (`smartcontracts/vectors/pqz/n2560-kmax16384/proof_pqzl.json`, byte-identical C = Rust = wasm32): TRANSFER
50,391 B, TRANSFER0 50,053, BURN 49,538, REFRESH 49,527, REGISTER 32,452, DISCLOSE-SENDER 32,985, -RECEIVER 33,763,
-AUDITOR 33,771; op 7 with the auditor M = 1 / 2 / 4 / 8: 50,390 / 51,216 / 54,817 / 72,704 B, without 50,031 /
50,557 / 51,558 / 69,888 B (all below `MAX_PROOF` 98,304). Object sizes: pk 20,480 B, ciphertext 20,608 B, op 1
statement 103,552 B (auditor on). Heap: C prover arena peaks (`pqz-core/runs/gate/t8b-n2560-fnv-c.jsonl`) 141 MB
(R_REG) … 457 MB (R_TX) … 1,094 MB (R_TXM M = 8 with the auditor: needs `PQZ_ARENA_MB=2048`).

Files: `set.toml` (input), `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, `<rel>_params.sage` (gen_set.py),
`pqz_<rel>_params.h` + `codegen.txt` (LaZer codegen), `rust/<rel>.rs` (to_rust.py), `e-s1.txt`, `e-s0.txt`,
`lazer-3330e48-kat.json` (+ `-build.txt`); made by `make.sh n2560-kmax16384 all`.
