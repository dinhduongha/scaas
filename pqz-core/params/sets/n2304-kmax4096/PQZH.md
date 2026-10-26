# Conditions for a chain to run PQZH — set `n2304-kmax4096`

PQZH (Ligero over F_q, `pqz-core/pqzh/ligero`) is the **backup** proof system (owner 2026-10-21); PQZL is the one on
chain. This file says what a chain needs before it can accept PQZH proofs at this parameter set. Plan 5h Task 8c
part 1 and 1b (preset B, owner 2026-10-22), part 2 (the preset in `set.toml` `[pqzh_preset]`, `pqzh_set.rs` generated;
PQZH in pqz-ffi, the vectors `smartcontracts/vectors/pqz/n2304-kmax4096/proof_pqzh.json` and the gate); the PQZH
`proofSystemId` of this set (Task 8d) is `keccak256("scaas/pqz/pqzh/ligero-fq46-n45752k952t120-keccak256-zk-proven/v3")` = `0x046859a8…944ead` (R0 review fix; v2 `0xe4bc6d17…885730` retired). [`SET.md`](SET.md) is this set's main description.

Sources: `[crate]` = the Rust crate built with `--features set-n2304-kmax4096` (`pqz-core/pqzh/ligero/runs/c8b-a-*`,
preset B); `[model]` = `python3 -I pqz-core/pqzh/ligero/ligero_params.py --set n2304-kmax4096`
(`runs/c8-params-n2304-kmax4096.txt`, equal to the crate on all 14 relations it checks); `[measured]` = an earlier
measurement named in place; `[estimate]` = scaled or assumed, not measured.

## Field and domains [crate]

| item | value |
|---|---|
| q | 61,275,424,977,257 (2^45.80), q ≡ 9 mod 16; q − 1 = 2^3 · 7 · 17 · 19 · 43 · 431 · 182,789 |
| F_q element in a proof | 46 bits in 6 bytes, big-endian, canonical (as at `n2048-kmax1024`) |
| extension | F_q^4 = F_q[X]/(X^4 − 3), 3 a non-square, \|F_q^4\| = 2^183.2 |
| generator | 3 (generates F_q^*) |
| domains | **preset B** (owner 2026-10-22): n = 45,752 = 2^3·7·19·43 (code on the coset 3·H_n), k = 952 = 2^3·7·17 (messages on H_k), t = 120, l = 831, products on H_2261 (7·17·19); FFT radices 2 / 7 / 17 / 19 / 43 / 431 (7 and 17 through the generic r-point stage); 3·H_n misses H_k (tested). `n2048-kmax1024`'s preset (THE preset: n 32,756, k 817, t 121) is the fallbacks' (below) |
| arithmetic | native: Barrett, u128 products; wasm32: three 16-bit limbs in u64 (no 64 × 64 → 128 multiply) |
| constants | `pqzh_set.rs` (this directory; the fallbacks' preset in `pqzh_set_fallback.rs`, spike B's t = 119 file `pqzh_set_spike_b.rs` kept, not compiled) + `rust/set.rs` (PQZL's) |

## Soundness [crate]

Every relation: 127.40 bits in total (query 128.94 = 120 columns × 0.9412 + 16 grinding; Keccak 128;
proximity ≥ 159.7, linear ≥ 169.3, quadratic 183.2). `n2048-kmax1024` and THE preset here: 127.23 (query 128.50); t = 120 is one
column above the model's minimum 119 so that the total stays above 127.23 (owner 2026-10-22). The query term depends
on n and k only, the field terms grow with q (`n2048-kmax1024`: 145.0 / 154.3 / 168.0).

## Sizes per form

The bound is the verifier's exact maximum (`Params::max_len_exact`): the length gate before anything is parsed.
Honest proofs: seeds 0 and 1 of the crate's test inputs (`runs/c8b-a-kat.jsonl`). Bounds `runs/c8b-a-sizes.jsonl`.

| relation | rows m | proof bound B [crate] | honest proofs B [crate] | statement B | input 5 + stmt + bound B |
|---|---|---|---|---|---|
| R_REG (op 3) | 63 | 207,688 | 204,358–204,936 | 18,528 | 226,221 |
| R_DS (op 4) | 63 | 207,688 | 204,616–205,416 | 37,280 | 244,973 |
| R_DR / R_DA (op 5) | 63 | 207,688 | 204,552–204,936 | 37,280 | 244,973 |
| R_TX (op 1, auditor) | 124 | 251,608 | 248,312–248,952 | 93,312 | 344,925 |
| R_TX0 (op 1, no auditor) | 124 | 251,608 | 247,544–248,376 | 74,752 | 326,365 |
| R_BURN / refresh (op 2) | 124 | 251,608 | 247,176–248,440 | 56,192 | 307,805 |
| R_TXM op 7 M = 1 / 2, auditor | 124 / 125 | 251,608 / 252,328 | 247,304–249,880 (with M = 4 at G = 1) | 93,312 / 112,000 | 344,925 / 364,333 |
| R_TXM op 7 M = 4, auditor (G = 2 since the R0 review fix; was 126 rows, 253,048 / 149,376 / 402,429 at G = 1) | — | 296,248 | 291,540–293,272 (`pqz-core/runs/gate/r01a-fix-n2304-kmax4096-ligero-multi.txt`) | 167,808 | 464,061 |
| R_TXM op 7 M = 1 / 2 / 4, no auditor | 124 / 124 / 125 | 251,608 / 251,608 / 252,328 | 246,792–249,384 | 74,752 / 93,312 / 130,432 | 326,365 / 344,925 / 382,765 |
| R_TXM op 7 M = 8, auditor / no auditor (not a PQZH shape; with the auditor G = 3 since the R0 review fix, was G = 2: 187 rows, 296,968 / 242,560 / 539,533) | — / 186 | 340,168 / 296,248 [not built; `../README.md` PQZH table] | — | 260,992 / 223,104 | 601,165 / 519,357 |

- `MAX_PROOF_PQZH` = 327,680 (owner 2026-10-25, decisions CTR-PQZ-10: the R0-1 audited R_TXM M = 4 with G = 2 has the
  bound 296,248, above the 262,144 kept until then): **every built form fits**, the largest bound by 31,432 B. With
  G = 1 preset B kept every debit bound 9,096–10,536 B under 262,144 (THE preset's were 1,640–3,092 B above it; see
  "Fallbacks").
- `MAX_INPUT`: pqz-stmt's at this set is 524,288 (512 KiB, plan 5h Task 8c part 2; decisions O8): every built form
  fits (largest input 464,061 at the bound, 495,493 = 5 + 167,808 + 327,680 at `MAX_PROOF_PQZH`). The node takes its
  limit from the library (`pqz_max_input()`, 524,288 at this set) since Task 8d part 1; before, its 393,216 did not fit
  op 7 M = 4 with the auditor.

## One transaction's calldata (EIP-7976) [measured, plan 5h Task 8d part 2b]

A transaction pays at least 15,000 + 64 gas per calldata byte (EIP-7976 floor, Task 7b's formula [measured on
Foundry 1.8.5 Amsterdam]); with Ethereum's per-transaction regular-gas cap 2^24 (EIP-7825) that is at most
**261,909 B**. Through the token or the registry the precompile input is built in memory, so only the call's calldata
(payload + proof + UA auth) counts; the proof at its bound:

| relation | path | calldata B | floor gas | fits 2^24 | smallest per-tx cap (floor) |
|---|---|---|---|---|---|
| R_REG | `UARegistry.register` | 231,716 | 14,844,824 | yes | 14.84 M |
| R_DS / R_DR | `verifyTransferAmount` (`eth_call`) | 207,908 | 13,321,112 | yes | 13.32 M |
| R_TX / R_TX0 | relayed `mtxExecute` (op 1) | 274,948 / 274,820 | 17,611,672 / 17,603,480 | **no** | 17.61 / 17.60 M |
| R_BURN / refresh | relayed `mtxExecute` (op 2) | 274,692 | 17,595,288 | **no** | 17.60 M |
| R_TXM op 7 M = 1 / 2, auditor | relayed `mtxExecute` | 275,012 / 276,036 | 17.62 / 17.68 M | **no** | 17.62 / 17.68 M |
| R_TXM op 7 M = 4, auditor (G = 2) / no auditor | relayed `mtxExecute` | 338,948 / 276,100 | 21.71 / 17.69 M | **no** | 21.71 / 17.69 M |

The largest proof one 2^24 transaction can carry on the debit paths is ≈ 237.6–238.8 KB. **A PQZH debit needs a
per-transaction regular-gas cap of at least ≈ 17.7 M, ≈ 21.8 M for op 7 M = 4 with the auditor** (e.g. 2^25; measured
through the token, `smartcontracts/evm/runs/2026-10-26-t8d2b-gas-n2304-kmax4096.txt`); with 2^24 only registration and the disclosure
`eth_call`s work. A direct call to the precompile carries the whole input as calldata: R_REG / R_DS / R_DR fit 2^24
(226,221 / 244,973 B), the debit forms do not.

## Gas per operation [estimate]

| item | value |
|---|---|
| PQZH precompile row (`G_op`) | **not calibrated at this set.** The SCaaS testnet runs provisional rows until plan 5h Task 9 (`pqz-core/nethermind/chain/engine-pqz-provisional-n2304.json`: transfer 5,492,000, transfer0 5,227,000, register 4,319,000 = the retired rows below × 1.3). The retired `n2048-kmax1024` rows [measured, P6f 2026-10-15, old ids]: transfer 4,225,000, transfer0 4,021,000, burn 3,738,000, register 3,322,000, disclose 3,283,000 / 2,881,000 (p99 valid 8.0–11.8 ms native). Part 1's row-scaled estimate for THE preset here (m + 12: 177 / 137, 95 / 75) ≈ 5.5 M transfer, ≈ 4.2 M register [estimate]; preset B's verifier does 0.97–1.04× THE preset's base-field products at this set [counted, spike B `runs/spike-b-count*.jsonl`], so the same estimate stands |
| regular gas of a debit | floor-bound [measured, plan 5h Task 8d part 2b, through the token at the provisional rows]: 17.60–17.69 M, 21.71 M for op 7 M = 4 with the auditor (the floor above; the execution part stays below it) |
| state gas of a debit (EIP-8037) | as PQZL's, independent of the proof system: op 1 29.63 M with 64-bit lanes, 21.54 M with the P46 layout of Task 8d; op 7 M = 4 31.64 / 23.21 M [measured at `n2304-kmax4096`, spike PACK `55d38e61`, precompile burnt]; through the built contracts (P46) a relayed PQZL R_TX stores 21.44 M [measured, plan 5h Task 8d part 2b] |
| total of a debit | ≈ 47 M (64-bit lanes) / ≈ 39 M (P46) [estimate, from the measured parts] |
| R_REG | regular ≈ max(14.67 M floor, execution) ≤ 2^24 [estimate]; state: the stored key as PQZL's registration |

## Block gas limit

One PQZH debit needs ≈ 39 M (P46) to ≈ 47 M (64-bit lanes) of block gas [estimate]: a 60 M block holds one (two PQZL
op 1 debits fit the same block with P46). The block must also allow the per-transaction cap above (≥ 17.8 M regular).

## Verify time

Target: p99 ≤ 60 ms in wasm32 (and native on the chain host). **Not measured at this set** (no timing in Task 8c). For
reference, `n2048-kmax1024`'s wasm32 p99 honest verify was 15–24 ms (`runs/rev2-proven-wasm.jsonl`, before the set-generic field,
which also changed the wasm32 reduction); at this set preset B's verifier does 0.97–1.04× the base-field products of
THE preset [counted, spike B], whose rows are 1.3× `n2048-kmax1024`'s [estimate, part 1]. Calibrate before any chain uses it.

## Summary: what a chain needs for PQZH at this set

1. The set's PQZH `proofSystemId` (PQZH v3 since the R0 review fix) in the chainspec's schedule rows, with `G_op`
   calibrated at this set (not done; the SCaaS testnet's rows are provisional).
2. Debits (op 1 / 2 / 7): a per-transaction regular-gas cap ≥ ≈ 17.7 M, ≥ ≈ 21.8 M for op 7 M = 4 with the auditor
   (2^24 is not enough). Proof sizes: every bound is under `MAX_PROOF_PQZH` 327,680 (raised from 262,144 on 2026-10-25
   for the audited op 7 M = 4).
3. Registration and disclosures: work under 2^24.
4. A block gas limit ≥ ≈ 47 M (≈ 39 M with P46) per PQZH debit.
5. Verify time measured ≤ 60 ms p99 (not yet).

## Fallbacks (owner 2026-10-22)

Production at this set is preset B (above; owner 2026-10-22: "chọn B, A và C là các phương án dự phòng"). Two
fallbacks are kept for the case that B is rejected later (e.g. by a review of its domains or a chain that wants no
set-specific preset); neither is in a production build. Analysis, numbers and the zero-knowledge argument:
`docs/research/pqzh-set-a-proof-limit.md`.

- **A — re-prove under `MAX_PROOF_PQZH`** (Cargo feature `fallback-retry` of `pqzh-ligero`, this set only; never in
  the default or production builds; also tag `pqzh-set-a-fallback-A` on the spike commit `4f3477b8`). It uses THE
  preset of `n2048-kmax1024` (n 32,756, k 817, t 121, radices 2 / 19 / 43 / 431; `pqzh_set_fallback.rs`; 127.23 bits)
  and the prover limit min(verifier bound, 262,144) (written for the limit of 2026-10-22) with up to 32 attempts (`ligero.rs` `prover_limit`). The verifier and its bounds
  (263,784–265,236 B) are unchanged; every accepted proof is ≤ 262,144. Cost: +38 % prover runs on average for op 7
  M = 4 with the auditor (27.6 % of first attempts exceed the limit, up to 7 runs seen in 200), ≈ +0.9 % for R_TX and
  op 7 M = 2 / M = 4 without the auditor, none for R_TX0 / R_BURN; failure after 32 attempts ≈ 10^−18 [measured,
  spike A]. Zero knowledge: the proof length is a function of the random-oracle query indices only, so rejection on
  length conditions on a public, witness-independent event that the simulator reproduces. Debit calldata with a proof at
  262,144: ≈ 285.5–286.4 KB [model], so a per-tx cap ≥ ≈ 18.4 M. Tested: `runs/c8b-fallback-tests.txt`.
- **C — raise `MAX_PROOF_PQZH` for this set** (documented only, no code): with THE preset, `MAX_PROOF_PQZH`
  ≥ 265,236 (the op 7 M = 4 auditor bound) as a per-set constant (pqz-stmt, the precompile, the node, the docs that
  quote 262,144). Against the owner's 2026-10-21 ruling that the limit stays, so only when neither B nor A is
  acceptable. Since overtaken in part: on 2026-10-25 the owner raised the limit at this set to 327,680 for the R0-1
  audited R_TXM M = 4, with preset B kept (decisions CTR-PQZ-10). Inputs: op 7 M = 4 auditor 414,617 B (above `n2048-kmax1024`'s `MAX_INPUT` 393,216; fits 512 KiB).
