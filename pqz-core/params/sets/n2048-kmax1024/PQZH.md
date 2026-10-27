# Conditions for a chain to run PQZH — set `n2048-kmax1024` (not recommended; frozen until the R0 review fix)

PQZH (Ligero over F_q, `pqz-core/pqzh/ligero`) is the **backup** proof system (owner 2026-10-21). At this set it is
the shipped PQZH (THE preset of the D3 id; `proofSystemId` since plan 5h Task 8d `keccak256("scaas/pqz/pqzh/ligero-fq42-n32756k817t121-keccak256-zk-proven/v3")` = `0x56293621…a7df5d` (R0 review fix; v2 `0x9d945089…a7dca4` retired), the D3 id v1 `0x0a47a768…2fead4` retired); the crate
built with `--features set-n2048-kmax1024` (or no set feature) reproduces its proofs byte for byte (plan 5h Task 8c:
`pqz-core/pqzh/ligero/runs/c8-v3-kat-vs-base.txt`, `c8-v3-replay.txt`). `SET.md` (Task 8b) is this set's main
description ([`SET.md`](SET.md)). Since plan 5h Task 8c part 2 its constants are generated: `pqzh_set.rs` from
`set.toml` `[pqzh_preset]` (THE preset), `MAX_PROOF_PQZH` / `MAX_INPUT` in `rust/set.rs` (327,680 / 524,288 since
the R0 review fix, owner 2026-10-25; were 262,144 / 393,216); the
proofs, the vectors and the crate's outputs were byte-identical (`pqz-core/pqzh/ligero/runs/c8c-n2048-*`) until the id
bump of Task 8d, which changes every statement's id word and so every proof.

Sources: `[crate]` `runs/c8-v3-*`; `[model]` `python3 -I pqz-core/pqzh/ligero/ligero_params.py --set n2048-kmax1024`
(`runs/c8-params-n2048-kmax1024.txt`, equal to the crate on 14 relations); `[measured]` named in place.

## Field and domains [crate]

q = 2^42 − 215 = 4,398,046,510,889, q − 1 = 2^3 · 19 · 43 · 431 · 1,561,243; F_q element 42 bits in 6 bytes;
F_q^4 = F_q[X]/(X^4 − 3), |F_q^4| = 2^168; generator 3; THE preset n = 32,756 (coset 3·H_n), k = 817 (H_k), t = 121,
l = 695, radices 2 / 19 / 43 / 431; wasm32: two 21-bit limbs in u64. Soundness 127.23 bits per relation (query 128.50).

## Sizes per form [crate]

| relation | rows m | proof bound B | statement B | input 5 + stmt + bound B |
|---|---|---|---|---|
| R_REG / R_DS / R_DR | 63 | 190,458 | 16,480 / 33,184 / 33,184 | 206,943 / 223,647 / 223,647 |
| R_TX / R_TX0 / R_BURN | 125 / 124 / 124 | 235,470 / 234,744 / 234,744 | 83,072 / 66,560 / 50,048 | 318,547 / 301,309 / 284,797 |
| R_TXM op 7 M = 1 / 2, auditor | 125 / 125 | 235,470 / 235,470 | 83,072 / 99,712 | 318,547 / 335,187 |
| R_TXM op 7 M = 4, auditor (G = 2 since the R0 review fix; was 126 rows, 236,196 / 132,992 / 369,193 at G = 1) | — | 279,756 | 149,376 | 429,137 |
| R_TXM op 7 M = 1 / 2 / 4, no auditor | 124 / 125 / 125 | 234,744 / 235,470 / 235,470 | 66,560 / 83,072 / 116,096 | 301,309 / 318,547 / 351,571 |

Every built form is within `MAX_PROOF_PQZH` 327,680 and `MAX_INPUT` 524,288 (unit test `limits_exact`); before the R0
review fix every form was within 262,144 / 393,216 (D5). Honest proofs 185,462–233,604 B (`runs/c8-v3-kat.jsonl`,
before the fix); the audited M = 4 at G = 2: 275,916–277,196 B (`pqz-core/runs/gate/r01a-fix-n2048-kmax1024-ligero-multi.txt`;
the M = 4 bound and input: `pqz-core/research/code-review-2026-10-25/r01a-limits/`).

## One transaction's calldata (EIP-7976: 15,000 + 64 gas / byte ≤ the cap; 261,909 B at 2^24) [measured, plan 5h Task 8d part 2b]

| relation | path | calldata B (proof at its bound) | floor gas | fits 2^24 |
|---|---|---|---|---|
| R_REG | `UARegistry.register` | 212,420 | 13,609,880 | yes |
| R_DS / R_DR | `verifyTransferAmount` (`eth_call`) | 190,660 | 12,217,240 | yes |
| R_TX / R_TX0 / R_BURN | relayed `mtxExecute` | 256,772 / 255,908 / 255,780 | 16.45 / 16.39 / 16.38 M | yes (margin 0.33–0.39 M) |
| R_TX / R_TX0 / R_BURN | relayed `uaExecute` (`mldsa65` fee UA) | 260,132 / 259,268 / 259,140 | 16.66 / 16.61 / 16.60 M | yes (margin 0.11–0.18 M) |
| R_TXM op 7 M = 1 / 2, auditor | relayed `mtxExecute` | 256,836 / 257,124 | 16.45 / 16.47 M | yes |
| R_TXM op 7 M = 4, auditor (G = 2 since the R0 fix) | relayed `mtxExecute` | 318,372 | 20.39 M | **no** |
| R_TXM op 7 M = 4, no auditor | relayed `mtxExecute` | 257,188 | 16.48 M | yes (margin 302,184 gas ≈ 4,721 B) |
| R_TXM op 7 M = 1 / 2 with the auditor, M = 4 without | relayed `uaExecute` | 260,196 / 260,484 / 260,548 | 16.67 / 16.69 / 16.69 M | yes (margin down to 87,144 gas ≈ 1,361 B at M = 4) |
| R_TX with the `acc` hint (materialised `acc`) | relayed `mtxExecute` | 267,620 | 17.14 M | **no** |

Measured through the token (`smartcontracts/evm/runs/2026-10-26-t8d2b-gas-n2048-kmax1024.txt`, both relay paths in
`…-t8d2b-fix-gas-n2048-kmax1024.txt`; the regular gas equals the floor: every debit is floor-bound). The `uaExecute`
envelope carries a 3,309-byte ML-DSA-65 signature: 3,360 B more calldata than `mtxExecute`, so the fitting debits keep
only 0.09–0.18 M there; any envelope growth must re-check this set. **Accepted fee-UA kinds on `uaExecute`:** an `mldsa65` (precompile) or `fndsa512` fee UA fits every built form (burn 1 with an `fndsa512` fee UA: 16,429,976); an `slhdsa128s` fee UA does not (burn 1: 16,890,776 regular gas, over 2^24; `runs/2026-10-27-review2-t2-holder-gas-n2048-kmax1024.txt`). It is the one excluded fee-UA kind. Every built form fits one 2^24 transaction under Amsterdam's floor, the debits only
just, **except op 7 M = 4 with the auditor** (G = 2 since the R0 review fix) and any debit that carries the `acc` hint;
under EIP-7623 alone (no EIP-7976) all would fit (`docs/research/pqzh-calldata-cap.md`). A direct call to the
precompile (input as calldata) fits for R_REG / R_DS / R_DR only.

## Gas, block, verify time

- PQZH rows `G_op` [measured, P6f 2026-10-15, the retired calibration at the old ids, `pqz-core/nethermind/chain/engine-pqz.json`]:
  transfer 4,225,000, transfer0 4,021,000, burn / refresh 3,738,000, register 3,322,000, disclose 3,283,000 /
  2,881,000; the largest honest direct transaction 11.67 M (before Amsterdam's floor). The provisional rows
  `engine-pqz-provisional-n2048.json` (at this set's ids, until plan 5h Task 9) are these × 1.3, rounded to 1,000 gas (transfer 5,492,000, register 4,319,000).
- Regular gas of a debit under Amsterdam [measured, plan 5h Task 8d part 2b]: floor-bound, 16.38–16.48 M (above);
  state gas of a relayed R_TX 17.58 M (P46 packing; `smartcontracts/evm/runs/2026-10-26-t8d2b-gas-n2048-kmax1024.txt`).
- Block: block gas used = max(Σ regular, Σ state) (EIP-8037), so a 60 M block holds three such debits [estimate, from
  the measured gas].
- Verify p99 [measured, `pqz-core/pqzh/ligero/runs/rev2-proven-wasm.jsonl`, wasm32, 1,000 honest verifies]: 15–24 ms
  (target 60 ms). The set-generic field of Task 8c changed the wasm32 reduction (same values): **not re-measured**.

## Summary

The shipped PQZH: works under a 2^24 per-transaction cap for every form (debits floor-bound, margin 0.30–0.39 M via
`mtxExecute`, 0.09–0.18 M via `uaExecute`)
except op 7 M = 4 with the auditor (G = 2 since the R0 review fix) and a debit that carries the `acc` hint; proof and
input limits met; verify time measured before Task 8c, to re-measure with the new reduction.
