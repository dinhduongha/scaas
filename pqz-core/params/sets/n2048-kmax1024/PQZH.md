# Conditions for a chain to run PQZH — set `n2048-kmax1024` (the frozen v3 set)

PQZH (Ligero over F_q, `pqz-core/pqzh/ligero`) is the **backup** proof system (owner 2026-10-21). At this set it is
the shipped PQZH (`proofSystemId` `keccak256("scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")`, D3); the crate
built with `--features set-n2048-kmax1024` (or no set feature) reproduces its proofs byte for byte (plan 5h Task 8c:
`pqz-core/pqzh/ligero/runs/c8-v3-kat-vs-base.txt`, `c8-v3-replay.txt`). `SET.md` (Task 8b) is this set's main
description.

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
| R_TXM op 7 M = 1 / 2 / 4, auditor | 125 / 125 / 126 | 235,470 / 235,470 / 236,196 | 83,072 / 99,712 / 132,992 | 318,547 / 335,187 / 369,193 |
| R_TXM op 7 M = 1 / 2 / 4, no auditor | 124 / 125 / 125 | 234,744 / 235,470 / 235,470 | 66,560 / 83,072 / 116,096 | 301,309 / 318,547 / 351,571 |

Every built form is within `MAX_PROOF_PQZH` 262,144 and `MAX_INPUT` 393,216 (D5; unit test `limits_exact`). Honest
proofs 185,462–233,604 B (`runs/c8-v3-kat.jsonl`).

## One transaction's calldata (EIP-7976: 15,000 + 64 gas / byte ≤ the cap; 261,909 B at 2^24) [model]

| relation | path | calldata B (proof at its bound) | floor gas | fits 2^24 |
|---|---|---|---|---|
| R_REG | `UARegistry.register` | 212,420 | 13,609,880 | yes |
| R_DS / R_DR | `verifyTransferAmount` (`eth_call`) | 190,660 | 12,217,240 | yes |
| R_TX / R_TX0 / R_BURN | relayed `mtxExecute` | 256,772 / 255,908 / 255,780 | 16.45 / 16.39 / 16.38 M | yes (margin ≈ 0.2–0.4 M) |
| R_TXM op 7 M = 1 / 2 / 4, auditor | relayed `mtxExecute` | 256,836 / 257,124 / 258,436 | 16.45 / 16.47 / 16.55 M | yes |

Every form fits one 2^24 transaction under Amsterdam's floor, the debits only just (floor-bound). A direct call to the
precompile (input as calldata) fits for R_REG / R_DS / R_DR only.

## Gas, block, verify time

- PQZH rows `G_op` [measured, P6f 2026-10-15, `pqz-core/nethermind/chain/engine-pqz.json`]: transfer 4,225,000,
  transfer0 4,021,000, burn / refresh 3,738,000, register 3,322,000, disclose 3,283,000 / 2,881,000; the largest honest
  direct transaction 11.67 M (before Amsterdam's floor).
- Regular gas of a debit under Amsterdam: ≥ the floor ≈ 16.4–16.6 M (above) [model]; state gas as PQZL's debit at this
  set (not re-measured for v3 under Amsterdam in plan 5h).
- Block: a debit's regular gas alone is ≈ 16.5 M; the state part depends on the stored layout of the chain's contracts.
- Verify p99 [measured, `pqz-core/pqzh/ligero/runs/rev2-proven-wasm.jsonl`, wasm32, 1,000 honest verifies]: 15–24 ms
  (target 60 ms). The set-generic field of Task 8c changed the wasm32 reduction (same values): **not re-measured**.

## Summary

The shipped PQZH: works under a 2^24 per-transaction cap for every form (debits floor-bound, ≈ 0.2–0.4 M margin), proof
and input limits met; verify time measured before Task 8c, to re-measure with the new reduction.
