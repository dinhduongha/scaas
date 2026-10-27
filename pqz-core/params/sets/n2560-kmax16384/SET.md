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
| PQZH | built (plan 5h Task 8c part 2): THE preset's radices and n / k (n 32,756, k 817) with t = 122 (owner 2026-10-23), `pqzh_set.rs` generated from `set.toml` `[pqzh_preset]`; debit bounds 303,412–305,120 B exceed 262,144 → **owner 2026-10-23: `MAX_PROOF_PQZH` = 327,680 B (320 KiB)** (decisions CTR-PQZ-10; first for this set only, since 2026-10-25 every PQZH set's), in `pqz-stmt` with `MAX_INPUT` 524,288; in pqz-ffi, the vectors and the gate; conditions: [PQZH.md](PQZH.md) |
| `ROLL_MAX` | 64 (`set.toml` `roll_max` → `PqzSet.ROLL_MAX`, plan 5h Task 8d part 2b; below) |
| LaZer codegen headers | byte-identical to the p16k record's (`pqzl/params/p16k/`, the 12 relations it has) until the R0 review fix, which regenerated reg / dr (`Bprime` 8, R0-C2; `9ac573ad`) |
| upstream KAT | `lazer-3330e48-kat.json`: pqz-core = upstream LaZer 3330e48 (+ HEXL), 19/19 |

## Conditions for this set to work on a chain

Measured where marked: plan 5h Task 8d part 2b, forge 1.8.5 under Amsterdam through the real token and registry, the
`PQZ` precompile at its provisional testnet row (`pqz-core/nethermind/chain/engine-pqz-provisional-n2560.json`, until
Task 9) + 3 per input word (`smartcontracts/evm/runs/2026-10-26-t8d2b-gas-n2560-kmax16384.txt`; the table in
[`../README.md`](../README.md#one-transactions-gas-per-relation-measured-plan-5h-task-8d-part-2b)). The rest [estimate].

1. **Contracts built for this set.** The contracts read `PqzSet.sol` since plan 5h Task 8d part 2a; `at-set.sh
   n2560-kmax16384` installs this set's file and runs forge (1,369 passed / 0 failed / 9 skipped,
   `smartcontracts/evm/runs/2026-10-26-t8d2b-fix-forge-n2560-kmax16384.txt`). A chain also needs the node library and
   plugin of this set (`PQZ_SET=n2560-kmax16384 build-image.sh`, its reviewed `ExpectedLibrarySha256` `5d113f32…`).
2. **Per-transaction regular gas ≤ 2^24** (Ethereum-like cap; no zero-gas or own-block-limit assumption, owner
   2026-10-21) [measured]: relayed op 1 (auditor) 9.35 M; op 7 M = 1 / 2 / 4 (auditor) 7.05 / 7.26 / 8.05 M; op 7 M = 8
   12.17 M with the auditor (G = 2), 10.91 M without; `UARegistry.register` 4.62 M; `mtxPrepareAcc` halves 3.17 M each;
   `mtxRollOver` at `ROLL_MAX` 64: 12,418,528 via `mtxExecute`, 12,576,880 via `uaExecute` (metatx split, `runs/2026-10-27-metatx-split-rollscan-n2560-kmax16384.txt`) (≤ 0.75 · 2^24, the
   rollover rule on both relay paths; spec §7.6).
3. **Calldata ≤ the EIP-7976 floor's 261,909 B per transaction:** the largest relayed PQZL calldata is 120,708 B (op 7
   M = 8, auditor) [measured]; the precompile input is built in memory by the token, bounded by `MAX_INPUT`, not by
   calldata.
4. **Block gas limit for the state dimension (EIP-8037):** every debit stores its op blob in state (SSTORE2; "Không
   được mất ciphertext": ciphertexts are never only in calldata / events), packed at ⌈log2 q⌉ = 50 bits (P46):
   25.69 M state gas per relayed op 1, 24.97 M per prepare half, 54.02 M for op 7 M = 8 with the auditor, 52.80 M
   without [measured]. Block gas used = max(Σ regular, Σ state) (EIP-8037), so Ethereum mainnet's 60 M block holds two
   op 1 debits of this set and one op 7 M = 8; a transaction needs a block limit ≥ its state gas (the SCaaS testnet:
   200 M); no rule assumes a larger limit. The real cost (state gas is paid) applies on a customer chain.
5. **`ROLL_MAX` 64** (largest multiple of 16 with the relayed rollover ≤ 0.75·2^24 regular gas on both relay paths;
   80 gives about 13,800,944 / 13,959,296 (linear fit on the split scan) via `mtxExecute` / `uaExecute`) [measured, `smartcontracts/evm/runs/2026-10-26-t8d2b-fix-rollscan-n2560-kmax16384.txt`;
   the Task 7b measurement, with the contracts of then, gave 80]. **Tight:** on `uaExecute` (the binding path) 64 is
   only 6,032 gas under the cap (12,576,880 of 12,582,912; the metatx split moved it from 15,281), so the next contract change may move it to 48: re-run the rollscan
   (`smartcontracts/evm/runs/2026-10-26-t8d2b-fix-rollscan.sh`). Controller proposal, owner may override.
6. **PQZH:** a backup only — its debit proofs (bounds 303,412–305,120 B [crate]) need `MAX_PROOF_PQZH` 327,680 B (owner
   2026-10-23, built in 8c part 2), and its debits exceed one transaction's calldata (relayed op 1 329,668 B, 21.11 M
   [measured]); `R_REG` (260,292 B, 16.67 M) and the disclosure `eth_call`s fit. [PQZH.md](PQZH.md).
7. **Security margins:** encryption β 508; since the R0 review fix ≤ 128 worst-case hints on one `(r_g, e1_g)` (an
   audited op 7 group of `s_aud` = 4 legs) DDGR20 β 467.60, dual_hybrid − offset 458.60 / 460.60 [estimate] (above 450,
   no exception needed); proof MSIS / MLWE β ≥ 450 per spec (`e-s1.txt`); exactness and Fiat–Shamir rounds MET
   (`e-s0.txt`); mint margin 3.36.
8. **Verify time** (≤ 60 ms p99 wasm32, the precompile's budget): not re-measured for this set (owner rule: no timing
   runs without the owner's go); the single-recipient proofs are 7–8 % above `n2304-kmax4096`'s, the audited op 7 M = 4 / 8 proofs smaller
   (fewer randomness groups: `s_aud` 4 against 3) (below).

Proof sizes (`smartcontracts/vectors/pqz/n2560-kmax16384/proof_pqzl.json`, since the R0 review fix, byte-identical C
= Rust = wasm32): TRANSFER 50,392 B, TRANSFER0 50,053, BURN 49,536, REFRESH 49,542, REGISTER 32,539, DISCLOSE-SENDER
32,967, -RECEIVER 33,866, -AUDITOR 33,872; op 7 with the auditor M = 1 / 2 / 4 / 8: 50,376 / 51,219 / 54,861 / 72,687 B
(G = 1 / 1 / 1 / 2), without 50,091 / 50,543 / 51,556 / 69,863 B (largest 72,761 B, M8-on-boundary: 25,543 B under
`MAX_PROOF` 98,304). Object sizes: pk 20,480 B, ciphertext 20,608 B, op 1 statement 103,552 B (auditor on). Heap: C
prover arena peaks (the gate's bench after the R0 review fix, `pqz-core/runs/gate/n2560-kmax16384-fnv-c.jsonl`) 457 MB
(R_TX) / 550 MB (R_TXM M = 2) / 1,094 MB (R_TXM M = 8 with the auditor: needs `PQZ_ARENA_MB=2048`).

Files: `set.toml` (input), `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, `<rel>_params.sage` (gen_set.py),
`pqz_<rel>_params.h` + `codegen.txt` (LaZer codegen), `rust/<rel>.rs` (to_rust.py), `e-s1.txt`, `e-s0.txt`,
`lazer-3330e48-kat.json` (+ `-build.txt`); made by `make.sh n2560-kmax16384 all`.
