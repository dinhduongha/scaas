# Parameter set `n2304-kmax4096` (the default set)

Candidate E of the n-study (plan 5h Task 7c), approved by the owner on 2026-10-21; it supersedes the approved
[`n2560-kmax16384`](../n2560-kmax16384/SET.md) (n 2560, `K_MAX` 16,384) as the target of plan 5h Task 8. The default set of the `pqzl` crate, of
`gate.sh` and, since plan 5h Task 8d part 1, of `pqz-ffi` (the node's library, owner 2026-10-21: the default set on
chain) and, since plan 5h Task 8d part 2, of the contracts (the committed `smartcontracts/evm/src/pqz/PqzSet.sol`). Input:
[`set.toml`](set.toml); every other file here is derived (see [`../README.md`](../README.md)).

| Item | Value |
|---|---|
| ring | n = 2304 = k·d, k = 36, d = 64 |
| q | 61,275,424,977,257 ≈ 2^45.80 (prime, q ≡ 9 mod 16: l = 4 NTT; q − 1 divisible by 2^3·19·43·431, PQZH's radices) |
| Δ | ⌊q / 2^18⌋ = 233,747,196 (even: a rounding tie at \|noise\| = Δ/2 ≈ 2^26.8 is possible in principle, never for an honest ciphertext, whose noise stays below E = 2^26; `pqz_dec` rounds ties up, the prover's M_i half away from zero, as before; noted for the 8b review) |
| `K_MAX` | 4,096; digit sums `M_i` 16 bits, carries 13 bits, `e_T` / `e'` + 2^26 in 27 bits |
| norm bounds | β_s 38 (CBD(1)), β_e 173 (CBD(20)), β_2 64; B_FRESH 13,212; worst case 4,095 · B_FRESH = 54,103,140 < E = 2^26 (margin 1.24), mint margin 3.08 (`worstcase_noise.json`) |
| proof MLWE rank (`kmlwe_min`) | 36 (`e-s1.txt`: every one of the 14 specs meets MSIS β 463–472, hiding MLWE uSVP 472, dual_hybrid 465 / 466 at `pqz_delta` 1.00366) |
| encryption, no hints | uSVP β 496; full estimate 2^142.2 classical / 2^129.6 quantum (dual_hybrid β 487 / 489) (`pqzl/params/n-study/enc-n.txt`, row 18) |
| encryption with hints (op 7 groups) | since the R0 review fix (R0-1, `s_aud` = 3: audited groups of 3 legs, 32·3 = 96 worst-case hints): DDGR20 β 463.04, dual_hybrid − offset 453.04 / 456.04 [estimate: a 3-β margin on a heuristic, `pqzl/params/anon/hints-s.txt`] — `s_aud` here rests on that heuristic: the lattice-estimator has no hints, so the study runs dual_hybrid on LWE(n − h) and subtracts the primal offset uSVP(n − h) − DDGR20(h); no hinted dual estimate exists; `s` = 4 would give 443.21 / 445.21, the direction is conservative and the smaller `s` was chosen (Fable's R0 review, decisions CTR-PQZ-04 Change 2026-10-26); groups of 4 without the auditor (64 hints): 473.91, 463.91 / 466.91; was 468.47 / 458.47 at 80 hints |
| e_s0 | budget, exactness of every norm proof (14 relations incl. txm4 / txm8) and Fiat–Shamir rounds (λ = 4 read from the headers: 183.20 bits; the final challenge from the η-filtered set the cores sample since the R0 review fix, R0-C3: P = 0.9143, 2/\|C\| = 2^-129.67): MET (`e-s0.txt`) |
| proofSystemId | PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k36-q46l4/v5")` = `0xef1ffbcb…90336e` (R0 review fix 2026-10-25; v4 `0x15d16d77…cb608a` retired); PQZH `keccak256("scaas/pqz/pqzh/ligero-fq46-n45752k952t120-keccak256-zk-proven/v3")` = `0x046859a8…944ead` (R0 review fix; v2 `0xe4bc6d17…885730` retired) (set.toml `pqzl_id` / `pqzh_id`; plan 5h Task 8d, the one bump of Task 8: controller proposal, decisions CTR-PQZ-09) |
| owner approval | 2026-10-21 (supersedes the approved `n2560-kmax16384`; progress.md) |
| stored-blob packing width (P46 ruling, owner 2026-10-21) | ⌈log2 q⌉ = 46 bits (P46: 4 coefficients per 23 bytes); `PqzSet.sol` `PACK_BITS`; built in 8d part 2: stored `ct` 13,340 B (64-bit lanes 18,560), `acc` 417 slots |
| `ROLL_MAX` | 80 (`set.toml` `roll_max` → `PqzSet.ROLL_MAX`, plan 5h Task 8d part 2b; controller proposal, owner may override): the largest multiple of 16 under 0.75 · 2^24 on both relay paths, the relayed full rollover 12,119,170 gas via `mtxExecute`, 12,277,522 via `uaExecute` (the binding path; 305,390 under; re-measured on the split bytecode, `runs/2026-10-27-metatx-split-gas-n2304-kmax4096.txt`), 96 would be 13,390,402 / 13,548,754 [measured, linear fit on the split bytecode, `runs/2026-10-27-metatx-split-gas-n2304-kmax4096.txt:495,504`; the pre-split scan gave 13,382,390 / 13,539,505, `smartcontracts/evm/runs/2026-10-26-t8d2b-fix-rollscan-n2304-kmax4096.txt`] |
| on chain | the SCaaS testnet's set: image `scaas/nethermind-pqz:2.2.0-pqz5` (library `dd0e7668…`, `OP_SELFTEST` `d6c01fbc…`) with provisional rows (`pqz-core/nethermind/chain/engine-pqz-provisional-n2304.json`) since 2026-10-26; measured gas per relation: [`../README.md`](../README.md#one-transactions-gas-per-relation-measured-plan-5h-task-8d-part-2b) |
| PQZH | built (plan 5h Task 8c part 2): preset B (radices 2/7/17/19/43/431, n 45,752, k 952, t 120; owner 2026-10-22), `pqzh_set.rs` generated from `set.toml` `[pqzh_preset]`; `MAX_PROOF_PQZH` 327,680 (owner 2026-10-25: the audited R_TXM M = 4 with G = 2 has the bound 296,248 B; was 262,144), `MAX_INPUT` 524,288; in pqz-ffi, the vectors and the gate; conditions: [PQZH.md](PQZH.md) |
| upstream KAT | `lazer-3330e48-kat.json`: pqz-core = upstream LaZer 3330e48 (+ HEXL), 19/19 |

Proof sizes (`smartcontracts/vectors/pqz/n2304-kmax4096/proof_pqzl.json`, byte-identical C = Rust = wasm32): TRANSFER
46,662 B, TRANSFER0 46,329, BURN 45,835, REFRESH 45,819, REGISTER 30,381, DISCLOSE-SENDER 30,814, -RECEIVER 31,546,
-AUDITOR 31,558; op 7 with the auditor M = 1 / 2 / 4 / 8: 46,678 / 47,503 / 63,885 / 80,290 B (G = 1 / 1 / 2 / 3), without 46,342 /
46,857 / 47,821 / 64,607 B (largest 80,290 B, the M = 8 row; M8-on-boundary 80,288 B; 18,014 B under `MAX_PROOF` 98,304); PQZH audited M = 4
293,112 B (bound 296,248). Object sizes: pk 18,432 B, ciphertext 18,560 B, op 1
statement 93,312 B (auditor on). Heap: C prover arena peaks after the R0 review fix (the gate's bench,
`pqz-core/runs/gate/n2304-kmax4096-fnv-c.jsonl`) 380 MB (R_TX) / 471 MB (R_TXM M = 2) / 1,345 MB (R_TXM M = 8 with the
auditor: needs `PQZ_ARENA_MB=2048`); before it 117 MB (R_REG) … 937 MB (R_TXM M = 8), `pqzl/runs/t8b-n2304-bench.txt`;
Rust peaks in the 8b report.

Files: `set.toml` (input), `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, `<rel>_params.sage` (gen_set.py),
`pqz_<rel>_params.h` + `codegen.txt` (LaZer codegen), `rust/<rel>.rs` (to_rust.py), `e-s1.txt`, `e-s0.txt`,
`lazer-3330e48-kat.json` (+ `-build.txt`). The first generator of these specs, `gen_pa.py` / `regen.sh`, is kept in
[`../legacy/n2304-kmax4096/`](../legacy/README.md).
