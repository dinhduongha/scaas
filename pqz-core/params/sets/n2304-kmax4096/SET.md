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
| proof MLWE rank (`kmlwe_min`) | 36 (`e-s1.txt`: every one of the 14 specs meets MSIS β 462–472, hiding MLWE uSVP 472, dual_hybrid 465 / 466 at `pqz_delta` 1.00366) |
| encryption, no hints | uSVP β 496; full estimate 2^142.2 classical / 2^129.6 quantum (dual_hybrid β 487 / 489) (`pqzl/params/n-study/enc-n.txt`, row 18) |
| encryption, 80 hints (op 7 group of 4 legs + auditor) | DDGR20 worst case β 468.47; dual_hybrid on the hinted instance 458.47 / 461.47 classical / quantum [estimate: n − 80 model minus the measured offset] (n-study §3.2 / §3.3) |
| e_s0 | budget, exactness of every norm proof (14 relations incl. txm4 / txm8) and Fiat–Shamir rounds (λ = 3: 137.4 bits; final challenge 2^-129.79): MET (`e-s0.txt`) |
| proofSystemId | PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k36-q46l4/v5")` = `0xef1ffbcb…90336e` (R0 review fix 2026-10-25; v4 `0x15d16d77…cb608a` retired); PQZH `keccak256("scaas/pqz/pqzh/ligero-fq46-n45752k952t120-keccak256-zk-proven/v3")` = `0x046859a8…944ead` (R0 review fix; v2 `0xe4bc6d17…885730` retired) (set.toml `pqzl_id` / `pqzh_id`; plan 5h Task 8d, the one bump of Task 8: controller proposal, decisions CTR-PQZ-09) |
| owner approval | 2026-10-21 (supersedes the approved `n2560-kmax16384`; progress.md) |
| stored-blob packing width (P46 ruling, owner 2026-10-21) | ⌈log2 q⌉ = 46 bits (P46: 4 coefficients per 23 bytes); `PqzSet.sol` `PACK_BITS`; built in 8d part 2: stored `ct` 13,340 B (64-bit lanes 18,560), `acc` 417 slots |
| PQZH | built (plan 5h Task 8c part 2): preset B (radices 2/7/17/19/43/431, n 45,752, k 952, t 120; owner 2026-10-22), `pqzh_set.rs` generated from `set.toml` `[pqzh_preset]`; `MAX_PROOF_PQZH` 262,144, `MAX_INPUT` 524,288; in pqz-ffi, the vectors and the gate; conditions: [PQZH.md](PQZH.md) |
| upstream KAT | `lazer-3330e48-kat.json`: pqz-core = upstream LaZer 3330e48 (+ HEXL), 19/19 |

Proof sizes (`smartcontracts/vectors/pqz/n2304-kmax4096/proof_pqzl.json`, byte-identical C = Rust = wasm32): TRANSFER
46,674 B, TRANSFER0 46,333, BURN 45,833, REFRESH 45,845, REGISTER 30,272, DISCLOSE-SENDER 30,795, -RECEIVER 31,472,
-AUDITOR 31,425; op 7 with the auditor M = 1 / 2 / 4 / 8: 46,642 / 47,474 / 50,748 / 67,579 B, without 46,326 /
46,827 / 47,851 / 64,597 B (all below `MAX_PROOF` 98,304). Object sizes: pk 18,432 B, ciphertext 18,560 B, op 1
statement 93,312 B (auditor on). Heap: C prover arena peaks 117 MB (R_REG) … 937 MB (R_TXM M = 8: needs
`PQZ_ARENA_MB=2048`), `pqzl/runs/t8b-n2304-bench.txt`; Rust peaks in the 8b report.

Files: `set.toml` (input), `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, `<rel>_params.sage` (gen_set.py),
`pqz_<rel>_params.h` + `codegen.txt` (LaZer codegen), `rust/<rel>.rs` (to_rust.py), `e-s1.txt`, `e-s0.txt`,
`lazer-3330e48-kat.json` (+ `-build.txt`). The first generator of these specs, `gen_pa.py` / `regen.sh`, is kept in
[`../legacy/n2304-kmax4096/`](../legacy/README.md).
