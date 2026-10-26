# Parameter set `n2816-kmax65536` (full PQZL set, no PQZH)

The `K_MAX` 65,536 candidate of plan 5h (research record [`pqz-core/pqzl/params/aprime/`](../../../pqzl/params/aprime/README.md):
owner choice 2026-10-19, superseded by [`n2560-kmax16384`](../n2560-kmax16384/SET.md) on 2026-10-20). Kept in
`params/sets/` on 2026-10-21 "in case a customer wants it" as a core-only set; **owner 2026-10-24: a full PQZL set,
deployable for a customer like the other sets** ("it must be done fully, for customers if they need it"): pqz-stmt, the precompile
(`pqz-ffi`, the Nethermind plugin), vectors (`smartcontracts/vectors/pqz/n2816-kmax65536/`) and the full gate since
plan 5h Task 8d part 1b; its contracts build and pass their suites since 8d part 2a (`at-set.sh n2816-kmax65536`), gas measured in 8d part 2b. **No PQZH** (owner ruling; why: below). Input: [`set.toml`](set.toml) (`core_only = false`, `pqzh = false`); every other file here is derived (see
[`../README.md`](../README.md)).

| Item | Value |
|---|---|
| ring | n = 2816 = k·d, k = 44, d = 64 |
| q | 2^54 − 327 = 18,014,398,509,481,657 (prime, q ≡ 9 mod 16) |
| NTT root | ζ = 5^((q − 1)/8): 3 is a quadratic residue mod this q, so `gen_set.py` takes the smallest non-residue g ≥ 3 (g = 3 for every other set) |
| Δ | ⌊q / 2^22⌋ = 2^32 − 1 = 4,294,967,295 (odd) |
| `K_MAX` | 65,536; digit sums `M_i` 20 bits, carries 17 bits, `e_T` / `e'` + 2^30 in 31 bits |
| norm bounds | β_s 42 (CBD(1)), β_e 189 (CBD(20)), β_2 64; B_FRESH 15,940; worst case 65,535 · B_FRESH = 1,044,627,900 < E = 2^30 (margin 1.03), mint margin 3.08 (`aprime/aprime.txt`) |
| proof MLWE rank (`kmlwe_min`) | **42** (`e-s1.txt`: every one of the 14 specs meets MSIS β 454–478, hiding MLWE uSVP 477–483, dual_hybrid 462 / 463 at `pqz_delta` 1.00366). The aprime record's 41 checked MSIS / uSVP only; at 41 dual_hybrid is 447 / 448 < 450 (`make.sh` e_s1 stop, 2026-10-23) |
| encryption, no hints | uSVP β 520; full estimate 2^149.3 classical / 2^135.9 quantum (dual_hybrid β 511 / 512) (`aprime/aprime.txt`) |
| encryption with hints (op 7 groups) | since the R0 review fix (R0-1, `s_aud` = 4: 128 worst-case hints with the auditor): DDGR20 β 483.09, dual_hybrid − offset 475.09 / 478.09 [estimate] (`pqzl/params/anon/hints-s.txt`); was 496.79 at 80 (`aprime/aprime.txt`) |
| e_s0 | budget, exactness of every norm proof (14 relations) and Fiat–Shamir rounds (λ = 4 read from the headers: 216.00 bits; the final challenge from the η-filtered set the cores sample since the R0 review fix, R0-C3: P = 0.9143, 2/\|C\| = 2^-129.67): MET (`e-s0.txt`) |
| upstream KAT | `lazer-3330e48-kat.json`: pqz-core = upstream LaZer 3330e48 (+ HEXL) at q = 2^54 − 327, 19/19 |
| 64-bit arithmetic | log2 q = 54 is within every bound of the set-generic cores: `PQZ_LOG2Q <= 55` since the R0 review fix (`pqz_sv.c` lift and the JL fold / `pqz_modq_i64`, review R2-C1; `pqz_ntt.c` wasm32 limbs <= 56), Barrett 2L + 4 = 112 ≤ L + 63, specialised verifier 5 CRT primes, Δ · 2^(MBITS − 1) = 2^51 in int64. The C core's wasm32 limb path (`PQZ_MUL128` 0, limb width LB = 27) runs: its wasm32 build (`B=build/gate-cwasm-n2816-kmax65536 ./build.sh wasm`, `test/run_wasm.mjs 2 1 16383`) gives the native C run's `proofs_fnv` on all 14 bench relations, 0 fails (8b fix round 1: `pqz-core/runs/gate/fix1-n2816-cwasm.*`; the gate checks it as part `fnv/cwasm`) |
| proofSystemId | PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k44-q54l4/v5")` = `0xa801f5c4…8e8aa9` (R0 review fix 2026-10-25; v4 `0x9d23a0de…bd53a3` retired) (set.toml `pqzl_id`, plan 5h Task 8d; controller proposal, decisions CTR-PQZ-09); no PQZH id (pqz-stmt `HAS_PQZH` false: its `PQZH_ID` is the zero word, refused like any unknown id) |
| owner approval | 2026-10-21: keep this set as a core-only set; 2026-10-24: a full PQZL set for customers (progress.md); its values are the research record's, not a frozen relation |
| stored-blob packing width | ⌈log2 q⌉ = 54 bits (`PqzSet.sol` `PACK_BITS`; built in 8d part 2: stored `ct` 19,116 B (64-bit lanes 22,656), `acc` 598 slots; lanes hold `(ROLL_MAX + 1) · q < 2^64`, i.e. at most 1,023 terms per rollover) |
| limits | `MAX_PROOF_PQZL` 98,304 B (every set's): largest proof 79,208 B (R_TXM M = 8 with the auditor, the vectors since the R0 fix), margin 19,096 B; `MAX_INPUT` 524,288 B (`set.toml` `max_input`, 512 KiB, every set's since the R0 review fix; `pqz_max_input()` gives it to the node): largest input at the limit 5 + 295,808 + 98,304 = 394,117 B (R_TXM M = 8 with the auditor), above `n2048-kmax1024`'s former 393,216 |
| self-test | `OP_SELFTEST` = `0x1e69e3cd…dee740` (R0 review fix; was `0x0aa1dfe2…491882`) (`selftest.json`: results 1, 0, 0, 0, no Ligero FFT); the Nethermind plugin built with `-p:PqzSet=n2816-kmax65536` pins it (`SelfTest.cs`) |
| PQZH | **none at this set** (owner ruling 2026-10-24): q − 1 = 2^3 · 3 · 1,789 · 419,563,967,521 has no power-of-two part beyond 2^3 and a smooth part of only 24, none of the radices the current Ligero presets use (19 / 43 / 431; 7 / 17 at `n2304-kmax4096`). F_q^* does have subgroups of order 1,789 and 42,936 (= 24 · 1,789), so PQZH here would need a radix-1,789 FFT step and a new preset at a different rate (k = 1,789, n = 42,936: rate 1/24 against ≈ 1/40 today, more column queries, a fresh soundness and size analysis) — unexplored work, not in scope — or another q, i.e. another set. **Not pursued (owner ruling 2026-10-25: no spike, write the reason down).** Controller estimate from the cost model of `pqz-core/pqzh/ligero/ligero_params.py` (`fft_cost(n) = n · Σ (r + 1)` over the radices of n; computed by hand, not run): (1) a radix-r stage costs ≈ r + 1 products per point, so the largest FFT at n = 42,936 = 2^3 · 3 · 1,789 is ≈ 77.4 M products against ≈ 3.7 M at `n2304-kmax4096`'s n = 45,752 (≈ 21×); k = 1,789 about halves the row count, so the prover's work is ≈ 10× `n2304-kmax4096`'s, most likely over the prover budget (`PMAX` 4e9 base products), and the prover runs on the client (wasm32 in the browser). (2) A fast 1,789-point DFT (Rader) needs a cyclic convolution of length 1,788 = 2^2 · 3 · 149, which has no NTT in F_q (149 does not divide q − 1); an extension field does not help (q + 1 = 2 · 31 · 109 · 409 · 6,517,458,439 is not smooth either); only nested Winograd-style convolutions remain — several days of work with an uncertain result. (3) The verifier (the precompile) would not be the problem: it evaluates at the t opened columns (Lagrange), with no size-n FFT. A chain that needs PQZH with `K_MAX` 65,536 needs another parameter set whose q − 1 is smooth like the other sets' (2^3 · 19 · 43 · 431 divides q − 1), with a full parameter and estimator run. pqz-ffi is built without PQZH (feature `pqzh` off; a compile-time check refuses it at this set), the vectors are PQZL only, the gate skips Ligero and the cross-checks |

Object sizes: pk 22,528 B, ciphertext 22,656 B, R_TX statement 113,792 B (auditor on).

## What a chain needs for this set

Measured where marked (plan 5h Task 8d part 2b: forge 1.8.5 under Amsterdam through the real token and registry, the
`PQZ` precompile at its provisional testnet row `pqz-core/nethermind/chain/engine-pqz-provisional-n2816.json` + 3 per
input word; `smartcontracts/evm/runs/2026-10-26-t8d2b-gas-n2816-kmax65536.txt`, the table in
[`../README.md`](../README.md#one-transactions-gas-per-relation-measured-plan-5h-task-8d-part-2b)); the rest [estimate].
Nothing here was timed (owner rule: no timing runs).

1. **The node library and plugin of this set.** `pqz-ffi` built with `--no-default-features --features
   pqzl-rust,set-n2816-kmax65536` (`pqz_max_input()` = 524,288) and the Nethermind plugin with `-p:PqzSet=n2816-kmax65536`
   (its `OP_SELFTEST` pin and the set's ids `PqzSetIds`); `PQZ_SET=n2816-kmax65536 build-image.sh <label>` builds that
   library, plugin and image, against the set's reviewed `ExpectedLibrarySha256` `17947f64…` in `SelfTest.cs` (R0
   review fix part b, `pqz-core/nethermind/runs/2026-10-26-r01b-ffi-n2816-kmax65536.txt`; no image of this set built
   yet). The plugin's tests pass at this set: 51 / 51 (`run-tests.sh` with `PQZ_SET=n2816-kmax65536`,
   `pqz-core/nethermind/runs/2026-10-26-t8d2b-test-n2816-kmax65536.txt`).
2. **Contracts built for this set**: wired to `PqzSet.sol` and tested at this set since plan 5h Task 8d part 2a; in part
   2b `ROLL_MAX` 48 is pinned (the relayed full rollover 12,575,616 gas, only 7,296 under 0.75 · 2^24; 64 would be
   14,069,552; `smartcontracts/evm/runs/2026-10-26-t8d2b-rollscan-n2816-kmax65536.txt`) and forge passes at this set
   (1,363 passed / 0 failed / 11 skipped, `smartcontracts/evm/runs/2026-10-26-t8d2b-forge-n2816-kmax65536.txt`).
3. **Per-transaction regular gas ≤ 2^24** [measured]: relayed op 1 (auditor) 9.55 M; op 7 M = 1 / 2 / 4 (auditor)
   7.25 / 7.51 / 8.27 M; op 7 M = 8 12.56 M with the auditor (131,268 B of calldata), 11.28 M without;
   `UARegistry.register` 4.71 M; `mtxPrepareAcc` halves 3.75 M each (spec §7.6).
4. **State gas:** every debit stores its op blob (ciphertexts never only in calldata / events), packed at 54 bits
   (P46) [measured]: 30.33 M per relayed op 1, 29.57 M per prepare half, 63.44 M for op 7 M = 8 with the auditor,
   62.11 M without. Block gas used = max(Σ regular, Σ state) (EIP-8037), so a 60 M block holds one op 1 debit of this
   set and no op 7 M = 8 [estimate, from the measured state gas].
5. **Precompile input:** ≤ 394,117 B at the limits (above), within `MAX_INPUT` 524,288; built in memory by the
   token / registry, so it is not calldata.
6. **Security margins:** encryption uSVP β 520; since the R0 review fix 128 worst-case hints (an audited op 7 group of
   `s_aud` = 4 legs) DDGR20 β 483.09, dual_hybrid − offset 475.09 / 478.09 [estimate] (was 496.79 at 80 hints); proof MSIS / MLWE β ≥ 450 per spec
   (`e-s1.txt`); exactness and Fiat–Shamir rounds MET (`e-s0.txt`); worst-case noise margin 1.02 against 2^30
   (`worstcase_noise.json` `margin_2_30`), mint margin 3.08.
7. **No PQZH backup** at this set (above): a chain that wants the hash-based backup proof system needs another set; the radix-1,789 preset is not pursued (owner 2026-10-25, reason in the PQZH row above).

Proof sizes (`smartcontracts/vectors/pqz/n2816-kmax65536/proof_pqzl.json` since the R0 review fix, byte-identical C =
Rust = wasm32): R_TX 54,849 B, R_TX0 54,505, R_BURN 54,026 (burn) / 53,996 (refresh), R_REG 35,479, R_DS 35,913, R_DR
36,828 (receiver) / 36,859 (auditor); R_TXM with the auditor M = 1 / 2 / 4 / 8: 54,824 / 57,779 / 59,548 / 79,208 B (the
M = 8 boundary row 79,207 B), without 54,504 / 55,020 / 58,086 / 76,340 B (all below `MAX_PROOF_PQZL` 98,304; the
pre-R0 values 79,196 / 79,199 B of this paragraph were stale, plan 5h Task 8d part 2b). Heap: C prover arena peaks
538 MB (R_TX) … 1,259 MB (R_TXM M = 8 with the auditor: needs `PQZ_ARENA_MB=2048`).

Files: `set.toml` (input), `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, `<rel>_params.sage` (gen_set.py),
`pqz_<rel>_params.h` + `codegen.txt` (LaZer codegen), `rust/<rel>.rs` (to_rust.py), `e-s1.txt`, `e-s0.txt`,
`lazer-3330e48-kat.json` (+ `-build.txt`); made by `make.sh n2816-kmax65536 all`.
