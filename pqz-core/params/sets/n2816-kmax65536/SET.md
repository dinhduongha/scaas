# Parameter set `n2816-kmax65536` (full PQZL set, no PQZH)

The `K_MAX` 65,536 candidate of plan 5h (research record [`pqz-core/pqzl/params/aprime/`](../../../pqzl/params/aprime/README.md):
owner choice 2026-10-19, superseded by [`n2560-kmax16384`](../n2560-kmax16384/SET.md) on 2026-10-20). Kept in
`params/sets/` on 2026-10-21 "in case a customer wants it" as a core-only set; **owner 2026-10-24: a full PQZL set,
deployable for a customer like the other sets** ("it must be done fully, for customers if they need it"): pqz-stmt, the precompile
(`pqz-ffi`, the Nethermind plugin), vectors (`smartcontracts/vectors/pqz/n2816-kmax65536/`) and the full gate since
plan 5h Task 8d part 1b; its contracts follow in 8d part 2 with the other sets. **No PQZH, and none possible at this q**
(below). Input: [`set.toml`](set.toml) (`core_only = false`, `pqzh = false`); every other file here is derived (see
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
| encryption, 80 hints | DDGR20 worst case β 496.79 (`aprime/aprime.txt`) |
| e_s0 | budget, exactness of every norm proof (14 relations) and Fiat–Shamir rounds: MET (`e-s0.txt`) |
| upstream KAT | `lazer-3330e48-kat.json`: pqz-core = upstream LaZer 3330e48 (+ HEXL) at q = 2^54 − 327, 19/19 |
| 64-bit arithmetic | log2 q = 54 is within every bound of the set-generic cores: `PQZ_LOG2Q <= 56` (`pqz_ntt.c` wasm32 limbs, `pqz_sv.c` lift), Barrett 2L + 4 = 112 ≤ L + 63, specialised verifier 5 CRT primes, Δ · 2^(MBITS − 1) = 2^51 in int64. The C core's wasm32 limb path (`PQZ_MUL128` 0, limb width LB = 27) runs: its wasm32 build (`B=build/gate-cwasm-n2816-kmax65536 ./build.sh wasm`, `test/run_wasm.mjs 2 1 16383`) gives the native C run's `proofs_fnv` on all 14 bench relations, 0 fails (8b fix round 1: `pqz-core/runs/gate/fix1-n2816-cwasm.*`; the gate checks it as part `fnv/cwasm`) |
| proofSystemId | PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k44-q54l4/v4")` = `0x9d23a0de…bd53a3` (set.toml `pqzl_id`, plan 5h Task 8d; controller proposal, decisions CTR-PQZ-09); no PQZH id (pqz-stmt `HAS_PQZH` false: its `PQZH_ID` is the zero word, refused like any unknown id) |
| owner approval | 2026-10-21: keep this set as a core-only set; 2026-10-24: a full PQZL set for customers (progress.md); its values are the research record's, not a frozen relation |
| stored-blob packing width | ⌈log2 q⌉ = 54 bits (`PqzSet.sol` `PACK_BITS`; the contracts are wired in 8d part 2) |
| limits | `MAX_PROOF_PQZL` 98,304 B (every set's): largest proof 79,199 B (R_TXM M = 8 with the auditor, the vectors), margin 19,105 B; `MAX_INPUT` 524,288 B (`set.toml` `max_input`, 512 KiB like the other non-frozen sets; `pqz_max_input()` gives it to the node): largest input at the limit 5 + 295,808 + 98,304 = 394,117 B (R_TXM M = 8 with the auditor), above the frozen set's 393,216 |
| self-test | `OP_SELFTEST` = `0x0aa1dfe2…491882` (`selftest.json`: results 1, 0, 0, 0, no Ligero FFT); the Nethermind plugin built with `-p:PqzSet=n2816-kmax65536` pins it (`SelfTest.cs`) |
| PQZH | **not possible at this q**: q − 1 = 2^3 · 3 · 1,789 · 419,563,967,521 has a smooth part of only 24, so no Ligero evaluation domain exists (PQZH's domains need small radices of q − 1: 19 / 43 / 431 at the other sets' q's, also 7 / 17 at `n2304-kmax4096`'s). PQZH here would need another q, i.e. another set (not in scope). pqz-ffi is built without PQZH (feature `pqzh` off; a compile-time check refuses it at this set), the vectors are PQZL only, the gate skips Ligero and the cross-checks |

Object sizes: pk 22,528 B, ciphertext 22,656 B, op 1 statement 113,792 B (auditor on).

## What a chain needs for this set

Measured where marked; the rest [estimate]. Nothing here was timed (owner rule: no timing runs).

1. **The node library and plugin of this set.** `pqz-ffi` built with `--no-default-features --features
   pqzl-rust,set-n2816-kmax65536` (`pqz_max_input()` = 524,288) and the Nethermind plugin with `-p:PqzSet=n2816-kmax65536`
   (its `OP_SELFTEST` pin); the image build (`Dockerfile`, `build-image.sh`) is for the default set only today, so a
   customer image of this set needs those two flags there and its own reviewed `ExpectedLibrarySha256`. The plugin's
   tests pass at this set (`run-tests.sh` with `PQZ_SET=n2816-kmax65536`).
2. **Contracts built for this set** (plan 5h Task 8d part 2, with the other sets: `PqzSet.sol` wired, `ROLL_MAX`,
   the per-op gas measured). Until then: not deployable on chain.
3. **Per-transaction regular gas ≤ 2^24**: the EIP-7976 calldata floor of the largest PQZL path (relayed R_TXM M = 8)
   is ≈ 6.98 M [model, `../README.md`], leaving ≈ 9.8 M for execution and the precompile; the execution gas is
   measured in 8d part 2.
4. **State gas:** every debit stores its op blob (ciphertexts never only in calldata / events); the objects are ≈ 10 %
   larger than `n2560-kmax16384`'s (ciphertext 22,656 vs 20,608 B), so the state gas per debit grows about as much
   [estimate; measured in 8d part 2], and with it the block gas limit a debit needs (`n2560-kmax16384`: ≥ ≈ 43 M per
   debit, [SET.md](../n2560-kmax16384/SET.md#conditions-for-this-set-to-work-on-a-chain)).
5. **Precompile input:** ≤ 394,117 B at the limits (above), within `MAX_INPUT` 524,288; built in memory by the
   token / registry, so it is not calldata.
6. **Security margins:** encryption uSVP β 520, 80 worst-case hints β 496.79; proof MSIS / MLWE β ≥ 450 per spec
   (`e-s1.txt`); exactness and Fiat–Shamir rounds MET (`e-s0.txt`); worst-case noise margin 1.02 against 2^30
   (`worstcase_noise.json` `margin_2_30`), mint margin 3.08.
7. **No PQZH backup** at this set (above): a chain that wants the hash-based backup proof system needs another set.

Proof sizes (`smartcontracts/vectors/pqz/n2816-kmax65536/proof_pqzl.json`, byte-identical C = Rust = wasm32): TRANSFER
54,843 B, TRANSFER0 54,531, BURN 54,012, REFRESH 53,983, REGISTER 35,407, DISCLOSE-SENDER 35,924, -RECEIVER 36,728,
-AUDITOR 36,742; R_TXM with the auditor M = 1 / 2 / 4 / 8: 54,844 / 57,746 / 59,508 / 79,196 B (the M = 8 boundary row
79,199 B), without 54,506 / 55,024 / 58,148 / 76,350 B (all below `MAX_PROOF_PQZL` 98,304). Heap: C prover arena peaks
538 MB (R_TX) … 1,259 MB (R_TXM M = 8 with the auditor: needs `PQZ_ARENA_MB=2048`).

Files: `set.toml` (input), `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, `<rel>_params.sage` (gen_set.py),
`pqz_<rel>_params.h` + `codegen.txt` (LaZer codegen), `rust/<rel>.rs` (to_rust.py), `e-s1.txt`, `e-s0.txt`,
`lazer-3330e48-kat.json` (+ `-build.txt`); made by `make.sh n2816-kmax65536 all`.
