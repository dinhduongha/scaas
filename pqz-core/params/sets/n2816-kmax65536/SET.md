# Parameter set `n2816-kmax65536` (core only)

The `K_MAX` 65,536 candidate of plan 5h (research record [`pqz-core/pqzl/params/aprime/`](../../../pqzl/params/aprime/README.md):
owner choice 2026-10-19, superseded by [`n2560-kmax16384`](../n2560-kmax16384/SET.md) on 2026-10-20). The owner asked on 2026-10-21 to
keep it in `params/sets/` "in case a customer wants it": **core only** (`core_only = true` in [`set.toml`](set.toml)):
the PQZL C and Rust cores build and test at this set (C = Rust; native = wasm32 for the Rust crate, and for the C
core through the gate's `fnv/cwasm` part, see "64-bit arithmetic" below; own KATs); there is no `pqz-stmt` /
precompile / vectors / contracts build for it. Every other file here is derived (see [`../README.md`](../README.md)).

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
| proofSystemId | PQZL `keccak256("scaas/pqz/lnp22/mlwe-d64k44-q54l4/v4")` = `0x9d23a0de…bd53a3` (set.toml `pqzl_id`, plan 5h Task 8d; the cores' bench statements carry it; no PQZH, no pqz-stmt build) |
| owner approval | 2026-10-21: keep this set as a core-only set (progress.md); its values are the research record's, not a frozen relation |
| stored-blob packing width | ⌈log2 q⌉ = 54 bits (`PqzSet.sol` `PACK_BITS`, not built: core only) |
| PQZH | not built (core only); q − 1 = 2^3 · 3 · 1,789 · 419,563,967,521 has none of the radices 19 / 43 / 431 of PQZH's Ligero domains (the q's of `n2048-kmax1024`, `n2304-kmax4096` and `n2560-kmax16384` have them), so PQZH at this q would need other domains |

Object sizes: pk 22,528 B, ciphertext 22,656 B, op 1 statement 113,792 B (auditor on).

## What "core only" means for a chain

A customer chain cannot run this set as it stands: the precompile (`pqz-ffi`), its statement layer (`pqz-stmt`), the
vectors and the contracts are built for `n2048-kmax1024` (today), `n2304-kmax4096` and `n2560-kmax16384` only. Using
this set on a chain would need, at least: a `pqz-stmt` / `pqz-ffi` build for the set (drop `core_only`, `make.sh … vectors`),
a PQZH id if PQZH is built (its PQZL id exists), `MAX_PROOF` / `MAX_INPUT` re-pinned (op 7 M = 8 codegen proof ≈ 82.7 KB), the contracts wired
to `PqzSet.sol` (plan 5h Task 8d), and the chain conditions of [`n2560-kmax16384`](../n2560-kmax16384/SET.md#conditions-for-this-set-to-work-on-a-chain)
re-measured at its larger objects (22.7 KB per ciphertext: more state gas per debit).

Files: `set.toml` (input), `pqz_set.h`, `rust/set.rs`, `set.json`, `PqzSet.sol`, `<rel>_params.sage` (gen_set.py),
`pqz_<rel>_params.h` + `codegen.txt` (LaZer codegen), `rust/<rel>.rs` (to_rust.py), `e-s1.txt`, `e-s0.txt`,
`lazer-3330e48-kat.json` (+ `-build.txt`); made by `make.sh n2816-kmax65536 all` (vectors / sol skipped: core only).
