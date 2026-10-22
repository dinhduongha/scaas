# PQZ vectors of parameter set n2560-kmax16384 (16k)

The same files as [the v3 set's directory](../README.md) (`smartcontracts/vectors/pqz/`, which the contracts read until
plan 5h Task 8d), for the parameter set [`n2560-kmax16384`](../../../../pqz-core/params/sets/n2560-kmax16384/SET.md)
(n = 2560, k = 40, `K_MAX` 16,384, q = 2^50 − 42,310,535; shippable for customer chains, owner 2026-10-21).
Differences:

- **PQZL only.** PQZH is not built for this set until plan 5h Task 8c (owner ruling 2026-10-21): there is no
  `proof_pqzh.json`; statement files carry the PQZL id's hashes only; `negative.json`'s "the other system's
  proofSystemId" rows put the PQZH id on a PQZL input, which this set's precompile build answers 0 (decoded, no
  verifier for that id: reason `verify`); `selftest.json` has no Ligero FFT (`fft` n 0, ok false) and PQZH results 0, 0.
- **The v3 proofSystemId** on every statement until the 8d bump (owner ruling 2026-10-21).
- Lengths, norms, noise ranges follow the set (pk 20,480 B; op 1 statement 103,552 B; worst case: 16,383 credits,
  B_FRESH 14,624, proven range 2^28, key `margin_2_28` 1.12, mint margin 3.36).

Regenerate / check: `PQZ_SET=n2560-kmax16384 scripts/capped pqz-core/ffi/vectors/run.sh <label> [write]`
(`pqz-vectors` built with `--no-default-features --features pqzl-rust,set-n2560-kmax16384`; `pqz_kat.py` with
`PQZ_SET=n2560-kmax16384` reads this directory and `pqz-core/params/sets/n2560-kmax16384/set.json`).
