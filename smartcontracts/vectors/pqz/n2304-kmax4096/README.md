# PQZ vectors of parameter set n2304-kmax4096 (set (a))

The same files as [the v3 set's directory](../README.md) (`smartcontracts/vectors/pqz/`, which the contracts read until
plan 5h Task 8d), for the parameter set [`n2304-kmax4096`](../../../../pqz-core/params/sets/n2304-kmax4096/SET.md)
(n = 2304, k = 36, `K_MAX` 4,096, q = 61,275,424,977,257; owner 2026-10-21). Differences:

- **PQZL only.** PQZH is not built for this set until plan 5h Task 8c (owner ruling 2026-10-21): there is no
  `proof_pqzh.json`; statement files carry the PQZL id's hashes only; `negative.json`'s "the other system's
  proofSystemId" rows put the PQZH id on a PQZL input, which this set's precompile build answers 0 (decoded, no
  verifier for that id: reason `verify`); `selftest.json` has no Ligero FFT (`fft` n 0, ok false) and PQZH results 0, 0.
- **The v3 proofSystemId** on every statement until the 8d bump (owner ruling 2026-10-21).
- Lengths, norms, noise ranges follow the set (pk 18,432 B; op 1 statement 93,312 B; worst case: 4,095 credits,
  B_FRESH 13,212, proven range 2^26, key `margin_2_26`).

Regenerate / check: `PQZ_SET=n2304-kmax4096 scripts/capped pqz-core/ffi/vectors/run.sh <label> [write]`
(`pqz-vectors` built with `--no-default-features --features pqzl-rust,set-n2304-kmax4096`; `pqz_kat.py` with
`PQZ_SET=n2304-kmax4096` reads this directory and `pqz-core/params/sets/n2304-kmax4096/set.json`).
