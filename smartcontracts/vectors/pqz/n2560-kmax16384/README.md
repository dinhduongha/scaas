# PQZ vectors of parameter set n2560-kmax16384

The same files as [the n2048-kmax1024 directory](../README.md) (`smartcontracts/vectors/pqz/`, which the contracts read until
plan 5h Task 8d), for the parameter set [`n2560-kmax16384`](../../../../pqz-core/params/sets/n2560-kmax16384/SET.md)
(n = 2560, k = 40, `K_MAX` 16,384, q = 2^50 − 42,310,535; shippable for customer chains, owner 2026-10-21).
Differences:

- **PQZH with the set's preset** (plan 5h Task 8c part 2): `proof_pqzh.json` (16 rows) from pqzh-ligero at THE
  preset's radices and n / k with t = 122 (n 32,756, k 817, l 694; owner 2026-10-23; its `params`), F_q elements of
  7 bytes; statement files carry both ids' hashes; `selftest.json` has the Ligero FFT (`fft` n 1,634, 7-byte elements,
  ok true) and results 1, 0, 1, 0. Limits: `MAX_PROOF_PQZH` 327,680 (this set only, owner 2026-10-23), `MAX_INPUT`
  524,288 (pqz-stmt at this set; the node's 393,216 until 8d), so the `negative.json` "MAX_PROOF(id)" and "MAX_INPUT"
  rows sit at those values.
- **The n2048-kmax1024 proofSystemIds** (PQZL `…/v3`, PQZH D3) on every statement until the 8d bump (owner ruling
  2026-10-21).
- Lengths, norms, noise ranges follow the set (pk 20,480 B; op 1 statement 103,552 B; worst case: 16,383 credits,
  B_FRESH 14,624, proven range 2^28, key `margin_2_28` 1.12, mint margin 3.36).

Regenerate / check: `PQZ_SET=n2560-kmax16384 scripts/capped pqz-core/ffi/vectors/run.sh <label> [write]`
(`pqz-vectors` built with `--no-default-features --features pqzl-rust,set-n2560-kmax16384`; `pqz_kat.py` with
`PQZ_SET=n2560-kmax16384` reads this directory and `pqz-core/params/sets/n2560-kmax16384/set.json`).
