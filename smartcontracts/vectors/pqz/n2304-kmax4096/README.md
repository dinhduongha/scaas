# PQZ vectors of parameter set n2304-kmax4096

The same files as [the n2048-kmax1024 directory](../README.md) (`smartcontracts/vectors/pqz/`, which the contracts read until
plan 5h Task 8d), for the parameter set [`n2304-kmax4096`](../../../../pqz-core/params/sets/n2304-kmax4096/SET.md)
(n = 2304, k = 36, `K_MAX` 4,096, q = 61,275,424,977,257; owner 2026-10-21). Differences:

- **PQZH with the set's preset** (plan 5h Task 8c part 2): `proof_pqzh.json` (20 rows) from pqzh-ligero at preset B
  (radices 2 / 7 / 17 / 19 / 43 / 431, n 45,752, k 952, t 120, l 831; its `params`), F_q elements of 6 bytes;
  statement files carry both ids' hashes; `selftest.json` has the Ligero FFT (`fft` n 1,634, ok true) and results
  1, 0, 1, 0. Limits: `MAX_PROOF_PQZH` 327,680 (262,144 before the R0 review fix; owner 2026-10-25), `MAX_INPUT` 524,288 (pqz-stmt at this set; the node reads it from the library,
  `pqz_max_input()`, since 8d part 1), so the `negative.json` "MAX_INPUT" rows sit at 524,288 / 524,289.
- **The set's own proofSystemIds** (`set.json`; decisions CTR-PQZ-09), since the R0 review fix (2026-10-25): PQZL
  `keccak256("scaas/pqz/lnp22/mlwe-d64k36-q46l4/v5")` = `0xef1ffbcb…90336e`, PQZH
  `keccak256("scaas/pqz/pqzh/ligero-fq46-n45752k952t120-keccak256-zk-proven/v3")` = `0x046859a8…944ead`; the retired
  ids (this set's v4 `0x15d16d77…cb608a` / PQZH v2 `0xe4bc6d17…885730` of plan 5h Task 8d, PQZL v2 / v3, PQZH v1) only
  in `negative.json`'s "retired … proofSystemId" rows. Audited op 7 groups of `S_AUD` = 3 legs: `M8-on-boundary`'s
  real legs are 5 and 6 (groups 1 and 2; R0 fix round m6).
- Lengths, norms, noise ranges follow the set (pk 18,432 B; op 1 statement 93,312 B; worst case: 4,095 credits,
  B_FRESH 13,212, proven range 2^26, key `margin_2_26`).

Regenerate / check: `PQZ_SET=n2304-kmax4096 scripts/capped pqz-core/ffi/vectors/run.sh <label> [write]`
(`pqz-vectors` built with `--no-default-features --features pqzl-rust,set-n2304-kmax4096`; `pqz_kat.py` with
`PQZ_SET=n2304-kmax4096` reads this directory and `pqz-core/params/sets/n2304-kmax4096/set.json`).
