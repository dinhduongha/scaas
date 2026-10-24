# PQZ vectors of parameter set n2816-kmax65536

The same files as [the n2048-kmax1024 directory](../README.md) (`smartcontracts/vectors/pqz/`), for the parameter set
[`n2816-kmax65536`](../../../../pqz-core/params/sets/n2816-kmax65536/SET.md) (n = 2816, k = 44, `K_MAX` 65,536,
q = 2^54 − 327; a full PQZL set for customers since plan 5h Task 8d part 1b, owner 2026-10-24). Differences:

- **PQZL only.** This set has no PQZH (owner ruling 2026-10-24: q − 1 = 2^3 · 3 · 1,789 · 419,563,967,521 has none of the
  current Ligero presets' radices; a radix-1,789 preset would be new, unexplored work, not in scope), so
  there is no `proof_pqzh.json`; `fee0.json` and the statement files carry the PQZL id only; `selftest.json` has no
  Ligero FFT (`fft` empty, ok false) and results 1, 0, 0, 0. pqz-stmt knows no PQZH id at this set (its `PQZH_ID` is
  the zero word, refused): `negative.json`'s "other system's id" rows are decoder rejects (`ProofSystemId`).
- **The set's own proofSystemId** (plan 5h Task 8d, `set.json`; decisions CTR-PQZ-09): PQZL
  `keccak256("scaas/pqz/lnp22/mlwe-d64k44-q54l4/v4")` = `0x9d23a0de…bd53a3`; the retired PQZL v2 / v3 and PQZH v1 ids
  only in `negative.json`'s "retired … proofSystemId" rows (all three on the PQZL inputs here).
- Limits: `MAX_PROOF_PQZL` 98,304 (largest proof 79,199 B, R_TXM M = 8 with the auditor), `MAX_INPUT` 524,288
  (largest input at the limit 5 + 295,808 + 98,304 = 394,117 B, R_TXM M = 8 with the auditor).
- Lengths, norms, noise ranges follow the set (pk 22,528 B; R_TX statement (auditor on) 113,792 B; worst case: 65,535 credits,
  B_FRESH 15,940, proven range 2^30, key `margin_2_30` 1.02, mint margin 3.08).

Regenerate / check: `PQZ_SET=n2816-kmax65536 scripts/capped pqz-core/ffi/vectors/run.sh <label> [write]`
(`pqz-vectors` built with `--no-default-features --features pqzl-rust,set-n2816-kmax65536`; `pqz_kat.py` with
`PQZ_SET=n2816-kmax65536` reads this directory and `pqz-core/params/sets/n2816-kmax65536/set.json`).
