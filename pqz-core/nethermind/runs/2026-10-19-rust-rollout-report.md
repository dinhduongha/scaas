# Rust PQZL roll-out on chain 7622: report (2026-10-19)

**Outcome: stopped before going live** (owner ruling "Dừng và rollback": PQZL Fiat–Shamir P0 finding; the fix changes
the `proofSystemId`). **Live 7622 was never touched**: there was no stop, backup or edit, and `runs/2026-10-19-rust-live.sh`
was never run. Checked afterwards: `mba_chain_node_nethermind` runs `scaas/nethermind-pqz:1.39.0-pqz2` (up 44 h), the
compose file names pqz2, the live `engine.Pqz` equals the committed `chain/engine-pqz.json` (two schedules), and the
head is advancing (48374). Nothing needed rolling back. The copy chain is torn down, and no background shells are left.

- Commit `60f30bb` on branch `p6-rust-rollout` (not merged, not pushed).
- Image `scaas/nethermind-pqz:1.39.0-pqz3` = `sha256:69e799a98cacbfa3c696be9039d1c2e738c97a8bfbe0e903c6dc6bebdf74efc1`;
  calib image `sha256:65cc5c846e2f…dbc054`. Library sha256 `16dd99ce77d05a9bea9f54142979bc21511240aeff6d4442d784470a428c9caf`
  (= the label), self-test `ed910a2c…d205`, test hooks 0, GMP / MPFR / HEXL 0. Both images are local only, never pushed.
- Calibration: two runs, both noisy (load 4.0 → 5.8 and 3.0 → 3.7; `iii` 100 %, `gnome-shell` 83 %). PQZH drifted up to
  +38 % and ML-DSA up to +75 %. Controller rule min(live, max(run 1, run 2)) gives: op 1 PQZL 83,072 B 5,409,000 →
  3,454,000; op 1 PQZL 66,560 B 5,223,000 → 3,848,000; op 5 PQZL 2,567,000 → 2,406,000; op 7 M2 auditor off 3,827,000 →
  3,331,000; `selftestGas` 2,567,000 → 2,406,000. Full tables: `2026-10-19-calib-rust-compare.md`.
- Copy rehearsal: probe 388 ok on pqz2, 388 ok on pqz3 before T, 388 ok after T, e2e 86 ok, and 388 ok on the final
  rows.
