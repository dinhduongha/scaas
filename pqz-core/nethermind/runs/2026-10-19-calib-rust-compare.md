# Rust PQZL core: calibration against the live schedule (2026-10-19)

Roll-out of the Rust-backed image on chain 7622 (owner 2026-10-19: "Đưa image Rust lên 7622, hiệu chỉnh gas").
Image `scaas/nethermind-pqz:1.39.0-pqz3` (`sha256:69e799a98cac…74efc1`, commit `1adbd56`, log
`2026-10-19-image-pqz3.txt`), library `libpqz_ffi.so` sha256
`16dd99ce77d05a9bea9f54142979bc21511240aeff6d4442d784470a428c9caf` (= image label; test-hook names 0, GMP / MPFR / HEXL
0, `--version` ok), image label self-test `ed910a2c…d205`; calib image `…-pqz3-calib` `sha256:65cc5c846e2f…dbc054`.

Command, twice: `scripts/capped pqz-core/nethermind/calibrate.sh pqz3 --ops 1,2,3,4,5,7` (every op with a row in the
live schedule 1; `chain/engine-pqz.json` untouched). Same method as P6f Task 6: p99 over 1,000 calls per set of valid
and adversarial inputs, `--cpus 4`, `t_ecMul` measured in the same run.

| Run | Log | Host load before / after (1, 5, 15 min) | `t_ecMul` median (p99) |
|---|---|---|---|
| 1 | `2026-10-19-calib-ops123457-run1-noisy.txt` | 4.02 4.58 4.36 / 5.00 5.75 5.27 (load from the image build still decaying) | 0.017 ms (0.032) ⇒ 0.355 M gas / ms |
| 2 | `2026-10-19-calib-ops123457-run2.txt` | 2.96 3.57 4.35 / 3.48 3.65 4.04 | 0.017 ms (0.029) ⇒ 0.359 M gas / ms |

Host conditions: nothing else under `scripts/capped`; no copy chain running during either run. Two external processes
held about two of the eight cores the whole time (`top`, 04:27: `iii`, the agentmemory engine, 100 % CPU;
`gnome-shell` 83 %). The load did not fall below about 2.5 in 10 minutes of watching. The C-core calibrations ran at
load 2.7–3.9 (`2026-10-15-calib.txt`, `2026-10-17-calib-ops7.txt`).

Tables: `python3 -I runs/2026-10-19-calib-compare.py chain/engine-pqz.json <run 1 json> <run 2 json>` and
`python3 -I runs/2026-10-19-calib-timing.py runs/2026-10-15-calib.txt,runs/2026-10-17-calib-ops7.txt <run 1 log> <run 2 log>`.

## Gas: live schedule 1 against the new runs

| op | PQZL stmtLen [M, auditorOn] | live (last schedule) | run 1 | change | run 2 | change |
|---|---|---|---|---|---|---|
| 1 | 83072 | 5,409,000 | 3,454,000 | -36.1 % | 3,225,000 | -40.4 % |
| 1 | 66560 | 5,223,000 | 3,848,000 | -26.3 % | 3,351,000 | -35.8 % |
| 2 | 50048 | 3,723,000 | 3,778,000 | +1.5 % | 4,039,000 | +8.5 % |
| 3 | 16480 | 2,695,000 | 2,998,000 | +11.2 % | 1,995,000 | -26.0 % |
| 4 | 33184 | 2,601,000 | 2,759,000 | +6.1 % | 2,539,000 | -2.4 % |
| 5 | 33184 | 2,567,000 | 2,406,000 | -6.3 % | 2,281,000 | -11.1 % |
| 7 | 215936 [8, 1] | 6,177,000 | 6,449,000 | +4.4 % | 7,307,000 | +18.3 % |
| 7 | 198528 [8, 0] | 5,339,000 | 5,650,000 | +5.8 % | 6,223,000 | +16.6 % |
| 7 | 132992 [4, 1] | 4,121,000 | 4,976,000 | +20.7 % | 3,799,000 | -7.8 % |
| 7 | 116096 [4, 0] | 3,972,000 | 4,058,000 | +2.2 % | 3,498,000 | -11.9 % |
| 7 | 99712 [2, 1] | 3,710,000 | 4,735,000 | +27.6 % | 4,696,000 | +26.6 % |
| 7 | 83072 [2, 0] | 3,827,000 | 3,331,000 | -13.0 % | 3,279,000 | -14.3 % |
| 7 | 83072 [1, 1] | 3,625,000 | 3,587,000 | -1.0 % | 4,412,000 | +21.7 % |
| 7 | 66560 [1, 0] | 3,953,000 | 4,662,000 | +17.9 % | 3,215,000 | -18.7 % |

PQZH (code unchanged by the port, so this is the control: any change here is the host, not the core):

| op | PQZH stmtLen [M, auditorOn] | live (last schedule) | run 1 | change | run 2 | change |
|---|---|---|---|---|---|---|
| 1 | 83072 | 4,225,000 | 4,329,000 | +2.5 % | 4,283,000 | +1.4 % |
| 1 | 66560 | 4,021,000 | 4,239,000 | +5.4 % | 4,294,000 | +6.8 % |
| 2 | 50048 | 3,738,000 | 4,342,000 | +16.2 % | 4,824,000 | +29.1 % |
| 3 | 16480 | 3,322,000 | 3,875,000 | +16.6 % | 3,059,000 | -7.9 % |
| 4 | 33184 | 3,283,000 | 3,728,000 | +13.6 % | 3,206,000 | -2.3 % |
| 5 | 33184 | 2,881,000 | 3,983,000 | +38.3 % | 3,204,000 | +11.2 % |
| 7 | 132992 [4, 1] | 4,935,000 | 5,364,000 | +8.7 % | 5,080,000 | +2.9 % |
| 7 | 116096 [4, 0] | 4,892,000 | 4,708,000 | -3.8 % | 4,472,000 | -8.6 % |
| 7 | 99712 [2, 1] | 4,001,000 | 4,631,000 | +15.7 % | 4,792,000 | +19.8 % |
| 7 | 83072 [2, 0] | 4,415,000 | 4,999,000 | +13.2 % | 4,253,000 | -3.7 % |
| 7 | 83072 [1, 1] | 3,864,000 | 4,733,000 | +22.5 % | 4,262,000 | +10.3 % |
| 7 | 66560 [1, 0] | 4,314,000 | 4,527,000 | +4.9 % | 5,445,000 | +26.2 % |

| price | live | run 1 | change | run 2 | change |
|---|---|---|---|---|---|
| selftestGas | 2,567,000 | 2,406,000 | -6.3 % | 1,995,000 | -22.3 % |
| mldsa44Gas | 49,000 | 68,000 | +38.8 % | 86,000 | +75.5 % |
| mldsa65Gas | 68,000 | 92,000 | +35.3 % | 119,000 | +75.0 % |

## Timing: p50 valid / p99 valid / p99 adversarial (ms)

The baseline is the C core (`2026-10-15-calib.txt` for ops 1–5, `2026-10-17-calib-ops7.txt` for op 7, same host,
same method).

| op | id | stmtLen [M, auditorOn] | C core (baseline) | Rust run 1 | Rust run 2 |
|---|---|---|---|---|---|
| 1 | pqzl | 83072 | 8.51 / 11.49 / 15.05 | 6.49 / 9.12 / 9.73 | 6.44 / 8.96 / 8.97 |
| 1 | pqzl | 66560 | 11.73 / 14.54 / 12.26 | 6.37 / 8.98 / 10.84 | 6.31 / 9.29 / 9.32 |
| 2 | pqzl | 50048 | 8.17 / 9.21 / 10.36 | 6.56 / 9.93 / 10.64 | 6.19 / 8.96 / 11.24 |
| 3 | pqzl | 16480 | 4.52 / 7.50 / 6.93 | 4.95 / 7.40 / 8.44 | 3.33 / 5.28 / 5.55 |
| 4 | pqzl | 33184 | 4.69 / 7.24 / 6.85 | 4.01 / 7.00 / 7.77 | 3.53 / 5.77 / 7.07 |
| 5 | pqzl | 33184 | 4.92 / 5.36 / 7.14 | 3.79 / 6.15 / 6.78 | 3.62 / 5.82 / 6.35 |
| 7 | pqzl | 215936[8,1] | 14.05 / 17.29 / 15.85 | 12.38 / 18.16 / 17.00 | 11.29 / 15.09 / 20.34 |
| 7 | pqzl | 198528[8,0] | 12.96 / 14.46 / 14.95 | 10.23 / 15.87 / 15.91 | 9.76 / 13.66 / 17.32 |
| 7 | pqzl | 132992[4,1] | 9.67 / 11.54 / 11.15 | 7.71 / 12.01 / 14.02 | 7.30 / 10.10 / 10.57 |
| 7 | pqzl | 116096[4,0] | 9.11 / 10.36 / 11.12 | 6.81 / 9.03 / 11.43 | 6.89 / 9.69 / 9.74 |
| 7 | pqzl | 99712[2,1] | 9.09 / 10.21 / 10.39 | 7.50 / 11.13 / 13.34 | 6.78 / 9.53 / 13.07 |
| 7 | pqzl | 83072[1,1] | 8.84 / 10.15 / 10.13 | 6.72 / 10.10 / 9.18 | 6.44 / 8.78 / 12.28 |
| 7 | pqzl | 83072[2,0] | 8.92 / 10.72 / 10.48 | 6.58 / 9.38 / 9.26 | 6.45 / 9.10 / 9.13 |
| 7 | pqzl | 66560[1,0] | 8.78 / 10.10 / 11.07 | 6.56 / 11.89 / 13.13 | 6.30 / 8.95 / 8.93 |
| 1 | pqzh | 83072 | 9.69 / 11.76 / 1.98 | 10.06 / 12.19 / 1.96 | 10.09 / 11.92 / 1.99 |
| 1 | pqzh | 66560 | 9.34 / 11.19 / 1.55 | 9.73 / 11.94 / 1.92 | 9.75 / 11.95 / 1.91 |
| 2 | pqzh | 50048 | 9.17 / 10.40 / 1.26 | 10.36 / 12.23 / 1.92 | 9.62 / 13.43 / 1.85 |
| 3 | pqzh | 16480 | 6.99 / 9.25 / 1.42 | 9.02 / 10.91 / 1.62 | 7.18 / 8.51 / 1.32 |
| 4 | pqzh | 33184 | 7.25 / 9.14 / 1.00 | 8.40 / 10.50 / 1.70 | 7.49 / 8.92 / 1.41 |
| 5 | pqzh | 33184 | 7.14 / 8.02 / 1.07 | 7.96 / 11.22 / 1.81 | 7.40 / 8.92 / 1.48 |
| 7 | pqzh | 132992[4,1] | 11.39 / 13.82 / 2.23 | 11.60 / 15.11 / 2.31 | 11.23 / 14.14 / 2.28 |
| 7 | pqzh | 116096[4,0] | 10.60 / 13.70 / 1.46 | 10.67 / 13.26 / 2.25 | 10.44 / 12.45 / 2.45 |
| 7 | pqzh | 99712[2,1] | 10.06 / 11.20 / 1.36 | 10.58 / 13.04 / 2.16 | 10.45 / 13.34 / 2.17 |
| 7 | pqzh | 83072[1,1] | 9.74 / 10.82 / 1.38 | 10.34 / 13.33 / 2.15 | 10.03 / 11.86 / 2.02 |
| 7 | pqzh | 83072[2,0] | 9.79 / 12.36 / 1.96 | 10.59 / 14.08 / 2.17 | 10.01 / 11.84 / 2.00 |
| 7 | pqzh | 66560[1,0] | 9.50 / 12.08 / 1.47 | 9.99 / 12.75 / 2.15 | 9.80 / 15.15 / 1.95 |

## Reading

- **The median shows the port; the p99 shows the host.** The PQZL p50 is lower than the C core's on 27 of 28 row-runs
  (−12 % to −46 %; the exception is op 3 in run 1, +10 %), in line with D6. The PQZH p50, whose code did not change,
  stays within −2 % / +5 % in run 2. The p99 columns, which set the price, move by ±25 % between two runs of the same
  image an hour apart: op 3 PQZL is 8.44 ms in run 1 and 5.55 ms in run 2, and op 7 [1, 1] is 9.18 ms against 12.28 ms.
  The same happens on the unchanged PQZH rows (op 2 +16 % / +29 %, op 7 [1, 0] +5 % / +26 %) and on ML-DSA (+35 % to
  +75 %).
- **Only the transfer rows give a clear signal:** op 1 PQZL is −36 % / −26 % in run 1 and −40 % / −36 % in run 2. The
  C core's 15.05 ms at op 1 was its adversarial "statement last word" set; the Rust core's value for that set is
  9.73 ms and 8.97 ms.
- **The stop rule triggers.** New PQZL rows came out HIGHER than the live row in both runs: op 7 [8, 1], [8, 0] and
  [2, 1] in both, and op 2, 3, 4, [4, 1], [4, 0], [1, 1] and [1, 0] in one of them. That contradicts D6 only on its face
  (the p50 is lower everywhere), but per the task the roll-out stopped before the live chain and reported (ruling
  below).
- **`selftestGas` is PQZL-led** (live = the smallest row = op 5 PQZL). It would drop by 6 % (run 1) or 22 % (run 2, now
  op 3 PQZL as the smallest row): unstable, like the rows.

Options reported to the controller after both runs: (1) a quieter calibration, (2) several runs combined per row,
(3) re-price only the rows with a stable signal, (4) switch only the image and keep every row.

## The rule for the live rows (controller ruling 2026-10-19, owner may override)

The controller's reasoning: both runs are noisy (the unchanged PQZH and ML-DSA prices read up to +29 % / +75 %, and the
op 7 rows are not monotonic in M). Its rule, per PQZL row: **new = min(live, max(run 1, run 2))**. The max of two noisy
runs is an upper estimate of the true cost. The result is never above live, because D6 measured the Rust core faster on
every PQZL row, so a row whose max exceeds live keeps live. The same rule applies to `selftestGas` (PQZL-led: the
smallest row). PQZH rows and the ML-DSA prices stay unchanged, and there is no third calibration run.

The script is `python3 -I runs/2026-10-19-pqzl-rows.py chain/engine-pqz.json <run 1 json> <run 2 json>
runs/2026-10-19-pqzl-rows-engine-pqz.json`. Its output goes to `chain/add-schedule.py … --ops 1,2,3,4,5,7 --id pqzl
--selftest`. Result: 4 PQZL rows and `selftestGas` change; every other price stays as live.

| op | PQZL stmtLen [M, auditorOn] | live (schedule 1) | run 1 | run 2 | new (schedule 2) | change |
|---|---|---|---|---|---|---|
| 1 | 83072 | 5,409,000 | 3,454,000 | 3,225,000 | **3,454,000** | −36.1 % |
| 1 | 66560 | 5,223,000 | 3,848,000 | 3,351,000 | **3,848,000** | −26.3 % |
| 2 | 50048 | 3,723,000 | 3,778,000 | 4,039,000 | 3,723,000 | 0 |
| 3 | 16480 | 2,695,000 | 2,998,000 | 1,995,000 | 2,695,000 | 0 |
| 4 | 33184 | 2,601,000 | 2,759,000 | 2,539,000 | 2,601,000 | 0 |
| 5 | 33184 | 2,567,000 | 2,406,000 | 2,281,000 | **2,406,000** | −6.3 % |
| 7 | 215936 [8, 1] | 6,177,000 | 6,449,000 | 7,307,000 | 6,177,000 | 0 |
| 7 | 198528 [8, 0] | 5,339,000 | 5,650,000 | 6,223,000 | 5,339,000 | 0 |
| 7 | 132992 [4, 1] | 4,121,000 | 4,976,000 | 3,799,000 | 4,121,000 | 0 |
| 7 | 116096 [4, 0] | 3,972,000 | 4,058,000 | 3,498,000 | 3,972,000 | 0 |
| 7 | 99712 [2, 1] | 3,710,000 | 4,735,000 | 4,696,000 | 3,710,000 | 0 |
| 7 | 83072 [2, 0] | 3,827,000 | 3,331,000 | 3,279,000 | **3,331,000** | −13.0 % |
| 7 | 83072 [1, 1] | 3,625,000 | 3,587,000 | 4,412,000 | 3,625,000 | 0 |
| 7 | 66560 [1, 0] | 3,953,000 | 4,662,000 | 3,215,000 | 3,953,000 | 0 |
| `selftestGas` | | 2,567,000 | 2,406,000 | 1,995,000 | **2,406,000** | −6.3 % |

The copy rehearsal (`2026-10-19-rust-copy-*`) first used run 2's raw PQZL rows to check the mechanics (steps 2–5), and
then a fourth schedule with the final rows above (steps 6–7).

## Rehearsal on the copy

The rehearsal ran on a fresh copy (`COPY=scratchpad/rust-copy`) started with `genesis0` and the live two schedules.

| Step | Log | Result |
|---|---|---|
| 1. pqz2 (C core), probe at schedule 1 | `2026-10-19-rust-copy-1-pqz2-probe.txt` | 388 ok, 0 FAIL |
| 2. third schedule at T = 1792360190 (run 2's raw PQZL rows, mechanics only) | `2026-10-19-rust-copy-2-add-schedule.txt` | 14 PQZL rows replaced |
| 3. pqz3 (Rust core), data kept, probe before T at schedule 1 | `2026-10-19-rust-copy-3-pqz3-before-T.txt` | `PQZ-START` library `16dd99ce…`, self-test `ed910a2c…`, three schedules; 388 ok, 0 FAIL (e.g. TRANSFER pqzl 5,420,799 gas) |
| 4. after T, probe | `2026-10-19-rust-copy-4-pqz3-after-T.txt` | 388 ok, 0 FAIL (TRANSFER pqzl 3,236,799) |
| 5. after T, e2e (throwaway signer key, UA included) | `2026-10-19-rust-copy-5-pqz3-e2e.txt` | 86 ok, 0 FAIL |
| 6. fourth schedule at T2 = 1792361238, the final rows + `selftestGas` (`--selftest`) | `2026-10-19-rust-copy-6-final-rows.txt` | `PQZ-START` four schedules, the last with selftest 2,406,000 |
| 7. after T2, probe | `2026-10-19-rust-copy-7-final-after-T2.txt` | 388 ok, 0 FAIL (TRANSFER pqzl 3,465,799; `OP_SELFTEST` 2,406,000) |

The copy was torn down afterwards (`copy.sh down`).

## Outcome: stopped before the live chain (owner, 2026-10-19)

The owner ruled "Dừng và rollback" (stop and roll back) before the live step. Reason: a whole-code review found a P0
Fiat–Shamir soundness break in PQZL, inherited from LaZer and present in both the C and the Rust core. Its fix changes
the `proofSystemId`, so this roll-out was abandoned. **Chain 7622 was never touched:** no stop, no backup, no edit. It
still runs image `pqz2` with its two schedules (checked: `docker ps`, the compose image, live `engine.Pqz` = the
committed `chain/engine-pqz.json`, head advancing). What is kept as record for the next roll-out:

- the two calibration runs and this note;
- the rule script `2026-10-19-pqzl-rows.py`;
- `chain/add-schedule.py` `--id` / `--selftest`;
- the copy logs;
- the prepared, never-run live script `2026-10-19-rust-live.sh`.
