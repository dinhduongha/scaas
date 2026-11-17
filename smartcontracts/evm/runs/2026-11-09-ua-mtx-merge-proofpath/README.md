# Group 3h T64: the proof-path invariants and the mutant harness

Spec `docs/superpowers/specs/2026-11-06-pqz-proof-path.md` §11.2, §11.3; plan T64. UNAUDITED.

- `test/pqz/invariant/ProofPathHandler.t.sol`, `ProofPathInvariants.t.sol`: P1-P7 and P1′ over shields (same-block merges), bulk
  shields rolled past `INLINE_MAX`, rollovers, every `NORMAL_PQZ` debit form at a `p` up to 16 below or above `rolled` (un-rolls)
  with `shieldIn` 0-2, 3g rotations and migrations, `setProofStore` and `disableFeature(24)`. A positive control
  (`test_handler_reachesEveryPath`) reaches every path; `afterInvariant` logs the debits, `LOG` debits and rollovers of a run.
- `mutants.py`: every spec mutant (M1-M22 without M12, M19) against those two files, one at a time on a clean tree, restored; the
  `unit` column names the T58-T61 file that kills it alone. M16 is equivalent on the built code: `cleared ≤ floor ≤ rolled`, so
  `max(floor, rolled) = rolled` (P1 asserts the order).
- `summary.txt`: `mutant | tests that went red | rc | unit` (full output in git-ignored `runs/2026-11-09-ua-mtx-merge-proofpath-mut-*.log`).

Run (from `smartcontracts/evm`, a second work tree at the commit): `python3 runs/2026-11-09-ua-mtx-merge-proofpath/mutants.py run`.
