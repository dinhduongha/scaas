# Group 3g mutant harness and measurements (pqz-key-versions spec §6.2, §14; plan T51-T56)

`mutants.py` holds every source mutant of the group's tasks, one row each: the task, the file, the exact text and its
replacement, the tests that must go red. One run per mutant on a clean tree: the edit is applied, the named tests run
through `scripts/capped` (only the match's test directory compiled, into `out/mutants` and `cache/mutants`, so the tree's
own build stays as it is), the file is restored in the same process, and `git diff --exit-code` must hold after.

    cd smartcontracts/evm
    python3 runs/2026-11-07-ua-mtx-merge-pqzver/mutants.py list
    python3 runs/2026-11-07-ua-mtx-merge-pqzver/mutants.py run <id> [<id> ...]

Each run appends `mutant | test that went red | rc` to `runs/2026-11-07-ua-mtx-merge-<task>-mutants.txt`; the full forge
output stays in the git-ignored `runs/2026-11-07-ua-mtx-merge-<task>-mut-<id>.log`. A mutant is killed when the run fails
(rc != 0) with a named test red; a compile error is reported as such and is not a kill. A survivor is a finding for its
owning task.

The match column: a forge `--match-path`; `node:<files>` runs `node --test` in `clients/clientkeys` (T54, M-C1 and the wallet
rules); `cargo:<filter>` runs `cargo test --lib <filter>` in `scaas-node` with `CAPPED_MEM=6G` (T55, M-N1). T56 re-runs the
token and registry mutants its invariant suite covers as `<id>@inv` against `test/pqz/invariant/*` (J1-J10).

`regdeploy/`: the registry's deploy gas (T51, spec §6.2) by T10's public-gate formula, `UARegistryLib` and `UARegistry`
each its own CREATE2 transaction, at one set per run (`measure.sh <set> <out dir>`); the same harness ran on a copy of the
3e tip for the old figures. **UNAUDITED.**
