# Group 3e mutant harness (pay-meta-tax spec §14; plan T37-T43)

`mutants.py` holds every source mutant of the group's contract tasks, one row each: the task, the file, the exact text
and its replacement, the tests that must go red. One run per mutant on a clean tree: the edit is applied, the named tests
run through `scripts/capped`, the file is restored in the same process, and `git diff --exit-code` must hold after.

    cd smartcontracts/evm
    python3 runs/2026-11-07-ua-mtx-merge-paytax/mutants.py list
    python3 runs/2026-11-07-ua-mtx-merge-paytax/mutants.py run <id> [<id> ...]

Each run appends `mutant | test that went red | rc` to `runs/2026-11-07-ua-mtx-merge-<task>-mutants.txt`; the full forge
output stays in the git-ignored `runs/2026-11-07-ua-mtx-merge-<task>-mut-<id>.log`. A mutant is killed when the run fails
(rc != 0) with a named test red; a compile error is reported as such and is not a kill. A survivor is a finding for its
owning task. **UNAUDITED.**
