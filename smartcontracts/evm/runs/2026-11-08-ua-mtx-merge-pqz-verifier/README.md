# Group 3f mutant harness (PQZ verifier mode spec §15; plan T44-T49)

`mutants.py` holds every contract mutant of spec §15's Binding, Verifier, Mode, Keys and Disclosure rows, plus T45's "the
verdict decoded but not passed on" and 3g's M-T6 (the pairwise key compare) moved here for the OFFCHAIN case: one row each,
the task, the file, the exact text and its replacement, the tests that must go red. One run per mutant on a clean tree: the
edit is applied, the named tests run through `scripts/capped` (only the match's test directory compiled, into
`out/mutants` and `cache/mutants`, so the tree's own build stays as it is), the file is restored in the same process, and
`git diff --exit-code` must hold after.

    cd smartcontracts/evm
    python3 runs/2026-11-08-ua-mtx-merge-pqz-verifier/mutants.py list
    python3 runs/2026-11-08-ua-mtx-merge-pqz-verifier/mutants.py run <id> [<id> ...]

Each run appends `mutant | test that went red | rc` to `runs/2026-11-08-ua-mtx-merge-<task>-mutants.txt`; the full forge
output stays in the git-ignored `runs/2026-11-08-ua-mtx-merge-<task>-mut-<id>.log`. A mutant is killed when the run fails
(rc != 0) with a named test red; a compile error is reported as such and is not a kill. A survivor is a finding for its
owning task. T49 re-runs the ones its invariants speak to with `MUTANTS_LOG_TASK=t49 MUTANTS_MATCH=test/pqz/invariant/PqzVerdictInvariants.t.sol`.

Not a row: spec §15's "the verifier read from calldata instead of storage" — the verdict carries no verifier field and the
signature check names `pqzVerifierUA` from storage only (`PqzCore.verdictStatus`), so there is no calldata source to
mutate to; the binding rows (the signer's domain, `PqzVerdictRejected`) are the tests that would catch a signer taken
from anywhere else. The Node and Service rows are T47's (`scaas-node/runs/`) and T48's (`scaas-pqz-verifier/runs/`).
**UNAUDITED.**

`gas.sh` runs `PqzOffchainGas.t.sol` (T50's docs figures, log only, not a gate): the same direct debit from the same state on a
PRECOMPILE token (the precompile mocked, its row left out) and on an OFFCHAIN token with an EOA verifier, and the verdict
parameter's calldata in each mode. The file is copied into `test/pqz/` for the run and removed after it.
