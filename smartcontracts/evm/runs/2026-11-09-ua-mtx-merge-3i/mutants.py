# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Group 3i T77 (spec 2026-11-09-service-pull §11 "Mutants"): "a service that forgets a check", one mutant at a time on a
clean tree, in the T64 harness's form: the edit applied to test/metatx/helpers/RefServiceEscrow.sol (test only: no src/
file is touched), forge through `scripts/capped` (sparse, out/mutants-3i), the file restored in the same process, then
`git diff --quiet --exit-code -- <file>`. M0 is the red-first run (every check of §3.3 and the delta check removed at once:
the service before its implementation). M1-M13 are the spec's list; M14, M15 are extra (the zero-amount half of check 5,
`used` never written). Each must turn a named negative red while the original stays green (the gate's own run).

Usage (from smartcontracts/evm): python3 runs/2026-11-09-ua-mtx-merge-3i/mutants.py list | run [<id> ...]
Full output: runs/2026-11-09-ua-mtx-merge-3i-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-09-ua-mtx-merge-3i/mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
PATH = "test/metatx/helpers/RefServiceEscrow.sol"
TESTS = "test/metatx/{ServicePull,ServicePullInvariant}.t.sol"

C1 = "        if (t.to != MetaTxLib.pad(address(this))) revert ServicePullShape(1);\n"
C2 = "        if (t.mode != MetaTxLib.MODE_RESTRICT_RELAYER || t.relayer != address(this)) revert ServicePullShape(2);\n"
C2F = "        if (t.fee != 0 || t.feeRecipient != address(0)) revert ServicePullShape(2);\n"
C3 = "        if (t.entryRef != ref) revert ServicePullShape(3);\n"
C4 = "        if (t.from != payer) revert ServicePullShape(4);\n"
C5 = "        if (t.value != amount || amount == 0) revert ServicePullShape(5);\n"
C6R = "        if (used[ref]) revert ServicePullReplayed(ref);\n"
C6F = ("        if (REGULATED && IRegulatedToken(TOKEN).isFrozen(MetaTxLib.pad(address(this)))) "
       "revert ServicePullFrozen();\n")
DELTA = "        if (b1 < b0 || b1 - b0 != t.value) revert ServicePullNotReceived(t.value, b1 < b0 ? 0 : b1 - b0);\n"
ORDER = ("        _checks(ref, payer, amount, t); // steps 1-6\n        used[ref] = true; // step 7\n"
         "        _pull(t, auth); // step 8\n")
PULL = "        IERC20MetaTx(TOKEN).mtxExecuteTransfer(t, auth);\n"

# id: [(old, new, occurrences)]
MUTANTS = {
    "M0-red-first-no-checks": [(C1 + C2 + C2F + C3 + C4 + C5 + C6R + C6F, "", 1), (DELTA, "", 1)],
    "M1-drop-check1-to": [(C1, "", 1)],
    "M2-drop-check2-mode-relayer": [(C2, "", 1)],
    "M3-drop-check2-fee-pins": [(C2F, "", 1)],
    "M4-drop-check3-entryRef": [(C3, "", 1)],
    "M5-drop-check4-payer": [(C4, "", 1)],
    "M6-drop-check5-value": [(C5, "", 1)],
    "M7-drop-replay-check": [(C6R, "", 1)],
    "M8-drop-freeze-check": [(C6F, "", 1)],
    "M9-drop-delta-check": [(DELTA, "", 1)],
    "M10-drop-reentrancy-guard": [(" nonReentrant", "", 3)],
    "M11-pull-before-checks": [(ORDER, "        _pull(t, auth);\n        _checks(ref, payer, amount, t);\n"
                                       "        used[ref] = true;\n", 1)],
    "M12-try-catch-pull": [(PULL, "        try IERC20MetaTx(TOKEN).mtxExecuteTransfer(t, auth) {} catch {}\n", 1)],
    "M13-credit-op-payer-no-check4": [(C4, "", 1), ("Custody(t.from, t.value, op.releaseAfter)",
                                                    "Custody(op.payer, t.value, op.releaseAfter)", 1),
                                      ("Custody(t.from, t.value, 0)", "Custody(op.payer, t.value, 0)", 1)],
    "M14-check5-zero-allowed": [(C5, "        if (t.value != amount) revert ServicePullShape(5);\n", 1)],
    "M15-used-never-written": [("        used[ref] = true; // step 7\n", "", 1)],
}


def run(mid):
    full = os.path.join(EVM, PATH)
    src = open(full).read()
    mut = src
    for old, new, n in MUTANTS[mid]:
        if mut.count(old) != n:
            raise SystemExit(f"{mid}: the mutated text occurs {mut.count(old)} times, not {n}")
        mut = mut.replace(old, new)
    logp = os.path.join(EVM, "runs", f"2026-11-09-ua-mtx-merge-3i-mut-{mid}.log")
    try:
        open(full, "w").write(mut)
        env = {**os.environ, "FOUNDRY_SPARSE_MODE": "true", "FOUNDRY_OUT": "out/mutants-3i",
               "FOUNDRY_CACHE_PATH": "cache/mutants-3i"}
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, FORGE, "test", "-j", "2", "--match-path", TESTS], cwd=EVM, env=env, stdout=log,
                                 stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if open(full).read() != src or subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", PATH], cwd=EVM) != 0:
        raise SystemExit(f"{mid}: {PATH} not restored")
    out = open(logp).read()
    red = sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)", out)) | set(re.findall(r"^\s+(invariant_\w+)\(\) \(runs:", out, re.M)))
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out
                                       else "red, unnamed (see the log)" if rc else "none (survived)")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:] or list(MUTANTS):
            run(m)
    else:
        raise SystemExit(__doc__)
