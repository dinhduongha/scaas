# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of group 3h (the PQZ proof path, contract side; plan T58-T61, spec 2026-11-06-pqz-proof-path §11.3). The shape
of runs/2026-11-08-ua-mtx-merge-t66a/mutants.py: one mutant per run on a clean tree (a second, detached work tree at the task's
commit), the source edit applied, the named test file run through `scripts/capped` (sparse: that file and its imports, out/mutants),
the file restored in the same process (finally), then `git diff --quiet --exit-code -- <file>` must hold. Killed = the run fails
(rc != 0) with a test red. Ids are the spec's (M1 ...); a mutant the spec names that is equivalent on the built code says so.

Usage (from smartcontracts/evm): python3 runs/2026-11-08-ua-mtx-merge-3h/mutants.py list | run <id> [<id> ...]
Full output: runs/2026-11-08-ua-mtx-merge-3h-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-08-ua-mtx-merge-3h/mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
CORE = "src/pqz/PqzCore.sol"
STATE = "src/pqz/PqzStateLib.sol"
REC = "test/pqz/PqzDebitRecord.t.sol"

# id: (file, old, new, test file)
MUTANTS = {
    # ---- T58: the debit record (spec §2)
    "M1-debit-delete-loop": (CORE, "        (a.rolled, a.floor, a.cleared) = (p, p, p);\n",
                             "        (a.rolled, a.floor) = (p, p);\n        for (uint64 i = a.cleared; i < p; ++i) delete a.pending[i];\n"
                             "        a.cleared = p;\n", REC),
    "M2-rollover-delete-loop": (STATE, "        if (end > a.cleared) {\n            a.cleared = end;\n",
                                "        if (end > a.cleared) {\n            for (uint64 i = a.cleared; i < end; ++i) delete a.pending[i];\n"
                                "            a.cleared = end;\n", REC),
    "M3-record-p-off-by-one": (CORE, "| uint256(o.p) << 32 |", "| uint256(o.p + 1) << 32 |", REC),
    "M4-prevBlob-new-blob": (CORE, "        _record(s, a, o);\n        (a.accBlob, a.accU, a.accV, a.accUnits, a.flags) = (ptr, uint16(uOff), uint16(vOff), 1, a.flags & ~MAT);\n",
                             "        (a.accBlob, a.accU, a.accV, a.accUnits, a.flags) = (ptr, uint16(uOff), uint16(vOff), 1, a.flags & ~MAT);\n        _record(s, a, o);\n", REC),
    "M5-w1-not-for-keyVersion": (CORE, "bool wide = o.shieldIn != 0 || o.kv != 0 || (last != 0", "bool wide = o.shieldIn != 0 || (last != 0", REC),
    "M6-record-bit-dropped": (CORE, "| (wide ? RECORD | WIDE : RECORD);", "| (wide ? WIDE : 0);", REC),
    "M17-rollover-floor-unconditional": (STATE, "        if (end > a.cleared) {\n            a.cleared = end;\n            if (end > a.floor) a.floor = end;\n",
                                         "        a.floor = end;\n        if (end > a.cleared) {\n            a.cleared = end;\n", REC),
    "M18-w1-not-for-shieldIn": (CORE, "bool wide = o.shieldIn != 0 || o.kv != 0 ||", "bool wide = o.kv != 0 ||", REC),
    "M21-deltaP-from-floor": (CORE, "uint64 pPrev = last == 0 ? 0 : uint64(rec[last - 1].w0 >> 32);", "uint64 pPrev = a.floor;", REC),
}


def red_tests(log):
    return sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)))


def run(mid):
    path, old, new, test = MUTANTS[mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(EVM, "runs", f"2026-11-08-ua-mtx-merge-3h-mut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        env = {**os.environ, "FOUNDRY_SPARSE_MODE": "true", "FOUNDRY_OUT": "out/mutants", "FOUNDRY_CACHE_PATH": "cache/mutants"}
        cmd = [CAPPED, FORGE, "test", "-j", "2", "--match-path", test]
        with open(logp, "w") as log:
            rc = subprocess.call(cmd, cwd=EVM, env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=EVM) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none")
    line = f"{mid} | {note} | {rc}"
    print(line)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:]:
            run(m)
    else:
        raise SystemExit(__doc__)
