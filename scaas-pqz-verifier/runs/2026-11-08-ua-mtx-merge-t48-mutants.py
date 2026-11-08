# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T48 mutants (3f spec §15, Service row, plus the statement-rebuild comparison): one at a time on a clean tree, each
applied to src/lib.rs, the whole test suite run through scripts/capped, the file restored in the same run, then
`git diff --exit-code`. Writes `mutant | test that went red | rc` to the -mutants.txt beside this file; full outputs to
git-ignored .log files. Run from scaas-pqz-verifier/: python3 runs/2026-11-08-ua-mtx-merge-t48-mutants.py"""
import re
import subprocess
import sys

SRC = "src/lib.rs"
OUT = "runs/2026-11-08-ua-mtx-merge-t48-mutants.txt"
MUTANTS = [
    ("signing on verdict 0",
     "if self.run(stmt::input(plan.op(), st, &req.proof)).await? != VALID {",
     "if self.run(stmt::input(plan.op(), st, &req.proof)).await? == [7u8; 32] {"),
    ("a key without stored pqzPop bytes given a verdict",
     "        if pop.is_empty() {\n            return Err(",
     "        if pop.is_empty() {\n            return self.remember(ua, version, h);\n        }\n        if false {\n            return Err("),
    ("a cache keyed by ua only",
     "Ok(k.ok.contains(&(ua, version, h)))",
     "Ok(k.ok.iter().any(|x| x.0 == ua))"),
    ("dispatch on the outer proofSystemId (the statement's word 32 unchecked)",
     "if st[32..64] != stmt::PQZL_ID {",
     "if false && st[32..64] != stmt::PQZL_ID {"),
    ("the statement-rebuild comparison skipped",
     "if rebuilt[..] != *st {",
     "if false && rebuilt[..] != *st {"),
]


def main():
    if subprocess.run(["git", "diff", "--quiet", "--exit-code", "--", "."]).returncode:
        sys.exit("the crate is not clean")
    orig = open(SRC).read()
    rows = []
    for i, (name, old, new) in enumerate(MUTANTS, 1):
        assert orig.count(old) == 1, name
        log = f"runs/2026-11-08-ua-mtx-merge-t48-mutant-{i}.log"
        try:
            open(SRC, "w").write(orig.replace(old, new))
            with open(log, "w") as f:
                rc = subprocess.run(["../scripts/capped", "cargo", "test", "--offline", "--locked", "-j2"],
                                    stdout=f, stderr=subprocess.STDOUT).returncode
        finally:
            open(SRC, "w").write(orig)
        clean = subprocess.run(["git", "diff", "--exit-code", "--", "."]).returncode
        assert clean == 0, f"{name}: not restored"
        red = re.findall(r"^test (\S+) \.\.\. FAILED$", open(log).read(), re.M)
        rows.append(f"{name} | {', '.join(red) or 'NONE (survivor)'} | {rc}")
        print(rows[-1], flush=True)
    with open(OUT, "w") as f:
        f.write("mutant | test that went red | rc\n" + "\n".join(rows) + "\n")


main()
