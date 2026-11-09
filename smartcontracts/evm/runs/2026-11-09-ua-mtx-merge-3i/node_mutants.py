# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Group 3i T79 (spec 2026-11-09-service-pull §11 "Node tests": one mutant of the guard rule, and more): the node's service
rule with one part removed at a time, on a clean tree, as `mutants.py` does for the reference service: the edit applied to
scaas-node/src, `cargo test --lib service` through `scripts/capped` (the tests named for the service kind), the file restored
in the same process and checked with `git diff --quiet`. M0 is the red-first run (the shape and the entry equality gutted: the
rule before its implementation).

Usage (from the repository root): python3 smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-3i/node_mutants.py list | run [<id> ...]
Full output: scaas-node/runs/2026-11-09-ua-mtx-merge-3i-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
node_mutants.txt here.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
NODE = os.path.join(ROOT, "scaas-node")
CAPPED = os.path.join(ROOT, "scripts", "capped")

SHAPE3 = "    if d.t.entryRef != r {\n"
MUTANTS = {
    "M0-red-first-no-shape-no-equality": [
        ("src/service.rs", "    let s = svc.address;\n    let refuse = |code: u8, why: &str| Err(format!(\"SERVICE_PULL_SHAPE: {code}: {why}\"));\n",
         "    let s = svc.address;\n    if s == s { return Ok(d.entry.token.unwrap_or_default()); }\n"
         "    let refuse = |code: u8, why: &str| Err(format!(\"SERVICE_PULL_SHAPE: {code}: {why}\"));\n"),
        ("src/service.rs", "    let mut out = vec![];\n    for (i, (sel, ty)) in sels.iter().zip(types).enumerate() {\n",
         "    if s == s { return Ok(cfg.iter().zip(tokens).map(|(e, t)| Entry { token: Some(*t), ..e.clone() }).collect()); }\n"
         "    let mut out = vec![];\n    for (i, (sel, ty)) in sels.iter().zip(types).enumerate() {\n")],
    "M1-guard-another-kind-on-a-service": [("src/guard.rs", "        if self.is_service(w.to) {\n", "        if false {\n")],
    "M2-relay-inner-service-rule-dropped": [("src/guard.rs", "            if self.is_service(target) {\n", "            if false {\n")],
    "M3-shape-check3-dropped": [("src/service.rs", SHAPE3, "    if false {\n")],
    "M4-entries-one-direction-only": [
        ("src/service.rs", "    if let Some(e) = cfg.iter().find(|e| !out.iter().any(|o| o.selector == e.selector)) {\n",
         "    if let Some(e) = cfg.iter().find(|_| false) {\n")],
    "M5-fee-nonce-dropped": [("src/service.rs", "        && word(nonce) != pn.checked_add(U256::from(1))\n", "        && false\n")],
    "M6-op-bytes-bound-dropped": [("src/service.rs", "        if len > types.max_op_bytes {\n", "        if false {\n")],
    "M7-pull-token-from-the-job": [("src/guard.rs", "        if job_token.is_some_and(|j| j != pull) {\n", "        if false {\n")],
}


def run(mid):
    edits = MUTANTS[mid]
    files = sorted({p for p, _, _ in edits})
    orig = {p: open(os.path.join(NODE, p)).read() for p in files}
    mut = dict(orig)
    for p, old, new in edits:
        if mut[p].count(old) != 1:
            raise SystemExit(f"{mid}: the mutated text occurs {mut[p].count(old)} times in {p}")
        mut[p] = mut[p].replace(old, new)
    logp = os.path.join(NODE, "runs", f"2026-11-09-ua-mtx-merge-3i-mut-{mid}.log")
    os.makedirs(os.path.dirname(logp), exist_ok=True)
    try:
        for p in files:
            open(os.path.join(NODE, p), "w").write(mut[p])
        env = {**os.environ, "CARGO_BUILD_JOBS": "2"}
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, "cargo", "test", "-j2", "--lib", "service"], cwd=NODE, env=env, stdout=log,
                                 stderr=subprocess.STDOUT)
    finally:
        for p in files:
            open(os.path.join(NODE, p), "w").write(orig[p])
    for p in files:
        if open(os.path.join(NODE, p)).read() != orig[p]:
            raise SystemExit(f"{mid}: {p} not restored")
    out = open(logp).read()
    red = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", out, re.M)))
    note = ", ".join(red) if red else ("compile error" if "error[" in out else "red, unnamed (see the log)" if rc else "none (survived)")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(HERE, "node_mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:] or list(MUTANTS):
            run(m)
    else:
        raise SystemExit(__doc__)
