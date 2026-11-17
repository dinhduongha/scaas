# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Node mutants of group 3h T63 (plan T63 Step 5; spec 2026-11-06-pqz-proof-path §10): one mutant per run on a clean scaas-node
tree, the source edit applied, `cargo test --lib -- <filters>` through `scripts/capped`, the file restored in the same process
(finally), then `git diff --quiet --exit-code -- <file>` must hold. Killed = the run fails with a test red.

Usage (from smartcontracts/evm): python3 runs/2026-11-08-ua-mtx-merge-3h/node-mutants.py list | run <id> [<id> ...]
Full output: runs/2026-11-08-ua-mtx-merge-3h-nodemut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-08-ua-mtx-merge-3h/mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
NODE = os.path.join(EVM, "..", "..", "scaas-node")
CAPPED = os.path.join(NODE, "..", "scripts", "capped")
FILTERS = ["pqz_own_tag", "pqz_old_shape", "proof_store_", "indexer_proof_store", "typed_ops_kat_every_entry",
           "guard_allows_every_named_entry_only", "allow_lists_equal_the_selector_audit"]

# id: (file, old, new)
MUTANTS = {
    "N1-router-row-missing-node-side": ("src/typed.rs",
        '    ("UASetProofStore", "mtxSetProofStore", GR, "bytes32 from,address target,uint8 next,E", ""),\n', ""),
    "N2-own-tag-defaulted-zero": ("src/submit.rs",
        "    let p = Op::parse(op, fee_recipient)?;\n    let ua = p.row.ua();\n",
        "    let mut op = op.clone();\n"
        "    if let Some(a) = op[\"args\"][\"args\"].as_object_mut() { a.entry(\"ownTag\").or_insert(serde_json::json!(format!(\"{:#x}\", alloy::primitives::B256::ZERO))); }\n"
        "    let p = Op::parse(&op, fee_recipient)?;\n    let ua = p.row.ua();\n"),
    "N3-lane-check-ignores-proofStore": ("src/submit.rs",
        "            Err(SimError::Revert(reason)) if guard::over_cap(&reason) && crate::pqz::is_debit(&w) => {\n",
        "            Err(SimError::Revert(reason)) if guard::over_cap(&reason) && crate::pqz::is_debit(&w) && false => {\n"),
}


def run(mid):
    path, old, new = MUTANTS[mid]
    full = os.path.join(NODE, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(EVM, "runs", f"2026-11-08-ua-mtx-merge-3h-nodemut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, "cargo", "test", "--lib", "--", *FILTERS], cwd=NODE, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=NODE) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = sorted(set(m.split("::")[-1] for m in re.findall(r"^test (\S+) \.\.\. FAILED", out, re.M)))
    note = ", ".join(red) if red else ("compile error" if "could not compile" in out else "none")
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
