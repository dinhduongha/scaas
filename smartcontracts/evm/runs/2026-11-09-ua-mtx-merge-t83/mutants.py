# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T83 (owner 2026-11-09) mutants: one at a time, each edit applied to its src/ file, forge through `scripts/capped`
(sparse, out/mutants-t83) on the pay and record tests, the file restored in the same process and checked byte-equal to its
content before the run (then `git diff --exit-code` when the tree is committed). M1-M7 are the plan's list; M8-M10 extra.
Each must turn a named negative red while the original stays green (the gate's own runs).

Usage (from smartcontracts/evm): python3 runs/2026-11-09-ua-mtx-merge-t83/mutants.py list | run [<id> ...]
Full output: runs/2026-11-09-ua-mtx-merge-t83-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-09-ua-mtx-merge-t83/mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
TESTS = "{test/metatx/PayRecords.t.sol,test/metatx/PayMeta.t.sol,test/as/Tax.t.sol}"
BASE = "src/metatx/MetaTokenBase.sol"
LIB = "src/metatx/MtxPipelineLib.sol"
REG = "src/regulated/RegulatedBase.sol"

PAY = ("        _uaExecuteTransfer(t, 0, auth, 0, 0);\n"
       "        _payRecord(meta, t.to, t.value); // the fee is on top: `to` received `value`\n")
PUSH = "        _payRecords().records[payNo].push(MetaTxLib.PayRecord(to, uint192(amount), uint64(block.number)));\n"
END = "        if (offset >= n) return page;\n"

# id: [(file, old, new, occurrences)]
MUTANTS = {
    "M1-record-before-transfer": [(BASE, PAY, "        _payRecord(meta, t.to, t.value);\n"
                                              "        _uaExecuteTransfer(t, 0, auth, 0, 0);\n", 1)],
    "M2-gross-amount-recorded": [(BASE, "_payRecord(meta, t.to, t.value - fee);", "_payRecord(meta, t.to, t.value);", 1),
                                 (REG, "_payRecord(meta, t.to, t.value - tax);", "_payRecord(meta, t.to, t.value);", 1),
                                 (REG, "_payRecord(meta, to, amount - tax);", "_payRecord(meta, to, amount);", 1)],
    "M3-save-false-recorded": [(BASE, "        if (m.save) MtxPipelineLib.payRecord(", "        MtxPipelineLib.payRecord(", 1)],
    "M4-save-outside-commitment": [(LIB, "keccak256(abi.encode(m.payNo, m.save, m.schema, m.body))",
                                    "keccak256(abi.encode(m.payNo, m.schema, m.body))", 1)],
    "M5-length-not-advanced": [(LIB, PUSH, PUSH.replace(";\n", ";\n        MetaTxLib.PayRecord[] storage q = _payRecords()"
                                                       ".records[payNo];\n        assembly (\"memory-safe\") { sstore(q.slot, "
                                                       "sub(sload(q.slot), 1)) }\n"), 1)],
    "M6-page-past-end-not-empty": [(LIB, END, "        if (offset >= n) {\n            if (n == 0) return page;\n"
                                              "            page = new MetaTxLib.PayRecord[](1);\n"
                                              "            page[0] = r[n - 1];\n            return page;\n        }\n", 1)],
    "M7-v2-tag-kept": [(LIB, '"scaas.pay.meta.v3"', '"scaas.pay.meta.v2"', 1)],
    "M8-save-without-payNo-accepted": [(LIB, " || (m.save && m.payNo == 0)", "", 1)],
    "M9-amount-bound-dropped": [(LIB, "        if (amount > type(uint192).max) revert IMetaTokenV2.PayRecordAmount(amount);\n",
                                 "", 1)],
    "M10-receiver-fee-record-skipped": [(BASE, "        _payRecord(meta, t.to, t.value - fee);", "", 1)],
}


def run(mid):
    edits = MUTANTS[mid]
    files = sorted({f for f, *_ in edits})
    orig = {f: open(os.path.join(EVM, f)).read() for f in files}
    mut = dict(orig)
    for f, old, new, n in edits:
        if mut[f].count(old) != n:
            raise SystemExit(f"{mid}: the mutated text occurs {mut[f].count(old)} times in {f}, not {n}")
        mut[f] = mut[f].replace(old, new)
    logp = os.path.join(EVM, "runs", f"2026-11-09-ua-mtx-merge-t83-mut-{mid}.log")
    try:
        for f in files:
            open(os.path.join(EVM, f), "w").write(mut[f])
        env = {**os.environ, "FOUNDRY_SPARSE_MODE": "true", "FOUNDRY_OUT": "out/mutants-t83",
               "FOUNDRY_CACHE_PATH": "cache/mutants-t83"}
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, FORGE, "test", "-j", "2", "--match-path", TESTS], cwd=EVM, env=env, stdout=log,
                                 stderr=subprocess.STDOUT)
    finally:
        for f in files:
            open(os.path.join(EVM, f), "w").write(orig[f])
    for f in files:
        if open(os.path.join(EVM, f)).read() != orig[f]:
            raise SystemExit(f"{mid}: {f} not restored")
    out = open(logp).read()
    red = sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)", out)))
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
