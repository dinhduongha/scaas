# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-liquidity L8c (spec 2026-11-10-dex-liquidity.md §14, "Node mutants"): M-N1..M-N6, and L6d's M-N7..M-N14 (one per
pre-check it added), one at a time, each edit applied to its scaas-node/src file, the node tests through `scripts/capped`
(cargo test --lib on the liquidity, allow-list and KAT tests; most also the RPC-level e2e `liquidity_pre_checks_on_a_chain` on
anvil), the file restored in the same process and
checked byte-equal (sha256) to its content before the run. Each must turn a named test red while the original stays green.
Stops before a launch while another capped job runs (no waiting here): rerun with the ids left.

Usage (from smartcontracts/evm): python3 runs/2026-11-10-ua-mtx-liquidity/node_mutants.py list | run [<id> ...]
Full output: runs/2026-11-10-ua-mtx-liquidity/node-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-10-ua-mtx-liquidity/node-mutants.txt.
"""
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NODE = os.path.join(os.path.dirname(os.path.dirname(HERE)), "..", "..", "scaas-node")
CAPPED = os.path.join(NODE, "..", "scripts", "capped")
G = "src/guard.rs"
T = "src/typed.rs"
S = "src/submit.rs"
LIB = ["cargo", "test", "--lib", "--", "liquidity", "allow_lists", "typed_ops_kat"]
E2E = ["cargo", "test", "--test", "e2e", "--", "--ignored", "liquidity_pre_checks_on_a_chain"]

# (file, old, new, occurrences), the commands
MUTANTS = {
    "control": ([], [LIB, E2E]),  # the original, green
    # signed -> ours: the node drops an entry the DEX signs (no row, no NOT_ROWS reason)
    "M-N1": ([(T, '    ("mtxLiquidity", D, "LiquidityPlan p,Interaction[] interactions"),\n', "", 1)], [LIB]),
    # ours -> signed: the node rows `mtxLiquidity` on the token kinds too, which sign no such entry
    "M-N2": ([(T, '("mtxLiquidity", D, ', '("mtxLiquidity", &["dex", "token"], ', 1)], [LIB]),
    "M-N3": ([(T, 'if el == "LiquidityToken" && a.len() > LIQUIDITY_MAX {', "if false {", 1)], [LIB]),
    "M-N4": ([(T, 'Val::Int(alloy::primitives::I256::try_from(n).expect("64 bits"), bits as usize)',
               'Val::Int(alloy::primitives::I256::try_from(if bits < 64 { n & ((1i64 << bits) - 1) } else { n }).expect("64 bits"), '
               "bits as usize)", 1)], [LIB]),
    "M-N5": ([(G, "    groups.contains(&GROUP_LIQUIDITY)\n", "    let _ = groups;\n    true\n", 1)], [LIB, E2E]),
    "M-N6": ([(G, "        if !ok {\n            return Err(policy(format!(\"LIQUIDITY_TOKEN_UNSUPPORTED",
               "        if false {\n            return Err(policy(format!(\"LIQUIDITY_TOKEN_UNSUPPORTED", 1)], [LIB, E2E]),
    # L6d: one per added pre-check
    "M-N7": ([(G, "    if o.relayer != Address::ZERO && o.relayer != chain.address() {", "    if false {", 1)], [LIB, E2E]),
    "M-N8": ([(G, "        Ok(d) if d == h => {}", "        Ok(_) => {}", 1)], [LIB, E2E]),
    "M-N9": ([(G, "        if !typed::recovers(h, &a.signature, who) {", "        if false {", 1)], [LIB, E2E]),
    "M-N10": ([(G, "        Ok(n) if n.is_zero() => {}", "        Ok(_) => {}", 1)], [LIB, E2E]),
    "M-N11": ([(S, "            Err(Refusal::Policy(reason)) if reason.starts_with(guard::LIQUIDITY_ORDER_CLOSED) => {",
                "            Err(Refusal::Policy(reason)) if false && reason.starts_with(guard::LIQUIDITY_ORDER_CLOSED) => {", 1)],
              [LIB, E2E]),
    "M-N12": ([(T, '.chain(nested("payment", 6)).chain(plan).min();', '.chain(nested("payment", 6)).min();', 1)], [LIB, E2E]),
    "M-N13": ([(G, "kind, max_gas_per_tx.min(block.limit)) {", "kind, block.limit.min(MAX_TX_GAS)) {", 1)], [LIB, E2E]),
    "M-N14": ([(G, "        0x0101 | 0x0100 | 0x0103 | 0x0108 | 0 => 50_000,", "        0x0101 | 0x0100 | 0x0103 | 0 => 50_000,", 1)],
              [LIB]),
}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def others():
    out = subprocess.run(["pgrep", "-af", "scripts/capped"], capture_output=True, text=True).stdout.splitlines()
    return [l for l in out if "pgrep" not in l and "bash -c source" not in l]  # not an agent's own shell line


def run(mid):
    edits, cmds = MUTANTS[mid]
    files = sorted({f for f, *_ in edits})
    orig = {f: open(os.path.join(NODE, f), "rb").read() for f in files}
    before = {f: sha(orig[f]) for f in files}
    mut = dict(orig)
    for f, old, new, n in edits:
        if mut[f].count(old.encode()) != n:
            raise SystemExit(f"{mid}: the mutated text occurs {mut[f].count(old.encode())} times in {f}, not {n}")
        mut[f] = mut[f].replace(old.encode(), new.encode())
    logp = os.path.join(HERE, f"node-mut-{mid}.log")
    env = {**os.environ, "CAPPED_SLOTS": "3", "PATH": os.path.expanduser("~/.foundry/bin") + ":" + os.environ["PATH"]}
    rcs = []
    try:
        for f in files:
            open(os.path.join(NODE, f), "wb").write(mut[f])
        with open(logp, "w") as log:
            for c in cmds:
                if others():
                    raise SystemExit(f"{mid}: another capped job runs: {others()}; stopped before launching")
                log.write(f"$ {' '.join(c)}\n")
                log.flush()
                rcs.append(subprocess.call([CAPPED, *c], cwd=NODE, env=env, stdout=log, stderr=subprocess.STDOUT))
    finally:
        for f in files:
            open(os.path.join(NODE, f), "wb").write(orig[f])
    for f in files:
        if sha(open(os.path.join(NODE, f), "rb").read()) != before[f]:
            raise SystemExit(f"{mid}: {f} not restored byte-equal")
    out = open(logp).read()
    red = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", out, re.M)))
    note = ", ".join(red) if red else ("compile error" if "error[E" in out or "could not compile" in out
                                       else "red, unnamed (see the log)" if any(rcs) else "none (survived)")
    line = f"{mid} | {note} | {'/'.join(map(str, rcs))}"
    print(line, flush=True)
    with open(os.path.join(HERE, "node-mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    else:
        for mid in sys.argv[2:] or [m for m in MUTANTS if m != "control"]:
            run(mid)
