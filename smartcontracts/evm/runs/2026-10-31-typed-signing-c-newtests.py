#!/usr/bin/env python3
"""typed-signing Task CG: the NEW_TESTS lines of Parts C0-C8, R2, N1 (git grep / git show, no checkout).
   python3 -I 2026-10-31-typed-signing-c-newtests.py [BASE]   BASE = the last commit of the P block (default 006c6dfe)
A name is listed when it is a test at HEAD and was not a test of the same group at BASE; a name removed later is not listed.
Groups: forge (smartcontracts/evm/test), cargo-zether-prover, cargo-scaas-node (unit tests; tests/e2e.rs -> node-e2e-anvil),
clientkeys (node:test titles). The ua-* / soroban client trees did not change after P."""
import re, subprocess, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "006c6dfe"

def git(*a):
    return subprocess.run(["git", *a], capture_output=True, text=True, check=True).stdout

def files(rev, prefix, ext):
    return [f for f in git("ls-tree", "-r", "--name-only", rev, "--", prefix).split("\n") if f.endswith(ext) and "/legacy/" not in f]

def forge(txt):
    return set(re.findall(r"function\s+((?:test|invariant)\w*)\s*\(", txt))

def cargo(txt):
    out, armed = set(), False
    for ln in txt.split("\n"):
        s = ln.strip()
        if re.match(r"#\[(tokio::|rstest::)?test\b", s):
            armed = True
        m = re.match(r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)", s)
        if m and armed:
            out.add(m.group(1)); armed = False
        elif m:
            armed = False
    return out

def node(txt):
    return {(a or b).replace("\\'", "'") for a, b in re.findall(r"^\s*test\((?:'((?:[^'\\]|\\.)*)'|`([^`]*)`)", txt, re.M)}

def collect(rev, prefix, ext, fn, skip=()):
    r = {}
    for f in files(rev, prefix, ext):
        if any(x in f for x in skip):
            continue
        r[f] = fn(git("show", f"{rev}:{f}"))
    return r

def new(prefix, ext, fn, skip=()):
    old = set().union(*collect(BASE, prefix, ext, fn, skip).values())
    cur = collect("HEAD", prefix, ext, fn, skip)
    return {f: sorted(n for n in v if n not in old) for f, v in cur.items() if any(n not in old for n in v)}

out = []
for f, ns in sorted(new("smartcontracts/evm/test", ".sol", forge).items()):
    out += [f"forge|forge|{n}" for n in ns]
for f, ns in sorted(new("clients/zether-prover", ".rs", cargo, ("/target/",)).items()):
    out += [f"cargo-zether-prover|cargo|{n}" for n in ns]
for f, ns in sorted(new("scaas-node", ".rs", cargo, ("/target/",)).items()):
    step = "node-e2e-anvil" if f.startswith("scaas-node/tests/e2e.rs") else "cargo-scaas-node"
    out += [f"{step}|cargo|{n}" for n in ns]
for f, ns in sorted(new("clients/clientkeys/test", ".js", node).items()):
    out += [f"clientkeys|node|{n}" for n in ns]
print("\n".join(out))
