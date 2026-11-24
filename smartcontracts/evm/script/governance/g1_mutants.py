# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""G1 (CTR-GOV-33, owner 2026-11-24): each new check of the router's per-target registry, mutated alone on a clean tree, then
`forge test` of `test/governance/RouterPerRelease.t.sol` through `scripts/capped`; the file restored byte-equal after each
(scripts/mutant_guard.py, ARCH-POS-23). One line per mutant: `mutant | red tests | rc` (rc 1 = killed). Full output in
git-ignored `.log` files under `<runs>/mutants/`.

usage (from smartcontracts/evm): python3 script/governance/g1_mutants.py <runs dir> [name ...]   UNAUDITED tooling."""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", "scripts"))
import mutant_guard as guard  # noqa: E402

RB = "src/governance/GovernanceRouterBase.sol"
T = "test/governance/RouterPerRelease.t.sol"

# (name, old, new): every mutant in RB
M = [
    # the router before G1: one registry for every target (the red-first evidence of the G1 expectations)
    (
        "registry-switch-removed",
        "address r = UAKinds.inNativeSpace(e.from) ? c.registry : registryFor(target);",
        "address r = c.registry;",
    ),
    # the target's code believed without the factory's index
    ("factory-check-removed", "        if (IOpenFactory(f).infoOf(target).addr != target) return own;\n", ""),
    # the foreign registry's nonces in the one map keyed by id only
    (
        "nonce-key-without-registry",
        "mapping(uint256 => uint256) storage lane = _routerNonces().nonce[c.registry][e.from];",
        "mapping(uint256 => uint256) storage lane = MtxPipelineLib._mtxStorage().nonce[e.from];",
    ),
    # G1' (rejected by the owner): every factory-made target on one registrar-set "newest" generation
    (
        "g1-prime-pointer",
        "address r = _cloneRegistry(target);",
        "address r = _cloneRegistry(target) == address(0) ? address(0) : 0x5cA0000000000000000000000000000000000008;",
    ),
]

FORGE = os.path.expanduser("~/.foundry/bin/forge")


def run(runs, name, old, new):
    src = open(RB).read()
    guard.refuse_dirty([RB], ".")
    assert src.count(old) == 1, name
    log = os.path.join(runs, "mutants", f"{name}.log")
    env = dict(os.environ, FOUNDRY_TEST="test/governance")
    cmd = ["../../scripts/capped", FORGE, "test", "--match-path", T]
    lim = guard.limit(cmd, env=env)
    saved = {RB: open(RB, "rb").read()}
    try:
        open(RB, "w").write(src.replace(old, new))
        with open(log, "w") as out:
            r = guard.run(cmd, lim, stdout=out, stderr=subprocess.STDOUT, env=env)
    finally:
        guard.restore(saved)
    if r.timeout:
        return r.returncode, [guard.outcome(r, "")]
    text = open(log).read()
    red = sorted(set(re.findall(r"^\[FAIL.*\] (\w+)\(", text, re.M)))
    if "Compiler run failed" in text:
        red = ["(compile error)"]
    return r.returncode, red


def main():
    runs = sys.argv[1]
    os.makedirs(os.path.join(runs, "mutants"), exist_ok=True)
    only = set(sys.argv[2:])
    out = os.path.join(runs, "mutants.txt")
    done = set()
    if os.path.exists(out):
        done = {line.split(" | ")[0] for line in open(out) if " | " in line and not line.startswith("mutant")}
    with open(out, "a") as o:
        if not done:
            o.write("mutant | red tests | rc\n")
        for name, old, new in M:
            if (only and name not in only) or name in done:
                continue
            rc, red = run(runs, name, old, new)
            line = f"{name} | {', '.join(red) or '-'} | {rc}\n"
            o.write(line)
            o.flush()
            print(line, end="", flush=True)


if __name__ == "__main__":
    main()
