# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqVault plan R1 step 4 (`requirePortableApp`, CTR-UA-46): one mutant per run, the source edit applied, test/ua compiled into
its own out/ and cache/ through `scripts/capped`, the file restored byte-equal in the same process (finally). Killed = forge
fails (rc != 0) with a test red. In the shape of runs/2026-11-10-ua-mtx-merge-3c/mutants.py.

Usage (from smartcontracts/evm): python3 runs/2026-11-17-pqvault/mutants-r1.py list | run <id> [<id> ...] | all
Full output: runs/2026-11-17-pqvault/r1/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` on stdout, copied into
runs/2026-11-17-pqvault-summary.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
L = "src/ua/UARegistryCoreLib.sol"
APP = "UARegistryPortableApp.t.sol"

# id: (file, old, new, match-path glob under test/ua)
MUTANTS = {
    "entry-closed-list": (L, "        if (appId == 0) revert IUARegistry.UAUnauthorized(ua);\n",
                          "        if (appId == 0) revert IUARegistry.UAUnauthorized(ua);\n        _portablePurpose(ua, UAKinds.appPurpose(appId));\n", APP),
    "appid-zero-dropped": (L, "        if (appId == 0) revert IUARegistry.UAUnauthorized(ua);\n", "", APP),
    "purpose-without-ns": (L, "        _portable(ua, UAKinds.appPurpose(appId), typedDigest, auth);", "        _portable(ua, appId, typedDigest, auth);", APP),
    "requireportable-open": (L, "        _portablePurpose(ua, purposeTag);\n        _portable(ua, purposeTag, typedDigest, auth);",
                             "        _portable(ua, purposeTag, typedDigest, auth);", APP),
    "portable-classical-shortcut": (L, "            ok = auth.keyData.length == 0 && auth.signature.length == 0\n                && _msig(",
                                    "            ok = auth.keyData.length == 0 && auth.signature.length == 0 && (!_pqEligible(UAStore.msig(ua, r.keyPtr), false) && auth.members.length == 0 ||\n                _msig(", APP),
    "sigok-guard-dropped": (L, "    ) internal view returns (bool) {\n        _portablePurpose(ua, purpose);\n        if (kind == UAKinds.MSIG) {",
                            "    ) internal view returns (bool) {\n        if (kind == UAKinds.MSIG) {", "UARegistryUA8.t.sol"),
}
# `portable-classical-shortcut` closes its parenthesis: the line after `_msig(` ends `auth.members);`, made `auth.members));`
CLOSE = ("UAStore.msig(ua, r.keyPtr), auth.members);\n        }\n        // No UAKeyNotCached",
         "UAStore.msig(ua, r.keyPtr), auth.members));\n        }\n        // No UAKeyNotCached")


def red_tests(log):
    return sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)))


def run(mid):
    path, old, new, match = MUTANTS[mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    mutated = src.replace(old, new)
    if mid == "portable-classical-shortcut":
        assert mutated.count(CLOSE[0]) == 1
        mutated = mutated.replace(*CLOSE)
    os.makedirs(os.path.join(HERE, "r1"), exist_ok=True)
    logp = os.path.join(HERE, "r1", f"mut-{mid}.log")
    try:
        open(full, "w").write(mutated)
        env = {**os.environ, "FOUNDRY_TEST": "test/ua", "FOUNDRY_SCRIPT": "test/ua", "FOUNDRY_OUT": "out/mutants-pv",
               "FOUNDRY_CACHE_PATH": "cache/mutants-pv"}
        cmd = [CAPPED, FORGE, "test", "-j", "1", "--match-path", f"test/ua/{match}"]
        with open(logp, "w") as log:
            rc = subprocess.call(cmd, cwd=EVM, env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if open(full).read() != src:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none")
    print(f"{mid} | {note} | {rc}", flush=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:]:
            run(m)
    elif sys.argv[1:2] == ["all"]:
        for m in MUTANTS:
            run(m)
    else:
        raise SystemExit(__doc__)
