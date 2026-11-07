# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of group 3g (pqz-key-versions spec §14; plan T51-T56). One mutant per run, on a clean tree: the source
edit is applied, the named tests run through `scripts/capped`, the file is restored in the same process (finally), then
`git diff --exit-code -- src` must hold. A mutant is killed when the run fails (rc != 0) and a test went red.

Usage (from smartcontracts/evm): python3 runs/2026-11-07-ua-mtx-merge-pqzver/mutants.py list
                                 python3 runs/2026-11-07-ua-mtx-merge-pqzver/mutants.py run <id> [<id> ...]
Full output: runs/<date>-ua-mtx-merge-<task>-mut-<id>.log (git-ignored); the line `mutant | test that went red | rc` is
appended to runs/2026-11-07-ua-mtx-merge-<task>-mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
DATE = "2026-11-07"

LIB = "src/ua/UARegistryLib.sol"
T51 = "test/ua/PqzKeyVersions.t.sol"
CORE = "src/pqz/PqzCore.sol"
T52 = "test/pqz/PqzKeyVersionsToken.t.sol"

# id: (task, file, old, new, --match-path glob)
MUTANTS = {
    # ---- T51: the registry (M-R1 ... M-R7)
    "m-r1-version-left-out": ("t51", LIB, "UAKinds.pqzKeyVersionDigest(ua, version, h))",
                              "UAKinds.pqzKeyVersionDigest(ua, 1, h))", T51),
    "m-r1-popv2-for-v1": ("t51", LIB,
                          "UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyVersionDigest(ua, version, h))",
                          "UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, UAKinds.pqzKeyVersionDigest(ua, version, h))",
                          T51),
    "m-r2-sequence-gte": ("t51", LIB, "} else if (!has0 || version != latest + 1) {", "} else if (!has0 || version <= latest) {",
                          T51),
    "m-r2-host-own-latest": ("t51", LIB, "            if (l1 > latest) latest = l1;\n", "", T51),
    "m-r3-current-latest": ("t51", LIB, "        vs.current = v;\n", "        vs.current = vs.latest;\n", T51),
    "m-r3-late-proof-lowers": ("t51", LIB, "        if (v < vs.current) return;\n", "", T51),
    "m-r3-current-at-setpqzkey": ("t51", LIB, "        s.pqzVersions[ua].latest = version;\n",
                                  "        s.pqzVersions[ua].latest = version;\n        s.pqzVersions[ua].current = version;\n", T51),
    "m-r4-marker-skipped": ("t51", LIB, "if (s.pqzKeyUsed[ua][h] || (host && IUARegistry(_pred()).pqzKeyUsed(ua, h)))",
                            "if (false)", T51),
    "m-r4-marker-not-on-predecessor": ("t51", LIB,
                                       "if (s.pqzKeyUsed[ua][h] || (host && IUARegistry(_pred()).pqzKeyUsed(ua, h)))",
                                       "if (s.pqzKeyUsed[ua][h])", T51),
    "m-r4-keyowner-v0-only": ("t51", LIB, "        if (owner != 0) revert IUARegistry.UAKeyInUse(h, owner);\n        s.keyOwner[h] = ua;",
                              "        if (owner != 0 && v == 0) revert IUARegistry.UAKeyInUse(h, owner);\n        s.keyOwner[h] = ua;",
                              T51),
    "m-r5-list-per-version": ("t51", LIB, "        if (!vs.listed) {", "        if (true) {", T51),
    "m-r6-length-ignored": ("t51", LIB, "if (proven || pqzKey.length == PqzSet.PK) _pqzCurrent(ua, v);", "_pqzCurrent(ua, v);",
                            T51),
    "m-r6-bytes-ignored": ("t51", LIB, "        s.pqzVersions[ua].latest = version;\n",
                           "        s.pqzVersions[ua].latest = version;\n"
                           "        if (uint160(_cfgPqz()) == 0 && pqzKey.length == PqzSet.PK) s.pqzVersions[ua].current = version;\n",
                           T51),
    "m-r7-replacement-kept": ("t51", LIB, "            if (has0) revert IUARegistry.UAPqzKeySet(ua);",
                              "            if (has0 && false) revert IUARegistry.UAPqzKeySet(ua);", T51),

    # ---- T52: the token (M-T1 ... M-T10; M-T6's ATTESTED-token kill is T44's) and T53 (M-T7)
    "m-t1-credit-to-latest": ("t52", CORE, "        (v, ptr,, proven) = IUARegistry(registry).pqzKeyOf(ua); // KV-7: the key and its version, one read\n",
                              "        (v, ptr,, proven) = IUARegistry(registry).pqzKeyOf(ua); // KV-7: the key and its version, one read\n"
                              "        v = IUARegistry(registry).pqzKeyLatest(ua);\n", T52),
    "m-t1-migration-to-keyversion": ("t52", CORE, "_credit(o.to, o.verT, ptr, 16, 16 + PqzCt.PKP, ref);",
                                     "_credit(o.to, o.from == o.to ? o.kv : o.verT, ptr, 16, 16 + PqzCt.PKP, ref);", T52),
    "m-t2-counter-per-version": ("t52", CORE, "        o.sendCounter = s.sendCounter[o.from];\n",
                                 "        o.sendCounter = o.kv == 0 ? s.sendCounter[o.from] : 0;\n", T52),
    "m-t3-credit-read-twice": ("t52", CORE, "        _credit(o.to, o.verT, ptr, 16, 16 + PqzCt.PKP, ref);",
                               "        { (uint64 vv,,,) = IUARegistry(o.registry).pqzKeyOf(o.to); _credit(o.to, vv, ptr, 16, 16 + PqzCt.PKP, ref); }",
                               T52),
    "m-t4-selftransfer-dropped": ("t52", CORE, "            if (o.kv == o.cur) revert IPqzToken.SelfTransfer();\n", "", T52),
    "m-t4-selftransfer-kept-for-migration": ("t52", CORE, "            if (o.kv == o.cur) revert IPqzToken.SelfTransfer();",
                                             "            revert IPqzToken.SelfTransfer();", T52),
    "m-t5-pkf-from-current": ("t52", CORE,
                              "        if (o.kv != o.cur) (ptr,, proven) = IUARegistry(registry).pqzKeyAt(o.from, o.kv);\n", "", T52),
    "m-t6-pairwise-dropped-op1": ("t52", CORE, "        if (o.auditorOn == 1) o.keyA = _keyPtr(e.registry, $().auditorUA);\n        _distinct(o);",
                                  "        if (o.auditorOn == 1) o.keyA = _keyPtr(e.registry, $().auditorUA);", T52),
    "m-t6-pairwise-dropped-op7": ("t52", CORE, "        if (o.auditorOn == 1) o.keyA = _keyPtr(e.registry, s.auditorUA);\n        _distinct(o);",
                                  "        if (o.auditorOn == 1) o.keyA = _keyPtr(e.registry, s.auditorUA);", T52),
    "m-t6-pkf-only": ("t52", CORE, "            for (uint256 k; k < i; ++k) {\n                if (h[k] == h[i]) {",
                      "            for (uint256 k; k < 1; ++k) {\n                if (h[k] == h[i]) {", T52),
    "m-t8-credited-without-version": ("t52", CORE, "emit IPqzToken.Credited(ua, i, v, ref);", "emit IPqzToken.Credited(ua, i, 0, ref);", T52),
    "m-t8-debited-without-version": ("t52", CORE, "emit IPqzToken.Debited(o.from, o.kv, p, p, ptr);",
                                     "emit IPqzToken.Debited(o.from, 0, p, p, ptr);", T52),
    "m-t9-stale-rule-dropped": ("t52", CORE, "        } else if (o.kv != o.cur) {\n            revert IPqzToken.StaleKeyVersion(o.from, o.kv, o.cur);\n        }",
                                "        }", T52),
    "m-t10-rollover-static-68": ("t52", "src/pqz/PqzLayer.sol", "sel == IPqzToken.mtxPrepareAcc.selector) ? 100 : 0);",
                                 "sel == IPqzToken.mtxPrepareAcc.selector) ? 68 : 0);", "test/pqz/PqzTyped.t.sol"),
    "m-t7-disclosure-current-key": ("t53", CORE, "        _key(buf, 288, _discKey(e.registry, owner, keyVersion));",
                                    "        _key(buf, 288, _keyPtr(e.registry, owner));", "test/pqz/PqzKeyVersionsDisclosure.t.sol"),
}


def red_tests(log):
    forge = re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log) + re.findall(r"\[FAIL[^\]]*\] (invariant_\w+)$", log, re.M)
    node = re.findall(r"^\u2716 (.+?) \(\d", log, re.M)  # node --test: "✖ <name> (<ms>)"
    node += re.findall(r"^test (\S+) \.\.\. FAILED$", log, re.M)  # cargo test
    return sorted(set(forge) | set(n for n in node if n != "failing tests:"))


def run(mid):
    task, path, old, new, match = MUTANTS[mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(EVM, "runs", f"{DATE}-ua-mtx-merge-{task}-mut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        with open(logp, "w") as log:
            if match.startswith("cargo:"):
                rc = subprocess.call([CAPPED, "cargo", "test", "--lib", match[6:]], cwd=os.path.join(EVM, "../../scaas-node"),
                                     env={**os.environ, "CAPPED_MEM": "6G"}, stdout=log, stderr=subprocess.STDOUT)
            elif match.startswith("node:"):
                rc = subprocess.call(["node", "--test", *match[5:].split()], cwd=os.path.join(EVM, "../../clients/clientkeys"),
                                     stdout=log, stderr=subprocess.STDOUT)
            else:
                # only the test directory of the match is compiled, into its own out/ and cache/ (the tree's stay as they are)
                d = match.split("/")[0] + "/" + match.split("/")[1] if match.count("/") > 1 else "test"
                env = {**os.environ, "FOUNDRY_TEST": d, "FOUNDRY_OUT": "out/mutants", "FOUNDRY_CACHE_PATH": "cache/mutants"}
                rc = subprocess.call([CAPPED, FORGE, "test", "--match-path", match], cwd=EVM, env=env, stdout=log,
                                     stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    # on an uncommitted task (MUTANTS_UNCOMMITTED=1) the file must equal what it held before the run; else git's HEAD
    clean = (open(full).read() != src) if os.environ.get("MUTANTS_UNCOMMITTED") == "1" \
        else subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=EVM)
    if clean != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none")
    line = f"{mid} | {note} | {rc}"
    print(line)
    with open(os.path.join(EVM, "runs", f"{DATE}-ua-mtx-merge-{task}-mutants.txt"), "a") as f:
        f.write(line + "\n")
    return rc


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "list":
        for k, v in MUTANTS.items():
            print(v[0], k)
    elif sys.argv[1] == "run":
        for mid in sys.argv[2:]:
            run(mid)
