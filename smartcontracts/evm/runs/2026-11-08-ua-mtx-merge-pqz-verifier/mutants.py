# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of group 3f (PQZ verifier mode spec §15; plan T44-T49). One mutant per run, on a clean tree: the source
edit is applied, the named tests run through `scripts/capped`, the file is restored in the same process (finally), then
`git diff --exit-code -- <file>` must hold. A mutant is killed when the run fails (rc != 0) and a test went red.

Usage (from smartcontracts/evm): python3 runs/2026-11-08-ua-mtx-merge-pqz-verifier/mutants.py list
                                 python3 runs/2026-11-08-ua-mtx-merge-pqz-verifier/mutants.py run <id> [<id> ...]
Full output: runs/<date>-ua-mtx-merge-<task>-mut-<id>.log (git-ignored); the line `mutant | test that went red | rc` is
appended to runs/2026-11-08-ua-mtx-merge-<task>-mutants.txt. The node and service rows are T47's and T48's (their own
harness files in scaas-node/runs and scaas-pqz-verifier/runs).
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
DATE = "2026-11-08"

CORE = "src/pqz/PqzCore.sol"
STATE = "src/pqz/PqzStateLib.sol"
LAYER = "src/pqz/PqzLayer.sol"
T_CORE = "test/pqz/PqzOffchainCore.t.sol"
T_VER = "test/pqz/PqzVerifier.t.sol"
T_ENT = "test/pqz/PqzOffchainEntries.t.sol"
T_INV = "test/pqz/invariant/PqzVerdictInvariants.t.sol"

# id: (task, file, old, new, --match-path glob)
MUTANTS = {
    # ---- Binding (spec §15): each field of the verdict unchecked, the statement hashed with its prefix
    "b1-token-unchecked": ("t44", CORE, "        if (pv.token != address(this)) return 16;\n", "", T_CORE),
    "b2-chainid-unchecked": ("t44", CORE, "        if (pv.chainId != block.chainid) return 17;\n", "", T_CORE),
    "b3-psid-unchecked": ("t44", CORE, "        if (pv.proofSystemId != s.psid) return 18;\n", "", T_CORE),
    "b4-proofhash-unchecked": ("t44", CORE, "        if (pv.proofHash != ph) return 20;\n", "", T_CORE),
    "b5-statement-with-prefix": ("t44", CORE, "assembly (\"memory-safe\") { sh := keccak256(add(buf, 37), len) }",
                                 "assembly (\"memory-safe\") { sh := keccak256(add(buf, 32), add(len, 5)) }", T_CORE),
    "b6-epoch-unchecked": ("t44", CORE, "        if (pv.pqzVerifierEpoch != s.pqzVerifierEpoch) return 21;\n", "", T_CORE),
    "b7-validuntil-unchecked": ("t44", CORE, "        if (pv.validUntil < block.timestamp) return 22;\n", "", T_CORE),
    "b8-statementhash-unchecked": ("t44", CORE, "        if (pv.statementHash != sh) return 19;\n", "", T_CORE),
    # ---- Verifier
    "v2-revocation-unchecked": ("t44", CORE, "        if (v == 0) return 1;\n", "", T_CORE),
    "v3-shape-not-recomputed": ("t44", CORE,
                                "        if (verifierShape(registry, v, false) != s.pqzVerifierShape) return 2;\n", "",
                                "test/pqz/{PqzOffchainCore,PqzVerifier}.t.sol"),
    "v4-kind-skipped-at-proposal": ("t44", STATE, "        PqzCore.verifierShape(registry, next, true);\n", "", T_VER),
    "v5-mldsa87-allowed": ("t44", CORE, "            || k == UAKinds.MLDSA65;",
                           "            || k == UAKinds.MLDSA65 || k == UAKinds.MLDSA87;", T_VER),
    "v6-notice-not-waited": ("t44", STATE,
                             "            if (block.timestamp < s.eta) revert IPqzToken.PqzVerifierNotReady(s.eta);\n", "", T_VER),
    "v7-any-owner-confirms": ("t44", STATE,
                              "        if (confirm && caller != s.pqzProposer) revert IGovernance.NotProposer(0, next, s.pqzProposer);\n",
                              "", T_VER),
    "v8-generation-ignored": ("t44", STATE,
                              "        return s.pqzPendingVerifier != 0 && s.pqzProposerGeneration == g.ownerGeneration\n",
                              "        return s.pqzPendingVerifier != 0 && g.ownerGeneration == g.ownerGeneration\n", T_VER),
    "v9-fixed-ignored": ("t44", STATE, "        if (s.pqzVerifierFixed) revert IPqzToken.PqzVerifierFixed();\n", "", T_VER),
    "v10-epoch-not-bumped-transfer": ("t44", STATE,
                                      "        s.pqzVerifierShape = PqzCore.verifierShape(registry, next, true);\n        uint32 e = s.pqzVerifierEpoch + 1;",
                                      "        s.pqzVerifierShape = PqzCore.verifierShape(registry, next, true);\n        uint32 e = s.pqzVerifierEpoch;",
                                      "test/pqz/{PqzOffchainCore,PqzVerifier}.t.sol"),
    "v11-epoch-not-bumped-revoke": ("t44", STATE,
                                    "        s.pqzVerifierShape = 0;\n        uint32 e = s.pqzVerifierEpoch + 1;",
                                    "        s.pqzVerifierShape = 0;\n        uint32 e = s.pqzVerifierEpoch;", T_VER),
    "v12-zero-verifier-proposable": ("t44", CORE,
                                     "        if (strict && v == 0) revert IPqzToken.PqzVerifierUnregistered(v);", "", T_VER),
    # ---- Mode
    "m1-setter-writes-mode": ("t44", STATE, "        uint32 e = s.pqzVerifierEpoch + 1;\n        s.pqzVerifierEpoch = e;\n        _dropPending(s);\n        emit IPqzToken.PqzVerifierSet",
                              "        uint32 e = s.pqzVerifierEpoch + 1;\n        s.pqzVerifierEpoch = e;\n        s.pqzVerifyMode = 0;\n        _dropPending(s);\n        emit IPqzToken.PqzVerifierSet",
                              T_VER),
    "m2-offchain-calls-precompile": ("t44", CORE,
                                     "        if ($().pqzVerifyMode == OFFCHAIN) return _offchain(o, buf, proof, pqzVerdict);",
                                     "        if ($().pqzVerifyMode == OFFCHAIN) _offchain(o, buf, proof, pqzVerdict);", T_CORE),
    "m3-precompile-reads-verdict": ("t44", CORE,
                                    "        if ($().pqzVerifyMode == OFFCHAIN) return _offchain(o, buf, proof, pqzVerdict);",
                                    "        if (true) return _offchain(o, buf, proof, pqzVerdict);", T_CORE),
    # ---- Keys (KV-12 / AV-6)
    "k1-offchain-length-dropped": ("t44", CORE,
                                   "        return (proven || $().pqzVerifyMode == OFFCHAIN) && ptr.code.length == PqzCt.PK + 1;",
                                   "        return (proven || $().pqzVerifyMode == OFFCHAIN) && (ptr.code.length == PqzCt.PK + 1 || $().pqzVerifyMode == OFFCHAIN);",
                                   T_CORE),
    "k2-precompile-unproven": ("t44", CORE,
                               "        return (proven || $().pqzVerifyMode == OFFCHAIN) && ptr.code.length == PqzCt.PK + 1;",
                               "        return ptr.code.length == PqzCt.PK + 1;", T_CORE),
    "k3-auditor-rule-in-precompile": ("t44", STATE, "        if (aud.length == 32) PqzCore._keyPtr(registry, a);",
                                      "        if (aud.length == 32 && off) PqzCore._keyPtr(registry, a);", T_CORE),
    "k4-pairwise-compare-dropped": ("t44", CORE,
                                    "                    revert IPqzToken.KeyReused(i > m ? $().auditorUA : o.op == 7 ? o.rec[i - 1] : o.to);",
                                    "                    {}", T_CORE),
    # ---- Disclosure
    "d1-five-arg-false": ("t45", LAYER,
                          "        if (PqzCore.$().pqzVerifyMode != PqzCore.PRECOMPILE) revert PqzVerdictRequired();",
                          "        if (PqzCore.$().pqzVerifyMode != PqzCore.PRECOMPILE) return false;", T_ENT),
    "d2-seven-arg-ignores-verdict": ("t45", LAYER,
                                     "        if (PqzCore.$().pqzVerifyMode == PqzCore.PRECOMPILE) return _verifyAmount(entryRef, leg, amount, kind, keyVersion, proof);",
                                     "        return _verifyAmount(entryRef, leg, amount, kind, keyVersion, proof);", T_ENT),
    # ---- T45: the verdict decoded but not passed on (the signed single form's self-call takes the empty verdict)
    "e1-signed-verdict-dropped": ("t45", LAYER,
                                  "        bytes calldata accHint, PqzSignedVerdict calldata pqzVerdict) private pure returns (bytes memory)\n    {\n        return abi.encodeWithSelector(sel, t, proof, pqzAuth, accHint, pqzVerdict);\n    }\n\n    /// @dev The entry reference",
                                  "        bytes calldata accHint, PqzSignedVerdict calldata pqzVerdict) private pure returns (bytes memory)\n    {\n        pqzVerdict;\n        PqzSignedVerdict memory z;\n        return abi.encodeWithSelector(sel, t, proof, pqzAuth, accHint, z);\n    }\n\n    /// @dev The entry reference",
                                  T_ENT),
}


def red_tests(log):
    forge = re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log) + re.findall(r"\[FAIL[^\]]*\] (invariant_\w+)$", log, re.M)
    forge += re.findall(r"^ (invariant_\w+)\(\) \(runs:", log, re.M)  # a failed invariant: its name on the line after the reason
    node = re.findall(r"^\u2716 (.+?) \(\d", log, re.M)  # node --test: "✖ <name> (<ms>)"
    node += re.findall(r"^test (\S+) \.\.\. FAILED$", log, re.M)  # cargo test
    return sorted(set(forge) | set(n for n in node if n != "failing tests:"))


def run(mid):
    task, path, old, new, match = MUTANTS[mid]
    task = os.environ.get("MUTANTS_LOG_TASK", task)  # T49 re-runs T44's and T45's mutants into its own table
    match = os.environ.get("MUTANTS_MATCH", match)  # ... against the invariant suite
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
                d = os.path.dirname(match) if match.count("/") > 1 else "test"
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
