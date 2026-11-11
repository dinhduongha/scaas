# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of round 3t (the verifier fee; spec docs/superpowers/specs/2026-11-11-verifier-fee.md §15), in the
shape of runs/2026-11-10-ua-mtx-merge-3c/mutants.py: one mutant per run on a clean tree (the mutated file committed), the
source edit applied, the named suite run alone through `scripts/capped`, the file restored in the same process (finally), then
`git diff --quiet --exit-code -- <file>` must hold (byte-equal). Killed = the run fails (rc != 0) with a test red.

A row: id -> (file from the repository root, old text (must occur once), new text, kind, where, match)
  kind "forge": FOUNDRY_TEST=smartcontracts/evm/<where>, `forge test --match-path <where>/<match>` (match a glob of files)
  kind "cargo": in <where> (e.g. scaas-node), `cargo test --lib <match>` (a test-name filter)
  kind "npm":   in <where> (e.g. clients/clientkeys), `npm test`

Usage (from the repository root): python3 smartcontracts/evm/runs/2026-11-11-ua-mtx-3t/mutants.py list | run <id> [<id> ...] | all
Full output: runs/2026-11-11-ua-mtx-3t/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-11-ua-mtx-3t/mutants.txt (committed). `all` skips ids already in mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
CAPPED = os.path.join(ROOT, "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")

# Rows are added by the task that builds the code they mutate (T2 ... T8); T10 runs the rest and checks the count.
PC = "smartcontracts/evm/src/pqz/PqzCore.sol"
PS = "smartcontracts/evm/src/pqz/PqzStateLib.sol"
PL = "smartcontracts/evm/src/pqz/PqzLayer.sol"
MUTANTS = {
    # T2 / T3 (spec §15): each against its targeted file; F = test/pqz PqzVerifierFee.t.sol, K = the kinds file, I = invariants
    "M1": (PC, "            o.fee += o.verifierFee;\n", "", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M2": (PC, "        if (s.pqzVerifyMode == OFFCHAIN) {\n            o.verifierFee = s.verifierFee;",
           "        o.verifierFee = s.verifierFee;\n        if (s.pqzVerifyMode == OFFCHAIN) {\n            o.verifierFee = s.verifierFee;",
           "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M3": (PC, "        o.fee += o.legs * d;\n", "        o.fee += o.legs * d + (o.legs - 1) * o.verifierFee;\n", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M4": (PL, "        _payFees(f, f.fee - f.verifierFee - f.legs * f.decoyFee);", "        _payFees(f, f.fee - f.legs * f.decoyFee);",
           "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M5": (PL, "        _fromPool(f.verifier, f.verifierFee);\n", "", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M6": (PC, "o.verifierFee == 0 ? bytes32(0) : $().pqzVerifierUA);", "o.verifierFee == 0 ? bytes32(0) : $().pqzPendingVerifier);",
           "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M7": (PS, "            || c.confidentialFee + c.verifierFeeMax + 8 * c.minDecoyFee >= c.maxShielded\n",
           "            || c.confidentialFee + c.verifierFee + 8 * c.minDecoyFee >= c.maxShielded\n", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M8": (PS, "        if (c.verifierFee > c.verifierFeeMax) revert", "        if (false) revert", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M9": (PS, "|| c.verifierFee != 0 || c.verifierFeeMax != 0)) {", ")) {", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M10": ("smartcontracts/evm/src/zether/ZetherLib.sol", "|| c.verifierFee != 0\n            || c.verifierFeeMax != 0) {", ") {",
            "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M11": (PS, "        if (next < cur) {\n            _setFee(s, cur, next);", "        if (next < cur && s.noticePeriod == 0) {\n            _setFee(s, cur, next);",
            "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M12": (PS, "        return s.verifierFeePending != 0 && s.verifierFeeProposerGeneration == g.adminGeneration\n",
            "        return s.verifierFeePending != 0\n", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M13": (PS, "        (s.verifierFeePending, s.verifierFeeEta, s.verifierFeeProposer, s.verifierFeeProposerGeneration) = (0, 0, 0, 0);\n        emit IPqzToken.VerifierFeeSet",
            "        emit IPqzToken.VerifierFeeSet", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M14": (PS, "        if (next > s.verifierFeeMax) revert IPqzToken.VerifierFeeAboveMax(next, s.verifierFeeMax);\n", "",
            "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M15": (PS, "        if (s.pqzVerifyMode != PqzCore.OFFCHAIN) revert IPqzToken.PqzVerifyConfigInvalid();\n        uint64 cur = s.verifierFee;",
            "        if (s.pqzVerifyMode != PqzCore.OFFCHAIN || s.pqzVerifierFixed) revert IPqzToken.PqzVerifyConfigInvalid();\n        uint64 cur = s.verifierFee;",
            "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M17": (PC, "        return s.pqzVerifyMode == OFFCHAIN && s.verifierFee != 0 ? s.pqzVerifierUA : bytes32(0);",
            "        return s.pqzVerifyMode == OFFCHAIN ? s.pqzVerifierUA : bytes32(0);", "forge", "test/as", "confidential/PqzVerifierFeeKinds.t.sol"),
    "M18": (PS, "        s.verifierFee = next;\n", "        (s.verifierFee, s.verifierFeeMax) = (next, next);\n", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M19": (PC, "o.verifierFee == 0 ? bytes32(0) : $().pqzVerifierUA);", "bytes32(0));", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M20": (PS, "        if (_feeLive(s, g)) (c.verifierFeePending, c.verifierFeeEta)", "        (c.verifierFeePending, c.verifierFeeEta)",
            "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M22": (PL, "        _regName(PqzCore.verifierPayee());\n        _pullShieldIn(t.shieldIn);\n        PqzCore.Paid memory f;\n        (r, f) = PqzTransferLib.transfer(e,",
            "        _pullShieldIn(t.shieldIn);\n        _regName(PqzCore.verifierPayee());\n        PqzCore.Paid memory f;\n        (r, f) = PqzTransferLib.transfer(e,",
            "forge", "test/as", "confidential/PqzVerifierFeeKinds.t.sol"),
    "M23": (PC, "        e.binding = e.binding == 0 && s.pqzVerifyMode == OFFCHAIN\n", "        e.binding = false\n",
            "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M24": (PC, "        e.binding = e.binding == 0 && s.pqzVerifyMode == OFFCHAIN\n", "        e.binding = e.binding == 0\n",
            "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "M25": (PS, "            if (!live) revert IPqzToken.VerifierFeeSame();\n            _setFee(s, cur, cur);", "            revert IPqzToken.VerifierFeeSame();\n            _setFee(s, cur, cur);",
            "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "B1": ("smartcontracts/evm/src/governance/GovernanceRouter.sol", "IPqzToken.setVerifierFee.selector, abi.encode(next), auth);",
           "IPqzToken.setVerifierFee.selector, abi.encode(next + 1), auth);", "forge", "test/pqz", "PqzVerifierFee.t.sol"),
    "F5": (PL, "        _fromPool(f.verifier, f.verifierFee);\n", "        _fromPool(f.verifier, f.verifierFee + 1);\n", "forge", "test/pqz/invariant",
           "PqzFeeInvariants.t.sol"),
    # T7 (spec §15 (11)): the service skips FEE_WORD_MISMATCH (only STATEMENT_MISMATCH left)
    "V1": ("scaas-pqz-verifier/src/lib.rs", "        if rebuilt.get(256..288) != st.get(256..288) {", "        if false {", "cargo-v", "scaas-pqz-verifier",
           "refuses_stale_fee_word"),
    # T6 (spec §15 (10)): the node skips the pre-check / leaves vf out (the fee word's one source)
    "N1": ("scaas-node/src/pqz.rs", "        fee_check(chain, w.to, p, &statement, c.verifierFee).await?;\n", "        let _ = p;\n", "cargo", "scaas-node",
           "pqz_fee_precheck"),
}


def red_tests(log):
    forge = re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)
    cargo = re.findall(r"^test (\S+) \.\.\. FAILED", log, re.M)
    node = re.findall(r"^not ok \d+ - (.+)$", log, re.M) + re.findall(r"^\s*✖ (.+?)(?: \(\d|$)", log, re.M)
    return sorted(set(forge + cargo + node))


def command(kind, where, match):
    if kind == "forge":
        n = "mutants-3t-" + where.replace("/", "-")
        env = {"FOUNDRY_TEST": where, "FOUNDRY_SCRIPT": where, "FOUNDRY_OUT": f"out/{n}", "FOUNDRY_CACHE_PATH": f"cache/{n}"}
        return os.path.join(ROOT, "smartcontracts", "evm"), env, [FORGE, "test", "-j", "2", "--match-path", f"{where}/{match}"]
    if kind == "cargo":
        return os.path.join(ROOT, where), {"CAPPED_MEM": "6G"}, ["cargo", "test", "-j", "2", "--lib", match]
    if kind == "cargo-v":  # the verifier service: its integration tests by name
        return os.path.join(ROOT, where), {}, ["cargo", "test", "-j", "2", "--test", "service", match]
    if kind == "npm":
        return os.path.join(ROOT, where), {}, ["npm", "test"]
    raise SystemExit(f"unknown kind {kind}")


def run(mid):
    path, old, new, kind, where, match = MUTANTS[mid]
    full = os.path.join(ROOT, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=ROOT) != 0:
        raise SystemExit(f"{mid}: {path} has uncommitted changes; commit first")
    logp = os.path.join(HERE, f"mut-{mid}.log")
    cwd, extra, cmd = command(kind, where, match)
    # MUT_IN_CAPPED=1: the batch already runs inside one `scripts/capped` scope (each mutant still alone and in order)
    cap = [] if os.environ.get("MUT_IN_CAPPED") == "1" else [CAPPED]
    try:
        open(full, "w").write(src.replace(old, new))
        with open(logp, "w") as log:
            rc = subprocess.call(cap + cmd, cwd=cwd, env={**os.environ, **extra}, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=ROOT) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    compile_err = "Compiler run failed" in out or "error[E" in out or "could not compile" in out
    note = ", ".join(red) if red else ("compile error" if compile_err else "none")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:]:
            run(m)
    elif sys.argv[1:2] == ["all"]:
        done = set()
        txt = os.path.join(HERE, "mutants.txt")
        if os.path.exists(txt):
            done = {l.split(" | ")[0] for l in open(txt) if " | " in l}
        for m in MUTANTS:
            if m not in done:
                run(m)
    else:
        raise SystemExit(__doc__)
