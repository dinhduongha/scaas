# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of round 3s (KYC bit 28, the allow and deny lists; spec docs/superpowers/specs/2026-11-10-token-lists.md §13), in the
shape of runs/2026-11-10-ua-mtx-3r/mutants.py: one mutant per run on a clean tree (the mutated file committed), the
source edit applied, the named suite run alone through `scripts/capped`, the file restored in the same process (finally), then
`git diff --quiet --exit-code -- <file>` must hold (byte-equal). Killed = the run fails (rc != 0) with a test red.

A row: id -> (file from the repository root, old text (must occur once), new text, kind, where, match)
  kind "forge": FOUNDRY_TEST=smartcontracts/evm/<where>, `forge test --match-path <where>/<match>` (match a glob of files)
  kind "cargo": in <where> (e.g. scaas-node), `cargo test --lib <match>` (a test-name filter)
  kind "npm":   in <where> (e.g. clients/clientkeys), `npm test`

Usage (from the repository root): python3 smartcontracts/evm/runs/2026-11-11-ua-mtx-3s/mutants.py list | run <id> [<id> ...] | all
Full output: runs/2026-11-11-ua-mtx-3s/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-11-ua-mtx-3s/mutants.txt (committed). `all` skips ids already in mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
CAPPED = os.path.join(ROOT, "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")

# Rows are added by the task that builds the code they mutate (T2 ... T7); T10 runs the rest and checks the count.
GL = "smartcontracts/evm/src/governance/GovernanceLib.sol"
GB = "smartcontracts/evm/src/governance/GovernanceBits.sol"
RB = "smartcontracts/evm/src/regulated/RegulatedBase.sol"
RL = "smartcontracts/evm/src/regulated/RegulatedLib.sol"
MUTANTS = {
    # T3 (spec §4.2, §4.3): the checks L at each hook
    "M1": (RB, "            _notFrozen(from);\n            _listed(from);\n", "            _notFrozen(from);\n",
           "forge", "test/as", "Lists.t.sol"),
    "M2": (RB, "            _listed(to);\n            _eligible(to);\n", "            _eligible(to);\n",
           "forge", "test/as", "Lists.t.sol"),
    "M3": (RB, "        _notFrozen(from);\n        _listed(from);\n    }", "        _notFrozen(from);\n    }",
           "forge", "test/as", "Lists.t.sol"),
    "M4": (RB, "revert IRegulatedToken.FeeRecipientFrozen(a);\n        _listed(a);\n",
           "revert IRegulatedToken.FeeRecipientFrozen(a);\n", "forge", "test/as", "Lists.t.sol"),
    "M5": (RB, "        _notFrozen(a);\n        _listed(a);\n", "        _notFrozen(a);\n",
           "forge", "test/as", "confidential/*Receiver.t.sol"),
    "M6": (RB, "        _listed(recipient);\n", "", "forge", "test/as", "confidential/*Receiver.t.sol"),
    "M7": (RB, "        _listed(to); // never", "        _listed(from);\n        _listed(to); // never",
           "forge", "test/as", "Lists.t.sol"),
    "M8": (RB, "        _listed(to); // never `L(from)`: the remedy reaches a blocked subject (round 3s, spec §4.3)\n", "",
           "forge", "test/as", "Lists.t.sol"),
    "M9": (RL, "    uint8 internal constant ALLOWED = 1;\n    uint8 internal constant DENIED = 2;",
           "    uint8 internal constant ALLOWED = 2;\n    uint8 internal constant DENIED = 1;", "forge", "test/as", "Lists.t.sol"),
    "M9b": (RL, "    uint8 internal constant C_ALLOW = 1 << 3;\n    uint8 internal constant C_DENY = 1 << 4;",
            "    uint8 internal constant C_ALLOW = 1 << 4;\n    uint8 internal constant C_DENY = 1 << 3;", "forge", "test/as", "Lists.t.sol"),
    # T3 (spec §6.1, §6.3): the list ops
    "M10": (RL, "m[a] = on ? fl | flag : fl & ~flag;", "m[a] = on ? fl | flag : 0;", "forge", "test/as", "ListGovernance.t.sol"),
    "M11": (RL, "        if (role == 0) revert IGovernance.MissingRole(bit, subject);\n", "", "forge", "test/as", "ListGovernance.t.sol"),
    "M11b": (RL, "        uint8 role = GovernanceLib.$().roles[bit][subject];\n",
             "        GovernanceUse.use(bit, subject, 0);\n        uint8 role = GovernanceLib.$().roles[bit][subject];\n",
             "forge", "test/as", "ListGovernance.t.sol"),
    "M12": (RL, "if (n == 0 || n > MAX_LIST_BATCH)", "if (n == 0 || n >= MAX_LIST_BATCH)", "forge", "test/as", "ListGovernance.t.sol"),
    "M12b": (RL, "if (n == 0 || n > MAX_LIST_BATCH)", "if (n == 0 || n > MAX_LIST_BATCH + 1)", "forge", "test/as", "ListGovernance.t.sol"),
    "M13": (RL, "            if (a == 0) revert IRegulatedToken.ListAccountZero();\n", "", "forge", "test/as", "ListGovernance.t.sol"),
    # T3 (spec §3): KYC
    "M14": (RB, "        if (c & RegulatedLib.C_KYC == 0) return;\n", "        if (c & RegulatedLib.C_LISTS == 0) return;\n",
            "forge", "test/as", "{Lists,Registry}.t.sol"),
    "M15": (RL, "return uint8(f >> GovernanceBits.FREEZE) & 0x3F | uint8((f >> GovernanceBits.KYC) & 1) << 6;",
            "return uint8(f >> GovernanceBits.FREEZE) & 0x3F;", "forge", "test/as", "{Registry,ListGovernance}.t.sol"),
    # T2 (spec §5.3): enableFeature, the ratchet, the locks
    "M16": (GL, "        if (GovernanceBits.ENABLEABLE & m == 0) revert IGovernance.FeatureNotEnableable(bit);\n", "",
            "forge", "test/as", "ListGovernance.t.sol"),
    "M17": (GL, "        if (s.lockedFeatures & m != 0) revert IGovernance.FeatureLocked(bit);\n", "",
            "forge", "test/as", "ListGovernance.t.sol"),
    "M18": (RB, "            if (RegulatedLib.$().complianceRegistry == address(0)) revert IRegulatedToken.ComplianceRegistryNotSet();\n",
            "", "forge", "test/as", "ListGovernance.t.sol"),
    "M19": (GL, "        if (GovernanceBits.NOT_DISABLEABLE & m != 0) revert IGovernance.FeatureNotDisableable(bit); // 8, 9: once on, never off\n",
            "", "forge", "test/as", "ListGovernance.t.sol"),
    "M20": (RB, "            | GovernanceBits.NOT_DISABLEABLE) | (uint256(1) << GovernanceBits.KYC);",
            "            | GovernanceBits.NOT_DISABLEABLE);", "forge", "test/as", "{ListGovernance,Registry}.t.sol"),
    "M21": (RB, "            | GovernanceBits.NOT_DISABLEABLE) | (uint256(1) << GovernanceBits.KYC);",
            ") | (uint256(1) << GovernanceBits.KYC);", "forge", "test/as", "ListGovernance.t.sol"),
    "M22": (GL, "if (locked & ~(features | (GovernanceBits.ENABLEABLE & valid)) != 0)", "if (locked & ~features != 0)",
            "forge", "test/as", "ListGovernance.t.sol"),
    "M22b": (GL, "if (locked & ~(features | (GovernanceBits.ENABLEABLE & valid)) != 0)", "if (locked & ~(features | valid) != 0)",
             "forge", "test/as", "ListGovernance.t.sol"),
    "M23": (GL, "GovernanceBits.ENABLEABLE & ~s.lockedFeatures & _bit(bit) == 0", "GovernanceBits.ENABLEABLE & _bit(bit) == 0",
            "forge", "test/as", "ListGovernance.t.sol"),
    "M23b": (GL, "if (s.features & _bit(bit) == 0 && GovernanceBits.ENABLEABLE & ~s.lockedFeatures & _bit(bit) == 0) {",
             "if (s.features & _bit(bit) == 0) {", "forge", "test/as", "ListGovernance.t.sol"),
    "M24": (RB, "        RegulatedLib.$().controls |= bit == GovernanceBits.KYC ? RegulatedLib.C_KYC : uint8(1 << (bit - GovernanceBits.FREEZE));\n",
            "", "forge", "test/as", "ListGovernance.t.sol"),
    "M25": (RB, "return (false, 5);", "return (false, 6);", "forge", "test/as", "Lists.t.sol"),
    "M26": (RL, "            || (p.termsHash != 0) != (f & TERMS_BITS != 0\n                || GovernanceBits.enableable(f, cfg.lockedFeatures, valid, cfg.admin, reg != address(0)) != 0)",
            "            || (p.termsHash != 0) != (f & TERMS_BITS != 0)", "forge", "test/as", "ListGovernance.t.sol"),
    "M27": ("smartcontracts/evm/src/metatx/WrappedTokenCore.sol",
            "        _burn(from, burned);\n        address u = WrappedLib.payOut(i, recipient, out, holder);",
            "        _burn(from, burned);\n        _regReceiver(MetaTxLib.pad(recipient));\n        address u = WrappedLib.payOut(i, recipient, out, holder);",
            "forge", "test/as", "Lists.t.sol"),
    "M28": ("smartcontracts/evm/src/pqz/PqzLayer.sol",
            "        _regName(t.beneficiaryUA);\n        _pullShieldIn(t.shieldIn);\n        PqzCore.Paid memory f;\n        (r, f) = PqzTransferLib.transfer(e, t,",
            "        _regName(t.beneficiaryUA);\n        _regReceiver(t.toUA);\n        _pullShieldIn(t.shieldIn);\n        PqzCore.Paid memory f;\n        (r, f) = PqzTransferLib.transfer(e, t,",
            "forge", "test/as", "confidential/PqzReceiver.t.sol"),
    # the review's rows (Fable P1-1, P1-2, P2-2)
    "M29": (RB, "        } else if (GovernanceLib.$().counts[bit].roots == 0) {\n            revert IRegulatedToken.ListHolderMissing(bit);\n        }",
            "        }", "forge", "test/as", "ListGovernance.t.sol"),
    "M30": (GL, "uint256 iss = (features | GovernanceBits.enableable(features, locked, valid, admin, false)) & GovernanceBits.ISSUER_BITS;",
            "uint256 iss = features & GovernanceBits.ISSUER_BITS;", "forge", "test/as", "ListGovernance.t.sol"),
    "M30b": (GL, "GovernanceBits.enableable(features, locked, valid, admin, false)", "GovernanceBits.enableable(features, 0, valid, admin, false)",
             "forge", "test/as", "ListGovernance.t.sol"),
    "M31": (RL, "            s.listFlags[h] = ALLOWED;\n", "", "forge", "test/as", "ListGovernance.t.sol"),
    "M31b": (RL, "if (f & (1 << GovernanceBits.ALLOWLIST) != 0 && cfg.initialSupply != 0) {", "if (f & (1 << GovernanceBits.ALLOWLIST) != 0) {",
             "forge", "test/as", "ListGovernance.t.sol"),
    "M31c": (RL, "if (f & (1 << GovernanceBits.ALLOWLIST) != 0 && cfg.initialSupply != 0) {", "if (cfg.initialSupply != 0) {",
             "forge", "test/as", "ListGovernance.t.sol"),
    "M33": (GB, "        if (!registry) e &= ~(uint256(1) << KYC);\n", "", "forge", "test/as", "ListGovernance.t.sol"),
    "M33b": (GB, "        if (admin == 0) return 0;\n", "", "forge", "test/as", "ListGovernance.t.sol"),
    # T4 (spec §6.2, B1-B3): a word dropped from each router struct (the binding matrix's control fails)
    "B1": ("smartcontracts/evm/src/governance/GovernanceRouter.sol",
           "_uaCall(T.UA_SET_ALLOWED, e, target, abi.encode(keccak256(abi.encodePacked(accounts)), on),",
           "_uaCall(T.UA_SET_ALLOWED, e, target, abi.encode(keccak256(abi.encodePacked(accounts))),",
           "forge", "test/as", "ListRouter.t.sol"),
    "B2": ("smartcontracts/evm/src/governance/GovernanceRouter.sol",
           "_uaCall(T.UA_SET_DENIED, e, target, abi.encode(keccak256(abi.encodePacked(accounts)), on),",
           "_uaCall(T.UA_SET_DENIED, e, target, abi.encode(on),",
           "forge", "test/as", "ListRouter.t.sol"),
    "B3": ("smartcontracts/evm/src/governance/GovernanceRouter.sol",
           "_ua(T.UA_ENABLE_FEATURE, e, target, IRegulatedToken.enableFeature.selector, abi.encode(bit), auth);",
           "_uaCall(T.UA_ENABLE_FEATURE, e, target, \"\", abi.encodeCall(IRegulatedToken.enableFeature, (bit)), auth);",
           "forge", "test/as", "ListRouter.t.sol"),
    # T7 (spec §9, test (13); Fable P2-1, R-1, R-7): the venue's list effects
    "M32": ("scaas-node/src/dex/venue.rs",
            "    if controls & bit == 0 {\n        return ListEffect::None; // R-1: a dormant list changes nothing on chain, nothing here\n    }\n",
            "", "cargo", "scaas-node", "list_effects_follow_the_live_bit"),
    "M32b": ("scaas-node/src/dex/venue.rs", "    } else if blocks {\n        ListEffect::Drop(a)\n",
             "    } else if blocks {\n        ListEffect::None\n", "cargo", "scaas-node", "list_effects_follow_the_live_bit"),
    "M34": ("scaas-node/src/dex/venue.rs", "    if venue.contains(&a) {\n        ListEffect::Halt(blocks)\n    } else if blocks {",
            "    if blocks {", "cargo", "scaas-node", "list_effects_follow_the_live_bit"),
}


def red_tests(log):
    forge = re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)
    cargo = re.findall(r"^test (\S+) \.\.\. FAILED", log, re.M)
    node = re.findall(r"^not ok \d+ - (.+)$", log, re.M) + re.findall(r"^\s*✖ (.+?)(?: \(\d|$)", log, re.M)
    return sorted(set(forge + cargo + node))


def command(kind, where, match):
    if kind == "forge":
        n = "mutants-3s-" + where.replace("/", "-")
        env = {"FOUNDRY_TEST": where, "FOUNDRY_SCRIPT": where, "FOUNDRY_OUT": f"out/{n}", "FOUNDRY_CACHE_PATH": f"cache/{n}"}
        return os.path.join(ROOT, "smartcontracts", "evm"), env, [FORGE, "test", "-j", "2", "--match-path", f"{where}/{match}"]
    if kind == "cargo":
        return os.path.join(ROOT, where), {"CAPPED_MEM": "6G"}, ["cargo", "test", "-j", "2", "--lib", match]
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
