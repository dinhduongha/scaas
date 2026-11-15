#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Round 3zh (owner 2026-11-15; spec 2026-11-15-mldsa-precompile-cache.md §4): the mutants the tests must catch, one change at a
time. Each mutant replaces one exact string in one file, runs the named tests (forge, through scripts/capped, foreground), expects
them to FAIL, and restores the file byte for byte (a copy kept in memory; `git diff` empty after the run is checked). A mutant
whose tests pass is a gap. Short lines on stdout; forge's output in git-ignored logs under the run dir given (default a mktemp).
  cd smartcontracts/evm && python3 -I runs/2026-11-15-3zh-mldsa-mutants.py [<log dir>]"""
import os
import subprocess
import sys
import tempfile

EVM = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CAPPED = os.path.join(EVM, "../../scripts/capped")
M = [
    ("M1 87 split boundary off by one row", "src/ua/MlDsa.sol",
     "last ? P.k : 3 * part + 3, last);", "last ? P.k : 3 * part + 2, last);",
     "test/ua/MlDsa.t.sol", "test_expandedKeyParts_split|test_expandedKey_nobleReference"),
    ("M2 the third ekPtr slot ignored", "src/ua/UAStore.sol",
     "for (uint256 i; i < n; ++i) {\n            if (i != 0) a = p[i];", "for (uint256 i; i < (n > 2 ? 2 : n); ++i) {\n            if (i != 0) a = p[i];",
     "test/ua/UARegistryPq.t.sol", "test_mldsa87_twoOfThreePartsNotCached"),
    ("M3 a missing part accepted", "src/ua/UAStore.sol",
     'if (a == address(0)) return "";\n            assembly', 'if (a == address(0) && i == 0) return "";\n            assembly',
     "test/ua/UARegistryPq.t.sol", "test_halfCacheRefusesPop|test_mldsa87_twoOfThreePartsNotCached"),
    ("M4 the UAKeyNotCached check removed (_sigOk)", "src/ua/UARegistryCoreLib.sol",
     "            _notCached(_cfgKind(), kind, ua);\n            revert IUARegistry.UAPoP();",
     "            revert IUARegistry.UAPoP();",
     "test/ua/UARegistryPq.t.sol", "test_mldsaCache_c1_under2p24|test_halfCacheRefusesPop"),
    ("M5 the UAKeyNotCached check removed (requireAuthorized)", "src/ua/UARegistry.sol",
     "            if (PqUA.mldsaParts(kind) != 0 && uint160(cfg) != 0 && UAStore.expanded(ua, kind).length == 0",
     "            if (false && PqUA.mldsaParts(kind) != 0 && uint160(cfg) != 0 && UAStore.expanded(ua, kind).length == 0",
     "test/ua/UARegistryPq.t.sol", "test_requireAuthorized_uncachedIsNamed"),
    ("M6 the 75 % check at 74", "script/DeployBase.sol",
     "return uint256(cap) * 100 <= uint256(budget) * 75;", "return uint256(cap) * 100 <= uint256(budget) * 74;",
     "test/ua/UADeploy.t.sol", "test_pqKindThreshold75"),
    ("M7 the 75 % check at 76", "script/DeployBase.sol",
     "return uint256(cap) * 100 <= uint256(budget) * 75;", "return uint256(cap) * 100 <= uint256(budget) * 76;",
     "test/ua/UADeploy.t.sol", "test_pqKindThreshold75"),
    ("M8 MD-5's block check removed", "script/DeployBase.sol",
     "if (reg * 105 / 100 >= TX_REGULAR_GAS_CAP || total > limit) {", "if (reg * 105 / 100 >= TX_REGULAR_GAS_CAP) {",
     "test/ua/UADeploy.t.sol", "test_mldsaCacheBlockGate"),
    ("M9 off accepting a precompile verifier", "script/DeployBase.sol",
     'require(given == address(0), string.concat(env, ": set with MLDSA_PRECOMPILE=off (pure Solidity with the cache)"));', "",
     "test/ua/UADeploy.t.sol", "test_mldsaPrecompileFlag"),
    ("M10 MD-13's single-key bound removed", "src/ua/UARegistryCoreLib.sol",
     "return _msigDebit(gen1 ? IUARegistry(g1).verifyCap(kind) : _cfgKind() >> 160, 192 + _slotBytes(kind, 0), ua);", "return;",
     "test/ua/UARegistryPqzBound.t.sol", "test_register_singleHolderBoundary_mldsa87"),
    ("M11 F-6's CREATE2 check removed", "script/DeployBase.sol",
     "require(given == _mldsaCreate2(i, MldsaVerifier(given).PRECOMPILE()), string.concat(env,",
     "require(true || given == _mldsaCreate2(i, MldsaVerifier(given).PRECOMPILE()), string.concat(env,",
     "test/governance/GovDeploy.t.sol", "test_deployPqzRefusals"),
    ("M12 MD-15's probe refusal removed", "script/DeployBase.sol",
     "require(answered || !mldsaPrecompile,", "require(true || answered || !mldsaPrecompile,",
     "test/ua/UADeploy.t.sol", "test_mldsaProbeFailureRefuses"),
    ("M14 U4h-1: the other-set path taken for the same set", "src/ua/UARegistryAuxLib.sol",
     "if (uint160(cfg) == 0 || key.length != PqzSet.PK) return false;",
     "if (uint160(cfg) == 0 || key.length == PqzSet.PK) return false;",
     "test/ua/PqzScopedKeys.t.sol", "test_u4h1_sameSet_withVerifier_provenOnChain"),
    ("M15 U4h-1: the fix removed (the verifier asked for another set)", "src/ua/UARegistryAuxLib.sol",
     "if (uint160(cfg) == 0 || key.length != PqzSet.PK) return false;", "if (uint160(cfg) == 0) return false;",
     "test/ua/PqzScopedKeys.t.sol", "test_u4h1_otherSet_withVerifier_storedUnproven"),
    ("M16 U4h-1: the unproven mark dropped (another set's proof taken as checked)", "src/ua/UARegistryAuxLib.sol",
     "if (uint160(cfg) == 0 || key.length != PqzSet.PK) return false;",
     "if (uint160(cfg) == 0) return false;\n        if (key.length != PqzSet.PK) { UAStore.layout().scopedKey[ua][scope][version].proven = true; return true; }",
     "test/ua/PqzScopedKeys.t.sol", "test_u4h1_otherSet_withVerifier_storedUnproven"),
    ("M17 U4h-2: the successor's list forwarding removed", "src/ua/UARegistryAuxLib.sol",
     "if (uint160(UARegistryCoreLib._cfgPqz()) == 0) p = UARegistryCoreLib._pred();", "",
     "test/ua/PqzScopedKeys.t.sol", "test_u4h2_successorListsInheritedHolders"),
    ("M13 the part count of 87 at 2", "src/ua/PqUA.sol",
     "kind == MLDSA87 ? 3 : 0;", "kind == MLDSA87 ? 2 : 0;",
     "test/ua/MlDsa.t.sol", "test_expandedKeyParts_split"),
]


def main():
    logs = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp()
    os.makedirs(logs, exist_ok=True)
    env = dict(os.environ, PATH=os.path.expanduser("~/.foundry/bin") + ":" + os.environ.get("PATH", ""))
    gaps = 0
    for i, (name, path, old, new, tpath, tests) in enumerate(M, 1):
        p = os.path.join(EVM, path)
        src = open(p).read()
        if src.count(old) != 1:
            print(f"BAD {name}: the original string is not there exactly once ({src.count(old)})", flush=True)
            gaps += 1
            continue
        open(p, "w").write(src.replace(old, new))
        try:
            log = os.path.join(logs, f"mutant-{i:02d}.log")
            with open(log, "w") as f:
                rc = subprocess.run([CAPPED, "forge", "test", "--match-path", tpath, "--match-test", tests], cwd=EVM, env=env,
                                    stdout=f, stderr=subprocess.STDOUT).returncode
        finally:
            open(p, "w").write(src)
        caught = rc != 0 and "[FAIL" in open(log).read()
        gaps += not caught
        print(f"{'caught' if caught else 'GAP   '} {name} ({tpath} {tests}) rc {rc}", flush=True)
    clean = subprocess.run(["git", "diff", "--quiet", "--", "src", "script"], cwd=EVM).returncode == 0
    print(f"mutants: {len(M) - gaps}/{len(M)} caught; sources restored: {'yes' if clean else 'NO'}")
    sys.exit(1 if gaps or not clean else 0)


if __name__ == "__main__":
    main()
