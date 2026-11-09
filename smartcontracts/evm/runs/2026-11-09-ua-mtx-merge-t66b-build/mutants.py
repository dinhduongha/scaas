# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T66b build (spec 2026-11-09-t66b-library-organisation.md §10) mutants: one at a time, each edit applied to its src/ file,
forge through `scripts/capped` (sparse, out/mutants-t66b) on the mutant's tests, the file restored in the same process and checked
byte-equal to its content before the run (then `git diff --exit-code` when the tree is committed). Each must turn a named negative
red while the original stays green (the gate's own runs).

Usage (from smartcontracts/evm): python3 runs/2026-11-09-ua-mtx-merge-t66b-build/mutants.py list | run [<id> ...]
Full output: runs/2026-11-09-ua-mtx-merge-t66b-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-09-ua-mtx-merge-t66b-build/mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
REG = "src/ua/UARegistry.sol"
AUX = "src/ua/UARegistryAuxLib.sol"
CORE = "src/ua/UARegistryCoreLib.sol"
PAIR = "test/ua/UARegistryPair.t.sol"
UA_W = "{test/ua/UARegistryPair.t.sol,test/ua/UARegistryUA8.t.sol,test/ua/UARegistryMembership.t.sol}"
UA_R = "{test/ua/UARegistryPair.t.sol,test/ua/UARegistryUA8.t.sol,test/ua/UARegistryNested.t.sol}"
NTM = "src/metatx/NormalTokenModules.sol"
AUTH = "        MtxPipelineLib._authorize(c, from, purpose, digest, auth);"
DEX, DEXD, DEXT = "src/dex/SCaaSDex.sol", "src/dex/SCaaSDexAdmin.sol", "test/ua/UADexAdmin.t.sol"

# id: (tests, [(file, old, new, occurrences)])
MUTANTS = {
    # §10: R-1's forward to the wrong library entry
    # (3.1d: the forward names its library; the R-1 mutant now on an Aux library forward)
    "R1-wrong-library-entry": (PAIR, [(REG, "_libPure(address(UARegistryAuxLib), UARegistryAuxLib.pqzKeyVersionDigest.selector);",
                                       "_libPure(address(UARegistryAuxLib), UARegistryAuxLib.pqzKeyRecordDigest.selector);", 1)]),
    # 3.1d (owner 2026-11-09, spec §11 (f)): a `*Digest` forward routed to the core again
    "R1d-digest-routed-to-core": (PAIR, [(REG, "_libPure(address(UARegistryAuxLib), UARegistryAuxLib.registrationDigest.selector);",
                                          "_libPure(address(UARegistryCoreLib), UARegistryAuxLib.registrationDigest.selector);", 1)]),
    # 3.1b (owner 2026-11-09): a writer routed to the wrong library; the two libraries' addresses swapped; a read routed to the
    # wrong library; the constructor's check of the auxiliary library dropped
    "B1-writer-wrong-library": (UA_W, [(REG, "_lib(address(UARegistryAuxLib), UARegistryAuxLib.setKemKey.selector,",
                                        "_lib(address(UARegistryCoreLib), UARegistryAuxLib.setKemKey.selector,", 1)]),
    "B2-library-addresses-swapped": (UA_W, [(REG, "_lib(address(UARegistryAuxLib),", "_lib(address(UARegistryCORE),", 4),
                                            (REG, "_lib(address(UARegistryCoreLib),", "_lib(address(UARegistryAuxLib),", 6),
                                            (REG, "_lib(address(UARegistryCORE),", "_lib(address(UARegistryCoreLib),", 4)]),
    "B3-read-wrong-library": (UA_R, [(REG, "_libView(address(UARegistryAuxLib), UARegistryAuxLib.popOf.selector,",
                                      "_libView(address(UARegistryCoreLib), UARegistryAuxLib.popOf.selector,", 1)]),
    "B4-aux-library-check-dropped": (PAIR, [(REG, " || address(UARegistryAuxLib).code.length == 0) revert UAConfig(0);",
                                             ") revert UAConfig(0);", 1)]),
    # 3.1c (owner 2026-11-09, spec §11 (f)): the auxiliary library linked to a wrong core; a core helper reachable by a direct
    # call (its call protection gone: `view`); a helper's result ignored
    "C1-aux-wrong-core": (PAIR, [(AUX, "address core = address(UARegistryCoreLib);", "address core = address(this);", 1)]),
    "C2a-core-helper-direct-call-portableOk": (PAIR, [(CORE, "IUARegistry.UASig calldata sig) external returns (bool)",
                                                       "IUARegistry.UASig calldata sig) external view returns (bool)", 1)]),
    "C2b-core-helper-direct-call-keyUa": (PAIR, [(CORE, "function keyUa(uint16 kind, bytes memory keyData) external returns",
                                                  "function keyUa(uint16 kind, bytes memory keyData) external view returns", 1)]),
    "C3-helper-result-ignored": (PAIR, [(AUX, "digest, sig)), (bool)\n        );", "digest, sig)), (bool)\n        ) || true;", 1)]),
    # 4.1, rule 4 for MtxPipelineLib (spec §4.1): a module's hook back on the library call (the code not compiled in: P's
    # typed transfer, T's trade authorisation, A's payment views); P's authorisation hook skipping the check
    "P1-P-pipeline-not-compiled-in": ("test/ua/UALedger.t.sol", [(NTM, "return MtxPipelineLib._preTransferUA(c, t, signed, have, auth);",
                                                             "return MtxPipelineLib.preTransferUA(c, t, signed, have, auth);", 1)]),
    "P2-T-authorize-not-compiled-in": ("test/ua/UATrade.t.sol", [(NTM, AUTH + "\n    }\n\n    function cancelOrderDigest",
                                                              AUTH.replace("._authorize", ".authorize") + "\n    }\n\n    function cancelOrderDigest", 1)]),
    "P3-A-payment-views-not-compiled-in": ("test/metatx/PayRecords.t.sol", [(NTM, "return MtxPipelineLib._paymentCount(payNo);",
                                                                          "return MtxPipelineLib.paymentCount(payNo);", 2)]),
    "P4-P-authorize-hook-skips-the-check": ("test/ua/UAReceiverFee.t.sol", [(NTM, AUTH + "\n    }\n\n    function _pipeCallDigest",
                                                                          "        c; from; purpose; digest; auth;\n    }\n\n    function _pipeCallDigest", 1)]),
    # 4.1, the DEX's admin module D (spec §4.2, §4.5): the DEX's check of D's group, of D's factory; D's `onlyDelegated`
    "D1-dex-group-check-dropped": (DEXT, [(DEX, "ITokenModule(d).moduleGroup() != GROUP_D || ", "", 1)]),
    "D2-dex-factory-check-dropped": (DEXT, [(DEX, " || ITokenModule(d).factory() != factory_", "", 1)]),
    "D3-d-onlyDelegated-dropped": (DEXT, [(DEXD, "if (address(this) == _SELF) revert NotDelegated();", "", 1)]),
}


def run(mid):
    tests, edits = MUTANTS[mid]
    files = sorted({f for f, *_ in edits})
    orig = {f: open(os.path.join(EVM, f)).read() for f in files}
    mut = dict(orig)
    for f, old, new, n in edits:
        if mut[f].count(old) != n:
            raise SystemExit(f"{mid}: the mutated text occurs {mut[f].count(old)} times in {f}, not {n}")
        mut[f] = mut[f].replace(old, new)
    logp = os.path.join(EVM, "runs", f"2026-11-09-ua-mtx-merge-t66b-mut-{mid}.log")
    try:
        for f in files:
            open(os.path.join(EVM, f), "w").write(mut[f])
        # T66b 4.1 on: one test directory per compile (FOUNDRY_TEST), as the gate's runner; sparse mode compiled other directories
        tdir = re.match(r"\{?(test/[a-z0-9]+)/", tests).group(1)
        env = {**os.environ, "FOUNDRY_TEST": tdir, "FOUNDRY_OUT": "out/mutants-t66b-" + tdir.replace("/", "-"),
               "FOUNDRY_CACHE_PATH": "cache/mutants-t66b-" + tdir.replace("/", "-")}
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, FORGE, "test", "-j", "2", "--match-path", tests], cwd=EVM, env=env, stdout=log,
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
