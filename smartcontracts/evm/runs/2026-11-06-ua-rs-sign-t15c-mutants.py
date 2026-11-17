#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15c (ARCH-POS-13, "never a decryption oracle", owner 2026-11-06; the lazy fail-closed step): the release command
lists, zether-prover's `hazmat` gate and `zether-read-balance --rpc` are caught by the release cells of tests/facade_pqz.rs,
tests/facade_zether.rs (`release_has_no_raw_decrypt`), zether-prover's tests/call_with_key.rs and tests/read_balance.rs, the
vectors cell of tests/facade_zether.rs, and the ua-c ctypes suite (a binding's view). One mutant per run on a clean tree, its
command, every file restored byte for byte after it. A mutant whose build fails is NOT-LOADED; a mutant whose command passes
SURVIVED: both are findings (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t15c-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t15c-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
ZP = "clients/zether-prover/"
RC = "clients/ua-c/"
Q = R + "src/facade/pqz.rs"
Z = R + "src/facade/zether.rs"
API = ZP + "src/api.rs"
ZT = ZP + "Cargo.toml"
RB = ZP + "src/bin/zether-read-balance.rs"
RT = R + "Cargo.toml"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
PQZ_REL = (R, CARGO + ["--test", "facade_pqz", "release_has_no_raw_decrypt"])
ZETHER_REL = (R, CARGO + ["--test", "facade_zether", "release_has_no_raw_decrypt"])
ZETHER_VEC = (R, CARGO + ["--features", "vectors", "--test", "facade_zether", "release_has_no_raw_decrypt"])
PROVER = (ZP, CARGO + ["--test", "call_with_key", "release_has_no_raw_decrypt"])
RPC = (ZP, CARGO + ["--test", "read_balance", "rpc_refused"])
DEFAULT = (ZP, CARGO + ["--test", "call_with_key", "hazmat_is_off_by_default"])
PY = (RC, ["bash", "-c", f"{CAPPED} cargo build --locked --offline -j2 && python3 -I tests/test_vectors.py WalletPqz WalletZether"])


def back(f, name):
    """`name`'s `#[cfg(feature = "vectors")]` in a COMMANDS list removed: the command back in a release build."""
    return [(f, f'    #[cfg(feature = "vectors")]\n    "{name}",\n', f'    "{name}",\n')]


M = [
    # the plan's three
    ("PQZ: `dec` back in the release list", back(Q, "dec"), PQZ_REL),
    ("zether-prover: `hazmat` on by default", [(ZT, "\nhazmat = []\n", "\ndefault = [\"hazmat\"]\nhazmat = []\n")], DEFAULT),
    # superseded (T15l re-check): T14b made `--rpc` a reading layer meeting R1-R7 by design; its checks are T14b's mutants
    ("zether-read-balance: `--rpc` accepted (superseded by T14b: --rpc is the R1-R7 reading layer)", [], None),
    # the controller's
    ("PQZ: `rawProveTransfer` back in the release list (T15e renamed the raw form)", back(Q, "rawProveTransfer"), PQZ_REL),
    ("PQZ: `rawProveDisclose` back in the release list (T15e renamed the raw form)", back(Q, "rawProveDisclose"), PQZ_REL),
    ("PQZ: `rawOpenMemo` back in the release list (T15e renamed the raw form)", back(Q, "rawOpenMemo"), PQZ_REL),
    ("PQZ: `dec` back, seen through the C ABI (ua-c ctypes)", back(Q, "dec"), PY),
    ("Zether: `rawCheckBalance` back in the facade's release list (T14b renamed the raw form)", back(Z, "rawCheckBalance"), ZETHER_REL),
    ("Zether: `rawRecoverTransfer` back in the facade's release list (T14b renamed the raw form)", back(Z, "rawRecoverTransfer"), ZETHER_REL),
    ("zether-prover: the api gate removed", [(API, "if !cfg!(feature = \"hazmat\") && HAZMAT.contains(&cmd) {", "if false && HAZMAT.contains(&cmd) {")], PROVER),
    ("zether-prover: `openDisclosure` off the HAZMAT list",
     [(API, "\"recoverTransfer\", \"openDisclosure\"];", "\"recoverTransfer\", \"pop\"];")], PROVER),
    ("ua-rs `vectors` without zether-prover's `hazmat`", [(RT, ", \"zether-prover?/hazmat\"]", "]")], ZETHER_VEC),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(cwd, cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout + r.stderr


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, where) in enumerate(M[lo - 1:hi], lo):
    if where is None:
        print(f"superseded | M{n} {name}", flush=True)
        continue
    cwd, cmd = where
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        rc, out = run(cwd, cmd)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)) | set(re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)))
    loaded = not re.search(r"^error(\[E\d+\])?: could not compile", out, re.M)
    verdict = "NOT-LOADED" if not loaded else "SURVIVED  " if rc == 0 else "killed    "
    bad += (not loaded) or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
