#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T13b (ua-qt: the QML singleton UaWallet over ua-cxx): the load check, the secret wipe of the C++ side, the handle
registry and the singleton's calls are caught by tests/tst_wallet.qml (Qt Quick Test, tst_ua with Qt 6.12, offscreen). One
mutant per run on a clean tree (one or more replacements), the CMake build (cxx-qt, cargo, the C++), the whole QML suite, every
file restored byte for byte after it. A mutant whose build fails is NOT-LOADED (it kills nothing); a mutant whose suite passes
SURVIVED: both are findings (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13b-mutants.py [first last]   (from the worktree root, foreground;
                                                                                            needs clients/ua-qt/build configured)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13b-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

Q = "clients/ua-qt/"
QW = Q + "src/ua_wallet.rs"
XW = "clients/ua-cxx/src/wallet.rs"
CAPPED = os.path.abspath("scripts/capped")
BUILD = [CAPPED, "cmake", "--build", Q + "build", "-j2"]
SUITE = [CAPPED, Q + "build/tst_ua", "-input", Q + "tests"]
ENV = dict(os.environ, QT_QPA_PLATFORM="offscreen")

M = [
    # the plan's three
    ("the load check skipped", [(QW, "            qobject::load().map_err(|e| e.what().split(\": \").next().unwrap_or(\"UAAbiMismatch\").to_string())?;\n", "")]),
    ("a secret buffer not wiped (the C++ side: from_mnemonic's words and passphrase)", [(XW, "    wipe(&mut [words, bip39_passphrase]);\n", "")]),
    ("a handle released twice: the registry keeps it, a second release succeeds", [(XW, "    REGISTRY.lock().map(|mut r| r.remove(&id).is_some()).unwrap_or(false)",
                                                                                     "    REGISTRY.lock().map(|r| r.get(&id).is_some()).unwrap_or(false)")]),
    # the controller's
    ("signTyped from QML skips the policy (Any)", [(QW, "            wallet(native_key(&k)?.sign_typed(&td, expect))",
                                                    "            let _ = expect;\n            wallet(native_key(&k)?.sign_typed(&td, uw::Expect::Any(uw::AllowAnyTypedData)))")]),
    ("seal ignores the aad", [(QW, "            let s = wallet(uw::seal(&bytes(kem_pk)?, &String::from(purpose), &bytes(aad)?, &pt))?;",
                               "            let _ = bytes(aad)?;\n            let s = wallet(uw::seal(&bytes(kem_pk)?, &String::from(purpose), &[], &pt))?;")]),
    ("uaSig keys in reverse order", [(QW, "            let keys = ids.into_iter().map(key).collect::<Res<Vec<Key>>>()?;",
                                      "            let keys = ids.into_iter().rev().map(key).collect::<Res<Vec<Key>>>()?;")]),
    ("lastError not cleared before a call", [(QW, "        self.as_mut().set_last_error(QString::default());\n", "")]),
    ("a revoked key's error code dropped (lastError UAArgument)", [(QW, "fn wallet<T>(r: uw::Result<T>) -> Res<T> {\n    r.map_err(|e| code(e.into()))",
                                                                  "fn wallet<T>(r: uw::Result<T>) -> Res<T> {\n    r.map_err(|_| ARG.to_string())")]),
]

if sys.argv[1:] == ["check"]:
    for name, reps in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, env=ENV)
    return r.returncode, r.stdout + r.stderr


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        lrc, lout = run(BUILD)
        rc, out = run(SUITE) if lrc == 0 else (lrc, lout)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^FAIL!\s+: ua::(\S+)\(\)", out, re.M)))
    totals = re.search(r"^Totals: .*", out, re.M)
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)} | "
          f"{totals.group(0) if totals else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
rc, _ = run(BUILD)  # the tree's own build again
raise SystemExit(1 if bad or rc else 0)
