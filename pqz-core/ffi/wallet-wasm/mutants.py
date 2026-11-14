# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The wallet module's mutants (TODO 3zf), after ./run.sh (it needs target/out): under scripts/capped,
    scripts/capped python3 pqz-core/ffi/wallet-wasm/mutants.py
A positive control (no change: the test passes), then one change at a time in the wrapper (lib.rs: the module rebuilt at
n2304-kmax4096) or the loader / handle (clientkeys src), clientkeys' test/pqz-wallet-wasm.test.js at n2304-kmax4096 and
n2048-kmax1024; each mutant must turn it red. The file is restored after each. Full output in target/mutants/*.log."""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CK = os.path.normpath(os.path.join(HERE, "..", "..", "..", "clients", "clientkeys"))
OUT, M = os.path.join(HERE, "target", "out"), os.path.join(HERE, "target", "mutants")
SETS = ["n2304-kmax4096", "n2048-kmax1024"]
LIB, LOADER, HANDLE = os.path.join(HERE, "lib.rs"), os.path.join(CK, "src", "pqzopenWasm.js"), os.path.join(CK, "src", "pqzopen.js")

MUTANTS = [
    ("R1 the n <= cap check dropped", LIB, "buf.get(..n as usize).and_then(parse)", "Some(&buf[..n as usize]).and_then(parse)"),
    ("R2 auditor outcomes swapped", LIB, "AuditorOutcome::RecipientUnreadable => 2,\n        AuditorOutcome::Unreadable => 0,",
     "AuditorOutcome::RecipientUnreadable => 0,\n        AuditorOutcome::Unreadable => 2,"),
    ("R3 bytes after the frame accepted", LIB, "f.0.is_empty().then_some(", "true.then_some("),
    ("R4 a fixed field's length word not checked", LIB, "if u32::from_be_bytes(*len) as usize != L {", "if false {"),
    ("R5 the output not zeroed first", LIB, "    OUT.with(|o| *o.borrow_mut() = [0; 16]);\n    INPUT", "    INPUT"),
    ("R6 the input not wiped after", LIB, "        buf.fill(0);\n", ""),
    ("R7 auditorOn other than 0 / 1 taken as on", LIB, "        _ => return None,\n", "        _ => Some(f.party()?),\n"),
    ("R8 recipient skip reported accepted", LIB, "        None => 0,\n", "        None => 1,\n"),
    ("J1 the loader's export check dropped", LOADER, "if (names.join() !== EXPORTS.join() ||", "if (false &&"),
    ("J2 the loader's auditor outcomes swapped", LOADER, "o.r === 2 ? 'recipient-unreadable' : 'unreadable'", "o.r === 2 ? 'unreadable' : 'recipient-unreadable'"),
    ("J3 isPqzWallet true for any object", LOADER, "export const isPqzWallet = (x) => WALLETS.has(x);",
     "export const isPqzWallet = (x) => typeof x === 'object';"),
    ("J4 the handle's set check dropped", HANDLE, "if (wallet && lanes(b.pu).length !== verify.pkBytes)", "if (false)"),
    ("J5 the loader's digits not read on code 1", LOADER, "return r === 1 ? { r, digits:", "return r === 2 ? { r, digits:"),
]


def sh(cmd, log, **kw):
    with open(log, "a") as f:
        return subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT, **kw).returncode


def build(log):
    return sh(["./build.sh", M], log, cwd=HERE, env={**os.environ, "PQZ_SET": SETS[0]})


def test(log):
    env = {**os.environ, "PQZ_WALLET_DIR": M, "PQZ_WALLET_SETS": " ".join(SETS)}
    return sh(["node", "--test", "test/pqz-wallet-wasm.test.js"], log, cwd=CK, env=env)


def main():
    os.makedirs(M, exist_ok=True)
    for s in SETS:
        for f in (f"pqz_wallet_{s}.wasm", f"cases-{s}.json"):
            shutil.copy(os.path.join(OUT, f), M)
    log = os.path.join(M, "control.log")
    open(log, "w").close()
    rc = build(log) or test(log)
    print(f"control (no change): rc={rc} {'ok' if rc == 0 else 'FAIL'}", flush=True)
    if rc:
        return 1
    killed = 0
    for i, (name, path, old, new) in enumerate(MUTANTS):
        src = open(path).read()
        if src.count(old) != 1:
            print(f"{name}: the pattern is not once in {os.path.basename(path)} [FAIL]", flush=True)
            return 1
        log = os.path.join(M, f"mutant-{i}.log")
        open(log, "w").close()
        try:
            open(path, "w").write(src.replace(old, new))
            rb = build(log) if path == LIB else 0
            rc = test(log) if rb == 0 else None
        finally:
            open(path, "w").write(src)
            if path == LIB:  # the unchanged module again before the next mutant
                rr = build(os.path.join(M, f"restore-{i}.log"))
                if rr:
                    print(f"{name}: the restore build failed rc={rr} [FAIL]", flush=True)
                    return 1
        # a mutant that does not build is no kill: it must build and turn the test red
        ok = rb == 0 and rc != 0
        killed += ok
        print(f"{name}: build rc={rb}, test rc={rc}: {'killed' if ok else 'SURVIVED'}", flush=True)
    rc = test(os.path.join(M, "control-after.log"))  # the control again on the restored tree
    print(f"mutants killed {killed}/{len(MUTANTS)}; control after: rc={rc}")
    return 0 if killed == len(MUTANTS) and rc == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
