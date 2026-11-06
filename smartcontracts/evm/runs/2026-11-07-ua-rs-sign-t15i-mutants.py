#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15i (ARCH-POS-13; spec no-decryption-oracle §4.12, §5): each mutant undoes one guard the oracle harness or the
wallet rows stand on and names the check that must catch it: the raw `dec` back in a release build (ua-rs tests/no_oracle.rs
and ua-py's harness through the C ABI), a caller's `T` beside the words, a crafted-query filter in the rebuild (the residual
control must notice the residual moved), the raw `dec` ignoring its window (the positive control must notice), and the `acc`
reference skipped in the rebuild, through ua-rs's wallet rows and through every binding's wallet-rows round trip. One mutant
per run on a clean tree, its command, every file restored byte for byte after it (the gate also runs `git diff --exit-code`).
A failing command kills, a build that does not compile is NOT-LOADED (a finding), a passing command SURVIVED (a finding, exit
1). The binding mutants rebuild a library from mutated source; the gate rebuilds them from the clean tree after.
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15i-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15i-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15i-mutants.py count           (the number of mutants)"""
import os
import re
import subprocess
import sys

R, Q = "clients/ua-rs/", "clients/ua-rs/src/facade/pqz.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
SH = lambda s: ["bash", "-c", s]
UARS = lambda t, feat="": (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", *(["--features", feat] if feat else []), "--test", t])
REL = f"{CAPPED} cargo build --release --locked --offline -j2 --manifest-path ../ua-c/Cargo.toml"
WORDS = "test_words_commands_on_the_forge_rows"
PY = lambda t: ("clients/ua-py", SH(f"{REL} && python3 -m unittest tests.test_wallet.Pqz.{t}"))
GO = ("clients/ua-go", SH(f"{REL} && {CAPPED} go test -count=1 -run TestPqzWordsOnTheForgeRows ./wallet/"))
CS = ("clients/ua-cs", SH(f"{REL} && {CAPPED} dotnet test Scaas.Ua.Tests --filter PqzWordsOnTheForgeRows; r=$?; "
                          "dotnet build-server shutdown >/dev/null 2>&1; exit $r"))
CXX = ("clients/ua-cxx", SH(f"{CAPPED} sh -c 'cmake --build build -j2 && ctest --test-dir build --output-on-failure -R wallet_pqz_words'"))
DART = ("clients/ua-dart-frb", SH(f"{CAPPED} sh -c 'cargo build --locked --offline -j2 --manifest-path rust/Cargo.toml && "
                                  "dart test test/wallet_test.dart -N pqz_words'"))
UAC = ("clients/ua-c", SH(f"{CAPPED} cargo build --locked --offline -j2 && python3 -m unittest tests.test_vectors.WalletPqz.{WORDS}"))

V = '#[cfg(feature = "vectors")]\n'
DEC = [  # every `vectors` gate of the raw `dec` removed (its command, allow-list, request, variant, arm, field reader, import)
    (Q, f'    "enc",\n    {V}    "dec",\n', '    "enc",\n    "dec",\n'),
    (Q, f'        {V}        "dec" => has(&["ct", "window"]),', '        "dec" => has(&["ct", "window"]),'),
    (Q, f'        {V}        "dec" => {{', '        "dec" => {'),
    (Q, f'    {V}    Dec {{ ct: Vec<u8>, window: usize }},', '    Dec { ct: Vec<u8>, window: usize },'),
    (Q, f'            {V}            Req::Dec {{ ct, window }} => {{', '            Req::Dec { ct, window } => {'),
    (Q, f'    {V}    fn ct(&self, k: &str) -> Result<Vec<u8>> {{', '    fn ct(&self, k: &str) -> Result<Vec<u8>> {'),
    (Q, f'{V}use pqz_ffi::stmt::check_ct;', 'use pqz_ffi::stmt::check_ct;'),
]
ACC_REF = [(Q, "    } else if a.acc_blob != [0; 20] {\n        add(&mut c, &load(blobs.data(&a.acc_blob)?, a.acc_u, a.acc_v)?);",
            "    } else if a.acc_blob == [1; 20] {\n        add(&mut c, &load(blobs.data(&a.acc_blob)?, a.acc_u, a.acc_v)?);")]
M = [
    ("PQZ: the raw `dec` in a release build, seen by ua-rs no_oracle", DEC, UARS("no_oracle"), "test"),
    ("PQZ: `balance` takes a caller's `T` beside the words", [
        (Q, '        "balance" => has(LOC) || has(ACCT),', '        "balance" => has(LOC) || has(ACCT) || field == "T",'),
        (Q, "(Req::Balance { t: o.t, p: o.p,", '(Req::Balance { t: if f.has("T") { f.bytes("T")? } else { o.t }, p: o.p,'),
    ], UARS("no_oracle"), "test"),
    ("PQZ: a crafted-query filter in the rebuild (a `u` with one non-zero coefficient refused): the residual moved", [
        (Q, "    Ok([part(u_off, PKP).ok_or(Error::Argument)?, part(v_off, VP).ok_or(Error::Argument)?].concat())",
         "    let u = part(u_off, PKP).ok_or(Error::Argument)?;\n"
         "    if u.chunks_exact(8).filter(|c| c.iter().any(|b| *b != 0)).count() <= 1 {\n        return Err(Error::Argument);\n    }\n"
         "    Ok([u, part(v_off, VP).ok_or(Error::Argument)?].concat())"),
    ], UARS("no_oracle"), "test"),
    ("PQZ: the raw `dec` ignores its window (the positive control must recover s at every window)", [
        (Q, "value(pqzl::dec_win(&sk.0.s, ct, *window)))?})", "value(pqzl::dec_win(&sk.0.s, ct, 0)))?})"),
    ], UARS("no_oracle", "vectors"), "test"),
    ("PQZ: the `acc` reference skipped in the rebuild, seen by ua-rs pqz_wallet_rows", ACC_REF, UARS("pqz_wallet_rows"), "test"),
    # through the C ABI and the bindings (each rebuilds its library from the mutated source)
    ("PQZ: the raw `dec` in a release build, seen by ua-py's harness through the C ABI", DEC, PY("test_no_oracle"), "test"),
    ("PQZ: the `acc` reference skipped, through ua-c (test_vectors.py)", ACC_REF, UAC, "test"),
    ("PQZ: the `acc` reference skipped, through ua-py", ACC_REF, PY(WORDS), "test"),
    ("PQZ: the `acc` reference skipped, through ua-go", ACC_REF, GO, "test"),
    ("PQZ: the `acc` reference skipped, through ua-cs", ACC_REF, CS, "test"),
    ("PQZ: the `acc` reference skipped, through ua-cxx", ACC_REF, CXX, "test"),
    ("PQZ: the `acc` reference skipped, through ua-dart-frb", ACC_REF, DART, "test"),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, f, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
if sys.argv[1:] == ["count"]:
    print(len(M))
    raise SystemExit(0)

NOT_BUILT = re.compile(r"^error(\[E\d+\])?: could not compile|ninja: build stopped|\[build failed\]|error CS\d+|Compilation failed|"
                       r"^Error: Compilation", re.M)


def run(cwd, cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env={**os.environ, **ENV})
    return r.returncode, r.stdout + r.stderr


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, (cwd, cmd), kind) in enumerate(M[lo - 1:hi], lo):
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
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)) | set(re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M))
                    | set(re.findall(r"^--- FAIL: (\S+)", out, re.M))
                    | set(re.findall(r"^\s*\d+/\d+ Test +#\d+: (\S+) .*\*\*\*Failed", out, re.M))
                    | set(re.findall(r"Failed (\S+) \[", out)) | set(re.findall(r"\[E\] (.*)$", out, re.M))
                    | set(re.findall(r"^\s*\d+:\d+ \S*\+\d+ -\d+: (.+?) \[E\]", out, re.M)))
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:400]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
