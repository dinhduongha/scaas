#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T13c follow-up (ua-dart-frb secrets, owner 2026-11-06): every secret, in or out, is a Rust-owned `SecretBytes`
that Dart fills and reads in place through dart:ffi, never through frb's codec. One mutant per run on a clean tree (one or more
replacements); for a mutant of the Rust surface, frb codegen first; then the cargo build of rust/ (the library the Dart tests
load), `cargo test` (the crate's unit tests) and the whole `dart test`; every file restored byte for byte after it (the
generated ones too). A mutant whose build fails is NOT-LOADED (it kills nothing); a mutant both suites pass SURVIVED: both are
findings (exit 1). M1 and M6 edit the generated lib/src/rust/api/wallet.dart (the Dart frb emits from the Rust `dart_code`).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13c-secrets-mutants.py [first last]   (worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13c-secrets-mutants.py check           (every replacement found once)"""
import os
import re
import subprocess
import sys

D = "clients/ua-dart-frb/"
RW = D + "rust/src/api/wallet.rs"
GD = D + "lib/src/rust/api/wallet.dart"
GEN = [GD, D + "lib/src/rust/api/ua.dart", D + "lib/src/rust/frb_generated.dart", D + "lib/src/rust/frb_generated.io.dart",
       D + "lib/src/rust/frb_generated.web.dart", D + "rust/src/frb_generated.rs"]
CAPPED = os.path.abspath("scripts/capped")
CODEGEN = ([CAPPED, "flutter_rust_bridge_codegen", "generate"], D)
BUILD = ([CAPPED, "cargo", "build", "--locked", "--offline", "-j2"], D + "rust")
UNIT = ([CAPPED, "cargo", "test", "--locked", "--offline", "-j2"], D + "rust")
SUITE = ([CAPPED, "dart", "test", "--reporter", "expanded"], D)

M = [
    # (name, codegen first, [(file, from, to)])
    ("take: the source not zeroed", False, [(GD, "    } finally {\n      src.fillRange(0, src.length, 0);\n    }", "    } finally {}")]),
    ("drop: the buffer not zeroed", False, [(RW, "        self.mem.iter_mut().for_each(|b| b.0.zeroize());\n", "")]),
    ("a buffer that moves: addr() reallocates (the old copy freed, not zeroed)", False,
     [(RW, "    pub fn addr(&mut self) -> usize {\n        self.mem.as_mut_ptr() as usize",
       "    pub fn addr(&mut self) -> usize {\n        self.mem = self.mem.iter().map(|b| Block(b.0)).collect();\n"
       "        self.mem.as_mut_ptr() as usize")]),
    ("a secret input through the codec again (wallet_seal_vault: Vec<u8>)", True,
     [(RW, "pub fn wallet_seal_vault(w: &UaWallet, vault_passphrase: &SecretBytes) -> R<String> {\n"
           "    Ok(w.0.seal_vault(text(vault_passphrase.get())?, None)?.to_json())",
       "pub fn wallet_seal_vault(w: &UaWallet, vault_passphrase: Vec<u8>) -> R<String> {\n"
       "    Ok(w.0.seal_vault(text(&vault_passphrase)?, None)?.to_json())")]),
    ("a secret output through the codec again (UaSeedBackup::reveal: Vec<u8>)", True,
     [(RW, "    pub fn reveal(&self) -> R<SecretBytes> {\n        out(self.0.lock().map_err(|_| arg())?.reveal()?.as_bytes())",
       "    pub fn reveal(&self) -> R<Vec<u8>> {\n        Ok(self.0.lock().map_err(|_| arg())?.reveal()?.as_bytes().to_vec())")]),
    ("take: nothing written", False, [(GD, ".asTypedList(src.length).setAll(0, src);", ".asTypedList(src.length);")]),
    ("no mlock", False, [(RW, "        let (locked, no_dump) = uw::protect::on(mem.as_mut_ptr().cast(), mem.len() * BLOCK);",
                          "        let (locked, no_dump) = (false, false);")]),
    ("no size bound", False, [(RW, "        if len > SECRET_MAX {\n", "        if len > usize::MAX - 1 {\n")]),
]

if sys.argv[1:] == ["check"]:
    for name, _, reps in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(cmd_cwd):
    cmd, cwd = cmd_cwd
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout + r.stderr


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, gen, reps) in enumerate(M[lo - 1:hi], lo):
    files = sorted({f for f, _, _ in reps} | (set(GEN) if gen else set()))
    orig = {f: open(f, encoding="utf-8").read() for f in files}
    new = {f: orig[f] for f, _, _ in reps}
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        grc = run(CODEGEN)[0] if gen else 0
        lrc, lout = run(BUILD) if grc == 0 else (grc, "codegen failed")
        urc, uout = run(UNIT) if lrc == 0 else (lrc, lout)
        rc, out = run(SUITE) if lrc == 0 else (lrc, lout)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    failed = sorted(set(re.findall(r"test/\w+\.dart: (.+?) \[E\]", out)))
    last = re.findall(r"^\d\d:\d\d \+(\d+)(?: ~\d+)?(?: -(\d+))?: ", out, re.M)
    counts = f"+{last[-1][0]} -{last[-1][1] or 0}" if last else "no count (did not compile)"
    ufailed = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", uout, re.M)))
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 and urc == 0 else "killed    "
    bad += lrc != 0 or (rc == 0 and urc == 0)
    print(f"{verdict} | M{n} {name} | {', '.join(f.removeprefix(D) for f, _, _ in reps)} | cargo test rc={urc}: "
          f"{', '.join(ufailed) or '-'} | dart test rc={rc}: {len(failed)} failed: {', '.join(failed)} | {counts}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
rc, _ = run(BUILD)  # the tree's own library again
raise SystemExit(1 if bad or rc else 0)
