#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T13c (ua-dart-frb, the wallet over the Rust API through flutter_rust_bridge): the load check, the secret wipes,
the handle ownership and the binding's own rules are caught by test/wallet_test.dart. One mutant per run on a clean tree (one or
more replacements), the cargo build of rust/ (the native library the tests load), the whole `dart test`, every file restored
byte for byte after it. A mutant whose build fails is NOT-LOADED (it kills nothing); a mutant whose suite passes SURVIVED: both
are findings (exit 1). M3 edits the generated rust/src/frb_generated.rs for the run only (a temporary mutant).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13c-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13c-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

D = "clients/ua-dart-frb/"
DW = D + "lib/src/wallet.dart"
RW = D + "rust/src/api/wallet.rs"
GEN = D + "rust/src/frb_generated.rs"
CAPPED = os.path.abspath("scripts/capped")
BUILD = ([CAPPED, "cargo", "build", "--locked", "--offline", "-j2"], D + "rust")
SUITE = ([CAPPED, "dart", "test", "--reporter", "expanded"], D)

KEY_DEC = ("RustAutoOpaqueInnerUaKey(\n        ptr: *const std::ffi::c_void,\n    ) {\n"
           "        MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<UaKey>>::decrement_strong_count(ptr as _);\n")
M = [
    # the plan's three
    # M1 (T18 refresh): 037d5a29 (T13c follow-up) dropped _secret; _loaded is the one wrapper that runs load()
    ("the load check skipped (every entry point)", [(DW, "Future<T> _loaded<T>(Future<T> Function() f) async {\n  load();\n",
                                                     "Future<T> _loaded<T>(Future<T> Function() f) async {\n")]),
    # M2, M4, M10 superseded by 037d5a29 (T13c follow-up): secrets are Rust-owned SecretBytes zeroed on dispose, the Dart-side
    # wipe of _secret is gone; its mutants are 2026-11-06-ua-rs-sign-t13c-secrets-mutants.py
    ("a secret buffer not wiped (superseded by 037d5a29: SecretBytes, t13c-secrets)", []),
    ("a handle freed twice (the generated native UaKey release decrements twice)",
     [(GEN, "pub extern \"C\" fn frbgen_scaas_ua_frb_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generated" + KEY_DEC,
       "pub extern \"C\" fn frbgen_scaas_ua_frb_rust_arc_decrement_strong_count_RustOpaque_flutter_rust_bridgefor_generated" + KEY_DEC
       + "        MoiArc::<flutter_rust_bridge::for_generated::RustAutoOpaqueInner<UaKey>>::decrement_strong_count(ptr as _);\n")]),
    # the controller's
    ("secrets wiped on success only (superseded by 037d5a29: SecretBytes, t13c-secrets)", []),
    # M5 (T18 refresh): 22d978ce (T15c2) reads the bits once into `f` and also refuses a vectors build
    ("load: any required feature bit passes", [(DW, "if (f & kRequiredFeatures != kRequiredFeatures ||",
                                                "if (f & kRequiredFeatures == BigInt.zero ||")]),
    ("kemEphemeral runs without the load check", [(DW, "Future<g.UaKemKey> kemEphemeral() => _loaded(g.kemEphemeral);",
                                                   "Future<g.UaKemKey> kemEphemeral() => g.kemEphemeral();")]),
    ("a version outside u64 not refused before frb wraps it", [(DW, "    v.isNegative || v.bitLength > 64 ? throw const UAError(code: 'UAArgument', reason: '') : v;",
                                                                "    v;")]),
    ("unlock: the passphrase tried first when both are given", [(RW, "    if let Some(p) = prf32 {\n",
                                                                 "    if let Some(v) = vault_passphrase {\n        return Ok(uw::Unlock::VaultPassphrase(text(v)?));\n    }\n"
                                                                 "    if let Some(p) = prf32 {\n")]),
    ("the UA prefix of a wallet error code dropped", [(RW, "e => UAError { code: format!(\"UA{}\", e.code()), reason: String::new() },",
                                                        "e => UAError { code: e.code().to_string(), reason: String::new() },")]),
    ("the seed-backup answers not wiped (superseded by 037d5a29: SecretBytes, t13c-secrets)", []),
]

if sys.argv[1:] == ["check"]:
    for name, reps in M:
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
for n, (name, reps) in enumerate(M[lo - 1:hi], lo):
    if not reps:
        print(f"superseded | M{n} {name}", flush=True)
        continue
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
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    failed = sorted(set(re.findall(r"test/\w+\.dart: (.+?) \[E\]", out)))
    last = re.findall(r"^\d\d:\d\d \+(\d+)(?: ~\d+)?(?: -(\d+))?: ", out, re.M)
    counts = f"+{last[-1][0]} -{last[-1][1] or 0}" if last else "no count (crashed)"
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)} | {counts}",
          flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
rc, _ = run(BUILD)  # the tree's own library again
raise SystemExit(1 if bad or rc else 0)
