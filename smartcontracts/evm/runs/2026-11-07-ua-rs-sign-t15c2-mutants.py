#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15c2 (ARCH-POS-13 follow-ups of T15c; spec no-decryption-oracle §4.7, §4.8, §9; Codex C1, C3, C7; Fable P2-5,
P3-1, P3-3): each mutant undoes one guard of T15c2 and names the check that must catch it. One mutant per run on a clean tree,
its command, every file restored byte for byte after it (the caller also runs `git diff --exit-code` on the paths). Kind
"test": a failing command kills, a build that does not compile is NOT-LOADED (a finding); kind "build": the guard is the
compiler, so a refused build (the named error code) kills. A mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15c2-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15c2-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R, ZP, C, Q = "clients/ua-rs/", "clients/zether-prover/", "clients/ua-c/", "clients/ua-rs/src/facade/pqz.rs"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
V = '#[cfg(feature = "vectors")]\n'
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
QT = os.path.expanduser(os.environ.get("QT_DIR", "~/usr/Qt/6.12.0/gcc_64"))  # the Qt kit of ua-qt's build (QMAKE, libraries)
SH = lambda s: ["bash", "-c", s]

PQZ_P33 = (R, CARGO + ["--test", "facade_pqz", "raw_requests_compile_only_under_vectors"])
PQZ_P31 = (R, CARGO + ["--test", "facade_pqz", "disclose_sender_compares_in_constant_time"])
PQZ_BUILD = (R, [CAPPED, "cargo", "build", "--locked", "--offline", "-j2", "--lib"])
MARKER = (R, CARGO + ["--features", "vectors", "--test", "vectors_marker"])
ZP_DOC = (ZP, CARGO + ["--doc"])
ZP_SRC = (ZP, CARGO + ["--test", "call_with_key", "hazmat_helpers_are_not_pub"])
ZP_DEFAULT = (ZP, CARGO + ["--test", "call_with_key", "hazmat_is_off_by_default"])
CHECK = (".", ["python3", "-I", "scripts/check_test_features.py"])
PY = ("clients/ua-py", ["python3", "-m", "unittest", "tests.test_wallet.Load"])
GO = ("clients/ua-go", [CAPPED, "go", "test", "-count=1", "-run", "TestLoadRefusesWrongAbiOrFeatures", "./wallet/"])
CS = ("clients/ua-cs", SH(f"{CAPPED} dotnet test Scaas.Ua.Tests --filter LoadRefusesWrongAbiOrFeatures; r=$?; dotnet build-server shutdown >/dev/null 2>&1; exit $r"))
CXX = lambda t: ("clients/ua-cxx", SH(f"{CAPPED} sh -c 'cmake --build build -j2 && ctest --test-dir build --output-on-failure -R {t}'"))
DART_LOAD = ("clients/ua-dart-frb", [CAPPED, "dart", "test", "test/wallet_test.dart", "-N", "load_refuses_wrong_abi_or_features"])
DART_Z = ("clients/ua-dart-frb", SH(f"{CAPPED} sh -c 'cargo build --locked --offline -j2 --manifest-path rust/Cargo.toml && dart test test/wallet_test.dart -N zether_facade'"))
QTT = ("clients/ua-qt", SH(f"QMAKE={QT}/bin/qmake6 LD_LIBRARY_PATH={QT}/lib QT_QPA_PLATFORM=offscreen {CAPPED} sh -c 'cmake --build build -j2 && ./build/tst_ua'"))

TOML_UAC = C + "Cargo.toml"
ZBOTH = [(R + "src/facade/zether.rs", "    " + V + "    \"decrypt\",\n", "    \"decrypt\",\n"),
         (ZP + "src/api.rs", "if !cfg!(feature = \"hazmat\") && HAZMAT.contains(&cmd) {", "if false && HAZMAT.contains(&cmd) {")]
M = [
    # Codex C1: the binding load checks (one per binding), the key-handle marker, the production-artifact check
    ("ua-py: check_build accepts a vectors build", [("clients/ua-py/scaas_ua/wallet.py", "    if features & FEATURE['vectors']:", "    if False and features & FEATURE['vectors']:")], PY, "test"),
    ("ua-go: CheckBuild accepts a vectors build", [("clients/ua-go/wallet/wallet.go", "if features&FeatureVectors != 0 {", "if features&FeatureVectors == 42 {")], GO, "test"),
    ("ua-cs: CheckBuild accepts a vectors build", [("clients/ua-cs/Scaas.Ua/Wallet.cs", "if ((features & FeatureVectors) != 0) throw", "if ((features & FeatureVectors) == 42) throw")], CS, "test"),
    ("ua-cxx: load() accepts a vectors build", [("clients/ua-cxx/src/wallet.cpp", " || (f & feature::kVectors)) throw", ") throw")], CXX("wallet_load_refuses"), "test"),
    ("ua-cxx's load() accepting a vectors build, seen through ua-qt", [("clients/ua-cxx/src/wallet.cpp", " || (f & feature::kVectors)) throw", ") throw")], QTT, "test"),
    ("ua-dart-frb: load() accepts a vectors build", [("clients/ua-dart-frb/lib/src/wallet.dart", " || f & BigInt.from(UaFeature.vectors) != BigInt.zero) {", ") {")], DART_LOAD, "test"),
    ("ua-rs: key handles in a vectors build without the marker", [(R + "src/facade/mod.rs", "    if !UNLOCKED.load(", "    if false && !UNLOCKED.load(")], MARKER, "test"),
    ("check_test_features: the graph check finds nothing", [("scripts/check_test_features.py", "            if depth == 1 and f and f.group(1) == pkg and f.group(2) in TEST:", "            if False:")], CHECK, "test"),
    ("check_test_features: the manifest check of dependencies finds nothing", [("scripts/check_test_features.py", "for f in feats if pkg in GUARDED and f in TEST]", "for f in feats if False]")], CHECK, "test"),
    ("ua-c's manifest asks for scaas-ua/vectors (a real violation)", [(TOML_UAC, 'features = ["json", "wallet"] }', 'features = ["json", "wallet", "vectors"] }')], CHECK, "test"),
    # Codex C7: hazmat reached from default through another feature
    ("zether-prover: default reaches hazmat through a feature", [(ZP + "Cargo.toml", "\nhazmat = []\n", "\ndefault = [\"std-tools\"]\nstd-tools = [\"hazmat\"]\nhazmat = []\n")], ZP_DEFAULT, "test"),
    # Codex C3: a helper left pub; the macro's release arm pub
    ("zether-prover: open_memo_json left pub", [(ZP + "src/api.rs", "fn open_memo_json<C: ZCurve>(v: &Value) -> R<Value> {\n    open_memo_with::<C>(None, v)\n}\n}\n",
                                                "fn open_memo_json_inner<C: ZCurve>(v: &Value) -> R<Value> {\n    open_memo_with::<C>(None, v)\n}\n}\npub fn open_memo_json<C: ZCurve>(v: &Value) -> R<Value> {\n    open_memo_with::<C>(None, v)\n}\n")], ZP_DOC, "test"),
    ("zether-prover: open_sender_cp left pub", [(ZP + "src/schnorr.rs", "hazmat_pub! {\n/// `SENDER_CP`", "/// `SENDER_CP`"),
                                                (ZP + "src/schnorr.rs", "fn open_sender_cp<C: ZCurve, R: RngCore + CryptoRng>(", "pub fn open_sender_cp<C: ZCurve, R: RngCore + CryptoRng>("),
                                                (ZP + "src/schnorr.rs", "    cp_open(e, amount, OpeningKind::SenderCp, s, rng)\n}\n}\n", "    cp_open(e, amount, OpeningKind::SenderCp, s, rng)\n}\n")], ZP_SRC, "test"),
    ("zether-prover: hazmat_pub!'s release arm pub", [(ZP + "src/lib.rs", "        #[allow(dead_code)]\n        $(#[$m])*\n        pub(crate) fn $($t)*", "        #[allow(dead_code)]\n        $(#[$m])*\n        pub fn $($t)*")], ZP_DOC, "test"),
    # Fable P3-3: Req::Dec in a release build
    ("PQZ: the Req::Dec variant compiled in release (run()'s match is no longer exhaustive)",
     [(Q, V + "    Dec { ct: Vec<u8>, window: usize },", "    Dec { ct: Vec<u8>, window: usize },")], PQZ_BUILD, "build"),
    ("PQZ: Req::Dec, its req() and run() arms compiled in release (the gated helpers refuse to build)",
     [(Q, V + "    Dec { ct: Vec<u8>, window: usize },", "    Dec { ct: Vec<u8>, window: usize },"), (Q, "        " + V + "        \"dec\" => {\n", "        \"dec\" => {\n"),
      (Q, "            " + V + "            Req::Dec { ct, window } => {", "            Req::Dec { ct, window } => {")], PQZ_BUILD, "build"),
    ("PQZ: the `dec` allow-list arm compiled in release (it compiles: the source assertion)",
     [(Q, "        " + V + "        \"dec\" => has(", "        \"dec\" => has(")], PQZ_P33, "test"),
    # Fable P3-1: the constant-time compare reverted
    ("PQZ: disclose_sender's ConstantTimeEq back to !=", [(Q, "        let v_eq = c.0.vs.get(i).map_or(Choice::from(0), |x| x[..].ct_eq(v));\n        if !bool::from(c.0.u[..].ct_eq(u) & v_eq) {",
                                                           "        if c.0.u[..] != *u || c.0.vs.get(i).map(|x| &x[..]) != Some(v) {")], PQZ_P31, "test"),
    # Fable P2-5: the Zether raw-command assertions of ua-cxx and ua-dart-frb see `decrypt` back in the release list
    # (both layers: with only the facade's list mutated, zether-prover's own gate still refuses and a binding sees UAArgument)
    ("Zether: `decrypt` back in the facade's release list and zether-prover's gate removed, seen through ua-cxx", ZBOTH, CXX("wallet_zether_facade"), "test"),
    ("Zether: `decrypt` back in the facade's release list and zether-prover's gate removed, seen through ua-dart-frb", ZBOTH, DART_Z, "test"),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, f, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)

NOT_BUILT = re.compile(r"^error(\[E\d+\])?: could not compile|ninja: build stopped|\[build failed\]|error CS\d+|Compilation failed|"
                       r"^Error: Compilation", re.M)
BUILD_KILL = re.compile(r"^error\[E0(004|425|599|412|433|422|560)\]", re.M)


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
                    | set(re.findall(r"^--- FAIL: (\S+)", out, re.M)) | set(re.findall(r"FINDING: (.+)", out))
                    | set(re.findall(r"^\s*\d+/\d+ Test +#\d+: (\S+) .*\*\*\*Failed", out, re.M))
                    | set(re.findall(r"^FAIL! +: (\S+)", out, re.M)) | set(re.findall(r"Failed (\S+) \[", out))
                    | set(re.findall(r"^error\[(E\d+)\]", out, re.M)) | set(re.findall(r": (\w+) \[E\]", out)))
    if kind == "build":
        verdict = "killed    " if rc != 0 and BUILD_KILL.search(out) else "SURVIVED  "
    else:
        verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:400]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
