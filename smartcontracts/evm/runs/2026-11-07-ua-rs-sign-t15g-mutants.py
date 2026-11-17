#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15g (ARCH-POS-13; spec no-decryption-oracle §4.3, §4.7, §4.13, §5): each mutant undoes one guard of the
bindings' words-command tests and names the check that must catch it: a binding that stops passing a field, a refusal mapped
to a second status (one per binding), a membership test reverted to equality, a raw form moved out of `vectors` in the source,
the fuzz command index not taken from COMMANDS. One mutant per run on a clean tree, its command, every file restored byte for
byte after it (the caller also runs `git diff --exit-code`). A failing command kills, a build that does not compile is
NOT-LOADED (a finding), a passing command SURVIVED (a finding, exit 1). Order matters: the mutants that rebuild a library
from mutated source come last (the release libscaas_ua_c, ua-cxx's and ua-dart-frb's builds are rebuilt by the gates after).
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15g-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15g-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R, Q, Z = "clients/ua-rs/", "clients/ua-rs/src/facade/pqz.rs", "clients/ua-rs/src/facade/zether.rs"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
SH = lambda s: ["bash", "-c", s]
REL = f"{CAPPED} cargo build --release --locked --offline -j2 --manifest-path ../ua-c/Cargo.toml"

PY = lambda c: ("clients/ua-py", ["python3", "-m", "unittest", f"tests.test_wallet.{c}.test_words_commands_on_the_forge_rows"])
PY_REL = lambda c: ("clients/ua-py", SH(f"{REL} && python3 -m unittest tests.test_wallet.{c}.test_words_commands_on_the_forge_rows"))
GO = lambda t, rel="": ("clients/ua-go", SH(f"{rel + ' && ' if rel else ''}{CAPPED} go test -count=1 -run {t} ./wallet/"))
CS = lambda t, rel="": ("clients/ua-cs", SH(f"{rel + ' && ' if rel else ''}{CAPPED} dotnet test Scaas.Ua.Tests --filter {t}; r=$?; dotnet build-server shutdown >/dev/null 2>&1; exit $r"))
CXX = lambda t: ("clients/ua-cxx", SH(f"{CAPPED} sh -c 'cmake --build build -j2 && ctest --test-dir build --output-on-failure -R {t}'"))
DART = lambda t: ("clients/ua-dart-frb", SH(f"{CAPPED} sh -c 'cargo build --locked --offline -j2 --manifest-path rust/Cargo.toml && dart test test/wallet_test.dart -N {t}'"))
UAC = lambda c: ("clients/ua-c", SH(f"{CAPPED} cargo build --locked --offline -j2 && python3 -m unittest tests.test_vectors.{c}.test_words_commands_on_the_forge_rows"))
# seeds.py --regress must succeed and leave the committed command-index inputs as they are (manifest/ is left out: a drift
# older than T15g, restored with the rest)
REGRESS = (".", SH("python3 -I clients/ua-rs/fuzz/seeds.py --regress >/dev/null && git diff --quiet -- clients/ua-rs/fuzz/regress/zether_cmd "
                   "clients/ua-rs/fuzz/regress/pqz_cmd; r=$?; git checkout -q -- clients/ua-rs/fuzz/regress; "
                   "[ $r = 0 ] || echo 'FINDING: seeds.py failed or the regress inputs moved (their command index)'; exit $r"))
FUZZ_CAPS = (R, CARGO + ["--features", "vectors", "--test", "fuzz_caps"])

KEYBIND = (Q, "        if c.key.as_ref().is_some_and(|k| *k != self.pk) {\n            return Err(Error::Argument);",
           "        if c.key.as_ref().is_some_and(|k| *k != self.pk) {\n            return Err(Error::KeyRevoked);")
PREPARE = (Z, "let p = zether_prover::state::prepare(c.cmd, &v, &y).map_err(|_| Error::Argument)?;",
           "let p = zether_prover::state::prepare(c.cmd, &v, &y).map_err(|_| Error::KeyRevoked)?;")
PSID = (Q, "    if *id == PQZL_ID || (pqz_ffi::PQZH && *id == PQZH_ID) {\n        Ok(*id)\n    } else {\n        Err(Error::PqzSetMismatch)",
        "    if *id == PQZL_ID || (pqz_ffi::PQZH && *id == PQZH_ID) {\n        Ok(*id)\n    } else {\n        Err(Error::Argument)")
AD, ADX = '"\\"accountData\\""', '"\\"accountDatum\\""'
M = [
    # a binding that stops passing a field (the Zether words round trip; each binding's own code, no library rebuilt)
    ("ua-py: ZetherKey.call drops accountData", [("clients/ua-py/scaas_ua/wallet.py", "_text(cmd), _text(request), cap=1 << 20)",
                                                 "_text(cmd), _text({f: x for f, x in request.items() if f != 'accountData'}), cap=1 << 20)")], PY("Zether"), "test"),
    ("ua-go: ZetherKey.Call renames accountData", [("clients/ua-go/wallet/wallet.go", "zkp(p), a.str(cmd), a.str(request),", f"zkp(p), a.str(cmd), a.str(strings.Replace(request, {AD}, {ADX}, 1)),"),
                                                   ("clients/ua-go/wallet/wallet.go", '\t"fmt"\n\t"runtime"\n', '\t"fmt"\n\t"runtime"\n\t"strings"\n')], GO("TestZetherWordsOnTheForgeRows"), "test"),
    ("ua-cs: ZetherKey.Call renames accountData", [("clients/ua-cs/Scaas.Ua/Wallet.cs", "        var r = a.Str(request);\n        return UaLib.OutStr(1 << 20, (o, ref n) => Native.scaas_ua_zether_call(",
                                                    f"        var r = a.Str(request.Replace({AD}, {ADX}));\n        return UaLib.OutStr(1 << 20, (o, ref n) => Native.scaas_ua_zether_call(")], CS("ZetherWordsOnTheForgeRows"), "test"),
    # a membership test reverted to equality
    ("ua-py: COMMANDS membership reverted to equality", [("clients/ua-py/tests/test_wallet.py", "        for c in ('balance', 'pendingBalance'):\n            self.assertIn(c, release)\n",
                                                          "        self.assertEqual(release, ['balance', 'pendingBalance'])\n")], PY("Zether"), "test"),
    ("ua-go: COMMANDS membership reverted to equality", [("clients/ua-go/wallet/wallet_test.go", 'if !in(release, "balance") || !in(release, "pendingBalance") || !in(raw, "decrypt")',
                                                          'if fmt.Sprint(release) != "[balance pendingBalance]" || !in(raw, "decrypt")')], GO("TestZetherWordsOnTheForgeRows"), "test"),
    ("ua-dart-frb: COMMANDS membership reverted to equality", [("clients/ua-dart-frb/test/wallet_test.dart", "    expect(release, containsAll(['balance', 'pendingBalance']));",
                                                                "    expect(release, ['balance', 'pendingBalance']);")], DART("zether_words"), "test"),
    # a raw form moved out of `vectors` in the source (the binding reads the list; the library is not rebuilt)
    ("Zether: `decrypt` no longer under vectors in COMMANDS, seen through ua-py", [(Z, '    #[cfg(feature = "vectors")]\n    "decrypt",\n', '    "decrypt",\n')], PY("Zether"), "test"),
    # the fuzz command index not taken from COMMANDS
    ("seeds.py: the Zether command index is not COMMANDS (its last command dropped)", [(R + "fuzz/seeds.py", 'ZCMDS = commands("zether")\n', 'ZCMDS = commands("zether")[:-1]\n')], REGRESS, "test"),
    ("fuzz_caps: the source rule skips the raw forms", [(R + "tests/fuzz_caps.rs", ".filter(|l| l.starts_with('\"'))", ".filter(|l| l.starts_with('\"') && !l.contains(\"raw\"))")], FUZZ_CAPS, "test"),
    # a binding that stops passing a field (the binding's Rust side or the C ABI: rebuilt from the mutated source)
    ("ua-cxx: zether_call renames accountData", [("clients/ua-cxx/src/wallet.rs", "fn zether_call(k: &ZetherKey, cmd: &str, request_json: &str) -> R<String> {\n    guard(|| Ok(k.0.call(cmd, request_json.as_bytes())?))",
                                                  f"fn zether_call(k: &ZetherKey, cmd: &str, request_json: &str) -> R<String> {{\n    guard(|| Ok(k.0.call(cmd, request_json.replacen({AD}, {ADX}, 1).as_bytes())?))")], CXX("wallet_zether_words"), "test"),
    ("ua-dart-frb: UaZetherKey.call renames accountData", [("clients/ua-dart-frb/rust/src/api/wallet.rs", "        Ok(self.0.call(&cmd, request_json.as_bytes())?)\n    }\n    pub fn seal_balance_cache(&self, entries_json:",
                                                            f"        Ok(self.0.call(&cmd, request_json.replacen({AD}, {ADX}, 1).as_bytes())?)\n    }}\n    pub fn seal_balance_cache(&self, entries_json:")], DART("zether_words"), "test"),
    ("ua-c: scaas_ua_zether_call renames accountData", [("clients/ua-c/src/lib.rs", "&zether(k)?.call(text(cmd)?, cstr(request_json)?)?);",
                                                         f"&zether(k)?.call(text(cmd)?, String::from_utf8_lossy(cstr(request_json)?).replacen({AD}, {ADX}, 1).as_bytes())?);")], UAC("WalletZether"), "test"),
    # a refusal mapped to a second status (scaas-ua; one per binding, each through its library rebuilt)
    ("PQZ: the key-binding refusal as KeyRevoked, through ua-py", [KEYBIND], PY_REL("Pqz"), "test"),
    ("Zether: the words refusal as KeyRevoked, through ua-go", [PREPARE], GO("TestZetherWordsOnTheForgeRows", REL), "test"),
    ("PQZ: the psid refusal as Argument, through ua-cs", [PSID], CS("PqzWordsOnTheForgeRows", REL), "test"),
    ("Zether: the words refusal as KeyRevoked, through ua-cxx", [PREPARE], CXX("wallet_zether_words"), "test"),
    ("PQZ: the key-binding refusal as KeyRevoked, through ua-dart-frb", [KEYBIND], DART("pqz_words"), "test"),
    ("PQZ: the psid refusal as Argument, through the C ABI (ua-c test_vectors.py)", [PSID], UAC("WalletPqz"), "test"),
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
