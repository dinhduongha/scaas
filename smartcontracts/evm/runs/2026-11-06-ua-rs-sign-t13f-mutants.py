#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T13f: the ua-cs binding's tests (clients/ua-cs Scaas.Ua.Tests/WalletTests.cs over Scaas.Ua/Wallet.cs and libscaas_ua_c)
catch a change in what they test. One mutant per run on a clean tree (one or more replacements), its tests run (dotnet test --filter,
through scripts/capped, then dotnet build-server shutdown), every file restored byte for byte after it. A mutant that does not build is
NOT-LOADED (it kills nothing); a mutant whose tests pass SURVIVED: both are findings (exit 1). Needs clients/ua-c/target/release.
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13f-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13f-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

CS = "clients/ua-cs/"
WC = CS + "Scaas.Ua/Wallet.cs"
CAPPED = os.path.abspath("scripts/capped")


def t(*names):
    return [CAPPED, "dotnet", "test", "Scaas.Ua.Tests", "--filter", "|".join(f"FullyQualifiedName~WalletTests.{n}" for n in names)]


M = [
    # the plan's T13 list
    ("the load check skipped", [(WC, "            CheckBuild(AbiVersionHook(Native.scaas_ua_abi_version()), Native.scaas_ua_features());\n", "")],
     t("LoadRefusesWrongAbiOrFeatures")),
    ("a secret buffer not wiped (every call)", [(WC, "        foreach (var x in _wipes) CryptographicOperations.ZeroMemory(x);\n", "")],
     t("SecretBufferWipedAfterCall")),
    ("a handle freed twice (an eager free in Dispose beside ReleaseHandle)", [(WC, "    protected abstract void Free(IntPtr p);\n",
        "    protected abstract void Free(IntPtr p);\n    protected override void Dispose(bool disposing) { if (!IsInvalid) Free(handle); base.Dispose(disposing); }\n")],
     t("HandleFreedExactlyOnce")),
    # the controller's
    ("the feature check skipped (ABI only)", [(WC, "        if ((features & need) != need || features >= FeatureEnd ||", "        if (false && (features & need) != need || false && features >= FeatureEnd || false &&")],
     t("LoadRefusesWrongAbiOrFeatures")),
    ("a constructor skips the load check (FromMnemonic)", [(WC,
        "    public static Wallet FromMnemonic(byte[] words, byte[]? bip39Passphrase = null)\n    {\n        UaLib.Load();\n",
        "    public static Wallet FromMnemonic(byte[] words, byte[]? bip39Passphrase = null)\n    {\n")], t("LoadRefusesWrongAbiOrFeatures")),
    ("a refused library marked loaded", [(WC,
        "            CheckBuild(AbiVersionHook(Native.scaas_ua_abi_version()), Native.scaas_ua_features());\n            _loaded = true;\n",
        "            _loaded = true;\n            CheckBuild(AbiVersionHook(Native.scaas_ua_abi_version()), Native.scaas_ua_features());\n")],
     t("LoadRefusesWrongAbiOrFeatures")),
    ("a secret copied outside the hook (never wiped)", [(WC, "        var x = UaLib.SecretBuf(b.Length + 1);", "        var x = GC.AllocateArray<byte>(b.Length + 1, pinned: true);")],
     t("SecretBufferWipedAfterCall")),
    ("Wipe does nothing", [(WC, "        if (b is not null) CryptographicOperations.ZeroMemory(b);", "        _ = b;")], t("SecretBufferWipedAfterCall")),
    ("a 31-byte PRF secret passed (an over-read)", [(WC, "    public byte* OptSized(byte[]? b, int n, string what) => b is null ? null : Sized(b, n, what);",
        "    public byte* OptSized(byte[]? b, int n, string what) => b is null ? null : Pin(b);")], t("FixedSizeAndShortSecretsAreRefused")),
    ("an 11-byte nonce passed (an over-read)", [(WC, "        var nn = a.Sized(nonce, 12, \"nonce\");", "        var nn = a.Pin(nonce);")],
     t("FixedSizeAndShortSecretsAreRefused")),
    ("restore ignores `installed` (an equal generation installs)", [(WC, "        return installed != 0 ? new Wallet(w) : null;", "        return new Wallet(w);")],
     t("SealJsonReplayBackupRows")),
    ("RestoreBackupRollback calls restore_backup", [(WC, "        Wallet? current = null, byte[]? bip39Passphrase = null) => Restore(true,",
        "        Wallet? current = null, byte[]? bip39Passphrase = null) => Restore(false,")], t("SealJsonReplayBackupRows")),
    ("a backup recipient's ephemeral flag dropped", [(WC, "Ephemeral = (byte)(r.Ephemeral ? 1 : 0) };", "Ephemeral = 0 };")],
     t("BackupSealRestoresAWallet")),
    ("UASig keys reversed", [(WC, "                ps[i] = keys[i].H.DangerousGetHandle();", "                ps[keys.Count - 1 - i] = keys[i].H.DangerousGetHandle();")],
     t("SignJsonMsigThroughUASig")),
    ("Take hands out entropy that was not taken", [(WC, "        if (taken == 0) return null;\n", "")], t("SeedBackupSequence")),
    ("a key's Dispose frees nothing (a call after it reaches the library)", [(WC,
        "    internal WalletKey(KeyHandle h) => H = h;\n    public void Dispose() => H.Dispose();", "    internal WalletKey(KeyHandle h) => H = h;\n    public void Dispose() { }")],
     t("UseAfterDisposeNeverReachesTheLibrary")),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)

bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, suite) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = subprocess.run(suite, cwd=CS, capture_output=True, text=True)
        rc, out = r.returncode, r.stdout + r.stderr
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
        subprocess.run(["dotnet", "build-server", "shutdown"], cwd=CS, capture_output=True)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    lrc = 1 if re.search(r"error CS\d+", out) else 0
    failed = sorted(set(re.findall(r"^\s*Failed (Scaas\.Ua\.Tests\.\S+)", out, re.M)))
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
