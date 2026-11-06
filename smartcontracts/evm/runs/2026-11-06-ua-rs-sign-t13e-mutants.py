#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T13e: the ua-go binding's tests (clients/ua-go wallet/wallet_test.go over wallet/wallet.go and libscaas_ua_c) catch a
change in what they test. One mutant per run on a clean tree (one or more replacements), its tests run (go test -count=1 -run),
every file restored byte for byte after it. A mutant that does not build is NOT-LOADED (it kills nothing); a mutant whose tests
pass SURVIVED: both are findings (exit 1). Needs clients/ua-c/target/release/libscaas_ua_c.so.
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13e-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13e-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

GO = "clients/ua-go/"
WG = GO + "wallet/wallet.go"
CAPPED = os.path.abspath("scripts/capped")


def t(*names):
    return [CAPPED, "go", "test", "-count=1", "-timeout", "600s", "-run", "^(" + "|".join(names) + ")$", "./wallet/"]


M = [
    # the plan's T13 list
    ("the load check skipped", [(WG,
        "\tif err := CheckBuild(abiVersionHook(uint32(C.scaas_ua_abi_version())), uint64(C.scaas_ua_features())); err != nil {\n\t\treturn err\n\t}\n", "")],
     t("TestLoadRefusesWrongAbiOrFeatures")),
    ("a secret buffer not wiped (every call)", [(WG, "\tfor _, x := range a.wipes {\n\t\tWipe(x)\n\t}", "\tfor _, x := range a.wipes {\n\t\t_ = x\n\t}")],
     t("TestSecretBufferWipedAfterCall")),
    ("a handle freed twice (Close does not clear the pointer)", [(WG, "\tp := h.p\n\th.p = nil\n\th.mu.Unlock()", "\tp := h.p\n\th.mu.Unlock()")],
     t("TestHandleFreedExactlyOnce")),
    # the controller's
    ("no finalizer set", [(WG, "\truntime.SetFinalizer(o, func(o T) { o.hd().Close() })\n", "")], t("TestHandleFreedExactlyOnce")),
    ("a constructor skips the load check (FromMnemonic)", [(WG,
        "func FromMnemonic(words, bip39Passphrase []byte) (*Wallet, error) {\n\tif err := Load(); err != nil {\n\t\treturn nil, err\n\t}\n",
        "func FromMnemonic(words, bip39Passphrase []byte) (*Wallet, error) {\n")], t("TestLoadRefusesWrongAbiOrFeatures")),
    ("the feature check skipped (ABI only)", [(WG, "\tif features&need != need || features >= featureEnd ||", "\tif false && features&need != need || false && features >= featureEnd || false &&")],
     t("TestLoadRefusesWrongAbiOrFeatures")),
    ("Close does not wait for a call in flight", [(WG, "\th.mu.Lock()\n\tp := h.p\n\th.p = nil\n\th.mu.Unlock()", "\tp := h.p\n\th.p = nil")],
     t("TestCloseWaitsForACallInFlight")),
    ("a call on a closed handle reaches the library", [(WG, "\th.mu.RLock()\n\tdefer h.mu.RUnlock()\n\tif h.p == nil {\n\t\treturn ErrClosed\n\t}\n\treturn f(h.p)",
        "\th.mu.RLock()\n\tdefer h.mu.RUnlock()\n\treturn f(h.p)")], t("TestUseAfterCloseNeverReachesTheLibrary")),
    ("a secret copied outside the hook (never wiped)", [(WG, "\tx := secretBuf(len(b) + 1)", "\tx := make([]byte, len(b)+1)")],
     t("TestSecretBufferWipedAfterCall")),
    ("Wipe does nothing", [(WG, "\tfor i := range b {\n\t\tb[i] = 0\n\t}\n\truntime.KeepAlive(b)", "\truntime.KeepAlive(b)")],
     t("TestSecretBufferWipedAfterCall")),
    ("a 31-byte PRF secret passed (an over-read)", [(WG, "\tif b == nil {\n\t\treturn nil, nil\n\t}\n\treturn sized(b, n, what)",
        "\tif b == nil {\n\t\treturn nil, nil\n\t}\n\treturn u8(b), nil")], t("TestFixedSizeAndShortSecretsAreRefused")),
    ("an 11-byte nonce passed (an over-read)", [(WG, "\tnn, err := sized(nonce, 12, \"nonce\")", "\tnn, err := u8(nonce), error(nil)")],
     t("TestFixedSizeAndShortSecretsAreRefused")),
    ("restore ignores `installed` (an equal generation installs)", [(WG, "\tif err != nil || !bool(installed) {", "\tif err != nil {")],
     t("TestSealJSONReplayBackupRows")),
    ("RestoreBackupRollback calls restore_backup", [(WG, "\treturn restore(true, kk,", "\treturn restore(false, kk,")],
     t("TestSealJSONReplayBackupRows")),
    ("a backup recipient's ephemeral flag dropped", [(WG, "ephemeral: C.bool(r.Ephemeral)}", "ephemeral: C.bool(false)}")],
     t("TestBackupSealRestoresAWallet")),
    ("UASig keys reversed", [(WG, "\t\t\tarr[i] = kp(p)", "\t\t\tarr[len(ps)-1-i] = kp(p)")], t("TestSignJSONMsigThroughUASig")),
    ("Take hands out entropy that was not taken", [(WG, "\t}); err != nil || !bool(taken) {", "\t}); err != nil {")],
     t("TestSeedBackupSequence")),
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
        lrc = subprocess.run([CAPPED, "go", "vet", "./wallet/"], cwd=GO, capture_output=True).returncode
        r = subprocess.run(suite, cwd=GO, capture_output=True, text=True) if lrc == 0 else None
        rc, out = (r.returncode, r.stdout + r.stderr) if r else (lrc, "")
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^--- FAIL: (\S+)", out, re.M)))
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
