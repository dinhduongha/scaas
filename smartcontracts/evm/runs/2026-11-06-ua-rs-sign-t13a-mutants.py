#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T13a (ua-cxx, the wallet over the Rust API): the load check, the secret wipes, the handle ownership and the binding's
own rules are caught by tests/wallet_test.cpp under ctest. One mutant per run on a clean tree (one or more replacements), the
build (cargo through CMake, then the C++), the named ctest cases, every file restored byte for byte after it. A mutant whose
build fails is NOT-LOADED (it kills nothing); a mutant whose cases pass SURVIVED: both are findings (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13a-mutants.py [first last]   (from the worktree root, foreground;
                                                                                            needs clients/ua-cxx/build configured)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t13a-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

X = "clients/ua-cxx/"
RS = X + "src/wallet.rs"
CPP = X + "src/wallet.cpp"
HPP = X + "include/scaas_ua.hpp"
CAPPED = os.path.abspath("scripts/capped")
BUILD = [CAPPED, "cmake", "--build", X + "build", "-j2"]


def cases(*names):
    return [CAPPED, "ctest", "--test-dir", X + "build", "--output-on-failure", "-R", "^wallet_(" + "|".join(names) + ")$"]


LOAD, WIPE, ONCE = "load_refuses_wrong_abi_or_features", "secret_buffer_wiped_after_call", "handle_freed_once"
M = [
    # the plan's three
    ("load: the abi_version check skipped", [(CPP, '    if (detail::reportedAbiVersion() != kAbiVersion) throw Error("UAAbiMismatch", "abi_version");\n', "")],
     cases(LOAD)),
    ("a secret buffer not wiped: from_mnemonic's words and passphrase", [(RS, "    wipe(&mut [words, bip39_passphrase]);\n", "")], cases(WIPE)),
    ("a handle freed twice: the move leaves the source owning", [(HPP, "    Handle(Handle&& o) noexcept : p_(std::exchange(o.p_, nullptr)) {}",
                                                                  "    Handle(Handle&& o) noexcept : p_(o.p_) {}")], cases(ONCE)),
    # the controller's
    # M4, M5 (T18 refresh): 9dc7fba7 (T15c2) reads the bits once into `f` and also refuses a vectors build; the required-bits
    # half of the condition is mutated, the vectors half (T15c2's own mutants) kept
    ("load: the features check skipped", [(CPP, "if ((f & kRequiredFeatures) != kRequiredFeatures || (f & feature::kVectors))",
                                           "if ((f & feature::kVectors))")], cases(LOAD)),
    ("load: any required bit passes", [(CPP, "if ((f & kRequiredFeatures) != kRequiredFeatures || (f & feature::kVectors))",
                                        "if ((f & kRequiredFeatures) == 0 || (f & feature::kVectors))")], cases(LOAD)),
    ("load: a factory runs without it (fromMnemonic)", [(CPP, "Wallet Wallet::fromMnemonic(Secret& words, Secret& bip39Passphrase) {\n    load();\n",
                                                          "Wallet Wallet::fromMnemonic(Secret& words, Secret& bip39Passphrase) {\n")], cases(LOAD)),
    ("a secret wiped on success only", [(RS, "    wipe(&mut [words, bip39_passphrase]);\n    r\n",
                                          "    if r.is_ok() {\n        wipe(&mut [words, bip39_passphrase]);\n    }\n    r\n")], cases(WIPE)),
    ("Secret::wipe a no-op (an output secret kept)", [(CPP, "void Secret::wipe() noexcept { zero(b_.data(), b_.size()); }",
                                                         "void Secret::wipe() noexcept {}")], cases(WIPE)),
    ("open_vault's passphrase not wiped", [(RS, "    wipe(&mut [vault_passphrase, prf32, bip39_passphrase]);\n    r\n}\nfn wallet_unlock",
                                           "    wipe(&mut [prf32, bip39_passphrase]);\n    r\n}\nfn wallet_unlock")], cases(WIPE)),
    ("an imported key's secret not wiped", [(RS, "    let r = guard(|| Ok(key(KeyInner::Native(w.0.import_native_key(network(net)?, secret)?))));\n    wipe(&mut [secret]);\n",
                                            "    let r = guard(|| Ok(key(KeyInner::Native(w.0.import_native_key(network(net)?, secret)?))));\n")], cases(WIPE)),
    ("the seed-backup answers not wiped", [(RS, "    wipe(&mut [word1, word2, word3]);\n", "    wipe(&mut [word1, word2]);\n")],
     cases("seed_backup_sequence")),
    ("rewrap_pin's passphrases not wiped", [(RS, "    wipe(&mut [old_passphrase, new_passphrase]);\n", "")], cases(WIPE)),
    ("a move assignment does not free the handle it overwrites", [(HPP, "        if (this != &o) {\n            reset();\n            p_ = std::exchange(o.p_, nullptr);",
                                                                   "        if (this != &o) {\n            p_ = std::exchange(o.p_, nullptr);")], cases(ONCE)),
    ("a moved-from handle used (no UAArgument)", [(HPP, '        if (!p_) throw Error("UAArgument", "");\n        return *p_;',
                                                    "        return *p_;")], cases(ONCE)),
    ("unlock: the passphrase before the PRF secret", [(RS, "    if !prf32.is_empty() {\n        return Ok(uw::Unlock::Prf(",
                                                       "    if !prf32.is_empty() && vault_passphrase.is_empty() {\n        return Ok(uw::Unlock::Prf(")],
     cases("vault_json")),
    ("restore over a wallet ignores it (no rollback refusal)", [(RS,
        "    restore(kk, container_json, expect_json, members_json, accepted_json, Some(current), None, bip39_passphrase)",
        "    let _ = current;\n    restore(kk, container_json, expect_json, members_json, accepted_json, None, None, bip39_passphrase)")],
     cases("backup_link_restore")),
    ("raw digest on a UA key: Argument, not RawDigestRefused", [(RS, '        KeyInner::Ua(_) => Err(UaErr("UARawDigestRefused".into())),',
                                                                "        KeyInner::Ua(_) => Err(argument()),")], cases("sign_json")),
    ("a wallet error loses its UA prefix", [(RS, '            e => UaErr(format!("UA{}", e.code())),', "            e => UaErr(e.code().into()),")],
     cases("custody")),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


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
        lrc, lout = run(BUILD)
        rc, out = run(suite) if lrc == 0 else (lrc, lout)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^\s+\d+ - (\S+) \(", out, re.M)))
    why = sorted(set(re.findall(r"wallet_test\.cpp:\d+: (.{0,80})", out)))[:2]
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    where = ", ".join(sorted(orig))
    print(f"{verdict} | M{n} {name} | {where} | rc={rc} | {len(failed)} failed: {', '.join(failed)} | {'; '.join(why)}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
# the tree's own build again, so the next step starts from the unmutated library
rc, _ = run(BUILD)
raise SystemExit(1 if bad or rc else 0)
