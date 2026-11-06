#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T12: the C ABI v6 tests (clients/ua-c: the lib tests, tests/header.rs, tests/test_vectors.py through ctypes,
tests/asan-smoke.sh) and the T12 decoders' caps (clients/ua-rs tests/fuzz_caps.rs) catch a change in what they test. One mutant
per run on a clean tree (one or more replacements), its suite run, every file restored byte for byte after it. A mutant whose
library does not build is NOT-LOADED (it kills nothing); a mutant whose suite passes SURVIVED: both are findings (exit 1).
A kill by a test target that does not compile counts only where that is the test (a static trait bound: M2).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t12-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t12-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

C = "clients/ua-c/"
UA = "clients/ua-rs/"
LIB = C + "src/lib.rs"
W = UA + "src/wallet/mod.rs"
SEAL = UA + "src/wallet/seal.rs"
UASIG = UA + "src/wallet/uasig.rs"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo"]
BUILD_C = (C, CARGO + ["build", "-j2", "--locked", "--offline"])
BUILD_UA = (UA, CARGO + ["build", "-j2", "--locked", "--offline", "--features", "vectors"])


def py(*classes):
    """test_vectors.py classes, after the debug library is rebuilt."""
    return [BUILD_C, (C, ["python3", "-m", "unittest"] + [f"tests.test_vectors.{c}" for c in classes])]


LIBTEST = [(C, CARGO + ["test", "-j2", "--locked", "--offline", "--lib"])]
HEADER = [(C, CARGO + ["test", "-j2", "--locked", "--offline", "--test", "header"])]
ASAN = [(C, [CAPPED, "tests/asan-smoke.sh"])]
CAPS = [(UA, CARGO + ["test", "-j2", "--locked", "--offline", "--features", "vectors", "--test", "fuzz_caps"])]
FEATURES_ = "        let on = |x: bool, bit: u64| if x { bit } else { 0 };"
FREE = "impl Drop for Wallet {\n    fn drop(&mut self) {\n        self.store.lock();\n"
M = [
    # the plan's T12 list
    ("an error string echoes its input (the vault JSON)", [(LIB, "    Ok(uw::Vault::from_json(cstr(json)?)?)",
        "    uw::Vault::from_json(cstr(json)?).map_err(|e| Fail(Fail::from(e).0, String::from_utf8_lossy(cstr(json).unwrap_or_default()).into_owned()))")],
     py("WalletErrors")),
    ("ZeroizeOnDrop removed from a handle's inner type (SeedBackup)", [(W, "impl zeroize::ZeroizeOnDrop for SeedBackup {}\n", "")], LIBTEST),
    ("KIND_UNAVAILABLE folded into KIND_UNKNOWN", [
        (LIB, "            E::KindUnavailable => SCAAS_UA_ERR_KIND_UNAVAILABLE,", "            E::KindUnavailable => SCAAS_UA_ERR_KIND_UNKNOWN,"),
        (LIB, "        let _ = (key_ref_json, cb, out);\n        Err(fail(SCAAS_UA_ERR_KIND_UNAVAILABLE))",
         "        let _ = (key_ref_json, cb, out);\n        Err(fail(SCAAS_UA_ERR_KIND_UNKNOWN))")], py("WalletAbi")),
    ("the catch_unwind wrapper dropped from one export (scaas_ua_features)", [
        (LIB, "pub extern \"C\" fn scaas_ua_features() -> u64 {\n    safe(0, || {", "pub extern \"C\" fn scaas_ua_features() -> u64 {\n    (|| {"),
        (LIB, "            | on(b::MLOCK, SCAAS_UA_FEATURE_MLOCK)\n    })\n}", "            | on(b::MLOCK, SCAAS_UA_FEATURE_MLOCK)\n    })()\n}")], HEADER),
    ("wallet_free frees the store under live children", [(W, FREE, FREE +
        "        for _ in 1..std::sync::Arc::strong_count(&self.store) {\n"
        "            unsafe { std::sync::Arc::decrement_strong_count(std::sync::Arc::as_ptr(&self.store)) };\n        }\n")], ASAN),
    # the controller's
    ("catch_unwind removed from the one guard", [(LIB, "    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(Fail(SCAAS_UA_ERR_INTERNAL, \"UAInternal: panic\".into())))",
        "    f()")], LIBTEST),
    ("both unlock secrets: the passphrase first", [(LIB, "    if !prf32.is_null() {\n        return Ok(uw::Unlock::Prf(arr(prf32)?));\n    }",
        "    if !prf32.is_null() && vault_passphrase.is_null() {\n        return Ok(uw::Unlock::Prf(arr(prf32)?));\n    }")], py("WalletVault")),
    ("accepted_json ignored: every member accepted", [(LIB, "        let accepted = |id: [u8; 32], i: u16| self.accepted.as_ref().is_some_and(|a| a.accepted(id, i));",
        "        let accepted = |_: [u8; 32], _: u16| true;")], py("WalletSeal.test_seal_json_acceptance")),
    ("members_json ignored", [(LIB, "        let members = |id: [u8; 32]| self.members.lookup(id);", "        let members = |_: [u8; 32]| None;")],
     py("WalletSeal.test_seal_json_containers")),
    ("restore: installed always true (the None flag lost)", [(LIB, "        put(installed, r.is_some())?;", "        put(installed, true)?;")],
     py("WalletSeal.test_seal_json_replay_backup_rows_and_the_none_flag")),
    ("restore_backup_rollback without its marker", [(LIB, "    let allow = Some(uw::AllowRollback);", "    let allow = None;")],
     py("WalletSeal.test_seal_json_replay_backup_rows_and_the_none_flag")),
    ("sign_digest_raw on a UA key: Argument, not RawDigestRefused", [(LIB, "        Key::Ua(_) => Err(fail(SCAAS_UA_ERR_RAW_DIGEST_REFUSED)),",
        "        Key::Ua(_) => Err(argument(\"a native key\")),")], py("WalletSign.test_sign_digest_raw_on_a_ua_key_is_RawDigestRefused")),
    ("WalletLocked reported as KeyRevoked", [(LIB, "            E::WalletLocked => SCAAS_UA_ERR_WALLET_LOCKED,", "            E::WalletLocked => SCAAS_UA_ERR_KEY_REVOKED,")],
     py("WalletCustody.test_lock_revokes_and_unlock_does_not_revive")),
    ("the link session not consumed on a failed install", [(LIB, "        let taken = lock(&s.0)?.take().ok_or_else(|| fail(SCAAS_UA_ERR_KEY_REVOKED))?;",
        "        let taken = uw::LinkSession::new()?;\n        drop(lock(&s.0)?);")], py("WalletSeal.test_link_session_is_consumed")),
    ("seed_backup_reveal without its capacity check (a short buffer reveals)", [(LIB,
        "        need(out_len, SCAAS_UA_MNEMONIC_MAX)?;\n        let words = lock(&b.0)?.reveal()?;", "        let words = lock(&b.0)?.reveal()?;")],
     py("WalletCustody.test_seed_backup_sequence")),
    ("the mlock bit never set", [(LIB, "            | on(b::MLOCK, SCAAS_UA_FEATURE_MLOCK)", "            | on(false, SCAAS_UA_FEATURE_MLOCK)")], LIBTEST),
    ("expect / members / accepted JSON past 16 KiB read", [(SEAL, "const LOOKUP_JSON: usize = 16 << 10;", "const LOOKUP_JSON: usize = 16 << 20;")], CAPS),
    ("expect / members / accepted JSON depth 5 read", [(SEAL, "const LOOKUP_DEPTH: usize = 4;", "const LOOKUP_DEPTH: usize = 5;")], CAPS),
    ("an approved set past 64 UAs read", [(SEAL, "            let l = l.as_array().filter(|l| l.len() <= SET_MAX)?;", "            let l = l.as_array()?;")], CAPS),
    ("UASig request depth 7 read", [(UASIG, "const REQUEST_DEPTH: usize = 6;", "const REQUEST_DEPTH: usize = 7;")], CAPS),
    ("expect_json read past an unknown key", [(SEAL, "    let o = only(v, &[\"purpose\", \"sender\", \"recipient\"])?;", "    let o = v.as_object()?;")], CAPS),
    ("UASig request: msig slots in another order than given (sorted)", [(UASIG,
        "            By::Msig { key_data: h(m.get(\"keyData\")?)?, inner, slots: slots.iter().map(slot).collect::<Option<_>>()? }",
        "            let mut slots: Vec<(u16, SlotBy)> = slots.iter().map(slot).collect::<Option<_>>()?;\n            slots.sort_by_key(|s| s.0);\n"
        "            By::Msig { key_data: h(m.get(\"keyData\")?)?, inner, slots }")], py("WalletSign.test_sign_json_msig_rows_through_uasig")),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(steps):
    out, rc = "", 0
    for cwd, cmd in steps:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        out += r.stdout + r.stderr
        rc = r.returncode
        if rc:
            break
    return rc, out


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
        # the mutated library builds (else it kills nothing), then its suite
        lrc, lout = run([BUILD_UA if any(f.startswith(UA) for f in orig) and not any(f.startswith(C) for f in orig) else BUILD_C])
        rc, out = run(suite) if lrc == 0 else (lrc, lout)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^(?:---- (.+?) stdout ----|(?:FAIL|ERROR): (\S+))", out, re.M)))
    failed = [a or b for a, b in failed]
    asan = "ERROR: AddressSanitizer" in out
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    where = ", ".join(sorted(orig))
    extra = " | AddressSanitizer: " + (re.search(r"AddressSanitizer: ([\w-]+)", out) or [None, "?"])[1] if asan else ""
    codes = sorted(set(re.findall(r"^error\[(E\d+)\]", out, re.M)))  # a test target that does not compile (M2: E0277)
    extra += f" | test build: {', '.join(codes)}" if codes and not lrc else ""
    print(f"{verdict} | M{n} {name} | {where} | rc={rc}{extra} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
