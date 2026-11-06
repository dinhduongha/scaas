#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T12 follow-ups (owner 2026-11-06): the link seal, the members_json cap, the imported keys after unlock and the ASan
script are caught by their tests (clients/ua-rs tests/wallet_link.rs and tests/fuzz_caps.rs, clients/ua-c tests/test_vectors.py,
tests/asan-smoke.sh). One mutant per run on a clean tree (one or more replacements), its suite run, every file restored byte for
byte after it. A mutant whose crate does not build is NOT-LOADED (it kills nothing); a mutant whose suite passes SURVIVED: both
are findings (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t12fu-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t12fu-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

C = "clients/ua-c/"
UA = "clients/ua-rs/"
LIB = C + "src/lib.rs"
MAN = UA + "src/wallet/manifest.rs"
SEAL = UA + "src/wallet/seal.rs"
ASAN_SH = C + "tests/asan-smoke.sh"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo"]
OPTS = ["-j2", "--locked", "--offline"]
BUILD = {
    C: (C, CARGO + ["build"] + OPTS),
    UA: (UA, CARGO + ["build"] + OPTS + ["--features", "vectors"]),
}


def link(*tests):
    """tests/wallet_link.rs (feature vectors), the named tests only."""
    return [(UA, CARGO + ["test"] + OPTS + ["--features", "vectors", "--test", "wallet_link", "--"] + list(tests))]


def py(*classes):
    """test_vectors.py classes, after the debug library is rebuilt."""
    return [BUILD[C], (C, ["python3", "-m", "unittest"] + [f"tests.test_vectors.{c}" for c in classes])]


CAPS = [(UA, CARGO + ["test"] + OPTS + ["--features", "vectors", "--test", "fuzz_caps", "longer"])]
ASAN = [(C, [CAPPED, "tests/asan-smoke.sh"])]
LINK_PY = "WalletSeal.test_link_seal_round_trip"
IMPORT_PY = "WalletCustody.test_imported_key_after_unlock"
M = [
    # 1. the link seal
    ("link_seal raises the backup generation", [(MAN, "        let pt = self.payload(sender, false)?;\n        let r = Recipient::ephemeral",
        "        let pt = self.payload(sender, true)?;\n        let r = Recipient::ephemeral")], link("link_seal_equals_clientkeys_link_row")),
    ("link_seal under the backup purpose", [(MAN, "        seal_container_with(&r, PURPOSE_LINK, &ContainerSigner::Key(sender), created, pt.as_bytes(), Some(short_code), encaps)",
        "        let _ = PURPOSE_LINK;\n        seal_container_with(&r, PURPOSE_BACKUP, &ContainerSigner::Key(sender), created, pt.as_bytes(), None, encaps)")],
     link("link_seal_then_from_link_installs")),
    ("the payload's sender not checked to be this wallet's", [(MAN,
        "        let ua = sender.ua.filter(|_| is_sender_kind(sender.kind) && sender.secret.of_store(&self.store)).ok_or(Error::Argument)?;",
        "        let ua = sender.ua.filter(|_| is_sender_kind(sender.kind)).ok_or(Error::Argument)?;")], link("link_seal_takes_a_container_key_of_this_wallet")),
    ("the link payload without the imported keys", [(MAN, "            let secrets = m\n                .imports\n                .iter()\n",
        "            let secrets = m\n                .imports\n                .iter()\n                .filter(|_| raise)\n")], link("link_seal_then_from_link_installs")),
    ("ua-c: link_seal under a fixed short code", [(LIB,
        "        let c = handle(w)?.0.link_seal(ua_key(handle(sender)?)?, bytes(session_kem_pk, session_kem_pk_len)?, text(short_code)?)?;",
        "        let _ = text(short_code)?;\n        let c = handle(w)?.0.link_seal(ua_key(handle(sender)?)?, bytes(session_kem_pk, session_kem_pk_len)?, \"00000000\")?;")],
     py(LINK_PY)),
    # 2. the members_json cap
    ("members_json back to 16 KiB", [(SEAL, "const MEMBERS_JSON: usize = 512 << 10;", "const MEMBERS_JSON: usize = 16 << 10;")],
     CAPS + link("members_json_holds_64_mldsa87_members_and_no_more")),
    ("members_json past 64 UAs read", [(SEAL, "            .filter(|o| o.len() <= SET_MAX)\n", "")],
     link("members_json_holds_64_mldsa87_members_and_no_more")),
    ("ua-c: members_json read at the expect cap", [(LIB,
        "        let members = if members_json.is_null() { uw::MembersJson::default() } else { uw::MembersJson::from_json(cstr(members_json)?)? };",
        "        let members = if members_json.is_null() { uw::MembersJson::default() } else { let m = cstr(members_json)?; "
        "if m.len() > 16 << 10 { return Err(argument(\"members\")); } uw::MembersJson::from_json(m)? };")],
     py("WalletSeal.test_container_json_inputs_are_bounded")),
    # 3. the imported keys after unlock
    ("ua-c: imported_key ignores its network", [(LIB, "        give(out, ScaasUaKey(Key::Native(handle(w)?.0.imported_key(self::network(network)?, n)?)))",
        "        let _ = self::network(network)?;\n        give(out, ScaasUaKey(Key::Native(handle(w)?.0.imported_key(uw::Network::Evm, n)?)))")], py(IMPORT_PY)),
    ("ua-c: open_label_vault opens nothing", [(LIB, "        Ok(w.0.open_label_vault(&v, unlock(vault_passphrase, prf32)?)?)",
        "        let _ = (w, v, unlock(vault_passphrase, prf32)?);\n        Ok(())")], py(IMPORT_PY)),
    ("ua-c: seal_label_vault seals the manifest whatever the label", [(LIB,
        "    run(|| write_str(out_json, out_len, &handle(w)?.0.seal_label_vault(text(label)?, text(vault_passphrase)?, None)?.to_json()))",
        "    run(|| { let _ = text(label)?; write_str(out_json, out_len, &handle(w)?.0.seal_label_vault(\"manifest\", text(vault_passphrase)?, None)?.to_json()) })")],
     py(IMPORT_PY)),
    # 4. the ASan script: the flag the owner accepted is needed (stable rustc refuses -Zsanitizer without it)
    ("asan-smoke.sh without RUSTC_BOOTSTRAP=1", [(ASAN_SH, "export RUSTC_BOOTSTRAP=1 RUSTFLAGS=", "export RUSTFLAGS=")], ASAN),
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
    crate = next(p for p in (C, UA) if all(f.startswith(p) for f in orig))
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        # the mutated crate builds (else it kills nothing; the ASan script is its own build), then its suite
        lrc, lout = (0, "") if all(f.endswith(".sh") for f in orig) else run([BUILD[crate]])
        rc, out = run(suite) if lrc == 0 else (lrc, lout)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^(?:---- (.+?) stdout ----|(?:FAIL|ERROR): (\S+))", out, re.M)))
    failed = [a or b for a, b in failed]
    flag = re.search(r"the option `Z` is only accepted on the nightly compiler", out)
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    where = ", ".join(sorted(orig))
    extra = " | rustc: -Z only on nightly" if flag else ""
    print(f"{verdict} | M{n} {name} | {where} | rc={rc}{extra} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
