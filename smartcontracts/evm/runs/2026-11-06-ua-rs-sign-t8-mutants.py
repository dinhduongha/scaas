#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T8: AEAD, HKDF, HMAC, seal / open and the sealed containers (tests/wallet_seal.rs: seal.json every row, the
acceptance and link rows, NIST GCM, RFC 8452, RFC 5869, RFC 4231, the refusals) catch a change in what they test. One mutant per
run on a clean tree (one or more replacements), its suite run, every file restored byte for byte after it; a mutant that does not
compile is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t8-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t8-mutants.py check           (every replacement found once, no run)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
S = UA + "src/wallet/seal.rs"
A = UA + "src/wallet/aead.rs"
U8 = UA + "src/ua8.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_seal"]
INFO = "    let info = [SEAL_INFO, &[1], &be16(p.len())?, p, &keccak256(kem_pk)].concat();"
SEAL_AEAD = "    let ciphertext = aead_seal(Alg::Aes256Gcm, &key, &[0; 12], aad, pt)?;"
OPEN_AEAD = "        aead_open(Alg::Aes256Gcm, &key, &[0; 12], aad, &s.ciphertext).map_err(|_| Error::SealOpen)"
EXPECT = "    if c.purpose != expect.purpose || c.recipient != expect.recipient || kk.recipient() != expect.recipient {"
SINGLE = "        auth.members.is_empty() && crate::verify::verify(kind, &auth.key_data, &m0, &auth.signature, false)"
MSIG_OK = "        auth.signature.is_empty() && msig_ok(&c.sender_ua, &auth.key_data, &m0, &auth.members, members, accepted)?"
ACC1 = "    accepted_ok(id, d, slots.iter().map(|s| s.index), accepted)?;\n"
ACC2 = "            accepted_ok(&m.id, key, s.members.iter().map(|x| x.index), accepted)?;\n"
WINDOW = "    if c.created < s.start || c.created > s.start.saturating_add(LINK_WINDOW) {"
MIN1 = "    if !msig_slots_minimal(key_data, &slots.iter().map(|s| s.index).collect::<Vec<_>>())? {\n        return Ok(false);"
MIN2 = "            if !msig_slots_minimal(&d, &s.members.iter().map(|x| x.index).collect::<Vec<_>>())? {"
M = [
    # the plan's T8 list
    ("kemPkHash left out of the HKDF info", [(S, INFO, "    let _ = kem_pk;\n    let info = [SEAL_INFO, &[1], &be16(p.len())?, p].concat();")], SUITE),
    ("purpose left out of the HKDF info", [(S, INFO, "    let info = [SEAL_INFO, &[1], &keccak256(kem_pk)].concat();")], SUITE),
    ("aad ignored (seal and open)", [(S, SEAL_AEAD, SEAL_AEAD.replace(" aad, pt)", " &[], pt)")),
        (S, OPEN_AEAD, OPEN_AEAD.replace(" aad, &s.ciphertext)", " &[], &s.ciphertext)"))], SUITE),
    ("open returns plaintext on a bad tag (the ciphertext without its tag)", [(A, "    out.map(Zeroizing::new).map_err(|_| Error::Aead)",
        "    out.map(Zeroizing::new).or_else(|_| Ok(Zeroizing::new(data.get(..data.len().saturating_sub(16)).unwrap_or_default().to_vec())))")], SUITE),
    ("container sender signature unchecked (single key)", [(S, SINGLE, "        auth.members.is_empty()")], SUITE),
    ("msig sender with a non-minimal set accepted (level 1)", [(U8, MIN1, MIN1.replace("    if !msig_slots_minimal(", "    if false && !msig_slots_minimal("))], SUITE),
    ("msig sender with a non-minimal set accepted (level 2)", [(U8, MIN2, MIN2.replace("if !msig_slots_minimal(", "if false && !msig_slots_minimal("))], SUITE),
    ("single-key UASig with members accepted", [(S, SINGLE, "        crate::verify::verify(kind, &auth.key_data, &m0, &auth.signature, false)")], SUITE),
    ("member acceptance skipped (level 1)", [(S, ACC1, "")], SUITE),
    ("member acceptance skipped (level 2)", [(S, ACC2, "")], SUITE),
    ("accepted weight counted over the signers, not the accepted ones", [(S, "        .filter(|i| accepted(*id, *i))\n", "")], SUITE),
    ("a missing accepted treated as all accepted", [(S, "        let accepted = accepted.ok_or(Error::ContainerSender)?;",
        "        let all = |_: [u8; 32], _: u16| true;\n        let accepted: &Accepted = accepted.unwrap_or(&all);")], SUITE),
    ("short code left out of the link aad", [(S, "        aad.extend(Sha256::digest(code.as_bytes()));\n", "        let _ = code;\n")], SUITE),
    ("expected sender ignored", [(S, "    if !allowed.contains(&c.sender_ua) {", "    if allowed.is_empty() {")], SUITE),
    ("purpose expectation skipped", [(S, EXPECT, EXPECT.replace("c.purpose != expect.purpose || ", ""))], SUITE),
    ("recipient expectation skipped (the container's recipient field)", [(S, EXPECT, EXPECT.replace("c.recipient != expect.recipient || ", ""))], SUITE),
    ("recipient expectation skipped (the opening key's own)", [(S, EXPECT, EXPECT.replace(" || kk.recipient() != expect.recipient", ""))], SUITE),
    ("derive_ua recomputation skipped (any kind whose key data parses)", [(S,
        "    let derives = |k: &u16| derive_ua(*k, &auth.key_data, false).ok() == Some(c.sender_ua);",
        "    let derives = |k: &u16| derive_ua(*k, &auth.key_data, false).is_ok();")], SUITE),
    ("link window not checked", [(S, WINDOW, "    if false {")], SUITE),
    # the controller's
    ("link window: lower bound only", [(S, WINDOW, "    if c.created < s.start {")], SUITE),
    ("link window: upper bound only", [(S, WINDOW, "    if c.created > s.start.saturating_add(LINK_WINDOW) {")], SUITE),
    ("scheme byte of the HKDF info changed (2)", [(S, INFO, INFO.replace("&[1]", "&[2]"))], SUITE),
    ("seal version / scheme not checked by open", [(S, "        if s.version != 1 || s.scheme != 1 {\n            return Err(Error::SealVersion);",
        "        if false {\n            return Err(Error::SealVersion);")], SUITE),
    ("plaintext over 1 MiB sealed", [(S, "    if pt.len() > MAX_PT {\n        return Err(Error::Argument);\n    }\n    let (mlkem_ct", "    let (mlkem_ct")], SUITE),
    ("purpose charset not checked", [(S, "&& p.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'/' | b'-'))", "")], SUITE),
    ("the sender signs the aad only (wire form left out)", [(S, "    keccak256(&[aad, &s.to_wire()].concat())", "    let _ = s;\n    keccak256(aad)")], SUITE),
    ("msig sender's own signature allowed", [(S, MSIG_OK, MSIG_OK.replace("auth.signature.is_empty() && ", ""))], SUITE),
    ("msig member of an msig with a signature of its own allowed", [(S,
        "            s.sig.is_empty() && !s.members.is_empty() && s.members",
        "            !s.members.is_empty() && s.members")], SUITE),
    ("approved sender set unbounded", [(S, "        ExpectedSender::Set(s) if s.len() <= SET_MAX => s,", "        ExpectedSender::Set(s) if true => s,")], SUITE),
    ("MD-11: Recipient::ua accepts a non-holder (an msig)", [(S, "        if !is_kem_holder(kind) {\n            return Err(Error::KemHolder);",
        "        if !is_kem_holder(kind) && kind != 0x0120 {\n            return Err(Error::KemHolder);")], SUITE),
    ("link session key not wiped", [(S, "        session.key.wipe_own_store();\n", "")], SUITE),
    ("GCM-SIV computed as GCM", [(A, "        Alg::Aes256GcmSiv => aes_gcm_siv::Aes256GcmSiv::new_from_slice(key).map_err(|_| Error::Argument)?.encrypt(nonce.into(), p),",
        "        Alg::Aes256GcmSiv => aes_gcm::Aes256Gcm::new_from_slice(key).map_err(|_| Error::Argument)?.encrypt(nonce.into(), p),")], SUITE),
    ("HMAC key ignored", [(A, "    let Ok(mut m) = <Hmac<Sha256> as Mac>::new_from_slice(key) else { return [0; 32] };",
        "    let Ok(mut m) = <Hmac<Sha256> as Mac>::new_from_slice(&key[..0]) else { return [0; 32] };")], SUITE),
    ("HKDF salt ignored", [(A, "    expand(&Hkdf::<Sha256>::new(Some(salt), ikm), info, len)", "    let _ = salt;\n    expand(&Hkdf::<Sha256>::new(None, ikm), info, len)")], SUITE),
    ("container JSON length bound raised (64 MiB)", [(S, "const CONTAINER_JSON: usize = 4 << 20;", "const CONTAINER_JSON: usize = 64 << 20;")], SUITE),
]
assert len({m[0] for m in M}) == len(M)
srcs = {f: open(f, encoding="utf-8").read() for _, reps, _ in M for f, _, _ in reps}
for name, reps, _ in M:
    new = dict(srcs)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, f, a, new[f].count(a))
        new[f] = new[f].replace(a, b)
if sys.argv[1:] == ["check"]:
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
        r = subprocess.run(suite, capture_output=True, text=True, cwd=UA)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    out = r.stdout + r.stderr
    loaded = "could not compile `scaas-ua` (lib" not in out and "could not compile `scaas-ua` (test" not in out \
        and "failed to run custom build command" not in out
    failed = sorted(set(re.findall(r"^---- (.+?) stdout ----", out, re.M)))
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    where = ", ".join(sorted({f.removeprefix(UA) for f, _, _ in reps}))
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
