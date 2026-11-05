#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T7: the UA KEM key, the combiner, the encapsulation and decapsulation checks (tests/wallet_kem.rs: kem.json every
row, ACVP ML-KEM-1024 keyGen / encapDecap, RFC 7748, the self-test record per store, revocation, C-05) catch a change in what they
test. One mutant per run on a clean tree (one or more replacements), its suite run, every file restored byte for byte after it; a
mutant that does not compile is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t7-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t7-mutants.py check           (every replacement found once, no run)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
K = UA + "src/wallet/kem.rs"
S = UA + "src/wallet/store.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_kem"]
INFO = "        .expand_multi_info(&[LABEL, ua, &version.to_be_bytes()], &mut okm)"
ZERO_ENC = "    if *ss_x == [0; 32] {\n        return Err(Error::KemCheck); // a small-order pk_X\n    }\n"
ZERO_DEC = "    if *ss_x == [0; 32] {\n        return Err(Error::KemCheck); // a small-order E: not contributory\n    }\n"
CT = "    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(mlkem_ct).map_err(|_| Error::KemCheck)?; // 1,568 bytes"
TESTED_OLD = """        if !arena.tested.contains(&id) {
            test(arena.get(self.slot)?)?;
            arena.tested.insert(id);"""
TESTED_NEW = """        static TESTED: std::sync::Mutex<Vec<KeyId>> = std::sync::Mutex::new(Vec::new());
        let mut tested = TESTED.lock().unwrap_or_else(PoisonError::into_inner);
        if !tested.contains(&id) {
            test(arena.get(self.slot)?)?;
            tested.push(id);"""
DERIVE_GEN = """        let mut g = self.store.write();
        if g.generation != self.generation {
            return Err(Error::KeyRevoked);
        }
        let arena = g.arena.as_mut().ok_or(Error::KeyRevoked)?;
        self.store.key_in("""
GEN = "        if g.generation != self.generation {\n            return Err(Error::KeyRevoked);\n        }\n"
SELF_GEN = """        let mut g = self.store.write();
        if g.generation != self.generation {
            return Err(Error::KeyRevoked);
        }
        let arena = g.arena.as_mut().ok_or(Error::KeyRevoked)?;
        if !arena.tested.contains(&id) {"""
M = [
    # the plan's T7 list
    ("modulus check removed (every coefficient accepted)", [(K, "    ek.len() == EK && ek.get(..1536).is_some_and(|t| t.chunks(3).all(lt_q))",
        "    let _ = lt_q;\n    ek.len() == EK")], SUITE),
    ("all-zero ss_X accepted (encaps)", [(K, ZERO_ENC, "")], SUITE),
    ("all-zero ss_X accepted (decaps)", [(K, ZERO_DEC, "")], SUITE),
    ("decaps length check removed (mlkem_ct zero-padded or cut to 1,568 bytes)", [(K, CT,
        "    let mut ct = ml_kem::Ciphertext::<MlKem1024>::default();\n"
        "    ct.iter_mut().zip(mlkem_ct).for_each(|(d, s)| *d = *s);")], SUITE),
    ("combiner fields reordered (ss_X before ss_M)", [(K, "    for part in [ss_m, ss_x, e, pk_x, LABEL] {",
        "    for part in [ss_x, ss_m, e, pk_x, LABEL] {")], SUITE),
    ("combiner without E", [(K, "    for part in [ss_m, ss_x, e, pk_x, LABEL] {", "    let _ = e;\n    for part in [ss_m, ss_x, pk_x, LABEL] {")], SUITE),
    ("label changed (scaas.kem.2)", [(K, 'const LABEL: &[u8] = b"scaas.kem.1";', 'const LABEL: &[u8] = b"scaas.kem.2";')], SUITE),
    ("KEM key derived for an msig (0x0120 a holder)", [(K, "    crate::is_pqz_holder(kind)\n", "    crate::is_pqz_holder(kind) || kind == 0x0120\n")], SUITE),
    ("KEM version ignored", [(K, INFO, "        .expand_multi_info(&[LABEL, ua, &0u64.to_be_bytes()], &mut okm)")], SUITE),
    ("self-test record process-wide instead of per store", [(S, TESTED_OLD, TESTED_NEW)], SUITE),
    # the controller's
    ("version little-endian (le64)", [(K, INFO, "        .expand_multi_info(&[LABEL, ua, &version.to_le_bytes()], &mut okm)")], SUITE),
    ("ua left out of the HKDF info", [(K, INFO, "        .expand_multi_info(&[LABEL, &version.to_be_bytes()], &mut okm)")], SUITE),
    ("salt changed (scaas.ua.kem.v2)", [(K, 'const SALT: &[u8] = b"scaas.ua.kem.v1";', 'const SALT: &[u8] = b"scaas.ua.kem.v2";')], SUITE),
    ("holder check removed (any kind with a UA)", [(K, "            Some(ua) if is_kem_holder(self.kind) => ua,", "            Some(ua) => ua,")], SUITE),
    ("scheme byte not checked", [(K, "    if kem_pk.first() != Some(&1) || kem_pk.len() != KEM_PK_LEN {", "    if kem_pk.len() != KEM_PK_LEN {")], SUITE),
    ("kem_key on a revoked handle derives from the reopened store (generation checks of derive and self_test removed)",
        [(S, DERIVE_GEN, DERIVE_GEN.replace(GEN, "")), (S, SELF_GEN, SELF_GEN.replace(GEN, ""))], SUITE),
    ("decapsulation-key check always true", [(K, "        (DK, Some(ek), Some(h)) => <[u8; 32]>::from(Sha3_256::digest(ek)).as_slice() == h,",
        "        (DK, Some(_), Some(_)) => true,")], SUITE),
    ("ephemeral key from a fixed seed (no OS randomness)", [(K, "        OsRng.try_fill_bytes(&mut s).map_err(|_| Error::Rng)?;\n", "")], SUITE),
    ("pk_X of the combiner taken from E (decaps)", [(K, "    let ss = combine(&ss_m, &ss_x, eph, pk_x);", "    let _ = pk_x;\n    let ss = combine(&ss_m, &ss_x, eph, eph);")], SUITE),
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
    # a doc test that does not compile is a test failure, not a crate that failed to build
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
