#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T3c: the pairing kinds' and group sessions' tests (tests/wallet_pairing.rs: sign.json pairing rows, fixed-aux
rows, the nonce map, BLS roles, MuSig2 / FROST sessions, the structural test of secret_mul per secret path; tests/wallet_keys.rs:
keys.json; tests/groups.rs: groups.json byte-equal) catch a change in what they test. One mutant per run on a clean tree (one
or more replacements in one file), the suite run, the file restored byte for byte after it; a mutant that does not compile is
reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t3c-mutants.py [first last]   (from the worktree root, foreground)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
P, D, MU, FR = UA + "src/wallet/pairing.rs", UA + "src/wallet/derive.rs", UA + "src/musig2.rs", UA + "src/frost.rs"
CT = "clients/scaas-ct/src/lib.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors",
         "--test", "wallet_pairing", "--test", "wallet_keys", "--test", "groups"]
BLIND = "let kp = blind(k.as_ref(), P::ScalarField::MODULUS.as_ref(), &rho);"
LOOP = "    for limb in kp.iter().rev() {\n        for j in (0..64).rev() {\n"
M = [
    # the plan's T3c list
    ("nonce reduced from 256 bits", P, [("    hash_to_scalar(&keccak(&[NONCE_TAG, sk, y, ua_msg, aux]))",
                                         "    F::from_be_bytes_mod_order(&keccak(&[NONCE_TAG, sk, y, ua_msg, aux]))")]),
    ("Y left out of the nonce", P, [("&[NONCE_TAG, sk, y, ua_msg, aux]", "&[NONCE_TAG, sk, ua_msg, aux]")]),
    ("secret_mul replaced by Projective * Fr (blinding erased)", CT, [
        ("    let mut rho = Zeroizing::new([0u64; 2]);\n", "    return Ok(base * *secret);\n    #[allow(unreachable_code)]\n    let mut rho = Zeroizing::new([0u64; 2]);\n")]),
    ("k' reduced mod r", CT, [(BLIND, "let kw = blind(k.as_ref(), P::ScalarField::MODULUS.as_ref(), &rho);\n"
                                      "    let kb: Vec<u8> = kw.iter().flat_map(|l| l.to_le_bytes()).collect();\n"
                                      "    let kp = blind(P::ScalarField::from_le_bytes_mod_order(&kb).into_bigint().as_ref(), &[0], &[0, 0]);")]),
    ("ladder width from the bit length of k'", CT, [(LOOP,
        "    let len = (0..LADDER_BITS).rev().find(|i| (kp[i / 64] >> (i % 64)) & 1 == 1).map_or(0, |i| i + 1);\n"
        "    for (n, limb) in kp.iter().enumerate().rev() {\n        for j in (0..64).rev() {\n"
        "            if n * 64 + j >= len {\n                continue;\n            }\n")]),
    ("rho = 0", CT, [(BLIND, "let kp = blind(k.as_ref(), P::ScalarField::MODULUS.as_ref(), &[0, 0]);")]),
    ("keygen G1 bypasses secret_mul", P, [("g1_bytes(&mul(Projective::<P>::generator(), &*scalar::<P::ScalarField>(s)?)?, w, &mut out)?;",
                                           "g1_bytes(&(Projective::<P>::generator() * *scalar::<P::ScalarField>(s)?), w, &mut out)?;")]),
    ("keygen G2 bypasses secret_mul", P, [("let p = mul(Projective::<P>::generator(), &*scalar::<P::ScalarField>(s)?)?.into_affine();",
                                           "let p = (Projective::<P>::generator() * *scalar::<P::ScalarField>(s)?).into_affine();")]),
    ("nonce point bypasses secret_mul", P, [("g1_bytes(&mul(Projective::<P>::generator(), &k)?, w, &mut sig)?;",
                                             "g1_bytes(&(Projective::<P>::generator() * *k), w, &mut sig)?;")]),
    ("BLS sign bypasses secret_mul", P, [
        ("g1_bytes(&mul(h.into_group(), &*scalar(secret)?)?, 64, &mut out)?;",
         "g1_bytes(&(h.into_group() * *scalar::<ark_bls12_381::Fr>(secret)?), 64, &mut out)?;"),
        ("g1_bytes(&mul(h.into_group(), &*scalar(secret)?)?, 32, &mut out)?;",
         "g1_bytes(&(h.into_group() * *scalar::<ark_bn254::Fr>(secret)?), 32, &mut out)?;")]),
    ("MuSig2-bn254 bypasses secret_mul", MU, [('scaas_ct::secret_mul(Self::g(), s).map_err(|_| Error::Value("OS RNG"))', "Ok(Self::g() * *s)")]),
    ("FROST-BN254 bypasses secret_mul", FR, [('Self(scaas_ct::secret_mul(self.0, &s).expect("OS RNG"))', "Self(self.0 * s)")]),
    ("BLS role ignored (always SIG)", P, [("let pop = role == SigRole::Pop;", "let pop = false;")]),
    ("musig2-bn254 on the secp256k1 path", D, [("0x0103 | 0x0108 | 0x0110 =>", "0x0103 | 0x0108 | 0x0110 | 0x0112 =>"),
                                               ("0x0104 | 0x0107 | 0x0112 =>", "0x0104 | 0x0107 =>")]),
    # the controller's additions
    ("masked swap swaps nothing", CT, [("            u64::conditional_swap(x, y, c);\n", "            let _ = (x, y, c);\n")]),
    ("rho the same every call", CT, [(BLIND, "let kp = blind(k.as_ref(), P::ScalarField::MODULUS.as_ref(), &[1, 0]);")]),
    ("MuSig2 session keeps its nonce (read, not spent)", P, [
        ("let k = self.nonce.take().ok_or(Error::Argument)?.take()?;",
         "let k = self.nonce.as_ref().ok_or(Error::Argument)?.with(|b| Zeroizing::new(b.to_vec()))?;")]),
    ("FROST session keeps its nonces", P, [("let n = self.nonces.take().ok_or(Error::Argument)?;", "let n = self.nonces.clone().ok_or(Error::Argument)?;")]),
    ("MuSig2 session without its own key accepted", P, [("        if !pks.contains(&self.key_data) {\n            return Err(Error::Argument);\n        }\n", "")]),
    ("Schnorr challenge without Y", P, [("&[SCHNORR_TAG, &sig, y, ua_msg]", "&[SCHNORR_TAG, &sig, ua_msg]")]),
    ("Schnorr z = k - e*sk", P, [("Zeroizing::new(*k + e * *sk)", "Zeroizing::new(*k - e * *sk)")]),
    ("BLS bn254 label of the other role", P, [("if pop { BN254_LABEL_POP } else { BN254_LABEL_SIG }", "if pop { BN254_LABEL_SIG } else { BN254_LABEL_POP }")]),
]
bad = 0
assert len({m[0] for m in M}) == len(M)
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, f, reps) in enumerate(M[lo - 1:hi], lo):
    src = open(f, encoding="utf-8").read()
    new = src
    for a, b in reps:
        assert new.count(a) == 1, (name, a, new.count(a))
        new = new.replace(a, b)
    open(f, "w", encoding="utf-8").write(new)
    try:
        r = subprocess.run(SUITE, capture_output=True, text=True, cwd=UA)
    finally:
        open(f, "w", encoding="utf-8").write(src)
    assert open(f, encoding="utf-8").read() == src
    out = r.stdout + r.stderr
    loaded = "could not compile" not in out and "failed to run custom build command" not in out
    failed = sorted(set(re.findall(r"^---- (\S+) stdout ----", out, re.M)))
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    where = f.removeprefix(UA).removeprefix("clients/")
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:160]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
