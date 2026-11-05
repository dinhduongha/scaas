#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T3a: the classic-curve signers' tests (tests/wallet_sign.rs: sign.json ua / member / chainSeparation rows, the
external RFC 6979 answers, keys.json addresses, the role rule, the refusals) catch a change in what they test. One mutant per run
on a clean tree (one or more replacements in one file), the suite run, the file restored byte for byte after it; a mutant that
does not compile is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t3a-mutants.py [first last]   (from the worktree root, foreground)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
S, D = UA + "src/wallet/sign.rs", UA + "src/wallet/derive.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_sign"]
K1 = "let (sig, rec) = sk.sign_prehash_recoverable(arr32(msg)?);"
# a fixed RNG of rand_core 0.10 (k256's generation) for the hedged mutants: RFC 6979 with additional data, as noble's
# `extraEntropy: true`
HEDGE = ("struct H;\n"
         "impl k256::ecdsa::signature::rand_core::TryRng for H {\n"
         "    type Error = core::convert::Infallible;\n"
         "    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> { Ok(1) }\n"
         "    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> { Ok(1) }\n"
         "    fn try_fill_bytes(&mut self, d: &mut [u8]) -> core::result::Result<(), Self::Error> { d.fill(1); Ok(()) }\n"
         "}\n"
         "impl k256::ecdsa::signature::rand_core::TryCryptoRng for H {}\n")
P1 = "let sig: p256::ecdsa::Signature = sk.sign_prehash(&Sha256::digest(msg)).map_err(|_| Error::Argument)?;"
M = [
    # the plan's T3a list
    ("low-s removed (P-256)", S, [("Ok(sig.normalize_s().to_bytes().to_vec())", "Ok(sig.to_bytes().to_vec())")]),
    ("v offset 27 lost", S, [("out.push(27 + rec.to_byte());", "out.push(rec.to_byte());")]),
    ("prehash added for 0x0108", S, [(K1, "let (sig, rec) = sk.sign_prehash_recoverable(&Sha256::digest(msg));")]),
    ("prehash removed for 0x0101", S, [(P1, P1.replace("&Sha256::digest(msg)", "msg"))]),
    ("purpose tag v1 for pop v2", S, [("ua_msg: ua_message(self.kind, purpose, digest)?",
                                       "ua_msg: ua_message(self.kind, &(if *purpose == pop_v2_tag() { purpose_tag(\"pop\")? } else { *purpose }), digest)?")]),
    ("another kind's TAG", S, [("ua_msg: ua_message(self.kind, purpose, digest)?", "ua_msg: ua_message(self.kind ^ 1, purpose, digest)?")]),
    # the controller's additions
    ("extraEntropy (hedged RFC 6979) on secp256k1", S, [(K1, HEDGE + "let (sig, rec) = sk.sign_prehash_recoverable_with_rng(&mut H, arr32(msg)?).map_err(|_| Error::Rng)?;")]),
    ("extraEntropy (hedged RFC 6979) on P-256", S, [(P1, HEDGE + "use p256::ecdsa::signature::hazmat::RandomizedPrehashSigner;\n"
                                                     "let sig: p256::ecdsa::Signature = sk.sign_prehash_with_rng(&mut H, &Sha256::digest(msg)).map_err(|_| Error::Argument)?;")]),
    ("BIP-340 release aux constant", S, [("(Scheme::Bip340, None) => Some(os_aux()?),", "(Scheme::Bip340, None) => Some([0u8; 32]),")]),
    ("BIP-340 aux of the caller ignored", S, [("let sig = sk.sign_raw(msg, aux.ok_or(Error::Argument)?)", "let sig = sk.sign_raw(msg, &[7u8; 32])")]),
    ("role ignored (always authorization)", S, [("role: role_of(purpose) })", "role: SigRole::Authorization })")]),
    ("kem not a PoP role", S, [("[\"kem\", \"pqz-key\"]", "[\"pqz-key\"]")]),
    ("address checksum dropped (EIP-55)", D, [("out.push(if k > '7' { c.to_ascii_uppercase() } else { c });", "out.push(c);")]),
    # beyond both lists
    ("bech32 checksum constant dropped", D, [("    chk ^= 1;\n", "")]),
    ("StrKey crc big-endian", D, [("crc.to_le_bytes()", "crc.to_be_bytes()")]),
    ("Sui flag byte dropped", D, [("[&[0u8][..], public_key].concat()", "public_key.to_vec()")]),
    ("purpose check skipped", S, [("if !known {", "if false {")]),
    ("seal purpose accepted by sign_ua", S, [("let known = *purpose == pop_v2_tag() ||",
                                              "let known = *purpose == pop_v2_tag() || *purpose == keccak256(b\"scaas.ua.purpose.seal.v1\") ||")]),
    ("kind check of the request skipped", S, [("if *kind != self.kind {", "if false {")]),
    ("member purpose wrong", S, [("purpose_tag(\"member\")?", "purpose_tag(\"membership\")?")]),
    ("key-proof prefix changed", S, [("b\"scaas-subject-key-proof-v1\"", "b\"scaas-subject-key-proof-v2\"")]),
    ("ed25519 native signed as secp256k1", S, [("if self.network.ed25519() { Scheme::Ed25519 } else { Scheme::Secp256k1 }", "Scheme::Secp256k1")]),
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
    loaded = "could not compile" not in out
    failed = sorted(set(re.findall(r"^---- (\S+) stdout ----", out, re.M)))
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    print(f"{verdict} | M{n} {name} | {f.removeprefix(UA)} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:160]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
