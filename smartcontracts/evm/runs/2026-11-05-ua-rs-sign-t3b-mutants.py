#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T3b: the PQ signers' tests (tests/wallet_pq.rs: pq_kat.json keys and signatures, sign.json PQ rows, ACVP sigGen,
release randomness, signed bytes per scheme, the arena form, rs_signatures.json; tests/wallet_keys.rs: keys.json Falcon rows;
tests/pq.rs and tests/ua8.rs: the verifiers on the vendored PQClean) catch a change in what they test. One mutant per run on a
clean tree (one or more replacements in one file), the suite run, the file restored byte for byte after it; a mutant that does
not compile is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t3b-mutants.py [first last]   (from the worktree root, foreground)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
P, F, C = UA + "src/wallet/pqsign.rs", UA + "src/falcon.rs", UA + "vendor/pqclean-falcon-seeded/seeded.c"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors",
         "--test", "wallet_pq", "--test", "wallet_keys", "--test", "pq", "--test", "ua8"]
OS = "None => OsRng.try_fill_bytes(&mut rnd).map_err(|_| Error::Rng)?,"
M = [
    # the plan's T3b list
    ("Falcon signs pq_msg", P, [("let m = signed_message(kind, ua_msg);", "let m = crate::keccak(&[&crate::tag(kind)?, ua_msg]).to_vec();")]),
    ("ML-DSA context non-empty", P, [("sk.expanded_key().sign_internal(mp, &rnd)",
                                      "sk.expanded_key().sign_internal(&[&[0, 1, 0x63], mp.last().copied().unwrap_or_default()], &rnd)")]),
    ("ML-DSA rnd fixed in a release build", P, [(OS, "None if rnd.len() == 32 => {}\n        " + OS)]),
    ("SLH-DSA M' without the two zero bytes", P, [("0x0133 => slhdsa(secret, &mp, Some(&rnd)),", "0x0133 => slhdsa(secret, &[&m], Some(&rnd)),")]),
    # the controller's additions
    ("SLH-DSA release opt_rand = PK.seed (deterministic)", P, [("0x0133 => slhdsa(secret, &mp, Some(&rnd)),", "0x0133 => slhdsa(secret, &mp, None),")]),
    ("Falcon randomness fixed in a release build", P, [(OS, "None if rnd.len() == 88 => {}\n        " + OS)]),
    ("SLH-DSA arena keeps the 48-byte seed (keygen per signature)", P, [("let secret = Zeroizing::new(b.to_vec());", "let secret = Zeroizing::new(seed.to_vec());")]),
    ("Falcon not routed to the PQ signer", P, [("matches!(kind, 0x0130..=0x0135)", "matches!(kind, 0x0130 | 0x0131 | 0x0133 | 0x0134)")]),
    ("Falcon keygen seed shortened (C)", C, [("inner_shake256_inject(&rng, seed, SEEDLEN);", "inner_shake256_inject(&rng, seed, SEEDLEN - 1);")]),
    ("Falcon verify: non-zero padding accepted (C)", C, [("                if (sigbuf[v++] != 0) {\n                    return -1;\n                }\n",
                                                          "                v++;\n")]),
    ("Falcon verify: unpadded length accepted", F, [("if pk.len() != p.pk || sig.len() != p.sig {\n        return false;\n    }\n    #[cfg(scaas_falcon)]\n    {\n        // SAFETY: `pk`",
                                                     "if pk.len() != p.pk || sig.len() > p.sig {\n        return false;\n    }\n    #[cfg(scaas_falcon)]\n    {\n        // SAFETY: `pk`")]),
    ("Falcon nonce not hashed with the message (C)", C, [("    memcpy(nonce, rnd, NONCELEN);\n\n    inner_shake256_init(&sc);\n    inner_shake256_inject(&sc, nonce, NONCELEN);",
                                                          "    memcpy(nonce, rnd, NONCELEN);\n\n    inner_shake256_init(&sc);")]),
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
    print(f"{verdict} | M{n} {name} | {f.removeprefix(UA)} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:160]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
