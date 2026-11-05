#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T2: the ua-rs wallet core's tests (tests/wallet_keys.rs: keys.json, BIP-32 / SLIP-10 / EIP-2333 published vectors,
R33, bounded JSON, the secret store) catch a change in what they test. One mutant per run on a clean tree (one or more replacements
in one file), the suite run, the file restored byte for byte after it; a mutant that does not compile is reported as such (it kills
nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t2-mutants.py [first last]   (from the worktree root, foreground)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
D, MOD, ST, BD = UA + "src/wallet/derive.rs", UA + "src/wallet/mod.rs", UA + "src/wallet/store.rs", UA + "src/wallet/bounded.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_keys"]
TREE = "[UA_PURPOSE | HARDENED, HARDENED, account | HARDENED, u32::from(kind) | HARDENED, index | HARDENED]"
M = [
    # the plan's T2 list
    ("hardened bit dropped (UA tree index step)", D, [(TREE, TREE.replace("index | HARDENED]", "index]"))]),
    ("HKDF salt / info order swapped (PQ seed)", D, [("Hkdf::<Sha256>::new(Some(PQ_SALT), seed).expand(&info, &mut out)",
                                                     "Hkdf::<Sha256>::new(Some(&info), seed).expand(PQ_SALT, &mut out)")]),
    ("account / index swapped (UA tree)", D, [(TREE, "[UA_PURPOSE | HARDENED, HARDENED, index | HARDENED, u32::from(kind) | HARDENED, account | HARDENED]")]),
    ("u32 little-endian (PQ seed info)", D, [("&account.to_be_bytes(), &index.to_be_bytes()", "&account.to_le_bytes(), &index.to_le_bytes()")]),
    ("non-hardened ed25519 step accepted", D, [("        } else if curve == Curve::Nist256p1 {\n            [&p256_compressed",
                                                "        } else if curve == Curve::Ed25519 {\n            [&[0u8][..], &k[..], &ser].concat()\n"
                                                "        } else if curve == Curve::Nist256p1 {\n            [&p256_compressed")]),
    ("wrong kindNo (kind + 1)", D, [(TREE, TREE.replace("u32::from(kind) | HARDENED", "(u32::from(kind) + 1) | HARDENED"))]),
    ("TAG(kind) for utf8(tag) in the HKDF info", D, [("let info = [tag.as_bytes(),", "let info = [&crate::keccak256(tag.as_bytes())[..],")]),
    ("account >= 2^31 accepted", D, [("    range(account)?;\n    range(index)?;\n    crate::kind_info", "    range(index)?;\n    crate::kind_info")]),
    ("NFKD dropped (mnemonic)", MOD, [("Zeroizing::new(words.nfkd().collect::<String>())", "Zeroizing::new(words.to_string())")]),
    ("depth bound removed", BD, [("if depth > max_depth {", "if false {")]),
    ("index 1 accepted for an EIP-2333 kind", D, [("if index == 0 { Ok([root, 0, account, u32::from(kind)]) }", "if true { Ok([root, 0, account, u32::from(kind)]) }")]),
    ("imported entropy padded to 32 bytes", MOD, [("a.get(..len).ok_or(Error::Argument)", "a.get(..32).ok_or(Error::Argument)")]),
    ("a key's bytes copied into its handle", ST, [
        ("    generation: u64,\n    slot: Slot,\n}", "    generation: u64,\n    slot: Slot,\n    copy: Zeroizing<Vec<u8>>,\n}"),
        ("Ok((Handle { store: self.clone(), generation, slot }, public))",
         "let copy = Zeroizing::new(arena.get(slot)?.to_vec());\n        Ok((Handle { store: self.clone(), generation, slot, copy }, public))"),
        ("Ok(f(g.arena.as_ref().ok_or(Error::KeyRevoked)?.get(self.slot)?))", "Ok(f(&self.copy))")]),
    # the store and SLIP-10 retries (beyond the plan's list)
    ("lock() does not raise the generation", ST, [("        g.arena = None;\n        g.generation += 1;", "        g.arena = None;")]),
    ("generation check skipped in Handle::with", ST, [("if g.generation != self.generation {", "if false {")]),
    ("dropping the wallet does not lock it", MOD, [("    fn drop(&mut self) {\n        self.store.lock();\n    }", "    fn drop(&mut self) {}")]),
    ("nist256p1 child retry over the wrong bytes", D, [("*data = [&[1u8][..], &ir[..], &ser].concat();", "*data = [&[1u8][..], &il[..], &ser].concat();")]),
    ("nist256p1 seed retry dropped", D, [("while curve == Curve::Nist256p1 && p256_key(&halves(&i).0).is_none() {", "while false {")]),
    ("lower case dropped (mnemonic)", MOD, [("Zeroizing::new(nfkd.to_lowercase())", "Zeroizing::new(nfkd.to_string())")]),
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
