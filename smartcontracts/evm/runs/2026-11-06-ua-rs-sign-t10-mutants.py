#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T10: custody and memory protection (tests/wallet_custody.rs, tests/wallet_memory.rs, the compile-fail doc tests of
`Wallet`) catch a change in what they test. One mutant per run on a clean tree (one or more replacements), its suite run, every
file restored byte for byte after it; a mutant that does not compile is reported as such (it kills nothing); a mutant that
passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t10-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t10-mutants.py check           (every replacement found once, no run)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
ST = UA + "src/wallet/store.rs"
W = UA + "src/wallet/mod.rs"
V = UA + "src/wallet/vault.rs"
K = UA + "src/wallet/kem.rs"
CAP = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked"]
CUSTODY = CAP + ["--features", "vectors,mlock", "--test", "wallet_custody", "--test", "wallet_memory"]
VAULT = CAP + ["--features", "vectors", "--test", "wallet_custody", "--test", "wallet_vault"]
DOC = CAP + ["--doc", "wallet::Wallet"]
WITH = ("        let g = self.store.read();\n        if g.generation != self.generation {\n            return Err(Error::KeyRevoked);\n"
        "        }\n        Ok(f(g.arena.as_ref().ok_or(Error::KeyRevoked)?.get(self.slot)?))")
DERIVE = ("        let mut g = self.store.write();\n        if g.generation != self.generation {\n            return Err(Error::KeyRevoked);\n"
          "        }\n        let arena = g.arena.as_mut().ok_or(Error::KeyRevoked)?;\n        self.store.key_in")
UAKEY = "/// A UA key handle: its store, generation and slot; no secret bytes. No `Clone`.\npub struct UaKey {"
KEMKP = "/// A KEM key: its `kemPk` and the handle of its 96-byte seed"
M = [
    # the plan's T10 list
    ("Clone on UaKey (a second handle of the secret)", [(W, UAKEY, "impl Clone for UaKey {\n    fn clone(&self) -> Self {\n"
        "        UaKey { kind: self.kind, account: self.account, index: self.index, key_data: self.key_data.clone(), ua: self.ua, "
        "secret: self.secret.dup() }\n    }\n}\n\n" + UAKEY)], DOC),
    ("lock keeps the entropy (the arena stays)", [(ST, "        g.arena = None;\n        g.generation += 1;", "        g.generation += 1;")], CUSTODY),
    ("generation not raised by lock()", [(ST, "        g.arena = None;\n        g.generation += 1;", "        g.arena = None;")], CUSTODY),
    ("generation check skipped in one secret operation (Handle::with: sign, decaps, open)", [(ST, WITH,
        "        let g = self.store.read();\n        Ok(f(g.arena.as_ref().ok_or(Error::KeyRevoked)?.get(self.slot)?))")], CUSTODY),
    ("unlock restores the old generation", [(ST, "        g.arena = Some(Arena::new(entropy, seed)?);",
        "        g.generation = g.generation.saturating_sub(1);\n        g.arena = Some(Arena::new(entropy, seed)?);")], CUSTODY),
    ("lock() not waiting for operations in flight (the operation runs outside the read guard)", [(ST, WITH,
        "        let s = {\n            let g = self.store.read();\n            if g.generation != self.generation {\n"
        "                return Err(Error::KeyRevoked);\n            }\n"
        "            Zeroizing::new(g.arena.as_ref().ok_or(Error::KeyRevoked)?.get(self.slot)?.to_vec())\n        };\n        Ok(f(&s))")], CUSTODY),
    ("mlock on another allocation only (the chunk reported locked, not locked)", [(ST,
        "        let (locked, no_dump) = protect::on(page.0.as_mut_ptr(), PAGE);",
        "        let (locked, no_dump) = { let _ = protect::on; let _ = &mut page; (true, true) };")], CUSTODY),
    # the controller's
    ("chunk not wiped at release", [(ST, "        self.page.0.zeroize();\n", "")], CUSTODY),
    ("release does not unlock or unmark", [(ST, "        protect::off(self.page.0.as_mut_ptr(), PAGE, self.locked, self.no_dump);",
        "        let _ = protect::off;")], CUSTODY),
    ("MADV_DONTDUMP not applied (reported)", [(ST,
        "        let no_dump = unsafe { libc::madvise(p as *mut c_void, len, libc::MADV_DONTDUMP) } == 0;", "        let no_dump = true;")], CUSTODY),
    ("a refused mlock reported as locked", [(ST, "        let locked = unsafe { libc::mlock(p as *const c_void, len) } == 0;",
        "        let locked = { unsafe { libc::mlock(p as *const c_void, len) }; true };")], CUSTODY),
    ("memory_protection counts every chunk as locked", [(ST, "            locked: a.chunks.iter().filter(|c| c.locked).count(),",
        "            locked: a.chunks.len(),")], CUSTODY),
    ("generation check skipped in Handle::derive (an old UA handle's kem_key)", [(ST, DERIVE,
        "        let mut g = self.store.write();\n        let arena = g.arena.as_mut().ok_or(Error::KeyRevoked)?;\n        self.store.key_in")], CUSTODY),
    ("unlock of an unlocked wallet replaces its arena", [(ST, "        if g.arena.is_some() {\n            return Err(Error::Argument);\n        }\n        g.arena = Some(",
        "        g.arena = Some(")], CUSTODY),
    ("dropping the wallet does not lock it", [(W, "impl Drop for Wallet {\n    fn drop(&mut self) {\n        self.store.lock();",
        "impl Drop for Wallet {\n    fn drop(&mut self) {\n        let _ = &self.store;")], CUSTODY),
    ("unlock skips the seed label check", [(V, "    if vault.label != \"seed\" {\n        return Err(Error::Argument);\n    }\n    let entropy = vault.open(unlock)?;",
        "    let entropy = vault.open(unlock)?;")], VAULT),
    ("unlock skips the entropy length check", [(V, "    if !SEED_LENGTHS.contains(&entropy.len()) {\n        return Err(Error::VaultOpen);\n    }\n    Ok(entropy)",
        "    Ok(entropy)")], VAULT),
    ("Debug on KemKeyPair", [(K, KEMKP, "impl core::fmt::Debug for KemKeyPair {\n    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {\n"
        "        f.write_str(\"KemKeyPair\")\n    }\n}\n\n" + KEMKP)], DOC),
    ("a secret accessor in a release build", [(W, "    /// The UA; `None` for a MuSig2 participant (`0x0110`, `0x0112`).",
        "    #[cfg(not(feature = \"vectors\"))]\n    pub fn vectors_with_secret<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {\n"
        "        self.secret.with(f)\n    }\n    /// The UA; `None` for a MuSig2 participant (`0x0110`, `0x0112`).")], DOC),
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
