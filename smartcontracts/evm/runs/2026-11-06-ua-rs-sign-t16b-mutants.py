#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T16b (owner 2026-11-06: the PQZ key rebuilt from an msig's k-of-n backup persists in the rebuilder's encrypted
vault and backup, as an imported key does): listing, sealing, the key-hash check on reload, the key id, the backup and the label
form are caught by tests/pqz_backup.rs (feature `vectors`: a forged pqz-held vault); the C getter by ua-c's tests/test_vectors.py
WalletPqzBackup. One mutant per run on a clean tree, its command, every file restored byte for byte after it. A mutant whose
build fails is NOT-LOADED; a mutant whose command passes SURVIVED: both are findings (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t16b-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t16b-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
RC = "clients/ua-c/"
MF = R + "src/wallet/manifest.rs"
WM = R + "src/wallet/mod.rs"
V = R + "src/wallet/vault.rs"
Q = R + "src/facade/pqz.rs"
LC = RC + "src/lib.rs"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors"]
T = (R, CARGO + ["--test", "pqz_backup"])
PY = (RC, ["bash", "-c", f"{CAPPED} cargo build --locked --offline -j2 && python3 -I tests/test_vectors.py WalletPqzBackup"])

M = [
    # the three the owner's task names
    ("not persisted: the rebuild does not list the key",
     [(WM, "self.store.note(|m| m.add_pqz_held(PqzHeldEntry { ua: *msig_ua, version, pqz_key_hash: *pqz_key_hash }));",
       "let _ = PqzHeldEntry { ua: *msig_ua, version, pqz_key_hash: *pqz_key_hash };")], T),
    ("persisted unencrypted: the vault's data in the clear",
     [(V, "        let data = gcm_seal(&dek, secret, &aad(label, \"data\"))?;",
       "        let data = GcmBox { iv: random::<12>()?.to_vec(), ct: secret.to_vec() };")], T),
    ("persisted unencrypted: the reopen lists seed32 in the public manifest",
     [(MF, "        self.store.note(|m| m.add_pqz_held(p));", "        self.store.note(|m| m.add_pqz_held(PqzHeldEntry { pqz_key_hash: *seed, ..p }));")], T),
    ("wrong key id: held under another hash",
     [(Q, "store.key(KeyId::PqzHeld(*pqz_key_hash), |_| Ok((Zeroizing::new(seed32.to_vec()), pk)))",
       "store.key(KeyId::PqzHeld([0; 32]), |_| Ok((Zeroizing::new(seed32.to_vec()), pk)))")], T),
    ("wrong key id on reload: checked against the label's ua, not its pqzKeyHash",
     [(MF, "crate::facade::pqz::install(&self.store, seed, &p.pqz_key_hash)?;", "crate::facade::pqz::install(&self.store, seed, &p.ua)?;")], T),
    # the controller's
    ("the key-hash check skipped on reload", [(Q, "    if crate::key_hash_of(crate::PQZ_SCHEME, &pk)? != Some(*pqz_key_hash) {",
                                               "    if false && crate::key_hash_of(crate::PQZ_SCHEME, &pk)? != Some(*pqz_key_hash) {")], T),
    ("the backup omits the held keys", [(MF, ".chain(m.pqz_held.iter().copied().map(Held::Pqz))",
                                         ".chain(m.pqz_held.iter().copied().map(Held::Pqz).take(0))")], T),
    ("a non-canonical label accepted", [(MF, "        (h.label() == label).then_some(h).ok_or(Error::Argument)", "        Ok(h)")], T),
    ("the manifest JSON drops pqzHeld", [(MF, "\\\"pqzHeld\\\":[{held}],", "\\\"pqzHeld\\\":[],")], T),
    ("C ABI: the getter ignores the key hash",
     [(LC, "handle(w)?.0.pqz_held_key(arr(pqz_key_hash32)?)?", "handle(w)?.0.pqz_held_key(&{ let _: &[u8; 32] = arr(pqz_key_hash32)?; [0u8; 32] })?")], PY),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(cwd, cmd):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    return r.returncode, r.stdout + r.stderr


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, (cwd, cmd)) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        rc, out = run(cwd, cmd)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)) | set(re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)))
    loaded = not re.search(r"^error(\[E\d+\])?: could not compile", out, re.M)
    verdict = "NOT-LOADED" if not loaded else "SURVIVED  " if rc == 0 else "killed    "
    bad += (not loaded) or rc == 0
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
