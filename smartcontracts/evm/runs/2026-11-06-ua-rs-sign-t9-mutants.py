#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T9: the vault v1, the manifest, discovery, import, SeedBackup, backup_seal and restore_backup (tests/wallet_vault.rs:
vault.json every row, rs_vault.json, seal.json's backup restore and rollback rows, the payload byte-equal row and its refusals)
catch a change in what they test. One mutant per run on a clean tree (one or more replacements), its suite run, every file
restored byte for byte after it; a mutant that does not compile is reported as such (it kills nothing); a mutant that passes is
a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t9-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t9-mutants.py check           (every replacement found once, no run)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
V = UA + "src/wallet/vault.rs"
F = UA + "src/wallet/manifest.rs"
W = UA + "src/wallet/mod.rs"
ST = UA + "src/wallet/store.rs"
K = UA + "src/wallet/kem.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_vault"]
LOGN = "                let log_n = LOG_N.iter().find(|l| 1u64 << **l == p.n).filter(|_| p.kdf == \"scrypt\" && p.r == 8 && p.p == 1);"
KEK = "                (pin_kek(pin, &p.salt, *log_n.ok_or(Error::VaultParams)?)?, &p.sealed, \"pin\")"
SEAL_E = "        let entropy = self.store.with_arena(|a| Ok(Zeroizing::new(a.entropy()?.to_vec())))?;\n        Vault::seal(\"seed\", &entropy,"
ROLL = "            if p.generation < m.backup_generation && rollback.is_none() {\n                return Err(Error::BackupRollback);\n            }\n"
EQ = "            if p.generation == m.backup_generation {\n                return Ok(None);\n            }\n"
M = [
    # the plan's T9 list
    ("AAD label dropped", [(V, "    format!(\"{label}|{part}\").into_bytes()", "    let _ = label;\n    format!(\"|{part}\").into_bytes()")], SUITE),
    ("stored scrypt parameters ignored (N of a new envelope)", [(V, KEK, KEK.replace("*log_n.ok_or(Error::VaultParams)?", "{ log_n.ok_or(Error::VaultParams)?; LOG_N_NEW }"))], SUITE),
    ("bounds check removed (any N, r, p)", [(V, LOGN, "                let log_n = Some(&(p.n.trailing_zeros() as u8));")], SUITE),
    ("NFKC dropped", [(V, "    let pw = Zeroizing::new(pin.nfkc().collect::<String>());", "    let pw = Zeroizing::new(pin.to_owned());")], SUITE),
    ("64-byte seed stored for the entropy", [(V, SEAL_E, "        let entropy = self.store.seed().map(|s| Zeroizing::new(s.to_vec()))?;\n        Vault::seal(\"seed\", &entropy[..],")], SUITE),
    ("entropy padded to 32 bytes (vault)", [(V, SEAL_E, SEAL_E.replace("a.entropy()?.to_vec()", "{ let mut e = a.entropy()?.to_vec(); e.resize(32, 0); e }"))], SUITE),
    ("entropy padded to 32 bytes (backup payload)", [(F, "            let entropy = Zeroizing::new(a.entropy()?.to_vec());",
        "            let entropy = Zeroizing::new({ let mut e = a.entropy()?.to_vec(); e.resize(32, 0); e });")], SUITE),
    ("v: 2 reported as a wrong passphrase", [(V, "            return Err(Error::VaultVersion);", "            return Err(Error::VaultOpen);")], SUITE),
    ("PRF envelope opened without its label", [(V, "        key32(gcm_open(&kek, sealed, &aad(&self.label, part))?, Error::VaultOpen)",
        "        key32(gcm_open(&kek, sealed, &aad(if part == \"prf\" { \"\" } else { &self.label }, part))?, Error::VaultOpen)")], SUITE),
    ("generation compare skipped", [(F, ROLL, "")], SUITE),
    ("backup self-consistency skipped", [(F, "        if !derives_sender(&p, &c.sender_ua, bip39_passphrase) {", "        if false {")], SUITE),
    # the controller's
    ("equal generation installs (no-op removed)", [(F, EQ, "")], SUITE),
    ("AllowRollback ignored", [(F, ROLL, ROLL.replace("rollback.is_none()", "rollback.is_some() || true"))], SUITE),
    ("backup_seal does not raise the generation", [(F, "            m.backup_generation = m.backup_generation.checked_add(1).ok_or(Error::Argument)?;\n", "")], SUITE),
    ("self-consistency at the first entry, not the sender's", [(F, "    let Some(e) = p.entries.iter().find(|e| e.ua == *sender) else { return false };",
        "    let Some(e) = p.entries.first() else { return false };")], SUITE),
    ("payload entropy length unchecked", [(F, "    let entropy = b64(v.get(\"entropy\")?).filter(|e| SEED_LENGTHS.contains(&e.len()))?;",
        "    let entropy = b64(v.get(\"entropy\")?)?;")], SUITE),
    ("manifest UA case unchecked", [(F, "    (to_hex(&b) == s).then_some(b)", "    Some(b)")], SUITE),
    ("imported key served for another network", [(F, "        if !self.store.manifest().imports.contains(&ImportEntry { network, n }) {",
        "        if !self.store.manifest().imports.iter().any(|i| i.n == n) {")], SUITE),
    ("passphrase policy: digits only accepted", [(V, "    if p.chars().count() < 8 || !other {", "    if p.chars().count() < 8 {")], SUITE),
    ("restore of a non-backup purpose", [(F, "        if expect.purpose != PURPOSE_BACKUP {\n            return Err(Error::Argument);\n        }\n        let p = BackupPayload",
        "        let p = BackupPayload")], SUITE),
    ("backup sealed with another wallet's key", [(F, "is_sender_kind(sender.kind) && sender.secret.of_store(&self.store)", "is_sender_kind(sender.kind)")], SUITE),
    ("lock wipes the manifest", [(ST, "        g.arena = None;\n        g.generation += 1;", "        g.arena = None;\n        g.manifest = Manifest::default();\n        g.generation += 1;")], SUITE),
    # M23, M24 (T18 refresh): T10 b2c56d53 moved both checks into the free fn seed_entropy (one indent less)
    ("open_vault label not checked", [(V, "    if vault.label != \"seed\" {\n        return Err(Error::Argument);\n    }\n", "")], SUITE),
    ("seed payload length not checked on open", [(V, "    if !SEED_LENGTHS.contains(&entropy.len()) {\n        return Err(Error::VaultOpen);\n    }\n", "")], SUITE),
    ("discovery past index 0 for EIP-2333 kinds", [(F, "        let n = if (0x0104..=0x0107).contains(&kind) { gap.min(1) } else { gap };", "        let n = gap;")], SUITE),
    ("link installs the entropy only", [(F, "    install(BackupPayload::from_json(pt)?, bip39_passphrase)",
        "    Wallet::from_entropy(&BackupPayload::from_json(pt)?.entropy, bip39_passphrase)")], SUITE),
    ("SeedBackup handed out unconfirmed", [(W, "        if self.state != BackupState::Verified {\n            return None;\n        }\n", "")], SUITE),
    ("SeedBackup revealed twice", [(W, "        if self.state != BackupState::Fresh {\n            return Err(Error::Argument);\n        }\n        let words", "        let words")], SUITE),
    ("needs_rewrap always false", [(V, "        !(self.pin.n >= 1 << LOG_N_NEW && self.pin.r >= 8 && self.pin.p >= 1)", "        false")], SUITE),
    ("rewrap_pin rotates the DEK (a new vault)", [(V, "        Ok(Vault { pin: pin_envelope(&self.label, &dek, new)?, ..self.clone() })",
        "        Vault::seal(&self.label, &gcm_open(&dek, &self.data, &aad(&self.label, \"data\"))?, new, None)")], SUITE),
    ("KEM key not written to the manifest", [(K, "        secret.note(|m| m.add_kem(ua, version));\n", "")], SUITE),
    ("payload field order changed (generation before v)", [(F, r'{{\"v\":1,\"generation\":{},', r'{{\"generation\":{},\"v\":1,')], SUITE),
    # M33 (T18 refresh): T16b a76814e7 installs every held secret (imports and rebuilt PQZ keys) through install_held
    ("restored imports dropped", [(F, "    for (h, secret) in &p.secrets {\n        w.install_held(*h, secret)?;\n    }\n", "    let _ = &p.secrets;\n")], SUITE),
    ("restored generation not set", [(F, "        m.backup_generation = p.generation;\n", "")], SUITE),
    ("bounds check: r and p not checked (N still bounded)", [(V, LOGN, LOGN.replace(' && p.r == 8 && p.p == 1', ''))], SUITE),
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
