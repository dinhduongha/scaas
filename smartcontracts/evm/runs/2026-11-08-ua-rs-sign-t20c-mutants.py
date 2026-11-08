#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20c (owner 2026-11-08, the CLI-SGN-29 Change: an imported key registers its own derived kind): each mutant undoes
one rule of the task (the plan's five, the Fable review's four on the spec delta, the clientkeys reference's two and the C entry's
one) and names the test that must catch it. One mutant per run on a clean tree, its command, every file restored byte for byte
after it (the caller also runs `git diff --exit-code`). A failing command kills; a build that does not compile is NOT-LOADED (a
finding); a mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20c-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20c-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20c-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R, UC, CK = "clients/ua-rs/", "clients/ua-c/", "clients/clientkeys/"
MF, MOD, SG = R + "src/wallet/manifest.rs", R + "src/wallet/mod.rs", R + "src/wallet/sign.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
IU = (R, CT + ["--features", "vectors", "--test", "wallet_import_ua"])
JS = (CK, [CAPPED, "node", "--test", "test/ua-import.test.js"])
# the C entry: the debug library the Python suite loads, then its T20c test
PY = (UC, [CAPPED, "sh", "-c", "cargo build --locked --offline -j2 && python3 -m unittest -v "
           "tests.test_vectors.WalletCustody.test_imported_ua_key_rows"])

M = [
    # the plan's five
    ("kind check dropped (bip340 accepted)",
     [(MF, "if kind != network.scheme_kind() || !self.store.manifest().imports.contains(&source) {",
       "if !self.store.manifest().imports.contains(&source) {")], IU),
    ("id over the wrong tag (no TAG(kind))",
     [(MF, "        let ua = derive_ua(kind, &key_data, false)?;\n        self.store.note(|m| m.set_imported_ua(",
       "        let ua = crate::keccak256(&key_data);\n        self.store.note(|m| m.set_imported_ua(")], IU),
    ("ed25519 seed used as secp256k1",
     [(MF, "let key_data = secret.with(|s| derive::ua_key_data(kind, s))??;",
       "let key_data = secret.with(|s| derive::ua_key_data(0x0108, s))??;")], IU),
    ("manifest source lost on restore", [(MF, "        m.imported_uas = p.imported_uas.clone();\n", "")], IU),
    ("native and derived domains swapped (the imported UA signs the bare digest)",
     [(SG, "    pub fn sign_ua(&self, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<Vec<u8>> {\n        self.sign_ua_msg(",
       "    pub fn sign_ua(&self, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<Vec<u8>> {\n        if self.imported {\n"
       "            let scheme = ua_scheme(self.kind)?;\n            return self.secret.with(|s| sign_scheme(scheme, s, digest, None))?;\n"
       "        }\n        self.sign_ua_msg(")], IU),
    # the spec's own rules
    ("the importedUas check skipped on restore",
     [(MF, "    for (i, e) in imported_uas.iter().enumerate() {", "    for (i, e) in imported_uas.iter().enumerate().take(0) {")], IU),
    ("an imported UA accepted as backup sender",
     [(MF, "        if sender.imported {\n            return Err(Error::Argument);\n        }\n", "")], IU),
    # the Fable review of the spec delta (P2-2, P3-2, P3-4)
    ("imported_ua_key writes the imported UA into entries",
     [(MF, "self.store.note(|m| m.set_imported_ua(ImportedUaEntry { kind, source, ua }));",
       "self.store.note(|m| { m.set_imported_ua(ImportedUaEntry { kind, source, ua }); m.add_ua(kind, u32::MAX, u32::MAX, ua) });")], IU),
    ("payload() checks the imported sender after add_ua (the order of 2026-11-08's spec delta)",
     [(MF, "        if sender.imported {\n            return Err(Error::Argument);\n        }\n", ""),
      (MF, "            m.add_ua(sender.kind, sender.account, sender.index, ua);\n",
       "            m.add_ua(sender.kind, sender.account, sender.index, ua);\n            if sender.imported {\n"
       "                return Err(Error::Argument);\n            }\n")], IU),
    ("an empty importedUas accepted",
     [(MF, "    if m.get(\"importedUas\").is_some() && imported_uas.is_empty() {\n        return None;\n    }\n", "")], IU),
    ("imported_ua_key reads ua from importedUas instead of recomputing it",
     [(MF, "        let ua = derive_ua(kind, &key_data, false)?;\n        self.store.note(|m| m.set_imported_ua(",
       "        let ua = match self.store.manifest().imported_uas.iter().find(|e| e.source == source) {\n"
       "            Some(e) => e.ua,\n            None => derive_ua(kind, &key_data, false)?,\n        };\n"
       "        self.store.note(|m| m.set_imported_ua(")], IU),
    # the clientkeys reference
    ("clientkeys: importedUAKey takes any kind",
     [(CK + "src/uakey.js", "  if (k !== importedKind(network)) fail('Argument', 'an imported key takes the derived kind of its own scheme only');\n",
       "")], JS),
    ("clientkeys: decodeBackup skips the importedUas check", [(CK + "src/seal.js", "  checkImportedUas(j.manifest, secrets);\n", "")], JS),
    # the C entry
    ("C: scaas_ua_wallet_imported_ua_key ignores kind",
     [(UC + "src/lib.rs", "handle(w)?.0.imported_ua_key(self::network(network)?, n, kind)?",
       "{ let net = self::network(network)?; let _ = kind; handle(w)?.0.imported_ua_key(net, n, net.scheme_kind())? }")], PY),
]

if sys.argv[1:] == ["count"]:
    print(len(M))
    raise SystemExit(0)
if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, f, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)

NOT_BUILT = re.compile(r"^error(\[E\d+\])?: could not compile", re.M)
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
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, env={**os.environ, **ENV})
        rc, out = r.returncode, r.stdout + r.stderr
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M) + re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)
                        + re.findall(r"^✖ (.+?) \(", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
