#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T21 O5 (b): the three-key handle in the wallet store (ua-rs `src/pqz3k/handle.rs`, clientkeys `pqzKeyHandle`): each guard's
test catches its removal. One mutant per run on a clean tree (one or more replacements), its suite run, every file restored
byte for byte after it; a mutant that does not compile is reported as such (it kills nothing); a mutant that passes is a
finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-16-pqz3k-handle-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-16-pqz3k-handle-mutants.py check           (every replacement found once, no run)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
CK = "clients/clientkeys/"
H = UA + "src/pqz3k/handle.rs"
J = CK + "src/pqzopen.js"
CAPPED = os.path.abspath("scripts/capped")
RS = ([CAPPED, "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "pqz3k", "--test", "no_oracle", "--",
       "handle::", "three_key"], UA)
JS = ([CAPPED, "node", "--test", "test/pqz-three-keys.test.js"], CK)
M = [
    # ua-rs with_secret_debit, in its order (design note §5)
    ("debit of another token than a class-3 handle's", [(H, "        if !self.token_ok(&d.token) {\n            return Err(Refused::NotThisHandle);\n        }\n        let counter", "        let counter")], RS),
    ("OwnRequired removed (the empty-window bypass back)", [(H, "            (_, None) => return Err(Refused::OwnRequired),", "            (_, None) => None,")], RS),
    ("own part at lastDebit 0 taken", [(H, "            (0, Some(_)) => return Err(Refused::Input(\"an own part on an account that never debited\")),", "            (0, Some(_)) => None,")], RS),
    ("EmptyDebit removed", [(H, "            (0, None) if d.window.is_empty() => return Err(Refused::EmptyDebit),\n", "")], RS),
    ("window entry of another token than the debit's", [(H, "            if e.token != d.token {\n                return Err(Refused::Window);\n            }\n", "")], RS),
    ("acceptance's token not compared", [(H, "a.handle == self.id && a.token == e.token && a.index", "a.handle == self.id && a.index")], RS),
    ("acceptance's handle not compared", [(H, "a.handle == self.id && a.token == e.token && a.index", "a.token == e.token && a.index")], RS),
    ("ownTag not compared", [(H, "                if !bool::from(want.ct_eq(&own.own_tag)) {", "                if !bool::from(want.ct_eq(&want)) {")], RS),
    ("own counter lastDebit, not lastDebit - 1", [(H, "u32::try_from(n - 1)", "u32::try_from(n)")], RS),
    ("lease dropped before the copy's use", [(H, "        let _lease = self.secret.lease();\n        let copy", "        drop(self.secret.lease());\n        let copy")], RS),
    # ua-rs check
    ("check: another token's credit on a class-3 handle", [(H, "        if !self.token_ok(&c.token) || blob.to_ua", "        if blob.to_ua")], RS),
    ("check: the recipient's key version not compared", [(H, " || blob.kv[0] != self.version {", " {")], RS),
    ("check: a skip of pqz-ffi taken as an acceptance", [(H, "            Ok(op::check_recipient(ok, &op::Credit {", "            Ok(Some(op::check_recipient(ok, &op::Credit {"),
        (H, " to, auditor: aud }))\n        })?;", " to, auditor: aud }).unwrap_or([0; 16])))\n        })?;")], RS),
    ("check: the acceptance names no token", [(H, "Accepted { handle: self.id, token: c.token, index", "Accepted { handle: self.id, token: [0; 20], index")], RS),
    # clientkeys withSecretDebit (the same shape)
    ("clientkeys: OwnRequired removed", [(J, "      if (last > 0n && !own) refuse('OwnRequired: lastDebit > 0 and no own part');\n", "")], JS),
    ("clientkeys: EmptyDebit removed", [(J, "      if (last === 0n && window.length === 0) refuse('EmptyDebit: no own part and no window entry');\n", "")], JS),
    ("clientkeys: window entry of another token", [(J, "        if (!eq(asBytes(e.token, 20, 'the window entry\\'s token'), tok)) refuse('a window entry of another token than the debit\\'s');\n", "")], JS),
    ("clientkeys: acceptance's token not compared", [(J, " || !eq(a.token, tok) || a.index", " || a.index")], JS),
    ("clientkeys: own counter lastDebit", [(J, "sendCounter: last - 1n,", "sendCounter: last,")], JS),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, (suite, cwd)) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = subprocess.run(suite, capture_output=True, text=True, cwd=cwd)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    out = r.stdout + r.stderr
    loaded = "could not compile `scaas-ua`" not in out and "SyntaxError" not in out
    failed = sorted(set(re.findall(r"^---- (.+?) stdout ----", out, re.M) + re.findall(r"^✖ (.+?) \(", out, re.M)))
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    where = ", ".join(sorted({f for f, _, _ in reps}))
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
