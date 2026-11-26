#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T21 O5 (b): the three-key handle in the wallet store (ua-rs `src/pqz3k/handle.rs`, clientkeys `pqzKeyHandle`): each guard's
test catches its removal. One mutant per run on a clean tree (one or more replacements), its suite run, every file restored
byte for byte after it; a mutant that does not compile is reported as such (it kills nothing); a mutant that passes is a
finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-16-pqz3k-handle-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-16-pqz3k-handle-mutants.py check           (every replacement found once, no run)
A hung run: the run past its deadline (3 x the unmutated baseline, at least 10 min, or `--timeout N`) has its process group killed and reads `killed (timeout N s)`; a target file that differs from HEAD refuses the run; the restore holds on SIGINT / SIGTERM (scripts/mutant_guard.py, owner 2026-11-24)."""
import sys
import os
import re

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts"))
import mutant_guard as guard  # noqa: E402

UA = "clients/ua-rs/"
CK = "clients/clientkeys/"
H = UA + "src/pqz3k/handle.rs"
J = CK + "src/pqzopen.js"
CAPPED = os.path.abspath("scripts/capped")
RS = ([CAPPED, "cargo", "test", "-j2", "--locked", "--no-fail-fast", "--features", "vectors", "--test", "pqz3k", "--test", "no_oracle",
       "--", "handle::", "three_key"], UA)
JS = ([CAPPED, "node", "--test", "test/pqz-three-keys.test.js"], CK)
M = [
    # ua-rs with_secret_debit, in its order (design note §5)
    ("debit of another token than a class-3 handle's", [(H, "        if !self.token_ok(&d.token) {\n            return Err(Refused::NotThisHandle);\n        }\n        let counter", "        let counter")], RS),
    ("OwnRequired removed (the empty-window bypass back)", [(H, "            (_, None) => return Err(Refused::OwnRequired),", "            (_, None) => None,")], RS),
    ("own part at lastDebit 0 taken", [(H, "            (0, Some(_)) => return Err(Refused::Input(\"an own part on an account that never debited\")),", "            (0, Some(_)) => None,")], RS),
    ("EmptyDebit removed", [(H, "            (0, None) if d.window.is_empty() && d.shield_in == 0 => return Err(Refused::EmptyDebit),\n", "")], RS),
    ("window entry of another token than the debit's", [(H, "            if e.token != d.token || last.is_some_and(|l| e.index <= l) {", "            if last.is_some_and(|l| e.index <= l) {")], RS),
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
    ("clientkeys: EmptyDebit removed", [(J, "      if (last === 0n && window.length === 0 && shield === 0n) refuse('EmptyDebit: no own part, no window entry and no shieldIn');\n", "")], JS),
    ("clientkeys: window entry of another token", [(J, "        if (!eq(asBytes(e.token, 20, 'the window entry\\'s token'), tok)) refuse('Window: a window entry of another token than the debit\\'s');\n", "")], JS),
    ("clientkeys: acceptance's token not compared", [(J, " || !eq(a.token, tok) || a.index", " || a.index")], JS),
    ("clientkeys: own counter lastDebit", [(J, "sendCounter: last - 1n,", "sendCounter: last,")], JS),
    # round 2 (the Fable + Codex review of a8927561e, owner "ok, as proposed"): one row per new guard and the missing rows (F10);
    # each mutant is the code before its fix
    ("F1: check does not bind the slot's offsets", [(H, "        if offsets(&c.slot) != (U_OFF, V_OFF) {", "        if false && offsets(&c.slot) != (U_OFF, V_OFF) {")], RS),
    ("Codex 1: the id names no key (pk, kemPk)", [(H, "&s.version.to_be_bytes(), &keccak(&[pk]), &keccak(&[kem_pk])]);", "&s.version.to_be_bytes()]);")], RS),
    ("Codex 1: the id names no derivation path", [(H, "&class_byte, &s.account.to_be_bytes(), &s.index.to_be_bytes(), &s.chain_uid,", "&class_byte, &s.chain_uid,")], RS),
    ("F2: window indexes not required ascending", [(H, "            if e.token != d.token || last.is_some_and(|l| e.index <= l) {", "            if e.token != d.token {")], RS),
    ("F2: no K_MAX bound on the window", [(H, "        if d.window.len() + 2 > K_MAX {", "        if d.window.len() + 2 > usize::MAX - 1 {")], RS),
    ("owner: shield_in ignored by EmptyDebit", [(H, " if d.window.is_empty() && d.shield_in == 0 => return", " if d.window.is_empty() => return")], RS),
    ("open_debit: Trivial(shieldIn) not added", [(H, "        add_trivial(&mut c, d.shield_in);\n", "")], RS),
    ("open_debit: a TRIVIAL entry's amount not added", [(H, "                add_trivial(&mut c, u64::from_be_bytes(e.slot[12..20].try_into().expect(\"8 bytes\")));\n", "")], RS),
    ("open_debit: the own part not added", [(H, "            add(&mut c, &[&lanes::<PK_BYTES>(o.pu, \"P(u_f)\")?[..], &lanes::<128>(o.pvf, \"P(v_f)\")?[..]].concat());", "            let _ = o;")], RS),
    ("P3: check answers KeyRevoked last", [(H, "    pub fn check(&self, c: &Credit) -> Result<Checked, Refused> {\n        self.live()?;\n", "    pub fn check(&self, c: &Credit) -> Result<Checked, Refused> {\n")], RS),
    ("P3: the debit answers KeyRevoked last", [(H, "    fn gate(&self, d: &Debit) -> Result<Option<u32>, Refused> {\n        self.live()?;\n", "    fn gate(&self, d: &Debit) -> Result<Option<u32>, Refused> {\n")], RS),
    ("Codex 4: the lease released right before the use", [(H, "        wallet::copied();\n        f(&copy)", "        wallet::copied();\n        drop(_lease);\n        f(&copy)")], RS),
    ("F6: an audited leg without the auditor's keys checked as unaudited", [(H, "            (Some(_), _, None) => return Err(Refused::Input(\"an audited leg without the auditor's keys\")),", "            (Some(_), _, None) => None,")], RS),
    ("F6: the auditor's key length not refused", [(H, "a.pk.to_vec().into_boxed_slice().try_into().map_err(|_| Refused::Input(\"the auditor's PQZ key length\"))?;",
        "{ let mut k = a.pk.to_vec(); k.resize(PK_BYTES, 0); k.into_boxed_slice().try_into().map_err(|_| Refused::Input(\"x\"))? };")], RS),
    ("F10: an unaccepted unmarked entry passes", [(H, "            if !ok {\n                return Err(Refused::Window);", "            if !ok && false {\n                return Err(Refused::Window);")], RS),
    ("F10: the acceptance's index not compared", [(H, "a.token == e.token && a.index == e.index\n", "a.token == e.token\n")], RS),
    ("F10: the acceptance's bytes not compared", [(H, "                && e.code.is_some() && a.content == entry_hash(e.index, &e.slot, e.code));", "                && e.code.is_some());")], RS),
    ("F10: check's recipient not compared", [(H, "        if !self.token_ok(&c.token) || blob.to_ua != self.ua || blob.kv[0]", "        if !self.token_ok(&c.token) || blob.kv[0]")], RS),
    ("F10: the 2^32 counter bound", [(H, "Some(u32::try_from(n - 1).map_err(|_| Refused::Input(\"lastDebit − 1 at or above 2^32\"))?)", "Some((n - 1) as u32)")], RS),
    ("prove_reg: the message not of the handle's version", [(H, "&self.scope, self.version, &pqz_key_hash);", "&self.scope, 0, &pqz_key_hash);")], RS),
    ("clientkeys F1: the slot's offsets not bound", [(J, "    if (((slot >> 80n) & 0xffffn) !== U_OFF || ((slot >> 64n) & 0xffffn) !== V_OFF) {", "    if (false) {")], JS),
    ("clientkeys Codex 1: the id names no key", [(J, "be64(v), keccak_256(pqzSeed), keccak_256(kemPk)));", "be64(v)));")], JS),
    ("clientkeys Codex 1: the id names no derivation path", [(J, "Uint8Array.of(token === undefined ? 2 : 3), be32(account),\n    be32(index), cu,", "Uint8Array.of(token === undefined ? 2 : 3),\n    cu,")], JS),
    ("clientkeys Codex 2: the acceptance keeps the caller's token buffer", [(J, "token: tok.slice(), index: accepted.index", "token: tok, index: accepted.index")], JS),
    ("clientkeys F2: indexes not required ascending", [(J, "        if (prev !== null && i <= prev) refuse(", "        if (false) refuse(")], JS),
    ("clientkeys F2: no kMax bound", [(J, "      if (window.length + 2 > layout.kMax) refuse(", "      if (false) refuse(")], JS),
    ("clientkeys owner: shieldIn ignored by EmptyDebit", [(J, "window.length === 0 && shield === 0n) refuse('EmptyDebit", "window.length === 0) refuse('EmptyDebit")], JS),
    ("clientkeys P3: the debit answers KeyRevoked last", [(J, "    withSecretDebit({ token: t, lastDebit, own, window, shieldIn }, f) {\n      live();\n", "    withSecretDebit({ token: t, lastDebit, own, window, shieldIn }, f) {\n")], JS),
    ("clientkeys F10: the acceptance's handle not compared", [(J, "        if (!a || !eq(a.handle, id) || !eq(a.token, tok)", "        if (!a || !eq(a.token, tok)")], JS),
    ("clientkeys F10: the acceptance's index not compared", [(J, " || a.index !== i || !e.code", " || !e.code")], JS),
    ("clientkeys F10: the acceptance's bytes not compared", [(J, "          || !eq(a.content, pqzEntryHash(e.index, slot, e.code))) {", "          ) {")], JS),
    ("clientkeys F10: the ownTag not compared", [(J, "if (!equalBytes(fromHex(want), asBytes(own.ownTag, 32, 'ownTag')))", "if (!equalBytes(fromHex(want), fromHex(want)))")], JS),
    ("clientkeys F10: a class-3 debit of another token", [(J, "      if (!tokenOk(tok)) refuse(`NotThisHandle: the debit is not this ${kind} handle's token`);\n", "")], JS),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
guard.refuse_dirty([f for _, reps, _ in M[lo - 1:hi] for f, _, _ in reps], ".")
for n, (name, reps, (suite, cwd)) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    lim, saved = guard.limit(suite, cwd=cwd), {f: open(f, "rb").read() for f in orig}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = guard.run(suite, lim, capture_output=True, text=True, cwd=cwd)
    finally:
        guard.restore(saved)
    out = r.stdout + r.stderr
    loaded = "could not compile `scaas-ua`" not in out and "SyntaxError" not in out
    failed = sorted(set(re.findall(r"^---- (.+?) stdout ----", out, re.M) + re.findall(r"^✖ (.+?) \(", out, re.M)))
    survived = not r.timeout and (r.returncode == 0 or not loaded)
    bad += survived
    verdict = guard.outcome(r, "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  ")
    where = ", ".join(sorted({f for f, _, _ in reps}))
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
