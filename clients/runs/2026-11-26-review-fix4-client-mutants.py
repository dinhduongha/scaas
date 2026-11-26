#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The Fable fix check of 2026-11-26, client rows (branch review-fix4-client): each check the round adds is caught by a test.
pqchat-core's mode-0 walk (C-1 the remembered record's hash, C-2 the parent's number, C-3 step 6 of the reader rule along a
session, A-1 the replica compare without the msig tags) and builders (C-5, E-2's named lists): `pqc`, cargo test --test signed
--test session. pqvault-core (C-3 step 6 along a vault, A-1 `epoch_agrees`): `pqv`, --test exits. The SDK's versions and the
tag strip: `sdkp` (tests/pqchat_keys.rs, tests/app_core_vault_records.rs) and `pqv`. The tree walk's step 6 over a signing msig
member (C-4, R-1): clientkeys `js` (node --test test/treekem.test.js test/pqchat-tree.test.js) and ua-rs `rs` (cargo test --test
tree, features app-core and vectors), on the lie rows of world msig-nested. C-7 (a version-0 KEM key by the registration):
`js`. fable-R's four hand mutants on the reader's inner tag (slotOk / authOk to version 0, to the current version) and their
ua-rs twins: `jsr` (ua-portable, ua-nested, ua-wallet, treekem) and `rsr` (ua_portable, json, wallet_uasig, nested, tree;
`nested` added after M33 and M34 survived without it: the requireAuthorized rows of nested.json are there). `sdka`: the SDK's
own chain-order row (M21's first run went to `sdkp`, which does not hold it). One mutant
per run, every file restored byte for byte after it; a Rust mutant that does not compile kills nothing; a mutant that passes
is a finding (exit 1) unless argued equivalent in the summary.
  python3 -I clients/runs/2026-11-26-review-fix4-client-mutants.py [first last]   (from the worktree root)
  python3 -I clients/runs/2026-11-26-review-fix4-client-mutants.py check           (every replacement found once)
A hung run: past its deadline (3 x the unmutated baseline, at least 10 min, or `--timeout N`) its process group is killed and
the row reads `killed (timeout N s)`; a target file that differs from HEAD refuses the run; the restore holds on SIGINT /
SIGTERM (scripts/mutant_guard.py, ARCH-POS-23)."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts"))
import mutant_guard as guard  # noqa: E402

J = "clients/clientkeys/src/treekem.js"
UV = "clients/clientkeys/src/ua-verify.js"
R = "clients/ua-rs/src/wallet/tree.rs"
RU = "clients/ua-rs/src/ua_portable.rs"
CS = "clients/pqchat-core/src/signed.rs"
CR = "clients/pqchat-core/src/reads.rs"
CB = "clients/pqchat-core/src/session.rs"
V = "clients/pqvault-core/src/vault.rs"
SA = "clients/scaas-sdk/src/app_core.rs"
SK = "clients/scaas-sdk/src/pqchat_keys.rs"
CAPPED = os.path.abspath("scripts/capped")
# inside a capped scope (the whole run as one capped job: scripts/capped exports CAPPED_SCOPE) each suite runs directly
CAP = [] if os.environ.get("CAPPED_SCOPE") else [CAPPED]
NODE = ["systemd-run", "--user", "--scope", "--quiet", "-p", "MemoryMax=3G", "-p", "MemorySwapMax=1G", "--", "node", "--test"]
RUST = {"CARGO_INCREMENTAL": "0"}
SUITES = {
    "js": ([*NODE, "test/treekem.test.js", "test/pqchat-tree.test.js"], "clients/clientkeys", {}),
    "jsr": (
        [*NODE, "test/ua-portable.test.js", "test/ua-nested.test.js", "test/ua-wallet.test.js", "test/treekem.test.js"],
        "clients/clientkeys",
        {},
    ),
    "rs": ([*CAP, "cargo", "test", "--locked", "--features", "app-core,vectors", "-j", "2", "--test", "tree"], "clients/ua-rs", RUST),
    "rsr": (
        [*CAP, "cargo", "test", "--locked", "--features", "app-core,vectors", "-j", "2", "--test", "ua_portable", "--test", "json",
         "--test", "wallet_uasig", "--test", "nested", "--test", "tree"],
        "clients/ua-rs",
        RUST,
    ),
    # the SDK's own chain-order row (tests/app_core.rs: a single record alone, then along a chain)
    "sdka": (
        [*CAP, "cargo", "test", "--locked", "-j", "2", "--features", "app-core,pqchat-records", "--test", "app_core",
         "verify_app_record_reads_the_registry"],
        "clients/scaas-sdk",
        RUST,
    ),
    "pqc": ([*CAP, "cargo", "test", "--locked", "-j", "2", "--test", "signed", "--test", "session"], "clients/pqchat-core", RUST),
    "pqv": ([*CAP, "cargo", "test", "--locked", "-j", "2", "--features", "vectors", "--test", "exits"], "clients/pqvault-core", RUST),
    "sdkp": (
        [*CAP, "cargo", "test", "--locked", "-j", "2", "--features", "app-core,pqchat-records,vectors", "--test", "pqchat_keys",
         "--test", "app_core_vault_records"],
        "clients/scaas-sdk",
        RUST,
    ),
}
M = [
    # ---- pqchat-core: the mode-0 walk
    ("pqc", "C-1: a remembered id's record not compared", [(CR, "                if *h != record_hash(cur)? {\n                    return Err(DropReason::Control);\n                }\n", "")]),
    ("pqc", "C-2: the parent's number not checked", [(CR, "            if p.epoch.checked_add(1) != Some(cur.epoch) {\n                return Err(DropReason::Control);\n            }\n", "")]),
    ("pqc", "C-2: a named ancestor's number unchecked", [(CS, "            k.map(|k| p.epoch.checked_sub(k as u64).ok_or(DropReason::Control))\n                .transpose()", "            Ok(k.map(|k| p.epoch - k as u64))")]),
    ("pqc", "C-3: step 6 along the epochs", [(CR, "            if !remembered && !msig_versions_up(&mut w.msig, &k.versions) {", "            if false {")]),
    ("pqc", "C-3: the versions not kept with the walk's memory", [(CR, "                for (u, v) in &w.msig {\n                    let e = m.msig.entry(u.clone()).or_insert(0);\n                    *e = (*e).max(*v);\n                }\n", "")]),
    ("pqc", "C-3: step 6 over the exits kept under an epoch", [(CR, "                    if !msig_versions_up(&mut f, v) {", "                    if false {")]),
    ("pqc", "C-3: the SDK names no version (mode 0)", [(SK, "                .then(|| crate::app_core::named_versions(&id, &sig, state))", "                .then(|| Some(vec![]))")]),
    ("pqc", "A-1: the replica compared with its tags", [(CR, "        if unhashed(home) == unhashed(rep) && a.without_tags() == b.without_tags() {", "        if home == rep {")]),
    # ---- pqchat-core: the builders (C-5)
    ("pqc", "C-5: a remover outside the named epoch's admins", [(CB, "            if !e.admins.contains(&ua) {\n                return Err(PqChatError::NotAdmin);\n            }\n", "")]),
    ("pqc", "C-5: a UA outside the named epoch's lists", [(CB, "            if m.iter().any(|u| !(e.has_member(u) || e.admins.contains(u))) {\n                return Err(PqChatError::NotMember);\n            }\n", "")]),
    ("pqc", "C-5: a leaver outside the named epoch", [(CB, "            || (h.id != e.id && !e.has_member(&ua))\n", "")]),
    # ---- pqvault-core
    ("pqv", "C-3: step 6 along the vault's epochs", [(V, "            Some(v) if msig_versions_up(seen, &v) => Ok(()),", "            Some(_) => Ok(()),")]),
    ("pqv", "C-3: the create record's versions not counted", [(V, "            .await?;\n        up(&mut seen, v)?;\n        for i in 0..s.epochs.len() {", "            .await?;\n        let _ = v;\n        for i in 0..s.epochs.len() {")]),
    ("pqv", "C-3: a removal judged without the versions before it", [(V, "                let mut f = floor.clone();\n", "                let mut f = BTreeMap::new();\n")]),
    ("pqv", "A-1: the replica's signature compared with its tags", [(V, "        && a.sig.without_tags() == b.sig.without_tags()\n", "        && a.sig == b.sig\n")]),
    # ---- scaas-sdk: the strip and the versions
    ("pqv", "A-1: the outer tag kept", [(SA, "            key_data: self.key_data.clone(),\n            signature: vec![],\n", "            key_data: self.key_data.clone(),\n            signature: self.signature.clone(),\n")]),
    ("pqv", "A-1: an inner msig slot's tag kept", [(SA, "                    sig: if m.members.is_empty() {\n                        m.sig.clone()\n                    } else {\n                        vec![]\n                    },\n", "                    sig: m.sig.clone(),\n")]),
    ("pqv", "A-1: a single key's signature stripped", [(SA, "        if self.members.is_empty() {\n            return self.clone();\n        }\n", "")]),
    ("sdkp", "C-3: the SDK names no version (PqVault)", [(SA, "        self.with_records(&chain, id, chain_bound, &sig, |state| {\n            f(&id, &p, &typed, &sig, state)\n                .then(|| named_versions(&id, &sig, state))", "        self.with_records(&chain, id, chain_bound, &sig, |state| {\n            f(&id, &p, &typed, &sig, state)\n                .then(|| Some(vec![]))")]),
    ("sdkp", "C-3: the SDK names no version (PqChat)", [(SK, "                .then(|| crate::app_core::named_versions(&id, &sig, state))", "                .then(|| Some(vec![]))")]),
    ("sdka", "C-3: a decrease accepted by msig_versions_up", [(SA, "        .any(|x| x.version < seen.get(&x.msig).copied().unwrap_or(0))", "        .any(|_| false)")]),
    # ---- the tree walk: a signing msig member's version (C-4, R-1)
    ("js", "C-4: an msig member's tag not named", [(UV, "    if (x.kind !== 0x0120) continue;\n", "    continue;\n")]),
    ("rs", "C-4: an msig member's tag not named", [(RU, "        if x.kind == 0x0120 {\n            out.push((x.id, tag_version(&m.sig)?));\n        }\n", "")]),
    # ---- C-7: a version-0 KEM key by the registration (clientkeys)
    ("js", "C-7: the registration's key commitment not checked", [(J, '      if (!committed) refuse("TreeKemRecord");\n', "")]),
    ("js", "C-7: the registration's proof not checked", [(J, '      uv.verifyRegistration({ kind: r.kind, keyData: r.keyData, attrs: at, pop: rec.pop, pqzPop: "0x" }, () => null);\n', "")]),
    ("js", "C-7: version 0 refused (the old reference)", [(J, "    if (keyId === 0) {\n", "    if (keyId === 0) {\n      refuse(\"TreeKemRecord\");\n")]),
    # ---- fable-R's four hand mutants (clientkeys, the reader's inner tag) and their ua-rs twins
    ("jsr", "R note 1: slotOk's inner tag read as version 0", [(UV, "    const t = tagged(members, m.id, s.sig);\n", '    const t = tagged(members, m.id, "0x");\n')]),
    ("jsr", "R note 1: slotOk's inner msig at its current version", [(UV, "    const t = tagged(members, m.id, s.sig);\n", "    const t = members(m.id) ? msigAt(members(m.id), null) : null;\n")]),
    ("jsr", "R note 1: authOk's inner tag read as version 0", [(UV, "m.kind === 0x0120 ? tagged(members, m.id, s.sig) : null;", 'm.kind === 0x0120 ? tagged(members, m.id, "0x") : null;')]),
    ("jsr", "R note 1: authOk's inner msig at its current version", [(UV, "m.kind === 0x0120 ? tagged(members, m.id, s.sig) : null;", "m.kind === 0x0120 ? msigAt(members(m.id), null) : null;")]),
    ("rsr", "R note 1 twin: slot_ok's inner tag read as version 0", [(RU, "        let Ok((sd, sen)) = cx.tagged(&m.id, key, &s.sig) else {", "        let Ok((sd, sen)) = cx.tagged(&m.id, key, &[]) else {")]),
    ("rsr", "R note 1 twin: slot_ok's inner msig at its current version", [(RU, "        let Ok((sd, sen)) = cx.tagged(&m.id, key, &s.sig) else {", "        let Ok((sd, sen)) = cx.at(&m.id, key, None).map(|(s, e, _)| (s, e)) else {")]),
    ("rsr", "R note 1 twin: auth_ok's inner tag read as version 0", [(RU, "            let Ok((sd, sen)) = cx.tagged(&m.id, &keys[i], &s.sig) else {", "            let Ok((sd, sen)) = cx.tagged(&m.id, &keys[i], &[]) else {")]),
    ("rsr", "R note 1 twin: auth_ok's inner msig at its current version", [(RU, "            let Ok((sd, sen)) = cx.tagged(&m.id, &keys[i], &s.sig) else {", "            let Ok((sd, sen)) = cx.at(&m.id, &keys[i], None).map(|(s, e, _)| (s, e)) else {")]),
]

if sys.argv[1:] == ["check"]:
    for _, name, reps in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
guard.refuse_dirty([f for _, _, reps in M[lo - 1:hi] for f, _, _ in reps], ".")
for n, (suite, name, reps) in enumerate(M[lo - 1:hi], lo):
    cmd, cwd, extra = SUITES[suite]
    env = dict(os.environ, **extra)
    lim = guard.limit(cmd, cwd=cwd, env=env)
    files = sorted({f for f, _, _ in reps})
    saved = {f: open(f, "rb").read() for f in files}
    new = {f: open(f, encoding="utf-8").read() for f in files}
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = guard.run(cmd, lim, capture_output=True, text=True, cwd=cwd, env=env)
    finally:
        guard.restore(saved)
    out = r.stdout + r.stderr
    loaded = not re.search(r"could not compile|^error\[E\d+\]", out, re.M)
    red = sorted(set(re.findall(r"^test (\w+) \.\.\. FAILED", out, re.M) + re.findall(r"^✖ (.{0,60})", out, re.M)))
    survived = not r.timeout and (r.returncode == 0 or not loaded)
    bad += survived
    verdict = guard.outcome(r, "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  ")
    where = ", ".join(sorted({f.split("/")[-1] for f in files}))
    print(f"{verdict} | M{n} {suite} {name} | {where} | rc={r.returncode} | {len(red)} red: {'; '.join(red)[:160]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
