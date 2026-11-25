#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The 2026-11-24 review fixes, client phase (branch review-fix-client): each check the round adds is caught by a test. The
forward walk (C25, C26), the exits of §10 step 5, the rights of §9 (F-2), the signer kinds (F-3), the builder's checks (F-4,
D-5, B-2, B-5, B-8), C-2, C-7, C-8: in clientkeys (`js`: node --test test/treekem.test.js test/pqchat-tree.test.js) and in
ua-rs (`rs`: cargo test --test tree, features app-core and vectors). One mutant per run, every file restored byte for byte
after it; a Rust mutant that does not compile kills nothing; a mutant that passes is a finding (exit 1).
  python3 -I clients/runs/2026-11-25-review-fix-client-mutants.py [first last]   (from the worktree root)
  python3 -I clients/runs/2026-11-25-review-fix-client-mutants.py check           (every replacement found once)
A hung run: past its deadline (3 x the unmutated baseline, at least 10 min, or `--timeout N`) its process group is killed and
the row reads `killed (timeout N s)`; a target file that differs from HEAD refuses the run; the restore holds on SIGINT /
SIGTERM (scripts/mutant_guard.py, ARCH-POS-23)."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts"))
import mutant_guard as guard  # noqa: E402

J = "clients/clientkeys/src/treekem.js"
PT = "clients/clientkeys/src/pqchat-tree.js"
UV = "clients/clientkeys/src/ua-verify.js"
R = "clients/ua-rs/src/wallet/tree.rs"
RP = "clients/ua-rs/src/wallet/tree_public.rs"
RQ = "clients/ua-rs/src/wallet/pqchat.rs"
RA = "clients/ua-rs/src/wallet/appkey.rs"
CAPPED = os.path.abspath("scripts/capped")
SUITES = {
    "js": ([CAPPED, "node", "--test", "test/treekem.test.js", "test/pqchat-tree.test.js"], "clients/clientkeys", {}),
    "rs": (
        [CAPPED, "cargo", "test", "--locked", "--features", "app-core,vectors", "-j", "2", "--test", "tree"],
        "clients/ua-rs",
        {"CARGO_INCREMENTAL": "0"},
    ),
}
M = [
    # ---- clientkeys: the walk's record checks (commitAt, walk)
    ("js", "the id at its number", [(J, "    hex(pc.epochId(a.sid, c.author, c.nonce)) !== a.ids[n] ||\n", "")]),
    ("js", "the record's treeId", [(J, "    c.treeId !== a.treeId ||\n", "")]),
    ("js", "the record's sessionId", [(J, "    c.sessionId !== a.sid ||\n", "")]),
    ("js", "the commit's signature", [(J, '  verified(sc, rd, "PqChatCommit", c, c.author, sig, where);\n', "")]),
    ("js", "parentEpochId", [(J, "if (c.parentEpochId !== ids[n - 1] || c.parentTreeHash !== tr.treeHash(tree)) corrupt(where);", "if (c.parentTreeHash !== tr.treeHash(tree)) corrupt(where);")]),
    ("js", "parentTreeHash", [(J, "if (c.parentEpochId !== ids[n - 1] || c.parentTreeHash !== tr.treeHash(tree)) corrupt(where);", "if (c.parentEpochId !== ids[n - 1]) corrupt(where);")]),
    ("js", "the rights and admins not judged", [(J, "        tr.judgeCommit(tree, applied.tree, c, a.admins[n - 1]);\n", "")]),
    ("js", "a gone author accepted", [(PT, '  if (t.goneUa.has(me.ua)) refuse("PqChatRemovedKept");\n', "")]),
    ("js", "the tree's hash", [(J, "        applied.treeHash !== c.treeHash ||\n", "")]),
    ("js", "the tree's size", [(J, "        applied.tree.leaves !== c.leaves ||\n", "")]),
    ("js", "ctCount", [(J, "        applied.ctTargets.length !== c.ctCount ||\n", "")]),
    ("js", "the empty list's hash", [(J, "        (c.ctCount === 0 && c.ctListHash !== hex(tr.pathListHash([], [])))\n", "        false\n")]),
    ("js", "sealedInfo above TREE_INFO_MAX", [(J, "    b(c.sealedInfo).length > TREE_INFO_MAX ||\n", "")]),
    ("js", "one wrap hash per Add", [(J, "    len(c.wrapHashes) !== len(c.adds) ||\n", "")]),
    # the exits (exitsAt)
    ("js", "no lag", [(J, "n < 0 || n > h || n < h - EXIT_LAG_MAX", "n < 0 || n > h")]),
    ("js", "the lag off by one", [(J, "n < 0 || n > h || n < h - EXIT_LAG_MAX", "n < 0 || n > h || n <= h - EXIT_LAG_MAX")]),
    ("js", "an unknown epoch named", [(J, "n < 0 || n > h || n < h - EXIT_LAG_MAX", "n > h || n < h - EXIT_LAG_MAX")]),
    ("js", "a leaver with no leaf", [(J, "    if (!holds(tree, r.member) || before(r.member)) corrupt(read);\n", "    if (before(r.member)) corrupt(read);\n")]),
    ("js", "a leave's signature", [(J, '    verified(sc, rd, "PqChatTreeLeave", r, r.member, sig, read);\n', "")]),
    ("js", "a remover outside the head's admins", [(J, "      a.admins[h].includes(r.admin) &&\n", "")]),
    ("js", "a removed UA that is no member", [(J, "(holds(tree, m) || a.admins[h].includes(m)) && !before(m)", "!before(m)")]),
    ("js", "a removal's nextEpoch", [(J, "      r.nextEpoch === n + 1 &&\n", "")]),
    ("js", "a removal's order", [(J, "      r.members.every((m, j) => j === 0 || m > r.members[j - 1]) &&\n", "")]),
    ("js", "a removal's signature", [(J, '    verified(sc, rd, "PqChatTreeRemove", r, r.admin, sig, read);\n', "")]),
    # the pin (sc-F-3), the snapshot, the list
    ("js", "a walk from the pin ignores its exits", [(J, "    if (pin && n === n0 && !pin.exits.every(", "    if (false && !pin.exits.every(")]),
    ("js", "the replay's pin check ignores its exits", [(J, "    !store.exits.every(([ua, kind]) => p.exits.some((x) => x[0] === ua && x[1] === kind))\n", "    false\n")]),
    ("js", "the snapshot's node keys not compared", [(J, "    nodes.every((x, i) => i % 2 === 0 || x.keyHash === (w.nodes[i]?.keyHash ?? ZERO));", "    true;")]),
    ("js", "the served list's targets not the walk's", [(J, "      JSON.stringify(p.list.ctTargets) !== JSON.stringify(a.targets[n]) ||\n", "")]),
    ("js", "the period's end not checked", [(J, '    if (!(endEpoch > joinEpoch && endEpoch <= head)) refuse("TreePeriod");\n', "")]),
    ("js", "a join past the head", [(J, '  if (!(joinEpoch <= head)) refuse("TreePeriod");\n', "")]),
    # judgeCommit (§8, §9; F-2)
    ("js", "judge: a non-admin's change accepted", [(PT, '  if (!plain && !head.includes(author)) refuse("PqChatNotAdmin");\n', "")]),
    ("js", "judge: a changed list with no leafy admin", [(PT, '  if (!keeps && !admins.some((x) => live(after).some((n) => n.ua === x))) refuse("PqChatTreeAdmins");\n', "")]),
    ("js", "judge: admins unsorted", [(PT, " || admins.some((x, i) => i > 0 && x <= admins[i - 1])) refuse", ") refuse")]),
    ("js", "judge: a gone admin kept", [(PT, '  if (admins.some(out)) refuse("PqChatRemovedKept");\n', "")]),
    ("js", "judge (F-2): dropping a gone admin is not plain", [(PT, "head.filter((x) => !out(x))", "head")]),
    ("js", "judge: a gone UA's Remove is not plain", [(PT, " || tree.goneUa.has(hex(x.ua))", "")]),
    # D-5, F-3, C-2, C-7, C-8
    ("js", "D-5: more than TREE_CHANGES_MAX changes", [(PT, '  if (removes.length + adds.length > TREE_CHANGES_MAX) refuse("PqChatShape");\n', "")]),
    ("js", "D-5: more than KEYS_PER_UA_MAX keys of one UA", [(PT, '  if (adds.some((a) => live(t).filter((n) => n.ua === hex(a.ua)).length > KEYS_PER_UA_MAX)) refuse("PqChatShape");\n', "")]),
    ("js", "F-3: an msig verified as a single key", [(UV, "kind === 0x0120 ? [s.members, s.signature] : [s.signature, s.members]", "[s.signature, s.members]")]),
    ("js", "C-2: decaps outside the try", [(J, "  try {\n    const ss = key.decaps(b(c.ct.mlkemCt), b(c.ct.x25519Eph));", "  const ss = key.decaps(b(c.ct.mlkemCt), b(c.ct.x25519Eph));\n  try {")]),
    ("js", "C-8: a non-canonical info opens", [(J, "    return pc.canonicalJson(JSON.parse(json)) === json ? { json } : null;", "    return { json };")]),
    ("js", "C-7: a node outside the tree", [(PT, '  if (!(Number.isInteger(x) && x >= 0 && x < nodeWidth(n))) refuse("PqChatShape");\n', "")]),
    # ---- ua-rs: the walk's record checks (commit_at, apply)
    ("rs", "the id at its number", [(R, "                    && sc.epoch_id(&self.sid, &author, u64j(&c, \"nonce\").ok()?)\n                        == at(&self.ids, n).ok()?\n", "")]),
    ("rs", "the record's treeId", [(R, "                    && b32j(&c, \"treeId\").ok()? == self.tree_id\n", "")]),
    ("rs", "the commit's signature", [(R, "        verified(sc, &*rd, \"PqChatCommit\", &c, &author, served(v.get(\"sig\"))?)?;\n", "        let _ = (&author, served(v.get(\"sig\"))?);\n")]),
    ("rs", "parentEpochId", [(R, "        if b32j(c, \"parentEpochId\")? != at(&self.ids, n - 1)?\n            || ", "        if ")]),
    ("rs", "parentTreeHash", [(R, "        if b32j(c, \"parentEpochId\")? != at(&self.ids, n - 1)?\n            || b32j(c, \"parentTreeHash\")? != tree.tree_hash()\n", "        if b32j(c, \"parentEpochId\")? != at(&self.ids, n - 1)?\n")]),
    ("rs", "the rights and admins not judged", [(R, "        tree.judge_commit(&applied.tree, &ch, &admins, head_admins)\n            .map_err(lie)?;\n", "")]),
    ("rs", "the tree's hash", [(R, "            || applied.tree_hash != b32j(c, \"treeHash\")?\n", "")]),
    ("rs", "the tree's size", [(R, "        if u64::from(applied.tree.leaves) != u64j(c, \"leaves\")?\n            || ", "        if ")]),
    ("rs", "ctCount", [(R, "            || applied.ct_targets.len() as u64 != ct_count\n", "")]),
    ("rs", "the empty list's hash", [(R, "            || (ct_count == 0 && b32j(c, \"ctListHash\")? != path_list_hash(sc.typed, &[], &[])?)\n", "")]),
    ("rs", "sealedInfo above TREE_INFO_MAX", [(R, "(1..=TREE_INFO_MAX).contains(", "(1..=usize::MAX).contains(")]),
    ("rs", "one wrap hash per Add", [(R, "                    && len(\"wrapHashes\")? == len(\"adds\")?\n", "")]),
    # the exits
    ("rs", "no lag", [(R, " && n <= h && n + EXIT_LAG_MAX >= h)", " && n <= h)")]),
    ("rs", "the lag off by one", [(R, " && n <= h && n + EXIT_LAG_MAX >= h)", " && n <= h && n + EXIT_LAG_MAX > h)")]),
    ("rs", "an unknown epoch named", [(R, "            let n = self.ids.iter().position(|x| *x == id)? as u64;", "            let n = self.ids.iter().position(|x| *x == id).unwrap_or(0) as u64;")]),
    ("rs", "a leaver with no leaf", [(R, "                (holds(tree, &member) && !before(&member)).then_some((r, member))", "                (!before(&member)).then_some((r, member))")]),
    ("rs", "a leave's signature", [(R, "                \"PqChatTreeLeave\",\n                &r,\n                &member,\n                served(v.get(\"sig\"))?,\n            )?;", "                \"PqChatTreeLeave\",\n                &r,\n                &member,\n                served(v.get(\"sig\"))?,\n            )\n            .ok();")]),
    ("rs", "a remover outside the head's admins", [(R, "                    && admins.contains(&admin)\n", "")]),
    ("rs", "a removed UA that is no member", [(R, ".all(|m| (holds(tree, m) || admins.contains(m)) && !before(m));", ".all(|m| !before(m));")]),
    ("rs", "a removal's nextEpoch", [(R, "                let ok = u64j(r0, \"nextEpoch\").ok()? == n + 1\n                    && ", "                let ok = ")]),
    ("rs", "a removal's order", [(R, "                    && members.windows(2).all(|x| x.first() < x.get(1))\n", "")]),
    ("rs", "a removal's signature", [(R, "                \"PqChatTreeRemove\",\n                &r,\n                &admin,\n                served(v.get(\"sig\"))?,\n            )?;", "                \"PqChatTreeRemove\",\n                &r,\n                &admin,\n                served(v.get(\"sig\"))?,\n            )\n            .ok();")]),
    # the pin, the snapshot, the list, the period
    ("rs", "a walk from the pin ignores its exits", [(R, "            if pin.is_some_and(|p| n == n0 && !p.exits.iter().all(|e| ex.contains(e))) {", "            if pin.is_some_and(|_| false) {")]),
    ("rs", "the replay's pin check ignores its exits", [(R, " || !s.exits.iter().all(|e| p.exits.contains(e))", "")]),
    ("rs", "the snapshot's node keys not compared", [(R, "                && nodes.iter().enumerate().all(|(x, nd)| {\n                    x % 2 == 0\n", "                && nodes.iter().enumerate().all(|(x, nd)| {\n                    true\n")]),
    ("rs", "the served list's targets not the walk's", [(R, "            if Some(&targets) != a.targets.get(&n)\n                || ", "            if ")]),
    ("rs", "the period's end not checked", [(R, "                if !(e > j && e <= head) {\n                    return refuse(TreeError::Period);\n                }\n", "")]),
    ("rs", "a join past the head", [(R, "        if join_epoch > head {\n            return refuse(TreeError::Period);\n        }\n", "")]),
    # judge_commit, the builder's checks
    ("rs", "judge: a non-admin's change accepted", [(RP, "        if !plain && !head_admins.contains(&c.author) {\n            return refuse(TreeError::NotAdmin);\n        }\n", "")]),
    ("rs", "judge: a changed list with no leafy admin", [(RP, "            return refuse(TreeError::Admins);\n", "")]),
    ("rs", "judge: admins unsorted", [(RP, " || admins.windows(2).any(|w| w.first() >= w.get(1))", "")]),
    ("rs", "judge: a gone admin kept", [(RP, "        if admins.iter().any(out) {\n            return refuse(TreeError::RemovedKept);\n        }\n", "")]),
    ("rs", "judge (F-2): dropping a gone admin is not plain", [(RP, ".filter(|x| !out(x))", ".filter(|_| true)")]),
    ("rs", "judge: a gone UA's Remove is not plain", [(RP, "                .all(|x| x.ua == c.author || self.gone_ua.contains(&x.ua));", "                .all(|x| x.ua == c.author);")]),
    ("rs", "D-5: more than TREE_CHANGES_MAX changes", [(RP, "        if c.removes.len() + c.adds.len() > TREE_CHANGES_MAX {", "        if false {")]),
    ("rs", "D-5: more than KEYS_PER_UA_MAX keys of one UA", [(RP, ".count() > KEYS_PER_UA_MAX)", ".count() > usize::MAX - 1)")]),
    ("rs", "D-5: the builder signs a commit the contract refuses", [(R, "        a.tree\n            .judge_commit(&applied.tree, &ch, &a.admins, &a.parent_admins)?;\n", "")]),
    ("rs", "F-3: an msig's members dropped", [(R, "                        crate::ua_portable::decode_member_sigs(&m)?\n", "                        vec![]\n")]),
    ("rs", "F-4: the parent tree hash", [(R, "        if a.tree.tree_hash() != a.parent_tree_hash {\n            return refuse(TreeError::Parent);\n        }\n", "")]),
    ("rs", "F-4: the author's leaf key", [(R, "        if a.tree.leaf(a.leaf).map(|l| l.kem_hash) != Some(keccak256(&a.kem.kem_pk())) {\n            return refuse(TreeError::KeyHash);\n        }\n", "")]),
    ("rs", "B-2: another struct under a tree record's name", [(RQ, "    if !TREE_RECORDS.contains(&td.primary_type()) || !own {", "    if !TREE_RECORDS.contains(&td.primary_type()) {")]),
    ("rs", "B-5: a tree's shape from JSON unbounded", [(RP, "        if !(leaves == 0 || leaves.is_power_of_two() && leaves <= TREE_LEAVES_MAX)\n            || used > leaves\n            || width != Some(node_width(leaves) as usize)\n", "        if false\n")]),
    ("rs", "B-8: a tree epoch key wrapped", [(RA, "        if matches!(key.origin, Origin::Tree) {\n            return Err(Error::Argument);\n        }\n", "")]),
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
