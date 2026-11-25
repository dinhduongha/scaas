#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The 2026-11-24 review fixes, client phase (branch review-fix-client), and the re-review of 2026-11-25 (branch
review-fix2-client: mode 0's reader and builders in pqchat-core, `pqc`; PqVault's exits, `pqv`; the SDK's exit reviews, `sdk`;
the key records, the msig's current structure, the replay from the pin, B2-6, C-3, C-5, C-6 in both clients): each check the
round adds is caught by a test. The
forward walk (C25, C26), the exits of §10 step 5, the rights of §9 (F-2), the signer kinds (F-3), the builder's checks (F-4,
D-5, B-2, B-5, B-8), C-2, C-7, C-8: in clientkeys (`js`: node --test test/treekem.test.js test/pqchat-tree.test.js) and in
ua-rs (`rs`: cargo test --test tree, features app-core and vectors); the node's tree bounds of D-4, D-7 and R8 (`node`: cargo
test --lib pqchat_tree_bounds_are_the_contract in scaas-node). One mutant per run, every file restored byte for byte
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
N = "scaas-node/src/typed.rs"
CC = "clients/pqchat-core/src/check.rs"
CS = "clients/pqchat-core/src/signed.rs"
CR = "clients/pqchat-core/src/reads.rs"
CB = "clients/pqchat-core/src/session.rs"
V = "clients/pqvault-core/src/vault.rs"
SL = "clients/scaas-sdk/src/pqchat_records.rs"
SA = "clients/scaas-sdk/src/app_core.rs"
CAPPED = os.path.abspath("scripts/capped")
SUITES = {
    "js": ([CAPPED, "node", "--test", "test/treekem.test.js", "test/pqchat-tree.test.js"], "clients/clientkeys", {}),
    "rs": (
        [CAPPED, "cargo", "test", "--locked", "--features", "app-core,vectors", "-j", "2", "--test", "tree"],
        "clients/ua-rs",
        {"CARGO_INCREMENTAL": "0"},
    ),
    # pqchat-core's mode-0 reader and builders (the re-review of 2026-11-25: E-1, U-1, E-4, D2-1, E-5, D2-4)
    "pqc": (
        [CAPPED, "cargo", "test", "--locked", "-j", "2", "--test", "check", "--test", "signed", "--test", "session"],
        "clients/pqchat-core",
        {"CARGO_INCREMENTAL": "0"},
    ),
    # pqvault-core's exits (B2-3)
    "pqv": (
        [CAPPED, "cargo", "test", "--locked", "-j", "2", "--features", "vectors", "--test", "core", "--test", "exits"],
        "clients/pqvault-core",
        {"CARGO_INCREMENTAL": "0"},
    ),
    # the SDK's exit reviews (F-4, D2-3)
    "sdk": (
        [CAPPED, "cargo", "test", "--locked", "-j", "2", "--features", "app-core,pqchat-records", "--test", "pqchat_records",
         "--test", "app_core_vault_records"],
        "clients/scaas-sdk",
        {"CARGO_INCREMENTAL": "0"},
    ),
    # the node's tree bounds (review D-4, D-7, R8; 2026-11-25, after the client phase)
    "node": (
        [CAPPED, "cargo", "test", "--locked", "-j", "2", "--lib", "pqchat_tree_bounds_are_the_contract"],
        "scaas-node",
        {"CARGO_INCREMENTAL": "0"},
    ),
}
M = [
    # ---- clientkeys: the walk's record checks (commitAt, walk)
    ("js", "the id at its number", [(J, "      hex(pc.epochId(a.sid, r.author, r.nonce)) === a.ids[n] &&\n", "")]),
    ("js", "the record's treeId", [(J, "      r.treeId === a.treeId &&\n", "")]),
    ("js", "the record's sessionId", [(J, "      r.epoch === n &&\n      r.sessionId === a.sid &&\n", "      r.epoch === n &&\n")]),
    ("js", "the commit's signature", [(J, '  verified(sc, rd, "PqChatCommit", ok, ok.author, sig, where);\n', "")]),
    ("js", "parentEpochId", [(J, "if (c.parentEpochId !== ids[n - 1] || c.parentTreeHash !== tr.treeHash(tree)) corrupt(where);", "if (c.parentTreeHash !== tr.treeHash(tree)) corrupt(where);")]),
    ("js", "parentTreeHash", [(J, "if (c.parentEpochId !== ids[n - 1] || c.parentTreeHash !== tr.treeHash(tree)) corrupt(where);", "if (c.parentEpochId !== ids[n - 1]) corrupt(where);")]),
    ("js", "the rights and admins not judged", [(J, "        tr.judgeCommit(tree, applied.tree, c, a.admins[n - 1]);\n", "")]),
    ("js", "a gone author accepted", [(PT, '  if (t.goneUa.has(me.ua)) refuse("PqChatRemovedKept");\n', "")]),
    ("js", "the tree's hash", [(J, "        applied.treeHash !== c.treeHash ||\n", "")]),
    ("js", "the tree's size", [(J, "        applied.tree.leaves !== c.leaves ||\n", "")]),
    ("js", "ctCount", [(J, "        applied.ctTargets.length !== c.ctCount ||\n", "")]),
    ("js", "the empty list's hash", [(J, "        (c.ctCount === 0 && c.ctListHash !== hex(tr.pathListHash([], [])))\n", "        false\n")]),
    ("js", "sealedInfo above TREE_INFO_MAX", [(J, "      b(r.sealedInfo).length <= TREE_INFO_MAX &&\n      [...r.removes", "      [...r.removes")]),
    ("js", "one wrap hash per Add", [(J, "      len(r.wrapHashes) === len(r.adds) &&\n", "")]),
    # the exits (exitsAt)
    ("js", "no lag", [(J, "m >= 0 && m >= h - EXIT_LAG_MAX; m--", "m >= 0; m--")]),
    ("js", "the lag off by one", [(J, "m >= 0 && m >= h - EXIT_LAG_MAX; m--", "m >= 0 && m > h - EXIT_LAG_MAX; m--")]),
    ("js", "an unknown epoch named", [(J, "    return corrupt(read);\n  };\n  const count", "    return h;\n  };\n  const count")]),
    ("js", "a leaver with no leaf", [(J, "    if (!holds(tree, r.member) || before(r.member)) corrupt(read);\n", "    if (before(r.member)) corrupt(read);\n")]),
    ("js", "a leave's signature", [(J, '    verified(sc, rd, "PqChatTreeLeave", r, r.member, sig, read);\n', "")]),
    ("js", "a remover outside the head's admins", [(J, "      a.admins[h].includes(r.admin) &&\n", "")]),
    ("js", "a removed UA that is no member", [(J, "(holds(tree, m) || a.admins[h].includes(m)) && !before(m)", "!before(m)")]),
    ("js", "a removal's nextEpoch", [(J, "      r.nextEpoch === n + 1 &&\n", "")]),
    ("js", "a removal's order", [(J, "      r.members.every((m, j) => j === 0 || m > r.members[j - 1]) &&\n", "")]),
    ("js", "a removal's signature", [(J, '    verified(sc, rd, "PqChatTreeRemove", r, r.admin, sig, read);\n', "")]),
    # the pin (sc-F-3), the snapshot, the list
    ("js", "a walk from the pin ignores its exits", [(J, "    if (pin && n === a.n0 && !pin.exits.every(", "    if (false && !pin.exits.every(")]),
    ("js", "the replay's pin check ignores its exits", [(J, "    !store.exits.every(([ua, kind]) => p.exits.some((x) => x[0] === ua && x[1] === kind))\n", "    false\n")]),
    ("js", "the snapshot's node keys not compared", [(J, "    nodes.every((x, i) => i % 2 === 0 || x.keyHash === (w.nodes[i]?.keyHash ?? ZERO));", "    true;")]),
    ("js", "the served list's targets not the walk's", [(J, "      JSON.stringify(p.list.ctTargets) !== JSON.stringify(a.targets[n]) ||\n", "")]),
    ("js", "the period's end not checked", [(J, "isNat(endEpoch) && endEpoch > joinEpoch && endEpoch <= head", "isNat(endEpoch)")]),
    ("js", "a join past the head", [(J, "(isNat(joinEpoch) && joinEpoch <= head)", "isNat(joinEpoch)")]),
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
    ("rs", "sealedInfo above TREE_INFO_MAX", [(R, "                    && (1..=TREE_INFO_MAX).contains(&bytes(c.get(\"sealedInfo\")?).ok()?.len())", "                    && (1..=usize::MAX).contains(&bytes(c.get(\"sealedInfo\")?).ok()?.len())")]),
    ("rs", "one wrap hash per Add", [(R, "                    && len(\"wrapHashes\")? == len(\"adds\")?\n", "")]),
    # the exits
    ("rs", "no lag", [(R, "        for m in (h.saturating_sub(EXIT_LAG_MAX)..=h).rev() {", "        for m in (0..=h).rev() {")]),
    ("rs", "the lag off by one", [(R, "        for m in (h.saturating_sub(EXIT_LAG_MAX)..=h).rev() {", "        for m in (h.saturating_sub(EXIT_LAG_MAX - 1)..=h).rev() {")]),
    ("rs", "an unknown epoch named", [(R, "                return Ok(m);\n            }\n        }\n        corrupt()\n", "                return Ok(m);\n            }\n        }\n        Ok(h)\n")]),
    ("rs", "a leaver with no leaf", [(R, "            if !holds(tree, &member) || before(&member) {", "            if before(&member) {")]),
    ("rs", "a leave's signature", [(R, "                \"PqChatTreeLeave\",\n                &r,\n                &member,\n                served(v.get(\"sig\"))?,\n            )?;", "                \"PqChatTreeLeave\",\n                &r,\n                &member,\n                served(v.get(\"sig\"))?,\n            )\n            .ok();")]),
    ("rs", "a remover outside the head's admins", [(R, "                && admins.contains(&admin)\n", "")]),
    ("rs", "a removed UA that is no member", [(R, ".all(|m| (holds(tree, m) || admins.contains(m)) && !before(m));", ".all(|m| !before(m));")]),
    ("rs", "a removal's nextEpoch", [(R, "            let ok = next == n + 1\n                && ", "            let ok = ")]),
    ("rs", "a removal's order", [(R, "                && members.windows(2).all(|x| x.first() < x.get(1))\n", "")]),
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
    ("rs", "D-5: the builder signs a commit the contract refuses", [(R, "        tree.judge_commit(&applied.tree, &ch, &a.admins, &pr.parent_admins)?;\n", "")]),
    ("rs", "F-3: an msig's members dropped", [(R, "                        crate::ua_portable::decode_member_sigs(&m)?\n", "                        vec![]\n")]),
    ("rs", "F-4: the author's leaf key", [(R, "        if tree.leaf(a.leaf).map(|l| l.kem_hash) != Some(keccak256(&a.kem.kem_pk())) {\n            return refuse(TreeError::KeyHash);\n        }\n", "")]),
    ("rs", "B-2: another struct under a tree record's name", [(RQ, "    if !TREE_RECORDS.contains(&td.primary_type()) || !own {", "    if !TREE_RECORDS.contains(&td.primary_type()) {")]),
    ("rs", "B-5: a tree's shape from JSON unbounded", [(RP, "        if !(leaves == 0 || leaves.is_power_of_two() && leaves <= TREE_LEAVES_MAX)\n            || used > leaves\n            || width != Some(node_width(leaves) as usize)\n", "        if false\n")]),
    ("rs", "B-8: a tree epoch key wrapped", [(RA, "        // a tree epoch key `K_e` is a handle and never wrapped (spec §15, B-8): a tree session needs no flat wrap of it\n        if matches!(key.origin, Origin::Tree) {\n            return Err(Error::Argument);\n        }\n", "")]),
    # ---- scaas-node: createSession's tree bounds (D-4) and the empty addPath (D-7)
    ("node", "D-4: a tree session's members unbounded", [(N, "                if len(sv(\"members\")) as u64 > TREE_LEAVES_MAX {", "                if false {")]),
    ("node", "D-4: a tree session's admins unbounded", [(N, "                if len(sv(\"admins\")) > TREE_ADMINS_MAX {", "                if false {")]),
    ("node", "D-4: a tree session's sealedInfo unbounded", [(N, "                    > TREE_INFO_MAX\n                {", "                    > usize::MAX\n                {")]),
    ("node", "D-4: the bounds on mode 0 too", [(N, "            if num(sv(\"groupMode\")) == 1 {", "            if num(sv(\"groupMode\")) <= 1 {")]),
    ("node", "D-7: an empty addPath", [(N, "            if len(at(\"cts\")) == 0 {", "            if false {")]),
    # ---- R8 256 -> 512 (owner 2026-11-25): each reader's bound
    ("rs", "R8: ua-rs's cap back at 256", [(RP, "pub const TREE_LEAVES_MAX: u32 = 512;", "pub const TREE_LEAVES_MAX: u32 = 256;")]),
    ("js", "R8: clientkeys' cap back at 256", [(PT, "export const TREE_LEAVES_MAX = 512;", "export const TREE_LEAVES_MAX = 256;")]),
    ("node", "R8: the node's cap back at 256", [(N, "const TREE_LEAVES_MAX: u64 = 512;", "const TREE_LEAVES_MAX: u64 = 256;")]),
    ("node", "R8: the node's depth back at 8", [(N, "const TREE_DEPTH_MAX: usize = 9;", "const TREE_DEPTH_MAX: usize = 8;")]),
    # ---- C10 32 -> 20 (owner 2026-11-25): each reader's change bound
    ("rs", "C10: ua-rs at 21 changes", [(RP, "pub const TREE_CHANGES_MAX: usize = 20;", "pub const TREE_CHANGES_MAX: usize = 21;")]),
    ("js", "C10: clientkeys at 21 changes", [(PT, "export const TREE_CHANGES_MAX = 20;", "export const TREE_CHANGES_MAX = 21;")]),
    ("node", "C10: the node at 21 changes", [(N, "const TREE_CHANGES_MAX: usize = 20;", "const TREE_CHANGES_MAX: usize = 21;")]),
    # ==== the re-review of 2026-11-25 (branch review-fix2-client) ====
    # ---- clientkeys
    ("js", "C-1: a cold tree's key unauthenticated", [(J, "  return recordKey(ua, keyId, v, rd.uaRecordOf, rd.accepted);\n", "  return v.kemPk;\n")]),
    ("js", "C-1: a KEM record's signature not verified", [(J, "    uv.verifyKemRecord({ ua: hex(ua), version: keyId, kemPk: rec.kemPk, sig: rec.sig }, uaRecordOf, accepted);\n", "")]),
    ("js", "C-1: an Add's key unauthenticated", [(J, "    const k = recordKey(x.ua, x.keyId, x, a.uaRecordOf, a.accepted);\n", "    const k = x.kemPk;\n")]),
    ("js", "C-1: a member's key unauthenticated at creation", [(J, "  const kemPks = session.members.map((m, i) => recordKey(m.ua, m.keyId, kems[i], uaRecordOf, accepted));", "  const kemPks = kems.map((k) => k.kemPk);")]),
    ("js", "C-7: UANotVerifiable read as a lying read", [(J, '  if (e?.code === "UANotVerifiable") refuse("UANotVerifiable");\n', "")]),
    ("js", "F-1: an msig judged on its first structure", [(UV, "const structureOf = (r) => (r.current ? toBytes(r.current) : r.keyData);", "const structureOf = (r) => r.keyData;")]),
    ("js", "C-3: ids below the pin taken as served", [(J, "  if (m >= a.n0 || m === 0) return m === 0 ? a.sid : a.ids[m];\n", "  return m === 0 ? a.sid : a.ids[m];\n")]),
    ("js", "B2-6: a UA exiting twice under one head", [(J, "    goes.size !== out.length ||\n", "")]),
    ("js", "B2-6, C21: the owed leaves unbounded", [(J, "    out.reduce((sum, x) => sum + leavesOf(tree, x.ua), 0) > tr.TREE_CHANGES_MAX ||\n", "")]),
    ("js", "B2-6, C24: the last leafy admin removed", [(J, "    (a.admins[h].some(leafyAdmin) &&\n", "    (false &&\n")]),
    ("js", "B2-6, C24: no leave exempts the last leafy admin", [(J, "      !out.some((x) => x.kind === 1 && leafyAdmin(x.ua)))", "      true)")]),
    ("js", "C-6: the exit count unbounded", [(J, "served(v, (x) => isNat(x) && x <= EXITS_MAX, read)", "served(v, (x) => isNat(x), read)")]),
    ("js", "C-6: a commit's shape unchecked", [(J, "  const { record: c, sig } = served(rd.commitOf(n), (x) => isObj(x) && isObj(x.record), where);", "  const { record: c, sig } = rd.commitOf(n);")]),
    ("js", "C-2: leaves left by the served joinEpoch", [(J, "        const y = a.trees[head].nodes[2 * x.leaf];\n        return y?.ua === x.ua && y.keyId === x.keyId && y.kemHash === x.kemHash;", "        return leaves[x.leaf]?.ua === x.ua && leaves[x.leaf].joinEpoch === n;")]),
    ("js", "E-3: a tree per epoch", [(J, '  const kept = (n) => keep === "all" || n === a.n0 || n === head || keep.includes(n);', "  const kept = () => true;")]),
    ("js", "E-3: a resumed replay walks from the cold tree", [(J, "  const a = from ? walk(sc, rd, from.pin) : walk(sc, rd, null, store ? [store.epoch] : []);", "  const a = walk(sc, rd, null, store ? [store.epoch] : []);")]),
    ("js", "E-3: rosters of every epoch", [(J, "      if (n >= first) rosters[n] = [...ros];", "      rosters[n] = [...ros];")]),
    ("js", "C-5: the session record's info unbounded", [(J, "      b(r.sealedInfo).length <= TREE_INFO_MAX,\n    \"sessionOf()\",", "      true,\n    \"sessionOf()\",")]),
    ("js", "C-5: one key at two leaves of a session read as its error", [(J, '      if (e instanceof pc.PqChatError) corrupt("sessionOf()");\n      throw e;\n    }\n  }', "      throw e;\n    }\n  }")]),
    ("js", "C-5: a commit's signed epoch not its number", [(J, "      r.epoch === n &&\n      r.sessionId === a.sid &&\n      hex(", "      r.sessionId === a.sid &&\n      hex(")]),
    ("js", "C-5: epochsOf's first id", [(J, 'if (head < 0 || ids[0] !== sid) corrupt("epochsOf()");', 'if (head < 0) corrupt("epochsOf()");')]),
    ("js", "C-5: groupMode", [(J, '  if (S0.groupMode !== 1) refuse("PqChatModeEntry");\n', "")]),
    ("js", "C-5: the snapshot's treeId", [(J, "    t.treeId === treeId &&\n", "")]),
    ("js", "C-5: the snapshot's used", [(J, "    t.used === w.used &&\n", "")]),
    ("js", "C-5: the snapshot's genesisTreeHash", [(J, "    (pin || t.genesisTreeHash === tr.treeHash(a.trees[0])) &&\n", "")]),
    ("js", "C-5: the node list's length", [(J, "    nodes.length === tr.nodeWidth(w.leaves) &&\n", "")]),
    ("js", "C-5: an empty sealedInfo", [(J, "      b(r.sealedInfo).length >= 1 &&\n      b(r.sealedInfo).length <= TREE_INFO_MAX &&\n      [...r", "      b(r.sealedInfo).length <= TREE_INFO_MAX &&\n      [...r")]),
    ("js", "C-5: an exit's sessionId", [(J, "    if (r.sessionId !== a.sid) corrupt(read);\n", "")]),
    ("js", "C-5: a removal of no UA", [(J, "      r.members.length > 0 &&\n", "")]),
    ("js", "C-5: the pin's tree not compared", [(J, "    JSON.stringify(p.tree) !== JSON.stringify(store.tree) ||\n", "")]),
    ("js", "C-5: the pin's gone register not compared", [(J, "    JSON.stringify(p.gone) !== JSON.stringify(store.gone) ||\n", "")]),
    ("js", "C-5: an admin's same info leaves the flag", [(J, '        if (admin) flagged = false;\n        info = "full";', '        info = "full";')]),
    ("js", "C-5: the info to seal of a period that ended", [(J, "  return e && e.epoch === r.pin.epoch && e.state", "  return e && e.state")]),
    ("js", "C-5: a cold tree with one key twice", [(PT, '    if (live(t).some((n) => n.kemHash === hex(m.kemHash))) refuse("PqChatTreeKeyLive");\n', "")]),
    ("js", "D2-9: 33 admins", [(PT, "  if (admins.length > TREE_ADMINS_MAX || ", "  if (admins.length > TREE_ADMINS_MAX + 1 || ")]),
    # ---- ua-rs
    ("rs", "C-1: a cold tree's key unauthenticated", [(R, "    kem_record_key(ua, key_id, &rec)\n}", "    Ok(rec.kem_pk().to_vec())\n}")]),
    ("rs", "F-1: an msig judged on its first structure", [(R, "        let current = |id: [u8; 32]| rd.current(&id);", "        let current = |_: [u8; 32]| None;")]),
    ("rs", "C-3: ids below the pin taken as served", [(R, "        if m >= self.n0 {\n            return at(&self.ids, m);", "        if true {\n            return at(&self.ids, m);")]),
    ("rs", "B2-6: a UA exiting twice under one head", [(R, "        if goes.len() != out.len()\n            || owed", "        if owed")]),
    ("rs", "B2-6, C21: the owed leaves unbounded", [(R, "            || owed > TREE_CHANGES_MAX\n", "")]),
    ("rs", "B2-6, C24: the last leafy admin removed", [(R, "            || (admins.iter().any(leafy)\n", "            || (false\n")]),
    ("rs", "B2-6, C24: no leave exempts the last leafy admin", [(R, "                && !out.iter().any(|(u, k)| *k == 1 && leafy(u)))", "                && true)")]),
    ("rs", "E-3: a tree per epoch", [(R, "            let kept = n == n0 || n == head || keep.is_none_or(|k| k.contains(&n));", "            let kept = true;")]),
    ("rs", "E-3: a resumed replay walks from the cold tree", [(R, "            Some(f) => Walk::new(sc, rd, Some(&f.pin), Some(&[]))?,", "            Some(_) => Walk::new(sc, rd, None, Some(&[]))?,")]),
    ("rs", "E-3: rosters of every epoch", [(R, "                if n >= first {\n                    rosters.insert(n, ros.clone());\n                }", "                rosters.insert(n, ros.clone());")]),
    ("rs", "C-2: leaves left by the served joinEpoch", [(R, "                    top.leaf(x.leaf).is_some_and(|l| {\n                        l.ua == x.ua && l.key_id == x.key_id && l.kem_hash == x.kem_hash\n                    })", "                    a.leaves.get(x.leaf as usize).is_some_and(|l| u64j(l, \"joinEpoch\").ok() == Some(n)) && top.used > 0")]),
    ("rs", "C-5: the session record's info unbounded", [(R, "                    && (1..=TREE_INFO_MAX).contains(&bytes(s0.get(\"sealedInfo\")?).ok()?.len()),", "                    && true,")]),
    ("rs", "C-5: one key at two leaves of a session read as its error", [(R, "        Tree::cold(&leaves).map_err(|_| Error::Tree(TreeError::ReadCorrupted))", "        Tree::cold(&leaves)")]),
    ("rs", "B2-8: a tree epoch key sealed", [(RA, "        // a tree epoch key `K_e` is a handle and never leaves sealed either (spec §15, B-8, B2-8), as `wrap_with` refuses\n        if matches!(key.origin, Origin::Tree) {\n            return Err(Error::Argument);\n        }\n", "")]),
    ("rs", "B-5: a leaf outside the tree", [(R, "    if author_leaf >= leaves {\n        return None;\n    }\n", "")]),
    ("rs", "F-4: the removal's review names another epoch", [(R, '    let within = applies_within(&format!("epoch {}", r.next_epoch.saturating_sub(1)));', '    let within = applies_within(&format!("epoch {}", r.next_epoch));')]),
    ("rs", "F-4: the leave's review says nothing of the lag", [(R, '        vec![("cannotComeBack".into(), back), within],\n    )\n}\n\n/// A `treeRemove`', '        vec![("cannotComeBack".into(), back)],\n    )\n}\n\n/// A `treeRemove`')]),
    ("rs", "D2-9: 33 admins in a commit", [(RP, "        if admins.len() > TREE_ADMINS_MAX || ", "        if admins.len() > TREE_ADMINS_MAX + 1 || ")]),
    # ---- pqchat-core
    ("pqc", "E-1: a flagged UA may not be dropped", [(CC, "        } else if child.get(j).is_some_and(|c| *c < p) || !flagged(p) {", "        } else if child.get(j).is_some_and(|c| *c < p) || true {")]),
    ("pqc", "E-1, D2-8: a removed UA not flagged", [(CC, "    let flagged = |u: &String| left.contains(u) || removed.contains(u);", "    let flagged = |u: &String| left.contains(u);")]),
    ("pqc", "E-1: an admin that left changes membership", [(CC, "        parent.admins.contains(a) && !left.contains(a) && !removed.contains(a)", "        parent.admins.contains(a)")]),
    ("pqc", "E-1: the builder's plain ignores removals", [(CB, "        let plain = crate::check::plain(&uas, &admins, p, &left, &removed);", "        let plain = crate::check::plain(&uas, &admins, p, &left, &[]);")]),
    ("pqc", "U-1: one link checked", [(CR, "        if self.verifies(&s.chain, contract).await? {\n            return self.walk(s, contract, e).await;\n        }\n", "")]),
    ("pqc", "D2-1: an ancestor's id not recomputed", [(CS, "            if !id.is_ok_and(|x| x.eq_ignore_ascii_case(epoch_id)) {", "            if id.is_err() {")]),
    ("pqc", "E-4: a remover outside the parent's admins", [(CS, "                && p.admins.contains(&admin)\n", "")]),
    ("pqc", "E-4: a removed UA outside the parent", [(CS, "                    .all(|m| p.has_member(m) || p.admins.contains(m));", "                    .all(|_| true);")]),
    ("pqc", "E-4: a leaver outside the parent", [(CS, "            if named(l).await?.is_some() && p.has_member(&member) {", "            if named(l).await?.is_some() {")]),
    ("pqc", "B2-4: the exit counts unbounded", [(CS, "            if n > most {", "            if false {")]),
    ("pqc", "B2-3: no lag on the ancestors", [(CS, "        while cur.epoch > 0 && (out.len() as u64) <= EXIT_LAG_MAX {", "        while cur.epoch > 0 {")]),
    ("pqc", "B2-3: a removal's nextEpoch", [(CS, "            if ok && named(r).await?.is_some_and(|n| next == n + 1) {", "            if ok && named(r).await?.is_some() {")]),
    ("pqc", "E-5: a replica judged", [(CR, "            let r = self.checked_at(s, rep, epoch_id, false).await?;", "            let r = self.checked_at(s, rep, epoch_id, true).await?;")]),
    ("pqc", "D2-4: no lag before signing", [(CB, "        if h.epoch < e.epoch || h.epoch > e.epoch + crate::signed::EXIT_LAG_MAX {", "        if h.epoch < e.epoch {")]),
    ("pqc", "D2-4: a removal pre-checked at the epoch named", [(CB, '            if self.flag(s, &h, "IPqChat.removedIn", u).await? {', '            if self.flag(s, e, "IPqChat.removedIn", u).await? {')]),
    # ---- pqvault-core
    ("pqv", "B2-3: no lag", [(V, ".get(i.saturating_sub(EXIT_LAG_MAX as usize)..=i)", ".get(0..=i)")]),
    ("pqv", "B2-3: the named epoch only", [(V, ".get(i.saturating_sub(EXIT_LAG_MAX as usize)..=i)", ".get(i..=i)")]),
    ("pqv", "B2-3: a removal's nextEpoch", [(V, "                    || named.is_none_or(|a| x.next_epoch.0 != a.number + 1)\n", "                    || named.is_none()\n")]),
    ("pqv", "B2-3: a remover outside the head's admins", [(V, "                    || !e.admins.contains(&x.admin)\n", "")]),
    # ---- scaas-sdk: the exit reviews (F-4, D2-3)
    ("sdk", "F-4: a mode-0 exit's review says nothing of the lag", [(SL, "        p.review.push(applies_within(&named));\n        Ok(p)\n    }\n\n    /// `PqChatRemove`", "        let _ = named;\n        Ok(p)\n    }\n\n    /// `PqChatRemove`")]),
    ("sdk", "F-4: a PqVault exit's review says nothing of the lag", [(SA, "        p.review.extend(within);\n", "        let _ = within;\n")]),
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
