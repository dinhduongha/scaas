#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T3d: the `UASig` builder's tests (tests/wallet_uasig.rs: sign.json msig rows byte-equal and refused, portable.json /
nested.json / pq_signatures.json msig rows rebuilt and verified by ua8.rs, the minimal rule at both levels, sorted slots, the slot's
key against its member, the single-key forms) catch a change in what they test. One mutant per run on a clean tree (one or more
replacements in one file), the suite run, the file restored byte for byte after it; a mutant that does not compile is reported as
such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t3d-mutants.py [first last]   (from the worktree root, foreground)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
U = UA + "src/wallet/uasig.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_uasig"]
L1 = "if !msig_slots_minimal(key_data, &slots.iter().map(Slot::index).collect::<Vec<_>>())? {"
L2 = "if !msig_slots_minimal(&d, &members.iter().map(|(j, _)| *j).collect::<Vec<_>>())? {"
M = [
    # the plan's T3d list
    ("minimal check skipped (level 1)", U, [(L1, "if false && " + L1[3:])]),
    ("minimal check skipped (level 2)", U, [(L2, "if false && " + L2[3:])]),
    ("memberDigest over the wrong structure (level 1: the member's id, not the msig's)", U, [
        ("leaf(*key, p.member.kind, ua, msg)?", "leaf(*key, p.member.kind, &p.member.id, msg)?")]),
    ("memberDigest over the wrong structure (level 2: the outer msig, not the inner)", U, [
        ("leaf(*key, m.kind, &p.member.id, &inner_msg)?", "leaf(*key, m.kind, ua, &inner_msg)?")]),
    ("memberDigest over the wrong structure (level 2: the inner message without the outer memberDigest)", U, [
        ("&purpose_tag(\"member\")?, &member_digest(ua, msg))?", "&purpose_tag(\"member\")?, msg)?")]),
    ("slots unsorted (level 1: sorted before the check, emitted as given)", U, [
        (L1, "if !msig_slots_minimal(key_data, &{ let mut v = slots.iter().map(Slot::index).collect::<Vec<_>>(); v.sort(); v })? {")]),
    ("slots unsorted (level 2: sorted before the check, emitted as given)", U, [
        (L2, "if !msig_slots_minimal(&d, &{ let mut v = members.iter().map(|(j, _)| *j).collect::<Vec<_>>(); v.sort(); v })? {")]),
    ("slots unsorted (emitted in reverse)", U, [("plans.iter().map(|p| sign(p, &ua, &msg))", "plans.iter().rev().map(|p| sign(p, &ua, &msg))")]),
    # the controller's additions
    ("membership digest of (member, msig)", U, [("&membership_digest(&ua, &p.member.id)", "&membership_digest(&p.member.id, &ua)")]),
    ("acceptance under the purpose member", U, [("&purpose_tag(\"membership\")?", "&purpose_tag(\"member\")?")]),
    ("slot key not checked against its member", U, [("        _ => Err(Error::Argument),\n    }\n}", "        _ => Ok(()),\n    }\n}")]),
    ("inner key data not checked against the member id", U, [
        ("            if derive_ua(MSIG, &d, false).ok() != Some(member.id) {", "            if false {")]),
    ("each slot signed as it is checked (a refused set signs)", U, [
        ("    let plans = slots.iter().map(|s| plan(&structure, s, inner)).collect::<Result<Vec<_>>>()?;\n"
         "    let msg = ua_message(MSIG, purpose, digest)?;\n"
         "    let members = plans.iter().map(|p| sign(p, &ua, &msg)).collect::<Result<Vec<_>>>()?;\n",
         "    let msg = ua_message(MSIG, purpose, digest)?;\n"
         "    let members = slots.iter().map(|s| sign(&plan(&structure, s, inner)?, &ua, &msg)).collect::<Result<Vec<_>>>()?;\n")]),
    ("ua_sig keeps keyData for a stored kind", U, [("let bare = stored(kind) || ", "let bare = ")]),
    ("ua_sig keeps keyData for the portable purposes", U, [("stored(kind) || is_portable_purpose(purpose) || ", "stored(kind) || ")]),
    ("ua_sig drops keyData for every kind", U, [("key_data: if bare { vec![] } else { key_data }", "key_data: vec![]")]),
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
    loaded = "could not compile" not in out and "failed to run custom build command" not in out
    failed = sorted(set(re.findall(r"^---- (\S+) stdout ----", out, re.M)))
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    where = f.removeprefix(UA)
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:160]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
