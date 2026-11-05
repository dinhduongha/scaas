#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T4: the EIP-712 hasher, the SCaaS builders' canonical step, the `Expect` policy and the native `UASig` / `msig` arms
(tests/wallet_typed.rs: typed_ops.json, portable.json, nested.json, sign.json typed / canon / policy rows, the bounds, the checked
path; tests/wallet_uasig.rs: the native member rows, R17) catch a change in what they test. One mutant per run on a clean tree (one
or more replacements, in one or more files), the suite run, every file restored byte for byte after it; a mutant that does not
compile is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t4-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t4-mutants.py check           (every replacement found once, no run)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
E = UA + "src/wallet/eip712.rs"
P = UA + "src/wallet/policy.rs"
U = UA + "src/wallet/uasig.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors",
         "--test", "wallet_typed", "--test", "wallet_uasig"]
ZEROED = ("\n/// mutant: the server's value canonicalised\npub(crate) fn zeroed(td: &TypedData) -> Result<TypedData> {\n"
          "    let mut c = td.clone();\n    c.message = td.canonical(&td.primary_type, Some(&td.message))?;\n    Ok(c)\n}\n")
M = [
    # the plan's T4 list
    ("unbound relayer hashed (the builders keep it)", [(E, "                if mode & 1 == 0 {", "                if false {")]),
    ("canon skipped on a nested struct", [(E, "                m.insert(n.clone(), self.canonical(t, o.get(n))?);",
        "                m.insert(n.clone(), if self.types.contains_key(t.as_str()) { o.get(n).cloned().unwrap_or(Value::Null) } "
        "else { self.canonical(t, o.get(n))? });")]),
    ("canon applied on Any (every request canonicalised)", [(E,
        "    Ok(SignRequest::Eip712 { domain_separator: td.domain_separator()?, struct_hash: td.struct_hash()?, typed_data: Box::new(td.clone()) })",
        "    let td = &TypedData { message: td.canonical(&td.primary_type, Some(&td.message))?, ..td.clone() };\n"
        "    Ok(SignRequest::Eip712 { domain_separator: td.domain_separator()?, struct_hash: td.struct_hash()?, typed_data: Box::new(td.clone()) })")]),
    ("the checked path zeroes a non-zero unbound field instead of refusing it", [
        (E, "\n// --- the SCaaS structs", ZEROED + "\n// --- the SCaaS structs"),
        (P, "        let req = eip712::request(td)?;",
            "        let z = if matches!(expect, Expect::Any(_)) { td.clone() } else { eip712::zeroed(td)? };\n"
            "        let req = eip712::request(&z)?;\n        let td = &z;")]),
    ("policy check skipped", [(P, "if !matches!(expect, Expect::Any(AllowAnyTypedData)) && check(td, &expect)? != digest {",
        "if false && check(td, &expect)? != digest {")]),
    ("EIP712Domain field order changed (version before name)", [(E,
        '[("name", "string"), ("version", "string"), ("chainId", "uint256")',
        '[("version", "string"), ("name", "string"), ("chainId", "uint256")')]),
    # the hasher
    ("unknown field accepted (hashStruct)", [(E,
        "        if o.keys().any(|k| !fields.iter().any(|(n, _)| n == k)) {\n            return Err(Error::Argument);\n        }\n"
        "        let mut enc = keccak256(self.encode_type_of(name).as_bytes()).to_vec();",
        "        let mut enc = keccak256(self.encode_type_of(name).as_bytes()).to_vec();")]),
    ("cyclic types accepted", [(E, "            Some(None) => return Err(Error::Argument), // a cycle", "            Some(None) => return Ok(0),")]),
    ("type reference depth unbounded", [(E, "        if d > MAX_TYPE_DEPTH {", "        if false {")]),
    ("negative int as its magnitude (no two's complement)", [(E, "    if !neg || mag == [0; 32] {", "    if true {")]),
    ("fixed array length not checked", [(E, "len.is_some_and(|k| k != items.len())", "false")]),
    ("array cap one past 1,024", [(E, "    if items.len() > MAX_ARRAY ||", "    if items.len() > MAX_ARRAY + 1 ||")]),
    ("uintN range not checked (256 bits only)", [(E, "                if bit_len(&x) > bits {", "                if bit_len(&x) > 256 {")]),
    ("canon: feeRecipient kept by the relayer bit", [(E, "                if mode & 2 == 0 {", "                if mode & 1 == 0 {")]),
    # the policy
    ("fee above the limit accepted", [(P, "    if fee > uint_str(max_fee)? {", "    if false {")]),
    ("deadline window unchecked", [(P, "    if until > u256_from(now) && until <= hi {", "    if until > u256_from(now) {")]),
    ("transfer / approve signed as a call", [(P, "    if never_called(selector) {", "    if false {")]),
    ("requireWhole: a named relayer without its mode bit", [(P, '    if dropped("relayer", 1) || dropped("feeRecipient", 2) {', "    if false {")]),
    ("Any without its marker", [(P, '                if x.take("allowAnyTypedData") != Some(Value::Bool(true)) {', "                if false {")]),
    # the native arms (R17, CTR-UA-07, CTR-UA-24)
    ("R17: a native UASig carries key data", [(U, "        return Ok(UASig { key_data: vec![], signature, members: vec![] });",
        "        return Ok(UASig { key_data: id.to_vec(), signature, members: vec![] });")]),
    ("native leaf UAAuth under the outer purpose tag metatx", [(U,
        "                    eip712::request(&eip712::ua_auth(d, &m.id, &purpose_tag(\"member\")?, &md)?)?",
        "                    eip712::request(&eip712::ua_auth(d, &m.id, &purpose_tag(\"metatx\")?, &md)?)?")]),
    ("native leaf UAAuth over the member's own id as the structure", [(U,
        "                    let md = member_digest(structure, level_msg);", "                    let md = member_digest(&m.id, level_msg);")]),
    ("native record not checked against the digest", [(U,
        "            if r.domain_separator()? != PORTABLE_DOMAIN_SEPARATOR || r.digest()? != *digest {",
        "            if r.domain_separator()? != PORTABLE_DOMAIN_SEPARATOR {")]),
    ("native UASig in a portable purpose", [(U, "        if is_portable_purpose(purpose) {\n            return Err(Error::Argument);\n        }\n        let td = eip712::ua_auth",
        "        let td = eip712::ua_auth")]),
]
assert len({m[0] for m in M}) == len(M)
srcs = {f: open(f, encoding="utf-8").read() for _, reps in M for f, _, _ in reps}
for name, reps in M:
    new = dict(srcs)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, f, a, new[f].count(a))
        new[f] = new[f].replace(a, b)
if sys.argv[1:] == ["check"]:
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = subprocess.run(SUITE, capture_output=True, text=True, cwd=UA)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    out = r.stdout + r.stderr
    loaded = "could not compile" not in out and "failed to run custom build command" not in out
    failed = sorted(set(re.findall(r"^---- (\S+) stdout ----", out, re.M)))
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    where = ", ".join(sorted({f.removeprefix(UA) for f, _, _ in reps}))
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:160]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
