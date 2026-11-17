#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20d2, `ownTag` and the 3h `memoHash` in every PQZ debit (C-PP-4; proof-path spec PP-3, C3, C4; no-oracle spec
§4.14.5): each mutant undoes one rule of the facade's `own_tag`, its packer or a debit builder's `memoHash`
(`clients/ua-rs/src/facade/pqz.rs`, `pqz_pack.rs`) and names the tests that must catch it (facade_pqz_state.rs:
`own_tag_of_every_debit`, `own_tag_and_memo_hash_kat`, the memo tests, `stored_form_is_the_contracts`; feature `vectors`, so the
KAT's facade half runs too). The plan's "the current version's seed for a stale debit" has no mutant: a handle holds the seed of
its one version (a debit's `keyVersion` must name the handle's key, KV-8), so no code path reaches another version's seed;
`own_tag_of_every_debit` pins the stale refresh and the migration to the stale seed and shows version 1's seed gives another tag.
One mutant per run on a clean tree, its command, every file restored byte for byte after it (the caller also runs `git diff
--exit-code`). A failing command kills; a build that does not compile is NOT-LOADED (a finding); a mutant whose command passes
SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d2-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d2-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-09-ua-rs-sign-t20d2-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
Q, P = R + "src/facade/pqz.rs", R + "src/facade/pqz_pack.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
T = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "facade_pqz_state", "--",
         "own_tag", "memo", "stored_form"])
H1 = "            Memo::Mode(_) => crate::keccak256(&[sealed.as_deref().unwrap_or_default(), &tag[..]].concat()),"
H7 = "            None => crate::keccak256(&[memo.as_deref().unwrap_or_default(), &tag[..]].concat()),"

M = [
    # the plan's
    ("another label", [(Q, 'const OWN_TAG_LABEL: &[u8] = b"PQZ/owntag/v1";', 'const OWN_TAG_LABEL: &[u8] = b"PQZ/owntag/v2";')], T),
    ("be64 counter", [(Q, "&ctr.to_be_bytes(), &crate::keccak256(&parts)", "&u64::from(ctr).to_be_bytes(), &crate::keccak256(&parts)")], T),
    ("P(v_f) ‖ P(u)", [(Q, "[super::pqz_pack::pack(u).ok_or(Error::Argument)?, super::pqz_pack::pack(v_f).ok_or(Error::Argument)?]",
                        "[super::pqz_pack::pack(v_f).ok_or(Error::Argument)?, super::pqz_pack::pack(u).ok_or(Error::Argument)?]")], T),
    ("the unpacked instead of the stored form",
     [(Q, "[super::pqz_pack::pack(u).ok_or(Error::Argument)?, super::pqz_pack::pack(v_f).ok_or(Error::Argument)?]", "[u.to_vec(), v_f.to_vec()]")], T),
    ("ownTag left out of op 1's HASH memoHash", [(Q, H1, "            Memo::Mode(_) => crate::keccak256(sealed.as_deref().unwrap_or_default()),")], T),
    ("ownTag left out of op 7's HASH memoHash", [(Q, H7, "            None => crate::keccak256(memo.as_deref().unwrap_or_default()),")], T),
    ("the pre-3h formula on a 3h token (op 1: keccak256(salt ‖ sealedMemo), BUNDLE 0)",
     [(Q, H1, "            Memo::Mode(_) => sealed.as_deref().map_or([0; 32], crate::keccak256),")], T),
    ("the pre-3h formula on a 3h token (burn, refresh: 0)", [(Q, "            None => crate::keccak256(&tag),", "            None => [0; 32],")], T),
    # the round's own
    ("the debit's answer without ownTag",
     [(Q, "Ok(with_tag(proved(&stmt, &prove(form.op(), &stmt, &wit, &d.rnd32)?), &tag))", "Ok(proved(&stmt, &prove(form.op(), &stmt, &wit, &d.rnd32)?))")], T),
    ("the counter from another header word (p)",
     [(Q, "pqz_ffi::stmt::word_u64(w(H_SEND_COUNTER)?)", "pqz_ffi::stmt::word_u64(w(H_P)?)")], T),
    ("the token as its 32-byte word", [(Q, "let token = w(H_TOKEN)?.get(12..)", "let token = w(H_TOKEN)?.get(0..)")], T),
    ("op 1's tag over v_t, not v_f", [(Q, "let tag = own_tag(seed32, &hd, &c.0.u[..], v(1)?)?;", "let tag = own_tag(seed32, &hd, &c.0.u[..], v(0)?)?;")], T),
    ("the packer takes a coefficient wider than B bits",
     [(P, "        if x >> B != 0 {\n            return None;\n        }\n", "")], T),
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
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
