#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15m (ARCH-POS-13; spec no-decryption-oracle §4.2 R1–R7): each mutant undoes one check of `pqz-read`, the PQZ
reference reading layer, and names the test that must catch it. One mutant per run on a clean tree, its command, every file
restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a build that does not
compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1). The CLI runs against a local
anvil (`ANVIL`, default ~/.foundry/bin/anvil; killed by the test).
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15m-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15m-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15m-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R, B = "clients/ua-rs/", "clients/ua-rs/src/bin/pqz-read.rs"
CTF = "scripts/check_test_features.py"
CAPPED = os.path.abspath("scripts/capped")
ANVIL = os.environ.get("ANVIL", os.path.expanduser("~/.foundry/bin/anvil"))
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "ANVIL": ANVIL}
T = (R, [CAPPED, "cargo", "test", "--locked", "--offline", "-j2", "--test", "pqz_read", "--", "--include-ignored"])
CHK = (".", ["python3", "-I", CTF])

M = [
    # R1: one source; the holder's configuration
    ("R1: a second --rpc accepted", [(B, "        if !seen.insert(f.clone()) {", '        if !seen.insert(f.clone()) && f != "--rpc" {')], T),
    ("--registry not required", [(B, '"--factory", "--registry", "--token", "--ua"];', '"--factory", "--token", "--ua"];')], T),
    # R2
    ("R2: chain id not compared", [(B, '    if qty(&rpc(url, "eth_chainId", json!([]))?)? != a.chain_id {', "    if false {")], T),
    ("R2: genesis hash not compared", [(B, '    if unhex(genesis["hash"].as_str().ok_or("R2: no genesis hash")?)? != a.chain_uid {', "    if false {")], T),
    # R3
    ("R3: a depth past the head read at genesis",
     [(B, '.checked_sub(d).ok_or("R3: the chain is shorter than the confirmation depth")?;', ".saturating_sub(d);")], T),
    ("R3: the node's block not compared with the one asked for", [(B, "    if want.is_some_and(|n| n != block) {", "    if false {")], T),
    ("R3: the block not re-checked after the reads", [(B, '    if again["hash"].as_str() != Some(r.hash.as_str()) {', "    if again.is_null() {")], T),
    ("R3: reads at latest, not by block hash", [(B, 'json!({"blockHash": self.hash, "requireCanonical": true})', 'json!("latest")')], T),
    # R5
    ("R5: the catalogue not read", [(B, "    if info[2] != 1 || !PQZ_KINDS.contains(&info[11]) {", "    if false {")], T),
    ("R5: exists not checked", [(B, "    if info[2] != 1 || !PQZ_KINDS.contains(&info[11]) {", "    if !PQZ_KINDS.contains(&info[11]) {")], T),
    ("R5: a Zether kind accepted", [(B, "const PQZ_KINDS: [u8; 4] = [4, 5, 12, 13];", "const PQZ_KINDS: [u8; 5] = [4, 5, 12, 13, 2];")], T),
    # R6
    ("R6: the registered key not compared with the handle's",
     [(B, "    if r.key_code.split_first() != Some((&0, k.pk().as_slice())) {", "    if false {")], T),
    ("R6: --ua not compared with auditorUA",
     [(B, "        if auditor_ua != a.ua || !matches!(field(&mode, \"auditorMode\")?, 1 | 2) {",
       "        if !matches!(field(&mode, \"auditorMode\")?, 1 | 2) {")], T),
    ("R6: auditorMode NONE accepted",
     [(B, "        if auditor_ua != a.ua || !matches!(field(&mode, \"auditorMode\")?, 1 | 2) {", "        if auditor_ua != a.ua {")], T),
    # the words (R4 and the facade's window)
    ("the pending window past INLINE_MAX", [(B, "    let p = count.min(rolled.saturating_add(inline.min(room)));", "    let p = count.min(rolled + room);")], T),
    ("op 7's PQZH window ignored",
     [(B, "    let inline = if a.for_op7 == Some(true) && psid == PQZH_ID { INLINE_MAX_PQZH } else { INLINE_MAX };",
       "    let inline = if a.for_op7 == Some(true) { INLINE_MAX_PQZH } else { INLINE_MAX };")], T),
    ("a materialised acc not read", [(B, "        if flags & 1 != 0 {\n            let first", "        if flags & 1 == 2 {\n            let first")], T),
    ("the acc reference's blob not read", [(B, "            ptrs.push(acc_blob);", "            let _ = acc_blob;")], T),
    ("a pending credit's blob not read", [(B, "                ptrs.push(low_addr(&e, 12));", "                let _ = low_addr(&e, 12);")], T),
    ("entryRef of another chain id", [(B, "be(a.chain_id), a.chain_uid, addr_word(&a.token)", "be(0), a.chain_uid, addr_word(&a.token)")], T),
    # the production-artifact check
    ("check_test_features: ua-rs not an artifact", [(CTF, '    ("clients/ua-rs", []),', "")], CHK),
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
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M)) | set(re.findall(r"^FINDING: (.+)$", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
