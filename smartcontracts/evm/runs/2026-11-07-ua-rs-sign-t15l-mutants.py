#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15l (the fix wave after the Fable review of 2026-11-07; spec no-decryption-oracle §4.6, §4.7, §4.8): each
mutant undoes one fix and names the test that must catch it. One mutant per run on a clean tree, its command, every file
restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a build that does not
compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15l-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15l-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t15l-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R, Q = "clients/ua-rs/", "clients/ua-rs/src/facade/pqz.rs"
ZP, ST, RB = "clients/zether-prover/", "clients/zether-prover/src/state.rs", "clients/zether-prover/src/bin/zether-read-balance.rs"
CTF = "scripts/check_test_features.py"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
PQ = lambda *n: (R, CARGO + ["--features", "vectors", "--test", "facade_pqz_state", *n])
SRC = lambda *n: (R, CARGO + ["--test", "facade_pqz", *n])
ZS = (ZP, CARGO + ["--test", "state"])
CHK = (".", ["python3", "-I", CTF])

M = [
    # P2-1: op 4 on the entry's words
    ("op 4: a caller's amount on the allow-list",
     [(Q, '"proveDiscloseSender" => has(LOC) || has(ENTRY) || has(&["registry", "leg", "legKeyRecords"]),',
       '"proveDiscloseSender" => has(LOC) || has(ENTRY) || has(&["registry", "leg", "legKeyRecords", "amount"]),')],
     PQ("sender_disclosure_negatives")),
    ("op 4: the leg's v not compared with the re-derivation (u only)",
     [(Q, "            if bool::from(v_eq) {\n                found = Some((x, pk_t, c, i, amount));",
       "            if true {\n                let _ = v_eq;\n                found = Some((x, pk_t, c, i, amount));")],
     PQ("sender_disclosure_negatives")),
    # (M3 and M4 first tried an M = 1 entry as op 1 only / op 7 only: both survived, because op 1 IS op 7's encryption at
    # M = 1, so the two re-derivations were one; the code now makes one, and these two mutants test the group arithmetic)
    ("op 4: the leg's index inside its group ignored", [(Q, "let (n, i) = ((lo + per).min(m) - lo, j - lo);", "let (n, i) = ((lo + per).min(m) - lo, 0);")],
     PQ("sender_disclosure_over_rebuilt_words")),
    ("op 4: group 0's seed for every group", [(Q, "&pqzl::enc_group_seed(seed, g)", "&pqzl::enc_group_seed(seed, 0)")],
     PQ("sender_disclosure_over_rebuilt_words")),
    ("op 4: the digit count off by one", [(Q, "let k = (1..16u64).fold(", "let k = (0..16u64).fold(")],
     PQ("sender_disclosure_over_rebuilt_words")),
    ("op 4: the leg owner's key taken from the sender's record",
     [(Q, 'let pk_ts = records.iter().map(|r| registered_key(r, &mut blobs)).collect::<Result<Vec<_>>>()?;',
       'let pk_ts = { records.iter().map(|r| registered_key(r, &mut blobs)).collect::<Result<Vec<_>>>()?; vec![key.clone()] };')],
     PQ("sender_disclosure_over_rebuilt_words")),
    # P3-2: the opened memo compared in constant time
    ("openMemo: the opened values compared with `!=` / `Iterator::ne`",
     [(Q, "let same = legs.iter().zip(uas).fold(u8::from(*a).ct_eq(&u8::from(aud)), |c, (l, w)| c & l.1.ct_eq(w));",
       "let same = Choice::from(u8::from(!(*a != aud || legs.iter().map(|l| l.1).ne(uas.iter().copied()))));")],
     SRC("open_memo_compares_in_constant_time")),
    # P3-6: forOp7
    ("balance: forOp7 ignored", [(Q, "            let (_, o) = own(f, op7, false)?;", "            let (_, o) = own(f, op7 && false, false)?;")],
     PQ("requests_carry_words_only")),
    ("balance: forOp7 defaults to false", [(Q, 'let op7 = f.get("forOp7")?.as_bool().ok_or(Error::Argument)?;',
                                            'let op7 = f.get("forOp7").ok().and_then(Value::as_bool).unwrap_or(false);')],
     PQ("requests_carry_words_only")),
    # P3-1: Zether's balance hint from the sealed box only
    ("checkBalance: a plain balance back on the allow-list", [(ST, '"checkBalance" => has(LOC) || has(ACCT) || field == "cacheBox",',
                                                               '"checkBalance" => has(LOC) || has(ACCT) || field == "cacheBox" || field == "balance",')],
     (R, CARGO + ["--features", "vectors", "--test", "facade_zether_state", "balances_from_the_words"])),
    ("checkBalance: the cache entry's accSeq not compared", [(ST, "let ok = seq == a.acc_seq && check_balance(", "let ok = seq == seq && check_balance(")],
     ZS),
    ("a debit: a stale cache entry used", [(ST, "                        (seq == a.acc_seq).then_some(b)", "                        Some(b)")], ZS),
    ("open_cache_entry: another UA's entry read", [(ST, 'entries.get(format!("{}:{}", hx(&k.ua()), hx(token)))',
                                                   'entries.as_object().and_then(|o| o.values().next())')],
     ZS),
    # P3-4: the test-feature check's new rows
    ("check_test_features: scaas-ct not guarded", [(CTF, 'GUARDED = ("scaas-ua", "zether-prover", "pqz-ffi", "scaas-ct")',
                                                    'GUARDED = ("scaas-ua", "zether-prover", "pqz-ffi")')], CHK),
    ("check_test_features: scaas-node not an artifact", [(CTF, '    ("scaas-node", []),', '')], CHK),
    ("check_test_features: pqz-core/ffi/wasm not an artifact", [(CTF, '    ("pqz-core/ffi/wasm", []),', '')], CHK),
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
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:400]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
