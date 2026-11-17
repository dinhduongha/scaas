#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15o (the client side of group 3g, versioned PQZ keys; spec 2026-11-06-pqz-key-versions.md on ua-mtx-merge): each
mutant undoes one new rule (the key version's derivation and store slot, the R_REG message of a version, the facade's version
words, the stale rule, the pairwise distinct keys, the additive sender recovery, pqz-read's versioned reads and its pending
decoy filter, the C ABI's version export and statuses, clientkeys' seed and the version-record builder, ua-py's version
parameter) and names the test that must catch it. One mutant per run on a clean tree, its command, every file restored byte
for byte after it (the caller also runs `git diff --exit-code`). A failing command kills; a build that does not compile is
NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1). The pqz-read tests run against a local
anvil (`ANVIL`, default ~/.foundry/bin/anvil; killed by the tests); the ua-py mutant loads the release libscaas_ua_c as built.
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t15o-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t15o-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t15o-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R, UC, CK, PY = "clients/ua-rs/", "clients/ua-c/", "clients/clientkeys/", "clients/ua-py/"
Q, DV, B, U8 = R + "src/facade/pqz.rs", R + "src/wallet/derive.rs", R + "src/bin/pqz-read.rs", R + "src/ua8.rs"
CLIB, JS, WP = UC + "src/lib.rs", CK + "src/pq.js", PY + "scaas_ua/wallet.py"
CAPPED = os.path.abspath("scripts/capped")
ANVIL = os.environ.get("ANVIL", os.path.expanduser("~/.foundry/bin/anvil"))
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "ANVIL": ANVIL}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
FP = lambda t: (R, CT + ["--test", "facade_pqz", t])
FS = (R, CT + ["--test", "facade_pqz_state", "key_versions"])
FSV = (R, CT + ["--features", "vectors", "--test", "facade_pqz_state", "key_versions"])
WN = (R, CT + ["--test", "facade_pqz_state", "word_negatives"])
PR = (R, CT + ["--test", "pqz_read", "--", "--include-ignored"])
PQ8 = (R, CT + ["--no-default-features", "--features", "pq", "--test", "ua8", "pqz_key_version"])
UACT = lambda t: (UC, [CAPPED, "sh", "-c", f"cargo build --locked --offline -j2 && python3 -m unittest tests.test_vectors.{t}"])
NODE = (CK, [CAPPED, "node", "--test", "test/pqz-versions.test.js"])
PYT = (PY, ["python3", "-m", "unittest", "tests.test_wallet.Pqz.test_pqz_key_versions_are_the_pq_kat_rows"])

M = [
    # C8: the key version's seed and store slot
    ("no be64(v) suffix for a version >= 1", [(DV, "if version == 0 { &[] } else { &v[..] }", "&[]")], FP("pqz_key_versions_are_the_pq_kat_rows")),
    ("the suffix on version 0 too", [(DV, "if version == 0 { &[] } else { &v[..] }", "&v[..]")], FP("pqz_key_versions_are_the_pq_kat_rows")),
    ("one store slot for every version", [(Q, "store.key(KeyId::Pqz(account, index, version), |seed| {", "store.key(KeyId::Pqz(account, index, 0), |seed| {")],
     FP("pqz_key_versions_are_the_pq_kat_rows")),
    # KV-1, KV-2: R_REG of a version
    ("proveKeyRecord ignores the version", [(Q, "v => crate::ua8::pqz_key_version_digest(ua, *v, &kh),", "_ => crate::ua8::pqz_key_digest(ua, &kh),")],
     FP("key_record_register_verifies")),
    # KV-3, KV-6: the version words
    ("a version above current accepted", [(Q, "if lo_u64(&w, 16, 1)? > 1 || current > latest || v > current {", "if lo_u64(&w, 16, 1)? > 1 || current > latest {")], WN),
    ("current above latest accepted", [(Q, "if lo_u64(&w, 16, 1)? > 1 || current > latest || v > current {", "if lo_u64(&w, 16, 1)? > 1 || v > current {")], WN),
    ("bits above the UA's sendCounter accepted", [(Q, "    only_low(counter, 8)?;\n", "")], WN),
    # KV-8, KV-9: the stale rule
    ("a stale version pays another UA", [(Q, "if o.stale != (f.word(\"toUA\")? == h.from_ua) {", "if !o.stale && f.word(\"toUA\")? == h.from_ua {")], FS),
    ("SelfTransfer at the current version", [(Q, "if o.stale != (f.word(\"toUA\")? == h.from_ua) {", "if o.stale && f.word(\"toUA\")? != h.from_ua {")], FS),
    ("a stale version burns", [(Q, "            if o.stale {\n                return Err(Error::Argument); // KV-8: a stale version burns nothing", "            if false {\n                return Err(Error::Argument); // KV-8: a stale version burns nothing")], FS),
    ("a stale version sends op 7", [(Q, "            if o.stale {\n                return Err(Error::Argument); // KV-8: no op 7", "            if false {\n                return Err(Error::Argument); // KV-8: no op 7")], FS),
    # KeyReused
    ("op 1's keys not compared", [(Q, "            distinct(&[Some(&o.key[..]), Some(&pk_t[..]), pk_a.as_deref()].into_iter().flatten().collect::<Vec<_>>())?;\n", "")], FS),
    ("op 7's keys not compared", [(Q, "            distinct(&std::iter::once(&o.key[..]).chain(pks.iter().map(|k| &k[..])).collect::<Vec<_>>())?;\n", "            let _ = &pks;\n")], FS),
    # KV-11: additive sender recovery
    ("the sender's version not checked first (u)", [(Q, "            if x == 0 && !bool::from(c.0.u[..].ct_eq(u)) {", "            if false {")], FSV),
    ("the matched leg key not named", [(Q, "                found = Some((x, pk_t, c, i, amount));", "                found = Some((0, pk_t, c, i, amount));")], FS),
    # pqz-read
    ("pqz-read: the account of version 0 whatever --key-version", [(B, "        let base = acct_base(&root, &a.ua, v)?;", "        let base = acct_base(&root, &a.ua, 0)?;")], PR),
    ("pqz-read: the key record of version 0", [(B, "    let key_record = r.word(&a.registry, &pqz_key_slot(&a.ua, v))?;", "    let key_record = r.word(&a.registry, &pqz_key_slot(&a.ua, 0))?;")], PR),
    ("pqz-read: the UA's sendCounter from the account struct", [(B, "json!(hx(&r.word(&a.token, &counter_slot(&root, &a.ua)?)?));", "json!(hx(&r.word(&a.token, &add(&base, 2))?));")], PR),
    ("pqz-read: no pending filter", [(B, "            if r.code(&low_addr(&rec, 0))?.len() == 1 + PK_BYTES {\n                continue;\n            }", "            let _ = r.code(&low_addr(&rec, 0))?;")], PR),
    ("pqz-read: a decoy's key at version 0", [(B, "&pqz_key_slot(&ua, d.current.get(&ua).copied().ok_or(\"pickDecoys: not a candidate\")?)", "&pqz_key_slot(&ua, 0)")], PR),
    # the C ABI
    ("C: the version ignored", [(CLIB, "ScaasUaPqzKey(handle(w)?.0.pqz_key_version(account, index, version)?)", "ScaasUaPqzKey(handle(w)?.0.pqz_key(account, index)?)")],
     UACT("WalletPqz.test_pqz_key_versions_are_the_pq_kat_rows")),
    ("C: statuses 41 and 42 named the other way round", [(CLIB, "        SCAAS_UA_ERR_PQZ_KEY_VERSION => c\"UAPqzKeyVersion\",\n        SCAAS_UA_ERR_KEY_IN_USE => c\"UAKeyInUse\",",
                                                           "        SCAAS_UA_ERR_PQZ_KEY_VERSION => c\"UAKeyInUse\",\n        SCAAS_UA_ERR_KEY_IN_USE => c\"UAPqzKeyVersion\",")],
     UACT("WalletAbi.test_status_codes_appended")),
    # clientkeys, the identity layer, ua-py
    ("clientkeys: the suffix on version 0 too", [(JS, "v === 0n ? new Uint8Array(0) : be64", "be64")], NODE),
    ("ua8: a key a stored version holds accepted", [(U8, "    if stored.iter().any(|s| s.1 == pqz_key_hash) {\n        return Err(UAError::KeyInUse);\n    }\n", "")], PQ8),
    ("ua-py: the version not passed", [(WP, "_new(PqzKey, _c('wallet_pqz_key_version'), w, account, index, version)", "_new(PqzKey, _c('wallet_pqz_key'), w, account, index)")], PYT),
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
    failed = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED", out, re.M) + re.findall(r"^(?:FAIL|ERROR): (\S+)", out, re.M)
                        + re.findall(r"^✖ (.+?) \(", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
