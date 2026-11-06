#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T14b (ARCH-POS-13, Codex C6, Fable P3-4; spec no-decryption-oracle §4.2, §4.7, §5): each mutant undoes one guard
of the Zether words path, of `secret_mul`, of `zether-read-balance` as a reading layer or of the facade, and names the test that
must catch it. One mutant per run on a clean tree, its command, every file restored byte for byte after it (the caller also runs
`git diff --exit-code` on the paths). A failing command kills; a build that does not compile is NOT-LOADED (a finding); a mutant
whose command passes SURVIVED (a finding, exit 1). zether-prover's `prepare` refusals are observed directly (no key in that
function); the facade's with feature `vectors` (the key-use counter); the CLI's against a local anvil (`ANVIL`, killed by the
test).
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t14b-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-07-ua-rs-sign-t14b-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

Z, R = "clients/zether-prover/", "clients/ua-rs/"
ST, EL, ZE, SC = Z + "src/state.rs", Z + "src/elgamal.rs", Z + "src/zether.rs", Z + "src/schnorr.rs"
CLI, FA = Z + "src/bin/zether-read-balance.rs", R + "src/facade/zether.rs"
CAPPED = os.path.abspath("scripts/capped")
ANVIL = os.environ.get("ANVIL", os.path.expanduser("~/.foundry/bin/anvil"))
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "ANVIL": ANVIL}
CARGO = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
S = lambda *f: (Z, [*CARGO, "--test", "state", *f])
SM = (Z, [*CARGO, "--test", "secret_mul"])
RB = lambda *f: (Z, [*CARGO, "--test", "read_balance", *f])
FS = lambda *f: (R, [*CARGO, "--features", "vectors", "--test", "facade_zether_state", *f])
NEG = "word_location_and_role_negatives_are_refused_before_the_key"

M = [
    # the plan's three
    ("raw acc accepted (checkBalance allow-list)", [(ST, '"checkBalance" => has(LOC) || has(ACCT) || field == "balance",',
                                                     '"checkBalance" => has(LOC) || has(ACCT) || field == "balance" || field == "acc",')], S(NEG)),
    ("decrypt's [x]D left variable-time", [(EL, "    Ok(ct.c - secret_mul(&ct.d, x)?)", "    Ok(ct.c - ct.d * *x)")], SM),
    ("the CLI's catalogue check skipped (R5)", [(CLI, "    if info[2] != 1 || !ZETHER_KINDS.contains(&info[11]) {", "    if false {")],
     RB("--", "--include-ignored", "rpc_reading_layer_against_anvil")),
    # every other key.x multiplication on a supplied point (Codex C6), one at a time
    ("the burn's balance check variable-time", [(ZE, "if acc.c - secret_mul(&acc.d, &key.x)? != generator::<C>() * Fr::<C>::from(balance) {",
                                                 "if acc.c - acc.d * key.x != generator::<C>() * Fr::<C>::from(balance) {")], SM),
    ("the transfer's A_bal nonce variable-time", [(ZE, "let a_bal = g * k_b + secret_mul(&(st.acc.d - st.d_out), &k_x)?;",
                                                   "let a_bal = g * k_b + (st.acc.d - st.d_out) * k_x;")], SM),
    ("the multi-recipient A_bal nonce variable-time", [(ZE, "g * k_b + secret_mul(&(st.acc.d - st.d_out), &k_x)?, // A_bal",
                                                        "g * k_b + (st.acc.d - st.d_out) * k_x, // A_bal")], SM),
    ("the opening's amount check variable-time", [(SC, "!= secret_mul(&b, &key.x)? {", "!= b * key.x {")], SM),
    ("the opening's nonce on B variable-time", [(SC, "let a2 = encode_point::<C>(&secret_mul(&b, &k)?);", "let a2 = encode_point::<C>(&(b * k));")], SM),
    # leg, role and location (the library's half of R6)
    ("the receiver's leg not bound to the handle", [(ST, 'Some("receiver") if leg[0] == *y => {}', 'Some("receiver") => {}')], S(NEG)),
    ("auditorMode NONE accepted", [(ST, 'if field_u64(&modes, "auditorMode")? == 0 || p.y_aud != *y', "if p.y_aud != *y")], S(NEG)),
    ("an auditor read of a leg without a copy", [(ST, "p.y_aud != *y || leg[3] == G::<B>::default()", "p.y_aud != *y")], S(NEG)),
    ("entryRef not recomputed (slots not checked)", [(ST, "    if slot != s {\n", "    if false {\n"),
                                                      (ST, "        if *slot != add(&d, i as u64) {", "        if false {")], S(NEG)),
    ("a sender's command on another's entry", [(ST, 'if cmd != "openDisclosure" && e.from != ua {', 'if false && e.from != ua {')], S(NEG)),
    ("another family's words accepted", [(ST, '    if !FAMILIES.contains(', '    if false && !FAMILIES.contains(')], S(NEG)),
    ("psid not compared", [(ST, '    if wordf(v, "psid")? != proof_system_id::<B>() {', '    if false {')], S(NEG)),
    ("ua not the reader's", [(ST, '    if wordf(v, "ua")? != ua {', '    if false {')], S(NEG)),
    ("pending counters not checked", [(ST, "    if a.pending_seq < a.last_rolled_pending_seq || (a.pending_seq == a.last_rolled_pending_seq && a.pending != Ciphertext::zero()) {",
                                       "    if a.pending_seq < a.last_rolled_pending_seq {")], S(NEG)),
    ("not an SSTORE2 code accepted", [(ST, "        if *stop != 0 {", "        if false {")], S(NEG)),
    ("a memo of another record accepted", [(ST, " || memo.get(..16) != record.get(..16) {", " {")], S(NEG)),
    ("a blob of another pointer accepted", [(ST, ' || hexb(get(b, "address")?)? != ptr_word[at..] {', " {")], S(NEG)),
    # the CLI as a reading layer (R2, R3) and the pasted --ct (Fable P3-4)
    ("the CLI's genesis check skipped (R2)", [(CLI, '    if unhex(genesis["hash"].as_str().ok_or("R2: no genesis hash")?)? != chain_uid {', "    if false {")],
     RB("--", "--include-ignored", "rpc_reading_layer_against_anvil")),
    ("the CLI's depth past the head read at genesis (R3)", [(CLI, "head.checked_sub(d).ok_or(", "Some(head.saturating_sub(d)).ok_or(")],
     RB("--", "--include-ignored", "rpc_reading_layer_against_anvil")),
    ("--ct back in a release build", [
        (CLI, '    #[cfg(feature = "hazmat")]\n    ct: Option<String>,', "    ct: Option<String>,"),
        (CLI, '            #[cfg(feature = "hazmat")]\n            "--ct"', '            "--ct"'),
        (CLI, '    #[cfg(feature = "hazmat")]\n    let pasted = a.ct.is_some();\n    #[cfg(not(feature = "hazmat"))]\n    let pasted = false;',
         "    let pasted = a.ct.is_some();"),
        (CLI, '#[cfg(feature = "hazmat")]\nfn run_pasted', "fn run_pasted"),
        (CLI, '    #[cfg(feature = "hazmat")]\n    if a.ct.is_some() {', "    if a.ct.is_some() {"),
        (CLI, "table::<C>(a)?.decrypt(&ct, &k.x, a.bound_bits)", "table::<C>(a)?.dlog(&(ct.c - ct.d * k.x), a.bound_bits)")],
     RB("ct_only_with_hazmat_and_rpc_only_as_a_reading_layer")),
    # the facade
    ("the facade uses the key before the words are checked", [
        (FA, "            let p = zether_prover::state::prepare(c.cmd, &v, &y).map_err(|_| Error::Argument)?;\n"
             "            return self.with_key(|k| zether_prover::state::run(&p, k, rng).map(|o| o.to_string()).map_err(|_| Error::Argument));",
             "            let _ = y;\n"
             "            return self.with_key(|k| zether_prover::state::call_with_key(c.cmd, &v, k, rng).map(|o| o.to_string()).map_err(|_| Error::Argument));")],
     FS("location_word_and_role_negatives_are_refused_with_the_key_unused")),
    ("a raw command in a release build", [(FA, '    #[cfg(feature = "vectors")]\n    "rawCheckBalance",', '    "rawCheckBalance",')],
     (R, [*CARGO, "--test", "facade_zether", "release_has_no_raw_decrypt"])),
]

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
    files = sorted({f for f, _, _ in reps})
    orig = {f: open(f, encoding="utf-8").read() for f in files}
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
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(files)} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:400]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
