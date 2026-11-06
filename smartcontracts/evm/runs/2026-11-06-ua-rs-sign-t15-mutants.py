#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T15: the PQZ facade's tests (clients/ua-rs tests/facade_pqz.rs and tests/fuzz_caps.rs, clients/ua-c tests/test_vectors.py,
the pqz_cmd fuzz target) catch a change in what they test. One mutant per run on a clean tree (one or more replacements), its suite
run, every file restored byte for byte after it. A mutant whose crate does not build is NOT-LOADED (it kills nothing); a mutant whose
suite passes SURVIVED: both are findings (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t15-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t15-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

C = "clients/ua-c/"
UA = "clients/ua-rs/"
LIB = C + "src/lib.rs"
FP = UA + "src/facade/pqz.rs"
STORE = UA + "src/wallet/store.rs"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo"]
OPTS = ["-j2", "--locked", "--offline"]
BUILD = {
    C: (C, CARGO + ["build"] + OPTS),
    UA: (UA, CARGO + ["build"] + OPTS + ["--features", "vectors"]),
}


def facade(*tests):
    """tests/facade_pqz.rs (feature vectors), the named tests only."""
    return [(UA, CARGO + ["test"] + OPTS + ["--features", "vectors", "--test", "facade_pqz", "--"] + list(tests))]


def py(*classes):
    """test_vectors.py classes, after the debug library is rebuilt."""
    return [BUILD[C], (C, ["python3", "-m", "unittest"] + [f"tests.test_vectors.{c}" for c in classes])]


CAPS = [(UA, CARGO + ["test"] + OPTS + ["--features", "vectors", "--test", "fuzz_caps", "pqz"])]
# the fuzz target's own build (UA_FUZZ_TAG=t15mut) and a 20 s run over the seeds: fails (kills) if the run is not clean
FUZZ = [(".", ["sh", "-c", f"UA_FUZZ_TAG=t15mut {CAPPED} clients/ua-rs/fuzz/build.sh >/dev/null 2>&1 && "
               f"UA_FUZZ_TAG=t15mut {CAPPED} clients/ua-rs/fuzz/run.sh pqz_cmd 20 t15mut | grep -q 'fuzz rc=0'"])]
WITH = ("    pub(crate) fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {\n        let g = self.store.read();\n"
        "        if g.generation != self.generation {\n            return Err(Error::KeyRevoked);\n        }\n")
TAG_KIND = ("{ let info = [&crate::tag(0x0142)?[..], &account.to_be_bytes(), &index.to_be_bytes()].concat(); "
            "let mut o = Zeroizing::new(vec![0u8; 32]); Hkdf::<Sha256>::new(Some(b\"scaas.ua.pq.v1\"), seed).expand(&info, &mut o)"
            ".map_err(|_| Error::Argument)?; o }")
M = [
    # the plan's T15 list
    ("rnd32 fixed in a release build", [(FP, "        Ok(Draw { rnd32: os32()?, seed_enc: None, salt: None, memo_key: None })",
        "        Ok(Draw { rnd32: [0; 32], seed_enc: None, salt: None, memo_key: None })")], facade("two_proofs_differ")),
    ("set mismatch accepted (any proofSystemId)", [(FP, "    if *id == PQZL_ID || (pqz_ffi::PQZH && *id == PQZH_ID) {", "    if true {")],
     facade("set_mismatch_refused")),
    ("TAG(kind) for utf8(tag) in the PQZ HKDF", [(FP, "        let seed32 = hkdf_pq(seed, TAG, account, index, 32)?;",
        "        let seed32 = " + TAG_KIND + ";")], facade("pqz_key_is_the_ua_pq_rule")),
    # the controller's
    ("a deployed set of another build accepted", [(FP, "    if *deployed == pqz_set() {", "    if deployed.name == pqz_set().name {")],
     facade("set_mismatch_refused")),
    ("a `key` field on every allow-list", [(FP, "    let has = |l: &[&str]| l.contains(&field);",
        "    let has = |l: &[&str]| l.contains(&field) || field == \"key\";")], facade("a_key_field_in_command_json_is_refused")),
    ("a `key` field allowed in a leg", [(FP, "const LEG: &[&str] = &[\"pk\", \"ua\", \"amount\"];",
        "const LEG: &[&str] = &[\"pk\", \"ua\", \"amount\", \"key\"];")], facade("a_key_field_in_command_json_is_refused")),
    ("seed_enc HKDF salt label changed (V3)", [(FP, "const ENC_SALT: &[u8] = b\"SCAAS-PQZ-ENC-V2\";", "const ENC_SALT: &[u8] = b\"SCAAS-PQZ-ENC-V3\";")],
     facade("transfer_and_disclosures_verify")),
    ("seed_enc without the salt (a re-proof at one counter reuses r)", [(FP,
        "    let info = [&chain_uid[..], token, from_ua, &ctr.to_be_bytes(), salt].concat();",
        "    let info = [&chain_uid[..], token, from_ua, &ctr.to_be_bytes()].concat();")], facade("transfer_and_disclosures_verify")),
    ("a burn's seed fixed (not fresh)", [(FP, "        let seed = Zeroizing::new(match d.seed_enc {\n            Some(s) => s,\n            None => os32()?,",
        "        let seed = Zeroizing::new(match d.seed_enc {\n            Some(s) => s,\n            None => [0; 32],")],
     facade("burn_and_refresh_verify")),
    ("cache AAD label changed (zether-cache:)", [(FP, "        [b\"pqz-cache:\", pqz_ffi::stmt::SET.as_bytes()].concat()",
        "        [b\"zether-cache:\", pqz_ffi::stmt::SET.as_bytes()].concat()")], facade("cache_box_key_and_label")),
    ("cache key info changed (v2)", [(FP, "const CACHE_INFO: &[u8] = b\"scaas-pqz-balance-cache-v1\";",
        "const CACHE_INFO: &[u8] = b\"scaas-pqz-balance-cache-v2\";")], facade("cache_box_key_and_label")),
    ("the memo sealed under another key", [(FP, "            None => seed32,\n        };\n        let memo", "            None => &[0u8; 32],\n        };\n        let memo")],
     facade("transfer_multi_memo_and_sender_disclosure")),
    ("recipientsHash not over the legs' UAs", [(FP, "crate::keccak256(&legs.iter().flat_map(|l| l.1).collect::<Vec<u8>>())", "[0u8; 32]")],
     facade("transfer_multi_memo_and_sender_disclosure")),
    ("the receiver disclosure's own-key check skipped", [(FP, "                if s.pk != &self.pk[..] {", "                if false {")],
     facade("transfer_and_disclosures_verify")),
    ("the sender disclosure's u / v check skipped", [(FP, "        if c.0.u[..] != *u || c.0.vs.get(i).map(|x| &x[..]) != Some(v) {", "        if false {")],
     facade("transfer_and_disclosures_verify", "transfer_multi_memo_and_sender_disclosure")),
    ("the balance check wrapping (an overdraft reaches the prover)", [(FP,
        "        let rest = debit.and_then(|x| bal.checked_sub(x)).ok_or(Error::Argument)?;",
        "        let rest = debit.map(|x| bal.wrapping_sub(x)).ok_or(Error::Argument)?;")], facade("transfer_and_disclosures_verify")),
    ("Transfer0 for an audited transfer", [(FP, "        let form = if pk_a.is_some() { Form::Transfer } else { Form::Transfer0 };",
        "        let form = if pk_a.is_some() { Form::Transfer0 } else { Form::Transfer };")], facade("vectors::proof_rows_through_the_facade")),
    ("dec window 4 accepted", [(FP, ".filter(|w| *w < 4)", ".filter(|w| *w < 5)")], facade("command_json_is_bounded_and_typed")),
    ("a float amount read as u64", [(FP, ".map(|v| v.as_u64().ok_or(Error::Argument));", ".map(|v| v.as_f64().map(|x| x as u64).ok_or(Error::Argument));")],
     facade("command_json_is_bounded_and_typed")),
    ("command JSON depth 9 read", [(FP, "pub const CMD_DEPTH: usize = 8;", "pub const CMD_DEPTH: usize = 9;")], CAPS),
    ("command JSON past 1 MiB read", [(FP, "pub const CMD_MAX: usize = 1 << 20;", "pub const CMD_MAX: usize = 2 << 20;")],
     CAPS + facade("command_json_is_bounded_and_typed")),
    ("cache box JSON past 2 MiB read", [(FP, "pub const BOX_MAX: usize = 2 << 20;", "pub const BOX_MAX: usize = 4 << 20;")], CAPS),
    ("cache box JSON depth 2 read", [(FP, "pub const BOX_DEPTH: usize = 1;", "pub const BOX_DEPTH: usize = 2;")], CAPS),
    ("the generation check of Handle::with skipped (unlock revives a PQZ handle)", [(STORE, WITH,
        "    pub(crate) fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {\n        let g = self.store.read();\n")],
     facade("unlock_does_not_revive_a_pqz_handle")),
    ("fuzz: a panic in the PQZ decoder (positive control of the unwinding fuzz profile)", [(FP,
        "        let cmd = *COMMANDS.iter().find(|c| **c == cmd).ok_or(Error::Argument)?;\n        let Value::Object(v) = bounded::json(json, CMD_MAX, CMD_DEPTH)?",
        "        let cmd = *COMMANDS.iter().find(|c| **c == cmd).ok_or(Error::Argument)?;\n        assert!(cmd != \"openMemo\", \"mutant\");\n"
        "        let Value::Object(v) = bounded::json(json, CMD_MAX, CMD_DEPTH)?")], FUZZ),
    ("ua-c: pqz not in the default build", [(C + "Cargo.toml", "default = [\"mlock\", \"zether\", \"pqz\", \"pqz-set-n2304-kmax4096\"]",
        "default = [\"mlock\", \"zether\"]")], py("WalletPqz.test_pqz_and_one_set_in_the_default_build")),
    ("ua-c: PqzSetMismatch folded into Internal", [(LIB, "            E::PqzSetMismatch => SCAAS_UA_ERR_PQZ_SET_MISMATCH,\n", "")],
     py("WalletPqz.test_register_set_mismatch_and_key_field")),
    ("ua-c: the leaf export writes zeros", [(LIB,
        "        return put(out32.cast::<[u8; 32]>(), *handle(w)?.0.export_pqz_leaf_raw(account, index, ua::facade::pqz::AllowSecretExport)?);",
        "        return put(out32.cast::<[u8; 32]>(), { let _ = handle(w)?.0.export_pqz_leaf_raw(account, index, ua::facade::pqz::AllowSecretExport)?; [0u8; 32] });")],
     py("WalletPqz.test_leaf_is_the_ua_pq_rule")),
    ("ua-c: a pqz_call error echoes its request", [(LIB,
        "        return write_str(out_json, out_len, &pqz(k)?.call(text(cmd)?, cstr(request_json)?)?);",
        "        return write_str(out_json, out_len, &pqz(k)?.call(text(cmd)?, cstr(request_json)?).map_err(|e| Fail(Fail::from(e).0, "
        "String::from_utf8_lossy(cstr(request_json).unwrap_or_default()).into_owned()))?);")], py("WalletErrors")),
]

if sys.argv[1:] == ["check"]:
    for name, reps, _ in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def run(steps):
    out, rc = "", 0
    for cwd, cmd in steps:
        r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        out += r.stdout + r.stderr
        rc = r.returncode
        if rc:
            break
    return rc, out


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, suite) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    crate = next(p for p in (C, UA) if all(f.startswith(p) for f in orig))
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        # the mutated crate builds (else it kills nothing), then its suite
        lrc, lout = run([BUILD[crate]])
        rc, out = run(suite) if lrc == 0 else (lrc, lout)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    failed = sorted(set(re.findall(r"^(?:---- (.+?) stdout ----|(?:FAIL|ERROR): (\S+))", out, re.M)))
    failed = [a or b for a, b in failed]
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    where = ", ".join(sorted(orig))
    print(f"{verdict} | M{n} {name} | {where} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
