#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T14: the Zether facade's tests (clients/ua-rs tests/facade_zether.rs and tests/fuzz_caps.rs, clients/zether-prover
tests/call_with_key.rs, clients/ua-c tests/test_vectors.py, tests/header.rs, tests/asan-smoke.sh) catch a change in what they
test. One mutant per run on a clean tree (one or more replacements), its suite run, every file restored byte for byte after it.
A mutant whose crate does not build is NOT-LOADED (it kills nothing); a mutant whose suite passes SURVIVED: both are findings
(exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t14-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t14-mutants.py check           (every replacement found once, no run)"""
import os
import re
import subprocess
import sys

C = "clients/ua-c/"
UA = "clients/ua-rs/"
ZP = "clients/zether-prover/"
LIB = C + "src/lib.rs"
FZ = UA + "src/facade/zether.rs"
STORE = UA + "src/wallet/store.rs"
API = ZP + "src/api.rs"
CAPPED = os.path.abspath("scripts/capped")
CARGO = [CAPPED, "cargo"]
OPTS = ["-j2", "--locked", "--offline"]
BUILD = {
    C: (C, CARGO + ["build"] + OPTS),
    UA: (UA, CARGO + ["build"] + OPTS + ["--features", "vectors"]),
    ZP: (ZP, CARGO + ["build"] + OPTS),
}


def facade(*tests):
    """tests/facade_zether.rs (feature vectors), the named tests only."""
    return [(UA, CARGO + ["test"] + OPTS + ["--features", "vectors", "--test", "facade_zether", "--"] + list(tests))]


def py(*classes):
    """test_vectors.py classes, after the debug library is rebuilt."""
    return [BUILD[C], (C, ["python3", "-m", "unittest"] + [f"tests.test_vectors.{c}" for c in classes])]


CAPS = [(UA, CARGO + ["test"] + OPTS + ["--features", "vectors", "--test", "fuzz_caps", "zether"])]
CWK = [(ZP, CARGO + ["test"] + OPTS + ["--test", "call_with_key"])]
HEADER = [(C, CARGO + ["test"] + OPTS + ["--test", "header"])]
ASAN = [(C, [CAPPED, "tests/asan-smoke.sh"])]
WITH = ("    pub(crate) fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {\n        let g = self.store.read();\n"
        "        if g.generation != self.generation {\n            return Err(Error::KeyRevoked);\n        }\n")
M = [
    # the plan's T14 list
    ("a `key` field forwarded to zether-prover (on every allow-list, any shape)", [
        (FZ, "    let has = |l: &[&str]| l.contains(&field);\n", "    let has = |l: &[&str]| l.contains(&field) || field == \"key\";\n"),
        (FZ, "        \"curve\" => x.as_str() == Some(\"bls12381\"),\n", "        \"curve\" => x.as_str() == Some(\"bls12381\"),\n        \"key\" => true,\n")],
     facade("a_key_field_in_command_json_is_refused")),
    ("cache AAD label changed (zether-cache:bn254)", [(FZ, "const CACHE_AAD: &[u8] = b\"zether-cache:bls12381\";",
        "const CACHE_AAD: &[u8] = b\"zether-cache:bn254\";")], facade("cache_box_equals_clientkeys")),
    # the controller's
    ("includeWitness on proveTransfer's allow-list", [(FZ, "\"proveTransfer\" => has(HEADER) || has(&[\"curve\", \"disclosureMode\",",
        "\"proveTransfer\" => has(HEADER) || has(&[\"includeWitness\", \"curve\", \"disclosureMode\",")],
     facade("fields_outside_the_allow_list_are_refused")),
    ("the ciphertext objects not shape-checked", [(FZ, "        \"acc\" | \"ct\" | \"pending\" => flat(x, &[\"C\", \"D\"]),",
        "        \"acc\" | \"ct\" | \"pending\" => x.is_object(),")], facade("a_key_field_in_command_json_is_refused")),
    ("the typed message not checked for a key", [(FZ, "        \"message\" => x.is_object() && clean(x),", "        \"message\" => x.is_object(),")],
     facade("a_key_field_in_command_json_is_refused")),
    ("command JSON depth 9 read", [(FZ, "pub const CMD_DEPTH: usize = 8;", "pub const CMD_DEPTH: usize = 9;")],
     facade("command_json_is_bounded_by_length_and_depth")),
    ("command JSON past 1 MiB read", [(FZ, "pub const CMD_MAX: usize = 1 << 20;", "pub const CMD_MAX: usize = 2 << 20;")],
     CAPS + facade("command_json_is_bounded_by_length_and_depth")),
    ("cache box JSON past 2 MiB read", [(FZ, "pub const BOX_MAX: usize = 2 << 20;", "pub const BOX_MAX: usize = 4 << 20;")], CAPS),
    ("cache box JSON depth 2 read", [(FZ, "pub const BOX_DEPTH: usize = 1;", "pub const BOX_DEPTH: usize = 2;")], CAPS),
    ("any JSON number accepted (floats, negatives)", [(FZ, "        Value::Number(n) => n.is_u64(),", "        Value::Number(_) => true,")],
     facade("numbers_other_than_u64_are_refused")),
    ("key_use not checked", [(FZ, "    if key_use != USE_CONF && key_use != USE_VIEWING {", "    if false {")],
     facade("key_use_other_than_conf_or_viewing_is_refused")),
    ("the viewing key derived at the conf path", [(FZ, "ProverKey::<Bls12381>::derive(seed, coin, account, key_use)",
        "ProverKey::<Bls12381>::derive(seed, coin, account, USE_CONF)")], facade("conf_and_viewing_keys_are_r33_keys")),
    ("cache key info changed (v2)", [(FZ, "const CACHE_INFO: &[u8] = b\"scaas-zether-balance-cache-v1\";",
        "const CACHE_INFO: &[u8] = b\"scaas-zether-balance-cache-v2\";")], facade("cache_box_equals_clientkeys")),
    ("the generation check of Handle::with skipped (unlock revives a Zether handle)", [(STORE, WITH,
        "    pub(crate) fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R> {\n        let g = self.store.read();\n")],
     facade("unlock_does_not_revive_a_zether_handle")),
    ("vectors_call ignores its RNG (the replay is real)", [(FZ, "        self.run(cmd, request_json, rng)\n    }\n    /// [`ZetherKey::seal_balance_cache`] at a given iv.",
        "        let _ = rng;\n        self.run(cmd, request_json, &mut OsRng)\n    }\n    /// [`ZetherKey::seal_balance_cache`] at a given iv.")],
     facade("zether_prover_vectors_through_the_facade")),
    ("zether-prover: call_with_key takes a `key` field", [(API, "    if let Some(f) = [\"key\", \"revealSecret\", \"includeWitness\"]",
        "    if let Some(f) = [\"revealSecret\", \"includeWitness\"]")], CWK),
    ("zether-prover: call_with_key takes includeWitness", [(API, "    if let Some(f) = [\"key\", \"revealSecret\", \"includeWitness\"]",
        "    if let Some(f) = [\"key\", \"revealSecret\"]")], CWK),
    ("zether-prover: the given key ignored (the request's key used)", [(API, "    match given {\n        Some(k) => Ok(k.clone()),\n        None => key::<C>(v),",
        "    match given {\n        Some(_) => key::<C>(v),\n        None => key::<C>(v),")], CWK),
    ("zether-prover: openDisclosure's receiver kind opened as the auditor's", [(API,
        "        Some(\"receiver\") => schnorr::OpeningKind::ReceiverX,", "        Some(\"receiver\") => schnorr::OpeningKind::Auditor,")], CWK),
    ("ua-c: zether_key_free outside the guard", [(LIB, "pub extern \"C\" fn scaas_ua_zether_key_free(k: *mut ScaasUaZetherKey) {\n    free(k)\n}",
        "pub extern \"C\" fn scaas_ua_zether_key_free(k: *mut ScaasUaZetherKey) {\n    if !k.is_null() {\n        drop(unsafe { Box::from_raw(k) })\n    }\n}")],
     HEADER),
    ("ua-c: zether_key_free frees nothing (a leaked handle)", [(LIB, "pub extern \"C\" fn scaas_ua_zether_key_free(k: *mut ScaasUaZetherKey) {\n    free(k)\n}",
        "pub extern \"C\" fn scaas_ua_zether_key_free(k: *mut ScaasUaZetherKey) {\n    free(std::ptr::null_mut::<ScaasUaZetherKey>());\n    let _ = k;\n}")],
     ASAN),
    ("ua-c: zether not in the default build", [(C + "Cargo.toml", "default = [\"mlock\", \"zether\"]", "default = [\"mlock\"]")],
     py("WalletZether.test_zether_feature_in_the_default_build")),
    ("ua-c: zether_public writes a zero UA", [(LIB, "            put(ua32.cast(), k.ua())", "            put(ua32.cast(), [0u8; 32])")],
     py("WalletZether.test_r33_keys")),
    ("ua-c: a zether_call error echoes its request", [(LIB,
        "        return write_str(out_json, out_len, &zether(k)?.call(text(cmd)?, cstr(request_json)?)?);",
        "        return write_str(out_json, out_len, &zether(k)?.call(text(cmd)?, cstr(request_json)?).map_err(|e| Fail(Fail::from(e).0, "
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
    crate = next(p for p in (C, ZP, UA) if all(f.startswith(p) for f in orig))
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
    asan = re.search(r"ERROR: (AddressSanitizer|LeakSanitizer): ([\w-]+)", out)
    verdict = "NOT-LOADED" if lrc else "SURVIVED  " if rc == 0 else "killed    "
    bad += lrc != 0 or rc == 0
    where = ", ".join(sorted(orig))
    extra = f" | {asan[1]}: {asan[2]}" if asan else ""
    print(f"{verdict} | M{n} {name} | {where} | rc={rc}{extra} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
