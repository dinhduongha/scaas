#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T11: one bound removed per fuzz target; both the corpus case (tests/fuzz_caps.rs, outside the fuzzer) and a short
fuzz run of the target (clients/ua-rs/fuzz, its own build under UA_FUZZ_TAG=mutant) must hit it. One mutant per run on a clean
tree, every file restored byte for byte after it; a mutant that does not compile kills nothing; a mutant the test or the fuzz
run misses is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t11-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-t11-mutants.py check           (every replacement found once, no run)"""
import os
import shutil
import subprocess
import sys

UA = "clients/ua-rs/"
W = UA + "src/wallet/"
CAP = os.path.abspath("scripts/capped")
TEST = [CAP, "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "fuzz_caps"]
ENV = dict(os.environ, UA_FUZZ_TAG="mutant")
NODEPTH = "usize::MAX"
M = [
    # the JSON decoders: the depth bound removed at the call site
    ("typed_data", "TypedData::from_json depth bound removed", W + "eip712.rs",
     "bounded::json(json, MAX_LEN, MAX_JSON_DEPTH)", f"bounded::json(json, MAX_LEN, {NODEPTH})"),
    ("expect", "Expect::from_json depth bound removed", W + "policy.rs",
     "bounded::json(json, MAX_LEN, MAX_DEPTH)", f"bounded::json(json, MAX_LEN, {NODEPTH})"),
    ("tx", "EvmTx::from_json depth bound removed", W + "tx.rs",
     "bounded::json(json, MAX_LEN, MAX_DEPTH)", f"bounded::json(json, MAX_LEN, {NODEPTH})"),
    ("vault", "Vault::from_json depth bound removed", W + "vault.rs",
     "bounded::json(json, VAULT_JSON, VAULT_DEPTH)", f"bounded::json(json, VAULT_JSON, {NODEPTH})"),
    ("manifest", "Manifest::from_json depth bound removed", W + "manifest.rs",
     "bounded::json(json, MANIFEST_JSON, MANIFEST_DEPTH)", f"bounded::json(json, MANIFEST_JSON, {NODEPTH})"),
    ("manifest", "backup payload depth bound removed", W + "manifest.rs",
     "bounded::json(pt, super::seal::MAX_PT, PAYLOAD_DEPTH)", f"bounded::json(pt, super::seal::MAX_PT, {NODEPTH})"),
    ("container", "SealedContainer::from_json depth bound removed", W + "seal.rs",
     "bounded::json(json, CONTAINER_JSON, CONTAINER_DEPTH)", f"bounded::json(json, CONTAINER_JSON, {NODEPTH})"),
    # the binary decoders have no depth: their bound
    ("sealed", "Sealed::from_wire tag length dropped from the minimum", W + "seal.rs",
     "let short = w.len() < 2 + CT + 32 + TAG;", "let short = w.len() < 2 + CT + 32;"),
    ("kem_pk", "kemPk scheme and length check removed", W + "kem.rs",
     "    if kem_pk.first() != Some(&1) || kem_pk.len() != KEM_PK_LEN {\n        return Err(Error::KemCheck);\n    }\n", ""),
    ("mnemonic", "mnemonic 1 KiB bound removed", W + "mod.rs",
     "    if words.len() > 1024 {\n        return Err(Error::Argument);\n    }\n", ""),
]

if sys.argv[1:] == ["check"]:
    for t, name, f, a, _ in M:
        assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)


def fuzz(t):
    """build (its own target dir) then a 60 s run; the lines that say what happened, and whether it found the mutant"""
    b = subprocess.run([CAP, UA + "fuzz/build.sh"], capture_output=True, text=True, env=ENV)
    if b.returncode:
        return False, "fuzz build failed: " + (b.stdout + b.stderr)[-300:]
    r = subprocess.run([CAP, UA + "fuzz/run.sh", t, "60", "mutant"], capture_output=True, text=True, env=ENV)
    out = r.stdout + r.stderr
    found = [ln for ln in out.splitlines() if "ua-fuzz FINDING" in ln]
    return bool(found), (found[0] if found else out.strip().replace("\n", " / "))[:220]


bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (t, name, f, a, b) in enumerate(M[lo - 1:hi], lo):
    orig = open(f, encoding="utf-8").read()
    assert orig.count(a) == 1, (name, a)
    try:
        open(f, "w", encoding="utf-8").write(orig.replace(a, b))
        r = subprocess.run(TEST, capture_output=True, text=True, cwd=UA)
        fz, why = fuzz(t)
    finally:
        open(f, "w", encoding="utf-8").write(orig)
    assert open(f, encoding="utf-8").read() == orig
    shutil.rmtree(UA + "target/fuzz-mutant/work", ignore_errors=True)  # a mutant's corpus is not the next one's
    out = r.stdout + r.stderr
    loaded = "could not compile `scaas-ua`" not in out
    failed = sorted({ln.split("----")[1].strip().removesuffix(" stdout") for ln in out.splitlines() if ln.startswith("---- ")})
    test_kill = r.returncode != 0 and loaded
    bad += not (test_kill and fz)
    verdict = "killed  " if test_kill and fz else "NO-LOAD " if not loaded else "SURVIVED"
    print(f"{verdict} | M{n} {t}: {name} | {f.removeprefix(UA)} | test rc={r.returncode} {', '.join(failed)} | fuzz: {why}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
