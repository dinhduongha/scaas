#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20b, third sync with ua-mtx-merge (after 3f and T66a): each mutant undoes one rule this round added (the purpose
`pqz-verdict` in PURPOSES, the `PqzVerdict` builder's struct, domain and domain checks, the router's three verifier rows, zether-prover's
list of the rows it does not build, the C header's holder rule) and names the test that must catch it. One mutant per run on a
clean tree, its command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`). A failing
command kills; a build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b5-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b5-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b5-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R, ZP, UC = "clients/ua-rs/", "clients/zether-prover/", "clients/ua-c/"
LIB, E = R + "src/lib.rs", R + "src/wallet/eip712.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
WT = (R, CT + ["--features", "vectors", "--test", "wallet_typed", "--test", "vectors"])
ZT = (ZP, CT + ["--test", "typed_ops"])
HD = (UC, CT + ["--test", "header"])
CK = ("clients/clientkeys/", [CAPPED, "node", "--test", "test/pqz-verdict.test.js", "test/ua.test.js"])
PY = ("clients/ua-py/", ["python3", "-m", "unittest", "-v", "tests.test_vectors.Vectors.test_table_groups_purposes_constants"])
GO = ("clients/ua-go/", [CAPPED, "go", "test", "-count=1", "-run", "TestTableGroupsPurposesConstants", "./..."])
RULE = "an msig never holds a KEM key, PQ-eligible or not"

M = [
    # the purpose
    ("ua-rs: pqz-verdict not in PURPOSES", [(LIB, '"membership", "pqz-verdict",', '"membership",')], WT),
    ("clientkeys: pqz-verdict not in PURPOSES", [("clients/clientkeys/src/ua.js", "'membership', 'pqz-verdict']", "'membership']")], CK),
    ("ua-py: pqz-verdict not in PURPOSES", [("clients/ua-py/scaas_ua/__init__.py", "'membership', 'pqz-verdict')", "'membership')")], PY),
    ("ua-go: pqz-verdict not in Purposes", [("clients/ua-go/ua.go", '"membership", "pqz-verdict"}', '"membership"}')], GO),
    # the PqzVerdict builder
    ("pqz_verdict_typed_data: the token check skipped",
     [(E, 'if field("token", "address")? != encode_atom("address", Some(&to_hex(contract).into()))?\n        || field',
       "if field")], WT),
    ("pqz_verdict_typed_data: the chainId check skipped",
     [(E, '\n        || field("chainId", "uint256")? != encode_atom("uint256", Some(&chain_id.into()))?\n', "\n")], WT),
    ("PqzVerdict: pqzVerifierEpoch uint64", [(E, "bytes32 proofHash,uint32 pqzVerifierEpoch,uint64 validUntil",
                                              "bytes32 proofHash,uint64 pqzVerifierEpoch,uint64 validUntil")], WT),
    ("PqzVerdict: signed in the MetaToken domain",
     [(E, 'let d = Def { primary, own: own.to_string(), domains: &[P], default_name: Some(P),',
       'let d = Def { primary, own: own.to_string(), domains: &[M], default_name: Some(M),')], WT),
    # the router's verifier rows
    ("UAPqzSetVerifier without next", [(E, 'op("UAPqzSetVerifier", "address target,bytes32 next",', 'op("UAPqzSetVerifier", "address target",')], WT),
    ("UAPqzRevokeVerifier in the PQZ token's domain", [(E, 'op("UAPqzRevokeVerifier", "address target", &[ROUTER], None),',
                                                       'op("UAPqzRevokeVerifier", "address target", &[P], None),')], WT),
    ("UAPqzCancelVerifier dropped", [(E, '    op("UAPqzCancelVerifier", "address target", &[ROUTER], None),\n', "")], WT),
    # zether-prover's rows it does not build
    ("zether-prover: UAPqzSetVerifier not listed", [(ZP + "tests/typed_ops.rs",
                                                     'const NOT_ZETHER: [&str; 59] = [', 'const NOT_ZETHER: [&str; 58] = [')
                                                    , (ZP + "tests/typed_ops.rs", '    "UAPqzSetVerifier", "UAPqzCancelVerifier",',
                                                       '    "UAPqzCancelVerifier",')], ZT),
    # the C header's holder rule (source and the generated header, so only the rule check can see it)
    ("C header: the msig KEM rule unstated", [(UC + "src/lib.rs", RULE, "an msig holds a KEM key, PQ-eligible or not"),
                                              (UC + "include/scaas_ua.h", RULE, "an msig holds a KEM key, PQ-eligible or not")], HD),
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
                        + re.findall(r"^✖ (.+?) \(", out, re.M) + re.findall(r"^--- FAIL: (\S+)", out, re.M)))
    why = re.findall(r"^thread '.*' .*panicked at .*\n(.*)$", out, re.M)
    verdict = "NOT-LOADED" if NOT_BUILT.search(out) else "SURVIVED  " if rc == 0 else "killed    "
    bad += verdict != "killed    "
    print(f"{verdict} | M{n} {name} | {', '.join(sorted(orig))} | rc={rc} | {len(failed)} failed: {', '.join(failed)[:300]}"
          f"{' | ' + why[0][:160] if why else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
