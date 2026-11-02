#!/usr/bin/env python3
"""typed-signing C8: each check added can fail. One change per run, restored byte for byte after it; a mutant that passes
is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-01-typed-signing-c8-mutants.py     (from the worktree root)"""
import os
import subprocess

E2E = "smartcontracts/evm/script/pqz/e2e.py"
KAT = "smartcontracts/vectors/pqz/pqz_kat.py"
ZS = "smartcontracts/evm/script/ZetherE2E.s.sol"
SELF = ["python3", "-I", E2E, "--self-test"]
LINKED = ["python3", "-I", "smartcontracts/evm/script/pqz/test_e2e_linked.py"]
ZETHER = ["scripts/capped", "scripts/e2e-zether.sh"]
M = [
    ("burn struct field order", E2E, 'BURN_F = "p validUntilBlock shieldIn fromUA beneficiaryUA u vFrom"', 'BURN_F = "p validUntilBlock shieldIn beneficiaryUA fromUA u vFrom"', SELF),
    ("unshield amount / recipient swapped in the struct", E2E, "amount=p[1][0], recipient=p[1][1]", "amount=p[1][1], recipient=p[1][0]", SELF),
    ("pqzAuth and accHint encoders swapped", E2E, 'f"bytes,{UASIG_S},bytes", ["b", UASIG_T, "b"]', 'f"bytes,{UASIG_S},bytes", ["b", "b", UASIG_T]', SELF),
    ("uaShield takes a UASig", E2E, 'raw = not ua or op == "UAShield"', "raw = not ua", SELF),
    ("a signature not in the ABI", E2E, 'n = cd("uaNonce(bytes32,uint256)"', 'n = cd("uaNonces(bytes32,uint256)"', SELF),
    ("an encoder list that is not the signature's", E2E, 'cd(API["rollOver"], ["w", "w"], ua.ua, n)', 'cd(API["rollOver"], ["w", "b"], ua.ua, n)', SELF),
    ("registerMsig member encoder", E2E, '("a", ("t", ["w", "b", "b"])), "b"]  # MsigStructure', '("a", ("t", ["b", "w", "b"])), "b"]  # MsigStructure', SELF),
    ("msig tag", E2E, 'MSIG: kc("scaas.ua.msig.v1")', 'MSIG: kc("scaas.ua.msig.v2")', SELF),
    ("PqzAuth: op after the header", KAT, "word(op), stmt[:640], kec(stmt[640:])", "stmt[:640], word(op), kec(stmt[640:])", SELF),
    ("Signed: a fee mode at fee 0", E2E, "0x20 if fee else 0", "0x20", LINKED),
    ("Signed: uaShield signed as a UASig", E2E, 'ml_auth(self.pq, self.signer, P_METATX, d) if op == "UAShield" else ', "", LINKED),
    ("msig member digest without the id", E2E, "md = kc(signer.ua, ua_msg(MSIG, purpose, digest))", "md = ua_msg(MSIG, purpose, digest)", LINKED),
    ("ZetherE2E: another key signs the envelope", ZS, "vm.sign(PAYER_PK, _cli(", "vm.sign(PAYER_PK + 1, _cli(", ZETHER),
    ("ZetherE2E: a wrong expected balance", ZS, '_expect(t, 1, SINGLE + MULTI4, NAMED_SINGLE, "bob', '_expect(t, 1, SINGLE + MULTI4, NAMED_SINGLE + 1, "bob', ZETHER),
]
bad = 0
for name, f, a, b, cmd in M:
    src = open(f, encoding="utf-8").read()
    assert src.count(a) == 1, (name, src.count(a))
    open(f, "w", encoding="utf-8").write(src.replace(a, b))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, PORT="18545"))
    finally:
        open(f, "w", encoding="utf-8").write(src)
    assert open(f, encoding="utf-8").read() == src
    out = r.stdout + r.stderr
    why = [x for x in out.splitlines() if x.startswith("FAIL") or "script failed" in x or "AssertionError" in x]
    bad += r.returncode == 0
    print(f"{'SURVIVED' if r.returncode == 0 else 'killed  '}  {name}: rc={r.returncode}: {why[0][:150] if why else ''}", flush=True)
print(f"mutants: {len(M)}, survived: {bad}")
raise SystemExit(1 if bad else 0)
