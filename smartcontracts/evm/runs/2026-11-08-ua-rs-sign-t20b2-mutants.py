#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20b, second sync (ua-mtx-merge 4f6d8605, the factory index and chain-neutral group): each mutant undoes one rule
of this milestone's client part (T15m2: `OpenFactory._rec[token]` at its pinned slot and packing in `pqz-read` and
`zether-read-balance`; the latter's registry slots from the layout pin; the CREATE3 predictor of `ua-rs`; the router's three
create rows in the op table; `uaEnvelope` through the Zether facade) and names the test that must catch it. One mutant per
run on a clean tree, its command, every file restored byte for byte after it (the caller also runs `git diff --exit-code`).
A failing command kills; a build that does not compile is NOT-LOADED (a finding); a mutant whose command passes SURVIVED (a
finding, exit 1). The reading-layer tests run against a local anvil (`ANVIL`, default ~/.foundry/bin/anvil; killed by the
tests).
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b2-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b2-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b2-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R, ZP = "clients/ua-rs/", "clients/zether-prover/"
B, E7, F, FZ = R + "src/bin/pqz-read.rs", R + "src/wallet/eip712.rs", R + "src/factory.rs", R + "src/facade/zether.rs"
ZB, API = ZP + "src/bin/zether-read-balance.rs", ZP + "src/api.rs"
CAPPED = os.path.abspath("scripts/capped")
ANVIL = os.environ.get("ANVIL", os.path.expanduser("~/.foundry/bin/anvil"))
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2", "ANVIL": ANVIL,
       "PATH": os.path.dirname(ANVIL) + os.pathsep + os.environ.get("PATH", "")}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
PIN = (R, CT + ["--bin", "pqz-read", "factory_record_is_the_layout_pin"])
PR = (R, CT + ["--test", "pqz_read", "--", "--include-ignored"])
ZPIN = lambda t: (ZP, CT + ["--bin", "zether-read-balance", t])
RB = (ZP, CT + ["--test", "read_balance", "--", "--include-ignored"])
FT = (R, CT + ["--test", "factory"])
WT = (R, CT + ["--test", "wallet_typed", "typed_ops_json_rows"])
FZT = (R, CT + ["--test", "facade_zether", "ua_envelope_through_the_facade"])

M = [
    # T15m2: pqz-read's R5 on T67's record
    ("pqz-read: R5 reads the record's word 0", [(B, "let rec = r.word(&a.factory, &add(&keccak256(&[addr_word(&a.token), be(REC_SLOT)].concat()), 2))?;",
                                                 "let rec = r.word(&a.factory, &keccak256(&[addr_word(&a.token), be(REC_SLOT)].concat()))?;")], PR),
    ("pqz-read: the class not checked", [(B, "    class == CLASS_TOKEN && PQZ_KINDS", "    let _ = class;\n    PQZ_KINDS")], PIN),
    ("pqz-read: the kind's low byte only", [(B, "    let kind = u16::from_be_bytes([rec[28], rec[29]]);\n    class == CLASS_TOKEN && PQZ",
                                             "    let kind = u16::from(rec[29]);\n    class == CLASS_TOKEN && PQZ")], PIN),
    ("pqz-read: the record one slot off", [(B, "const REC_SLOT: u64 = 8;", "const REC_SLOT: u64 = 9;")], PIN),
    # T15m2: zether-read-balance's R5, its registry slots
    ("zether-read-balance: R5 reads the record's word 0", [(ZB, "let rec = r.word(factory, &add(&keccak256(&[key, be(REC_SLOT)].concat()), 2))?;",
                                                            "let rec = r.word(factory, &keccak256(&[key, be(REC_SLOT)].concat()))?;")], RB),
    ("zether-read-balance: the class not checked", [(ZB, "    class == CLASS_TOKEN && ZETHER_KINDS", "    let _ = class;\n    ZETHER_KINDS")],
     ZPIN("factory_record_is_the_layout_pin")),
    ("zether-read-balance: uaAt one slot off", [(ZB, "const REG_AT_SLOT: u64 = 5;", "const REG_AT_SLOT: u64 = 6;")], ZPIN("registry_slots_are_the_layout_pin")),
    # the CREATE3 predictor
    ("create3: class and kind swapped in s", [(F, "&word(u64::from(contract_class)), &word(u64::from(kind)), salt", "&word(u64::from(kind)), &word(u64::from(contract_class)), salt")], FT),
    ("create3: the instance at the proxy's nonce 0", [(F, "&[0xd6, 0x94], &proxy, &[0x01]", "&[0xd6, 0x94], &proxy, &[0x80]")], FT),
    # the router's create rows
    ("UACreateToken's kind a uint16", [(E7, 'op("UACreateToken", "address target,uint8 kind,', 'op("UACreateToken", "address target,uint16 kind,')], WT),
    ("UACreateInstance row dropped", [(E7, '    op("UACreateInstance", "address target,uint16 contractClass,uint16 kind,uint64 version,bytes32 initHash,bytes32 salt", &[ROUTER], None),\n', "")], WT),
    # uaEnvelope through the Zether facade
    ("facade: uaEnvelope's fields off the list", [(FZ, '        "envelope" | "uaEnvelope" => has(&["chainId", "chainUid", "token", "meta"]),',
                                                   '        "envelope" => has(&["chainId", "chainUid", "token", "meta"]),')], FZT),
    ("prover: call_with_key without uaEnvelope", [(API, '        "envelope" | "uaEnvelope" | "typedDigest" | "namedCall" => keyless(cmd, v),',
                                                   '        "envelope" | "typedDigest" | "namedCall" => keyless(cmd, v),')], FZT),
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
