#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T20b, first sync (ua-mtx-merge aa898cf6): each mutant undoes one rule of the port to the merged-entry typed rows
(typed_ops.json 112 -> 80 structs: `keyVersion` in the PQZ args, `UAPrepareAcc`, the PQZ `UARollOver` row `UAPqzRollOver`; the
checks on the `UA` structs, `PayMeta` v2) or of the registry slots held to the layout pin, and names the test that must catch
it. One mutant per run on a clean tree, its command, every file restored byte for byte after it (the caller also runs
`git diff --exit-code`). A failing command kills; a build that does not compile is NOT-LOADED (a finding); a mutant whose
command passes SURVIVED (a finding, exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b1-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b1-mutants.py check           (every replacement found once, no run)
  python3 -I smartcontracts/evm/runs/2026-11-08-ua-rs-sign-t20b1-mutants.py count           (the number of mutants)
UNAUDITED."""
import os
import re
import subprocess
import sys

R = "clients/ua-rs/"
P, E7, B = R + "src/wallet/policy.rs", R + "src/wallet/eip712.rs", R + "src/bin/pqz-read.rs"
CAPPED = os.path.abspath("scripts/capped")
ENV = {"CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "2"}
CT = [CAPPED, "cargo", "test", "--locked", "--offline", "-j2"]
WT = lambda t: (R, CT + ["--test", "wallet_typed", t])
PIN = (R, CT + ["--bin", "pqz-read", "registry_slots_are_the_layout_pin"])

M = [
    # the op table: group 3g's rows and the struct chosen by domain
    ("keyVersion dropped from PqzTransferArgs", [(E7, "bytes32 fromUA,uint64 keyVersion,bytes32 toUA", "bytes32 fromUA,bytes32 toUA")], WT("typed_ops_json_rows")),
    ("UAPrepareAcc without keyVersion", [(E7, 'op("UAPrepareAcc", "bytes32 ua,uint64 keyVersion,uint256 half"', 'op("UAPrepareAcc", "bytes32 ua,uint256 half"')],
     WT("typed_ops_json_rows")),
    ("a primary type of two structs built without a domain", [(E7, "        [o] => Ok(op_def(o)),", "        [o, ..] => Ok(op_def(o)),")],
     WT("pqz_rollover_is_its_own_op")),
    # checkOp: the op asked for, never another struct of its primary type
    ("checkOp builds by primary type", [(P, "    typed_data_of(&o, name_of(td), contract, chain_id, chain_uid, &Value::Object(full))",
                                         "    scaas_typed_data(o.primary, name_of(td), contract, chain_id, chain_uid, &Value::Object(full))")],
     WT("pqz_rollover_is_its_own_op")),
    ("checkOp compares the row name, not its primary type", [(P, "    if td.primary_type() != o.primary {", "    if td.primary_type() != op {")],
     WT("pqz_rollover_is_its_own_op")),
    # the UA structs
    ("payment: the address MetaTransfer", [(P, '    if td.primary_type() != "UAMetaTransfer" {', '    if td.primary_type() != "MetaTransfer" {')],
     WT("sign_json_policy_rows")),
    ("receiver fee: the address ReceiverFee", [(P, '    if td.primary_type() != "UAReceiverFee" {', '    if td.primary_type() != "ReceiverFee" {')],
     WT("sign_json_policy_rows")),
    ("trade order: ua off by default", [(P, '                    ua: if x.0.contains_key("ua") { x.flag("ua")? } else { !outside },',
                                         '                    ua: x.flag("ua")?,')], WT("trade_order_takes_the_ua_struct")),
    ("trade order: the address TradeOrder accepted", [(P, "    if ua == outside {", "    if ua && outside {")], WT("trade_order_takes_the_ua_struct")),
    # PayMeta v2
    ("PayMeta: the request's entryRef not compared", [(P, "            if entry_ref.is_some_and(|e| e != pay_id) {", "            if false {")],
     WT("pay_meta_v2_body_rules")),
    ("PayMeta: the body not read", [(P, "            decode_meta_body(meta.schema, &meta.body)?;\n", "")], WT("pay_meta_v2_body_rules")),
    ("schema 1: no UTF-8 check", [(P, "        1 if !b.is_empty() => utf8(b),", "        1 if !b.is_empty() => Ok(()),")], WT("pay_meta_v2_body_rules")),
    ("schema 2: no canonical form", [(P, "|| canon != b {", " {")], WT("pay_meta_v2_body_rules")),
    ("schema 3: any length", [(P, "        3 if b.len() == 96 => Ok(()),\n        3 => refuse(),\n", "        3 => Ok(()),\n")], WT("pay_meta_v2_body_rules")),
    # the registry's layout pin
    ("pqz-read: pqzVersions one slot off", [(B, "const REG_PQZ_VERSIONS_SLOT: u64 = 17;", "const REG_PQZ_VERSIONS_SLOT: u64 = 16;")], PIN),
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
