#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T5: EVM transaction signing, types 0-3 (tests/wallet_tx.rs: sign.json tx rows, the EIP-155 published row, the
refusals, chain separation, the 16 KiB bound; the doc tests of src/wallet/tx.rs: four types and no type 4) catch a change in what
they test. One mutant per run on a clean tree (one or more replacements), its suite run, every file restored byte for byte after
it; a mutant that does not compile is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t5-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t5-mutants.py check           (every replacement found once, no run)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
T = UA + "src/wallet/tx.rs"
CARGO = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors"]
TESTS = CARGO + ["--test", "wallet_tx"]
DOCS = CARGO + ["--doc", "wallet::tx"]
M = [
    # the plan's T5 list
    ("type-4 variant added (EIP-7702)", [
        (T, "        blob_versioned_hashes: Vec<[u8; 32]>,\n    },\n}", "        blob_versioned_hashes: Vec<[u8; 32]>,\n    },\n    Eip7702 { chain_id: u64 },\n}"),
        (T, "            EvmTx::Eip4844 { .. } => 3,", "            EvmTx::Eip4844 { .. } => 3,\n            EvmTx::Eip7702 { .. } => 4,"),
        (T, "            | EvmTx::Eip4844 { chain_id, .. } => *chain_id,", "            | EvmTx::Eip4844 { chain_id, .. }\n            | EvmTx::Eip7702 { chain_id } => *chain_id,"),
        (T, "            EvmTx::Legacy { nonce, gas_price, gas_limit, to, value, data, .. } => {",
            "            EvmTx::Eip7702 { .. } => vec![],\n            EvmTx::Legacy { nonce, gas_price, gas_limit, to, value, data, .. } => {")], DOCS),
    ("chainId dropped from the legacy sighash", [(T,
        "            EvmTx::Legacy { chain_id, .. } => vec![rlp_u64(*chain_id), rlp_bytes(&[]), rlp_bytes(&[])],",
        "            EvmTx::Legacy { .. } => vec![],")], TESTS),
    # the envelope and the signature
    ("legacy v without EIP-155 (27 + yParity)", [(T, "alloy_rlp::encode(u128::from(*chain_id) * 2 + 35 + u128::from(y_parity))",
        "alloy_rlp::encode(27 + u128::from(y_parity) + 0 * u128::from(*chain_id))")], TESTS),
    ("typed envelope yParity as v (27 + yParity)", [(T, "            _ => rlp_u64(u64::from(y_parity)),",
        "            _ => rlp_u64(27 + u64::from(y_parity)),")], TESTS),
    ("type byte dropped from a typed envelope", [(T, "            t => [&[t][..], &list].concat(),", "            _ => list,")], TESTS),
    ("integers not minimal (leading zero bytes kept)", [(T, "rlp_bytes(x.get(x.iter().position(|b| *b != 0).unwrap_or(32)..).unwrap_or_default())",
        "rlp_bytes(x)")], TESTS),
    ("access list entry as [storageKeys, address]", [(T,
        "rlp_list(&[rlp_bytes(&e.address), rlp_list(&e.storage_keys.iter().map(|k| rlp_bytes(k)).collect::<Vec<_>>())])",
        "rlp_list(&[rlp_list(&e.storage_keys.iter().map(|k| rlp_bytes(k)).collect::<Vec<_>>()), rlp_bytes(&e.address)])")], TESTS),
    ("type 3: maxFeePerBlobGas left out", [(T, "                    rlp_uint(max_fee_per_blob_gas),\n", "")], TESTS),
    # the refusals
    ("chain id 0 accepted", [(T, "        if self.chain_id() == 0 {", "        if false {")], TESTS),
    ("type 3 without a blob hash accepted", [(T, "                if blob_versioned_hashes.is_empty() {", "                if false {")], TESTS),
    ("a field of another type accepted", [(T, 'if o.keys().any(|k| k != "type" && !names.contains(&k.as_str())) {', "if false {")], TESTS),
    ("an integer as hex accepted", [(T, "            Value::String(s) => u256_dec(s),",
        "            Value::String(s) => super::eip712::uint_value(Some(&Value::String(s.clone()))).ok(),")], TESTS),
    ("nonce / gasLimit / chainId past 2^64 truncated", [(T, "        if hi.iter().any(|b| *b != 0) {", "        if false {")], TESTS),
    ("tx JSON cap one past 16 KiB", [(T, "const MAX_LEN: usize = 16 * 1024;", "const MAX_LEN: usize = 16 * 1024 + 1;")], TESTS),
]
assert len({m[0] for m in M}) == len(M)
srcs = {f: open(f, encoding="utf-8").read() for _, reps, _ in M for f, _, _ in reps}
for name, reps, _ in M:
    new = dict(srcs)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, f, a, new[f].count(a))
        new[f] = new[f].replace(a, b)
if sys.argv[1:] == ["check"]:
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, reps, suite) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _ in reps}
    new = dict(orig)
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = subprocess.run(suite, capture_output=True, text=True, cwd=UA)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    out = r.stdout + r.stderr
    # a doc test that does not compile is a test failure, not a crate that failed to build
    loaded = "could not compile `scaas-ua` (lib" not in out and "could not compile `scaas-ua` (test" not in out \
        and "failed to run custom build command" not in out
    failed = sorted(set(re.findall(r"^---- (.+?) stdout ----", out, re.M)))
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    where = ", ".join(sorted({f.removeprefix(UA) for f, _, _ in reps}))
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {', '.join(failed)[:200]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
