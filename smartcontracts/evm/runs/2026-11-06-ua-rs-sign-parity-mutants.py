#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign client parity (2026-11-06): the EVM transaction chainId cap (< 2^64, as ua-rs) and the WebAuthn clientDataJSON
UTF-8 refusal, in clientkeys and ua-rs, catch a change in what they test. One mutant per run on a clean tree (a replacement
found exactly `n` times), its suite run, every file restored byte for byte after it; a mutant that passes is a finding (exit 1).
The MD-11 record-builder refusal was not built in this round (see the summary), so it has no mutant here.
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-parity-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-06-ua-rs-sign-parity-mutants.py check           (every replacement found, no run)"""
import sys
import os
import re
import subprocess

CK, UA = "clients/clientkeys/", "clients/ua-rs/"
EVM, UAKEY = CK + "src/evm.js", CK + "src/uakey.js"
TX, WA = UA + "src/wallet/tx.rs", UA + "src/wallet/webauthn.rs"
CAPPED = os.path.abspath("scripts/capped")
JS = ([CAPPED, "node", "--test", "test/ua-wallet.test.js"], CK)
RS_TX = ([CAPPED, "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_tx"], UA)
RS_WA = ([CAPPED, "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_webauthn"], UA)
UTF8_JS = "  try { new TextDecoder('utf-8', { fatal: true }).decode(clientDataJSON); } catch { no('clientDataJSON is not UTF-8'); }\n"
M = [
    # one per refusal removed (the task's)
    ("clientkeys: chainId cap removed (up to 2^256 - 1 again)", [(EVM,
        "const U64 = new Set(['chainId', 'nonce', 'gasLimit']);", "const U64 = new Set(['nonce', 'gasLimit']);", 1)], JS),
    ("clientkeys: webauthnAssertion UTF-8 check removed", [(UAKEY, UTF8_JS, "", 1)], JS),
    # the controller's
    ("clientkeys: the UTF-8 check with a lossy decoder (fatal: false)", [(UAKEY, UTF8_JS,
        UTF8_JS.replace("fatal: true", "fatal: false"), 1)], JS),
    ("ua-rs: webauthn_assertion UTF-8 check removed", [(WA,
        "    if core::str::from_utf8(client_data_json).is_err() || !client_data_ok(", "    if !client_data_ok(", 1)], RS_WA),
    ("ua-rs: chainId wraps mod 2^64 (types 0-3)", [(TX, 'f.u64("chainId")?',
        'f.uint("chainId").map(|w| u64::from_be_bytes(w[24..].try_into().unwrap_or_default()))?', 4)], RS_TX),
]
assert len({m[0] for m in M}) == len(M)
for name, reps, _ in M:
    for f, a, _, n in reps:
        assert open(f, encoding="utf-8").read().count(a) == n, (name, f, a)
if sys.argv[1:] == ["check"]:
    print(f"{len(M)} mutants, every replacement found")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for k, (name, reps, (suite, cwd)) in enumerate(M[lo - 1:hi], lo):
    orig = {f: open(f, encoding="utf-8").read() for f, _, _, _ in reps}
    new = dict(orig)
    for f, a, b, _ in reps:
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = subprocess.run(suite, capture_output=True, text=True, cwd=cwd)
    finally:
        for f, s in orig.items():
            open(f, "w", encoding="utf-8").write(s)
    for f, s in orig.items():
        assert open(f, encoding="utf-8").read() == s
    out = r.stdout + r.stderr
    loaded = "could not compile `scaas-ua`" not in out and "SyntaxError" not in out
    failed = sorted(set(re.findall(r"^---- (.+?) stdout ----", out, re.M) + re.findall(r"^✖ (.+?) \(\d", out, re.M)))
    bad += r.returncode == 0 or not loaded
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    where = ", ".join(sorted({f for f, _, _, _ in reps}))
    print(f"{verdict} | M{k} {name} | {where} | rc={r.returncode} | {len(failed)} failed: {'; '.join(failed)[:240]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
