#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The clientkeys group-kind verifiers (branch clientkeys-group-verify, 2026-11-26; src/ua-group.js and its hook in src/ua-verify.js):
each check is caught by a test (node --test test/ua-groups.test.js test/ua-portable.test.js). One mutant per run, every file
restored byte for byte after it; a mutant that passes is a finding (exit 1), unless it is listed in EQUIVALENT with the argument
why no input the contract or ua-rs can meet tells it apart.
  python3 -I clients/runs/2026-11-26-clientkeys-group-verify-mutants.py [first last]   (from the worktree root)
  python3 -I clients/runs/2026-11-26-clientkeys-group-verify-mutants.py check           (every replacement found once)
A hung run is killed past its deadline; a target file that differs from HEAD refuses the run; the restore holds on SIGINT /
SIGTERM (scripts/mutant_guard.py, ARCH-POS-23)."""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts"))
import mutant_guard as guard  # noqa: E402

G = "clients/clientkeys/src/ua-group.js"
UV = "clients/clientkeys/src/ua-verify.js"
CMD = ["systemd-run", "--user", "--scope", "--quiet", "-p", "MemoryMax=3G", "-p", "MemorySwapMax=1G", "--", "node", "--test",
       "test/ua-groups.test.js", "test/ua-portable.test.js"]
CWD = "clients/clientkeys"

M = [
    # verify by the stored vk
    ("musig2-secp256k1 vk prefix not read", [(G, "  vk.length === 33 && (vk[0] === 2 || vk[0] === 3) && sig.length === 64", "  vk.length === 33 && sig.length === 64")]),
    ("musig2-secp256k1 vk length not read", [(G, "  vk.length === 33 && (vk[0] === 2 || vk[0] === 3) && sig.length === 64", "  (vk[0] === 2 || vk[0] === 3) && sig.length === 64")]),
    ("frost-secp256k1 sig length not read", [(G, "  if (sig.length !== 65) return false;\n  const Y", "  const Y")]),
    ("frost-secp256k1 the challenge without Y", [(G, 'H("chal", concatBytes(sig.subarray(0, 33), y, msg))', 'H("chal", concatBytes(sig.subarray(0, 33), msg))')]),
    ("frost-secp256k1 z reduced, not range-checked", [(G, "const scalar = (b, n) => (b.length === 32 && int(b) < n ? int(b) : fail());", "const scalar = (b, n) => (b.length === 32 ? int(b) % n : fail());")]),
    ("SEC1 prefix not read", [(G, "(b.length === 33 && (b[0] === 2 || b[0] === 3) && int(b.subarray(1)) < P ?", "(b.length === 33 && int(b.subarray(1)) < P ?")]),
    ("SEC1 x < p not read", [(G, "(b.length === 33 && (b[0] === 2 || b[0] === 3) && int(b.subarray(1)) < P ?", "(b.length === 33 && (b[0] === 2 || b[0] === 3) ?")]),
    ("bn254 vk length not read", [(G, "const bnSchnorr = (vk, msg, sig) => vk.length === 64 && VERIFY", "const bnSchnorr = (vk, msg, sig) => VERIFY")]),
    # verifyPop
    ("key data not validated in verifyPop", [(G, "    validateKeyData(kind, key); // throws UAError: the caller's refusal\n", "")]),
    ("musig2-secp256k1 pop length not read", [(G, "  if (pop.length !== 64 + 64 * n) return false;\n", "")]),
    ("musig2-secp256k1 x(P_i) < N not read", [(G, "    if (int(pks[i].subarray(1)) >= N) return false; // ecrecover refuses r = x(P_i) ≥ N\n", "")]),
    ("musig2-secp256k1 hints not compared", [(G, "    if (!eq(address(h.toBytes(false).subarray(1)), address(pop.subarray(64 + 64 * i, 128 + 64 * i)))) return false;\n", "")]),
    ("musig2-secp256k1 Q not compared", [(G, "  return eq(secpEnc(S), kd.subarray(0, 33)) && schnorr.verify(", "  return schnorr.verify(")]),
    ("musig2-secp256k1 Q's parity not read", [(G, "  return eq(secpEnc(S), kd.subarray(0, 33)) && schnorr.verify(", "  return eq(secpEnc(S).subarray(1), kd.subarray(1, 33)) && schnorr.verify(")]),
    ("KeyAgg: no second-key exception", [(G, "  return pks.map((p) => (second && eq(p, second) ? 1n : coef(L, p)));", "  return pks.map((p) => coef(L, p));")]),
    ("musig2-bn254 Q not compared", [(G, "  return eq(bnEnc(Q), kd.subarray(0, 64)) && bnSchnorr(", "  return bnSchnorr(")]),
    ("bn254 wide hash: 255-bit shift", [(G, "const wide = (h) => ((int(h(0)) << 256n) + int(h(1))) % R;", "const wide = (h) => ((int(h(0)) << 255n) + int(h(1))) % R;")]),
    ("DKG: PoK not checked", [(G, "    if (!pok(i + 1, b.subarray(0, w), b.subarray(t * w, (t + 1) * w), b.subarray((t + 1) * w))) return false;\n", "")]),
    ("DKG: PoK identifiers from 0", [(G, "    if (!pok(i + 1, b.subarray(0, w),", "    if (!pok(i, b.subarray(0, w),")]),
    ("DKG: repeated / cancelling C_i0 accepted", [(G, "    if (w === 33 && S && eq(enc(S).subarray(1), b.subarray(1, w))) return false;\n", "")]),
    ("DKG: Y not compared", [(G, "  return S !== null && eq(enc(S), kd.subarray(0, w));", "  return S !== null;")]),
    ("frost-secp256k1 pop: the signature not checked", [(G, "dkgOk(key, 33, secpPt, secpEnc, secpPok) && frostSecp(key.subarray(0, 33), msg, sig);", "dkgOk(key, 33, secpPt, secpEnc, secpPok);")]),
    ("frost-bn254 pop: the signature not checked", [(G, "dkgOk(key, 64, bnG1, bnEnc, bnPok) && bnSchnorr(key.subarray(0, 64), msg, sig);", "dkgOk(key, 64, bnG1, bnEnc, bnPok);")]),
    ("bn254 PoK: μ_i·G only", [(G, "  return Rp.equals(BN.BASE.multiplyUnsafe(m).subtract(C0.multiplyUnsafe(c)));", "  return Rp.equals(BN.BASE.multiplyUnsafe(m));")]),
    # the hook in ua-verify.js
    ("a group member's slot judged on its whole key data", [(UV, "  if (groupVkLength(m.kind)) key = toBytes(key).subarray(0, groupVkLength(m.kind));\n", "")]),
    ("a group record judged by its vk path", [(UV, "(kd, msg, sig, pop) => groupOk(k, kd, msg, sig, pop)", "(kd, msg, sig) => groupOk(k, kd, msg, sig, false)")]),
]
# a mutant that survives only for these reasons (no input the contract, ua-rs or this verifier can meet tells it apart)
EQUIVALENT = {
    "musig2-secp256k1 vk length not read": "schnorr.verify refuses a 33+-byte x-only key itself",
    "frost-secp256k1 sig length not read": "`scalar` refuses a z that is not 32 bytes, so a longer or shorter sig is refused anyway",
    "frost-secp256k1 z reduced, not range-checked": "z + N fits in 32 bytes only for z < 2^256 - N (about 2^128): no signer can aim at such a z",
    "SEC1 prefix not read": "noble Point.fromBytes refuses a 33-byte encoding without prefix 02 / 03",
    "SEC1 x < p not read": "noble Point.fromBytes refuses x >= p",
    "bn254 vk length not read": "the scaas Schnorr challenge hashes the whole vk bytes, so a longer vk changes e",
    "musig2-secp256k1 x(P_i) < N not read": "a key with x(P_i) >= N has no known discrete log: Q's BIP-340 PoP cannot exist (row pk-x-ge-n: sigValid false)",
}

if sys.argv[1:] == ["check"]:
    for name, reps in M:
        for f, a, _ in reps:
            assert open(f, encoding="utf-8").read().count(a) == 1, (name, a)
    assert set(EQUIVALENT) <= {n for n, _ in M}
    print(f"{len(M)} mutants, every replacement found once")
    raise SystemExit(0)
bad = 0
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
guard.refuse_dirty([f for _, reps in M[lo - 1:hi] for f, _, _ in reps], ".")
lim = guard.limit(CMD, cwd=CWD, env=dict(os.environ))
for n, (name, reps) in enumerate(M[lo - 1:hi], lo):
    files = sorted({f for f, _, _ in reps})
    saved = {f: open(f, "rb").read() for f in files}
    new = {f: open(f, encoding="utf-8").read() for f in files}
    for f, a, b in reps:
        assert new[f].count(a) == 1, (name, a)
        new[f] = new[f].replace(a, b)
    try:
        for f, s in new.items():
            open(f, "w", encoding="utf-8").write(s)
        r = guard.run(CMD, lim, capture_output=True, text=True, cwd=CWD, env=dict(os.environ))
    finally:
        guard.restore(saved)
    out = r.stdout + r.stderr
    red = sorted(set(re.findall(r"^✖ (.{0,60})", out, re.M)))
    survived = not r.timeout and r.returncode == 0
    eqv = survived and name in EQUIVALENT
    bad += survived and not eqv
    verdict = guard.outcome(r, "EQUIV   " if eqv else "SURVIVED" if survived else "killed  ")
    where = ", ".join(sorted({f.split("/")[-1] for f in files}))
    print(f"{verdict} | M{n} {name} | {where} | rc={r.returncode} | {len(red)} red: {'; '.join(red)[:160]}", flush=True)
    if eqv:
        print(f"           equivalent: {EQUIVALENT[name]}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived (not equivalent): {bad}")
raise SystemExit(1 if bad else 0)
