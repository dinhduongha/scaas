#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T6: the WebAuthn builders (tests/wallet_webauthn.rs: sign.json webauthn accepted and refused rows, the webauthn-p256
rows of signatures.json and portable.json, assertions signed with a test key, a passkey through the UASig builder) catch a change in
what they test. One mutant per run on a clean tree (one or more replacements), its suite run, every file restored byte for byte
after it; a mutant that does not compile is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t6-mutants.py [first last]   (from the worktree root, foreground)
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t6-mutants.py check           (every replacement found once, no run)"""
import sys
import os
import re
import subprocess

UA = "clients/ua-rs/"
W = UA + "src/wallet/webauthn.rs"
V = UA + "src/verify.rs"
S = UA + "src/wallet/sign.rs"
SUITE = [os.path.abspath("scripts/capped"), "cargo", "test", "-j2", "--locked", "--features", "vectors", "--test", "wallet_webauthn"]
RANGE = "    let sig = p256::ecdsa::Signature::from_scalars(*r, *s).map_err(|_| Error::WebAuthnAssertion)?.normalize_s();"
JSON_CHALLENGE = """    // the challenge decoded from the untrusted JSON (base64url at bytes 36..79 of the fixed prefix) used as the reference
    let from_json = client_data_json.get(36..79).map(|t| {
        let (mut n, mut bits, mut out) = (0u32, 0, vec![]);
        for c in t {
            let v = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".iter().position(|x| x == c).unwrap_or(0) as u32;
            n = (n << 6 | v) & 0xffff;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((n >> bits) as u8);
            }
        }
        out
    });
    let json_challenge: [u8; 32] = from_json.and_then(|v| v.try_into().ok()).unwrap_or(*expected_challenge);
    let expected_challenge = &json_challenge;
"""
CDO = "pub(crate) fn client_data_ok(cd: &[u8], challenge: &[u8; 32]) -> bool {\n"
M = [
    # the plan's T6 list
    ("WebAuthn high-s accepted (no normalisation)", [(W, ".map_err(|_| Error::WebAuthnAssertion)?.normalize_s();",
        ".map_err(|_| Error::WebAuthnAssertion)?;")], SUITE),
    ("challenge compared without base64url (standard base64 alphabet)", [(V,
        'const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";',
        'const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";')], SUITE),
    ("challenge read from the JSON instead of expected_challenge", [(W, RANGE + "\n", JSON_CHALLENGE + RANGE + "\n")], SUITE),
    ("a generic JSON parser in place of client_data_ok", [(V, CDO, CDO
        + '    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(cd) {\n'
        + '        return v["type"] == "webauthn.get" && v["challenge"] == base64url(challenge).as_str();\n    }\n')], SUITE),
    ("verify-before-return skipped", [(W, "    if !verify(0x0100, key_data, expected_challenge, &blob, false) {", "    if false {")], SUITE),
    ("range check after normalisation (s reduced mod n and made low first)", [(W, RANGE,
        "    use p256::elliptic_curve::{ops::Reduce, scalar::IsHigh};\n"
        "    let s = <p256::Scalar as Reduce<p256::FieldBytes>>::reduce(&p256::FieldBytes::from(*s));\n"
        "    let s = if bool::from(s.is_high()) { -s } else { s };\n"
        "    let sig = p256::ecdsa::Signature::from_scalars(*r, s.to_bytes()).map_err(|_| Error::WebAuthnAssertion)?;")], SUITE),
    # the controller's
    ("clientDataJSON UTF-8 check dropped", [(W, "    if core::str::from_utf8(client_data_json).is_err() || !client_data_ok(",
        "    if !client_data_ok(")], SUITE),
    ("a 0x0100 key asked UaMsg, not WebAuthn", [(S, "    if kind == 0x0100 {", "    if false {")], SUITE),
    ("purpose check skipped (ua_request)", [(S, "    check_purpose(purpose)?;\n    Ok(request(", "    Ok(request(")], SUITE),
    ("clientDataJSON head offset without padding", [(W, "crate::word(0xa0 + auth_data.len().next_multiple_of(32) as u64)",
        "crate::word(0xa0 + auth_data.len() as u64)")], SUITE),
    ("r or s out of range refused as Argument", [(W, "from_scalars(*r, *s).map_err(|_| Error::WebAuthnAssertion)",
        "from_scalars(*r, *s).map_err(|_| Error::Argument)")], SUITE),
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
