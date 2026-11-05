#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T1b: each check of the clientkeys KEM key, encapsulation / decapsulation, seal / open, container acceptance, link window,
backup generation and seed vault can fail. One change per run on a clean tree, the suite run, the file restored byte for byte after it;
a mutant that does not load is reported as such (it kills nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t1b-mutants.py [first last]   (from the worktree root, foreground)"""
import sys
import os
import subprocess

CK = "clients/clientkeys/"
KEM, SEAL, VAULT, UAKEY = CK + "src/kem.js", CK + "src/seal.js", CK + "src/vault.js", CK + "src/uakey.js"
SUITE = [os.path.abspath("scripts/capped"), "node", "--test", "test/kem.test.js", "test/seal.test.js", "test/vault.test.js"]
M = [
    # the plan's T1b list
    ("modulus check removed", KEM, "if (!ekModulusOk(ek)) fail('KemCheck', 'ek modulus check (FIPS 203 §7.2)');", ""),
    ("all-zero ss_X accepted (encaps)", KEM, "if (zero(ssX)) fail('KemCheck', 'ss_X is all zero (small-order pk_X)');", ""),
    ("all-zero ss_X accepted (decaps)", KEM, "if (zero(ssX)) fail('KemCheck', 'ss_X is all zero (small-order E)');", ""),
    ("combiner E dropped", KEM, "sha3_256(concatBytes(ssM, ssX, E, pkX, LABEL))", "sha3_256(concatBytes(ssM, ssX, pkX, LABEL))"),
    ("kemPkHash out of the seal info", SEAL, "be16(p.length), p, keccak_256(kemPk)), 32);", "be16(p.length), p), 32);"),
    ("short code out of the link aad", SEAL, "    parts.push(sha256(utf8ToBytes(shortCode)));\n", ""),
    ("NFKC dropped", VAULT, "utf8ToBytes(String(pin ?? '').normalize('NFKC'))", "utf8ToBytes(String(pin ?? ''))"),
    ("AAD label dropped", VAULT, "additionalData: utf8ToBytes(aad) };", "additionalData: utf8ToBytes(aad.slice(aad.indexOf('|'))) };"),
    ("expected sender ignored", SEAL, "if (!allowed.some((u) => eq(b32(u, 'expect.sender'), senderUa))) no(", "if (false) no("),
    ("backup self-consistency skipped", SEAL, "if (derived !== senderUa) fail('ContainerSender',", "if (false) fail('ContainerSender',"),
    ("entropy padded to 32", VAULT, "  return entropy;\n}\n\n/** Add passkey-PRF", "  const p = new Uint8Array(32); p.set(entropy); return p;\n}\n\n/** Add passkey-PRF"),
    # T7 / T8 / T9 / C-03 / C-11 checks on the JS side
    ("decaps length check removed", KEM, "if (!(mlkemCt instanceof Uint8Array) || mlkemCt.length !== CT) fail('KemCheck', `mlkemCt: ${CT} bytes`);", ""),
    ("KEM key version ignored", KEM, "concatBytes(LABEL, ua, v), 96)", "concatBytes(LABEL, ua, be64(0)), 96)"),
    ("KEM key info without the ua", KEM, "concatBytes(LABEL, ua, v), 96)", "concatBytes(LABEL, v), 96)"),
    ("KEM key asked of an msig (not a UA key)", KEM, "if (typeof key?.kemKey !== 'function') fail('KemHolder',", "if (false) fail('KemHolder',"),
    ("KEM key for a non-holder", UAKEY, "let prk = isKemHolder(k) ? kemPrk(seed) : null;", "let prk = kemPrk(seed);"),
    ("purpose out of the seal info", SEAL, "Uint8Array.of(1), be16(p.length), p, keccak_256(kemPk)), 32);", "Uint8Array.of(1), keccak_256(kemPk)), 32);"),
    ("purpose check skipped", SEAL, "if (c.purpose !== expect?.purpose) no('purpose not the expected one');", ""),
    ("recipient expectation skipped", SEAL, "if (got.form !== want.form || !eq(got.id, want.id) || got.version !== want.version) no(", "if (false) no("),
    ("opener's own recipient not checked", SEAL, "if (own.form !== want.form || !eq(own.id, want.id) || own.version !== want.version) no(", "if (false) no("),
    ("derive_ua recomputation skipped", SEAL, "if (!eq(derived, senderUa)) no('the sender key does not derive sender.ua');", ""),
    ("container sender signature unchecked", SEAL, "if (!senderSigOk(senderKey.kind, keyData, msg, decode(() => fromB64url(c.sender.sig)))) fail(", "if (false) fail("),
    ("link window not checked", SEAL, "if (!Number.isSafeInteger(c?.created) || c.created < session.start || c.created > session.end) {", "if (false) {"),
    ("link session not used up", SEAL, "  session.used = true;\n", ""),
    ("generation compare skipped", SEAL, "if (payload.generation < current.generation && allowRollback !== true) fail(", "if (false) fail("),
    ("seed payload length not checked", VAULT, "if (!SEED_LENGTHS.includes(entropy.length)) {", "if (false) {"),
    ("v 2 reported as a wrong passphrase", VAULT, "refuse('VaultVersion', 'Unknown vault version.');", "refuse('VaultOpen', 'Wrong PIN or the vault was altered.');"),
    ("open: a seal version other than 1 accepted", SEAL, "if (sealed?.version !== 1 || sealed?.scheme !== 1) fail('SealVersion',", "if (false) fail('SealVersion',"),
]
bad = 0
assert len({m[0] for m in M}) == len(M)
lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
for n, (name, f, a, b) in enumerate(M[lo - 1:hi], lo):
    src = open(f, encoding="utf-8").read()
    assert src.count(a) == 1, (name, src.count(a))
    open(f, "w", encoding="utf-8").write(src.replace(a, b))
    try:
        r = subprocess.run(SUITE, capture_output=True, text=True, cwd=CK)
    finally:
        open(f, "w", encoding="utf-8").write(src)
    assert open(f, encoding="utf-8").read() == src
    out = r.stdout + r.stderr
    loaded = "SyntaxError" not in out and "ERR_MODULE_NOT_FOUND" not in out and "does not provide an export" not in out
    failed = [x[2:].split(" (")[0] for x in out.splitlines() if x.startswith("✖ ") and "failing tests" not in x]
    survived = r.returncode == 0 or not loaded
    bad += survived
    verdict = "SURVIVED" if r.returncode == 0 else "NO-LOAD " if not loaded else "killed  "
    print(f"{verdict} | M{n} {name} | {f.removeprefix(CK)} | rc={r.returncode} | {len(set(failed))} failed: {sorted(set(failed))[0][:90] if failed else ''}", flush=True)
print(f"mutants M{lo}-M{hi} of {len(M)}, survived or not loaded: {bad}")
raise SystemExit(1 if bad else 0)
