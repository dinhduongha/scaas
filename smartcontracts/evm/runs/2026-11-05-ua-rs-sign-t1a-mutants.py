#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-sign T1a: each check of the clientkeys UA tree, signers, typed / policy / tx / WebAuthn / msig rows can fail. One change per
run on a clean tree, the suite run, the file restored byte for byte after it; a mutant that does not load is reported as such (it kills
nothing); a mutant that passes is a finding (exit 1).
  python3 -I smartcontracts/evm/runs/2026-11-05-ua-rs-sign-t1a-mutants.py [first last]   (from the worktree root; a run is ~30 s,
  so the list goes in slices, each a foreground call: 1 15, 16 30, 31 <n>)"""
import sys
import os
import subprocess

CK = "clients/clientkeys/"
SEED, PQ, UAKEY, EVM, ZETHER = CK + "src/seed.js", CK + "src/pq.js", CK + "src/uakey.js", CK + "src/evm.js", CK + "src/zether.js"
SUITE = [os.path.abspath("scripts/capped"), "node", "--test", "test/ua-wallet.test.js", "test/seed.test.js", "test/pq.test.js"]
M = [
    # derivation (the T2 list, JS side)
    ("SLIP-10 hardened bit dropped", SEED, "+ (hard ? HARDENED : 0)) >>> 0;", "+ 0) >>> 0;"),
    ("UA tree index level not hardened", UAKEY, "path: `m/22776'/0'/${account}'/${kind}'/${index}'`", "path: `m/22776'/0'/${account}'/${kind}'/${index}`"),
    ("account / index swapped", UAKEY, "path: `m/22776'/0'/${account}'/${kind}'/${index}'`", "path: `m/22776'/0'/${index}'/${kind}'/${account}'`"),
    ("SLIP-10 ser32 little-endian", SEED, "const ser = new Uint8Array([idx >>> 24, (idx >>> 16) & 255, (idx >>> 8) & 255, idx & 255]);",
     "const ser = new Uint8Array([idx & 255, (idx >>> 8) & 255, (idx >>> 16) & 255, idx >>> 24]);"),
    ("PQ HKDF u32 little-endian", PQ, "return new Uint8Array([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);",
     "return new Uint8Array([v & 255, (v >>> 8) & 255, (v >>> 16) & 255, v >>> 24]);"),
    ("non-hardened ed25519 step accepted", SEED, "if (!hard && !c.n) throw new Error(`${curve} derivation is hardened-only: ${path}`);", ""),
    ("wrong kindNo (hex digits)", UAKEY, "path: `m/22776'/0'/${account}'/${kind}'/${index}'`", "path: `m/22776'/0'/${account}'/${kind.toString(16)}'/${index}'`"),
    ("wrong kindNo on the EIP-2333 path", UAKEY, "eip: [c.root, 0, account, kind] };", "eip: [c.root, 0, account, kind & 0xff] };"),
    ("TAG(kind) for utf8(tag) in the HKDF info", PQ, "const info = concatBytes(utf8ToBytes(s.tag), ", "const info = concatBytes(keccak_256(utf8ToBytes(s.tag)), "),
    ("NFKD dropped", SEED, "return String(text).normalize('NFKD').trim()", "return String(text).trim()"),
    ("account >= 2^31 accepted", UAKEY, "if (!Number.isInteger(v) || v < 0 || v >= HARD) fail(", "if (!Number.isInteger(v) || v < 0 || v > 2 ** 32) fail("),
    ("index 1 accepted for an EIP-2333 kind", UAKEY, "if (index !== 0) fail('Argument',", "if (false) fail('Argument',"),
    ("an index child appended to an EIP-2333 path", UAKEY, "eip: [c.root, 0, account, kind] };", "eip: [c.root, 0, account, kind, index] };"),
    ("bn254 UA salt swapped for EIP-2333's", UAKEY, "salt: 'SCAAS-UA-BN254-v1'", "salt: 'BLS-SIG-KEYGEN-SALT-'"),
    ("SLIP-10 nist256p1 child retry dropped", SEED, "if (il < c.n && k !== 0n) {", "if (true) {"),
    ("SLIP-10 nist256p1 master retry dropped", SEED, "while (c.n && (big(I.subarray(0, 32)) === 0n", "while (false && (big(I.subarray(0, 32)) === 0n"),
    ("native index >= 2^31 accepted", SEED, "if (!Number.isInteger(i) || i < 0 || i >= HARDENED) throw", "if (!Number.isInteger(i) || i < 0) throw"),
    # signing
    ("extraEntropy true for 0x0101 (a default that changed)", UAKEY, "lowS: true, extraEntropy: false, format: 'compact' }",
     "lowS: true, extraEntropy: true, format: 'compact' }"),
    ("extraEntropy true for native typed signing", SEED, "{ prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });\n    return concatBytes",
     "{ prehash: false, lowS: true, extraEntropy: true, format: 'recovered' });\n    return concatBytes"),
    ("low-s removed for 0x0108", UAKEY, "const rec = secp256k1.sign(msg, secret, { prehash: false, lowS: true,", "const rec = secp256k1.sign(msg, secret, { prehash: false, lowS: false,"),
    ("prehash added for 0x0108", UAKEY, "const rec = secp256k1.sign(msg, secret,", "const rec = secp256k1.sign(sha256(msg), secret,"),
    ("prehash removed for 0x0101", UAKEY, "case 0x0101: return p256.sign(sha256(msg), secret,", "case 0x0101: return p256.sign(msg, secret,"),
    ("scaas Schnorr nonce reduced from 256 bits", UAKEY, "return hashToScalar(keccak_256(concatBytes(utf8ToBytes('scaas.ua.schnorr.nonce.v1'), be(sk, 32), Y, uaMsg, aux)), r);",
     "return BigInt(hex(keccak_256(concatBytes(utf8ToBytes('scaas.ua.schnorr.nonce.v1'), be(sk, 32), Y, uaMsg, aux)))) % r;"),
    ("Y left out of the nonce", UAKEY, "be(sk, 32), Y, uaMsg, aux)), r);", "be(sk, 32), uaMsg, aux)), r);"),
    ("BLS12-381 role ignored (always SIG)", UAKEY, "DST: BLS_DST[role === 'pop' ? 'pop' : 'sig']", "DST: BLS_DST.sig"),
    ("BLS-bn254 role ignored (always SIG)", UAKEY, "BN_LABEL[role === 'pop' ? 'pop' : 'sig']", "BN_LABEL.sig"),
    ("kem not a PoP role", UAKEY, "[ua.POP_V2_TAG, ua.KEM_TAG, ua.PQZ_KEY_TAG]", "[ua.POP_V2_TAG, ua.PQZ_KEY_TAG]"),
    ("purpose check skipped", UAKEY, "!PURPOSE_TAGS.has(hex(tag))", "false"),
    # typed data
    ("unbound relayer hashed (canon dropped on mode bit 1)", EVM, "if (!(BigInt(m.mode) & 1n)) m.relayer = ZERO_ADDRESS;", ""),
    ("canon skipped on a nested struct", EVM, "const m = Object.fromEntries(types[type].map((f) => [f.name, canonical(f.type, v?.[f.name], types)]));",
     "const m = Object.fromEntries(types[type].map((f) => [f.name, types[f.type] ? v?.[f.name] : canonical(f.type, v?.[f.name], types)]));"),
    ("canon applied in the generic hasher (unrelated Order)", EVM, "...types[primary].map((f) => encodeValue(f.type, data?.[f.name], types)),",
     "...types[primary].map((f) => encodeValue(f.type, (['relayer', 'feeRecipient'].includes(f.name) && data && 'mode' in data"
     " && !(BigInt(data.mode) & (f.name === 'relayer' ? 1n : 2n))) ? '0x' + '00'.repeat(20) : data?.[f.name], types)),"),
    ("unknown field accepted by the hasher", EVM, "if (!types[primary].some((f) => f.name === k)) throw new Error(`EIP-712: ${k} is not a field of ${primary}`);", ""),
    ("int two's complement wrong", EVM, "return word(v < 0n ? (1n << 256n) + v : v);", "return word(v < 0n ? -v : v);"),
    ("policy check skipped (Payment)", EVM, "  Payment: (td, x) => checkPayment(td, x).digest,", "  Payment: (td) => digestOf(td),"),
    ("Any without its marker", EVM, "Any: (td, x) => (x.allowAnyTypedData === true ? digestOf(td)", "Any: (td, x) => (true ? digestOf(td)"),
    # transactions
    ("type-4 transaction built", EVM, "if (!Object.hasOwn(TX_FIELDS, String(type)) || !Number.isInteger(type)) refuse(",
     "if (!Number.isInteger(type)) refuse("),
    ("EIP-155 v offset lost", EVM, "minimal(BigInt(t.fields.chainId) * 2n + 35n + BigInt(yParity))", "minimal(27n + BigInt(yParity))"),
    ("legacy sighash without the EIP-155 chainId", EVM, "[...list.slice(1), minimal(chainId), new Uint8Array(0), new Uint8Array(0)]", "[...list.slice(1)]"),
    ("extraEntropy true for transactions", SEED, "const rec = secp256k1.sign(t.sighash, key.privateKey, { prehash: false, lowS: true, extraEntropy: false,",
     "const rec = secp256k1.sign(t.sighash, key.privateKey, { prehash: false, lowS: true, extraEntropy: true,"),
    # WebAuthn
    ("WebAuthn verify-before-return skipped", UAKEY, "if (!webauthnOk(keyData, expectedChallenge, blob)) no(", "if (false) no("),
    ("WebAuthn high-s kept", UAKEY, "be(S > P256_N / 2n ? P256_N - S : S, 32)", "be(S, 32)"),
    # msig
    ("msig minimal check skipped", UAKEY, "if (!ua.msigSigMinimal(keyData, list, inner)) fail('UAPoP',", "if (false) fail('UAPoP',"),
    ("msig level-2 members sign the outer digest", UAKEY, "const msg = ua.uaMessage(0x0120, MEMBER, ua.memberDigest(id, md));", "const msg = md;"),
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
