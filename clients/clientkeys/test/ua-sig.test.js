// smartcontracts/vectors/ua/signatures.json (UA-2a): the generator reproduces it byte for byte, and every row is re-verified
// here with noble through verifiers written from accounts.md §1.9 (not the generator's signing code): positives pass,
// negatives fail, msig sets give their stated verdict. ed25519 (UA-2b): the derived row, the ed25519Rfc8032 section and
// ed25519_fuzz.json (T-FUZZ) against a strict verifier = noble zip215:false + the two ed25519-dalek verify_strict rules
// noble leaves out (R not small order, the cofactorless equation).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import * as ua from '../src/ua.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, b64url } from '../src/bytes.js';

const dir = new URL('../../../smartcontracts/vectors/ua/', import.meta.url);
const V = JSON.parse(readFileSync(new URL('signatures.json', dir)));
const FUZZ = JSON.parse(readFileSync(new URL('ed25519_fuzz.json', dir)));
const int = (b) => BigInt(hex(b));
const B = (h) => fromHex(h);
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const tag = (p) => ua.purposeTag(p);
const attempt = (f) => { try { return f(); } catch { return false; } };

test('the generator reproduces signatures.json, ed25519_fuzz.json, metatx3.json and pq_signatures.json byte for byte', () => {
  const out = mkdtempSync(join(tmpdir(), 'ua-sig-vectors-'));
  try {
    const r = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/ua-sig-vectors.mjs', import.meta.url)), out], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    for (const f of ['signatures.json', 'ed25519_fuzz.json', 'metatx3.json', 'pq_signatures.json']) assert.equal(readFileSync(join(out, f), 'utf8'), readFileSync(new URL(f, dir), 'utf8'), f);
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

// --- ABI reading (offsets as the decoder sees them) ---
const wordAt = (b, o) => Number(int(b.subarray(o, o + 32)));
const bytesAt = (b, base, head) => { const o = base + wordAt(b, head); return b.subarray(o + 32, o + 32 + wordAt(b, o)); };

// --- verifiers (§1.9) ---
const P256_N = p256.Point.Fn.ORDER;
const p256Ok = (xy, h, r, s) => int(s) <= P256_N / 2n
  && p256.verify(concatBytes(r, s), h, concatBytes(Uint8Array.of(4), xy), { prehash: false, lowS: true });

/** SmartKeyAccount._clientDataOk without the origin comparison. */
function clientDataOk(cd, challenge) {
  const prefix = `{"type":"webauthn.get","challenge":"${b64url(challenge)}","origin":"`;
  const s = new TextDecoder().decode(cd);
  const n = s.length;
  if (n < prefix.length + 2 || !s.startsWith(prefix)) return false;
  const end = s.indexOf('"', prefix.length);
  if (end < 0 || end + 1 >= n) return false;
  if (s[end + 1] === '}') return end + 2 === n;
  const cross = ',"crossOrigin":false';
  const after = end + 1 + cross.length;
  if (after >= n || s.slice(end + 1, after) !== cross) return false;
  return s[after] === '}' ? after + 1 === n : s[after] === ',';
}
function webauthnOk(kd, msg, blob) {
  const authData = bytesAt(blob, 0, 0);
  const cd = bytesAt(blob, 0, 32);
  if (authData.length < 37 || !eq(authData.subarray(0, 32), kd.subarray(64, 96)) || (authData[32] & 0x05) !== 0x05) return false;
  if (!clientDataOk(cd, msg)) return false;
  return p256Ok(kd.subarray(0, 64), sha256(concatBytes(authData, sha256(cd))), blob.subarray(64, 96), blob.subarray(96, 128));
}

const hashToScalar = (seed, r) => ((int(keccak_256(concatBytes(seed, Uint8Array.of(2)))) << 256n)
  + int(keccak_256(concatBytes(seed, Uint8Array.of(3))))) % r;
const bnG1 = (b) => {
  const x = int(b.subarray(0, 32)); const y = int(b.subarray(32, 64));
  if (x === 0n && y === 0n) throw new Error('identity');
  const P = bn254.G1.Point.fromAffine({ x, y }); P.assertValidity(); return P;
};
const blsFp = (b) => { if (!b.subarray(0, 16).every((v) => v === 0)) throw new Error('padding'); return int(b.subarray(16, 64)); };
const blsG1 = (b) => {
  const x = blsFp(b.subarray(0, 64)); const y = blsFp(b.subarray(64, 128));
  if (x === 0n && y === 0n) throw new Error('identity');
  const P = bls12_381.G1.Point.fromAffine({ x, y }); P.assertValidity(); return P; // assertValidity includes the subgroup
};
const schnorrOk = (G, r, size, dec) => (kd, msg, sig) => {
  if (sig.length !== size + 32) return false;
  const Rb = sig.subarray(0, size);
  const z = int(sig.subarray(size));
  const R = dec(Rb); const Y = dec(kd);
  const e = hashToScalar(keccak_256(concatBytes(utf8ToBytes('scaas.ua.schnorr.v1'), Rb, kd, msg)), r);
  if (z >= r || e === 0n) return false;
  return G.BASE.multiplyUnsafe(z).equals(R.add(Y.multiply(e)));
};

function mapToG1Bn254(prefix) {
  const { Fp } = bn254.fields;
  for (let ctr = 0; ; ctr++) {
    const c = new Uint8Array(4); new DataView(c.buffer).setUint32(0, ctr);
    const x = int(keccak_256(concatBytes(prefix, c))) % Fp.ORDER;
    const rhs = Fp.add(Fp.mul(Fp.sqr(x), x), 3n);
    let y = Fp.pow(rhs, (Fp.ORDER + 1n) / 4n);
    if (Fp.eql(Fp.sqr(y), rhs)) return bn254.G1.Point.fromAffine({ x, y: y & 1n ? Fp.ORDER - y : y });
  }
}
const pairingEq = (curve, a, b, c, d) => curve.fields.Fp12.eql(curve.pairing(a, b), curve.pairing(c, d));
function blsBn254Ok(kd, msg, sig, pop) {
  if (sig.length !== 64) return false;
  const S = bnG1(sig);
  const w = [0, 1, 2, 3].map((i) => int(kd.subarray(32 * i, 32 * i + 32)));
  const pk = bn254.G2.Point.fromAffine({ x: { c0: w[1], c1: w[0] }, y: { c0: w[3], c1: w[2] } });
  const H = mapToG1Bn254(concatBytes(utf8ToBytes(pop ? 'SCAAS-UA-BLS-BN254-POP-V1' : 'SCAAS-UA-BLS-BN254-SIG-V1'), msg));
  return pairingEq(bn254, S, bn254.G2.Point.BASE, H, pk);
}
function bls12381Ok(kd, msg, sig, pop) {
  if (sig.length !== 128) return false;
  const S = blsG1(sig);
  const w = [0, 1, 2, 3].map((i) => blsFp(kd.subarray(64 * i, 64 * i + 64)));
  const pk = bls12_381.G2.Point.fromAffine({ x: { c0: w[0], c1: w[1] }, y: { c0: w[2], c1: w[3] } });
  const H = bls12_381.G1.hashToCurve(msg, { DST: `SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_${pop ? 'POP' : 'SIG'}_` });
  return pairingEq(bls12_381, S, bls12_381.G2.Point.BASE, H, pk);
}
// ed25519 (§1.9 "RFC 8032 strict"): noble zip215:false refuses non-canonical A / R, S ≥ L and small-order A and checks the
// cofactored equation; verify_strict also refuses small-order R and checks [S]B == R + [k]A without the cofactor.
const ED_L = ed25519.Point.Fn.ORDER;
const leInt = (b) => int(Uint8Array.from(b).reverse());
const edNoble = (pk, msg, sig) => attempt(() => ed25519.verify(sig, msg, pk, { zip215: false }));
function ed25519Ok(pk, msg, sig) {
  if (sig.length !== 64 || !edNoble(pk, msg, sig)) return false;
  const R = ed25519.Point.fromBytes(sig.subarray(0, 32));
  if (R.isSmallOrder()) return false;
  const k = leInt(sha512(concatBytes(sig.subarray(0, 32), pk, msg))) % ED_L;
  return ed25519.Point.BASE.multiplyUnsafe(leInt(sig.subarray(32))).equals(R.add(ed25519.Point.fromBytes(pk).multiplyUnsafe(k)));
}
const VERIFY = {
  0x0100: webauthnOk,
  0x0102: ed25519Ok,
  0x0101: (kd, msg, sig) => sig.length === 64 && p256Ok(kd, sha256(msg), sig.subarray(0, 32), sig.subarray(32)),
  0x0103: (kd, msg, sig) => sig.length === 64 && schnorr.verify(sig, msg, kd),
  0x0104: schnorrOk(bn254.G1.Point, bn254.fields.Fr.ORDER, 64, bnG1),
  0x0105: schnorrOk(bls12_381.G1.Point, bls12_381.fields.Fr.ORDER, 128, blsG1),
  0x0106: bls12381Ok,
  0x0107: blsBn254Ok,
  // secp256k1 (ECDSA): r‖s‖v over ua_msg recovering address(keccak256(x ‖ y)), as the native EOA rule
  0x0108: (kd, msg, sig) => kd.length === 64 && nativeOk(hex(keccak_256(kd).subarray(12)), msg, hex(sig)),
};
/** `verify` / `verifyPop` (pop only matters for the BLS kinds); any throw is a refusal. */
const verify = (kind, kd, msg, sig, pop = false) => attempt(() => VERIFY[kind](B(kd), B(msg), B(sig), pop) === true);

const SECP_N = secp256k1.Point.Fn.ORDER;
/** Native EOA: low-s ECDSA r‖s‖v over UAAuth(ua, purpose, digest) under the registry domain. */
function nativeOk(address, h, sig) {
  return attempt(() => {
    const s = B(sig);
    if (s.length !== 65 || (s[64] !== 27 && s[64] !== 28) || int(s.subarray(32, 64)) > SECP_N / 2n) return false;
    const pub = secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(s[64] - 27), s.subarray(0, 64)), h, { prehash: false });
    return eq(keccak_256(secp256k1.Point.fromBytes(pub).toBytes(false).subarray(1)).subarray(12), B(address));
  });
}
const domain = (ctx, generation) => ({ generation, ...V.contexts[ctx] });

test('derived kinds: key data, ids, PoP messages, every signature verifies', () => {
  assert.equal(V.derived.length, 9);
  assert.deepEqual(V.derived.map((r) => r.kind), [0x0100, 0x0101, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0102, 0x0108]); // append-only
  for (const r of V.derived) {
    const kd = B(r.keyData);
    assert.equal(hex(ua.deriveUA(r.kind, kd)), r.ua, r.name);
    for (const p of [r.pop, r.popOther]) {
      const d = ua.popDigest({ ...V.contexts[p.context], ua: B(r.ua) });
      assert.equal(hex(d), p.popDigest, `${r.name} popDigest ${p.context}`);
      assert.equal(hex(ua.uaMessage(r.kind, ua.POP_TAG, d)), p.message);
      assert.ok(verify(r.kind, r.keyData, p.message, p.sig, true), `${r.name} pop ${p.context}`);
    }
    for (const s of r.sigs) {
      assert.equal(hex(ua.uaMessage(r.kind, tag(s.purpose), B(s.digest))), s.message);
      assert.ok(verify(r.kind, r.keyData, s.message, s.sig), `${r.name} ${s.purpose} ${s.variant ?? ''}`);
    }
  }
});

test('derived kinds: every negative fails', () => {
  for (const r of V.derived) {
    assert.ok(r.negatives.length >= 6, r.name);
    for (const n of r.negatives) assert.equal(verify(r.kind, r.keyData, n.message, n.sig, n.verifyPop), false, `${r.name} ${n.name}`);
  }
});

test('native EOA: UAAuth signatures verify, negatives fail', () => {
  const N = V.native;
  assert.equal(hex(ua.nativeId(0x0001, B(N.address))), N.ua);
  for (const s of N.sigs) {
    const h = ua.uaAuthDigest(domain(s.context, s.generation), B(N.ua), tag(s.purpose), B(s.digest));
    assert.equal(hex(h), s.uaAuthDigest);
    assert.ok(nativeOk(N.address, h, s.sig), `${s.context} ${s.generation} ${s.purpose}`);
  }
  for (const n of N.negatives) {
    const h = ua.uaAuthDigest(domain(n.context, n.generation), B(N.ua), tag(n.purpose), B(n.digest));
    assert.equal(nativeOk(N.address, h, n.sig), false, n.name);
  }
  // high-s must be refused for the low-s rule alone: raw recovery of the negative still yields the native address
  const hs = N.negatives.find((n) => n.name === 'high-s');
  const sg = B(hs.sig);
  assert.ok(int(sg.subarray(32, 64)) > SECP_N / 2n);
  const hh = ua.uaAuthDigest(domain(hs.context, hs.generation), B(N.ua), tag(hs.purpose), B(hs.digest));
  const pub = secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(sg[64] - 27), sg.subarray(0, 64)), hh, { prehash: false });
  assert.equal(hex(keccak_256(secp256k1.Point.fromBytes(pub).toBytes(false).subarray(1)).subarray(12)), N.address);
});

/** The registry's msig path (§1.9): auth = abi.encode(bytes keyData, bytes abi.encode(MemberSig[])). */
function msigOk(structureUa, purposeTag, digest, auth) {
  return attempt(() => {
    const keyData = bytesAt(auth, 0, 0);
    const sigs = bytesAt(auth, 0, 32);
    if (!eq(ua.uaOf(0x0120, keyData), structureUa)) return false;
    const threshold = (keyData[0] << 8) | keyData[1];
    const count = (keyData[2] << 8) | keyData[3];
    const md = ua.memberDigest(structureUa, ua.uaMessage(0x0120, purposeTag, digest));
    const a = wordAt(sigs, 0);
    const n = wordAt(sigs, a);
    const base = a + 32; // element offsets are relative to here
    let sum = 0;
    let last = -1;
    for (let i = 0; i < n; i++) {
      if (sum >= threshold) return false; // stops at the threshold
      const t = base + wordAt(sigs, base + 32 * i);
      const index = wordAt(sigs, t);
      if (index <= last || index >= count) return false;
      last = index;
      const o = 4 + 36 * index;
      const kind = (keyData[o] << 8) | keyData[o + 1];
      const id = keyData.subarray(o + 2, o + 34);
      const weight = (keyData[o + 34] << 8) | keyData[o + 35];
      const mkd = bytesAt(sigs, t, t + 32);
      const sig = bytesAt(sigs, t, t + 64);
      const ok = ua.isNativeKind(kind)
        ? mkd.length === 0 && nativeOk(hex(id.subarray(12)), ua.uaAuthDigest(domain(V.msig.context, V.msig.generation), id, tag('member'), md), hex(sig))
        : eq(ua.uaOf(kind, mkd), id) && verify(kind, hex(mkd), hex(ua.uaMessage(kind, tag('member'), md)), hex(sig));
      if (!ok) return false;
      sum += weight;
    }
    return sum >= threshold;
  });
}

test('msig: structure id, members, every set gives its verdict', () => {
  const M = V.msig;
  const members = M.members.map((m) => ({ kind: m.kind, id: B(m.id), weight: m.weight }));
  assert.equal(hex(ua.encodeMsig(M.threshold, members)), M.keyData);
  assert.equal(hex(ua.deriveUA(0x0120, B(M.keyData))), M.ua);
  for (const m of M.members) {
    const id = m.kind === 1 ? V.native.ua : V.derived.find((r) => r.name === m.secretRef).ua;
    assert.equal(m.id, id, m.name);
  }
  for (const s of M.sets) {
    assert.equal(hex(ua.memberDigest(B(M.ua), ua.uaMessage(0x0120, tag(s.purpose), B(s.digest)))), s.memberDigest);
    assert.equal(msigOk(B(M.ua), tag(s.purpose), B(s.digest), B(s.auth)), s.valid, s.name);
  }
  assert.equal(M.sets.length, 9);
  assert.equal(M.sets.filter((s) => s.valid).length, 2);
});

test('BIP-340 official vectors (32-byte messages) give their verdict', () => {
  assert.equal(V.bip340Official.length, 15);
  for (const t of V.bip340Official) assert.equal(verify(0x0103, t.publicKey, t.message, t.sig), t.valid, `vector ${t.index}`);
});

test('ed25519: the strict-only negatives are the ones noble zip215:false alone accepts', () => {
  const r = V.derived.find((x) => x.kind === 0x0102);
  assert.equal(r.negatives.length, 14);
  const nobleAccepts = r.negatives.filter((n) => edNoble(B(r.keyData), B(n.message), B(n.sig))).map((n) => n.name);
  assert.deepEqual(nobleAccepts, ['r-identity', 'r-small-order', 'r-mixed-order']);
  const S = (n) => leInt(B(r.negatives.find((x) => x.name === n).sig).subarray(32));
  const S0 = leInt(B(r.sigs[0].sig).subarray(32));
  assert.equal(S('s-plus-l'), S0 + ED_L);
  assert.ok(S('s-ge-l') >= 1n << 255n && S('s-ge-l') % ED_L === S0);
});

test('ed25519Rfc8032: RFC 8032 §7.1 TEST 1, 2, 3, 1024, SHA(abc) verify; the A-side cases give their verdict', () => {
  const T = V.ed25519Rfc8032;
  assert.equal(T.length, 11);
  assert.deepEqual(T.slice(0, 5).map((t) => B(t.message).length), [0, 1, 2, 1023, 64]);
  assert.equal(T[4].message, hex(sha512(utf8ToBytes('abc'))));
  for (const t of T) assert.equal(ed25519Ok(B(t.publicKey), B(t.message), B(t.sig)), t.valid, t.name);
  assert.deepEqual(T.filter((t) => t.valid).map((t) => t.name), ['TEST 1', 'TEST 2', 'TEST 3', 'TEST 1024', 'TEST SHA(abc)', 'a-mixed-order-k0']);
});

test('ed25519_fuzz.json: every case gives its strict verdict; noble zip215:false alone differs only in the listed classes', () => {
  const C = FUZZ.cases;
  assert.ok(C.length >= 2000);
  let differs = 0;
  for (const [i, c] of C.entries()) {
    const [pk, msg, sig] = [c.pk, c.msg, c.sig].map(B);
    assert.equal(msg.length, 32);
    assert.equal(ed25519Ok(pk, msg, sig), c.valid, `case ${i} ${c.class}`);
    assert.equal(edNoble(pk, msg, sig), c.noble, `case ${i} ${c.class} noble`);
    if (c.noble !== c.valid) { differs++; assert.ok(FUZZ.nobleDiffers.includes(c.class), `case ${i} ${c.class}`); }
  }
  assert.deepEqual(FUZZ.nobleDiffers, ['r-small-order', 'r-mixed-order', 'a-mixed-order']);
  for (const [cls, n] of Object.entries(FUZZ.counts)) assert.equal(C.filter((c) => c.class === cls).length, n.cases, cls);
  assert.equal(C.filter((c) => c.valid).length, 291);
  assert.equal(differs, 191);
});
