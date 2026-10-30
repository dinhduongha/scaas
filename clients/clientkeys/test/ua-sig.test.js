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
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import * as ua from '../src/ua.js';
import { hex, keccak_256, utf8ToBytes, concatBytes } from '../src/bytes.js';
import { int, B, eq, attempt, wordAt, bytesAt, ED_L, leInt, edNoble, ed25519Ok, verify, SECP_N, nativeOk } from './ua-verify.js';
import { dir } from './ua-vectors-dir.js';
const V = JSON.parse(readFileSync(new URL('signatures.json', dir)));
const FUZZ = JSON.parse(readFileSync(new URL('ed25519_fuzz.json', dir)));
const tag = (p) => ua.purposeTag(p);

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

const domain = (ctx, generation) => ({ generation, ...V.contexts[ctx] });

test('derived kinds: key data, ids, portable PoP messages, every signature verifies', () => {
  assert.equal(V.derived.length, 10);
  assert.deepEqual(V.derived.map((r) => r.kind), [0x0100, 0x0101, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0102, 0x0108, 0x0141]); // append-only
  for (const r of V.derived) {
    const kd = B(r.keyData);
    assert.equal(hex(ua.deriveUA(r.kind, kd)), r.ua, r.name);
    // UA-8: the portable PoP, the same on every context (popDigest = portablePopDigest, message over registrationDigest)
    const m = ua.holderPopMessage(r.kind, { ua: r.ua });
    for (const p of [r.pop, r.popOther]) {
      assert.deepEqual([p.popDigest, p.registrationDigest, p.message], [m.portablePopDigest, m.registrationDigest, m.message].map(hex),
        `${r.name} pop ${p.context}`);
      assert.ok(verify(r.kind, r.keyData, p.message, p.sig, true), `${r.name} pop ${p.context}`);
    }
    assert.deepEqual({ ...r.pop, context: r.popOther.context }, r.popOther, `${r.name}: one PoP for every chain`);
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
    // UA-8: a PoP over the chain-bound digest or under the v1 purpose is refused; no per-chain negative is left
    const pops = ['chain-bound-pop', 'pop-v1-purpose', 'other-chain-uid', 'other-registry'];
    assert.deepEqual(r.negatives.filter((n) => pops.includes(n.name)).map((n) => [n.name, n.verifyPop, n.message]),
      [['chain-bound-pop', true, r.pop.message], ['pop-v1-purpose', true, r.pop.message]], r.name);
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

/** The registered derived keys (id → keyData): the records the registry reads a member's key from (CTR-UA-33). */
const registered = new Map(V.derived.map((r) => [r.ua, r.keyData]));
/** The registry's msig path (§1.9): auth = abi.encode(bytes keyData, bytes abi.encode(MemberSig[])); every MemberSig
 *  carries an empty keyData (native: R12; registered: CTR-UA-33, the key comes from the member's record). */
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
        : mkd.length === 0 && registered.has(hex(id))
          && verify(kind, registered.get(hex(id)), hex(ua.uaMessage(kind, tag('member'), md)), hex(sig)); // CTR-UA-33
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
  assert.equal(M.sets.length, 10);
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
