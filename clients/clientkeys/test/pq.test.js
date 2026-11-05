// PQ UA kinds (src/pq.js) against smartcontracts/vectors/ua/pq_kat.json, the vectors the forge suite verifies on chain
// (test/ua/*.t.sol through test/ua/PqVectors.sol): same keys from the seed, same ids and messages, the same deterministic signatures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { seedFromWords } from '../src/seed.js';
import {
  PQ_KINDS, pqSeed, pqKeygen, kindTag, uaId, uaMessage, pqMessage, signedMessage, signUA, verifyUA, purposeTag, mldsaExpandedKey,
} from '../src/pq.js';
import { hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';
import { shake256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/ua/pq_kat.json', import.meta.url)));
const seed = seedFromWords(V.mnemonic);
const purpose = fromHex(V.purpose_tag);
const digest = fromHex(V.digest);

test('purpose tag and digest of the vectors', () => {
  assert.equal(hex(purposeTag('pop')), V.purpose_tag);
  assert.equal(hex(digest), hex(keccak_256(utf8ToBytes('scaas p6a pq vector digest'))));
});

for (const name of Object.keys(PQ_KINDS)) {
  const v = V.kinds[name];
  test(`${name}: seed → key, UA id, ua_msg, signed message = vectors`, () => {
    const kp = pqKeygen(seed, name, V.account, V.index);
    assert.equal(hex(kp.publicKey), v.pk);
    assert.equal(hex(kp.ua), v.ua);
    assert.equal(hex(uaId(name, kp.publicKey)), v.ua);
    assert.equal(hex(kindTag(name)), v.tag_hash);
    assert.equal(hex(uaMessage(name, purpose, digest)), v.ua_msg);
    const signed = signedMessage(name, purpose, digest);
    assert.equal(hex(signed), v.signed_message);
    // ML-DSA and SLH-DSA sign pq_msg; Falcon signs ua_msg itself
    assert.equal(hex(signed), PQ_KINDS[name].pq ? hex(pqMessage(name, fromHex(v.ua_msg))) : v.ua_msg);
  });

  test(`${name}: deterministic signature = vector; verifies; tampering fails`, () => {
    const kp = pqKeygen(seed, name, V.account, V.index);
    const opts = name.startsWith('fndsa')
      ? { random: (n) => shake256(utf8ToBytes('scaas p6a falcon randomness'), { dkLen: n }) }
      : { extraEntropy: false };
    const sig = signUA(name, kp.secretKey, purpose, digest, opts);
    assert.equal(hex(sig), v.sig);
    assert.ok(verifyUA(name, kp.publicKey, purpose, digest, sig));
    assert.ok(!verifyUA(name, kp.publicKey, purposeTag('metatx'), digest, sig), 'another purpose');
    const other = name === 'mldsa44' ? 'mldsa65' : 'mldsa44';
    assert.notEqual(hex(signedMessage(other, purpose, digest)), hex(signedMessage(name, purpose, digest)), 'kind-tagged');
    // hedged signing (the default) still verifies
    assert.ok(verifyUA(name, kp.publicKey, purpose, digest, signUA(name, kp.secretKey, purpose, digest)));
  });
}

test('PQ seeds: HKDF per kind, account and index; lengths per scheme', () => {
  assert.equal(pqSeed(seed, 'mldsa44', 0, 0).length, 32);
  assert.equal(pqSeed(seed, 'slhdsa128s', 0, 0).length, 48);
  assert.equal(pqSeed(seed, 'fndsa512', 0, 0).length, 48);
  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa44', 0, 1)));
  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa44', 1, 0)));
  assert.notEqual(hex(pqSeed(seed, 'mldsa44', 0, 0)), hex(pqSeed(seed, 'mldsa65', 0, 0)));
  // no aliasing: account and index are u32, never wrapped or truncated
  for (const bad of [2 ** 32, -1, 1.5, NaN, '0']) {
    assert.throws(() => pqSeed(seed, 'mldsa44', bad, 0), /account must be/);
    assert.throws(() => pqSeed(seed, 'mldsa44', 0, bad), /index must be/);
  }
  assert.equal(pqSeed(seed, 'mldsa44', 0xffffffff, 0).length, 32);
  assert.throws(() => pqSeed(hex(seed), 'mldsa44', 0, 0), /seed must be/);
});

test('pq-external.mjs refuses a download whose SHA-256 is not the pinned one, before writing anything', () => {
  const out = new URL('../../../smartcontracts/vectors/ua/pq_external.json', import.meta.url);
  const before = readFileSync(out);
  const dir = mkdtempSync(`${tmpdir()}/pq-external-`);
  try {
    mkdirSync(`${dir}/ML-DSA-sigVer-FIPS204`);
    writeFileSync(`${dir}/ML-DSA-sigVer-FIPS204/internalProjection.json`, '{"testGroups":[]}'); // parses, wrong bytes
    const r = spawnSync(process.execPath, [new URL('../scripts/pq-external.mjs', import.meta.url).pathname, dir]);
    assert.notEqual(r.status, 0);
    assert.match(r.stderr.toString(), /sha256 mismatch ML-DSA-sigVer-FIPS204\/internalProjection\.json/);
    assert.deepEqual(readFileSync(out), before);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('EIP-8051 expanded key = vectors (the forge suite derives the same bytes on chain)', () => {
  for (const name of ['mldsa44', 'mldsa65']) {
    assert.equal(hex(mldsaExpandedKey(name, fromHex(V.kinds[name].pk))), V.kinds[name].expanded_key);
  }
  assert.throws(() => mldsaExpandedKey('fndsa512', fromHex(V.kinds.fndsa512.pk)));
});

test('no raw-digest signing: purpose and digest must be 32 bytes', () => {
  const kp = pqKeygen(seed, 'mldsa44', 0, 0);
  assert.throws(() => signUA('mldsa44', kp.secretKey, purpose, new Uint8Array(31)), /32 bytes/);
  assert.throws(() => signUA('mldsa44', kp.secretKey, new Uint8Array(5), digest), /32 bytes/);
  assert.throws(() => signUA('rsa', kp.secretKey, purpose, digest), /unknown PQ kind/);
});

test('mldsa87 (CTR-UA-39): kind 0x0134, a 2,592 B key, a holder, PQ weight; pq_kat.json row from the seed, its c~ word flip refused', async () => {
  const ua = await import('../src/ua.js');
  assert.equal(PQ_KINDS.mldsa87.kind, 0x0134);
  assert.equal(PQ_KINDS.mldsa87.tag, 'scaas.ua.mldsa87.v1');
  assert.deepEqual([ua.kindInfo(0x0134).name, ua.kindInfo(0x0134).lengths, ua.kindInfo(0x0134).group], ['mldsa87', [2592], 'mldsa87']);
  assert.ok(ua.isSigningKind(0x0134) && ua.isMemberKind(0x0134, false) && ua.isPqzHolder(0x0134) && !ua.isPqzHolder(0x0133));
  const k = V.kinds.mldsa87;
  const kp = pqKeygen(seed, 'mldsa87', 0, 0);
  assert.equal(hex(kp.publicKey), k.pk);
  assert.equal(hex(kp.ua), k.ua);
  assert.equal(k.expanded_key, undefined, 'no expanded-key cache for 0x0134 (Q1)');
  assert.ok(verifyUA('mldsa87', kp.publicKey, purpose, digest, fromHex(k.sig)));
  const ct = k.mutations.find((m) => m.what.startsWith('sig[40]'));
  assert.equal(ct.valid, false);
  const m = (kind, w) => ({ kind, id: kind === 0x0134 ? fromHex(k.ua) : new Uint8Array(32).fill(kind & 0xff), weight: w });
  const sort = (ms) => [...ms].sort((a, b) => Buffer.compare(Buffer.from(a.id), Buffer.from(b.id)));
  assert.equal(ua.msigPqzEligible(ua.encodeMsig(2, sort([m(0x0101, 1), m(0x0134, 1)]))), true, 'PQ weight (Q3)');
  assert.equal(ua.msigPqzEligible(ua.encodeMsig(1, sort([m(0x0101, 1), m(0x0134, 1)]))), false);
});

test('fndsa1024 (CTR-UA-40): kind 0x0135, a 1,793 B 0x0A key, a holder, PQ weight; pq_kat.json row from the seed; the NIST round-3 KATs', async () => {
  const ua = await import('../src/ua.js');
  const { falcon1024padded } = await import('@noble/post-quantum/falcon.js');
  const ext = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/ua/pq_external.json', import.meta.url), 'utf8'));
  assert.equal(PQ_KINDS.fndsa1024.kind, 0x0135);
  assert.equal(PQ_KINDS.fndsa1024.tag, 'scaas.ua.fndsa1024.v1');
  assert.equal(PQ_KINDS.fndsa1024.pq, false, 'Falcon signs ua_msg');
  assert.deepEqual([ua.kindInfo(0x0135).name, ua.kindInfo(0x0135).lengths, ua.kindInfo(0x0135).group], ['fndsa1024', [1793], 'fndsa1024']);
  assert.ok(ua.isSigningKind(0x0135) && ua.isMemberKind(0x0135, false) && ua.isPqzHolder(0x0135) && !ua.isPqzHolder(0x0136));
  assert.equal(pqSeed(seed, 'fndsa1024', 0, 0).length, 48);
  const k = V.kinds.fndsa1024;
  const kp = pqKeygen(seed, 'fndsa1024', 0, 0);
  assert.equal(hex(kp.publicKey), k.pk);
  assert.equal(kp.publicKey[0], 0x0a);
  assert.equal(fromHex(k.sig).length, 1280);
  assert.ok(verifyUA('fndsa1024', kp.publicKey, purpose, digest, fromHex(k.sig)));
  assert.ok(!verifyUA('fndsa512', kp.publicKey, purpose, digest, fromHex(k.sig)), 'the other size');
  ua.validateKeyData(0x0135, kp.publicKey);
  assert.throws(() => ua.validateKeyData(0x0135, Uint8Array.from([0x09, ...kp.publicKey.subarray(1)])), /UAKeyData/);
  const m = (kind, w) => ({ kind, id: kind === 0x0135 ? fromHex(k.ua) : new Uint8Array(32).fill(kind & 0xff), weight: w });
  const sort = (ms) => [...ms].sort((a, b) => Buffer.compare(Buffer.from(a.id), Buffer.from(b.id)));
  assert.equal(ua.msigPqzEligible(ua.encodeMsig(2, sort([m(0x0101, 1), m(0x0135, 1)]))), true, 'PQ weight (Q3)');
  assert.equal(ua.msigPqzEligible(ua.encodeMsig(1, sort([m(0x0101, 1), m(0x0135, 1)]))), false);
  const kat = ext.falcon1024_kat;
  assert.equal(kat.sha256, '036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d');
  assert.deepEqual(kat.rows_over_1239, [82]);
  assert.equal(kat.cases.length, 10);
  for (const c of kat.cases) assert.ok(falcon1024padded.verify(fromHex(c.sig), fromHex(c.msg), fromHex(c.pk)), `count ${c.count}`);
});

// ua-rs-sign T1c: the external known answers of pq_external.json the signers and the KEM are held to (spec §11, F-10): ACVP
// ML-KEM-1024 keyGen / encapDecap (and the two key checks), RFC 7748 X25519, ACVP ML-DSA / SLH-DSA sigGen; and the pinned-source
// rule of the importers (a flipped source byte fails its sha256 check).
const KEMX = await import('../src/kem.js').catch(() => ({}));
const PINNED = await import('../scripts/pinned.mjs').catch(() => ({}));
const X = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/ua/pq_external.json', import.meta.url)));
const Hx = (s) => fromHex(s);
const ACVP_PREFIX = 'https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/';

test('pq_external.json: every T1c section names its source URL and a sha256', () => {
  for (const k of ['acvp_mlkem_keygen', 'acvp_mlkem_encapdecap', 'acvp_mldsa_siggen', 'acvp_slhdsa_siggen', 'rfc7748']) {
    assert.ok(X[k], k);
    assert.match(X[k].sha256, /^[0-9a-f]{64}$/, k);
    assert.ok(X[k].source.startsWith(k === 'rfc7748' ? 'https://www.rfc-editor.org/' : ACVP_PREFIX), k);
  }
});

test('ACVP ML-KEM-1024 keyGen: KeyGen_internal(d, z) = (ek, dk)', () => {
  assert.equal(X.acvp_mlkem_keygen.cases.length, 5);
  for (const c of X.acvp_mlkem_keygen.cases) {
    const { ek, dk } = KEMX.mlkemKeyGen(Hx(c.d), Hx(c.z));
    assert.equal(hex(ek), c.ek, `tc ${c.tc}`);
    assert.equal(hex(dk), c.dk, `tc ${c.tc}`);
    assert.ok(KEMX.dkCheckOk(dk) && KEMX.ekModulusOk(ek));
  }
});

test('ACVP ML-KEM-1024 encapDecap: encapsulation (m → c, K), decapsulation (valid and modified c), key checks', () => {
  const s = X.acvp_mlkem_encapdecap;
  for (const c of s.encapsulation) {
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(Hx(c.ek), Hx(c.m));
    assert.equal(hex(cipherText), c.c, `tc ${c.tc}`);
    assert.equal(hex(sharedSecret), c.k, `tc ${c.tc}`);
  }
  assert.ok(s.decapsulation.some((c) => c.reason === 'modified ciphertext') && s.decapsulation.some((c) => c.reason === 'valid decapsulation'));
  for (const c of s.decapsulation) assert.equal(hex(ml_kem1024.decapsulate(Hx(c.c), Hx(c.dk))), c.k, `tc ${c.tc} ${c.reason}`);
  assert.equal(s.dkCheck.filter((c) => !c.valid).length > 0 && s.ekCheck.filter((c) => !c.valid).length > 0, true);
  for (const c of s.dkCheck) assert.equal(KEMX.dkCheckOk(Hx(c.dk)), c.valid, `dk check tc ${c.tc}`);
  for (const c of s.ekCheck) assert.equal(KEMX.ekModulusOk(Hx(c.ek)), c.valid, `ek check tc ${c.tc}`);
});

test('RFC 7748 X25519: §5.2 scalar multiplications and the iterated function (1, 1,000), §6.1 Diffie-Hellman', () => {
  const r = X.rfc7748;
  for (const v of r.scalarMult) assert.equal(hex(KEMX.x25519(Hx(v.k), Hx(v.u))), v.out);
  let [k, u] = [Hx('0x09'.padEnd(66, '0')), Hx('0x09'.padEnd(66, '0'))];
  for (let i = 1; i <= 1000; i++) {
    [k, u] = [KEMX.x25519(k, u), k];
    const want = r.iterated.find((x) => x.iterations === i);
    if (want) assert.equal(hex(k), want.out, `after ${i}`);
  }
  const nine = Hx('0x09'.padEnd(66, '0'));
  assert.equal(hex(KEMX.x25519(Hx(r.dh.a), nine)), r.dh.A);
  assert.equal(hex(KEMX.x25519(Hx(r.dh.b), nine)), r.dh.B);
  assert.equal(hex(KEMX.x25519(Hx(r.dh.a), Hx(r.dh.B))), r.dh.K);
  assert.equal(hex(KEMX.x25519(Hx(r.dh.b), Hx(r.dh.A))), r.dh.K);
});

test('ACVP sigGen: the ML-DSA and SLH-DSA signers reproduce deterministic and hedged signatures over M\' (internal and pure external)', () => {
  const ALG = { 'ML-DSA-44': PQ_KINDS.mldsa44.alg, 'ML-DSA-65': PQ_KINDS.mldsa65.alg, 'ML-DSA-87': PQ_KINDS.mldsa87.alg,
    'SLH-DSA-SHA2-128s': PQ_KINDS.slhdsa128s.alg };
  const cases = [...X.acvp_mldsa_siggen.cases, ...X.acvp_slhdsa_siggen.cases];
  assert.equal(cases.length, 16);
  for (const set of Object.keys(ALG)) {
    for (const det of [true, false]) for (const iface of ['internal', 'external']) {
      assert.ok(cases.some((c) => c.set === set && c.deterministic === det && c.iface === iface), `${set} ${det} ${iface}`);
    }
  }
  for (const c of cases) {
    const rand = c.deterministic ? false : Hx(c.rnd ?? c.addRand);
    assert.equal(hex(ALG[c.set].internal.sign(Hx(c.mprime), Hx(c.sk), { extraEntropy: rand })), c.sig, `${c.set} tc ${c.tc}`);
    assert.ok(ALG[c.set].internal.verify(Hx(c.sig), Hx(c.mprime), Hx(c.pk)));
  }
});

test('pinned sources: a download is read only at its sha256; one flipped byte is refused', () => {
  const dir = mkdtempSync(`${tmpdir()}/pinned-`);
  try {
    const f = `${dir}/source.txt`;
    const body = utf8ToBytes('X25519 test vectors, RFC 7748 section 5.2');
    writeFileSync(f, body);
    const pin = Buffer.from(sha256(body)).toString('hex');
    assert.equal(Buffer.from(PINNED.readPinned(f, pin)).toString(), 'X25519 test vectors, RFC 7748 section 5.2');
    const flipped = body.slice(); flipped[3] ^= 1;
    writeFileSync(f, flipped);
    assert.throws(() => PINNED.readPinned(f, pin), /sha256 mismatch/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
