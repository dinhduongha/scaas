// R33 Zether conf keys: EIP-2333 published vectors (BLS12-381) and S3's pinned vectors
// (zether-prover/vectors/{r33_keys,schnorr_bls12381}.json, copied verbatim) — the
// browser derivation must be byte-for-byte the prover's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  deriveMasterSk, deriveChildSk, deriveConfKey, confPublic, schnorrSign, schnorrVerify, zetherKind, zetherPop, zetherSign, zetherOwnerAuth,
  sealConfKey, openConfKey, confLabel, CURVES, encodePoint, decodePoint, checkBalance, sealBalanceCache, openBalanceCache,
  setCachedBalance, cacheAfterDebit, cacheAfterRollOver, readBalance,
} from '../src/zether.js';
import { deriveKey, seedFromWords, NETWORKS } from '../src/seed.js';
import { fromHex, hex, abiEncode } from '../src/bytes.js';
import { uaMessage, purposeTag, holderPopMessage, portablePopDigest, registrationDigest, POP_V2_TAG } from '../src/ua.js';
import { dir } from './ua-vectors-dir.js';

const vec = (f) => JSON.parse(readFileSync(new URL(`./vectors/${f}`, import.meta.url)));
const R33 = vec('r33_keys.json');
const S = JSON.parse(readFileSync(new URL('structures.json', dir)));

test('EIP-2333 published test cases (BLS12-381)', () => {
  const cases = [
    ['c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04',
      6083874454709270928345386274498605044986640685124978867557563392430687146096n, 0,
      20397789859736650942317412262472558107875392172444076792671091975210932703118n],
    ['3141592653589793238462643383279502884197169399375105820974944592',
      29757020647961307431480504535336562678282505419141012933316116377660817309383n, 3141592653,
      25457201688850691947727629385191704516744796114925897962676248250929345014287n],
    ['0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00',
      27580842291869792442942448775674722299803720648445448686099262467207037398656n, 4294967295,
      29358610794459428860402234341874281240803786294062035874021252734817515685787n],
    ['d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3',
      19022158461524446591288038168518313374041767046816487870552872741050760015818n, 42,
      31372231650479070279774297061823572166496564838472787488249775572789064611981n],
  ];
  for (const [seed, master, idx, child] of cases) {
    const m = deriveMasterSk('bls12381', fromHex(seed));
    assert.equal(m, master);
    assert.equal(deriveChildSk('bls12381', m, idx), child);
  }
  assert.throws(() => deriveMasterSk('bls12381', new Uint8Array(31)), /32 bytes/);
});

test('bn254 is gone since UA-6 (kept in legacy/ua6/zether.js)', () => {
  assert.throws(() => deriveMasterSk('bn254', new Uint8Array(32)), /bls12381/);
  assert.throws(() => zetherKind('bn254'), /bls12381/);
  assert.equal(zetherKind('bls12381'), 0x0141);
  assert.deepEqual(Object.keys(CURVES), ['bls12381']);
});

test('conf/disclosure keys from the mnemonic == S3 (x, Y, UA, path) on both curves', () => {
  const seed = seedFromWords(R33.mnemonic, R33.passphrase);
  assert.equal(hex(seed), R33.seed);
  for (const curve of ['bls12381']) {
    for (const k of R33[curve].keys) {
      const [, , coin, account, use] = k.path.split('/').map(Number);
      const got = deriveConfKey(seed, { curve, coin, account, use });
      assert.equal(got.path, k.path);
      assert.equal(hex(got.x), k.x, k.path);
      assert.equal(got.Y, k.Y, k.path);
      assert.equal(got.UA, k.UA, k.path);
    }
  }
});

test('the Zether PoP is portable (UA-8 P1): no chain field, over registrationDigest(portablePopDigest(UA, 0, 0), 0)', () => {
  for (const curve of ['bls12381']) {
    for (const k of R33[curve].keys.filter((x) => x.pop)) {
      assert.equal(zetherKind(curve), k.pop.kind);
      const mine = zetherPop(curve, fromHex(k.x));
      const hp = holderPopMessage(0x0141, { ua: k.UA });
      assert.deepEqual([mine.UA, mine.popDigest, mine.registrationDigest, mine.uaMsg],
        [k.UA, hex(hp.portablePopDigest), hex(hp.registrationDigest), hex(hp.message)]);
      assert.equal(hex(hp.message), hex(uaMessage(0x0141, POP_V2_TAG, registrationDigest(portablePopDigest({ ua: k.UA })))));
      assert.ok(schnorrVerify(curve, fromHex(k.Y), fromHex(mine.uaMsg), fromHex(mine.pop)), `${curve} ${k.path}`);
      // the S3 vector's PoP (r33_keys.json; the prover moves to the portable PoP in UA-8 A3) verifies over its own message
      assert.ok(schnorrVerify(curve, fromHex(k.Y), fromHex(k.pop.uaMsg), fromHex(k.pop.pop)), `${curve} ${k.path} S3`);
      // chain fields are not inputs any more: a caller still passing the old context gets an error, not a silent drop
      const ctx = { chainId: 7622, chainUid: '0x' + '25'.repeat(32), registry: '0x' + 'ab'.repeat(20) };
      assert.throws(() => zetherPop(curve, fromHex(k.x), ctx), /no chain context/);
      assert.notEqual(zetherPop(curve, fromHex(k.x)).pop, mine.pop, 'hedged nonce');
      // the v1 purpose does not verify the portable PoP
      assert.equal(schnorrVerify(curve, fromHex(k.Y), uaMessage(0x0141, purposeTag('pop'), fromHex(mine.registrationDigest)),
        fromHex(mine.pop)), false);
    }
  }
  const z = S.pop.find((p) => p.kind === 0x0141);
  assert.equal(hex(portablePopDigest({ ua: z.ua })), z.portablePopDigest, 'structures.json: the Zether row');
});

test('owner op: abi.encode(bytes(""), Schnorr over uaMessage(kind, zether-owner, digest))', () => {
  for (const curve of ['bls12381']) {
    const k = R33[curve].keys[0];
    const digest = '0x' + '77'.repeat(32);
    const auth = fromHex(zetherOwnerAuth(curve, fromHex(k.x), digest));
    const sig = auth.subarray(auth.length - 160);
    assert.equal(hex(auth), hex(abiEncode(['bytes', 'bytes'], [new Uint8Array(0), sig])));
    const m = uaMessage(zetherKind(curve), purposeTag('zether-owner'), digest);
    assert.ok(schnorrVerify(curve, fromHex(k.Y), m, sig));
    assert.equal(schnorrVerify(curve, fromHex(k.Y), fromHex(digest), sig), false, 'never the raw digest');
    assert.equal(schnorrVerify(curve, fromHex(k.Y), uaMessage(zetherKind(curve), purposeTag('zether-auth'), digest), sig), false);
    assert.equal(schnorrVerify(curve, fromHex(k.Y), uaMessage(zetherKind(curve), purposeTag('metatx'), digest), sig), false);
  }
});

test('every UA-ledger write: Schnorr by x over uaMessage(0x0141, purpose, digest); no raw digest, no other purpose', () => {
  const k = R33.bls12381.keys[0];
  const digest = '0x' + '5a'.repeat(32);
  for (const purpose of ['metatx', 'metatx-cancel', 'keyop', 'receiver-fee', 'vp', 'vc-anchor', 'trade', 'zether-owner']) {
    const sig = zetherSign('bls12381', fromHex(k.x), purpose, digest);
    assert.equal(sig.length, 160);
    assert.ok(schnorrVerify('bls12381', fromHex(k.Y), uaMessage(0x0141, purposeTag(purpose), digest), sig), purpose);
    assert.equal(schnorrVerify('bls12381', fromHex(k.Y), uaMessage(0x0141, purposeTag('pop'), digest), sig), false, purpose);
  }
  assert.throws(() => zetherSign('bls12381', fromHex(k.x), 'authref', digest), /does not sign/);
  for (const p of ['member', 'zether-auth']) assert.throws(() => zetherSign('bls12381', fromHex(k.x), p, digest), /does not sign/, p);
});

test('Schnorr with S3 fixed nonce is byte-identical; tampering fails', () => {
  for (const curve of ['bls12381']) {
    const v = vec(`schnorr_${curve}.json`);
    const sig = schnorrSign(curve, fromHex(v.x), fromHex(v.msg), BigInt(v.k));
    assert.equal(hex(sig), v.sig);
    assert.equal(confPublic(curve, fromHex(v.x)).Y, v.Y);
    assert.ok(schnorrVerify(curve, fromHex(v.Y), fromHex(v.msg), sig));
    const bad = sig.slice();
    bad[bad.length - 1] ^= 1;
    assert.equal(schnorrVerify(curve, fromHex(v.Y), fromHex(v.msg), bad), false);
    assert.equal(schnorrVerify(curve, fromHex(v.Y), fromHex(v.msg), sig.subarray(1)), false);
    assert.equal(schnorrVerify(curve, new Uint8Array(fromHex(v.Y).length), fromHex(v.msg), sig), false);
  }
});

test('conf key is apart from signing keys: other path/curve/account ⇒ other x; never a signing scalar', () => {
  const seed = seedFromWords(R33.mnemonic);
  const xs = new Set();
  for (const curve of ['bls12381']) {
    for (const account of [0, 1]) for (const use of [7, 8]) xs.add(hex(deriveConfKey(seed, { curve, coin: 60, account, use }).x));
    xs.add(hex(deriveConfKey(seed, { curve, coin: 784, account: 0 }).x));
  }
  assert.equal(xs.size, 5);
  for (const net of Object.keys(NETWORKS)) {
    for (const i of [0, 1]) {
      const sk = deriveKey(seed, net, i).privateKey;
      assert.ok(!xs.has(hex(sk)), `${net}/${i}`);
    }
  }
});

test('x is sealed at rest like the seed; only Y/UA come back', async () => {
  const seed = seedFromWords(R33.mnemonic);
  const { vault, Y, UA } = await sealConfKey({ seed, curve: 'bls12381', coin: 60, account: 0, pin: 'river-otter-7' });
  assert.equal(Y, R33.bls12381.keys[0].Y);
  assert.equal(UA, R33.bls12381.keys[0].UA);
  assert.equal(vault.label, confLabel('bls12381', 60, 0));
  assert.ok(!JSON.stringify(vault).includes(R33.bls12381.keys[0].x.slice(2)));
  assert.equal(hex(await openConfKey(vault, { pin: 'river-otter-7' })), R33.bls12381.keys[0].x);
  await assert.rejects(openConfKey(vault, { pin: 'river-otter-8' }), /Wrong PIN/);
});

// S3 `vectors/r33_inputs.json` (copied verbatim): the prover's JSON API accepts a path index only as
// an integer in [0, 2^32 - 1] (number or decimal string). Same rule here, same key when accepted.
test('path-index rule == S3 prover (r33_inputs.json)', () => {
  const v = vec('r33_inputs.json');
  const seed = fromHex(v.seed);
  for (const c of v.index_cases) {
    const run = () => deriveConfKey(seed, { curve: v.curve, coin: c.coin, account: v.account });
    if (c.ok) assert.equal(run().Y, c.Y, `coin ${JSON.stringify(c.coin)}`);
    else assert.throws(run, /path index/, `coin ${JSON.stringify(c.coin)}`);
  }
  for (const account of [-1, 2 ** 32, 0.5, NaN]) {
    assert.throws(() => deriveConfKey(seed, { curve: 'bls12381', coin: 60, account }), /path index/);
  }
  assert.equal(hex(seedFromWords(v.passphrase.mnemonic, v.passphrase.passphrase_nfc)), v.passphrase.seed);
});

// ------------------------------------------------------------------ balance cache (zether-limits §5)

const mul = (P, k) => (k === 0n ? P.constructor.ZERO : P.multiply(k));
function enc(curve, Y, b, r) {
  const { Point } = CURVES[curve];
  return { C: mul(Point.BASE, b).add(mul(Y, r)), D: mul(Point.BASE, r) };
}
const hexCt = (curve, ct) => ({ C: hex(encodePoint(curve, ct.C)), D: hex(encodePoint(curve, ct.D)) });

/** Stand-in for the prover's device BSGS (bound 2^12 here): decrypts `ct` under the test key or throws. */
function deviceFor(curve, x) {
  const { Point } = CURVES[curve];
  return async (ct) => {
    const M = decodePoint(curve, fromHex(ct.C)).subtract(mul(decodePoint(curve, fromHex(ct.D)), x));
    let acc = Point.ZERO;
    for (let j = 0n; j < 1n << 12n; j++, acc = acc.add(Point.BASE)) if (acc.equals(M)) return String(j);
    throw new Error('plaintext outside [0, 2^bound_bits)');
  };
}

for (const curve of ['bls12381']) {
  const { Point } = CURVES[curve];
  const x = 0x5eed1234n;
  const Y = Point.BASE.multiply(x);
  const ua = '0x' + 'aa'.repeat(32);
  const token = '0x5FbDB2315678afecb367f032d93F642f64180aa3';
  const device = deviceFor(curve, x);

  test(`${curve}: checkBalance — one comparison, any size, exact`, () => {
    const big = (1n << 54n) - 5n; // past Number.MAX_SAFE_INTEGER
    const acc = hexCt(curve, enc(curve, Y, big, 77n));
    assert.equal(checkBalance(curve, x, acc, big), true);
    assert.equal(checkBalance(curve, x, acc, big - 1n), false);
    assert.equal(checkBalance(curve, x, acc, String(big)), true);
    assert.equal(checkBalance(curve, x + 1n, acc, big), false);
    assert.equal(checkBalance(curve, x, acc, -1n), false);
    const zero = hexCt(curve, { C: Point.ZERO, D: Point.ZERO }); // fresh account (O, O)
    assert.equal(checkBalance(curve, x, zero, 0n), true);
    assert.equal(checkBalance(curve, x, zero, 1n), false);
  });

  test(`${curve}: cache box opens only with x, BigInt survives`, async () => {
    const entries = { k: { ua, token, accSeq: 3, balance: (1n << 54n) - 1n } };
    const box = await sealBalanceCache(curve, x, entries);
    assert.deepEqual(await openBalanceCache(curve, x, box), entries);
    assert.deepEqual(await openBalanceCache(curve, x + 1n, box), {});
    assert.deepEqual(await openBalanceCache(curve, x, { ...box, ct: box.ct.slice(0, -2) + 'AA' }), {});
    assert.deepEqual(await openBalanceCache(curve, x, undefined), {});
    assert.ok(!JSON.stringify(box).includes(String((1n << 54n) - 1n)), 'balance is not stored in clear');
  });

  test(`${curve}: balance > 2^44 — device refuses, CLI value validated, debit and rollOver tracked`, async () => {
    const b0 = (1n << 44n) + (1n << 34n);
    let acc = enc(curve, Y, b0, 99n);
    const st = () => ({ ua, token, acc: hexCt(curve, acc), accSeq: 1 });
    const entries = {};
    const tooBig = async () => { throw new Error('plaintext outside [0, 2^bound_bits)'); };
    await assert.rejects(readBalance(curve, x, entries, st(), tooBig), /zether-read-balance/);
    // The desktop reader's answer is entered — a wrong one is refused.
    assert.equal(setCachedBalance(curve, x, entries, st(), b0 + 1n), false);
    assert.equal(setCachedBalance(curve, x, entries, st(), b0), true);
    assert.deepEqual(await readBalance(curve, x, entries, st(), tooBig), { balance: b0, source: 'cache' });
    // Own transfer: acc −= (C_deb + [fee]G, D_out), v > 2^32.
    const v = (1n << 33n) + 7n, fee = 300n, s = 4242n;
    acc = { C: acc.C.subtract(mul(Point.BASE, v).add(Y.multiply(s))).subtract(mul(Point.BASE, fee)), D: acc.D.subtract(Point.BASE.multiply(s)) };
    assert.equal(cacheAfterDebit(curve, x, entries, st(), v, fee), true);
    const b1 = b0 - v - fee;
    assert.equal((await readBalance(curve, x, entries, st(), tooBig)).balance, b1);
    // rollOver: acc += pending; the device decrypts only pending.
    const p = 1234n;
    acc = { C: acc.C.add(enc(curve, Y, p, 5n).C), D: acc.D.add(enc(curve, Y, p, 5n).D) };
    assert.equal(cacheAfterRollOver(curve, x, entries, st(), p + 1n), false, 'wrong pending refused');
    assert.equal(setCachedBalance(curve, x, entries, st(), b1), false, 'stale value after rollOver refused');
    // The last checked balance stays as the anchor: the device reads the difference, not the 2^44+ total.
    assert.deepEqual(await readBalance(curve, x, entries, st(), device), { balance: b1 + p, source: 'delta' });
    assert.equal((await readBalance(curve, x, entries, st(), tooBig)).balance, b1 + p);
  });

  // review M1: a rollOver the wallet did not do (rollOverPublic / rollOverBatch by anyone, late credits swept
  // by rollOverSigned) and a debit it did not record must not strand a > 2^44 balance on the device.
  test(`${curve}: cached balance > 2^44 survives third-party rollOver griefing and unrecorded debits`, async () => {
    let b = (1n << 50n) + 77n;
    let acc = enc(curve, Y, b, 31n);
    const st = () => ({ ua, token, acc: hexCt(curve, acc), accSeq: 1 });
    const entries = {};
    assert.equal(setCachedBalance(curve, x, entries, st(), b), true);
    for (let i = 0n; i < 3n; i++) { // attacker: fund(victim, 1 + i) then rollOverPublic(victim), repeatedly
      const credit = enc(curve, Y, 1n + i, 900n + i);
      acc = { C: acc.C.add(credit.C), D: acc.D.add(credit.D) };
      b += 1n + i;
      assert.deepEqual(await readBalance(curve, x, entries, st(), device), { balance: b, source: 'delta' });
    }
    // Own transfer the wallet never recorded (v + fee = 502) plus a credit of 100 rolled by someone else.
    const s = 777n;
    acc = { C: acc.C.subtract(mul(Point.BASE, 500n).add(Y.multiply(s))).subtract(mul(Point.BASE, 2n)), D: acc.D.subtract(Point.BASE.multiply(s)) };
    const credit = enc(curve, Y, 100n, 12n);
    acc = { C: acc.C.add(credit.C), D: acc.D.add(credit.D) };
    b = b - 502n + 100n;
    assert.deepEqual(await readBalance(curve, x, entries, st(), device), { balance: b, source: 'delta' });
    // A change beyond the device bound still sends the user to the CLI, and the anchor is kept.
    const big = enc(curve, Y, 1n << 40n, 13n);
    acc = { C: acc.C.add(big.C), D: acc.D.add(big.D) };
    await assert.rejects(readBalance(curve, x, entries, st(), device), /zether-read-balance/);
    assert.equal(Object.values(entries)[0].balance, b);
  });

  // review N2: a backend/RPC knows Y and can forge an `acc` for any balance; an older accSeq must never
  // become the anchor, or a lie within the device bound would replace a real > 2^44 balance.
  test(`${curve}: accSeq is monotonic — a forged lower-seq acc does not move the anchor`, async () => {
    const b = (1n << 50n) + 5n;
    const entries = {};
    assert.equal(setCachedBalance(curve, x, entries, { ua, token, acc: hexCt(curve, enc(curve, Y, b, 4n)), accSeq: 5 }, b), true);
    const forged = { ua, token, acc: hexCt(curve, enc(curve, Y, b + 10n, 8n)), accSeq: 3 };
    assert.equal(setCachedBalance(curve, x, entries, forged, b + 10n), false);
    await assert.rejects(readBalance(curve, x, entries, forged, device), /accSeq/);
    assert.equal(Object.values(entries)[0].balance, b);
    assert.equal(Object.values(entries)[0].accSeq, 5);
    // Same or higher seq is fine (debits do not bump accSeq; rollOvers do).
    const later = { ua, token, acc: hexCt(curve, enc(curve, Y, b + 10n, 8n)), accSeq: 6 };
    assert.deepEqual(await readBalance(curve, x, entries, later, device), { balance: b + 10n, source: 'delta' });
  });

  // review N1 (not applied): the last try, BSGS on acc itself, still hits when a big anchor was spent down
  // elsewhere (same seed on another device, or the CLI) — the difference is then beyond the bound both ways.
  test(`${curve}: big anchor, balance spent down elsewhere — full device BSGS still recovers it`, async () => {
    const entries = {};
    assert.equal(setCachedBalance(curve, x, entries, { ua, token, acc: hexCt(curve, enc(curve, Y, 1n << 50n, 4n)), accSeq: 1 }, 1n << 50n), true);
    const now = { ua, token, acc: hexCt(curve, enc(curve, Y, 1000n, 9n)), accSeq: 1 };
    assert.deepEqual(await readBalance(curve, x, entries, now, device), { balance: 1000n, source: 'bsgs' });
  });

  test(`${curve}: small balance — cache miss falls back to device BSGS and fills the cache`, async () => {
    const acc = hexCt(curve, enc(curve, Y, 5000n, 3n));
    const entries = {};
    const state = { ua, token, acc, accSeq: 2 };
    let calls = 0;
    const decrypt = async () => { calls++; return '5000'; };
    assert.deepEqual(await readBalance(curve, x, entries, state, decrypt), { balance: 5000n, source: 'bsgs' });
    assert.deepEqual(await readBalance(curve, x, entries, state, decrypt), { balance: 5000n, source: 'cache' });
    assert.equal(calls, 1);
    await assert.rejects(readBalance(curve, x, {}, state, async () => '5001'), /does not match/);
  });
}
