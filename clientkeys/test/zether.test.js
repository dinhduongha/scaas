// R33 Zether conf keys: EIP-2333 published vectors (BLS12-381) and S3's pinned vectors
// (zether-prover/vectors/{r33_keys,schnorr_bn254,schnorr_bls12381}.json, copied verbatim) — the
// browser derivation must be byte-for-byte the prover's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  deriveMasterSk, deriveChildSk, deriveConfKey, confPublic, schnorrSign, schnorrVerify, popMessage, zetherPop,
  sealConfKey, openConfKey, confLabel, CURVES, encodePoint, checkBalance, sealBalanceCache, openBalanceCache,
  setCachedBalance, cacheAfterDebit, cacheAfterRollOver, readBalance,
} from '../src/zether.js';
import { deriveKey, seedFromWords, NETWORKS } from '../src/seed.js';
import { fromHex, hex } from '../src/bytes.js';

const vec = (f) => JSON.parse(readFileSync(new URL(`./vectors/${f}`, import.meta.url)));
const R33 = vec('r33_keys.json');

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
  assert.throws(() => deriveMasterSk('bn254', new Uint8Array(31)), /32 bytes/);
});

test('bn254 EIP-2333 variant == S3 pinned vectors', () => {
  for (const v of R33.eip2333_bn254_variant) {
    const m = deriveMasterSk('bn254', fromHex(v.seed));
    assert.equal(m, BigInt(v.master_SK));
    assert.equal(deriveChildSk('bn254', m, v.child_index), BigInt(v.child_SK));
  }
});

test('conf/disclosure keys from the mnemonic == S3 (x, Y, UA, path) on both curves', () => {
  const seed = seedFromWords(R33.mnemonic, R33.passphrase);
  assert.equal(hex(seed), R33.seed);
  for (const curve of ['bn254', 'bls12381']) {
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

test('S3 PoP vectors verify here; our PoP has the same c and verifies', () => {
  for (const curve of ['bn254', 'bls12381']) {
    for (const k of R33[curve].keys.filter((x) => x.pop)) {
      const { registry, account } = k.pop;
      const c = popMessage(curve, registry, k.Y, account);
      assert.equal(hex(c), k.pop.c);
      assert.ok(schnorrVerify(curve, fromHex(k.Y), c, fromHex(k.pop.schnorrPop)), `${curve} ${k.path}`);
      const mine = zetherPop(curve, fromHex(k.x), { registry, account });
      assert.equal(mine.c, k.pop.c);
      assert.ok(schnorrVerify(curve, fromHex(k.Y), c, fromHex(mine.schnorrPop)));
      assert.notEqual(mine.schnorrPop, k.pop.schnorrPop, 'hedged nonce');
      // popSignature = abi.encode(bytes schnorrPop, bytes "") — same layout as S3
      assert.equal(mine.popSignature.length, k.pop.popSignature.length);
      assert.equal(mine.popSignature.slice(0, 2 + 64 * 3), k.pop.popSignature.slice(0, 2 + 64 * 3));
      // bound to the account: another account or registry fails
      const other = popMessage(curve, registry, k.Y, '0x' + 'cc'.repeat(20));
      assert.equal(schnorrVerify(curve, fromHex(k.Y), other, fromHex(k.pop.schnorrPop)), false);
    }
  }
});

test('Schnorr with S3 fixed nonce is byte-identical; tampering fails', () => {
  for (const curve of ['bn254', 'bls12381']) {
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
  for (const curve of ['bn254', 'bls12381']) {
    for (const account of [0, 1]) for (const use of [7, 8]) xs.add(hex(deriveConfKey(seed, { curve, coin: 60, account, use }).x));
    xs.add(hex(deriveConfKey(seed, { curve, coin: 784, account: 0 }).x));
  }
  assert.equal(xs.size, 10);
  for (const net of Object.keys(NETWORKS)) {
    for (const i of [0, 1]) {
      const sk = deriveKey(seed, net, i).privateKey;
      assert.ok(!xs.has(hex(sk)), `${net}/${i}`);
    }
  }
});

test('x is sealed at rest like the seed; only Y/UA come back', async () => {
  const seed = seedFromWords(R33.mnemonic);
  const { vault, Y, UA } = await sealConfKey({ seed, curve: 'bn254', coin: 60, account: 0, pin: 'river-otter-7' });
  assert.equal(Y, R33.bn254.keys[0].Y);
  assert.equal(UA, R33.bn254.keys[0].UA);
  assert.equal(vault.label, confLabel('bn254', 60, 0));
  assert.ok(!JSON.stringify(vault).includes(R33.bn254.keys[0].x.slice(2)));
  assert.equal(hex(await openConfKey(vault, { pin: 'river-otter-7' })), R33.bn254.keys[0].x);
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
    assert.throws(() => deriveConfKey(seed, { curve: 'bn254', coin: 60, account }), /path index/);
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

for (const curve of ['bn254', 'bls12381']) {
  const { Point } = CURVES[curve];
  const x = 0x5eed1234n;
  const Y = Point.BASE.multiply(x);
  const ua = '0x' + 'aa'.repeat(32);
  const token = '0x5FbDB2315678afecb367f032d93F642f64180aa3';

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
    const p = 123_456_789n;
    acc = { C: acc.C.add(enc(curve, Y, p, 5n).C), D: acc.D.add(enc(curve, Y, p, 5n).D) };
    assert.equal(cacheAfterRollOver(curve, x, entries, st(), p + 1n), false, 'wrong pending: entry dropped');
    await assert.rejects(readBalance(curve, x, entries, st(), tooBig), /zether-read-balance/);
    assert.equal(setCachedBalance(curve, x, entries, st(), b1), false, 'stale value after rollOver refused');
    assert.equal(setCachedBalance(curve, x, entries, st(), b1 + p), true);
    assert.equal((await readBalance(curve, x, entries, st(), tooBig)).balance, b1 + p);
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
