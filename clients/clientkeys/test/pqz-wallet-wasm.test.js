// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The wallet module (pqz-core/ffi/wallet-wasm, TODO 3zf; CLI-SGN-51) through its loader src/pqzopenWasm.js: opening.json's rows
// rebuilt natively (wallet-wasm/cases.rs) and checked field by field against the vectors, every case's outcome in wasm equal
// to pqz-ffi's native outcome, the raw ABI's one outcome on malformed frames, the loader's on malformed inputs, and
// `pqzKeyHandle.check(credit, wallet)` on real credits. Needs the built modules and cases: PQZ_WALLET_DIR (wallet-wasm/run.sh
// sets it; without it these tests are skipped). UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { hex, fromHex, concatBytes } from '../src/bytes.js';
import { loadPqzWallet, pqzUnpack, isPqzWallet } from '../src/pqzopenWasm.js';
import { pqzKeyHandle, pqzLayout, pqzOpeningAad, sealOpening } from '../src/pqzopen.js';

const DIR = process.env.PQZ_WALLET_DIR;
const ROOT = new URL('../../../', import.meta.url);
const SETS = (process.env.PQZ_WALLET_SETS ?? 'n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536').split(/\s+/)
  .filter((s) => DIR && existsSync(`${DIR}/pqz_wallet_${s}.wasm`));
const vectors = (s) => JSON.parse(readFileSync(new URL(`smartcontracts/vectors/pqz/${s === 'n2048-kmax1024' ? '' : `${s}/`}opening.json`, ROOT)));
const h0 = (x) => (x.startsWith('0x') ? x : `0x${x}`);
const outcomeR = (o) => (o === null ? 'skip' : `accepted:${hex(o.digits)}`);
const outcomeA = (o) => (o.outcome === 'read' ? `read:${hex(o.digits)}` : o.outcome);

// an independent framing of lib.rs's ABI (not the loader's)
const be4 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const be8 = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v)); return b; };
const fields = (seed, c) => {
  const p = (x) => [fromHex(x.ua), be8(x.keyVersion), fromHex(x.pk), fromHex(x.kemPk), fromHex(x.v), fromHex(x.opening)];
  return [fromHex(seed), fromHex(c.chainUid), fromHex(c.token), fromHex(c.u), ...p(c.to), Uint8Array.of(c.auditor ? 1 : 0),
    ...(c.auditor ? p(c.auditor) : [])];
};
const frame = (fs) => concatBytes(...fs.flatMap((f) => [be4(f.length), f]));

test('wallet module: PQZ_WALLET_DIR names the built modules', { skip: DIR ? false : 'PQZ_WALLET_DIR unset (wallet-wasm/run.sh)' }, () => {
  assert.ok(SETS.length > 0, `no pqz_wallet_<set>.wasm in ${DIR}`);
});

for (const set of SETS) {
  const bytes = readFileSync(`${DIR}/pqz_wallet_${set}.wasm`);
  const C = JSON.parse(readFileSync(`${DIR}/cases-${set}.json`, 'utf8'));
  const K = vectors(set);

  test(`${set}: opening.json's rows = the natively rebuilt credits, field by field`, () => {
    assert.equal(C.set, set);
    assert.equal(K.rows.length, C.rows.length);
    for (const r of K.rows) {
      const x = C.rows.find((y) => y.auditorOn === r.auditorOn);
      const c = x.credit;
      assert.equal(x.seed_leg, h0(r.seed_leg));
      assert.equal(hex(keccak_256(fromHex(c.u))), h0(r.u_keccak));
      assert.equal(hex(keccak_256(fromHex(c.to.pk))), h0(r.pk_t_keccak));
      assert.equal(c.to.v, h0(r.v_t));
      assert.equal(c.to.opening, h0(r.opening_t));
      assert.equal(c.to.ua, h0(r.toUA));
      const b = fromHex(x.pvt).length / 2; // vp = 16·PACK_BITS / 8 bytes
      assert.equal(hex(pqzUnpack(fromHex(x.pu), b)), c.u, 'pqzUnpack(P(u)) = u');
      assert.equal(hex(pqzUnpack(fromHex(x.pvt), b)), c.to.v, 'pqzUnpack(P(v_t)) = v_t');
      assert.equal(hex(pqzOpeningAad({ chainUid: c.chainUid, token: c.token, ua: c.to.ua, keyVersion: 0, pu: x.pu, pv: x.pvt })), h0(r.aad_t));
      if (r.auditorOn) {
        assert.equal(c.auditor.v, h0(r.v_a));
        assert.equal(c.auditor.opening, h0(r.opening_a));
        assert.equal(hex(pqzOpeningAad({ chainUid: c.chainUid, token: c.token, ua: c.auditor.ua, keyVersion: 0, pu: x.pu, pv: x.pva })), h0(r.aad_a));
      } else assert.equal(c.auditor, null);
    }
    K.openKemSeeds.forEach((r, i) => {
      const cs = C.cases.filter((c) => c.name.endsWith(`openKemSeeds[${i}]`));
      assert.equal(cs.length, 2);
      for (const c of cs) assert.equal(c.openKemSeed, h0(r.openKemSeed));
    });
  });

  test(`${set}: every case, wasm = native (pqz-ffi opening::check_recipient / check_auditor)`, async () => {
    const w = await loadPqzWallet(bytes);
    assert.ok(isPqzWallet(w) && Object.isFrozen(w));
    assert.equal(w.pkBytes, C.pkBytes);
    const seen = new Set();
    for (const c of C.cases) {
      const got = c.check === 'recipient' ? outcomeR(w.checkRecipient(c.openKemSeed, c.credit)) : outcomeA(w.checkAuditor(c.openKemSeed, c.credit));
      assert.equal(got, c.native, c.name);
      seen.add(c.native.split(':')[0]);
    }
    // the cases reach every outcome
    assert.deepEqual([...seen].sort(), ['accepted', 'read', 'recipient-unreadable', 'skip', 'unreadable']);
    const ok = w.checkRecipient(C.cases[0].openKemSeed, C.cases[0].credit);
    assert.equal(ok.amount, ok.digits.reduceRight((a, d) => a * 16n + BigInt(d), 0n));
    console.log(`# ${set}: ${C.cases.length} cases wasm = native`);
  });

  test(`${set}: opening.json's rejects (review 3w-delta U2-2): wasm = the native outcomes the generator recorded`, async () => {
    const w = await loadPqzWallet(bytes);
    const x = C.rows.find((y) => y.auditorOn);
    assert.ok(K.rejects.length >= 22);
    for (const r of K.rejects) {
      const c = structuredClone(x.credit);
      if (r.field === 'chainUid') c.chainUid = h0(r.value); // T21 L66b: an aad of another chain or key version
      else if (r.field === 'to.keyVersion') c.to.keyVersion = Number(BigInt(h0(r.value)));
      else {
        const [who, f] = r.field.split('.');
        assert.ok((who === 'to' || who === 'auditor') && (f === 'opening' || f === 'kemPk'), r.field);
        c[who][f] = h0(r.value);
      }
      assert.equal(outcomeR(w.checkRecipient(x.openKemSeedT, c)), r.recipient, r.case);
      assert.equal(outcomeA(w.checkAuditor(x.openKemSeedA, c)), r.auditor, r.case);
    }
    // control: the unedited credit reads
    assert.ok(outcomeA(w.checkAuditor(x.openKemSeedA, x.credit)).startsWith('read:'));
  });

  test(`${set}: the raw ABI: a malformed frame is the one outcome, no trap; output and input cleared`, async () => {
    const { instance: { exports: e } } = await WebAssembly.instantiate(bytes, {});
    const view = (ptr, n) => new Uint8Array(e.memory.buffer, ptr, n); // call ptr() first: it may grow the memory
    const cap = e.input_cap();
    const call = (fn, f) => {
      if (f.length > cap) return e[fn](f.length); // the module must refuse n > cap itself
      view(e.input_ptr(), cap).set(f);
      return e[fn](f.length);
    };
    const out = () => hex(view(e.out_ptr(), 16));
    const zeroIn = () => view(e.input_ptr(), cap).every((x) => x === 0);
    const ZERO = hex(new Uint8Array(16));
    const rc = C.cases.find((c) => c.name === 'aud recipient control');
    const ac = C.cases.find((c) => c.name === 'aud auditor control');
    const fr = fields(rc.openKemSeed, rc.credit);
    // positive control
    assert.equal(call('check_recipient', frame(fr)), 1);
    assert.equal(`accepted:${out()}`, rc.native);
    assert.ok(zeroIn(), 'the input (the opening KEM seed) is zeroed after the call');
    assert.equal(call('check_auditor', frame(fields(ac.openKemSeed, ac.credit))), 1);
    assert.equal(`read:${out()}`, ac.native);
    let n = 0;
    const bad = (f, why) => {
      for (const fn of ['check_recipient', 'check_auditor']) {
        assert.equal(call(fn, f), 0, `${fn}: ${why}`);
        assert.equal(out(), ZERO, `${fn}: output cleared: ${why}`);
        assert.ok(zeroIn(), `${fn}: input cleared: ${why}`);
        n++;
      }
    };
    const good = frame(fr);
    bad(new Uint8Array(0), 'n = 0');
    bad(good.subarray(0, good.length - 1), 'one byte short');
    bad(concatBytes(good, Uint8Array.of(0)), 'one byte after the frame');
    bad(concatBytes(good, new Uint8Array(cap - good.length + 1)), 'n = cap + 1');
    assert.equal(e.check_recipient(0xffffffff), 0, 'n = 2^32 - 1');
    fr.forEach((f, i) => {
      if (f.length > 1) bad(frame(fr.map((g, j) => (j === i ? g.subarray(0, g.length - 1) : g))), `field ${i} short`);
      bad(frame(fr.map((g, j) => (j === i ? concatBytes(g, Uint8Array.of(0)) : g))), `field ${i} long`);
      const lie = frame(fr); // the length word of field i one less than its bytes
      const off = fr.slice(0, i).reduce((a, g) => a + 4 + g.length, 0);
      new DataView(lie.buffer).setUint32(off, f.length - 1);
      bad(lie, `field ${i} length word`);
    });
    const flag = fr.findIndex((f, i) => i > 0 && f.length === 1);
    bad(frame(fr.map((g, j) => (j === flag ? Uint8Array.of(2) : g))), 'auditorOn = 2');
    bad(frame(fr.slice(0, flag + 1).map((g, j) => (j === flag ? Uint8Array.of(1) : g))), 'auditorOn = 1, no auditor');
    bad(frame([...fr, ...fr.slice(flag + 1)]), 'a third party');
    // the plain row with auditorOn = 1 and nothing after: refused; its control still accepts
    const pc = C.cases.find((c) => c.name === 'plain recipient control');
    const pf = fields(pc.openKemSeed, pc.credit);
    assert.equal(call('check_recipient', frame(pf)), 1);
    bad(frame(pf.map((g, j) => (j === pf.length - 1 ? Uint8Array.of(1) : g))), 'plain: auditorOn = 1, no auditor');
    console.log(`# ${set}: ${n} raw malformed frames, one outcome each`);
  });

  test(`${set}: the loader: malformed inputs give the one outcome, never a throw`, async () => {
    const w = await loadPqzWallet(new WebAssembly.Module(bytes));
    const rc = C.cases.find((c) => c.name === 'aud recipient control');
    const seed = rc.openKemSeed, c = rc.credit;
    const both = (s, x, why) => {
      assert.equal(w.checkRecipient(s, x), null, why);
      assert.deepEqual(w.checkAuditor(s, x), { outcome: 'unreadable' }, why);
    };
    const sh = (x) => x.slice(0, -2), lg = (x) => `${x}00`;
    let n = 0;
    const each = (why, s, x) => { both(s, x, why); n++; };
    each('seed short', sh(seed), c);
    each('seed long', lg(seed), c);
    each('seed odd hex', seed.slice(0, -1), c);
    each('seed not hex', seed.replace(/.$/, 'g'), c);
    each('seed undefined', undefined, c);
    each('seed a number', 7, c);
    each('credit null', seed, null);
    each('credit a string', seed, 'x');
    for (const k of ['chainUid', 'token', 'u']) {
      each(`${k} short`, seed, { ...c, [k]: sh(c[k]) });
      each(`${k} long`, seed, { ...c, [k]: lg(c[k]) });
      each(`${k} missing`, seed, { ...c, [k]: undefined });
    }
    for (const who of ['to', 'auditor']) {
      for (const k of ['ua', 'pk', 'kemPk', 'v', 'opening']) {
        each(`${who}.${k} short`, seed, { ...c, [who]: { ...c[who], [k]: sh(c[who][k]) } });
        each(`${who}.${k} long`, seed, { ...c, [who]: { ...c[who], [k]: lg(c[who][k]) } });
      }
      for (const kv of [-1, 2 ** 53, 1n << 64n, 0.5, '0', null]) each(`${who}.keyVersion ${kv}`, seed, { ...c, [who]: { ...c[who], keyVersion: kv } });
      each(`${who} a number`, seed, { ...c, [who]: 3 });
    }
    each('to missing', seed, { ...c, to: undefined });
    // the tampered openings and the wrong seeds are cases of the differential; here the outcomes again, by name
    for (const name of ['aud recipient O_t tag flipped', 'aud recipient O_t sealedSeed flipped', 'aud recipient O_t mlkemCt flipped',
      'aud recipient the auditor\'s seed', 'aud recipient seed ML-KEM half flipped', 'aud recipient seed X25519 half flipped',
      'aud recipient openKemSeeds[1]', 'aud recipient O_a tag flipped']) {
      const x = C.cases.find((y) => y.name === name);
      assert.equal(w.checkRecipient(x.openKemSeed, x.credit), null, name);
      n++;
    }
    // still answering: the control after all of the above
    assert.equal(outcomeR(w.checkRecipient(seed, c)), rc.native);
    console.log(`# ${set}: ${n} loader negatives, one outcome each`);
  });

  test(`${set}: a trap drops the instance: the next call runs on a fresh one and gives the right outcome`, async () => {
    // a correct module cannot be made to trap from outside, so the test wraps the loader's first instance: once armed, its
    // checks throw WebAssembly.RuntimeError and keep throwing (a trapped instance's state is not trusted again)
    const Real = WebAssembly.Instance;
    let made = 0, armed = false, trapped = false;
    WebAssembly.Instance = function (m, imports) {
      const i = new Real(m, imports);
      if (++made > 1) return i;
      const trap = (f) => (...a) => { if (armed || trapped) { trapped = true; throw new WebAssembly.RuntimeError('unreachable'); } return f(...a); };
      return { exports: { ...i.exports, check_recipient: trap(i.exports.check_recipient), check_auditor: trap(i.exports.check_auditor) } };
    };
    try {
      const w = await loadPqzWallet(bytes);
      const rc = C.cases.find((c) => c.name === 'aud recipient control');
      const ac = C.cases.find((c) => c.name === 'aud auditor control');
      assert.equal(outcomeR(w.checkRecipient(rc.openKemSeed, rc.credit)), rc.native, 'control on the first instance');
      assert.equal(made, 1);
      armed = true;
      assert.equal(w.checkRecipient(rc.openKemSeed, rc.credit), null, 'a trap is the one outcome, no throw');
      assert.ok(trapped);
      armed = false;
      assert.equal(made, 2, 'the trapped instance was replaced');
      assert.equal(outcomeR(w.checkRecipient(rc.openKemSeed, rc.credit)), rc.native, 'the next call: the right outcome');
      assert.equal(outcomeA(w.checkAuditor(ac.openKemSeed, ac.credit)), ac.native);
      armed = true; // the auditor side too, on the fresh instance: no wrap there, so no trap and no new instance
      assert.equal(outcomeA(w.checkAuditor(ac.openKemSeed, ac.credit)), ac.native);
      assert.equal(made, 2);
    } finally {
      WebAssembly.Instance = Real;
    }
  });

  test(`${set}: pqzKeyHandle.check(credit, wallet): accepted with the module's digits; a planted u* is a skip`, async () => {
    const w = await loadPqzWallet(bytes);
    const BIP39 = fromHex(h0(K.bip39_seed));
    const x = C.rows.find((r) => r.auditorOn);
    const c = x.credit;
    const packBits = fromHex(x.pvt).length / 2;
    const layout = pqzLayout((fromHex(x.pu).length * 8) / packBits, packBits);
    const h = pqzKeyHandle(BIP39, { chainUid: c.chainUid, ua: c.to.ua, version: 0, layout });
    assert.equal(hex(h.openKem), c.to.kemPk, 'the handle\'s opening KEM key is the credit\'s');
    // an op 1 credit's offsets (16, 16 + P(u)): the handle binds them (T21 O5 (b) review, F1)
    const SLOT = '0x' + (BigInt('0x5e' + '00'.repeat(19)) << 96n | 16n << 80n | BigInt(16 + layout.pkp) << 64n | 7n).toString(16).padStart(64, '0');
    const filled = (k, v) => new Uint8Array(k).fill(v);
    const blob = ({ pu = fromHex(x.pu), oT = fromHex(c.to.opening), oA = fromHex(c.auditor.opening) } = {}) => concatBytes(
      Uint8Array.of(0), filled(16, 3), pu, fromHex(x.pvt), fromHex(x.pva), fromHex(c.to.ua), filled(layout.pkp, 4), filled(layout.vp, 5),
      oT, oA, filled(32, 6), be8(0), be8(0), Uint8Array.of(2));
    const credit = (code, more = {}) => ({ token: c.token, index: 5, slot: SLOT, code, pk: c.to.pk, reads: { block: 1, finalized: true,
      strictMajority: true }, auditor: { ua: c.auditor.ua, pk: c.auditor.pk, kemPk: c.auditor.kemPk }, ...more });
    const want = C.cases.find((y) => y.name === 'aud recipient control').native;
    const ok = h.check(credit(blob()), w);
    assert.ok(ok.accepted, 'positive control');
    assert.equal(`accepted:${hex(ok.value.digits)}`, want);
    // a planted u*: the sender seals O_t and O_a over a crafted u; steps 3-4, 8 and 9's opening pass in clientkeys, the
    // module's Enc-expand (step 6) refuses it
    const pu = fromHex(x.pu).slice();
    pu[0] ^= 1;
    const aad = (ua, pv) => pqzOpeningAad({ chainUid: c.chainUid, token: c.token, ua, keyVersion: 0, pu, pv });
    const oT = sealOpening({ seedLeg: fromHex(x.seed_leg), role: 0, kemPk: fromHex(c.to.kemPk), aad: aad(c.to.ua, x.pvt) }).bytes;
    const oA = sealOpening({ seedLeg: fromHex(x.seed_leg), role: 1, kemPk: fromHex(c.auditor.kemPk), aad: aad(c.auditor.ua, x.pva) }).bytes;
    let ran = 0;
    assert.equal(h.check(credit(blob({ pu, oT, oA })), () => { ran++; return 1n; }).value, 1n, 'clientkeys alone passes it to verify');
    assert.equal(ran, 1);
    assert.ok(h.check(credit(blob({ pu, oT, oA })), w).skip, 'the module skips the planted u*');
    // the holder's own pk decides step 7: the auditor's pk in its place is a skip
    assert.ok(h.check(credit(blob(), { pk: c.auditor.pk }), w).skip, 'another pk');
    // inputs missing locally are an error before the check, never a skip
    assert.throws(() => h.check(credit(blob(), { pk: undefined }), w), /PQZ keys of the leg/);
    // a module of another set: refused
    const other = SETS.find((s) => s !== set);
    if (other) {
      const w2 = await loadPqzWallet(readFileSync(`${DIR}/pqz_wallet_${other}.wasm`));
      assert.throws(() => h.check(credit(blob()), w2), /another parameter set/);
    }
    // an object that looks like a wallet gets nothing: it is called as a plain verify, which it is not
    const fake = Object.freeze({ pkBytes: w.pkBytes, checkRecipient: () => { throw new Error('the fake got the seed'); } });
    assert.throws(() => h.check(credit(blob()), fake), TypeError);
    assert.equal(h.secretLoads, 0);
  });
}

test('the loader refuses a module that is not the wallet\'s', { skip: SETS.length ? false : 'no wallet module' }, async () => {
  // an empty module, and bytes that are no module
  const tiny = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
  await assert.rejects(loadPqzWallet(tiny), /not the PQZ wallet module/);
  await assert.rejects(loadPqzWallet(new Uint8Array([1, 2, 3])));
});
