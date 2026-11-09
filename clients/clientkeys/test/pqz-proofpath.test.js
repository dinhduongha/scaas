// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Group 3h, plan T59 (pqz-proof-path spec §3, §9.3; C3, C4, C9): `pqzOwnTag` and `pqzMemoHash` against the shared KAT rows of
// smartcontracts/vectors/ua/pq_kat.json (forge's PqzOwnTag.t.sol reads the same `memoHash` rows against the statement views), and
// the six typed rows of release 3h. UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { pqzOwnTag, pqzMemoHash, pqzDebitRecordOf, pqzBlobTailOf, pqzDebitProofOf, TYPED_OPS } from '../src/evm.js';
import { pqzKeySeed } from '../src/pq.js';
import { seedFromWords } from '../src/seed.js';
import { hex, fromHex, utf8ToBytes, concatBytes } from '../src/bytes.js';

const KAT = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/ua/pq_kat.json', import.meta.url), 'utf8'));
const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/typed/typed_ops.json', import.meta.url), 'utf8'));
// T62: the forge state vectors of the default set and n2048-kmax1024 (PqzStateVectors.t.sol, STATE_VECTORS=1)
const STATES = ['n2304-kmax4096/state.json', 'state.json'].map((f) =>
  JSON.parse(readFileSync(new URL(`../../../smartcontracts/vectors/pqz/${f}`, import.meta.url), 'utf8')));

test('ownTag: the KAT rows, recomputed here with HKDF-SHA256 then HMAC-SHA256 (label PQZ/owntag/v1, empty salt)', () => {
  const seed = seedFromWords(KAT.mnemonic);
  assert.equal(KAT.ownTag.length, 3);
  for (const r of KAT.ownTag) {
    assert.equal(r.label, 'PQZ/owntag/v1');
    assert.equal(r.seed32, hex(pqzKeySeed(seed, 0, 0, r.version)), `the version ${r.version} seed`);
    const key = hkdf(sha256, fromHex(r.seed32), new Uint8Array(0), utf8ToBytes('PQZ/owntag/v1'), 32);
    const be32 = fromHex(BigInt(r.sendCounter).toString(16).padStart(8, '0'));
    const msg = concatBytes(fromHex(r.chainUid), fromHex(r.token), fromHex(r.fromUA), be32, fromHex(r.ctHash));
    assert.equal(msg.length, 32 + 20 + 32 + 4 + 32);
    assert.deepEqual([r.key, r.message, r.ownTag], [hex(key), hex(msg), hex(hmac(sha256, key, msg))], `v${r.version} c${r.sendCounter}`);
    assert.deepEqual(pqzOwnTag(r), { key: r.key, message: r.message, ownTag: r.ownTag });
  }
  // the key is counter-free (one per seed version); the counter and the ciphertext are in the message
  assert.equal(KAT.ownTag[0].key, KAT.ownTag[1].key);
  assert.notEqual(KAT.ownTag[1].key, KAT.ownTag[2].key, 'another version, another key');
  assert.notEqual(KAT.ownTag[0].ownTag, KAT.ownTag[1].ownTag);
});

test('ownTag: from the packed parts, keccak256(P(u) ‖ P(v_f)); every input changes it; be32 counter only', () => {
  const r = KAT.ownTag[0];
  const pu = utf8ToBytes('a packed u');
  const pvf = utf8ToBytes('a packed v_f');
  const t = pqzOwnTag({ ...r, ctHash: undefined, pu, pvf });
  assert.equal(t.ownTag, pqzOwnTag({ ...r, ctHash: hex(keccak_256(concatBytes(pu, pvf))) }).ownTag);
  for (const [k, v] of [['sendCounter', 1], ['token', '0x' + '11'.repeat(20)], ['fromUA', '0x' + '22'.repeat(32)],
    ['chainUid', '0x' + '33'.repeat(32)], ['ctHash', '0x' + '44'.repeat(32)]]) {
    assert.notEqual(pqzOwnTag({ ...r, [k]: v }).ownTag, r.ownTag, k);
  }
  assert.throws(() => pqzOwnTag({ ...r, sendCounter: 2n ** 32n }), /be32/);
  assert.throws(() => pqzOwnTag({ ...r, token: '0x' + '11'.repeat(32) }), /20 bytes/);
});

test('memoHash: keccak256(memo ‖ ownTag), the HASH memo salt ‖ sealedMemo, empty on BUNDLE and a burn; without ownTag it differs', () => {
  assert.deepEqual(KAT.memoHash.map((m) => m.form), ['hash', 'bundle', 'burn']);
  assert.equal(fromHex(KAT.memoHash[0].memo).length, 16 + 42, 'op 1 commit-reveal: salt(16) ‖ sealedMemo(2 + 40)');
  for (const m of KAT.memoHash) {
    assert.equal(m.memoHash, hex(keccak_256(concatBytes(fromHex(m.memo), fromHex(m.ownTag)))), m.form);
    assert.equal(pqzMemoHash(m.memo, m.ownTag), m.memoHash, m.form);
    assert.notEqual(hex(keccak_256(fromHex(m.memo))), m.memoHash, `${m.form}: the tag is in the preimage`);
  }
  assert.equal(KAT.memoHash[1].memoHash, hex(keccak_256(fromHex(KAT.memoHash[1].ownTag))), 'BUNDLE: keccak256(ownTag)');
});

test('the six PQZ debit rows of release 3h: ownTag in the args struct, signed, the relayer and fee recipient unbound at fee 0', () => {
  const three = Object.entries(V.ops).filter(([, r]) => r.release === '3h').map(([n]) => n);
  assert.deepEqual(three.sort(), ['UAPqzTransfer', 'UAPqzTransferCompact', 'UAPqzTransferSingle', 'UAPqzTransferSingleCompact',
    'UAPqzUnshield', 'UAPqzUnshieldUnwrap']);
  for (const n of three) {
    const r = V.ops[n];
    assert.match(r.typeString, /bytes32 ownTag,bytes(\[\])? u,/, n);
    assert.equal(r.typeString, TYPED_OPS[n].typeString, n);
    assert.equal(fromHex(r.message.args.ownTag).length, 32, n);
    assert.deepEqual([r.message.mode, r.message.fee], [0, '0'], `${n}: fee NONE at 0, no restriction bit`);
    assert.deepEqual([r.message.relayer, r.message.feeRecipient], ['0x' + '00'.repeat(20), '0x' + '00'.repeat(20)], `${n}: canonical 0`);
  }
});

// Group 3h, plan T62 (spec §2.2, §3.2, §4.2, §9.3; C-PP-1): the record words, the op blob tails and the logged P of the forge state
// vectors at two sets, read here from the bytes alone and equal to what the contract's own views answered (`pqzDebitRecord`, the
// statement's key versions, the event as emitted).
test('state.json (two sets): release 3h; every debit record decodes from its two words to pqzDebitRecord\'s view', () => {
  for (const st of STATES) {
    assert.equal(st.release, '3h', st.set);
    const forms = new Set();
    for (const r of st.records) {
      const v = pqzDebitRecordOf(r.w0, r.w1, r.counter);
      for (const k of ['p', 'deltaP', 'proofStore', 'shieldIn', 'keyVersion', 'prevCounter']) {
        assert.equal(v[k], BigInt(r.view[k]), `${st.set} ${r.ua} ${r.counter}: ${k}`);
      }
      assert.deepEqual([v.prevBlob, v.hasPrev], [r.view.prevBlob, r.view.hasPrev], `${st.set} ${r.ua} ${r.counter}`);
      assert.equal(v.flags & 1n, 1n, 'RECORD always set');
      forms.add(v.flags & 2n ? 'wide' : 'narrow');
      if (v.proofStore === 1n) forms.add('log');
      if (!(v.flags & 2n)) assert.equal(BigInt(r.w1), 0n, `${st.set} ${r.ua} ${r.counter}: no w1 when narrow`);
    }
    assert.deepEqual([...forms].sort(), ['log', 'narrow', 'wide'], `${st.set}: narrow, wide and a LOG record`);
    assert.throws(() => pqzDebitRecordOf('0x' + '00'.repeat(32), '0x00', 0), /DebitRecordUnknown/);
  }
});

test('state.json (two sets): every op blob\'s tail ownTag ‖ kv ‖ u8(n), read from the last byte, and R before P(v_f)', () => {
  for (const st of STATES) {
    const ns = new Set();
    for (const t of st.tails) {
      const x = pqzBlobTailOf(t.code);
      assert.deepEqual([x.ownTag, x.kv.map(String), x.n], [t.ownTag, t.kv.map(String), t.n], `${st.set} ${t.name}`);
      assert.equal(x.dataLen - x.tailLen - t.vp, t.rLen, `${st.set} ${t.name}: R ends where P(v_f) starts`);
      ns.add(t.n);
    }
    assert.ok(ns.has(0) && ns.has(1) && ns.has(2), `${st.set}: a burn (n 0), op 1 with and without the auditor`);
    assert.ok(st.tails.some((t) => t.kv.some((v) => BigInt(v) !== 0n)), `${st.set}: a leg at a key version above 0`);
    assert.ok(st.tails.some((t) => BigInt(t.ownTag) !== 0n), `${st.set}: a non-zero ownTag`);
  }
});

test('state.json (two sets): the logged P, PqzDebitProof(blob, ua, sendCounter, header, proof), decodes from its log', () => {
  for (const st of STATES) {
    assert.ok(st.proofLogs.length > 0, st.set);
    for (const l of st.proofLogs) {
      const d = pqzDebitProofOf(l);
      assert.deepEqual([d.blob, d.ua, d.sendCounter, d.header, d.proof], [l.blob, l.ua, BigInt(l.sendCounter), l.header, l.proof], st.set);
      assert.equal(fromHex(d.header).length, 640, 'the verified header');
      const rec = st.records.find((r) => r.ua === l.ua && r.counter === l.sendCounter);
      assert.equal(BigInt(rec.view.proofStore), 1n, 'its record says LOG');
    }
    assert.throws(() => pqzDebitProofOf({ ...st.proofLogs[0], topics: ['0x' + '00'.repeat(32), ...st.proofLogs[0].topics.slice(1)] }),
      /PqzDebitProof/);
  }
});
