// UA-8 (portable registrations, spec P1, P2, P7, P10, P11): smartcontracts/vectors/ua/portable.json against src/ua.js.
// The generator reproduces it byte for byte; every digest is rebuilt from its 32-byte words by hand (no chain id, no chain
// uid, no registry anywhere); the holder rules refuse what the registry refuses; every pop and KEM record signature
// verifies under the kind's verifier (test/ua-verify.js for the classical kinds, noble for the PQ kinds, msig per member,
// a native member by EIP-191 personal_sign); every negative gives its error.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ua from '../src/ua.js';
import { PQ_KINDS, pqMessage } from '../src/pq.js';
import { hex, keccak_256, utf8ToBytes, concatBytes, word } from '../src/bytes.js';
import { portableJson } from '../scripts/ua-portable-vectors.mjs';
import { B, attempt, verify, nativeOk, wordAt, bytesAt } from './ua-verify.js';

import { dir } from './ua-vectors-dir.js';
const TEXT = readFileSync(new URL('portable.json', dir), 'utf8');
const P = JSON.parse(TEXT);
const Z = `0x${'00'.repeat(32)}`;
const h = (s) => keccak_256(utf8ToBytes(s));
const row = (name) => P.registrations.find((r) => r.name === name) ?? assert.fail(`no row ${name}`);
const SETS = ['n2048-kmax1024', 'n2304-kmax4096', 'n2560-kmax16384', 'n2816-kmax65536'];
const args = (r) => ({ ua: r.ua, keyData: r.keyData, pqzKey: r.attrs.pqzKey, pqzPopHash: r.attrs.pqzPopHash,
  kemVersion: r.attrs.kemVersion, kemPk: r.attrs.kemPk });

const pqName = (kind) => Object.keys(PQ_KINDS).find((n) => PQ_KINDS[n].kind === kind);
/** A derived kind's signature over a 32-byte ua_msg: test/ua-verify.js (classical, BLS pop DST) or noble (PQ). */
function sigOk(kind, keyData, msg, sig) {
  const n = pqName(kind);
  if (!n) return verify(kind, keyData, msg, sig, true);
  return attempt(() => PQ_KINDS[n].alg.verify(B(sig), PQ_KINDS[n].pq ? pqMessage(n, B(msg)) : B(msg), B(keyData)));
}
/** `abi.decode(blob, (MemberSig[]))`, MemberSig = (uint16 index, bytes keyData, bytes sig). */
function memberSigs(blob) {
  const b = B(blob);
  const a = wordAt(b, 0);
  const base = a + 32;
  return Array.from({ length: wordAt(b, a) }, (_, i) => {
    const t = base + wordAt(b, base + 32 * i);
    return { index: wordAt(b, t), keyData: bytesAt(b, t, t + 32), sig: bytesAt(b, t, t + 64) };
  });
}
/** An msig signature: indices strictly increasing, each member verifies over `memberDigest` (derived members by key data
 *  from `keyOf`, under `member`; a native member by EIP-191 personal_sign, no key data), weight at least the threshold. */
function msigOk(r, md, blob, keyOf) {
  let weight = 0;
  let last = -1;
  for (const s of memberSigs(blob)) {
    const m = r.members[s.index];
    if (!m || s.index <= last) return false;
    last = s.index;
    const ok = ua.isNativeKind(m.kind)
      ? s.keyData.length === 0 && nativeOk(`0x${m.id.slice(26)}`, ua.personalSignDigest(B(md)), hex(s.sig))
      : s.keyData.length === 0 && sigOk(m.kind, keyOf(m.id), hex(ua.uaMessage(m.kind, ua.purposeTag('member'), B(md))), hex(s.sig));
    if (!ok) return false;
    weight += m.weight;
  }
  return weight >= r.threshold;
}
const rec = (name) => P.pqzKeyRecords.find((r) => r.name === name) ?? assert.fail(`no PQZ key record ${name}`);
const regOf = (id) => P.registrations.find((x) => x.ua === id) ?? assert.fail(`no registration of ${id}`);
const keyOf = (id) => P.registrations.find((x) => x.ua === id)?.keyData ?? assert.fail(`no registration for member ${id}`);

test('portable.json reproduced byte for byte', () => {
  assert.equal(portableJson(), TEXT);
});

test('portable PoP has no chain context', () => {
  assert.deepEqual(P.tags, {
    PURPOSE_POP_V2: { tag: 'scaas.ua.purpose.pop.v2', hash: hex(h('scaas.ua.purpose.pop.v2')) },
    PURPOSE_KEM: { tag: 'scaas.ua.purpose.kem.v1', hash: hex(h('scaas.ua.purpose.kem.v1')) },
    KEM_RECORD_TAG: { tag: 'scaas.ua.kem-record.v1', hash: hex(h('scaas.ua.kem-record.v1')) },
    PURPOSE_PQZ_KEY: { tag: 'scaas.ua.purpose.pqz-key.v1', hash: hex(h('scaas.ua.purpose.pqz-key.v1')) },
    PQZ_KEY_RECORD_TAG: { tag: 'scaas.ua.pqz-key-record.v1', hash: hex(h('scaas.ua.pqz-key-record.v1')) },
    PQZ_KEY_GROUP: { tag: 'scaas.ua.group.pqz-mlwe.v1', hash: hex(h('scaas.ua.group.pqz-mlwe.v1')) },
  });
  assert.deepEqual(P.checked, { none: 0, chain: 1, relayer: 2 });
  assert.deepEqual([ua.POP_V2_TAG, ua.KEM_TAG, ua.KEM_RECORD_TAG, ua.PQZ_KEY_TAG, ua.PQZ_KEY_RECORD_TAG, ua.GROUP('pqz-mlwe')].map(hex),
    Object.values(P.tags).map((t) => t.hash));
  // pqzKeyHash = keyHash(0x0142, pqzKey) = keccak256(PQZ_KEY_GROUP ‖ pqzKey), not a plain keccak of the key
  const k = row('mldsa65/n2048-kmax1024');
  assert.equal(k.pqzKeyHash, hex(keccak_256(concatBytes(h('scaas.ua.group.pqz-mlwe.v1'), B(k.attrs.pqzKey)))));
  assert.match(P.note, /pqzKeyHash = keccak256\(PQZ_KEY_GROUP \| pqzKey\)/);
  assert.deepEqual(ua.CHECKED, P.checked);
  assert.equal(ua.KEM_PK_LENGTH, P.kemPkLength);
  // one row by hand: keccak256 of the four words
  const r = row('mldsa65/n2304-kmax4096');
  const hand = keccak_256(concatBytes(h('scaas.ua.purpose.pop.v2'), B(r.ua), B(r.pqzKeyHash), B(r.kemRecordHash)));
  assert.equal(hex(hand), r.portablePopDigest);
  assert.notEqual(r.pqzKeyHash, Z);
  assert.notEqual(r.kemRecordHash, Z);
  for (const x of P.registrations) {
    assert.equal(hex(ua.portablePopDigest({ ua: x.ua, pqzKeyHash: x.pqzKeyHash, kemRecordHash: x.kemRecordHash })), x.portablePopDigest, x.name);
    assert.equal(x.pqzKeyHash, x.attrs.pqzKey === '0x' ? Z : hex(ua.keyHashOf(0x0142, B(x.attrs.pqzKey))), x.name);
    assert.equal(hex(ua.deriveUA(x.kind, B(x.keyData))), x.ua, x.name);
    assert.equal(x.kindName, ua.kindInfo(x.kind).name, x.name);
  }
  assert.doesNotMatch(TEXT, /chainId|chainUid|registry"/);
});

test('registration digest covers the proof hash', () => {
  for (const r of P.registrations) {
    const hand = keccak_256(concatBytes(B(r.portablePopDigest), B(r.attrs.pqzPopHash)));
    assert.equal(hex(hand), r.registrationDigest, r.name);
    assert.equal(hex(ua.uaMessage(r.kind, ua.POP_V2_TAG, hand)), r.popMessage, r.name);
    const m = ua.holderPopMessage(r.kind, args(r));
    assert.deepEqual([m.pqzKeyHash, m.pqzPopHash, m.kemRecordHash, m.portablePopDigest, m.registrationDigest, m.message].map(hex),
      [r.pqzKeyHash, r.attrs.pqzPopHash, r.kemRecordHash, r.portablePopDigest, r.registrationDigest, r.popMessage], r.name);
    if (r.attrs.pqzKey === '0x') {
      assert.deepEqual([r.attrs.pqzPopHash, r.pqzPop, r.pqzRegMessage, r.set], [Z, '0x', Z, ''], r.name);
      continue;
    }
    // the proof's hash is in attrs, covered by pop; the proof's own message (R_REG) does not contain it
    assert.equal(r.attrs.pqzPopHash, hex(keccak_256(B(r.pqzPop))), r.name);
    assert.equal(hex(ua.holderPopMessage(r.kind, { ...args(r), pqzPopHash: undefined, pqzPop: r.pqzPop }).registrationDigest), r.registrationDigest);
    assert.notEqual(hex(ua.registrationDigest(B(r.portablePopDigest), keccak_256(B(r.portablePopDigest)))), r.registrationDigest);
    assert.equal(r.pqzRegMessage, hex(ua.uaMessage(0x0142, ua.POP_V2_TAG, B(r.portablePopDigest))), r.name);
    assert.equal(hex(ua.pqzRegMessage(args(r))), r.pqzRegMessage, r.name);
    assert.equal(B(r.attrs.pqzKey).length, P.sets[r.set].pqzKeyLength, r.name);
    assert.equal(B(r.pqzPop).length, P.sets[r.set].pqzPopLength, r.name);
  }
  // PQZ rows at every parameter set, no gaps
  assert.deepEqual(Object.keys(P.sets), SETS);
  for (const base of ['mldsa65', 'msig-pq']) {
    assert.deepEqual(P.registrations.filter((r) => r.name.startsWith(`${base}/`)).map((r) => r.set), SETS, base);
  }
  assert.deepEqual(SETS.map((s) => P.sets[s].pqzKeyLength), [16384, 18432, 20480, 22528]);
});

test('kem record digest matches the hand-built words', () => {
  assert.deepEqual([...new Set(P.kemRecords.map((k) => k.name))], ['mldsa65', 'fndsa512', 'msig-pq']);
  for (const k of P.kemRecords) {
    const hand = keccak_256(concatBytes(h('scaas.ua.kem-record.v1'), B(k.ua), word(k.version), keccak_256(B(k.kemPk))));
    assert.equal(hex(hand), k.digest, `${k.name} v${k.version}`);
    assert.equal(hex(ua.kemRecordDigest({ ua: k.ua, version: k.version, kemPk: k.kemPk })), k.digest);
    assert.equal(hex(ua.uaMessage(k.kind, h('scaas.ua.purpose.kem.v1'), hand)), k.message);
    assert.equal(hex(ua.kemRecordMessage(k.kind, { ua: k.ua, version: k.version, kemPk: k.kemPk })), k.message);
    assert.equal(B(k.kemPk).length, 1601);
    assert.equal(B(k.kemPk)[0], ua.KEM_SCHEME.mlkem1024X25519, 'scheme byte');
  }
  for (const name of ['mldsa65', 'fndsa512', 'msig-pq']) {
    const ks = P.kemRecords.filter((k) => k.name === name);
    assert.deepEqual(ks.map((k) => k.version), [1, 2, 3], name);
    assert.equal(new Set(ks.map((k) => k.kemPk)).size, 3, `${name}: a key per version`);
    // the registration's initial record is version 1 of the same key
    for (const r of P.registrations.filter((x) => x.name === name || x.name.startsWith(`${name}/`))) {
      assert.deepEqual([r.attrs.kemVersion, r.attrs.kemPk, r.kemRecordHash], [1, ks[0].kemPk, ks[0].digest], r.name);
    }
  }
});

test('kem scheme byte: scheme 1 at 1,601 B only; the pre-scheme form, scheme 2 (reserved) and unknown bytes refused', () => {
  const code = (c) => (e) => e instanceof ua.UAError && e.code === c;
  const k = P.kemRecords[0];
  const pk = B(k.kemPk);
  const with0 = (s, p = pk) => Uint8Array.from([s, ...p.subarray(1)]);
  const d = (kemPk) => ua.kemRecordDigest({ ua: k.ua, version: 1, kemPk });
  assert.deepEqual([ua.KEM_SCHEME.mlkem1024X25519, ua.KEM_SCHEME.mlkem1024HqcX25519, ua.KEM_PK_LENGTH, P.kemScheme], [1, 2, 1601, 1]);
  assert.deepEqual([0, 1, 2, 3, 255].map(ua.kemPkLength), [0, 1601, 0, 0, 0]);
  assert.equal(hex(d(pk)), hex(ua.kemRecordDigest({ ua: k.ua, version: 1, kemPk: k.kemPk })));
  for (const s of [0, 2, 3, 0xff]) assert.throws(() => d(with0(s)), code('UAKemScheme'), `scheme ${s}`);
  assert.throws(() => d(Uint8Array.from([2, ...new Uint8Array(1600 + 32)])), code('UAKemScheme'), 'scheme 2 at any length');
  assert.throws(() => d(pk.subarray(1)), (e) => e.code === (pk[1] === 1 ? 'UAKemKeyLength' : 'UAKemScheme'), 'pre-scheme 1,600-byte key');
  for (const n of [0, 1, 1600, 1602]) assert.throws(() => d(Uint8Array.from({ length: n }, (_, i) => (i === 0 ? 1 : 7))), code('UAKemKeyLength'), `${n} B`);
  const mlz = row('mldsa65/n2048-kmax1024');
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), kemPk: with0(2) }), code('UAKemScheme'), 'the initial record too');
});

test('holder refusals', () => {
  const code = (c) => (e) => e instanceof ua.UAError && e.code === c;
  const kem = P.kemRecords[0];
  const mlz = row('mldsa65/n2048-kmax1024');
  const withKem = (r) => ({ ...args(r), kemVersion: 1, kemPk: kem.kemPk });
  const withPqz = (r) => ({ ...args(r), pqzKey: mlz.attrs.pqzKey, pqzPopHash: mlz.attrs.pqzPopHash });
  assert.throws(() => ua.holderPopMessage(0x0108, withKem(row('secp256k1'))), code('UAKemHolder'));
  assert.throws(() => ua.holderPopMessage(0x0133, withPqz(row('slhdsa128s'))), code('UAPqzHolder'));
  assert.throws(() => ua.holderPopMessage(0x0133, withKem(row('slhdsa128s'))), code('UAKemHolder'));
  assert.throws(() => ua.holderPopMessage(0x0120, withKem(row('msig-classical'))), code('UAKemHolder'));
  assert.throws(() => ua.holderPopMessage(0x0120, { ...withPqz(row('msig-pq/n2048-kmax1024')), keyData: undefined }), code('UAPqzHolder'));
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), pqzPopHash: undefined }), code('UAPqzPopHash'));
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), pqzKey: undefined }), code('UAPqzPopHash'));
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), pqzPop: mlz.pqzPop.slice(0, -2) }), code('UAPqzPopHash'));
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), kemPk: kem.kemPk.slice(0, -2) }), code('UAKemKeyLength'));
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), kemVersion: 0 }), code('UAKemVersion'));
  assert.throws(() => ua.kemRecordDigest({ ua: kem.ua, version: 2n ** 64n, kemPk: kem.kemPk }), code('UAKemVersion'));
  // the shared KATs (review part 2 I-C1): the mesh chain key and the top byte of the 8-byte KEM version word; the KEM key is
  // scheme 1 with a zero key (0x01 ‖ 1,600 zero bytes, CTR-UA-32)
  const KAT_KEM_PK = new Uint8Array(1601).fill(1, 0, 1);
  assert.equal(hex(ua.chainKeyHash(2n ** 40n + 7n)), '0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950'); // keccak256("evm:1099511627783")
  assert.equal(hex(ua.kemRecordDigest({ ua: new Uint8Array(32).fill(1), version: 2n ** 64n - 1n, kemPk: KAT_KEM_PK })),
    '0x8c997440926a352465f61b53b75606d794efa60c66ac4a7a63f25369a15f7092');
  // the proof-hash rule (review part 2 m-J1): a zero-length hash is absent, a hash of another length is UAPqzPopHash
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), pqzPopHash: new Uint8Array(0) }), code('UAPqzPopHash'), 'key without hash');
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), pqzPopHash: mlz.attrs.pqzPopHash.slice(0, -2) }), code('UAPqzPopHash'));
  assert.throws(() => ua.pqzKeyRecordMessage(0x0131, { ...args(mlz), pqzPopHash: '0x' }), code('UAPqzPopHash'));
  const none = ua.holderPopMessage(0x0131, { ...args(mlz), pqzKey: undefined, pqzPopHash: new Uint8Array(0) });
  assert.equal(hex(none.pqzPopHash), hex(new Uint8Array(32)), 'zero-length hash = absent');
  assert.throws(() => ua.purposeTag('metatx', 2), code('UAPurposeUnknown'));
  assert.equal(hex(ua.holderPopMessage(0x0131, withKem(row('mldsa65/n2048-kmax1024'))).kemRecordHash), kem.digest);
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), kemPk: undefined }), code('UAKemKeyLength'), 'kemPk omitted = empty');
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), pqzKey: new Uint8Array(32) }), code('UAKeyData'), 'no set has this key length');
  assert.deepEqual(ua.PQZ_KEY_LENGTHS, SETS.map((x) => P.sets[x].pqzKeyLength));
  // the PQZ key record (setPqzKey): the same holder rules, a key of a set's length, its proof hash
  const fr = rec('fndsa512/n2048-kmax1024');
  const recArgs = (r) => ({ ua: r.ua, pqzKey: r.pqzKey, pqzPopHash: r.pqzPopHash });
  assert.throws(() => ua.pqzKeyRecordMessage(0x0133, { ...recArgs(fr), ua: row('slhdsa128s').ua }), code('UAPqzHolder'));
  assert.throws(() => ua.pqzKeyRecordMessage(0x0108, { ...recArgs(fr), ua: row('secp256k1').ua }), code('UAPqzHolder'));
  assert.throws(() => ua.pqzKeyRecordMessage(0x0120, { ...recArgs(fr), ua: row('msig-classical').ua, keyData: row('msig-classical').keyData }),
    code('UAPqzHolder'));
  assert.throws(() => ua.pqzKeyRecordMessage(0x0132, { ...recArgs(fr), pqzPopHash: undefined }), code('UAPqzPopHash'));
  assert.throws(() => ua.pqzKeyRecordMessage(0x0132, { ...recArgs(fr), pqzKey: undefined }), code('UAKeyData'));
  assert.throws(() => ua.pqzKeyRecordMessage(0x0132, { ...recArgs(fr), pqzKey: fr.pqzKey.slice(0, -2) }), code('UAKeyData'));
  // every negative, by entry point (the note's table): register's attribute errors as holderPopMessage refusals, UAPoP as
  // a pop that does not verify on the row's (moved) digest, storePqzPop / setPqzKey / setKemKey / requireAuthorized below
  assert.deepEqual([...new Set(P.negatives.map((n) => n.error))].sort(), ['UAKemHolder', 'UAKemKeyLength', 'UAKemScheme', 'UAKemVersion', 'UAKeyData',
    'UAPoP', 'UAPqzHolder', 'UAPqzKeySet', 'UAPqzPopHash', 'UAUnauthorized']);
  assert.deepEqual([...new Set(P.negatives.map((n) => n.entry))].sort(), ['register', 'requireAuthorized', 'setKemKey', 'setPqzKey', 'storePqzPop']);
  for (const n of P.negatives) {
    const set = n.mutation.set;
    if (n.entry === 'storePqzPop') {
      const r = row(n.mutation.row);
      assert.equal(n.error, 'UAPqzPopHash', n.name);
      assert.deepEqual(n.mutation.registerWith, { pqzPop: '0x' }, `${n.name}: registered without the proof bytes first`);
      assert.notEqual(hex(keccak_256(B(set.pqzPop))), r.attrs.pqzPopHash, n.name);
      assert.equal(B(set.pqzPop).length, B(r.pqzPop).length, `${n.name}: same length, other bytes`);
    } else if (n.entry === 'register') {
      const r = row(n.mutation.row);
      const a = { ...args(r) };
      for (const [path, v] of Object.entries(set)) {
        assert.ok(path.startsWith('attrs.') || path === 'pqzPop' || path === 'pop', `${n.name}: ${path}`);
        if (path.startsWith('attrs.')) a[path.slice(6)] = v;
        if (path === 'pqzPop') a.pqzPop = v;
      }
      if (n.error !== 'UAPoP') {
        assert.throws(() => ua.holderPopMessage(r.kind, a), code(n.error), n.name);
        continue;
      }
      const m = ua.holderPopMessage(r.kind, a);
      const pop = set.pop ?? r.pop;
      if (!('pop' in set)) assert.notEqual(hex(m.registrationDigest), r.registrationDigest, n.name);
      assert.equal(r.kind === 0x0120 ? msigOk(r, hex(m.memberDigest), pop, keyOf) : sigOk(r.kind, r.keyData, hex(m.message), pop), false, n.name);
    } else if (n.entry === 'setKemKey') {
      const k = P.kemRecords.find((x) => x.id === n.mutation.row);
      const target = set.ua ?? k.ua;
      const t = regOf(target);
      const m = ua.kemRecordMessage(t.kind, { ua: target, version: set.version ?? k.version, kemPk: set.kemPk ?? k.kemPk });
      assert.equal(n.error, 'UAUnauthorized', n.name);
      assert.equal(sigOk(t.kind, t.keyData, hex(m), set.sig ?? k.sig), false, n.name);
    } else if (n.entry === 'setPqzKey') {
      const k = rec(n.mutation.row);
      const target = set.ua ?? k.ua;
      const t = regOf(target);
      const a = { ua: target, keyData: t.keyData, pqzKey: set.pqzKey ?? k.pqzKey, pqzPopHash: set.pqzPopHash ?? k.pqzPopHash };
      if (n.error === 'UAPqzHolder' || n.error === 'UAPqzPopHash') {
        assert.throws(() => ua.pqzKeyRecordMessage(t.kind, a), code(n.error), n.name);
        continue;
      }
      const m = ua.pqzKeyRecordMessage(t.kind, a);
      const ok = t.kind === 0x0120 ? msigOk(t, hex(m.memberDigest), set.sig ?? k.sig, keyOf) : sigOk(t.kind, t.keyData, hex(m.message), set.sig ?? k.sig);
      if (n.error === 'UAPqzKeySet') {
        // a valid record: the only fault is that the registration already carries a PQZ key (set once per chain)
        assert.ok(ok, n.name);
        assert.notEqual(t.attrs.pqzKey, '0x', n.name);
      } else {
        assert.equal(n.error, 'UAUnauthorized', n.name);
        assert.equal(ok, false, n.name);
      }
    } else {
      // requireAuthorized: a personal_sign member signature under a non-portable purpose (C7: UAAuth there)
      const r = row(n.mutation.row);
      assert.deepEqual([n.entry, n.error], ['requireAuthorized', 'UAUnauthorized'], n.name);
      assert.equal(ua.isPortablePurpose(set.purposeTag), false, n.name);
      const auth = B(set.auth);
      assert.equal(hex(bytesAt(auth, 0, 0)), r.keyData, n.name);
      const md = ua.memberDigest(B(r.ua), ua.uaMessage(0x0120, B(set.purposeTag), B(set.digest)));
      assert.ok(msigOk(r, hex(md), hex(bytesAt(auth, 0, 32)), keyOf), `${n.name}: valid only if personal_sign were allowed here`);
    }
  }
});

test('pqz key record: signed, portable, write-once, only for a registration without a PQZ key (setPqzKey)', () => {
  assert.deepEqual([...new Set(P.pqzKeyRecords.map((r) => r.name.split('/')[0]))], ['fndsa512', 'msig-pq-native']);
  for (const base of ['fndsa512', 'msig-pq-native']) {
    assert.deepEqual(P.pqzKeyRecords.filter((r) => r.name.startsWith(`${base}/`)).map((r) => r.set), SETS, base);
  }
  for (const r of P.pqzKeyRecords) {
    const reg = regOf(r.ua);
    assert.equal(reg.attrs.pqzKey, '0x', `${r.name}: registered without a PQZ key`);
    assert.equal(B(r.pqzKey).length, P.sets[r.set].pqzKeyLength, r.name);
    assert.equal(r.pqzKeyHash, hex(ua.keyHashOf(0x0142, B(r.pqzKey))), r.name);
    assert.equal(r.pqzPopHash, hex(keccak_256(B(row(`mldsa65/${r.set}`).pqzPop))), `${r.name}: the set's proof filler`);
    const kd = keccak_256(concatBytes(h('scaas.ua.pqz-key-record.v1'), B(r.ua), B(r.pqzKeyHash)));
    assert.equal(hex(kd), r.pqzKeyDigest, r.name);
    assert.equal(hex(keccak_256(concatBytes(kd, B(r.pqzPopHash)))), r.recordDigest, r.name);
    assert.equal(hex(ua.uaMessage(r.kind, h('scaas.ua.purpose.pqz-key.v1'), B(r.recordDigest))), r.message, r.name);
    assert.equal(hex(ua.uaMessage(0x0142, h('scaas.ua.purpose.pqz-key.v1'), kd)), r.pqzRegMessage, `${r.name}: R_REG, no proof hash`);
    const m = ua.pqzKeyRecordMessage(r.kind, { ua: r.ua, keyData: reg.keyData, pqzKey: r.pqzKey, pqzPopHash: r.pqzPopHash });
    assert.deepEqual([m.pqzKeyHash, m.pqzPopHash, m.pqzKeyDigest, m.recordDigest, m.message, m.pqzRegMessage].map(hex),
      [r.pqzKeyHash, r.pqzPopHash, r.pqzKeyDigest, r.recordDigest, r.message, r.pqzRegMessage], r.name);
    if (r.kind === 0x0120) {
      assert.equal(hex(m.memberDigest), r.memberDigest);
      assert.ok(msigOk(reg, r.memberDigest, r.sig, keyOf), r.name);
    } else {
      assert.ok(sigOk(r.kind, reg.keyData, r.message, r.sig), r.name);
    }
  }
  // one UA per proven PQZ key: every UA of the vectors has its own key at a set
  for (const set of SETS) {
    const keys = [...P.registrations.filter((r) => r.set === set).map((r) => r.attrs.pqzKey),
      ...P.pqzKeyRecords.filter((r) => r.set === set).map((r) => r.pqzKey)];
    assert.equal(new Set(keys).size, keys.length, set);
  }
  assert.match(P.note, /one PQZ key per UA/);
});

test('C7 scope: personal_sign only for the portable records of code-less native msig members', () => {
  for (const t of [ua.POP_V2_TAG, ua.KEM_TAG, ua.PQZ_KEY_TAG]) assert.ok(ua.isPortablePurpose(t));
  for (const p of ['pop', 'metatx', 'member', 'keyop', 'trade']) assert.equal(ua.isPortablePurpose(ua.purposeTag(p)), false, p);
  for (const phrase of [/personal_sign only for PURPOSE_POP_V2, PURPOSE_KEM and PURPOSE_PQZ_KEY/, /UAAuth .*CTR-MTX-14/,
    /ERC-1271/, /65-byte r \| s \| v, low-s, v in \{27, 28\}/]) assert.match(P.note, phrase);
  // the two negatives that pin it: a UAAuth-framed native signature inside a portable pop, personal_sign under metatx
  const names = P.negatives.map((n) => n.name);
  assert.ok(names.includes('native-uaauth-in-portable-pop') && names.includes('native-personal-sign-under-metatx'));
  const n = P.negatives.find((x) => x.name === 'native-uaauth-in-portable-pop');
  const r = row(n.mutation.row);
  const s = memberSigs(n.mutation.set.pop).find((x) => ua.isNativeKind(r.members[x.index].kind));
  assert.equal(nativeOk(`0x${r.members[s.index].id.slice(26)}`, ua.personalSignDigest(B(r.memberDigest)), hex(s.sig)), false);
});

test('every portable pop verifies', () => {
  const kinds = P.registrations.map((r) => r.kindName);
  for (const k of ['webauthn-p256', 'p256', 'ed25519', 'bip340', 'secp256k1', 'schnorr-bn254', 'schnorr-bls12381', 'bls12381-minsig',
    'bls-bn254-minsig', 'zether-bls12381', 'mldsa44', 'mldsa65', 'fndsa512', 'slhdsa128s', 'msig']) assert.ok(kinds.includes(k), k);
  let natives = 0;
  for (const r of P.registrations) {
    if (r.kind !== 0x0120) {
      assert.ok(sigOk(r.kind, r.keyData, r.popMessage, r.pop), r.name);
      assert.equal(sigOk(r.kind, r.keyData, hex(ua.uaMessage(r.kind, ua.POP_TAG, B(r.registrationDigest))), r.pop), false,
        `${r.name}: not under the v1 purpose`);
      continue;
    }
    const kd = B(r.keyData);
    assert.equal(hex(ua.encodeMsig(r.threshold, r.members.map((m) => ({ kind: m.kind, id: B(m.id), weight: m.weight })))), r.keyData);
    assert.equal(r.memberDigest, hex(ua.memberDigest(B(r.ua), B(r.popMessage))), r.name);
    if (!ua.msigPqzEligible(kd)) {
      assert.equal(r.pop, '0x', `${r.name}: a classical msig has no pop`);
      continue;
    }
    assert.ok(msigOk(r, r.memberDigest, r.pop, keyOf), r.name);
    assert.deepEqual(memberSigs(r.pop).map((s) => s.index), r.popSigners, r.name);
    const native = r.members.findIndex((m) => ua.isNativeKind(m.kind));
    if (native >= 0) {
      natives++;
      // chain-free: the native member's signature recovers its address over personal_sign(memberDigest), nothing else
      const s = memberSigs(r.pop).find((x) => x.index === native);
      const addr = `0x${r.members[native].id.slice(26)}`;
      assert.ok(nativeOk(addr, ua.personalSignDigest(B(r.memberDigest)), hex(s.sig)));
      assert.equal(nativeOk(addr, B(r.memberDigest), hex(s.sig)), false, 'not the raw digest');
    }
  }
  assert.equal(natives, 1, 'one msig with a native member (C7)');
  for (const k of P.kemRecords) {
    const r = P.registrations.find((x) => x.name === k.name || x.name.startsWith(`${k.name}/`));
    if (k.kind === 0x0120) {
      assert.equal(k.memberDigest, hex(ua.memberDigest(B(k.ua), B(k.message))));
      assert.ok(msigOk(r, k.memberDigest, k.sig, keyOf), `${k.name} v${k.version}`);
    } else {
      assert.ok(sigOk(k.kind, r.keyData, k.message, k.sig), `${k.name} v${k.version}`);
    }
  }
});
