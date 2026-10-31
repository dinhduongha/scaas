// UA-8 (portable registrations, spec P1, P2, P7, P10, P11) on the typed records (typed-signing TS-D1 … TS-D4):
// smartcontracts/vectors/ua/portable.json against src/ua.js. The generator reproduces it byte for byte; every digest is
// rebuilt by hand from the pinned typehashes and the domain separator of EIP712Domain(string name,string version) =
// ("SCaaS UA Portable", "1") (no chain id, no chain uid, no registry anywhere) and equals hashTypedData of the row's
// typedData (src/evm.js, the eth_signTypedData_v4 rules); the holder rules refuse what the registry refuses; every pop and
// KEM record signature verifies under the kind's verifier (test/ua-verify.js for the classical kinds, noble for the PQ
// kinds, msig per member, a native member by ECDSA over the record's typed digest); every negative gives its error.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ua from '../src/ua.js';
import { hex, keccak_256, utf8ToBytes, concatBytes, word } from '../src/bytes.js';
import { hashStruct, hashTypedData } from '../src/evm.js';
import { personalSignDigest } from '../legacy/typed-signing/ua-portable-raw.js';
import { portableJson } from '../scripts/ua-portable-vectors.mjs';
import { B, nativeOk, bytesAt, sigOk, memberSigs, msigOk } from './ua-verify.js';

import { dir } from './ua-vectors-dir.js';
const TEXT = readFileSync(new URL('portable.json', dir), 'utf8');
const P = JSON.parse(TEXT);
const Z = `0x${'00'.repeat(32)}`;
const h = (s) => keccak_256(utf8ToBytes(s));
const row = (name) => P.registrations.find((r) => r.name === name) ?? assert.fail(`no row ${name}`);
const SETS = ['n2048-kmax1024', 'n2304-kmax4096', 'n2560-kmax16384', 'n2816-kmax65536'];
const args = (r) => ({ ua: r.ua, keyData: r.keyData, pqzKey: r.attrs.pqzKey, pqzPopHash: r.attrs.pqzPopHash,
  kemVersion: r.attrs.kemVersion, kemPk: r.attrs.kemPk });

// TS-D1, pinned here as literals (re-derived with cast 1.8.5 in the plan; every implementation pins the same values)
const DS_P = '0x9a2c390d4dc940ccdb5fa6b21e673e87159bdd99aeef22ea791bcea9efc64ca1';
const KEM_T = 'UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)';
const REC_T = 'UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)';
const PK_T = 'UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)';
const TYPES = {
  UAKemRecord: [KEM_T, '0x0ab7989827627b89c268e88a0a0b06b62aefa70b0a466014931ca44acfa9a201'],
  UAPortableRecord: [REC_T + KEM_T, '0x0c1553cfab3c35326558484df79963dced75ead85272d2a85985f264757bfe7f'],
  UARegistration: ['UARegistration(UAPortableRecord record,bytes32 pqzPopHash)' + KEM_T + REC_T,
    '0xc78b548ceb2fadf1f0a895f79f88b517327c120f0f9ab345f02981441048c87e'],
  UAPqzKey: [PK_T, '0x827d90728b100bc830d06b04dd2b9b5f7853adaa05502b4082875f881d925a00'],
  UAPqzKeyRecord: ['UAPqzKeyRecord(UAPqzKey key,bytes32 pqzPopHash)' + PK_T, '0xaba20a80603724f71232573a76d2506ae38f60f39ea9cd8e71f4b64775dd7567'],
};
const TH = Object.fromEntries(Object.entries(TYPES).map(([k, [, t]]) => [k, B(t)]));
const typedHand = (structHash) => keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), B(DS_P), structHash));
const kemHand = (u, version, scheme, kemPkHash) => keccak_256(concatBytes(TH.UAKemRecord, B(u), word(version), word(scheme), B(kemPkHash)));
const recHand = (u, kind, pqzKeyHash, kemHash) => keccak_256(concatBytes(TH.UAPortableRecord, B(u), word(kind), B(pqzKeyHash), B(kemHash)));
const regHand = (recHash, pqzPopHash) => keccak_256(concatBytes(TH.UARegistration, recHash, B(pqzPopHash)));
const pkHand = (u, pqzKeyHash) => keccak_256(concatBytes(TH.UAPqzKey, B(u), B(pqzKeyHash)));
const pkrHand = (keyHash, pqzPopHash) => keccak_256(concatBytes(TH.UAPqzKeyRecord, keyHash, B(pqzPopHash)));
// the shared KEM KAT (review part 2 I-C1): ua = 0x01 × 32, version 2^64 − 1, kemPk = 0x01 ‖ 1,600 zero bytes, now typed
const KAT_KEM_DIGEST = '0xa0063a84b56d80c83688d8caf5aeb4be8fb4556928e8bc649686449573938f07';
const zeroKem = (u) => ({ ua: u, version: 0, scheme: 0, kemPkHash: Z });

const rec = (name) => P.pqzKeyRecords.find((r) => r.name === name) ?? assert.fail(`no PQZ key record ${name}`);
const regOf = (id) => P.registrations.find((x) => x.ua === id) ?? assert.fail(`no registration of ${id}`);
const keyOf = (id) => P.registrations.find((x) => x.ua === id)?.keyData ?? assert.fail(`no registration for member ${id}`);

test('portable.json reproduced byte for byte', () => {
  assert.equal(portableJson(), TEXT);
});

test('portable domain separator is 0x9a2c…4ca1 (name + version only)', () => {
  assert.deepEqual(ua.PORTABLE_DOMAIN, { name: 'SCaaS UA Portable', version: '1' });
  assert.deepEqual(ua.PORTABLE_TYPES.EIP712Domain, [{ name: 'name', type: 'string' }, { name: 'version', type: 'string' }]);
  assert.equal(hex(ua.portableDomainSeparator()), DS_P);
  assert.equal(hex(keccak_256(concatBytes(h('EIP712Domain(string name,string version)'), h('SCaaS UA Portable'), h('1')))), DS_P);
  assert.equal(hex(hashStruct(ua.PORTABLE_TYPES, 'EIP712Domain', ua.PORTABLE_DOMAIN)), DS_P);
  assert.deepEqual(P.typed.domain, ua.PORTABLE_DOMAIN);
  assert.equal(P.typed.domainSeparator, DS_P);
  assert.equal(P.typed.domainType, 'EIP712Domain(string name,string version)');
});

test('portable typehashes pinned', () => {
  assert.deepEqual(Object.keys(ua.PORTABLE_TYPES).filter((t) => t !== 'EIP712Domain'), Object.keys(TYPES));
  for (const [t, [type, typehash]] of Object.entries(TYPES)) {
    assert.equal(hex(h(type)), typehash, t);
    assert.equal(hex(ua.PORTABLE_TYPEHASH[t]), typehash, t);
    assert.deepEqual(P.typed.types[t], { type, typehash }, t);
  }
});

test('typed digest equals hashTypedData(portableTypedData(…)) for every row', () => {
  const td = (primary, message, row, what) => {
    const t = ua.portableTypedData(primary, message);
    assert.deepEqual(Object.keys(t), ['domain', 'types', 'primaryType', 'message'], what);
    assert.deepEqual(t.domain, { name: 'SCaaS UA Portable', version: '1' }, what);
    assert.equal(t.primaryType, primary, what);
    if (row) assert.deepEqual(row, t, what);
    return hex(hashTypedData(t));
  };
  for (const r of P.registrations) {
    assert.equal(td('UARegistration', r.typedData.message, r.typedData, r.name), r.registrationDigest, r.name);
    assert.equal(td('UAPortableRecord', r.typedData.message.record), r.portableRecordDigest, r.name);
    assert.deepEqual(Object.keys(r.typedData.types), ['EIP712Domain', 'UARegistration', 'UAPortableRecord', 'UAKemRecord'], r.name);
    const m = ua.holderPopMessage(r.kind, args(r));
    assert.deepEqual(m.typedData, r.typedData, r.name);
    assert.equal(r.typedData.message.pqzPopHash, r.attrs.pqzPopHash, r.name);
    assert.deepEqual(r.typedData.message.record, ua.portableRecordStruct({ ua: r.ua, kind: r.kind, pqzKeyHash: r.pqzKeyHash,
      kem: ua.kemRecordStruct({ ua: r.ua, version: r.attrs.kemVersion, kemPk: r.attrs.kemPk }) }), r.name);
  }
  for (const k of P.kemRecords) {
    assert.equal(td('UAKemRecord', k.typedData.message, k.typedData, k.id), k.digest, k.id);
    assert.deepEqual(k.typedData.message, ua.kemRecordStruct({ ua: k.ua, version: k.version, kemPk: k.kemPk }), k.id);
    assert.equal(hex(hashStruct(ua.PORTABLE_TYPES, 'UAKemRecord', k.typedData.message)), k.structHash, k.id);
  }
  for (const r of P.pqzKeyRecords) {
    assert.equal(td('UAPqzKeyRecord', r.typedData.message, r.typedData, r.name), r.recordDigest, r.name);
    assert.equal(td('UAPqzKey', r.typedData.message.key), r.pqzKeyDigest, r.name);
    assert.deepEqual(r.typedData.message, { key: { ua: r.ua, pqzKeyHash: r.pqzKeyHash }, pqzPopHash: r.pqzPopHash }, r.name);
  }
});

test('no-KEM record is {ua,0,0,0}', () => {
  let n = 0;
  for (const r of P.registrations.filter((x) => x.attrs.kemPk === '0x')) {
    assert.deepEqual(r.typedData.message.record.kem, zeroKem(r.ua), r.name);
    assert.equal(r.kemRecordHash, hex(kemHand(r.ua, 0, 0, Z)), r.name);
    assert.equal(hex(ua.kemRecordHash({ ua: r.ua })), r.kemRecordHash, r.name);
    n++;
  }
  assert.ok(n > 10);
  // version 0 is never a valid record (UAKemVersion), so the zero record is unambiguous; it is no setKemKey record
  const u = row('fndsa512').ua;
  assert.throws(() => ua.kemRecordDigest({ ua: u, version: 0, kemPk: '0x' }), (e) => e.code === 'UAKemVersion');
  assert.throws(() => ua.kemRecordHash({ ua: u, version: 0, kemPk: row('fndsa512').attrs.kemPk }), (e) => e.code === 'UAKemVersion');
});

test('kind field equals the row\'s kind', () => {
  for (const r of P.registrations) {
    assert.equal(r.typedData.message.record.kind, r.kind, r.name);
    assert.equal(r.typedData.message.record.ua, r.ua, r.name);
  }
  // the kind is bound: the same UA and attributes under another kind is another record
  const r = row('p256');
  assert.notEqual(hex(ua.registrationDigest({ ua: r.ua, kind: 0x0100 })), r.registrationDigest);
  assert.equal(hex(ua.registrationDigest({ ua: r.ua, kind: r.kind })), r.registrationDigest);
});

test('zether PoP message (0x0141, no PQZ, no KEM)', () => {
  const r = row('zether-bls12381');
  assert.equal(r.kind, 0x0141);
  assert.deepEqual(r.typedData.message, { record: { ua: r.ua, kind: 0x0141, pqzKeyHash: Z, kem: zeroKem(r.ua) }, pqzPopHash: Z });
  const d = typedHand(regHand(recHand(r.ua, 0x0141, Z, hex(kemHand(r.ua, 0, 0, Z))), Z));
  assert.equal(hex(d), r.registrationDigest);
  assert.equal(hex(ua.uaMessage(0x0141, ua.POP_V2_TAG, d)), r.popMessage);
  assert.equal(hex(ua.holderPopMessage(0x0141, { ua: r.ua }).message), r.popMessage);
  assert.ok(sigOk(0x0141, r.keyData, r.popMessage, r.pop));
});

test('portable PoP has no chain context', () => {
  assert.deepEqual(P.tags, {
    PURPOSE_POP_V2: { tag: 'scaas.ua.purpose.pop.v2', hash: hex(h('scaas.ua.purpose.pop.v2')) },
    PURPOSE_KEM: { tag: 'scaas.ua.purpose.kem.v1', hash: hex(h('scaas.ua.purpose.kem.v1')) },
    PURPOSE_PQZ_KEY: { tag: 'scaas.ua.purpose.pqz-key.v1', hash: hex(h('scaas.ua.purpose.pqz-key.v1')) },
    PQZ_KEY_GROUP: { tag: 'scaas.ua.group.pqz-mlwe.v1', hash: hex(h('scaas.ua.group.pqz-mlwe.v1')) },
  });
  assert.deepEqual(P.checked, { none: 0, chain: 1, relayer: 2 });
  assert.equal('KEM_RECORD_TAG' in ua || 'PQZ_KEY_RECORD_TAG' in ua, false, 'the raw record tags are legacy (TS-D3)');
  assert.deepEqual([ua.POP_V2_TAG, ua.KEM_TAG, ua.PQZ_KEY_TAG, ua.GROUP('pqz-mlwe')].map(hex),
    Object.values(P.tags).map((t) => t.hash));
  // pqzKeyHash = keyHash(0x0142, pqzKey) = keccak256(PQZ_KEY_GROUP ‖ pqzKey), not a plain keccak of the key
  const k = row('mldsa65/n2048-kmax1024');
  assert.equal(k.pqzKeyHash, hex(keccak_256(concatBytes(h('scaas.ua.group.pqz-mlwe.v1'), B(k.attrs.pqzKey)))));
  assert.match(P.note, /pqzKeyHash = keccak256\(PQZ_KEY_GROUP \| pqzKey\)/);
  assert.deepEqual(ua.CHECKED, P.checked);
  assert.equal(ua.KEM_PK_LENGTH, P.kemPkLength);
  // every row by hand: the typed UAPortableRecord over its words, the nested UAKemRecord by its struct hash
  const r = row('mldsa65/n2304-kmax4096');
  assert.notEqual(r.pqzKeyHash, Z);
  assert.notEqual(r.kemRecordHash, Z);
  for (const x of P.registrations) {
    assert.equal(hex(typedHand(recHand(x.ua, x.kind, x.pqzKeyHash, x.kemRecordHash))), x.portableRecordDigest, x.name);
    assert.equal(hex(ua.portableRecordDigest({ ua: x.ua, kind: x.kind, pqzKeyHash: x.pqzKeyHash, kemRecordHash: x.kemRecordHash })),
      x.portableRecordDigest, x.name);
    assert.equal(x.pqzKeyHash, x.attrs.pqzKey === '0x' ? Z : hex(ua.keyHashOf(0x0142, B(x.attrs.pqzKey))), x.name);
    assert.equal(hex(ua.deriveUA(x.kind, B(x.keyData))), x.ua, x.name);
    assert.equal(x.kindName, ua.kindInfo(x.kind).name, x.name);
  }
  assert.doesNotMatch(TEXT, /chainId|chainUid|registry"/);
});

test('registration digest covers the proof hash', () => {
  for (const r of P.registrations) {
    const hand = typedHand(regHand(recHand(r.ua, r.kind, r.pqzKeyHash, r.kemRecordHash), r.attrs.pqzPopHash));
    assert.equal(hex(hand), r.registrationDigest, r.name);
    assert.equal(hex(ua.uaMessage(r.kind, ua.POP_V2_TAG, hand)), r.popMessage, r.name);
    const m = ua.holderPopMessage(r.kind, args(r));
    assert.deepEqual([m.pqzKeyHash, m.pqzPopHash, m.kemRecordHash, m.portableRecordDigest, m.registrationDigest, m.message].map(hex),
      [r.pqzKeyHash, r.attrs.pqzPopHash, r.kemRecordHash, r.portableRecordDigest, r.registrationDigest, r.popMessage], r.name);
    if (r.attrs.pqzKey === '0x') {
      assert.deepEqual([r.attrs.pqzPopHash, r.pqzPop, r.pqzRegMessage, r.set], [Z, '0x', Z, ''], r.name);
      continue;
    }
    // the proof's hash is in attrs, covered by pop; the proof's own message (R_REG) does not contain it
    assert.equal(r.attrs.pqzPopHash, hex(keccak_256(B(r.pqzPop))), r.name);
    assert.equal(hex(ua.holderPopMessage(r.kind, { ...args(r), pqzPopHash: undefined, pqzPop: r.pqzPop }).registrationDigest), r.registrationDigest);
    const w = { ua: r.ua, kind: r.kind, pqzKeyHash: r.pqzKeyHash, kemRecordHash: r.kemRecordHash };
    assert.equal(hex(ua.registrationDigest({ ...w, pqzPopHash: r.attrs.pqzPopHash })), r.registrationDigest, r.name);
    assert.notEqual(hex(ua.registrationDigest({ ...w, pqzPopHash: keccak_256(B(r.pqzPop).subarray(1)) })), r.registrationDigest);
    assert.equal(r.pqzRegMessage, hex(ua.uaMessage(0x0142, ua.POP_V2_TAG, B(r.portableRecordDigest))), r.name);
    assert.equal(hex(ua.pqzRegMessage({ ...args(r), kind: r.kind })), r.pqzRegMessage, r.name);
    assert.throws(() => ua.pqzRegMessage(args(r)), /kind/, 'the R_REG record names the registering kind');
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
    const sh = kemHand(k.ua, k.version, B(k.kemPk)[0], hex(keccak_256(B(k.kemPk))));
    assert.equal(hex(sh), k.structHash, `${k.name} v${k.version}`);
    assert.equal(hex(ua.kemRecordHash({ ua: k.ua, version: k.version, kemPk: k.kemPk })), k.structHash);
    const hand = typedHand(sh);
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
      assert.deepEqual([r.attrs.kemVersion, r.attrs.kemPk, r.kemRecordHash], [1, ks[0].kemPk, ks[0].structHash], r.name);
      assert.deepEqual(r.typedData.message.record.kem, ks[0].typedData.message, r.name);
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
  // typed-signing: the KAT is the typed UAKemRecord digest (pre-round raw value 0x8c99…7092, legacy/typed-signing)
  const katUa = new Uint8Array(32).fill(1);
  assert.equal(hex(ua.kemRecordDigest({ ua: katUa, version: 2n ** 64n - 1n, kemPk: KAT_KEM_PK })),
    hex(typedHand(kemHand(hex(katUa), 2n ** 64n - 1n, 1, hex(keccak_256(KAT_KEM_PK))))));
  assert.equal(hex(ua.kemRecordDigest({ ua: katUa, version: 2n ** 64n - 1n, kemPk: KAT_KEM_PK })), KAT_KEM_DIGEST);
  // the proof-hash rule (review part 2 m-J1): a zero-length hash is absent, a hash of another length is UAPqzPopHash
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), pqzPopHash: new Uint8Array(0) }), code('UAPqzPopHash'), 'key without hash');
  assert.throws(() => ua.holderPopMessage(0x0131, { ...args(mlz), pqzPopHash: mlz.attrs.pqzPopHash.slice(0, -2) }), code('UAPqzPopHash'));
  assert.throws(() => ua.pqzKeyRecordMessage(0x0131, { ...args(mlz), pqzPopHash: '0x' }), code('UAPqzPopHash'));
  const none = ua.holderPopMessage(0x0131, { ...args(mlz), pqzKey: undefined, pqzPopHash: new Uint8Array(0) });
  assert.equal(hex(none.pqzPopHash), hex(new Uint8Array(32)), 'zero-length hash = absent');
  assert.throws(() => ua.purposeTag('metatx', 2), code('UAPurposeUnknown'));
  assert.equal(hex(ua.holderPopMessage(0x0131, withKem(row('mldsa65/n2048-kmax1024'))).kemRecordHash), kem.structHash);
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
      assert.equal(r.kind === 0x0120 ? msigOk(r, hex(m.memberDigest), pop, keyOf, m.registrationDigest)
        : sigOk(r.kind, r.keyData, hex(m.message), pop), false, n.name);
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
      const ok = t.kind === 0x0120 ? msigOk(t, hex(m.memberDigest), set.sig ?? k.sig, keyOf, m.recordDigest)
        : sigOk(t.kind, t.keyData, hex(m.message), set.sig ?? k.sig);
      if (n.error === 'UAPqzKeySet') {
        // a valid record: the only fault is that the registration already carries a PQZ key (set once per chain)
        assert.ok(ok, n.name);
        assert.notEqual(t.attrs.pqzKey, '0x', n.name);
      } else {
        assert.equal(n.error, 'UAUnauthorized', n.name);
        assert.equal(ok, false, n.name);
      }
    } else {
      // requireAuthorized: a personal_sign member signature under a non-portable purpose (UAAuth there, CTR-MTX-14)
      const r = row(n.mutation.row);
      assert.deepEqual([n.entry, n.error], ['requireAuthorized', 'UAUnauthorized'], n.name);
      assert.equal(ua.isPortablePurpose(set.purposeTag), false, n.name);
      const auth = B(set.auth);
      assert.equal(hex(bytesAt(auth, 0, 0)), r.keyData, n.name);
      const md = ua.memberDigest(B(r.ua), ua.uaMessage(0x0120, B(set.purposeTag), B(set.digest)));
      assert.ok(msigOk(r, hex(md), hex(bytesAt(auth, 0, 32)), keyOf, personalSignDigest(md)),
        `${n.name}: valid only if personal_sign were allowed here`);
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
    const ks = pkHand(r.ua, r.pqzKeyHash);
    const kd = typedHand(ks);
    assert.equal(hex(kd), r.pqzKeyDigest, r.name);
    assert.equal(hex(typedHand(pkrHand(ks, r.pqzPopHash))), r.recordDigest, r.name);
    assert.equal(hex(ua.pqzKeyDigest({ ua: r.ua, pqzKeyHash: r.pqzKeyHash })), r.pqzKeyDigest, r.name);
    assert.equal(hex(ua.pqzKeyRecordDigest({ ua: r.ua, pqzKeyHash: r.pqzKeyHash, pqzPopHash: r.pqzPopHash })), r.recordDigest, r.name);
    assert.equal(hex(ua.uaMessage(r.kind, h('scaas.ua.purpose.pqz-key.v1'), B(r.recordDigest))), r.message, r.name);
    assert.equal(hex(ua.uaMessage(0x0142, h('scaas.ua.purpose.pqz-key.v1'), kd)), r.pqzRegMessage, `${r.name}: R_REG, no proof hash`);
    const m = ua.pqzKeyRecordMessage(r.kind, { ua: r.ua, keyData: reg.keyData, pqzKey: r.pqzKey, pqzPopHash: r.pqzPopHash });
    assert.deepEqual([m.pqzKeyHash, m.pqzPopHash, m.pqzKeyDigest, m.recordDigest, m.message, m.pqzRegMessage].map(hex),
      [r.pqzKeyHash, r.pqzPopHash, r.pqzKeyDigest, r.recordDigest, r.message, r.pqzRegMessage], r.name);
    if (r.kind === 0x0120) {
      assert.equal(hex(m.memberDigest), r.memberDigest);
      assert.ok(msigOk(reg, r.memberDigest, r.sig, keyOf, B(r.recordDigest)), r.name);
    } else {
      assert.ok(sigOk(r.kind, reg.keyData, r.message, r.sig), r.name);
    }
    assert.deepEqual(m.typedData, r.typedData, r.name);
  }
  // one UA per proven PQZ key: every UA of the vectors has its own key at a set
  for (const set of SETS) {
    const keys = [...P.registrations.filter((r) => r.set === set).map((r) => r.attrs.pqzKey),
      ...P.pqzKeyRecords.filter((r) => r.set === set).map((r) => r.pqzKey)];
    assert.equal(new Set(keys).size, keys.length, set);
  }
  assert.match(P.note, /one PQZ key per UA/);
});

test('TS-D4 scope: a code-less native msig member signs the typed digest of the portable records only', () => {
  for (const t of [ua.POP_V2_TAG, ua.KEM_TAG, ua.PQZ_KEY_TAG]) assert.ok(ua.isPortablePurpose(t));
  for (const p of ['pop', 'metatx', 'member', 'keyop', 'trade']) assert.equal(ua.isPortablePurpose(ua.purposeTag(p)), false, p);
  assert.equal('personalSignDigest' in ua, false, 'personal_sign is legacy (TS-D4)');
  for (const phrase of [/eth_signTypedData_v4/, /UAAuth .*CTR-MTX-14/, /ERC-1271 isValidSignature\(typedDigest/,
    /65-byte r \| s \| v, low-s, v in \{27, 28\}/]) assert.match(P.note, phrase);
  assert.doesNotMatch(P.note, /personal_sign only for/);
  // the negatives that pin it: the old personal_sign form, a UAAuth-framed native signature inside a portable pop,
  // personal_sign under metatx, a pop over another kind's record, a KEM record's typed digest signed as a pop
  const names = P.negatives.map((n) => n.name);
  for (const x of ['native-member-personal-sign', 'native-uaauth-in-portable-pop', 'native-personal-sign-under-metatx',
    'record-kind-mismatch', 'kem-record-as-registration']) assert.ok(names.includes(x), x);
  for (const x of ['native-member-personal-sign', 'native-uaauth-in-portable-pop', 'record-kind-mismatch', 'kem-record-as-registration']) {
    const n = P.negatives.find((y) => y.name === x);
    assert.deepEqual([n.entry, n.error, Object.keys(n.mutation.set)], ['register', 'UAPoP', ['pop']], x);
  }
  const n = P.negatives.find((x) => x.name === 'native-uaauth-in-portable-pop');
  const r = row(n.mutation.row);
  const s = memberSigs(n.mutation.set.pop).find((x) => ua.isNativeKind(r.members[x.index].kind));
  assert.equal(nativeOk(`0x${r.members[s.index].id.slice(26)}`, B(r.registrationDigest), hex(s.sig)), false);
  // record-kind-mismatch: a valid signature by the row's key, over the same UA and attributes under another kind
  const km = P.negatives.find((x) => x.name === 'record-kind-mismatch');
  const kr = row(km.mutation.row);
  const other = ua.uaMessage(kr.kind, ua.POP_V2_TAG, ua.registrationDigest({ ua: kr.ua, kind: km.mutation.otherKind }));
  assert.notEqual(km.mutation.otherKind, kr.kind);
  assert.ok(sigOk(kr.kind, kr.keyData, hex(other), km.mutation.set.pop), 'signed over the other kind');
  // kem-record-as-registration: a valid signature over the row's own initial KEM record's typed digest under pop v2
  const kn = P.negatives.find((x) => x.name === 'kem-record-as-registration');
  const knr = row(kn.mutation.row);
  const kv1 = P.kemRecords.find((k) => k.id === `${knr.name}/v1`);
  assert.ok(sigOk(knr.kind, knr.keyData, hex(ua.uaMessage(knr.kind, ua.POP_V2_TAG, B(kv1.digest))), kn.mutation.set.pop));
});

test('native EOA member signs the typed digest (ECDSA recovers the member)', () => {
  const regs = P.registrations.filter((r) => r.kind === 0x0120 && r.members.some((m) => ua.isNativeKind(m.kind)) && r.pop !== '0x');
  const recs = P.pqzKeyRecords.filter((r) => r.kind === 0x0120 && regOf(r.ua).members.some((m) => ua.isNativeKind(m.kind)));
  assert.equal(regs.length, 1);
  assert.equal(recs.length, SETS.length);
  for (const [r, digest, blob] of [...regs.map((x) => [x, x.registrationDigest, x.pop]),
    ...recs.map((x) => [regOf(x.ua), x.recordDigest, x.sig])]) {
    const i = r.members.findIndex((m) => ua.isNativeKind(m.kind));
    const s = memberSigs(blob).find((x) => x.index === i);
    const addr = `0x${r.members[i].id.slice(26)}`;
    assert.equal(s.keyData.length, 0);
    assert.ok(nativeOk(addr, B(digest), hex(s.sig)), `${r.name}: recovers the member over the typed digest`);
  }
});

test('personal_sign of md is refused by the reference verifier', () => {
  const n = P.negatives.find((x) => x.name === 'native-member-personal-sign');
  const r = row(n.mutation.row);
  const i = r.members.findIndex((m) => ua.isNativeKind(m.kind));
  const s = memberSigs(n.mutation.set.pop).find((x) => x.index === i);
  const addr = `0x${r.members[i].id.slice(26)}`;
  // the old form: EIP-191 personal_sign of the member digest, a valid ECDSA signature by the member
  assert.ok(nativeOk(addr, personalSignDigest(B(r.memberDigest)), hex(s.sig)));
  assert.equal(msigOk(r, r.memberDigest, n.mutation.set.pop, keyOf, B(r.registrationDigest)), false);
  assert.ok(msigOk(r, r.memberDigest, r.pop, keyOf, B(r.registrationDigest)));
  assert.equal(msigOk(r, r.memberDigest, r.pop, keyOf, personalSignDigest(B(r.memberDigest))), false);
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
    assert.ok(msigOk(r, r.memberDigest, r.pop, keyOf, B(r.registrationDigest)), r.name);
    assert.deepEqual(memberSigs(r.pop).map((s) => s.index), r.popSigners, r.name);
    const native = r.members.findIndex((m) => ua.isNativeKind(m.kind));
    if (native >= 0) {
      natives++;
      // chain-free: the native member's signature recovers its address over the typed registration digest, nothing else
      const s = memberSigs(r.pop).find((x) => x.index === native);
      const addr = `0x${r.members[native].id.slice(26)}`;
      assert.ok(nativeOk(addr, B(r.registrationDigest), hex(s.sig)));
      assert.equal(nativeOk(addr, B(r.memberDigest), hex(s.sig)), false, 'not the member digest');
      assert.equal(nativeOk(addr, personalSignDigest(B(r.memberDigest)), hex(s.sig)), false, 'not personal_sign');
    }
  }
  assert.equal(natives, 1, 'one msig with a native member (TS-D4)');
  for (const k of P.kemRecords) {
    const r = P.registrations.find((x) => x.name === k.name || x.name.startsWith(`${k.name}/`));
    if (k.kind === 0x0120) {
      assert.equal(k.memberDigest, hex(ua.memberDigest(B(k.ua), B(k.message))));
      assert.ok(msigOk(r, k.memberDigest, k.sig, keyOf, B(k.digest)), `${k.name} v${k.version}`);
    } else {
      assert.ok(sigOk(k.kind, r.keyData, k.message, k.sig), `${k.name} v${k.version}`);
    }
  }
});
