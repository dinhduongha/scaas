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
const keyOf = (id) => P.registrations.find((x) => x.ua === id)?.keyData ?? assert.fail(`no registration for member ${id}`);

test('portable.json reproduced byte for byte', () => {
  assert.equal(portableJson(), TEXT);
});

test('portable PoP has no chain context', () => {
  assert.deepEqual(P.tags, {
    PURPOSE_POP_V2: { tag: 'scaas.ua.purpose.pop.v2', hash: hex(h('scaas.ua.purpose.pop.v2')) },
    PURPOSE_KEM: { tag: 'scaas.ua.purpose.kem.v1', hash: hex(h('scaas.ua.purpose.kem.v1')) },
    KEM_RECORD_TAG: { tag: 'scaas.ua.kem-record.v1', hash: hex(h('scaas.ua.kem-record.v1')) },
  });
  assert.deepEqual(P.checked, { none: 0, chain: 1, relayer: 2 });
  assert.deepEqual([hex(ua.POP_V2_TAG), hex(ua.KEM_TAG), hex(ua.KEM_RECORD_TAG)], Object.values(P.tags).map((t) => t.hash));
  assert.deepEqual(ua.CHECKED, P.checked);
  assert.equal(ua.KEM_PK_LENGTH, P.kemPkLength);
  // one row by hand: keccak256 of the four words
  const r = row('mldsa65/n2304-kmax4096');
  const hand = keccak_256(concatBytes(h('scaas.ua.purpose.pop.v2'), B(r.ua), B(r.pqzKeyHash), B(r.kemRecordHash)));
  assert.equal(hex(hand), r.portablePopDigest);
  assert.notEqual(r.pqzKeyHash, Z);
  assert.notEqual(r.kemRecordHash, Z);
  // the function takes no chain field: any extra one is ignored, the digest is the same
  const words = { ua: r.ua, pqzKeyHash: r.pqzKeyHash, kemRecordHash: r.kemRecordHash };
  for (const ctx of [{ chainId: 1 }, { chainId: 7622, chainUid: `0x${'24'.repeat(32)}`, registry: `0x${'aa'.repeat(20)}` }]) {
    assert.equal(hex(ua.portablePopDigest({ ...words, ...ctx })), r.portablePopDigest);
  }
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
    assert.equal(B(k.kemPk).length, 1600);
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
  assert.throws(() => ua.purposeTag('metatx', 2), code('UAPurposeUnknown'));
  assert.equal(hex(ua.holderPopMessage(0x0131, withKem(row('mldsa65/n2048-kmax1024'))).kemRecordHash), kem.digest);
  // every negative: register's attribute errors as holderPopMessage refusals, UAPoP as a moved digest the row's pop
  // does not verify on, storePqzPop as other bytes than the stored hash
  assert.deepEqual([...new Set(P.negatives.map((n) => n.error))].sort(),
    ['UAKemHolder', 'UAKemKeyLength', 'UAKemVersion', 'UAPoP', 'UAPqzHolder', 'UAPqzPopHash']);
  for (const n of P.negatives) {
    const r = row(n.mutation.row);
    if (n.entry === 'storePqzPop') {
      assert.equal(n.error, 'UAPqzPopHash', n.name);
      assert.notEqual(hex(keccak_256(B(n.mutation.set.pqzPop))), r.attrs.pqzPopHash, n.name);
      assert.equal(B(n.mutation.set.pqzPop).length, B(r.pqzPop).length, `${n.name}: same length, other bytes`);
      continue;
    }
    assert.equal(n.entry, 'register', n.name);
    const a = { ...args(r) };
    for (const [path, v] of Object.entries(n.mutation.set)) {
      assert.ok(path.startsWith('attrs.') || path === 'pqzPop', `${n.name}: ${path}`);
      if (path.startsWith('attrs.')) a[path.slice(6)] = v;
    }
    if (n.error === 'UAPoP') {
      const m = ua.holderPopMessage(r.kind, a);
      assert.notEqual(hex(m.registrationDigest), r.registrationDigest, n.name);
      assert.equal(sigOk(r.kind, r.keyData, hex(m.message), r.pop), false, n.name);
    } else {
      assert.throws(() => ua.holderPopMessage(r.kind, a), code(n.error), n.name);
    }
  }
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
