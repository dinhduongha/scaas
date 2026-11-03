// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Nested `msig` (spec 2026-11-02-msig-nested, CTR-UA-09): every row of smartcontracts/vectors/ua/nested.json through the verifier of
// src/ua-verify.js, the same rows forge runs on the registry (test/ua/UARegistryNestedVectors.t.sol). UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as ua from '../src/ua.js';
import * as sor from '../src/soroban.js';
import { hex, abiEncode, concatBytes, word, keccak_256 } from '../src/bytes.js';
import { nestedJson } from '../scripts/ua-portable-vectors.mjs';
import { B, kindVerify, nativeOk, encodeMemberSigs, decodeMemberSigs, encodeInnerSigs, replayedMemberSig, verifyRegistration, verifyKemRecord, verifyPqzKeyRecord,
  verifyMembership, verifyAuthorization } from '../src/ua-verify.js';
import { dir } from './ua-vectors-dir.js';

const TEXT = readFileSync(new URL('nested.json', dir), 'utf8');
const N = JSON.parse(TEXT);
const row = (name) => N.registrations.find((r) => r.name === name) ?? assert.fail(`no row ${name}`);
const records = (id) => [...N.registrations, ...N.afterAcceptance].find((r) => r.ua === id);
const code = (c) => (e) => e.code === c;
const flip = (h, at = 40) => { const b = B(h); b[at] ^= 1; return hex(b); };
const msigs = N.registrations.filter((r) => r.kind === 0x0120);
const nested = msigs.filter((r) => r.innerDigests?.length);
// the accepted bits (CTR-UA-37): what each msig row's pop accepted as it registered, then also what the memberships rows accept
const popBits = N.registrations.flatMap((r) => (r.popSigners ?? []).map((index) => `${r.ua}/${index}`));
const atRegistration = (id, index) => popBits.includes(`${id}/${index}`);
const afterMemberships = (id, index) => atRegistration(id, index) || N.memberships.some((m) => m.ua === id && m.index === index);
const typedSlots = (l) => l.map((s) => ({ index: s.index, members: s.members.map((m) => ({ index: m.index, sig: B(m.sig) })), sig: B(s.sig) }));

test('nested.json is what the generator writes', () => assert.equal(nestedJson(), TEXT));

test('eligibility: an msig member by its own rule, read from its record', () => {
  assert.equal(N.eligibility.length, 3);
  for (const r of N.eligibility) {
    assert.equal(ua.msigPqzEligible(r.keyData, (id) => r.inner[id]), r.eligible, r.reason);
    assert.throws(() => ua.msigPqzEligible(r.keyData), code('UAMemberUnknown'), 'the key data alone does not show it');
  }
  const third = row('msig-nested-pq');
  assert.throws(() => ua.msigPqzEligible(ua.encodeMsig(1, [{ kind: 0x0120, id: third.ua, weight: 1 }]), () => third.keyData), code('UAMemberUnknown'), 'a third level');
});

test('registrations: every row verifies, typed list and stored bytes agree, md_I rebuilds', () => {
  assert.equal(nested.length, 6);
  for (const r of N.registrations) verifyRegistration({ ...r, attrs: r.attrs }, records, atRegistration);
  for (const r of msigs.filter((x) => x.pop !== '0x')) {
    assert.equal(hex(encodeMemberSigs(typedSlots(r.args.pop))), r.pop, r.name);
    assert.deepEqual(typedSlots(r.args.pop).map((s) => s.index), decodeMemberSigs(r.pop).map((s) => s.index), r.name);
  }
  // owner 2026-11-03: memberSigHashOf per slot, the hash of the bytes its UAMemberSig carries
  for (const r of msigs) {
    const slots = r.pop === '0x' ? [] : decodeMemberSigs(r.pop);
    assert.deepEqual(slots.map((s) => ({ index: s.index, hash: hex(keccak_256(s.members.length ? encodeInnerSigs(s.members) : s.sig)) })), r.memberSigHashes, r.name);
  }
  for (const r of nested) {
    for (const d of r.innerDigests) {
      assert.equal(hex(ua.innerDigest(B(d.inner), B(r.memberDigest))), d.memberDigest, r.name);
      assert.equal(hex(ua.memberDigest(B(d.inner), ua.uaMessage(0x0120, ua.purposeTag('member'), B(r.memberDigest)))), d.memberDigest, 'as the spec writes it');
    }
  }
});

test('N5: one native signature serves both slots of msig-nested-twice, that record only', () => {
  const r = row('msig-nested-twice');
  const [a, b] = decodeMemberSigs(r.pop);
  const ix = (s) => ua.msigStructure(records(r.members[s.index].id).keyData).members.findIndex((m) => m.kind === 0x0001);
  const sa = a.members.find((m) => m.index === ix(a)).sig;
  assert.deepEqual(sa, b.members.find((m) => m.index === ix(b)).sig);
  assert.ok(nativeOk(`0x${records(r.members[0].id).members.find((m) => m.kind === 1).id.slice(26)}`, B(r.registrationDigest), hex(sa)));
});

test('negatives: each row refused with the error of the registry, the same record with its own pop passes', () => {
  assert.equal(N.negatives.length, 13);
  for (const n of N.negatives) {
    const r = [...N.registrations, ...N.afterAcceptance].find((x) => x.name === n.row);
    assert.equal(hex(encodeMemberSigs(typedSlots(n.popTyped))), n.pop, n.name);
    if (n.name !== 'inner-slot-not-accepted') assert.notEqual(n.pop, r.pop, n.name); // that one: the state differs, not the bytes
    assert.throws(() => verifyRegistration({ ...r, pop: n.pop }, records, atRegistration), code(n.error), n.name);
  }
});

test('structures: a third level, an unregistered inner are refused from the records', () => {
  assert.equal(N.structures.length, 2);
  for (const s of N.structures) {
    assert.equal(s.error, 'UAMemberUnknown');
    const attrs = { pqzKey: '0x', pqzPopHash: hex(new Uint8Array(32)), kemPk: '0x' };
    assert.throws(() => verifyRegistration({ kind: 0x0120, keyData: s.keyData, attrs, pop: '0x', pqzPop: '0x' }, records), code('UAMemberUnknown'), s.name);
  }
  // an acceptance never asks eligibility, so the record check alone refuses a third level
  const third = N.structures.find((s) => s.name === 'third-level');
  const withThird = (id) => (id === third.ua ? { kind: 0x0120, keyData: third.keyData } : records(id));
  assert.throws(() => verifyMembership({ ua: third.ua, index: 0, sig: '0x', members: [{ index: 0, sig: '0x' }] }, withThird), code('UAMemberUnknown'));
});

test('the minimal rule at both levels', () => {
  const inner = (id) => records(id)?.keyData;
  const r = row('msig-nested-heavy-inner');
  const slot = r.members.findIndex((m) => m.kind === 0x0120);
  const sets = (list) => [0, 1].map((index) => ({ index, members: index === slot ? list : [] }));
  assert.ok(ua.msigSigMinimal(r.keyData, sets([{ index: 1 }]), inner), 'the weight-2 leaf alone');
  assert.ok(!ua.msigSigMinimal(r.keyData, sets([{ index: 0 }, { index: 1 }]), inner), 'a redundant leaf');
  assert.ok(!ua.msigSigMinimal(r.keyData, sets([{ index: 0 }]), inner), 'below the inner threshold');
  assert.throws(() => ua.msigSigMinimal(r.keyData, sets([{ index: 1 }])), code('UAMemberUnknown'));
  const o = row('msig-nested-heavy-outer');
  const heavy = o.members.findIndex((m) => m.kind === 0x0120);
  assert.ok(ua.msigSigMinimal(o.keyData, [{ index: heavy, members: [{ index: 0 }, { index: 1 }] }], inner));
  assert.ok(!ua.msigSigMinimal(o.keyData, [0, 1].map((index) => ({ index, members: index === heavy ? [{ index: 0 }, { index: 1 }] : [] })), inner), 'a redundant slot');
  assert.throws(() => ua.registrationArgs({ kind: 0x0120, keyData: r.keyData, pop: sets([{ index: 0 }, { index: 1 }]).map((s) => ({ ...s, sig: '0x' })), inner }), code('UAPoP'));
});

test('records and acceptances: every row verifies, a flipped leaf byte is refused', () => {
  assert.equal(N.kemRecords.length, 1);
  assert.equal(N.pqzKeyRecords.length, 4);
  for (const r of N.kemRecords) {
    verifyKemRecord(r, records, atRegistration);
    assert.throws(() => verifyKemRecord({ ...r, sig: flip(r.sig, r.sig.length / 2 - 100) }, records, atRegistration), code('UAUnauthorized'));
    assert.equal(hex(encodeMemberSigs(typedSlots(r.args.sig.members))), r.sig);
  }
  for (const r of N.pqzKeyRecords) {
    verifyPqzKeyRecord(r, records, atRegistration);
    assert.throws(() => verifyPqzKeyRecord({ ...r, sig: flip(r.sig, r.sig.length / 2 - 100) }, records, atRegistration), code('UAUnauthorized'));
  }
  assert.equal(N.memberships.filter((m) => m.members.length).length, 1, 'one inner slot accepts');
  for (const m of N.memberships) {
    verifyMembership(m, records, afterMemberships);
    const bad = m.members.length ? { ...m, members: m.members.map((x) => ({ ...x, sig: flip(x.sig) })) } : { ...m, sig: flip(m.sig) };
    assert.throws(() => verifyMembership(bad, records, afterMemberships), code('UAUnauthorized'), m.name);
    if (m.members.length) assert.throws(() => verifyMembership({ ...m, sig: '0x01' }, records, afterMemberships), code('UAUnauthorized'), 'a sig on an msig slot');
    else assert.throws(() => verifyMembership({ ...m, members: [{ index: 0, sig: m.sig }] }, records, afterMemberships), code('UAUnauthorized'), 'a list on a signing slot');
  }
});

test('authorizations: a leaf one level down signs md_I, a native leaf UAAuth in the registry domain', () => {
  const { contexts } = JSON.parse(readFileSync(new URL('structures.json', dir), 'utf8'));
  const domain = { generation: 1, ...contexts.A };
  const member = ua.purposeTag('member');
  const a = N.authorizations.find((x) => x.valid);
  assert.deepEqual(N.authorizations.filter((x) => x.valid).length, 1);
  const r = records(a.ua);
  const md = ua.memberDigest(B(a.ua), ua.uaMessage(0x0120, B(a.purposeTag), B(a.digest)));
  assert.equal(hex(md), a.memberDigest);
  const leaf = (m, sig, over) => (m.kind === 0x0001
    ? nativeOk(`0x${m.id.slice(26)}`, ua.uaAuthDigest(domain, B(m.id), member, over), hex(sig))
    : kindVerify(m.kind, records(m.id).keyData, ua.uaMessage(m.kind, member, over), sig, false));
  for (const s of decodeMemberSigs(a.sig)) {
    const m = r.members[s.index];
    if (m.kind !== 0x0120) { assert.ok(leaf(m, s.sig, md)); continue; }
    const over = ua.innerDigest(B(m.id), md);
    const leaves = ua.msigStructure(records(m.id).keyData).members;
    for (const x of s.members) assert.ok(leaf(leaves[x.index], x.sig, over));
    assert.ok(!leaf(leaves[s.members[0].index], s.members[0].sig, md), 'not over the outer digest');
  }
});

test('CTR-UA-37: the stored acceptance replays with no new signature, an msig slot by its list', () => {
  assert.equal(N.memberships.length, 4);
  for (const m of N.memberships) {
    const { keyData } = records(m.ua);
    assert.equal(hex(keccak_256(B(m.stored))), m.storedHash, `${m.name}: the event's bytes hash to memberSigHashOf`);
    const again = replayedMemberSig(keyData, m.index, m.stored);
    assert.equal(hex(again.sig), m.sig, m.name);
    assert.deepEqual(again.members.map((x) => ({ index: x.index, sig: hex(x.sig) })), m.members, m.name);
    verifyMembership({ ...m, members: m.members, sig: hex(again.sig) }, records, afterMemberships);
  }
  const m = N.memberships.find((x) => x.members.length);
  const { keyData } = records(m.ua);
  assert.equal(hex(encodeInnerSigs(m.members.map((x) => ({ index: x.index, sig: B(x.sig) })))), m.stored);
  assert.throws(() => replayedMemberSig(keyData, m.index, `${m.stored}00`), code('UAUnauthorized'), 'not canonical');
  assert.throws(() => replayedMemberSig(keyData, m.index, '0x'), code('UAUnauthorized'), 'an msig slot has a list');
  assert.throws(() => replayedMemberSig(keyData, 16, '0x'), code('UAUnauthorized'), 'past the members');
  for (const r of N.afterAcceptance) verifyRegistration(r, records, afterMemberships);
});

test('inner acceptance: accepted(id, index) read at the inner level always, unchecked without it, a pop accepting its own record only', () => {
  const lists = nested.filter((r) => r.pop !== '0x');
  assert.equal(lists.length, 5);
  for (const r of lists) assert.throws(() => verifyRegistration(r, records), code('UANotVerifiable'), `${r.name}: never OK unread`);
  for (const r of N.registrations.filter((x) => !x.innerDigests?.length)) verifyRegistration(r, records); // no inner level: nothing to read
  const [after] = N.afterAcceptance;
  const n = N.negatives.find((x) => x.name === 'inner-slot-not-accepted');
  assert.equal(n.pop, after.pop);
  assert.throws(() => verifyRegistration(after, records, atRegistration), code('UAPoP'), 'before the memberships rows');
  assert.throws(() => verifyRegistration(after, records), code('UANotVerifiable'));
  verifyRegistration(after, records, afterMemberships);
  // a record's own bits, outside its pop, when they are given (setKemKey, setPqzKey)
  const [k] = N.kemRecords;
  assert.throws(() => verifyKemRecord(k, records, (id, i) => id !== k.ua && atRegistration(id, i)), code('UAUnauthorized'));
  assert.throws(() => verifyKemRecord(k, records), code('UANotVerifiable'));
  const p = N.pqzKeyRecords[0];
  assert.throws(() => verifyPqzKeyRecord(p, records), code('UANotVerifiable'));
  // an msig slot's acceptance: its list counts only the inner's accepted slots
  const m = N.memberships.find((x) => x.members.length);
  assert.throws(() => verifyMembership(m, records, atRegistration), code('UAUnauthorized'));
  assert.throws(() => verifyMembership(m, records), code('UANotVerifiable'));
  for (const x of N.memberships.filter((y) => !y.members.length)) verifyMembership(x, records); // a signing slot: no inner level
});

test('replayedMemberSig: truncated or out-of-range bytes are UAUnauthorized, never another throw', () => {
  const m = N.memberships.find((x) => x.members.length);
  const { keyData } = records(m.ua);
  for (const stored of [concatBytes(word(32), word(1)), concatBytes(word(32), word(1), word(2n ** 64n - 80n)), concatBytes(word(32), word(1), word(2n ** 255n))]) {
    assert.throws(() => replayedMemberSig(keyData, m.index, stored), code('UAUnauthorized'), hex(stored).slice(0, 200));
  }
});

test('authorizations: every row as requireAuthorized checks it, valid or UAUnauthorized, unchecked without the accepted bits', () => {
  const { contexts } = JSON.parse(readFileSync(new URL('structures.json', dir), 'utf8'));
  const domain = { generation: 1, ...contexts.A };
  assert.equal(N.authorizations.length, 5);
  for (const a of N.authorizations) {
    if (a.valid) verifyAuthorization(a, records, domain, atRegistration);
    else assert.throws(() => verifyAuthorization(a, records, domain, atRegistration), code('UAUnauthorized'), a.name);
  }
  const a = N.authorizations.find((x) => x.valid);
  assert.throws(() => verifyAuthorization(a, records, domain), code('UANotVerifiable'));
  assert.throws(() => verifyAuthorization(a, records, domain, (id, i) => id !== a.ua && atRegistration(id, i)), code('UAUnauthorized'), 'the outer bits');
  const inner = records(a.ua).members.find((x) => x.kind === 0x0120).id;
  assert.throws(() => verifyAuthorization(a, records, domain, (id, i) => id !== inner && atRegistration(id, i)), code('UAUnauthorized'), 'the inner bits');
  assert.throws(() => verifyAuthorization(a, records, { ...domain, generation: 2 }, atRegistration), code('UAUnauthorized'), 'another domain');
  assert.throws(() => verifyAuthorization({ ...a, sig: flip(a.sig, a.sig.length / 2 - 40) }, records, domain, atRegistration), code('UAUnauthorized'));
});

test('Q4: the minimal rule, every weight vector of up to 4 slots of weight 1-4, every threshold, every subset', () => {
  const key = (t, w) => ua.encodeMsig(t, w.map((weight, i) => ({ kind: 0x0131, id: new Uint8Array(32).fill(i + 1), weight })));
  let sets = 0;
  const vectors = (n) => (n === 0 ? [[]] : vectors(n - 1).flatMap((v) => [1, 2, 3, 4].map((x) => [...v, x])));
  for (const n of [1, 2, 3, 4]) {
    for (const w of vectors(n)) {
      const total = w.reduce((a, b) => a + b, 0);
      const light = [...w].sort((a, b) => a - b);
      for (let t = 1; t <= total; t++) {
        let c = 0;
        for (let acc = 0; acc < t; c++) acc += light[c];
        const d = key(t, w);
        for (let bits = 1; bits < 1 << n; bits++) {
          const slots = w.map((_, i) => i).filter((i) => bits >> i & 1);
          const sum = slots.reduce((a, i) => a + w[i], 0);
          const every = sum >= t && slots.every((i) => sum - w[i] < t); // each slot necessary, by definition
          assert.equal(ua.msigSlotsMinimal(d, slots), every, `${w} t ${t} ${slots}`);
          // what the registry stops at: walking the slots, no signature comes after the threshold
          if (every) {
            let acc = 0;
            for (const i of slots) { assert.ok(acc < t, 'a minimal set passes stop-at-threshold'); acc += w[i]; }
            assert.ok(slots.length <= c, 'no quorum is larger than the bound counts');
          }
          sets++;
        }
      }
    }
  }
  assert.equal(sets, 42_010);
});

test('flat bytes did not change: the empty list encodes as the empty keyData did', () => {
  const sig = Uint8Array.of(1, 2, 3);
  const old = abiEncode(['uint16', 'bytes', 'bytes'], [7, new Uint8Array(0), sig]);
  assert.equal(hex(encodeMemberSigs([{ index: 7, members: [], sig }]).subarray(96)), hex(old));
});

test('decodeMemberSigs: canonical, 16 at each level, an index in a u16', () => {
  const sig = new Uint8Array(1).fill(9);
  const blob = encodeMemberSigs([{ index: 0, members: [{ index: 1, sig }], sig: new Uint8Array(0) }]);
  assert.deepEqual(decodeMemberSigs(blob)[0].members[0].index, 1);
  assert.equal(decodeMemberSigs(concatBytes(blob, new Uint8Array(32))), null, 'trailing bytes');
  const big = (n) => encodeMemberSigs([{ index: 0, members: Array.from({ length: n }, (_, index) => ({ index, sig })), sig: new Uint8Array(0) }]);
  assert.equal(decodeMemberSigs(big(16))[0].members.length, 16);
  assert.equal(decodeMemberSigs(big(17)), null);
  assert.equal(decodeMemberSigs(encodeMemberSigs([{ index: 0, members: [{ index: 65536, sig }], sig: new Uint8Array(0) }])), null);
});

test('Soroban stays flat until its round: an msig member and a nested list are refused', () => {
  const id = B(row('msig-inner-pq').ua);
  assert.throws(() => sor.encodeMsig(1, [{ kind: 0x0120, id, weight: 1 }]), code('KeyData'));
  assert.throws(() => sor.uaSig({ members: [{ index: 0, keyData: '0x', members: [{ index: 0, sig: '0x01' }], sig: '0x' }] }), code('MemberUnknown'));
});
