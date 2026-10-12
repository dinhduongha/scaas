// Imports the published PQ vectors into smartcontracts/vectors/ua/pq_external.json (input: a directory holding the
// downloaded files, see docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md Task 1; each section records its source
// URL and the file's SHA-256, and a file whose SHA-256 differs from `PIN` is refused before it is parsed). Every entry is
// also checked here with @noble/post-quantum, so the file only holds vectors that two implementations (noble and the
// Solidity verifiers) must agree on.
//   node scripts/pq-external.mjs <download dir>
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ml_dsa44, ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { falcon512padded } from '@noble/post-quantum/falcon.js';

const dir = process.argv[2];
if (!dir) throw new Error('usage: node scripts/pq-external.mjs <download dir>');
/** SHA-256 of each download at the pinned commits (ACVP-Server 975de31e, EIPs 3aea9f36). */
const PIN = {
  'ML-DSA-sigVer-FIPS204/internalProjection.json': '47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437',
  'SLH-DSA-sigVer-FIPS205/internalProjection.json': 'a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792',
  'mldsa_nist.rsp': '1d29c3b4ec68e3455f87f49b3386a2a6fc5e167c76e476c4770317ffbb97d242',
  'test-vectors.json': '2029f73ffa8f514b4a105e6c93522d55bbbe0370c3ed5644773a88c1a91aeabd',
  'kat_FALCONCORE_512.rsp': 'c79c1dd457a92760ef30bbd63f1783aa634b9817acd2c1f1c3885c0c668b15ad',
  'kat_HASHTOPOINT_512.rsp': '05b0ac54f4b329b9a778c826a81cb4184ce4c03b637607383b435efaf2899fcb',
};
const raw = (f) => {
  const b = readFileSync(`${dir}/${f}`);
  if (createHash('sha256').update(b).digest('hex') !== PIN[f]) throw new Error(`sha256 mismatch ${f}`);
  return b;
};
const sha = (f) => PIN[f];
const h = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const x = (u) => '0x' + Buffer.from(u).toString('hex');
const rsp = (f) => raw(f).toString('utf8').split('count = ').slice(1)
  .map((r) => Object.fromEntries([...r.matchAll(/^(\w+) ?= ?(.*)$/gm)].map((m) => [m[1], m[2].trim()])));
const ACVP = 'https://raw.githubusercontent.com/usnistgov/ACVP-Server/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/';
const EIPS = 'https://raw.githubusercontent.com/ethereum/EIPs/3aea9f3673a684dddfcc17c0d1f74d484e20e6ac/assets/';
const ALG = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'SLH-DSA-SHA2-128s': slh_dsa_sha2_128s };

/** ACVP sigVer, pure (external) and internal groups: `mprime` is the formatted message M' the core verifies. */
function acvp(file, sets) {
  const j = JSON.parse(raw(file));
  const cases = [];
  for (const g of j.testGroups) {
    if (!sets.includes(g.parameterSet) || g.preHash === 'preHash' || g.externalMu) continue;
    for (const t of g.tests) {
      const ctx = h(t.context || '');
      const m = h(t.message);
      const mprime = g.signatureInterface === 'internal' ? m : Uint8Array.from([0, ctx.length, ...ctx, ...m]);
      const a = ALG[g.parameterSet];
      let ok;
      try { ok = a.internal.verify(h(t.signature), mprime, h(t.pk)); } catch { ok = false; }
      if (ok !== t.testPassed) throw new Error(`noble disagrees with ACVP ${g.parameterSet} tc ${t.tcId}`);
      cases.push({ set: g.parameterSet, tc: t.tcId, iface: g.signatureInterface, pk: x(h(t.pk)), mprime: x(mprime),
        sig: x(h(t.signature)), valid: t.testPassed, reason: t.reason });
    }
  }
  return { source: ACVP + file, sha256: sha(file), cases };
}

// EIP-8051 `mldsa_nist.rsp`: FIPS 204 ML-DSA-44 KATs (sm = sig ‖ msg), the empty context ⇒ M' = 0x00 ‖ 0x00 ‖ msg.
function eip8051(file, n) {
  const cases = rsp(file).slice(0, n).map((r) => {
    const sm = h(r.sm), mlen = +r.mlen, sig = sm.slice(0, sm.length - mlen), msg = sm.slice(sm.length - mlen);
    if (!ml_dsa44.verify(sig, msg, h(r.pk))) throw new Error('8051 KAT fails in noble');
    return { pk: x(h(r.pk)), mprime: x(Uint8Array.from([0, 0, ...msg])), sig: x(sig), valid: true };
  });
  return { source: EIPS + 'eip-8051/' + file, sha256: sha(file), cases };
}

// EIP-8355 test cases: input = pk (1312) ‖ sig (2420) ‖ msg for VERIFY_MLDSA44.
function eip8355(file) {
  const cases = JSON.parse(raw(file)).map((c) => {
    const inp = h(c.Input), valid = BigInt('0x' + c.Expected) === 1n;
    if (inp.length < 3732) return { name: c.Name, input: x(inp), valid };
    const pk = inp.slice(0, 1312), sig = inp.slice(1312, 3732), msg = inp.slice(3732);
    if (ml_dsa44.verify(sig, msg, pk) !== valid) throw new Error('8355 case disagrees in noble');
    return { name: c.Name, input: x(inp), pk: x(pk), mprime: x(Uint8Array.from([0, 0, ...msg])), sig: x(sig), valid };
  });
  return { source: EIPS + 'eip-8355/' + file, sha256: sha(file), cases };
}

// Falcon-512 NIST round-3 KATs as published with EIP-8052: pk and the compressed s2 from kat_FALCONCORE_512.rsp
// (`s2` = msg ‖ 0x29 ‖ compressed), the salt from kat_HASHTOPOINT_512.rsp (same seeds), rebuilt as padded signatures
// 0x39 ‖ salt ‖ compressed ‖ zeros (666 bytes).
function falcon(coreFile, h2pFile, n) {
  const core = rsp(coreFile), h2p = rsp(h2pFile);
  const cases = [];
  for (let i = 0; i < n; i++) {
    const c = core[i], p = h2p[i];
    if (c.seed !== p.seed) throw new Error('falcon KAT seeds differ');
    const mlen = +p.mlen, s2 = h(c.s2), msg = s2.slice(0, mlen), comp = s2.slice(mlen + 1), salt = h(p.salt);
    if (s2[mlen] !== 0x29 || (c.mlen !== undefined && +c.mlen !== mlen) || salt.length !== 40) throw new Error('falcon KAT format');
    const sig = new Uint8Array(666);
    sig[0] = 0x39; sig.set(salt, 1); sig.set(comp, 41);
    if (!falcon512padded.verify(sig, msg, h(c.pk))) throw new Error('falcon KAT fails in noble');
    cases.push({ count: i, pk: x(h(c.pk)), msg: x(msg), sig: x(sig), valid: true });
  }
  return { sources: [EIPS + 'eip-8052/' + coreFile, EIPS + 'eip-8052/' + h2pFile], sha256: [sha(coreFile), sha(h2pFile)], cases };
}

const out = {
  note: 'Imported by clients/clientkeys/scripts/pq-external.mjs; every entry re-checked with @noble/post-quantum 0.7.1.',
  acvp_mldsa: acvp('ML-DSA-sigVer-FIPS204/internalProjection.json', ['ML-DSA-44', 'ML-DSA-65']),
  acvp_slhdsa: acvp('SLH-DSA-sigVer-FIPS205/internalProjection.json', ['SLH-DSA-SHA2-128s']),
  eip8051_nist_kat: eip8051('mldsa_nist.rsp', 10),
  eip8355: eip8355('test-vectors.json'),
  falcon_kat: falcon('kat_FALCONCORE_512.rsp', 'kat_HASHTOPOINT_512.rsp', 10),
};
writeFileSync(new URL('../../../smartcontracts/vectors/ua/pq_external.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
for (const [k, v] of Object.entries(out)) if (v.cases) console.log(k, v.cases.length, 'cases,', v.cases.filter((c) => c.valid).length, 'valid');
