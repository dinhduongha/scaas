// Imports the published PQ vectors into smartcontracts/vectors/ua/pq_external.json (input: a directory holding the
// downloaded files, see docs/superpowers/plans/2026-10-12-p6a-pq-verifiers.md Task 1; each section records its source
// URL and the file's SHA-256, and a file whose SHA-256 differs from `PIN` is refused before it is parsed). Every entry is
// also checked here with @noble/post-quantum, so the file only holds vectors that two implementations (noble and the
// Solidity verifiers) must agree on.
//   node scripts/pq-external.mjs <download dir>
// falcon1024-KAT.rsp (fndsa1024, CTR-UA-40) is the member Falcon/falcon-round3/KAT/falcon1024-KAT.rsp of the NIST round-3
// package Falcon-Round3.zip (SHA-256 fd58f045...5362f44), taken out with the stdlib and no other code, the zip untrusted:
//   python3 -I -c 'import hashlib,sys,zipfile; b=open(sys.argv[1],"rb").read(); assert hashlib.sha256(b).hexdigest()==sys.argv[3]
//     z=zipfile.ZipFile(sys.argv[1]); open(sys.argv[2],"wb").write(z.read("Falcon/falcon-round3/KAT/falcon1024-KAT.rsp"))' \
//     Falcon-Round3.zip <download dir>/falcon1024-KAT.rsp fd58f0454f6bfb4713734e60b2d2d75d96fbae62d5180fceeef1039df5362f44
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { falcon512padded, falcon1024, falcon1024padded } from '@noble/post-quantum/falcon.js';

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
  'falcon1024-KAT.rsp': '036a0bf5260573cec44977284dfef756cd1143db9961b981bd1fb55828acb20d',
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
const ALG = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87, 'SLH-DSA-SHA2-128s': slh_dsa_sha2_128s };

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

// Falcon-1024 NIST round-3 KATs (`falcon1024-KAT.rsp`: sm = u16 sig_len ‖ nonce (40) ‖ msg ‖ 0x2A ‖ compressed), rebuilt as padded
// signatures 0x3A ‖ nonce ‖ compressed ‖ zeros (1,280 bytes); the first `n` rows whose compressed s2 fits 1,239 bytes (a longer one,
// such as count 82, has no padded form: its signer signs again). noble checks the NIST form and the padded one.
function falcon1024Kat(file, n) {
  const all = rsp(file);
  if (all.length !== 100) throw new Error('falcon1024 KAT: 100 rows');
  const cases = [];
  const over = [];
  for (const [count, r] of all.entries()) {
    const pk = h(r.pk), msg = h(r.msg), sm = h(r.sm), mlen = +r.mlen, len = (sm[0] << 8) | sm[1];
    const nonce = sm.slice(2, 42), body = sm.slice(42 + mlen);
    if (pk.length !== 1793 || pk[0] !== 0x0a || msg.length !== mlen || Buffer.compare(sm.slice(42, 42 + mlen), msg) !== 0
      || body.length !== len || body[0] !== 0x2a || +r.smlen !== sm.length) throw new Error(`falcon1024 KAT format, count ${count}`);
    const opened = falcon1024.attached.open(sm, pk);
    if (Buffer.compare(opened, msg) !== 0) throw new Error(`falcon1024 KAT fails in noble (NIST form), count ${count}`);
    const comp = body.slice(1);
    if (comp.length > 1239) { over.push(count); continue; }
    if (cases.length === n) continue;
    const sig = new Uint8Array(1280);
    sig[0] = 0x3a; sig.set(nonce, 1); sig.set(comp, 41);
    if (!falcon1024padded.verify(sig, msg, pk)) throw new Error(`falcon1024 KAT fails in noble (padded), count ${count}`);
    cases.push({ count, pk: x(pk), msg: x(msg), sig: x(sig), valid: true });
  }
  const zip = 'https://csrc.nist.gov/CSRC/media/Projects/post-quantum-cryptography/documents/round-3/submissions/Falcon-Round3.zip';
  return { source: `${zip} (member Falcon/falcon-round3/KAT/${file})`,
    sha256_zip: 'fd58f0454f6bfb4713734e60b2d2d75d96fbae62d5180fceeef1039df5362f44', sha256: sha(file), rows_over_1239: over, cases };
}

const out = {
  note: 'Imported by clients/clientkeys/scripts/pq-external.mjs; every entry re-checked with @noble/post-quantum 0.7.1.',
  acvp_mldsa: acvp('ML-DSA-sigVer-FIPS204/internalProjection.json', ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']),
  acvp_slhdsa: acvp('SLH-DSA-sigVer-FIPS205/internalProjection.json', ['SLH-DSA-SHA2-128s']),
  eip8051_nist_kat: eip8051('mldsa_nist.rsp', 10),
  eip8355: eip8355('test-vectors.json'),
  falcon_kat: falcon('kat_FALCONCORE_512.rsp', 'kat_HASHTOPOINT_512.rsp', 10),
  falcon1024_kat: falcon1024Kat('falcon1024-KAT.rsp', 10),
};
writeFileSync(new URL('../../../smartcontracts/vectors/ua/pq_external.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
for (const [k, v] of Object.entries(out)) if (v.cases) console.log(k, v.cases.length, 'cases,', v.cases.filter((c) => c.valid).length, 'valid');
