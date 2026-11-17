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
import { writeFileSync } from 'node:fs';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { readPinned } from './pinned.mjs';
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
  // ua-rs-sign T1c (spec §11, F-10): the signers' and the KEM's known answers
  'ML-KEM-keyGen-FIPS203/internalProjection.json': 'd7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b',
  'ML-KEM-encapDecap-FIPS203/internalProjection.json': 'a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f',
  'ML-DSA-sigGen-FIPS204/internalProjection.json': '72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22',
  'SLH-DSA-sigGen-FIPS205/internalProjection.json': '62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba',
  'rfc7748.txt': '279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3',
};
const raw = (f) => readPinned(`${dir}/${f}`, PIN[f], f);
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


// ACVP ML-KEM-1024 (FIPS 203) keyGen: d, z → ek, dk (the first `n` cases).
function acvpMlkemKeygen(file, n) {
  const g = JSON.parse(raw(file)).testGroups.find((t) => t.parameterSet === 'ML-KEM-1024');
  const cases = g.tests.slice(0, n).map((t) => {
    const { publicKey, secretKey } = ml_kem1024.keygen(h(t.d + t.z));
    if (x(publicKey) !== x(h(t.ek)) || x(secretKey) !== x(h(t.dk))) throw new Error(`noble disagrees with ACVP ML-KEM keyGen tc ${t.tcId}`);
    return { tc: t.tcId, d: x(h(t.d)), z: x(h(t.z)), ek: x(h(t.ek)), dk: x(h(t.dk)) };
  });
  return { source: ACVP + file, sha256: sha(file), cases };
}

// ACVP ML-KEM-1024 encapDecap: encapsulation (ek, m → c, k), decapsulation (dk, c → k; modified ciphertexts give the implicit
// rejection key), and the two input checks (decapsulationKeyCheck: FIPS 203 §7.3; encapsulationKeyCheck: the §7.2 modulus check).
function acvpMlkemEncapDecap(file, nEncaps) {
  const groups = JSON.parse(raw(file)).testGroups.filter((t) => t.parameterSet === 'ML-KEM-1024');
  const by = (f) => groups.find((t) => t.function === f).tests;
  const encapsulation = by('encapsulation').slice(0, nEncaps).map((t) => {
    const { cipherText, sharedSecret } = ml_kem1024.encapsulate(h(t.ek), h(t.m));
    if (x(cipherText) !== x(h(t.c)) || x(sharedSecret) !== x(h(t.k))) throw new Error(`noble disagrees with ACVP encapsulation tc ${t.tcId}`);
    return { tc: t.tcId, ek: x(h(t.ek)), m: x(h(t.m)), c: x(h(t.c)), k: x(h(t.k)) };
  });
  const decapsulation = by('decapsulation').map((t) => {
    if (x(ml_kem1024.decapsulate(h(t.c), h(t.dk))) !== x(h(t.k))) throw new Error(`noble disagrees with ACVP decapsulation tc ${t.tcId}`);
    return { tc: t.tcId, dk: x(h(t.dk)), c: x(h(t.c)), k: x(h(t.k)), reason: t.reason };
  });
  const dkCheck = by('decapsulationKeyCheck').map((t) => ({ tc: t.tcId, dk: x(h(t.dk)), valid: t.testPassed, reason: t.reason }));
  const ekCheck = by('encapsulationKeyCheck').map((t) => {
    let ok = true;
    try { ml_kem1024.encapsulate(h(t.ek), new Uint8Array(32)); } catch { ok = false; }
    if (ok !== t.testPassed) throw new Error(`noble disagrees with ACVP encapsulationKeyCheck tc ${t.tcId}`);
    return { tc: t.tcId, ek: x(h(t.ek)), valid: t.testPassed, reason: t.reason };
  });
  return { source: ACVP + file, sha256: sha(file), encapsulation, decapsulation, dkCheck, ekCheck };
}

// ACVP sigGen for the signers (ua-rs T3b): pure external (M' = 0 ‖ len(ctx) ‖ ctx ‖ M) and internal (M' = the message) groups,
// deterministic and hedged / randomized, `n` cases per group; `mprime` is what `internal.sign` signs, `rnd` the hedge (ML-DSA,
// absent = deterministic = 32 zero bytes), `addRand` SLH-DSA's opt_rand (absent = PK.seed).
function acvpSigGen(file, sets, n) {
  const j = JSON.parse(raw(file));
  const cases = [];
  for (const g of j.testGroups) {
    if (!sets.includes(g.parameterSet) || g.preHash === 'preHash' || g.externalMu) continue;
    for (const t of g.tests.slice(0, n)) {
      const ctx = h(t.context || '');
      const m = h(t.message);
      const mprime = g.signatureInterface === 'internal' ? m : Uint8Array.from([0, ctx.length, ...ctx, ...m]);
      const rand = t.rnd ?? t.additionalRandomness;
      const sig = ALG[g.parameterSet].internal.sign(mprime, h(t.sk), { extraEntropy: g.deterministic ? false : h(rand) });
      if (x(sig) !== x(h(t.signature))) throw new Error(`noble disagrees with ACVP sigGen ${g.parameterSet} tc ${t.tcId}`);
      cases.push({ set: g.parameterSet, tc: t.tcId, iface: g.signatureInterface, deterministic: g.deterministic, sk: x(h(t.sk)),
        pk: x(h(t.pk)), mprime: x(mprime), ...(g.deterministic ? {} : t.rnd ? { rnd: x(h(t.rnd)) } : { addRand: x(h(rand)) }), sig: x(sig) });
    }
  }
  return { source: ACVP + file, sha256: sha(file), cases };
}

// RFC 7748 X25519: §5.2 (two scalar multiplications; the iterated function after 1 and 1,000 iterations; 1,000,000 not run) and
// §6.1 (the Diffie-Hellman example). Every value is quoted from the RFC text and found in it here.
function rfc7748(file) {
  const text = raw(file).toString('utf8').replace(/\s+/g, ' ');
  const v = {
    scalarMult: [
      { k: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4', u: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
        out: 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552' },
      { k: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d', u: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
        out: '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957' },
    ],
    iterated: [{ iterations: 1, out: '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079' },
      { iterations: 1000, out: '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51' }],
    dh: { a: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a', A: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
      b: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb', B: 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
      K: '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742' },
  };
  const quoted = [...v.scalarMult.flatMap((r) => [r.k, r.u, r.out]), ...v.iterated.map((r) => r.out), ...Object.values(v.dh)];
  for (const q of quoted) if (!text.includes(q)) throw new Error(`rfc7748.txt does not quote ${q.slice(0, 16)}`);
  for (const r of v.scalarMult) if (x(x25519.scalarMult(h(r.k), h(r.u))) !== '0x' + r.out) throw new Error('RFC 7748 §5.2 in noble');
  let [k, u] = [h('09'.padEnd(64, '0')), h('09'.padEnd(64, '0'))];
  for (let i = 1; i <= 1000; i++) {
    [k, u] = [x25519.scalarMult(k, u), k];
    const want = v.iterated.find((r) => r.iterations === i);
    if (want && x(k) !== '0x' + want.out) throw new Error(`RFC 7748 iterated ${i} in noble`);
  }
  const d = v.dh;
  if (x(x25519.getPublicKey(h(d.a))) !== '0x' + d.A || x(x25519.getSharedSecret(h(d.b), h(d.A))) !== '0x' + d.K) throw new Error('RFC 7748 §6.1 in noble');
  const p = (s) => '0x' + s;
  return { source: 'https://www.rfc-editor.org/rfc/rfc7748.txt', sha256: sha(file),
    scalarMult: v.scalarMult.map((r) => ({ k: p(r.k), u: p(r.u), out: p(r.out) })), iterated: v.iterated.map((r) => ({ ...r, out: p(r.out) })),
    dh: Object.fromEntries(Object.entries(d).map(([kk, vv]) => [kk, p(vv)])) };
}

const out = {
  note: 'Imported by clients/clientkeys/scripts/pq-external.mjs; every entry re-checked with @noble/post-quantum 0.7.1 (X25519: '
    + '@noble/curves 2.4.0). Each section: its source URL and the downloaded file\'s sha256 (refused before parsing on a mismatch).',
  acvp_mldsa: acvp('ML-DSA-sigVer-FIPS204/internalProjection.json', ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']),
  acvp_slhdsa: acvp('SLH-DSA-sigVer-FIPS205/internalProjection.json', ['SLH-DSA-SHA2-128s']),
  eip8051_nist_kat: eip8051('mldsa_nist.rsp', 10),
  eip8355: eip8355('test-vectors.json'),
  falcon_kat: falcon('kat_FALCONCORE_512.rsp', 'kat_HASHTOPOINT_512.rsp', 10),
  falcon1024_kat: falcon1024Kat('falcon1024-KAT.rsp', 10),
  acvp_mlkem_keygen: acvpMlkemKeygen('ML-KEM-keyGen-FIPS203/internalProjection.json', 5),
  acvp_mlkem_encapdecap: acvpMlkemEncapDecap('ML-KEM-encapDecap-FIPS203/internalProjection.json', 5),
  acvp_mldsa_siggen: acvpSigGen('ML-DSA-sigGen-FIPS204/internalProjection.json', ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'], 1),
  acvp_slhdsa_siggen: acvpSigGen('SLH-DSA-sigGen-FIPS205/internalProjection.json', ['SLH-DSA-SHA2-128s'], 1),
  rfc7748: rfc7748('rfc7748.txt'),
};
writeFileSync(new URL('../../../smartcontracts/vectors/ua/pq_external.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
for (const [k, v] of Object.entries(out)) if (v.cases) console.log(k, v.cases.length, 'cases,', v.cases.filter((c) => c.valid).length, 'valid');
