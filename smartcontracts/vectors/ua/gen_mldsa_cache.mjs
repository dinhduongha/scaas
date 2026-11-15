// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Round 3zh (owner 2026-11-15; spec 2026-11-15-mldsa-precompile-cache.md §7 F-9 / F-2): writes mldsa_cache.json, the ML-DSA
// expanded-key cache's independent reference and gas batch, from @noble/post-quantum 0.7.1 (clientkeys' pinned copy) only:
//   - per level (44 / 65 / 87) 12 keys: 10 from noble's keygen on fixed seeds, the pq_kat.json and pq_signatures.json keys;
//     each with the SHA-256 of its EIP-8051 expanded key `Â ‖ tr ‖ NTT(t1·2^13)` (u32 big-endian, `tr` 64 B) and of each
//     cache part (PqUA.mldsaParts: rows 3p … min(3p + 3, k) − 1, the last part with tr ‖ t̂1), built from noble's own
//     primitives (`_crystals.js`: XOF128 for RejNTTPoly, genCrystals' NTT), not from the Solidity code nor from clientkeys'
//     `mldsaExpandedKey`; for 44 / 65 it must equal pq_kat.json's `expanded_key` (clientkeys), checked here.
//   - per level a batch of UA-shaped signatures (deterministic, noble `sign(pq_msg, sk)`, empty context, so M' = 0 ‖ 0 ‖ pq_msg
//     as the registry verifies) under keys[0], with their hint counts, and one `omega_row`: an accepting signature with exactly
//     ω hints when 4,000 more messages give one (`valid` true), else the one with the most hints padded to exactly ω
//     (well-formed, rejected only at the final c̃ check, so its verify runs every hint step: an upper bound on any accepting
//     signature's hint work; `valid` false), for the cap's worst case (F-2).
// Run from the repo root after `npm ci --ignore-scripts` in clients/clientkeys:
//   node smartcontracts/vectors/ua/gen_mldsa_cache.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const NM = new URL('../../../clients/clientkeys/node_modules/', import.meta.url);
const pq = await import(new URL('@noble/post-quantum/ml-dsa.js', NM));
const cr = await import(new URL('@noble/post-quantum/_crystals.js', NM));
const { shake256, keccak_256 } = await import(new URL('@noble/hashes/sha3.js', NM));
const pkg = JSON.parse(readFileSync(new URL('@noble/post-quantum/package.json', NM)));
if (pkg.version !== '0.7.1') throw new Error(`@noble/post-quantum ${pkg.version}, want 0.7.1`);

const Q = 8380417;
const L = { mldsa44: [4, 4, 80, pq.ml_dsa44], mldsa65: [6, 5, 55, pq.ml_dsa65], mldsa87: [8, 7, 75, pq.ml_dsa87] };
const { NTT } = cr.genCrystals({ N: 256, Q, F: 8347681, ROOT_OF_UNITY: 1753, brvBits: 8, isKyber: false,
  newPoly: (n) => new Int32Array(n) });
const hex = (u) => '0x' + Buffer.from(u).toString('hex');
const unhex = (s) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));
const sha = (u) => '0x' + createHash('sha256').update(u).digest('hex');
const utf8 = (s) => new TextEncoder().encode(s);
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };

/** FIPS 204 RejNTTPoly(ρ ‖ s ‖ r) through noble's XOF128 reader (`get(s, r)` appends the two coordinate bytes). */
function rejNtt(xof, s, r) {
  const out = new Int32Array(256);
  const next = xof.get(s, r);
  for (let n = 0; n < 256;) {
    const b = next();
    for (let o = 0; o + 2 < b.length && n < 256; o += 3) {
      const v = b[o] | (b[o + 1] << 8) | ((b[o + 2] & 0x7f) << 16);
      if (v < Q) out[n++] = v;
    }
  }
  return out;
}

/** The expanded key of `pk` at level `name` (rows of Â, then tr, then t̂1), u32 big-endian. */
function expanded(name, pk) {
  const [k, l] = L[name];
  const rows = [];
  const put = (poly) => { const b = new Uint8Array(1024); const dv = new DataView(b.buffer); for (let i = 0; i < 256; i++) dv.setUint32(4 * i, ((poly[i] % Q) + Q) % Q); return b; };
  const xof = cr.XOF128(pk.subarray(0, 32));
  for (let i = 0; i < k; i++) rows.push(cat(...Array.from({ length: l }, (_, j) => put(rejNtt(xof, j, i)))));
  xof.clean?.();
  const t1 = [];
  for (let i = 0; i < k; i++) {
    const t = new Int32Array(256);
    const base = 32 + 320 * i;
    for (let c = 0; c < 256; c++) {
      const bit = 10 * c, by = base + (bit >> 3);
      t[c] = ((((pk[by] | (pk[by + 1] << 8)) >> (bit & 7)) & 0x3ff) * 8192) % Q;
    }
    t1.push(put(NTT.encode(t)));
  }
  const tail = cat(shake256(pk, { dkLen: 64 }), ...t1);
  const n = k === 4 ? 1 : k === 6 ? 2 : 3; // PqUA.mldsaParts
  const parts = [];
  for (let p = 0; p < n; p++) {
    const last = p + 1 === n;
    parts.push(cat(...rows.slice(3 * p, last ? k : 3 * p + 3), ...(last ? [tail] : [])));
  }
  return { ek: cat(...parts), parts };
}

const kat = JSON.parse(readFileSync(new URL('pq_kat.json', import.meta.url)));
const sigs = JSON.parse(readFileSync(new URL('pq_signatures.json', import.meta.url)));
const seed = (...s) => createHash('sha256').update(utf8(['scaas.mldsa.cache.v1', ...s].join('|'))).digest();

/** The hint count of a signature (HintBitPack: the last k bytes are the cumulative counts). */
const hints = (name, sig) => sig[sig.length - 1];

/** `sig` with its hints padded to exactly ω, kept well-formed (strictly increasing per row, cumulative counts). */
function padHints(name, sig) {
  const [k, , omega] = L[name];
  const y = sig.subarray(sig.length - omega - k);
  const rows = [];
  let prev = 0;
  for (let i = 0; i < k; i++) { rows.push(Array.from(y.subarray(prev, y[omega + i]))); prev = y[omega + i]; }
  let total = prev;
  for (let i = 0; i < k && total < omega; i++) {
    for (let c = 0; c < 256 && total < omega; c++) if (!rows[i].includes(c)) { rows[i].push(c); total++; }
    rows[i].sort((a, b) => a - b);
  }
  const out = Uint8Array.from(sig);
  const z = out.subarray(out.length - omega - k);
  z.fill(0);
  let o = 0;
  for (let i = 0; i < k; i++) { for (const c of rows[i]) z[o++] = c; z[omega + i] = o; }
  if (o !== omega) throw new Error('pad');
  return out;
}

const out = { note: 'Round 3zh (owner 2026-11-15, spec 2026-11-15-mldsa-precompile-cache.md F-9 / F-2): generated by gen_mldsa_cache.mjs from @noble/post-quantum 0.7.1 only; do not edit. keys: the expanded key (Â ‖ tr ‖ t̂1, u32 big-endian) and each cache part by SHA-256; batch: UA-shaped signatures (M\' = 0 ‖ 0 ‖ keccak256(TAG ‖ ua_msg)) under keys[0]; omega_row: an accepting signature with exactly ω hints (valid true), else the one with the most hints padded to ω (valid false, rejected at the final c̃ check only).', noble: pkg.version, levels: {} };
for (const name of Object.keys(L)) {
  const [, , omega, alg] = L[name];
  const keys = [];
  const sks = [];
  for (let i = 0; i < 10; i++) {
    const kp = alg.keygen(seed(name, 'key', String(i)));
    keys.push(kp.publicKey);
    sks.push(kp.secretKey);
  }
  keys.push(unhex(kat.kinds[name].pk));
  keys.push(unhex(sigs.kinds.find((x) => x.name === name).keyData));
  const rows = keys.map((pk) => {
    const { ek, parts } = expanded(name, pk);
    return { pk: hex(pk), ek_sha256: sha(ek), parts_sha256: parts.map(sha), parts_len: parts.map((p) => p.length) };
  });
  if (name !== 'mldsa87') {
    const want = kat.kinds[name].expanded_key.toLowerCase();
    if (hex(expanded(name, keys[10]).ek) !== want) throw new Error(`${name}: noble's expansion differs from pq_kat.json (clientkeys)`);
  }
  const tag = keccak_256(utf8(`scaas.ua.${name}.v1`));
  const batch = [];
  for (let i = 0; i < 16; i++) {
    const uaMsg = seed(name, 'msg', String(i));
    const pqMsg = keccak_256(cat(tag, uaMsg));
    const sig = alg.sign(pqMsg, sks[0], { extraEntropy: false });
    if (!alg.verify(sig, pqMsg, keys[0])) throw new Error('sign');
    batch.push({ ua_msg: hex(uaMsg), sig: hex(sig), hints: hints(name, sig) });
  }
  // a genuine accepting signature with exactly ω hints, searched over further messages; else the padded upper bound
  let omegaRow = null;
  let most = batch.reduce((x, y) => (y.hints > x.hints ? y : x));
  for (let i = 0; i < 4000 && most.hints < omega; i++) {
    const uaMsg = seed(name, 'omega', String(i));
    const sig = alg.sign(keccak_256(cat(tag, uaMsg)), sks[0], { extraEntropy: false });
    if (hints(name, sig) > most.hints) most = { ua_msg: hex(uaMsg), sig: hex(sig), hints: hints(name, sig) };
  }
  if (most.hints === omega) {
    omegaRow = { ua_msg: most.ua_msg, sig: most.sig, hints: omega, valid: true };
  } else {
    const padded = padHints(name, unhex(most.sig));
    if (alg.verify(padded, keccak_256(cat(tag, unhex(most.ua_msg))), keys[0])) throw new Error('padded hints verified');
    omegaRow = { ua_msg: most.ua_msg, sig: hex(padded), hints: omega, valid: false, from_hints: most.hints };
  }
  out.levels[name] = { omega, keys: rows, batch, omega_row: omegaRow };
  console.log(`${name}: ${rows.length} keys, batch ${batch.length} (hints ${Math.min(...batch.map((b) => b.hints))}-${Math.max(...batch.map((b) => b.hints))}), omega row ${omegaRow.valid ? 'valid' : `padded from ${omegaRow.from_hints}`}`);
}
writeFileSync(new URL('mldsa_cache.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
