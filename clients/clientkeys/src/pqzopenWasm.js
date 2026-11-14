// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The browser wallet's K3-7 holder check (CLI-SGN-51; TODO 3zf): the loader of the wallet module of pqz-core/ffi/wallet-wasm
// (pqz-ffi `opening::check_recipient` / `check_auditor` in wasm32, one module per parameter set). The caller gives the module's
// bytes or a compiled `WebAssembly.Module`; nothing is fetched. Every failure is the one outcome, as the Rust API: `null` (skip)
// for the recipient, `unreadable` / `recipient-unreadable` for the auditor; a malformed input is that outcome too, never a
// throw with detail. `pqzKeyHandle(...).check(credit, wallet)` (src/pqzopen.js) hands the handle's opening KEM seed to a
// wallet this loader made, and to nothing else. UNAUDITED.

const EXPORTS = ['check_auditor', 'check_recipient', 'input_cap', 'input_ptr', 'memory', 'out_ptr', 'pk_bytes'];
const WALLETS = new WeakSet();
const SKIP = Symbol('skip');

/** True for a wallet `loadPqzWallet` made (frozen; its checks are the module's). */
export const isPqzWallet = (x) => WALLETS.has(x);

const bytesOf = (x) => {
  if (x instanceof Uint8Array) return x;
  if (typeof x !== 'string' || !/^(0x)?([0-9a-fA-F]{2})*$/.test(x)) throw SKIP;
  const h = x.startsWith('0x') ? x.slice(2) : x;
  return Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
};
const be4 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const be8 = (v) => {
  if ((typeof v !== 'number' || !Number.isSafeInteger(v)) && typeof v !== 'bigint') throw SKIP;
  let x = BigInt(v);
  if (x < 0n || x >= 1n << 64n) throw SKIP;
  const b = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) { b[i] = Number(x & 255n); x >>= 8n; }
  return b;
};

/** The frame of lib.rs: every field `be4(len) ‖ bytes`; the module checks each length. */
function frameOf(openKemSeed, c) {
  const parts = [];
  const field = (b) => parts.push(be4(b.length), b);
  const party = (p) => {
    if (p === null || typeof p !== 'object') throw SKIP;
    for (const b of [bytesOf(p.ua), be8(p.keyVersion), bytesOf(p.pk), bytesOf(p.kemPk), bytesOf(p.v), bytesOf(p.opening)]) field(b);
  };
  if (c === null || typeof c !== 'object') throw SKIP;
  for (const b of [bytesOf(openKemSeed), bytesOf(c.chainUid), bytesOf(c.token), bytesOf(c.u)]) field(b);
  party(c.to);
  field(Uint8Array.of(c.auditor == null ? 0 : 1));
  if (c.auditor != null) party(c.auditor);
  const out = new Uint8Array(parts.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const b of parts) { out.set(b, o); o += b.length; }
  return out;
}

const amountOf = (d) => d.reduceRight((a, x) => a * 16n + BigInt(x), 0n);

/** Loads the wallet module of one set from its bytes (`Uint8Array` / `ArrayBuffer`) or a `WebAssembly.Module`. Refuses (throws)
 *  a module whose exports or imports are not exactly the wallet's. `{ pkBytes, checkRecipient, checkAuditor }`:
 *  - `checkRecipient(openKemSeed, credit)`: `{ digits, amount }` of an accepted credit, else `null`;
 *  - `checkAuditor(openKemSeed, credit)`: `{ outcome: 'read', digits, amount }`, `{ outcome: 'recipient-unreadable' }` or
 *    `{ outcome: 'unreadable' }`;
 *  `credit = { chainUid, token, u, to: { ua, keyVersion, pk, kemPk, v, opening }, auditor: { …the same } | null }`, bytes as
 *  `Uint8Array` or hex, `u`, `v` the be8 lanes (`pqzUnpack` of the stored form). A trap re-instantiates the module. */
export async function loadPqzWallet(source) {
  const module = source instanceof WebAssembly.Module ? source
    : await WebAssembly.compile(source instanceof ArrayBuffer ? new Uint8Array(source) : source);
  const names = WebAssembly.Module.exports(module).map((e) => e.name).sort();
  if (names.join() !== EXPORTS.join() || WebAssembly.Module.imports(module).length !== 0) {
    throw new Error('Refusing: not the PQZ wallet module (its exports or imports differ).');
  }
  let ex = null;
  const fresh = () => { ex = new WebAssembly.Instance(module, {}).exports; };
  fresh();
  const pkBytes = ex.pk_bytes();
  const cap = ex.input_cap();
  // the module's code, or SKIP; the digits on code 1
  function run(fn, openKemSeed, credit) {
    let frame = null;
    try {
      frame = frameOf(openKemSeed, credit);
      if (frame.length > cap) return SKIP;
      const at = ex.input_ptr(); // first, then the buffer: the first call allocates and may grow (detach) the memory
      new Uint8Array(ex.memory.buffer, at, cap).set(frame);
      const r = ex[fn](frame.length);
      const out = ex.out_ptr();
      return r === 1 ? { r, digits: new Uint8Array(ex.memory.buffer, out, 16).slice() } : { r };
    } catch (e) {
      if (e !== SKIP) fresh(); // a trap: the old instance's state is not trusted again
      return SKIP;
    } finally {
      if (frame) frame.fill(0);
    }
  }
  const read = (digits) => ({ digits, amount: amountOf(digits) });
  const wallet = Object.freeze({
    pkBytes,
    checkRecipient(openKemSeed, credit) {
      const o = run('check_recipient', openKemSeed, credit);
      return o !== SKIP && o.r === 1 ? Object.freeze(read(o.digits)) : null;
    },
    checkAuditor(openKemSeed, credit) {
      const o = run('check_auditor', openKemSeed, credit);
      if (o !== SKIP && o.r === 1) return Object.freeze({ outcome: 'read', ...read(o.digits) });
      return Object.freeze({ outcome: o !== SKIP && o.r === 2 ? 'recipient-unreadable' : 'unreadable' });
    },
  });
  WALLETS.add(wallet);
  return wallet;
}

/** The be8 lanes of a stored form `P` (P46, pqz-ffi `opening::pack` reversed): `packBits` bits per coefficient, big-endian. */
export function pqzUnpack(p, packBits) {
  const b = BigInt(packBits);
  const n = Math.floor((p.length * 8) / packBits);
  const out = new Uint8Array(8 * n);
  let acc = 0n, bits = 0n, j = 0;
  for (const x of p) {
    acc = (acc << 8n) | BigInt(x);
    bits += 8n;
    if (bits >= b) {
      bits -= b;
      let c = acc >> bits;
      acc &= (1n << bits) - 1n;
      for (let i = 7; i >= 0; i--) { out[8 * j + i] = Number(c & 255n); c >>= 8n; }
      j++;
    }
  }
  return out;
}
